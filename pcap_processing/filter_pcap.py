#!/usr/bin/env python3
"""
Pre-filter a PCAP to only packets belonging to DDoS or Benign flows
according to Zeek conn.log.labeled ground truth.

The filtered PCAP is much smaller and can be fed straight to cicflowmeter.
Packets whose 5-tuple does not appear in the Zeek log (or belongs to a
non-DDoS malicious flow) are dropped.

Usage:
    python3 filter_pcap.py \\
        --pcap  datasets/iot23-pcaps/34-1_192.168.1.195.pcap \\
        --zeek  datasets/opt/.../CTU-IoT-Malware-Capture-34-1/bro/conn.log.labeled \\
        --output datasets/iot23-filtered/34-1_filtered.pcap

Auto-discover Zeek log from filename prefix:
    python3 filter_pcap.py \\
        --pcap    datasets/iot23-pcaps/34-1_192.168.1.195.pcap \\
        --zeek-dir datasets/opt/Malware-Project/BigDataset/IoTScenarios \\
        --output  datasets/iot23-filtered/34-1_filtered.pcap
"""

import os
import sys
import struct
import socket
import argparse

import dpkt

PROTO_MAP = {"tcp": 6, "udp": 17, "icmp": 1}


def parse_arguments():
    parser = argparse.ArgumentParser(description="Filter PCAP to DDoS+Benign flows using Zeek labels")
    parser.add_argument("--pcap", required=True, help="Input PCAP file")
    parser.add_argument("--output", required=True, help="Output filtered PCAP file")
    parser.add_argument("--zeek", default=None, help="Explicit path to conn.log.labeled")
    parser.add_argument("--zeek-dir", default="datasets/opt/Malware-Project/BigDataset/IoTScenarios",
                        help="Base dir for auto-discovering conn.log.labeled")
    return parser.parse_args()


def find_zeek_log(prefix, zeek_dir):
    capture_num = prefix.split("-")[0]
    if "honeypot" in prefix.lower():
        capture_dir = os.path.join(zeek_dir, f"CTU-Honeypot-Capture-{capture_num}-1")
    else:
        capture_dir = os.path.join(zeek_dir, f"CTU-IoT-Malware-Capture-{capture_num}-1")

    if not os.path.isdir(capture_dir):
        return None

    for dirpath, _, filenames in os.walk(capture_dir):
        if "conn.log.labeled" in filenames:
            return os.path.join(dirpath, "conn.log.labeled")

    return None


def parse_zeek_conn_log(log_path):
    """Parse conn.log.labeled into a set of 5-tuples to keep.

    Returns a set of (src_ip_int, dst_ip_int, src_port, dst_port, proto) tuples
    (using integer IPs for fast lookup against dpkt's raw IP addresses).
    Only DDoS malicious and Benign flows are included.
    """
    keep = set()
    skipped = 0

    with open(log_path, "r") as f:
        for line in f:
            if line.startswith("#"):
                continue
            line = line.rstrip("\n")
            if not line:
                continue

            parts = line.split("\t")
            if len(parts) < 7:
                continue

            tail_parts = parts[-1].split("   ")
            if len(tail_parts) < 2:
                continue
            label_str = tail_parts[1].strip()
            detailed  = tail_parts[2].strip() if len(tail_parts) >= 3 else "-"

            is_malicious = label_str.lower().startswith("malicious")
            if is_malicious and "ddos" not in detailed.lower():
                skipped += 1
                continue

            try:
                src_ip = struct.unpack("!I", socket.inet_aton(parts[2]))[0]
                dst_ip = struct.unpack("!I", socket.inet_aton(parts[4]))[0]
                src_port = int(parts[3])
                dst_port = int(parts[5])
            except (socket.error, ValueError, IndexError):
                continue

            proto_num = PROTO_MAP.get(parts[6].lower())
            if proto_num is None:
                continue

            keep.add((src_ip, dst_ip, src_port, dst_port, proto_num))
            # Also add reverse direction so we catch both sides of a flow
            keep.add((dst_ip, src_ip, dst_port, src_port, proto_num))

    if skipped:
        print(f"  Zeek: skipped {skipped:,} non-DDoS malicious entries")
    return keep


def filter_pcap(pcap_path, keep_set, output_path):
    """Stream through pcap_path, writing packets whose 5-tuple is in keep_set."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    total = kept = 0
    REPORT_INTERVAL = 500_000

    with open(pcap_path, "rb") as in_f, open(output_path, "wb") as out_f:
        reader = dpkt.pcap.Reader(in_f)
        writer = dpkt.pcap.Writer(out_f)
        it = iter(reader)

        while True:
            try:
                ts, raw = next(it)
            except StopIteration:
                break
            except Exception as e:
                print(f"  Warning: truncated/corrupt record at packet ~{total} ({e}), stopping early")
                break

            total += 1
            if total % REPORT_INTERVAL == 0:
                print(f"  {total:,} packets processed, {kept:,} kept...")

            try:
                eth = dpkt.ethernet.Ethernet(raw)
            except Exception:
                continue

            if not isinstance(eth.data, dpkt.ip.IP):
                continue

            ip = eth.data
            proto = ip.p

            if proto == dpkt.ip.IP_PROTO_TCP and isinstance(ip.data, dpkt.tcp.TCP):
                transport = ip.data
            elif proto == dpkt.ip.IP_PROTO_UDP and isinstance(ip.data, dpkt.udp.UDP):
                transport = ip.data
            else:
                continue

            src_ip   = struct.unpack("!I", ip.src)[0]
            dst_ip   = struct.unpack("!I", ip.dst)[0]
            src_port = transport.sport
            dst_port = transport.dport

            if keep_set is None or (src_ip, dst_ip, src_port, dst_port, proto) in keep_set:
                kept += 1
                writer.writepkt(raw, ts=ts)

    return total, kept


def main():
    args = parse_arguments()

    zeek_log_path = args.zeek
    basename = os.path.basename(args.pcap)
    prefix = basename.split("_")[0]
    is_honeypot = "honeypot" in prefix.lower()

    if zeek_log_path is None:
        zeek_log_path = find_zeek_log(prefix, args.zeek_dir)

    print(f"PCAP     : {args.pcap}  ({os.path.getsize(args.pcap) / 1e9:.2f} GB)")

    if zeek_log_path is None:
        if is_honeypot:
            print(f"Zeek log : not found — honeypot capture, treating all traffic as benign")
            keep_set = None
        else:
            print(f"Error: could not find conn.log.labeled for prefix '{prefix}' under {args.zeek_dir}")
            print("Use --zeek to provide the path explicitly.")
            sys.exit(1)
    else:
        print(f"Zeek log : {zeek_log_path}")
        print("\nLoading Zeek labels...")
        keep_set = parse_zeek_conn_log(zeek_log_path)
        print(f"  {len(keep_set) // 2:,} unique flows to keep (both directions indexed: {len(keep_set):,} tuples)")

    print(f"Output   : {args.output}")

    print("\nFiltering PCAP...")
    total, kept = filter_pcap(args.pcap, keep_set, args.output)

    in_size  = os.path.getsize(args.pcap)
    out_size = os.path.getsize(args.output)
    print(f"\nDone.")
    print(f"  Packets : {total:,} → {kept:,} kept ({kept/total*100:.1f}%)")
    print(f"  Size    : {in_size/1e9:.2f} GB → {out_size/1e9:.2f} GB")


if __name__ == "__main__":
    main()
