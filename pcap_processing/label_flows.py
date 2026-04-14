#!/usr/bin/env python3
"""
Label cicflowmeter CSV output using Zeek conn.log.labeled ground truth.

Reads a cicflowmeter-generated CSV, looks up each flow's 5-tuple in the
Zeek labeled connection log, adds a Label column, and keeps only DDoS and
Benign flows. Non-DDoS malicious flows and unmatched flows are dropped.

Usage (single file):
    python3 label_flows.py \\
        --input  datasets/iot23-filtered/34-1_flows.csv \\
        --zeek   datasets/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-34-1/bro/conn.log.labeled \\
        --output datasets/iot23-labeled/34-1_labeled.csv

Usage (auto-discover Zeek log from capture prefix):
    python3 label_flows.py \\
        --input   datasets/iot23-filtered/34-1_flows.csv \\
        --zeek-dir datasets/opt/Malware-Project/BigDataset/IoTScenarios \\
        --output  datasets/iot23-labeled/34-1_labeled.csv
"""

import os
import csv
import sys
import argparse

# Maps Zeek protocol strings to IANA numbers
PROTO_MAP = {"tcp": 6, "udp": 17, "icmp": 1}


def parse_arguments():
    parser = argparse.ArgumentParser(description="Label cicflowmeter CSV with Zeek ground truth")
    parser.add_argument("--input", required=True,
                        help="cicflowmeter CSV to label")
    parser.add_argument("--output", required=True,
                        help="Output labeled CSV path")
    parser.add_argument("--zeek", default=None,
                        help="Path to conn.log.labeled (explicit)")
    parser.add_argument("--zeek-dir", default="datasets/opt/Malware-Project/BigDataset/IoTScenarios",
                        help="Base dir for auto-discovering conn.log.labeled from capture prefix")
    return parser.parse_args()


# -----------------------------------------------------------------------------
# Zeek log parsing
# -----------------------------------------------------------------------------

def find_zeek_log(prefix, zeek_dir):
    """Resolve a capture prefix like '34-1' or '5-1-Honeypot' to its conn.log.labeled path."""
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
    """Parse conn.log.labeled into a 5-tuple → (label, detailed_label) dict.

    Keeps only Benign and DDoS-malicious entries to limit memory.
    If a 5-tuple appears more than once, Malicious takes priority over Benign.
    """
    labels = {}
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

            # The last tab-field contains "tunnel_parents   label   detailed-label"
            tail_parts = parts[-1].split("   ")
            if len(tail_parts) < 2:
                continue
            label_str = tail_parts[1].strip()
            detailed   = tail_parts[2].strip() if len(tail_parts) >= 3 else "-"

            is_malicious = label_str.lower().startswith("malicious")
            if is_malicious and "ddos" not in detailed.lower():
                skipped += 1
                continue

            src_ip = parts[2]
            dst_ip = parts[4]
            try:
                src_port = int(parts[3])
                dst_port = int(parts[5])
            except (ValueError, IndexError):
                continue

            proto_num = PROTO_MAP.get(parts[6].lower())
            if proto_num is None:
                continue

            label = "Malicious" if is_malicious else "BENIGN"
            key   = (src_ip, dst_ip, src_port, dst_port, proto_num)

            # Malicious takes priority if the key already exists
            if key not in labels or label == "Malicious":
                labels[key] = (label, detailed)

    if skipped:
        print(f"  Zeek: skipped {skipped:,} non-DDoS malicious entries")
    return labels


def lookup_label(zeek_labels, src_ip, dst_ip, src_port, dst_port, proto):
    """Try forward then reverse 5-tuple lookup."""
    result = zeek_labels.get((src_ip, dst_ip, src_port, dst_port, proto))
    if result is None:
        result = zeek_labels.get((dst_ip, src_ip, dst_port, src_port, proto))
    return result


def main():
    args = parse_arguments()

    # Resolve Zeek log path
    zeek_log_path = args.zeek
    basename = os.path.basename(args.input)
    prefix   = basename.split("_")[0]
    is_honeypot = "honeypot" in prefix.lower()

    if zeek_log_path is None:
        zeek_log_path = find_zeek_log(prefix, args.zeek_dir)

    print(f"Input    : {args.input}")
    print(f"Output   : {args.output}")

    if zeek_log_path is None:
        if is_honeypot:
            print(f"Zeek log : not found — honeypot capture, all flows labeled BENIGN")
            zeek_labels = None
        else:
            print(f"Error: could not find conn.log.labeled for prefix '{prefix}' under {args.zeek_dir}")
            print("Use --zeek to provide the path explicitly.")
            sys.exit(1)
    else:
        print(f"Zeek log : {zeek_log_path}")
        print("Loading Zeek labels...")
        zeek_labels = parse_zeek_conn_log(zeek_log_path)
        n_mal = sum(1 for l, _ in zeek_labels.values() if l == "Malicious")
        n_ben = sum(1 for l, _ in zeek_labels.values() if l == "BENIGN")
        print(f"  {len(zeek_labels):,} entries loaded ({n_mal:,} DDoS, {n_ben:,} benign)")

    total = matched_ddos = matched_benign = unmatched = non_ddos = 0

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)

    with open(args.input, newline="") as in_f, \
         open(args.output, "w", newline="") as out_f:

        reader = csv.DictReader(in_f)
        if not reader.fieldnames:
            print("  Warning: input CSV is empty, nothing to label.")
            return
        fieldnames = reader.fieldnames + ["Label", "detailed_label"]
        writer = csv.DictWriter(out_f, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            total += 1
            try:
                src_port = int(row["src_port"])
                dst_port = int(row["dst_port"])
                proto    = int(row["protocol"])
            except (ValueError, KeyError):
                unmatched += 1
                continue

            if zeek_labels is None:
                # Honeypot: no Zeek log, label everything benign
                label, detailed = "BENIGN", "-"
            else:
                result = lookup_label(zeek_labels, row["src_ip"], row["dst_ip"],
                                      src_port, dst_port, proto)
                if result is None:
                    unmatched += 1
                    continue
                label, detailed = result
                if label == "Malicious" and "ddos" not in detailed.lower():
                    non_ddos += 1
                    continue

            row["Label"]          = label
            row["detailed_label"] = detailed
            writer.writerow(row)

            if label == "Malicious":
                matched_ddos += 1
            else:
                matched_benign += 1

    print(f"\nResults:")
    print(f"  Total flows in input : {total:,}")
    print(f"  Labeled DDoS         : {matched_ddos:,}")
    print(f"  Labeled Benign       : {matched_benign:,}")
    print(f"  Non-DDoS malicious   : {non_ddos:,}  (dropped)")
    print(f"  Unmatched            : {unmatched:,}  (dropped)")
    print(f"  Written to           : {args.output}")


if __name__ == "__main__":
    main()
