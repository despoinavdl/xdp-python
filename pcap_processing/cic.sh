#!/usr/bin/env bash
# Full pipeline: filter PCAP → cicflowmeter (fwd features only) → label with Zeek
#
# Outputs per capture:
#   datasets/iot23-filtered/<prefix>_filtered.pcap   (DDoS+Benign packets only)
#   datasets/iot23-labeled/<prefix>_labeled.csv      (labeled, fwd-only features)

set -e

# Always run relative to the project root regardless of where the script is invoked from.
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$SCRIPT_DIR/.."

FIELDS="src_ip,dst_ip,src_port,dst_port,protocol,timestamp,\
tot_fwd_pkts,totlen_fwd_pkts,fwd_pkts_s,\
fwd_iat_tot,fwd_iat_mean,fwd_iat_min,fwd_iat_max,fwd_iat_std,\
fwd_pkt_len_max,fwd_pkt_len_min,fwd_pkt_len_mean,fwd_pkt_len_std,\
fwd_header_len,fwd_seg_size_min,init_fwd_win_byts,fwd_act_data_pkts,\
fin_flag_cnt,syn_flag_cnt,rst_flag_cnt,psh_flag_cnt,ack_flag_cnt"

# PCAPs to process. Add raw PCAP paths here (datasets/iot23-pcaps/...).
# If a run is interrupted, the skip check below makes it safe to re-run.
PENDING=(
)

mkdir -p datasets/iot23-filtered datasets/iot23-labeled

# Max number of PCAPs to process concurrently.
# Keep low (2-3) when large PCAPs are in the list — cicflowmeter holds
# all flow state in memory, so RAM usage scales with input size.
MAX_PARALLEL=3

active_jobs=0

for pcap in "${PENDING[@]}"; do
    base=$(basename "${pcap%.pcap}")
    # For honeypot captures like 7-1-Honeypot_01, keep the full name as prefix
    # so each part gets its own output files. For normal captures like
    # 44-1_192.168.1.199, use only the first underscore-delimited field.
    if [[ "$base" =~ ^[0-9]+-[0-9]+-[A-Za-z]+_[0-9]+$ ]]; then
        prefix="$base"
    else
        prefix=$(echo "$base" | cut -d'_' -f1)
    fi
    filtered="datasets/iot23-filtered/${prefix}_filtered.pcap"
    flows="datasets/iot23-filtered/${prefix}_flows.csv"
    labeled="datasets/iot23-labeled/${prefix}_labeled.csv"

    if [ -f "$labeled" ]; then
        echo "=== $prefix — already done, skipping ==="
        echo ""
        continue
    fi

    echo "=== $prefix ==="

    # Capture loop variables in locals so the subshell sees the right values
    # even after the outer loop advances to the next iteration.
    _pcap="$pcap" _filtered="$filtered" _flows="$flows" _labeled="$labeled" _prefix="$prefix"
    (
        echo "  [1/3] Filtering PCAP..."
        python3 pcap_processing/filter_pcap.py --pcap "$_pcap" --output "$_filtered"

        echo "  [2/3] Running cicflowmeter..."
        cicflowmeter -f "$_filtered" --fields "$FIELDS" -c "$_flows"

        echo "  [3/3] Labeling flows..."
        python3 pcap_processing/label_flows.py --input "$_flows" --output "$_labeled"

        echo "  Done: $_labeled"
        echo ""
    ) &

    active_jobs=$((active_jobs + 1))
    if (( active_jobs >= MAX_PARALLEL )); then
        wait -n
        active_jobs=$((active_jobs - 1))
    fi

done

wait
echo "=== All captures processed ==="
echo "Labeled CSVs in datasets/iot23-labeled/"
