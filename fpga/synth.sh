#!/usr/bin/env bash
# Open-source implementation flow for the LEAP core.
#   ECP5 (LFE5UM-85F): yosys synth_ecp5 + nextpnr-ecp5 place & route -> utilisation and Fmax
#   UltraScale+ (xcup): yosys synth_xilinx technology mapping -> LUT/FF/BRAM/DSP counts (no timing)
# Usage: fpga/synth.sh <LOGW> <LEARNED 0|1> [freq_MHz] [REPORT 0|1]   (REPORT=1: leap_core_rep.v, report-on-crossing)
set -euo pipefail
cd "$(dirname "$0")"
LOGW=${1:-12}; LEARNED=${2:-1}; FREQ=${3:-150}; REPORT=${4:-0}
OUT=build_w${LOGW}_l${LEARNED}; SRC=leap_core.v; TOP=leap_core
[ "$REPORT" = 1 ] && { OUT=${OUT}_r1; SRC=leap_core_rep.v; TOP=leap_core_rep; }
mkdir -p $OUT
yosys -q -l $OUT/ecp5_synth.log -p "read_verilog -I. $SRC; chparam -set LOGW $LOGW -set LEARNED $LEARNED $TOP; synth_ecp5 -top $TOP -json $OUT/leap_ecp5.json; tee -o $OUT/ecp5_stat.txt stat"
nextpnr-ecp5 --85k --package CABGA381 --json $OUT/leap_ecp5.json --freq $FREQ --seed 1 \
    --report $OUT/ecp5_report.json --log $OUT/ecp5_pnr.log --textcfg $OUT/leap_ecp5.config >/dev/null 2>&1 || true
yosys -q -l $OUT/xcup_synth.log -p "read_verilog -I. $SRC; chparam -set LOGW $LOGW -set LEARNED $LEARNED $TOP; synth_xilinx -family xcup -top $TOP; tee -o $OUT/xcup_stat.txt stat"
echo "== $OUT"; grep -E "Max frequency" $OUT/ecp5_pnr.log | tail -1
grep -E "TRELLIS_COMB|TRELLIS_FF|DP16KD|MULT18X18D|TRELLIS_RAMW" $OUT/ecp5_pnr.log | tail -5
grep -E "LUT[1-6]|FD[RS]E|RAMB|DSP|RAM[0-9]" $OUT/xcup_stat.txt
