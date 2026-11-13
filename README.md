# LEAP: Hardware-Aware Learned Eviction for Line-Rate Persistent Flow Measurement on FPGAs and Programmable Switches

LEAP is a persistence sketch that estimates in how many measurement windows each flow appears. Like Pontus, it keeps
one owner flow and its count per bucket and, on a full collision, decays the minimum-count owner. Instead of the
hand-tuned decay probability 1/(P+1), it reads a learned table indexed by the owner's count, whether the owner was
seen in the two previous windows (two bits taken from the fingerprint, so a bucket stays 32 bits), and the time in
the measurement period. The table costs one memory read and one comparison per full collision, so the same policy runs
on a CPU, an FPGA pipeline, and a Tofino switch.

This repository contains LEAP on these three platforms, the learned table, and the code that trains it. The
[technical report](LEAP_technical_report.pdf) has the analysis, the training procedure, and the hardware details.

| Path | Content |
|---|---|
| `table/leap_table.txt` | The learned policy compiled into a table: header `8 4 24`, then 768 decay probabilities in `[time bin][H][count bin]` order (8 time bins, 4 presence patterns, 24 count bins). Each platform stores them as 16-bit thresholds. |
| `table/leap_policy.json` | The nine parameters (theta) of the learned logistic policy from which the table is compiled. |
| `train/learn_policy.py` | Two-stage training: Stage 1 fits a classifier on hindsight labels and derives a starting policy; Stage 2 refines it with CMA-ES, scoring every candidate table on the training trace. |
| `train/leap_sim.cpp` | Functional model of LEAP used in the training loop (bit-identical to `cpu/leap.h`), with the Pontus rule as the baseline and the log of decay opportunities for Stage 1. |
| `cpu/leap.h` | Header-only C++17 implementation (32-bit buckets, d rows, learned table, report-on-crossing). |
| `cpu/leap_demo.cpp` | Runs LEAP over a stream of flow keys and prints the accuracy on the persistent flows. |
| `cpu/pcap2keys.cpp` | Converts a pcap stream into 8-byte flow keys (IPv4 source and destination). |
| `fpga/leap_core.v` | Seven-stage Verilog pipeline (S0-S6) that accepts a packet almost every clock cycle. |
| `fpga/leap_core_rep.v` | The same core with report-on-crossing: flags the packet whose flow's count reaches a threshold. |
| `fpga/model/` | Bit-exact C++ model of the core and the generator of test vectors (`golden.cpp`). |
| `fpga/tb_leap.v`, `fpga/tb_leap_rep.v` | Test benches that check the RTL packet by packet against the model. |
| `fpga/synth.sh` | Synthesis and place-and-route with Yosys and nextpnr (Lattice ECP5), and synthesis for UltraScale+. |
| `tofino/leap.p4` | P4_16 program for Tofino 1 (TNA); `-DREPORT` adds report-on-crossing digests. |
| `tofino/controller.py` | Control plane (bfrt_python): installs the tables and advances the window. |

## CPU

The paper uses the public MAWI traces of samplepoint F (https://mawi.wide.ad.jp/mawi/samplepoint-F/2026/), captured
at 14:00 on the 15th of January (training), April, May, July and October 2026 (test), e.g. `202604151400.pcap.gz`.
Tested with g++ 13, Python 3.13 (numpy, scikit-learn, cma), Icarus Verilog 12, Yosys 0.33 and nextpnr 0.6.

```bash
cd cpu && make
zcat 202604151400.pcap.gz | ./pcap2keys 30000000 > keys.bin   # first 30 M IPv4 packets -> 8-byte keys
./leap_demo keys.bin ../table/leap_table.txt 32 1500 0.4  # 32 KB, M = 1500 windows, persistence threshold 0.4
```
`leap_demo` splits the stream into M windows of equal length and prints the average absolute and relative error
(AAE, ARE) on the flows that appear in at least alpha*M windows, and the flows reported on crossing.
On the April 2026 MAWI trace of the paper (first 30 M packets), it prints `"AAE":4.8205` for seed 1 at 32 KB.

To use LEAP in other code (compile with `-I cpu`):
```cpp
#include "leap.h"
leap::Table table = leap::Table::load("table/leap_table.txt");
leap::Sketch sk(32 * 1024, /*d=*/2, /*M=*/1500, table, /*seed=*/1);
sk.set_report_threshold(600);                 // optional: ceil(alpha * M)
bool report = sk.update(key);                 // per packet; true: this packet's flow just became persistent
sk.new_window();                              // at the end of each window
uint32_t estimate = sk.query(key);
```

## Training

The policy is trained on one trace (in the paper, the first 30 M packets of the MAWI trace of 15 January 2026,
14:00) and then used unchanged on all others.
```bash
pip install -r requirements.txt
mkdir -p data/logs && zcat 202601151400.pcap.gz | cpu/pcap2keys 30000000 > data/mawi_202601151400.bin
g++ -O3 -std=c++17 -o train/leap_sim train/leap_sim.cpp
# Stage 1 data: every decay opportunity under the Pontus rule, labeled by whether the owner ends up persistent
for m in 16 32; do train/leap_sim log data/mawi_202601151400.bin 1500 $m 1 data/logs/jan_m$m.bin; done
POLICY_DIR=policy python3 train/learn_policy.py 14 8                                         # Stage 1, then 14 generations
POLICY_DIR=policy_final python3 train/learn_policy.py 12 8 train/out/policy/leap_policy.json  # restart: 12 more
```
Each candidate is compiled into the table format and run by `leap_sim` at 16, 32, and 64 KB with two hash seeds; its
fitness is its AAE relative to the Pontus rule in the same buckets. A run of 26 generations with population 8 takes
about 40 minutes on four cores; the result is in `train/out/policy_final/leap_table.txt` (same format as
`table/leap_table.txt`).

## FPGA

`leap_core` is a seven-stage pipeline (S0-S6) that accepts a packet (key, 4-bit window id) per cycle and outputs the
flow's estimate six cycles later, while S6 writes the buckets back. Buckets are 36-bit block-RAM words: the 32-bit
bucket (17-bit fingerprint, 11-bit count P, flags F and R, presence bits H) plus a 4-bit window stamp in the parity
bits, which replaces the end-of-window sweep by a lazy roll-over on the next access. Hashes are H3 (XOR trees), the
random number comes from a 16-bit LFSR, and the threshold comparison is made one stage early, in S4, while S5 takes
the final decision on the latest bucket state (Section IV-A of the paper, Theorem S2 of the report).
Interface rules: leave a one-cycle input gap (`in_valid` low) when `in_win` changes; write the 96 thresholds of a new
time bin through `cfg_we/cfg_addr/cfg_data` (address `{H, count bin}`) while the pipeline is empty. The core starts
from cleared block RAM and does not clear its buckets between measurement periods.

```bash
cd fpga/model && g++ -O2 -std=c++17 -o golden golden.cpp
# 400 K packets, windows of 300 packets, 1300 windows per period, 2^12 buckets per row (32 KB), learned table
./golden ../../cpu/keys.bin 400000 300 1300 12 ../../table/leap_table.txt ../vectors.hex ../thr.hex
cd .. && iverilog -g2005 -o tb.vvp tb_leap.v leap_core.v && vvp -n tb.vvp      # prints mismatches=0 and PASS
./synth.sh 12 1 150          # LOGW = 12, learned table: utilization and Fmax in build_w12_l1/
```
The 150 MHz target only steers the placer; nextpnr reports the achieved Fmax (67.3 MHz for the 32 KB core on an
ECP5-85F), and the "FAIL at 150 MHz" line in its log is expected. The report-on-crossing variant (threshold 520):
```bash
cd fpga/model && ./golden ../../cpu/keys.bin 400000 300 1300 12 ../../table/leap_table.txt ../vectors.hex ../thr.hex 520
cd .. && iverilog -g2005 -P tb_leap_rep.REP=1 -P tb_leap_rep.RTHR=520 -o tb_rep.vvp tb_leap_rep.v leap_core_rep.v
vvp -n tb_rep.vvp            # prints mismatches=0 and PASS
./synth.sh 12 1 150 1        # synthesis of the report variant
```

## Tofino

```bash
cd tofino
bf-p4c --target tofino --arch tna -o build leap.p4               # 11 of the 12 stages of Tofino 1
bf-p4c --target tofino --arch tna -DREPORT -o build_rep leap.p4  # with report digests (same 11 stages)
```
Each of the two rows keeps five register arrays per bucket: fingerprint (32 bits), count, last window seen, whether
the owner was also seen in the window before, and window of the last decay (16 bits each), 96 bits in all. The flags of the paper follow from them
(`F = (t - last == 0)`, and so on), because the stateful ALUs of Tofino cannot shift the packed bits. Register actions
are selected by small tables, not by branches, so the two rows overlap in the pipeline. A decay is decided in stage 9
and applied by a recirculated request that re-checks the owner's fingerprint.

`controller.py` runs in `bfshell` after `bf_switchd` has loaded the program; it reads its settings from the
environment, so give `LEAP_TABLE` as an absolute path (and export the variables where the bfrt_python script runs):
```bash
LEAP_TABLE=$PWD/../table/leap_table.txt LEAP_M=1500 bfshell -b controller.py   # LEAP_REPORT_THR=600 for the report build
```
It installs the 44 count-bin entries and the 768 policy entries, clears the registers, and opens window 1. Call
`set_window(w, M)` at the start of every window and `start_period()` at the start of every measurement period.
The program forwards nothing (measurement logic only); in a deployment, the decay request is an ingress-mirrored,
truncated copy, so the original packet is forwarded unchanged. We ran a reduced build (`-DSMALL_ROWS -DRND_FROM_PACKET`:
256 buckets per row, random numbers taken from the packet) on Intel's Tofino model, where it matched a C++ reference
(not included) register for register; the report entries of `controller.py` were compiled but not run.
