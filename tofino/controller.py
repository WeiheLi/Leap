# Control plane of leap.p4 (bfrt_python; run inside bfshell, e.g. `bfshell -b controller.py`, after bf_switchd has
# loaded the program). It installs the count-bin and policy tables once, clears the registers at the start of a
# measurement period, and writes the window register at the start of every window.
#   install("../table/leap_table.txt")               # 2 x 22 count-bin entries, 768 policy entries
#   install(..., report_threshold=600)               # report build (-DREPORT): also the report entries, ceil(alpha*M)
#   start_period(); then for w in 1..M: set_window(w, M) at the start of window w
import os

ing = bfrt.leap.pipe.Ingress
OP_ACCESS, CLS_OWN = 1, 0


def install(table_path, report_threshold=None):
    # count bins: pbin = 2*msb(P) + the bit below it, as ternary entries on the 16-bit count (default action: 23)
    ents = [(1, 0xFFFF, 0)]
    for k in range(1, 12):
        for b in (0, 1):
            if 2 * k + b <= 22:
                ents.append(((1 << k) | (b << (k - 1)), 0xFFFF & ~((1 << (k - 1)) - 1), 2 * k + b))
    for prio, (val, mask, pb) in enumerate(ents):
        ing.t_pbin1.add_with_set_pbin1(cnt=val, cnt_mask=mask, MATCH_PRIORITY=prio, b=pb)
        ing.t_pbin2.add_with_set_pbin2(cnt=val, cnt_mask=mask, MATCH_PRIORITY=prio, b=pb)
    # learned thresholds T[tbin][H][pbin] as 16-bit values (key: eligible = 1, tbin, H, pbin)
    tok = open(table_path).read().split()
    T, HB, NP = int(tok[0]), int(tok[1]), int(tok[2])
    vals = [float(x) for x in tok[3:3 + T * HB * NP]]
    for tb in range(T):
        for h in range(HB):
            for pb in range(NP):
                thr = int(round(min(65535.0, max(0.0, vals[(tb * HB + h) * NP + pb] * 65536.0))))
                ing.t_policy.add_with_set_thr(elig=1, tbin=tb, h=h, pbin=pb, thr=thr)
    # report build: flag the packet whose own count reaches the threshold (or passes it by the +2 after a decay)
    if report_threshold is not None:
        for t in (ing.t_rep1, ing.t_rep2):
            t.add_with_report(op=OP_ACCESS, stored=CLS_OWN, stored_mask=0xFFFFFFFF, cnt=report_threshold, r=0, r_mask=0,
                              MATCH_PRIORITY=0)
            t.add_with_report(op=OP_ACCESS, stored=CLS_OWN, stored_mask=0xFFFFFFFF, cnt=report_threshold + 1, r=1, r_mask=1,
                              MATCH_PRIORITY=1)
    print("installed", 2 * len(ents), "count-bin and", T * HB * NP, "policy entries", flush=True)
    return T


def start_period():
    # all registers to 0: every bucket is empty (an owner that was never seen)
    for row in (ing.row1, ing.row2):
        for reg in ("reg_fp", "reg_last", "reg_prev", "reg_dec", "reg_cnt"):
            getattr(row, reg).clear()


def set_window(w, M, T=8):
    # window w = 1..M of the period; window ids start at 2 (0xFFFF means "never"), the time bin is the eighth of the period
    tbin = (w - 1) * T // M
    ing.reg_window.mod(REGISTER_INDEX=0, f1=(tbin << 16) | (w + 1))


# as a script: install the tables, clear the registers, and open window 1; then call set_window(w, M) once per window
TABLE = os.environ.get("LEAP_TABLE", os.path.join(os.getcwd(), "..", "table", "leap_table.txt"))
install(TABLE, int(os.environ["LEAP_REPORT_THR"]) if "LEAP_REPORT_THR" in os.environ else None)
start_period()
set_window(1, int(os.environ.get("LEAP_M", "1500")))
