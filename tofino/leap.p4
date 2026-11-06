/* LEAP on Tofino 1 (TNA, P4_16): persistence sketch with a learned eviction table, d = 2 rows.
 * Compiles with the open-source bf-p4c (p4lang/p4c, backends/tofino, 9.13.4):
 *   bf-p4c --target tofino --arch tna -o build leap.p4      (placement and control plane: see README.md)
 *
 * Per bucket, five register arrays (Tofino stateful ALUs compare/add/assign but cannot shift, so the FPGA's packed
 * F/R/H bits with lazy roll-over become window stamps plus one flag; the decisions are the same):
 *   reg_fp   bit<32> : owner fingerprint (17 bits, bit 17 set; 0 = empty bucket)
 *   reg_last bit<16> : last window in which the owner was seen        -> dl = t - last: F = (dl == 0), H_0 = (dl == 1)
 *   reg_prev bit<16> : 1 iff the owner was also seen in the window before `last` -> H_1 = (dl == 2) or (dl == 1 and prev)
 *   reg_dec  bit<16> : window of the owner's last decay              -> R = (dec == t)
 *   reg_cnt  bit<16> : owner persistence P
 * Window ids run from 2 to 65534 within a measurement period (the controller resets all registers to 0 at its
 * start); NONE = 0xFFFF is never a window id. An empty bucket (all registers 0) then behaves exactly like an owner
 * that was never seen, so inserting a flow is the same operation as counting its first arrival: last = t,
 * prev = 0 (t - 0 >= 2), R = 0, P = 0 + 1.
 *
 * Every register action is selected by a table keyed on the operation and on the class of the bucket (match,
 * insert, other owner), not by if-statements, so the program has no nested control flow and the two rows
 * overlap in the pipeline (row 2 starts two stages after row 1).
 * Pass 1 (every IPv4 packet): row 1 is accessed; row 2 only if row 1 holds another owner. If both rows hold other
 *   owners, the minimum-count owner (row 1 on ties) is the candidate; if it is eligible (F = R = 0), its count bin
 *   (TCAM) and presence bits index the learned threshold table T[tbin][H][pbin], whose action compares the
 *   threshold with a 16-bit random number. A winning packet recirculates a decay request.
 * Pass 2 (decay request): DECAY re-validates that the owner is unchanged (same fingerprint, not seen and not
 *   decayed in this window) before decrementing P; REPLACE (P was 1) is a compare-and-swap on the fingerprint.
 * Test build (-DRND_FROM_PACKET): the random number is taken from the IPv4 identification field, so a replay on
 * the Tofino model can be compared bit for bit with a software reference.
 * Report build (-DREPORT): the increment returns the new count, and a table per row (installed by the controller
 *   with the report threshold ceil(alpha M); one table per row, two entries each) flags the packet that lifts its own bucket's count to the threshold; the
 *   deparser then exports its flow key in a digest, so persistent flows are listed without storing keys.
 * Forwarding is omitted (measurement logic only). In a deployment, the decay request is an ingress-mirrored,
 * truncated copy sent to the recirculation port, so the original packet is forwarded unchanged.
 */
#include <core.p4>
#include <tna.p4>

#ifdef SMALL_ROWS                          // test build: 256 buckets per row, so a short replay fills the rows
const bit<32> ROW_W = 256;
typedef bit<8> idx_t;
#define IDX1(h) h[7:0]
#define IDX2(h) h[23:16]
#define IDX_IN(x) x[7:0]
#define IDX_OUT(x) 8w0 ++ x
#else
const bit<32> ROW_W = 4096;                // buckets per row: 2 x 4096 x 32 bit = 32 KB (algorithmic layout)
typedef bit<12> idx_t;                     // log2(ROW_W)
#define IDX1(h) h[11:0]
#define IDX2(h) h[27:16]
#define IDX_IN(x) x[11:0]
#define IDX_OUT(x) 4w0 ++ x
#endif
const PortId_t RECIRC_PORT = 68;
const bit<16> NONE = 16w0xFFFF;            // "never" decay stamp written on insertion (never a window id)
const bit<2> OP_NONE = 0;                  // initial value of md.r*.op (auto-initialized metadata)
const bit<2> OP_ACCESS = 1;                // pass 1
const bit<2> OP_DECAY = 2;                 // pass 2
const bit<2> OP_REPLACE = 3;               // pass 2
// class of a bucket in pass 1, as returned by the fingerprint register (fingerprints have bit 17 set, so they
// are never 0): 0 = owned by this flow (match, or empty and now inserted), anything else = other owner's fp
const bit<32> CLS_OWN = 0;

header ethernet_h { bit<48> dst; bit<48> src; bit<16> ether_type; }
header ipv4_h {
    bit<4> version; bit<4> ihl; bit<8> diffserv; bit<16> total_len; bit<16> identification;
    bit<3> flags; bit<13> frag_offset; bit<8> ttl; bit<8> protocol; bit<16> hdr_checksum;
    bit<32> src_addr; bit<32> dst_addr;
}
// recirculated decay request (byte-aligned fields: one write source per PHV container)
header leap_h { bit<8> op; bit<8> row; bit<16> idx; bit<32> ofp; bit<32> nfp; bit<16> win; }
struct headers_t { leap_h leap; ethernet_h ethernet; ipv4_h ipv4; }

// per-row inputs/outputs of LeapRow
struct row_t {
    bit<2> op; idx_t idx; bit<32> fp; bit<32> ofp; bit<16> win;
    bit<32> stored;                        // pass 1: CLS_OWN or the other owner's fingerprint; pass 2: 1 = owner unchanged
    bit<16> dl;                            // t - last (mod 2^16)
    bit<16> pflag;                         // other owner: seen in the window before its last presence
    bit<16> r;                             // pass 1: 1 iff the owner was decayed in this window; pass 2: 1 = decay claimed
    bit<16> cnt;                           // other owner: its count P
    bit<1> f; bit<2> h;                    // other owner: F and H
}
struct meta_t {
    row_t r1; row_t r2;
    bit<3> tbin;
    bit<16> diff;                          // cnt1 |-| cnt2 (> 0 iff row 2 holds the smaller count)
    bit<5> pbin1; bit<5> pbin2;
    bit<1> elig;                           // a candidate exists and is eligible (F = R = 0)
    bit<8> row; idx_t idx; bit<32> ofp; bit<16> cnt; bit<2> h; bit<5> pbin;
    bit<16> rnd; bit<16> gap;              // gap = thr |-| rnd (> 0 iff rnd < thr)
}
struct report_t { bit<32> src; bit<32> dst; bit<16> win; }   // digest of a flow whose count reached the threshold

parser IngressParser(packet_in pkt, out headers_t hdr, out meta_t md, out ingress_intrinsic_metadata_t ig_md) {
    state start {
        pkt.extract(ig_md); pkt.advance(PORT_METADATA_SIZE);
        transition select(ig_md.ingress_port) { RECIRC_PORT: parse_leap; default: parse_ethernet; }
    }
    state parse_leap { pkt.extract(hdr.leap); transition parse_ethernet; }
    state parse_ethernet { pkt.extract(hdr.ethernet); transition select(hdr.ethernet.ether_type) { 0x0800: parse_ipv4; default: accept; } }
    state parse_ipv4 { pkt.extract(hdr.ipv4); transition accept; }
}

// One row of buckets. Four dependent stages: fp | last | prev, dec | cnt, flags.
control LeapRow(inout row_t io) {
    Register<bit<32>, idx_t>(ROW_W, 0) reg_fp;
    Register<bit<16>, idx_t>(ROW_W, 0) reg_last;
    Register<bit<16>, idx_t>(ROW_W, 0) reg_prev;
    Register<bit<16>, idx_t>(ROW_W, 0) reg_dec;
    Register<bit<16>, idx_t>(ROW_W, 0) reg_cnt;

    // ---- stage 1: fingerprint (insert into an empty bucket; classify)
    RegisterAction<bit<32>, idx_t, bit<32>>(reg_fp) ra_fp_access = {
        void apply(inout bit<32> v, out bit<32> o) {
            // a stateful ALU outputs 0 when no output instruction executes: insert and match return 0 = CLS_OWN
            if (v == 0) { v = io.fp; }                                  // insert
            else if (v != io.fp) { o = v; }                             // other owner
        }
    };
    // all actions of a register return into the same field (one action-bus slot per register)
    RegisterAction<bit<32>, idx_t, bit<32>>(reg_fp) ra_fp_check = {         // DECAY: owner unchanged?
        void apply(inout bit<32> v, out bit<32> o) { if (v == io.ofp) { o = 1; } else { o = 0; } }
    };
    RegisterAction<bit<32>, idx_t, bit<32>>(reg_fp) ra_fp_swap = {          // REPLACE: compare-and-swap the owner
        void apply(inout bit<32> v, out bit<32> o) { if (v == io.ofp) { v = io.fp; o = 1; } else { o = 0; } }
    };
    action a_fp_access() { io.stored = ra_fp_access.execute(io.idx); }
    action a_fp_check()  { io.stored = ra_fp_check.execute(io.idx); }
    action a_fp_swap()   { io.stored = ra_fp_swap.execute(io.idx); }
    table t_fp {
        key = { io.op : exact; }
        actions = { a_fp_access; a_fp_check; a_fp_swap; NoAction; }
        const entries = { OP_ACCESS : a_fp_access(); OP_DECAY : a_fp_check(); OP_REPLACE : a_fp_swap(); }
        default_action = NoAction(); size = 4;
    }

    // ---- stage 2: last-presence stamp; returns dl = t - last
    RegisterAction<bit<16>, idx_t, bit<16>>(reg_last) ra_last_seen = { void apply(inout bit<16> v, out bit<16> o) { o = io.win - v; v = io.win; } };
    RegisterAction<bit<16>, idx_t, bit<16>>(reg_last) ra_last_read = { void apply(inout bit<16> v, out bit<16> o) { o = io.win - v; } };
    RegisterAction<bit<16>, idx_t, bit<16>>(reg_last) ra_last_set  = { void apply(inout bit<16> v) { v = io.win; } };
    action a_last_seen() { io.dl = ra_last_seen.execute(io.idx); }
    action a_last_read() { io.dl = ra_last_read.execute(io.idx); }
    action a_last_set()  { ra_last_set.execute(io.idx); }
    table t_last {
        key = { io.op : exact; io.stored : ternary; }
        actions = { a_last_seen; a_last_read; a_last_set; NoAction; }
        const entries = {
            (OP_ACCESS, CLS_OWN &&& 0xFFFFFFFF) : a_last_seen();            // owner: stamp t
            (OP_ACCESS, 0 &&& 0) : a_last_read();                            // other owner: read only
            (OP_DECAY, 1 &&& 0xFFFFFFFF) : a_last_read();                    // validated decay: owner seen in t?
            (OP_REPLACE, 1 &&& 0xFFFFFFFF) : a_last_set();                   // installed challenger: stamp t
        }
        default_action = NoAction(); size = 8;                               // dl stays 0: a failed DECAY is not claimed
    }

    // ---- stage 3: previous-presence flag and decay stamp
    RegisterAction<bit<16>, idx_t, bit<16>>(reg_prev) ra_prev_shift = {     // first arrival in window t: prev = (last == t-1)
        void apply(inout bit<16> v) { if (io.dl == 1) { v = 1; } else if (io.dl != 0) { v = 0; } }
    };
    RegisterAction<bit<16>, idx_t, bit<16>>(reg_prev) ra_prev_read  = { void apply(inout bit<16> v, out bit<16> o) { o = v; } };
    RegisterAction<bit<16>, idx_t, bit<16>>(reg_prev) ra_prev_reset = { void apply(inout bit<16> v) { v = 0; } };
    action a_prev_shift() { ra_prev_shift.execute(io.idx); }
    action a_prev_read()  { io.pflag = ra_prev_read.execute(io.idx); }
    action a_prev_reset() { ra_prev_reset.execute(io.idx); }
    table t_prev {
        key = { io.op : exact; io.stored : ternary; }
        actions = { a_prev_shift; a_prev_read; a_prev_reset; NoAction; }
        const entries = {
            (OP_ACCESS, CLS_OWN &&& 0xFFFFFFFF) : a_prev_shift();
            (OP_ACCESS, 0 &&& 0) : a_prev_read();
            (OP_REPLACE, 1 &&& 0xFFFFFFFF) : a_prev_reset();
        }
        default_action = NoAction(); size = 8;
    }
    RegisterAction<bit<16>, idx_t, bit<16>>(reg_dec) ra_dec_read  = {        // R = 1 iff decayed in window t
        void apply(inout bit<16> v, out bit<16> o) { if (v == io.win) { o = 1; } else { o = 0; } }
    };
    RegisterAction<bit<16>, idx_t, bit<16>>(reg_dec) ra_dec_reset = { void apply(inout bit<16> v) { v = NONE; } };
    RegisterAction<bit<16>, idx_t, bit<16>>(reg_dec) ra_dec_claim = {        // DECAY: owner absent in t and not yet decayed in t
        void apply(inout bit<16> v, out bit<16> o) { if (io.dl != 0 && v != io.win) { v = io.win; o = 1; } else { o = 0; } }
    };
    action a_dec_read()  { io.r = ra_dec_read.execute(io.idx); }
    action a_dec_reset() { ra_dec_reset.execute(io.idx); }
    action a_dec_claim() { io.r = ra_dec_claim.execute(io.idx); }
    table t_dec {
        key = { io.op : exact; io.stored : ternary; }
        actions = { a_dec_read; a_dec_reset; a_dec_claim; NoAction; }
        const entries = {
            (OP_ACCESS, 0 &&& 0) : a_dec_read();                             // owner or other owner
            (OP_DECAY, 1 &&& 0xFFFFFFFF) : a_dec_claim();
            (OP_REPLACE, 1 &&& 0xFFFFFFFF) : a_dec_reset();
        }
        default_action = NoAction(); size = 8;
    }

    // ---- stage 4: count, and the window-state bits of another owner
    RegisterAction<bit<16>, idx_t, bit<16>>(reg_cnt) ra_cnt_set1 = { void apply(inout bit<16> v) { v = 1; } };
#ifdef REPORT
    RegisterAction<bit<16>, idx_t, bit<16>>(reg_cnt) ra_cnt_inc  = {         // once per window; +2 after a decay in t; returns the new count
        void apply(inout bit<16> v, out bit<16> o) { if (io.dl != 0) { if (io.r == 1) { v = v + 2; } else { v = v + 1; } o = v; } }
    };
#else
    RegisterAction<bit<16>, idx_t, bit<16>>(reg_cnt) ra_cnt_inc  = {         // once per window; +2 after a decay in t
        void apply(inout bit<16> v) { if (io.dl != 0) { if (io.r == 1) { v = v + 2; } else { v = v + 1; } } }
    };
#endif
    RegisterAction<bit<16>, idx_t, bit<16>>(reg_cnt) ra_cnt_read = { void apply(inout bit<16> v, out bit<16> o) { o = v; } };
    RegisterAction<bit<16>, idx_t, bit<16>>(reg_cnt) ra_cnt_dec  = { void apply(inout bit<16> v) { if (v > 1) { v = v - 1; } } };
    action a_cnt_set1() { ra_cnt_set1.execute(io.idx); }
#ifdef REPORT
    action a_cnt_inc()  { io.cnt = ra_cnt_inc.execute(io.idx); }       // own bucket: io.cnt = new count (0 if not incremented)
#else
    action a_cnt_inc()  { ra_cnt_inc.execute(io.idx); }
#endif
    action a_cnt_read() { io.cnt = ra_cnt_read.execute(io.idx); }
    action a_cnt_dec()  { ra_cnt_dec.execute(io.idx); }
    table t_cnt {
        key = { io.op : exact; io.stored : ternary; io.r : ternary; }
        actions = { a_cnt_set1; a_cnt_inc; a_cnt_read; a_cnt_dec; NoAction; }
        const entries = {
            (OP_ACCESS, CLS_OWN &&& 0xFFFFFFFF, 0 &&& 0) : a_cnt_inc();
            (OP_ACCESS, 0 &&& 0, 0 &&& 0) : a_cnt_read();
            (OP_DECAY, 1 &&& 0xFFFFFFFF, 1 &&& 0xFFFF) : a_cnt_dec();
            (OP_REPLACE, 1 &&& 0xFFFFFFFF, 0 &&& 0) : a_cnt_set1();
        }
        default_action = NoAction(); size = 8;
    }
    action set_flags(bit<1> f, bit<2> h) { io.f = f; io.h = h; }
    table t_flags {                                                          // F = (dl == 0); H = (H_1, H_0)
        key = { io.dl : ternary; io.pflag : ternary; }
        actions = { set_flags; }
        const entries = {
            (0 &&& 0xFFFF, 0 &&& 0) : set_flags(1, 0);
            (1 &&& 0xFFFF, 1 &&& 0xFFFF) : set_flags(0, 3);
            (1 &&& 0xFFFF, 0 &&& 0) : set_flags(0, 1);
            (2 &&& 0xFFFF, 0 &&& 0) : set_flags(0, 2);
        }
        default_action = set_flags(0, 0); size = 8;
    }

    apply {
        t_fp.apply();
        t_last.apply();
        t_prev.apply();
        t_dec.apply();
        t_cnt.apply();
        t_flags.apply();
    }
}

control Ingress(inout headers_t hdr, inout meta_t md, in ingress_intrinsic_metadata_t ig_md,
                in ingress_intrinsic_metadata_from_parser_t prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t tm_md) {

    Hash<bit<32>>(HashAlgorithm_t.CRC32) h_idx;                       // two 12-bit row indices
    CRCPolynomial<bit<32>>(0x1EDC6F41, true, false, false, 0xFFFFFFFF, 0xFFFFFFFF) crc32c;
    Hash<bit<17>>(HashAlgorithm_t.CUSTOM, crc32c) h_fp;                // 17-bit fingerprint
    Random<bit<16>>() rng;
    LeapRow() row1;
    LeapRow() row2;

    Register<bit<32>, bit<1>>(1, 0) reg_window;                        // {tbin(3), win(16)}: written by the controller per window
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_window) ra_window = { void apply(inout bit<32> v, out bit<32> o) { o = v; } };

    // ---- stage 0: pass-2 request or pass-1 hashing (hash/RNG outputs: at most 32 immediate bits per table)
    action from_request() {
        md.r1.idx = IDX_IN(hdr.leap.idx); md.r1.ofp = hdr.leap.ofp; md.r1.fp = hdr.leap.nfp; md.r1.win = hdr.leap.win;
        md.r2.idx = IDX_IN(hdr.leap.idx); md.r2.ofp = hdr.leap.ofp; md.r2.fp = hdr.leap.nfp; md.r2.win = hdr.leap.win;
        dprsr_md.drop_ctl = 1;
    }
    action op_row1() { md.r1.op = hdr.leap.op[1:0]; }
    action op_row2() { md.r2.op = hdr.leap.op[1:0]; }
    table t_req_row { key = { hdr.leap.row : exact; } actions = { op_row1; op_row2; } const entries = { 0 : op_row1(); 1 : op_row2(); } default_action = op_row1(); size = 2; }
    action get_window() { bit<32> wv = ra_window.execute(0); md.tbin = wv[18:16]; md.r1.win = wv[15:0]; md.r2.win = wv[15:0]; }
    action get_idx() { bit<32> hv = h_idx.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr}); md.r1.idx = IDX1(hv); md.r2.idx = IDX2(hv); md.r1.op = OP_ACCESS; }
    action get_fp()  {                                                 // bit 17 set: a fingerprint is never 0
        bit<17> f = h_fp.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr}); md.r1.fp = 14w0 ++ 1w1 ++ f; md.r2.fp = 14w0 ++ 1w1 ++ f;
    }
#ifdef RND_FROM_PACKET
    action get_rnd() { md.rnd = hdr.ipv4.identification; }           // test build: draws supplied by the replay tool
#else
    action get_rnd() { md.rnd = rng.get(); }
#endif
    table t_window { actions = { get_window; } default_action = get_window(); size = 1; }
    table t_idx { actions = { get_idx; } default_action = get_idx(); size = 1; }
    table t_fp  { actions = { get_fp; }  default_action = get_fp();  size = 1; }
    table t_rnd { actions = { get_rnd; } default_action = get_rnd(); size = 1; }

    // ---- row 2 is accessed only if row 1 holds another owner
    action go2() { md.r2.op = OP_ACCESS; }
    table t_go {
        key = { md.r1.op : exact; md.r1.stored : ternary; }
        actions = { go2; NoAction; }
        const entries = {
            (OP_ACCESS, CLS_OWN &&& 0xFFFFFFFF) : NoAction();
            (OP_ACCESS, 0 &&& 0) : go2();
        }
        default_action = NoAction(); size = 4;
    }

    // ---- candidate selection, count bins, learned threshold, decay request
    // count bin pbin = 2*msb(P) + next bit: 22 ternary entries per row (installed by the controller)
    action set_pbin1(bit<5> b) { md.pbin1 = b; }
    action set_pbin2(bit<5> b) { md.pbin2 = b; }
    table t_pbin1 { key = { md.r1.cnt : ternary; } actions = { set_pbin1; } size = 32; default_action = set_pbin1(23); }
    table t_pbin2 { key = { md.r2.cnt : ternary; } actions = { set_pbin2; } size = 32; default_action = set_pbin2(23); }
    action calc_diff() { md.diff = md.r1.cnt |-| md.r2.cnt; }
    table t_diff { actions = { calc_diff; } default_action = calc_diff(); size = 1; }
    action sel_row1() { md.row = 0; md.idx = md.r1.idx; md.ofp = md.r1.stored; md.cnt = md.r1.cnt; md.h = md.r1.h; md.pbin = md.pbin1; md.elig = 1; }
    action sel_row2() { md.row = 1; md.idx = md.r2.idx; md.ofp = md.r2.stored; md.cnt = md.r2.cnt; md.h = md.r2.h; md.pbin = md.pbin2; md.elig = 1; }
    table t_sel {                                                      // both rows hold other owners; min count, row 1 on ties
        key = { md.r2.op : exact; md.r2.stored : ternary; md.diff : ternary;
                md.r1.f : ternary; md.r1.r : ternary; md.r2.f : ternary; md.r2.r : ternary; }
        actions = { sel_row1; sel_row2; NoAction; }
        const entries = {
            (OP_ACCESS, CLS_OWN &&& 0xFFFFFFFF, 0 &&& 0, 0 &&& 0, 0 &&& 0, 0 &&& 0, 0 &&& 0) : NoAction();
            (OP_ACCESS, 0 &&& 0, 0 &&& 0xFFFF, 0 &&& 1, 0 &&& 0xFFFF, 0 &&& 0, 0 &&& 0) : sel_row1();   // diff = 0, row 1 eligible (F = R = 0)
            (OP_ACCESS, 0 &&& 0, 0 &&& 0xFFFF, 0 &&& 0, 0 &&& 0, 0 &&& 0, 0 &&& 0) : NoAction();       // diff = 0, row 1 not eligible
            (OP_ACCESS, 0 &&& 0, 0 &&& 0, 0 &&& 0, 0 &&& 0, 0 &&& 1, 0 &&& 0xFFFF) : sel_row2();      // diff > 0, row 2 eligible
        }
        default_action = NoAction(); size = 8;                         // otherwise the candidate is not eligible
    }
    // learned decay thresholds T[tbin][H][pbin]: 8 x 4 x 24 = 768 exact-match entries; the action fuses the
    // 16-bit comparison with the random draw into one saturating subtraction
    action set_thr(bit<16> thr) { md.gap = thr |-| md.rnd; }
    table t_policy { key = { md.elig : exact; md.tbin : exact; md.h : exact; md.pbin : exact; } actions = { set_thr; } size = 1024; default_action = set_thr(0); }
    action req(bit<8> op) {
        hdr.leap.setValid(); hdr.leap.op = op; hdr.leap.row = md.row; hdr.leap.idx = IDX_OUT(md.idx);
        hdr.leap.ofp = md.ofp; hdr.leap.nfp = md.r1.fp; hdr.leap.win = md.r1.win;
        tm_md.ucast_egress_port = RECIRC_PORT;
    }
#ifdef REPORT
    // report-on-crossing: the flow's own bucket was incremented to the threshold (or past it by the +2 after a decay);
    // entries (installed with thr = ceil(alpha M)): (ACCESS, own, thr, *) and (ACCESS, own, thr + 1, r = 1)
    action report() { dprsr_md.digest_type = 1; }
    table t_rep1 { key = { md.r1.op : exact; md.r1.stored : ternary; md.r1.cnt : exact; md.r1.r : ternary; }
                   actions = { report; NoAction; } default_action = NoAction(); size = 4; }
    table t_rep2 { key = { md.r2.op : exact; md.r2.stored : ternary; md.r2.cnt : exact; md.r2.r : ternary; }
                   actions = { report; NoAction; } default_action = NoAction(); size = 4; }
#endif
    table t_req {                                                      // rnd < T: request a decay (P = 1: the decay evicts the owner)
        key = { md.gap : ternary; md.cnt : ternary; }
        actions = { req; NoAction; }
        const entries = {
            (0 &&& 0xFFFF, 0 &&& 0) : NoAction();
            (0 &&& 0, 1 &&& 0xFFFF) : req(6w0 ++ OP_REPLACE);
            (0 &&& 0, 0 &&& 0) : req(6w0 ++ OP_DECAY);
        }
        default_action = NoAction(); size = 4;
    }

    apply {
        if (hdr.leap.isValid()) { from_request(); t_req_row.apply(); }          // pass 2
        else if (hdr.ipv4.isValid()) { t_window.apply(); t_idx.apply(); t_fp.apply(); t_rnd.apply(); }   // pass 1
        row1.apply(md.r1);
        t_go.apply();
        row2.apply(md.r2);
        t_pbin1.apply(); t_pbin2.apply();
        t_diff.apply();
        t_sel.apply();
        t_policy.apply();
        t_req.apply();
#ifdef REPORT
        t_rep1.apply(); t_rep2.apply();
#endif
    }
}

control IngressDeparser(packet_out pkt, inout headers_t hdr, in meta_t md, in ingress_intrinsic_metadata_for_deparser_t dprsr_md) {
#ifdef REPORT
    Digest<report_t>() rep_digest;
    apply {
        if (dprsr_md.digest_type == 1) { rep_digest.pack({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, md.r1.win}); }
        pkt.emit(hdr);
    }
#else
    apply { pkt.emit(hdr); }
#endif
}
parser EgressParser(packet_in pkt, out headers_t hdr, out meta_t md, out egress_intrinsic_metadata_t eg_md) {
    state start { pkt.extract(eg_md); transition accept; }
}
control Egress(inout headers_t hdr, inout meta_t md, in egress_intrinsic_metadata_t eg_md,
               in egress_intrinsic_metadata_from_parser_t eprsr_md, inout egress_intrinsic_metadata_for_deparser_t edprsr_md,
               inout egress_intrinsic_metadata_for_output_port_t eoport_md) { apply { } }
control EgressDeparser(packet_out pkt, inout headers_t hdr, in meta_t md, in egress_intrinsic_metadata_for_deparser_t edprsr_md) {
    apply { pkt.emit(hdr); }
}
@pa_auto_init_metadata                     // metadata starts at 0 (OP_NONE, no candidate, ...)
Pipeline(IngressParser(), Ingress(), IngressDeparser(), EgressParser(), Egress(), EgressDeparser()) pipe;
Switch(pipe) main;
