// LEAP: line-rate persistence sketch with a learned eviction table (FPGA core, v3).
// One packet per clock, 7-stage pipeline:
//   A input -> B H3 hashing -> C BRAM read -> D pbin of the read words
//   -> E speculative decay draw: threshold slice[{H, pbin}] vs. 16-bit LFSR, on the newest committed state
//   -> F final decision: forwards the word of the immediately preceding packet; any change it made to a
//        bucket sets F or R, which makes that bucket ineligible for decay, so the threshold path never
//        needs same-cycle forwarding
//   -> G write-back + estimate.
// Forwarding: the E logic (on D registers) selects among {G (2 ahead), H1 (3 ahead), H2 (4 ahead), BRAM};
// the F logic (on E registers) among {G (1 ahead), E's word}.
// All forwarding selects are compared one stage early and registered.
// Interface rule: keep in_valid low for one cycle whenever in_win changes, so that the packets on either
// side of a window boundary are two stages apart (the roll-over clears F/R across the boundary, and S4
// forwarding then sees the update of the last packet of the old window).
// Bit-exact with model/leap_hw.h (tb_leap.v, model/golden.cpp).
`default_nettype none
module leap_core #(
    parameter LOGW = 12,                 // buckets per row = 2^LOGW (2 rows of 36-bit words)
    parameter LEARNED = 1                // 1: threshold = slice[{H, pbin}]; 0: Pontus rule, slice[{0, pbin}]
) (
    input  wire        clk,
    input  wire        rst,
    input  wire        in_valid,
    input  wire [63:0] in_key,
    input  wire [3:0]  in_win,           // current window id (mod 16)
    output reg         out_valid,
    output reg  [10:0] out_est,          // persistence estimate of the packet's flow
    input  wire        cfg_we,           // threshold slice write port (controller)
    input  wire [6:0]  cfg_addr,         // {H, pbin}
    input  wire [15:0] cfg_data
);
    `include "h3_masks.vh"
    localparam W = 1 << LOGW;

    reg [35:0] mem0 [0:W-1];
    reg [35:0] mem1 [0:W-1];
    reg [15:0] slice [0:127];
    integer i;
    initial begin
        for (i = 0; i < W; i = i + 1) begin mem0[i] = 36'd0; mem1[i] = 36'd0; end
        for (i = 0; i < 128; i = i + 1) slice[i] = 16'd0;
    end
    always @(posedge clk) if (cfg_we) slice[cfg_addr] <= cfg_data;

    // ---------------- helpers ----------------
    function [15:0] h3row0; input [63:0] k; begin
        h3row0 = {^(k & H3_R0_15), ^(k & H3_R0_14), ^(k & H3_R0_13), ^(k & H3_R0_12), ^(k & H3_R0_11), ^(k & H3_R0_10),
                  ^(k & H3_R0_9),  ^(k & H3_R0_8),  ^(k & H3_R0_7),  ^(k & H3_R0_6),  ^(k & H3_R0_5),  ^(k & H3_R0_4),
                  ^(k & H3_R0_3),  ^(k & H3_R0_2),  ^(k & H3_R0_1),  ^(k & H3_R0_0)}; end endfunction
    function [15:0] h3row1; input [63:0] k; begin
        h3row1 = {^(k & H3_R1_15), ^(k & H3_R1_14), ^(k & H3_R1_13), ^(k & H3_R1_12), ^(k & H3_R1_11), ^(k & H3_R1_10),
                  ^(k & H3_R1_9),  ^(k & H3_R1_8),  ^(k & H3_R1_7),  ^(k & H3_R1_6),  ^(k & H3_R1_5),  ^(k & H3_R1_4),
                  ^(k & H3_R1_3),  ^(k & H3_R1_2),  ^(k & H3_R1_1),  ^(k & H3_R1_0)}; end endfunction
    function [16:0] h3fp; input [63:0] k; begin
        h3fp = {^(k & H3_FP_16), ^(k & H3_FP_15), ^(k & H3_FP_14), ^(k & H3_FP_13), ^(k & H3_FP_12), ^(k & H3_FP_11),
                ^(k & H3_FP_10), ^(k & H3_FP_9),  ^(k & H3_FP_8),  ^(k & H3_FP_7),  ^(k & H3_FP_6),  ^(k & H3_FP_5),
                ^(k & H3_FP_4),  ^(k & H3_FP_3),  ^(k & H3_FP_2),  ^(k & H3_FP_1),  ^(k & H3_FP_0)}; end endfunction
    // lazy window roll-over: clear F/R, shift owner-presence bits H by the elapsed windows
    function [35:0] roll; input [35:0] w; input [3:0] cur; reg [3:0] dl; reg [1:0] h; begin
        dl = cur - w[3:0];
        if (dl == 4'd0) roll = w;
        else begin
            if (dl == 4'd1)      h = {w[4], w[7]};
            else if (dl == 4'd2) h = {w[7], 1'b0};
            else                 h = 2'b00;
            roll = {w[35:8], 1'b0, 1'b0, h, cur};
        end
    end endfunction
    // count bin: 2*msb(P) + next bit (leading-one detector, no adder)
    function [4:0] pbin; input [10:0] p; begin
        casez (p)
            11'b1??????????: pbin = {4'd10, 1'b0} + p[9];
            11'b01?????????: pbin = {4'd9,  1'b0} + p[8];
            11'b001????????: pbin = {4'd8,  1'b0} + p[7];
            11'b0001???????: pbin = {4'd7,  1'b0} + p[6];
            11'b00001??????: pbin = {4'd6,  1'b0} + p[5];
            11'b000001?????: pbin = {4'd5,  1'b0} + p[4];
            11'b0000001????: pbin = {4'd4,  1'b0} + p[3];
            11'b00000001???: pbin = {4'd3,  1'b0} + p[2];
            11'b000000001??: pbin = {4'd2,  1'b0} + p[1];
            11'b0000000001?: pbin = {4'd1,  1'b0} + p[0];
            default:         pbin = 5'd0;
        endcase
    end endfunction

    // ---------------- A/B: input, hashing, RNG ----------------
    reg a_v; reg [63:0] a_k; reg [3:0] a_win;
    always @(posedge clk) begin a_v <= rst ? 1'b0 : in_valid; a_k <= in_key; a_win <= in_win; end
    wire [15:0] hr0 = h3row0(a_k), hr1 = h3row1(a_k);
    reg b_v; reg [LOGW-1:0] b_i0, b_i1; reg [16:0] b_fp; reg [3:0] b_win; reg [15:0] b_rnd;
    reg [15:0] lfsr;
    wire [15:0] lfsr_nx = lfsr[0] ? ((lfsr >> 1) ^ 16'hB400) : (lfsr >> 1);
    always @(posedge clk) begin
        if (rst) lfsr <= 16'hACE1; else if (a_v) lfsr <= lfsr_nx;
        b_v <= rst ? 1'b0 : a_v;
        b_i0 <= hr0[LOGW-1:0]; b_i1 <= hr1[LOGW-1:0]; b_fp <= h3fp(a_k); b_win <= a_win; b_rnd <= lfsr_nx;
    end

    // ---------------- C: BRAM read ----------------
    reg c_v; reg [LOGW-1:0] c_i0, c_i1; reg [16:0] c_fp; reg [3:0] c_win; reg [15:0] c_rnd;
    reg [35:0] rd0, rd1;
    always @(posedge clk) begin
        rd0 <= mem0[b_i0]; rd1 <= mem1[b_i1];
        c_v <= rst ? 1'b0 : b_v; c_i0 <= b_i0; c_i1 <= b_i1; c_fp <= b_fp; c_win <= b_win; c_rnd <= b_rnd;
    end

    // forward/write history: G = decided one cycle ago (writes this cycle), H1/H2 = written 1/2 edges ago
    reg g_v; reg [LOGW-1:0] g_i0, g_i1; reg [35:0] g_w0, g_w1;
    reg h1_v; reg [LOGW-1:0] h1_i0, h1_i1; reg [35:0] h1_w0, h1_w1; reg [4:0] h1_pb0, h1_pb1;
    reg h2_v; reg [LOGW-1:0] h2_i0, h2_i1; reg [35:0] h2_w0, h2_w1; reg [4:0] h2_pb0, h2_pb1;

    // ---------------- D: pbin of the read words, early forwarding compares for E ----------------
    reg d_v; reg [LOGW-1:0] d_i0, d_i1; reg [16:0] d_fp; reg [3:0] d_win; reg [15:0] d_rnd;
    reg [35:0] d_w0, d_w1; reg [4:0] d_pb0, d_pb1;
    reg [1:0] d_sel0, d_sel1;          // 0: BRAM, 1: G (2 ahead at E), 2: H1, 3: H2
    // timing: while this packet is in C, the packets in E / G / H1 will be in G / H1 / H2 when it is in D
    reg e_v; reg [LOGW-1:0] e_i0, e_i1; reg [16:0] e_fp; reg [3:0] e_win;
    always @(posedge clk) begin
        d_v <= rst ? 1'b0 : c_v; d_i0 <= c_i0; d_i1 <= c_i1; d_fp <= c_fp; d_win <= c_win; d_rnd <= c_rnd;
        d_w0 <= rd0; d_w1 <= rd1; d_pb0 <= pbin(rd0[18:8]); d_pb1 <= pbin(rd1[18:8]);
        d_sel0 <= (e_v && e_i0 == c_i0) ? 2'd1 : (g_v && g_i0 == c_i0) ? 2'd2 : (h1_v && h1_i0 == c_i0) ? 2'd3 : 2'd0;
        d_sel1 <= (e_v && e_i1 == c_i1) ? 2'd1 : (g_v && g_i1 == c_i1) ? 2'd2 : (h1_v && h1_i1 == c_i1) ? 2'd3 : 2'd0;
    end

    // ---------------- E: speculative decay draw ----------------
    // When this packet is in E: packet two ahead is in G (word registered), three ahead in H1, four ahead in H2.
    wire [35:0] s0 = (d_sel0 == 2'd1) ? g_w0 : (d_sel0 == 2'd2) ? h1_w0 : (d_sel0 == 2'd3) ? h2_w0 : d_w0;
    wire [35:0] s1 = (d_sel1 == 2'd1) ? g_w1 : (d_sel1 == 2'd2) ? h1_w1 : (d_sel1 == 2'd3) ? h2_w1 : d_w1;
    wire [4:0]  sp0 = (d_sel0 == 2'd1) ? pbin(g_w0[18:8]) : (d_sel0 == 2'd2) ? h1_pb0 : (d_sel0 == 2'd3) ? h2_pb0 : d_pb0;
    wire [4:0]  sp1 = (d_sel1 == 2'd1) ? pbin(g_w1[18:8]) : (d_sel1 == 2'd2) ? h1_pb1 : (d_sel1 == 2'd3) ? h2_pb1 : d_pb1;
    wire [35:0] sr0 = roll(s0, d_win), sr1 = roll(s1, d_win);
    wire [15:0] t0 = slice[{(LEARNED ? sr0[5:4] : 2'b00), sp0}];
    wire [15:0] t1 = slice[{(LEARNED ? sr1[5:4] : 2'b00), sp1}];
    reg [15:0] e_rnd; reg [35:0] e_w0, e_w1; reg e_dr0, e_dr1; reg e_fw0, e_fw1;
    always @(posedge clk) begin
        e_v <= rst ? 1'b0 : d_v; e_i0 <= d_i0; e_i1 <= d_i1; e_fp <= d_fp; e_win <= d_win; e_rnd <= d_rnd;
        e_w0 <= s0; e_w1 <= s1;
        e_dr0 <= (d_rnd < t0); e_dr1 <= (d_rnd < t1);            // draw outcome for each row's bucket
        // will the immediately preceding packet (now in E, deciding next cycle in F) touch the same bucket?
        e_fw0 <= e_v && (e_i0 == d_i0); e_fw1 <= e_v && (e_i1 == d_i1);
    end

    // ---------------- F: final decision ----------------
    wire [35:0] q0 = e_fw0 && g_v ? g_w0 : e_w0;     // g holds the word decided last cycle (packet one ahead)
    wire [35:0] q1 = e_fw1 && g_v ? g_w1 : e_w1;
    wire [35:0] b0 = roll(q0, e_win), b1 = roll(q1, e_win);
    wire [16:0] f0 = b0[35:19], f1 = b1[35:19];
    wire [10:0] P0 = b0[18:8],  P1 = b1[18:8];
    wire        F0 = b0[7], R0 = b0[6], F1 = b1[7], R1 = b1[6];
    wire [1:0]  H0 = b0[5:4], H1 = b1[5:4];
    wire [35:0] fresh = {e_fp, 11'd1, 1'b1, 1'b0, 2'b00, e_win};
    wire e0 = (P0 == 11'd0), m0 = (f0 == e_fp);
    wire e1 = (P1 == 11'd0), m1 = (f1 == e_fp);
    wire [11:0] inc0 = {1'b0, P0} + (R0 ? 12'd2 : 12'd1);
    wire [11:0] inc1 = {1'b0, P1} + (R1 ? 12'd2 : 12'd1);
    wire [10:0] up0 = F0 ? P0 : (inc0[11] ? 11'h7FF : inc0[10:0]);
    wire [10:0] up1 = F1 ? P1 : (inc1[11] ? 11'h7FF : inc1[10:0]);
    wire        loc = (P1 < P0);
    // eligible buckets were not changed by the preceding packet, so the speculative draw applies
    wire        dec0 = !F0 && !R0 && e_dr0, dec1 = !F1 && !R1 && e_dr1;
    wire [35:0] dw0 = (P0 == 11'd1) ? fresh : {f0, P0 - 11'd1, F0, 1'b1, H0, b0[3:0]};
    wire [35:0] dw1 = (P1 == 11'd1) ? fresh : {f1, P1 - 11'd1, F1, 1'b1, H1, b1[3:0]};
    reg [35:0] n0, n1; reg [10:0] est;
    always @(*) begin
        n0 = b0; n1 = b1; est = 11'd0;
        if (e0)       begin n0 = fresh; est = 11'd1; end
        else if (m0)  begin n0 = {f0, up0, 1'b1, R0, H0, b0[3:0]}; est = up0; end
        else if (e1)  begin n1 = fresh; est = 11'd1; end
        else if (m1)  begin n1 = {f1, up1, 1'b1, R1, H1, b1[3:0]}; est = up1; end
        else begin
            if (!loc && dec0) n0 = dw0;
            if ( loc && dec1) n1 = dw1;
            est = (n0[18:8] < n1[18:8]) ? n0[18:8] : n1[18:8];
        end
    end

    // ---------------- G: write-back, history, output ----------------
    always @(posedge clk) begin
        g_v <= rst ? 1'b0 : e_v; g_i0 <= e_i0; g_i1 <= e_i1; g_w0 <= n0; g_w1 <= n1;
        h1_v <= rst ? 1'b0 : g_v; h1_i0 <= g_i0; h1_i1 <= g_i1; h1_w0 <= g_w0; h1_w1 <= g_w1;
        h1_pb0 <= pbin(g_w0[18:8]); h1_pb1 <= pbin(g_w1[18:8]);
        h2_v <= rst ? 1'b0 : h1_v; h2_i0 <= h1_i0; h2_i1 <= h1_i1; h2_w0 <= h1_w0; h2_w1 <= h1_w1; h2_pb0 <= h1_pb0; h2_pb1 <= h1_pb1;
        out_valid <= rst ? 1'b0 : e_v; out_est <= est;
    end
    always @(posedge clk) if (g_v) begin mem0[g_i0] <= g_w0; mem1[g_i1] <= g_w1; end
endmodule
`default_nettype wire
