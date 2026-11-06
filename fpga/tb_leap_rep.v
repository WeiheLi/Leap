// Testbench for leap_core_rep: streams golden vectors (key, window, tbin, estimate, report flag) through the core one
// packet per cycle with random idle cycles. When the time bin changes, the pipeline is drained and
// the 96-entry threshold slice of the new bin is written through the cfg port (as the controller does).
// When the window id changes, the input stays idle for one cycle (interface rule of leap_core), so the
// packets on either side of a window boundary are at least two stages apart.
`timescale 1ns/1ps
module tb_leap_rep;
    parameter LOGW = 12;
    parameter VEC = "vectors.hex";
    parameter THR = "thr.hex";
    parameter GAP_PCT = 10;
    parameter REP = 0;                  // 1: vectors carry the expected report flag, checked against out_report
    parameter RTHR = 0;
    reg clk = 0, rst = 1;
    always #2 clk = ~clk;
    reg in_valid = 0; reg [63:0] in_key = 0; reg [3:0] in_win = 0;
    reg cfg_we = 0; reg [6:0] cfg_addr = 0; reg [15:0] cfg_data = 0;
    wire out_valid; wire [10:0] out_est; wire out_report;
    leap_core_rep #(.LOGW(LOGW), .LEARNED(1), .REPORT(REP)) dut (
        .clk(clk), .rst(rst), .in_valid(in_valid), .in_key(in_key), .in_win(in_win),
        .out_valid(out_valid), .out_est(out_est), .cfg_we(cfg_we), .cfg_addr(cfg_addr), .cfg_data(cfg_data),
        .cfg_rthr(RTHR[10:0]), .out_report(out_report));

    reg [15:0] table_all [0:767];
    integer fd, r, n_in, n_out, n_err, seed, cur_tb, cur_w, j;
    reg [63:0] k; reg [15:0] w; reg [3:0] tb; reg [11:0] e; reg [3:0] rp; integer n_rep;
    reg [10:0] expq [0:4194303]; reg expr [0:4194303];
    task load_slice(input integer tbin); begin
        @(negedge clk); in_valid = 0;               // let the last packet be sampled first
        repeat (10) @(negedge clk);                       // drain the pipeline
        for (j = 0; j < 96; j = j + 1) begin
            @(negedge clk); cfg_we = 1; cfg_addr = (j / 24) * 32 + (j % 24); cfg_data = table_all[tbin * 96 + j];
        end
        @(negedge clk); cfg_we = 0;
    end endtask
    initial begin
        $readmemh(THR, table_all);
        fd = $fopen(VEC, "r"); n_in = 0; n_out = 0; n_err = 0; seed = 1; cur_tb = -1; cur_w = -1; n_rep = 0; rp = 0;
        repeat (4) @(posedge clk); rst = 0;
        while (!$feof(fd)) begin
            if (REP) r = $fscanf(fd, "%h %h %h %h %h\n", k, w, tb, e, rp) - 1; else r = $fscanf(fd, "%h %h %h %h\n", k, w, tb, e);
            if (r == 4) begin
                if (tb != cur_tb) begin load_slice(tb); cur_tb = tb; end
                if (cur_w >= 0 && w != cur_w) begin @(negedge clk); in_valid = 0; end   // one idle cycle per window boundary
                cur_w = w;
                while (($random(seed) % 100 + 100) % 100 < GAP_PCT) begin @(negedge clk); in_valid = 0; end
                @(negedge clk);
                in_valid = 1; in_key = k; in_win = w[3:0];
                expq[n_in] = e[10:0]; expr[n_in] = rp[0]; n_in = n_in + 1;
            end
        end
        @(negedge clk); in_valid = 0;
        repeat (12) @(posedge clk);
        $display("packets in=%0d out=%0d mismatches=%0d reports=%0d", n_in, n_out, n_err, n_rep);
        if (n_err == 0 && n_in == n_out) $display("PASS"); else $display("FAIL");
        $finish;
    end
    always @(posedge clk) if (out_valid) begin
        if (out_est !== expq[n_out] || (REP && out_report !== expr[n_out])) begin
            if (n_err < 10) $display("mismatch @%0d: got %0d/%0d expected %0d/%0d", n_out, out_est, out_report, expq[n_out], expr[n_out]);
            n_err = n_err + 1;
        end
        if (out_report) n_rep = n_rep + 1;
        n_out = n_out + 1;
    end
endmodule
