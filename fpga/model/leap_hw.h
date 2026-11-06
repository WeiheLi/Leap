// LEAP hardware reference model (bit-exact specification shared by the FPGA RTL testbench
// and the Tofino P4 program). Header-only, no dependencies.
//
// Bucket word (36 bit, stored in BRAM data+parity bits):
//   [35:19] fp (17)   [18:8] P (11)   [7] F   [6] R   [5:4] H   [3:0] E (window stamp, mod 16)
//   P == 0 marks an empty bucket.
// Per packet: H3 hashes of the 64-bit key give D row indices and the fingerprint,
// lazily roll each touched bucket into the current window (clear F/R, shift owner-presence bits H),
// then apply the Pontus-style insert / match / decay logic with a table-driven decay threshold.
#pragma once
#include <cstdlib>
#include <cstdint>
#include <vector>
#include <algorithm>
#ifndef LEAP_H3_RUNTIME     // define to supply runtime-drawn masks instead
#include "h3_masks.h"
#endif

namespace leaphw {

constexpr int D = 2, FPB = 17, PB = 11;
constexpr uint32_t PMAX = (1u << PB) - 1;
constexpr int T_BINS = 8, H_BINS = 4, NP = 24;

struct Bucket { uint32_t fp = 0, P = 0, F = 0, R = 0, H = 0, E = 0; };

// H3 universal hashing: output bit i = parity(key & mask_i)  (XOR trees in hardware)
inline uint32_t h3(uint64_t key, const uint64_t* masks, int bits) {
    uint32_t o = 0; for (int i = 0; i < bits; i++) o |= (uint32_t)(__builtin_popcountll(key & masks[i]) & 1) << i; return o;
}
inline uint32_t row_index(uint64_t key, int r, int logw) { return h3(key, H3_ROW[r], logw); }
inline uint32_t fingerprint(uint64_t key) { return h3(key, H3_FP, FPB); }
inline int pbin(uint32_t P) {               // leading-one detector: 2*msb(P) + next bit (P = 0 -> 0)
    if (P == 0) return 0;
    int k = 31 - __builtin_clz(P); int b = k > 0 ? (P >> (k - 1)) & 1 : 0;
    return std::min(2 * k + b, NP - 1);
}
inline uint64_t pack(const Bucket& b) {
    return ((uint64_t)b.fp << 19) | ((uint64_t)b.P << 8) | (b.F << 7) | (b.R << 6) | (b.H << 4) | b.E;
}
inline Bucket unpack(uint64_t w) {
    Bucket b; b.fp = (w >> 19) & ((1u << FPB) - 1); b.P = (w >> 8) & PMAX; b.F = (w >> 7) & 1;
    b.R = (w >> 6) & 1; b.H = (w >> 4) & 3; b.E = w & 15; return b;
}
inline Bucket roll(Bucket b, uint32_t cur) {   // lazy window roll-over
    uint32_t delta = (cur - b.E) & 15;
    if (delta) {
        uint32_t h = delta >= 3 ? 0 : (((b.H << delta) | (b.F << (delta - 1))) & 3);
        b.H = h; b.F = 0; b.R = 0; b.E = cur & 15;
    }
    return b;
}
inline uint16_t lfsr_next(uint16_t s) {        // Galois LFSR, x^16 + x^14 + x^13 + x^11 + 1
    uint16_t lsb = s & 1; s >>= 1; if (lsb) s ^= 0xB400; return s;
}

struct Model {
    int logw; std::vector<uint64_t> mem[D]; std::vector<uint16_t> thr; uint16_t rng = 0xACE1;
    uint32_t rthr = 0; bool report = false;
    int lfsr_steps = getenv("LFSR_STEPS") ? atoi(getenv("LFSR_STEPS")) : 1;   // LFSR steps per packet (RTL: 1)   // report-on-crossing: set when this packet lifts its count to rthr (0 = off)
    explicit Model(int logw_, const std::vector<uint16_t>& table) : logw(logw_), thr(table) {
        for (int r = 0; r < D; r++) mem[r].assign((size_t)1 << logw, 0);
    }
    // returns the current persistence estimate of the packet's flow (after the update)
    uint32_t process(uint64_t key, uint32_t cur, uint32_t tbin) {
        for (int k = 0; k < lfsr_steps; k++) rng = lfsr_next(rng);
        report = false;
        uint32_t fp = fingerprint(key);
        uint32_t idx[D]; Bucket b[D];
        for (int r = 0; r < D; r++) { idx[r] = row_index(key, r, logw); b[r] = roll(unpack(mem[r][idx[r]]), cur); }
        int hit = -1, loc = 0; uint32_t est = 0; bool done = false;
        for (int r = 0; r < D && !done; r++) {
            if (b[r].P == 0) { b[r] = Bucket{fp, 1, 1, 0, 0, cur & 15}; est = 1; done = true; hit = r; }
            else if (b[r].fp == fp) {
                if (!b[r].F) { uint32_t old = b[r].P; b[r].P = std::min(PMAX, b[r].P + (b[r].R ? 2u : 1u)); b[r].F = 1;
                               report = rthr && old < rthr && b[r].P >= rthr; }
                est = b[r].P; done = true; hit = r;
            }
        }
        if (!done) {
            loc = (b[1].P < b[0].P) ? 1 : 0;
            Bucket& m = b[loc];
            if (!m.F && !m.R) {
                uint16_t t = thr[(size_t)(tbin * H_BINS + m.H) * NP + pbin(m.P)];
                if (rng < t) {
                    m.P -= 1; m.R = 1;
                    if (m.P == 0) m = Bucket{fp, 1, 1, 0, 0, cur & 15};
                }
            }
            est = std::min(b[0].P, b[1].P);
        }
        (void)hit;
        for (int r = 0; r < D; r++) mem[r][idx[r]] = pack(b[r]);
        return est;
    }
};

}  // namespace leaphw
