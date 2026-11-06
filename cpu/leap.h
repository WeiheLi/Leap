// LEAP: persistence sketch with a learned eviction table (header-only C++17, no dependencies).
//
// d rows of w buckets; each bucket is one 32-bit word:
//   [16:0] fp (17)   [27:17] P (11)   [28] F   [29] R   [31:30] H        P == 0 marks an empty bucket
//   fp : fingerprint of the owner flow          P : persistence count of the owner
//   F  : owner arrived in the current window    R : owner was decayed in the current window
//   H  : owner presence in the two previous windows (bit 0: window t-1, bit 1: window t-2)
// Update of an arriving flow e (as in Pontus, except for the decay probability):
//   empty bucket -> insert e with P = 1;  own bucket -> P += 1 (+2 if R = 1, undoing a decay) once per window;
//   otherwise the minimum-count owner m (row 1 on ties), if F = R = 0, is decayed with probability
//   T[tbin(t)][H_m][pbin(P_m)] (a 16-bit threshold against a 16-bit random number); at P = 0, e replaces m.
// The table T (8 time bins x 4 presence patterns x 24 count bins) is the learned policy (table/leap_table.txt).
// Query: P of the flow's own bucket, else the minimum count of its d buckets.
#pragma once
#include <cstdint>
#include <cstdio>
#include <cmath>
#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

namespace leap {

inline uint64_t mix64(uint64_t x) {
    x ^= x >> 33; x *= 0xff51afd7ed558ccdULL; x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL; x ^= x >> 33; return x;
}

// Learned decay table, stored as 16-bit thresholds: decay iff rand16 < thr[tbin][H][pbin].
struct Table {
    int T = 0, H = 0, NP = 0;
    std::vector<uint16_t> thr;
    // text format: "T H NP" followed by T*H*NP probabilities in [tbin][H][pbin] order
    static Table load(const std::string& path) {
        Table t; FILE* f = fopen(path.c_str(), "r");
        if (!f || fscanf(f, "%d %d %d", &t.T, &t.H, &t.NP) != 3) throw std::runtime_error("cannot read table " + path);
        t.thr.resize((size_t)t.T * t.H * t.NP);
        for (auto& v : t.thr) {
            double p; if (fscanf(f, "%lf", &p) != 1) throw std::runtime_error("short table " + path);
            v = (uint16_t)std::lround(std::min(65535.0, std::max(0.0, p * 65536.0)));
        }
        fclose(f); return t;
    }
    static int pbin(uint32_t P) {          // count bin: 2 * msb(P) + the bit below it (a leading-one detector)
        if (P == 0) return 0;
        int k = 31 - __builtin_clz(P); int b = k > 0 ? (P >> (k - 1)) & 1 : 0; return 2 * k + b;
    }
    uint16_t at(int tbin, int h, uint32_t P) const {
        return thr[((size_t)tbin * H + std::min(h, H - 1)) * NP + std::min(pbin(P), NP - 1)];
    }
};

class Sketch {
public:
    static constexpr int FPB = 17;                       // fingerprint bits
    // mem_bytes: memory of the buckets (4 bytes each); M: windows per measurement period; seed: hashes and RNG
    Sketch(double mem_bytes, int d, int M, const Table& table, uint64_t seed)
        : d_(d), w_((int)(mem_bytes / (4.0 * d))), M_(M), tab_(table), rng_(seed ^ 0x9e3779b97f4a7c15ULL) {
        if (w_ < 1 || d_ < 1) throw std::invalid_argument("memory too small");
        if (M_ < 1 || M_ > 2047) throw std::invalid_argument("M must be in 1..2047 (11-bit counts)");
        if (!rng_) rng_ = 88172645463325252ULL;
        for (int i = 0; i < d_; i++) seeds_.push_back(mix64(seed * 1315423911ULL + i + 1));
        b_.assign((size_t)d_ * w_, 0);
    }

    // Report-on-crossing (optional): update() returns true for the arrival that lifts its own count to thr
    // (e.g., thr = ceil(alpha * M)); that packet carries the flow key, so persistent flows are listed without keys.
    void set_report_threshold(uint32_t thr) { rep_thr_ = thr; }

    bool update(uint64_t key) {
        const uint32_t g = fp(key);
        size_t cand = 0; uint32_t minP = UINT32_MAX;
        for (int r = 0; r < d_; r++) {
            const size_t i = idx(r, key); uint32_t& x = b_[i];
            if (P(x) == 0) { x = pack(g, 1, 1, 0, 0); return false; }                     // empty: insert
            if (fpof(x) == g) {                                                            // own bucket: count once per window
                if (F(x)) return false;
                const uint32_t old = P(x), now = old + (R(x) ? 2 : 1);
                x = pack(g, now, 1, R(x), H(x));
                return rep_thr_ && old < rep_thr_ && now >= rep_thr_;
            }
            if (P(x) < minP) { minP = P(x); cand = i; }
        }
        uint32_t& m = b_[cand];                                                            // full collision
        if (F(m) || R(m)) return false;                                                    // at most one decay per window
        if (rng_u16() < tab_.at(tbin_, H(m), P(m))) {
            const uint32_t p = P(m) - 1;
            m = p ? pack(fpof(m), p, 0, 1, H(m)) : pack(g, 1, 1, 0, 0);                    // decay; at 0, e replaces m
        }
        return false;
    }

    // End of a window: shift F into H and clear F, R (the FPGA does this lazily, on the next access of each bucket).
    void new_window() {
        for (auto& x : b_) if (P(x)) x = pack(fpof(x), P(x), 0, 0, ((H(x) << 1) | F(x)) & 3);
        ++cur_; tbin_ = std::min(tab_.T - 1, (cur_ - 1) * tab_.T / M_);
    }

    uint32_t query(uint64_t key) const {
        const uint32_t g = fp(key); uint32_t mn = UINT32_MAX;
        for (int r = 0; r < d_; r++) { const uint32_t x = b_[idx(r, key)]; if (P(x) && fpof(x) == g) return P(x); mn = std::min(mn, P(x)); }
        return mn;
    }
    bool tracked(uint64_t key) const {
        const uint32_t g = fp(key);
        for (int r = 0; r < d_; r++) { const uint32_t x = b_[idx(r, key)]; if (P(x) && fpof(x) == g) return true; }
        return false;
    }
    int rows() const { return d_; }
    int width() const { return w_; }

private:
    static uint32_t pack(uint32_t f, uint32_t p, uint32_t Fb, uint32_t Rb, uint32_t h) {
        return f | (p << 17) | (Fb << 28) | (Rb << 29) | (h << 30);
    }
    static uint32_t fpof(uint32_t x) { return x & 0x1FFFF; }
    static uint32_t P(uint32_t x) { return (x >> 17) & 0x7FF; }
    static uint32_t F(uint32_t x) { return (x >> 28) & 1; }
    static uint32_t R(uint32_t x) { return (x >> 29) & 1; }
    static uint32_t H(uint32_t x) { return x >> 30; }
    uint32_t fp(uint64_t k) const { return (uint32_t)(mix64(k ^ 0x5bd1e9955bd1e995ULL) & ((1u << FPB) - 1)); }
    size_t idx(int r, uint64_t k) const { return (size_t)r * w_ + mix64(k ^ seeds_[r]) % w_; }
    uint32_t rng_u16() {                                  // xorshift64*; the top 16 bits as the random number
        rng_ ^= rng_ >> 12; rng_ ^= rng_ << 25; rng_ ^= rng_ >> 27; return (uint32_t)((rng_ * 2685821657736338717ULL) >> 48);
    }

    int d_, w_, M_;
    const Table& tab_;
    uint64_t rng_;
    std::vector<uint64_t> seeds_;
    std::vector<uint32_t> b_;
    int cur_ = 1, tbin_ = 0;
    uint32_t rep_thr_ = 0;
};

}  // namespace leap
