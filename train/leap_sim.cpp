// Functional model of LEAP used in the training loop (the same update as ../cpu/leap.h, bit for bit), plus the two
// things training needs: the Pontus rule 1/(P+1) as the baseline (table "-"), and a log of the decay opportunities.
//
// Usage:
//   leap_sim eval <keys.bin> <M> <mem_KB> <seed> <table.txt|-> [alpha=0.4]
//        -> one JSON line: AAE / ARE on the persistent flows (present in >= alpha*M windows) at the end of the stream
//   leap_sim log  <keys.bin> <M> <mem_KB> <seed> <out.bin> [table.txt|-] [alpha=0.4]
//        -> every eligible decay opportunity as four uint16: owner count P, presence bits H, time bin,
//           1 if the owner is a persistent flow at the end of the stream (hindsight label of Stage 1)
// Buckets: fp(17) P(11) F R H(2) = 32 bits, d = 2 rows; keys are 8-byte little-endian integers.
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cmath>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>

static inline uint64_t mix64(uint64_t x) {
    x ^= x >> 33; x *= 0xff51afd7ed558ccdULL; x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL; x ^= x >> 33; return x;
}
struct Rng {
    uint64_t s; explicit Rng(uint64_t seed) : s(seed ? seed : 88172645463325252ULL) {}
    inline uint64_t next() { s ^= s >> 12; s ^= s << 25; s ^= s >> 27; return s * 2685821657736338717ULL; }
    inline double uni() { return (double)(next() >> 11) * (1.0 / 9007199254740992.0); }
    inline uint32_t u16() { return (uint32_t)(next() >> 48); }
};

struct Policy {   // learned decay table; empty -> Pontus rule 1/(P+1)
    int T = 0, H = 0, NP = 0; std::vector<uint16_t> thr;  // 16-bit thresholds; decay iff rand16 < thr
    bool load(const char* fn) {
        FILE* f = fopen(fn, "r"); if (!f) return false;
        if (fscanf(f, "%d %d %d", &T, &H, &NP) != 3) return false;
        thr.resize((size_t)T * H * NP);
        for (auto& v : thr) { double p; if (fscanf(f, "%lf", &p) != 1) return false; v = (uint16_t)std::lround(std::min(65535.0, std::max(0.0, p * 65536.0))); }
        fclose(f); return true;
    }
    static int pbin(int P) {          // hardware definition: 2*msb(P) + next bit (leading-one detector)
        if (P <= 0) return 0;
        unsigned v = (unsigned)P; int k = 31 - __builtin_clz(v); int b = k > 0 ? (v >> (k - 1)) & 1 : 0; return 2 * k + b;
    }
    inline int index(int P, int h, int tb) const { return ((tb * H) + std::min(h, H - 1)) * NP + std::min(pbin(P), NP - 1); }
};

struct Bucket { uint64_t id = 0, full = 0; uint16_t P = 0; uint8_t occ = 0, F = 0, R = 0, H = 0; };   // full: owner key (logging only)

struct Sketch {
    static constexpr int FPB = 17;
    int d, w; std::vector<Bucket> b; std::vector<uint64_t> seeds; Rng rng;
    const Policy* pol = nullptr; int M = 1, cur = 1, cur_tbin = 0;
    FILE* logf = nullptr; const std::unordered_map<uint64_t, uint16_t>* finalP = nullptr; double pers_thr = 0;

    Sketch(int d_, int w_, uint64_t seed) : d(d_), w(w_), rng(seed ^ 0x9e3779b97f4a7c15ULL) {
        for (int i = 0; i < d; i++) seeds.push_back(mix64(seed * 1315423911ULL + i + 1));
        b.resize((size_t)d * w);
    }
    inline size_t idx(int r, uint64_t k) const { return (size_t)r * w + mix64(k ^ seeds[r]) % w; }
    inline uint64_t tag(uint64_t k) const { return mix64(k ^ 0x5bd1e9955bd1e995ULL) & ((1ULL << FPB) - 1); }
    inline int tbin_of(int c) const { return pol && pol->T ? std::min(pol->T - 1, (c - 1) * pol->T / M) : 0; }

    void update(uint64_t k) {
        int loc = -1; int minP = 1 << 30; uint64_t tg = tag(k);
        for (int r = 0; r < d; r++) {
            size_t i = idx(r, k); Bucket& x = b[i];
            if (!x.occ) { x.occ = 1; x.id = tg; x.full = k; x.P = 1; x.F = 1; x.H = 0; return; }
            if (x.id == tg) { if (!x.F) { x.P += x.R ? 2 : 1; x.F = 1; } return; }
            if (x.P < minP) { minP = x.P; loc = (int)i; }
        }
        Bucket& m = b[loc];
        if (m.F || m.R) return;
        bool dec;
        if (pol && !pol->thr.empty()) {
            int h = m.H & 3, ix = pol->index(m.P, h, cur_tbin);
            if (logf) { auto it = finalP->find(m.full); uint16_t rec[4] = {m.P, (uint16_t)h, (uint16_t)cur_tbin, (uint16_t)(it != finalP->end() && it->second >= pers_thr)}; fwrite(rec, 2, 4, logf); }
            dec = rng.u16() < pol->thr[ix];
        } else {
            if (logf) { auto it = finalP->find(m.full); uint16_t rec[4] = {m.P, (uint16_t)(m.H & 3), 0, (uint16_t)(it != finalP->end() && it->second >= pers_thr)}; fwrite(rec, 2, 4, logf); }
            dec = rng.uni() < 1.0 / (m.P + 1.0);
        }
        if (dec) {
            m.P -= 1; m.R = 1;
            if (m.P == 0) { m.id = tg; m.full = k; m.P = 1; m.F = 1; m.H = 0; }
        }
    }
    void new_window() {
        for (auto& x : b) { x.H = (uint8_t)(((x.H << 1) | x.F) & 3); x.F = 0; x.R = 0; }
        cur++; cur_tbin = tbin_of(cur);
    }
    double query(uint64_t k) const {
        uint64_t tg = tag(k); int mn = 1 << 30;
        for (int r = 0; r < d; r++) { const Bucket& x = b[idx(r, k)]; if (x.occ && x.id == tg) return x.P; mn = std::min<int>(mn, x.P); }
        return mn;
    }
};

static std::vector<uint64_t> read_keys(const char* path) {
    FILE* f = fopen(path, "rb"); if (!f) { perror("open"); exit(1); }
    fseek(f, 0, SEEK_END); uint64_t n = ftell(f) / 8; fseek(f, 0, SEEK_SET);
    std::vector<uint64_t> keys(n); if (fread(keys.data(), 8, n, f) != n) exit(1); fclose(f); return keys;
}

int main(int argc, char** argv) {
    if (argc < 7) { fprintf(stderr, "usage: see the header of leap_sim.cpp\n"); return 1; }
    std::string mode = argv[1];
    auto keys = read_keys(argv[2]); int M = atoi(argv[3]); double memKB = atof(argv[4]); uint64_t seed = strtoull(argv[5], 0, 10);
    const int d = 2, w = (int)(memKB * 1024 / (4.0 * d));
    const uint64_t n = keys.size(), winlen = (n + M - 1) / M;
    Policy pol; Sketch sk(d, w, seed); sk.M = M;
    if (mode == "eval") {
        std::string tfile = argv[6]; double alpha = argc > 7 ? atof(argv[7]) : 0.4;
        if (tfile != "-") { if (!pol.load(tfile.c_str())) { fprintf(stderr, "bad table\n"); return 1; } sk.pol = &pol; }
        std::unordered_map<uint64_t, std::pair<uint16_t, uint16_t>> truth; truth.reserve(n / 4);   // windows present, last window
        for (uint64_t i = 0; i < n; i++) {
            uint64_t k = keys[i]; uint16_t win = (uint16_t)(i / winlen) + 1;
            auto& t = truth[k]; if (t.second != win) { t.first++; t.second = win; }
            sk.update(k);
            if (((i + 1) % winlen == 0) || (i + 1 == n)) sk.new_window();
        }
        double thr = alpha * M, sae = 0, sre = 0; size_t np = 0;
        for (auto& kv : truth) {
            if (kv.second.first < thr) continue;
            double P = kv.second.first, e = sk.query(kv.first); sae += std::fabs(e - P); sre += std::fabs(e - P) / P; np++;
        }
        printf("{\"mem_KB\":%.1f,\"seed\":%llu,\"M\":%d,\"alpha\":%.2f,\"n_pers\":%zu,\"AAE\":%.4f,\"ARE\":%.6f}\n",
               memKB, (unsigned long long)seed, M, alpha, np, np ? sae / np : 0, np ? sre / np : 0);
        return 0;
    }
    if (mode == "log") {
        const char* out = argv[6]; std::string tfile = argc > 7 ? argv[7] : "-"; double alpha = argc > 8 ? atof(argv[8]) : 0.4;
        if (tfile != "-") { if (!pol.load(tfile.c_str())) return 1; sk.pol = &pol; }
        std::unordered_map<uint64_t, uint16_t> fin, last; fin.reserve(n / 4); last.reserve(n / 4);
        for (uint64_t i = 0; i < n; i++) { uint16_t wn = (uint16_t)(i / winlen) + 1; auto& l = last[keys[i]]; if (l != wn) { fin[keys[i]]++; l = wn; } }
        sk.finalP = &fin; sk.pers_thr = alpha * M; sk.logf = fopen(out, "wb");
        for (uint64_t i = 0; i < n; i++) { sk.update(keys[i]); if (((i + 1) % winlen == 0) || (i + 1 == n)) sk.new_window(); }
        fclose(sk.logf); return 0;
    }
    return 1;
}
