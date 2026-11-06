// Run LEAP over a stream of 8-byte flow keys and report its accuracy on the persistent flows.
// Usage: leap_demo <keys.bin> <table.txt> [mem_KB=32] [M=1500] [alpha=0.4] [seed=1] [d=2]
//   keys.bin : flow keys as little-endian uint64 (e.g., IPv4 source and destination), in arrival order
//   The stream is split into M windows of equal length; a flow is persistent if it appears in at least alpha*M of
//   them. Output (JSON): AAE and ARE of the estimates of the persistent flows, and the flows reported on crossing.
#include "leap.h"
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <unordered_map>
#include <unordered_set>

int main(int argc, char** argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <keys.bin> <table.txt> [mem_KB=32] [M=1500] [alpha=0.4] [seed=1] [d=2]\n", argv[0]); return 1; }
    const double memKB = argc > 3 ? atof(argv[3]) : 32; const int M = argc > 4 ? atoi(argv[4]) : 1500;
    const double alpha = argc > 5 ? atof(argv[5]) : 0.4; const uint64_t seed = argc > 6 ? strtoull(argv[6], 0, 10) : 1;
    const int d = argc > 7 ? atoi(argv[7]) : 2;
    FILE* f = fopen(argv[1], "rb"); if (!f) { perror(argv[1]); return 1; }
    fseek(f, 0, SEEK_END); const uint64_t n = ftell(f) / 8; fseek(f, 0, SEEK_SET);
    std::vector<uint64_t> keys(n); if (fread(keys.data(), 8, n, f) != n) return 1; fclose(f);

    const leap::Table table = leap::Table::load(argv[2]);
    leap::Sketch sk(memKB * 1024, d, M, table, seed);
    const uint32_t thr = (uint32_t)std::ceil(alpha * M - 1e-9);
    sk.set_report_threshold(thr);

    std::unordered_map<uint64_t, std::pair<uint32_t, uint32_t>> truth;    // flow -> (windows present, last window)
    std::unordered_set<uint64_t> reported;
    const uint64_t winlen = (n + M - 1) / M;
    for (uint64_t i = 0; i < n; i++) {
        const uint64_t k = keys[i]; const uint32_t win = (uint32_t)(i / winlen) + 1;
        auto& t = truth[k]; if (t.second != win) { t.first++; t.second = win; }
        if (sk.update(k)) reported.insert(k);
        if ((i + 1) % winlen == 0 || i + 1 == n) sk.new_window();
    }
    const double pthr = alpha * M; double sae = 0, sre = 0; size_t np = 0, tp = 0;
    for (auto& kv : truth) {
        if (kv.second.first < pthr) continue;
        const double P = kv.second.first, e = sk.query(kv.first);
        sae += std::fabs(e - P); sre += std::fabs(e - P) / P; np++;
    }
    for (uint64_t k : reported) { auto it = truth.find(k); tp += it != truth.end() && it->second.first >= pthr; }
    printf("{\"items\":%llu,\"mem_KB\":%.1f,\"d\":%d,\"w\":%d,\"M\":%d,\"alpha\":%.2f,\"seed\":%llu,\"n_pers\":%zu,"
           "\"AAE\":%.4f,\"ARE\":%.6f,\"reported\":%zu,\"reported_persistent\":%zu}\n",
           (unsigned long long)n, memKB, sk.rows(), sk.width(), M, alpha, (unsigned long long)seed, np,
           np ? sae / np : 0, np ? sre / np : 0, reported.size(), tp);
    return 0;
}
