// Golden-vector generator for the LEAP RTL.
// Usage: golden <keys.bin> <npkts> <winlen> <M> <logw> <table.txt|-> <out_vectors.hex> <out_thr.hex> [rthr]
//   with rthr > 0, each vector line gets a fifth field: 1 if the packet lifts its count to rthr (report-on-crossing)
//   vectors: one line per packet "key(16 hex) win(4 hex) tbin(1 hex) est(3 hex)"
//   thr.hex: the 768 16-bit decay thresholds in [tbin][H][pbin] order (for $readmemh)
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <string>
#include "leap_hw.h"
using namespace leaphw;

int main(int argc, char** argv) {
    if (argc < 9) { fprintf(stderr, "usage\n"); return 1; }
    FILE* f = fopen(argv[1], "rb"); uint64_t n = strtoull(argv[2], 0, 10); uint64_t winlen = strtoull(argv[3], 0, 10);
    int M = atoi(argv[4]); int logw = atoi(argv[5]); std::string tf = argv[6];
    std::vector<uint16_t> thr((size_t)T_BINS * H_BINS * NP);
    if (tf == "-") {   // Pontus rule 1/(P+1) evaluated at the bin's representative count
        for (int t = 0; t < T_BINS; t++) for (int h = 0; h < H_BINS; h++) for (int p = 0; p < NP; p++) {
            int k = p / 2, bb = p % 2; double v = std::ldexp(1.0 + 0.5 * bb + 0.25, k); double P = std::max(1.0, v - 1);
            thr[(size_t)(t * H_BINS + h) * NP + p] = (uint16_t)std::min(65535.0, std::round(65536.0 / (P + 1)));
        }
    } else {
        FILE* ft = fopen(tf.c_str(), "r"); int T, H, NPf; if (fscanf(ft, "%d %d %d", &T, &H, &NPf) != 3) return 1;
        for (auto& v : thr) { double p; if (fscanf(ft, "%lf", &p) != 1) return 1; v = (uint16_t)std::lround(std::min(65535.0, std::max(0.0, p * 65536.0))); }
        fclose(ft);
    }
    Model m(logw, thr); m.rthr = argc > 9 ? (uint32_t)atoi(argv[9]) : 0;
    FILE* fo = fopen(argv[7], "w");
    for (uint64_t i = 0; i < n; i++) {
        uint64_t key; if (fread(&key, 8, 1, f) != 1) break;
        uint32_t win = (uint32_t)(i / winlen) + 1;
        uint32_t tbin = std::min<uint32_t>(T_BINS - 1, (win - 1) * T_BINS / M);
        uint32_t est = m.process(key, win, tbin);
        if (m.rthr) fprintf(fo, "%016llx %04x %x %03x %x\n", (unsigned long long)key, win & 0xFFFF, tbin, est, (unsigned)m.report);
        else fprintf(fo, "%016llx %04x %x %03x\n", (unsigned long long)key, win & 0xFFFF, tbin, est);
    }
    fclose(fo); fclose(f);
    FILE* fth = fopen(argv[8], "w"); for (auto v : thr) fprintf(fth, "%04x\n", v); fclose(fth);
    return 0;
}
