// Read a libpcap stream from stdin, write one 8-byte key (IPv4 src,dst) per IPv4 packet
// to stdout as raw binary. Stops after max_pkts IPv4 packets (argv[1], 0 = unlimited).
// Handles Ethernet (linktype 1), raw IP (101/12/228) and Linux SLL (113); skips 802.1Q tags.
// With TS=1 in the environment, each key is preceded by its 8-byte timestamp in microseconds (for merging
// several captures by time).
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

static bool readn(void* p, size_t n) { return fread(p, 1, n, stdin) == n; }

int main(int argc, char** argv) {
    unsigned long long max_pkts = argc > 1 ? strtoull(argv[1], nullptr, 10) : 0;
    uint8_t gh[24];
    if (!readn(gh, 24)) { fprintf(stderr, "no pcap header\n"); return 1; }
    uint32_t magic; memcpy(&magic, gh, 4);
    bool swap = false;
    if (magic == 0xa1b2c3d4 || magic == 0xa1b23c4d) swap = false;
    else if (magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1) swap = true;
    else { fprintf(stderr, "bad magic %08x\n", magic); return 1; }
    auto rd32 = [&](const uint8_t* p) { uint32_t v; memcpy(&v, p, 4); return swap ? __builtin_bswap32(v) : v; };
    uint32_t linktype = rd32(gh + 20);
    std::vector<uint8_t> buf(1 << 18);
    unsigned long long n_ip = 0, n_all = 0; const bool ts = getenv("TS") != nullptr;
    const bool nsec = magic == 0xa1b23c4d || magic == 0x4d3cb2a1;
    uint8_t ph[16];
    while (readn(ph, 16)) {
        uint32_t incl = rd32(ph + 8);
        if (incl > buf.size()) buf.resize(incl);
        if (!readn(buf.data(), incl)) break;
        n_all++;
        const uint8_t* p = buf.data(); size_t len = incl, off = 0;
        if (linktype == 1) {               // Ethernet
            if (len < 14) continue;
            uint16_t et = (p[12] << 8) | p[13]; off = 14;
            while ((et == 0x8100 || et == 0x88a8) && len >= off + 4) { et = (p[off + 2] << 8) | p[off + 3]; off += 4; }
            if (et != 0x0800) continue;
        } else if (linktype == 113) {      // Linux cooked
            if (len < 16) continue;
            uint16_t et = (p[14] << 8) | p[15]; off = 16;
            if (et != 0x0800) continue;
        } else if (linktype == 101 || linktype == 12 || linktype == 228) {
            off = 0;
        } else { fprintf(stderr, "unsupported linktype %u\n", linktype); return 1; }
        if (len < off + 20 || (p[off] >> 4) != 4) continue;
        if (ts) { uint64_t t = (uint64_t)rd32(ph) * 1000000ULL + (nsec ? rd32(ph + 4) / 1000 : rd32(ph + 4)); fwrite(&t, 8, 1, stdout); }
        fwrite(p + off + 12, 1, 8, stdout);   // src(4) + dst(4)
        if (++n_ip == max_pkts) break;
    }
    fprintf(stderr, "pcap packets read: %llu, IPv4 keys written: %llu\n", n_all, n_ip);
    return 0;
}
