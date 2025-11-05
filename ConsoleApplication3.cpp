#define _CRT_SECURE_NO_WARNINGS
#include <fstream>
#include <vector>
#include <cstdint>
#include <cstring>
#include <string>

extern "C" {
#include "AES.h"
}

static const uint8_t AES_KEY[16] = {
    0x1D, 0x8E, 0xBB, 0x9D, 0x6A, 0x2E, 0x05, 0xBB,
    0x89, 0x6B, 0xF6, 0x9C, 0x03, 0x5A, 0x65, 0x90
};

static const uint8_t NONCE_COUNTER[16] = {
    0xBB, 0x8B, 0xDD, 0xFB, 0x81, 0x2F, 0x8D, 0x35,
    0x6A, 0xC9, 0x3A, 0xC4, 0x11, 0x2A, 0x7F, 0x82
};

int main(int argc, char* argv[]) {
    if (argc < 2) return 1; // allows drag-and-drop to work

    std::string inputPath = argv[1];
    std::ifstream fin(inputPath, std::ios::binary);
    if (!fin) return 1;

    std::vector<uint8_t> in((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
    fin.close();

    std::vector<uint8_t> out(in.size());
    uint8_t counter[16];
    memcpy(counter, NONCE_COUNTER, 16);
    uint8_t ks[16];
    size_t pos = 0;

    // AES-CTR decrypt/encrypt
    while (pos < in.size()) {
        AES_ECB_encrypt(counter, AES_KEY, ks, 16);
        size_t chunk = std::min<size_t>(16, in.size() - pos);
        for (size_t i = 0; i < chunk; ++i)
            out[pos + i] = in[pos + i] ^ ks[i];
        for (int i = 15; i >= 0; --i)
            if (++counter[i] != 0) break;
        pos += chunk;
    }

    // Check if decrypted (starts with 00 00 00 00)
    bool is_decrypted = (in.size() >= 4 &&
        in[0] == 0x00 && in[1] == 0x00 &&
        in[2] == 0x00 && in[3] == 0x00);

    // Only disable integrity checks when decrypting
    if (is_decrypted) {
        const size_t offsets[] = {
            0x169204, 0x169245, 0x169248,
            0x16926C, 0x169277, 0x17CD0C, 0x1DE794
        };
        for (size_t off : offsets)
            if (off < out.size())
                out[off] = 0;
    }

    std::string outputPath = inputPath + "_out.bin";
    std::ofstream fout(outputPath, std::ios::binary);
    if (!fout) return 1;
    fout.write(reinterpret_cast<const char*>(out.data()), out.size());
    fout.close();

    return 0;
}
