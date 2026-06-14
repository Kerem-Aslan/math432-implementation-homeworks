#ifndef DES_COMMON_H
#define DES_COMMON_H

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const int DES_IP[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

static const int DES_FP[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
};

static const int DES_E[48] = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
};

static const int DES_P[32] = {
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
};

static const int DES_PC1[56] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
};

static const int DES_PC2[48] = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

static const int DES_SHIFTS[16] = {
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1
};

static const uint8_t DES_S[8][64] = {
    {
        14, 4, 13, 1, 2, 15, 11, 8,
        3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1,
        10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11,
        15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7,
        5, 11, 3, 14, 10, 0, 6, 13
    },
    {
        15, 1, 8, 14, 6, 11, 3, 4,
        9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14,
        12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1,
        5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2,
        11, 6, 7, 12, 0, 5, 14, 9
    },
    {
        10, 0, 9, 14, 6, 3, 15, 5,
        1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10,
        2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0,
        11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7,
        4, 15, 14, 3, 11, 5, 2, 12
    },
    {
        7, 13, 14, 3, 0, 6, 9, 10,
        1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3,
        4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13,
        15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8,
        9, 4, 5, 11, 12, 7, 2, 14
    },
    {
        2, 12, 4, 1, 7, 10, 11, 6,
        8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1,
        5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8,
        15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13,
        6, 15, 0, 9, 10, 4, 5, 3
    },
    {
        12, 1, 10, 15, 9, 2, 6, 8,
        0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5,
        6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3,
        7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10,
        11, 14, 1, 7, 6, 0, 8, 13
    },
    {
        4, 11, 2, 14, 15, 0, 8, 13,
        3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10,
        14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14,
        10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7,
        9, 5, 0, 15, 14, 2, 3, 12
    },
    {
        13, 2, 8, 4, 6, 15, 11, 1,
        10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4,
        12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2,
        0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13,
        15, 12, 9, 0, 3, 5, 6, 11
    }
};

static inline void chomp_line(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[--n] = '\0';
    }
}

static inline int hex_nibble(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static inline int parse_u64_line(const char *line, uint64_t *out) {
    const char *p = line;
    while (*p && isspace((unsigned char)*p)) {
        p++;
    }
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
    }
    if (!*p) {
        return -1;
    }

    uint64_t value = 0;
    size_t digits = 0;
    for (; *p; p++) {
        if (isspace((unsigned char)*p)) {
            continue;
        }
        int nib = hex_nibble((unsigned char)*p);
        if (nib < 0) {
            return -1;
        }
        if (digits >= 16) {
            return -2;
        }
        value = (value << 4) | (uint64_t)nib;
        digits++;
    }

    if (digits == 0) {
        return -1;
    }
    *out = value;
    return 0;
}

static inline int parse_size_t_line(const char *line, size_t *out) {
    char *end = NULL;
    unsigned long long v = strtoull(line, &end, 10);
    if (end == line) {
        return -1;
    }
    while (*end) {
        if (!isspace((unsigned char)*end)) {
            return -1;
        }
        end++;
    }
    *out = (size_t)v;
    return 0;
}

static inline uint64_t permute(uint64_t input, const int *table, size_t out_bits, size_t in_bits) {
    uint64_t out = 0;
    for (size_t i = 0; i < out_bits; i++) {
        size_t src = (size_t)table[i];
        uint64_t bit = (input >> (in_bits - src)) & 1ULL;
        out = (out << 1) | bit;
    }
    return out;
}

static inline uint64_t rotl28(uint64_t value, int shift) {
    value &= 0x0FFFFFFFULL;
    return ((value << shift) | (value >> (28 - shift))) & 0x0FFFFFFFULL;
}

static inline void generate_subkeys(uint64_t key64, uint64_t subkeys[16]) {
    uint64_t key56 = permute(key64, DES_PC1, 56, 64);
    uint64_t c = (key56 >> 28) & 0x0FFFFFFFULL;
    uint64_t d = key56 & 0x0FFFFFFFULL;

    for (size_t round = 0; round < 16; round++) {
        c = rotl28(c, DES_SHIFTS[round]);
        d = rotl28(d, DES_SHIFTS[round]);
        uint64_t cd = (c << 28) | d;
        subkeys[round] = permute(cd, DES_PC2, 48, 56);
    }
}

static inline uint32_t feistel(uint32_t right32, uint64_t subkey48) {
    uint64_t expanded48 = permute((uint64_t)right32, DES_E, 48, 32);
    uint64_t mixed48 = expanded48 ^ subkey48;
    uint32_t sbox_out32 = 0;

    for (size_t box = 0; box < 8; box++) {
        size_t shift = (7 - box) * 6;
        uint8_t chunk6 = (uint8_t)((mixed48 >> shift) & 0x3FU);
        uint8_t row = (uint8_t)(((chunk6 & 0x20U) >> 4) | (chunk6 & 0x01U));
        uint8_t col = (uint8_t)((chunk6 >> 1) & 0x0FU);
        uint8_t index = (uint8_t)(row * 16U + col);
        uint8_t s_value = DES_S[box][index];
        sbox_out32 = (sbox_out32 << 4) | (uint32_t)(s_value & 0x0FU);
    }

    return (uint32_t)permute((uint64_t)sbox_out32, DES_P, 32, 32);
}

static inline uint64_t des_encrypt_rounds(uint64_t plaintext64, const uint64_t subkeys[16], int rounds) {
    uint64_t ip_block = permute(plaintext64, DES_IP, 64, 64);
    uint32_t left = (uint32_t)(ip_block >> 32);
    uint32_t right = (uint32_t)(ip_block & 0xFFFFFFFFULL);

    for (int round = 0; round < rounds; round++) {
        uint32_t next_left = right;
        uint32_t next_right = left ^ feistel(right, subkeys[round]);
        left = next_left;
        right = next_right;
    }

    uint64_t preoutput = ((uint64_t)right << 32) | (uint64_t)left;
    return permute(preoutput, DES_FP, 64, 64);
}

static inline int parity32(uint32_t x) {
    x ^= x >> 16;
    x ^= x >> 8;
    x ^= x >> 4;
    x ^= x >> 2;
    x ^= x >> 1;
    return x & 1;
}

static inline int parity64(uint64_t x) {
    x ^= x >> 32;
    x ^= x >> 16;
    x ^= x >> 8;
    x ^= x >> 4;
    x ^= x >> 2;
    x ^= x >> 1;
    return x & 1;
}

static inline void xorshift64star_seed(uint64_t *state) {
    if (*state == 0) {
        *state = 0x9E3779B97F4A7C15ULL;
    }
}

static inline uint64_t xorshift64star(uint64_t *state) {
    uint64_t x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 2685821657736338717ULL;
}

#endif
