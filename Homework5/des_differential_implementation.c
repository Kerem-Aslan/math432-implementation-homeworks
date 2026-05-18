#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const int IP[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

static const int FP[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
};

static const int E[48] = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
};

static const int P[32] = {
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
};

static const int PC1[56] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
};

static const int PC2[48] = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

static const int SHIFTS[16] = {
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1
};

static const uint8_t S[8][64] = {
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

typedef struct {
    uint32_t dl[6];
    uint32_t dr[6];
    uint32_t raw_f[5];
    uint32_t f_out[5];
    uint64_t expanded[5];
    double round_prob[5];
    double total_prob;
} Trail;

static void chomp_line(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[--n] = '\0';
    }
}

static int hex_nibble(int c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    }
    return -1;
}

static int parse_u64_line(const char *line, uint64_t *out) {
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

static int parse_size_t_line(const char *line, size_t *out) {
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

static uint64_t permute(uint64_t input, const int *table, size_t out_bits, size_t in_bits) {
    uint64_t out = 0;
    for (size_t i = 0; i < out_bits; i++) {
        size_t src = (size_t)table[i];
        uint64_t bit = (input >> (in_bits - src)) & 1ULL;
        out = (out << 1) | bit;
    }
    return out;
}

static uint64_t rotl28(uint64_t value, int shift) {
    value &= 0x0FFFFFFFULL;
    return ((value << shift) | (value >> (28 - shift))) & 0x0FFFFFFFULL;
}

static void generate_subkeys(uint64_t key64, uint64_t subkeys[16]) {
    uint64_t key56 = permute(key64, PC1, 56, 64);
    uint64_t c = (key56 >> 28) & 0x0FFFFFFFULL;
    uint64_t d = key56 & 0x0FFFFFFFULL;

    for (size_t round = 0; round < 16; round++) {
        c = rotl28(c, SHIFTS[round]);
        d = rotl28(d, SHIFTS[round]);
        uint64_t cd = (c << 28) | d;
        subkeys[round] = permute(cd, PC2, 48, 56);
    }
}

static uint32_t feistel(uint32_t right32, uint64_t subkey48) {
    uint64_t expanded48 = permute((uint64_t)right32, E, 48, 32);
    uint64_t mixed48 = expanded48 ^ subkey48;
    uint32_t sbox_out32 = 0;

    for (size_t box = 0; box < 8; box++) {
        size_t shift = (7 - box) * 6;
        uint8_t chunk6 = (uint8_t)((mixed48 >> shift) & 0x3FU);
        uint8_t row = (uint8_t)(((chunk6 & 0x20U) >> 4) | (chunk6 & 0x01U));
        uint8_t col = (uint8_t)((chunk6 >> 1) & 0x0FU);
        uint8_t index = (uint8_t)(row * 16U + col);
        uint8_t s_value = S[box][index];
        sbox_out32 = (sbox_out32 << 4) | (uint32_t)(s_value & 0x0FU);
    }

    return (uint32_t)permute((uint64_t)sbox_out32, P, 32, 32);
}

static uint64_t des_encrypt_rounds(uint64_t plaintext64, const uint64_t subkeys[16], int rounds) {
    uint64_t ip_block = permute(plaintext64, IP, 64, 64);
    uint32_t left = (uint32_t)(ip_block >> 32);
    uint32_t right = (uint32_t)(ip_block & 0xFFFFFFFFULL);

    for (int round = 0; round < rounds; round++) {
        uint32_t next_left = right;
        uint32_t next_right = left ^ feistel(right, subkeys[round]);
        left = next_left;
        right = next_right;
    }

    uint64_t preoutput = ((uint64_t)right << 32) | (uint64_t)left;
    return permute(preoutput, FP, 64, 64);
}

static void build_ddt_tables(uint8_t ddt[8][64][16]) {
    memset(ddt, 0, 8 * 64 * 16 * sizeof(uint8_t));
    for (size_t box = 0; box < 8; box++) {
        for (size_t dx = 0; dx < 64; dx++) {
            for (size_t x = 0; x < 64; x++) {
                uint8_t y1 = S[box][x];
                uint8_t y2 = S[box][x ^ dx];
                ddt[box][dx][y1 ^ y2]++;
            }
        }
    }
}

static void print_ddt_box(FILE *out, size_t box, uint8_t ddt[64][16]) {
    fprintf(out, "\nS-box %zu differential distribution table\n", box + 1);
    fprintf(out, "      ");
    for (size_t dy = 0; dy < 16; dy++) {
        fprintf(out, "%3X", (unsigned)dy);
    }
    fprintf(out, "   | best\n");

    for (size_t dx = 0; dx < 64; dx++) {
        unsigned best_count = 0;
        size_t best_dy = 0;
        fprintf(out, "%02X : ", (unsigned)dx);
        for (size_t dy = 0; dy < 16; dy++) {
            unsigned count = ddt[dx][dy];
            fprintf(out, "%3u", count);
            if (count > best_count || (count == best_count && dy < best_dy)) {
                best_count = count;
                best_dy = dy;
            }
        }
        fprintf(out, "   | %02X (%u/64)\n", (unsigned)best_dy, best_count);
    }
}

static void print_ddt_summary(FILE *out, uint8_t ddt[8][64][16]) {
    for (size_t box = 0; box < 8; box++) {
        unsigned best_count = 0;
        size_t best_dx = 0;
        size_t best_dy = 0;

        for (size_t dx = 0; dx < 64; dx++) {
            for (size_t dy = 0; dy < 16; dy++) {
                unsigned count = ddt[box][dx][dy];
                if (count > best_count) {
                    best_count = count;
                    best_dx = dx;
                    best_dy = dy;
                }
            }
        }

        fprintf(out, "S-box %zu max entry: dx=%02X -> dy=%02X with probability %u/64 = %.4f\n",
                box + 1, (unsigned)best_dx, (unsigned)best_dy, best_count, (double)best_count / 64.0);
    }
}

static void print_ddt_report(FILE *out, uint8_t ddt[8][64][16]) {
    for (size_t box = 0; box < 8; box++) {
        print_ddt_box(out, box, ddt[box]);
    }
    fprintf(out, "\nSummary\n");
    print_ddt_summary(out, ddt);
}

static uint8_t best_output_diff(uint8_t ddt[64][16], uint8_t dx, uint8_t *best_count) {
    uint8_t chosen = 0;
    uint8_t count = 0;
    for (uint8_t dy = 0; dy < 16; dy++) {
        uint8_t candidate = ddt[dx][dy];
        if (candidate > count || (candidate == count && dy < chosen)) {
            count = candidate;
            chosen = dy;
        }
    }
    *best_count = count;
    return chosen;
}

static void build_trail(uint32_t dl0, uint32_t dr0, uint8_t ddt[8][64][16], Trail *trail) {
    memset(trail, 0, sizeof(*trail));
    trail->dl[0] = dl0;
    trail->dr[0] = dr0;
    trail->total_prob = 1.0;

    for (size_t round = 0; round < 5; round++) {
        uint64_t expanded = permute((uint64_t)trail->dr[round], E, 48, 32);
        trail->expanded[round] = expanded;

        uint32_t raw_f = 0;
        double round_prob = 1.0;

        for (size_t box = 0; box < 8; box++) {
            uint8_t dx = (uint8_t)((expanded >> ((7 - box) * 6)) & 0x3FU);
            uint8_t best_cnt = 0;
            uint8_t dy = best_output_diff(ddt[box], dx, &best_cnt);
            raw_f = (raw_f << 4) | (uint32_t)dy;
            round_prob *= (double)best_cnt / 64.0;
        }

        trail->raw_f[round] = raw_f;
        trail->f_out[round] = (uint32_t)permute((uint64_t)raw_f, P, 32, 32);
        trail->round_prob[round] = round_prob;
        trail->total_prob *= round_prob;

        trail->dl[round + 1] = trail->dr[round];
        trail->dr[round + 1] = trail->dl[round] ^ trail->f_out[round];
    }
}

static int trail_is_non_iterative(const Trail *trail) {
    return trail->dl[0] != trail->dl[5] || trail->dr[0] != trail->dr[5];
}

static void print_state_diff(const char *label, uint32_t dl, uint32_t dr) {
    printf("%sdL=%08X  dR=%08X\n", label, dl, dr);
}

static void print_trail(const Trail *trail) {
    printf("\nConstructed 5-round differential characteristic\n");
    print_state_diff("Round 0 : ", trail->dl[0], trail->dr[0]);

    for (size_t round = 0; round < 5; round++) {
        printf("Round %zu : ", round + 1);
        printf("dF=%08X  p=%.6e\n", trail->f_out[round], trail->round_prob[round]);
        printf("          S-box input/output diffs: ");
        for (size_t box = 0; box < 8; box++) {
            uint8_t dx = (uint8_t)((trail->expanded[round] >> ((7 - box) * 6)) & 0x3FU);
            uint8_t dy = (uint8_t)((trail->raw_f[round] >> ((7 - box) * 4)) & 0x0FU);
            printf("S%zu:%02X->%X ", box + 1, dx, dy);
        }
        printf("\n");
        print_state_diff("          Next : ", trail->dl[round + 1], trail->dr[round + 1]);
    }

    uint64_t start_plain = permute(((uint64_t)trail->dl[0] << 32) | (uint64_t)trail->dr[0], FP, 64, 64);
    uint64_t end_cipher = permute(((uint64_t)trail->dl[5] << 32) | (uint64_t)trail->dr[5], FP, 64, 64);

    printf("\nInternal start difference: %08X %08X\n", trail->dl[0], trail->dr[0]);
    printf("Equivalent plaintext difference : %016llX\n", (unsigned long long)start_plain);
    printf("Predicted final internal diff   : %08X %08X\n", trail->dl[5], trail->dr[5]);
    printf("Equivalent ciphertext diff      : %016llX\n", (unsigned long long)end_cipher);
    printf("Theoretical trail probability   : %.12e\n", trail->total_prob);
}

static void xorshift64star_seed(uint64_t *state) {
    if (*state == 0) {
        *state = 0x9E3779B97F4A7C15ULL;
    }
}

static uint64_t xorshift64star(uint64_t *state) {
    uint64_t x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 2685821657736338717ULL;
}

static void find_best_trail(uint8_t ddt[8][64][16], Trail *best, uint32_t *best_dl0, uint32_t *best_dr0) {
    int have_non_iterative = 0;
    int have_any = 0;
    double best_non_iterative_prob = -1.0;
    double best_any_prob = -1.0;
    Trail cand;
    Trail best_non_iterative;
    Trail best_any;
    uint32_t cand_dl0 = 0;
    uint32_t cand_dr0 = 0;

    for (size_t bit = 0; bit < 32; bit++) {
        cand_dl0 = 0;
        cand_dr0 = (uint32_t)1u << bit;
        build_trail(cand_dl0, cand_dr0, ddt, &cand);

        if (!have_any || cand.total_prob > best_any_prob) {
            best_any_prob = cand.total_prob;
            best_any = cand;
            *best_dl0 = cand_dl0;
            *best_dr0 = cand_dr0;
            have_any = 1;
        }

        if (trail_is_non_iterative(&cand)) {
            if (!have_non_iterative || cand.total_prob > best_non_iterative_prob) {
                best_non_iterative_prob = cand.total_prob;
                best_non_iterative = cand;
                have_non_iterative = 1;
            }
        }
    }

    if (have_non_iterative) {
        *best = best_non_iterative;
    } else {
        *best = best_any;
    }

    *best_dl0 = best->dl[0];
    *best_dr0 = best->dr[0];
}

static void run_experiment(const Trail *trail, const uint64_t subkeys[16], size_t pair_count) {
    uint64_t diff_plain = permute(((uint64_t)trail->dl[0] << 32) | (uint64_t)trail->dr[0], FP, 64, 64);
    uint64_t diff_cipher = permute(((uint64_t)trail->dl[5] << 32) | (uint64_t)trail->dr[5], FP, 64, 64);
    uint64_t rng = 0x123456789ABCDEF0ULL;
    size_t hits = 0;

    xorshift64star_seed(&rng);
    for (size_t i = 0; i < pair_count; i++) {
        uint64_t plain = xorshift64star(&rng);
        uint64_t other = plain ^ diff_plain;
        uint64_t c1 = des_encrypt_rounds(plain, subkeys, 5);
        uint64_t c2 = des_encrypt_rounds(other, subkeys, 5);
        if ((c1 ^ c2) == diff_cipher) {
            hits++;
        }
    }

    printf("\nExperiment on %zu plaintext pairs\n", pair_count);
    printf("Observed matches : %zu\n", hits);
    printf("Empirical probability : %.12f\n", pair_count == 0 ? 0.0 : (double)hits / (double)pair_count);
}

static int prompt_yes_no(const char *prompt) {
    char line[32];

    printf("%s", prompt);
    if (!fgets(line, sizeof(line), stdin)) {
        return 0;
    }

    return line[0] == 'y' || line[0] == 'Y';
}

int main(void) {
    uint8_t ddt[8][64][16];
    uint64_t key64 = 0;
    uint64_t subkeys[16];
    char line[256];

    build_ddt_tables(ddt);

    printf("DES differential analysis (Homework 5)\n");
    printf("1) Print DES S-box DDTs\n");
    printf("2) Construct and test a 5-round characteristic\n");
    printf("Select mode: ");
    if (!fgets(line, sizeof(line), stdin)) {
        fprintf(stderr, "Input error.\n");
        return 1;
    }

    int mode = (int)strtol(line, NULL, 10);
    if (mode == 1) {
        print_ddt_report(stdout, ddt);

        if (prompt_yes_no("\nWrite the same output to des_sbox_ddt.txt as well? (y/n): ")) {
            FILE *txt = fopen("des_sbox_ddt.txt", "w");
            if (!txt) {
                fprintf(stderr, "Could not create des_sbox_ddt.txt.\n");
                return 1;
            }

            print_ddt_report(txt, ddt);
            fclose(txt);
            printf("Saved to des_sbox_ddt.txt\n");
        }
        return 0;
    }

    if (mode != 2) {
        fprintf(stderr, "Select mode 1 or 2.\n");
        return 1;
    }

    printf("Key (64-bit hex, optional 0x, default 0x133457799BBCDFF1): ");
    if (!fgets(line, sizeof(line), stdin)) {
        fprintf(stderr, "Input error.\n");
        return 1;
    }
    chomp_line(line);
    if (line[0] == '\0') {
        key64 = 0x133457799BBCDFF1ULL;
    } else {
        if (parse_u64_line(line, &key64) != 0) {
            fprintf(stderr, "Invalid key.\n");
            return 1;
        }
    }

    printf("Number of plaintext pairs to test: ");
    if (!fgets(line, sizeof(line), stdin)) {
        fprintf(stderr, "Input error.\n");
        return 1;
    }
    size_t pair_count = 0;
    if (parse_size_t_line(line, &pair_count) != 0 || pair_count == 0) {
        fprintf(stderr, "Invalid pair count.\n");
        return 1;
    }

    generate_subkeys(key64, subkeys);

    Trail trail;
    uint32_t start_dl0 = 0;
    uint32_t start_dr0 = 0;
    find_best_trail(ddt, &trail, &start_dl0, &start_dr0);

    printf("\nBest automatically constructed non-iterative trail from one-bit right-half starts\n");
    print_trail(&trail);
    run_experiment(&trail, subkeys, pair_count);

    printf("\nPress Enter to exit...");
    fflush(stdout);
    (void)getchar();
    return 0;
}
