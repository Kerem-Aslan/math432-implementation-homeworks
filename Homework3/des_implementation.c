#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

// Tables from FIPS Pub 46-3
// Initial Permutation Table
static const uint8_t IP[] = {
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7
};

// Final Permutation Table (inverse of IP)
static const uint8_t FP[] = {
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25
};

// Expansion Table
static const uint8_t E[] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

// Post S-Box Permutation Table
static const uint8_t P[] = {
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
};

// The S-Box tables
static const uint8_t S[8][64] = {{
    /* S1 */
    14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
     0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
     4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
    15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
},{
    /* S2 */
    15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
     3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
     0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
    13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
},{
    /* S3 */
    10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
    13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
    13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
     1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
},{
    /* S4 */
     7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
    13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
    10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
     3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
},{
    /* S5 */
     2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
    14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
     4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
    11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
},{
    /* S6 */
    12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
    10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
     9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
     4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
},{
    /* S7 */
     4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
    13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
     1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
     6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
},{
    /* S8 */
    13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
     1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
     7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
     2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
}};

// Permuted Choice 1 and 2 Tables
static const uint8_t PC1[] = {
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
};

static const uint8_t PC2[] = {
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

// Iteration Shift Array
static const uint8_t IS[] = {
    /* 1   2   3   4   5   6   7   8   9  10  11  12  13  14  15  16 */
       1,  1,  2,  2,  2,  2,  2,  2,  1,  2,  2,  2,  2,  2,  2,  1
};

// function prototypes
static inline uint8_t get_position_bit(uint64_t x, size_t pos, size_t width);
static inline void change_position_bit(uint64_t *x, size_t pos, uint8_t bit, size_t width);
uint64_t permute(uint64_t input, const uint8_t *table, size_t out_len, size_t in_len);
uint32_t left_rotate28(uint32_t x, uint8_t shift);
void generate_subkeys(uint64_t key64, uint64_t subkeys[16]);
uint32_t feistel(uint32_t right32, uint64_t subkey48);
uint64_t des_encrypt_block(uint64_t plaintext64, uint64_t key64);
uint64_t des_decrypt_block(uint64_t ciphertext64, uint64_t key64);


int main(void) {
    int mode = 0;
    int exit_code = 0;
    unsigned long long input_value = 0ULL;
    unsigned long long key_value = 0ULL;

    // mode selection
    printf("Select DES mode:\n1) Encrypt (plaintext + key)\n2) Decrypt (ciphertext + key)\nMode: ");
    if (scanf_s("%d", &mode) != 1) {
        printf("Invalid mode input.\n");
        exit_code = 1;
        goto finish;
    }
    // encryption mode
    if (mode == 1) {
        printf("\nPlaintext (16 hex): ");
        if (scanf_s("%16llx", &input_value) != 1) {
            printf("Invalid plaintext input.\n");
            exit_code = 1;
            goto finish;
        }
        printf("Key (16 hex): ");
        if (scanf_s("%16llx", &key_value) != 1) {
            printf("Invalid key input.\n");
            exit_code = 1;
            goto finish;
        }
        uint64_t cipher = des_encrypt_block((uint64_t)input_value, (uint64_t)key_value);
        printf("Ciphertext: %016llX\n", (unsigned long long)cipher);
    }
    // decryption mode
    else if (mode == 2) {
        printf("\nCiphertext (16 hex): ");
        if (scanf_s("%16llx", &input_value) != 1) {
            printf("Invalid ciphertext input.\n");
            exit_code = 1;
            goto finish;
        }
        printf("Key (16 hex): ");
        if (scanf_s("%16llx", &key_value) != 1) {
            printf("Invalid key input.\n");
            exit_code = 1;
            goto finish;
        }
        uint64_t plain = des_decrypt_block((uint64_t)input_value, (uint64_t)key_value);
        printf("Plaintext: %016llX\n", (unsigned long long)plain);
    }
    else {
        printf("Mode 1 or 2 should be selected.\n");
        exit_code = 1;
        goto finish;
    }

finish:
    printf("\nPress Enter to exit...");
    {
        int c = 0;
        while ((c = getchar()) != '\n' && c != EOF) {
        }
    }
    getchar();
    return exit_code;
}

// one-based function, so pos = 1 -> msb, pos = width -> lsb (left to right)
static inline uint8_t get_position_bit(uint64_t x, size_t pos, size_t width) {
    if (pos < 1 || pos > width) return 0; // if the position is out of range, return 0
    size_t shift = width - pos;
    return (uint8_t)((x >> shift) & 1ULL);
}

// this one is one based too. sets (or clears depending on "bit") the bit at position "pos".
static inline void change_position_bit(uint64_t *x, size_t pos, uint8_t bit, size_t width) {
    if (pos < 1 || pos > width) return; // if the position is out of range, return
    size_t shift = width - pos;
    if (bit == 1)
        *x |= 1ULL << shift;
    else
        *x &= ~(1ULL << shift);
}

// permutes from a provided table
uint64_t permute(uint64_t input, const uint8_t *table, size_t out_len, size_t in_len) {
    uint64_t output = 0;
    for (size_t i = 1; i <= out_len; i++) {
        size_t src_pos = table[i-1]; // gets src_pos from a table
        uint8_t bit = get_position_bit(input, src_pos, in_len); // gets the bit info from the provided position
        change_position_bit(&output, i, bit, out_len); // changes the output bit
    }
    return output;
}

// left rotating in a 28 bit value
uint32_t left_rotate28(uint32_t x, uint8_t shift) {
    const uint32_t MASK28 = 0x0FFFFFFF; // first 28 bit
    x &= MASK28;
    shift %= 28; // ring
    if (shift == 0) return x;
    return ((x << shift) | (x >> (28 - shift))) & MASK28;
}

// generates 16 round keys (48-bit each in uint64_t)
void generate_subkeys(uint64_t key64, uint64_t subkeys[16]) {
    const uint32_t MASK28 = 0x0FFFFFFF;
    uint64_t key56 = permute(key64, PC1, 56, 64);
    uint32_t c = (uint32_t)((key56 >> 28) & MASK28);
    uint32_t d = (uint32_t)(key56 & MASK28);
    // generates 16 round keys
    for (size_t round = 0; round < 16; round++) {
        c = left_rotate28(c, IS[round]);
        d = left_rotate28(d, IS[round]);

        uint64_t cd = ((uint64_t)c << 28) | (uint64_t)d;
        subkeys[round] = permute(cd, PC2, 48, 56);
    }
}

// DES round function: F(R, K) -> 32-bit
uint32_t feistel(uint32_t right32, uint64_t subkey48) {
    uint64_t expanded48 = permute((uint64_t)right32, E, 48, 32);
    uint64_t mixed48 = expanded48 ^ subkey48;
    uint32_t sbox_out32 = 0;

    for (size_t box = 0; box < 8; box++) { // 8 s-boxes
        size_t shift = (7 - box) * 6;
        uint8_t chunk6 = (uint8_t)((mixed48 >> shift) & 0b111111ULL);

        // row: first+last bits, col: middle 4 bits
        uint8_t row = (uint8_t)(((chunk6 & 0b100000U) >> 4) | (chunk6 & 0b000001U));
        uint8_t col = (uint8_t)((chunk6 >> 1) & 0x0FU);

        uint8_t index = row * 16 + col;
        uint8_t s_value = S[box][index];
        sbox_out32 = (sbox_out32 << 4) | (uint32_t)(s_value & 0x0FU);
    }

    // p permutation after s-boxes
    return (uint32_t)permute((uint64_t)sbox_out32, P, 32, 32);
}

// encrypt block
uint64_t des_encrypt_block(uint64_t plaintext64, uint64_t key64) {
    uint64_t subkeys[16];
    generate_subkeys(key64, subkeys);
    // initial permutation
    uint64_t ip_block = permute(plaintext64, IP, 64, 64);
    // split into left and right 32-bit blocks
    uint32_t left = (uint32_t)(ip_block >> 32);
    uint32_t right = (uint32_t)(ip_block & 0xFFFFFFFFULL);
    // 16 rounds of feistel function
    for (size_t round = 0; round < 16; round++) {
        uint32_t next_left = right;
        uint32_t next_right = left ^ feistel(right, subkeys[round]);
        left = next_left;
        right = next_right;
    }
    // final permutation
    uint64_t preoutput = ((uint64_t)right << 32) | (uint64_t)left;
    return permute(preoutput, FP, 64, 64);
}

// decrypt block
uint64_t des_decrypt_block(uint64_t ciphertext64, uint64_t key64) {
    uint64_t subkeys[16];
    generate_subkeys(key64, subkeys);
    // initial permutation
    uint64_t ip_block = permute(ciphertext64, IP, 64, 64);
    // split into left and right 32-bit blocks
    uint32_t left = (uint32_t)(ip_block >> 32);
    uint32_t right = (uint32_t)(ip_block & 0xFFFFFFFFULL);
    // 16 rounds of feistel function (reverse order)
    for (int round = 15; round >= 0; round--) {
        uint32_t next_left = right;
        uint32_t next_right = left ^ feistel(right, subkeys[round]);
        left = next_left;
        right = next_right;
    }
    // final permutation
    uint64_t preoutput = ((uint64_t)right << 32) | (uint64_t)left;
    return permute(preoutput, FP, 64, 64);
}
