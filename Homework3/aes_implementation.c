#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// AES-192 constants
#define AES_BLOCK_BYTES 16
#define AES192_KEY_BYTES 24
#define AES192_NK 6
#define AES192_NR 12
#define AES192_EXPANDED_KEY_BYTES (AES_BLOCK_BYTES * (AES192_NR + 1)) // 208

// Forward S-Box
static const uint8_t SBOX[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

// Inverse S-Box
static const uint8_t INV_SBOX[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
    0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
    0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
    0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
    0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
    0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
    0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
    0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
    0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
    0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
    0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
    0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

// Round constants for key expansion
static const uint8_t RCON[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

// function prototypes
int parse_fixed_hex(const char *text, uint8_t *out, size_t out_len, int *used_padding);
void print_hex_block(const uint8_t *data, size_t len);
uint8_t xtime(uint8_t x);
uint8_t gf_mul(uint8_t a, uint8_t b);
void add_round_key(uint8_t state[16], const uint8_t round_key[16]);
void sub_bytes(uint8_t state[16]);
void inv_sub_bytes(uint8_t state[16]);
void shift_rows(uint8_t state[16]);
void inv_shift_rows(uint8_t state[16]);
void mix_columns(uint8_t state[16]);
void inv_mix_columns(uint8_t state[16]);
void rot_word(uint8_t w[4]);
void sub_word(uint8_t w[4]);
void aes192_key_expansion(const uint8_t key[24], uint8_t expanded[AES192_EXPANDED_KEY_BYTES]);
void aes192_encrypt_block(const uint8_t plaintext[16], const uint8_t expanded[AES192_EXPANDED_KEY_BYTES], uint8_t ciphertext[16]);
void aes192_decrypt_block(const uint8_t ciphertext[16], const uint8_t expanded[AES192_EXPANDED_KEY_BYTES], uint8_t plaintext[16]);

int main(void) {
    int mode = 0;
    int exit_code = 0;
    char input_text[65] = {0};
    char key_text[65] = {0};
    uint8_t input_block[16] = {0};
    uint8_t key[24] = {0};
    uint8_t expanded[AES192_EXPANDED_KEY_BYTES] = {0};
    uint8_t output_block[16] = {0};

    // mode selection
    printf("Select AES-192 mode:\n1) Encrypt (plaintext + key)\n2) Decrypt (ciphertext + key)\nMode: ");
    if (scanf_s("%d", &mode) != 1) {
        printf("Invalid mode input.\n");
        exit_code = 1;
        goto finish;
    }

    if (mode == 1) {
        // encryption mode
        printf("\nPlaintext (max 32 hex chars, shorter inputs are left-padded with 00): ");
        int padded = 0;
        if (scanf_s("%64s", input_text, (unsigned)sizeof(input_text)) != 1 ||
            !parse_fixed_hex(input_text, input_block, AES_BLOCK_BYTES, &padded)) {
            printf("Invalid plaintext input.\n");
            exit_code = 1;
            goto finish;
        }
        if (padded) {
            printf("Plaintext was left-padded with 00 bytes.\n");
        }
    } else if (mode == 2) {
        // decryption mode
        printf("\nCiphertext (max 32 hex chars, shorter inputs are left-padded with 00): ");
        int padded = 0;
        if (scanf_s("%64s", input_text, (unsigned)sizeof(input_text)) != 1 ||
            !parse_fixed_hex(input_text, input_block, AES_BLOCK_BYTES, &padded)) {
            printf("Invalid ciphertext input.\n");
            exit_code = 1;
            goto finish;
        }
        if (padded) {
            printf("Ciphertext was left-padded with 00 bytes.\n");
        }
    } else {
        printf("Mode 1 or 2 should be selected.\n");
        exit_code = 1;
        goto finish;
    }

    printf("Key (max 48 hex chars, shorter inputs are left-padded with 00): ");
    int key_padded = 0;
    if (scanf_s("%64s", key_text, (unsigned)sizeof(key_text)) != 1 ||
        !parse_fixed_hex(key_text, key, AES192_KEY_BYTES, &key_padded)) {
        printf("Invalid key input.\n");
        exit_code = 1;
        goto finish;
    }
    if (key_padded) {
        printf("Key was left-padded with 00 bytes.\n");
    }

    aes192_key_expansion(key, expanded);

    if (mode == 1) {
        aes192_encrypt_block(input_block, expanded, output_block);
        printf("Ciphertext: ");
        print_hex_block(output_block, AES_BLOCK_BYTES);
    } else {
        aes192_decrypt_block(input_block, expanded, output_block);
        printf("Plaintext: ");
        print_hex_block(output_block, AES_BLOCK_BYTES);
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

int parse_fixed_hex(const char *text, uint8_t *out, size_t out_len, int *used_padding) {
    size_t len = strlen(text);
    size_t start = 0;
    size_t max_hex_chars = out_len * 2;
    char normalized[129];

    if (len > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        start = 2;
        len -= 2;
    }

    if (len == 0 || len > max_hex_chars || max_hex_chars >= sizeof(normalized)) {
        return 0;
    }

    // clear output and build a normalized hex string (left-padded with '0')
    memset(out, 0, out_len);
    memset(normalized, '0', max_hex_chars);
    normalized[max_hex_chars] = '\0';

    for (size_t i = 0; i < len; i++) {
        char ch = text[start + i];
        if (!isxdigit((unsigned char)ch)) {
            return 0;
        }
        normalized[(max_hex_chars - len) + i] = ch;
    }

    if (used_padding != NULL) {
        *used_padding = (len < max_hex_chars) ? 1 : 0;
    }

    // convert normalized hex into bytes
    for (size_t i = 0; i < out_len; i++) {
        char hi = normalized[2 * i];
        char lo = normalized[(2 * i) + 1];
        char tmp[3] = {hi, lo, '\0'};
        unsigned long v = strtoul(tmp, NULL, 16);
        out[i] = (uint8_t)v;
    }

    return 1;
}

void print_hex_block(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    putchar('\n');
}

uint8_t xtime(uint8_t x) {
    // multiply by x in GF(2^8)
    return (uint8_t)((x << 1) ^ ((x & 0x80U) ? 0x1BU : 0x00U));
}

uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    while (b != 0U) {
        if (b & 1U) {
            result ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    return result;
}

void add_round_key(uint8_t state[16], const uint8_t round_key[16]) {
    for (size_t i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}

void sub_bytes(uint8_t state[16]) {
    for (size_t i = 0; i < 16; i++) {
        state[i] = SBOX[state[i]];
    }
}

void inv_sub_bytes(uint8_t state[16]) {
    for (size_t i = 0; i < 16; i++) {
        state[i] = INV_SBOX[state[i]];
    }
}

void shift_rows(uint8_t state[16]) {
    uint8_t tmp[16];
    memcpy(tmp, state, 16);

    // AES state is column-major: state[row + 4*col]
    state[0] = tmp[0];
    state[4] = tmp[4];
    state[8] = tmp[8];
    state[12] = tmp[12];

    state[1] = tmp[5];
    state[5] = tmp[9];
    state[9] = tmp[13];
    state[13] = tmp[1];

    state[2] = tmp[10];
    state[6] = tmp[14];
    state[10] = tmp[2];
    state[14] = tmp[6];

    state[3] = tmp[15];
    state[7] = tmp[3];
    state[11] = tmp[7];
    state[15] = tmp[11];
}

void inv_shift_rows(uint8_t state[16]) {
    uint8_t tmp[16];
    memcpy(tmp, state, 16);

    // inverse row shifts
    state[0] = tmp[0];
    state[4] = tmp[4];
    state[8] = tmp[8];
    state[12] = tmp[12];

    state[1] = tmp[13];
    state[5] = tmp[1];
    state[9] = tmp[5];
    state[13] = tmp[9];

    state[2] = tmp[10];
    state[6] = tmp[14];
    state[10] = tmp[2];
    state[14] = tmp[6];

    state[3] = tmp[7];
    state[7] = tmp[11];
    state[11] = tmp[15];
    state[15] = tmp[3];
}

void mix_columns(uint8_t state[16]) {
    // mix each column in GF(2^8)
    for (size_t c = 0; c < 4; c++) {
        uint8_t a0 = state[4 * c + 0];
        uint8_t a1 = state[4 * c + 1];
        uint8_t a2 = state[4 * c + 2];
        uint8_t a3 = state[4 * c + 3];

        state[4 * c + 0] = (uint8_t)(gf_mul(a0, 0x02U) ^ gf_mul(a1, 0x03U) ^ a2 ^ a3);
        state[4 * c + 1] = (uint8_t)(a0 ^ gf_mul(a1, 0x02U) ^ gf_mul(a2, 0x03U) ^ a3);
        state[4 * c + 2] = (uint8_t)(a0 ^ a1 ^ gf_mul(a2, 0x02U) ^ gf_mul(a3, 0x03U));
        state[4 * c + 3] = (uint8_t)(gf_mul(a0, 0x03U) ^ a1 ^ a2 ^ gf_mul(a3, 0x02U));
    }
}

void inv_mix_columns(uint8_t state[16]) {
    // inverse mix for decryption
    for (size_t c = 0; c < 4; c++) {
        uint8_t a0 = state[4 * c + 0];
        uint8_t a1 = state[4 * c + 1];
        uint8_t a2 = state[4 * c + 2];
        uint8_t a3 = state[4 * c + 3];

        state[4 * c + 0] = (uint8_t)(gf_mul(a0, 0x0EU) ^ gf_mul(a1, 0x0BU) ^ gf_mul(a2, 0x0DU) ^ gf_mul(a3, 0x09U));
        state[4 * c + 1] = (uint8_t)(gf_mul(a0, 0x09U) ^ gf_mul(a1, 0x0EU) ^ gf_mul(a2, 0x0BU) ^ gf_mul(a3, 0x0DU));
        state[4 * c + 2] = (uint8_t)(gf_mul(a0, 0x0DU) ^ gf_mul(a1, 0x09U) ^ gf_mul(a2, 0x0EU) ^ gf_mul(a3, 0x0BU));
        state[4 * c + 3] = (uint8_t)(gf_mul(a0, 0x0BU) ^ gf_mul(a1, 0x0DU) ^ gf_mul(a2, 0x09U) ^ gf_mul(a3, 0x0EU));
    }
}

void rot_word(uint8_t w[4]) {
    uint8_t t = w[0];
    w[0] = w[1];
    w[1] = w[2];
    w[2] = w[3];
    w[3] = t;
}

void sub_word(uint8_t w[4]) {
    for (size_t i = 0; i < 4; i++) {
        w[i] = SBOX[w[i]];
    }
}

void aes192_key_expansion(const uint8_t key[24], uint8_t expanded[AES192_EXPANDED_KEY_BYTES]) {
    // first 24 bytes come directly from the key
    memcpy(expanded, key, AES192_KEY_BYTES);

    size_t bytes_generated = AES192_KEY_BYTES;
    uint8_t temp[4];
    size_t rcon_index = 0;

    while (bytes_generated < AES192_EXPANDED_KEY_BYTES) {
        for (size_t i = 0; i < 4; i++) {
            temp[i] = expanded[bytes_generated - 4 + i];
        }

        if ((bytes_generated / 4) % AES192_NK == 0) {
            // every Nk words: RotWord + SubWord + Rcon
            rot_word(temp);
            sub_word(temp);
            temp[0] ^= RCON[rcon_index++];
        }

        // w[i] = w[i-Nk] XOR temp
        for (size_t i = 0; i < 4; i++) {
            expanded[bytes_generated] = (uint8_t)(expanded[bytes_generated - AES192_KEY_BYTES] ^ temp[i]);
            bytes_generated++;
        }
    }
}

void aes192_encrypt_block(const uint8_t plaintext[16], const uint8_t expanded[AES192_EXPANDED_KEY_BYTES], uint8_t ciphertext[16]) {
    uint8_t state[16];
    memcpy(state, plaintext, 16);

    // initial round key
    add_round_key(state, &expanded[0]);

    // rounds 1..11
    for (size_t round = 1; round < AES192_NR; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &expanded[round * 16]);
    }

    // final round (without mix_columns)
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &expanded[AES192_NR * 16]);

    memcpy(ciphertext, state, 16);
}

void aes192_decrypt_block(const uint8_t ciphertext[16], const uint8_t expanded[AES192_EXPANDED_KEY_BYTES], uint8_t plaintext[16]) {
    uint8_t state[16];
    memcpy(state, ciphertext, 16);

    // start with last round key
    add_round_key(state, &expanded[AES192_NR * 16]);

    // rounds 11..1
    for (size_t round = AES192_NR - 1; round > 0; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, &expanded[round * 16]);
        inv_mix_columns(state);
    }

    // final inverse round (without inv_mix_columns)
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, &expanded[0]);

    memcpy(plaintext, state, 16);
}
