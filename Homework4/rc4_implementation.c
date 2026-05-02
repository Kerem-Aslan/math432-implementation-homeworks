#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// remove newline characters from a string
static void chomp_line(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[--n] = '\0';
    }
}

// convert a hex character to a nibble
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

// parse hex from a line into a newly allocated buffer
static int parse_hex_alloc(const char *line, uint8_t **out, size_t *out_len) {
    const char *p = line;
    while (*p && isspace((unsigned char)*p)) {
        p++;
    }
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
    }
    const char *start = p;

    size_t hex_digits = 0;
    for (; *p; p++) {
        if (isspace((unsigned char)*p)) {
            continue;
        }
        if (hex_nibble((unsigned char)*p) < 0) {
            return -1;
        }
        hex_digits++;
    }
    if (hex_digits == 0 || (hex_digits % 2u) != 0u) {
        return -1;
    }

    size_t nbytes = hex_digits / 2u;
    uint8_t *buf = (uint8_t *)malloc(nbytes);
    if (!buf) {
        return -2;
    }

    p = start;
    size_t i = 0;
    int hi = -1;
    for (; *p; p++) {
        if (isspace((unsigned char)*p)) {
            continue;
        }
        int v = hex_nibble((unsigned char)*p);
        if (hi < 0) {
            hi = v;
        } else {
            buf[i++] = (uint8_t)((unsigned)(hi << 4) | (unsigned)v);
            hi = -1;
        }
    }

    *out = buf;
    *out_len = nbytes;
    return 0;
}

// swap two bytes
static void rc4_swap(uint8_t *a, uint8_t *b) {
    uint8_t t = *a;
    *a = *b;
    *b = t;
}

// RC4 stream cipher encryption and decryption
static void rc4_crypt(uint8_t *data, size_t len, const uint8_t *key, size_t key_len) {
    uint8_t S[256];
    for (int i = 0; i < 256; i++) {
        S[i] = (uint8_t)i;
    }
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key_len]) % 256;
        rc4_swap(&S[i], &S[j]);
    }

    int i = 0;
    j = 0;
    for (size_t n = 0; n < len; n++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        rc4_swap(&S[i], &S[j]);
        uint8_t k = S[(uint8_t)(S[i] + S[j])];
        data[n] ^= k;
    }
}

// print the hex string
static void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    putchar('\n');
}

// main function
int main(void) {
    char line[1048576];
    char mode_line[64];
    int mode = 0;
    uint8_t *key = NULL;
    uint8_t *buf = NULL;
    size_t key_len = 0;
    size_t buf_len = 0;

    printf("RC4 stream cipher\n");
    printf("1) Encrypt (plaintext hex + key hex)\n");
    printf("2) Decrypt (ciphertext hex + key hex)\n");
    printf("Mode: ");
    if (!fgets(mode_line, sizeof(mode_line), stdin)) {
        fprintf(stderr, "Input error.\n");
        return 1;
    }
    mode = (int)strtol(mode_line, NULL, 10);

    if (mode == 1) {
        printf("Plaintext (hex, even number of digits, optional 0x): ");
    } else if (mode == 2) {
        printf("Ciphertext (hex, even number of digits, optional 0x): ");
    } else {
        fprintf(stderr, "Select mode 1 or 2.\n");
        return 1;
    }

    if (!fgets(line, sizeof(line), stdin)) {
        fprintf(stderr, "Input error.\n");
        return 1;
    }
    chomp_line(line);
    int pr = parse_hex_alloc(line, &buf, &buf_len);
    if (pr == -2) {
        fprintf(stderr, "Out of memory.\n");
        return 1;
    }
    if (pr != 0) {
        fprintf(stderr, "Invalid data: use hex with an even length.\n");
        return 1;
    }

    printf("Key (hex, even number of digits, optional 0x): ");
    if (!fgets(line, sizeof(line), stdin)) {
        fprintf(stderr, "Input error.\n");
        free(buf);
        return 1;
    }
    chomp_line(line);
    pr = parse_hex_alloc(line, &key, &key_len);
    if (pr == -2) {
        fprintf(stderr, "Out of memory.\n");
        free(buf);
        return 1;
    }
    if (pr != 0 || key_len == 0) {
        fprintf(stderr, "Invalid key: non-empty hex with even length required.\n");
        free(buf);
        free(key);
        return 1;
    }

    rc4_crypt(buf, buf_len, key, key_len);

    if (mode == 1) {
        printf("Ciphertext: ");
    } else {
        printf("Plaintext: ");
    }
    print_hex(buf, buf_len);

    free(buf);
    free(key);

    printf("\nPress Enter to exit...");
    fflush(stdout);
    (void)getchar();

    return 0;
}
