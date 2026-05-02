#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// parse a binary sequence from a line of input
static int parse_binary_line(const char *line, uint8_t **bits, size_t *out_len) {
    size_t cap = 64;
    size_t n = 0;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) return -1; // out of memory

    for (const char *p = line; *p; p++) {
        if (*p == '0' || *p == '1') {
            if (n + 1 > cap) {
                cap *= 2;
                uint8_t *nb = (uint8_t *)realloc(buf, cap);
                if (!nb) {
                    free(buf);
                    return -1;
                }
                buf = nb;
            }
            buf[n++] = (uint8_t)(*p - '0');
        } else if (!isspace((unsigned char)*p)) {
            free(buf);
            return -2;
        }
    }
    *bits = buf;
    *out_len = n;
    return 0;
}

// Berlekamp-Massey algorithm to find the minimal LFSR connection polynomial
static size_t berlekamp_massey(const uint8_t *s, size_t n, uint8_t *C, uint8_t *work_B, uint8_t *work_T) {
    if (n == 0) {
        C[0] = 1;
        return 0;
    }

    memset(C, 0, (n + 2) * sizeof(uint8_t));
    memset(work_B, 0, (n + 2) * sizeof(uint8_t));
    C[0] = 1;
    work_B[0] = 1;

    size_t L = 0;
    size_t m = 1;

    for (size_t idx = 0; idx < n; idx++) {
        uint8_t d = s[idx];
        for (size_t i = 1; i <= L; i++) {
            if (idx >= i) {
                d ^= (uint8_t)(C[i] & s[idx - i]);
            }
        }

        if (d == 0) {
            m++;
        } else {
            memcpy(work_T, C, (n + 2) * sizeof(uint8_t));

            for (size_t j = 0; j < n + 2; j++) {
                if (work_B[j]) {
                    // GF(2): C := C + d * B * x^m (same as + (d/b) B x^m since b = 1 always over F_2)
                    C[j + m] ^= (uint8_t)(d & work_B[j]);
                }
            }

            if (2 * L <= idx) {
                L = idx + 1 - L;
                memcpy(work_B, work_T, (n + 2) * sizeof(uint8_t));
                m = 1;
            } else {
                m++;
            }
        }
    }
    return L;
}

// print the connection polynomial
static void print_connection_polynomial(const uint8_t *C, size_t L) {
    printf("Connection polynomial C(D) = ");
    int first = 1;
    if (C[0]) {
        printf("1");
        first = 0;
    }
    for (size_t i = 1; i <= L; i++) {
        if (!C[i]) {
            continue;
        }
        if (!first) {
            printf(" + ");
        }
        first = 0;
        if (i == 1) {
            printf("D");
        } else {
            printf("D^%zu", i);
        }
    }
    if (first) {
        printf("0");
    }
    printf("\n");
}

// print the monic characteristic polynomial
static void print_monic_characteristic(const uint8_t *C, size_t L) {
    printf("Monic characteristic polynomial f(x) = x^L C(1/x) = ");
    if (L == 0) {
        printf("1\n");
        return;
    }
    /* x^L */
    if (L == 1) {
        printf("x");
    } else {
        printf("x^%zu", L);
    }
    for (size_t i = 1; i <= L; i++) {
        if (!C[i]) {
            continue;
        }
        printf(" + ");
        if (L - i == 1) {
            printf("x");
        } else if (L - i == 0) {
            printf("1");
        } else {
            printf("x^%zu", L - i);
        }
    }
    printf("\n");
}

// main function
int main(void) {
    char line[1048576];
    uint8_t *bits = NULL;
    size_t n = 0;

    printf("Berlekamp-Massey (GF(2)) - minimal LFSR connection polynomial\n");
    printf("Enter a binary sequence (only 0/1, optional spaces/newlines). End line with Enter:\n");

    if (!fgets(line, sizeof(line), stdin)) {
        fprintf(stderr, "Input error.\n");
        return 1;
    }

    int pr = parse_binary_line(line, &bits, &n);
    if (pr == -1) {
        fprintf(stderr, "Out of memory.\n");
        return 1;
    }
    if (pr == -2) {
        fprintf(stderr, "Invalid character: use only 0, 1, and whitespace.\n");
        return 1;
    }
    if (n == 0) {
        fprintf(stderr, "Empty sequence.\n");
        free(bits);
        return 1;
    }

    uint8_t *C = (uint8_t *)calloc(n + 2, sizeof(uint8_t));
    uint8_t *B = (uint8_t *)calloc(n + 2, sizeof(uint8_t));
    uint8_t *T = (uint8_t *)calloc(n + 2, sizeof(uint8_t));
    if (!C || !B || !T) {
        fprintf(stderr, "Out of memory.\n");
        free(bits);
        free(C);
        free(B);
        free(T);
        return 1;
    }

    size_t L = berlekamp_massey(bits, n, C, B, T);

    printf("\nSequence length: %zu\n", n);
    printf("Minimal LFSR length (linear complexity) L = %zu\n\n", L);
    print_connection_polynomial(C, L);
    print_monic_characteristic(C, L);

    free(bits);
    free(C);
    free(B);
    free(T);
    return 0;
}
