#include "des_common.h"

int main(void) {
    uint8_t ddt[8][64][16];
    uint64_t key64 = 0;
    uint64_t subkeys[16];
    char line[256];

    build_ddt_tables(ddt);

    printf("DES differential analysis (Homework 5)\n");
    printf("Part 2: 5-round differential characteristic\n");

    printf("Key (64-bit hex, optional 0x, default 0x133457799BBCDFF1): ");
    if (!fgets(line, sizeof(line), stdin)) {
        fprintf(stderr, "Input error.\n");
        return 1;
    }
    chomp_line(line);
    if (line[0] == '\0') {
        key64 = 0x133457799BBCDFF1ULL;
    } else if (parse_u64_line(line, &key64) != 0) {
        fprintf(stderr, "Invalid key.\n");
        return 1;
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
    (void)fgets(line, sizeof(line), stdin);
    return 0;
}
