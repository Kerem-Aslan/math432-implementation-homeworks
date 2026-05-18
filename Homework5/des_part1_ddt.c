#include "des_common.h"

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
    char line[256];

    build_ddt_tables(ddt);

    printf("DES differential analysis (Homework 5)\n");
    printf("Part 1: DES S-box DDTs\n");
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

    printf("\nPress Enter to exit...");
    fflush(stdout);
    (void)fgets(line, sizeof(line), stdin);
    return 0;
}
