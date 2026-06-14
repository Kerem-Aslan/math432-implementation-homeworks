#include "des_common.h"

static int prompt_yes_no(const char *prompt) {
  char line[32];
  printf("%s", prompt);
  if (!fgets(line, sizeof(line), stdin)) {
    return 0;
  }
  return line[0] == 'y' || line[0] == 'Y';
}

void build_lat(int sbox_idx, int lat[64][16]) {
  for (int a = 0; a < 64; a++) {
    for (int b = 0; b < 16; b++) {
      int matches = 0;
      for (int x = 0; x < 64; x++) {
        int row = ((x >> 5) & 1) << 1 | (x & 1);
        int col = (x >> 1) & 0x0F;
        int y = DES_S[sbox_idx][row * 16 + col];

        int val = parity32(a & x) ^ parity32(b & y);
        if (val == 0) {
          matches++;
        }
      }
      lat[a][b] = matches - 32;
    }
  }
}

void print_lat_report(FILE *out, int sbox_idx, int lat[64][16]) {
  fprintf(out, "\nDES S-box %d Linear Approximation Table (LAT)\n",
          sbox_idx + 1);
  fprintf(
      out,
      "Values represent (Number of Matches - 32), ranging from -32 to +32.\n");
  fprintf(out, "Rows = Input Masks (0x00 to 0x3F), Columns = Output Masks (0x0 "
               "to 0xF).\n\n");

  fprintf(out, "      ");
  for (int b = 0; b < 16; b++) {
    fprintf(out, "%4X", b);
  }
  fprintf(out, "   | Max Bias\n");
  fprintf(out, "-----");
  for (int b = 0; b < 16; b++) {
    fprintf(out, "----");
  }
  fprintf(out, "---------------\n");

  int max_abs_val = 0;
  int max_row = 0;
  int max_col = 0;

  for (int a = 0; a < 64; a++) {
    fprintf(out, "0x%02X : ", a);
    int best_b_row = 0;
    int best_val_row = 0;
    for (int b = 0; b < 16; b++) {
      int val = lat[a][b];
      fprintf(out, "%4d", val);

      if (a != 0 || b != 0) {
        if (abs(val) > max_abs_val) {
          max_abs_val = abs(val);
          max_row = a;
          max_col = b;
        }
      }

      if (abs(val) > abs(best_val_row)) {
        best_val_row = val;
        best_b_row = b;
      }
    }
    fprintf(out, "   | 0x%X (%+d/64)\n", best_b_row, best_val_row);
  }

  fprintf(out, "\nMax linear approximation (excluding 0->0):\n");
  fprintf(out, "Input mask  (alpha): 0x%02X\n", max_row);
  fprintf(out, "Output mask (beta) : 0x%X\n", max_col);
  fprintf(out, "LAT entry          : %d\n", lat[max_row][max_col]);
  fprintf(out, "Probability        : %d/64 = %.4f\n",
          32 + lat[max_row][max_col],
          (double)(32 + lat[max_row][max_col]) / 64.0);
  fprintf(out, "Linear Bias        : %+d/64 = %.4f\n", lat[max_row][max_col],
          (double)lat[max_row][max_col] / 64.0);
}

int main(void) {
  char line[256];
  int sbox_num = 0;
  int lat[64][16];

  printf("DES Linear Cryptanalysis (Homework 7)\n");
  printf("Question 1: DES S-box LAT Computation\n\n");

  while (1) {
    printf("Enter S-box number to analyze (1-8): ");
    if (!fgets(line, sizeof(line), stdin)) {
      fprintf(stderr, "Input error.\n");
      return 1;
    }
    chomp_line(line);
    sbox_num = atoi(line);
    if (sbox_num >= 1 && sbox_num <= 8) {
      break;
    }
    printf("Invalid choice. Please enter a number between 1 and 8.\n");
  }

  int sbox_idx = sbox_num - 1;
  build_lat(sbox_idx, lat);
  print_lat_report(stdout, sbox_idx, lat);

  if (prompt_yes_no(
          "\nWrite the same output to sbox_lat.txt as well? (y/n): ")) {
    FILE *txt = fopen("sbox_lat.txt", "w");
    if (!txt) {
      fprintf(stderr, "Could not create sbox_lat.txt.\n");
      return 1;
    }
    print_lat_report(txt, sbox_idx, lat);
    fclose(txt);
    printf("Saved to sbox_lat.txt\n");
  }

  printf("\nPress Enter to exit...");
  fflush(stdout);
  (void)fgets(line, sizeof(line), stdin);
  return 0;
}
