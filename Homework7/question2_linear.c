#include "des_common.h"
#include <math.h>

void build_lat(int lat[8][64][16]) {
  for (int box = 0; box < 8; box++) {
    for (int a = 0; a < 64; a++) {
      for (int b = 0; b < 16; b++) {
        int matches = 0;
        for (int x = 0; x < 64; x++) {
          int row = ((x >> 5) & 1) << 1 | (x & 1);
          int col = (x >> 1) & 0x0F;
          int y = DES_S[box][row * 16 + col];

          int val = parity32(a & x) ^ parity32(b & y);
          if (val == 0) {
            matches++;
          }
        }
        lat[box][a][b] = matches - 32;
      }
    }
  }
}

uint32_t permute_P(uint32_t val) {
  uint32_t out = 0;
  for (int i = 0; i < 32; i++) {
    int pos = DES_P[i] - 1;
    uint32_t bit = (val >> (31 - pos)) & 1;
    out |= bit << (31 - i);
  }
  return out;
}

uint32_t permute_P_inv(uint32_t val) {
  uint32_t out = 0;
  for (int i = 0; i < 32; i++) {
    uint32_t bit = (val >> (31 - i)) & 1;
    int pos = DES_P[i] - 1;
    out |= bit << (31 - pos);
  }
  return out;
}

uint32_t E_transpose(uint64_t MS) {
  uint32_t C = 0;
  for (int k = 0; k < 48; k++) {
    uint32_t bit = (uint32_t)((MS >> (47 - k)) & 1);
    int pos = DES_E[k] - 1;
    C ^= bit << (31 - pos);
  }
  return C;
}

uint64_t get_best_Sbox_input_mask(int lat[8][64][16], uint32_t ns_32,
                                  double *bias_out, int *active_count) {
  uint64_t ms_48 = 0;
  double total_bias_num = 1.0;
  int act = 0;

  for (int box = 0; box < 8; box++) {
    uint8_t ns_j = (ns_32 >> ((7 - box) * 4)) & 0x0F;
    if (ns_j == 0) {
      continue;
    }

    act++;
    int best_ms = 0;
    int best_lat_abs = 0;
    int best_lat_val = 0;

    for (int ms = 1; ms < 64; ms++) {
      int val = lat[box][ms][ns_j];
      if (abs(val) > best_lat_abs) {
        best_lat_abs = abs(val);
        best_lat_val = val;
        best_ms = ms;
      }
    }

    total_bias_num *= ((double)best_lat_val / 32.0);
    ms_48 |= ((uint64_t)best_ms) << ((7 - box) * 6);
  }

  *bias_out = total_bias_num / 2.0;
  *active_count = act;
  return ms_48;
}

int main(void) {
  int lat[8][64][16];
  char line[256];

  build_lat(lat);

  printf("DES Linear Cryptanalysis (Homework 7)\n");
  printf("Question 2: 5-round Linear Characteristic & Bias Estimation\n\n");

  uint32_t single_sbox_masks[120];
  int idx = 0;
  for (int box = 0; box < 8; box++) {
    for (int ns = 1; ns <= 15; ns++) {
      single_sbox_masks[idx++] = ns << ((7 - box) * 4);
    }
  }

  printf("Searching for best 5-round linear characteristic (active in every "
         "round)...\n");

  double best_bias = 0.0;
  uint32_t best_B[6] = {0};
  uint32_t best_C[5] = {0};
  uint64_t best_ms[5] = {0};
  uint32_t best_ns[5] = {0};
  int best_active_count = 999;

  for (int i = 0; i < 120; i++) {
    uint32_t ns1 = single_sbox_masks[i];
    uint32_t B_1 = permute_P(ns1);

    double bias1;
    int act1;
    uint64_t ms1 = get_best_Sbox_input_mask(lat, ns1, &bias1, &act1);
    uint32_t C_0 = E_transpose(ms1);

    for (int j = 0; j < 120; j++) {
      uint32_t ns2 = single_sbox_masks[j];
      uint32_t B_2 = permute_P(ns2);

      double bias2;
      int act2;
      uint64_t ms2 = get_best_Sbox_input_mask(lat, ns2, &bias2, &act2);
      uint32_t C_1 = E_transpose(ms2);

      uint32_t B_3 = B_1 ^ C_1;
      if (B_3 == 0)
        continue;

      uint32_t ns3 = permute_P_inv(B_3);
      double bias3;
      int act3;
      uint64_t ms3 = get_best_Sbox_input_mask(lat, ns3, &bias3, &act3);
      uint32_t C_2 = E_transpose(ms3);

      uint32_t B_4 = B_2 ^ C_2;
      if (B_4 == 0)
        continue;

      uint32_t ns4 = permute_P_inv(B_4);
      double bias4;
      int act4;
      uint64_t ms4 = get_best_Sbox_input_mask(lat, ns4, &bias4, &act4);
      uint32_t C_3 = E_transpose(ms4);

      uint32_t B_5 = B_3 ^ C_3;
      if (B_5 == 0)
        continue;

      uint32_t ns5 = permute_P_inv(B_5);
      double bias5;
      int act5;
      uint64_t ms5 = get_best_Sbox_input_mask(lat, ns5, &bias5, &act5);
      uint32_t C_4 = E_transpose(ms5);

      double total_bias = 16.0 * bias1 * bias2 * bias3 * bias4 * bias5;
      int total_act = act1 + act2 + act3 + act4 + act5;

      if (fabs(total_bias) > fabs(best_bias) ||
          (fabs(total_bias) == fabs(best_bias) &&
           total_act < best_active_count)) {
        best_bias = total_bias;
        best_active_count = total_act;
        best_B[0] = B_2 ^ C_0; // B_0
        best_B[1] = B_1;
        best_B[2] = B_2;
        best_B[3] = B_3;
        best_B[4] = B_4;
        best_B[5] = B_5;
        best_C[0] = C_0;
        best_C[1] = C_1;
        best_C[2] = C_2;
        best_C[3] = C_3;
        best_C[4] = C_4;
        best_ms[0] = ms1;
        best_ms[1] = ms2;
        best_ms[2] = ms3;
        best_ms[3] = ms4;
        best_ms[4] = ms5;
        best_ns[0] = ns1;
        best_ns[1] = ns2;
        best_ns[2] = ns3;
        best_ns[3] = ns4;
        best_ns[4] = ns5;
      }
    }
  }

  if (best_active_count == 999) {
    printf("Error: Could not find any valid 5-round linear characteristic.\n");
    return 1;
  }

  printf("\nBest 5-Round Linear Characteristic Found:\n");
  printf("Theoretical Bias: %+.12f (magnitude: %.12f)\n", best_bias,
         fabs(best_bias));
  printf("Total Active S-boxes: %d (exactly 1 active S-box per round)\n\n",
         best_active_count);

  for (int r = 0; r < 5; r++) {
    printf("Round %d:\n", r + 1);
    printf("  Input Mask C_%d      : 0x%08X\n", r, best_C[r]);
    printf("  Output Mask B_%d     : 0x%08X\n", r + 1, best_B[r + 1]);
    printf("  S-box Out Mask NS_%d : 0x%08X\n", r + 1, best_ns[r]);
    printf("  S-box In Mask MS_%d  : 0x%012llX\n", r,
           (unsigned long long)best_ms[r]);

    // Find which Sbox is active
    for (int box = 0; box < 8; box++) {
      uint8_t ns_j = (best_ns[r] >> ((7 - box) * 4)) & 0x0F;
      if (ns_j != 0) {
        uint8_t ms_j = (best_ms[r] >> ((7 - box) * 6)) & 0x3F;
        printf("  Active S-box       : S%d (Input Mask: 0x%02X -> Output Mask: "
               "0x%X, LAT entry: %d)\n",
               box + 1, ms_j, ns_j, lat[box][ms_j][ns_j]);
      }
    }
    printf("\n");
  }

  printf("Linear Characteristic Relation:\n");
  printf(
      "  B_1 . L_0 ^ B_0 . R_0 ^ (B_4 ^ C_4) . L_5 ^ B_5 . R_5 = Key_bits\n");
  printf("  Masks:\n");
  printf("    L_0 mask (B_1)        : 0x%08X\n", best_B[1]);
  printf("    R_0 mask (B_0)        : 0x%08X\n", best_B[0]);
  printf("    L_5 mask (B_4 ^ C_4)  : 0x%08X\n", best_B[4] ^ best_C[4]);
  printf("    R_5 mask (B_5)        : 0x%08X\n", best_B[5]);

  // Setup key and subkeys
  uint64_t key64 = 0x133457799BBCDFF1ULL;
  uint64_t subkeys[16];
  generate_subkeys(key64, subkeys);

  printf("\nKey to encrypt with: 0x%016llX\n", (unsigned long long)key64);

  // Run experiment for different sample sizes
  size_t test_sizes[] = {1000, 10000, 100000, 1000000};
  int num_tests = sizeof(test_sizes) / sizeof(test_sizes[0]);

  printf(
      "\nRunning experimental verification over different sample sizes...\n");
  printf("%10s | %10s | %14s | %14s | %12s\n", "Pairs (N)", "Matches",
         "Empirical Bias", "Theory Bias", "Difference");
  printf("---------------------------------------------------------------------"
         "---\n");

  uint64_t rng = 0x9E3779B97F4A7C15ULL;
  xorshift64star_seed(&rng);

  for (int t = 0; t < num_tests; t++) {
    size_t N = test_sizes[t];
    size_t matches = 0;

    for (size_t i = 0; i < N; i++) {
      uint64_t plaintext = xorshift64star(&rng);
      uint64_t ciphertext = des_encrypt_rounds(plaintext, subkeys, 5);

      uint64_t ip_plain = permute(plaintext, DES_IP, 64, 64);
      uint32_t L_0 = (uint32_t)(ip_plain >> 32);
      uint32_t R_0 = (uint32_t)(ip_plain & 0xFFFFFFFFULL);

      uint64_t preoutput = permute(ciphertext, DES_IP, 64, 64);
      uint32_t R_5 = (uint32_t)(preoutput >> 32);
      uint32_t L_5 = (uint32_t)(preoutput & 0xFFFFFFFFULL);

      int val = parity32(best_B[1] & L_0) ^ parity32(best_B[0] & R_0) ^
                parity32((best_B[4] ^ best_C[4]) & L_5) ^
                parity32(best_B[5] & R_5);

      if (val == 0) {
        matches++;
      }
    }

    double emp_bias = ((double)matches - (double)N / 2.0) / (double)N;
    double abs_emp_bias = fabs(emp_bias);
    double abs_theory_bias = fabs(best_bias);
    double diff = fabs(abs_emp_bias - abs_theory_bias);

    printf("%10llu | %10llu | %14.6f | %14.6f | %12.6f\n",
           (unsigned long long)N, (unsigned long long)matches, emp_bias,
           best_bias, diff);
  }

  printf("\nPress Enter to exit...");
  fflush(stdout);
  (void)fgets(line, sizeof(line), stdin);
  return 0;
}
