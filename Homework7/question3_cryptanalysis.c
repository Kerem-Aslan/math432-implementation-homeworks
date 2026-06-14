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

int count_active_sboxes(uint32_t val) {
  int count = 0;
  for (int box = 0; box < 8; box++) {
    if (((val >> ((7 - box) * 4)) & 0x0F) != 0) {
      count++;
    }
  }
  return count;
}

typedef struct {
  double bias;
  int active_sboxes;
  int round6_active_sboxes;
  uint32_t B[6];
  uint32_t C[5];
  uint64_t ms[5];
  uint32_t ns[5];
} Characteristic;

int main(void) {
  static int lat[8][64][16];
  char line[256];

  build_lat(lat);

  printf("DES Linear Cryptanalysis (Homework 7)\n");
  printf("Question 3: 1-round Linear Cryptanalysis Attack against 6-round "
         "DES\n\n");

  // Generate masks with 1 or 2 active S-boxes (6420 masks total)
  static uint32_t masks[6420];
  int mask_count = 0;

  for (int box = 0; box < 8; box++) {
    for (int ns = 1; ns <= 15; ns++) {
      masks[mask_count++] = ns << ((7 - box) * 4);
    }
  }
  for (int box1 = 0; box1 < 7; box1++) {
    for (int box2 = box1 + 1; box2 < 8; box2++) {
      for (int ns1 = 1; ns1 <= 15; ns1++) {
        for (int ns2 = 1; ns2 <= 15; ns2++) {
          masks[mask_count++] =
              (ns1 << ((7 - box1) * 4)) | (ns2 << ((7 - box2) * 4));
        }
      }
    }
  }

  printf("Searching for optimal 5-round linear characteristic (active in round "
         "6 <= 2)...\n");

  Characteristic best_char = {0};
  best_char.round6_active_sboxes = 999;

  for (int i = 0; i < mask_count; i++) {
    uint32_t ns1 = masks[i];
    uint32_t B_1 = permute_P(ns1);

    double bias1;
    int act1;
    uint64_t ms1 = get_best_Sbox_input_mask(lat, ns1, &bias1, &act1);
    uint32_t C_0 = E_transpose(ms1);

    if (fabs(bias1) < 0.0001)
      continue;

    for (int j = 0; j < mask_count; j++) {
      uint32_t ns2 = masks[j];
      uint32_t B_2 = permute_P(ns2);

      double bias2;
      int act2;
      uint64_t ms2 = get_best_Sbox_input_mask(lat, ns2, &bias2, &act2);
      uint32_t C_1 = E_transpose(ms2);

      double bias12 = 2.0 * bias1 * bias2;
      if (fabs(bias12) < 0.00005)
        continue;

      uint32_t B_3 = B_1 ^ C_1;
      if (B_3 == 0)
        continue;

      uint32_t ns3 = permute_P_inv(B_3);
      double bias3;
      int act3;
      uint64_t ms3 = get_best_Sbox_input_mask(lat, ns3, &bias3, &act3);
      uint32_t C_2 = E_transpose(ms3);

      double bias123 = 2.0 * bias12 * bias3;
      if (fabs(bias123) < 0.00002)
        continue;

      uint32_t B_4 = B_2 ^ C_2;
      if (B_4 == 0)
        continue;

      uint32_t ns4 = permute_P_inv(B_4);
      double bias4;
      int act4;
      uint64_t ms4 = get_best_Sbox_input_mask(lat, ns4, &bias4, &act4);
      uint32_t C_3 = E_transpose(ms4);

      double bias1234 = 2.0 * bias123 * bias4;
      if (fabs(bias1234) < 0.00001)
        continue;

      uint32_t B_5 = B_3 ^ C_3;
      if (B_5 == 0)
        continue;

      uint32_t ns5 = permute_P_inv(B_5);
      double bias5;
      int act5;
      uint64_t ms5 = get_best_Sbox_input_mask(lat, ns5, &bias5, &act5);
      uint32_t C_4 = E_transpose(ms5);

      double total_bias = 2.0 * bias1234 * bias5;

      uint32_t mask_F6 = B_4 ^ C_4;
      uint32_t ns6 = permute_P_inv(mask_F6);
      int act6 = count_active_sboxes(ns6);

      if (act6 <= 2 && fabs(total_bias) > 0.0001) {
        if (act6 < best_char.round6_active_sboxes ||
            (act6 == best_char.round6_active_sboxes &&
             fabs(total_bias) > fabs(best_char.bias))) {
          best_char.bias = total_bias;
          best_char.active_sboxes = act1 + act2 + act3 + act4 + act5;
          best_char.round6_active_sboxes = act6;
          best_char.B[0] = B_2 ^ C_0;
          best_char.B[1] = B_1;
          best_char.B[2] = B_2;
          best_char.B[3] = B_3;
          best_char.B[4] = B_4;
          best_char.B[5] = B_5;
          best_char.C[0] = C_0;
          best_char.C[1] = C_1;
          best_char.C[2] = C_2;
          best_char.C[3] = C_3;
          best_char.C[4] = C_4;
          best_char.ms[0] = ms1;
          best_char.ms[1] = ms2;
          best_char.ms[2] = ms3;
          best_char.ms[3] = ms4;
          best_char.ms[4] = ms5;
          best_char.ns[0] = ns1;
          best_char.ns[1] = ns2;
          best_char.ns[2] = ns3;
          best_char.ns[3] = ns4;
          best_char.ns[4] = ns5;
        }
      }
    }
  }

  if (best_char.round6_active_sboxes == 999) {
    printf("Error: Could not find any valid characteristic.\n");
    return 1;
  }

  printf("\nSelected Characteristic for Attack:\n");
  printf("Theoretical Bias: %+.12f (magnitude: %.12f)\n", best_char.bias,
         fabs(best_char.bias));
  printf("Active S-boxes in Rounds 1-5: %d\n", best_char.active_sboxes);
  printf("Active S-boxes in Round 6    : %d\n\n",
         best_char.round6_active_sboxes);

  uint32_t mask_F6 = best_char.B[4] ^ best_char.C[4];
  uint32_t ns6 = permute_P_inv(mask_F6);

  int box1 = -1, box2 = -1;
  uint8_t ns1_val = 0, ns2_val = 0;

  for (int box = 0; box < 8; box++) {
    uint8_t ns_j = (ns6 >> ((7 - box) * 4)) & 0x0F;
    if (ns_j != 0) {
      printf("Active S-box in Round 6: S%d (Output Mask: 0x%X)\n", box + 1,
             ns_j);
      if (box1 == -1) {
        box1 = box;
        ns1_val = ns_j;
      } else if (box2 == -1) {
        box2 = box;
        ns2_val = ns_j;
      }
    }
  }

  if (box1 == -1 || box2 == -1 || best_char.round6_active_sboxes != 2) {
    printf("Error: Expected exactly 2 active S-boxes in Round 6 for joint "
           "attack.\n");
    return 1;
  }

  printf("\nWe will attack S%d and S%d jointly (12-bit subkey space = 4096 "
         "candidates).\n",
         box1 + 1, box2 + 1);

  // Setup key and subkeys
  uint64_t key64 = 0x133457799BBCDFF1ULL;
  uint64_t subkeys[16];
  generate_subkeys(key64, subkeys);

  printf("Secret Key: 0x%016llX\n", (unsigned long long)key64);

  // Extract the correct subkey bits for box1 and box2 in round 6 (subkey 6 is
  // index 5)
  uint64_t k6 = subkeys[5];
  uint8_t correct_k1 = (uint8_t)((k6 >> ((7 - box1) * 6)) & 0x3F);
  uint8_t correct_k2 = (uint8_t)((k6 >> ((7 - box2) * 6)) & 0x3F);
  uint16_t correct_combined =
      (uint16_t)(((uint16_t)correct_k2 << 6) | correct_k1);

  printf("Correct Subkey for S%d in Round 6: 0x%02X (%d)\n", box1 + 1,
         correct_k1, correct_k1);
  printf("Correct Subkey for S%d in Round 6: 0x%02X (%d)\n", box2 + 1,
         correct_k2, correct_k2);
  printf("Correct Combined Subkey (12-bit):  0x%03X (%d)\n\n", correct_combined,
         correct_combined);

  static uint8_t parity_table1[64];
  static uint8_t parity_table2[64];

  for (int x = 0; x < 64; x++) {
    uint8_t row1 = ((x >> 5) & 1) << 1 | (x & 1);
    uint8_t col1 = (x >> 1) & 0x0F;
    uint8_t s_out1 = DES_S[box1][row1 * 16 + col1];
    parity_table1[x] = parity32(ns1_val & s_out1);

    uint8_t row2 = ((x >> 5) & 1) << 1 | (x & 1);
    uint8_t col2 = (x >> 1) & 0x0F;
    uint8_t s_out2 = DES_S[box2][row2 * 16 + col2];
    parity_table2[x] = parity32(ns2_val & s_out2);
  }

  printf("Number of plaintext-ciphertext pairs to use (default 8000000): ");
  if (!fgets(line, sizeof(line), stdin)) {
    fprintf(stderr, "Input error.\n");
    return 1;
  }
  chomp_line(line);
  size_t pair_count = 8000000;
  if (line[0] != '\0') {
    parse_size_t_line(line, &pair_count);
  }

  printf("Generating %llu pairs and running the joint attack...\n",
         (unsigned long long)pair_count);

  static size_t candidate_votes[4096] = {0};

  uint64_t rng = 0xCAFEBABE12345678ULL;
  xorshift64star_seed(&rng);

  for (size_t i = 0; i < pair_count; i++) {
    uint64_t plaintext = xorshift64star(&rng);
    uint64_t ciphertext = des_encrypt_rounds(plaintext, subkeys, 6);

    // L_0, R_0 from plaintext
    uint64_t ip_plain = permute(plaintext, DES_IP, 64, 64);
    uint32_t L_0 = (uint32_t)(ip_plain >> 32);
    uint32_t R_0 = (uint32_t)(ip_plain & 0xFFFFFFFFULL);

    // L_6, R_6 from ciphertext
    uint64_t preoutput = permute(ciphertext, DES_IP, 64, 64);
    uint32_t R_6 = (uint32_t)(preoutput >> 32);
    uint32_t L_6 = (uint32_t)(preoutput & 0xFFFFFFFFULL);

    // Compute fixed bits of the relationship
    int fixed_bits = parity32(best_char.B[1] & L_0) ^
                     parity32(best_char.B[0] & R_0) ^ parity32(mask_F6 & R_6) ^
                     parity32(best_char.B[5] & L_6);

    // S-box inputs in round 6
    uint64_t expanded = permute((uint64_t)L_6, DES_E, 48, 32);
    uint8_t s_in1 = (uint8_t)((expanded >> ((7 - box1) * 6)) & 0x3FU);
    uint8_t s_in2 = (uint8_t)((expanded >> ((7 - box2) * 6)) & 0x3FU);

    // Guess the combined 12-bit subkey (highly optimized loop)
    for (int guess = 0; guess < 4096; guess++) {
      uint8_t guess1 = guess & 0x3F;
      uint8_t guess2 = guess >> 6;

      int val = fixed_bits ^ parity_table1[s_in1 ^ guess1] ^
                parity_table2[s_in2 ^ guess2];

      if (val == 0) {
        candidate_votes[guess]++;
      }
    }
  }

  // Rank candidates by their absolute bias
  typedef struct {
    int key_guess;
    double bias;
    size_t votes;
  } Candidate;

  static Candidate candidates[4096];
  for (int g = 0; g < 4096; g++) {
    candidates[g].key_guess = g;
    candidates[g].votes = candidate_votes[g];
    candidates[g].bias =
        ((double)candidate_votes[g] - (double)pair_count / 2.0) /
        (double)pair_count;
  }

  for (int i = 0; i < 20; i++) {
    int max_idx = i;
    for (int j = i + 1; j < 4096; j++) {
      if (fabs(candidates[j].bias) > fabs(candidates[max_idx].bias)) {
        max_idx = j;
      }
    }
    if (max_idx != i) {
      Candidate temp = candidates[i];
      candidates[i] = candidates[max_idx];
      candidates[max_idx] = temp;
    }
  }

  // Find the rank of the correct subkey
  int correct_rank = -1;
  for (int r = 0; r < 4096; r++) {
    if (candidates[r].key_guess == correct_combined) {
      correct_rank = r + 1;
      break;
    }
  }

  printf("\nTop 15 Subkey Candidates:\n");
  printf("%4s | %10s | %10s | %10s | %10s | %14s | %s\n", "Rank", "Joint Hex",
         "Sub1 (S3)", "Sub2 (S7)", "Votes", "Observed Bias", "Status");
  printf("---------------------------------------------------------------------"
         "------------------\n");

  for (int r = 0; r < 15; r++) {
    uint8_t k1_guess = candidates[r].key_guess & 0x3F;
    uint8_t k2_guess = candidates[r].key_guess >> 6;
    int is_correct = (candidates[r].key_guess == correct_combined);
    printf("%4d |      0x%03X |       0x%02X |       0x%02X | %10llu | %+14.6f "
           "| %s\n",
           r + 1, candidates[r].key_guess, k1_guess, k2_guess,
           (unsigned long long)candidates[r].votes, candidates[r].bias,
           is_correct ? "CORRECT SUBKEY" : "");
  }

  // Print correct subkey if it was not in the top 15
  if (correct_rank > 15) {
    // Find it in the array
    for (int r = 15; r < 4096; r++) {
      if (candidates[r].key_guess == correct_combined) {
        uint8_t k1_guess = candidates[r].key_guess & 0x3F;
        uint8_t k2_guess = candidates[r].key_guess >> 6;
        printf("...\n");
        printf("%4d |      0x%03X |       0x%02X |       0x%02X | %10llu | "
               "%+14.6f | %s\n",
               correct_rank, candidates[r].key_guess, k1_guess, k2_guess,
               (unsigned long long)candidates[r].votes, candidates[r].bias,
               "CORRECT SUBKEY");
        break;
      }
    }
  }

  printf("\nAttack Result:\n");
  if (correct_rank == 1) {
    printf("SUCCESS: The correct 12-bit subkey 0x%03X was successfully "
           "recovered at Rank 1!\n",
           correct_combined);
  } else if (correct_rank <= 10) {
    printf("SUCCESS: The correct 12-bit subkey 0x%03X was recovered within the "
           "top 10 (Rank %d).\n",
           correct_combined, correct_rank);
  } else {
    printf("FAILURE: The correct 12-bit subkey 0x%03X was ranked %d. More "
           "plaintexts may be needed.\n",
           correct_combined, correct_rank);
  }

  printf("\nPress Enter to exit...");
  fflush(stdout);
  (void)fgets(line, sizeof(line), stdin);
  return 0;
}
