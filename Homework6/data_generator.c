#include <stdio.h>
#include <stdlib.h>
#include <time.h>

const int S1[4][16] = {
    {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
    {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
    {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
    {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
};

unsigned char expand_S1(unsigned int R) {
    unsigned char out = 0;
    out |= ((R >> 31) & 1) << 5;
    out |= ((R >> 30) & 1) << 4;
    out |= ((R >> 29) & 1) << 3;
    out |= ((R >> 28) & 1) << 2;
    out |= ((R >> 27) & 1) << 1;
    out |= ((R >> 26) & 1) << 0;
    return out;
}

unsigned char apply_S1(unsigned char input) {
    int row = ((input >> 5) & 1) << 1 | (input & 1);
    int col = (input >> 1) & 0x0F;
    return S1[row][col];
}

void round_function(unsigned int R, unsigned char subkey, unsigned int *f_out) {
    unsigned char exp = expand_S1(R);
    unsigned char s_in = exp ^ subkey;
    unsigned char s_out = apply_S1(s_in);
    *f_out = ((unsigned int)s_out) << 28; 
}

int main() {
    srand(time(NULL));
    unsigned char REAL_SUBKEY = 0x2A; 
    int PAIR_COUNT = 5000;
    
    unsigned int delta_L0 = 0x90000000;
    unsigned int delta_R0 = 0x00000000;
    
    FILE *fptr = fopen("ciphertext_data.txt", "w");
    if (fptr == NULL) {
        return 1;
    }
    
    for(int i = 0; i < PAIR_COUNT; i++) {
        unsigned int L0 = rand() | (rand() << 16);
        unsigned int R0 = rand() | (rand() << 16);
        
        unsigned int L0_prime = L0 ^ delta_L0;
        unsigned int R0_prime = R0 ^ delta_R0;
        
        unsigned int L = L0, R = R0;
        for(int r = 0; r < 6; r++) {
            unsigned int next_L = R;
            unsigned int f_res = 0;
            unsigned char k = (r == 5) ? REAL_SUBKEY : 0x1F; 
            round_function(R, k, &f_res);
            unsigned int next_R = L ^ f_res;
            L = next_L; R = next_R;
        }
        unsigned int L6 = L;
        unsigned int R6 = R;
        
        L = L0_prime; R = R0_prime;
        for(int r = 0; r < 6; r++) {
            unsigned int next_L = R;
            unsigned int f_res = 0;
            unsigned char k = (r == 5) ? REAL_SUBKEY : 0x1F;
            round_function(R, k, &f_res);
            unsigned int next_R = L ^ f_res;
            L = next_L; R = next_R;
        }
        unsigned int L6_prime = L;
        unsigned int R6_prime = R;
        
        fprintf(fptr, "%08X %08X %08X %08X\n", L6, R6, L6_prime, R6_prime);
    }
    
    fclose(fptr);
    return 0;
}