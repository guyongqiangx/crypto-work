#include <stdio.h>
#include <stdint.h>

/* Initial Permutation Table */
static uint8_t IP[64] =
{
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7,
};

int main(int argc, char *argv[])
{
    uint8_t i, j;

    uint8_t REVERSE_IP[64];

    for (i=0; i<64; i++)
    {
        j = IP[i]-1;
        REVERSE_IP[j] = i+1;
    }

    printf("Reverse IP Table:\n");
    for (i=0; i<64; i++)
    {
        printf("%2d, ", REVERSE_IP[i]);
        if (i%8==7)
            printf("\n");
    }
    return 0;
}