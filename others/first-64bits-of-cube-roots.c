#include <math.h>
#include <stdint.h>

/* first 32 bits of the factional parts of the cube roots of the first 64 prime numbers
 * $ gcc first-64bits-of-cube-roots.c -lm -o cube
 * $ ./cube 
 * 0x71374491
 * 0xb5c0fbcf
 * 0xe9b5dba5
 * 0x3956c25b
 * 0x59f111f1
 * 0x923f82a4
 * 0xab1c5ed5
 * 0xd807aa98
 * 0x12835b01
 * 0x243185be
 * 0x550c7dc3
 * 0x72be5d74
 * 0x80deb1fe
 * 0x9bdc06a7
 * 0xc19bf174
 * 0xe49b69c1
 * 0xefbe4786
 * 0x0fc19dc6
 * 0x240ca1cc
 * 0x2de92c6f
 * 0x4a7484aa
 * 0x5cb0a9dc
 * 0x76f988da
 * 0x983e5152
 */
int x[25] =
{
    2, 3, 5, 7, 
    11, 13, 17, 19, 
    23, 29, 
    31, 37, 
    41, 43, 47, 
    53, 59,
    61, 67,
    71, 73, 79, 
    83, 89, 
    97
};

int main() { 
    int i;
    double intpart, fractpart;
    uint64_t t = 1ULL;

    //printf("sizeof(1ULL)=%lu, sizeof(x)=%lu\n", sizeof(1ULL), sizeof(t));
    for (i=1; i<25; i++)
        {
        fractpart = modf(pow(x[i],1/3.0), &intpart);
        //printf("0x%016llx\n", (unsigned long long)(fabs(fractpart * 18446744073709551616ULL)));
        //printf("0x%016llx\n", (unsigned long long)(fabs(fractpart * (t<<63))));
        printf("0x%016llx\n", (unsigned long long)(fabs(fractpart * (t << 63))));

        }
    return 0;
}


