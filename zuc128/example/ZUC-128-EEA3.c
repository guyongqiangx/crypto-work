typedef unsigned char u8;
typedef unsigned int u32;
/* The ZUC algorithm, see ref. [3]*/
void ZUC(u8 *k, u8 *iv, u32 *ks, int len)
{
    /* The initialization of ZUC, see page 17 of ref. [3]*/
    Initialization(k, iv);
    /* The procedure of generating keystream of ZUC, see page 18 of ref. [3]*/
    GenerateKeystream(ks, len);
}
void EEA3(u8 *CK, u32 COUNT, u32 BEARER, u32 DIRECTION, u32 LENGTH, u32 *M, u32 *C)
{
    u32 *z, L, i;
    u8 IV[16];
    L = (LENGTH + 31) / 32;
    z = (u32 *)malloc(L * sizeof(u32));
    IV[0] = (COUNT >> 24) & 0xFF;
    IV[1] = (COUNT >> 16) & 0xFF;
    IV[2] = (COUNT >> 8) & 0xFF;
    IV[3] = COUNT & 0xFF;
    IV[4] = ((BEARER << 3) | ((DIRECTION & 1) << 2)) & 0xFC;
    IV[5] = 0;
    IV[6] = 0;
    IV[7] = 0;
    IV[8] = IV[0];
    IV[9] = IV[1];
    IV[10] = IV[2];
    IV[11] = IV[3];
    IV[12] = IV[4];
    IV[13] = IV[5];
    IV[14] = IV[6];
    IV[15] = IV[7];
    ZUC(CK, IV, z, L);
    for (i = 0; i < L; i++)
    {
        C[i] = M[i] ^ z[i];
    }
    free(z);
}