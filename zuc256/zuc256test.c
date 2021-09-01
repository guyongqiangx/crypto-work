/*
 * @        file: zuctest.c
 * @ description: test tool for zuc
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>  /* printf, fopen, fread, fclose... */
#include <stdlib.h> /* exit */
#include <string.h> /* strlen */
#include <unistd.h> /* getopt */

#include "zuc256.h"

static void TestingZUC(uint8_t *key, uint8_t *iv, uint32_t len)
{
    int i;
    ZUC256_CTX ctx;

    uint32_t *z;

    z = (uint32_t *)malloc(len * sizeof(uint32_t));

    ZUC256_Init(&ctx, key, iv);
    printf("R1=0x%08x, R2=0x%08x\n", ctx.R1, ctx.R2);
    for (i=0; i<16; i++)
    {
        printf("s[%2d]=0x%08x\n", i, ctx.s[i]);
    }
    ZUC256_GenerateKeyStream(&ctx, z, len);
    printf("out stream: \n");
    for (i=0; i<len; i++)
    {
        printf("0x%08x ", z[i]);
        if (i%8 == 7)
        {
            printf("\n");
        }
    }
    printf("\n\n");

    free(z);
    z = NULL;
}

static void ZUCTests(void)
{
    /* 测试向量1(全0) */
    uint8_t key1[32] =
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    uint8_t iv1[25] =
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /*  0~15 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00                                            /* 16~24 */
    };

    /* 测试向量2(全1) */
    uint8_t key2[32] =
    {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    uint8_t iv2[25] =
    {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /*  0~15 */
        0xff, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f                                            /* 16~24 */
    };

    printf("Test All 0...\n");
    TestingZUC(key1, iv1, 20);

    printf("Test All 1...\n");
    TestingZUC(key2, iv2, 20);
}

#if 0
static void TestingEEA3(uint8_t *ck, uint32_t count, uint32_t bearer, uint32_t direction, uint32_t length, uint32_t *ibs)
{
    int i;
    uint32_t *obs, size;

    size = (length + 31) / 32;
    obs = (uint32_t *)malloc(size * 4);
    memset(obs, 0, size * 4);

    EEA3(ck, count, bearer, direction, length, ibs, obs);

    printf("Input Bit Stream:\n");
    for (i=0; i<size; i++)
    {
        printf("0x%08x ", ibs[i]);
        if (i%8 == 7)
        {
            printf("\n");
        }
    }
    printf("\n");
    printf("Output Bit Stream:\n");
    for (i=0; i<size; i++)
    {
        printf("0x%08x ", obs[i]);
        if (i%8 == 7)
        {
            printf("\n");
        }
    }
    printf("\n");
    free(obs);
    obs = NULL;
}

static void EEA3Tests(void)
{
    {
        /* 附录A. 第一组加密实例 */
        uint8_t ck[16] =
        {
            0x17, 0x3d, 0x14, 0xba, 0x50, 0x03, 0x73, 0x1d, 0x7a, 0x60, 0x04, 0x94, 0x70, 0xf0, 0x0a, 0x29
        };
        uint32_t ibs[] = {
            0x6cf65340, 0x735552ab, 0x0c9752fa, 0x6f9025fe, 0x0bd675d9, 0x005875b2, 0x00000000
        };
        uint32_t     count = 0x66035492;
        uint32_t    bearer = 0x0f;
        uint32_t direction = 0;
        uint32_t    length = 0xc1; /* 193 bits */

        printf("Test Set 1:\n");
        TestingEEA3(ck, count, bearer, direction, length, ibs);
    }

    {
        /* 附录A. 第二组加密实例 */
        uint8_t ck[16] =
        {
            0xe5, 0xbd, 0x3e, 0xa0, 0xeb, 0x55, 0xad, 0xe8, 0x66, 0xc6, 0xac, 0x58, 0xbd, 0x54, 0x30, 0x2a
        };
        uint32_t ibs[] = {
            0x14a8ef69, 0x3d678507, 0xbbe7270a, 0x7f67ff50, 0x06c3525b, 0x9807e467, 0xc4e56000, 0xba338f5d,
            0x42955903, 0x67518222, 0x46c80d3b, 0x38f07f4b, 0xe2d8ff58, 0x05f51322, 0x29bde93b, 0xbbdcaf38,
            0x2bf1ee97, 0x2fbf9977, 0xbada8945, 0x847a2a6c, 0x9ad34a66, 0x7554e04d, 0x1f7fa2c3, 0x3241bd8f,
            0x01ba220d
        };
        uint32_t     count = 0x56823;
        uint32_t    bearer = 0x18;
        uint32_t direction = 0x1;
        uint32_t    length = 0x320; /* 800 bits */

        printf("Test Set 2:\n");
        TestingEEA3(ck, count, bearer, direction, length, ibs);
    }

    {
        /* Test Set 3 */
        uint8_t ck[16] =
        {
            0xd4, 0x55, 0x2a, 0x8f, 0xd6, 0xe6, 0x1c, 0xc8, 0x1a, 0x20, 0x09, 0x14, 0x1a, 0x29, 0xc1, 0x0b
        };
        uint32_t ibs[] = {
            0x38f07f4b, 0xe2d8ff58, 0x05f51322, 0x29bde93b, 0xbbdcaf38, 0x2bf1ee97, 0x2fbf9977, 0xbada8945,
            0x847a2a6c, 0x9ad34a66, 0x7554e04d, 0x1f7fa2c3, 0x3241bd8f, 0x01ba220d, 0x3ca4ec41, 0xe074595f,
            0x54ae2b45, 0x4fd97143, 0x20436019, 0x65cca85c, 0x2417ed6c, 0xbec3bada, 0x84fc8a57, 0x9aea7837,
            0xb0271177, 0x242a64dc, 0x0a9de71a, 0x8edee86c, 0xa3d47d03, 0x3d6bf539, 0x804eca86, 0xc584a905,
            0x2de46ad3, 0xfced6554, 0x3bd90207, 0x372b27af, 0xb79234f5, 0xff43ea87, 0x0820e2c2, 0xb78a8aae,
            0x61cce52a, 0x0515e348, 0xd196664a, 0x3456b182, 0xa07c406e, 0x4a207912, 0x71cfeda1, 0x65d535ec,
            0x5ea2d4df, 0x40000000,
        };
        uint32_t     count = 0x76452ec1;
        uint32_t    bearer = 0x02;
        uint32_t direction = 0x1;
        uint32_t    length = 1570;

        printf("Test Set 3:\n");
        TestingEEA3(ck, count, bearer, direction, length, ibs);
    }

    {
        /* Test Set 4 */
        uint8_t ck[16] =
        {
            0xdb, 0x84, 0xb4, 0xfb, 0xcc, 0xda, 0x56, 0x3b, 0x66, 0x22, 0x7b, 0xfe, 0x45, 0x6f, 0x0f, 0x77
        };
        uint32_t ibs[] = {
            0xe539f3b8, 0x973240da, 0x03f2b8aa, 0x05ee0a00, 0xdbafc0e1, 0x82055dfe, 0x3d7383d9, 0x2cef40e9,
            0x2928605d, 0x52d05f4f, 0x9018a1f1, 0x89ae3997, 0xce19155f, 0xb1221db8, 0xbb0951a8, 0x53ad852c,
            0xe16cff07, 0x382c93a1, 0x57de00dd, 0xb125c753, 0x9fd85045, 0xe4ee07e0, 0xc43f9e9d, 0x6f414fc4,
            0xd1c62917, 0x813f74c0, 0x0fc83f3e, 0x2ed7c45b, 0xa5835264, 0xb43e0b20, 0xafda6b30, 0x53bfb642,
            0x3b7fce25, 0x479ff5f1, 0x39dd9b5b, 0x995558e2, 0xa56be18d, 0xd581cd01, 0x7c735e6f, 0x0d0d97c4,
            0xddc1d1da, 0x70c6db4a, 0x12cc9277, 0x8e2fbbd6, 0xf3ba52af, 0x91c9c6b6, 0x4e8da4f7, 0xa2c266d0,
            0x2d001753, 0xdf089603, 0x93c5d568, 0x88bf49eb, 0x5c16d9a8, 0x0427a416, 0xbcb597df, 0x5bfe6f13,
            0x890a07ee, 0x1340e647, 0x6b0d9aa8, 0xf822ab0f, 0xd1ab0d20, 0x4f40b7ce, 0x6f2e136e, 0xb67485e5,
            0x07804d50, 0x4588ad37, 0xffd81656, 0x8b2dc403, 0x11dfb654, 0xcdead47e, 0x2385c343, 0x6203dd83,
            0x6f9c64d9, 0x7462ad5d, 0xfa63b5cf, 0xe08acb95, 0x32866f5c, 0xa787566f, 0xca93e6b1, 0x693ee15c,
            0xf6f7a2d6, 0x89d97417, 0x98dc1c23, 0x8e1be650, 0x733b18fb, 0x34ff880e, 0x16bbd21b, 0x47ac0000,
        };
        uint32_t     count = 0xe4850fe1;
        uint32_t    bearer = 0x10;
        uint32_t direction = 0x1;
        uint32_t    length = 2798;

        printf("Test Set 4:\n");
        TestingEEA3(ck, count, bearer, direction, length, ibs);
    }

    {
        /* Test Set 5 */
        uint8_t ck[16] =
        {
            0xe1, 0x3f, 0xed, 0x21, 0xb4, 0x6e, 0x4e, 0x7e, 0xc3, 0x12, 0x53, 0xb2, 0xbb, 0x17, 0xb3, 0xe0
        };
        uint32_t ibs[] = {
            0x8d74e20d, 0x54894e06, 0xd3cb13cb, 0x3933065e, 0x8674be62, 0xadb1c72b, 0x3a646965, 0xab63cb7b,
            0x7854dfdc, 0x27e84929, 0xf49c64b8, 0x72a490b1, 0x3f957b64, 0x827e71f4, 0x1fbd4269, 0xa42c97f8,
            0x24537027, 0xf86e9f4a, 0xd82d1df4, 0x51690fdd, 0x98b6d03f, 0x3a0ebe3a, 0x312d6b84, 0x0ba5a182,
            0x0b2a2c97, 0x09c090d2, 0x45ed267c, 0xf845ae41, 0xfa975d33, 0x33ac3009, 0xfd40eba9, 0xeb5b8857,
            0x14b768b6, 0x97138baf, 0x21380eca, 0x49f644d4, 0x8689e421, 0x5760b906, 0x739f0d2b, 0x3f091133,
            0xca15d981, 0xcbe401ba, 0xf72d05ac, 0xe05cccb2, 0xd297f4ef, 0x6a5f58d9, 0x1246cfa7, 0x7215b892,
            0xab441d52, 0x78452795, 0xccb7f5d7, 0x9057a1c4, 0xf77f80d4, 0x6db2033c, 0xb79bedf8, 0xe60551ce,
            0x10c667f6, 0x2a97abaf, 0xabbcd677, 0x2018df96, 0xa282ea73, 0x7ce2cb33, 0x1211f60d, 0x5354ce78,
            0xf9918d9c, 0x206ca042, 0xc9b62387, 0xdd709604, 0xa50af16d, 0x8d35a890, 0x6be484cf, 0x2e74a928,
            0x99403643, 0x53249b27, 0xb4c9ae29, 0xeddfc7da, 0x6418791a, 0x4e7baa06, 0x60fa6451, 0x1f2d685c,
            0xc3a5ff70, 0xe0d2b742, 0x92e3b8a0, 0xcd6b04b1, 0xc790b8ea, 0xd2703708, 0x540dea2f, 0xc09c3da7,
            0x70f65449, 0xe84d817a, 0x4f551055, 0xe19ab850, 0x18a0028b, 0x71a144d9, 0x6791e9a3, 0x57793350,
            0x4eee0060, 0x340c69d2, 0x74e1bf9d, 0x805dcbcc, 0x1a6faa97, 0x6800b6ff, 0x2b671dc4, 0x63652fa8,
            0xa33ee509, 0x74c1c21b, 0xe01eabb2, 0x16743026, 0x9d72ee51, 0x1c9dde30, 0x797c9a25, 0xd86ce74f,
            0x5b961be5, 0xfdfb6807, 0x814039e7, 0x137636bd, 0x1d7fa9e0, 0x9efd2007, 0x505906a5, 0xac45dfde,
            0xed7757bb, 0xee745749, 0xc2963335, 0x0bee0ea6, 0xf409df45, 0x80160000,
        };
        uint32_t     count = 0x2738cdaa;
        uint32_t    bearer = 0x1a;
        uint32_t direction = 0x0;
        uint32_t    length = 4019;

        printf("Test Set 5:\n");
        TestingEEA3(ck, count, bearer, direction, length, ibs);
    }

}

// static void TestingEEA3(uint8_t *ck, uint32_t count, uint32_t bearer, uint32_t direction, uint32_t length, uint32_t *ibs)
static void TestingEIA3(uint8_t *ik, uint32_t count, uint32_t bearer, uint32_t direction, uint32_t length, uint32_t *m)
{
    int i;
    uint32_t size, mac;

    EIA3(ik, count, bearer, direction, length, m, &mac);

    size = (length + 31) / 32;
    printf("Input Bit Stream:\n");
    for (i=0; i<size; i++)
    {
        printf("0x%08x ", m[i]);
        if (i%8 == 7)
        {
            printf("\n");
        }
    }
    printf("\n");
    printf("Output MAC: 0x%08x\n", mac);
}

static void EIA3Tests(void)
{
    {
        /* Test Set 1 */
        uint8_t ik[16] =
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        uint32_t m[] = {
            0x00000000,
        };
        uint32_t     count = 0x00;
        uint32_t    bearer = 0x00;
        uint32_t direction = 0x0;
        uint32_t    length = 0x01; /* 1 bits */

        printf("EIA3 Test Set 1:\n");
        TestingEIA3(ik, count, bearer, direction, length, m);
        printf("\n");
    }

    {
        /* Test Set 2 */
        uint8_t ik[16] =
        {
            0x47, 0x05, 0x41, 0x25, 0x56, 0x1e, 0xb2, 0xdd, 0xa9, 0x40, 0x59, 0xda, 0x05, 0x09, 0x78, 0x50
        };
        uint32_t m[] = {
            0x00000000, 0x00000000, 0x00000000,
        };
        uint32_t     count = 0x561eb2dd;
        uint32_t    bearer = 0x14;
        uint32_t direction = 0x0;
        uint32_t    length = 90; /* 90 bits */

        printf("EIA3 Test Set 2:\n");
        TestingEIA3(ik, count, bearer, direction, length, m);
        printf("\n");
    }

    {
        /* Test Set 3 */
        uint8_t ik[16] =
        {
            0xc9, 0xe6, 0xce, 0xc4, 0x60, 0x7c, 0x72, 0xdb, 0x00, 0x0a, 0xef, 0xa8, 0x83, 0x85, 0xab, 0x0a
        };
        uint32_t m[] = {
            0x983b41d4, 0x7d780c9e, 0x1ad11d7e, 0xb70391b1, 0xde0b35da, 0x2dc62f83, 0xe7b78d63, 0x06ca0ea0,
            0x7e941b7b, 0xe91348f9, 0xfcb170e2, 0x217fecd9, 0x7f9f68ad, 0xb16e5d7d, 0x21e569d2, 0x80ed775c,
            0xebde3f40, 0x93c53881, 0x00000000
        };
        uint32_t     count = 0xa94059da;
        uint32_t    bearer = 0x0a;
        uint32_t direction = 0x1;
        uint32_t    length = 577; /* 577 bits */

        printf("EIA3 Test Set 3:\n");
        TestingEIA3(ik, count, bearer, direction, length, m);
        printf("\n");
    }

    {
        /* Test Set 4 */
        uint8_t ik[16] =
        {
            0xc8, 0xa4, 0x82, 0x62, 0xd0, 0xc2, 0xe2, 0xba, 0xc4, 0xb9, 0x6e, 0xf7, 0x7e, 0x80, 0xca, 0x59
        };
        uint32_t m[] = {
            0xb546430b, 0xf87b4f1e, 0xe834704c, 0xd6951c36, 0xe26f108c, 0xf731788f, 0x48dc34f1, 0x678c0522,
            0x1c8fa7ff, 0x2f39f477, 0xe7e49ef6, 0x0a4ec2c3, 0xde24312a, 0x96aa26e1, 0xcfba5756, 0x3838b297,
            0xf47e8510, 0xc779fd66, 0x54b14338, 0x6fa639d3, 0x1edbd6c0, 0x6e47d159, 0xd94362f2, 0x6aeeedee,
            0x0e4f49d9, 0xbf841299, 0x5415bfad, 0x56ee82d1, 0xca7463ab, 0xf085b082, 0xb09904d6, 0xd990d43c,
            0xf2e062f4, 0x0839d932, 0x48b1eb92, 0xcdfed530, 0x0bc14828, 0x0430b6d0, 0xcaa094b6, 0xec8911ab,
            0x7dc36824, 0xb824dc0a, 0xf6682b09, 0x35fde7b4, 0x92a14dc2, 0xf4364803, 0x8da2cf79, 0x170d2d50,
            0x133fd494, 0x16cb6e33, 0xbea90b8b, 0xf4559b03, 0x732a01ea, 0x290e6d07, 0x4f79bb83, 0xc10e5800,
            0x15cc1a85, 0xb36b5501, 0x046e9c4b, 0xdcae5135, 0x690b8666, 0xbd54b7a7, 0x03ea7b6f, 0x220a5469,
            0xa568027e,
        };
        uint32_t     count = 0x05097850;
        uint32_t    bearer = 0x10;
        uint32_t direction = 0x1;
        uint32_t    length = 2079; /* 2079 bits */

        printf("EIA3 Test Set 4:\n");
        TestingEIA3(ik, count, bearer, direction, length, m);
        printf("\n");
    }

    {
        /* Test Set 5 */
        uint8_t ik[16] =
        {
            0x6b, 0x8b, 0x08, 0xee, 0x79, 0xe0, 0xb5, 0x98, 0x2d, 0x6d, 0x12, 0x8e, 0xa9, 0xf2, 0x20, 0xcb
        };
        uint32_t m[] = {
            0x5bad7247, 0x10ba1c56, 0xd5a315f8, 0xd40f6e09, 0x3780be8e, 0x8de07b69, 0x92432018, 0xe08ed96a,
            0x5734af8b, 0xad8a575d, 0x3a1f162f, 0x85045cc7, 0x70925571, 0xd9f5b94e, 0x454a77c1, 0x6e72936b,
            0xf016ae15, 0x7499f054, 0x3b5d52ca, 0xa6dbeab6, 0x97d2bb73, 0xe41b8075, 0xdce79b4b, 0x86044f66,
            0x1d4485a5, 0x43dd7860, 0x6e0419e8, 0x059859d3, 0xcb2b67ce, 0x0977603f, 0x81ff839e, 0x33185954,
            0x4cfbc8d0, 0x0fef1a4c, 0x8510fb54, 0x7d6b06c6, 0x11ef44f1, 0xbce107cf, 0xa45a06aa, 0xb360152b,
            0x28dc1ebe, 0x6f7fe09b, 0x0516f9a5, 0xb02a1bd8, 0x4bb0181e, 0x2e89e19b, 0xd8125930, 0xd178682f,
            0x3862dc51, 0xb636f04e, 0x720c47c3, 0xce51ad70, 0xd94b9b22, 0x55fbae90, 0x6549f499, 0xf8c6d399,
            0x47ed5e5d, 0xf8e2def1, 0x13253e7b, 0x08d0a76b, 0x6bfc68c8, 0x12f375c7, 0x9b8fe5fd, 0x85976aa6,
            0xd46b4a23, 0x39d8ae51, 0x47f680fb, 0xe70f978b, 0x38effd7b, 0x2f7866a2, 0x2554e193, 0xa94e98a6,
            0x8b74bd25, 0xbb2b3f5f, 0xb0a5fd59, 0x887f9ab6, 0x8159b717, 0x8d5b7b67, 0x7cb546bf, 0x41eadca2,
            0x16fc1085, 0x0128f8bd, 0xef5c8d89, 0xf96afa4f, 0xa8b54885, 0x565ed838, 0xa950fee5, 0xf1c3b0a4,
            0xf6fb71e5, 0x4dfd169e, 0x82cecc72, 0x66c850e6, 0x7c5ef0ba, 0x960f5214, 0x060e71eb, 0x172a75fc,
            0x1486835c, 0xbea65344, 0x65b055c9, 0x6a72e410, 0x52241823, 0x25d83041, 0x4b40214d, 0xaa8091d2,
            0xe0fb010a, 0xe15c6de9, 0x0850973b, 0xdf1e423b, 0xe148a237, 0xb87a0c9f, 0x34d4b476, 0x05b803d7,
            0x43a86a90, 0x399a4af3, 0x96d3a120, 0x0a62f3d9, 0x507962e8, 0xe5bee6d3, 0xda2bb3f7, 0x237664ac,
            0x7a292823, 0x900bc635, 0x03b29e80, 0xd63f6067, 0xbf8e1716, 0xac25beba, 0x350deb62, 0xa99fe031,
            0x85eb4f69, 0x937ecd38, 0x7941fda5, 0x44ba67db, 0x09117749, 0x38b01827, 0xbcc69c92, 0xb3f772a9,
            0xd2859ef0, 0x03398b1f, 0x6bbad7b5, 0x74f7989a, 0x1d10b2df, 0x798e0dbf, 0x30d65874, 0x64d24878,
            0xcd00c0ea, 0xee8a1a0c, 0xc753a279, 0x79e11b41, 0xdb1de3d5, 0x038afaf4, 0x9f5c682c, 0x3748d8a3,
            0xa9ec54e6, 0xa371275f, 0x1683510f, 0x8e4f9093, 0x8f9ab6e1, 0x34c2cfdf, 0x4841cba8, 0x8e0cff2b,
            0x0bcc8e6a, 0xdcb71109, 0xb5198fec, 0xf1bb7e5c, 0x531aca50, 0xa56a8a3b, 0x6de59862, 0xd41fa113,
            0xd9cd9578, 0x08f08571, 0xd9a4bb79, 0x2af271f6, 0xcc6dbb8d, 0xc7ec36e3, 0x6be1ed30, 0x8164c31c,
            0x7c0afc54, 0x1c000000,
        };
        uint32_t     count = 0x561eb2dd;
        uint32_t    bearer = 0x1c;
        uint32_t direction = 0x0;
        uint32_t    length = 5670; /* 5670 bits */

        printf("EIA3 Test Set 5:\n");
        TestingEIA3(ik, count, bearer, direction, length, m);
        printf("\n");
    }

}
#endif

int main(int argc, char *argv[])
{
    ZUCTests();
    //EEA3Tests();
    //EIA3Tests();

    return 0;
}
