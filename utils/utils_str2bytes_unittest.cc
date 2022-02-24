#include <stdio.h>
#include "gtest/gtest.h"
#include "utils.h"

TEST(UTILS, String2HexBytesTest)
{
    int res;
    unsigned char buf[512];

    char str1[]    = "10001";
    unsigned char arr11[] = {0x01, 0x00, 0x01};
    unsigned char arr12[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01};

    res = str2bytes(NULL, buf, 3, 0);
    EXPECT_EQ(-1, res);

    res = str2bytes("", buf, 3, 0);
    EXPECT_EQ(0, res);

    res = str2bytes(str1, buf, 3, 0);
    EXPECT_EQ(3, res);
    EXPECT_EQ(0, memcmp(buf, arr11, 3));

    res = str2bytes(str1, buf, 8, 1);
    EXPECT_EQ(8, res);
    EXPECT_EQ(0, memcmp(buf, arr12, 8));

    char str2[]    = "a2ba40ee07e3b2bd2f02ce227f36a195024486e49c19cb41bbbdfbba98b22b0e";
    unsigned char arr21[] = {
        0xa2, 0xba, 0x40, 0xee, 0x07, 0xe3, 0xb2, 0xbd, 0x2f, 0x02, 0xce, 0x22, 0x7f, 0x36, 0xa1, 0x95,
        0x02, 0x44, 0x86, 0xe4, 0x9c, 0x19, 0xcb, 0x41, 0xbb, 0xbd, 0xfb, 0xba, 0x98, 0xb2, 0x2b, 0x0e
    };
    unsigned char arr22[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xa2, 0xba, 0x40, 0xee, 0x07, 0xe3, 0xb2, 0xbd, 0x2f, 0x02, 0xce, 0x22, 0x7f, 0x36, 0xa1, 0x95,
        0x02, 0x44, 0x86, 0xe4, 0x9c, 0x19, 0xcb, 0x41, 0xbb, 0xbd, 0xfb, 0xba, 0x98, 0xb2, 0x2b, 0x0e
    };

    res = str2bytes(str2, buf, 32, 0);
    EXPECT_EQ(32, res);
    EXPECT_EQ(0, memcmp(buf, arr21, 32));

    res = str2bytes(str2, buf, 48, 1);
    EXPECT_EQ(48, res);
    EXPECT_EQ(0, memcmp(buf, arr22, 48));

    char str3[]    =  "2ba40ee07e3b2bd2f02ce227f36a195024486e49c19cb41bbbdfbba98b22b0e";
    unsigned char arr31[] = {
        0x02, 0xba, 0x40, 0xee, 0x07, 0xe3, 0xb2, 0xbd, 0x2f, 0x02, 0xce, 0x22, 0x7f, 0x36, 0xa1, 0x95,
        0x02, 0x44, 0x86, 0xe4, 0x9c, 0x19, 0xcb, 0x41, 0xbb, 0xbd, 0xfb, 0xba, 0x98, 0xb2, 0x2b, 0x0e
    };
    unsigned char arr32[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0xba, 0x40, 0xee, 0x07, 0xe3, 0xb2, 0xbd, 0x2f, 0x02, 0xce, 0x22, 0x7f, 0x36, 0xa1, 0x95,
        0x02, 0x44, 0x86, 0xe4, 0x9c, 0x19, 0xcb, 0x41, 0xbb, 0xbd, 0xfb, 0xba, 0x98, 0xb2, 0x2b, 0x0e
    };

    res = str2bytes(str3, buf, 32, 0);
    EXPECT_EQ(32, res);
    EXPECT_EQ(0, memcmp(buf, arr31, 32));

    res = str2bytes(str3, buf, 48, 1);
    EXPECT_EQ(48, res);
    EXPECT_EQ(0, memcmp(buf, arr32, 48));

    char str4[]  = "a2ba40ee07e3b2bd2f02ce227f36a195024486e49c19cb41bbbdfbba98b22b0e"
                   "577c2eeaffa20d883a76e65e394c69d4b3c05a1e8fadda27edb2a42bc000fe88"
                   "8b9b32c22d15add0cd76b3e7936e19955b220dd17d4ea904b1ec102b2e4de775"
                   "1222aa99151024c7cb41cc5ea21d00eeb41f7c800834d2c6e06bce3bce7ea9a5";
    unsigned char arr41[] = {
        0xa2, 0xba, 0x40, 0xee, 0x07, 0xe3, 0xb2, 0xbd, 0x2f, 0x02, 0xce, 0x22, 0x7f, 0x36, 0xa1, 0x95,
        0x02, 0x44, 0x86, 0xe4, 0x9c, 0x19, 0xcb, 0x41, 0xbb, 0xbd, 0xfb, 0xba, 0x98, 0xb2, 0x2b, 0x0e,
        0x57, 0x7c, 0x2e, 0xea, 0xff, 0xa2, 0x0d, 0x88, 0x3a, 0x76, 0xe6, 0x5e, 0x39, 0x4c, 0x69, 0xd4,
        0xb3, 0xc0, 0x5a, 0x1e, 0x8f, 0xad, 0xda, 0x27, 0xed, 0xb2, 0xa4, 0x2b, 0xc0, 0x00, 0xfe, 0x88,
        0x8b, 0x9b, 0x32, 0xc2, 0x2d, 0x15, 0xad, 0xd0, 0xcd, 0x76, 0xb3, 0xe7, 0x93, 0x6e, 0x19, 0x95,
        0x5b, 0x22, 0x0d, 0xd1, 0x7d, 0x4e, 0xa9, 0x04, 0xb1, 0xec, 0x10, 0x2b, 0x2e, 0x4d, 0xe7, 0x75,
        0x12, 0x22, 0xaa, 0x99, 0x15, 0x10, 0x24, 0xc7, 0xcb, 0x41, 0xcc, 0x5e, 0xa2, 0x1d, 0x00, 0xee,
        0xb4, 0x1f, 0x7c, 0x80, 0x08, 0x34, 0xd2, 0xc6, 0xe0, 0x6b, 0xce, 0x3b, 0xce, 0x7e, 0xa9, 0xa5
    };

    res = str2bytes(str4, buf, 128, 0);
    EXPECT_EQ(128, res);
    EXPECT_EQ(0, memcmp(buf, arr41, 128));

    char str51[] = "0000000000000000000000000000000000000000000000000000000000000000"
                   "0000000000000000000000000000000000000000000000000000000000000000"
                   "0000000000000000000000000000000000000000000000000000000000000000"
                   "0000000000000000000000000000000000000000000000000000000000010001";
    char str52[] = "0000000000000000000000000000000000000000000000000000000000000000"
                   "0000000000000000000000000000000000000000000000000000000000010001";
    char str53[] =  "000000000000000000000000000000000000000000000000000000000000000"
                   "0000000000000000000000000000000000000000000000000000000000010001";
    unsigned char arr51 [] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01
    };

    res = str2bytes(str51, buf, 64, 0);
    EXPECT_EQ(-1, res);

    res = str2bytes(str51, buf, 128, 0);
    EXPECT_EQ(128, res);
    EXPECT_EQ(0, memcmp(buf, arr51, 128));

    res = str2bytes(str52, buf, 128, 1);
    EXPECT_EQ(128, res);
    EXPECT_EQ(0, memcmp(buf, arr51, 128));

    res = str2bytes(str53, buf, 128, 1);
    EXPECT_EQ(128, res);
    EXPECT_EQ(0, memcmp(buf, arr51, 128));
}