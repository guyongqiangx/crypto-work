#include <stdio.h>
#include "gtest/gtest.h"
#include "utils.h"

TEST(UTILS, DumpHexTest)
{
    char data[] = {
        0xa2, 0xba, 0x40, 0xee, 0x07, 0xe3, 0xb2, 0xbd, 0x2f, 0x02, 0xce, 0x22, 0x7f, 0x36, 0xa1, 0x95,
        0x02, 0x44, 0x86, 0xe4, 0x9c, 0x19, 0xcb, 0x41, 0xbb, 0xbd, 0xfb, 0xba, 0x98, 0xb2, 0x2b, 0x0e,
        0x57, 0x7c, 0x2e, 0xea, 0xff, 0xa2, 0x0d, 0x88, 0x3a, 0x76, 0xe6, 0x5e, 0x39, 0x4c, 0x69, 0xd4,
        0xb3, 0xc0, 0x5a, 0x1e, 0x8f, 0xad, 0xda, 0x27, 0xed, 0xb2, 0xa4, 0x2b, 0xc0, 0x00, 0xfe, 0x88,
        0x8b, 0x9b, 0x32, 0xc2, 0x2d, 0x15, 0xad, 0xd0, 0xcd, 0x76, 0xb3, 0xe7, 0x93, 0x6e, 0x19, 0x95,
        0x5b, 0x22, 0x0d, 0xd1, 0x7d, 0x4e, 0xa9, 0x04, 0xb1, 0xec, 0x10, 0x2b, 0x2e, 0x4d, 0xe7, 0x75,
        0x12, 0x22, 0xaa, 0x99, 0x15, 0x10, 0x24, 0xc7, 0xcb, 0x41, 0xcc, 0x5e, 0xa2, 0x1d, 0x00, 0xee,
        0xb4, 0x1f, 0x7c, 0x80, 0x08, 0x34, 0xd2, 0xc6, 0xe0, 0x6b, 0xce, 0x3b, 0xce, 0x7e, 0xa9, 0xa5
    };

    int i;
    char tips[20];
    char indent[30];

    memset(tips, 0, sizeof(tips));
    memset(indent, 0, sizeof(indent));

    for (i=10; i<=40; i+=3)
    {
        sprintf(tips, "dumphex %3d bytes:", i);
        dumphex(tips, data, i, NULL, 16);
    }

    dumphex(   NULL, data, 30, "     ", 16);
    dumphex("data:", data, 60, "  ", 8);
    dumphex("data:", data, 60, "   ", 16);
    dumphex("data:", data, 60, "    ", 32);

    memset(tips, 0, sizeof(tips));

    for (i=20; i<=50; i++)
    {
        sprintf(tips, "dump %3d bytes:", i);
        dump(tips, data, i);
    }
}
