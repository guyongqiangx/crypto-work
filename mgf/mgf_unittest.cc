#include <stdio.h>
#include "gtest/gtest.h"
#include "hash.h"
#include "mgf.h"

/*
 * From: https://en.wikipedia.org/wiki/Mask_generation_function
 *
 * Example outputs of MGF1:
 *
 * Python 2.7.6 (default, Sep  9 2014, 15:04:36) 
 * [GCC 4.2.1 Compatible Apple LLVM 6.0 (clang-600.0.39)] on darwin
 * Type "help", "copyright", "credits" or "license" for more information.
 * >>> from mgf1 import mgf1
 * >>> from binascii import hexlify
 * >>> from hashlib import sha256
 * >>> hexlify(mgf1('foo', 3))
 * '1ac907'
 * >>> hexlify(mgf1('foo', 5))
 * '1ac9075cd4'
 * >>> hexlify(mgf1('bar', 5))
 * 'bc0c655e01'
 * >>> hexlify(mgf1('bar', 50))
 * 'bc0c655e016bc2931d85a2e675181adcef7f581f76df2739da74faac41627be2f7f415c89e983fd0ce80ced9878641cb4876'
 * >>> hexlify(mgf1('bar', 50, sha256))
 * '382576a7841021cc28fc4c0948753fb8312090cea942ea4c4e735d10dc724b155f9f6069f289d61daca0cb814502ef04eae1'
 */
TEST(MGF, MGFMetaTest)
{
    char buf[256];
    int i, size;

    /*
     * Test 1
     */
    const char *str1 = "foo";
    const int res1[] = {0x1a, 0xc9, 0x07};
    size = strlen(str1);
    MGF1("foo", HASH_ALG_SHA1, size, buf);
    for (i=0; i<size; i++)
    {
        EXPECT_EQ(buf[i], res1[i]);
    }

    /*
     * Test 2
     */
    const char *str2 = "foo";
    const int res2[] = {0x1a, 0xc9, 0x07, 0x5c, 0xd4};
    size = strlen(str2);
    MGF1("foo", HASH_ALG_SHA1, size, buf);
    for (i=0; i<size; i++)
    {
        EXPECT_EQ(buf[i], res2[i]);
    }

    /*
     * Test 3
     */
    const char *str3 = "bar";
    const int res3[] = {0xbc, 0x0c, 0x65, 0x5e, 0x01};
    size = strlen(str3);
    MGF1("foo", HASH_ALG_SHA1, size, buf);
    for (i=0; i<size; i++)
    {
        EXPECT_EQ(buf[i], res3[i]);
    }

    /*
     * Test 4
     */
    const char *str4 = "bar";
    const int res4[] = {0xbc, 0x0c, 0x65, 0x5e, 0x01, 0x6b, 0xc2, 0x93, 0x1d, 0x85, 0xa2, 0xe6, 0x75, 0x18, 0x1a, 0xdc,
                       0xef, 0x7f, 0x58, 0x1f, 0x76, 0xdf, 0x27, 0x39, 0xda, 0x74, 0xfa, 0xac, 0x41, 0x62, 0x7b, 0xe2,
                       0xf7, 0xf4, 0x15, 0xc8, 0x9e, 0x98, 0x3f, 0xd0, 0xce, 0x80, 0xce, 0xd9, 0x87, 0x86, 0x41, 0xcb,
                       0x48, 0x76};
    size = strlen(str4);
    MGF1("foo", HASH_ALG_SHA256, size, buf);
    for (i=0; i<size; i++)
    {
        EXPECT_EQ(buf[i], res4[i]);
    }

    /*
     * Test 5
     */
    const char *str5 = "bar";
    const int res5[] = {0x38, 0x25, 0x76, 0xa7, 0x84, 0x10, 0x21, 0xcc, 0x28, 0xfc, 0x4c, 0x09, 0x48, 0x75, 0x3f, 0xb8,
                       0x31, 0x20, 0x90, 0xce, 0xa9, 0x42, 0xea, 0x4c, 0x4e, 0x73, 0x5d, 0x10, 0xdc, 0x72, 0x4b, 0x15,
                       0x5f, 0x9f, 0x60, 0x69, 0xf2, 0x89, 0xd6, 0x1d, 0xac, 0xa0, 0xcb, 0x81, 0x45, 0x02, 0xef, 0x04,
                       0xea, 0xe1};
    size = strlen(str5);
    MGF1("foo", HASH_ALG_SHA1, size, buf);
    for (i=0; i<size; i++)
    {
        EXPECT_EQ(buf[i], res5[i]);
    }
}