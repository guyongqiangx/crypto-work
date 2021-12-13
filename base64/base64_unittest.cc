#include <stdio.h>
#include <string.h>
#include "gtest/gtest.h"
#include "base64.h"
#include "utils.h"

TEST(BASE64, BASE64Test1)
{
    /*
     * Test Vectors come from: https://en.wikipedia.org/wiki/Base64
     *
     * $ echo -n "Many hands make light work." | base64
     * TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu
     */
    char data[] = "Many hands make light work.";
    char result[] = "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu";

    unsigned char buf[128], dec[128];
    int len, count;

    printf("Origin: %s\n", data);

    memset(buf, 0, sizeof(buf));
    Base64Encode((unsigned char *)data, strlen(data), (char *)buf, &len);

    EXPECT_EQ(0, memcmp(buf, result, len));

    printf("Expect: %s\n", result);
    printf("Encode: %s\n", buf);

    Base64Decode(result, strlen(result), dec, &count);
    dump("Decode: ", dec, count);

    EXPECT_EQ(0, memcmp(dec, data, count));
}

TEST(BASE64, BASE64Test2)
{
    unsigned char buf[128], dec[128];
    int len, count;

    int i;
    unsigned char temp[][12] = {
        "light work.",
        "light work",
        "light wor",
        "light wo",
        "light w"
    };
    char expect[][17] = {
        "bGlnaHQgd29yay4=",
        "bGlnaHQgd29yaw==",
        "bGlnaHQgd29y",
        "bGlnaHQgd28=",
        "bGlnaHQgdw==",
    };
    printf("\n");
    for (i=0; i<5; i++)
    {
        printf("Origin: %s\n", temp[i]);

        memset(buf, 0, sizeof(buf));
        Base64Encode(temp[i], strlen((char *)temp[i]), (char *)buf, &len);

        EXPECT_EQ(0, memcmp(buf, expect[i], len));

        printf("Expect: %s\n", expect[i]);
        printf("Encode: %s\n", buf);

        Base64Decode((char *)buf, len, dec, &count);
        dump("Decode: ", dec, count);

        EXPECT_EQ(0, memcmp(dec, temp[i], count));
    }
}