#include <stdio.h>
#include <string.h> /* memset */
#include "utils.h"
#include "base64.h"

/*
 * $ gcc base64.c base64test.c -I../out/include -L../out/lib -lutils -o base64
 */
int main(int argc, char *argv[])
{
    unsigned char data[27] = "Many hands make light work.";
    unsigned char result[] = "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu";

    char buf[128], dec[128];
    int len, count;

    printf("Origin: %s\n", data);

    memset(buf, 0, sizeof(buf));
    Base64Encode(data, sizeof(data), buf, &len);

    printf("Expect: %s\n", result);
    printf("Encode: %s\n", buf);

    Base64Decode(result, strlen(result), dec, &count);
    dump("Decode: ", dec, count);

    {
        int i;
        unsigned char *temp[] = {
            "light work.",
            "light work",
            "light wor",
            "light wo",
            "light w"
        };
        unsigned char *expect[] = {
            "bGlnaHQgd29yay4=",
            "bGlnaHQgd29yaw==",
            "bGlnaHQgd29y",
            "bGlnaHQgd28=",
            "bGlnaHQgdw==",
        };
        printf("\n");
        for (i=0; i<sizeof(temp)/sizeof(temp[0]); i++)
        {
            printf("Origin: %s\n", temp[i]);

            memset(buf, 0, sizeof(buf));
            Base64Encode(temp[i], strlen(temp[i]), buf, &len);

            printf("Expect: %s\n", expect[i]);
            printf("Encode: %s\n", buf);

            Base64Decode(buf, len, dec, &count);
            dump("Decode: ", dec, count);
        }
    }

    return 0;
}