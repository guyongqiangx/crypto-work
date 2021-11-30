#include <string.h>
#include "fakerand.h"

/*
 * 测试时，先调用 Set_Random_Data 设置伪随机数据，然后相关的库中就会通过 Get_Random_Bytes 获得预先设置的伪随机数，便于测试
 */
static char seed_buffer[256];

void Set_Random_Data(char *buf, unsigned long len)
{
    memcpy(seed_buffer, buf, len);
}

int Get_Random_Bytes(char *buf, unsigned long len)
{
    memcpy(buf, seed_buffer, len);

    return 0;
}

int Get_Random_NonZero_Bytes(char *buf, unsigned long len)
{
    memcpy(buf, seed_buffer, len);

    return 0;
}