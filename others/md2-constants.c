#include <stdio.h>

/*
 * Refer: How is the MD2 hash function S-table constructed from Pi?
 * https://crypto.stackexchange.com/questions/11935/how-is-the-md2-hash-function-s-table-constructed-from-pi
 *
 * 算法描述:
 *
 * S = [0, 1, ..., 255]
 * digits_Pi = [3, 1, 4, 1, 5, 9, ...] # the digits of pi
 *
 * def rand(n):
 *   x = next(digits_Pi)
 *   y = 10
 *
 *   if n > 10:
 *     x = x*10 + next(digits_Pi)
 *     y = 100
 *   if n > 100:
 *     x  = x*10 + next(digits_Pi)
 *     y = 1000
 *
 *   if x < (n*(y/n)): # division here is integer division
 *     return x % n
 *   else:
 *     # x value is too large, don't use it
 *     return rand(n)
 *
 * for i in 2...256: #inclusive
 *   j = rand(i)
 *   tmp = S[j]
 *   S[j] = S[i-1]
 *   S[i-1] = tmp
 */

static unsigned int next_pi_digit(void)
{
    /*
     * Python使用 sympy 工具包可以轻松获得一些数学常量的高精度数值
     * 具体参考:
     * https://blog.csdn.net/zhuoqingjoking97298/article/details/106635679
     *
     */
    static char pi[731]="3"
        "1415926535897932384626433832795028841971693993751058209749445923078164062"
        "8620899862803482534211706798214808651328230664709384460955058223172535940"
        "8128481117450284102701938521105559644622948954930381964428810975665933446"
        "1284756482337867831652712019091456485669234603486104543266482133936072602"
        "4914127372458700660631558817488152092096282925409171536436789259036001133"
        "0530548820466521384146951941511609433057270365759591953092186117381932611"
        "7931051185480744623799627495673518857527248912279381830119491298336733624"
        "4065664308602139494639522473719070217986094370277053921717629317675238467"
        "4818467669405132000568127145263560827785771342757789609173637178721468440"
        "901224953430146549585371050792279689258923542019956112129021960864034418";
    static unsigned int pos = 0;

    if (pos == 730)
    {
        printf("WARNING!! pi string is not long enough, wrap around!\n");
        pos = 0;
    }

    return pi[pos++]-'0';
}

static unsigned int rand(unsigned int n)
{
    unsigned int x, y;

    x = next_pi_digit();
    y = 10;

    if (n > 10)
    {
        x = x * 10 + next_pi_digit();
        y = 100;
    }

    if (n > 100)
    {
        x = x * 10 + next_pi_digit();
        y = 1000;
    }

	/*
	 * 这里使用n进行整除和取模，所以n不能为0
	 */
    if (x < (n*(y/n))) /* division here is integer division */
    {
        return x % n;
    }
    else
    {
        /* x value is too large, don't use it */
        return rand(n);
    }
}

static int generate_s_box(unsigned int *S, unsigned int size)
{
    unsigned int i;
    unsigned int j;
    unsigned int tmp;

	/* 初始化随机置换数组S[0, 1, 2, ..., 255] */
    for (i=0; i<size; i++)
    {
        S[i] = i;
    }

	/* i = 2, 3, ..., 256 */
    for (i=2; i<size+1; i++)
    {
        j = rand(i);
		printf("S[%3d]=0x%02X <--> S[%3d]=0x%02X\n", j, S[j], i-1, S[i-1]);
        tmp = S[j];
        S[j] = S[i-1];
        S[i-1] = tmp;
    }

    return 0;
}

int main(int argc, char* argv)
{
    unsigned int S[256];
    int i;

    generate_s_box(S, 256);

    printf("S Box:\n");
    for (i=0; i<256; i++)
    {
        printf("0x%02X ", (unsigned char)S[i]);
        if (i%16 == 15)
            printf("\n");
        else if (i==255)
            printf("\n");
    }

    return 0;
}
