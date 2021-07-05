// 来源: http://yuncode.net/code/c_505aade50745453

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define ENCRYPT 1
#define DECRYPT 0

static void printHex ( char *cmd, int len );
static void printArray ( const char *In, int len );

static void F_func ( bool In[32], const bool Ki[48] );    // f函数
static void S_func ( bool Out[32], const bool In[48] );   // S盒代替

static void Transform ( bool *Out, bool *In, const char *Table, int len ); // 变换
static void Xor ( bool *InA, const bool *InB, int len );   // 异或
static void RotateL ( bool *In, int len, int loop );    // 循环左移
static void ByteToBit ( bool *Out, const char *In, int bits );  // 字节组转换成位组
static void BitToByte ( char *Out, const bool *In, int bits );  // 位组转换成字节组

// 16位子密钥
static bool SubKey[16][48];

// 64位经过PC1转换为56位 (PC-1)
const static char PC1_Table[56] =
{
	57, 49, 41, 33, 25, 17,  9,
	1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27,
	19, 11,  3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29,
	21, 13,  5, 28, 20, 12,  4
};

// 左移
const static char LOOP_Table[16] =
{
	1, 1, 2, 2, 2, 2, 2, 2,
	1, 2, 2, 2, 2, 2, 2, 1
};

// 排列选择 2 (PC-2)
const static char PC2_Table[48] =
{
	14, 17, 11, 24,   1,   5,
	3,  28, 15,  6,  21,  10,
	23, 19, 12,  4,  26,   8,
	16,  7, 27, 20,  13,   2,
	41, 52, 31, 37,  47,  55,
	30, 40, 51, 45,  33,  48,
	44, 49, 39, 56,  34,  53,
	46, 42, 50, 36,  29,  32
};

// Ri_1（32位）经过变换E后膨胀为48位 (E)  void F_func
static const char E_Table[48] =
{
	32,   1,   2,   3,   4,   5,
	4,   5,   6,   7,   8,   9,
	8,   9,  10,  11,  12,  13,
	12,  13,  14,  15,  16,  17,
	16,  17,  18,  19,  20,  21,
	20,  21,  22,  23,  24,  25,
	24,  25,  26,  27,  28,  29,
	28,  29,  30,  31,  32,   1
};

// 8个4比特合并为32比特的排列 P
const static char P_Table[32] =
{
	16,  7, 20, 21,
	29, 12, 28, 17,
	1, 15, 23, 26,
	5, 18, 31, 10,
	2,  8, 24, 14,
	32, 27,  3,  9,
	19, 13, 30,  6,
	22, 11,  4, 25,
};

// 经过S盒 S-boxes
const static char S_Box[8][4][16] =
{
	{
		// S1
		{  14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7   },
		{   0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8   },
		{   4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0   },
		{  15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13   }
	},
	{
		// S2
		{  15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10   },
		{   3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5   },
		{   0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15   },
		{  13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9   }
	},
	{
		// S3
		{  10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8   },
		{  13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1   },
		{  13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7   },
		{   1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12   }
	},
	{
		// S4
		{   7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15   },
		{  13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9   },
		{  10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4   },
		{   3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14   }
	},
	{
		// S5
		{   2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9   },
		{  14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6   },
		{   4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14   },
		{  11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3   }
	},
	{
		// S6
		{  12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11   },
		{  10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8   },
		{   9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6   },
		{   4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13   }
	},
	{
		// S7
		{   4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1   },
		{  13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6   },
		{   1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2   },
		{   6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12   }
	},
	{
		// S8
		{  13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7   },
		{   1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2   },
		{   7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8   },
		{   2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11   }
	}
};

// 初始排列 (IP)
const static char IP_Table[64] =
{
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17,  9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7
};

// L16与R16合并后经过IP_1的最终排列 (IP**-1)
const static char IPR_Table[64] =
{
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41,  9, 49, 17, 57, 25
};

void Des_SetKey ( const char Key[8] );  //生成子密钥
void Des_Run ( char Out[8], char In[8], bool Type );  //DES算法

int main ( int argc, char *argv[] )
{
	char key[12]={1,2,3,4,5,6,7,8};
	char str[12]="Hello";
	char str2[12];

	//printArray( PC2_Table, sizeof(PC2_Table)/sizeof(PC2_Table[0]) );

	printf ( "Before encrypting: " );
	puts ( str );

	Des_SetKey ( key );

	memset ( str2, 0, sizeof ( str2 ) );
	Des_Run ( str2, str, ENCRYPT );
	printf ( "After  encrypting: " );
	printHex ( str2, 8 );

	memset ( str, 0, sizeof ( str ) );
	printf ( "After  decrypting: " );
	Des_Run ( str, str2, DECRYPT );
	puts ( str );

	return 0;
}

void Des_SetKey ( const char Key[8] )
{
	int i;
	static bool K[64], *KL = &K[0], *KR = &K[28];

	ByteToBit ( K, Key, 64 );   //转换为二进制

	Transform ( K, K, PC1_Table, 56 );   //64比特的密钥K，经过PC-1后，生成56比特的串。

	//生成16个子密钥
	for ( i=0; i<16; i++ )
	{
		//循环左移，合并
		RotateL ( KL, 28, LOOP_Table[i] );
		RotateL ( KR, 28, LOOP_Table[i] );
		Transform ( SubKey[i], K, PC2_Table, 48 );
	}
}

void Des_Run ( char Out[8], char In[8], bool Type )
{
	int i;
	static bool M[64], tmp[32], *Li = &M[0], *Ri = &M[32];

	//转换为64位的数据块
	ByteToBit ( M, In, 64 );

	//IP置换 （初始）
	Transform ( M, M, IP_Table, 64 );

	//该比特串被分为32位的L0和32位的R0两部分。

	if ( Type == ENCRYPT )
	{
		//16轮置换
		for ( i=0; i<16; i++ )
		{
			memcpy ( tmp, Ri, 32 );

			// R[i] = L[i-1] xor f(R[i-1], K[i])
			F_func ( Ri, SubKey[i] );

			// 2.4.6 Exclusive-or the resulting value with L[i-1].
			// R[I]=P XOR L[I-1]
			Xor ( Ri, Li, 32 );

			// L[i] = R[i-1]
			memcpy ( Li, tmp, 32 );

		}
	}
	else
	{
		// 如果解密则反转子密钥顺序
		for ( i=15; i>=0; i-- )
		{
			memcpy ( tmp, Li, 32 );
			F_func ( Li, SubKey[i] );
			Xor ( Li, Ri, 32 );
			memcpy ( Ri, tmp, 32 );
		}
	}

	//R16与L16合并成64位的比特串。R16一定要排在L16前面。R16与L16合并后成的比特串，经过置换IP-1后所得的比特串就是密文。
	Transform ( M, M, IPR_Table, 64 );

	BitToByte ( Out, M, 64 );
}

//将32比特的输入再转化为32比特的输出
void F_func ( bool In[32], const bool Ki[48] )
{
	static bool MR[48];

	//输入Ri-1(32比特)经过变换E后，膨胀为48比特
	Transform ( MR, In, E_Table, 48 );

	//异或
	Xor ( MR, Ki, 48 );

	//膨胀后的比特串分为8组，每组6比特。各组经过各自的S盒后，又变为4比特(具体过程见后)，合并后又成为32比特。
	S_func ( In, MR );

	//该32比特经过P变换后，输出的比特串才是32比特的f (Ri-1,Ki)。
	Transform ( In, In, P_Table, 32 );
}

void S_func ( bool Out[32], const bool In[48] )
{
	char j,m,n;

	//膨胀后的比特串分为8组，每组6比特。
	for ( j=0; j<8; j++,In+=6,Out+=4 )
	{
		//在其输入In[0],In[1],In[2],In[3],In[4],In[5]中，计算出m=In[0]*2+In[5], n=In[4]+In[3]*2+In[2]*4+In[1]*8，再从Sj表中查出m行，n列的值Smn。将Smn化为二进制，即得Si盒的输出。
		m = ( In[0]<<1 ) + In[5];
		n = ( In[1]<<3 ) + ( In[2]<<2 ) + ( In[3]<<1 ) + In[4];

		ByteToBit ( Out, &S_Box[ ( int ) j][ ( int ) m][ ( int ) n], 4 );
	}
}

// 打印指定位置指定长度HEX值
static void printHex ( char *cmd, int len )
{
	int i;

	for ( i=0; i<len; i++ )
	{
		printf ( "[%02X]", ( unsigned char ) cmd[i] );
	}
	printf ( "\n" );
}

// 打印数组测试用
static void printArray ( const char *In, int len )
{
	int   i;
	char tmp[256];

	memset ( tmp, 0, sizeof ( tmp ) );

	for ( i=0; i<len; i++ )
	{
		tmp[ ( int ) In[i]]=In[i];
	}

	for ( i=0; i<len; i++ )
	{
		printf ( "[%02d]", ( unsigned char ) tmp[i] );
	}
	printf ( "\n" );
}

void Transform ( bool *Out, bool *In, const char *Table, int len )
{
	int i;
	static bool tmp[256];

	for ( i=0; i<len; i++ )
	{
		tmp[i] = In[ Table[i]-1 ];
	}
	memcpy ( Out, tmp, len );
}

void Xor ( bool *InA, const bool *InB, int len )
{
	int i;

	for ( i=0; i<len; i++ )
	{
		InA[i] ^= InB[i];
	}
}

void RotateL ( bool *In, int len, int loop )
{
	static bool tmp[256];               // Sample:  loop=2
	memcpy ( tmp, In, loop );           // In=12345678 tmp=12
	memcpy ( In, In+loop, len-loop );   // In=345678
	memcpy ( In+len-loop, tmp, loop );  // In=34567812
}

// Sample:
// In = [0x01]
// Out = [0x01] [0x00] [0x00] [0x00] [0x00] [0x00] [0x00] [0x00]
void ByteToBit ( bool *Out, const char *In, int bits )
{
	int i;

	for ( i=0; i<bits; i++ )
	{
		// In[i]的第N位右移N位并和0x01按位"与"运算(N=1~8)
		Out[i] = ( In[i/8]>> ( i%8 ) ) & 1;
	}
}

void BitToByte ( char *Out, const bool *In, int bits )
{
	int i;

	memset ( Out, 0, ( bits+7 ) /8 );
	for ( i=0; i<bits; i++ )
	{
		Out[i/8] |= In[i]<< ( i%8 );
	}
}
