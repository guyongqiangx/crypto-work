#ifndef __ROCKY_OAEP__H
#define __ROCKY_OAEP__H
#ifdef __cplusplus
extern "C"
{
#endif

#include "hash.h"

/**
 * @description:
 * @param {HASH_ALG} alg, OAEP 填充使用的哈希算法
 * @param {unsigned long} k, RSA 秘钥中模数 n 的长度
 * @param {unsigned char} *M, 待填充的消息 M
 * @param {unsigned long} mLen, 带填充消息 M 的长度
 * @param {char} *L, 可选字符串 L, 为空则计算空字符串 "" 的哈希
 * @param {unsigned long} lLen, 可选字符串 L 的长度
 * @param {unsigned char} *EM, OAEP 填充编码后输出的消息
 * @param {unsigned long} emLen, OAEP 填充编码生成消息的长度，和 k 值一样
 * @return {*}, 编码成功返回 0; 编码失败返回 -1;
 */
int OAEP_Encoding(HASH_ALG alg, unsigned long k, unsigned char *M, unsigned long mLen, const char *L, unsigned long lLen, unsigned char *EM, unsigned long emLen);

/**
 * @description:
 * @param {HASH_ALG} alg, OAEP 填充使用的哈希算法
 * @param {unsigned long} k, RSA 秘钥中模数 n 的长度
 * @param {char} *L, 可选字符串 L, 为空则计算空字符串 "" 的哈希
 * @param {unsigned long} lLen, 可选字符串 L 的长度
 * @param {unsigned char} *EM, OAEP 中待解码的消息
 * @param {unsigned long} emLen, OAEP 中待解码消息的长度
 * @param {unsigned char} *M, OAEP 解码还原得到的消息
 * @param {unsigned long} *mLen, OAEP 解码还原得到的消息的长度
 * @return {*}, 解码成功返回 0, 解码失败返回 -1
 */
int OAEP_Decoding(HASH_ALG alg, unsigned long k, const char *L, unsigned long lLen, unsigned char *EM, unsigned long emLen, unsigned char *M, unsigned long *mLen);

#ifdef __cplusplus
}
#endif
#endif