#include <stdio.h>
#include <string.h>

#include "hash.h"
#include "mgf.h"
#include "rand.h"
#include "oaep.h"

/*
 * Optimal Asymmetric Encryption Padding (OAEP): 最优非对称加密填充
 *
 * EME-OAEP Encoding Operation
 *
 *                                +----------+------+--+-------+
 *                           DB = |  lHash   |  PS  |01|   M   |
 *                                +----------+------+--+-------+
 *                                               |
 *                     +----------+              |
 *                     |   seed   |              |
 *                     +----------+              |
 *                           |                   |
 *                           |-------> MGF ---> xor
 *                           |                   |
 *                  +--+     V                   |
 *                  |00|    xor <----- MGF <-----|
 *                  +--+     |                   |
 *                    |      |                   |
 *                    V      V                   V
 *                  +--+----------+----------------------------+
 *            EM =  |00|maskedSeed|          maskedDB          |
 *                  +--+----------+----------------------------+
 *
 *    DB: Data Block
 * lHash: Hash(L)
 *    PS: Padding String, k - mLen - 2hLen - 2 zero octets
 *    01: a single octet with hexadecimal value 0x01
 *     M: message to be encrypted
 *        DB = lHash || PS || 0x01 || M
 *    EM: Encoded Message
 */

/*
 * RFC 8017                      PKCS #1 v2.2                 November 2016
 *
 * 7.1.1.  Encryption Operation
 * Steps:
 *   2.  EME-OAEP encoding (see Figure 1 below):
 *
 *     a.  If the label L is not provided, let L be the empty string.
 *         Let lHash = Hash(L), an octet string of length hLen (see
 *         the note below).
 *
 *     b.  Generate a padding string PS consisting of k - mLen -
 *         2hLen - 2 zero octets.  The length of PS may be zero.
 *
 *     c.  Concatenate lHash, PS, a single octet with hexadecimal
 *         value 0x01, and the message M to form a data block DB of
 *         length k - hLen - 1 octets as
 *
 *             DB = lHash || PS || 0x01 || M.
 *
 *     d.  Generate a random octet string seed of length hLen.
 *
 *     e.  Let dbMask = MGF(seed, k - hLen - 1).
 *
 *     f.  Let maskedDB = DB \xor dbMask.
 *
 *     g.  Let seedMask = MGF(maskedDB, hLen).
 *
 *     h.  Let maskedSeed = seed \xor seedMask.
 *
 *     i.  Concatenate a single octet with hexadecimal value 0x00,
 *         maskedSeed, and maskedDB to form an encoded message EM of
 *         length k octets as
 *
 *             EM = 0x00 || maskedSeed || maskedDB.
 */
int OAEP_Encoding(char *M, unsigned long msgLen, const char *L, unsigned long lLen, HASH_ALG alg, char *EM, unsigned long emLen);

/*
 * RFC 8017                      PKCS #1 v2.2                 November 2016
 *
 * 7.1.2.  Decryption Operation
 * Steps:
 *   3.  EME-OAEP decoding:
 *
 *     a.  If the label L is not provided, let L be the empty string.
 *         Let lHash = Hash(L), an octet string of length hLen (see
 *         the note in Section 7.1.1).
 *
 *     b.  Separate the encoded message EM into a single octet Y, an
 *         octet string maskedSeed of length hLen, and an octet
 *         string maskedDB of length k - hLen - 1 as
 *
 *             EM = Y || maskedSeed || maskedDB.
 *
 *     c.  Let seedMask = MGF(maskedDB, hLen).
 *
 *     d.  Let seed = maskedSeed \xor seedMask.
 *
 *     e.  Let dbMask = MGF(seed, k - hLen - 1).
 *
 *     f.  Let DB = maskedDB \xor dbMask.
 *
 *     g.  Separate DB into an octet string lHash' of length hLen, a
 *         (possibly empty) padding string PS consisting of octets
 *         with hexadecimal value 0x00, and a message M as
 *
 *             DB = lHash' || PS || 0x01 || M.
 *
 *         If there is no octet with hexadecimal value 0x01 to
 *         separate PS from M, if lHash does not equal lHash', or if
 *         Y is nonzero, output "decryption error" and stop.  (See
 *         the note below.)
 */
int OAEP_Decoding(const char *L, unsigned long lLen, char *em, unsigned long emLen, HASH_ALG alg, char *M, unsigned long mLen);
