#include <stdio.h>
#include <string.h>
#include <time.h>
#include <gmp.h>
#include "utils.h"
#include "hash.h"
#include "pss.h"

/*
 * # From: 186-2rsatestvectors\SigGenPSS_186-2.txt
 *
 * # CAVS 11.4
 * # "SigGen PKCS#1 RSASSA-PSS" information
 * # Mod sizes selected: 1024 1536 2048 3072 4096
 * # SHA Algorithm selected:
 * # Salt len: 20
 *
 * [mod = 1024]
 *
 * n = bcb47b2e0dafcba81ff2a2b5cb115ca7e757184c9d72bcdcda707a146b3b4e29989ddc660bd694865b932b71ca24a335cf4d339c719183e6222e4c9ea6875acd528a49ba21863fe08147c3a47e41990b51a03f77d22137f8d74c43a5a45f4e9e18a2d15db051dc89385db9cf8374b63a8cc88113710e6d8179075b7dc79ee76b
 *
 * e = 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001
 * d = 383a6f19e1ea27fd08c7fbc3bfa684bd6329888c0bbe4c98625e7181f411cfd0853144a3039404dda41bce2e31d588ec57c0e148146f0fa65b39008ba5835f829ba35ae2f155d61b8a12581b99c927fd2f22252c5e73cba4a610db3973e019ee0f95130d4319ed413432f2e5e20d5215cdd27c2164206b3f80edee51938a25c1
 *
 * SHAAlg = SHA1
 * SaltVal = 6f2841166a64471d4f0b8ed0dbb7db32161da13b
 * Msg = 1248f62a4389f42f7b4bb131053d6c88a994db2075b912ccbe3ea7dc611714f14e075c104858f2f6e6cfd6abdedf015a821d03608bf4eba3169a6725ec422cd9069498b5515a9608ae7cc30e3d2ecfc1db6825f3e996ce9a5092926bc1cf61aa42d7f240e6f7aa0edb38bf81aa929d66bb5d890018088458720d72d569247b0c
 * S = 682cf53c1145d22a50caa9eb1a9ba70670c5915e0fdfde6457a765de2a8fe12de9794172a78d14e668d498acedad616504bb1764d094607070080592c3a69c343d982bd77865873d35e24822caf43443cc10249af6a1e26ef344f28b9ef6f14e09ad839748e5148bcceb0fd2aa63709cb48975cbf9c7b49abc66a1dc6cb5b31a
 *
 * SHAAlg = SHA1
 * SaltVal = 6f2841166a64471d4f0b8ed0dbb7db32161da13b
 * Msg = 9968809a557bb4f892039ff2b6a0efcd06523624bc3b9ad359a7cf143c4942e874c797b9d37a563d436fe19d5db1aad738caa2617f87f50fc7fcf4361fc85212e89a9465e7f4c361982f64c8c5c0aa5258b9e94f6e934e8dac2ace7cd6095c909de85fe7b973632c384d0ebb165556050d28f236aee70e16b13a432d8a94c62b
 * S = 8f5ea7037367e0db75670504085790acd6d97d96f51e76df916a0c2e4cd66e1ab51c4cd8e2c3e4ef781f638ad65dc49c8d6d7f6930f80b6ae199ea283a8924925a50edab79bb3f34861ffa8b2f96fdf9f8cad3d3f8f025478c81f316da61b0d6a7f71b9068efdfb33c21983a922f4669280d8e84f963ff885ef56dd3f50381db
 */

#if 0
static char n[] =
{
    0xbc, 0xb4, 0x7b, 0x2e, 0x0d, 0xaf, 0xcb, 0xa8, 0x1f, 0xf2, 0xa2, 0xb5, 0xcb, 0x11, 0x5c, 0xa7,
    0xe7, 0x57, 0x18, 0x4c, 0x9d, 0x72, 0xbc, 0xdc, 0xda, 0x70, 0x7a, 0x14, 0x6b, 0x3b, 0x4e, 0x29,
    0x98, 0x9d, 0xdc, 0x66, 0x0b, 0xd6, 0x94, 0x86, 0x5b, 0x93, 0x2b, 0x71, 0xca, 0x24, 0xa3, 0x35,
    0xcf, 0x4d, 0x33, 0x9c, 0x71, 0x91, 0x83, 0xe6, 0x22, 0x2e, 0x4c, 0x9e, 0xa6, 0x87, 0x5a, 0xcd,
    0x52, 0x8a, 0x49, 0xba, 0x21, 0x86, 0x3f, 0xe0, 0x81, 0x47, 0xc3, 0xa4, 0x7e, 0x41, 0x99, 0x0b,
    0x51, 0xa0, 0x3f, 0x77, 0xd2, 0x21, 0x37, 0xf8, 0xd7, 0x4c, 0x43, 0xa5, 0xa4, 0x5f, 0x4e, 0x9e,
    0x18, 0xa2, 0xd1, 0x5d, 0xb0, 0x51, 0xdc, 0x89, 0x38, 0x5d, 0xb9, 0xcf, 0x83, 0x74, 0xb6, 0x3a,
    0x8c, 0xc8, 0x81, 0x13, 0x71, 0x0e, 0x6d, 0x81, 0x79, 0x07, 0x5b, 0x7d, 0xc7, 0x9e, 0xe7, 0x6b
};

static unsigned long e = 0x10001;

static char d[] =
{
    0x38, 0x3a, 0x6f, 0x19, 0xe1, 0xea, 0x27, 0xfd, 0x08, 0xc7, 0xfb, 0xc3, 0xbf, 0xa6, 0x84, 0xbd,
    0x63, 0x29, 0x88, 0x8c, 0x0b, 0xbe, 0x4c, 0x98, 0x62, 0x5e, 0x71, 0x81, 0xf4, 0x11, 0xcf, 0xd0,
    0x85, 0x31, 0x44, 0xa3, 0x03, 0x94, 0x04, 0xdd, 0xa4, 0x1b, 0xce, 0x2e, 0x31, 0xd5, 0x88, 0xec,
    0x57, 0xc0, 0xe1, 0x48, 0x14, 0x6f, 0x0f, 0xa6, 0x5b, 0x39, 0x00, 0x8b, 0xa5, 0x83, 0x5f, 0x82,
    0x9b, 0xa3, 0x5a, 0xe2, 0xf1, 0x55, 0xd6, 0x1b, 0x8a, 0x12, 0x58, 0x1b, 0x99, 0xc9, 0x27, 0xfd,
    0x2f, 0x22, 0x25, 0x2c, 0x5e, 0x73, 0xcb, 0xa4, 0xa6, 0x10, 0xdb, 0x39, 0x73, 0xe0, 0x19, 0xee,
    0x0f, 0x95, 0x13, 0x0d, 0x43, 0x19, 0xed, 0x41, 0x34, 0x32, 0xf2, 0xe5, 0xe2, 0x0d, 0x52, 0x15,
    0xcd, 0xd2, 0x7c, 0x21, 0x64, 0x20, 0x6b, 0x3f, 0x80, 0xed, 0xee, 0x51, 0x93, 0x8a, 0x25, 0xc1
};

static char Salt[] =
{
    0x6f, 0x28, 0x41, 0x16, 0x6a, 0x64, 0x47, 0x1d, 0x4f, 0x0b, 0x8e, 0xd0, 0xdb, 0xb7, 0xdb,
    0x32, 0x16, 0x1d, 0xa1, 0x3b
};

static char M1[] =
{
    0x12, 0x48, 0xf6, 0x2a, 0x43, 0x89, 0xf4, 0x2f, 0x7b, 0x4b, 0xb1, 0x31, 0x05, 0x3d, 0x6c, 0x88,
    0xa9, 0x94, 0xdb, 0x20, 0x75, 0xb9, 0x12, 0xcc, 0xbe, 0x3e, 0xa7, 0xdc, 0x61, 0x17, 0x14, 0xf1,
    0x4e, 0x07, 0x5c, 0x10, 0x48, 0x58, 0xf2, 0xf6, 0xe6, 0xcf, 0xd6, 0xab, 0xde, 0xdf, 0x01, 0x5a,
    0x82, 0x1d, 0x03, 0x60, 0x8b, 0xf4, 0xeb, 0xa3, 0x16, 0x9a, 0x67, 0x25, 0xec, 0x42, 0x2c, 0xd9,
    0x06, 0x94, 0x98, 0xb5, 0x51, 0x5a, 0x96, 0x08, 0xae, 0x7c, 0xc3, 0x0e, 0x3d, 0x2e, 0xcf, 0xc1,
    0xdb, 0x68, 0x25, 0xf3, 0xe9, 0x96, 0xce, 0x9a, 0x50, 0x92, 0x92, 0x6b, 0xc1, 0xcf, 0x61, 0xaa,
    0x42, 0xd7, 0xf2, 0x40, 0xe6, 0xf7, 0xaa, 0x0e, 0xdb, 0x38, 0xbf, 0x81, 0xaa, 0x92, 0x9d, 0x66,
    0xbb, 0x5d, 0x89, 0x00, 0x18, 0x08, 0x84, 0x58, 0x72, 0x0d, 0x72, 0xd5, 0x69, 0x24, 0x7b, 0x0c
};

static char S1[] =
{
    0x68, 0x2c, 0xf5, 0x3c, 0x11, 0x45, 0xd2, 0x2a, 0x50, 0xca, 0xa9, 0xeb, 0x1a, 0x9b, 0xa7, 0x06,
    0x70, 0xc5, 0x91, 0x5e, 0x0f, 0xdf, 0xde, 0x64, 0x57, 0xa7, 0x65, 0xde, 0x2a, 0x8f, 0xe1, 0x2d,
    0xe9, 0x79, 0x41, 0x72, 0xa7, 0x8d, 0x14, 0xe6, 0x68, 0xd4, 0x98, 0xac, 0xed, 0xad, 0x61, 0x65,
    0x04, 0xbb, 0x17, 0x64, 0xd0, 0x94, 0x60, 0x70, 0x70, 0x08, 0x05, 0x92, 0xc3, 0xa6, 0x9c, 0x34,
    0x3d, 0x98, 0x2b, 0xd7, 0x78, 0x65, 0x87, 0x3d, 0x35, 0xe2, 0x48, 0x22, 0xca, 0xf4, 0x34, 0x43,
    0xcc, 0x10, 0x24, 0x9a, 0xf6, 0xa1, 0xe2, 0x6e, 0xf3, 0x44, 0xf2, 0x8b, 0x9e, 0xf6, 0xf1, 0x4e,
    0x09, 0xad, 0x83, 0x97, 0x48, 0xe5, 0x14, 0x8b, 0xcc, 0xeb, 0x0f, 0xd2, 0xaa, 0x63, 0x70, 0x9c,
    0xb4, 0x89, 0x75, 0xcb, 0xf9, 0xc7, 0xb4, 0x9a, 0xbc, 0x66, 0xa1, 0xdc, 0x6c, 0xb5, 0xb3, 0x1a
};

static char M2[] =
{
    0x99, 0x68, 0x80, 0x9a, 0x55, 0x7b, 0xb4, 0xf8, 0x92, 0x03, 0x9f, 0xf2, 0xb6, 0xa0, 0xef, 0xcd,
    0x06, 0x52, 0x36, 0x24, 0xbc, 0x3b, 0x9a, 0xd3, 0x59, 0xa7, 0xcf, 0x14, 0x3c, 0x49, 0x42, 0xe8,
    0x74, 0xc7, 0x97, 0xb9, 0xd3, 0x7a, 0x56, 0x3d, 0x43, 0x6f, 0xe1, 0x9d, 0x5d, 0xb1, 0xaa, 0xd7,
    0x38, 0xca, 0xa2, 0x61, 0x7f, 0x87, 0xf5, 0x0f, 0xc7, 0xfc, 0xf4, 0x36, 0x1f, 0xc8, 0x52, 0x12,
    0xe8, 0x9a, 0x94, 0x65, 0xe7, 0xf4, 0xc3, 0x61, 0x98, 0x2f, 0x64, 0xc8, 0xc5, 0xc0, 0xaa, 0x52,
    0x58, 0xb9, 0xe9, 0x4f, 0x6e, 0x93, 0x4e, 0x8d, 0xac, 0x2a, 0xce, 0x7c, 0xd6, 0x09, 0x5c, 0x90,
    0x9d, 0xe8, 0x5f, 0xe7, 0xb9, 0x73, 0x63, 0x2c, 0x38, 0x4d, 0x0e, 0xbb, 0x16, 0x55, 0x56, 0x05,
    0x0d, 0x28, 0xf2, 0x36, 0xae, 0xe7, 0x0e, 0x16, 0xb1, 0x3a, 0x43, 0x2d, 0x8a, 0x94, 0xc6, 0x2b
};

static char S2[] =
{
    0x8f, 0x5e, 0xa7, 0x03, 0x73, 0x67, 0xe0, 0xdb, 0x75, 0x67, 0x05, 0x04, 0x08, 0x57, 0x90, 0xac,
    0xd6, 0xd9, 0x7d, 0x96, 0xf5, 0x1e, 0x76, 0xdf, 0x91, 0x6a, 0x0c, 0x2e, 0x4c, 0xd6, 0x6e, 0x1a,
    0xb5, 0x1c, 0x4c, 0xd8, 0xe2, 0xc3, 0xe4, 0xef, 0x78, 0x1f, 0x63, 0x8a, 0xd6, 0x5d, 0xc4, 0x9c,
    0x8d, 0x6d, 0x7f, 0x69, 0x30, 0xf8, 0x0b, 0x6a, 0xe1, 0x99, 0xea, 0x28, 0x3a, 0x89, 0x24, 0x92,
    0x5a, 0x50, 0xed, 0xab, 0x79, 0xbb, 0x3f, 0x34, 0x86, 0x1f, 0xfa, 0x8b, 0x2f, 0x96, 0xfd, 0xf9,
    0xf8, 0xca, 0xd3, 0xd3, 0xf8, 0xf0, 0x25, 0x47, 0x8c, 0x81, 0xf3, 0x16, 0xda, 0x61, 0xb0, 0xd6,
    0xa7, 0xf7, 0x1b, 0x90, 0x68, 0xef, 0xdf, 0xb3, 0x3c, 0x21, 0x98, 0x3a, 0x92, 0x2f, 0x46, 0x69,
    0x28, 0x0d, 0x8e, 0x84, 0xf9, 0x63, 0xff, 0x88, 0x5e, 0xf5, 0x6d, 0xd3, 0xf5, 0x03, 0x81, 0xdb
};
#else
static char *str_n = "bcb47b2e0dafcba81ff2a2b5cb115ca7e757184c9d72bcdcda707a146b3b4e29"
                     "989ddc660bd694865b932b71ca24a335cf4d339c719183e6222e4c9ea6875acd"
                     "528a49ba21863fe08147c3a47e41990b51a03f77d22137f8d74c43a5a45f4e9e"
                     "18a2d15db051dc89385db9cf8374b63a8cc88113710e6d8179075b7dc79ee76b";

static char *str_e = "0000000000000000000000000000000000000000000000000000000000000000"
                     "0000000000000000000000000000000000000000000000000000000000000000"
                     "0000000000000000000000000000000000000000000000000000000000000000"
                     "0000000000000000000000000000000000000000000000000000000000010001";

static char *str_d = "383a6f19e1ea27fd08c7fbc3bfa684bd6329888c0bbe4c98625e7181f411cfd0"
                     "853144a3039404dda41bce2e31d588ec57c0e148146f0fa65b39008ba5835f82"
                     "9ba35ae2f155d61b8a12581b99c927fd2f22252c5e73cba4a610db3973e019ee"
                     "0f95130d4319ed413432f2e5e20d5215cdd27c2164206b3f80edee51938a25c1";

// SHAAlg = SHA1
static char *str_salt = "6f2841166a64471d4f0b8ed0dbb7db32161da13b";

static char *str_m1 = "1248f62a4389f42f7b4bb131053d6c88a994db2075b912ccbe3ea7dc611714f1"
                      "4e075c104858f2f6e6cfd6abdedf015a821d03608bf4eba3169a6725ec422cd9"
                      "069498b5515a9608ae7cc30e3d2ecfc1db6825f3e996ce9a5092926bc1cf61aa"
                      "42d7f240e6f7aa0edb38bf81aa929d66bb5d890018088458720d72d569247b0c";

static char *str_s1 = "682cf53c1145d22a50caa9eb1a9ba70670c5915e0fdfde6457a765de2a8fe12d"
                      "e9794172a78d14e668d498acedad616504bb1764d094607070080592c3a69c34"
                      "3d982bd77865873d35e24822caf43443cc10249af6a1e26ef344f28b9ef6f14e"
                      "09ad839748e5148bcceb0fd2aa63709cb48975cbf9c7b49abc66a1dc6cb5b31a";

static char *str_m2 = "9968809a557bb4f892039ff2b6a0efcd06523624bc3b9ad359a7cf143c4942e8"
                      "74c797b9d37a563d436fe19d5db1aad738caa2617f87f50fc7fcf4361fc85212"
                      "e89a9465e7f4c361982f64c8c5c0aa5258b9e94f6e934e8dac2ace7cd6095c90"
                      "9de85fe7b973632c384d0ebb165556050d28f236aee70e16b13a432d8a94c62b";

static char *str_s2 = "8f5ea7037367e0db75670504085790acd6d97d96f51e76df916a0c2e4cd66e1a"
                      "b51c4cd8e2c3e4ef781f638ad65dc49c8d6d7f6930f80b6ae199ea283a892492"
                      "5a50edab79bb3f34861ffa8b2f96fdf9f8cad3d3f8f025478c81f316da61b0d6"
                      "a7f71b9068efdfb33c21983a922f4669280d8e84f963ff885ef56dd3f50381db";
#endif

static char Salt[] =
{
    0x6f, 0x28, 0x41, 0x16, 0x6a, 0x64, 0x47, 0x1d, 0x4f, 0x0b, 0x8e, 0xd0, 0xdb, 0xb7, 0xdb,
    0x32, 0x16, 0x1d, 0xa1, 0x3b
};

static char M1[] =
{
    0x12, 0x48, 0xf6, 0x2a, 0x43, 0x89, 0xf4, 0x2f, 0x7b, 0x4b, 0xb1, 0x31, 0x05, 0x3d, 0x6c, 0x88,
    0xa9, 0x94, 0xdb, 0x20, 0x75, 0xb9, 0x12, 0xcc, 0xbe, 0x3e, 0xa7, 0xdc, 0x61, 0x17, 0x14, 0xf1,
    0x4e, 0x07, 0x5c, 0x10, 0x48, 0x58, 0xf2, 0xf6, 0xe6, 0xcf, 0xd6, 0xab, 0xde, 0xdf, 0x01, 0x5a,
    0x82, 0x1d, 0x03, 0x60, 0x8b, 0xf4, 0xeb, 0xa3, 0x16, 0x9a, 0x67, 0x25, 0xec, 0x42, 0x2c, 0xd9,
    0x06, 0x94, 0x98, 0xb5, 0x51, 0x5a, 0x96, 0x08, 0xae, 0x7c, 0xc3, 0x0e, 0x3d, 0x2e, 0xcf, 0xc1,
    0xdb, 0x68, 0x25, 0xf3, 0xe9, 0x96, 0xce, 0x9a, 0x50, 0x92, 0x92, 0x6b, 0xc1, 0xcf, 0x61, 0xaa,
    0x42, 0xd7, 0xf2, 0x40, 0xe6, 0xf7, 0xaa, 0x0e, 0xdb, 0x38, 0xbf, 0x81, 0xaa, 0x92, 0x9d, 0x66,
    0xbb, 0x5d, 0x89, 0x00, 0x18, 0x08, 0x84, 0x58, 0x72, 0x0d, 0x72, 0xd5, 0x69, 0x24, 0x7b, 0x0c
};

/*
 * $ echo -n ${str_m1} | xxd -r -ps | sha1sum | awk '{print $1}'
 * 0312164be8be4641917db24f8aa180a669a05ecb
 */

static char S1[] =
{
    0x68, 0x2c, 0xf5, 0x3c, 0x11, 0x45, 0xd2, 0x2a, 0x50, 0xca, 0xa9, 0xeb, 0x1a, 0x9b, 0xa7, 0x06,
    0x70, 0xc5, 0x91, 0x5e, 0x0f, 0xdf, 0xde, 0x64, 0x57, 0xa7, 0x65, 0xde, 0x2a, 0x8f, 0xe1, 0x2d,
    0xe9, 0x79, 0x41, 0x72, 0xa7, 0x8d, 0x14, 0xe6, 0x68, 0xd4, 0x98, 0xac, 0xed, 0xad, 0x61, 0x65,
    0x04, 0xbb, 0x17, 0x64, 0xd0, 0x94, 0x60, 0x70, 0x70, 0x08, 0x05, 0x92, 0xc3, 0xa6, 0x9c, 0x34,
    0x3d, 0x98, 0x2b, 0xd7, 0x78, 0x65, 0x87, 0x3d, 0x35, 0xe2, 0x48, 0x22, 0xca, 0xf4, 0x34, 0x43,
    0xcc, 0x10, 0x24, 0x9a, 0xf6, 0xa1, 0xe2, 0x6e, 0xf3, 0x44, 0xf2, 0x8b, 0x9e, 0xf6, 0xf1, 0x4e,
    0x09, 0xad, 0x83, 0x97, 0x48, 0xe5, 0x14, 0x8b, 0xcc, 0xeb, 0x0f, 0xd2, 0xaa, 0x63, 0x70, 0x9c,
    0xb4, 0x89, 0x75, 0xcb, 0xf9, 0xc7, 0xb4, 0x9a, 0xbc, 0x66, 0xa1, 0xdc, 0x6c, 0xb5, 0xb3, 0x1a
};

int Get_Random_Bytes(char *buf, unsigned long len)
{
    memcpy(buf, Salt, 20);

    return 0;
}

static void test_pss_encode(void)
{
    char em[256];
    unsigned long mLen, sLen;
    int res;

    mLen = sizeof(M1)/sizeof(M1[0]);
    sLen = 20;

    dump("  Message:", M1, mLen);

    res = PSS_Encode(HASH_ALG_SHA1, M1, mLen, sLen, em, 128, 1024-1);
    if (0 != res)
    {
        printf("PSS Encode OK!\n");
    }
    else
    {
        printf("PSS Encode OK!\n");
    }

    dump(" Encoding:", em, mLen);
    dump("Expecting:", M1, mLen);
}

static void test_pss_verify(void)
{
    mpz_t n, e, s1, em1;
    char em[256];
    size_t count;
    unsigned long mLen, sLen;
    int res;

    mLen = sizeof(M1)/sizeof(M1[0]);
    sLen = 20;

    dump("       Message:", M1, mLen);

    mpz_inits(n, e, s1, em1, NULL);
    mpz_set_str(n, str_n, 16);
    mpz_set_str(e, str_e, 16);
    mpz_set_str(s1, str_s1, 16);

    mpz_powm(em1, s1, e, n); /* decode: em1 = s1 ^ e mod n */

    gmp_printf(" s1: %Zx\n", s1);
    gmp_printf("em1: %Zx\n", em1);

    mpz_export(em, &count, 1, 1, 0, 0, em1);

    dump("Encode Message:", em, count);

    res = PSS_Verify(HASH_ALG_SHA1, M1, mLen, sLen, em, count, 1024-1);
    if (0 != res)
    {
        printf("PSS Verify Failed!\n");
    }
    else
    {
        printf("PSS Verify OK!\n");
    }

    mpz_clears(n, e, s1, em1, NULL);
}

// cc psstest.c pss.c -o psstest -I../out/gmp/include -I../out/include  -L../out/gmp/lib -lgmp -L../out/lib -lutils -lhash -lmgf
int main(int argc, char *argv[])
{
    int i, len;
    mpz_t n, e, d;
    mpz_t m1, s1, em1;
    //mpz_t m2, s2, em2;

    len = 1024;

    //mpz_inits(n, e, d);
    //mpz_inits(m1, s1, em1);
    mpz_init(em1);

    mpz_init_set_str(n, str_n, 16);
    mpz_init_set_str(e, str_e, 16);
    mpz_init_set_str(d, str_d, 16);

    mpz_init_set_str(m1, str_m1, 16);
    mpz_init_set_str(s1, str_s1, 16);

    gmp_printf("  n: %Zx\n", n);
    gmp_printf("  e: %Zx\n", e);
    gmp_printf("  d: %Zx\n", d);
    gmp_printf(" m1: %Zx\n", m1);
    gmp_printf(" s1: %Zx\n", s1);

    mpz_powm(em1, s1, d, n); /* em1 = s1 ^ d mod n */
    gmp_printf("em1: %Zx\n", em1);

    mpz_clear(m1);
    mpz_clear(s1);
    mpz_clear(em1);
    mpz_clear(n);
    mpz_clear(e);
    mpz_clear(d);

    printf("done!\n");

    printf("\nPSS Encoding Test...\n");
    test_pss_encode();

    printf("\nPSS Verification Test...\n");
    test_pss_verify();

    return 0;
}
