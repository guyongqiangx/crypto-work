# echo -n "" | openssl dgst -sha512
# echo -n "a" | openssl dgst -sha512
# echo -n "abc" | openssl dgst -sha512
# echo -n "message digest" | openssl dgst -sha512
# echo -n "abcdefghijklmnopqrstuvwxyz" | openssl dgst -sha512
# echo -n "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" | openssl dgst -sha512
# echo -n "12345678901234567890123456789012345678901234567890123456789012345678901234567890" | openssl dgst -sha512
# 
# $ echo -n "" | openssl dgst -sm3
# (stdin)= 1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b
# $ echo -n "a" | openssl dgst -sm3
# (stdin)= 623476ac18f65a2909e43c7fec61b49c7e764a91a18ccb82f1917a29c86c5e88
# $ echo -n "abc" | openssl dgst -sm3
# (stdin)= 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
# $ echo -n "message digest" | openssl dgst -sm3
# (stdin)= c522a942e89bd80d97dd666e7a5531b36188c9817149e9b258dfe51ece98ed77
# $ echo -n "abcdefghijklmnopqrstuvwxyz" | openssl dgst -sm3
# (stdin)= b80fe97a4da24afc277564f66a359ef440462ad28dcc6d63adb24d5c20a61595
# $ echo -n "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" | openssl dgst -sm3
# (stdin)= 2971d10c8842b70c979e55063480c50bacffd90e98e2e60d2512ab8abfdfcec5
# $ echo -n "12345678901234567890123456789012345678901234567890123456789012345678901234567890" | openssl dgst -sm3
# (stdin)= ad81805321f3e69d251235bf886a564844873b56dd7dde400f055b7dde39307a

$ openssl version
OpenSSL 1.1.1f  31 Mar 2020
$ openssl dgst -list
Supported digests:
-blake2b512                -blake2s256                -md4
-md5                       -md5-sha1                  -ripemd
-ripemd160                 -rmd160                    -sha1
-sha224                    -sha256                    -sha3-224
-sha3-256                  -sha3-384                  -sha3-512
-sha384                    -sha512                    -sha512-224
-sha512-256                -shake128                  -shake256
-sm3                       -ssl3-md5                  -ssl3-sha1
-whirlpool

$ echo -n "a" | openssl dgst -sha3-256
(stdin)= 80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b
$ echo -n "abc" | openssl dgst -sha3-256
(stdin)= 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
$ echo -n "message digest" | openssl dgst -sha3-256
(stdin)= edcdb2069366e75243860c18c3a11465eca34bce6143d30c8665cefcfd32bffd
$ echo -n "abcdefghijklmnopqrstuvwxyz" | openssl dgst -sha3-256
(stdin)= 7cab2dc765e21b241dbc1c255ce620b29f527c6d5e7f5f843e56288f0d707521
$ echo -n "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" | openssl dgst -sha3-256
(stdin)= a79d6a9da47f04a3b9a9323ec9991f2105d4c78a7bc7beeb103855a7a11dfb9f
$ echo -n "12345678901234567890123456789012345678901234567890123456789012345678901234567890" | openssl dgst -sha3-256
(stdin)= 293e5ce4ce54ee71990ab06e511b7ccd62722b1beb414f5ff65c8274e0f5be1d
$
$ echo -n "" | openssl dgst -sha3-512
(stdin)= a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26
$ echo -n "a" | openssl dgst -sha3-512
(stdin)= 697f2d856172cb8309d6b8b97dac4de344b549d4dee61edfb4962d8698b7fa803f4f93ff24393586e28b5b957ac3d1d369420ce53332712f997bd336d09ab02a
$ echo -n "abc" | openssl dgst -sha3-512
(stdin)= b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0
$ echo -n "message digest" | openssl dgst -sha3-512
(stdin)= 3444e155881fa15511f57726c7d7cfe80302a7433067b29d59a71415ca9dd141ac892d310bc4d78128c98fda839d18d7f0556f2fe7acb3c0cda4bff3a25f5f59
$ echo -n "abcdefghijklmnopqrstuvwxyz" | openssl dgst -sha3-512
(stdin)= af328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68
$ echo -n "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" | openssl dgst -sha3-512
(stdin)= d1db17b4745b255e5eb159f66593cc9c143850979fc7a3951796aba80165aab536b46174ce19e3f707f0e5c6487f5f03084bc0ec9461691ef20113e42ad28163
$ echo -n "12345678901234567890123456789012345678901234567890123456789012345678901234567890" | openssl dgst -sha3-512
(stdin)= 9524b9a5536b91069526b4f6196b7e9475b4da69e01f0c855797f224cd7335ddb286fd99b9b32ffe33b59ad424cc1744f6eb59137f5fb8601932e8a8af0ae930
$

