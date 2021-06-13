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

