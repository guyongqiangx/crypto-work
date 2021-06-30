#!/bin/bash

#set -x

for key in "I Love China!" "12345678901234567890123456789012345678901234567890123456789012345678901234567890" "6f8d7b44785ecf4865ad83d57e273eb507fdcbf59aeb11230c49e828fbc0105822db7a4db0467eaba86818b98b0d52bf846dea4f0aaacef559567bccf681d713"
do
	for s in "" "a" "abc" "message digest" "abcdefghijklmnopqrstuvwxyz" "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
	do
		for alg in "md4" "md5" "sha1" "sha224" "sha256" "sha384" "sha512" "sha512-224" "sha512-256" "sha3-224" "sha3-256" "sha3-384" "sha3-512" "sm3"
		do
			echo "     vector:   s='$s'"
			echo "        key: key='$key'"
			echo "openssl cmd: echo -n '\$s' | openssl dgst -$alg -hmac '\$key' | awk '{print \$NF}'"
			echo "   hmac cmd: ./hmac -a $alg -k '\$key' -s '\$s' | awk '{print \$NF}'"
			test1=$(echo -n '$s' | openssl dgst -$alg -hmac '$key' 2>/dev/null | awk '{print $NF}');
			test2=$(./hmac -a $alg -k '$key' -s '$s' | awk '{print $NF}');
			echo "openssl out: $test1"
			echo "   hmac out: $test2"
			echo -n "     result: "
			if [ x$test1 = x$test2 ]
			then
				echo -e "\033[32mPASS\033[0m"
			else
				echo -e "\033[31mFAIL\033[0m"
			fi
			echo
		done
	done
done
