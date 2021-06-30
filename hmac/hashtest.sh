#!/bin/bash

#set -x

for s in "" "a" "abc" "message digest" "abcdefghijklmnopqrstuvwxyz" "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
do
	for alg in "md4" "md5" "sha1" "sha224" "sha256" "sha384" "sha512" "sha512-224" "sha512-256" "sha3-224" "sha3-256" "sha3-384" "sha3-512" "sm3"
	do
		echo "     vector: s='$s'"
		echo "openssl cmd: echo -n '\$s' | openssl dgst -$alg | awk '{print \$NF}'"
		echo "   hash cmd: ./hash -a $alg -s '\$s' | awk '{print \$NF}'"
		test1=$(echo -n '$s' | openssl dgst -$alg 2>/dev/null | awk '{print $NF}');
		test2=$(./hash -a $alg -s '$s' | awk '{print $NF}');
		echo "openssl out: $test1"
		echo "   hash out: $test2"
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
