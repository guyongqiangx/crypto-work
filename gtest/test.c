#include "foo.h"
#include <gtest/gtest.h>

TEST(GCDTest, EvenTest)
{
    EXPECT_EQ(2, gcd(4, 10)) << "gcd(4, 10): " << gcd(4, 10);
    EXPECT_EQ(3, gcd(30, 18)) << "gcd(4, 10): " << gcd(30, 18);
    EXPECT_EQ(5, gcd(30, 18));
}

TEST(GCDTest, PrimeTest)
{
    EXPECT_EQ(1, gcd(23, 10));
    EXPECT_EQ(1, gcd(359, 71));
    EXPECT_EQ(1, gcd(47, 83));
}

// Tests factorial of 0.
TEST(FactorialTest, HandlesZeroInput) {
  EXPECT_EQ(Factorial(0), 1);
}

// Tests factorial of positive numbers.
TEST(FactorialTest, HandlesPositiveInput) {
  EXPECT_EQ(Factorial(1), 1);
  EXPECT_EQ(Factorial(2), 2);
  EXPECT_EQ(Factorial(3), 6);
  EXPECT_EQ(Factorial(8), 40320);
}

// int _tmain(int argc, _TCHAR* argv[])
// {
//     testing::InitGoogleTest(&argc, argv);
//     return RUN_ALL_TESTS();
// }

// int main(int argc, char *argv[])
// {
//     testing::InitGoogleTest(&argc, argv);
//     return RUN_ALL_TESTS();
// }

/*
 * 1. Building
 * 1). with main in test.c
 * $ g++ test.c foo.c -o test -Igtest/include -Lgtest/lib -lgtest -lpthread
 *
 * 2). no main in test.c, link with libgtest_main.a
 * $ g++ test.c foo.c -o test -Igtest/include -Lgtest/lib -lgtest_main -lgtest -lpthread
 *
 * 2. Running
 * $ ./test
 * [==========] Running 1 test from 1 test suite.
 * [----------] Global test environment set-up.
 * [----------] 1 test from GCDTest
 * [ RUN      ] GCDTest.gcdtest
 * test.c:9: Failure
 * Expected equality of these values:
 *   5
 *   gcd(30, 18)
 *     Which is: 6
 * [  FAILED  ] GCDTest.gcdtest (0 ms)
 * [----------] 1 test from GCDTest (0 ms total)
 * 
 * [----------] Global test environment tear-down
 * [==========] 1 test from 1 test suite ran. (0 ms total)
 * [  PASSED  ] 0 tests.
 * [  FAILED  ] 1 test, listed below:
 * [  FAILED  ] GCDTest.gcdtest
 * 
 *  1 FAILED TEST
 * $
 */