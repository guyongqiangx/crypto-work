#include "foo.h"
// #include "build/_deps/googletest-src/googletest/include/
#include "gtest/gtest.h"

TEST(GCDTest, gcdtest)
{
    EXPECT_EQ(2, gcd(4, 10));
    EXPECT_EQ(6, gcd(30, 18));
    EXPECT_EQ(5, gcd(30, 18));
}

// int _tmain(int argc, _TCHAR* argv[])
// {
//     testing::InitGoogleTest(&argc, argv);
//     return RUN_ALL_TESTS();
// }

int main(int argc, char *argv[])
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

/*
 * 1. Building
 * $ g++ test.c foo.c -L. -lgtest -lpthread -Ibuild/_deps/googletest-src/googletest/include/ -o test
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