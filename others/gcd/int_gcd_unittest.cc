// g++ int_gcd.c int_gcd_unittest.cc -o int_gcd -Igtest/include -Lgtest/lib -lgtest_main -lgtest -lpthread
#include "gcd.h"
#include <gtest/gtest.h>

TEST(IntegerGCDTest, CompositeTest)
{
    /* gcd(60, 0) = 60, gcd(0, 20) = 20 */
    EXPECT_EQ(60, int_gcd(60,  0));
    EXPECT_EQ(20, int_gcd( 0, 20));

    EXPECT_EQ(12, int_gcd(60, 24));
    EXPECT_EQ(11, int_gcd(55, 22));
    EXPECT_EQ( 3, int_gcd(33, 18));
    EXPECT_EQ( 3, int_gcd(27, 21));
    EXPECT_EQ( 6, int_gcd(84, 30));
    EXPECT_EQ(10, int_gcd(50, 30));
    EXPECT_EQ( 7, int_gcd(973, 301));

    EXPECT_EQ(77, int_gcd(7469, 2464));
    EXPECT_EQ(34, int_gcd(24140, 16762));
    EXPECT_EQ(35, int_gcd(4655, 12075));
    EXPECT_EQ(1078, int_gcd(1160718174, 316258250));
}

TEST(IntegerGCDTest, PrimeTest)
{
    EXPECT_EQ(1, int_gcd(67, 12));
    EXPECT_EQ(1, int_gcd(29, 100));
    EXPECT_EQ(1, int_gcd(1759, 550));
    EXPECT_EQ(1, int_gcd(2689, 4001));
}

TEST(IntegerExtEuclideanTest, GCDTest)
{
    int ia, ib;

    EXPECT_EQ(3, int_gcd_ex(33, 18, &ia, &ib));
    EXPECT_EQ(3, int_gcd_ex(18, 33, &ia, &ib));

    EXPECT_EQ(1, int_gcd_ex(100, 29, &ia, &ib));
    EXPECT_EQ(1, int_gcd_ex(29, 100, &ia, &ib));

    EXPECT_EQ(10, int_gcd_ex(50, 30, &ia, &ib));

    EXPECT_EQ(1, int_gcd_ex(1759, 550, &ia, &ib));
}

TEST(IntegerExtEuclideanTest, InverseTest)
{
    int res, ia, ib;

    /* 198 x (-11) + 243 x 9 = 9 = gcd(198, 243) */
    res = int_gcd_ex(198, 243, &ia, &ib);
    EXPECT_EQ(  9, res);
    EXPECT_EQ(-11, ia);
    EXPECT_EQ(  9, ib);

    /* 1819 x 71 + 3587 x (-36) = 17 = gcd(1819, 3587) */
    res = int_gcd_ex(1819, 3587, &ia, &ib);
    EXPECT_EQ( 17, res);
    EXPECT_EQ( 71, ia);
    EXPECT_EQ(-36, ib);

    res = int_gcd_ex(100, 29, &ia, &ib);
    EXPECT_EQ(  1, res);
    EXPECT_EQ(  9, ia);
    EXPECT_EQ(-31, ib);

    res = int_gcd_ex(12, 67, &ia, &ib);
    EXPECT_EQ( 1, res);
    EXPECT_EQ(28, ia);
    EXPECT_EQ(-5, ib);

    res = int_gcd_ex(973, 301, &ia, &ib);
    EXPECT_EQ(  7, res);
    EXPECT_EQ( 13, ia);
    EXPECT_EQ(-42, ib);

    res = int_gcd_ex(1234, 4321, &ia, &ib);
    EXPECT_EQ(    1, res);
    EXPECT_EQ(-1082, ia);
    EXPECT_EQ(  309, ib);

    res = int_gcd_ex(24140, 40902, &ia, &ib);
    EXPECT_EQ(  34, res);
    EXPECT_EQ(-571, ia);
    EXPECT_EQ(337, ib);

    res = int_gcd_ex(1759, 550, &ia, &ib);
    EXPECT_EQ(   1, res);
    EXPECT_EQ(-111, ia);
    EXPECT_EQ( 355, ib);

    res = int_gcd_ex(550, 1769, &ia, &ib);
    EXPECT_EQ(   1, res);
    EXPECT_EQ( 550, ia);
    EXPECT_EQ(-171, ib);
}

TEST(IntegerInverseTest, InverseTest)
{
    /* gcd(33, 18) = 3, no inverse */
    EXPECT_EQ(0, int_inv(33, 18));
    /* gcd(30, 50) = 10, no inverse */
    EXPECT_EQ(0, int_inv(30, 50));

    /* gcd(12, 67) = 1, 12 x 28 mod 67 = 1 */
    EXPECT_EQ(28, int_inv(12, 67));

    /* gcd(1759, 550) = 1, 1759 x 439 mod 550 = 1 */
    EXPECT_EQ(439, int_inv(1759, 550));
    EXPECT_EQ(355, int_inv(550, 1759));

    EXPECT_EQ(3239, int_inv(1234, 4321));
    EXPECT_EQ(0, int_inv(24140, 40902));
    EXPECT_EQ(550, int_inv(550, 1769));

    EXPECT_EQ(69, int_inv(29, 100));
    EXPECT_EQ(9, int_inv(100, 29));
}