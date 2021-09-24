// g++ integer_ext_euclidean_alg.c -o int_gcd -Igtest/include -Lgtest/lib -lgtest_main -lgtest -lpthread
#include "gcd.h"
#include <gtest/gtest.h>

TEST(IntegerGCDTest, CompositeTest)
{
    EXPECT_EQ(3, int_gcd(33, 18));
    EXPECT_EQ(3, int_gcd(18, 33));

    EXPECT_EQ(10, int_gcd(50, 30));
}

TEST(IntegerGCDTest, PrimeTest)
{
    EXPECT_EQ(1, int_gcd(100, 29));
    EXPECT_EQ(1, int_gcd(29, 100));
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

    res = int_gcd_ex(100, 29, &ia, &ib);
    EXPECT_EQ(1, res);
    EXPECT_EQ(9, ia);
    EXPECT_EQ(-31, ib);

    res = int_gcd_ex(29, 100, &ia, &ib);
    EXPECT_EQ(1, res);
    EXPECT_EQ(-31, ia);
    EXPECT_EQ(9, ib);

    res = int_gcd_ex(1759, 550, &ia, &ib);
    EXPECT_EQ(1, res);
    EXPECT_EQ(-111, ia);
    EXPECT_EQ(355, ib);
}

TEST(IntegerInverseTest, InverseTest)
{
    EXPECT_EQ(0, int_inv(33, 18));
    EXPECT_EQ(0, int_inv(30, 50));

    EXPECT_EQ(439, int_inv(1759, 550));
    EXPECT_EQ(355, int_inv(550, 1759));

    EXPECT_EQ(69, int_inv(29, 100));
    EXPECT_EQ(9, int_inv(100, 29));
}