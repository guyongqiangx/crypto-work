#include "gtest/gtest.h"

extern "C" {
#include "widget.h"
}

TEST(widget, ok) {
  ASSERT_EQ(widget_ok(1, 1), 1);
}

TEST(testy, not_ok) {
  ASSERT_EQ(widget_ok(1, 2), 0);
}