#include "widget.h"

int private_ok_value = 2;

int widget_ok(int a, int b) {
  return a + b == private_ok_value;
}