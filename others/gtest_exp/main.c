#include "testy/customer.h"
#include "testy/widget.h"

int main() {
  if (widget_ok(1, 1)) {
    return customer_check(5);
  }

  return 0;
}