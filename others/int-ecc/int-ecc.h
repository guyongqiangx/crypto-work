/*
 * @        file: 
 * @ description: 
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */

struct point {
    int x;
    int y;
};

struct param {
    int p;
    int a;
    int b;
};

int ecc_point_add(int p, int a, const struct point *p1, const struct point *p2, struct point *p3);
int ecc_point_mul(int p, int a, int x, const struct point *p1, struct point *p2);

int ecc_point_on_curve(int p, int a, int b, const struct point *p1);

int ecc_point_order(int p, int a, int b, const struct point *p1);

void ecc_point_show_group(int p, int a, int b, const struct point *p1);