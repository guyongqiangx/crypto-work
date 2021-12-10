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

struct ec_param {
    int p;
    int a;
    int b;
};

/*
 * struct ec_private_key {
 *     struct ec_param param;
 *     struct point g;
 *     int d;
 * };
 *
 * struct ec_public_key {
 *     struct ec_param param;
 *     struct point g;
 *     struct point pa;
 * };
 */

int ec_point_add(const struct ec_param *param, const struct point *p1, const struct point *p2, struct point *p3);
int ec_point_mul(const struct ec_param *param, int x, const struct point *p1, struct point *p2);

int ec_point_on_curve(const struct ec_param *param, const struct point *p1);

int ec_point_order(const struct ec_param *param, const struct point *p1);

void ec_point_show_group(const struct ec_param *param, const struct point *p1);