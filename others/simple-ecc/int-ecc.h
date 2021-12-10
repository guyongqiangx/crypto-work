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

int ec_point_add(struct ec_param *param, const struct point *p1, const struct point *p2, struct point *p3);
int ec_point_mul(struct ec_param *param, int x, const struct point *p1, struct point *p2);

int ec_point_on_curve(struct ec_param *param, const struct point *p1);

int ec_point_order(struct ec_param *param, const struct point *p1);

void ec_point_show_group(struct ec_param *param, const struct point *p1);