#ifndef __ROCKY_UTILS__H
#define __ROCKY_UTILS__H
#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @description: Dump hex data from an array
 * @param {char}    *tips, tips at the first line of output
 * @param {void}    *data, binary data to be dump out
 * @param {int} data_size, binary data size to be dump out
 * @param {char}  *indent, indent size for each line
 * @param {int} line_size, line size for each line
 * @return {*}           , no return
 */
void dumphex(const char *tips, const void *data, int data_size, const char *indent, int line_size);

/**
 * @description: Dump hex data from an array, same as dumphex with no indent and line size 16
 * @param {char}    *tips, tips at the first line of output
 * @param {void}    *data, binary data to be dump out
 * @param {int} data_size, binary data size to be dump out
 * @return {*}           , no return
 */
void dump(const char *tips, const void *data, int data_size);

#ifdef DISABLE_DUMP_FUNCTIONS
#define dumphex(...)
#define dump(...)
#endif

/**
 * @description: Convert hexdecimal string to bytes array
 * @param {char}           *str, hexdecimal string, like: "1234567890"
 * @param {unsigned char} *data, data array to store the out put
 * @param {int}            size, output data array size
 * @param {int}         padding, if padding=1, then fill 0x00 before the output data to get the total size bytes
 * @return {*}
 */
int str2bytes(const char *str, unsigned char *data, int size, int padding);

#ifdef __cplusplus
}
#endif
#endif