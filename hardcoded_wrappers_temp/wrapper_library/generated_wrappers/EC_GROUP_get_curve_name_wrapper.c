#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/ui.h>
#include <openssl/safestack.h>
#include <openssl/ssl.h>
#include <openssl/e_os2.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>
#include <openssl/srp.h>

#include "../arg_struct.h"

int bb_EC_GROUP_get_curve_name(const EC_GROUP * arg_a);

int EC_GROUP_get_curve_name(const EC_GROUP * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EC_GROUP_get_curve_name called %lu\n", in_lib);
    if (!in_lib)
        return bb_EC_GROUP_get_curve_name(arg_a);
    else {
        int (*orig_EC_GROUP_get_curve_name)(const EC_GROUP *);
        orig_EC_GROUP_get_curve_name = dlsym(RTLD_NEXT, "EC_GROUP_get_curve_name");
        return orig_EC_GROUP_get_curve_name(arg_a);
    }
}

int bb_EC_GROUP_get_curve_name(const EC_GROUP * arg_a) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            8884097, 8, 0, /* 0: pointer.func */
            8884097, 8, 0, /* 3: pointer.func */
            0, 40, 5, /* 6: struct.ec_extra_data_st */
            	19, 0,
            	24, 8,
            	3, 16,
            	27, 24,
            	27, 32,
            1, 8, 1, /* 19: pointer.struct.ec_extra_data_st */
            	6, 0,
            0, 8, 0, /* 24: pointer.void */
            8884097, 8, 0, /* 27: pointer.func */
            1, 8, 1, /* 30: pointer.struct.ec_extra_data_st */
            	6, 0,
            0, 4, 0, /* 35: unsigned int */
            8884099, 8, 2, /* 38: pointer_to_array_of_pointers_to_stack */
            	35, 0,
            	45, 12,
            0, 4, 0, /* 45: int */
            0, 24, 1, /* 48: struct.bignum_st */
            	53, 0,
            8884099, 8, 2, /* 53: pointer_to_array_of_pointers_to_stack */
            	35, 0,
            	45, 12,
            8884097, 8, 0, /* 60: pointer.func */
            8884097, 8, 0, /* 63: pointer.func */
            8884097, 8, 0, /* 66: pointer.func */
            8884097, 8, 0, /* 69: pointer.func */
            8884097, 8, 0, /* 72: pointer.func */
            8884097, 8, 0, /* 75: pointer.func */
            8884097, 8, 0, /* 78: pointer.func */
            8884097, 8, 0, /* 81: pointer.func */
            8884097, 8, 0, /* 84: pointer.func */
            8884097, 8, 0, /* 87: pointer.func */
            8884097, 8, 0, /* 90: pointer.func */
            0, 232, 12, /* 93: struct.ec_group_st */
            	120, 0,
            	283, 8,
            	447, 16,
            	447, 40,
            	452, 80,
            	30, 96,
            	447, 104,
            	447, 152,
            	447, 176,
            	24, 208,
            	24, 216,
            	0, 224,
            1, 8, 1, /* 120: pointer.struct.ec_method_st */
            	125, 0,
            0, 304, 37, /* 125: struct.ec_method_st */
            	202, 8,
            	205, 16,
            	205, 24,
            	208, 32,
            	211, 40,
            	214, 48,
            	217, 56,
            	220, 64,
            	223, 72,
            	226, 80,
            	226, 88,
            	229, 96,
            	232, 104,
            	235, 112,
            	238, 120,
            	241, 128,
            	244, 136,
            	247, 144,
            	250, 152,
            	253, 160,
            	90, 168,
            	84, 176,
            	256, 184,
            	81, 192,
            	259, 200,
            	262, 208,
            	256, 216,
            	265, 224,
            	268, 232,
            	271, 240,
            	217, 248,
            	274, 256,
            	277, 264,
            	274, 272,
            	277, 280,
            	277, 288,
            	280, 296,
            8884097, 8, 0, /* 202: pointer.func */
            8884097, 8, 0, /* 205: pointer.func */
            8884097, 8, 0, /* 208: pointer.func */
            8884097, 8, 0, /* 211: pointer.func */
            8884097, 8, 0, /* 214: pointer.func */
            8884097, 8, 0, /* 217: pointer.func */
            8884097, 8, 0, /* 220: pointer.func */
            8884097, 8, 0, /* 223: pointer.func */
            8884097, 8, 0, /* 226: pointer.func */
            8884097, 8, 0, /* 229: pointer.func */
            8884097, 8, 0, /* 232: pointer.func */
            8884097, 8, 0, /* 235: pointer.func */
            8884097, 8, 0, /* 238: pointer.func */
            8884097, 8, 0, /* 241: pointer.func */
            8884097, 8, 0, /* 244: pointer.func */
            8884097, 8, 0, /* 247: pointer.func */
            8884097, 8, 0, /* 250: pointer.func */
            8884097, 8, 0, /* 253: pointer.func */
            8884097, 8, 0, /* 256: pointer.func */
            8884097, 8, 0, /* 259: pointer.func */
            8884097, 8, 0, /* 262: pointer.func */
            8884097, 8, 0, /* 265: pointer.func */
            8884097, 8, 0, /* 268: pointer.func */
            8884097, 8, 0, /* 271: pointer.func */
            8884097, 8, 0, /* 274: pointer.func */
            8884097, 8, 0, /* 277: pointer.func */
            8884097, 8, 0, /* 280: pointer.func */
            1, 8, 1, /* 283: pointer.struct.ec_point_st */
            	288, 0,
            0, 88, 4, /* 288: struct.ec_point_st */
            	299, 0,
            	48, 8,
            	48, 32,
            	48, 56,
            1, 8, 1, /* 299: pointer.struct.ec_method_st */
            	304, 0,
            0, 304, 37, /* 304: struct.ec_method_st */
            	381, 8,
            	384, 16,
            	384, 24,
            	387, 32,
            	390, 40,
            	393, 48,
            	396, 56,
            	399, 64,
            	402, 72,
            	405, 80,
            	405, 88,
            	408, 96,
            	411, 104,
            	414, 112,
            	417, 120,
            	420, 128,
            	423, 136,
            	87, 144,
            	426, 152,
            	429, 160,
            	432, 168,
            	435, 176,
            	78, 184,
            	72, 192,
            	69, 200,
            	438, 208,
            	78, 216,
            	441, 224,
            	66, 232,
            	444, 240,
            	396, 248,
            	63, 256,
            	75, 264,
            	63, 272,
            	75, 280,
            	75, 288,
            	60, 296,
            8884097, 8, 0, /* 381: pointer.func */
            8884097, 8, 0, /* 384: pointer.func */
            8884097, 8, 0, /* 387: pointer.func */
            8884097, 8, 0, /* 390: pointer.func */
            8884097, 8, 0, /* 393: pointer.func */
            8884097, 8, 0, /* 396: pointer.func */
            8884097, 8, 0, /* 399: pointer.func */
            8884097, 8, 0, /* 402: pointer.func */
            8884097, 8, 0, /* 405: pointer.func */
            8884097, 8, 0, /* 408: pointer.func */
            8884097, 8, 0, /* 411: pointer.func */
            8884097, 8, 0, /* 414: pointer.func */
            8884097, 8, 0, /* 417: pointer.func */
            8884097, 8, 0, /* 420: pointer.func */
            8884097, 8, 0, /* 423: pointer.func */
            8884097, 8, 0, /* 426: pointer.func */
            8884097, 8, 0, /* 429: pointer.func */
            8884097, 8, 0, /* 432: pointer.func */
            8884097, 8, 0, /* 435: pointer.func */
            8884097, 8, 0, /* 438: pointer.func */
            8884097, 8, 0, /* 441: pointer.func */
            8884097, 8, 0, /* 444: pointer.func */
            0, 24, 1, /* 447: struct.bignum_st */
            	38, 0,
            1, 8, 1, /* 452: pointer.unsigned char */
            	457, 0,
            0, 1, 0, /* 457: unsigned char */
            1, 8, 1, /* 460: pointer.struct.ec_group_st */
            	93, 0,
        },
        .arg_entity_index = { 460, },
        .ret_entity_index = 45,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const EC_GROUP * new_arg_a = *((const EC_GROUP * *)new_args->args[0]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EC_GROUP_get_curve_name)(const EC_GROUP *);
    orig_EC_GROUP_get_curve_name = dlsym(RTLD_NEXT, "EC_GROUP_get_curve_name");
    *new_ret_ptr = (*orig_EC_GROUP_get_curve_name)(new_arg_a);

    syscall(889);

    return ret;
}

