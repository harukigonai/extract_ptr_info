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

EC_KEY * bb_EC_KEY_new_by_curve_name(int arg_a);

EC_KEY * EC_KEY_new_by_curve_name(int arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EC_KEY_new_by_curve_name called %lu\n", in_lib);
    if (!in_lib)
        return bb_EC_KEY_new_by_curve_name(arg_a);
    else {
        EC_KEY * (*orig_EC_KEY_new_by_curve_name)(int);
        orig_EC_KEY_new_by_curve_name = dlsym(RTLD_NEXT, "EC_KEY_new_by_curve_name");
        return orig_EC_KEY_new_by_curve_name(arg_a);
    }
}

EC_KEY * bb_EC_KEY_new_by_curve_name(int arg_a) 
{
    EC_KEY * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 40, 5, /* 0: struct.ec_extra_data_st */
            	13, 0,
            	18, 8,
            	21, 16,
            	24, 24,
            	24, 32,
            1, 8, 1, /* 13: pointer.struct.ec_extra_data_st */
            	0, 0,
            0, 8, 0, /* 18: pointer.void */
            8884097, 8, 0, /* 21: pointer.func */
            8884097, 8, 0, /* 24: pointer.func */
            1, 8, 1, /* 27: pointer.struct.ec_extra_data_st */
            	0, 0,
            0, 24, 1, /* 32: struct.bignum_st */
            	37, 0,
            1, 8, 1, /* 37: pointer.unsigned int */
            	42, 0,
            0, 4, 0, /* 42: unsigned int */
            1, 8, 1, /* 45: pointer.struct.bignum_st */
            	32, 0,
            1, 8, 1, /* 50: pointer.struct.ec_extra_data_st */
            	55, 0,
            0, 40, 5, /* 55: struct.ec_extra_data_st */
            	50, 0,
            	18, 8,
            	21, 16,
            	24, 24,
            	24, 32,
            1, 8, 1, /* 68: pointer.unsigned char */
            	73, 0,
            0, 1, 0, /* 73: unsigned char */
            0, 24, 1, /* 76: struct.bignum_st */
            	37, 0,
            8884097, 8, 0, /* 81: pointer.func */
            8884097, 8, 0, /* 84: pointer.func */
            8884097, 8, 0, /* 87: pointer.func */
            8884097, 8, 0, /* 90: pointer.func */
            8884097, 8, 0, /* 93: pointer.func */
            0, 24, 1, /* 96: struct.bignum_st */
            	37, 0,
            8884097, 8, 0, /* 101: pointer.func */
            8884097, 8, 0, /* 104: pointer.func */
            0, 304, 37, /* 107: struct.ec_method_st */
            	184, 8,
            	187, 16,
            	187, 24,
            	190, 32,
            	193, 40,
            	196, 48,
            	199, 56,
            	202, 64,
            	205, 72,
            	208, 80,
            	208, 88,
            	211, 96,
            	214, 104,
            	217, 112,
            	220, 120,
            	223, 128,
            	226, 136,
            	229, 144,
            	232, 152,
            	235, 160,
            	238, 168,
            	241, 176,
            	244, 184,
            	104, 192,
            	247, 200,
            	250, 208,
            	244, 216,
            	253, 224,
            	256, 232,
            	259, 240,
            	199, 248,
            	262, 256,
            	265, 264,
            	262, 272,
            	265, 280,
            	265, 288,
            	268, 296,
            8884097, 8, 0, /* 184: pointer.func */
            8884097, 8, 0, /* 187: pointer.func */
            8884097, 8, 0, /* 190: pointer.func */
            8884097, 8, 0, /* 193: pointer.func */
            8884097, 8, 0, /* 196: pointer.func */
            8884097, 8, 0, /* 199: pointer.func */
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
            1, 8, 1, /* 274: pointer.struct.ec_method_st */
            	107, 0,
            8884097, 8, 0, /* 279: pointer.func */
            8884097, 8, 0, /* 282: pointer.func */
            1, 8, 1, /* 285: pointer.struct.ec_extra_data_st */
            	55, 0,
            8884097, 8, 0, /* 290: pointer.func */
            8884097, 8, 0, /* 293: pointer.func */
            0, 4, 0, /* 296: int */
            8884097, 8, 0, /* 299: pointer.func */
            1, 8, 1, /* 302: pointer.struct.ec_group_st */
            	307, 0,
            0, 232, 12, /* 307: struct.ec_group_st */
            	274, 0,
            	334, 8,
            	76, 16,
            	76, 40,
            	68, 80,
            	285, 96,
            	76, 104,
            	76, 152,
            	76, 176,
            	18, 208,
            	18, 216,
            	299, 224,
            1, 8, 1, /* 334: pointer.struct.ec_point_st */
            	339, 0,
            0, 88, 4, /* 339: struct.ec_point_st */
            	350, 0,
            	96, 8,
            	96, 32,
            	96, 56,
            1, 8, 1, /* 350: pointer.struct.ec_method_st */
            	355, 0,
            0, 304, 37, /* 355: struct.ec_method_st */
            	432, 8,
            	435, 16,
            	435, 24,
            	438, 32,
            	441, 40,
            	444, 48,
            	447, 56,
            	450, 64,
            	453, 72,
            	456, 80,
            	456, 88,
            	459, 96,
            	462, 104,
            	465, 112,
            	468, 120,
            	279, 128,
            	471, 136,
            	474, 144,
            	290, 152,
            	477, 160,
            	101, 168,
            	480, 176,
            	483, 184,
            	293, 192,
            	93, 200,
            	282, 208,
            	483, 216,
            	90, 224,
            	87, 232,
            	271, 240,
            	447, 248,
            	84, 256,
            	486, 264,
            	84, 272,
            	486, 280,
            	486, 288,
            	81, 296,
            8884097, 8, 0, /* 432: pointer.func */
            8884097, 8, 0, /* 435: pointer.func */
            8884097, 8, 0, /* 438: pointer.func */
            8884097, 8, 0, /* 441: pointer.func */
            8884097, 8, 0, /* 444: pointer.func */
            8884097, 8, 0, /* 447: pointer.func */
            8884097, 8, 0, /* 450: pointer.func */
            8884097, 8, 0, /* 453: pointer.func */
            8884097, 8, 0, /* 456: pointer.func */
            8884097, 8, 0, /* 459: pointer.func */
            8884097, 8, 0, /* 462: pointer.func */
            8884097, 8, 0, /* 465: pointer.func */
            8884097, 8, 0, /* 468: pointer.func */
            8884097, 8, 0, /* 471: pointer.func */
            8884097, 8, 0, /* 474: pointer.func */
            8884097, 8, 0, /* 477: pointer.func */
            8884097, 8, 0, /* 480: pointer.func */
            8884097, 8, 0, /* 483: pointer.func */
            8884097, 8, 0, /* 486: pointer.func */
            1, 8, 1, /* 489: pointer.struct.ec_key_st */
            	494, 0,
            0, 56, 4, /* 494: struct.ec_key_st */
            	302, 8,
            	505, 16,
            	45, 24,
            	27, 48,
            1, 8, 1, /* 505: pointer.struct.ec_point_st */
            	339, 0,
        },
        .arg_entity_index = { 296, },
        .ret_entity_index = 489,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    int new_arg_a = *((int *)new_args->args[0]);

    EC_KEY * *new_ret_ptr = (EC_KEY * *)new_args->ret;

    EC_KEY * (*orig_EC_KEY_new_by_curve_name)(int);
    orig_EC_KEY_new_by_curve_name = dlsym(RTLD_NEXT, "EC_KEY_new_by_curve_name");
    *new_ret_ptr = (*orig_EC_KEY_new_by_curve_name)(new_arg_a);

    syscall(889);

    return ret;
}

