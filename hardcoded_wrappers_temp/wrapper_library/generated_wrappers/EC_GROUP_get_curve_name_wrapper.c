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
            0, 0, 0, /* 0: func */
            4097, 8, 0, /* 3: pointer.func */
            0, 24, 0, /* 6: array[6].int */
            0, 0, 0, /* 9: func */
            1, 8, 1, /* 12: pointer.int */
            	17, 0,
            0, 4, 0, /* 17: int */
            4097, 8, 0, /* 20: pointer.func */
            4097, 8, 0, /* 23: pointer.func */
            4097, 8, 0, /* 26: pointer.func */
            0, 0, 0, /* 29: func */
            0, 0, 0, /* 32: func */
            0, 0, 0, /* 35: func */
            4097, 8, 0, /* 38: pointer.func */
            0, 0, 0, /* 41: func */
            4097, 8, 0, /* 44: pointer.func */
            4097, 8, 0, /* 47: pointer.func */
            0, 8, 0, /* 50: pointer.void */
            4097, 8, 0, /* 53: pointer.func */
            0, 24, 1, /* 56: struct.bignum_st */
            	12, 0,
            0, 0, 0, /* 61: func */
            0, 0, 0, /* 64: func */
            1, 8, 1, /* 67: pointer.struct.ec_group_st */
            	72, 0,
            0, 232, 12, /* 72: struct.ec_group_st */
            	99, 0,
            	226, 8,
            	56, 16,
            	56, 40,
            	242, 80,
            	247, 96,
            	56, 104,
            	56, 152,
            	56, 176,
            	50, 208,
            	50, 216,
            	3, 224,
            1, 8, 1, /* 99: pointer.struct.ec_method_st */
            	104, 0,
            0, 304, 37, /* 104: struct.ec_method_st */
            	181, 8,
            	184, 16,
            	184, 24,
            	187, 32,
            	190, 40,
            	190, 48,
            	181, 56,
            	44, 64,
            	26, 72,
            	20, 80,
            	20, 88,
            	47, 96,
            	193, 104,
            	196, 112,
            	196, 120,
            	23, 128,
            	23, 136,
            	199, 144,
            	202, 152,
            	205, 160,
            	208, 168,
            	211, 176,
            	53, 184,
            	193, 192,
            	53, 200,
            	211, 208,
            	53, 216,
            	214, 224,
            	217, 232,
            	44, 240,
            	181, 248,
            	190, 256,
            	220, 264,
            	190, 272,
            	220, 280,
            	220, 288,
            	223, 296,
            4097, 8, 0, /* 181: pointer.func */
            4097, 8, 0, /* 184: pointer.func */
            4097, 8, 0, /* 187: pointer.func */
            4097, 8, 0, /* 190: pointer.func */
            4097, 8, 0, /* 193: pointer.func */
            4097, 8, 0, /* 196: pointer.func */
            4097, 8, 0, /* 199: pointer.func */
            4097, 8, 0, /* 202: pointer.func */
            4097, 8, 0, /* 205: pointer.func */
            4097, 8, 0, /* 208: pointer.func */
            4097, 8, 0, /* 211: pointer.func */
            4097, 8, 0, /* 214: pointer.func */
            4097, 8, 0, /* 217: pointer.func */
            4097, 8, 0, /* 220: pointer.func */
            4097, 8, 0, /* 223: pointer.func */
            1, 8, 1, /* 226: pointer.struct.ec_point_st */
            	231, 0,
            0, 88, 4, /* 231: struct.ec_point_st */
            	99, 0,
            	56, 8,
            	56, 32,
            	56, 56,
            1, 8, 1, /* 242: pointer.char */
            	4096, 0,
            1, 8, 1, /* 247: pointer.struct.ec_extra_data_st */
            	252, 0,
            0, 40, 5, /* 252: struct.ec_extra_data_st */
            	247, 0,
            	50, 8,
            	265, 16,
            	38, 24,
            	38, 32,
            4097, 8, 0, /* 265: pointer.func */
            0, 0, 0, /* 268: func */
            0, 0, 0, /* 271: func */
            0, 0, 0, /* 274: func */
            0, 0, 0, /* 277: func */
            0, 0, 0, /* 280: func */
            0, 0, 0, /* 283: func */
            0, 0, 0, /* 286: func */
            0, 0, 0, /* 289: func */
            0, 0, 0, /* 292: func */
            0, 8, 0, /* 295: long */
            0, 0, 0, /* 298: func */
            0, 0, 0, /* 301: func */
            0, 1, 0, /* 304: char */
            0, 0, 0, /* 307: func */
            0, 0, 0, /* 310: func */
            0, 0, 0, /* 313: func */
            0, 0, 0, /* 316: func */
            0, 0, 0, /* 319: func */
        },
        .arg_entity_index = { 67, },
        .ret_entity_index = 17,
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

