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
            4097, 8, 0, /* 9: pointer.func */
            0, 0, 0, /* 12: func */
            0, 0, 0, /* 15: func */
            4097, 8, 0, /* 18: pointer.func */
            4097, 8, 0, /* 21: pointer.func */
            0, 0, 0, /* 24: func */
            4097, 8, 0, /* 27: pointer.func */
            0, 0, 0, /* 30: func */
            0, 0, 0, /* 33: func */
            1, 8, 1, /* 36: pointer.struct.ec_method_st */
            	41, 0,
            0, 304, 0, /* 41: struct.ec_method_st */
            4097, 8, 0, /* 44: pointer.func */
            0, 0, 0, /* 47: func */
            4097, 8, 0, /* 50: pointer.func */
            4097, 8, 0, /* 53: pointer.func */
            0, 0, 0, /* 56: func */
            1, 8, 1, /* 59: pointer.struct.ec_group_st */
            	64, 0,
            0, 232, 11, /* 64: struct.ec_group_st */
            	36, 0,
            	89, 8,
            	105, 16,
            	105, 40,
            	118, 80,
            	123, 96,
            	105, 104,
            	105, 152,
            	105, 176,
            	118, 208,
            	118, 216,
            1, 8, 1, /* 89: pointer.struct.ec_point_st */
            	94, 0,
            0, 88, 4, /* 94: struct.ec_point_st */
            	36, 0,
            	105, 8,
            	105, 32,
            	105, 56,
            0, 24, 1, /* 105: struct.bignum_st */
            	110, 0,
            1, 8, 1, /* 110: pointer.int */
            	115, 0,
            0, 4, 0, /* 115: int */
            1, 8, 1, /* 118: pointer.char */
            	4096, 0,
            1, 8, 1, /* 123: pointer.struct.ec_extra_data_st */
            	128, 0,
            0, 40, 2, /* 128: struct.ec_extra_data_st */
            	123, 0,
            	118, 8,
            0, 0, 0, /* 135: func */
            4097, 8, 0, /* 138: pointer.func */
            0, 0, 0, /* 141: func */
            4097, 8, 0, /* 144: pointer.func */
            0, 0, 0, /* 147: func */
            4097, 8, 0, /* 150: pointer.func */
            4097, 8, 0, /* 153: pointer.func */
            4097, 8, 0, /* 156: pointer.func */
            4097, 8, 0, /* 159: pointer.func */
            0, 0, 0, /* 162: func */
            0, 0, 0, /* 165: func */
            0, 0, 0, /* 168: func */
            0, 0, 0, /* 171: func */
            0, 0, 0, /* 174: func */
            4097, 8, 0, /* 177: pointer.func */
            0, 0, 0, /* 180: func */
            4097, 8, 0, /* 183: pointer.func */
            0, 0, 0, /* 186: func */
            4097, 8, 0, /* 189: pointer.func */
            0, 0, 0, /* 192: func */
            4097, 8, 0, /* 195: pointer.func */
            4097, 8, 0, /* 198: pointer.func */
            0, 0, 0, /* 201: func */
            4097, 8, 0, /* 204: pointer.func */
            0, 1, 0, /* 207: char */
            4097, 8, 0, /* 210: pointer.func */
            0, 0, 0, /* 213: func */
            0, 0, 0, /* 216: func */
            4097, 8, 0, /* 219: pointer.func */
            0, 0, 0, /* 222: func */
            0, 8, 0, /* 225: long */
            4097, 8, 0, /* 228: pointer.func */
            0, 0, 0, /* 231: func */
            4097, 8, 0, /* 234: pointer.func */
        },
        .arg_entity_index = { 59, },
        .ret_entity_index = 115,
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

