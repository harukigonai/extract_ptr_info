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
            4097, 8, 0, /* 0: pointer.func */
            4097, 8, 0, /* 3: pointer.func */
            0, 40, 5, /* 6: struct.ec_extra_data_st */
            	19, 0,
            	24, 8,
            	27, 16,
            	3, 24,
            	3, 32,
            1, 8, 1, /* 19: pointer.struct.ec_extra_data_st */
            	6, 0,
            0, 8, 0, /* 24: pointer.void */
            4097, 8, 0, /* 27: pointer.func */
            4097, 8, 0, /* 30: pointer.func */
            0, 1, 0, /* 33: char */
            4097, 8, 0, /* 36: pointer.func */
            4097, 8, 0, /* 39: pointer.func */
            4097, 8, 0, /* 42: pointer.func */
            4097, 8, 0, /* 45: pointer.func */
            4097, 8, 0, /* 48: pointer.func */
            1, 8, 1, /* 51: pointer.struct.ec_point_st */
            	56, 0,
            0, 88, 4, /* 56: struct.ec_point_st */
            	67, 0,
            	194, 8,
            	194, 32,
            	194, 56,
            1, 8, 1, /* 67: pointer.struct.ec_method_st */
            	72, 0,
            0, 304, 37, /* 72: struct.ec_method_st */
            	149, 8,
            	45, 16,
            	45, 24,
            	152, 32,
            	39, 40,
            	39, 48,
            	149, 56,
            	155, 64,
            	158, 72,
            	30, 80,
            	30, 88,
            	161, 96,
            	164, 104,
            	167, 112,
            	167, 120,
            	170, 128,
            	170, 136,
            	48, 144,
            	173, 152,
            	176, 160,
            	179, 168,
            	36, 176,
            	182, 184,
            	164, 192,
            	182, 200,
            	36, 208,
            	182, 216,
            	42, 224,
            	185, 232,
            	155, 240,
            	149, 248,
            	39, 256,
            	188, 264,
            	39, 272,
            	188, 280,
            	188, 288,
            	191, 296,
            4097, 8, 0, /* 149: pointer.func */
            4097, 8, 0, /* 152: pointer.func */
            4097, 8, 0, /* 155: pointer.func */
            4097, 8, 0, /* 158: pointer.func */
            4097, 8, 0, /* 161: pointer.func */
            4097, 8, 0, /* 164: pointer.func */
            4097, 8, 0, /* 167: pointer.func */
            4097, 8, 0, /* 170: pointer.func */
            4097, 8, 0, /* 173: pointer.func */
            4097, 8, 0, /* 176: pointer.func */
            4097, 8, 0, /* 179: pointer.func */
            4097, 8, 0, /* 182: pointer.func */
            4097, 8, 0, /* 185: pointer.func */
            4097, 8, 0, /* 188: pointer.func */
            4097, 8, 0, /* 191: pointer.func */
            0, 24, 1, /* 194: struct.bignum_st */
            	199, 0,
            1, 8, 1, /* 199: pointer.int */
            	204, 0,
            0, 4, 0, /* 204: int */
            1, 8, 1, /* 207: pointer.char */
            	4096, 0,
            0, 232, 12, /* 212: struct.ec_group_st */
            	67, 0,
            	51, 8,
            	194, 16,
            	194, 40,
            	207, 80,
            	19, 96,
            	194, 104,
            	194, 152,
            	194, 176,
            	207, 208,
            	207, 216,
            	0, 224,
            1, 8, 1, /* 239: pointer.struct.ec_group_st */
            	212, 0,
        },
        .arg_entity_index = { 239, },
        .ret_entity_index = 204,
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

