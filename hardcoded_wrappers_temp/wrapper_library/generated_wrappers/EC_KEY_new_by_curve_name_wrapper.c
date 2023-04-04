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
            1, 8, 1, /* 30: pointer.struct.ec_point_st */
            	35, 0,
            0, 88, 4, /* 35: struct.ec_point_st */
            	46, 0,
            	191, 8,
            	191, 32,
            	191, 56,
            1, 8, 1, /* 46: pointer.struct.ec_method_st */
            	51, 0,
            0, 304, 37, /* 51: struct.ec_method_st */
            	128, 8,
            	131, 16,
            	131, 24,
            	134, 32,
            	137, 40,
            	137, 48,
            	128, 56,
            	140, 64,
            	143, 72,
            	146, 80,
            	146, 88,
            	149, 96,
            	152, 104,
            	155, 112,
            	155, 120,
            	158, 128,
            	158, 136,
            	161, 144,
            	164, 152,
            	167, 160,
            	170, 168,
            	173, 176,
            	176, 184,
            	152, 192,
            	176, 200,
            	173, 208,
            	176, 216,
            	179, 224,
            	182, 232,
            	140, 240,
            	128, 248,
            	137, 256,
            	185, 264,
            	137, 272,
            	185, 280,
            	185, 288,
            	188, 296,
            4097, 8, 0, /* 128: pointer.func */
            4097, 8, 0, /* 131: pointer.func */
            4097, 8, 0, /* 134: pointer.func */
            4097, 8, 0, /* 137: pointer.func */
            4097, 8, 0, /* 140: pointer.func */
            4097, 8, 0, /* 143: pointer.func */
            4097, 8, 0, /* 146: pointer.func */
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
            0, 24, 1, /* 191: struct.bignum_st */
            	196, 0,
            1, 8, 1, /* 196: pointer.int */
            	201, 0,
            0, 4, 0, /* 201: int */
            0, 232, 12, /* 204: struct.ec_group_st */
            	46, 0,
            	30, 8,
            	191, 16,
            	191, 40,
            	231, 80,
            	19, 96,
            	191, 104,
            	191, 152,
            	191, 176,
            	231, 208,
            	231, 216,
            	0, 224,
            1, 8, 1, /* 231: pointer.char */
            	4096, 0,
            1, 8, 1, /* 236: pointer.struct.bignum_st */
            	191, 0,
            1, 8, 1, /* 241: pointer.struct.ec_group_st */
            	204, 0,
            0, 56, 4, /* 246: struct.ec_key_st */
            	241, 8,
            	30, 16,
            	236, 24,
            	19, 48,
            0, 1, 0, /* 257: char */
            1, 8, 1, /* 260: pointer.struct.ec_key_st */
            	246, 0,
        },
        .arg_entity_index = { 201, },
        .ret_entity_index = 260,
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

