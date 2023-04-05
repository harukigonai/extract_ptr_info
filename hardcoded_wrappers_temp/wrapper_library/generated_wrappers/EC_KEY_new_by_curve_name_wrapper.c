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
            0, 8, 0, /* 6: pointer.void */
            1, 8, 1, /* 9: pointer.struct.ec_extra_data_st */
            	14, 0,
            0, 40, 5, /* 14: struct.ec_extra_data_st */
            	27, 0,
            	6, 8,
            	32, 16,
            	3, 24,
            	3, 32,
            1, 8, 1, /* 27: pointer.struct.ec_extra_data_st */
            	14, 0,
            4097, 8, 0, /* 32: pointer.func */
            0, 4, 0, /* 35: unsigned int */
            1, 8, 1, /* 38: pointer.unsigned int */
            	35, 0,
            0, 24, 1, /* 43: struct.bignum_st */
            	38, 0,
            0, 88, 4, /* 48: struct.ec_point_st */
            	59, 0,
            	43, 8,
            	43, 32,
            	43, 56,
            1, 8, 1, /* 59: pointer.struct.ec_method_st */
            	64, 0,
            0, 304, 37, /* 64: struct.ec_method_st */
            	141, 8,
            	144, 16,
            	144, 24,
            	147, 32,
            	150, 40,
            	153, 48,
            	156, 56,
            	159, 64,
            	162, 72,
            	165, 80,
            	165, 88,
            	168, 96,
            	171, 104,
            	174, 112,
            	177, 120,
            	180, 128,
            	183, 136,
            	186, 144,
            	189, 152,
            	192, 160,
            	195, 168,
            	198, 176,
            	201, 184,
            	204, 192,
            	207, 200,
            	210, 208,
            	201, 216,
            	213, 224,
            	216, 232,
            	219, 240,
            	156, 248,
            	222, 256,
            	225, 264,
            	222, 272,
            	225, 280,
            	225, 288,
            	228, 296,
            4097, 8, 0, /* 141: pointer.func */
            4097, 8, 0, /* 144: pointer.func */
            4097, 8, 0, /* 147: pointer.func */
            4097, 8, 0, /* 150: pointer.func */
            4097, 8, 0, /* 153: pointer.func */
            4097, 8, 0, /* 156: pointer.func */
            4097, 8, 0, /* 159: pointer.func */
            4097, 8, 0, /* 162: pointer.func */
            4097, 8, 0, /* 165: pointer.func */
            4097, 8, 0, /* 168: pointer.func */
            4097, 8, 0, /* 171: pointer.func */
            4097, 8, 0, /* 174: pointer.func */
            4097, 8, 0, /* 177: pointer.func */
            4097, 8, 0, /* 180: pointer.func */
            4097, 8, 0, /* 183: pointer.func */
            4097, 8, 0, /* 186: pointer.func */
            4097, 8, 0, /* 189: pointer.func */
            4097, 8, 0, /* 192: pointer.func */
            4097, 8, 0, /* 195: pointer.func */
            4097, 8, 0, /* 198: pointer.func */
            4097, 8, 0, /* 201: pointer.func */
            4097, 8, 0, /* 204: pointer.func */
            4097, 8, 0, /* 207: pointer.func */
            4097, 8, 0, /* 210: pointer.func */
            4097, 8, 0, /* 213: pointer.func */
            4097, 8, 0, /* 216: pointer.func */
            4097, 8, 0, /* 219: pointer.func */
            4097, 8, 0, /* 222: pointer.func */
            4097, 8, 0, /* 225: pointer.func */
            4097, 8, 0, /* 228: pointer.func */
            1, 8, 1, /* 231: pointer.unsigned char */
            	236, 0,
            0, 1, 0, /* 236: unsigned char */
            1, 8, 1, /* 239: pointer.struct.ec_group_st */
            	244, 0,
            0, 232, 12, /* 244: struct.ec_group_st */
            	59, 0,
            	271, 8,
            	43, 16,
            	43, 40,
            	231, 80,
            	9, 96,
            	43, 104,
            	43, 152,
            	43, 176,
            	6, 208,
            	6, 216,
            	0, 224,
            1, 8, 1, /* 271: pointer.struct.ec_point_st */
            	48, 0,
            0, 56, 4, /* 276: struct.ec_key_st */
            	239, 8,
            	271, 16,
            	287, 24,
            	9, 48,
            1, 8, 1, /* 287: pointer.struct.bignum_st */
            	43, 0,
            1, 8, 1, /* 292: pointer.struct.ec_key_st */
            	276, 0,
            0, 4, 0, /* 297: int */
        },
        .arg_entity_index = { 297, },
        .ret_entity_index = 292,
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

