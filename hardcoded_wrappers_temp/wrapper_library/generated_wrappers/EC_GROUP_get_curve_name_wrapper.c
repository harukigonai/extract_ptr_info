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
            0, 8, 0, /* 0: pointer.void */
            0, 40, 5, /* 3: struct.ec_extra_data_st */
            	16, 0,
            	0, 8,
            	21, 16,
            	24, 24,
            	24, 32,
            1, 8, 1, /* 16: pointer.struct.ec_extra_data_st */
            	3, 0,
            64097, 8, 0, /* 21: pointer.func */
            64097, 8, 0, /* 24: pointer.func */
            0, 1, 0, /* 27: unsigned char */
            0, 24, 1, /* 30: struct.bignum_st */
            	35, 0,
            1, 8, 1, /* 35: pointer.unsigned int */
            	40, 0,
            0, 4, 0, /* 40: unsigned int */
            0, 88, 4, /* 43: struct.ec_point_st */
            	54, 0,
            	30, 8,
            	30, 32,
            	30, 56,
            1, 8, 1, /* 54: pointer.struct.ec_method_st */
            	59, 0,
            0, 304, 37, /* 59: struct.ec_method_st */
            	136, 8,
            	139, 16,
            	139, 24,
            	142, 32,
            	145, 40,
            	148, 48,
            	151, 56,
            	154, 64,
            	157, 72,
            	160, 80,
            	160, 88,
            	163, 96,
            	166, 104,
            	169, 112,
            	172, 120,
            	175, 128,
            	178, 136,
            	181, 144,
            	184, 152,
            	187, 160,
            	190, 168,
            	193, 176,
            	196, 184,
            	199, 192,
            	202, 200,
            	205, 208,
            	196, 216,
            	208, 224,
            	211, 232,
            	214, 240,
            	151, 248,
            	217, 256,
            	220, 264,
            	217, 272,
            	220, 280,
            	220, 288,
            	223, 296,
            64097, 8, 0, /* 136: pointer.func */
            64097, 8, 0, /* 139: pointer.func */
            64097, 8, 0, /* 142: pointer.func */
            64097, 8, 0, /* 145: pointer.func */
            64097, 8, 0, /* 148: pointer.func */
            64097, 8, 0, /* 151: pointer.func */
            64097, 8, 0, /* 154: pointer.func */
            64097, 8, 0, /* 157: pointer.func */
            64097, 8, 0, /* 160: pointer.func */
            64097, 8, 0, /* 163: pointer.func */
            64097, 8, 0, /* 166: pointer.func */
            64097, 8, 0, /* 169: pointer.func */
            64097, 8, 0, /* 172: pointer.func */
            64097, 8, 0, /* 175: pointer.func */
            64097, 8, 0, /* 178: pointer.func */
            64097, 8, 0, /* 181: pointer.func */
            64097, 8, 0, /* 184: pointer.func */
            64097, 8, 0, /* 187: pointer.func */
            64097, 8, 0, /* 190: pointer.func */
            64097, 8, 0, /* 193: pointer.func */
            64097, 8, 0, /* 196: pointer.func */
            64097, 8, 0, /* 199: pointer.func */
            64097, 8, 0, /* 202: pointer.func */
            64097, 8, 0, /* 205: pointer.func */
            64097, 8, 0, /* 208: pointer.func */
            64097, 8, 0, /* 211: pointer.func */
            64097, 8, 0, /* 214: pointer.func */
            64097, 8, 0, /* 217: pointer.func */
            64097, 8, 0, /* 220: pointer.func */
            64097, 8, 0, /* 223: pointer.func */
            1, 8, 1, /* 226: pointer.struct.ec_point_st */
            	43, 0,
            1, 8, 1, /* 231: pointer.struct.ec_extra_data_st */
            	3, 0,
            0, 4, 0, /* 236: int */
            1, 8, 1, /* 239: pointer.unsigned char */
            	27, 0,
            0, 232, 12, /* 244: struct.ec_group_st */
            	54, 0,
            	226, 8,
            	30, 16,
            	30, 40,
            	239, 80,
            	231, 96,
            	30, 104,
            	30, 152,
            	30, 176,
            	0, 208,
            	0, 216,
            	271, 224,
            64097, 8, 0, /* 271: pointer.func */
            1, 8, 1, /* 274: pointer.struct.ec_group_st */
            	244, 0,
        },
        .arg_entity_index = { 274, },
        .ret_entity_index = 236,
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

