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

const EC_GROUP * bb_EC_KEY_get0_group(const EC_KEY * arg_a);

const EC_GROUP * EC_KEY_get0_group(const EC_KEY * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EC_KEY_get0_group called %lu\n", in_lib);
    if (!in_lib)
        return bb_EC_KEY_get0_group(arg_a);
    else {
        const EC_GROUP * (*orig_EC_KEY_get0_group)(const EC_KEY *);
        orig_EC_KEY_get0_group = dlsym(RTLD_NEXT, "EC_KEY_get0_group");
        return orig_EC_KEY_get0_group(arg_a);
    }
}

const EC_GROUP * bb_EC_KEY_get0_group(const EC_KEY * arg_a) 
{
    const EC_GROUP * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 56, 4, /* 0: struct.ec_key_st */
            	11, 8,
            	188, 16,
            	252, 24,
            	222, 48,
            1, 8, 1, /* 11: pointer.struct.ec_group_st */
            	16, 0,
            0, 232, 12, /* 16: struct.ec_group_st */
            	43, 0,
            	188, 8,
            	204, 16,
            	204, 40,
            	217, 80,
            	222, 96,
            	204, 104,
            	204, 152,
            	204, 176,
            	217, 208,
            	217, 216,
            	249, 224,
            1, 8, 1, /* 43: pointer.struct.ec_method_st */
            	48, 0,
            0, 304, 37, /* 48: struct.ec_method_st */
            	125, 8,
            	128, 16,
            	128, 24,
            	131, 32,
            	134, 40,
            	134, 48,
            	125, 56,
            	137, 64,
            	140, 72,
            	143, 80,
            	143, 88,
            	146, 96,
            	149, 104,
            	152, 112,
            	152, 120,
            	155, 128,
            	155, 136,
            	158, 144,
            	161, 152,
            	164, 160,
            	167, 168,
            	170, 176,
            	173, 184,
            	149, 192,
            	173, 200,
            	170, 208,
            	173, 216,
            	176, 224,
            	179, 232,
            	137, 240,
            	125, 248,
            	134, 256,
            	182, 264,
            	134, 272,
            	182, 280,
            	182, 288,
            	185, 296,
            4097, 8, 0, /* 125: pointer.func */
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
            1, 8, 1, /* 188: pointer.struct.ec_point_st */
            	193, 0,
            0, 88, 4, /* 193: struct.ec_point_st */
            	43, 0,
            	204, 8,
            	204, 32,
            	204, 56,
            0, 24, 1, /* 204: struct.bignum_st */
            	209, 0,
            1, 8, 1, /* 209: pointer.int */
            	214, 0,
            0, 4, 0, /* 214: int */
            1, 8, 1, /* 217: pointer.char */
            	4096, 0,
            1, 8, 1, /* 222: pointer.struct.ec_extra_data_st */
            	227, 0,
            0, 40, 5, /* 227: struct.ec_extra_data_st */
            	222, 0,
            	240, 8,
            	243, 16,
            	246, 24,
            	246, 32,
            0, 8, 0, /* 240: pointer.void */
            4097, 8, 0, /* 243: pointer.func */
            4097, 8, 0, /* 246: pointer.func */
            4097, 8, 0, /* 249: pointer.func */
            1, 8, 1, /* 252: pointer.struct.bignum_st */
            	204, 0,
            0, 1, 0, /* 257: char */
            1, 8, 1, /* 260: pointer.struct.ec_key_st */
            	0, 0,
        },
        .arg_entity_index = { 260, },
        .ret_entity_index = 11,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const EC_KEY * new_arg_a = *((const EC_KEY * *)new_args->args[0]);

    const EC_GROUP * *new_ret_ptr = (const EC_GROUP * *)new_args->ret;

    const EC_GROUP * (*orig_EC_KEY_get0_group)(const EC_KEY *);
    orig_EC_KEY_get0_group = dlsym(RTLD_NEXT, "EC_KEY_get0_group");
    *new_ret_ptr = (*orig_EC_KEY_get0_group)(new_arg_a);

    syscall(889);

    return ret;
}

