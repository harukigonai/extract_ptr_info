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
            1, 8, 1, /* 50: pointer.struct.ec_key_st */
            	55, 0,
            0, 56, 4, /* 55: struct.ec_key_st */
            	66, 8,
            	502, 16,
            	45, 24,
            	27, 48,
            1, 8, 1, /* 66: pointer.struct.ec_group_st */
            	71, 0,
            0, 232, 12, /* 71: struct.ec_group_st */
            	98, 0,
            	270, 8,
            	463, 16,
            	463, 40,
            	468, 80,
            	476, 96,
            	463, 104,
            	463, 152,
            	463, 176,
            	18, 208,
            	18, 216,
            	499, 224,
            1, 8, 1, /* 98: pointer.struct.ec_method_st */
            	103, 0,
            0, 304, 37, /* 103: struct.ec_method_st */
            	180, 8,
            	183, 16,
            	183, 24,
            	186, 32,
            	189, 40,
            	192, 48,
            	195, 56,
            	198, 64,
            	201, 72,
            	204, 80,
            	204, 88,
            	207, 96,
            	210, 104,
            	213, 112,
            	216, 120,
            	219, 128,
            	222, 136,
            	225, 144,
            	228, 152,
            	231, 160,
            	234, 168,
            	237, 176,
            	240, 184,
            	243, 192,
            	246, 200,
            	249, 208,
            	240, 216,
            	252, 224,
            	255, 232,
            	258, 240,
            	195, 248,
            	261, 256,
            	264, 264,
            	261, 272,
            	264, 280,
            	264, 288,
            	267, 296,
            8884097, 8, 0, /* 180: pointer.func */
            8884097, 8, 0, /* 183: pointer.func */
            8884097, 8, 0, /* 186: pointer.func */
            8884097, 8, 0, /* 189: pointer.func */
            8884097, 8, 0, /* 192: pointer.func */
            8884097, 8, 0, /* 195: pointer.func */
            8884097, 8, 0, /* 198: pointer.func */
            8884097, 8, 0, /* 201: pointer.func */
            8884097, 8, 0, /* 204: pointer.func */
            8884097, 8, 0, /* 207: pointer.func */
            8884097, 8, 0, /* 210: pointer.func */
            8884097, 8, 0, /* 213: pointer.func */
            8884097, 8, 0, /* 216: pointer.func */
            8884097, 8, 0, /* 219: pointer.func */
            8884097, 8, 0, /* 222: pointer.func */
            8884097, 8, 0, /* 225: pointer.func */
            8884097, 8, 0, /* 228: pointer.func */
            8884097, 8, 0, /* 231: pointer.func */
            8884097, 8, 0, /* 234: pointer.func */
            8884097, 8, 0, /* 237: pointer.func */
            8884097, 8, 0, /* 240: pointer.func */
            8884097, 8, 0, /* 243: pointer.func */
            8884097, 8, 0, /* 246: pointer.func */
            8884097, 8, 0, /* 249: pointer.func */
            8884097, 8, 0, /* 252: pointer.func */
            8884097, 8, 0, /* 255: pointer.func */
            8884097, 8, 0, /* 258: pointer.func */
            8884097, 8, 0, /* 261: pointer.func */
            8884097, 8, 0, /* 264: pointer.func */
            8884097, 8, 0, /* 267: pointer.func */
            1, 8, 1, /* 270: pointer.struct.ec_point_st */
            	275, 0,
            0, 88, 4, /* 275: struct.ec_point_st */
            	286, 0,
            	458, 8,
            	458, 32,
            	458, 56,
            1, 8, 1, /* 286: pointer.struct.ec_method_st */
            	291, 0,
            0, 304, 37, /* 291: struct.ec_method_st */
            	368, 8,
            	371, 16,
            	371, 24,
            	374, 32,
            	377, 40,
            	380, 48,
            	383, 56,
            	386, 64,
            	389, 72,
            	392, 80,
            	392, 88,
            	395, 96,
            	398, 104,
            	401, 112,
            	404, 120,
            	407, 128,
            	410, 136,
            	413, 144,
            	416, 152,
            	419, 160,
            	422, 168,
            	425, 176,
            	428, 184,
            	431, 192,
            	434, 200,
            	437, 208,
            	428, 216,
            	440, 224,
            	443, 232,
            	446, 240,
            	383, 248,
            	449, 256,
            	452, 264,
            	449, 272,
            	452, 280,
            	452, 288,
            	455, 296,
            8884097, 8, 0, /* 368: pointer.func */
            8884097, 8, 0, /* 371: pointer.func */
            8884097, 8, 0, /* 374: pointer.func */
            8884097, 8, 0, /* 377: pointer.func */
            8884097, 8, 0, /* 380: pointer.func */
            8884097, 8, 0, /* 383: pointer.func */
            8884097, 8, 0, /* 386: pointer.func */
            8884097, 8, 0, /* 389: pointer.func */
            8884097, 8, 0, /* 392: pointer.func */
            8884097, 8, 0, /* 395: pointer.func */
            8884097, 8, 0, /* 398: pointer.func */
            8884097, 8, 0, /* 401: pointer.func */
            8884097, 8, 0, /* 404: pointer.func */
            8884097, 8, 0, /* 407: pointer.func */
            8884097, 8, 0, /* 410: pointer.func */
            8884097, 8, 0, /* 413: pointer.func */
            8884097, 8, 0, /* 416: pointer.func */
            8884097, 8, 0, /* 419: pointer.func */
            8884097, 8, 0, /* 422: pointer.func */
            8884097, 8, 0, /* 425: pointer.func */
            8884097, 8, 0, /* 428: pointer.func */
            8884097, 8, 0, /* 431: pointer.func */
            8884097, 8, 0, /* 434: pointer.func */
            8884097, 8, 0, /* 437: pointer.func */
            8884097, 8, 0, /* 440: pointer.func */
            8884097, 8, 0, /* 443: pointer.func */
            8884097, 8, 0, /* 446: pointer.func */
            8884097, 8, 0, /* 449: pointer.func */
            8884097, 8, 0, /* 452: pointer.func */
            8884097, 8, 0, /* 455: pointer.func */
            0, 24, 1, /* 458: struct.bignum_st */
            	37, 0,
            0, 24, 1, /* 463: struct.bignum_st */
            	37, 0,
            1, 8, 1, /* 468: pointer.unsigned char */
            	473, 0,
            0, 1, 0, /* 473: unsigned char */
            1, 8, 1, /* 476: pointer.struct.ec_extra_data_st */
            	481, 0,
            0, 40, 5, /* 481: struct.ec_extra_data_st */
            	494, 0,
            	18, 8,
            	21, 16,
            	24, 24,
            	24, 32,
            1, 8, 1, /* 494: pointer.struct.ec_extra_data_st */
            	481, 0,
            8884097, 8, 0, /* 499: pointer.func */
            1, 8, 1, /* 502: pointer.struct.ec_point_st */
            	275, 0,
            1, 8, 1, /* 507: pointer.struct.ec_group_st */
            	71, 0,
        },
        .arg_entity_index = { 50, },
        .ret_entity_index = 507,
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

