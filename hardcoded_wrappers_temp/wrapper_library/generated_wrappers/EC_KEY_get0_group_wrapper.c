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
            1, 8, 1, /* 0: pointer.struct.ec_group_st */
            	5, 0,
            0, 232, 12, /* 5: struct.ec_group_st */
            	32, 0,
            	204, 8,
            	220, 16,
            	220, 40,
            	233, 80,
            	241, 96,
            	220, 104,
            	220, 152,
            	220, 176,
            	264, 208,
            	264, 216,
            	273, 224,
            1, 8, 1, /* 32: pointer.struct.ec_method_st */
            	37, 0,
            0, 304, 37, /* 37: struct.ec_method_st */
            	114, 8,
            	117, 16,
            	117, 24,
            	120, 32,
            	123, 40,
            	126, 48,
            	129, 56,
            	132, 64,
            	135, 72,
            	138, 80,
            	138, 88,
            	141, 96,
            	144, 104,
            	147, 112,
            	150, 120,
            	153, 128,
            	156, 136,
            	159, 144,
            	162, 152,
            	165, 160,
            	168, 168,
            	171, 176,
            	174, 184,
            	177, 192,
            	180, 200,
            	183, 208,
            	174, 216,
            	186, 224,
            	189, 232,
            	192, 240,
            	129, 248,
            	195, 256,
            	198, 264,
            	195, 272,
            	198, 280,
            	198, 288,
            	201, 296,
            64097, 8, 0, /* 114: pointer.func */
            64097, 8, 0, /* 117: pointer.func */
            64097, 8, 0, /* 120: pointer.func */
            64097, 8, 0, /* 123: pointer.func */
            64097, 8, 0, /* 126: pointer.func */
            64097, 8, 0, /* 129: pointer.func */
            64097, 8, 0, /* 132: pointer.func */
            64097, 8, 0, /* 135: pointer.func */
            64097, 8, 0, /* 138: pointer.func */
            64097, 8, 0, /* 141: pointer.func */
            64097, 8, 0, /* 144: pointer.func */
            64097, 8, 0, /* 147: pointer.func */
            64097, 8, 0, /* 150: pointer.func */
            64097, 8, 0, /* 153: pointer.func */
            64097, 8, 0, /* 156: pointer.func */
            64097, 8, 0, /* 159: pointer.func */
            64097, 8, 0, /* 162: pointer.func */
            64097, 8, 0, /* 165: pointer.func */
            64097, 8, 0, /* 168: pointer.func */
            64097, 8, 0, /* 171: pointer.func */
            64097, 8, 0, /* 174: pointer.func */
            64097, 8, 0, /* 177: pointer.func */
            64097, 8, 0, /* 180: pointer.func */
            64097, 8, 0, /* 183: pointer.func */
            64097, 8, 0, /* 186: pointer.func */
            64097, 8, 0, /* 189: pointer.func */
            64097, 8, 0, /* 192: pointer.func */
            64097, 8, 0, /* 195: pointer.func */
            64097, 8, 0, /* 198: pointer.func */
            64097, 8, 0, /* 201: pointer.func */
            1, 8, 1, /* 204: pointer.struct.ec_point_st */
            	209, 0,
            0, 88, 4, /* 209: struct.ec_point_st */
            	32, 0,
            	220, 8,
            	220, 32,
            	220, 56,
            0, 24, 1, /* 220: struct.bignum_st */
            	225, 0,
            1, 8, 1, /* 225: pointer.unsigned int */
            	230, 0,
            0, 4, 0, /* 230: unsigned int */
            1, 8, 1, /* 233: pointer.unsigned char */
            	238, 0,
            0, 1, 0, /* 238: unsigned char */
            1, 8, 1, /* 241: pointer.struct.ec_extra_data_st */
            	246, 0,
            0, 40, 5, /* 246: struct.ec_extra_data_st */
            	259, 0,
            	264, 8,
            	267, 16,
            	270, 24,
            	270, 32,
            1, 8, 1, /* 259: pointer.struct.ec_extra_data_st */
            	246, 0,
            0, 8, 0, /* 264: pointer.void */
            64097, 8, 0, /* 267: pointer.func */
            64097, 8, 0, /* 270: pointer.func */
            64097, 8, 0, /* 273: pointer.func */
            0, 56, 4, /* 276: struct.ec_key_st */
            	0, 8,
            	204, 16,
            	287, 24,
            	241, 48,
            1, 8, 1, /* 287: pointer.struct.bignum_st */
            	220, 0,
            1, 8, 1, /* 292: pointer.struct.ec_key_st */
            	276, 0,
            1, 8, 1, /* 297: pointer.struct.ec_group_st */
            	5, 0,
        },
        .arg_entity_index = { 292, },
        .ret_entity_index = 297,
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

