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
            0, 8, 0, /* 0: pointer.void */
            0, 56, 4, /* 3: struct.ec_key_st */
            	14, 8,
            	191, 16,
            	252, 24,
            	225, 48,
            0, 8, 1, /* 14: pointer.struct.ec_group_st */
            	19, 0,
            0, 232, 12, /* 19: struct.ec_group_st */
            	46, 0,
            	191, 8,
            	207, 16,
            	207, 40,
            	220, 80,
            	225, 96,
            	207, 104,
            	207, 152,
            	207, 176,
            	0, 208,
            	0, 216,
            	249, 224,
            0, 8, 1, /* 46: pointer.struct.ec_method_st */
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
            0, 8, 1, /* 191: pointer.struct.ec_point_st */
            	196, 0,
            0, 88, 4, /* 196: struct.ec_point_st */
            	46, 0,
            	207, 8,
            	207, 32,
            	207, 56,
            0, 24, 1, /* 207: struct.bignum_st */
            	212, 0,
            0, 8, 1, /* 212: pointer.int */
            	217, 0,
            0, 4, 0, /* 217: int */
            0, 8, 1, /* 220: pointer.char */
            	4096, 0,
            0, 8, 1, /* 225: pointer.struct.ec_extra_data_st */
            	230, 0,
            0, 40, 5, /* 230: struct.ec_extra_data_st */
            	225, 0,
            	0, 8,
            	243, 16,
            	246, 24,
            	246, 32,
            4097, 8, 0, /* 243: pointer.func */
            4097, 8, 0, /* 246: pointer.func */
            4097, 8, 0, /* 249: pointer.func */
            0, 8, 1, /* 252: pointer.struct.bignum_st */
            	207, 0,
            0, 8, 1, /* 257: pointer.struct.ec_key_st */
            	3, 0,
            0, 0, 0, /* 262: func */
            0, 24, 0, /* 265: array[6].int */
            0, 0, 0, /* 268: func */
            0, 0, 0, /* 271: func */
            0, 0, 0, /* 274: func */
            0, 0, 0, /* 277: func */
            0, 0, 0, /* 280: func */
            0, 0, 0, /* 283: func */
            0, 0, 0, /* 286: func */
            0, 0, 0, /* 289: func */
            0, 0, 0, /* 292: func */
            0, 0, 0, /* 295: func */
            0, 0, 0, /* 298: func */
            0, 0, 0, /* 301: func */
            0, 0, 0, /* 304: func */
            0, 0, 0, /* 307: func */
            0, 0, 0, /* 310: func */
            0, 0, 0, /* 313: func */
            0, 8, 0, /* 316: long */
            0, 0, 0, /* 319: func */
            0, 0, 0, /* 322: func */
            0, 1, 0, /* 325: char */
            0, 0, 0, /* 328: func */
            0, 0, 0, /* 331: func */
            0, 0, 0, /* 334: func */
            0, 0, 0, /* 337: func */
            0, 0, 0, /* 340: func */
        },
        .arg_entity_index = { 257, },
        .ret_entity_index = 14,
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

