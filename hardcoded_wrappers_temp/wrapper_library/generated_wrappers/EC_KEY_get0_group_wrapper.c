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
            1, 8, 1, /* 0: pointer.struct.ec_extra_data_st */
            	5, 0,
            0, 40, 5, /* 5: struct.ec_extra_data_st */
            	0, 0,
            	18, 8,
            	21, 16,
            	24, 24,
            	24, 32,
            0, 8, 0, /* 18: pointer.void */
            8884097, 8, 0, /* 21: pointer.func */
            8884097, 8, 0, /* 24: pointer.func */
            1, 8, 1, /* 27: pointer.struct.ec_group_st */
            	32, 0,
            0, 232, 12, /* 32: struct.ec_group_st */
            	59, 0,
            	231, 8,
            	437, 16,
            	437, 40,
            	449, 80,
            	457, 96,
            	437, 104,
            	437, 152,
            	437, 176,
            	18, 208,
            	18, 216,
            	480, 224,
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
            8884097, 8, 0, /* 141: pointer.func */
            8884097, 8, 0, /* 144: pointer.func */
            8884097, 8, 0, /* 147: pointer.func */
            8884097, 8, 0, /* 150: pointer.func */
            8884097, 8, 0, /* 153: pointer.func */
            8884097, 8, 0, /* 156: pointer.func */
            8884097, 8, 0, /* 159: pointer.func */
            8884097, 8, 0, /* 162: pointer.func */
            8884097, 8, 0, /* 165: pointer.func */
            8884097, 8, 0, /* 168: pointer.func */
            8884097, 8, 0, /* 171: pointer.func */
            8884097, 8, 0, /* 174: pointer.func */
            8884097, 8, 0, /* 177: pointer.func */
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
            1, 8, 1, /* 231: pointer.struct.ec_point_st */
            	236, 0,
            0, 88, 4, /* 236: struct.ec_point_st */
            	247, 0,
            	419, 8,
            	419, 32,
            	419, 56,
            1, 8, 1, /* 247: pointer.struct.ec_method_st */
            	252, 0,
            0, 304, 37, /* 252: struct.ec_method_st */
            	329, 8,
            	332, 16,
            	332, 24,
            	335, 32,
            	338, 40,
            	341, 48,
            	344, 56,
            	347, 64,
            	350, 72,
            	353, 80,
            	353, 88,
            	356, 96,
            	359, 104,
            	362, 112,
            	365, 120,
            	368, 128,
            	371, 136,
            	374, 144,
            	377, 152,
            	380, 160,
            	383, 168,
            	386, 176,
            	389, 184,
            	392, 192,
            	395, 200,
            	398, 208,
            	389, 216,
            	401, 224,
            	404, 232,
            	407, 240,
            	344, 248,
            	410, 256,
            	413, 264,
            	410, 272,
            	413, 280,
            	413, 288,
            	416, 296,
            8884097, 8, 0, /* 329: pointer.func */
            8884097, 8, 0, /* 332: pointer.func */
            8884097, 8, 0, /* 335: pointer.func */
            8884097, 8, 0, /* 338: pointer.func */
            8884097, 8, 0, /* 341: pointer.func */
            8884097, 8, 0, /* 344: pointer.func */
            8884097, 8, 0, /* 347: pointer.func */
            8884097, 8, 0, /* 350: pointer.func */
            8884097, 8, 0, /* 353: pointer.func */
            8884097, 8, 0, /* 356: pointer.func */
            8884097, 8, 0, /* 359: pointer.func */
            8884097, 8, 0, /* 362: pointer.func */
            8884097, 8, 0, /* 365: pointer.func */
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
            0, 24, 1, /* 419: struct.bignum_st */
            	424, 0,
            8884099, 8, 2, /* 424: pointer_to_array_of_pointers_to_stack */
            	431, 0,
            	434, 12,
            0, 4, 0, /* 431: unsigned int */
            0, 4, 0, /* 434: int */
            0, 24, 1, /* 437: struct.bignum_st */
            	442, 0,
            8884099, 8, 2, /* 442: pointer_to_array_of_pointers_to_stack */
            	431, 0,
            	434, 12,
            1, 8, 1, /* 449: pointer.unsigned char */
            	454, 0,
            0, 1, 0, /* 454: unsigned char */
            1, 8, 1, /* 457: pointer.struct.ec_extra_data_st */
            	462, 0,
            0, 40, 5, /* 462: struct.ec_extra_data_st */
            	475, 0,
            	18, 8,
            	21, 16,
            	24, 24,
            	24, 32,
            1, 8, 1, /* 475: pointer.struct.ec_extra_data_st */
            	462, 0,
            8884097, 8, 0, /* 480: pointer.func */
            0, 56, 4, /* 483: struct.ec_key_st */
            	27, 8,
            	494, 16,
            	499, 24,
            	516, 48,
            1, 8, 1, /* 494: pointer.struct.ec_point_st */
            	236, 0,
            1, 8, 1, /* 499: pointer.struct.bignum_st */
            	504, 0,
            0, 24, 1, /* 504: struct.bignum_st */
            	509, 0,
            8884099, 8, 2, /* 509: pointer_to_array_of_pointers_to_stack */
            	431, 0,
            	434, 12,
            1, 8, 1, /* 516: pointer.struct.ec_extra_data_st */
            	5, 0,
            1, 8, 1, /* 521: pointer.struct.ec_key_st */
            	483, 0,
            1, 8, 1, /* 526: pointer.struct.ec_group_st */
            	32, 0,
        },
        .arg_entity_index = { 521, },
        .ret_entity_index = 526,
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

