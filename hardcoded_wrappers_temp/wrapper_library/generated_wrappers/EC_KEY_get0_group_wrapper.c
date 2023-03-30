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
    printf("EC_KEY_get0_group called\n");
    if (!syscall(890))
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
            1, 8, 1, /* 0: pointer.struct.bignum_st */
            	5, 0,
            0, 24, 1, /* 5: struct.bignum_st */
            	10, 0,
            1, 8, 1, /* 10: pointer.int */
            	15, 0,
            0, 4, 0, /* 15: int */
            0, 56, 4, /* 18: struct.ec_key_st.284 */
            	29, 8,
            	67, 16,
            	0, 24,
            	91, 48,
            1, 8, 1, /* 29: pointer.struct.ec_group_st */
            	34, 0,
            0, 232, 11, /* 34: struct.ec_group_st */
            	59, 0,
            	67, 8,
            	5, 16,
            	5, 40,
            	83, 80,
            	91, 96,
            	5, 104,
            	5, 152,
            	5, 176,
            	83, 208,
            	83, 216,
            1, 8, 1, /* 59: pointer.struct.ec_method_st */
            	64, 0,
            0, 304, 0, /* 64: struct.ec_method_st */
            1, 8, 1, /* 67: pointer.struct.ec_point_st */
            	72, 0,
            0, 88, 4, /* 72: struct.ec_point_st */
            	59, 0,
            	5, 8,
            	5, 32,
            	5, 56,
            1, 8, 1, /* 83: pointer.char */
            	88, 0,
            0, 1, 0, /* 88: char */
            1, 8, 1, /* 91: pointer.struct.ec_extra_data_st */
            	96, 0,
            0, 40, 2, /* 96: struct.ec_extra_data_st */
            	91, 0,
            	83, 8,
            0, 0, 0, /* 103: func */
            0, 8, 0, /* 106: pointer.func */
            0, 0, 0, /* 109: func */
            0, 8, 0, /* 112: pointer.func */
            0, 0, 0, /* 115: func */
            0, 0, 0, /* 118: func */
            0, 8, 0, /* 121: pointer.func */
            0, 0, 0, /* 124: func */
            0, 8, 0, /* 127: pointer.func */
            0, 8, 0, /* 130: pointer.func */
            0, 0, 0, /* 133: func */
            0, 0, 0, /* 136: func */
            0, 8, 0, /* 139: pointer.func */
            0, 8, 0, /* 142: pointer.func */
            0, 0, 0, /* 145: func */
            0, 0, 0, /* 148: func */
            0, 8, 0, /* 151: pointer.func */
            0, 8, 0, /* 154: pointer.func */
            0, 8, 0, /* 157: pointer.func */
            1, 8, 1, /* 160: pointer.struct.ec_key_st.284 */
            	18, 0,
            0, 8, 0, /* 165: pointer.func */
            0, 8, 0, /* 168: pointer.func */
            0, 0, 0, /* 171: func */
            0, 0, 0, /* 174: func */
            0, 8, 0, /* 177: pointer.func */
            0, 0, 0, /* 180: func */
            0, 0, 0, /* 183: func */
            0, 8, 0, /* 186: pointer.func */
            0, 0, 0, /* 189: func */
            0, 8, 0, /* 192: pointer.func */
            0, 8, 0, /* 195: pointer.func */
            0, 0, 0, /* 198: func */
            0, 8, 0, /* 201: pointer.func */
            0, 8, 0, /* 204: pointer.func */
            0, 0, 0, /* 207: func */
            0, 8, 0, /* 210: pointer.func */
            0, 24, 0, /* 213: array[6].int */
            0, 0, 0, /* 216: func */
            0, 8, 0, /* 219: pointer.func */
            0, 8, 0, /* 222: pointer.func */
            0, 8, 0, /* 225: long */
            0, 0, 0, /* 228: func */
            0, 0, 0, /* 231: func */
            0, 8, 0, /* 234: pointer.func */
            0, 8, 0, /* 237: pointer.func */
            0, 0, 0, /* 240: func */
            0, 0, 0, /* 243: func */
            0, 0, 0, /* 246: func */
            0, 8, 0, /* 249: pointer.func */
            0, 0, 0, /* 252: func */
            0, 0, 0, /* 255: func */
        },
        .arg_entity_index = { 160, },
        .ret_entity_index = 29,
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

