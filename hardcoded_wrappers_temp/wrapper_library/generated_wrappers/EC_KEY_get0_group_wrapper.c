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
            0, 56, 4, /* 0: struct.ec_key_st.284 */
            	11, 8,
            	49, 16,
            	95, 24,
            	83, 48,
            1, 8, 1, /* 11: pointer.struct.ec_group_st */
            	16, 0,
            0, 232, 11, /* 16: struct.ec_group_st */
            	41, 0,
            	49, 8,
            	65, 16,
            	65, 40,
            	78, 80,
            	83, 96,
            	65, 104,
            	65, 152,
            	65, 176,
            	78, 208,
            	78, 216,
            1, 8, 1, /* 41: pointer.struct.ec_method_st */
            	46, 0,
            0, 304, 0, /* 46: struct.ec_method_st */
            1, 8, 1, /* 49: pointer.struct.ec_point_st */
            	54, 0,
            0, 88, 4, /* 54: struct.ec_point_st */
            	41, 0,
            	65, 8,
            	65, 32,
            	65, 56,
            0, 24, 1, /* 65: struct.bignum_st */
            	70, 0,
            1, 8, 1, /* 70: pointer.int */
            	75, 0,
            0, 4, 0, /* 75: int */
            1, 8, 1, /* 78: pointer.char */
            	4096, 0,
            1, 8, 1, /* 83: pointer.struct.ec_extra_data_st */
            	88, 0,
            0, 40, 2, /* 88: struct.ec_extra_data_st */
            	83, 0,
            	78, 8,
            1, 8, 1, /* 95: pointer.struct.bignum_st */
            	65, 0,
            1, 8, 1, /* 100: pointer.struct.ec_key_st.284 */
            	0, 0,
            0, 0, 0, /* 105: func */
            4097, 0, 0, /* 108: pointer.func */
            0, 24, 0, /* 111: array[6].int */
            4097, 0, 0, /* 114: pointer.func */
            0, 0, 0, /* 117: func */
            0, 0, 0, /* 120: func */
            4097, 0, 0, /* 123: pointer.func */
            4097, 0, 0, /* 126: pointer.func */
            0, 0, 0, /* 129: func */
            4097, 0, 0, /* 132: pointer.func */
            0, 0, 0, /* 135: func */
            0, 0, 0, /* 138: func */
            4097, 0, 0, /* 141: pointer.func */
            0, 0, 0, /* 144: func */
            0, 0, 0, /* 147: func */
            4097, 0, 0, /* 150: pointer.func */
            0, 0, 0, /* 153: func */
            4097, 0, 0, /* 156: pointer.func */
            4097, 0, 0, /* 159: pointer.func */
            4097, 0, 0, /* 162: pointer.func */
            0, 0, 0, /* 165: func */
            0, 0, 0, /* 168: func */
            4097, 0, 0, /* 171: pointer.func */
            4097, 0, 0, /* 174: pointer.func */
            4097, 0, 0, /* 177: pointer.func */
            4097, 0, 0, /* 180: pointer.func */
            0, 0, 0, /* 183: func */
            0, 0, 0, /* 186: func */
            0, 0, 0, /* 189: func */
            0, 0, 0, /* 192: func */
            0, 0, 0, /* 195: func */
            4097, 0, 0, /* 198: pointer.func */
            0, 0, 0, /* 201: func */
            4097, 0, 0, /* 204: pointer.func */
            0, 0, 0, /* 207: func */
            4097, 0, 0, /* 210: pointer.func */
            0, 0, 0, /* 213: func */
            4097, 0, 0, /* 216: pointer.func */
            4097, 0, 0, /* 219: pointer.func */
            0, 0, 0, /* 222: func */
            4097, 0, 0, /* 225: pointer.func */
            0, 1, 0, /* 228: char */
            4097, 0, 0, /* 231: pointer.func */
            0, 0, 0, /* 234: func */
            0, 0, 0, /* 237: func */
            4097, 0, 0, /* 240: pointer.func */
            0, 0, 0, /* 243: func */
            0, 8, 0, /* 246: long */
            4097, 0, 0, /* 249: pointer.func */
            0, 0, 0, /* 252: func */
            4097, 0, 0, /* 255: pointer.func */
        },
        .arg_entity_index = { 100, },
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

