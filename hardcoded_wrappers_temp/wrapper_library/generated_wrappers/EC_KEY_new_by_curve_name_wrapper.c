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
            0, 0, 0, /* 0: func */
            4097, 0, 0, /* 3: pointer.func */
            0, 24, 0, /* 6: array[6].int */
            4097, 0, 0, /* 9: pointer.func */
            0, 0, 0, /* 12: func */
            4097, 0, 0, /* 15: pointer.func */
            0, 0, 0, /* 18: func */
            0, 0, 0, /* 21: func */
            1, 8, 1, /* 24: pointer.struct.ec_key_st.284 */
            	29, 0,
            0, 56, 4, /* 29: struct.ec_key_st.284 */
            	40, 8,
            	78, 16,
            	124, 24,
            	112, 48,
            1, 8, 1, /* 40: pointer.struct.ec_group_st */
            	45, 0,
            0, 232, 11, /* 45: struct.ec_group_st */
            	70, 0,
            	78, 8,
            	94, 16,
            	94, 40,
            	107, 80,
            	112, 96,
            	94, 104,
            	94, 152,
            	94, 176,
            	107, 208,
            	107, 216,
            1, 8, 1, /* 70: pointer.struct.ec_method_st */
            	75, 0,
            0, 304, 0, /* 75: struct.ec_method_st */
            1, 8, 1, /* 78: pointer.struct.ec_point_st */
            	83, 0,
            0, 88, 4, /* 83: struct.ec_point_st */
            	70, 0,
            	94, 8,
            	94, 32,
            	94, 56,
            0, 24, 1, /* 94: struct.bignum_st */
            	99, 0,
            1, 8, 1, /* 99: pointer.int */
            	104, 0,
            0, 4, 0, /* 104: int */
            1, 8, 1, /* 107: pointer.char */
            	4096, 0,
            1, 8, 1, /* 112: pointer.struct.ec_extra_data_st */
            	117, 0,
            0, 40, 2, /* 117: struct.ec_extra_data_st */
            	112, 0,
            	107, 8,
            1, 8, 1, /* 124: pointer.struct.bignum_st */
            	94, 0,
            4097, 0, 0, /* 129: pointer.func */
            4097, 0, 0, /* 132: pointer.func */
            0, 0, 0, /* 135: func */
            4097, 0, 0, /* 138: pointer.func */
            0, 0, 0, /* 141: func */
            0, 0, 0, /* 144: func */
            4097, 0, 0, /* 147: pointer.func */
            0, 0, 0, /* 150: func */
            0, 0, 0, /* 153: func */
            0, 0, 0, /* 156: func */
            0, 0, 0, /* 159: func */
            4097, 0, 0, /* 162: pointer.func */
            4097, 0, 0, /* 165: pointer.func */
            4097, 0, 0, /* 168: pointer.func */
            0, 0, 0, /* 171: func */
            4097, 0, 0, /* 174: pointer.func */
            0, 0, 0, /* 177: func */
            4097, 0, 0, /* 180: pointer.func */
            4097, 0, 0, /* 183: pointer.func */
            4097, 0, 0, /* 186: pointer.func */
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
            0, 0, 0, /* 219: func */
            4097, 0, 0, /* 222: pointer.func */
            4097, 0, 0, /* 225: pointer.func */
            0, 0, 0, /* 228: func */
            4097, 0, 0, /* 231: pointer.func */
            0, 1, 0, /* 234: char */
            4097, 0, 0, /* 237: pointer.func */
            0, 0, 0, /* 240: func */
            0, 0, 0, /* 243: func */
            4097, 0, 0, /* 246: pointer.func */
            0, 0, 0, /* 249: func */
            0, 8, 0, /* 252: long */
            4097, 0, 0, /* 255: pointer.func */
        },
        .arg_entity_index = { 104, },
        .ret_entity_index = 24,
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

