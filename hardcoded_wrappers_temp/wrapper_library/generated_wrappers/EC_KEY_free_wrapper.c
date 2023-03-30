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

void bb_EC_KEY_free(EC_KEY * arg_a);

void EC_KEY_free(EC_KEY * arg_a) 
{
    printf("EC_KEY_free called\n");
    if (!syscall(890))
        bb_EC_KEY_free(arg_a);
    else {
        void (*orig_EC_KEY_free)(EC_KEY *);
        orig_EC_KEY_free = dlsym(RTLD_NEXT, "EC_KEY_free");
        orig_EC_KEY_free(arg_a);
    }
}

void bb_EC_KEY_free(EC_KEY * arg_a) 
{
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
            0, 0, 0, /* 18: func */
            0, 8, 0, /* 21: pointer.func */
            0, 0, 0, /* 24: func */
            0, 8, 0, /* 27: pointer.func */
            0, 8, 0, /* 30: pointer.func */
            0, 0, 0, /* 33: func */
            0, 1, 0, /* 36: char */
            0, 0, 0, /* 39: func */
            0, 8, 0, /* 42: pointer.func */
            0, 0, 0, /* 45: func */
            0, 8, 0, /* 48: pointer.func */
            0, 8, 0, /* 51: pointer.func */
            0, 0, 0, /* 54: func */
            0, 8, 0, /* 57: pointer.func */
            0, 0, 0, /* 60: func */
            1, 8, 1, /* 63: pointer.struct.ec_method_st */
            	68, 0,
            0, 304, 0, /* 68: struct.ec_method_st */
            0, 8, 0, /* 71: pointer.func */
            0, 8, 0, /* 74: pointer.func */
            0, 8, 0, /* 77: pointer.func */
            0, 0, 0, /* 80: func */
            0, 0, 0, /* 83: func */
            0, 0, 0, /* 86: func */
            1, 8, 1, /* 89: pointer.struct.ec_group_st */
            	94, 0,
            0, 232, 11, /* 94: struct.ec_group_st */
            	63, 0,
            	119, 8,
            	5, 16,
            	5, 40,
            	135, 80,
            	140, 96,
            	5, 104,
            	5, 152,
            	5, 176,
            	135, 208,
            	135, 216,
            1, 8, 1, /* 119: pointer.struct.ec_point_st */
            	124, 0,
            0, 88, 4, /* 124: struct.ec_point_st */
            	63, 0,
            	5, 8,
            	5, 32,
            	5, 56,
            1, 8, 1, /* 135: pointer.char */
            	36, 0,
            1, 8, 1, /* 140: pointer.struct.ec_extra_data_st */
            	145, 0,
            0, 40, 2, /* 145: struct.ec_extra_data_st */
            	140, 0,
            	135, 8,
            0, 8, 0, /* 152: pointer.func */
            0, 56, 4, /* 155: struct.ec_key_st.284 */
            	89, 8,
            	119, 16,
            	0, 24,
            	140, 48,
            0, 8, 0, /* 166: pointer.func */
            0, 8, 0, /* 169: pointer.func */
            1, 8, 1, /* 172: pointer.struct.ec_key_st.284 */
            	155, 0,
            0, 8, 0, /* 177: pointer.func */
            0, 0, 0, /* 180: func */
            0, 0, 0, /* 183: func */
            0, 8, 0, /* 186: pointer.func */
            0, 0, 0, /* 189: func */
            0, 0, 0, /* 192: func */
            0, 0, 0, /* 195: func */
            0, 0, 0, /* 198: func */
            0, 8, 0, /* 201: pointer.func */
            0, 0, 0, /* 204: func */
            0, 8, 0, /* 207: pointer.func */
            0, 8, 0, /* 210: pointer.func */
            0, 0, 0, /* 213: func */
            0, 8, 0, /* 216: pointer.func */
            0, 24, 0, /* 219: array[6].int */
            0, 0, 0, /* 222: func */
            0, 8, 0, /* 225: pointer.func */
            0, 8, 0, /* 228: pointer.func */
            0, 8, 0, /* 231: long */
            0, 0, 0, /* 234: func */
            0, 0, 0, /* 237: func */
            0, 8, 0, /* 240: pointer.func */
            0, 8, 0, /* 243: pointer.func */
            0, 0, 0, /* 246: func */
            0, 0, 0, /* 249: func */
            0, 0, 0, /* 252: func */
            0, 8, 0, /* 255: pointer.func */
        },
        .arg_entity_index = { 172, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EC_KEY * new_arg_a = *((EC_KEY * *)new_args->args[0]);

    void (*orig_EC_KEY_free)(EC_KEY *);
    orig_EC_KEY_free = dlsym(RTLD_NEXT, "EC_KEY_free");
    (*orig_EC_KEY_free)(new_arg_a);

    syscall(889);

}

