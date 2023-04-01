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

DH * bb_DH_new(void);

DH * DH_new(void) 
{
    unsigned long in_lib = syscall(890);
    printf("DH_new called %lu\n", in_lib);
    if (!in_lib)
        return bb_DH_new();
    else {
        DH * (*orig_DH_new)(void);
        orig_DH_new = dlsym(RTLD_NEXT, "DH_new");
        return orig_DH_new();
    }
}

DH * bb_DH_new(void) 
{
    DH * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            4097, 0, 0, /* 3: pointer.func */
            0, 0, 0, /* 6: func */
            4097, 0, 0, /* 9: pointer.func */
            0, 0, 0, /* 12: func */
            4097, 0, 0, /* 15: pointer.func */
            0, 0, 0, /* 18: struct.store_method_st */
            1, 8, 1, /* 21: pointer.struct.store_method_st */
            	18, 0,
            0, 0, 0, /* 26: func */
            4097, 0, 0, /* 29: pointer.func */
            0, 0, 0, /* 32: func */
            4097, 0, 0, /* 35: pointer.func */
            1, 8, 1, /* 38: pointer.struct.rand_meth_st */
            	43, 0,
            0, 48, 0, /* 43: struct.rand_meth_st */
            0, 0, 0, /* 46: func */
            0, 32, 2, /* 49: struct.ENGINE_CMD_DEFN_st */
            	56, 8,
            	56, 16,
            1, 8, 1, /* 56: pointer.char */
            	4096, 0,
            4097, 0, 0, /* 61: pointer.func */
            0, 0, 0, /* 64: func */
            4097, 0, 0, /* 67: pointer.func */
            0, 0, 0, /* 70: func */
            0, 0, 0, /* 73: func */
            4097, 0, 0, /* 76: pointer.func */
            0, 32, 2, /* 79: struct.ecdh_method */
            	56, 0,
            	56, 24,
            1, 8, 1, /* 86: pointer.struct.ecdh_method */
            	79, 0,
            0, 0, 0, /* 91: func */
            4097, 0, 0, /* 94: pointer.func */
            4097, 0, 0, /* 97: pointer.func */
            0, 0, 0, /* 100: func */
            4097, 0, 0, /* 103: pointer.func */
            4097, 0, 0, /* 106: pointer.func */
            0, 0, 0, /* 109: func */
            4097, 0, 0, /* 112: pointer.func */
            0, 0, 0, /* 115: func */
            0, 0, 0, /* 118: func */
            4097, 0, 0, /* 121: pointer.func */
            0, 0, 0, /* 124: func */
            0, 0, 0, /* 127: func */
            0, 0, 0, /* 130: func */
            0, 0, 0, /* 133: func */
            1, 8, 1, /* 136: pointer.struct.dh_method */
            	141, 0,
            0, 72, 2, /* 141: struct.dh_method */
            	56, 0,
            	56, 56,
            0, 0, 0, /* 148: func */
            1, 8, 1, /* 151: pointer.pointer.char */
            	56, 0,
            0, 4, 0, /* 156: int */
            4097, 0, 0, /* 159: pointer.func */
            4097, 0, 0, /* 162: pointer.func */
            4097, 0, 0, /* 165: pointer.func */
            4097, 0, 0, /* 168: pointer.func */
            0, 0, 0, /* 171: func */
            4097, 0, 0, /* 174: pointer.func */
            1, 8, 1, /* 177: pointer.struct.bn_mont_ctx_st */
            	182, 0,
            0, 96, 3, /* 182: struct.bn_mont_ctx_st */
            	191, 8,
            	191, 32,
            	191, 56,
            0, 24, 1, /* 191: struct.bignum_st */
            	196, 0,
            1, 8, 1, /* 196: pointer.int */
            	156, 0,
            0, 0, 0, /* 201: func */
            0, 0, 0, /* 204: func */
            0, 32, 1, /* 207: struct.stack_st_OPENSSL_STRING */
            	212, 0,
            0, 32, 1, /* 212: struct.stack_st */
            	151, 8,
            4097, 0, 0, /* 217: pointer.func */
            1, 8, 1, /* 220: pointer.struct.ENGINE_CMD_DEFN_st */
            	49, 0,
            0, 0, 0, /* 225: func */
            0, 144, 12, /* 228: struct.dh_st */
            	255, 8,
            	255, 16,
            	255, 32,
            	255, 40,
            	177, 56,
            	255, 64,
            	255, 72,
            	56, 80,
            	255, 96,
            	260, 112,
            	136, 128,
            	270, 136,
            1, 8, 1, /* 255: pointer.struct.bignum_st */
            	191, 0,
            0, 16, 1, /* 260: struct.crypto_ex_data_st */
            	265, 0,
            1, 8, 1, /* 265: pointer.struct.stack_st_OPENSSL_STRING */
            	207, 0,
            1, 8, 1, /* 270: pointer.struct.engine_st */
            	275, 0,
            0, 216, 13, /* 275: struct.engine_st */
            	56, 0,
            	56, 8,
            	304, 16,
            	316, 24,
            	136, 32,
            	86, 40,
            	328, 48,
            	38, 56,
            	21, 64,
            	220, 160,
            	260, 184,
            	270, 200,
            	270, 208,
            1, 8, 1, /* 304: pointer.struct.rsa_meth_st */
            	309, 0,
            0, 112, 2, /* 309: struct.rsa_meth_st */
            	56, 0,
            	56, 80,
            1, 8, 1, /* 316: pointer.struct.dsa_method.1040 */
            	321, 0,
            0, 96, 2, /* 321: struct.dsa_method.1040 */
            	56, 0,
            	56, 72,
            1, 8, 1, /* 328: pointer.struct.ecdsa_method */
            	333, 0,
            0, 48, 2, /* 333: struct.ecdsa_method */
            	56, 0,
            	56, 40,
            4097, 0, 0, /* 340: pointer.func */
            4097, 0, 0, /* 343: pointer.func */
            0, 0, 0, /* 346: func */
            0, 8, 0, /* 349: long */
            4097, 0, 0, /* 352: pointer.func */
            0, 0, 0, /* 355: func */
            4097, 0, 0, /* 358: pointer.func */
            0, 0, 0, /* 361: func */
            0, 0, 0, /* 364: func */
            4097, 0, 0, /* 367: pointer.func */
            4097, 0, 0, /* 370: pointer.func */
            0, 8, 0, /* 373: array[2].int */
            0, 1, 0, /* 376: char */
            4097, 0, 0, /* 379: pointer.func */
            0, 0, 0, /* 382: func */
            0, 0, 0, /* 385: func */
            4097, 0, 0, /* 388: pointer.func */
            4097, 0, 0, /* 391: pointer.func */
            4097, 0, 0, /* 394: pointer.func */
            0, 0, 0, /* 397: func */
            0, 0, 0, /* 400: func */
            4097, 0, 0, /* 403: pointer.func */
            0, 0, 0, /* 406: func */
            0, 0, 0, /* 409: func */
            4097, 0, 0, /* 412: pointer.func */
            1, 8, 1, /* 415: pointer.struct.dh_st */
            	228, 0,
            0, 0, 0, /* 420: func */
            4097, 0, 0, /* 423: pointer.func */
            0, 0, 0, /* 426: func */
            4097, 0, 0, /* 429: pointer.func */
            0, 0, 0, /* 432: func */
            4097, 0, 0, /* 435: pointer.func */
            4097, 0, 0, /* 438: pointer.func */
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 415,
    };
    struct lib_enter_args *args_addr = &args;
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    DH * *new_ret_ptr = (DH * *)new_args->ret;

    DH * (*orig_DH_new)(void);
    orig_DH_new = dlsym(RTLD_NEXT, "DH_new");
    *new_ret_ptr = (*orig_DH_new)();

    syscall(889);

    return ret;
}

