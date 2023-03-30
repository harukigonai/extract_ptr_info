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

void bb_DH_free(DH * arg_a);

void DH_free(DH * arg_a) 
{
    printf("DH_free called\n");
    if (!syscall(890))
        bb_DH_free(arg_a);
    else {
        void (*orig_DH_free)(DH *);
        orig_DH_free = dlsym(RTLD_NEXT, "DH_free");
        orig_DH_free(arg_a);
    }
}

void bb_DH_free(DH * arg_a) 
{
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 32, 2, /* 0: struct.ENGINE_CMD_DEFN_st */
            	7, 8,
            	7, 16,
            1, 8, 1, /* 7: pointer.char */
            	12, 0,
            0, 1, 0, /* 12: char */
            0, 8, 0, /* 15: pointer.func */
            0, 0, 0, /* 18: func */
            0, 0, 0, /* 21: func */
            0, 0, 0, /* 24: func */
            0, 8, 0, /* 27: pointer.func */
            0, 0, 0, /* 30: func */
            0, 8, 0, /* 33: pointer.func */
            0, 8, 0, /* 36: pointer.func */
            0, 0, 0, /* 39: func */
            0, 8, 0, /* 42: pointer.func */
            0, 0, 0, /* 45: func */
            0, 8, 0, /* 48: pointer.func */
            0, 0, 0, /* 51: struct.store_method_st */
            1, 8, 1, /* 54: pointer.struct.store_method_st */
            	51, 0,
            0, 8, 0, /* 59: pointer.func */
            0, 0, 0, /* 62: func */
            0, 0, 0, /* 65: func */
            0, 0, 0, /* 68: func */
            0, 48, 0, /* 71: struct.rand_meth_st */
            1, 8, 1, /* 74: pointer.struct.rand_meth_st */
            	71, 0,
            0, 0, 0, /* 79: func */
            0, 8, 0, /* 82: pointer.func */
            0, 48, 2, /* 85: struct.ecdsa_method */
            	7, 0,
            	7, 40,
            0, 0, 0, /* 92: func */
            0, 8, 0, /* 95: pointer.func */
            0, 32, 2, /* 98: struct.ecdh_method */
            	7, 0,
            	7, 24,
            0, 8, 0, /* 105: pointer.func */
            0, 0, 0, /* 108: func */
            0, 8, 0, /* 111: pointer.func */
            0, 8, 0, /* 114: pointer.func */
            0, 0, 0, /* 117: func */
            0, 8, 0, /* 120: pointer.func */
            0, 8, 0, /* 123: pointer.func */
            1, 8, 1, /* 126: pointer.struct.bignum_st */
            	131, 0,
            0, 24, 1, /* 131: struct.bignum_st */
            	136, 0,
            1, 8, 1, /* 136: pointer.int */
            	141, 0,
            0, 4, 0, /* 141: int */
            0, 72, 2, /* 144: struct.dh_method */
            	7, 0,
            	7, 56,
            0, 0, 0, /* 151: func */
            0, 0, 0, /* 154: func */
            1, 8, 1, /* 157: pointer.struct.ecdsa_method */
            	85, 0,
            0, 8, 0, /* 162: array[2].int */
            0, 0, 0, /* 165: func */
            0, 0, 0, /* 168: func */
            0, 8, 0, /* 171: pointer.func */
            0, 0, 0, /* 174: func */
            0, 0, 0, /* 177: func */
            0, 144, 12, /* 180: struct.dh_st */
            	126, 8,
            	126, 16,
            	126, 32,
            	126, 40,
            	207, 56,
            	126, 64,
            	126, 72,
            	7, 80,
            	126, 96,
            	221, 112,
            	246, 128,
            	251, 136,
            1, 8, 1, /* 207: pointer.struct.bn_mont_ctx_st */
            	212, 0,
            0, 96, 3, /* 212: struct.bn_mont_ctx_st */
            	131, 8,
            	131, 32,
            	131, 56,
            0, 16, 1, /* 221: struct.crypto_ex_data_st */
            	226, 0,
            1, 8, 1, /* 226: pointer.struct.stack_st_OPENSSL_STRING */
            	231, 0,
            0, 32, 1, /* 231: struct.stack_st_OPENSSL_STRING */
            	236, 0,
            0, 32, 1, /* 236: struct.stack_st */
            	241, 8,
            1, 8, 1, /* 241: pointer.pointer.char */
            	7, 0,
            1, 8, 1, /* 246: pointer.struct.dh_method */
            	144, 0,
            1, 8, 1, /* 251: pointer.struct.engine_st */
            	256, 0,
            0, 216, 13, /* 256: struct.engine_st */
            	7, 0,
            	7, 8,
            	285, 16,
            	297, 24,
            	246, 32,
            	309, 40,
            	157, 48,
            	74, 56,
            	54, 64,
            	314, 160,
            	221, 184,
            	251, 200,
            	251, 208,
            1, 8, 1, /* 285: pointer.struct.rsa_meth_st */
            	290, 0,
            0, 112, 2, /* 290: struct.rsa_meth_st */
            	7, 0,
            	7, 80,
            1, 8, 1, /* 297: pointer.struct.dsa_method.1040 */
            	302, 0,
            0, 96, 2, /* 302: struct.dsa_method.1040 */
            	7, 0,
            	7, 72,
            1, 8, 1, /* 309: pointer.struct.ecdh_method */
            	98, 0,
            1, 8, 1, /* 314: pointer.struct.ENGINE_CMD_DEFN_st */
            	0, 0,
            0, 0, 0, /* 319: func */
            0, 8, 0, /* 322: pointer.func */
            0, 8, 0, /* 325: pointer.func */
            0, 0, 0, /* 328: func */
            0, 8, 0, /* 331: pointer.func */
            0, 8, 0, /* 334: pointer.func */
            0, 0, 0, /* 337: func */
            0, 8, 0, /* 340: pointer.func */
            0, 0, 0, /* 343: func */
            0, 0, 0, /* 346: func */
            0, 8, 0, /* 349: pointer.func */
            0, 0, 0, /* 352: func */
            0, 8, 0, /* 355: long */
            0, 0, 0, /* 358: func */
            0, 8, 0, /* 361: pointer.func */
            0, 0, 0, /* 364: func */
            0, 0, 0, /* 367: func */
            0, 8, 0, /* 370: pointer.func */
            0, 8, 0, /* 373: pointer.func */
            0, 8, 0, /* 376: pointer.func */
            0, 0, 0, /* 379: func */
            0, 8, 0, /* 382: pointer.func */
            0, 0, 0, /* 385: func */
            0, 0, 0, /* 388: func */
            0, 8, 0, /* 391: pointer.func */
            0, 8, 0, /* 394: pointer.func */
            0, 8, 0, /* 397: pointer.func */
            0, 8, 0, /* 400: pointer.func */
            0, 0, 0, /* 403: func */
            0, 8, 0, /* 406: pointer.func */
            0, 8, 0, /* 409: pointer.func */
            0, 0, 0, /* 412: func */
            1, 8, 1, /* 415: pointer.struct.dh_st */
            	180, 0,
            0, 0, 0, /* 420: func */
            0, 8, 0, /* 423: pointer.func */
            0, 0, 0, /* 426: func */
            0, 8, 0, /* 429: pointer.func */
            0, 8, 0, /* 432: pointer.func */
            0, 0, 0, /* 435: func */
            0, 8, 0, /* 438: pointer.func */
        },
        .arg_entity_index = { 415, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    DH * new_arg_a = *((DH * *)new_args->args[0]);

    void (*orig_DH_free)(DH *);
    orig_DH_free = dlsym(RTLD_NEXT, "DH_free");
    (*orig_DH_free)(new_arg_a);

    syscall(889);

}

