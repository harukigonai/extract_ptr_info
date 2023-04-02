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
            0, 32, 2, /* 0: struct.ENGINE_CMD_DEFN_st */
            	7, 8,
            	7, 16,
            1, 8, 1, /* 7: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 12: pointer.func */
            4097, 8, 0, /* 15: pointer.func */
            0, 0, 0, /* 18: func */
            0, 8, 0, /* 21: pointer.void */
            4097, 8, 0, /* 24: pointer.func */
            4097, 8, 0, /* 27: pointer.func */
            0, 0, 0, /* 30: func */
            1, 8, 1, /* 33: pointer.struct.store_method_st */
            	38, 0,
            0, 0, 0, /* 38: struct.store_method_st */
            0, 0, 0, /* 41: func */
            4097, 8, 0, /* 44: pointer.func */
            0, 0, 0, /* 47: func */
            4097, 8, 0, /* 50: pointer.func */
            0, 48, 6, /* 53: struct.rand_meth_st */
            	68, 0,
            	71, 8,
            	50, 16,
            	44, 24,
            	71, 32,
            	74, 40,
            4097, 8, 0, /* 68: pointer.func */
            4097, 8, 0, /* 71: pointer.func */
            4097, 8, 0, /* 74: pointer.func */
            1, 8, 1, /* 77: pointer.struct.rand_meth_st */
            	53, 0,
            4097, 8, 0, /* 82: pointer.func */
            0, 0, 0, /* 85: func */
            4097, 8, 0, /* 88: pointer.func */
            0, 32, 3, /* 91: struct.ecdh_method */
            	7, 0,
            	88, 8,
            	7, 24,
            1, 8, 1, /* 100: pointer.struct.ecdh_method */
            	91, 0,
            0, 0, 0, /* 105: func */
            4097, 8, 0, /* 108: pointer.func */
            0, 0, 0, /* 111: func */
            4097, 8, 0, /* 114: pointer.func */
            0, 0, 0, /* 117: func */
            0, 0, 0, /* 120: func */
            0, 96, 3, /* 123: struct.bn_mont_ctx_st */
            	132, 8,
            	132, 32,
            	132, 56,
            0, 24, 1, /* 132: struct.bignum_st */
            	137, 0,
            1, 8, 1, /* 137: pointer.int */
            	142, 0,
            0, 4, 0, /* 142: int */
            0, 0, 0, /* 145: func */
            0, 0, 0, /* 148: func */
            0, 0, 0, /* 151: func */
            4097, 8, 0, /* 154: pointer.func */
            0, 0, 0, /* 157: func */
            0, 0, 0, /* 160: func */
            0, 0, 0, /* 163: func */
            0, 0, 0, /* 166: func */
            1, 8, 1, /* 169: pointer.struct.dh_method */
            	174, 0,
            0, 72, 8, /* 174: struct.dh_method */
            	7, 0,
            	193, 8,
            	196, 16,
            	154, 24,
            	193, 32,
            	193, 40,
            	7, 56,
            	199, 64,
            4097, 8, 0, /* 193: pointer.func */
            4097, 8, 0, /* 196: pointer.func */
            4097, 8, 0, /* 199: pointer.func */
            1, 8, 1, /* 202: pointer.pointer.char */
            	7, 0,
            0, 32, 1, /* 207: struct.stack_st_OPENSSL_STRING */
            	212, 0,
            0, 32, 2, /* 212: struct.stack_st */
            	202, 8,
            	219, 24,
            4097, 8, 0, /* 219: pointer.func */
            0, 0, 0, /* 222: func */
            4097, 8, 0, /* 225: pointer.func */
            0, 144, 12, /* 228: struct.dh_st */
            	255, 8,
            	255, 16,
            	255, 32,
            	255, 40,
            	260, 56,
            	255, 64,
            	255, 72,
            	7, 80,
            	255, 96,
            	265, 112,
            	169, 128,
            	275, 136,
            1, 8, 1, /* 255: pointer.struct.bignum_st */
            	132, 0,
            1, 8, 1, /* 260: pointer.struct.bn_mont_ctx_st */
            	123, 0,
            0, 16, 1, /* 265: struct.crypto_ex_data_st */
            	270, 0,
            1, 8, 1, /* 270: pointer.struct.stack_st_OPENSSL_STRING */
            	207, 0,
            1, 8, 1, /* 275: pointer.struct.engine_st */
            	280, 0,
            0, 216, 24, /* 280: struct.engine_st */
            	7, 0,
            	7, 8,
            	331, 16,
            	386, 24,
            	169, 32,
            	100, 40,
            	428, 48,
            	77, 56,
            	33, 64,
            	452, 72,
            	455, 80,
            	458, 88,
            	461, 96,
            	24, 104,
            	24, 112,
            	24, 120,
            	27, 128,
            	15, 136,
            	15, 144,
            	12, 152,
            	464, 160,
            	265, 184,
            	275, 200,
            	275, 208,
            1, 8, 1, /* 331: pointer.struct.rsa_meth_st */
            	336, 0,
            0, 112, 13, /* 336: struct.rsa_meth_st */
            	7, 0,
            	365, 8,
            	365, 16,
            	365, 24,
            	365, 32,
            	368, 40,
            	371, 48,
            	374, 56,
            	374, 64,
            	7, 80,
            	377, 88,
            	380, 96,
            	383, 104,
            4097, 8, 0, /* 365: pointer.func */
            4097, 8, 0, /* 368: pointer.func */
            4097, 8, 0, /* 371: pointer.func */
            4097, 8, 0, /* 374: pointer.func */
            4097, 8, 0, /* 377: pointer.func */
            4097, 8, 0, /* 380: pointer.func */
            4097, 8, 0, /* 383: pointer.func */
            1, 8, 1, /* 386: pointer.struct.dsa_method */
            	391, 0,
            0, 96, 11, /* 391: struct.dsa_method */
            	7, 0,
            	416, 8,
            	225, 16,
            	419, 24,
            	422, 32,
            	425, 40,
            	114, 48,
            	114, 56,
            	7, 72,
            	108, 80,
            	114, 88,
            4097, 8, 0, /* 416: pointer.func */
            4097, 8, 0, /* 419: pointer.func */
            4097, 8, 0, /* 422: pointer.func */
            4097, 8, 0, /* 425: pointer.func */
            1, 8, 1, /* 428: pointer.struct.ecdsa_method */
            	433, 0,
            0, 48, 5, /* 433: struct.ecdsa_method */
            	7, 0,
            	82, 8,
            	446, 16,
            	449, 24,
            	7, 40,
            4097, 8, 0, /* 446: pointer.func */
            4097, 8, 0, /* 449: pointer.func */
            4097, 8, 0, /* 452: pointer.func */
            4097, 8, 0, /* 455: pointer.func */
            4097, 8, 0, /* 458: pointer.func */
            4097, 8, 0, /* 461: pointer.func */
            1, 8, 1, /* 464: pointer.struct.ENGINE_CMD_DEFN_st */
            	0, 0,
            0, 0, 0, /* 469: func */
            0, 1, 0, /* 472: char */
            0, 0, 0, /* 475: func */
            0, 0, 0, /* 478: func */
            0, 0, 0, /* 481: func */
            0, 0, 0, /* 484: func */
            0, 0, 0, /* 487: func */
            0, 0, 0, /* 490: func */
            0, 8, 0, /* 493: long */
            1, 8, 1, /* 496: pointer.struct.dh_st */
            	228, 0,
            0, 0, 0, /* 501: func */
            0, 0, 0, /* 504: func */
            0, 8, 0, /* 507: array[2].int */
            0, 0, 0, /* 510: func */
            0, 0, 0, /* 513: func */
            0, 0, 0, /* 516: func */
            0, 0, 0, /* 519: func */
            0, 0, 0, /* 522: func */
            0, 0, 0, /* 525: func */
            0, 0, 0, /* 528: func */
            0, 0, 0, /* 531: func */
            0, 0, 0, /* 534: func */
            0, 0, 0, /* 537: func */
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 496,
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

