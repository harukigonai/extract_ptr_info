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
            4097, 8, 0, /* 18: pointer.func */
            4097, 8, 0, /* 21: pointer.func */
            4097, 8, 0, /* 24: pointer.func */
            4097, 8, 0, /* 27: pointer.func */
            4097, 8, 0, /* 30: pointer.func */
            0, 216, 24, /* 33: struct.engine_st */
            	7, 0,
            	7, 8,
            	84, 16,
            	133, 24,
            	181, 32,
            	217, 40,
            	234, 48,
            	261, 56,
            	296, 64,
            	304, 72,
            	307, 80,
            	310, 88,
            	313, 96,
            	21, 104,
            	21, 112,
            	21, 120,
            	18, 128,
            	15, 136,
            	15, 144,
            	12, 152,
            	316, 160,
            	321, 184,
            	351, 200,
            	351, 208,
            1, 8, 1, /* 84: pointer.struct.rsa_meth_st */
            	89, 0,
            0, 112, 13, /* 89: struct.rsa_meth_st */
            	7, 0,
            	30, 8,
            	30, 16,
            	30, 24,
            	30, 32,
            	24, 40,
            	118, 48,
            	121, 56,
            	121, 64,
            	7, 80,
            	124, 88,
            	127, 96,
            	130, 104,
            4097, 8, 0, /* 118: pointer.func */
            4097, 8, 0, /* 121: pointer.func */
            4097, 8, 0, /* 124: pointer.func */
            4097, 8, 0, /* 127: pointer.func */
            4097, 8, 0, /* 130: pointer.func */
            1, 8, 1, /* 133: pointer.struct.dsa_method */
            	138, 0,
            0, 96, 11, /* 138: struct.dsa_method */
            	7, 0,
            	163, 8,
            	166, 16,
            	169, 24,
            	172, 32,
            	175, 40,
            	178, 48,
            	178, 56,
            	7, 72,
            	27, 80,
            	178, 88,
            4097, 8, 0, /* 163: pointer.func */
            4097, 8, 0, /* 166: pointer.func */
            4097, 8, 0, /* 169: pointer.func */
            4097, 8, 0, /* 172: pointer.func */
            4097, 8, 0, /* 175: pointer.func */
            4097, 8, 0, /* 178: pointer.func */
            1, 8, 1, /* 181: pointer.struct.dh_method */
            	186, 0,
            0, 72, 8, /* 186: struct.dh_method */
            	7, 0,
            	205, 8,
            	208, 16,
            	211, 24,
            	205, 32,
            	205, 40,
            	7, 56,
            	214, 64,
            4097, 8, 0, /* 205: pointer.func */
            4097, 8, 0, /* 208: pointer.func */
            4097, 8, 0, /* 211: pointer.func */
            4097, 8, 0, /* 214: pointer.func */
            1, 8, 1, /* 217: pointer.struct.ecdh_method */
            	222, 0,
            0, 32, 3, /* 222: struct.ecdh_method */
            	7, 0,
            	231, 8,
            	7, 24,
            4097, 8, 0, /* 231: pointer.func */
            1, 8, 1, /* 234: pointer.struct.ecdsa_method */
            	239, 0,
            0, 48, 5, /* 239: struct.ecdsa_method */
            	7, 0,
            	252, 8,
            	255, 16,
            	258, 24,
            	7, 40,
            4097, 8, 0, /* 252: pointer.func */
            4097, 8, 0, /* 255: pointer.func */
            4097, 8, 0, /* 258: pointer.func */
            1, 8, 1, /* 261: pointer.struct.rand_meth_st */
            	266, 0,
            0, 48, 6, /* 266: struct.rand_meth_st */
            	281, 0,
            	284, 8,
            	287, 16,
            	290, 24,
            	284, 32,
            	293, 40,
            4097, 8, 0, /* 281: pointer.func */
            4097, 8, 0, /* 284: pointer.func */
            4097, 8, 0, /* 287: pointer.func */
            4097, 8, 0, /* 290: pointer.func */
            4097, 8, 0, /* 293: pointer.func */
            1, 8, 1, /* 296: pointer.struct.store_method_st */
            	301, 0,
            0, 0, 0, /* 301: struct.store_method_st */
            4097, 8, 0, /* 304: pointer.func */
            4097, 8, 0, /* 307: pointer.func */
            4097, 8, 0, /* 310: pointer.func */
            4097, 8, 0, /* 313: pointer.func */
            1, 8, 1, /* 316: pointer.struct.ENGINE_CMD_DEFN_st */
            	0, 0,
            0, 16, 1, /* 321: struct.crypto_ex_data_st */
            	326, 0,
            1, 8, 1, /* 326: pointer.struct.stack_st_OPENSSL_STRING */
            	331, 0,
            0, 32, 1, /* 331: struct.stack_st_OPENSSL_STRING */
            	336, 0,
            0, 32, 2, /* 336: struct.stack_st */
            	343, 8,
            	348, 24,
            1, 8, 1, /* 343: pointer.pointer.char */
            	7, 0,
            4097, 8, 0, /* 348: pointer.func */
            1, 8, 1, /* 351: pointer.struct.engine_st */
            	33, 0,
            0, 1, 0, /* 356: char */
            1, 8, 1, /* 359: pointer.struct.dh_st */
            	364, 0,
            0, 144, 12, /* 364: struct.dh_st */
            	391, 8,
            	391, 16,
            	391, 32,
            	391, 40,
            	409, 56,
            	391, 64,
            	391, 72,
            	7, 80,
            	391, 96,
            	321, 112,
            	181, 128,
            	351, 136,
            1, 8, 1, /* 391: pointer.struct.bignum_st */
            	396, 0,
            0, 24, 1, /* 396: struct.bignum_st */
            	401, 0,
            1, 8, 1, /* 401: pointer.int */
            	406, 0,
            0, 4, 0, /* 406: int */
            1, 8, 1, /* 409: pointer.struct.bn_mont_ctx_st */
            	414, 0,
            0, 96, 3, /* 414: struct.bn_mont_ctx_st */
            	396, 8,
            	396, 32,
            	396, 56,
            0, 8, 0, /* 423: pointer.void */
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 359,
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

