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
    unsigned long in_lib = syscall(890);
    printf("DH_free called %lu\n", in_lib);
    if (!in_lib)
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
            4097, 8, 0, /* 0: pointer.func */
            4097, 8, 0, /* 3: pointer.func */
            0, 72, 8, /* 6: struct.dh_method */
            	25, 0,
            	3, 8,
            	30, 16,
            	0, 24,
            	3, 32,
            	3, 40,
            	33, 56,
            	38, 64,
            1, 8, 1, /* 25: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 30: pointer.func */
            1, 8, 1, /* 33: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 38: pointer.func */
            1, 8, 1, /* 41: pointer.struct.dh_method */
            	6, 0,
            0, 1, 0, /* 46: char */
            0, 0, 0, /* 49: struct.engine_st */
            0, 32, 2, /* 52: struct.stack_st */
            	59, 8,
            	64, 24,
            1, 8, 1, /* 59: pointer.pointer.char */
            	33, 0,
            4097, 8, 0, /* 64: pointer.func */
            1, 8, 1, /* 67: pointer.struct.dh_st */
            	72, 0,
            0, 144, 12, /* 72: struct.dh_st */
            	99, 8,
            	99, 16,
            	99, 32,
            	99, 40,
            	117, 56,
            	99, 64,
            	99, 72,
            	131, 80,
            	99, 96,
            	139, 112,
            	41, 128,
            	154, 136,
            1, 8, 1, /* 99: pointer.struct.bignum_st */
            	104, 0,
            0, 24, 1, /* 104: struct.bignum_st */
            	109, 0,
            1, 8, 1, /* 109: pointer.unsigned int */
            	114, 0,
            0, 4, 0, /* 114: unsigned int */
            1, 8, 1, /* 117: pointer.struct.bn_mont_ctx_st */
            	122, 0,
            0, 96, 3, /* 122: struct.bn_mont_ctx_st */
            	104, 8,
            	104, 32,
            	104, 56,
            1, 8, 1, /* 131: pointer.unsigned char */
            	136, 0,
            0, 1, 0, /* 136: unsigned char */
            0, 16, 1, /* 139: struct.crypto_ex_data_st */
            	144, 0,
            1, 8, 1, /* 144: pointer.struct.stack_st_void */
            	149, 0,
            0, 32, 1, /* 149: struct.stack_st_void */
            	52, 0,
            1, 8, 1, /* 154: pointer.struct.engine_st */
            	49, 0,
        },
        .arg_entity_index = { 67, },
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

