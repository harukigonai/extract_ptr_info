#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
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

void bb_CRYPTO_THREADID_set_numeric(CRYPTO_THREADID * arg_a,unsigned long arg_b);

void CRYPTO_THREADID_set_numeric(CRYPTO_THREADID * arg_a,unsigned long arg_b) 
{
    unsigned long in_lib = syscall(890);
    printf("CRYPTO_THREADID_set_numeric called %lu\n", in_lib);
    if (!in_lib)
        bb_CRYPTO_THREADID_set_numeric(arg_a,arg_b);
    else {
        void (*orig_CRYPTO_THREADID_set_numeric)(CRYPTO_THREADID *,unsigned long);
        orig_CRYPTO_THREADID_set_numeric = dlsym(RTLD_NEXT, "CRYPTO_THREADID_set_numeric");
        orig_CRYPTO_THREADID_set_numeric(arg_a,arg_b);
    }
}

void bb_CRYPTO_THREADID_set_numeric(CRYPTO_THREADID * arg_a,unsigned long arg_b) 
{
    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 0; em[1] = 8; em[2] = 0; /* 0: pointer.void */
    em[3] = 0; em[4] = 16; em[5] = 1; /* 3: struct.crypto_threadid_st */
    	em[6] = 0; em[7] = 0; 
    em[8] = 1; em[9] = 8; em[10] = 1; /* 8: pointer.struct.crypto_threadid_st */
    	em[11] = 3; em[12] = 0; 
    em[13] = 0; em[14] = 8; em[15] = 0; /* 13: long unsigned int */
    args_addr->arg_entity_index[0] = 8;
    args_addr->arg_entity_index[1] = 13;
    args_addr->ret_entity_index = -1;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    CRYPTO_THREADID * new_arg_a = *((CRYPTO_THREADID * *)new_args->args[0]);

    unsigned long new_arg_b = *((unsigned long *)new_args->args[1]);

    void (*orig_CRYPTO_THREADID_set_numeric)(CRYPTO_THREADID *,unsigned long);
    orig_CRYPTO_THREADID_set_numeric = dlsym(RTLD_NEXT, "CRYPTO_THREADID_set_numeric");
    (*orig_CRYPTO_THREADID_set_numeric)(new_arg_a,new_arg_b);

    syscall(889);

    free(args_addr);

}

