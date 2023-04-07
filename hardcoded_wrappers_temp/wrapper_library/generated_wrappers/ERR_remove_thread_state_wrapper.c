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

void bb_ERR_remove_thread_state(const CRYPTO_THREADID * arg_a);

void ERR_remove_thread_state(const CRYPTO_THREADID * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("ERR_remove_thread_state called %lu\n", in_lib);
    if (!in_lib)
        bb_ERR_remove_thread_state(arg_a);
    else {
        void (*orig_ERR_remove_thread_state)(const CRYPTO_THREADID *);
        orig_ERR_remove_thread_state = dlsym(RTLD_NEXT, "ERR_remove_thread_state");
        orig_ERR_remove_thread_state(arg_a);
    }
}

void bb_ERR_remove_thread_state(const CRYPTO_THREADID * arg_a) 
{
    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 0; em[1] = 8; em[2] = 0; /* 0: pointer.void */
    em[3] = 0; em[4] = 16; em[5] = 1; /* 3: struct.crypto_threadid_st */
    	em[6] = 0; em[7] = 0; 
    em[8] = 1; em[9] = 8; em[10] = 1; /* 8: pointer.struct.crypto_threadid_st */
    	em[11] = 3; em[12] = 0; 
    args_addr->arg_entity_index[0] = 8;
    args_addr->ret_entity_index = -1;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const CRYPTO_THREADID * new_arg_a = *((const CRYPTO_THREADID * *)new_args->args[0]);

    void (*orig_ERR_remove_thread_state)(const CRYPTO_THREADID *);
    orig_ERR_remove_thread_state = dlsym(RTLD_NEXT, "ERR_remove_thread_state");
    (*orig_ERR_remove_thread_state)(new_arg_a);

    syscall(889);

    free(args_addr);

}

