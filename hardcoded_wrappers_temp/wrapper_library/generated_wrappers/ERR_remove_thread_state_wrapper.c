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
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 8, 0, /* 0: pointer.void */
            0, 1, 0, /* 3: char */
            0, 8, 1, /* 6: pointer.char */
            	4096, 0,
            0, 16, 1, /* 11: struct.iovec */
            	6, 0,
            0, 8, 0, /* 16: long */
            0, 8, 1, /* 19: pointer.struct.iovec */
            	11, 0,
        },
        .arg_entity_index = { 19, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const CRYPTO_THREADID * new_arg_a = *((const CRYPTO_THREADID * *)new_args->args[0]);

    void (*orig_ERR_remove_thread_state)(const CRYPTO_THREADID *);
    orig_ERR_remove_thread_state = dlsym(RTLD_NEXT, "ERR_remove_thread_state");
    (*orig_ERR_remove_thread_state)(new_arg_a);

    syscall(889);

}

