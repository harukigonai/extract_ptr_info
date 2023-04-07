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

int bb_CRYPTO_THREADID_set_callback(void (*arg_a)(CRYPTO_THREADID *));

int CRYPTO_THREADID_set_callback(void (*arg_a)(CRYPTO_THREADID *)) 
{
    unsigned long in_lib = syscall(890);
    printf("CRYPTO_THREADID_set_callback called %lu\n", in_lib);
    if (!in_lib)
        return bb_CRYPTO_THREADID_set_callback(arg_a);
    else {
        int (*orig_CRYPTO_THREADID_set_callback)(void (*)(CRYPTO_THREADID *));
        orig_CRYPTO_THREADID_set_callback = dlsym(RTLD_NEXT, "CRYPTO_THREADID_set_callback");
        return orig_CRYPTO_THREADID_set_callback(arg_a);
    }
}

int bb_CRYPTO_THREADID_set_callback(void (*arg_a)(CRYPTO_THREADID *)) 
{
    int ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 8884097; em[1] = 8; em[2] = 0; /* 0: pointer.func */
    em[3] = 0; em[4] = 4; em[5] = 0; /* 3: int */
    args_addr->arg_entity_index[0] = 0;
    args_addr->ret_entity_index = 3;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    void (*new_arg_a)(CRYPTO_THREADID *) = *((void (**)(CRYPTO_THREADID *))new_args->args[0]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_CRYPTO_THREADID_set_callback)(void (*)(CRYPTO_THREADID *));
    orig_CRYPTO_THREADID_set_callback = dlsym(RTLD_NEXT, "CRYPTO_THREADID_set_callback");
    *new_ret_ptr = (*orig_CRYPTO_THREADID_set_callback)(new_arg_a);

    syscall(889);

    free(args_addr);

    return ret;
}

