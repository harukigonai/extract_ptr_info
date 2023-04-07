#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
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

void bb_CRYPTO_set_dynlock_lock_callback(void (*arg_a)(int, struct CRYPTO_dynlock_value *, const char *, int));

void CRYPTO_set_dynlock_lock_callback(void (*arg_a)(int, struct CRYPTO_dynlock_value *, const char *, int)) 
{
    unsigned long in_lib = syscall(890);
    printf("CRYPTO_set_dynlock_lock_callback called %lu\n", in_lib);
    if (!in_lib)
        bb_CRYPTO_set_dynlock_lock_callback(arg_a);
    else {
        void (*orig_CRYPTO_set_dynlock_lock_callback)(void (*)(int, struct CRYPTO_dynlock_value *, const char *, int));
        orig_CRYPTO_set_dynlock_lock_callback = dlsym(RTLD_NEXT, "CRYPTO_set_dynlock_lock_callback");
        orig_CRYPTO_set_dynlock_lock_callback(arg_a);
    }
}

void bb_CRYPTO_set_dynlock_lock_callback(void (*arg_a)(int, struct CRYPTO_dynlock_value *, const char *, int)) 
{
    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 8884097; em[1] = 8; em[2] = 0; /* 0: pointer.func */
    args_addr->arg_entity_index[0] = 0;
    args_addr->ret_entity_index = -1;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    void (*new_arg_a)(int, struct CRYPTO_dynlock_value *, const char *, int) = *((void (**)(int, struct CRYPTO_dynlock_value *, const char *, int))new_args->args[0]);

    void (*orig_CRYPTO_set_dynlock_lock_callback)(void (*)(int, struct CRYPTO_dynlock_value *, const char *, int));
    orig_CRYPTO_set_dynlock_lock_callback = dlsym(RTLD_NEXT, "CRYPTO_set_dynlock_lock_callback");
    (*orig_CRYPTO_set_dynlock_lock_callback)(new_arg_a);

    syscall(889);

    free(args_addr);

}

