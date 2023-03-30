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

void bb_CRYPTO_set_dynlock_destroy_callback(void (*arg_a)(struct CRYPTO_dynlock_value *, const char *, int));

void CRYPTO_set_dynlock_destroy_callback(void (*arg_a)(struct CRYPTO_dynlock_value *, const char *, int)) 
{
    printf("CRYPTO_set_dynlock_destroy_callback called\n");
    if (!syscall(890))
        bb_CRYPTO_set_dynlock_destroy_callback(arg_a);
    else {
        void (*orig_CRYPTO_set_dynlock_destroy_callback)(void (*)(struct CRYPTO_dynlock_value *, const char *, int));
        orig_CRYPTO_set_dynlock_destroy_callback = dlsym(RTLD_NEXT, "CRYPTO_set_dynlock_destroy_callback");
        orig_CRYPTO_set_dynlock_destroy_callback(arg_a);
    }
}

void bb_CRYPTO_set_dynlock_destroy_callback(void (*arg_a)(struct CRYPTO_dynlock_value *, const char *, int)) 
{
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            1, 8, 1, /* 3: pointer.func */
            	0, 0,
        },
        .arg_entity_index = { 3, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    void (*new_arg_a)(struct CRYPTO_dynlock_value *, const char *, int) = *((void (**)(struct CRYPTO_dynlock_value *, const char *, int))new_args->args[0]);

    void (*orig_CRYPTO_set_dynlock_destroy_callback)(void (*)(struct CRYPTO_dynlock_value *, const char *, int));
    orig_CRYPTO_set_dynlock_destroy_callback = dlsym(RTLD_NEXT, "CRYPTO_set_dynlock_destroy_callback");
    (*orig_CRYPTO_set_dynlock_destroy_callback)(new_arg_a);

    syscall(889);

}

