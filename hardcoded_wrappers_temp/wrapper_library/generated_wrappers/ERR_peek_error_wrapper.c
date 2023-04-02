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

unsigned long bb_ERR_peek_error(void);

unsigned long ERR_peek_error(void) 
{
    unsigned long in_lib = syscall(890);
    printf("ERR_peek_error called %lu\n", in_lib);
    if (!in_lib)
        return bb_ERR_peek_error();
    else {
        unsigned long (*orig_ERR_peek_error)(void);
        orig_ERR_peek_error = dlsym(RTLD_NEXT, "ERR_peek_error");
        return orig_ERR_peek_error();
    }
}

unsigned long bb_ERR_peek_error(void) 
{
    unsigned long ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 8, 0, /* 0: pointer.void */
            0, 8, 0, /* 3: long */
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 3,
    };
    struct lib_enter_args *args_addr = &args;
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    unsigned long *new_ret_ptr = (unsigned long *)new_args->ret;

    unsigned long (*orig_ERR_peek_error)(void);
    orig_ERR_peek_error = dlsym(RTLD_NEXT, "ERR_peek_error");
    *new_ret_ptr = (*orig_ERR_peek_error)();

    syscall(889);

    return ret;
}

