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

void RAND_seed(void * arg_a,int arg_b) 
{
    struct lib_enter_args args = {
        .entity_metadata = {
            0, 4, 0, /* 0: int */
            0, 1, 0, /* 3: char */
            1, 8, 1, /* 6: pointer.char */
            	3, 0,
        },
        .arg_entity_index = { 6, 0, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    void * new_arg_a = *((void * *)new_args->args[0]);

    int new_arg_b = *((int *)new_args->args[1]);

    void (*orig_RAND_seed)(void *,int);
    orig_RAND_seed = dlsym(RTLD_NEXT, "RAND_seed");
    (*orig_RAND_seed)(new_arg_a,new_arg_b);

    syscall(889);

}
