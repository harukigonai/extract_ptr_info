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

int RAND_bytes(unsigned char * arg_a,int arg_b) 
{
    printf("RAND_bytes called\n");
    int ret;

    struct lib_enter_args args = {
        .entity_metadata = {
            0, 1, 0, /* 0: char */
            1, 8, 1, /* 3: pointer.char */
            	0, 0,
            0, 4, 0, /* 8: int */
        },
        .arg_entity_index = { 3, 8, },
        .ret_entity_index = 8,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    unsigned char * new_arg_a = *((unsigned char * *)new_args->args[0]);

    int new_arg_b = *((int *)new_args->args[1]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_RAND_bytes)(unsigned char *,int);
    orig_RAND_bytes = dlsym(RTLD_NEXT, "RAND_bytes");
    *new_ret_ptr = (*orig_RAND_bytes)(new_arg_a,new_arg_b);

    syscall(889);

    return ret;
}

