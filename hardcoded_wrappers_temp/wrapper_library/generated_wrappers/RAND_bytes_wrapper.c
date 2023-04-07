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

int bb_RAND_bytes(unsigned char * arg_a,int arg_b);

int RAND_bytes(unsigned char * arg_a,int arg_b) 
{
    unsigned long in_lib = syscall(890);
    printf("RAND_bytes called %lu\n", in_lib);
    if (!in_lib)
        return bb_RAND_bytes(arg_a,arg_b);
    else {
        int (*orig_RAND_bytes)(unsigned char *,int);
        orig_RAND_bytes = dlsym(RTLD_NEXT, "RAND_bytes");
        return orig_RAND_bytes(arg_a,arg_b);
    }
}

int bb_RAND_bytes(unsigned char * arg_a,int arg_b) 
{
    int ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 0; em[1] = 1; em[2] = 0; /* 0: unsigned char */
    em[3] = 1; em[4] = 8; em[5] = 1; /* 3: pointer.unsigned char */
    	em[6] = 0; em[7] = 0; 
    em[8] = 0; em[9] = 4; em[10] = 0; /* 8: int */
    args_addr->arg_entity_index[0] = 3;
    args_addr->arg_entity_index[1] = 8;
    args_addr->ret_entity_index = 8;
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

    free(args_addr);

    return ret;
}

