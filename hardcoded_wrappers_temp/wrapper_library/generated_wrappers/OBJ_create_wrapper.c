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

int bb_OBJ_create(const char * arg_a,const char * arg_b,const char * arg_c);

int OBJ_create(const char * arg_a,const char * arg_b,const char * arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("OBJ_create called %lu\n", in_lib);
    if (!in_lib)
        return bb_OBJ_create(arg_a,arg_b,arg_c);
    else {
        int (*orig_OBJ_create)(const char *,const char *,const char *);
        orig_OBJ_create = dlsym(RTLD_NEXT, "OBJ_create");
        return orig_OBJ_create(arg_a,arg_b,arg_c);
    }
}

int bb_OBJ_create(const char * arg_a,const char * arg_b,const char * arg_c) 
{
    int ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 1; em[1] = 8; em[2] = 1; /* 0: pointer.char */
    	em[3] = 8884096; em[4] = 0; 
    em[5] = 0; em[6] = 1; em[7] = 0; /* 5: char */
    em[8] = 0; em[9] = 4; em[10] = 0; /* 8: int */
    args_addr->arg_entity_index[0] = 0;
    args_addr->arg_entity_index[1] = 0;
    args_addr->arg_entity_index[2] = 0;
    args_addr->ret_entity_index = 8;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const char * new_arg_a = *((const char * *)new_args->args[0]);

    const char * new_arg_b = *((const char * *)new_args->args[1]);

    const char * new_arg_c = *((const char * *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_OBJ_create)(const char *,const char *,const char *);
    orig_OBJ_create = dlsym(RTLD_NEXT, "OBJ_create");
    *new_ret_ptr = (*orig_OBJ_create)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    free(args_addr);

    return ret;
}

