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

int X509_NAME_get_index_by_NID(X509_NAME * arg_a,int arg_b,int arg_c) 
{
    int ret;

    struct lib_enter_args args = {
        .entity_metadata = {
            0, 8, 0, /* 0: long */
            1, 8, 1, /* 3: pointer.func */
            	8, 0,
            0, 0, 0, /* 8: func */
            1, 8, 1, /* 11: pointer.struct.X509_name_st */
            	16, 0,
            0, 40, 3, /* 16: struct.X509_name_st */
            	25, 0,
            	55, 16,
            	47, 24,
            1, 8, 1, /* 25: pointer.struct.stack_st_OPENSSL_STRING */
            	30, 0,
            0, 32, 1, /* 30: struct.stack_st_OPENSSL_STRING */
            	35, 0,
            0, 32, 2, /* 35: struct.stack_st */
            	42, 8,
            	3, 24,
            1, 8, 1, /* 42: pointer.pointer.char */
            	47, 0,
            1, 8, 1, /* 47: pointer.char */
            	52, 0,
            0, 1, 0, /* 52: char */
            1, 8, 1, /* 55: pointer.struct.buf_mem_st */
            	60, 0,
            0, 24, 1, /* 60: struct.buf_mem_st */
            	47, 8,
            0, 4, 0, /* 65: int */
        },
        .arg_entity_index = { 11, 65, 65, },
        .ret_entity_index = 65,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509_NAME * new_arg_a = *((X509_NAME * *)new_args->args[0]);

    int new_arg_b = *((int *)new_args->args[1]);

    int new_arg_c = *((int *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_X509_NAME_get_index_by_NID)(X509_NAME *,int,int);
    orig_X509_NAME_get_index_by_NID = dlsym(RTLD_NEXT, "X509_NAME_get_index_by_NID");
    *new_ret_ptr = (*orig_X509_NAME_get_index_by_NID)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    return ret;
}

