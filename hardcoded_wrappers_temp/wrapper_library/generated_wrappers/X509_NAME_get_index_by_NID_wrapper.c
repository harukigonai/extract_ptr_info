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

int bb_X509_NAME_get_index_by_NID(X509_NAME * arg_a,int arg_b,int arg_c);

int X509_NAME_get_index_by_NID(X509_NAME * arg_a,int arg_b,int arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_NAME_get_index_by_NID called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_NAME_get_index_by_NID(arg_a,arg_b,arg_c);
    else {
        int (*orig_X509_NAME_get_index_by_NID)(X509_NAME *,int,int);
        orig_X509_NAME_get_index_by_NID = dlsym(RTLD_NEXT, "X509_NAME_get_index_by_NID");
        return orig_X509_NAME_get_index_by_NID(arg_a,arg_b,arg_c);
    }
}

int bb_X509_NAME_get_index_by_NID(X509_NAME * arg_a,int arg_b,int arg_c) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 8, 0, /* 0: long */
            1, 8, 1, /* 3: pointer.char */
            	4096, 0,
            1, 8, 1, /* 8: pointer.struct.X509_name_st */
            	13, 0,
            0, 40, 3, /* 13: struct.X509_name_st */
            	22, 0,
            	42, 16,
            	3, 24,
            1, 8, 1, /* 22: pointer.struct.stack_st_OPENSSL_STRING */
            	27, 0,
            0, 32, 1, /* 27: struct.stack_st_OPENSSL_STRING */
            	32, 0,
            0, 32, 1, /* 32: struct.stack_st */
            	37, 8,
            1, 8, 1, /* 37: pointer.pointer.char */
            	3, 0,
            1, 8, 1, /* 42: pointer.struct.buf_mem_st */
            	47, 0,
            0, 24, 1, /* 47: struct.buf_mem_st */
            	3, 8,
            0, 1, 0, /* 52: char */
            4097, 94396186125840, 94396186129968, /* 55: pointer.func */
            	0, 4,
            	0, 0,
            	0, 0,
        },
        .arg_entity_index = { 8, 58, 58, },
        .ret_entity_index = 58,
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

