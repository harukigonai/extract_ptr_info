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
            0, 4, 0, /* 0: int */
            0, 1, 0, /* 3: char */
            0, 1, 0, /* 6: unsigned char */
            0, 32, 1, /* 9: struct.stack_st_X509_NAME_ENTRY */
            	14, 0,
            0, 32, 2, /* 14: struct.stack_st */
            	21, 8,
            	31, 24,
            1, 8, 1, /* 21: pointer.pointer.char */
            	26, 0,
            1, 8, 1, /* 26: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 31: pointer.func */
            1, 8, 1, /* 34: pointer.unsigned char */
            	6, 0,
            0, 40, 3, /* 39: struct.X509_name_st */
            	48, 0,
            	53, 16,
            	34, 24,
            1, 8, 1, /* 48: pointer.struct.stack_st_X509_NAME_ENTRY */
            	9, 0,
            1, 8, 1, /* 53: pointer.struct.buf_mem_st */
            	58, 0,
            0, 24, 1, /* 58: struct.buf_mem_st */
            	26, 8,
            1, 8, 1, /* 63: pointer.struct.X509_name_st */
            	39, 0,
        },
        .arg_entity_index = { 63, 0, 0, },
        .ret_entity_index = 0,
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

