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
            1, 8, 1, /* 0: pointer.char */
            	8884096, 0,
            0, 24, 1, /* 5: struct.buf_mem_st */
            	0, 8,
            1, 8, 1, /* 10: pointer.struct.buf_mem_st */
            	5, 0,
            0, 1, 0, /* 15: unsigned char */
            0, 32, 2, /* 18: struct.stack_st_fake_X509_NAME_ENTRY */
            	25, 8,
            	91, 24,
            8884099, 8, 2, /* 25: pointer_to_array_of_pointers_to_stack */
            	32, 0,
            	88, 20,
            0, 8, 1, /* 32: pointer.X509_NAME_ENTRY */
            	37, 0,
            0, 0, 1, /* 37: X509_NAME_ENTRY */
            	42, 0,
            0, 24, 2, /* 42: struct.X509_name_entry_st */
            	49, 0,
            	73, 8,
            1, 8, 1, /* 49: pointer.struct.asn1_object_st */
            	54, 0,
            0, 40, 3, /* 54: struct.asn1_object_st */
            	63, 0,
            	63, 8,
            	68, 24,
            1, 8, 1, /* 63: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 68: pointer.unsigned char */
            	15, 0,
            1, 8, 1, /* 73: pointer.struct.asn1_string_st */
            	78, 0,
            0, 24, 1, /* 78: struct.asn1_string_st */
            	83, 8,
            1, 8, 1, /* 83: pointer.unsigned char */
            	15, 0,
            0, 4, 0, /* 88: int */
            8884097, 8, 0, /* 91: pointer.func */
            0, 1, 0, /* 94: char */
            1, 8, 1, /* 97: pointer.struct.X509_name_st */
            	102, 0,
            0, 40, 3, /* 102: struct.X509_name_st */
            	111, 0,
            	10, 16,
            	83, 24,
            1, 8, 1, /* 111: pointer.struct.stack_st_X509_NAME_ENTRY */
            	18, 0,
        },
        .arg_entity_index = { 97, 88, 88, },
        .ret_entity_index = 88,
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

