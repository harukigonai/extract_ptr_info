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

EVP_PKEY * bb_PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d);

EVP_PKEY * PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d) 
{
    unsigned long in_lib = syscall(890);
    printf("PEM_read_bio_PrivateKey called %lu\n", in_lib);
    if (!in_lib)
        return bb_PEM_read_bio_PrivateKey(arg_a,arg_b,arg_c,arg_d);
    else {
        EVP_PKEY * (*orig_PEM_read_bio_PrivateKey)(BIO *,EVP_PKEY **,pem_password_cb *,void *);
        orig_PEM_read_bio_PrivateKey = dlsym(RTLD_NEXT, "PEM_read_bio_PrivateKey");
        return orig_PEM_read_bio_PrivateKey(arg_a,arg_b,arg_c,arg_d);
    }
}

EVP_PKEY * bb_PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d) 
{
    EVP_PKEY * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            4097, 94416425456486, 94396202975600, /* 3: pointer.func */
            	0, 0,
            	0, 4097,
            	94396099098208, 94396202970688,
            	0, 0,
            	0, 4097,
            	94396202975760, 94396202962784,
            	0, 0,
            	0, 4097,
            	112, 48,
            	0, 0,
            	0, 0,
            	80, 1,
            	32, 8,
            	1, 8,
            	1, 4096,
            	0, 0,
            	112, 6,
            	52, 0,
            	32, 16,
            	32, 48,
            	57, 56,
            	57, 64,
            	62, 96,
            	1, 8,
            	1, 27,
            	0, 1,
            	8, 1,
            	37, 0,
            	0, 16,
            	1, 67,
            	0, 1,
            	8, 1,
            	72, 0,
            	0, 32,
            	1, 77,
            	0, 0,
            	32, 1,
            	82, 8,
            	1, 8,
            	1, 32,
            	0, 0,
            	8, 1,
            	32, 0,
            	0, 0,
            	0, 4097,
            	94416425462182, 94396202970272,
            	0, 0,
            	0, 1,
            	8, 1,
            	106, 0,
            	0, 96,
            	2, 32,
            	0, 32,
            	72, 4097,
            	272, 48,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 94396099098464,
            	32, 0,
            	112, 2,
            	32, 0,
            	32, 80,
            	4097, 94396202970464,
            	32, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	1, 8,
            	1, 149,
            	0, 0,
            	32, 2,
            	32, 8,
            	32, 16,
            	4097, 94396202970352,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	94416425462342, 94396201433296,
            	0, 0,
            	0, 0,
            	48, 2,
            	32, 0,
            	32, 40,
            	4097, 193,
            	94396099098208, 4097,
            	32, 48,
            	1, 8,
            	1, 189,
            	0, 0,
            	216, 13,
            	32, 0,
            	32, 8,
            	218, 16,
            	101, 24,
            	223, 32,
            	235, 40,
            	247, 48,
            	252, 56,
            	260, 64,
            	144, 160,
            	62, 184,
            	184, 200,
            	184, 208,
            	1, 8,
            	1, 125,
            	0, 1,
            	8, 1,
            	228, 0,
            	0, 72,
            	2, 32,
            	0, 32,
            	56, 1,
            	8, 1,
            	240, 0,
            	0, 32,
            	2, 32,
            	0, 32,
            	24, 1,
            	8, 1,
            	171, 0,
            	1, 8,
            	1, 257,
            	0, 0,
            	48, 0,
            	1, 8,
            	1, 265,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	112, 48,
            	0, 0,
            	0, 4097,
            	94396202783568, 673,
            	4097, 94396202969248,
            	32, 0,
            	0, 0,
            	4097, 94396202970896,
            	94396202627744, 4097,
            	94396202969648, 94396202969824,
            	4097, 48,
            	94416425462103, 4097,
            	94396202971056, 94396202971456,
            	1, 8,
            	1, 303,
            	0, 0,
            	208, 2,
            	32, 16,
            	32, 24,
            	0, 0,
            	0, 4097,
            	94416425457351, 94396202965040,
            	4097, 94396202964128,
            	94396201899760, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	32, 48,
            	0, 0,
            	0, 4097,
            	94396201433296, 33,
            	0, 0,
            	0, 4097,
            	94416425456951, 94396202965040,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 48,
            	94416506812871, 4097,
            	94396202975280, 94396202968480,
            	0, 8,
            	0, 4097,
            	2912, 48,
            	0, 0,
            	0, 0,
            	56, 4,
            	298, 16,
            	184, 24,
            	87, 32,
            	67, 48,
            	1, 8,
            	1, 367,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 1,
            	8, 1,
            	378, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	0, 1,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 0,
            	4, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 481,
        },
        .arg_entity_index = { 57, 437, 484, 32, },
        .ret_entity_index = 378,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    BIO * new_arg_a = *((BIO * *)new_args->args[0]);

    EVP_PKEY ** new_arg_b = *((EVP_PKEY ** *)new_args->args[1]);

    pem_password_cb * new_arg_c = *((pem_password_cb * *)new_args->args[2]);

    void * new_arg_d = *((void * *)new_args->args[3]);

    EVP_PKEY * *new_ret_ptr = (EVP_PKEY * *)new_args->ret;

    EVP_PKEY * (*orig_PEM_read_bio_PrivateKey)(BIO *,EVP_PKEY **,pem_password_cb *,void *);
    orig_PEM_read_bio_PrivateKey = dlsym(RTLD_NEXT, "PEM_read_bio_PrivateKey");
    *new_ret_ptr = (*orig_PEM_read_bio_PrivateKey)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    return ret;
}

