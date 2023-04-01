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

int bb_EC_GROUP_get_curve_name(const EC_GROUP * arg_a);

int EC_GROUP_get_curve_name(const EC_GROUP * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EC_GROUP_get_curve_name called %lu\n", in_lib);
    if (!in_lib)
        return bb_EC_GROUP_get_curve_name(arg_a);
    else {
        int (*orig_EC_GROUP_get_curve_name)(const EC_GROUP *);
        orig_EC_GROUP_get_curve_name = dlsym(RTLD_NEXT, "EC_GROUP_get_curve_name");
        return orig_EC_GROUP_get_curve_name(arg_a);
    }
}

int bb_EC_GROUP_get_curve_name(const EC_GROUP * arg_a) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            4097, 18446744073709547520, 0, /* 3: pointer.func */
            0, 24, 0, /* 6: array[6].int */
            4097, 94396104177544, 94396099892520, /* 9: pointer.func */
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 94396099435280,
            	18446744073709547520, 4097,
            	18446744073709547520, 0,
            	0, 0,
            	0, 4097,
            	94396103412376, 94396099715664,
            	0, 0,
            	0, 0,
            	0, 0,
            	1, 8,
            	1, 41,
            	0, 0,
            	304, 0,
            	4097, 94396099309520,
            	18446744073709547520, 0,
            	0, 0,
            	4097, 0,
            	18446744073709547520, 4097,
            	94396102905336, 94396099402464,
            	0, 0,
            	0, 1,
            	8, 1,
            	64, 0,
            	0, 232,
            	11, 36,
            	0, 89,
            	8, 105,
            	16, 105,
            	40, 118,
            	80, 123,
            	96, 105,
            	104, 105,
            	152, 105,
            	176, 118,
            	208, 118,
            	216, 1,
            	8, 1,
            	94, 0,
            	0, 88,
            	4, 36,
            	0, 105,
            	8, 105,
            	32, 105,
            	56, 0,
            	24, 1,
            	110, 0,
            	1, 8,
            	1, 115,
            	0, 0,
            	4, 0,
            	1, 8,
            	1, 4096,
            	0, 1,
            	8, 1,
            	128, 0,
            	0, 40,
            	2, 123,
            	0, 118,
            	8, 0,
            	0, 0,
            	4097, 94396099891040,
            	18446744073709547520, 0,
            	0, 0,
            	4097, 94396099285168,
            	18446744073709547520, 0,
            	0, 0,
            	4097, 94396099273824,
            	18446744073709547520, 4097,
            	18446744073709547520, 0,
            	4097, 0,
            	18446744073709547520, 4097,
            	18446744073709547520, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	94396102904120, 94396099633024,
            	0, 0,
            	0, 4097,
            	94396101379992, 94396099496096,
            	0, 0,
            	0, 4097,
            	18446744073709547520, 0,
            	0, 0,
            	0, 4097,
            	18446744073709547520, 0,
            	4097, 94396099850976,
            	18446744073709547520, 0,
            	0, 0,
            	4097, 94396099890784,
            	18446744073709547520, 0,
            	1, 0,
            	4097, 94396099285088,
            	18446744073709547520, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	94396102650776, 94396099502208,
            	0, 0,
            	0, 0,
            	8, 0,
            	4097, 94396099850576,
            	18446744073709547520, 0,
            	0, 0,
            	4097, 0,
            	18446744073709547520, 193,
        },
        .arg_entity_index = { 59, },
        .ret_entity_index = 115,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const EC_GROUP * new_arg_a = *((const EC_GROUP * *)new_args->args[0]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EC_GROUP_get_curve_name)(const EC_GROUP *);
    orig_EC_GROUP_get_curve_name = dlsym(RTLD_NEXT, "EC_GROUP_get_curve_name");
    *new_ret_ptr = (*orig_EC_GROUP_get_curve_name)(new_arg_a);

    syscall(889);

    return ret;
}

