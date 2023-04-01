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

void bb_EC_GROUP_free(EC_GROUP * arg_a);

void EC_GROUP_free(EC_GROUP * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EC_GROUP_free called %lu\n", in_lib);
    if (!in_lib)
        bb_EC_GROUP_free(arg_a);
    else {
        void (*orig_EC_GROUP_free)(EC_GROUP *);
        orig_EC_GROUP_free = dlsym(RTLD_NEXT, "EC_GROUP_free");
        orig_EC_GROUP_free(arg_a);
    }
}

void bb_EC_GROUP_free(EC_GROUP * arg_a) 
{
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            4097, 0, 0, /* 3: pointer.func */
            0, 24, 0, /* 6: array[6].int */
            4097, 0, 0, /* 9: pointer.func */
            0, 0, 0, /* 12: func */
            0, 0, 0, /* 15: func */
            4097, 0, 0, /* 18: pointer.func */
            4097, 0, 0, /* 21: pointer.func */
            0, 0, 0, /* 24: func */
            4097, 0, 0, /* 27: pointer.func */
            0, 0, 0, /* 30: func */
            0, 0, 0, /* 33: func */
            1, 8, 1, /* 36: pointer.struct.ec_method_st */
            	41, 0,
            0, 304, 0, /* 41: struct.ec_method_st */
            4097, 0, 0, /* 44: pointer.func */
            0, 0, 0, /* 47: func */
            1, 8, 1, /* 50: pointer.struct.ec_group_st */
            	55, 0,
            0, 232, 11, /* 55: struct.ec_group_st */
            	36, 0,
            	80, 8,
            	96, 16,
            	96, 40,
            	109, 80,
            	114, 96,
            	96, 104,
            	96, 152,
            	96, 176,
            	109, 208,
            	109, 216,
            1, 8, 1, /* 80: pointer.struct.ec_point_st */
            	85, 0,
            0, 88, 4, /* 85: struct.ec_point_st */
            	36, 0,
            	96, 8,
            	96, 32,
            	96, 56,
            0, 24, 1, /* 96: struct.bignum_st */
            	101, 0,
            1, 8, 1, /* 101: pointer.int */
            	106, 0,
            0, 4, 0, /* 106: int */
            1, 8, 1, /* 109: pointer.char */
            	4096, 0,
            1, 8, 1, /* 114: pointer.struct.ec_extra_data_st */
            	119, 0,
            0, 40, 2, /* 119: struct.ec_extra_data_st */
            	114, 0,
            	109, 8,
            0, 0, 0, /* 126: func */
            4097, 0, 0, /* 129: pointer.func */
            0, 0, 0, /* 132: func */
            4097, 0, 0, /* 135: pointer.func */
            4097, 0, 0, /* 138: pointer.func */
            4097, 0, 0, /* 141: pointer.func */
            0, 0, 0, /* 144: func */
            0, 0, 0, /* 147: func */
            4097, 0, 0, /* 150: pointer.func */
            4097, 0, 0, /* 153: pointer.func */
            4097, 0, 0, /* 156: pointer.func */
            4097, 0, 0, /* 159: pointer.func */
            0, 0, 0, /* 162: func */
            0, 0, 0, /* 165: func */
            0, 0, 0, /* 168: func */
            0, 0, 0, /* 171: func */
            0, 0, 0, /* 174: func */
            4097, 0, 0, /* 177: pointer.func */
            0, 0, 0, /* 180: func */
            4097, 0, 0, /* 183: pointer.func */
            0, 0, 0, /* 186: func */
            4097, 0, 0, /* 189: pointer.func */
            0, 0, 0, /* 192: func */
            4097, 0, 0, /* 195: pointer.func */
            4097, 0, 0, /* 198: pointer.func */
            0, 0, 0, /* 201: func */
            4097, 0, 0, /* 204: pointer.func */
            0, 1, 0, /* 207: char */
            4097, 0, 0, /* 210: pointer.func */
            0, 0, 0, /* 213: func */
            0, 0, 0, /* 216: func */
            4097, 0, 0, /* 219: pointer.func */
            0, 0, 0, /* 222: func */
            0, 8, 0, /* 225: long */
            4097, 0, 0, /* 228: pointer.func */
            0, 0, 0, /* 231: func */
            4097, 0, 0, /* 234: pointer.func */
        },
        .arg_entity_index = { 50, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EC_GROUP * new_arg_a = *((EC_GROUP * *)new_args->args[0]);

    void (*orig_EC_GROUP_free)(EC_GROUP *);
    orig_EC_GROUP_free = dlsym(RTLD_NEXT, "EC_GROUP_free");
    (*orig_EC_GROUP_free)(new_arg_a);

    syscall(889);

}

