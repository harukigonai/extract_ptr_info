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
    printf("EC_GROUP_free called\n");
    if (!syscall(890))
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
            0, 8, 0, /* 3: pointer.func */
            0, 0, 0, /* 6: func */
            0, 8, 0, /* 9: pointer.func */
            0, 0, 0, /* 12: func */
            0, 1, 0, /* 15: char */
            0, 0, 0, /* 18: func */
            0, 8, 0, /* 21: pointer.func */
            0, 0, 0, /* 24: func */
            1, 8, 1, /* 27: pointer.struct.ec_group_st */
            	32, 0,
            0, 232, 11, /* 32: struct.ec_group_st */
            	57, 0,
            	65, 8,
            	81, 16,
            	81, 40,
            	94, 80,
            	99, 96,
            	81, 104,
            	81, 152,
            	81, 176,
            	94, 208,
            	94, 216,
            1, 8, 1, /* 57: pointer.struct.ec_method_st */
            	62, 0,
            0, 304, 0, /* 62: struct.ec_method_st */
            1, 8, 1, /* 65: pointer.struct.ec_point_st */
            	70, 0,
            0, 88, 4, /* 70: struct.ec_point_st */
            	57, 0,
            	81, 8,
            	81, 32,
            	81, 56,
            0, 24, 1, /* 81: struct.bignum_st */
            	86, 0,
            1, 8, 1, /* 86: pointer.int */
            	91, 0,
            0, 4, 0, /* 91: int */
            1, 8, 1, /* 94: pointer.char */
            	15, 0,
            1, 8, 1, /* 99: pointer.struct.ec_extra_data_st */
            	104, 0,
            0, 40, 2, /* 104: struct.ec_extra_data_st */
            	99, 0,
            	94, 8,
            0, 8, 0, /* 111: pointer.func */
            0, 8, 0, /* 114: pointer.func */
            0, 0, 0, /* 117: func */
            0, 0, 0, /* 120: func */
            0, 8, 0, /* 123: pointer.func */
            0, 8, 0, /* 126: pointer.func */
            0, 0, 0, /* 129: func */
            0, 0, 0, /* 132: func */
            0, 8, 0, /* 135: pointer.func */
            0, 8, 0, /* 138: pointer.func */
            0, 8, 0, /* 141: pointer.func */
            0, 8, 0, /* 144: pointer.func */
            0, 8, 0, /* 147: pointer.func */
            0, 0, 0, /* 150: func */
            0, 0, 0, /* 153: func */
            0, 8, 0, /* 156: pointer.func */
            0, 0, 0, /* 159: func */
            0, 0, 0, /* 162: func */
            0, 8, 0, /* 165: pointer.func */
            0, 0, 0, /* 168: func */
            0, 8, 0, /* 171: pointer.func */
            0, 8, 0, /* 174: pointer.func */
            0, 0, 0, /* 177: func */
            0, 8, 0, /* 180: pointer.func */
            0, 8, 0, /* 183: pointer.func */
            0, 0, 0, /* 186: func */
            0, 8, 0, /* 189: pointer.func */
            0, 24, 0, /* 192: array[6].int */
            0, 0, 0, /* 195: func */
            0, 8, 0, /* 198: pointer.func */
            0, 8, 0, /* 201: pointer.func */
            0, 8, 0, /* 204: long */
            0, 0, 0, /* 207: func */
            0, 0, 0, /* 210: func */
            0, 8, 0, /* 213: pointer.func */
            0, 8, 0, /* 216: pointer.func */
            0, 0, 0, /* 219: func */
            0, 0, 0, /* 222: func */
            0, 0, 0, /* 225: func */
            0, 8, 0, /* 228: pointer.func */
            0, 0, 0, /* 231: func */
            0, 0, 0, /* 234: func */
        },
        .arg_entity_index = { 27, },
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

