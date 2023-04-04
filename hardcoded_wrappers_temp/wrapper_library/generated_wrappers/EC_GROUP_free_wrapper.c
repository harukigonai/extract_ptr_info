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
            4097, 8, 0, /* 0: pointer.func */
            4097, 8, 0, /* 3: pointer.func */
            0, 40, 5, /* 6: struct.ec_extra_data_st */
            	19, 0,
            	24, 8,
            	27, 16,
            	3, 24,
            	3, 32,
            1, 8, 1, /* 19: pointer.struct.ec_extra_data_st */
            	6, 0,
            0, 8, 0, /* 24: pointer.void */
            4097, 8, 0, /* 27: pointer.func */
            0, 4, 0, /* 30: int */
            4097, 8, 0, /* 33: pointer.func */
            4097, 8, 0, /* 36: pointer.func */
            0, 1, 0, /* 39: char */
            4097, 8, 0, /* 42: pointer.func */
            4097, 8, 0, /* 45: pointer.func */
            4097, 8, 0, /* 48: pointer.func */
            4097, 8, 0, /* 51: pointer.func */
            4097, 8, 0, /* 54: pointer.func */
            4097, 8, 0, /* 57: pointer.func */
            1, 8, 1, /* 60: pointer.struct.ec_point_st */
            	65, 0,
            0, 88, 4, /* 65: struct.ec_point_st */
            	76, 0,
            	197, 8,
            	197, 32,
            	197, 56,
            1, 8, 1, /* 76: pointer.struct.ec_method_st */
            	81, 0,
            0, 304, 37, /* 81: struct.ec_method_st */
            	158, 8,
            	54, 16,
            	54, 24,
            	161, 32,
            	48, 40,
            	48, 48,
            	158, 56,
            	45, 64,
            	164, 72,
            	36, 80,
            	36, 88,
            	167, 96,
            	170, 104,
            	173, 112,
            	173, 120,
            	176, 128,
            	176, 136,
            	57, 144,
            	179, 152,
            	182, 160,
            	185, 168,
            	42, 176,
            	188, 184,
            	170, 192,
            	188, 200,
            	42, 208,
            	188, 216,
            	51, 224,
            	191, 232,
            	45, 240,
            	158, 248,
            	48, 256,
            	194, 264,
            	48, 272,
            	194, 280,
            	194, 288,
            	33, 296,
            4097, 8, 0, /* 158: pointer.func */
            4097, 8, 0, /* 161: pointer.func */
            4097, 8, 0, /* 164: pointer.func */
            4097, 8, 0, /* 167: pointer.func */
            4097, 8, 0, /* 170: pointer.func */
            4097, 8, 0, /* 173: pointer.func */
            4097, 8, 0, /* 176: pointer.func */
            4097, 8, 0, /* 179: pointer.func */
            4097, 8, 0, /* 182: pointer.func */
            4097, 8, 0, /* 185: pointer.func */
            4097, 8, 0, /* 188: pointer.func */
            4097, 8, 0, /* 191: pointer.func */
            4097, 8, 0, /* 194: pointer.func */
            0, 24, 1, /* 197: struct.bignum_st */
            	202, 0,
            1, 8, 1, /* 202: pointer.int */
            	30, 0,
            1, 8, 1, /* 207: pointer.char */
            	4096, 0,
            0, 232, 12, /* 212: struct.ec_group_st */
            	76, 0,
            	60, 8,
            	197, 16,
            	197, 40,
            	207, 80,
            	19, 96,
            	197, 104,
            	197, 152,
            	197, 176,
            	207, 208,
            	207, 216,
            	0, 224,
            1, 8, 1, /* 239: pointer.struct.ec_group_st */
            	212, 0,
        },
        .arg_entity_index = { 239, },
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

