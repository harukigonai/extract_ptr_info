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

void bb_EC_KEY_free(EC_KEY * arg_a);

void EC_KEY_free(EC_KEY * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EC_KEY_free called %lu\n", in_lib);
    if (!in_lib)
        bb_EC_KEY_free(arg_a);
    else {
        void (*orig_EC_KEY_free)(EC_KEY *);
        orig_EC_KEY_free = dlsym(RTLD_NEXT, "EC_KEY_free");
        orig_EC_KEY_free(arg_a);
    }
}

void bb_EC_KEY_free(EC_KEY * arg_a) 
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
            4097, 8, 0, /* 39: pointer.func */
            1, 8, 1, /* 42: pointer.struct.ec_point_st */
            	47, 0,
            0, 88, 4, /* 47: struct.ec_point_st */
            	58, 0,
            	194, 8,
            	194, 32,
            	194, 56,
            1, 8, 1, /* 58: pointer.struct.ec_method_st */
            	63, 0,
            0, 304, 37, /* 63: struct.ec_method_st */
            	140, 8,
            	143, 16,
            	143, 24,
            	146, 32,
            	36, 40,
            	36, 48,
            	140, 56,
            	33, 64,
            	149, 72,
            	152, 80,
            	152, 88,
            	155, 96,
            	158, 104,
            	161, 112,
            	161, 120,
            	164, 128,
            	164, 136,
            	167, 144,
            	170, 152,
            	173, 160,
            	176, 168,
            	179, 176,
            	182, 184,
            	158, 192,
            	182, 200,
            	179, 208,
            	182, 216,
            	39, 224,
            	185, 232,
            	33, 240,
            	140, 248,
            	36, 256,
            	188, 264,
            	36, 272,
            	188, 280,
            	188, 288,
            	191, 296,
            4097, 8, 0, /* 140: pointer.func */
            4097, 8, 0, /* 143: pointer.func */
            4097, 8, 0, /* 146: pointer.func */
            4097, 8, 0, /* 149: pointer.func */
            4097, 8, 0, /* 152: pointer.func */
            4097, 8, 0, /* 155: pointer.func */
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
            0, 24, 1, /* 194: struct.bignum_st */
            	199, 0,
            1, 8, 1, /* 199: pointer.int */
            	30, 0,
            0, 232, 12, /* 204: struct.ec_group_st */
            	58, 0,
            	42, 8,
            	194, 16,
            	194, 40,
            	231, 80,
            	19, 96,
            	194, 104,
            	194, 152,
            	194, 176,
            	231, 208,
            	231, 216,
            	0, 224,
            1, 8, 1, /* 231: pointer.char */
            	4096, 0,
            1, 8, 1, /* 236: pointer.struct.bignum_st */
            	194, 0,
            1, 8, 1, /* 241: pointer.struct.ec_group_st */
            	204, 0,
            0, 56, 4, /* 246: struct.ec_key_st */
            	241, 8,
            	42, 16,
            	236, 24,
            	19, 48,
            0, 1, 0, /* 257: char */
            1, 8, 1, /* 260: pointer.struct.ec_key_st */
            	246, 0,
        },
        .arg_entity_index = { 260, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EC_KEY * new_arg_a = *((EC_KEY * *)new_args->args[0]);

    void (*orig_EC_KEY_free)(EC_KEY *);
    orig_EC_KEY_free = dlsym(RTLD_NEXT, "EC_KEY_free");
    (*orig_EC_KEY_free)(new_arg_a);

    syscall(889);

}

