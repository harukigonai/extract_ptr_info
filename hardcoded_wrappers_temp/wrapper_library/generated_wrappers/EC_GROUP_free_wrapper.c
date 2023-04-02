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
            0, 8, 0, /* 0: pointer.void */
            0, 0, 0, /* 3: func */
            4097, 8, 0, /* 6: pointer.func */
            0, 24, 0, /* 9: array[6].int */
            0, 0, 0, /* 12: func */
            0, 8, 1, /* 15: pointer.int */
            	20, 0,
            0, 4, 0, /* 20: int */
            4097, 8, 0, /* 23: pointer.func */
            4097, 8, 0, /* 26: pointer.func */
            4097, 8, 0, /* 29: pointer.func */
            0, 0, 0, /* 32: func */
            0, 0, 0, /* 35: func */
            0, 0, 0, /* 38: func */
            4097, 8, 0, /* 41: pointer.func */
            0, 0, 0, /* 44: func */
            4097, 8, 0, /* 47: pointer.func */
            0, 0, 0, /* 50: func */
            0, 8, 1, /* 53: pointer.struct.ec_group_st */
            	58, 0,
            0, 232, 12, /* 58: struct.ec_group_st */
            	85, 0,
            	218, 8,
            	234, 16,
            	234, 40,
            	239, 80,
            	244, 96,
            	234, 104,
            	234, 152,
            	234, 176,
            	0, 208,
            	0, 216,
            	6, 224,
            0, 8, 1, /* 85: pointer.struct.ec_method_st */
            	90, 0,
            0, 304, 37, /* 90: struct.ec_method_st */
            	167, 8,
            	170, 16,
            	170, 24,
            	173, 32,
            	176, 40,
            	176, 48,
            	167, 56,
            	47, 64,
            	29, 72,
            	23, 80,
            	23, 88,
            	179, 96,
            	182, 104,
            	185, 112,
            	185, 120,
            	26, 128,
            	26, 136,
            	188, 144,
            	191, 152,
            	194, 160,
            	197, 168,
            	200, 176,
            	203, 184,
            	182, 192,
            	203, 200,
            	200, 208,
            	203, 216,
            	206, 224,
            	209, 232,
            	47, 240,
            	167, 248,
            	176, 256,
            	212, 264,
            	176, 272,
            	212, 280,
            	212, 288,
            	215, 296,
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
            4097, 8, 0, /* 197: pointer.func */
            4097, 8, 0, /* 200: pointer.func */
            4097, 8, 0, /* 203: pointer.func */
            4097, 8, 0, /* 206: pointer.func */
            4097, 8, 0, /* 209: pointer.func */
            4097, 8, 0, /* 212: pointer.func */
            4097, 8, 0, /* 215: pointer.func */
            0, 8, 1, /* 218: pointer.struct.ec_point_st */
            	223, 0,
            0, 88, 4, /* 223: struct.ec_point_st */
            	85, 0,
            	234, 8,
            	234, 32,
            	234, 56,
            0, 24, 1, /* 234: struct.bignum_st */
            	15, 0,
            0, 8, 1, /* 239: pointer.char */
            	4096, 0,
            0, 8, 1, /* 244: pointer.struct.ec_extra_data_st */
            	249, 0,
            0, 40, 5, /* 249: struct.ec_extra_data_st */
            	244, 0,
            	0, 8,
            	262, 16,
            	41, 24,
            	41, 32,
            4097, 8, 0, /* 262: pointer.func */
            0, 0, 0, /* 265: func */
            0, 0, 0, /* 268: func */
            0, 0, 0, /* 271: func */
            0, 0, 0, /* 274: func */
            0, 0, 0, /* 277: func */
            0, 0, 0, /* 280: func */
            0, 0, 0, /* 283: func */
            0, 0, 0, /* 286: func */
            0, 0, 0, /* 289: func */
            0, 0, 0, /* 292: func */
            0, 8, 0, /* 295: long */
            0, 0, 0, /* 298: func */
            0, 0, 0, /* 301: func */
            0, 1, 0, /* 304: char */
            0, 0, 0, /* 307: func */
            0, 0, 0, /* 310: func */
            0, 0, 0, /* 313: func */
            0, 0, 0, /* 316: func */
            0, 0, 0, /* 319: func */
        },
        .arg_entity_index = { 53, },
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

