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
            4097, 8, 0, /* 3: pointer.func */
            0, 24, 0, /* 6: array[6].int */
            0, 0, 0, /* 9: func */
            1, 8, 1, /* 12: pointer.int */
            	17, 0,
            0, 4, 0, /* 17: int */
            4097, 8, 0, /* 20: pointer.func */
            4097, 8, 0, /* 23: pointer.func */
            4097, 8, 0, /* 26: pointer.func */
            0, 0, 0, /* 29: func */
            0, 0, 0, /* 32: func */
            0, 0, 0, /* 35: func */
            4097, 8, 0, /* 38: pointer.func */
            0, 0, 0, /* 41: func */
            4097, 8, 0, /* 44: pointer.func */
            0, 0, 0, /* 47: func */
            1, 8, 1, /* 50: pointer.struct.ec_group_st */
            	55, 0,
            0, 232, 12, /* 55: struct.ec_group_st */
            	82, 0,
            	215, 8,
            	231, 16,
            	231, 40,
            	236, 80,
            	241, 96,
            	231, 104,
            	231, 152,
            	231, 176,
            	259, 208,
            	259, 216,
            	3, 224,
            1, 8, 1, /* 82: pointer.struct.ec_method_st */
            	87, 0,
            0, 304, 37, /* 87: struct.ec_method_st */
            	164, 8,
            	167, 16,
            	167, 24,
            	170, 32,
            	173, 40,
            	173, 48,
            	164, 56,
            	44, 64,
            	26, 72,
            	20, 80,
            	20, 88,
            	176, 96,
            	179, 104,
            	182, 112,
            	182, 120,
            	23, 128,
            	23, 136,
            	185, 144,
            	188, 152,
            	191, 160,
            	194, 168,
            	197, 176,
            	200, 184,
            	179, 192,
            	200, 200,
            	197, 208,
            	200, 216,
            	203, 224,
            	206, 232,
            	44, 240,
            	164, 248,
            	173, 256,
            	209, 264,
            	173, 272,
            	209, 280,
            	209, 288,
            	212, 296,
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
            4097, 8, 0, /* 197: pointer.func */
            4097, 8, 0, /* 200: pointer.func */
            4097, 8, 0, /* 203: pointer.func */
            4097, 8, 0, /* 206: pointer.func */
            4097, 8, 0, /* 209: pointer.func */
            4097, 8, 0, /* 212: pointer.func */
            1, 8, 1, /* 215: pointer.struct.ec_point_st */
            	220, 0,
            0, 88, 4, /* 220: struct.ec_point_st */
            	82, 0,
            	231, 8,
            	231, 32,
            	231, 56,
            0, 24, 1, /* 231: struct.bignum_st */
            	12, 0,
            1, 8, 1, /* 236: pointer.char */
            	4096, 0,
            1, 8, 1, /* 241: pointer.struct.ec_extra_data_st */
            	246, 0,
            0, 40, 5, /* 246: struct.ec_extra_data_st */
            	241, 0,
            	259, 8,
            	262, 16,
            	38, 24,
            	38, 32,
            0, 8, 0, /* 259: pointer.void */
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

