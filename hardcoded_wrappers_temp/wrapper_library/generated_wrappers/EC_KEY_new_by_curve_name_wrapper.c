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

EC_KEY * bb_EC_KEY_new_by_curve_name(int arg_a);

EC_KEY * EC_KEY_new_by_curve_name(int arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EC_KEY_new_by_curve_name called %lu\n", in_lib);
    if (!in_lib)
        return bb_EC_KEY_new_by_curve_name(arg_a);
    else {
        EC_KEY * (*orig_EC_KEY_new_by_curve_name)(int);
        orig_EC_KEY_new_by_curve_name = dlsym(RTLD_NEXT, "EC_KEY_new_by_curve_name");
        return orig_EC_KEY_new_by_curve_name(arg_a);
    }
}

EC_KEY * bb_EC_KEY_new_by_curve_name(int arg_a) 
{
    EC_KEY * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            4097, 8, 0, /* 3: pointer.func */
            0, 24, 0, /* 6: array[6].int */
            4097, 8, 0, /* 9: pointer.func */
            0, 0, 0, /* 12: func */
            0, 0, 0, /* 15: func */
            1, 8, 1, /* 18: pointer.int */
            	23, 0,
            0, 4, 0, /* 23: int */
            4097, 8, 0, /* 26: pointer.func */
            4097, 8, 0, /* 29: pointer.func */
            0, 0, 0, /* 32: func */
            0, 0, 0, /* 35: func */
            0, 0, 0, /* 38: func */
            4097, 8, 0, /* 41: pointer.func */
            0, 0, 0, /* 44: func */
            4097, 8, 0, /* 47: pointer.func */
            0, 304, 37, /* 50: struct.ec_method_st */
            	127, 8,
            	130, 16,
            	130, 24,
            	133, 32,
            	47, 40,
            	47, 48,
            	127, 56,
            	41, 64,
            	29, 72,
            	136, 80,
            	136, 88,
            	139, 96,
            	142, 104,
            	145, 112,
            	145, 120,
            	26, 128,
            	26, 136,
            	148, 144,
            	151, 152,
            	154, 160,
            	157, 168,
            	160, 176,
            	163, 184,
            	142, 192,
            	163, 200,
            	160, 208,
            	163, 216,
            	166, 224,
            	169, 232,
            	41, 240,
            	127, 248,
            	47, 256,
            	172, 264,
            	47, 272,
            	172, 280,
            	172, 288,
            	175, 296,
            4097, 8, 0, /* 127: pointer.func */
            4097, 8, 0, /* 130: pointer.func */
            4097, 8, 0, /* 133: pointer.func */
            4097, 8, 0, /* 136: pointer.func */
            4097, 8, 0, /* 139: pointer.func */
            4097, 8, 0, /* 142: pointer.func */
            4097, 8, 0, /* 145: pointer.func */
            4097, 8, 0, /* 148: pointer.func */
            4097, 8, 0, /* 151: pointer.func */
            4097, 8, 0, /* 154: pointer.func */
            4097, 8, 0, /* 157: pointer.func */
            4097, 8, 0, /* 160: pointer.func */
            4097, 8, 0, /* 163: pointer.func */
            4097, 8, 0, /* 166: pointer.func */
            4097, 8, 0, /* 169: pointer.func */
            4097, 8, 0, /* 172: pointer.func */
            4097, 8, 0, /* 175: pointer.func */
            0, 0, 0, /* 178: func */
            0, 56, 4, /* 181: struct.ec_key_st */
            	192, 8,
            	229, 16,
            	279, 24,
            	255, 48,
            1, 8, 1, /* 192: pointer.struct.ec_group_st */
            	197, 0,
            0, 232, 12, /* 197: struct.ec_group_st */
            	224, 0,
            	229, 8,
            	245, 16,
            	245, 40,
            	250, 80,
            	255, 96,
            	245, 104,
            	245, 152,
            	245, 176,
            	273, 208,
            	273, 216,
            	3, 224,
            1, 8, 1, /* 224: pointer.struct.ec_method_st */
            	50, 0,
            1, 8, 1, /* 229: pointer.struct.ec_point_st */
            	234, 0,
            0, 88, 4, /* 234: struct.ec_point_st */
            	224, 0,
            	245, 8,
            	245, 32,
            	245, 56,
            0, 24, 1, /* 245: struct.bignum_st */
            	18, 0,
            1, 8, 1, /* 250: pointer.char */
            	4096, 0,
            1, 8, 1, /* 255: pointer.struct.ec_extra_data_st */
            	260, 0,
            0, 40, 5, /* 260: struct.ec_extra_data_st */
            	255, 0,
            	273, 8,
            	276, 16,
            	9, 24,
            	9, 32,
            0, 8, 0, /* 273: pointer.void */
            4097, 8, 0, /* 276: pointer.func */
            1, 8, 1, /* 279: pointer.struct.bignum_st */
            	245, 0,
            0, 0, 0, /* 284: func */
            1, 8, 1, /* 287: pointer.struct.ec_key_st */
            	181, 0,
            0, 0, 0, /* 292: func */
            0, 0, 0, /* 295: func */
            0, 0, 0, /* 298: func */
            0, 0, 0, /* 301: func */
            0, 0, 0, /* 304: func */
            0, 0, 0, /* 307: func */
            0, 0, 0, /* 310: func */
            0, 0, 0, /* 313: func */
            0, 8, 0, /* 316: long */
            0, 0, 0, /* 319: func */
            0, 0, 0, /* 322: func */
            0, 1, 0, /* 325: char */
            0, 0, 0, /* 328: func */
            0, 0, 0, /* 331: func */
            0, 0, 0, /* 334: func */
            0, 0, 0, /* 337: func */
            0, 0, 0, /* 340: func */
        },
        .arg_entity_index = { 23, },
        .ret_entity_index = 287,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    int new_arg_a = *((int *)new_args->args[0]);

    EC_KEY * *new_ret_ptr = (EC_KEY * *)new_args->ret;

    EC_KEY * (*orig_EC_KEY_new_by_curve_name)(int);
    orig_EC_KEY_new_by_curve_name = dlsym(RTLD_NEXT, "EC_KEY_new_by_curve_name");
    *new_ret_ptr = (*orig_EC_KEY_new_by_curve_name)(new_arg_a);

    syscall(889);

    return ret;
}

