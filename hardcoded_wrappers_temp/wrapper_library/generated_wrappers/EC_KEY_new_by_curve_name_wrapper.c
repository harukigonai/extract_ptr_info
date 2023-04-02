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
            0, 8, 0, /* 0: pointer.void */
            0, 0, 0, /* 3: func */
            4097, 8, 0, /* 6: pointer.func */
            0, 24, 0, /* 9: array[6].int */
            4097, 8, 0, /* 12: pointer.func */
            0, 0, 0, /* 15: func */
            0, 0, 0, /* 18: func */
            0, 8, 1, /* 21: pointer.int */
            	26, 0,
            0, 4, 0, /* 26: int */
            4097, 8, 0, /* 29: pointer.func */
            4097, 8, 0, /* 32: pointer.func */
            0, 0, 0, /* 35: func */
            0, 0, 0, /* 38: func */
            0, 0, 0, /* 41: func */
            4097, 8, 0, /* 44: pointer.func */
            0, 0, 0, /* 47: func */
            4097, 8, 0, /* 50: pointer.func */
            0, 304, 37, /* 53: struct.ec_method_st */
            	130, 8,
            	133, 16,
            	133, 24,
            	136, 32,
            	50, 40,
            	50, 48,
            	130, 56,
            	44, 64,
            	32, 72,
            	139, 80,
            	139, 88,
            	142, 96,
            	145, 104,
            	148, 112,
            	148, 120,
            	29, 128,
            	29, 136,
            	151, 144,
            	154, 152,
            	157, 160,
            	160, 168,
            	163, 176,
            	166, 184,
            	145, 192,
            	166, 200,
            	163, 208,
            	166, 216,
            	169, 224,
            	172, 232,
            	44, 240,
            	130, 248,
            	50, 256,
            	175, 264,
            	50, 272,
            	175, 280,
            	175, 288,
            	178, 296,
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
            4097, 8, 0, /* 178: pointer.func */
            0, 0, 0, /* 181: func */
            0, 56, 4, /* 184: struct.ec_key_st */
            	195, 8,
            	232, 16,
            	279, 24,
            	258, 48,
            0, 8, 1, /* 195: pointer.struct.ec_group_st */
            	200, 0,
            0, 232, 12, /* 200: struct.ec_group_st */
            	227, 0,
            	232, 8,
            	248, 16,
            	248, 40,
            	253, 80,
            	258, 96,
            	248, 104,
            	248, 152,
            	248, 176,
            	0, 208,
            	0, 216,
            	6, 224,
            0, 8, 1, /* 227: pointer.struct.ec_method_st */
            	53, 0,
            0, 8, 1, /* 232: pointer.struct.ec_point_st */
            	237, 0,
            0, 88, 4, /* 237: struct.ec_point_st */
            	227, 0,
            	248, 8,
            	248, 32,
            	248, 56,
            0, 24, 1, /* 248: struct.bignum_st */
            	21, 0,
            0, 8, 1, /* 253: pointer.char */
            	4096, 0,
            0, 8, 1, /* 258: pointer.struct.ec_extra_data_st */
            	263, 0,
            0, 40, 5, /* 263: struct.ec_extra_data_st */
            	258, 0,
            	0, 8,
            	276, 16,
            	12, 24,
            	12, 32,
            4097, 8, 0, /* 276: pointer.func */
            0, 8, 1, /* 279: pointer.struct.bignum_st */
            	248, 0,
            0, 0, 0, /* 284: func */
            0, 8, 1, /* 287: pointer.struct.ec_key_st */
            	184, 0,
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
        .arg_entity_index = { 26, },
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

