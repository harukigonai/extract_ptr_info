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

int EC_GROUP_get_curve_name(const EC_GROUP * arg_a) 
{
    int ret;

    struct lib_enter_args args = {
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            1, 8, 1, /* 3: pointer.func */
            	0, 0,
            0, 0, 0, /* 8: func */
            1, 8, 1, /* 11: pointer.func */
            	16, 0,
            0, 0, 0, /* 16: func */
            0, 0, 0, /* 19: func */
            1, 8, 1, /* 22: pointer.func */
            	27, 0,
            0, 0, 0, /* 27: func */
            1, 8, 1, /* 30: pointer.func */
            	35, 0,
            0, 0, 0, /* 35: func */
            1, 8, 1, /* 38: pointer.func */
            	43, 0,
            0, 0, 0, /* 43: func */
            0, 0, 0, /* 46: func */
            1, 8, 1, /* 49: pointer.struct.ec_method_st */
            	54, 0,
            0, 304, 39, /* 54: struct.ec_method_st */
            	135, 0,
            	135, 4,
            	22, 8,
            	138, 16,
            	138, 24,
            	146, 32,
            	154, 40,
            	154, 48,
            	22, 56,
            	159, 64,
            	164, 72,
            	172, 80,
            	172, 88,
            	180, 96,
            	38, 104,
            	188, 112,
            	188, 120,
            	11, 128,
            	11, 136,
            	30, 144,
            	196, 152,
            	204, 160,
            	212, 168,
            	220, 176,
            	228, 184,
            	38, 192,
            	228, 200,
            	220, 208,
            	228, 216,
            	236, 224,
            	244, 232,
            	159, 240,
            	22, 248,
            	154, 256,
            	252, 264,
            	154, 272,
            	252, 280,
            	252, 288,
            	260, 296,
            0, 4, 0, /* 135: int */
            1, 8, 1, /* 138: pointer.func */
            	143, 0,
            0, 0, 0, /* 143: func */
            1, 8, 1, /* 146: pointer.func */
            	151, 0,
            0, 0, 0, /* 151: func */
            1, 8, 1, /* 154: pointer.func */
            	19, 0,
            1, 8, 1, /* 159: pointer.func */
            	46, 0,
            1, 8, 1, /* 164: pointer.func */
            	169, 0,
            0, 0, 0, /* 169: func */
            1, 8, 1, /* 172: pointer.func */
            	177, 0,
            0, 0, 0, /* 177: func */
            1, 8, 1, /* 180: pointer.func */
            	185, 0,
            0, 0, 0, /* 185: func */
            1, 8, 1, /* 188: pointer.func */
            	193, 0,
            0, 0, 0, /* 193: func */
            1, 8, 1, /* 196: pointer.func */
            	201, 0,
            0, 0, 0, /* 201: func */
            1, 8, 1, /* 204: pointer.func */
            	209, 0,
            0, 0, 0, /* 209: func */
            1, 8, 1, /* 212: pointer.func */
            	217, 0,
            0, 0, 0, /* 217: func */
            1, 8, 1, /* 220: pointer.func */
            	225, 0,
            0, 0, 0, /* 225: func */
            1, 8, 1, /* 228: pointer.func */
            	233, 0,
            0, 0, 0, /* 233: func */
            1, 8, 1, /* 236: pointer.func */
            	241, 0,
            0, 0, 0, /* 241: func */
            1, 8, 1, /* 244: pointer.func */
            	249, 0,
            0, 0, 0, /* 249: func */
            1, 8, 1, /* 252: pointer.func */
            	257, 0,
            0, 0, 0, /* 257: func */
            1, 8, 1, /* 260: pointer.func */
            	265, 0,
            0, 0, 0, /* 265: func */
            1, 8, 1, /* 268: pointer.struct.ec_group_st */
            	273, 0,
            0, 232, 18, /* 273: struct.ec_group_st */
            	49, 0,
            	312, 8,
            	330, 16,
            	330, 40,
            	135, 64,
            	135, 68,
            	135, 72,
            	348, 80,
            	356, 88,
            	359, 96,
            	330, 104,
            	390, 128,
            	330, 152,
            	330, 176,
            	135, 200,
            	348, 208,
            	348, 216,
            	3, 224,
            1, 8, 1, /* 312: pointer.struct.ec_point_st */
            	317, 0,
            0, 88, 5, /* 317: struct.ec_point_st */
            	49, 0,
            	330, 8,
            	330, 32,
            	330, 56,
            	135, 80,
            0, 24, 5, /* 330: struct.bignum_st */
            	343, 0,
            	135, 8,
            	135, 12,
            	135, 16,
            	135, 20,
            1, 8, 1, /* 343: pointer.int */
            	135, 0,
            1, 8, 1, /* 348: pointer.char */
            	353, 0,
            0, 1, 0, /* 353: char */
            0, 8, 0, /* 356: long */
            1, 8, 1, /* 359: pointer.struct.ec_extra_data_st */
            	364, 0,
            0, 40, 5, /* 364: struct.ec_extra_data_st */
            	359, 0,
            	348, 8,
            	377, 16,
            	385, 24,
            	385, 32,
            1, 8, 1, /* 377: pointer.func */
            	382, 0,
            0, 0, 0, /* 382: func */
            1, 8, 1, /* 385: pointer.func */
            	8, 0,
            0, 24, 6, /* 390: array[6].int */
            	135, 0,
            	135, 4,
            	135, 8,
            	135, 12,
            	135, 16,
            	135, 20,
        },
        .arg_entity_index = { 268, },
        .ret_entity_index = 135,
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

