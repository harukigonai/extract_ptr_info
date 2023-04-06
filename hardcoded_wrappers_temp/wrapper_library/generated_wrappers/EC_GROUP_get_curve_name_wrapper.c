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
            8884097, 8, 0, /* 0: pointer.func */
            1, 8, 1, /* 3: pointer.struct.ec_extra_data_st */
            	8, 0,
            0, 40, 5, /* 8: struct.ec_extra_data_st */
            	3, 0,
            	21, 8,
            	24, 16,
            	27, 24,
            	27, 32,
            0, 8, 0, /* 21: pointer.void */
            8884097, 8, 0, /* 24: pointer.func */
            8884097, 8, 0, /* 27: pointer.func */
            1, 8, 1, /* 30: pointer.unsigned char */
            	35, 0,
            0, 1, 0, /* 35: unsigned char */
            0, 24, 1, /* 38: struct.bignum_st */
            	43, 0,
            1, 8, 1, /* 43: pointer.unsigned int */
            	48, 0,
            0, 4, 0, /* 48: unsigned int */
            8884097, 8, 0, /* 51: pointer.func */
            8884097, 8, 0, /* 54: pointer.func */
            8884097, 8, 0, /* 57: pointer.func */
            8884097, 8, 0, /* 60: pointer.func */
            8884097, 8, 0, /* 63: pointer.func */
            8884097, 8, 0, /* 66: pointer.func */
            0, 304, 37, /* 69: struct.ec_method_st */
            	146, 8,
            	149, 16,
            	149, 24,
            	152, 32,
            	155, 40,
            	158, 48,
            	161, 56,
            	164, 64,
            	167, 72,
            	170, 80,
            	170, 88,
            	173, 96,
            	176, 104,
            	179, 112,
            	182, 120,
            	185, 128,
            	188, 136,
            	191, 144,
            	194, 152,
            	197, 160,
            	200, 168,
            	203, 176,
            	206, 184,
            	66, 192,
            	209, 200,
            	212, 208,
            	206, 216,
            	215, 224,
            	218, 232,
            	221, 240,
            	161, 248,
            	224, 256,
            	227, 264,
            	224, 272,
            	227, 280,
            	227, 288,
            	230, 296,
            8884097, 8, 0, /* 146: pointer.func */
            8884097, 8, 0, /* 149: pointer.func */
            8884097, 8, 0, /* 152: pointer.func */
            8884097, 8, 0, /* 155: pointer.func */
            8884097, 8, 0, /* 158: pointer.func */
            8884097, 8, 0, /* 161: pointer.func */
            8884097, 8, 0, /* 164: pointer.func */
            8884097, 8, 0, /* 167: pointer.func */
            8884097, 8, 0, /* 170: pointer.func */
            8884097, 8, 0, /* 173: pointer.func */
            8884097, 8, 0, /* 176: pointer.func */
            8884097, 8, 0, /* 179: pointer.func */
            8884097, 8, 0, /* 182: pointer.func */
            8884097, 8, 0, /* 185: pointer.func */
            8884097, 8, 0, /* 188: pointer.func */
            8884097, 8, 0, /* 191: pointer.func */
            8884097, 8, 0, /* 194: pointer.func */
            8884097, 8, 0, /* 197: pointer.func */
            8884097, 8, 0, /* 200: pointer.func */
            8884097, 8, 0, /* 203: pointer.func */
            8884097, 8, 0, /* 206: pointer.func */
            8884097, 8, 0, /* 209: pointer.func */
            8884097, 8, 0, /* 212: pointer.func */
            8884097, 8, 0, /* 215: pointer.func */
            8884097, 8, 0, /* 218: pointer.func */
            8884097, 8, 0, /* 221: pointer.func */
            8884097, 8, 0, /* 224: pointer.func */
            8884097, 8, 0, /* 227: pointer.func */
            8884097, 8, 0, /* 230: pointer.func */
            8884097, 8, 0, /* 233: pointer.func */
            1, 8, 1, /* 236: pointer.struct.ec_method_st */
            	69, 0,
            8884097, 8, 0, /* 241: pointer.func */
            8884097, 8, 0, /* 244: pointer.func */
            1, 8, 1, /* 247: pointer.struct.ec_extra_data_st */
            	8, 0,
            8884097, 8, 0, /* 252: pointer.func */
            0, 4, 0, /* 255: int */
            8884097, 8, 0, /* 258: pointer.func */
            1, 8, 1, /* 261: pointer.struct.ec_group_st */
            	266, 0,
            0, 232, 12, /* 266: struct.ec_group_st */
            	236, 0,
            	293, 8,
            	38, 16,
            	38, 40,
            	30, 80,
            	247, 96,
            	38, 104,
            	38, 152,
            	38, 176,
            	21, 208,
            	21, 216,
            	0, 224,
            1, 8, 1, /* 293: pointer.struct.ec_point_st */
            	298, 0,
            0, 88, 4, /* 298: struct.ec_point_st */
            	309, 0,
            	451, 8,
            	451, 32,
            	451, 56,
            1, 8, 1, /* 309: pointer.struct.ec_method_st */
            	314, 0,
            0, 304, 37, /* 314: struct.ec_method_st */
            	391, 8,
            	394, 16,
            	394, 24,
            	397, 32,
            	400, 40,
            	403, 48,
            	406, 56,
            	409, 64,
            	412, 72,
            	415, 80,
            	415, 88,
            	418, 96,
            	421, 104,
            	424, 112,
            	427, 120,
            	241, 128,
            	430, 136,
            	433, 144,
            	252, 152,
            	436, 160,
            	439, 168,
            	442, 176,
            	445, 184,
            	258, 192,
            	63, 200,
            	244, 208,
            	445, 216,
            	60, 224,
            	57, 232,
            	233, 240,
            	406, 248,
            	54, 256,
            	448, 264,
            	54, 272,
            	448, 280,
            	448, 288,
            	51, 296,
            8884097, 8, 0, /* 391: pointer.func */
            8884097, 8, 0, /* 394: pointer.func */
            8884097, 8, 0, /* 397: pointer.func */
            8884097, 8, 0, /* 400: pointer.func */
            8884097, 8, 0, /* 403: pointer.func */
            8884097, 8, 0, /* 406: pointer.func */
            8884097, 8, 0, /* 409: pointer.func */
            8884097, 8, 0, /* 412: pointer.func */
            8884097, 8, 0, /* 415: pointer.func */
            8884097, 8, 0, /* 418: pointer.func */
            8884097, 8, 0, /* 421: pointer.func */
            8884097, 8, 0, /* 424: pointer.func */
            8884097, 8, 0, /* 427: pointer.func */
            8884097, 8, 0, /* 430: pointer.func */
            8884097, 8, 0, /* 433: pointer.func */
            8884097, 8, 0, /* 436: pointer.func */
            8884097, 8, 0, /* 439: pointer.func */
            8884097, 8, 0, /* 442: pointer.func */
            8884097, 8, 0, /* 445: pointer.func */
            8884097, 8, 0, /* 448: pointer.func */
            0, 24, 1, /* 451: struct.bignum_st */
            	43, 0,
        },
        .arg_entity_index = { 261, },
        .ret_entity_index = 255,
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

