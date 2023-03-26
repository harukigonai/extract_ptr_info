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
    printf("EC_GROUP_get_curve_name called\n");
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
            0, 1, 0, /* 22: char */
            0, 0, 0, /* 25: func */
            1, 8, 1, /* 28: pointer.func */
            	33, 0,
            0, 0, 0, /* 33: func */
            0, 0, 0, /* 36: func */
            1, 8, 1, /* 39: pointer.struct.ec_group_st */
            	44, 0,
            0, 232, 12, /* 44: struct.ec_group_st */
            	71, 0,
            	296, 8,
            	312, 16,
            	312, 40,
            	325, 80,
            	330, 96,
            	312, 104,
            	312, 152,
            	312, 176,
            	325, 208,
            	325, 216,
            	3, 224,
            1, 8, 1, /* 71: pointer.struct.ec_method_st */
            	76, 0,
            0, 304, 37, /* 76: struct.ec_method_st */
            	28, 8,
            	153, 16,
            	153, 24,
            	161, 32,
            	169, 40,
            	169, 48,
            	28, 56,
            	174, 64,
            	182, 72,
            	190, 80,
            	190, 88,
            	198, 96,
            	206, 104,
            	211, 112,
            	211, 120,
            	11, 128,
            	11, 136,
            	216, 144,
            	224, 152,
            	232, 160,
            	240, 168,
            	248, 176,
            	256, 184,
            	206, 192,
            	256, 200,
            	248, 208,
            	256, 216,
            	264, 224,
            	272, 232,
            	174, 240,
            	28, 248,
            	169, 256,
            	280, 264,
            	169, 272,
            	280, 280,
            	280, 288,
            	288, 296,
            1, 8, 1, /* 153: pointer.func */
            	158, 0,
            0, 0, 0, /* 158: func */
            1, 8, 1, /* 161: pointer.func */
            	166, 0,
            0, 0, 0, /* 166: func */
            1, 8, 1, /* 169: pointer.func */
            	19, 0,
            1, 8, 1, /* 174: pointer.func */
            	179, 0,
            0, 0, 0, /* 179: func */
            1, 8, 1, /* 182: pointer.func */
            	187, 0,
            0, 0, 0, /* 187: func */
            1, 8, 1, /* 190: pointer.func */
            	195, 0,
            0, 0, 0, /* 195: func */
            1, 8, 1, /* 198: pointer.func */
            	203, 0,
            0, 0, 0, /* 203: func */
            1, 8, 1, /* 206: pointer.func */
            	36, 0,
            1, 8, 1, /* 211: pointer.func */
            	25, 0,
            1, 8, 1, /* 216: pointer.func */
            	221, 0,
            0, 0, 0, /* 221: func */
            1, 8, 1, /* 224: pointer.func */
            	229, 0,
            0, 0, 0, /* 229: func */
            1, 8, 1, /* 232: pointer.func */
            	237, 0,
            0, 0, 0, /* 237: func */
            1, 8, 1, /* 240: pointer.func */
            	245, 0,
            0, 0, 0, /* 245: func */
            1, 8, 1, /* 248: pointer.func */
            	253, 0,
            0, 0, 0, /* 253: func */
            1, 8, 1, /* 256: pointer.func */
            	261, 0,
            0, 0, 0, /* 261: func */
            1, 8, 1, /* 264: pointer.func */
            	269, 0,
            0, 0, 0, /* 269: func */
            1, 8, 1, /* 272: pointer.func */
            	277, 0,
            0, 0, 0, /* 277: func */
            1, 8, 1, /* 280: pointer.func */
            	285, 0,
            0, 0, 0, /* 285: func */
            1, 8, 1, /* 288: pointer.func */
            	293, 0,
            0, 0, 0, /* 293: func */
            1, 8, 1, /* 296: pointer.struct.ec_point_st */
            	301, 0,
            0, 88, 4, /* 301: struct.ec_point_st */
            	71, 0,
            	312, 8,
            	312, 32,
            	312, 56,
            0, 24, 1, /* 312: struct.bignum_st */
            	317, 0,
            1, 8, 1, /* 317: pointer.int */
            	322, 0,
            0, 4, 0, /* 322: int */
            1, 8, 1, /* 325: pointer.char */
            	22, 0,
            1, 8, 1, /* 330: pointer.struct.ec_extra_data_st */
            	335, 0,
            0, 40, 5, /* 335: struct.ec_extra_data_st */
            	330, 0,
            	325, 8,
            	348, 16,
            	356, 24,
            	356, 32,
            1, 8, 1, /* 348: pointer.func */
            	353, 0,
            0, 0, 0, /* 353: func */
            1, 8, 1, /* 356: pointer.func */
            	8, 0,
            0, 24, 0, /* 361: array[6].int */
            0, 8, 0, /* 364: long */
        },
        .arg_entity_index = { 39, },
        .ret_entity_index = 322,
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

