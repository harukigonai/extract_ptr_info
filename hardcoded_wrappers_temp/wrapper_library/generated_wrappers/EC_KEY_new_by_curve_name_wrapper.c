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

EC_KEY * EC_KEY_new_by_curve_name(int arg_a) 
{
    EC_KEY * ret;

    struct lib_enter_args args = {
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.struct.bignum_st */
            	5, 0,
            0, 24, 5, /* 5: struct.bignum_st */
            	18, 0,
            	23, 8,
            	23, 12,
            	23, 16,
            	23, 20,
            1, 8, 1, /* 18: pointer.int */
            	23, 0,
            0, 4, 0, /* 23: int */
            0, 0, 0, /* 26: func */
            1, 8, 1, /* 29: pointer.func */
            	26, 0,
            0, 0, 0, /* 34: func */
            1, 8, 1, /* 37: pointer.func */
            	34, 0,
            1, 8, 1, /* 42: pointer.func */
            	47, 0,
            0, 0, 0, /* 47: func */
            0, 0, 0, /* 50: func */
            1, 8, 1, /* 53: pointer.func */
            	58, 0,
            0, 0, 0, /* 58: func */
            0, 0, 0, /* 61: func */
            1, 8, 1, /* 64: pointer.func */
            	61, 0,
            1, 8, 1, /* 69: pointer.func */
            	74, 0,
            0, 0, 0, /* 74: func */
            0, 0, 0, /* 77: func */
            1, 8, 1, /* 80: pointer.func */
            	85, 0,
            0, 0, 0, /* 85: func */
            1, 8, 1, /* 88: pointer.func */
            	93, 0,
            0, 0, 0, /* 93: func */
            0, 0, 0, /* 96: func */
            1, 8, 1, /* 99: pointer.struct.ec_method_st */
            	104, 0,
            0, 304, 39, /* 104: struct.ec_method_st */
            	23, 0,
            	23, 4,
            	53, 8,
            	185, 16,
            	185, 24,
            	193, 32,
            	201, 40,
            	201, 48,
            	53, 56,
            	206, 64,
            	80, 72,
            	211, 80,
            	211, 88,
            	64, 96,
            	88, 104,
            	216, 112,
            	216, 120,
            	42, 128,
            	42, 136,
            	224, 144,
            	232, 152,
            	240, 160,
            	248, 168,
            	256, 176,
            	69, 184,
            	88, 192,
            	69, 200,
            	256, 208,
            	69, 216,
            	264, 224,
            	272, 232,
            	206, 240,
            	53, 248,
            	201, 256,
            	280, 264,
            	201, 272,
            	280, 280,
            	280, 288,
            	288, 296,
            1, 8, 1, /* 185: pointer.func */
            	190, 0,
            0, 0, 0, /* 190: func */
            1, 8, 1, /* 193: pointer.func */
            	198, 0,
            0, 0, 0, /* 198: func */
            1, 8, 1, /* 201: pointer.func */
            	50, 0,
            1, 8, 1, /* 206: pointer.func */
            	96, 0,
            1, 8, 1, /* 211: pointer.func */
            	77, 0,
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
            0, 0, 0, /* 296: func */
            1, 8, 1, /* 299: pointer.struct.ec_group_st */
            	304, 0,
            0, 232, 18, /* 304: struct.ec_group_st */
            	99, 0,
            	343, 8,
            	5, 16,
            	5, 40,
            	23, 64,
            	23, 68,
            	23, 72,
            	361, 80,
            	369, 88,
            	372, 96,
            	5, 104,
            	395, 128,
            	5, 152,
            	5, 176,
            	23, 200,
            	361, 208,
            	361, 216,
            	29, 224,
            1, 8, 1, /* 343: pointer.struct.ec_point_st */
            	348, 0,
            0, 88, 5, /* 348: struct.ec_point_st */
            	99, 0,
            	5, 8,
            	5, 32,
            	5, 56,
            	23, 80,
            1, 8, 1, /* 361: pointer.char */
            	366, 0,
            0, 1, 0, /* 366: char */
            0, 8, 0, /* 369: long */
            1, 8, 1, /* 372: pointer.struct.ec_extra_data_st */
            	377, 0,
            0, 40, 5, /* 377: struct.ec_extra_data_st */
            	372, 0,
            	361, 8,
            	390, 16,
            	37, 24,
            	37, 32,
            1, 8, 1, /* 390: pointer.func */
            	296, 0,
            0, 24, 6, /* 395: array[6].int */
            	23, 0,
            	23, 4,
            	23, 8,
            	23, 12,
            	23, 16,
            	23, 20,
            0, 56, 9, /* 410: struct.ec_key_st.284 */
            	23, 0,
            	299, 8,
            	343, 16,
            	0, 24,
            	23, 32,
            	23, 36,
            	23, 40,
            	23, 44,
            	372, 48,
            1, 8, 1, /* 431: pointer.struct.ec_key_st.284 */
            	410, 0,
        },
        .arg_entity_index = { 23, },
        .ret_entity_index = 431,
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

