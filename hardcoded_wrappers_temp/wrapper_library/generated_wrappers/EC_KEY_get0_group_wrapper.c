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

const EC_GROUP * EC_KEY_get0_group(const EC_KEY * arg_a) 
{
    const EC_GROUP * ret;

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
            0, 56, 9, /* 26: struct.ec_key_st.284 */
            	23, 0,
            	47, 8,
            	345, 16,
            	0, 24,
            	23, 32,
            	23, 36,
            	23, 40,
            	23, 44,
            	374, 48,
            1, 8, 1, /* 47: pointer.struct.ec_group_st */
            	52, 0,
            0, 232, 18, /* 52: struct.ec_group_st */
            	91, 0,
            	345, 8,
            	5, 16,
            	5, 40,
            	23, 64,
            	23, 68,
            	23, 72,
            	363, 80,
            	371, 88,
            	374, 96,
            	5, 104,
            	408, 128,
            	5, 152,
            	5, 176,
            	23, 200,
            	363, 208,
            	363, 216,
            	423, 224,
            1, 8, 1, /* 91: pointer.struct.ec_method_st */
            	96, 0,
            0, 304, 39, /* 96: struct.ec_method_st */
            	23, 0,
            	23, 4,
            	177, 8,
            	185, 16,
            	185, 24,
            	193, 32,
            	201, 40,
            	201, 48,
            	177, 56,
            	209, 64,
            	217, 72,
            	225, 80,
            	225, 88,
            	233, 96,
            	241, 104,
            	249, 112,
            	249, 120,
            	257, 128,
            	257, 136,
            	265, 144,
            	273, 152,
            	281, 160,
            	289, 168,
            	297, 176,
            	305, 184,
            	241, 192,
            	305, 200,
            	297, 208,
            	305, 216,
            	313, 224,
            	321, 232,
            	209, 240,
            	177, 248,
            	201, 256,
            	329, 264,
            	201, 272,
            	329, 280,
            	329, 288,
            	337, 296,
            1, 8, 1, /* 177: pointer.func */
            	182, 0,
            0, 0, 0, /* 182: func */
            1, 8, 1, /* 185: pointer.func */
            	190, 0,
            0, 0, 0, /* 190: func */
            1, 8, 1, /* 193: pointer.func */
            	198, 0,
            0, 0, 0, /* 198: func */
            1, 8, 1, /* 201: pointer.func */
            	206, 0,
            0, 0, 0, /* 206: func */
            1, 8, 1, /* 209: pointer.func */
            	214, 0,
            0, 0, 0, /* 214: func */
            1, 8, 1, /* 217: pointer.func */
            	222, 0,
            0, 0, 0, /* 222: func */
            1, 8, 1, /* 225: pointer.func */
            	230, 0,
            0, 0, 0, /* 230: func */
            1, 8, 1, /* 233: pointer.func */
            	238, 0,
            0, 0, 0, /* 238: func */
            1, 8, 1, /* 241: pointer.func */
            	246, 0,
            0, 0, 0, /* 246: func */
            1, 8, 1, /* 249: pointer.func */
            	254, 0,
            0, 0, 0, /* 254: func */
            1, 8, 1, /* 257: pointer.func */
            	262, 0,
            0, 0, 0, /* 262: func */
            1, 8, 1, /* 265: pointer.func */
            	270, 0,
            0, 0, 0, /* 270: func */
            1, 8, 1, /* 273: pointer.func */
            	278, 0,
            0, 0, 0, /* 278: func */
            1, 8, 1, /* 281: pointer.func */
            	286, 0,
            0, 0, 0, /* 286: func */
            1, 8, 1, /* 289: pointer.func */
            	294, 0,
            0, 0, 0, /* 294: func */
            1, 8, 1, /* 297: pointer.func */
            	302, 0,
            0, 0, 0, /* 302: func */
            1, 8, 1, /* 305: pointer.func */
            	310, 0,
            0, 0, 0, /* 310: func */
            1, 8, 1, /* 313: pointer.func */
            	318, 0,
            0, 0, 0, /* 318: func */
            1, 8, 1, /* 321: pointer.func */
            	326, 0,
            0, 0, 0, /* 326: func */
            1, 8, 1, /* 329: pointer.func */
            	334, 0,
            0, 0, 0, /* 334: func */
            1, 8, 1, /* 337: pointer.func */
            	342, 0,
            0, 0, 0, /* 342: func */
            1, 8, 1, /* 345: pointer.struct.ec_point_st */
            	350, 0,
            0, 88, 5, /* 350: struct.ec_point_st */
            	91, 0,
            	5, 8,
            	5, 32,
            	5, 56,
            	23, 80,
            1, 8, 1, /* 363: pointer.char */
            	368, 0,
            0, 1, 0, /* 368: char */
            0, 8, 0, /* 371: long */
            1, 8, 1, /* 374: pointer.struct.ec_extra_data_st */
            	379, 0,
            0, 40, 5, /* 379: struct.ec_extra_data_st */
            	374, 0,
            	363, 8,
            	392, 16,
            	400, 24,
            	400, 32,
            1, 8, 1, /* 392: pointer.func */
            	397, 0,
            0, 0, 0, /* 397: func */
            1, 8, 1, /* 400: pointer.func */
            	405, 0,
            0, 0, 0, /* 405: func */
            0, 24, 6, /* 408: array[6].int */
            	23, 0,
            	23, 4,
            	23, 8,
            	23, 12,
            	23, 16,
            	23, 20,
            1, 8, 1, /* 423: pointer.func */
            	428, 0,
            0, 0, 0, /* 428: func */
            1, 8, 1, /* 431: pointer.struct.ec_key_st.284 */
            	26, 0,
        },
        .arg_entity_index = { 431, },
        .ret_entity_index = 47,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const EC_KEY * new_arg_a = *((const EC_KEY * *)new_args->args[0]);

    const EC_GROUP * *new_ret_ptr = (const EC_GROUP * *)new_args->ret;

    const EC_GROUP * (*orig_EC_KEY_get0_group)(const EC_KEY *);
    orig_EC_KEY_get0_group = dlsym(RTLD_NEXT, "EC_KEY_get0_group");
    *new_ret_ptr = (*orig_EC_KEY_get0_group)(new_arg_a);

    syscall(889);

    return ret;
}
