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

void EC_KEY_free(EC_KEY * arg_a) 
{
    if (syscall(890))
        _EC_KEY_free(arg_a)
    else {
        void (*orig_EC_KEY_free)(EC_KEY *);
        orig_EC_KEY_free = dlsym(RTLD_NEXT, "EC_KEY_free");
        orig_EC_KEY_free(arg_a);
    }
}

void _EC_KEY_free(EC_KEY * arg_a) 
{
    printf("EC_KEY_free called\n");
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.struct.bignum_st */
            	5, 0,
            0, 24, 1, /* 5: struct.bignum_st */
            	10, 0,
            1, 8, 1, /* 10: pointer.int */
            	15, 0,
            0, 4, 0, /* 15: int */
            0, 0, 0, /* 18: func */
            1, 8, 1, /* 21: pointer.func */
            	18, 0,
            0, 0, 0, /* 26: func */
            1, 8, 1, /* 29: pointer.func */
            	26, 0,
            1, 8, 1, /* 34: pointer.func */
            	39, 0,
            0, 0, 0, /* 39: func */
            0, 0, 0, /* 42: func */
            0, 1, 0, /* 45: char */
            0, 0, 0, /* 48: func */
            1, 8, 1, /* 51: pointer.func */
            	56, 0,
            0, 0, 0, /* 56: func */
            0, 0, 0, /* 59: func */
            1, 8, 1, /* 62: pointer.func */
            	59, 0,
            1, 8, 1, /* 67: pointer.func */
            	72, 0,
            0, 0, 0, /* 72: func */
            0, 0, 0, /* 75: func */
            1, 8, 1, /* 78: pointer.func */
            	83, 0,
            0, 0, 0, /* 83: func */
            0, 0, 0, /* 86: func */
            1, 8, 1, /* 89: pointer.struct.ec_method_st */
            	94, 0,
            0, 304, 37, /* 94: struct.ec_method_st */
            	51, 8,
            	171, 16,
            	171, 24,
            	179, 32,
            	187, 40,
            	187, 48,
            	51, 56,
            	192, 64,
            	197, 72,
            	205, 80,
            	205, 88,
            	62, 96,
            	78, 104,
            	210, 112,
            	210, 120,
            	34, 128,
            	34, 136,
            	215, 144,
            	223, 152,
            	231, 160,
            	239, 168,
            	247, 176,
            	67, 184,
            	78, 192,
            	67, 200,
            	247, 208,
            	67, 216,
            	255, 224,
            	263, 232,
            	192, 240,
            	51, 248,
            	187, 256,
            	271, 264,
            	187, 272,
            	271, 280,
            	271, 288,
            	279, 296,
            1, 8, 1, /* 171: pointer.func */
            	176, 0,
            0, 0, 0, /* 176: func */
            1, 8, 1, /* 179: pointer.func */
            	184, 0,
            0, 0, 0, /* 184: func */
            1, 8, 1, /* 187: pointer.func */
            	42, 0,
            1, 8, 1, /* 192: pointer.func */
            	86, 0,
            1, 8, 1, /* 197: pointer.func */
            	202, 0,
            0, 0, 0, /* 202: func */
            1, 8, 1, /* 205: pointer.func */
            	75, 0,
            1, 8, 1, /* 210: pointer.func */
            	48, 0,
            1, 8, 1, /* 215: pointer.func */
            	220, 0,
            0, 0, 0, /* 220: func */
            1, 8, 1, /* 223: pointer.func */
            	228, 0,
            0, 0, 0, /* 228: func */
            1, 8, 1, /* 231: pointer.func */
            	236, 0,
            0, 0, 0, /* 236: func */
            1, 8, 1, /* 239: pointer.func */
            	244, 0,
            0, 0, 0, /* 244: func */
            1, 8, 1, /* 247: pointer.func */
            	252, 0,
            0, 0, 0, /* 252: func */
            1, 8, 1, /* 255: pointer.func */
            	260, 0,
            0, 0, 0, /* 260: func */
            1, 8, 1, /* 263: pointer.func */
            	268, 0,
            0, 0, 0, /* 268: func */
            1, 8, 1, /* 271: pointer.func */
            	276, 0,
            0, 0, 0, /* 276: func */
            1, 8, 1, /* 279: pointer.func */
            	284, 0,
            0, 0, 0, /* 284: func */
            0, 0, 0, /* 287: func */
            1, 8, 1, /* 290: pointer.struct.ec_group_st */
            	295, 0,
            0, 232, 12, /* 295: struct.ec_group_st */
            	89, 0,
            	322, 8,
            	5, 16,
            	5, 40,
            	338, 80,
            	343, 96,
            	5, 104,
            	5, 152,
            	5, 176,
            	338, 208,
            	338, 216,
            	21, 224,
            1, 8, 1, /* 322: pointer.struct.ec_point_st */
            	327, 0,
            0, 88, 4, /* 327: struct.ec_point_st */
            	89, 0,
            	5, 8,
            	5, 32,
            	5, 56,
            1, 8, 1, /* 338: pointer.char */
            	45, 0,
            1, 8, 1, /* 343: pointer.struct.ec_extra_data_st */
            	348, 0,
            0, 40, 5, /* 348: struct.ec_extra_data_st */
            	343, 0,
            	338, 8,
            	361, 16,
            	29, 24,
            	29, 32,
            1, 8, 1, /* 361: pointer.func */
            	287, 0,
            0, 56, 4, /* 366: struct.ec_key_st.284 */
            	290, 8,
            	322, 16,
            	0, 24,
            	343, 48,
            1, 8, 1, /* 377: pointer.struct.ec_key_st.284 */
            	366, 0,
            0, 24, 0, /* 382: array[6].int */
            0, 8, 0, /* 385: long */
        },
        .arg_entity_index = { 377, },
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

