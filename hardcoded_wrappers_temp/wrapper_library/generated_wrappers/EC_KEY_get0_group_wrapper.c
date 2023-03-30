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

const EC_GROUP * bb_EC_KEY_get0_group(const EC_KEY * arg_a);

const EC_GROUP * EC_KEY_get0_group(const EC_KEY * arg_a) 
{
    if (syscall(890))
        return bb_EC_KEY_get0_group(arg_a);
    else {
        const EC_GROUP * (*orig_EC_KEY_get0_group)(const EC_KEY *);
        orig_EC_KEY_get0_group = dlsym(RTLD_NEXT, "EC_KEY_get0_group");
        return orig_EC_KEY_get0_group(arg_a);
    }
}

const EC_GROUP * bb_EC_KEY_get0_group(const EC_KEY * arg_a) 
{
    printf("EC_KEY_get0_group called\n");
    const EC_GROUP * ret;

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
            0, 56, 4, /* 18: struct.ec_key_st.284 */
            	29, 8,
            	311, 16,
            	0, 24,
            	335, 48,
            1, 8, 1, /* 29: pointer.struct.ec_group_st */
            	34, 0,
            0, 232, 12, /* 34: struct.ec_group_st */
            	61, 0,
            	311, 8,
            	5, 16,
            	5, 40,
            	327, 80,
            	335, 96,
            	5, 104,
            	5, 152,
            	5, 176,
            	327, 208,
            	327, 216,
            	369, 224,
            1, 8, 1, /* 61: pointer.struct.ec_method_st */
            	66, 0,
            0, 304, 37, /* 66: struct.ec_method_st */
            	143, 8,
            	151, 16,
            	151, 24,
            	159, 32,
            	167, 40,
            	167, 48,
            	143, 56,
            	175, 64,
            	183, 72,
            	191, 80,
            	191, 88,
            	199, 96,
            	207, 104,
            	215, 112,
            	215, 120,
            	223, 128,
            	223, 136,
            	231, 144,
            	239, 152,
            	247, 160,
            	255, 168,
            	263, 176,
            	271, 184,
            	207, 192,
            	271, 200,
            	263, 208,
            	271, 216,
            	279, 224,
            	287, 232,
            	175, 240,
            	143, 248,
            	167, 256,
            	295, 264,
            	167, 272,
            	295, 280,
            	295, 288,
            	303, 296,
            1, 8, 1, /* 143: pointer.func */
            	148, 0,
            0, 0, 0, /* 148: func */
            1, 8, 1, /* 151: pointer.func */
            	156, 0,
            0, 0, 0, /* 156: func */
            1, 8, 1, /* 159: pointer.func */
            	164, 0,
            0, 0, 0, /* 164: func */
            1, 8, 1, /* 167: pointer.func */
            	172, 0,
            0, 0, 0, /* 172: func */
            1, 8, 1, /* 175: pointer.func */
            	180, 0,
            0, 0, 0, /* 180: func */
            1, 8, 1, /* 183: pointer.func */
            	188, 0,
            0, 0, 0, /* 188: func */
            1, 8, 1, /* 191: pointer.func */
            	196, 0,
            0, 0, 0, /* 196: func */
            1, 8, 1, /* 199: pointer.func */
            	204, 0,
            0, 0, 0, /* 204: func */
            1, 8, 1, /* 207: pointer.func */
            	212, 0,
            0, 0, 0, /* 212: func */
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
            1, 8, 1, /* 287: pointer.func */
            	292, 0,
            0, 0, 0, /* 292: func */
            1, 8, 1, /* 295: pointer.func */
            	300, 0,
            0, 0, 0, /* 300: func */
            1, 8, 1, /* 303: pointer.func */
            	308, 0,
            0, 0, 0, /* 308: func */
            1, 8, 1, /* 311: pointer.struct.ec_point_st */
            	316, 0,
            0, 88, 4, /* 316: struct.ec_point_st */
            	61, 0,
            	5, 8,
            	5, 32,
            	5, 56,
            1, 8, 1, /* 327: pointer.char */
            	332, 0,
            0, 1, 0, /* 332: char */
            1, 8, 1, /* 335: pointer.struct.ec_extra_data_st */
            	340, 0,
            0, 40, 5, /* 340: struct.ec_extra_data_st */
            	335, 0,
            	327, 8,
            	353, 16,
            	361, 24,
            	361, 32,
            1, 8, 1, /* 353: pointer.func */
            	358, 0,
            0, 0, 0, /* 358: func */
            1, 8, 1, /* 361: pointer.func */
            	366, 0,
            0, 0, 0, /* 366: func */
            1, 8, 1, /* 369: pointer.func */
            	374, 0,
            0, 0, 0, /* 374: func */
            1, 8, 1, /* 377: pointer.struct.ec_key_st.284 */
            	18, 0,
            0, 24, 0, /* 382: array[6].int */
            0, 8, 0, /* 385: long */
        },
        .arg_entity_index = { 377, },
        .ret_entity_index = 29,
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

