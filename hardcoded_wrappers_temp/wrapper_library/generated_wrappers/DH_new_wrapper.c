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

DH * DH_new(void) 
{
    DH * ret;

    struct lib_enter_args args = {
        .entity_metadata = {
            0, 32, 2, /* 0: struct.ENGINE_CMD_DEFN_st */
            	7, 8,
            	7, 16,
            1, 8, 1, /* 7: pointer.char */
            	12, 0,
            0, 1, 0, /* 12: char */
            1, 8, 1, /* 15: pointer.func */
            	20, 0,
            0, 0, 0, /* 20: func */
            0, 0, 0, /* 23: func */
            0, 0, 0, /* 26: func */
            0, 0, 0, /* 29: func */
            1, 8, 1, /* 32: pointer.func */
            	29, 0,
            0, 0, 0, /* 37: func */
            1, 8, 1, /* 40: pointer.func */
            	37, 0,
            1, 8, 1, /* 45: pointer.func */
            	50, 0,
            0, 0, 0, /* 50: func */
            0, 0, 0, /* 53: func */
            1, 8, 1, /* 56: pointer.func */
            	53, 0,
            0, 0, 0, /* 61: func */
            1, 8, 1, /* 64: pointer.func */
            	61, 0,
            0, 0, 0, /* 69: struct.store_method_st */
            1, 8, 1, /* 72: pointer.struct.store_method_st */
            	69, 0,
            1, 8, 1, /* 77: pointer.func */
            	82, 0,
            0, 0, 0, /* 82: func */
            0, 0, 0, /* 85: func */
            0, 0, 0, /* 88: func */
            0, 0, 0, /* 91: func */
            0, 48, 6, /* 94: struct.rand_meth_st */
            	109, 0,
            	114, 8,
            	119, 16,
            	77, 24,
            	114, 32,
            	124, 40,
            1, 8, 1, /* 109: pointer.func */
            	91, 0,
            1, 8, 1, /* 114: pointer.func */
            	88, 0,
            1, 8, 1, /* 119: pointer.func */
            	85, 0,
            1, 8, 1, /* 124: pointer.func */
            	129, 0,
            0, 0, 0, /* 129: func */
            1, 8, 1, /* 132: pointer.struct.rand_meth_st */
            	94, 0,
            0, 0, 0, /* 137: func */
            1, 8, 1, /* 140: pointer.func */
            	137, 0,
            0, 48, 5, /* 145: struct.ecdsa_method */
            	7, 0,
            	140, 8,
            	158, 16,
            	166, 24,
            	7, 40,
            1, 8, 1, /* 158: pointer.func */
            	163, 0,
            0, 0, 0, /* 163: func */
            1, 8, 1, /* 166: pointer.func */
            	171, 0,
            0, 0, 0, /* 171: func */
            0, 0, 0, /* 174: func */
            1, 8, 1, /* 177: pointer.func */
            	174, 0,
            0, 32, 3, /* 182: struct.ecdh_method */
            	7, 0,
            	177, 8,
            	7, 24,
            1, 8, 1, /* 191: pointer.func */
            	196, 0,
            0, 0, 0, /* 196: func */
            0, 0, 0, /* 199: func */
            1, 8, 1, /* 202: pointer.func */
            	199, 0,
            0, 0, 0, /* 207: func */
            1, 8, 1, /* 210: pointer.func */
            	215, 0,
            0, 0, 0, /* 215: func */
            1, 8, 1, /* 218: pointer.struct.bignum_st */
            	223, 0,
            0, 24, 1, /* 223: struct.bignum_st */
            	228, 0,
            1, 8, 1, /* 228: pointer.int */
            	233, 0,
            0, 4, 0, /* 233: int */
            0, 72, 8, /* 236: struct.dh_method */
            	7, 0,
            	255, 8,
            	210, 16,
            	263, 24,
            	255, 32,
            	255, 40,
            	7, 56,
            	271, 64,
            1, 8, 1, /* 255: pointer.func */
            	260, 0,
            0, 0, 0, /* 260: func */
            1, 8, 1, /* 263: pointer.func */
            	268, 0,
            0, 0, 0, /* 268: func */
            1, 8, 1, /* 271: pointer.func */
            	207, 0,
            1, 8, 1, /* 276: pointer.struct.ecdsa_method */
            	145, 0,
            0, 8, 0, /* 281: array[2].int */
            0, 0, 0, /* 284: func */
            0, 0, 0, /* 287: func */
            0, 0, 0, /* 290: func */
            0, 144, 12, /* 293: struct.dh_st */
            	218, 8,
            	218, 16,
            	218, 32,
            	218, 40,
            	320, 56,
            	218, 64,
            	218, 72,
            	7, 80,
            	218, 96,
            	334, 112,
            	366, 128,
            	371, 136,
            1, 8, 1, /* 320: pointer.struct.bn_mont_ctx_st */
            	325, 0,
            0, 96, 3, /* 325: struct.bn_mont_ctx_st */
            	223, 8,
            	223, 32,
            	223, 56,
            0, 16, 1, /* 334: struct.crypto_ex_data_st */
            	339, 0,
            1, 8, 1, /* 339: pointer.struct.stack_st_OPENSSL_STRING */
            	344, 0,
            0, 32, 1, /* 344: struct.stack_st_OPENSSL_STRING */
            	349, 0,
            0, 32, 2, /* 349: struct.stack_st */
            	356, 8,
            	361, 24,
            1, 8, 1, /* 356: pointer.pointer.char */
            	7, 0,
            1, 8, 1, /* 361: pointer.func */
            	287, 0,
            1, 8, 1, /* 366: pointer.struct.dh_method */
            	236, 0,
            1, 8, 1, /* 371: pointer.struct.engine_st */
            	376, 0,
            0, 216, 24, /* 376: struct.engine_st */
            	7, 0,
            	7, 8,
            	427, 16,
            	511, 24,
            	366, 32,
            	581, 40,
            	276, 48,
            	132, 56,
            	72, 64,
            	64, 72,
            	56, 80,
            	40, 88,
            	32, 96,
            	586, 104,
            	586, 112,
            	586, 120,
            	45, 128,
            	591, 136,
            	591, 144,
            	15, 152,
            	596, 160,
            	334, 184,
            	371, 200,
            	371, 208,
            1, 8, 1, /* 427: pointer.struct.rsa_meth_st */
            	432, 0,
            0, 112, 13, /* 432: struct.rsa_meth_st */
            	7, 0,
            	461, 8,
            	461, 16,
            	461, 24,
            	461, 32,
            	466, 40,
            	474, 48,
            	482, 56,
            	482, 64,
            	7, 80,
            	490, 88,
            	498, 96,
            	506, 104,
            1, 8, 1, /* 461: pointer.func */
            	290, 0,
            1, 8, 1, /* 466: pointer.func */
            	471, 0,
            0, 0, 0, /* 471: func */
            1, 8, 1, /* 474: pointer.func */
            	479, 0,
            0, 0, 0, /* 479: func */
            1, 8, 1, /* 482: pointer.func */
            	487, 0,
            0, 0, 0, /* 487: func */
            1, 8, 1, /* 490: pointer.func */
            	495, 0,
            0, 0, 0, /* 495: func */
            1, 8, 1, /* 498: pointer.func */
            	503, 0,
            0, 0, 0, /* 503: func */
            1, 8, 1, /* 506: pointer.func */
            	284, 0,
            1, 8, 1, /* 511: pointer.struct.dsa_method.1040 */
            	516, 0,
            0, 96, 11, /* 516: struct.dsa_method.1040 */
            	7, 0,
            	541, 8,
            	549, 16,
            	557, 24,
            	565, 32,
            	573, 40,
            	202, 48,
            	202, 56,
            	7, 72,
            	191, 80,
            	202, 88,
            1, 8, 1, /* 541: pointer.func */
            	546, 0,
            0, 0, 0, /* 546: func */
            1, 8, 1, /* 549: pointer.func */
            	554, 0,
            0, 0, 0, /* 554: func */
            1, 8, 1, /* 557: pointer.func */
            	562, 0,
            0, 0, 0, /* 562: func */
            1, 8, 1, /* 565: pointer.func */
            	570, 0,
            0, 0, 0, /* 570: func */
            1, 8, 1, /* 573: pointer.func */
            	578, 0,
            0, 0, 0, /* 578: func */
            1, 8, 1, /* 581: pointer.struct.ecdh_method */
            	182, 0,
            1, 8, 1, /* 586: pointer.func */
            	26, 0,
            1, 8, 1, /* 591: pointer.func */
            	23, 0,
            1, 8, 1, /* 596: pointer.struct.ENGINE_CMD_DEFN_st */
            	0, 0,
            0, 8, 0, /* 601: long */
            1, 8, 1, /* 604: pointer.struct.dh_st */
            	293, 0,
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 604,
    };
    struct lib_enter_args *args_addr = &args;
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    DH * *new_ret_ptr = (DH * *)new_args->ret;

    DH * (*orig_DH_new)(void);
    orig_DH_new = dlsym(RTLD_NEXT, "DH_new");
    *new_ret_ptr = (*orig_DH_new)();

    syscall(889);

    return ret;
}

