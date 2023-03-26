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

void DH_free(DH * arg_a) 
{
    struct lib_enter_args args = {
        .entity_metadata = {
            0, 32, 4, /* 0: struct.ENGINE_CMD_DEFN_st */
            	11, 0,
            	14, 8,
            	14, 16,
            	11, 24,
            0, 4, 0, /* 11: int */
            1, 8, 1, /* 14: pointer.char */
            	19, 0,
            0, 1, 0, /* 19: char */
            1, 8, 1, /* 22: pointer.func */
            	27, 0,
            0, 0, 0, /* 27: func */
            0, 0, 0, /* 30: func */
            0, 0, 0, /* 33: func */
            0, 0, 0, /* 36: func */
            1, 8, 1, /* 39: pointer.func */
            	36, 0,
            0, 0, 0, /* 44: func */
            1, 8, 1, /* 47: pointer.func */
            	44, 0,
            1, 8, 1, /* 52: pointer.func */
            	57, 0,
            0, 0, 0, /* 57: func */
            0, 0, 0, /* 60: func */
            1, 8, 1, /* 63: pointer.func */
            	60, 0,
            0, 0, 0, /* 68: func */
            1, 8, 1, /* 71: pointer.func */
            	68, 0,
            0, 0, 0, /* 76: struct.store_method_st */
            1, 8, 1, /* 79: pointer.struct.store_method_st */
            	76, 0,
            1, 8, 1, /* 84: pointer.func */
            	89, 0,
            0, 0, 0, /* 89: func */
            0, 0, 0, /* 92: func */
            0, 0, 0, /* 95: func */
            0, 0, 0, /* 98: func */
            0, 48, 6, /* 101: struct.rand_meth_st */
            	116, 0,
            	121, 8,
            	126, 16,
            	84, 24,
            	121, 32,
            	131, 40,
            1, 8, 1, /* 116: pointer.func */
            	98, 0,
            1, 8, 1, /* 121: pointer.func */
            	95, 0,
            1, 8, 1, /* 126: pointer.func */
            	92, 0,
            1, 8, 1, /* 131: pointer.func */
            	136, 0,
            0, 0, 0, /* 136: func */
            1, 8, 1, /* 139: pointer.struct.rand_meth_st */
            	101, 0,
            0, 0, 0, /* 144: func */
            1, 8, 1, /* 147: pointer.func */
            	144, 0,
            0, 48, 6, /* 152: struct.ecdsa_method */
            	14, 0,
            	147, 8,
            	167, 16,
            	175, 24,
            	11, 32,
            	14, 40,
            1, 8, 1, /* 167: pointer.func */
            	172, 0,
            0, 0, 0, /* 172: func */
            1, 8, 1, /* 175: pointer.func */
            	180, 0,
            0, 0, 0, /* 180: func */
            0, 0, 0, /* 183: func */
            1, 8, 1, /* 186: pointer.func */
            	183, 0,
            0, 32, 4, /* 191: struct.ecdh_method */
            	14, 0,
            	186, 8,
            	11, 16,
            	14, 24,
            1, 8, 1, /* 202: pointer.func */
            	207, 0,
            0, 0, 0, /* 207: func */
            0, 0, 0, /* 210: func */
            1, 8, 1, /* 213: pointer.func */
            	210, 0,
            0, 0, 0, /* 218: func */
            1, 8, 1, /* 221: pointer.func */
            	226, 0,
            0, 0, 0, /* 226: func */
            1, 8, 1, /* 229: pointer.struct.bignum_st */
            	234, 0,
            0, 24, 5, /* 234: struct.bignum_st */
            	247, 0,
            	11, 8,
            	11, 12,
            	11, 16,
            	11, 20,
            1, 8, 1, /* 247: pointer.int */
            	11, 0,
            0, 72, 9, /* 252: struct.dh_method */
            	14, 0,
            	273, 8,
            	221, 16,
            	281, 24,
            	273, 32,
            	273, 40,
            	11, 48,
            	14, 56,
            	289, 64,
            1, 8, 1, /* 273: pointer.func */
            	278, 0,
            0, 0, 0, /* 278: func */
            1, 8, 1, /* 281: pointer.func */
            	286, 0,
            0, 0, 0, /* 286: func */
            1, 8, 1, /* 289: pointer.func */
            	218, 0,
            1, 8, 1, /* 294: pointer.struct.ecdsa_method */
            	152, 0,
            0, 8, 2, /* 299: array[2].int */
            	11, 0,
            	11, 4,
            0, 0, 0, /* 306: func */
            0, 0, 0, /* 309: func */
            0, 16, 2, /* 312: struct.crypto_ex_data_st */
            	319, 0,
            	11, 8,
            1, 8, 1, /* 319: pointer.struct.stack_st_OPENSSL_STRING */
            	324, 0,
            0, 32, 1, /* 324: struct.stack_st_OPENSSL_STRING */
            	329, 0,
            0, 32, 5, /* 329: struct.stack_st */
            	11, 0,
            	342, 8,
            	11, 16,
            	11, 20,
            	347, 24,
            1, 8, 1, /* 342: pointer.pointer.char */
            	14, 0,
            1, 8, 1, /* 347: pointer.func */
            	309, 0,
            1, 8, 1, /* 352: pointer.struct.ENGINE_CMD_DEFN_st */
            	0, 0,
            1, 8, 1, /* 357: pointer.struct.dh_method */
            	252, 0,
            0, 0, 0, /* 362: func */
            0, 0, 0, /* 365: func */
            1, 8, 1, /* 368: pointer.struct.rsa_meth_st */
            	373, 0,
            0, 112, 14, /* 373: struct.rsa_meth_st */
            	14, 0,
            	404, 8,
            	404, 16,
            	404, 24,
            	404, 32,
            	409, 40,
            	417, 48,
            	425, 56,
            	425, 64,
            	11, 72,
            	14, 80,
            	433, 88,
            	438, 96,
            	446, 104,
            1, 8, 1, /* 404: pointer.func */
            	365, 0,
            1, 8, 1, /* 409: pointer.func */
            	414, 0,
            0, 0, 0, /* 414: func */
            1, 8, 1, /* 417: pointer.func */
            	422, 0,
            0, 0, 0, /* 422: func */
            1, 8, 1, /* 425: pointer.func */
            	430, 0,
            0, 0, 0, /* 430: func */
            1, 8, 1, /* 433: pointer.func */
            	362, 0,
            1, 8, 1, /* 438: pointer.func */
            	443, 0,
            0, 0, 0, /* 443: func */
            1, 8, 1, /* 446: pointer.func */
            	306, 0,
            1, 8, 1, /* 451: pointer.func */
            	456, 0,
            0, 0, 0, /* 456: func */
            0, 144, 18, /* 459: struct.dh_st */
            	11, 0,
            	11, 4,
            	229, 8,
            	229, 16,
            	498, 24,
            	229, 32,
            	229, 40,
            	11, 48,
            	501, 56,
            	229, 64,
            	229, 72,
            	14, 80,
            	11, 88,
            	229, 96,
            	11, 104,
            	312, 112,
            	357, 128,
            	521, 136,
            0, 8, 0, /* 498: long */
            1, 8, 1, /* 501: pointer.struct.bn_mont_ctx_st */
            	506, 0,
            0, 96, 6, /* 506: struct.bn_mont_ctx_st */
            	11, 0,
            	234, 8,
            	234, 32,
            	234, 56,
            	299, 80,
            	11, 88,
            1, 8, 1, /* 521: pointer.struct.engine_st */
            	526, 0,
            0, 216, 27, /* 526: struct.engine_st */
            	14, 0,
            	14, 8,
            	368, 16,
            	583, 24,
            	357, 32,
            	647, 40,
            	294, 48,
            	139, 56,
            	79, 64,
            	71, 72,
            	63, 80,
            	47, 88,
            	39, 96,
            	652, 104,
            	652, 112,
            	652, 120,
            	52, 128,
            	657, 136,
            	657, 144,
            	22, 152,
            	352, 160,
            	11, 168,
            	11, 172,
            	11, 176,
            	312, 184,
            	521, 200,
            	521, 208,
            1, 8, 1, /* 583: pointer.struct.dsa_method.1040 */
            	588, 0,
            0, 96, 12, /* 588: struct.dsa_method.1040 */
            	14, 0,
            	615, 8,
            	451, 16,
            	623, 24,
            	631, 32,
            	639, 40,
            	213, 48,
            	213, 56,
            	11, 64,
            	14, 72,
            	202, 80,
            	213, 88,
            1, 8, 1, /* 615: pointer.func */
            	620, 0,
            0, 0, 0, /* 620: func */
            1, 8, 1, /* 623: pointer.func */
            	628, 0,
            0, 0, 0, /* 628: func */
            1, 8, 1, /* 631: pointer.func */
            	636, 0,
            0, 0, 0, /* 636: func */
            1, 8, 1, /* 639: pointer.func */
            	644, 0,
            0, 0, 0, /* 644: func */
            1, 8, 1, /* 647: pointer.struct.ecdh_method */
            	191, 0,
            1, 8, 1, /* 652: pointer.func */
            	33, 0,
            1, 8, 1, /* 657: pointer.func */
            	30, 0,
            1, 8, 1, /* 662: pointer.struct.dh_st */
            	459, 0,
        },
        .arg_entity_index = { 662, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    DH * new_arg_a = *((DH * *)new_args->args[0]);

    void (*orig_DH_free)(DH *);
    orig_DH_free = dlsym(RTLD_NEXT, "DH_free");
    (*orig_DH_free)(new_arg_a);

    syscall(889);

}
