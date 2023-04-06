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

void bb_DH_free(DH * arg_a);

void DH_free(DH * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("DH_free called %lu\n", in_lib);
    if (!in_lib)
        bb_DH_free(arg_a);
    else {
        void (*orig_DH_free)(DH *);
        orig_DH_free = dlsym(RTLD_NEXT, "DH_free");
        orig_DH_free(arg_a);
    }
}

void bb_DH_free(DH * arg_a) 
{
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.struct.engine_st */
            	5, 0,
            0, 216, 24, /* 5: struct.engine_st */
            	56, 0,
            	56, 8,
            	61, 16,
            	121, 24,
            	172, 32,
            	208, 40,
            	225, 48,
            	252, 56,
            	287, 64,
            	295, 72,
            	298, 80,
            	301, 88,
            	304, 96,
            	307, 104,
            	307, 112,
            	307, 120,
            	310, 128,
            	313, 136,
            	313, 144,
            	316, 152,
            	319, 160,
            	331, 184,
            	0, 200,
            	0, 208,
            1, 8, 1, /* 56: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 61: pointer.struct.rsa_meth_st */
            	66, 0,
            0, 112, 13, /* 66: struct.rsa_meth_st */
            	56, 0,
            	95, 8,
            	95, 16,
            	95, 24,
            	95, 32,
            	98, 40,
            	101, 48,
            	104, 56,
            	104, 64,
            	107, 80,
            	112, 88,
            	115, 96,
            	118, 104,
            8884097, 8, 0, /* 95: pointer.func */
            8884097, 8, 0, /* 98: pointer.func */
            8884097, 8, 0, /* 101: pointer.func */
            8884097, 8, 0, /* 104: pointer.func */
            1, 8, 1, /* 107: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 112: pointer.func */
            8884097, 8, 0, /* 115: pointer.func */
            8884097, 8, 0, /* 118: pointer.func */
            1, 8, 1, /* 121: pointer.struct.dsa_method */
            	126, 0,
            0, 96, 11, /* 126: struct.dsa_method */
            	56, 0,
            	151, 8,
            	154, 16,
            	157, 24,
            	160, 32,
            	163, 40,
            	166, 48,
            	166, 56,
            	107, 72,
            	169, 80,
            	166, 88,
            8884097, 8, 0, /* 151: pointer.func */
            8884097, 8, 0, /* 154: pointer.func */
            8884097, 8, 0, /* 157: pointer.func */
            8884097, 8, 0, /* 160: pointer.func */
            8884097, 8, 0, /* 163: pointer.func */
            8884097, 8, 0, /* 166: pointer.func */
            8884097, 8, 0, /* 169: pointer.func */
            1, 8, 1, /* 172: pointer.struct.dh_method */
            	177, 0,
            0, 72, 8, /* 177: struct.dh_method */
            	56, 0,
            	196, 8,
            	199, 16,
            	202, 24,
            	196, 32,
            	196, 40,
            	107, 56,
            	205, 64,
            8884097, 8, 0, /* 196: pointer.func */
            8884097, 8, 0, /* 199: pointer.func */
            8884097, 8, 0, /* 202: pointer.func */
            8884097, 8, 0, /* 205: pointer.func */
            1, 8, 1, /* 208: pointer.struct.ecdh_method */
            	213, 0,
            0, 32, 3, /* 213: struct.ecdh_method */
            	56, 0,
            	222, 8,
            	107, 24,
            8884097, 8, 0, /* 222: pointer.func */
            1, 8, 1, /* 225: pointer.struct.ecdsa_method */
            	230, 0,
            0, 48, 5, /* 230: struct.ecdsa_method */
            	56, 0,
            	243, 8,
            	246, 16,
            	249, 24,
            	107, 40,
            8884097, 8, 0, /* 243: pointer.func */
            8884097, 8, 0, /* 246: pointer.func */
            8884097, 8, 0, /* 249: pointer.func */
            1, 8, 1, /* 252: pointer.struct.rand_meth_st */
            	257, 0,
            0, 48, 6, /* 257: struct.rand_meth_st */
            	272, 0,
            	275, 8,
            	278, 16,
            	281, 24,
            	275, 32,
            	284, 40,
            8884097, 8, 0, /* 272: pointer.func */
            8884097, 8, 0, /* 275: pointer.func */
            8884097, 8, 0, /* 278: pointer.func */
            8884097, 8, 0, /* 281: pointer.func */
            8884097, 8, 0, /* 284: pointer.func */
            1, 8, 1, /* 287: pointer.struct.store_method_st */
            	292, 0,
            0, 0, 0, /* 292: struct.store_method_st */
            8884097, 8, 0, /* 295: pointer.func */
            8884097, 8, 0, /* 298: pointer.func */
            8884097, 8, 0, /* 301: pointer.func */
            8884097, 8, 0, /* 304: pointer.func */
            8884097, 8, 0, /* 307: pointer.func */
            8884097, 8, 0, /* 310: pointer.func */
            8884097, 8, 0, /* 313: pointer.func */
            8884097, 8, 0, /* 316: pointer.func */
            1, 8, 1, /* 319: pointer.struct.ENGINE_CMD_DEFN_st */
            	324, 0,
            0, 32, 2, /* 324: struct.ENGINE_CMD_DEFN_st */
            	56, 8,
            	56, 16,
            0, 16, 1, /* 331: struct.crypto_ex_data_st */
            	336, 0,
            1, 8, 1, /* 336: pointer.struct.stack_st_void */
            	341, 0,
            0, 32, 1, /* 341: struct.stack_st_void */
            	346, 0,
            0, 32, 2, /* 346: struct.stack_st */
            	353, 8,
            	358, 24,
            1, 8, 1, /* 353: pointer.pointer.char */
            	107, 0,
            8884097, 8, 0, /* 358: pointer.func */
            8884097, 8, 0, /* 361: pointer.func */
            0, 72, 8, /* 364: struct.dh_method */
            	56, 0,
            	361, 8,
            	383, 16,
            	386, 24,
            	361, 32,
            	361, 40,
            	107, 56,
            	389, 64,
            8884097, 8, 0, /* 383: pointer.func */
            8884097, 8, 0, /* 386: pointer.func */
            8884097, 8, 0, /* 389: pointer.func */
            0, 24, 1, /* 392: struct.bignum_st */
            	397, 0,
            1, 8, 1, /* 397: pointer.unsigned int */
            	402, 0,
            0, 4, 0, /* 402: unsigned int */
            0, 1, 0, /* 405: char */
            0, 32, 2, /* 408: struct.stack_st */
            	353, 8,
            	358, 24,
            1, 8, 1, /* 415: pointer.struct.dh_st */
            	420, 0,
            0, 144, 12, /* 420: struct.dh_st */
            	447, 8,
            	447, 16,
            	447, 32,
            	447, 40,
            	452, 56,
            	447, 64,
            	447, 72,
            	466, 80,
            	447, 96,
            	474, 112,
            	489, 128,
            	494, 136,
            1, 8, 1, /* 447: pointer.struct.bignum_st */
            	392, 0,
            1, 8, 1, /* 452: pointer.struct.bn_mont_ctx_st */
            	457, 0,
            0, 96, 3, /* 457: struct.bn_mont_ctx_st */
            	392, 8,
            	392, 32,
            	392, 56,
            1, 8, 1, /* 466: pointer.unsigned char */
            	471, 0,
            0, 1, 0, /* 471: unsigned char */
            0, 16, 1, /* 474: struct.crypto_ex_data_st */
            	479, 0,
            1, 8, 1, /* 479: pointer.struct.stack_st_void */
            	484, 0,
            0, 32, 1, /* 484: struct.stack_st_void */
            	408, 0,
            1, 8, 1, /* 489: pointer.struct.dh_method */
            	364, 0,
            1, 8, 1, /* 494: pointer.struct.engine_st */
            	5, 0,
        },
        .arg_entity_index = { 415, },
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

