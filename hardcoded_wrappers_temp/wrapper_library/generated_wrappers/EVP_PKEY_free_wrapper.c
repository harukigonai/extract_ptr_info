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

void bb_EVP_PKEY_free(EVP_PKEY * arg_a);

void EVP_PKEY_free(EVP_PKEY * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_PKEY_free called %lu\n", in_lib);
    if (!in_lib)
        bb_EVP_PKEY_free(arg_a);
    else {
        void (*orig_EVP_PKEY_free)(EVP_PKEY *);
        orig_EVP_PKEY_free = dlsym(RTLD_NEXT, "EVP_PKEY_free");
        orig_EVP_PKEY_free(arg_a);
    }
}

void bb_EVP_PKEY_free(EVP_PKEY * arg_a) 
{
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 8, 1, /* 0: struct.fnames */
            	5, 0,
            1, 8, 1, /* 5: pointer.char */
            	4096, 0,
            0, 0, 0, /* 10: func */
            4097, 8, 0, /* 13: pointer.func */
            1, 8, 1, /* 16: pointer.pointer.char */
            	5, 0,
            0, 0, 0, /* 21: func */
            1, 8, 1, /* 24: pointer.struct.dsa_method.1040 */
            	29, 0,
            0, 96, 2, /* 29: struct.dsa_method.1040 */
            	5, 0,
            	5, 72,
            4097, 8, 0, /* 36: pointer.func */
            0, 0, 0, /* 39: func */
            0, 0, 0, /* 42: func */
            4097, 8, 0, /* 45: pointer.func */
            0, 112, 2, /* 48: struct.rsa_meth_st */
            	5, 0,
            	5, 80,
            4097, 8, 0, /* 55: pointer.func */
            0, 0, 0, /* 58: func */
            0, 0, 0, /* 61: func */
            1, 8, 1, /* 64: pointer.struct.ENGINE_CMD_DEFN_st */
            	69, 0,
            0, 32, 2, /* 69: struct.ENGINE_CMD_DEFN_st */
            	5, 8,
            	5, 16,
            4097, 8, 0, /* 76: pointer.func */
            0, 0, 0, /* 79: func */
            0, 0, 0, /* 82: func */
            4097, 8, 0, /* 85: pointer.func */
            0, 0, 0, /* 88: func */
            0, 48, 2, /* 91: struct.ecdsa_method */
            	5, 0,
            	5, 40,
            4097, 8, 0, /* 98: pointer.func */
            4097, 8, 0, /* 101: pointer.func */
            1, 8, 1, /* 104: pointer.struct.engine_st */
            	109, 0,
            0, 216, 13, /* 109: struct.engine_st */
            	5, 0,
            	5, 8,
            	138, 16,
            	24, 24,
            	143, 32,
            	155, 40,
            	167, 48,
            	172, 56,
            	180, 64,
            	64, 160,
            	188, 184,
            	104, 200,
            	104, 208,
            1, 8, 1, /* 138: pointer.struct.rsa_meth_st */
            	48, 0,
            1, 8, 1, /* 143: pointer.struct.dh_method */
            	148, 0,
            0, 72, 2, /* 148: struct.dh_method */
            	5, 0,
            	5, 56,
            1, 8, 1, /* 155: pointer.struct.ecdh_method */
            	160, 0,
            0, 32, 2, /* 160: struct.ecdh_method */
            	5, 0,
            	5, 24,
            1, 8, 1, /* 167: pointer.struct.ecdsa_method */
            	91, 0,
            1, 8, 1, /* 172: pointer.struct.rand_meth_st */
            	177, 0,
            0, 48, 0, /* 177: struct.rand_meth_st */
            1, 8, 1, /* 180: pointer.struct.store_method_st */
            	185, 0,
            0, 0, 0, /* 185: struct.store_method_st */
            0, 16, 1, /* 188: struct.crypto_ex_data_st */
            	193, 0,
            1, 8, 1, /* 193: pointer.struct.stack_st_OPENSSL_STRING */
            	198, 0,
            0, 32, 1, /* 198: struct.stack_st_OPENSSL_STRING */
            	203, 0,
            0, 32, 1, /* 203: struct.stack_st */
            	16, 8,
            0, 0, 0, /* 208: func */
            4097, 8, 0, /* 211: pointer.func */
            0, 0, 0, /* 214: func */
            4097, 8, 0, /* 217: pointer.func */
            0, 0, 0, /* 220: func */
            4097, 8, 0, /* 223: pointer.func */
            4097, 8, 0, /* 226: pointer.func */
            4097, 8, 0, /* 229: pointer.func */
            4097, 8, 0, /* 232: pointer.func */
            1, 8, 1, /* 235: pointer.struct.evp_pkey_asn1_method_st.2593 */
            	240, 0,
            0, 208, 2, /* 240: struct.evp_pkey_asn1_method_st.2593 */
            	5, 16,
            	5, 24,
            0, 0, 0, /* 247: func */
            4097, 8, 0, /* 250: pointer.func */
            4097, 8, 0, /* 253: pointer.func */
            0, 0, 0, /* 256: func */
            0, 0, 0, /* 259: func */
            4097, 8, 0, /* 262: pointer.func */
            0, 0, 0, /* 265: func */
            4097, 8, 0, /* 268: pointer.func */
            0, 0, 0, /* 271: func */
            4097, 8, 0, /* 274: pointer.func */
            0, 0, 0, /* 277: func */
            4097, 8, 0, /* 280: pointer.func */
            0, 0, 0, /* 283: func */
            0, 0, 0, /* 286: func */
            4097, 8, 0, /* 289: pointer.func */
            4097, 8, 0, /* 292: pointer.func */
            0, 8, 0, /* 295: long */
            4097, 8, 0, /* 298: pointer.func */
            0, 0, 0, /* 301: func */
            0, 56, 4, /* 304: struct.evp_pkey_st.2595 */
            	235, 16,
            	104, 24,
            	0, 32,
            	193, 48,
            1, 8, 1, /* 315: pointer.struct.evp_pkey_st.2595 */
            	304, 0,
            4097, 8, 0, /* 320: pointer.func */
            0, 0, 0, /* 323: func */
            4097, 8, 0, /* 326: pointer.func */
            0, 0, 0, /* 329: func */
            4097, 8, 0, /* 332: pointer.func */
            0, 0, 0, /* 335: func */
            4097, 8, 0, /* 338: pointer.func */
            4097, 8, 0, /* 341: pointer.func */
            4097, 8, 0, /* 344: pointer.func */
            0, 0, 0, /* 347: func */
            4097, 8, 0, /* 350: pointer.func */
            4097, 8, 0, /* 353: pointer.func */
            4097, 8, 0, /* 356: pointer.func */
            0, 0, 0, /* 359: func */
            0, 0, 0, /* 362: func */
            4097, 8, 0, /* 365: pointer.func */
            0, 0, 0, /* 368: func */
            4097, 8, 0, /* 371: pointer.func */
            0, 0, 0, /* 374: func */
            0, 0, 0, /* 377: func */
            4097, 8, 0, /* 380: pointer.func */
            0, 0, 0, /* 383: func */
            0, 0, 0, /* 386: func */
            0, 0, 0, /* 389: func */
            0, 0, 0, /* 392: func */
            4097, 8, 0, /* 395: pointer.func */
            0, 0, 0, /* 398: func */
            4097, 8, 0, /* 401: pointer.func */
            4097, 8, 0, /* 404: pointer.func */
            0, 0, 0, /* 407: func */
            4097, 8, 0, /* 410: pointer.func */
            0, 0, 0, /* 413: func */
            0, 1, 0, /* 416: char */
            0, 0, 0, /* 419: func */
            4097, 8, 0, /* 422: pointer.func */
            0, 0, 0, /* 425: func */
            4097, 8, 0, /* 428: pointer.func */
            4097, 8, 0, /* 431: pointer.func */
            0, 0, 0, /* 434: func */
            0, 0, 0, /* 437: func */
            4097, 8, 0, /* 440: pointer.func */
            4097, 8, 0, /* 443: pointer.func */
            4097, 8, 0, /* 446: pointer.func */
            0, 0, 0, /* 449: func */
            0, 0, 0, /* 452: func */
            4097, 8, 0, /* 455: pointer.func */
            0, 0, 0, /* 458: func */
            4097, 8, 0, /* 461: pointer.func */
            0, 0, 0, /* 464: func */
            0, 0, 0, /* 467: func */
            4097, 8, 0, /* 470: pointer.func */
            0, 0, 0, /* 473: func */
            0, 0, 0, /* 476: func */
            4097, 8, 0, /* 479: pointer.func */
            0, 4, 0, /* 482: int */
            0, 0, 0, /* 485: func */
            4097, 8, 0, /* 488: pointer.func */
            0, 0, 0, /* 491: func */
        },
        .arg_entity_index = { 315, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_PKEY * new_arg_a = *((EVP_PKEY * *)new_args->args[0]);

    void (*orig_EVP_PKEY_free)(EVP_PKEY *);
    orig_EVP_PKEY_free = dlsym(RTLD_NEXT, "EVP_PKEY_free");
    (*orig_EVP_PKEY_free)(new_arg_a);

    syscall(889);

}

