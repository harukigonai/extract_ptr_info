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
            0, 32, 1, /* 10: struct.stack_st_OPENSSL_STRING */
            	15, 0,
            0, 32, 2, /* 15: struct.stack_st */
            	22, 8,
            	27, 24,
            1, 8, 1, /* 22: pointer.pointer.char */
            	5, 0,
            4097, 8, 0, /* 27: pointer.func */
            1, 8, 1, /* 30: pointer.struct.stack_st_OPENSSL_STRING */
            	10, 0,
            0, 16, 1, /* 35: struct.crypto_ex_data_st */
            	30, 0,
            0, 32, 2, /* 40: struct.ENGINE_CMD_DEFN_st */
            	5, 8,
            	5, 16,
            1, 8, 1, /* 47: pointer.struct.ENGINE_CMD_DEFN_st */
            	40, 0,
            4097, 8, 0, /* 52: pointer.func */
            4097, 8, 0, /* 55: pointer.func */
            4097, 8, 0, /* 58: pointer.func */
            4097, 8, 0, /* 61: pointer.func */
            4097, 8, 0, /* 64: pointer.func */
            0, 0, 0, /* 67: struct.store_method_st */
            4097, 8, 0, /* 70: pointer.func */
            4097, 8, 0, /* 73: pointer.func */
            0, 216, 24, /* 76: struct.engine_st */
            	5, 0,
            	5, 8,
            	127, 16,
            	182, 24,
            	233, 32,
            	269, 40,
            	286, 48,
            	313, 56,
            	342, 64,
            	347, 72,
            	64, 80,
            	350, 88,
            	353, 96,
            	61, 104,
            	61, 112,
            	61, 120,
            	58, 128,
            	55, 136,
            	55, 144,
            	52, 152,
            	47, 160,
            	35, 184,
            	356, 200,
            	356, 208,
            1, 8, 1, /* 127: pointer.struct.rsa_meth_st */
            	132, 0,
            0, 112, 13, /* 132: struct.rsa_meth_st */
            	5, 0,
            	161, 8,
            	161, 16,
            	161, 24,
            	161, 32,
            	164, 40,
            	167, 48,
            	170, 56,
            	170, 64,
            	5, 80,
            	173, 88,
            	176, 96,
            	179, 104,
            4097, 8, 0, /* 161: pointer.func */
            4097, 8, 0, /* 164: pointer.func */
            4097, 8, 0, /* 167: pointer.func */
            4097, 8, 0, /* 170: pointer.func */
            4097, 8, 0, /* 173: pointer.func */
            4097, 8, 0, /* 176: pointer.func */
            4097, 8, 0, /* 179: pointer.func */
            1, 8, 1, /* 182: pointer.struct.dsa_method */
            	187, 0,
            0, 96, 11, /* 187: struct.dsa_method */
            	5, 0,
            	212, 8,
            	215, 16,
            	218, 24,
            	221, 32,
            	224, 40,
            	227, 48,
            	227, 56,
            	5, 72,
            	230, 80,
            	227, 88,
            4097, 8, 0, /* 212: pointer.func */
            4097, 8, 0, /* 215: pointer.func */
            4097, 8, 0, /* 218: pointer.func */
            4097, 8, 0, /* 221: pointer.func */
            4097, 8, 0, /* 224: pointer.func */
            4097, 8, 0, /* 227: pointer.func */
            4097, 8, 0, /* 230: pointer.func */
            1, 8, 1, /* 233: pointer.struct.dh_method */
            	238, 0,
            0, 72, 8, /* 238: struct.dh_method */
            	5, 0,
            	257, 8,
            	260, 16,
            	263, 24,
            	257, 32,
            	257, 40,
            	5, 56,
            	266, 64,
            4097, 8, 0, /* 257: pointer.func */
            4097, 8, 0, /* 260: pointer.func */
            4097, 8, 0, /* 263: pointer.func */
            4097, 8, 0, /* 266: pointer.func */
            1, 8, 1, /* 269: pointer.struct.ecdh_method */
            	274, 0,
            0, 32, 3, /* 274: struct.ecdh_method */
            	5, 0,
            	283, 8,
            	5, 24,
            4097, 8, 0, /* 283: pointer.func */
            1, 8, 1, /* 286: pointer.struct.ecdsa_method */
            	291, 0,
            0, 48, 5, /* 291: struct.ecdsa_method */
            	5, 0,
            	304, 8,
            	307, 16,
            	310, 24,
            	5, 40,
            4097, 8, 0, /* 304: pointer.func */
            4097, 8, 0, /* 307: pointer.func */
            4097, 8, 0, /* 310: pointer.func */
            1, 8, 1, /* 313: pointer.struct.rand_meth_st */
            	318, 0,
            0, 48, 6, /* 318: struct.rand_meth_st */
            	333, 0,
            	336, 8,
            	73, 16,
            	339, 24,
            	336, 32,
            	70, 40,
            4097, 8, 0, /* 333: pointer.func */
            4097, 8, 0, /* 336: pointer.func */
            4097, 8, 0, /* 339: pointer.func */
            1, 8, 1, /* 342: pointer.struct.store_method_st */
            	67, 0,
            4097, 8, 0, /* 347: pointer.func */
            4097, 8, 0, /* 350: pointer.func */
            4097, 8, 0, /* 353: pointer.func */
            1, 8, 1, /* 356: pointer.struct.engine_st */
            	76, 0,
            4097, 8, 0, /* 361: pointer.func */
            0, 1, 0, /* 364: char */
            4097, 8, 0, /* 367: pointer.func */
            4097, 8, 0, /* 370: pointer.func */
            0, 56, 4, /* 373: struct.evp_pkey_st */
            	384, 16,
            	356, 24,
            	0, 32,
            	30, 48,
            1, 8, 1, /* 384: pointer.struct.evp_pkey_asn1_method_st */
            	389, 0,
            0, 208, 24, /* 389: struct.evp_pkey_asn1_method_st */
            	5, 16,
            	5, 24,
            	440, 32,
            	443, 40,
            	446, 48,
            	449, 56,
            	452, 64,
            	455, 72,
            	449, 80,
            	458, 88,
            	458, 96,
            	461, 104,
            	370, 112,
            	458, 120,
            	446, 128,
            	446, 136,
            	449, 144,
            	464, 152,
            	467, 160,
            	367, 168,
            	461, 176,
            	370, 184,
            	470, 192,
            	361, 200,
            4097, 8, 0, /* 440: pointer.func */
            4097, 8, 0, /* 443: pointer.func */
            4097, 8, 0, /* 446: pointer.func */
            4097, 8, 0, /* 449: pointer.func */
            4097, 8, 0, /* 452: pointer.func */
            4097, 8, 0, /* 455: pointer.func */
            4097, 8, 0, /* 458: pointer.func */
            4097, 8, 0, /* 461: pointer.func */
            4097, 8, 0, /* 464: pointer.func */
            4097, 8, 0, /* 467: pointer.func */
            4097, 8, 0, /* 470: pointer.func */
            0, 8, 0, /* 473: pointer.void */
            1, 8, 1, /* 476: pointer.struct.evp_pkey_st */
            	373, 0,
        },
        .arg_entity_index = { 476, },
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

