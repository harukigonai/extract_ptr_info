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
            0, 32, 1, /* 0: struct.stack_st_X509_ATTRIBUTE */
            	5, 0,
            0, 32, 2, /* 5: struct.stack_st */
            	12, 8,
            	22, 24,
            1, 8, 1, /* 12: pointer.pointer.char */
            	17, 0,
            1, 8, 1, /* 17: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 22: pointer.func */
            0, 0, 0, /* 25: struct.ec_key_st */
            1, 8, 1, /* 28: pointer.struct.ec_key_st */
            	25, 0,
            4097, 8, 0, /* 33: pointer.func */
            4097, 8, 0, /* 36: pointer.func */
            4097, 8, 0, /* 39: pointer.func */
            0, 72, 8, /* 42: struct.dh_method */
            	61, 0,
            	39, 8,
            	66, 16,
            	36, 24,
            	39, 32,
            	39, 40,
            	17, 56,
            	33, 64,
            1, 8, 1, /* 61: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 66: pointer.func */
            0, 1, 0, /* 69: unsigned char */
            1, 8, 1, /* 72: pointer.unsigned char */
            	69, 0,
            1, 8, 1, /* 77: pointer.struct.stack_st_X509_ATTRIBUTE */
            	0, 0,
            0, 144, 12, /* 82: struct.dh_st */
            	109, 8,
            	109, 16,
            	109, 32,
            	109, 40,
            	127, 56,
            	109, 64,
            	109, 72,
            	72, 80,
            	109, 96,
            	141, 112,
            	156, 128,
            	161, 136,
            1, 8, 1, /* 109: pointer.struct.bignum_st */
            	114, 0,
            0, 24, 1, /* 114: struct.bignum_st */
            	119, 0,
            1, 8, 1, /* 119: pointer.unsigned int */
            	124, 0,
            0, 4, 0, /* 124: unsigned int */
            1, 8, 1, /* 127: pointer.struct.bn_mont_ctx_st */
            	132, 0,
            0, 96, 3, /* 132: struct.bn_mont_ctx_st */
            	114, 8,
            	114, 32,
            	114, 56,
            0, 16, 1, /* 141: struct.crypto_ex_data_st */
            	146, 0,
            1, 8, 1, /* 146: pointer.struct.stack_st_void */
            	151, 0,
            0, 32, 1, /* 151: struct.stack_st_void */
            	5, 0,
            1, 8, 1, /* 156: pointer.struct.dh_method */
            	42, 0,
            1, 8, 1, /* 161: pointer.struct.engine_st */
            	166, 0,
            0, 0, 0, /* 166: struct.engine_st */
            0, 112, 13, /* 169: struct.rsa_meth_st */
            	61, 0,
            	198, 8,
            	198, 16,
            	198, 24,
            	198, 32,
            	201, 40,
            	204, 48,
            	207, 56,
            	207, 64,
            	17, 80,
            	210, 88,
            	213, 96,
            	216, 104,
            4097, 8, 0, /* 198: pointer.func */
            4097, 8, 0, /* 201: pointer.func */
            4097, 8, 0, /* 204: pointer.func */
            4097, 8, 0, /* 207: pointer.func */
            4097, 8, 0, /* 210: pointer.func */
            4097, 8, 0, /* 213: pointer.func */
            4097, 8, 0, /* 216: pointer.func */
            0, 0, 0, /* 219: struct.bn_blinding_st */
            1, 8, 1, /* 222: pointer.struct.rsa_st */
            	227, 0,
            0, 168, 17, /* 227: struct.rsa_st */
            	264, 16,
            	161, 24,
            	109, 32,
            	109, 40,
            	109, 48,
            	109, 56,
            	109, 64,
            	109, 72,
            	109, 80,
            	109, 88,
            	141, 96,
            	127, 120,
            	127, 128,
            	127, 136,
            	17, 144,
            	269, 152,
            	269, 160,
            1, 8, 1, /* 264: pointer.struct.rsa_meth_st */
            	169, 0,
            1, 8, 1, /* 269: pointer.struct.bn_blinding_st */
            	219, 0,
            1, 8, 1, /* 274: pointer.struct.dsa_method */
            	279, 0,
            0, 96, 11, /* 279: struct.dsa_method */
            	61, 0,
            	304, 8,
            	307, 16,
            	310, 24,
            	313, 32,
            	316, 40,
            	319, 48,
            	319, 56,
            	17, 72,
            	322, 80,
            	319, 88,
            4097, 8, 0, /* 304: pointer.func */
            4097, 8, 0, /* 307: pointer.func */
            4097, 8, 0, /* 310: pointer.func */
            4097, 8, 0, /* 313: pointer.func */
            4097, 8, 0, /* 316: pointer.func */
            4097, 8, 0, /* 319: pointer.func */
            4097, 8, 0, /* 322: pointer.func */
            4097, 8, 0, /* 325: pointer.func */
            4097, 8, 0, /* 328: pointer.func */
            4097, 8, 0, /* 331: pointer.func */
            4097, 8, 0, /* 334: pointer.func */
            4097, 8, 0, /* 337: pointer.func */
            1, 8, 1, /* 340: pointer.struct.evp_pkey_st */
            	345, 0,
            0, 56, 4, /* 345: struct.evp_pkey_st */
            	356, 16,
            	161, 24,
            	442, 32,
            	77, 48,
            1, 8, 1, /* 356: pointer.struct.evp_pkey_asn1_method_st */
            	361, 0,
            0, 208, 24, /* 361: struct.evp_pkey_asn1_method_st */
            	17, 16,
            	17, 24,
            	334, 32,
            	412, 40,
            	415, 48,
            	418, 56,
            	421, 64,
            	424, 72,
            	418, 80,
            	427, 88,
            	427, 96,
            	337, 104,
            	328, 112,
            	427, 120,
            	430, 128,
            	415, 136,
            	418, 144,
            	325, 152,
            	433, 160,
            	331, 168,
            	337, 176,
            	328, 184,
            	436, 192,
            	439, 200,
            4097, 8, 0, /* 412: pointer.func */
            4097, 8, 0, /* 415: pointer.func */
            4097, 8, 0, /* 418: pointer.func */
            4097, 8, 0, /* 421: pointer.func */
            4097, 8, 0, /* 424: pointer.func */
            4097, 8, 0, /* 427: pointer.func */
            4097, 8, 0, /* 430: pointer.func */
            4097, 8, 0, /* 433: pointer.func */
            4097, 8, 0, /* 436: pointer.func */
            4097, 8, 0, /* 439: pointer.func */
            0, 8, 5, /* 442: union.unknown */
            	17, 0,
            	222, 0,
            	455, 0,
            	485, 0,
            	28, 0,
            1, 8, 1, /* 455: pointer.struct.dsa_st */
            	460, 0,
            0, 136, 11, /* 460: struct.dsa_st */
            	109, 24,
            	109, 32,
            	109, 40,
            	109, 48,
            	109, 56,
            	109, 64,
            	109, 72,
            	127, 88,
            	141, 104,
            	274, 120,
            	161, 128,
            1, 8, 1, /* 485: pointer.struct.dh_st */
            	82, 0,
            0, 1, 0, /* 490: char */
        },
        .arg_entity_index = { 340, },
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

