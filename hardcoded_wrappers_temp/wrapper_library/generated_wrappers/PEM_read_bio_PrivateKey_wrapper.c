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

EVP_PKEY * bb_PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d);

EVP_PKEY * PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d) 
{
    unsigned long in_lib = syscall(890);
    printf("PEM_read_bio_PrivateKey called %lu\n", in_lib);
    if (!in_lib)
        return bb_PEM_read_bio_PrivateKey(arg_a,arg_b,arg_c,arg_d);
    else {
        EVP_PKEY * (*orig_PEM_read_bio_PrivateKey)(BIO *,EVP_PKEY **,pem_password_cb *,void *);
        orig_PEM_read_bio_PrivateKey = dlsym(RTLD_NEXT, "PEM_read_bio_PrivateKey");
        return orig_PEM_read_bio_PrivateKey(arg_a,arg_b,arg_c,arg_d);
    }
}

EVP_PKEY * bb_PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d) 
{
    EVP_PKEY * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 8, 1, /* 0: struct.fnames */
            	5, 0,
            1, 8, 1, /* 5: pointer.char */
            	4096, 0,
            0, 32, 2, /* 10: struct.ENGINE_CMD_DEFN_st */
            	5, 8,
            	5, 16,
            4097, 8, 0, /* 17: pointer.func */
            4097, 8, 0, /* 20: pointer.func */
            4097, 8, 0, /* 23: pointer.func */
            4097, 8, 0, /* 26: pointer.func */
            4097, 8, 0, /* 29: pointer.func */
            4097, 8, 0, /* 32: pointer.func */
            4097, 8, 0, /* 35: pointer.func */
            0, 48, 6, /* 38: struct.rand_meth_st */
            	53, 0,
            	35, 8,
            	32, 16,
            	56, 24,
            	35, 32,
            	29, 40,
            4097, 8, 0, /* 53: pointer.func */
            4097, 8, 0, /* 56: pointer.func */
            1, 8, 1, /* 59: pointer.struct.rand_meth_st */
            	38, 0,
            4097, 8, 0, /* 64: pointer.func */
            4097, 8, 0, /* 67: pointer.func */
            0, 48, 5, /* 70: struct.ecdsa_method */
            	5, 0,
            	64, 8,
            	83, 16,
            	86, 24,
            	5, 40,
            4097, 8, 0, /* 83: pointer.func */
            4097, 8, 0, /* 86: pointer.func */
            1, 8, 1, /* 89: pointer.struct.ecdsa_method */
            	70, 0,
            4097, 8, 0, /* 94: pointer.func */
            0, 32, 3, /* 97: struct.ecdh_method */
            	5, 0,
            	94, 8,
            	5, 24,
            1, 8, 1, /* 106: pointer.struct.ecdh_method */
            	97, 0,
            4097, 8, 0, /* 111: pointer.func */
            0, 72, 8, /* 114: struct.dh_method */
            	5, 0,
            	133, 8,
            	136, 16,
            	111, 24,
            	133, 32,
            	133, 40,
            	5, 56,
            	139, 64,
            4097, 8, 0, /* 133: pointer.func */
            4097, 8, 0, /* 136: pointer.func */
            4097, 8, 0, /* 139: pointer.func */
            4097, 8, 0, /* 142: pointer.func */
            4097, 8, 0, /* 145: pointer.func */
            0, 112, 7, /* 148: struct.bio_st */
            	165, 0,
            	206, 8,
            	5, 16,
            	5, 48,
            	209, 56,
            	209, 64,
            	214, 96,
            1, 8, 1, /* 165: pointer.struct.bio_method_st */
            	170, 0,
            0, 80, 9, /* 170: struct.bio_method_st */
            	5, 8,
            	191, 16,
            	191, 24,
            	194, 32,
            	191, 40,
            	197, 48,
            	200, 56,
            	200, 64,
            	203, 72,
            4097, 8, 0, /* 191: pointer.func */
            4097, 8, 0, /* 194: pointer.func */
            4097, 8, 0, /* 197: pointer.func */
            4097, 8, 0, /* 200: pointer.func */
            4097, 8, 0, /* 203: pointer.func */
            4097, 8, 0, /* 206: pointer.func */
            1, 8, 1, /* 209: pointer.struct.bio_st */
            	148, 0,
            0, 16, 1, /* 214: struct.crypto_ex_data_st */
            	219, 0,
            1, 8, 1, /* 219: pointer.struct.stack_st_OPENSSL_STRING */
            	224, 0,
            0, 32, 1, /* 224: struct.stack_st_OPENSSL_STRING */
            	229, 0,
            0, 32, 2, /* 229: struct.stack_st */
            	236, 8,
            	241, 24,
            1, 8, 1, /* 236: pointer.pointer.char */
            	5, 0,
            4097, 8, 0, /* 241: pointer.func */
            4097, 8, 0, /* 244: pointer.func */
            4097, 8, 0, /* 247: pointer.func */
            0, 208, 24, /* 250: struct.evp_pkey_asn1_method_st */
            	5, 16,
            	5, 24,
            	301, 32,
            	244, 40,
            	304, 48,
            	145, 56,
            	142, 64,
            	307, 72,
            	145, 80,
            	310, 88,
            	310, 96,
            	313, 104,
            	316, 112,
            	310, 120,
            	304, 128,
            	304, 136,
            	145, 144,
            	319, 152,
            	322, 160,
            	325, 168,
            	313, 176,
            	316, 184,
            	328, 192,
            	331, 200,
            4097, 8, 0, /* 301: pointer.func */
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
            1, 8, 1, /* 334: pointer.struct.evp_pkey_asn1_method_st */
            	250, 0,
            4097, 8, 0, /* 339: pointer.func */
            0, 56, 4, /* 342: struct.evp_pkey_st */
            	334, 16,
            	353, 24,
            	0, 32,
            	219, 48,
            1, 8, 1, /* 353: pointer.struct.engine_st */
            	358, 0,
            0, 216, 24, /* 358: struct.engine_st */
            	5, 0,
            	5, 8,
            	409, 16,
            	464, 24,
            	512, 32,
            	106, 40,
            	89, 48,
            	59, 56,
            	517, 64,
            	67, 72,
            	525, 80,
            	528, 88,
            	531, 96,
            	26, 104,
            	26, 112,
            	26, 120,
            	23, 128,
            	20, 136,
            	20, 144,
            	17, 152,
            	534, 160,
            	214, 184,
            	353, 200,
            	353, 208,
            1, 8, 1, /* 409: pointer.struct.rsa_meth_st */
            	414, 0,
            0, 112, 13, /* 414: struct.rsa_meth_st */
            	5, 0,
            	443, 8,
            	443, 16,
            	443, 24,
            	443, 32,
            	446, 40,
            	449, 48,
            	452, 56,
            	452, 64,
            	5, 80,
            	455, 88,
            	458, 96,
            	461, 104,
            4097, 8, 0, /* 443: pointer.func */
            4097, 8, 0, /* 446: pointer.func */
            4097, 8, 0, /* 449: pointer.func */
            4097, 8, 0, /* 452: pointer.func */
            4097, 8, 0, /* 455: pointer.func */
            4097, 8, 0, /* 458: pointer.func */
            4097, 8, 0, /* 461: pointer.func */
            1, 8, 1, /* 464: pointer.struct.dsa_method */
            	469, 0,
            0, 96, 11, /* 469: struct.dsa_method */
            	5, 0,
            	494, 8,
            	497, 16,
            	500, 24,
            	503, 32,
            	506, 40,
            	247, 48,
            	247, 56,
            	5, 72,
            	509, 80,
            	247, 88,
            4097, 8, 0, /* 494: pointer.func */
            4097, 8, 0, /* 497: pointer.func */
            4097, 8, 0, /* 500: pointer.func */
            4097, 8, 0, /* 503: pointer.func */
            4097, 8, 0, /* 506: pointer.func */
            4097, 8, 0, /* 509: pointer.func */
            1, 8, 1, /* 512: pointer.struct.dh_method */
            	114, 0,
            1, 8, 1, /* 517: pointer.struct.store_method_st */
            	522, 0,
            0, 0, 0, /* 522: struct.store_method_st */
            4097, 8, 0, /* 525: pointer.func */
            4097, 8, 0, /* 528: pointer.func */
            4097, 8, 0, /* 531: pointer.func */
            1, 8, 1, /* 534: pointer.struct.ENGINE_CMD_DEFN_st */
            	10, 0,
            0, 1, 0, /* 539: char */
            1, 8, 1, /* 542: pointer.pointer.struct.evp_pkey_st */
            	547, 0,
            1, 8, 1, /* 547: pointer.struct.evp_pkey_st */
            	342, 0,
            0, 8, 0, /* 552: pointer.void */
        },
        .arg_entity_index = { 209, 542, 339, 552, },
        .ret_entity_index = 547,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    BIO * new_arg_a = *((BIO * *)new_args->args[0]);

    EVP_PKEY ** new_arg_b = *((EVP_PKEY ** *)new_args->args[1]);

    pem_password_cb * new_arg_c = *((pem_password_cb * *)new_args->args[2]);

    void * new_arg_d = *((void * *)new_args->args[3]);

    EVP_PKEY * *new_ret_ptr = (EVP_PKEY * *)new_args->ret;

    EVP_PKEY * (*orig_PEM_read_bio_PrivateKey)(BIO *,EVP_PKEY **,pem_password_cb *,void *);
    orig_PEM_read_bio_PrivateKey = dlsym(RTLD_NEXT, "PEM_read_bio_PrivateKey");
    *new_ret_ptr = (*orig_PEM_read_bio_PrivateKey)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    return ret;
}

