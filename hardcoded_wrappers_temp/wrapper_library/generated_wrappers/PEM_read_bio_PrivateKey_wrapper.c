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
            1, 8, 1, /* 0: pointer.pointer.struct.evp_pkey_st */
            	5, 0,
            1, 8, 1, /* 5: pointer.struct.evp_pkey_st */
            	10, 0,
            0, 56, 4, /* 10: struct.evp_pkey_st */
            	21, 16,
            	127, 24,
            	135, 32,
            	485, 48,
            1, 8, 1, /* 21: pointer.struct.evp_pkey_asn1_method_st */
            	26, 0,
            0, 208, 24, /* 26: struct.evp_pkey_asn1_method_st */
            	77, 16,
            	77, 24,
            	82, 32,
            	85, 40,
            	88, 48,
            	91, 56,
            	94, 64,
            	97, 72,
            	91, 80,
            	100, 88,
            	100, 96,
            	103, 104,
            	106, 112,
            	100, 120,
            	109, 128,
            	88, 136,
            	91, 144,
            	112, 152,
            	115, 160,
            	118, 168,
            	103, 176,
            	106, 184,
            	121, 192,
            	124, 200,
            1, 8, 1, /* 77: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 82: pointer.func */
            4097, 8, 0, /* 85: pointer.func */
            4097, 8, 0, /* 88: pointer.func */
            4097, 8, 0, /* 91: pointer.func */
            4097, 8, 0, /* 94: pointer.func */
            4097, 8, 0, /* 97: pointer.func */
            4097, 8, 0, /* 100: pointer.func */
            4097, 8, 0, /* 103: pointer.func */
            4097, 8, 0, /* 106: pointer.func */
            4097, 8, 0, /* 109: pointer.func */
            4097, 8, 0, /* 112: pointer.func */
            4097, 8, 0, /* 115: pointer.func */
            4097, 8, 0, /* 118: pointer.func */
            4097, 8, 0, /* 121: pointer.func */
            4097, 8, 0, /* 124: pointer.func */
            1, 8, 1, /* 127: pointer.struct.engine_st */
            	132, 0,
            0, 0, 0, /* 132: struct.engine_st */
            0, 8, 5, /* 135: union.unknown */
            	77, 0,
            	148, 0,
            	320, 0,
            	401, 0,
            	477, 0,
            1, 8, 1, /* 148: pointer.struct.rsa_st */
            	153, 0,
            0, 168, 17, /* 153: struct.rsa_st */
            	190, 16,
            	127, 24,
            	250, 32,
            	250, 40,
            	250, 48,
            	250, 56,
            	250, 64,
            	250, 72,
            	250, 80,
            	250, 88,
            	268, 96,
            	298, 120,
            	298, 128,
            	298, 136,
            	77, 144,
            	312, 152,
            	312, 160,
            1, 8, 1, /* 190: pointer.struct.rsa_meth_st */
            	195, 0,
            0, 112, 13, /* 195: struct.rsa_meth_st */
            	224, 0,
            	229, 8,
            	229, 16,
            	229, 24,
            	229, 32,
            	232, 40,
            	235, 48,
            	238, 56,
            	238, 64,
            	77, 80,
            	241, 88,
            	244, 96,
            	247, 104,
            1, 8, 1, /* 224: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 229: pointer.func */
            4097, 8, 0, /* 232: pointer.func */
            4097, 8, 0, /* 235: pointer.func */
            4097, 8, 0, /* 238: pointer.func */
            4097, 8, 0, /* 241: pointer.func */
            4097, 8, 0, /* 244: pointer.func */
            4097, 8, 0, /* 247: pointer.func */
            1, 8, 1, /* 250: pointer.struct.bignum_st */
            	255, 0,
            0, 24, 1, /* 255: struct.bignum_st */
            	260, 0,
            1, 8, 1, /* 260: pointer.unsigned int */
            	265, 0,
            0, 4, 0, /* 265: unsigned int */
            0, 16, 1, /* 268: struct.crypto_ex_data_st */
            	273, 0,
            1, 8, 1, /* 273: pointer.struct.stack_st_void */
            	278, 0,
            0, 32, 1, /* 278: struct.stack_st_void */
            	283, 0,
            0, 32, 2, /* 283: struct.stack_st */
            	290, 8,
            	295, 24,
            1, 8, 1, /* 290: pointer.pointer.char */
            	77, 0,
            4097, 8, 0, /* 295: pointer.func */
            1, 8, 1, /* 298: pointer.struct.bn_mont_ctx_st */
            	303, 0,
            0, 96, 3, /* 303: struct.bn_mont_ctx_st */
            	255, 8,
            	255, 32,
            	255, 56,
            1, 8, 1, /* 312: pointer.struct.bn_blinding_st */
            	317, 0,
            0, 0, 0, /* 317: struct.bn_blinding_st */
            1, 8, 1, /* 320: pointer.struct.dsa_st */
            	325, 0,
            0, 136, 11, /* 325: struct.dsa_st */
            	250, 24,
            	250, 32,
            	250, 40,
            	250, 48,
            	250, 56,
            	250, 64,
            	250, 72,
            	298, 88,
            	268, 104,
            	350, 120,
            	127, 128,
            1, 8, 1, /* 350: pointer.struct.dsa_method */
            	355, 0,
            0, 96, 11, /* 355: struct.dsa_method */
            	224, 0,
            	380, 8,
            	383, 16,
            	386, 24,
            	389, 32,
            	392, 40,
            	395, 48,
            	395, 56,
            	77, 72,
            	398, 80,
            	395, 88,
            4097, 8, 0, /* 380: pointer.func */
            4097, 8, 0, /* 383: pointer.func */
            4097, 8, 0, /* 386: pointer.func */
            4097, 8, 0, /* 389: pointer.func */
            4097, 8, 0, /* 392: pointer.func */
            4097, 8, 0, /* 395: pointer.func */
            4097, 8, 0, /* 398: pointer.func */
            1, 8, 1, /* 401: pointer.struct.dh_st */
            	406, 0,
            0, 144, 12, /* 406: struct.dh_st */
            	250, 8,
            	250, 16,
            	250, 32,
            	250, 40,
            	298, 56,
            	250, 64,
            	250, 72,
            	433, 80,
            	250, 96,
            	268, 112,
            	441, 128,
            	127, 136,
            1, 8, 1, /* 433: pointer.unsigned char */
            	438, 0,
            0, 1, 0, /* 438: unsigned char */
            1, 8, 1, /* 441: pointer.struct.dh_method */
            	446, 0,
            0, 72, 8, /* 446: struct.dh_method */
            	224, 0,
            	465, 8,
            	468, 16,
            	471, 24,
            	465, 32,
            	465, 40,
            	77, 56,
            	474, 64,
            4097, 8, 0, /* 465: pointer.func */
            4097, 8, 0, /* 468: pointer.func */
            4097, 8, 0, /* 471: pointer.func */
            4097, 8, 0, /* 474: pointer.func */
            1, 8, 1, /* 477: pointer.struct.ec_key_st */
            	482, 0,
            0, 0, 0, /* 482: struct.ec_key_st */
            1, 8, 1, /* 485: pointer.struct.stack_st_X509_ATTRIBUTE */
            	490, 0,
            0, 32, 1, /* 490: struct.stack_st_X509_ATTRIBUTE */
            	283, 0,
            4097, 8, 0, /* 495: pointer.func */
            1, 8, 1, /* 498: pointer.struct.bio_st */
            	503, 0,
            0, 112, 7, /* 503: struct.bio_st */
            	520, 0,
            	564, 8,
            	77, 16,
            	567, 48,
            	498, 56,
            	498, 64,
            	268, 96,
            1, 8, 1, /* 520: pointer.struct.bio_method_st */
            	525, 0,
            0, 80, 9, /* 525: struct.bio_method_st */
            	224, 8,
            	546, 16,
            	549, 24,
            	552, 32,
            	549, 40,
            	555, 48,
            	558, 56,
            	558, 64,
            	561, 72,
            4097, 8, 0, /* 546: pointer.func */
            4097, 8, 0, /* 549: pointer.func */
            4097, 8, 0, /* 552: pointer.func */
            4097, 8, 0, /* 555: pointer.func */
            4097, 8, 0, /* 558: pointer.func */
            4097, 8, 0, /* 561: pointer.func */
            4097, 8, 0, /* 564: pointer.func */
            0, 8, 0, /* 567: pointer.void */
            1, 8, 1, /* 570: pointer.struct.bio_st */
            	503, 0,
            0, 1, 0, /* 575: char */
        },
        .arg_entity_index = { 570, 0, 495, 567, },
        .ret_entity_index = 5,
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

