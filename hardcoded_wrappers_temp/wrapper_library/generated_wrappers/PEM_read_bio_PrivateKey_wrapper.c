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
            4097, 8, 0, /* 0: pointer.func */
            0, 0, 0, /* 3: func */
            4097, 8, 0, /* 6: pointer.func */
            0, 0, 0, /* 9: func */
            4097, 8, 0, /* 12: pointer.func */
            0, 0, 0, /* 15: func */
            4097, 8, 0, /* 18: pointer.func */
            4097, 8, 0, /* 21: pointer.func */
            0, 112, 7, /* 24: struct.bio_st */
            	41, 0,
            	0, 8,
            	67, 16,
            	75, 48,
            	78, 56,
            	78, 64,
            	83, 96,
            0, 8, 1, /* 41: pointer.struct.bio_method_st */
            	46, 0,
            0, 80, 9, /* 46: struct.bio_method_st */
            	67, 8,
            	72, 16,
            	72, 24,
            	21, 32,
            	72, 40,
            	18, 48,
            	12, 56,
            	12, 64,
            	6, 72,
            0, 8, 1, /* 67: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 72: pointer.func */
            0, 8, 0, /* 75: pointer.void */
            0, 8, 1, /* 78: pointer.struct.bio_st */
            	24, 0,
            0, 16, 1, /* 83: struct.crypto_ex_data_st */
            	88, 0,
            0, 8, 1, /* 88: pointer.struct.stack_st_OPENSSL_STRING */
            	93, 0,
            0, 32, 1, /* 93: struct.stack_st_OPENSSL_STRING */
            	98, 0,
            0, 32, 2, /* 98: struct.stack_st */
            	105, 8,
            	110, 24,
            0, 8, 1, /* 105: pointer.pointer.char */
            	67, 0,
            4097, 8, 0, /* 110: pointer.func */
            0, 8, 1, /* 113: struct.fnames */
            	67, 0,
            0, 0, 0, /* 118: func */
            0, 8, 1, /* 121: pointer.struct.ENGINE_CMD_DEFN_st */
            	126, 0,
            0, 32, 2, /* 126: struct.ENGINE_CMD_DEFN_st */
            	67, 8,
            	67, 16,
            0, 8, 1, /* 133: pointer.struct.evp_pkey_st */
            	138, 0,
            0, 56, 4, /* 138: struct.evp_pkey_st */
            	149, 16,
            	247, 24,
            	113, 32,
            	88, 48,
            0, 8, 1, /* 149: pointer.struct.evp_pkey_asn1_method_st */
            	154, 0,
            0, 208, 24, /* 154: struct.evp_pkey_asn1_method_st */
            	67, 16,
            	67, 24,
            	205, 32,
            	208, 40,
            	211, 48,
            	214, 56,
            	217, 64,
            	220, 72,
            	214, 80,
            	223, 88,
            	223, 96,
            	226, 104,
            	229, 112,
            	223, 120,
            	211, 128,
            	211, 136,
            	214, 144,
            	232, 152,
            	235, 160,
            	238, 168,
            	226, 176,
            	229, 184,
            	241, 192,
            	244, 200,
            4097, 8, 0, /* 205: pointer.func */
            4097, 8, 0, /* 208: pointer.func */
            4097, 8, 0, /* 211: pointer.func */
            4097, 8, 0, /* 214: pointer.func */
            4097, 8, 0, /* 217: pointer.func */
            4097, 8, 0, /* 220: pointer.func */
            4097, 8, 0, /* 223: pointer.func */
            4097, 8, 0, /* 226: pointer.func */
            4097, 8, 0, /* 229: pointer.func */
            4097, 8, 0, /* 232: pointer.func */
            4097, 8, 0, /* 235: pointer.func */
            4097, 8, 0, /* 238: pointer.func */
            4097, 8, 0, /* 241: pointer.func */
            4097, 8, 0, /* 244: pointer.func */
            0, 8, 1, /* 247: pointer.struct.engine_st */
            	252, 0,
            0, 216, 24, /* 252: struct.engine_st */
            	67, 0,
            	67, 8,
            	303, 16,
            	358, 24,
            	409, 32,
            	445, 40,
            	462, 48,
            	489, 56,
            	524, 64,
            	532, 72,
            	535, 80,
            	538, 88,
            	541, 96,
            	544, 104,
            	544, 112,
            	544, 120,
            	547, 128,
            	550, 136,
            	550, 144,
            	553, 152,
            	121, 160,
            	83, 184,
            	247, 200,
            	247, 208,
            0, 8, 1, /* 303: pointer.struct.rsa_meth_st */
            	308, 0,
            0, 112, 13, /* 308: struct.rsa_meth_st */
            	67, 0,
            	337, 8,
            	337, 16,
            	337, 24,
            	337, 32,
            	340, 40,
            	343, 48,
            	346, 56,
            	346, 64,
            	67, 80,
            	349, 88,
            	352, 96,
            	355, 104,
            4097, 8, 0, /* 337: pointer.func */
            4097, 8, 0, /* 340: pointer.func */
            4097, 8, 0, /* 343: pointer.func */
            4097, 8, 0, /* 346: pointer.func */
            4097, 8, 0, /* 349: pointer.func */
            4097, 8, 0, /* 352: pointer.func */
            4097, 8, 0, /* 355: pointer.func */
            0, 8, 1, /* 358: pointer.struct.dsa_method */
            	363, 0,
            0, 96, 11, /* 363: struct.dsa_method */
            	67, 0,
            	388, 8,
            	391, 16,
            	394, 24,
            	397, 32,
            	400, 40,
            	403, 48,
            	403, 56,
            	67, 72,
            	406, 80,
            	403, 88,
            4097, 8, 0, /* 388: pointer.func */
            4097, 8, 0, /* 391: pointer.func */
            4097, 8, 0, /* 394: pointer.func */
            4097, 8, 0, /* 397: pointer.func */
            4097, 8, 0, /* 400: pointer.func */
            4097, 8, 0, /* 403: pointer.func */
            4097, 8, 0, /* 406: pointer.func */
            0, 8, 1, /* 409: pointer.struct.dh_method */
            	414, 0,
            0, 72, 8, /* 414: struct.dh_method */
            	67, 0,
            	433, 8,
            	436, 16,
            	439, 24,
            	433, 32,
            	433, 40,
            	67, 56,
            	442, 64,
            4097, 8, 0, /* 433: pointer.func */
            4097, 8, 0, /* 436: pointer.func */
            4097, 8, 0, /* 439: pointer.func */
            4097, 8, 0, /* 442: pointer.func */
            0, 8, 1, /* 445: pointer.struct.ecdh_method */
            	450, 0,
            0, 32, 3, /* 450: struct.ecdh_method */
            	67, 0,
            	459, 8,
            	67, 24,
            4097, 8, 0, /* 459: pointer.func */
            0, 8, 1, /* 462: pointer.struct.ecdsa_method */
            	467, 0,
            0, 48, 5, /* 467: struct.ecdsa_method */
            	67, 0,
            	480, 8,
            	483, 16,
            	486, 24,
            	67, 40,
            4097, 8, 0, /* 480: pointer.func */
            4097, 8, 0, /* 483: pointer.func */
            4097, 8, 0, /* 486: pointer.func */
            0, 8, 1, /* 489: pointer.struct.rand_meth_st */
            	494, 0,
            0, 48, 6, /* 494: struct.rand_meth_st */
            	509, 0,
            	512, 8,
            	515, 16,
            	518, 24,
            	512, 32,
            	521, 40,
            4097, 8, 0, /* 509: pointer.func */
            4097, 8, 0, /* 512: pointer.func */
            4097, 8, 0, /* 515: pointer.func */
            4097, 8, 0, /* 518: pointer.func */
            4097, 8, 0, /* 521: pointer.func */
            0, 8, 1, /* 524: pointer.struct.store_method_st */
            	529, 0,
            0, 0, 0, /* 529: struct.store_method_st */
            4097, 8, 0, /* 532: pointer.func */
            4097, 8, 0, /* 535: pointer.func */
            4097, 8, 0, /* 538: pointer.func */
            4097, 8, 0, /* 541: pointer.func */
            4097, 8, 0, /* 544: pointer.func */
            4097, 8, 0, /* 547: pointer.func */
            4097, 8, 0, /* 550: pointer.func */
            4097, 8, 0, /* 553: pointer.func */
            0, 0, 0, /* 556: func */
            0, 0, 0, /* 559: func */
            0, 0, 0, /* 562: func */
            0, 0, 0, /* 565: func */
            0, 0, 0, /* 568: func */
            0, 0, 0, /* 571: func */
            0, 0, 0, /* 574: func */
            0, 0, 0, /* 577: func */
            0, 0, 0, /* 580: func */
            0, 0, 0, /* 583: func */
            0, 0, 0, /* 586: func */
            0, 0, 0, /* 589: func */
            0, 0, 0, /* 592: func */
            0, 0, 0, /* 595: func */
            0, 8, 0, /* 598: long */
            0, 0, 0, /* 601: func */
            0, 0, 0, /* 604: func */
            0, 0, 0, /* 607: func */
            0, 0, 0, /* 610: func */
            0, 0, 0, /* 613: func */
            0, 4, 0, /* 616: int */
            0, 0, 0, /* 619: func */
            0, 0, 0, /* 622: func */
            0, 0, 0, /* 625: func */
            0, 0, 0, /* 628: func */
            0, 0, 0, /* 631: func */
            0, 0, 0, /* 634: func */
            0, 0, 0, /* 637: func */
            0, 1, 0, /* 640: char */
            0, 0, 0, /* 643: func */
            0, 0, 0, /* 646: func */
            0, 0, 0, /* 649: func */
            0, 0, 0, /* 652: func */
            0, 0, 0, /* 655: func */
            0, 0, 0, /* 658: func */
            0, 0, 0, /* 661: func */
            0, 0, 0, /* 664: func */
            0, 0, 0, /* 667: func */
            0, 0, 0, /* 670: func */
            0, 0, 0, /* 673: func */
            0, 0, 0, /* 676: func */
            0, 0, 0, /* 679: func */
            0, 0, 0, /* 682: func */
            0, 0, 0, /* 685: func */
            0, 8, 1, /* 688: pointer.pointer.struct.evp_pkey_st */
            	133, 0,
            0, 0, 0, /* 693: func */
            0, 0, 0, /* 696: func */
            0, 0, 0, /* 699: func */
            4097, 8, 0, /* 702: pointer.func */
            0, 0, 0, /* 705: func */
            0, 0, 0, /* 708: func */
            0, 0, 0, /* 711: func */
            0, 0, 0, /* 714: func */
            0, 0, 0, /* 717: func */
            0, 0, 0, /* 720: func */
            0, 0, 0, /* 723: func */
            0, 0, 0, /* 726: func */
            0, 0, 0, /* 729: func */
        },
        .arg_entity_index = { 78, 688, 702, 75, },
        .ret_entity_index = 133,
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

