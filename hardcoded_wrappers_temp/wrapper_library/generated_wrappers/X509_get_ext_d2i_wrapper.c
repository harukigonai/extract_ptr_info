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

void * bb_X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d);

void * X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d) 
{
    printf("X509_get_ext_d2i called\n");
    if (!syscall(890))
        return bb_X509_get_ext_d2i(arg_a,arg_b,arg_c,arg_d);
    else {
        void * (*orig_X509_get_ext_d2i)(X509 *,int,int *,int *);
        orig_X509_get_ext_d2i = dlsym(RTLD_NEXT, "X509_get_ext_d2i");
        return orig_X509_get_ext_d2i(arg_a,arg_b,arg_c,arg_d);
    }
}

void * bb_X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d) 
{
    void * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 40, 5, /* 0: struct.x509_cert_aux_st */
            	13, 0,
            	13, 8,
            	41, 16,
            	41, 24,
            	13, 32,
            1, 8, 1, /* 13: pointer.struct.stack_st_OPENSSL_STRING */
            	18, 0,
            0, 32, 1, /* 18: struct.stack_st_OPENSSL_STRING */
            	23, 0,
            0, 32, 1, /* 23: struct.stack_st */
            	28, 8,
            1, 8, 1, /* 28: pointer.pointer.char */
            	33, 0,
            1, 8, 1, /* 33: pointer.char */
            	38, 0,
            0, 1, 0, /* 38: char */
            1, 8, 1, /* 41: pointer.struct.asn1_string_st */
            	46, 0,
            0, 24, 1, /* 46: struct.asn1_string_st */
            	33, 8,
            1, 8, 1, /* 51: pointer.struct.x509_cert_aux_st */
            	0, 0,
            0, 16, 2, /* 56: struct.NAME_CONSTRAINTS_st */
            	13, 0,
            	13, 8,
            1, 8, 1, /* 63: pointer.struct.NAME_CONSTRAINTS_st */
            	56, 0,
            0, 32, 3, /* 68: struct.X509_POLICY_DATA_st */
            	77, 8,
            	13, 16,
            	13, 24,
            1, 8, 1, /* 77: pointer.struct.asn1_object_st */
            	82, 0,
            0, 40, 3, /* 82: struct.asn1_object_st */
            	33, 0,
            	33, 8,
            	33, 24,
            1, 8, 1, /* 91: pointer.struct.X509_POLICY_DATA_st */
            	68, 0,
            1, 8, 1, /* 96: pointer.struct.X509_POLICY_CACHE_st */
            	101, 0,
            0, 40, 2, /* 101: struct.X509_POLICY_CACHE_st */
            	91, 0,
            	13, 8,
            1, 8, 1, /* 108: pointer.struct.AUTHORITY_KEYID_st */
            	113, 0,
            0, 24, 3, /* 113: struct.AUTHORITY_KEYID_st */
            	41, 0,
            	13, 8,
            	41, 16,
            0, 8, 0, /* 122: pointer.func */
            0, 0, 0, /* 125: func */
            0, 8, 0, /* 128: pointer.func */
            0, 0, 0, /* 131: func */
            0, 0, 0, /* 134: func */
            0, 8, 0, /* 137: pointer.func */
            0, 0, 0, /* 140: func */
            0, 8, 0, /* 143: pointer.func */
            0, 0, 0, /* 146: func */
            0, 8, 0, /* 149: pointer.func */
            0, 0, 0, /* 152: func */
            0, 8, 0, /* 155: pointer.func */
            0, 8, 0, /* 158: pointer.func */
            0, 0, 0, /* 161: struct.store_method_st */
            1, 8, 1, /* 164: pointer.struct.store_method_st */
            	161, 0,
            0, 0, 0, /* 169: func */
            1, 8, 1, /* 172: pointer.struct.ENGINE_CMD_DEFN_st */
            	177, 0,
            0, 32, 2, /* 177: struct.ENGINE_CMD_DEFN_st */
            	33, 8,
            	33, 16,
            0, 8, 0, /* 184: pointer.func */
            0, 0, 0, /* 187: func */
            0, 8, 0, /* 190: pointer.func */
            0, 0, 0, /* 193: func */
            0, 0, 0, /* 196: func */
            0, 0, 0, /* 199: func */
            0, 8, 0, /* 202: pointer.func */
            0, 56, 4, /* 205: struct.evp_pkey_st */
            	216, 16,
            	238, 24,
            	345, 32,
            	13, 48,
            1, 8, 1, /* 216: pointer.struct.evp_pkey_asn1_method_st */
            	221, 0,
            0, 208, 3, /* 221: struct.evp_pkey_asn1_method_st */
            	33, 16,
            	33, 24,
            	230, 32,
            1, 8, 1, /* 230: pointer.struct.unnamed */
            	235, 0,
            0, 0, 0, /* 235: struct.unnamed */
            1, 8, 1, /* 238: pointer.struct.engine_st */
            	243, 0,
            0, 216, 13, /* 243: struct.engine_st */
            	33, 0,
            	33, 8,
            	272, 16,
            	284, 24,
            	296, 32,
            	308, 40,
            	320, 48,
            	332, 56,
            	164, 64,
            	172, 160,
            	340, 184,
            	238, 200,
            	238, 208,
            1, 8, 1, /* 272: pointer.struct.rsa_meth_st */
            	277, 0,
            0, 112, 2, /* 277: struct.rsa_meth_st */
            	33, 0,
            	33, 80,
            1, 8, 1, /* 284: pointer.struct.dsa_method.1040 */
            	289, 0,
            0, 96, 2, /* 289: struct.dsa_method.1040 */
            	33, 0,
            	33, 72,
            1, 8, 1, /* 296: pointer.struct.dh_method */
            	301, 0,
            0, 72, 2, /* 301: struct.dh_method */
            	33, 0,
            	33, 56,
            1, 8, 1, /* 308: pointer.struct.ecdh_method */
            	313, 0,
            0, 32, 2, /* 313: struct.ecdh_method */
            	33, 0,
            	33, 24,
            1, 8, 1, /* 320: pointer.struct.ecdsa_method */
            	325, 0,
            0, 48, 2, /* 325: struct.ecdsa_method */
            	33, 0,
            	33, 40,
            1, 8, 1, /* 332: pointer.struct.rand_meth_st */
            	337, 0,
            0, 48, 0, /* 337: struct.rand_meth_st */
            0, 16, 1, /* 340: struct.crypto_ex_data_st */
            	13, 0,
            0, 8, 1, /* 345: struct.fnames */
            	33, 0,
            0, 8, 0, /* 350: pointer.func */
            0, 0, 0, /* 353: func */
            1, 8, 1, /* 356: pointer.struct.x509_st */
            	361, 0,
            0, 184, 12, /* 361: struct.x509_st */
            	388, 0,
            	418, 8,
            	41, 16,
            	33, 32,
            	340, 40,
            	41, 104,
            	108, 112,
            	96, 120,
            	13, 128,
            	13, 136,
            	63, 144,
            	51, 176,
            1, 8, 1, /* 388: pointer.struct.x509_cinf_st */
            	393, 0,
            0, 104, 11, /* 393: struct.x509_cinf_st */
            	41, 0,
            	41, 8,
            	418, 16,
            	440, 24,
            	464, 32,
            	440, 40,
            	476, 48,
            	41, 56,
            	41, 64,
            	13, 72,
            	495, 80,
            1, 8, 1, /* 418: pointer.struct.X509_algor_st */
            	423, 0,
            0, 16, 2, /* 423: struct.X509_algor_st */
            	77, 0,
            	430, 8,
            1, 8, 1, /* 430: pointer.struct.asn1_type_st */
            	435, 0,
            0, 16, 1, /* 435: struct.asn1_type_st */
            	345, 8,
            1, 8, 1, /* 440: pointer.struct.X509_name_st */
            	445, 0,
            0, 40, 3, /* 445: struct.X509_name_st */
            	13, 0,
            	454, 16,
            	33, 24,
            1, 8, 1, /* 454: pointer.struct.buf_mem_st */
            	459, 0,
            0, 24, 1, /* 459: struct.buf_mem_st */
            	33, 8,
            1, 8, 1, /* 464: pointer.struct.X509_val_st */
            	469, 0,
            0, 16, 2, /* 469: struct.X509_val_st */
            	41, 0,
            	41, 8,
            1, 8, 1, /* 476: pointer.struct.X509_pubkey_st */
            	481, 0,
            0, 24, 3, /* 481: struct.X509_pubkey_st */
            	418, 0,
            	41, 8,
            	490, 16,
            1, 8, 1, /* 490: pointer.struct.evp_pkey_st */
            	205, 0,
            0, 24, 1, /* 495: struct.ASN1_ENCODING_st */
            	33, 0,
            0, 8, 0, /* 500: pointer.func */
            0, 0, 0, /* 503: func */
            0, 8, 0, /* 506: pointer.func */
            0, 8, 0, /* 509: pointer.func */
            0, 8, 0, /* 512: pointer.func */
            0, 0, 0, /* 515: func */
            0, 0, 0, /* 518: func */
            0, 8, 0, /* 521: pointer.func */
            0, 0, 0, /* 524: func */
            0, 4, 0, /* 527: int */
            0, 8, 0, /* 530: pointer.func */
            0, 0, 0, /* 533: func */
            0, 20, 0, /* 536: array[20].char */
            0, 0, 0, /* 539: func */
            0, 0, 0, /* 542: func */
            0, 8, 0, /* 545: long */
            0, 8, 0, /* 548: pointer.func */
            0, 8, 0, /* 551: pointer.func */
            0, 8, 0, /* 554: pointer.func */
            0, 8, 0, /* 557: pointer.func */
            0, 0, 0, /* 560: func */
            0, 0, 0, /* 563: func */
            0, 8, 0, /* 566: pointer.func */
            0, 8, 0, /* 569: pointer.func */
            0, 8, 0, /* 572: pointer.func */
            0, 0, 0, /* 575: func */
            0, 8, 0, /* 578: pointer.func */
            0, 8, 0, /* 581: pointer.func */
            0, 8, 0, /* 584: pointer.func */
            0, 8, 0, /* 587: pointer.func */
            0, 0, 0, /* 590: func */
            0, 0, 0, /* 593: func */
            0, 0, 0, /* 596: func */
            0, 0, 0, /* 599: func */
            0, 0, 0, /* 602: func */
            0, 8, 0, /* 605: pointer.func */
            0, 0, 0, /* 608: func */
            0, 8, 0, /* 611: pointer.func */
            0, 8, 0, /* 614: pointer.func */
            0, 0, 0, /* 617: func */
            0, 0, 0, /* 620: func */
            0, 8, 0, /* 623: pointer.func */
            0, 0, 0, /* 626: func */
            0, 0, 0, /* 629: func */
            0, 8, 0, /* 632: pointer.func */
            0, 0, 0, /* 635: func */
            0, 8, 0, /* 638: pointer.func */
            0, 0, 0, /* 641: func */
            0, 8, 0, /* 644: pointer.func */
            0, 0, 0, /* 647: func */
            0, 8, 0, /* 650: pointer.func */
            0, 0, 0, /* 653: func */
            0, 8, 0, /* 656: pointer.func */
            0, 8, 0, /* 659: pointer.func */
            0, 8, 0, /* 662: pointer.func */
            0, 8, 0, /* 665: pointer.func */
            0, 0, 0, /* 668: func */
            0, 8, 0, /* 671: pointer.func */
            0, 0, 0, /* 674: func */
            0, 8, 0, /* 677: pointer.func */
            0, 0, 0, /* 680: func */
            0, 0, 0, /* 683: func */
            0, 8, 0, /* 686: pointer.func */
            0, 0, 0, /* 689: func */
            1, 8, 1, /* 692: pointer.int */
            	527, 0,
            0, 8, 0, /* 697: pointer.func */
            0, 8, 0, /* 700: pointer.func */
            0, 8, 0, /* 703: pointer.func */
            0, 0, 0, /* 706: func */
            0, 8, 0, /* 709: pointer.func */
            0, 0, 0, /* 712: func */
            0, 8, 0, /* 715: pointer.func */
            0, 0, 0, /* 718: func */
            0, 0, 0, /* 721: func */
            0, 8, 0, /* 724: pointer.func */
            0, 0, 0, /* 727: func */
            0, 0, 0, /* 730: func */
            0, 0, 0, /* 733: func */
            0, 0, 0, /* 736: func */
        },
        .arg_entity_index = { 356, 527, 692, 692, },
        .ret_entity_index = 33,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    int new_arg_b = *((int *)new_args->args[1]);

    int * new_arg_c = *((int * *)new_args->args[2]);

    int * new_arg_d = *((int * *)new_args->args[3]);

    void * *new_ret_ptr = (void * *)new_args->ret;

    void * (*orig_X509_get_ext_d2i)(X509 *,int,int *,int *);
    orig_X509_get_ext_d2i = dlsym(RTLD_NEXT, "X509_get_ext_d2i");
    *new_ret_ptr = (*orig_X509_get_ext_d2i)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    return ret;
}

