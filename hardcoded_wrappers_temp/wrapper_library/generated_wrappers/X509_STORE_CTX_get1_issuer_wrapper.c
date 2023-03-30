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

int bb_X509_STORE_CTX_get1_issuer(X509 ** arg_a,X509_STORE_CTX * arg_b,X509 * arg_c);

int X509_STORE_CTX_get1_issuer(X509 ** arg_a,X509_STORE_CTX * arg_b,X509 * arg_c) 
{
    printf("X509_STORE_CTX_get1_issuer called\n");
    if (!syscall(890))
        return bb_X509_STORE_CTX_get1_issuer(arg_a,arg_b,arg_c);
    else {
        int (*orig_X509_STORE_CTX_get1_issuer)(X509 **,X509_STORE_CTX *,X509 *);
        orig_X509_STORE_CTX_get1_issuer = dlsym(RTLD_NEXT, "X509_STORE_CTX_get1_issuer");
        return orig_X509_STORE_CTX_get1_issuer(arg_a,arg_b,arg_c);
    }
}

int bb_X509_STORE_CTX_get1_issuer(X509 ** arg_a,X509_STORE_CTX * arg_b,X509 * arg_c) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            0, 0, 0, /* 3: func */
            1, 8, 1, /* 6: pointer.struct.x509_crl_method_st */
            	11, 0,
            0, 40, 0, /* 11: struct.x509_crl_method_st */
            0, 8, 1, /* 14: union.anon.1.3070 */
            	19, 0,
            1, 8, 1, /* 19: pointer.struct.stack_st_OPENSSL_STRING */
            	24, 0,
            0, 32, 1, /* 24: struct.stack_st_OPENSSL_STRING */
            	29, 0,
            0, 32, 1, /* 29: struct.stack_st */
            	34, 8,
            1, 8, 1, /* 34: pointer.pointer.char */
            	39, 0,
            1, 8, 1, /* 39: pointer.char */
            	44, 0,
            0, 1, 0, /* 44: char */
            0, 24, 2, /* 47: struct.DIST_POINT_NAME_st */
            	14, 8,
            	54, 16,
            1, 8, 1, /* 54: pointer.struct.X509_name_st */
            	59, 0,
            0, 40, 3, /* 59: struct.X509_name_st */
            	19, 0,
            	68, 16,
            	39, 24,
            1, 8, 1, /* 68: pointer.struct.buf_mem_st */
            	73, 0,
            0, 24, 1, /* 73: struct.buf_mem_st */
            	39, 8,
            1, 8, 1, /* 78: pointer.struct.DIST_POINT_NAME_st */
            	47, 0,
            0, 32, 2, /* 83: struct.ISSUING_DIST_POINT_st */
            	78, 0,
            	90, 16,
            1, 8, 1, /* 90: pointer.struct.asn1_string_st */
            	95, 0,
            0, 24, 1, /* 95: struct.asn1_string_st */
            	39, 8,
            0, 80, 8, /* 100: struct.X509_crl_info_st */
            	90, 0,
            	119, 8,
            	54, 16,
            	90, 24,
            	90, 32,
            	19, 40,
            	19, 48,
            	160, 56,
            1, 8, 1, /* 119: pointer.struct.X509_algor_st */
            	124, 0,
            0, 16, 2, /* 124: struct.X509_algor_st */
            	131, 0,
            	145, 8,
            1, 8, 1, /* 131: pointer.struct.asn1_object_st */
            	136, 0,
            0, 40, 3, /* 136: struct.asn1_object_st */
            	39, 0,
            	39, 8,
            	39, 24,
            1, 8, 1, /* 145: pointer.struct.asn1_type_st */
            	150, 0,
            0, 16, 1, /* 150: struct.asn1_type_st */
            	155, 8,
            0, 8, 1, /* 155: struct.fnames */
            	39, 0,
            0, 24, 1, /* 160: struct.ASN1_ENCODING_st */
            	39, 0,
            1, 8, 1, /* 165: pointer.struct.X509_crl_info_st */
            	100, 0,
            0, 24, 2, /* 170: struct.X509_POLICY_NODE_st */
            	177, 0,
            	191, 8,
            1, 8, 1, /* 177: pointer.struct.X509_POLICY_DATA_st */
            	182, 0,
            0, 32, 3, /* 182: struct.X509_POLICY_DATA_st */
            	131, 8,
            	19, 16,
            	19, 24,
            1, 8, 1, /* 191: pointer.struct.X509_POLICY_NODE_st */
            	170, 0,
            0, 48, 4, /* 196: struct.X509_POLICY_TREE_st */
            	207, 0,
            	19, 16,
            	19, 24,
            	19, 32,
            1, 8, 1, /* 207: pointer.struct.X509_POLICY_LEVEL_st */
            	212, 0,
            0, 32, 3, /* 212: struct.X509_POLICY_LEVEL_st */
            	221, 0,
            	19, 8,
            	191, 16,
            1, 8, 1, /* 221: pointer.struct.x509_st */
            	226, 0,
            0, 184, 12, /* 226: struct.x509_st */
            	253, 0,
            	119, 8,
            	90, 16,
            	39, 32,
            	469, 40,
            	90, 104,
            	474, 112,
            	488, 120,
            	19, 128,
            	19, 136,
            	500, 144,
            	512, 176,
            1, 8, 1, /* 253: pointer.struct.x509_cinf_st */
            	258, 0,
            0, 104, 11, /* 258: struct.x509_cinf_st */
            	90, 0,
            	90, 8,
            	119, 16,
            	54, 24,
            	283, 32,
            	54, 40,
            	295, 48,
            	90, 56,
            	90, 64,
            	19, 72,
            	160, 80,
            1, 8, 1, /* 283: pointer.struct.X509_val_st */
            	288, 0,
            0, 16, 2, /* 288: struct.X509_val_st */
            	90, 0,
            	90, 8,
            1, 8, 1, /* 295: pointer.struct.X509_pubkey_st */
            	300, 0,
            0, 24, 3, /* 300: struct.X509_pubkey_st */
            	119, 0,
            	90, 8,
            	309, 16,
            1, 8, 1, /* 309: pointer.struct.evp_pkey_st */
            	314, 0,
            0, 56, 4, /* 314: struct.evp_pkey_st */
            	325, 16,
            	347, 24,
            	155, 32,
            	19, 48,
            1, 8, 1, /* 325: pointer.struct.evp_pkey_asn1_method_st */
            	330, 0,
            0, 208, 3, /* 330: struct.evp_pkey_asn1_method_st */
            	39, 16,
            	39, 24,
            	339, 32,
            1, 8, 1, /* 339: pointer.struct.unnamed */
            	344, 0,
            0, 0, 0, /* 344: struct.unnamed */
            1, 8, 1, /* 347: pointer.struct.engine_st */
            	352, 0,
            0, 216, 13, /* 352: struct.engine_st */
            	39, 0,
            	39, 8,
            	381, 16,
            	393, 24,
            	405, 32,
            	417, 40,
            	429, 48,
            	441, 56,
            	449, 64,
            	457, 160,
            	469, 184,
            	347, 200,
            	347, 208,
            1, 8, 1, /* 381: pointer.struct.rsa_meth_st */
            	386, 0,
            0, 112, 2, /* 386: struct.rsa_meth_st */
            	39, 0,
            	39, 80,
            1, 8, 1, /* 393: pointer.struct.dsa_method.1040 */
            	398, 0,
            0, 96, 2, /* 398: struct.dsa_method.1040 */
            	39, 0,
            	39, 72,
            1, 8, 1, /* 405: pointer.struct.dh_method */
            	410, 0,
            0, 72, 2, /* 410: struct.dh_method */
            	39, 0,
            	39, 56,
            1, 8, 1, /* 417: pointer.struct.ecdh_method */
            	422, 0,
            0, 32, 2, /* 422: struct.ecdh_method */
            	39, 0,
            	39, 24,
            1, 8, 1, /* 429: pointer.struct.ecdsa_method */
            	434, 0,
            0, 48, 2, /* 434: struct.ecdsa_method */
            	39, 0,
            	39, 40,
            1, 8, 1, /* 441: pointer.struct.rand_meth_st */
            	446, 0,
            0, 48, 0, /* 446: struct.rand_meth_st */
            1, 8, 1, /* 449: pointer.struct.store_method_st */
            	454, 0,
            0, 0, 0, /* 454: struct.store_method_st */
            1, 8, 1, /* 457: pointer.struct.ENGINE_CMD_DEFN_st */
            	462, 0,
            0, 32, 2, /* 462: struct.ENGINE_CMD_DEFN_st */
            	39, 8,
            	39, 16,
            0, 16, 1, /* 469: struct.crypto_ex_data_st */
            	19, 0,
            1, 8, 1, /* 474: pointer.struct.AUTHORITY_KEYID_st */
            	479, 0,
            0, 24, 3, /* 479: struct.AUTHORITY_KEYID_st */
            	90, 0,
            	19, 8,
            	90, 16,
            1, 8, 1, /* 488: pointer.struct.X509_POLICY_CACHE_st */
            	493, 0,
            0, 40, 2, /* 493: struct.X509_POLICY_CACHE_st */
            	177, 0,
            	19, 8,
            1, 8, 1, /* 500: pointer.struct.NAME_CONSTRAINTS_st */
            	505, 0,
            0, 16, 2, /* 505: struct.NAME_CONSTRAINTS_st */
            	19, 0,
            	19, 8,
            1, 8, 1, /* 512: pointer.struct.x509_cert_aux_st */
            	517, 0,
            0, 40, 5, /* 517: struct.x509_cert_aux_st */
            	19, 0,
            	19, 8,
            	90, 16,
            	90, 24,
            	19, 32,
            1, 8, 1, /* 530: pointer.struct.X509_POLICY_TREE_st */
            	196, 0,
            0, 0, 0, /* 535: func */
            0, 8, 0, /* 538: pointer.func */
            0, 0, 0, /* 541: func */
            0, 56, 2, /* 544: struct.X509_VERIFY_PARAM_st */
            	39, 0,
            	19, 48,
            1, 8, 1, /* 551: pointer.struct.X509_VERIFY_PARAM_st */
            	544, 0,
            0, 144, 4, /* 556: struct.x509_store_st */
            	19, 8,
            	19, 16,
            	551, 24,
            	469, 120,
            1, 8, 1, /* 567: pointer.struct.x509_store_st */
            	556, 0,
            0, 248, 17, /* 572: struct.x509_store_ctx_st */
            	567, 0,
            	221, 16,
            	19, 24,
            	19, 32,
            	551, 40,
            	39, 48,
            	339, 56,
            	339, 88,
            	339, 120,
            	339, 144,
            	19, 160,
            	530, 168,
            	221, 192,
            	221, 200,
            	609, 208,
            	642, 224,
            	469, 232,
            1, 8, 1, /* 609: pointer.struct.X509_crl_st */
            	614, 0,
            0, 120, 10, /* 614: struct.X509_crl_st */
            	165, 0,
            	119, 8,
            	90, 16,
            	474, 32,
            	637, 40,
            	90, 56,
            	90, 64,
            	19, 96,
            	6, 104,
            	39, 112,
            1, 8, 1, /* 637: pointer.struct.ISSUING_DIST_POINT_st */
            	83, 0,
            1, 8, 1, /* 642: pointer.struct.x509_store_ctx_st */
            	572, 0,
            0, 8, 0, /* 647: pointer.func */
            0, 0, 0, /* 650: func */
            0, 8, 0, /* 653: pointer.func */
            0, 0, 0, /* 656: func */
            0, 0, 0, /* 659: func */
            0, 8, 0, /* 662: pointer.func */
            0, 0, 0, /* 665: func */
            0, 0, 0, /* 668: func */
            0, 8, 0, /* 671: pointer.func */
            0, 0, 0, /* 674: func */
            0, 8, 0, /* 677: pointer.func */
            0, 0, 0, /* 680: func */
            0, 8, 0, /* 683: pointer.func */
            0, 8, 0, /* 686: pointer.func */
            0, 0, 0, /* 689: func */
            0, 8, 0, /* 692: pointer.func */
            0, 0, 0, /* 695: func */
            0, 8, 0, /* 698: pointer.func */
            0, 0, 0, /* 701: func */
            0, 0, 0, /* 704: func */
            0, 0, 0, /* 707: func */
            0, 0, 0, /* 710: func */
            0, 0, 0, /* 713: func */
            0, 8, 0, /* 716: pointer.func */
            0, 8, 0, /* 719: pointer.func */
            0, 0, 0, /* 722: func */
            0, 8, 0, /* 725: pointer.func */
            0, 0, 0, /* 728: func */
            0, 8, 0, /* 731: pointer.func */
            0, 0, 0, /* 734: func */
            0, 8, 0, /* 737: pointer.func */
            0, 8, 0, /* 740: pointer.func */
            0, 0, 0, /* 743: func */
            0, 0, 0, /* 746: func */
            0, 0, 0, /* 749: func */
            0, 8, 0, /* 752: pointer.func */
            0, 0, 0, /* 755: func */
            0, 0, 0, /* 758: func */
            0, 0, 0, /* 761: func */
            0, 8, 0, /* 764: pointer.func */
            0, 20, 0, /* 767: array[20].char */
            0, 0, 0, /* 770: func */
            0, 0, 0, /* 773: func */
            0, 0, 0, /* 776: func */
            0, 8, 0, /* 779: long */
            0, 8, 0, /* 782: pointer.func */
            0, 8, 0, /* 785: pointer.func */
            0, 8, 0, /* 788: pointer.func */
            0, 8, 0, /* 791: pointer.func */
            0, 0, 0, /* 794: func */
            0, 4, 0, /* 797: int */
            0, 8, 0, /* 800: pointer.func */
            0, 8, 0, /* 803: pointer.func */
            0, 0, 0, /* 806: func */
            1, 8, 1, /* 809: pointer.pointer.struct.x509_st */
            	221, 0,
            0, 8, 0, /* 814: pointer.func */
            0, 8, 0, /* 817: pointer.func */
            0, 0, 0, /* 820: func */
            0, 0, 0, /* 823: func */
            0, 8, 0, /* 826: pointer.func */
            0, 8, 0, /* 829: pointer.func */
            0, 8, 0, /* 832: pointer.func */
            0, 8, 0, /* 835: pointer.func */
            0, 0, 0, /* 838: func */
            0, 0, 0, /* 841: func */
            0, 0, 0, /* 844: func */
            0, 0, 0, /* 847: func */
            0, 8, 0, /* 850: pointer.func */
            0, 0, 0, /* 853: func */
            0, 0, 0, /* 856: func */
            0, 8, 0, /* 859: pointer.func */
            0, 8, 0, /* 862: pointer.func */
            0, 8, 0, /* 865: pointer.func */
            0, 0, 0, /* 868: func */
            0, 0, 0, /* 871: func */
            0, 0, 0, /* 874: func */
            0, 8, 0, /* 877: pointer.func */
            0, 0, 0, /* 880: func */
            0, 0, 0, /* 883: func */
            0, 8, 0, /* 886: pointer.func */
            0, 8, 0, /* 889: pointer.func */
            0, 0, 0, /* 892: func */
            0, 8, 0, /* 895: pointer.func */
            0, 0, 0, /* 898: func */
            0, 8, 0, /* 901: pointer.func */
            0, 0, 0, /* 904: func */
            0, 8, 0, /* 907: pointer.func */
            0, 8, 0, /* 910: pointer.func */
            0, 0, 0, /* 913: func */
            0, 8, 0, /* 916: pointer.func */
            0, 8, 0, /* 919: pointer.func */
            0, 8, 0, /* 922: pointer.func */
            0, 8, 0, /* 925: pointer.func */
            0, 0, 0, /* 928: func */
            0, 8, 0, /* 931: pointer.func */
            0, 0, 0, /* 934: func */
            0, 8, 0, /* 937: pointer.func */
            0, 0, 0, /* 940: func */
            0, 8, 0, /* 943: pointer.func */
            0, 0, 0, /* 946: func */
            0, 8, 0, /* 949: pointer.func */
            0, 0, 0, /* 952: func */
            0, 8, 0, /* 955: pointer.func */
            0, 8, 0, /* 958: pointer.func */
            0, 8, 0, /* 961: pointer.func */
            0, 8, 0, /* 964: pointer.func */
            0, 0, 0, /* 967: func */
            0, 8, 0, /* 970: pointer.func */
            0, 8, 0, /* 973: pointer.func */
            0, 8, 0, /* 976: pointer.func */
            0, 0, 0, /* 979: func */
            0, 8, 0, /* 982: pointer.func */
            0, 8, 0, /* 985: pointer.func */
            0, 8, 0, /* 988: pointer.func */
            0, 0, 0, /* 991: func */
            0, 0, 0, /* 994: func */
            0, 8, 0, /* 997: pointer.func */
            0, 0, 0, /* 1000: func */
            0, 0, 0, /* 1003: func */
        },
        .arg_entity_index = { 809, 642, 221, },
        .ret_entity_index = 797,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 ** new_arg_a = *((X509 ** *)new_args->args[0]);

    X509_STORE_CTX * new_arg_b = *((X509_STORE_CTX * *)new_args->args[1]);

    X509 * new_arg_c = *((X509 * *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_X509_STORE_CTX_get1_issuer)(X509 **,X509_STORE_CTX *,X509 *);
    orig_X509_STORE_CTX_get1_issuer = dlsym(RTLD_NEXT, "X509_STORE_CTX_get1_issuer");
    *new_ret_ptr = (*orig_X509_STORE_CTX_get1_issuer)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    return ret;
}

