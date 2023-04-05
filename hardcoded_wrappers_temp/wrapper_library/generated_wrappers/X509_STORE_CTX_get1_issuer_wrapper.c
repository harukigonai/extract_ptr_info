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
    unsigned long in_lib = syscall(890);
    printf("X509_STORE_CTX_get1_issuer called %lu\n", in_lib);
    if (!in_lib)
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
            0, 0, 0, /* 0: struct.x509_crl_method_st */
            1, 8, 1, /* 3: pointer.struct.x509_crl_method_st */
            	0, 0,
            0, 0, 0, /* 8: struct.stack_st_GENERAL_NAMES */
            0, 8, 2, /* 11: union.unknown */
            	18, 0,
            	48, 0,
            1, 8, 1, /* 18: pointer.struct.stack_st_GENERAL_NAME */
            	23, 0,
            0, 32, 1, /* 23: struct.stack_st_GENERAL_NAME */
            	28, 0,
            0, 32, 2, /* 28: struct.stack_st */
            	35, 8,
            	45, 24,
            1, 8, 1, /* 35: pointer.pointer.char */
            	40, 0,
            1, 8, 1, /* 40: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 45: pointer.func */
            1, 8, 1, /* 48: pointer.struct.stack_st_X509_NAME_ENTRY */
            	53, 0,
            0, 32, 1, /* 53: struct.stack_st_X509_NAME_ENTRY */
            	28, 0,
            0, 32, 2, /* 58: struct.ISSUING_DIST_POINT_st */
            	65, 0,
            	109, 16,
            1, 8, 1, /* 65: pointer.struct.DIST_POINT_NAME_st */
            	70, 0,
            0, 24, 2, /* 70: struct.DIST_POINT_NAME_st */
            	11, 8,
            	77, 16,
            1, 8, 1, /* 77: pointer.struct.X509_name_st */
            	82, 0,
            0, 40, 3, /* 82: struct.X509_name_st */
            	48, 0,
            	91, 16,
            	101, 24,
            1, 8, 1, /* 91: pointer.struct.buf_mem_st */
            	96, 0,
            0, 24, 1, /* 96: struct.buf_mem_st */
            	40, 8,
            1, 8, 1, /* 101: pointer.unsigned char */
            	106, 0,
            0, 1, 0, /* 106: unsigned char */
            1, 8, 1, /* 109: pointer.struct.asn1_string_st */
            	114, 0,
            0, 24, 1, /* 114: struct.asn1_string_st */
            	101, 8,
            0, 32, 1, /* 119: struct.stack_st_X509_REVOKED */
            	28, 0,
            0, 80, 8, /* 124: struct.X509_crl_info_st */
            	143, 0,
            	148, 8,
            	77, 16,
            	310, 24,
            	310, 32,
            	315, 40,
            	320, 48,
            	330, 56,
            1, 8, 1, /* 143: pointer.struct.asn1_string_st */
            	114, 0,
            1, 8, 1, /* 148: pointer.struct.X509_algor_st */
            	153, 0,
            0, 16, 2, /* 153: struct.X509_algor_st */
            	160, 0,
            	184, 8,
            1, 8, 1, /* 160: pointer.struct.asn1_object_st */
            	165, 0,
            0, 40, 3, /* 165: struct.asn1_object_st */
            	174, 0,
            	174, 8,
            	179, 24,
            1, 8, 1, /* 174: pointer.char */
            	4096, 0,
            1, 8, 1, /* 179: pointer.unsigned char */
            	106, 0,
            1, 8, 1, /* 184: pointer.struct.asn1_type_st */
            	189, 0,
            0, 16, 1, /* 189: struct.asn1_type_st */
            	194, 8,
            0, 8, 20, /* 194: union.unknown */
            	40, 0,
            	237, 0,
            	160, 0,
            	143, 0,
            	242, 0,
            	109, 0,
            	247, 0,
            	252, 0,
            	257, 0,
            	262, 0,
            	267, 0,
            	272, 0,
            	277, 0,
            	282, 0,
            	287, 0,
            	292, 0,
            	297, 0,
            	237, 0,
            	237, 0,
            	302, 0,
            1, 8, 1, /* 237: pointer.struct.asn1_string_st */
            	114, 0,
            1, 8, 1, /* 242: pointer.struct.asn1_string_st */
            	114, 0,
            1, 8, 1, /* 247: pointer.struct.asn1_string_st */
            	114, 0,
            1, 8, 1, /* 252: pointer.struct.asn1_string_st */
            	114, 0,
            1, 8, 1, /* 257: pointer.struct.asn1_string_st */
            	114, 0,
            1, 8, 1, /* 262: pointer.struct.asn1_string_st */
            	114, 0,
            1, 8, 1, /* 267: pointer.struct.asn1_string_st */
            	114, 0,
            1, 8, 1, /* 272: pointer.struct.asn1_string_st */
            	114, 0,
            1, 8, 1, /* 277: pointer.struct.asn1_string_st */
            	114, 0,
            1, 8, 1, /* 282: pointer.struct.asn1_string_st */
            	114, 0,
            1, 8, 1, /* 287: pointer.struct.asn1_string_st */
            	114, 0,
            1, 8, 1, /* 292: pointer.struct.asn1_string_st */
            	114, 0,
            1, 8, 1, /* 297: pointer.struct.asn1_string_st */
            	114, 0,
            1, 8, 1, /* 302: pointer.struct.ASN1_VALUE_st */
            	307, 0,
            0, 0, 0, /* 307: struct.ASN1_VALUE_st */
            1, 8, 1, /* 310: pointer.struct.asn1_string_st */
            	114, 0,
            1, 8, 1, /* 315: pointer.struct.stack_st_X509_REVOKED */
            	119, 0,
            1, 8, 1, /* 320: pointer.struct.stack_st_X509_EXTENSION */
            	325, 0,
            0, 32, 1, /* 325: struct.stack_st_X509_EXTENSION */
            	28, 0,
            0, 24, 1, /* 330: struct.ASN1_ENCODING_st */
            	101, 0,
            1, 8, 1, /* 335: pointer.struct.X509_crl_info_st */
            	124, 0,
            0, 120, 10, /* 340: struct.X509_crl_st */
            	335, 0,
            	148, 8,
            	109, 16,
            	363, 32,
            	377, 40,
            	143, 56,
            	143, 64,
            	382, 96,
            	3, 104,
            	387, 112,
            1, 8, 1, /* 363: pointer.struct.AUTHORITY_KEYID_st */
            	368, 0,
            0, 24, 3, /* 368: struct.AUTHORITY_KEYID_st */
            	247, 0,
            	18, 8,
            	143, 16,
            1, 8, 1, /* 377: pointer.struct.ISSUING_DIST_POINT_st */
            	58, 0,
            1, 8, 1, /* 382: pointer.struct.stack_st_GENERAL_NAMES */
            	8, 0,
            0, 8, 0, /* 387: pointer.void */
            0, 0, 0, /* 390: struct.X509_POLICY_TREE_st */
            0, 32, 1, /* 393: struct.stack_st_X509_CRL */
            	28, 0,
            0, 32, 1, /* 398: struct.stack_st_X509 */
            	28, 0,
            4097, 8, 0, /* 403: pointer.func */
            4097, 8, 0, /* 406: pointer.func */
            4097, 8, 0, /* 409: pointer.func */
            4097, 8, 0, /* 412: pointer.func */
            4097, 8, 0, /* 415: pointer.func */
            4097, 8, 0, /* 418: pointer.func */
            4097, 8, 0, /* 421: pointer.func */
            4097, 8, 0, /* 424: pointer.func */
            0, 56, 2, /* 427: struct.X509_VERIFY_PARAM_st */
            	40, 0,
            	434, 48,
            1, 8, 1, /* 434: pointer.struct.stack_st_ASN1_OBJECT */
            	439, 0,
            0, 32, 1, /* 439: struct.stack_st_ASN1_OBJECT */
            	28, 0,
            1, 8, 1, /* 444: pointer.struct.X509_VERIFY_PARAM_st */
            	427, 0,
            1, 8, 1, /* 449: pointer.struct.X509_POLICY_TREE_st */
            	390, 0,
            0, 32, 1, /* 454: struct.stack_st_X509_LOOKUP */
            	28, 0,
            0, 32, 1, /* 459: struct.stack_st_X509_OBJECT */
            	28, 0,
            0, 144, 15, /* 464: struct.x509_store_st */
            	497, 8,
            	502, 16,
            	444, 24,
            	424, 32,
            	421, 40,
            	507, 48,
            	418, 56,
            	424, 64,
            	415, 72,
            	412, 80,
            	409, 88,
            	406, 96,
            	403, 104,
            	424, 112,
            	510, 120,
            1, 8, 1, /* 497: pointer.struct.stack_st_X509_OBJECT */
            	459, 0,
            1, 8, 1, /* 502: pointer.struct.stack_st_X509_LOOKUP */
            	454, 0,
            4097, 8, 0, /* 507: pointer.func */
            0, 16, 1, /* 510: struct.crypto_ex_data_st */
            	515, 0,
            1, 8, 1, /* 515: pointer.struct.stack_st_void */
            	520, 0,
            0, 32, 1, /* 520: struct.stack_st_void */
            	28, 0,
            0, 168, 17, /* 525: struct.rsa_st */
            	562, 16,
            	617, 24,
            	625, 32,
            	625, 40,
            	625, 48,
            	625, 56,
            	625, 64,
            	625, 72,
            	625, 80,
            	625, 88,
            	510, 96,
            	643, 120,
            	643, 128,
            	643, 136,
            	40, 144,
            	657, 152,
            	657, 160,
            1, 8, 1, /* 562: pointer.struct.rsa_meth_st */
            	567, 0,
            0, 112, 13, /* 567: struct.rsa_meth_st */
            	174, 0,
            	596, 8,
            	596, 16,
            	596, 24,
            	596, 32,
            	599, 40,
            	602, 48,
            	605, 56,
            	605, 64,
            	40, 80,
            	608, 88,
            	611, 96,
            	614, 104,
            4097, 8, 0, /* 596: pointer.func */
            4097, 8, 0, /* 599: pointer.func */
            4097, 8, 0, /* 602: pointer.func */
            4097, 8, 0, /* 605: pointer.func */
            4097, 8, 0, /* 608: pointer.func */
            4097, 8, 0, /* 611: pointer.func */
            4097, 8, 0, /* 614: pointer.func */
            1, 8, 1, /* 617: pointer.struct.engine_st */
            	622, 0,
            0, 0, 0, /* 622: struct.engine_st */
            1, 8, 1, /* 625: pointer.struct.bignum_st */
            	630, 0,
            0, 24, 1, /* 630: struct.bignum_st */
            	635, 0,
            1, 8, 1, /* 635: pointer.unsigned int */
            	640, 0,
            0, 4, 0, /* 640: unsigned int */
            1, 8, 1, /* 643: pointer.struct.bn_mont_ctx_st */
            	648, 0,
            0, 96, 3, /* 648: struct.bn_mont_ctx_st */
            	630, 8,
            	630, 32,
            	630, 56,
            1, 8, 1, /* 657: pointer.struct.bn_blinding_st */
            	662, 0,
            0, 0, 0, /* 662: struct.bn_blinding_st */
            1, 8, 1, /* 665: pointer.struct.rsa_st */
            	525, 0,
            0, 8, 5, /* 670: union.unknown */
            	40, 0,
            	665, 0,
            	683, 0,
            	764, 0,
            	832, 0,
            1, 8, 1, /* 683: pointer.struct.dsa_st */
            	688, 0,
            0, 136, 11, /* 688: struct.dsa_st */
            	625, 24,
            	625, 32,
            	625, 40,
            	625, 48,
            	625, 56,
            	625, 64,
            	625, 72,
            	643, 88,
            	510, 104,
            	713, 120,
            	617, 128,
            1, 8, 1, /* 713: pointer.struct.dsa_method */
            	718, 0,
            0, 96, 11, /* 718: struct.dsa_method */
            	174, 0,
            	743, 8,
            	746, 16,
            	749, 24,
            	752, 32,
            	755, 40,
            	758, 48,
            	758, 56,
            	40, 72,
            	761, 80,
            	758, 88,
            4097, 8, 0, /* 743: pointer.func */
            4097, 8, 0, /* 746: pointer.func */
            4097, 8, 0, /* 749: pointer.func */
            4097, 8, 0, /* 752: pointer.func */
            4097, 8, 0, /* 755: pointer.func */
            4097, 8, 0, /* 758: pointer.func */
            4097, 8, 0, /* 761: pointer.func */
            1, 8, 1, /* 764: pointer.struct.dh_st */
            	769, 0,
            0, 144, 12, /* 769: struct.dh_st */
            	625, 8,
            	625, 16,
            	625, 32,
            	625, 40,
            	643, 56,
            	625, 64,
            	625, 72,
            	101, 80,
            	625, 96,
            	510, 112,
            	796, 128,
            	617, 136,
            1, 8, 1, /* 796: pointer.struct.dh_method */
            	801, 0,
            0, 72, 8, /* 801: struct.dh_method */
            	174, 0,
            	820, 8,
            	823, 16,
            	826, 24,
            	820, 32,
            	820, 40,
            	40, 56,
            	829, 64,
            4097, 8, 0, /* 820: pointer.func */
            4097, 8, 0, /* 823: pointer.func */
            4097, 8, 0, /* 826: pointer.func */
            4097, 8, 0, /* 829: pointer.func */
            1, 8, 1, /* 832: pointer.struct.ec_key_st */
            	837, 0,
            0, 0, 0, /* 837: struct.ec_key_st */
            1, 8, 1, /* 840: pointer.struct.stack_st_X509_ALGOR */
            	845, 0,
            0, 32, 1, /* 845: struct.stack_st_X509_ALGOR */
            	28, 0,
            0, 56, 4, /* 850: struct.evp_pkey_st */
            	861, 16,
            	617, 24,
            	670, 32,
            	869, 48,
            1, 8, 1, /* 861: pointer.struct.evp_pkey_asn1_method_st */
            	866, 0,
            0, 0, 0, /* 866: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 869: pointer.struct.stack_st_X509_ATTRIBUTE */
            	874, 0,
            0, 32, 1, /* 874: struct.stack_st_X509_ATTRIBUTE */
            	28, 0,
            1, 8, 1, /* 879: pointer.pointer.struct.x509_st */
            	884, 0,
            1, 8, 1, /* 884: pointer.struct.x509_st */
            	889, 0,
            0, 184, 12, /* 889: struct.x509_st */
            	916, 0,
            	148, 8,
            	109, 16,
            	40, 32,
            	510, 40,
            	247, 104,
            	363, 112,
            	977, 120,
            	985, 128,
            	995, 136,
            	1000, 144,
            	1022, 176,
            1, 8, 1, /* 916: pointer.struct.x509_cinf_st */
            	921, 0,
            0, 104, 11, /* 921: struct.x509_cinf_st */
            	143, 0,
            	143, 8,
            	148, 16,
            	77, 24,
            	946, 32,
            	77, 40,
            	958, 48,
            	109, 56,
            	109, 64,
            	320, 72,
            	330, 80,
            1, 8, 1, /* 946: pointer.struct.X509_val_st */
            	951, 0,
            0, 16, 2, /* 951: struct.X509_val_st */
            	310, 0,
            	310, 8,
            1, 8, 1, /* 958: pointer.struct.X509_pubkey_st */
            	963, 0,
            0, 24, 3, /* 963: struct.X509_pubkey_st */
            	148, 0,
            	109, 8,
            	972, 16,
            1, 8, 1, /* 972: pointer.struct.evp_pkey_st */
            	850, 0,
            1, 8, 1, /* 977: pointer.struct.X509_POLICY_CACHE_st */
            	982, 0,
            0, 0, 0, /* 982: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 985: pointer.struct.stack_st_DIST_POINT */
            	990, 0,
            0, 32, 1, /* 990: struct.stack_st_DIST_POINT */
            	28, 0,
            1, 8, 1, /* 995: pointer.struct.stack_st_GENERAL_NAME */
            	23, 0,
            1, 8, 1, /* 1000: pointer.struct.NAME_CONSTRAINTS_st */
            	1005, 0,
            0, 16, 2, /* 1005: struct.NAME_CONSTRAINTS_st */
            	1012, 0,
            	1012, 8,
            1, 8, 1, /* 1012: pointer.struct.stack_st_GENERAL_SUBTREE */
            	1017, 0,
            0, 32, 1, /* 1017: struct.stack_st_GENERAL_SUBTREE */
            	28, 0,
            1, 8, 1, /* 1022: pointer.struct.x509_cert_aux_st */
            	1027, 0,
            0, 40, 5, /* 1027: struct.x509_cert_aux_st */
            	434, 0,
            	434, 8,
            	297, 16,
            	247, 24,
            	840, 32,
            1, 8, 1, /* 1040: pointer.struct.x509_store_st */
            	464, 0,
            1, 8, 1, /* 1045: pointer.struct.stack_st_X509_CRL */
            	393, 0,
            1, 8, 1, /* 1050: pointer.struct.stack_st_X509 */
            	398, 0,
            0, 1, 0, /* 1055: char */
            0, 4, 0, /* 1058: int */
            1, 8, 1, /* 1061: pointer.struct.X509_crl_st */
            	340, 0,
            1, 8, 1, /* 1066: pointer.struct.x509_store_ctx_st */
            	1071, 0,
            0, 248, 25, /* 1071: struct.x509_store_ctx_st */
            	1040, 0,
            	884, 16,
            	1050, 24,
            	1045, 32,
            	444, 40,
            	387, 48,
            	424, 56,
            	421, 64,
            	507, 72,
            	418, 80,
            	424, 88,
            	415, 96,
            	412, 104,
            	409, 112,
            	424, 120,
            	406, 128,
            	403, 136,
            	424, 144,
            	1050, 160,
            	449, 168,
            	884, 192,
            	884, 200,
            	1061, 208,
            	1066, 224,
            	510, 232,
        },
        .arg_entity_index = { 879, 1066, 884, },
        .ret_entity_index = 1058,
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

