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
            0, 8, 0, /* 0: pointer.void */
            0, 0, 0, /* 3: func */
            0, 0, 0, /* 6: func */
            4097, 8, 0, /* 9: pointer.func */
            0, 0, 0, /* 12: func */
            4097, 8, 0, /* 15: pointer.func */
            0, 40, 4, /* 18: struct.x509_crl_method_st */
            	15, 8,
            	15, 16,
            	9, 24,
            	29, 32,
            4097, 8, 0, /* 29: pointer.func */
            0, 8, 1, /* 32: union.anon.1.3127 */
            	37, 0,
            1, 8, 1, /* 37: pointer.struct.stack_st_OPENSSL_STRING */
            	42, 0,
            0, 32, 1, /* 42: struct.stack_st_OPENSSL_STRING */
            	47, 0,
            0, 32, 2, /* 47: struct.stack_st */
            	54, 8,
            	64, 24,
            1, 8, 1, /* 54: pointer.pointer.char */
            	59, 0,
            1, 8, 1, /* 59: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 64: pointer.func */
            0, 32, 2, /* 67: struct.ISSUING_DIST_POINT_st */
            	74, 0,
            	110, 16,
            1, 8, 1, /* 74: pointer.struct.DIST_POINT_NAME_st */
            	79, 0,
            0, 24, 2, /* 79: struct.DIST_POINT_NAME_st */
            	32, 8,
            	86, 16,
            1, 8, 1, /* 86: pointer.struct.X509_name_st */
            	91, 0,
            0, 40, 3, /* 91: struct.X509_name_st */
            	37, 0,
            	100, 16,
            	59, 24,
            1, 8, 1, /* 100: pointer.struct.buf_mem_st */
            	105, 0,
            0, 24, 1, /* 105: struct.buf_mem_st */
            	59, 8,
            1, 8, 1, /* 110: pointer.struct.asn1_string_st */
            	115, 0,
            0, 24, 1, /* 115: struct.asn1_string_st */
            	59, 8,
            1, 8, 1, /* 120: pointer.struct.X509_crl_info_st */
            	125, 0,
            0, 80, 8, /* 125: struct.X509_crl_info_st */
            	110, 0,
            	144, 8,
            	86, 16,
            	110, 24,
            	110, 32,
            	37, 40,
            	37, 48,
            	185, 56,
            1, 8, 1, /* 144: pointer.struct.X509_algor_st */
            	149, 0,
            0, 16, 2, /* 149: struct.X509_algor_st */
            	156, 0,
            	170, 8,
            1, 8, 1, /* 156: pointer.struct.asn1_object_st */
            	161, 0,
            0, 40, 3, /* 161: struct.asn1_object_st */
            	59, 0,
            	59, 8,
            	59, 24,
            1, 8, 1, /* 170: pointer.struct.asn1_type_st */
            	175, 0,
            0, 16, 1, /* 175: struct.asn1_type_st */
            	180, 8,
            0, 8, 1, /* 180: struct.fnames */
            	59, 0,
            0, 24, 1, /* 185: struct.ASN1_ENCODING_st */
            	59, 0,
            1, 8, 1, /* 190: pointer.struct.ISSUING_DIST_POINT_st */
            	67, 0,
            1, 8, 1, /* 195: pointer.struct.X509_POLICY_NODE_st */
            	200, 0,
            0, 24, 2, /* 200: struct.X509_POLICY_NODE_st */
            	207, 0,
            	195, 8,
            1, 8, 1, /* 207: pointer.struct.X509_POLICY_DATA_st */
            	212, 0,
            0, 32, 3, /* 212: struct.X509_POLICY_DATA_st */
            	156, 8,
            	37, 16,
            	37, 24,
            1, 8, 1, /* 221: pointer.struct.X509_POLICY_LEVEL_st */
            	226, 0,
            0, 32, 3, /* 226: struct.X509_POLICY_LEVEL_st */
            	235, 0,
            	37, 8,
            	195, 16,
            1, 8, 1, /* 235: pointer.struct.x509_st */
            	240, 0,
            0, 184, 12, /* 240: struct.x509_st */
            	267, 0,
            	144, 8,
            	110, 16,
            	59, 32,
            	763, 40,
            	110, 104,
            	768, 112,
            	782, 120,
            	37, 128,
            	37, 136,
            	794, 144,
            	806, 176,
            1, 8, 1, /* 267: pointer.struct.x509_cinf_st */
            	272, 0,
            0, 104, 11, /* 272: struct.x509_cinf_st */
            	110, 0,
            	110, 8,
            	144, 16,
            	86, 24,
            	297, 32,
            	86, 40,
            	309, 48,
            	110, 56,
            	110, 64,
            	37, 72,
            	185, 80,
            1, 8, 1, /* 297: pointer.struct.X509_val_st */
            	302, 0,
            0, 16, 2, /* 302: struct.X509_val_st */
            	110, 0,
            	110, 8,
            1, 8, 1, /* 309: pointer.struct.X509_pubkey_st */
            	314, 0,
            0, 24, 3, /* 314: struct.X509_pubkey_st */
            	144, 0,
            	110, 8,
            	323, 16,
            1, 8, 1, /* 323: pointer.struct.evp_pkey_st */
            	328, 0,
            0, 56, 4, /* 328: struct.evp_pkey_st */
            	339, 16,
            	442, 24,
            	180, 32,
            	37, 48,
            1, 8, 1, /* 339: pointer.struct.evp_pkey_asn1_method_st */
            	344, 0,
            0, 208, 24, /* 344: struct.evp_pkey_asn1_method_st */
            	59, 16,
            	59, 24,
            	395, 32,
            	403, 40,
            	406, 48,
            	409, 56,
            	412, 64,
            	415, 72,
            	409, 80,
            	418, 88,
            	418, 96,
            	421, 104,
            	424, 112,
            	418, 120,
            	406, 128,
            	406, 136,
            	409, 144,
            	427, 152,
            	430, 160,
            	433, 168,
            	421, 176,
            	424, 184,
            	436, 192,
            	439, 200,
            1, 8, 1, /* 395: pointer.struct.unnamed */
            	400, 0,
            0, 0, 0, /* 400: struct.unnamed */
            4097, 8, 0, /* 403: pointer.func */
            4097, 8, 0, /* 406: pointer.func */
            4097, 8, 0, /* 409: pointer.func */
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
            1, 8, 1, /* 442: pointer.struct.engine_st */
            	447, 0,
            0, 216, 24, /* 447: struct.engine_st */
            	59, 0,
            	59, 8,
            	498, 16,
            	553, 24,
            	604, 32,
            	640, 40,
            	657, 48,
            	684, 56,
            	719, 64,
            	727, 72,
            	730, 80,
            	733, 88,
            	736, 96,
            	739, 104,
            	739, 112,
            	739, 120,
            	742, 128,
            	745, 136,
            	745, 144,
            	748, 152,
            	751, 160,
            	763, 184,
            	442, 200,
            	442, 208,
            1, 8, 1, /* 498: pointer.struct.rsa_meth_st */
            	503, 0,
            0, 112, 13, /* 503: struct.rsa_meth_st */
            	59, 0,
            	532, 8,
            	532, 16,
            	532, 24,
            	532, 32,
            	535, 40,
            	538, 48,
            	541, 56,
            	541, 64,
            	59, 80,
            	544, 88,
            	547, 96,
            	550, 104,
            4097, 8, 0, /* 532: pointer.func */
            4097, 8, 0, /* 535: pointer.func */
            4097, 8, 0, /* 538: pointer.func */
            4097, 8, 0, /* 541: pointer.func */
            4097, 8, 0, /* 544: pointer.func */
            4097, 8, 0, /* 547: pointer.func */
            4097, 8, 0, /* 550: pointer.func */
            1, 8, 1, /* 553: pointer.struct.dsa_method */
            	558, 0,
            0, 96, 11, /* 558: struct.dsa_method */
            	59, 0,
            	583, 8,
            	586, 16,
            	589, 24,
            	592, 32,
            	595, 40,
            	598, 48,
            	598, 56,
            	59, 72,
            	601, 80,
            	598, 88,
            4097, 8, 0, /* 583: pointer.func */
            4097, 8, 0, /* 586: pointer.func */
            4097, 8, 0, /* 589: pointer.func */
            4097, 8, 0, /* 592: pointer.func */
            4097, 8, 0, /* 595: pointer.func */
            4097, 8, 0, /* 598: pointer.func */
            4097, 8, 0, /* 601: pointer.func */
            1, 8, 1, /* 604: pointer.struct.dh_method */
            	609, 0,
            0, 72, 8, /* 609: struct.dh_method */
            	59, 0,
            	628, 8,
            	631, 16,
            	634, 24,
            	628, 32,
            	628, 40,
            	59, 56,
            	637, 64,
            4097, 8, 0, /* 628: pointer.func */
            4097, 8, 0, /* 631: pointer.func */
            4097, 8, 0, /* 634: pointer.func */
            4097, 8, 0, /* 637: pointer.func */
            1, 8, 1, /* 640: pointer.struct.ecdh_method */
            	645, 0,
            0, 32, 3, /* 645: struct.ecdh_method */
            	59, 0,
            	654, 8,
            	59, 24,
            4097, 8, 0, /* 654: pointer.func */
            1, 8, 1, /* 657: pointer.struct.ecdsa_method */
            	662, 0,
            0, 48, 5, /* 662: struct.ecdsa_method */
            	59, 0,
            	675, 8,
            	678, 16,
            	681, 24,
            	59, 40,
            4097, 8, 0, /* 675: pointer.func */
            4097, 8, 0, /* 678: pointer.func */
            4097, 8, 0, /* 681: pointer.func */
            1, 8, 1, /* 684: pointer.struct.rand_meth_st */
            	689, 0,
            0, 48, 6, /* 689: struct.rand_meth_st */
            	704, 0,
            	707, 8,
            	710, 16,
            	713, 24,
            	707, 32,
            	716, 40,
            4097, 8, 0, /* 704: pointer.func */
            4097, 8, 0, /* 707: pointer.func */
            4097, 8, 0, /* 710: pointer.func */
            4097, 8, 0, /* 713: pointer.func */
            4097, 8, 0, /* 716: pointer.func */
            1, 8, 1, /* 719: pointer.struct.store_method_st */
            	724, 0,
            0, 0, 0, /* 724: struct.store_method_st */
            4097, 8, 0, /* 727: pointer.func */
            4097, 8, 0, /* 730: pointer.func */
            4097, 8, 0, /* 733: pointer.func */
            4097, 8, 0, /* 736: pointer.func */
            4097, 8, 0, /* 739: pointer.func */
            4097, 8, 0, /* 742: pointer.func */
            4097, 8, 0, /* 745: pointer.func */
            4097, 8, 0, /* 748: pointer.func */
            1, 8, 1, /* 751: pointer.struct.ENGINE_CMD_DEFN_st */
            	756, 0,
            0, 32, 2, /* 756: struct.ENGINE_CMD_DEFN_st */
            	59, 8,
            	59, 16,
            0, 16, 1, /* 763: struct.crypto_ex_data_st */
            	37, 0,
            1, 8, 1, /* 768: pointer.struct.AUTHORITY_KEYID_st */
            	773, 0,
            0, 24, 3, /* 773: struct.AUTHORITY_KEYID_st */
            	110, 0,
            	37, 8,
            	110, 16,
            1, 8, 1, /* 782: pointer.struct.X509_POLICY_CACHE_st */
            	787, 0,
            0, 40, 2, /* 787: struct.X509_POLICY_CACHE_st */
            	207, 0,
            	37, 8,
            1, 8, 1, /* 794: pointer.struct.NAME_CONSTRAINTS_st */
            	799, 0,
            0, 16, 2, /* 799: struct.NAME_CONSTRAINTS_st */
            	37, 0,
            	37, 8,
            1, 8, 1, /* 806: pointer.struct.x509_cert_aux_st */
            	811, 0,
            0, 40, 5, /* 811: struct.x509_cert_aux_st */
            	37, 0,
            	37, 8,
            	110, 16,
            	110, 24,
            	37, 32,
            1, 8, 1, /* 824: pointer.struct.X509_POLICY_TREE_st */
            	829, 0,
            0, 48, 4, /* 829: struct.X509_POLICY_TREE_st */
            	221, 0,
            	37, 16,
            	37, 24,
            	37, 32,
            0, 0, 0, /* 840: func */
            4097, 8, 0, /* 843: pointer.func */
            4097, 8, 0, /* 846: pointer.func */
            0, 0, 0, /* 849: func */
            0, 0, 0, /* 852: func */
            0, 56, 2, /* 855: struct.X509_VERIFY_PARAM_st */
            	59, 0,
            	37, 48,
            0, 0, 0, /* 862: func */
            1, 8, 1, /* 865: pointer.struct.X509_VERIFY_PARAM_st */
            	855, 0,
            0, 20, 0, /* 870: array[20].char */
            0, 144, 15, /* 873: struct.x509_store_st */
            	37, 8,
            	37, 16,
            	865, 24,
            	906, 32,
            	909, 40,
            	846, 48,
            	912, 56,
            	906, 64,
            	915, 72,
            	843, 80,
            	918, 88,
            	921, 96,
            	921, 104,
            	906, 112,
            	763, 120,
            4097, 8, 0, /* 906: pointer.func */
            4097, 8, 0, /* 909: pointer.func */
            4097, 8, 0, /* 912: pointer.func */
            4097, 8, 0, /* 915: pointer.func */
            4097, 8, 0, /* 918: pointer.func */
            4097, 8, 0, /* 921: pointer.func */
            0, 0, 0, /* 924: func */
            0, 0, 0, /* 927: func */
            0, 0, 0, /* 930: func */
            0, 0, 0, /* 933: func */
            0, 0, 0, /* 936: func */
            0, 0, 0, /* 939: func */
            0, 0, 0, /* 942: func */
            0, 0, 0, /* 945: func */
            0, 0, 0, /* 948: func */
            0, 0, 0, /* 951: func */
            0, 0, 0, /* 954: func */
            0, 0, 0, /* 957: func */
            0, 0, 0, /* 960: func */
            0, 0, 0, /* 963: func */
            0, 0, 0, /* 966: func */
            0, 0, 0, /* 969: func */
            0, 0, 0, /* 972: func */
            0, 8, 0, /* 975: long */
            1, 8, 1, /* 978: pointer.struct.X509_crl_st */
            	983, 0,
            0, 120, 10, /* 983: struct.X509_crl_st */
            	120, 0,
            	144, 8,
            	110, 16,
            	768, 32,
            	190, 40,
            	110, 56,
            	110, 64,
            	37, 96,
            	1006, 104,
            	0, 112,
            1, 8, 1, /* 1006: pointer.struct.x509_crl_method_st */
            	18, 0,
            0, 0, 0, /* 1011: func */
            0, 0, 0, /* 1014: func */
            0, 1, 0, /* 1017: char */
            1, 8, 1, /* 1020: pointer.pointer.struct.x509_st */
            	235, 0,
            0, 0, 0, /* 1025: func */
            0, 0, 0, /* 1028: func */
            0, 0, 0, /* 1031: func */
            0, 0, 0, /* 1034: func */
            0, 0, 0, /* 1037: func */
            0, 0, 0, /* 1040: func */
            0, 0, 0, /* 1043: func */
            0, 4, 0, /* 1046: int */
            0, 0, 0, /* 1049: func */
            0, 0, 0, /* 1052: func */
            0, 0, 0, /* 1055: func */
            0, 0, 0, /* 1058: func */
            0, 0, 0, /* 1061: func */
            0, 0, 0, /* 1064: func */
            0, 0, 0, /* 1067: func */
            0, 0, 0, /* 1070: func */
            1, 8, 1, /* 1073: pointer.struct.x509_store_st */
            	873, 0,
            0, 0, 0, /* 1078: func */
            0, 0, 0, /* 1081: func */
            0, 0, 0, /* 1084: func */
            0, 0, 0, /* 1087: func */
            0, 0, 0, /* 1090: func */
            0, 0, 0, /* 1093: func */
            1, 8, 1, /* 1096: pointer.struct.x509_store_ctx_st */
            	1101, 0,
            0, 248, 25, /* 1101: struct.x509_store_ctx_st */
            	1073, 0,
            	235, 16,
            	37, 24,
            	37, 32,
            	865, 40,
            	0, 48,
            	395, 56,
            	909, 64,
            	846, 72,
            	912, 80,
            	395, 88,
            	915, 96,
            	843, 104,
            	918, 112,
            	395, 120,
            	921, 128,
            	921, 136,
            	395, 144,
            	37, 160,
            	824, 168,
            	235, 192,
            	235, 200,
            	978, 208,
            	1096, 224,
            	763, 232,
            0, 0, 0, /* 1154: func */
            0, 0, 0, /* 1157: func */
            0, 0, 0, /* 1160: func */
            0, 0, 0, /* 1163: func */
            0, 0, 0, /* 1166: func */
            0, 0, 0, /* 1169: func */
            0, 0, 0, /* 1172: func */
            0, 0, 0, /* 1175: func */
            0, 0, 0, /* 1178: func */
            0, 0, 0, /* 1181: func */
            0, 0, 0, /* 1184: func */
            0, 0, 0, /* 1187: func */
            0, 0, 0, /* 1190: func */
        },
        .arg_entity_index = { 1020, 1096, 235, },
        .ret_entity_index = 1046,
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

