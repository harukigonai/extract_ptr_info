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

int bb_SSL_CTX_use_certificate_chain_file(SSL_CTX * arg_a,const char * arg_b);

int SSL_CTX_use_certificate_chain_file(SSL_CTX * arg_a,const char * arg_b) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_use_certificate_chain_file called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_CTX_use_certificate_chain_file(arg_a,arg_b);
    else {
        int (*orig_SSL_CTX_use_certificate_chain_file)(SSL_CTX *,const char *);
        orig_SSL_CTX_use_certificate_chain_file = dlsym(RTLD_NEXT, "SSL_CTX_use_certificate_chain_file");
        return orig_SSL_CTX_use_certificate_chain_file(arg_a,arg_b);
    }
}

int bb_SSL_CTX_use_certificate_chain_file(SSL_CTX * arg_a,const char * arg_b) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 32, 1, /* 0: struct.stack_st_SRTP_PROTECTION_PROFILE */
            	5, 0,
            0, 32, 2, /* 5: struct.stack_st */
            	12, 8,
            	22, 24,
            1, 8, 1, /* 12: pointer.pointer.char */
            	17, 0,
            1, 8, 1, /* 17: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 22: pointer.func */
            1, 8, 1, /* 25: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	0, 0,
            4097, 8, 0, /* 30: pointer.func */
            0, 8, 1, /* 33: struct.ssl3_buf_freelist_entry_st */
            	38, 0,
            1, 8, 1, /* 38: pointer.struct.ssl3_buf_freelist_entry_st */
            	33, 0,
            0, 24, 1, /* 43: struct.ssl3_buf_freelist_st */
            	38, 16,
            4097, 8, 0, /* 48: pointer.func */
            4097, 8, 0, /* 51: pointer.func */
            1, 8, 1, /* 54: pointer.struct.cert_st */
            	59, 0,
            0, 296, 7, /* 59: struct.cert_st */
            	76, 0,
            	904, 48,
            	909, 56,
            	912, 64,
            	51, 72,
            	917, 80,
            	922, 88,
            1, 8, 1, /* 76: pointer.struct.cert_pkey_st */
            	81, 0,
            0, 24, 3, /* 81: struct.cert_pkey_st */
            	90, 0,
            	402, 8,
            	859, 16,
            1, 8, 1, /* 90: pointer.struct.x509_st */
            	95, 0,
            0, 184, 12, /* 95: struct.x509_st */
            	122, 0,
            	170, 8,
            	269, 16,
            	17, 32,
            	562, 40,
            	274, 104,
            	781, 112,
            	789, 120,
            	797, 128,
            	805, 136,
            	813, 144,
            	821, 176,
            1, 8, 1, /* 122: pointer.struct.x509_cinf_st */
            	127, 0,
            0, 104, 11, /* 127: struct.x509_cinf_st */
            	152, 0,
            	152, 8,
            	170, 16,
            	337, 24,
            	371, 32,
            	337, 40,
            	388, 48,
            	269, 56,
            	269, 64,
            	766, 72,
            	776, 80,
            1, 8, 1, /* 152: pointer.struct.asn1_string_st */
            	157, 0,
            0, 24, 1, /* 157: struct.asn1_string_st */
            	162, 8,
            1, 8, 1, /* 162: pointer.unsigned char */
            	167, 0,
            0, 1, 0, /* 167: unsigned char */
            1, 8, 1, /* 170: pointer.struct.X509_algor_st */
            	175, 0,
            0, 16, 2, /* 175: struct.X509_algor_st */
            	182, 0,
            	206, 8,
            1, 8, 1, /* 182: pointer.struct.asn1_object_st */
            	187, 0,
            0, 40, 3, /* 187: struct.asn1_object_st */
            	196, 0,
            	196, 8,
            	201, 24,
            1, 8, 1, /* 196: pointer.char */
            	4096, 0,
            1, 8, 1, /* 201: pointer.unsigned char */
            	167, 0,
            1, 8, 1, /* 206: pointer.struct.asn1_type_st */
            	211, 0,
            0, 16, 1, /* 211: struct.asn1_type_st */
            	216, 8,
            0, 8, 20, /* 216: union.unknown */
            	17, 0,
            	259, 0,
            	182, 0,
            	152, 0,
            	264, 0,
            	269, 0,
            	274, 0,
            	279, 0,
            	284, 0,
            	289, 0,
            	294, 0,
            	299, 0,
            	304, 0,
            	309, 0,
            	314, 0,
            	319, 0,
            	324, 0,
            	259, 0,
            	259, 0,
            	329, 0,
            1, 8, 1, /* 259: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 264: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 269: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 274: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 279: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 284: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 289: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 294: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 299: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 304: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 309: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 314: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 319: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 324: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 329: pointer.struct.ASN1_VALUE_st */
            	334, 0,
            0, 0, 0, /* 334: struct.ASN1_VALUE_st */
            1, 8, 1, /* 337: pointer.struct.X509_name_st */
            	342, 0,
            0, 40, 3, /* 342: struct.X509_name_st */
            	351, 0,
            	361, 16,
            	162, 24,
            1, 8, 1, /* 351: pointer.struct.stack_st_X509_NAME_ENTRY */
            	356, 0,
            0, 32, 1, /* 356: struct.stack_st_X509_NAME_ENTRY */
            	5, 0,
            1, 8, 1, /* 361: pointer.struct.buf_mem_st */
            	366, 0,
            0, 24, 1, /* 366: struct.buf_mem_st */
            	17, 8,
            1, 8, 1, /* 371: pointer.struct.X509_val_st */
            	376, 0,
            0, 16, 2, /* 376: struct.X509_val_st */
            	383, 0,
            	383, 8,
            1, 8, 1, /* 383: pointer.struct.asn1_string_st */
            	157, 0,
            1, 8, 1, /* 388: pointer.struct.X509_pubkey_st */
            	393, 0,
            0, 24, 3, /* 393: struct.X509_pubkey_st */
            	170, 0,
            	269, 8,
            	402, 16,
            1, 8, 1, /* 402: pointer.struct.evp_pkey_st */
            	407, 0,
            0, 56, 4, /* 407: struct.evp_pkey_st */
            	418, 16,
            	426, 24,
            	434, 32,
            	756, 48,
            1, 8, 1, /* 418: pointer.struct.evp_pkey_asn1_method_st */
            	423, 0,
            0, 0, 0, /* 423: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 426: pointer.struct.engine_st */
            	431, 0,
            0, 0, 0, /* 431: struct.engine_st */
            0, 8, 5, /* 434: union.unknown */
            	17, 0,
            	447, 0,
            	599, 0,
            	680, 0,
            	748, 0,
            1, 8, 1, /* 447: pointer.struct.rsa_st */
            	452, 0,
            0, 168, 17, /* 452: struct.rsa_st */
            	489, 16,
            	426, 24,
            	544, 32,
            	544, 40,
            	544, 48,
            	544, 56,
            	544, 64,
            	544, 72,
            	544, 80,
            	544, 88,
            	562, 96,
            	577, 120,
            	577, 128,
            	577, 136,
            	17, 144,
            	591, 152,
            	591, 160,
            1, 8, 1, /* 489: pointer.struct.rsa_meth_st */
            	494, 0,
            0, 112, 13, /* 494: struct.rsa_meth_st */
            	196, 0,
            	523, 8,
            	523, 16,
            	523, 24,
            	523, 32,
            	526, 40,
            	529, 48,
            	532, 56,
            	532, 64,
            	17, 80,
            	535, 88,
            	538, 96,
            	541, 104,
            4097, 8, 0, /* 523: pointer.func */
            4097, 8, 0, /* 526: pointer.func */
            4097, 8, 0, /* 529: pointer.func */
            4097, 8, 0, /* 532: pointer.func */
            4097, 8, 0, /* 535: pointer.func */
            4097, 8, 0, /* 538: pointer.func */
            4097, 8, 0, /* 541: pointer.func */
            1, 8, 1, /* 544: pointer.struct.bignum_st */
            	549, 0,
            0, 24, 1, /* 549: struct.bignum_st */
            	554, 0,
            1, 8, 1, /* 554: pointer.unsigned int */
            	559, 0,
            0, 4, 0, /* 559: unsigned int */
            0, 16, 1, /* 562: struct.crypto_ex_data_st */
            	567, 0,
            1, 8, 1, /* 567: pointer.struct.stack_st_void */
            	572, 0,
            0, 32, 1, /* 572: struct.stack_st_void */
            	5, 0,
            1, 8, 1, /* 577: pointer.struct.bn_mont_ctx_st */
            	582, 0,
            0, 96, 3, /* 582: struct.bn_mont_ctx_st */
            	549, 8,
            	549, 32,
            	549, 56,
            1, 8, 1, /* 591: pointer.struct.bn_blinding_st */
            	596, 0,
            0, 0, 0, /* 596: struct.bn_blinding_st */
            1, 8, 1, /* 599: pointer.struct.dsa_st */
            	604, 0,
            0, 136, 11, /* 604: struct.dsa_st */
            	544, 24,
            	544, 32,
            	544, 40,
            	544, 48,
            	544, 56,
            	544, 64,
            	544, 72,
            	577, 88,
            	562, 104,
            	629, 120,
            	426, 128,
            1, 8, 1, /* 629: pointer.struct.dsa_method */
            	634, 0,
            0, 96, 11, /* 634: struct.dsa_method */
            	196, 0,
            	659, 8,
            	662, 16,
            	665, 24,
            	668, 32,
            	671, 40,
            	674, 48,
            	674, 56,
            	17, 72,
            	677, 80,
            	674, 88,
            4097, 8, 0, /* 659: pointer.func */
            4097, 8, 0, /* 662: pointer.func */
            4097, 8, 0, /* 665: pointer.func */
            4097, 8, 0, /* 668: pointer.func */
            4097, 8, 0, /* 671: pointer.func */
            4097, 8, 0, /* 674: pointer.func */
            4097, 8, 0, /* 677: pointer.func */
            1, 8, 1, /* 680: pointer.struct.dh_st */
            	685, 0,
            0, 144, 12, /* 685: struct.dh_st */
            	544, 8,
            	544, 16,
            	544, 32,
            	544, 40,
            	577, 56,
            	544, 64,
            	544, 72,
            	162, 80,
            	544, 96,
            	562, 112,
            	712, 128,
            	426, 136,
            1, 8, 1, /* 712: pointer.struct.dh_method */
            	717, 0,
            0, 72, 8, /* 717: struct.dh_method */
            	196, 0,
            	736, 8,
            	739, 16,
            	742, 24,
            	736, 32,
            	736, 40,
            	17, 56,
            	745, 64,
            4097, 8, 0, /* 736: pointer.func */
            4097, 8, 0, /* 739: pointer.func */
            4097, 8, 0, /* 742: pointer.func */
            4097, 8, 0, /* 745: pointer.func */
            1, 8, 1, /* 748: pointer.struct.ec_key_st */
            	753, 0,
            0, 0, 0, /* 753: struct.ec_key_st */
            1, 8, 1, /* 756: pointer.struct.stack_st_X509_ATTRIBUTE */
            	761, 0,
            0, 32, 1, /* 761: struct.stack_st_X509_ATTRIBUTE */
            	5, 0,
            1, 8, 1, /* 766: pointer.struct.stack_st_X509_EXTENSION */
            	771, 0,
            0, 32, 1, /* 771: struct.stack_st_X509_EXTENSION */
            	5, 0,
            0, 24, 1, /* 776: struct.ASN1_ENCODING_st */
            	162, 0,
            1, 8, 1, /* 781: pointer.struct.AUTHORITY_KEYID_st */
            	786, 0,
            0, 0, 0, /* 786: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 789: pointer.struct.X509_POLICY_CACHE_st */
            	794, 0,
            0, 0, 0, /* 794: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 797: pointer.struct.stack_st_DIST_POINT */
            	802, 0,
            0, 0, 0, /* 802: struct.stack_st_DIST_POINT */
            1, 8, 1, /* 805: pointer.struct.stack_st_GENERAL_NAME */
            	810, 0,
            0, 0, 0, /* 810: struct.stack_st_GENERAL_NAME */
            1, 8, 1, /* 813: pointer.struct.NAME_CONSTRAINTS_st */
            	818, 0,
            0, 0, 0, /* 818: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 821: pointer.struct.x509_cert_aux_st */
            	826, 0,
            0, 40, 5, /* 826: struct.x509_cert_aux_st */
            	839, 0,
            	839, 8,
            	324, 16,
            	274, 24,
            	849, 32,
            1, 8, 1, /* 839: pointer.struct.stack_st_ASN1_OBJECT */
            	844, 0,
            0, 32, 1, /* 844: struct.stack_st_ASN1_OBJECT */
            	5, 0,
            1, 8, 1, /* 849: pointer.struct.stack_st_X509_ALGOR */
            	854, 0,
            0, 32, 1, /* 854: struct.stack_st_X509_ALGOR */
            	5, 0,
            1, 8, 1, /* 859: pointer.struct.env_md_st */
            	864, 0,
            0, 120, 8, /* 864: struct.env_md_st */
            	883, 24,
            	886, 32,
            	889, 40,
            	892, 48,
            	883, 56,
            	895, 64,
            	898, 72,
            	901, 112,
            4097, 8, 0, /* 883: pointer.func */
            4097, 8, 0, /* 886: pointer.func */
            4097, 8, 0, /* 889: pointer.func */
            4097, 8, 0, /* 892: pointer.func */
            4097, 8, 0, /* 895: pointer.func */
            4097, 8, 0, /* 898: pointer.func */
            4097, 8, 0, /* 901: pointer.func */
            1, 8, 1, /* 904: pointer.struct.rsa_st */
            	452, 0,
            4097, 8, 0, /* 909: pointer.func */
            1, 8, 1, /* 912: pointer.struct.dh_st */
            	685, 0,
            1, 8, 1, /* 917: pointer.struct.ec_key_st */
            	753, 0,
            4097, 8, 0, /* 922: pointer.func */
            4097, 8, 0, /* 925: pointer.func */
            0, 32, 1, /* 928: struct.stack_st_X509_NAME */
            	5, 0,
            4097, 8, 0, /* 933: pointer.func */
            1, 8, 1, /* 936: pointer.struct.stack_st_SSL_COMP */
            	941, 0,
            0, 32, 1, /* 941: struct.stack_st_SSL_COMP */
            	5, 0,
            4097, 8, 0, /* 946: pointer.func */
            4097, 8, 0, /* 949: pointer.func */
            0, 88, 1, /* 952: struct.ssl_cipher_st */
            	196, 8,
            4097, 8, 0, /* 957: pointer.func */
            1, 8, 1, /* 960: pointer.struct.ssl_cipher_st */
            	952, 0,
            4097, 8, 0, /* 965: pointer.func */
            4097, 8, 0, /* 968: pointer.func */
            4097, 8, 0, /* 971: pointer.func */
            1, 8, 1, /* 974: pointer.struct.ssl3_buf_freelist_st */
            	43, 0,
            4097, 8, 0, /* 979: pointer.func */
            0, 176, 3, /* 982: struct.lhash_st */
            	991, 0,
            	22, 8,
            	1016, 16,
            1, 8, 1, /* 991: pointer.pointer.struct.lhash_node_st */
            	996, 0,
            1, 8, 1, /* 996: pointer.struct.lhash_node_st */
            	1001, 0,
            0, 24, 2, /* 1001: struct.lhash_node_st */
            	1008, 0,
            	1011, 8,
            0, 8, 0, /* 1008: pointer.void */
            1, 8, 1, /* 1011: pointer.struct.lhash_node_st */
            	1001, 0,
            4097, 8, 0, /* 1016: pointer.func */
            4097, 8, 0, /* 1019: pointer.func */
            4097, 8, 0, /* 1022: pointer.func */
            4097, 8, 0, /* 1025: pointer.func */
            0, 1, 0, /* 1028: char */
            4097, 8, 0, /* 1031: pointer.func */
            4097, 8, 0, /* 1034: pointer.func */
            1, 8, 1, /* 1037: pointer.struct.stack_st_X509_LOOKUP */
            	1042, 0,
            0, 32, 1, /* 1042: struct.stack_st_X509_LOOKUP */
            	5, 0,
            0, 32, 1, /* 1047: struct.stack_st_SSL_CIPHER */
            	5, 0,
            1, 8, 1, /* 1052: pointer.struct.x509_store_st */
            	1057, 0,
            0, 144, 15, /* 1057: struct.x509_store_st */
            	1090, 8,
            	1037, 16,
            	1100, 24,
            	1112, 32,
            	1115, 40,
            	1022, 48,
            	1118, 56,
            	1112, 64,
            	1121, 72,
            	1031, 80,
            	1124, 88,
            	979, 96,
            	1127, 104,
            	1112, 112,
            	562, 120,
            1, 8, 1, /* 1090: pointer.struct.stack_st_X509_OBJECT */
            	1095, 0,
            0, 32, 1, /* 1095: struct.stack_st_X509_OBJECT */
            	5, 0,
            1, 8, 1, /* 1100: pointer.struct.X509_VERIFY_PARAM_st */
            	1105, 0,
            0, 56, 2, /* 1105: struct.X509_VERIFY_PARAM_st */
            	17, 0,
            	839, 48,
            4097, 8, 0, /* 1112: pointer.func */
            4097, 8, 0, /* 1115: pointer.func */
            4097, 8, 0, /* 1118: pointer.func */
            4097, 8, 0, /* 1121: pointer.func */
            4097, 8, 0, /* 1124: pointer.func */
            4097, 8, 0, /* 1127: pointer.func */
            4097, 8, 0, /* 1130: pointer.func */
            4097, 8, 0, /* 1133: pointer.func */
            0, 248, 5, /* 1136: struct.sess_cert_st */
            	1149, 0,
            	76, 16,
            	904, 216,
            	912, 224,
            	917, 232,
            1, 8, 1, /* 1149: pointer.struct.stack_st_X509 */
            	1154, 0,
            0, 32, 1, /* 1154: struct.stack_st_X509 */
            	5, 0,
            4097, 8, 0, /* 1159: pointer.func */
            4097, 8, 0, /* 1162: pointer.func */
            4097, 8, 0, /* 1165: pointer.func */
            4097, 8, 0, /* 1168: pointer.func */
            4097, 8, 0, /* 1171: pointer.func */
            4097, 8, 0, /* 1174: pointer.func */
            1, 8, 1, /* 1177: pointer.struct.ssl_method_st */
            	1182, 0,
            0, 232, 28, /* 1182: struct.ssl_method_st */
            	1241, 8,
            	1025, 16,
            	1025, 24,
            	1241, 32,
            	1241, 40,
            	1133, 48,
            	1133, 56,
            	1244, 64,
            	1241, 72,
            	1241, 80,
            	1241, 88,
            	1247, 96,
            	1171, 104,
            	1250, 112,
            	1241, 120,
            	1253, 128,
            	1256, 136,
            	1259, 144,
            	1262, 152,
            	1265, 160,
            	1268, 168,
            	1271, 176,
            	1274, 184,
            	1277, 192,
            	1280, 200,
            	1268, 208,
            	1165, 216,
            	1325, 224,
            4097, 8, 0, /* 1241: pointer.func */
            4097, 8, 0, /* 1244: pointer.func */
            4097, 8, 0, /* 1247: pointer.func */
            4097, 8, 0, /* 1250: pointer.func */
            4097, 8, 0, /* 1253: pointer.func */
            4097, 8, 0, /* 1256: pointer.func */
            4097, 8, 0, /* 1259: pointer.func */
            4097, 8, 0, /* 1262: pointer.func */
            4097, 8, 0, /* 1265: pointer.func */
            4097, 8, 0, /* 1268: pointer.func */
            4097, 8, 0, /* 1271: pointer.func */
            4097, 8, 0, /* 1274: pointer.func */
            4097, 8, 0, /* 1277: pointer.func */
            1, 8, 1, /* 1280: pointer.struct.ssl3_enc_method */
            	1285, 0,
            0, 112, 11, /* 1285: struct.ssl3_enc_method */
            	1174, 0,
            	1310, 8,
            	1241, 16,
            	1313, 24,
            	1174, 32,
            	1316, 40,
            	1319, 56,
            	196, 64,
            	196, 80,
            	1162, 96,
            	1322, 104,
            4097, 8, 0, /* 1310: pointer.func */
            4097, 8, 0, /* 1313: pointer.func */
            4097, 8, 0, /* 1316: pointer.func */
            4097, 8, 0, /* 1319: pointer.func */
            4097, 8, 0, /* 1322: pointer.func */
            4097, 8, 0, /* 1325: pointer.func */
            1, 8, 1, /* 1328: pointer.struct.ssl_ctx_st */
            	1333, 0,
            0, 736, 50, /* 1333: struct.ssl_ctx_st */
            	1177, 0,
            	1436, 8,
            	1436, 16,
            	1052, 24,
            	1441, 32,
            	1446, 48,
            	1446, 56,
            	965, 80,
            	957, 88,
            	1487, 96,
            	1034, 152,
            	1008, 160,
            	1490, 168,
            	1008, 176,
            	968, 184,
            	949, 192,
            	946, 200,
            	562, 208,
            	859, 224,
            	859, 232,
            	859, 240,
            	1149, 248,
            	936, 256,
            	933, 264,
            	1493, 272,
            	54, 304,
            	1168, 320,
            	1008, 328,
            	1115, 376,
            	1498, 384,
            	1100, 392,
            	426, 408,
            	1019, 416,
            	1008, 424,
            	1501, 480,
            	1130, 488,
            	1008, 496,
            	1504, 504,
            	1008, 512,
            	17, 520,
            	925, 528,
            	48, 536,
            	974, 552,
            	974, 560,
            	1507, 568,
            	30, 696,
            	1008, 704,
            	971, 712,
            	1008, 720,
            	25, 728,
            1, 8, 1, /* 1436: pointer.struct.stack_st_SSL_CIPHER */
            	1047, 0,
            1, 8, 1, /* 1441: pointer.struct.lhash_st */
            	982, 0,
            1, 8, 1, /* 1446: pointer.struct.ssl_session_st */
            	1451, 0,
            0, 352, 14, /* 1451: struct.ssl_session_st */
            	17, 144,
            	17, 152,
            	1482, 168,
            	90, 176,
            	960, 224,
            	1436, 240,
            	562, 248,
            	1446, 264,
            	1446, 272,
            	17, 280,
            	162, 296,
            	162, 312,
            	162, 320,
            	17, 344,
            1, 8, 1, /* 1482: pointer.struct.sess_cert_st */
            	1136, 0,
            4097, 8, 0, /* 1487: pointer.func */
            4097, 8, 0, /* 1490: pointer.func */
            1, 8, 1, /* 1493: pointer.struct.stack_st_X509_NAME */
            	928, 0,
            4097, 8, 0, /* 1498: pointer.func */
            4097, 8, 0, /* 1501: pointer.func */
            4097, 8, 0, /* 1504: pointer.func */
            0, 128, 14, /* 1507: struct.srp_ctx_st */
            	1008, 0,
            	1019, 8,
            	1130, 16,
            	1159, 24,
            	17, 32,
            	544, 40,
            	544, 48,
            	544, 56,
            	544, 64,
            	544, 72,
            	544, 80,
            	544, 88,
            	544, 96,
            	17, 104,
            0, 4, 0, /* 1538: int */
        },
        .arg_entity_index = { 1328, 196, },
        .ret_entity_index = 1538,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    const char * new_arg_b = *((const char * *)new_args->args[1]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_SSL_CTX_use_certificate_chain_file)(SSL_CTX *,const char *);
    orig_SSL_CTX_use_certificate_chain_file = dlsym(RTLD_NEXT, "SSL_CTX_use_certificate_chain_file");
    *new_ret_ptr = (*orig_SSL_CTX_use_certificate_chain_file)(new_arg_a,new_arg_b);

    syscall(889);

    return ret;
}

