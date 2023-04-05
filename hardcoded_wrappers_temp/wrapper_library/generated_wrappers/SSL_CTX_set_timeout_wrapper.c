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

long bb_SSL_CTX_set_timeout(SSL_CTX * arg_a,long arg_b);

long SSL_CTX_set_timeout(SSL_CTX * arg_a,long arg_b) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_set_timeout called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_CTX_set_timeout(arg_a,arg_b);
    else {
        long (*orig_SSL_CTX_set_timeout)(SSL_CTX *,long);
        orig_SSL_CTX_set_timeout = dlsym(RTLD_NEXT, "SSL_CTX_set_timeout");
        return orig_SSL_CTX_set_timeout(arg_a,arg_b);
    }
}

long bb_SSL_CTX_set_timeout(SSL_CTX * arg_a,long arg_b) 
{
    long ret;

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
            4097, 8, 0, /* 33: pointer.func */
            0, 8, 1, /* 36: struct.ssl3_buf_freelist_entry_st */
            	41, 0,
            1, 8, 1, /* 41: pointer.struct.ssl3_buf_freelist_entry_st */
            	36, 0,
            4097, 8, 0, /* 46: pointer.func */
            4097, 8, 0, /* 49: pointer.func */
            4097, 8, 0, /* 52: pointer.func */
            4097, 8, 0, /* 55: pointer.func */
            0, 296, 7, /* 58: struct.cert_st */
            	75, 0,
            	903, 48,
            	908, 56,
            	911, 64,
            	55, 72,
            	916, 80,
            	921, 88,
            1, 8, 1, /* 75: pointer.struct.cert_pkey_st */
            	80, 0,
            0, 24, 3, /* 80: struct.cert_pkey_st */
            	89, 0,
            	401, 8,
            	858, 16,
            1, 8, 1, /* 89: pointer.struct.x509_st */
            	94, 0,
            0, 184, 12, /* 94: struct.x509_st */
            	121, 0,
            	169, 8,
            	268, 16,
            	17, 32,
            	561, 40,
            	273, 104,
            	780, 112,
            	788, 120,
            	796, 128,
            	804, 136,
            	812, 144,
            	820, 176,
            1, 8, 1, /* 121: pointer.struct.x509_cinf_st */
            	126, 0,
            0, 104, 11, /* 126: struct.x509_cinf_st */
            	151, 0,
            	151, 8,
            	169, 16,
            	336, 24,
            	370, 32,
            	336, 40,
            	387, 48,
            	268, 56,
            	268, 64,
            	765, 72,
            	775, 80,
            1, 8, 1, /* 151: pointer.struct.asn1_string_st */
            	156, 0,
            0, 24, 1, /* 156: struct.asn1_string_st */
            	161, 8,
            1, 8, 1, /* 161: pointer.unsigned char */
            	166, 0,
            0, 1, 0, /* 166: unsigned char */
            1, 8, 1, /* 169: pointer.struct.X509_algor_st */
            	174, 0,
            0, 16, 2, /* 174: struct.X509_algor_st */
            	181, 0,
            	205, 8,
            1, 8, 1, /* 181: pointer.struct.asn1_object_st */
            	186, 0,
            0, 40, 3, /* 186: struct.asn1_object_st */
            	195, 0,
            	195, 8,
            	200, 24,
            1, 8, 1, /* 195: pointer.char */
            	4096, 0,
            1, 8, 1, /* 200: pointer.unsigned char */
            	166, 0,
            1, 8, 1, /* 205: pointer.struct.asn1_type_st */
            	210, 0,
            0, 16, 1, /* 210: struct.asn1_type_st */
            	215, 8,
            0, 8, 20, /* 215: union.unknown */
            	17, 0,
            	258, 0,
            	181, 0,
            	151, 0,
            	263, 0,
            	268, 0,
            	273, 0,
            	278, 0,
            	283, 0,
            	288, 0,
            	293, 0,
            	298, 0,
            	303, 0,
            	308, 0,
            	313, 0,
            	318, 0,
            	323, 0,
            	258, 0,
            	258, 0,
            	328, 0,
            1, 8, 1, /* 258: pointer.struct.asn1_string_st */
            	156, 0,
            1, 8, 1, /* 263: pointer.struct.asn1_string_st */
            	156, 0,
            1, 8, 1, /* 268: pointer.struct.asn1_string_st */
            	156, 0,
            1, 8, 1, /* 273: pointer.struct.asn1_string_st */
            	156, 0,
            1, 8, 1, /* 278: pointer.struct.asn1_string_st */
            	156, 0,
            1, 8, 1, /* 283: pointer.struct.asn1_string_st */
            	156, 0,
            1, 8, 1, /* 288: pointer.struct.asn1_string_st */
            	156, 0,
            1, 8, 1, /* 293: pointer.struct.asn1_string_st */
            	156, 0,
            1, 8, 1, /* 298: pointer.struct.asn1_string_st */
            	156, 0,
            1, 8, 1, /* 303: pointer.struct.asn1_string_st */
            	156, 0,
            1, 8, 1, /* 308: pointer.struct.asn1_string_st */
            	156, 0,
            1, 8, 1, /* 313: pointer.struct.asn1_string_st */
            	156, 0,
            1, 8, 1, /* 318: pointer.struct.asn1_string_st */
            	156, 0,
            1, 8, 1, /* 323: pointer.struct.asn1_string_st */
            	156, 0,
            1, 8, 1, /* 328: pointer.struct.ASN1_VALUE_st */
            	333, 0,
            0, 0, 0, /* 333: struct.ASN1_VALUE_st */
            1, 8, 1, /* 336: pointer.struct.X509_name_st */
            	341, 0,
            0, 40, 3, /* 341: struct.X509_name_st */
            	350, 0,
            	360, 16,
            	161, 24,
            1, 8, 1, /* 350: pointer.struct.stack_st_X509_NAME_ENTRY */
            	355, 0,
            0, 32, 1, /* 355: struct.stack_st_X509_NAME_ENTRY */
            	5, 0,
            1, 8, 1, /* 360: pointer.struct.buf_mem_st */
            	365, 0,
            0, 24, 1, /* 365: struct.buf_mem_st */
            	17, 8,
            1, 8, 1, /* 370: pointer.struct.X509_val_st */
            	375, 0,
            0, 16, 2, /* 375: struct.X509_val_st */
            	382, 0,
            	382, 8,
            1, 8, 1, /* 382: pointer.struct.asn1_string_st */
            	156, 0,
            1, 8, 1, /* 387: pointer.struct.X509_pubkey_st */
            	392, 0,
            0, 24, 3, /* 392: struct.X509_pubkey_st */
            	169, 0,
            	268, 8,
            	401, 16,
            1, 8, 1, /* 401: pointer.struct.evp_pkey_st */
            	406, 0,
            0, 56, 4, /* 406: struct.evp_pkey_st */
            	417, 16,
            	425, 24,
            	433, 32,
            	755, 48,
            1, 8, 1, /* 417: pointer.struct.evp_pkey_asn1_method_st */
            	422, 0,
            0, 0, 0, /* 422: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 425: pointer.struct.engine_st */
            	430, 0,
            0, 0, 0, /* 430: struct.engine_st */
            0, 8, 5, /* 433: union.unknown */
            	17, 0,
            	446, 0,
            	598, 0,
            	679, 0,
            	747, 0,
            1, 8, 1, /* 446: pointer.struct.rsa_st */
            	451, 0,
            0, 168, 17, /* 451: struct.rsa_st */
            	488, 16,
            	425, 24,
            	543, 32,
            	543, 40,
            	543, 48,
            	543, 56,
            	543, 64,
            	543, 72,
            	543, 80,
            	543, 88,
            	561, 96,
            	576, 120,
            	576, 128,
            	576, 136,
            	17, 144,
            	590, 152,
            	590, 160,
            1, 8, 1, /* 488: pointer.struct.rsa_meth_st */
            	493, 0,
            0, 112, 13, /* 493: struct.rsa_meth_st */
            	195, 0,
            	522, 8,
            	522, 16,
            	522, 24,
            	522, 32,
            	525, 40,
            	528, 48,
            	531, 56,
            	531, 64,
            	17, 80,
            	534, 88,
            	537, 96,
            	540, 104,
            4097, 8, 0, /* 522: pointer.func */
            4097, 8, 0, /* 525: pointer.func */
            4097, 8, 0, /* 528: pointer.func */
            4097, 8, 0, /* 531: pointer.func */
            4097, 8, 0, /* 534: pointer.func */
            4097, 8, 0, /* 537: pointer.func */
            4097, 8, 0, /* 540: pointer.func */
            1, 8, 1, /* 543: pointer.struct.bignum_st */
            	548, 0,
            0, 24, 1, /* 548: struct.bignum_st */
            	553, 0,
            1, 8, 1, /* 553: pointer.unsigned int */
            	558, 0,
            0, 4, 0, /* 558: unsigned int */
            0, 16, 1, /* 561: struct.crypto_ex_data_st */
            	566, 0,
            1, 8, 1, /* 566: pointer.struct.stack_st_void */
            	571, 0,
            0, 32, 1, /* 571: struct.stack_st_void */
            	5, 0,
            1, 8, 1, /* 576: pointer.struct.bn_mont_ctx_st */
            	581, 0,
            0, 96, 3, /* 581: struct.bn_mont_ctx_st */
            	548, 8,
            	548, 32,
            	548, 56,
            1, 8, 1, /* 590: pointer.struct.bn_blinding_st */
            	595, 0,
            0, 0, 0, /* 595: struct.bn_blinding_st */
            1, 8, 1, /* 598: pointer.struct.dsa_st */
            	603, 0,
            0, 136, 11, /* 603: struct.dsa_st */
            	543, 24,
            	543, 32,
            	543, 40,
            	543, 48,
            	543, 56,
            	543, 64,
            	543, 72,
            	576, 88,
            	561, 104,
            	628, 120,
            	425, 128,
            1, 8, 1, /* 628: pointer.struct.dsa_method */
            	633, 0,
            0, 96, 11, /* 633: struct.dsa_method */
            	195, 0,
            	658, 8,
            	661, 16,
            	664, 24,
            	667, 32,
            	670, 40,
            	673, 48,
            	673, 56,
            	17, 72,
            	676, 80,
            	673, 88,
            4097, 8, 0, /* 658: pointer.func */
            4097, 8, 0, /* 661: pointer.func */
            4097, 8, 0, /* 664: pointer.func */
            4097, 8, 0, /* 667: pointer.func */
            4097, 8, 0, /* 670: pointer.func */
            4097, 8, 0, /* 673: pointer.func */
            4097, 8, 0, /* 676: pointer.func */
            1, 8, 1, /* 679: pointer.struct.dh_st */
            	684, 0,
            0, 144, 12, /* 684: struct.dh_st */
            	543, 8,
            	543, 16,
            	543, 32,
            	543, 40,
            	576, 56,
            	543, 64,
            	543, 72,
            	161, 80,
            	543, 96,
            	561, 112,
            	711, 128,
            	425, 136,
            1, 8, 1, /* 711: pointer.struct.dh_method */
            	716, 0,
            0, 72, 8, /* 716: struct.dh_method */
            	195, 0,
            	735, 8,
            	738, 16,
            	741, 24,
            	735, 32,
            	735, 40,
            	17, 56,
            	744, 64,
            4097, 8, 0, /* 735: pointer.func */
            4097, 8, 0, /* 738: pointer.func */
            4097, 8, 0, /* 741: pointer.func */
            4097, 8, 0, /* 744: pointer.func */
            1, 8, 1, /* 747: pointer.struct.ec_key_st */
            	752, 0,
            0, 0, 0, /* 752: struct.ec_key_st */
            1, 8, 1, /* 755: pointer.struct.stack_st_X509_ATTRIBUTE */
            	760, 0,
            0, 32, 1, /* 760: struct.stack_st_X509_ATTRIBUTE */
            	5, 0,
            1, 8, 1, /* 765: pointer.struct.stack_st_X509_EXTENSION */
            	770, 0,
            0, 32, 1, /* 770: struct.stack_st_X509_EXTENSION */
            	5, 0,
            0, 24, 1, /* 775: struct.ASN1_ENCODING_st */
            	161, 0,
            1, 8, 1, /* 780: pointer.struct.AUTHORITY_KEYID_st */
            	785, 0,
            0, 0, 0, /* 785: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 788: pointer.struct.X509_POLICY_CACHE_st */
            	793, 0,
            0, 0, 0, /* 793: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 796: pointer.struct.stack_st_DIST_POINT */
            	801, 0,
            0, 0, 0, /* 801: struct.stack_st_DIST_POINT */
            1, 8, 1, /* 804: pointer.struct.stack_st_GENERAL_NAME */
            	809, 0,
            0, 0, 0, /* 809: struct.stack_st_GENERAL_NAME */
            1, 8, 1, /* 812: pointer.struct.NAME_CONSTRAINTS_st */
            	817, 0,
            0, 0, 0, /* 817: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 820: pointer.struct.x509_cert_aux_st */
            	825, 0,
            0, 40, 5, /* 825: struct.x509_cert_aux_st */
            	838, 0,
            	838, 8,
            	323, 16,
            	273, 24,
            	848, 32,
            1, 8, 1, /* 838: pointer.struct.stack_st_ASN1_OBJECT */
            	843, 0,
            0, 32, 1, /* 843: struct.stack_st_ASN1_OBJECT */
            	5, 0,
            1, 8, 1, /* 848: pointer.struct.stack_st_X509_ALGOR */
            	853, 0,
            0, 32, 1, /* 853: struct.stack_st_X509_ALGOR */
            	5, 0,
            1, 8, 1, /* 858: pointer.struct.env_md_st */
            	863, 0,
            0, 120, 8, /* 863: struct.env_md_st */
            	882, 24,
            	885, 32,
            	888, 40,
            	891, 48,
            	882, 56,
            	894, 64,
            	897, 72,
            	900, 112,
            4097, 8, 0, /* 882: pointer.func */
            4097, 8, 0, /* 885: pointer.func */
            4097, 8, 0, /* 888: pointer.func */
            4097, 8, 0, /* 891: pointer.func */
            4097, 8, 0, /* 894: pointer.func */
            4097, 8, 0, /* 897: pointer.func */
            4097, 8, 0, /* 900: pointer.func */
            1, 8, 1, /* 903: pointer.struct.rsa_st */
            	451, 0,
            4097, 8, 0, /* 908: pointer.func */
            1, 8, 1, /* 911: pointer.struct.dh_st */
            	684, 0,
            1, 8, 1, /* 916: pointer.struct.ec_key_st */
            	752, 0,
            4097, 8, 0, /* 921: pointer.func */
            0, 32, 1, /* 924: struct.stack_st_X509_NAME */
            	5, 0,
            4097, 8, 0, /* 929: pointer.func */
            4097, 8, 0, /* 932: pointer.func */
            4097, 8, 0, /* 935: pointer.func */
            4097, 8, 0, /* 938: pointer.func */
            4097, 8, 0, /* 941: pointer.func */
            4097, 8, 0, /* 944: pointer.func */
            0, 88, 1, /* 947: struct.ssl_cipher_st */
            	195, 8,
            0, 24, 1, /* 952: struct.ssl3_buf_freelist_st */
            	41, 16,
            4097, 8, 0, /* 957: pointer.func */
            4097, 8, 0, /* 960: pointer.func */
            4097, 8, 0, /* 963: pointer.func */
            1, 8, 1, /* 966: pointer.struct.ssl3_buf_freelist_st */
            	952, 0,
            0, 112, 11, /* 971: struct.ssl3_enc_method */
            	996, 0,
            	999, 8,
            	1002, 16,
            	1005, 24,
            	996, 32,
            	1008, 40,
            	1011, 56,
            	195, 64,
            	195, 80,
            	1014, 96,
            	1017, 104,
            4097, 8, 0, /* 996: pointer.func */
            4097, 8, 0, /* 999: pointer.func */
            4097, 8, 0, /* 1002: pointer.func */
            4097, 8, 0, /* 1005: pointer.func */
            4097, 8, 0, /* 1008: pointer.func */
            4097, 8, 0, /* 1011: pointer.func */
            4097, 8, 0, /* 1014: pointer.func */
            4097, 8, 0, /* 1017: pointer.func */
            4097, 8, 0, /* 1020: pointer.func */
            0, 56, 2, /* 1023: struct.X509_VERIFY_PARAM_st */
            	17, 0,
            	838, 48,
            1, 8, 1, /* 1030: pointer.struct.ssl_cipher_st */
            	947, 0,
            0, 32, 1, /* 1035: struct.stack_st_X509_OBJECT */
            	5, 0,
            1, 8, 1, /* 1040: pointer.struct.cert_st */
            	58, 0,
            4097, 8, 0, /* 1045: pointer.func */
            1, 8, 1, /* 1048: pointer.struct.stack_st_X509_OBJECT */
            	1035, 0,
            0, 144, 15, /* 1053: struct.x509_store_st */
            	1048, 8,
            	1086, 16,
            	1096, 24,
            	1101, 32,
            	1104, 40,
            	1107, 48,
            	1110, 56,
            	1101, 64,
            	1113, 72,
            	1116, 80,
            	1119, 88,
            	1045, 96,
            	1122, 104,
            	1101, 112,
            	561, 120,
            1, 8, 1, /* 1086: pointer.struct.stack_st_X509_LOOKUP */
            	1091, 0,
            0, 32, 1, /* 1091: struct.stack_st_X509_LOOKUP */
            	5, 0,
            1, 8, 1, /* 1096: pointer.struct.X509_VERIFY_PARAM_st */
            	1023, 0,
            4097, 8, 0, /* 1101: pointer.func */
            4097, 8, 0, /* 1104: pointer.func */
            4097, 8, 0, /* 1107: pointer.func */
            4097, 8, 0, /* 1110: pointer.func */
            4097, 8, 0, /* 1113: pointer.func */
            4097, 8, 0, /* 1116: pointer.func */
            4097, 8, 0, /* 1119: pointer.func */
            4097, 8, 0, /* 1122: pointer.func */
            1, 8, 1, /* 1125: pointer.struct.stack_st_X509_NAME */
            	924, 0,
            0, 32, 1, /* 1130: struct.stack_st_SSL_COMP */
            	5, 0,
            1, 8, 1, /* 1135: pointer.struct.ssl3_enc_method */
            	971, 0,
            0, 32, 1, /* 1140: struct.stack_st_SSL_CIPHER */
            	5, 0,
            4097, 8, 0, /* 1145: pointer.func */
            4097, 8, 0, /* 1148: pointer.func */
            0, 232, 28, /* 1151: struct.ssl_method_st */
            	1002, 8,
            	1210, 16,
            	1210, 24,
            	1002, 32,
            	1002, 40,
            	1213, 48,
            	1213, 56,
            	1216, 64,
            	1002, 72,
            	1002, 80,
            	1002, 88,
            	1145, 96,
            	1219, 104,
            	1222, 112,
            	1002, 120,
            	1225, 128,
            	1228, 136,
            	1231, 144,
            	1234, 152,
            	1237, 160,
            	1240, 168,
            	1243, 176,
            	1246, 184,
            	1249, 192,
            	1135, 200,
            	1240, 208,
            	1148, 216,
            	1252, 224,
            4097, 8, 0, /* 1210: pointer.func */
            4097, 8, 0, /* 1213: pointer.func */
            4097, 8, 0, /* 1216: pointer.func */
            4097, 8, 0, /* 1219: pointer.func */
            4097, 8, 0, /* 1222: pointer.func */
            4097, 8, 0, /* 1225: pointer.func */
            4097, 8, 0, /* 1228: pointer.func */
            4097, 8, 0, /* 1231: pointer.func */
            4097, 8, 0, /* 1234: pointer.func */
            4097, 8, 0, /* 1237: pointer.func */
            4097, 8, 0, /* 1240: pointer.func */
            4097, 8, 0, /* 1243: pointer.func */
            4097, 8, 0, /* 1246: pointer.func */
            4097, 8, 0, /* 1249: pointer.func */
            4097, 8, 0, /* 1252: pointer.func */
            4097, 8, 0, /* 1255: pointer.func */
            1, 8, 1, /* 1258: pointer.struct.stack_st_SSL_CIPHER */
            	1140, 0,
            1, 8, 1, /* 1263: pointer.struct.x509_store_st */
            	1053, 0,
            1, 8, 1, /* 1268: pointer.struct.lhash_node_st */
            	1273, 0,
            0, 24, 2, /* 1273: struct.lhash_node_st */
            	1280, 0,
            	1283, 8,
            0, 8, 0, /* 1280: pointer.void */
            1, 8, 1, /* 1283: pointer.struct.lhash_node_st */
            	1273, 0,
            0, 736, 50, /* 1288: struct.ssl_ctx_st */
            	1391, 0,
            	1258, 8,
            	1258, 16,
            	1263, 24,
            	1396, 32,
            	1418, 48,
            	1418, 56,
            	957, 80,
            	1482, 88,
            	944, 96,
            	941, 152,
            	1280, 160,
            	938, 168,
            	1280, 176,
            	1485, 184,
            	935, 192,
            	932, 200,
            	561, 208,
            	858, 224,
            	858, 232,
            	858, 240,
            	1472, 248,
            	1488, 256,
            	929, 264,
            	1125, 272,
            	1040, 304,
            	1493, 320,
            	1280, 328,
            	1104, 376,
            	960, 384,
            	1096, 392,
            	425, 408,
            	1255, 416,
            	1280, 424,
            	1020, 480,
            	52, 488,
            	1280, 496,
            	963, 504,
            	1280, 512,
            	17, 520,
            	49, 528,
            	46, 536,
            	966, 552,
            	966, 560,
            	1496, 568,
            	1527, 696,
            	1280, 704,
            	30, 712,
            	1280, 720,
            	25, 728,
            1, 8, 1, /* 1391: pointer.struct.ssl_method_st */
            	1151, 0,
            1, 8, 1, /* 1396: pointer.struct.lhash_st */
            	1401, 0,
            0, 176, 3, /* 1401: struct.lhash_st */
            	1410, 0,
            	22, 8,
            	1415, 16,
            1, 8, 1, /* 1410: pointer.pointer.struct.lhash_node_st */
            	1268, 0,
            4097, 8, 0, /* 1415: pointer.func */
            1, 8, 1, /* 1418: pointer.struct.ssl_session_st */
            	1423, 0,
            0, 352, 14, /* 1423: struct.ssl_session_st */
            	17, 144,
            	17, 152,
            	1454, 168,
            	89, 176,
            	1030, 224,
            	1258, 240,
            	561, 248,
            	1418, 264,
            	1418, 272,
            	17, 280,
            	161, 296,
            	161, 312,
            	161, 320,
            	17, 344,
            1, 8, 1, /* 1454: pointer.struct.sess_cert_st */
            	1459, 0,
            0, 248, 5, /* 1459: struct.sess_cert_st */
            	1472, 0,
            	75, 16,
            	903, 216,
            	911, 224,
            	916, 232,
            1, 8, 1, /* 1472: pointer.struct.stack_st_X509 */
            	1477, 0,
            0, 32, 1, /* 1477: struct.stack_st_X509 */
            	5, 0,
            4097, 8, 0, /* 1482: pointer.func */
            4097, 8, 0, /* 1485: pointer.func */
            1, 8, 1, /* 1488: pointer.struct.stack_st_SSL_COMP */
            	1130, 0,
            4097, 8, 0, /* 1493: pointer.func */
            0, 128, 14, /* 1496: struct.srp_ctx_st */
            	1280, 0,
            	1255, 8,
            	52, 16,
            	33, 24,
            	17, 32,
            	543, 40,
            	543, 48,
            	543, 56,
            	543, 64,
            	543, 72,
            	543, 80,
            	543, 88,
            	543, 96,
            	17, 104,
            4097, 8, 0, /* 1527: pointer.func */
            1, 8, 1, /* 1530: pointer.struct.ssl_ctx_st */
            	1288, 0,
            0, 8, 0, /* 1535: long int */
            0, 1, 0, /* 1538: char */
        },
        .arg_entity_index = { 1530, 1535, },
        .ret_entity_index = 1535,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    long new_arg_b = *((long *)new_args->args[1]);

    long *new_ret_ptr = (long *)new_args->ret;

    long (*orig_SSL_CTX_set_timeout)(SSL_CTX *,long);
    orig_SSL_CTX_set_timeout = dlsym(RTLD_NEXT, "SSL_CTX_set_timeout");
    *new_ret_ptr = (*orig_SSL_CTX_set_timeout)(new_arg_a,new_arg_b);

    syscall(889);

    return ret;
}

