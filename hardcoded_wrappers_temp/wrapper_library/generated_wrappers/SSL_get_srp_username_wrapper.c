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

char * bb_SSL_get_srp_username(SSL * arg_a);

char * SSL_get_srp_username(SSL * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_get_srp_username called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_get_srp_username(arg_a);
    else {
        char * (*orig_SSL_get_srp_username)(SSL *);
        orig_SSL_get_srp_username = dlsym(RTLD_NEXT, "SSL_get_srp_username");
        return orig_SSL_get_srp_username(arg_a);
    }
}

char * bb_SSL_get_srp_username(SSL * arg_a) 
{
    char * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.struct.srtp_protection_profile_st */
            	5, 0,
            0, 16, 1, /* 5: struct.srtp_protection_profile_st */
            	10, 0,
            1, 8, 1, /* 10: pointer.char */
            	4096, 0,
            0, 16, 1, /* 15: struct.tls_session_ticket_ext_st */
            	20, 8,
            0, 8, 0, /* 20: pointer.void */
            1, 8, 1, /* 23: pointer.struct.tls_session_ticket_ext_st */
            	15, 0,
            1, 8, 1, /* 28: pointer.struct.stack_st_X509_EXTENSION */
            	33, 0,
            0, 32, 1, /* 33: struct.stack_st_X509_EXTENSION */
            	38, 0,
            0, 32, 2, /* 38: struct.stack_st */
            	45, 8,
            	55, 24,
            1, 8, 1, /* 45: pointer.pointer.char */
            	50, 0,
            1, 8, 1, /* 50: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 55: pointer.func */
            0, 0, 0, /* 58: struct.stack_st_OCSP_RESPID */
            4097, 8, 0, /* 61: pointer.func */
            1, 8, 1, /* 64: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	69, 0,
            0, 32, 1, /* 69: struct.stack_st_SRTP_PROTECTION_PROFILE */
            	38, 0,
            4097, 8, 0, /* 74: pointer.func */
            4097, 8, 0, /* 77: pointer.func */
            0, 8, 1, /* 80: struct.ssl3_buf_freelist_entry_st */
            	85, 0,
            1, 8, 1, /* 85: pointer.struct.ssl3_buf_freelist_entry_st */
            	80, 0,
            0, 24, 1, /* 90: struct.ssl3_buf_freelist_st */
            	85, 16,
            4097, 8, 0, /* 95: pointer.func */
            4097, 8, 0, /* 98: pointer.func */
            0, 32, 1, /* 101: struct.stack_st_SSL_COMP */
            	38, 0,
            1, 8, 1, /* 106: pointer.struct.stack_st_SSL_COMP */
            	101, 0,
            4097, 8, 0, /* 111: pointer.func */
            4097, 8, 0, /* 114: pointer.func */
            4097, 8, 0, /* 117: pointer.func */
            4097, 8, 0, /* 120: pointer.func */
            1, 8, 1, /* 123: pointer.struct.lhash_node_st */
            	128, 0,
            0, 24, 2, /* 128: struct.lhash_node_st */
            	20, 0,
            	123, 8,
            1, 8, 1, /* 135: pointer.struct.lhash_st */
            	140, 0,
            0, 176, 3, /* 140: struct.lhash_st */
            	149, 0,
            	55, 8,
            	159, 16,
            1, 8, 1, /* 149: pointer.pointer.struct.lhash_node_st */
            	154, 0,
            1, 8, 1, /* 154: pointer.struct.lhash_node_st */
            	128, 0,
            4097, 8, 0, /* 159: pointer.func */
            4097, 8, 0, /* 162: pointer.func */
            4097, 8, 0, /* 165: pointer.func */
            0, 0, 0, /* 168: struct.stack_st_DIST_POINT */
            0, 56, 2, /* 171: struct.comp_ctx_st */
            	178, 0,
            	212, 40,
            1, 8, 1, /* 178: pointer.struct.comp_method_st */
            	183, 0,
            0, 64, 7, /* 183: struct.comp_method_st */
            	10, 8,
            	200, 16,
            	203, 24,
            	206, 32,
            	206, 40,
            	209, 48,
            	209, 56,
            4097, 8, 0, /* 200: pointer.func */
            4097, 8, 0, /* 203: pointer.func */
            4097, 8, 0, /* 206: pointer.func */
            4097, 8, 0, /* 209: pointer.func */
            0, 16, 1, /* 212: struct.crypto_ex_data_st */
            	217, 0,
            1, 8, 1, /* 217: pointer.struct.stack_st_void */
            	222, 0,
            0, 32, 1, /* 222: struct.stack_st_void */
            	38, 0,
            1, 8, 1, /* 227: pointer.struct.comp_ctx_st */
            	171, 0,
            0, 168, 4, /* 232: struct.evp_cipher_ctx_st */
            	243, 0,
            	280, 8,
            	20, 96,
            	20, 120,
            1, 8, 1, /* 243: pointer.struct.evp_cipher_st */
            	248, 0,
            0, 88, 7, /* 248: struct.evp_cipher_st */
            	265, 24,
            	268, 32,
            	271, 40,
            	274, 56,
            	274, 64,
            	277, 72,
            	20, 80,
            4097, 8, 0, /* 265: pointer.func */
            4097, 8, 0, /* 268: pointer.func */
            4097, 8, 0, /* 271: pointer.func */
            4097, 8, 0, /* 274: pointer.func */
            4097, 8, 0, /* 277: pointer.func */
            1, 8, 1, /* 280: pointer.struct.engine_st */
            	285, 0,
            0, 0, 0, /* 285: struct.engine_st */
            0, 16, 1, /* 288: struct.record_pqueue_st */
            	293, 8,
            1, 8, 1, /* 293: pointer.struct._pqueue */
            	298, 0,
            0, 0, 0, /* 298: struct._pqueue */
            4097, 8, 0, /* 301: pointer.func */
            4097, 8, 0, /* 304: pointer.func */
            4097, 8, 0, /* 307: pointer.func */
            4097, 8, 0, /* 310: pointer.func */
            1, 8, 1, /* 313: pointer.struct.stack_st_X509_NAME_ENTRY */
            	318, 0,
            0, 32, 1, /* 318: struct.stack_st_X509_NAME_ENTRY */
            	38, 0,
            4097, 8, 0, /* 323: pointer.func */
            0, 0, 0, /* 326: struct.ec_key_st */
            4097, 8, 0, /* 329: pointer.func */
            1, 8, 1, /* 332: pointer.struct.bio_st */
            	337, 0,
            0, 112, 7, /* 337: struct.bio_st */
            	354, 0,
            	398, 8,
            	50, 16,
            	20, 48,
            	332, 56,
            	332, 64,
            	212, 96,
            1, 8, 1, /* 354: pointer.struct.bio_method_st */
            	359, 0,
            0, 80, 9, /* 359: struct.bio_method_st */
            	10, 8,
            	380, 16,
            	383, 24,
            	386, 32,
            	383, 40,
            	389, 48,
            	392, 56,
            	392, 64,
            	395, 72,
            4097, 8, 0, /* 380: pointer.func */
            4097, 8, 0, /* 383: pointer.func */
            4097, 8, 0, /* 386: pointer.func */
            4097, 8, 0, /* 389: pointer.func */
            4097, 8, 0, /* 392: pointer.func */
            4097, 8, 0, /* 395: pointer.func */
            4097, 8, 0, /* 398: pointer.func */
            0, 104, 11, /* 401: struct.x509_cinf_st */
            	426, 0,
            	426, 8,
            	444, 16,
            	606, 24,
            	630, 32,
            	606, 40,
            	647, 48,
            	538, 56,
            	538, 64,
            	993, 72,
            	998, 80,
            1, 8, 1, /* 426: pointer.struct.asn1_string_st */
            	431, 0,
            0, 24, 1, /* 431: struct.asn1_string_st */
            	436, 8,
            1, 8, 1, /* 436: pointer.unsigned char */
            	441, 0,
            0, 1, 0, /* 441: unsigned char */
            1, 8, 1, /* 444: pointer.struct.X509_algor_st */
            	449, 0,
            0, 16, 2, /* 449: struct.X509_algor_st */
            	456, 0,
            	475, 8,
            1, 8, 1, /* 456: pointer.struct.asn1_object_st */
            	461, 0,
            0, 40, 3, /* 461: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	470, 24,
            1, 8, 1, /* 470: pointer.unsigned char */
            	441, 0,
            1, 8, 1, /* 475: pointer.struct.asn1_type_st */
            	480, 0,
            0, 16, 1, /* 480: struct.asn1_type_st */
            	485, 8,
            0, 8, 20, /* 485: union.unknown */
            	50, 0,
            	528, 0,
            	456, 0,
            	426, 0,
            	533, 0,
            	538, 0,
            	543, 0,
            	548, 0,
            	553, 0,
            	558, 0,
            	563, 0,
            	568, 0,
            	573, 0,
            	578, 0,
            	583, 0,
            	588, 0,
            	593, 0,
            	528, 0,
            	528, 0,
            	598, 0,
            1, 8, 1, /* 528: pointer.struct.asn1_string_st */
            	431, 0,
            1, 8, 1, /* 533: pointer.struct.asn1_string_st */
            	431, 0,
            1, 8, 1, /* 538: pointer.struct.asn1_string_st */
            	431, 0,
            1, 8, 1, /* 543: pointer.struct.asn1_string_st */
            	431, 0,
            1, 8, 1, /* 548: pointer.struct.asn1_string_st */
            	431, 0,
            1, 8, 1, /* 553: pointer.struct.asn1_string_st */
            	431, 0,
            1, 8, 1, /* 558: pointer.struct.asn1_string_st */
            	431, 0,
            1, 8, 1, /* 563: pointer.struct.asn1_string_st */
            	431, 0,
            1, 8, 1, /* 568: pointer.struct.asn1_string_st */
            	431, 0,
            1, 8, 1, /* 573: pointer.struct.asn1_string_st */
            	431, 0,
            1, 8, 1, /* 578: pointer.struct.asn1_string_st */
            	431, 0,
            1, 8, 1, /* 583: pointer.struct.asn1_string_st */
            	431, 0,
            1, 8, 1, /* 588: pointer.struct.asn1_string_st */
            	431, 0,
            1, 8, 1, /* 593: pointer.struct.asn1_string_st */
            	431, 0,
            1, 8, 1, /* 598: pointer.struct.ASN1_VALUE_st */
            	603, 0,
            0, 0, 0, /* 603: struct.ASN1_VALUE_st */
            1, 8, 1, /* 606: pointer.struct.X509_name_st */
            	611, 0,
            0, 40, 3, /* 611: struct.X509_name_st */
            	313, 0,
            	620, 16,
            	436, 24,
            1, 8, 1, /* 620: pointer.struct.buf_mem_st */
            	625, 0,
            0, 24, 1, /* 625: struct.buf_mem_st */
            	50, 8,
            1, 8, 1, /* 630: pointer.struct.X509_val_st */
            	635, 0,
            0, 16, 2, /* 635: struct.X509_val_st */
            	642, 0,
            	642, 8,
            1, 8, 1, /* 642: pointer.struct.asn1_string_st */
            	431, 0,
            1, 8, 1, /* 647: pointer.struct.X509_pubkey_st */
            	652, 0,
            0, 24, 3, /* 652: struct.X509_pubkey_st */
            	444, 0,
            	538, 8,
            	661, 16,
            1, 8, 1, /* 661: pointer.struct.evp_pkey_st */
            	666, 0,
            0, 56, 4, /* 666: struct.evp_pkey_st */
            	677, 16,
            	280, 24,
            	685, 32,
            	983, 48,
            1, 8, 1, /* 677: pointer.struct.evp_pkey_asn1_method_st */
            	682, 0,
            0, 0, 0, /* 682: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 685: union.unknown */
            	50, 0,
            	698, 0,
            	832, 0,
            	913, 0,
            	978, 0,
            1, 8, 1, /* 698: pointer.struct.rsa_st */
            	703, 0,
            0, 168, 17, /* 703: struct.rsa_st */
            	740, 16,
            	280, 24,
            	792, 32,
            	792, 40,
            	792, 48,
            	792, 56,
            	792, 64,
            	792, 72,
            	792, 80,
            	792, 88,
            	212, 96,
            	810, 120,
            	810, 128,
            	810, 136,
            	50, 144,
            	824, 152,
            	824, 160,
            1, 8, 1, /* 740: pointer.struct.rsa_meth_st */
            	745, 0,
            0, 112, 13, /* 745: struct.rsa_meth_st */
            	10, 0,
            	774, 8,
            	774, 16,
            	774, 24,
            	774, 32,
            	777, 40,
            	780, 48,
            	165, 56,
            	165, 64,
            	50, 80,
            	783, 88,
            	786, 96,
            	789, 104,
            4097, 8, 0, /* 774: pointer.func */
            4097, 8, 0, /* 777: pointer.func */
            4097, 8, 0, /* 780: pointer.func */
            4097, 8, 0, /* 783: pointer.func */
            4097, 8, 0, /* 786: pointer.func */
            4097, 8, 0, /* 789: pointer.func */
            1, 8, 1, /* 792: pointer.struct.bignum_st */
            	797, 0,
            0, 24, 1, /* 797: struct.bignum_st */
            	802, 0,
            1, 8, 1, /* 802: pointer.unsigned int */
            	807, 0,
            0, 4, 0, /* 807: unsigned int */
            1, 8, 1, /* 810: pointer.struct.bn_mont_ctx_st */
            	815, 0,
            0, 96, 3, /* 815: struct.bn_mont_ctx_st */
            	797, 8,
            	797, 32,
            	797, 56,
            1, 8, 1, /* 824: pointer.struct.bn_blinding_st */
            	829, 0,
            0, 0, 0, /* 829: struct.bn_blinding_st */
            1, 8, 1, /* 832: pointer.struct.dsa_st */
            	837, 0,
            0, 136, 11, /* 837: struct.dsa_st */
            	792, 24,
            	792, 32,
            	792, 40,
            	792, 48,
            	792, 56,
            	792, 64,
            	792, 72,
            	810, 88,
            	212, 104,
            	862, 120,
            	280, 128,
            1, 8, 1, /* 862: pointer.struct.dsa_method */
            	867, 0,
            0, 96, 11, /* 867: struct.dsa_method */
            	10, 0,
            	892, 8,
            	895, 16,
            	898, 24,
            	901, 32,
            	904, 40,
            	907, 48,
            	907, 56,
            	50, 72,
            	910, 80,
            	907, 88,
            4097, 8, 0, /* 892: pointer.func */
            4097, 8, 0, /* 895: pointer.func */
            4097, 8, 0, /* 898: pointer.func */
            4097, 8, 0, /* 901: pointer.func */
            4097, 8, 0, /* 904: pointer.func */
            4097, 8, 0, /* 907: pointer.func */
            4097, 8, 0, /* 910: pointer.func */
            1, 8, 1, /* 913: pointer.struct.dh_st */
            	918, 0,
            0, 144, 12, /* 918: struct.dh_st */
            	792, 8,
            	792, 16,
            	792, 32,
            	792, 40,
            	810, 56,
            	792, 64,
            	792, 72,
            	436, 80,
            	792, 96,
            	212, 112,
            	945, 128,
            	280, 136,
            1, 8, 1, /* 945: pointer.struct.dh_method */
            	950, 0,
            0, 72, 8, /* 950: struct.dh_method */
            	10, 0,
            	969, 8,
            	329, 16,
            	972, 24,
            	969, 32,
            	969, 40,
            	50, 56,
            	975, 64,
            4097, 8, 0, /* 969: pointer.func */
            4097, 8, 0, /* 972: pointer.func */
            4097, 8, 0, /* 975: pointer.func */
            1, 8, 1, /* 978: pointer.struct.ec_key_st */
            	326, 0,
            1, 8, 1, /* 983: pointer.struct.stack_st_X509_ATTRIBUTE */
            	988, 0,
            0, 32, 1, /* 988: struct.stack_st_X509_ATTRIBUTE */
            	38, 0,
            1, 8, 1, /* 993: pointer.struct.stack_st_X509_EXTENSION */
            	33, 0,
            0, 24, 1, /* 998: struct.ASN1_ENCODING_st */
            	436, 0,
            0, 40, 4, /* 1003: struct.dtls1_retransmit_state */
            	1014, 0,
            	1019, 8,
            	227, 16,
            	1087, 24,
            1, 8, 1, /* 1014: pointer.struct.evp_cipher_ctx_st */
            	232, 0,
            1, 8, 1, /* 1019: pointer.struct.env_md_ctx_st */
            	1024, 0,
            0, 48, 5, /* 1024: struct.env_md_ctx_st */
            	1037, 0,
            	280, 8,
            	20, 24,
            	1079, 32,
            	1064, 40,
            1, 8, 1, /* 1037: pointer.struct.env_md_st */
            	1042, 0,
            0, 120, 8, /* 1042: struct.env_md_st */
            	1061, 24,
            	1064, 32,
            	1067, 40,
            	1070, 48,
            	1061, 56,
            	162, 64,
            	1073, 72,
            	1076, 112,
            4097, 8, 0, /* 1061: pointer.func */
            4097, 8, 0, /* 1064: pointer.func */
            4097, 8, 0, /* 1067: pointer.func */
            4097, 8, 0, /* 1070: pointer.func */
            4097, 8, 0, /* 1073: pointer.func */
            4097, 8, 0, /* 1076: pointer.func */
            1, 8, 1, /* 1079: pointer.struct.evp_pkey_ctx_st */
            	1084, 0,
            0, 0, 0, /* 1084: struct.evp_pkey_ctx_st */
            1, 8, 1, /* 1087: pointer.struct.ssl_session_st */
            	1092, 0,
            0, 352, 14, /* 1092: struct.ssl_session_st */
            	50, 144,
            	50, 152,
            	1123, 168,
            	1165, 176,
            	1292, 224,
            	1302, 240,
            	212, 248,
            	1312, 264,
            	1312, 272,
            	50, 280,
            	436, 296,
            	436, 312,
            	436, 320,
            	50, 344,
            1, 8, 1, /* 1123: pointer.struct.sess_cert_st */
            	1128, 0,
            0, 248, 5, /* 1128: struct.sess_cert_st */
            	1141, 0,
            	1151, 16,
            	1277, 216,
            	1282, 224,
            	1287, 232,
            1, 8, 1, /* 1141: pointer.struct.stack_st_X509 */
            	1146, 0,
            0, 32, 1, /* 1146: struct.stack_st_X509 */
            	38, 0,
            1, 8, 1, /* 1151: pointer.struct.cert_pkey_st */
            	1156, 0,
            0, 24, 3, /* 1156: struct.cert_pkey_st */
            	1165, 0,
            	661, 8,
            	1037, 16,
            1, 8, 1, /* 1165: pointer.struct.x509_st */
            	1170, 0,
            0, 184, 12, /* 1170: struct.x509_st */
            	1197, 0,
            	444, 8,
            	538, 16,
            	50, 32,
            	212, 40,
            	543, 104,
            	1202, 112,
            	1210, 120,
            	1218, 128,
            	1223, 136,
            	1231, 144,
            	1239, 176,
            1, 8, 1, /* 1197: pointer.struct.x509_cinf_st */
            	401, 0,
            1, 8, 1, /* 1202: pointer.struct.AUTHORITY_KEYID_st */
            	1207, 0,
            0, 0, 0, /* 1207: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 1210: pointer.struct.X509_POLICY_CACHE_st */
            	1215, 0,
            0, 0, 0, /* 1215: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1218: pointer.struct.stack_st_DIST_POINT */
            	168, 0,
            1, 8, 1, /* 1223: pointer.struct.stack_st_GENERAL_NAME */
            	1228, 0,
            0, 0, 0, /* 1228: struct.stack_st_GENERAL_NAME */
            1, 8, 1, /* 1231: pointer.struct.NAME_CONSTRAINTS_st */
            	1236, 0,
            0, 0, 0, /* 1236: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 1239: pointer.struct.x509_cert_aux_st */
            	1244, 0,
            0, 40, 5, /* 1244: struct.x509_cert_aux_st */
            	1257, 0,
            	1257, 8,
            	593, 16,
            	543, 24,
            	1267, 32,
            1, 8, 1, /* 1257: pointer.struct.stack_st_ASN1_OBJECT */
            	1262, 0,
            0, 32, 1, /* 1262: struct.stack_st_ASN1_OBJECT */
            	38, 0,
            1, 8, 1, /* 1267: pointer.struct.stack_st_X509_ALGOR */
            	1272, 0,
            0, 32, 1, /* 1272: struct.stack_st_X509_ALGOR */
            	38, 0,
            1, 8, 1, /* 1277: pointer.struct.rsa_st */
            	703, 0,
            1, 8, 1, /* 1282: pointer.struct.dh_st */
            	918, 0,
            1, 8, 1, /* 1287: pointer.struct.ec_key_st */
            	326, 0,
            1, 8, 1, /* 1292: pointer.struct.ssl_cipher_st */
            	1297, 0,
            0, 88, 1, /* 1297: struct.ssl_cipher_st */
            	10, 8,
            1, 8, 1, /* 1302: pointer.struct.stack_st_SSL_CIPHER */
            	1307, 0,
            0, 32, 1, /* 1307: struct.stack_st_SSL_CIPHER */
            	38, 0,
            1, 8, 1, /* 1312: pointer.struct.ssl_session_st */
            	1092, 0,
            0, 528, 8, /* 1317: struct.unknown */
            	1292, 408,
            	1282, 416,
            	1287, 424,
            	1336, 464,
            	436, 480,
            	243, 488,
            	1037, 496,
            	1346, 512,
            1, 8, 1, /* 1336: pointer.struct.stack_st_X509_NAME */
            	1341, 0,
            0, 32, 1, /* 1341: struct.stack_st_X509_NAME */
            	38, 0,
            1, 8, 1, /* 1346: pointer.struct.ssl_comp_st */
            	1351, 0,
            0, 24, 2, /* 1351: struct.ssl_comp_st */
            	10, 8,
            	178, 16,
            4097, 8, 0, /* 1358: pointer.func */
            4097, 8, 0, /* 1361: pointer.func */
            0, 88, 1, /* 1364: struct.hm_header_st */
            	1003, 48,
            4097, 8, 0, /* 1369: pointer.func */
            0, 56, 3, /* 1372: struct.ssl3_record_st */
            	436, 16,
            	436, 24,
            	436, 32,
            4097, 8, 0, /* 1381: pointer.func */
            0, 128, 14, /* 1384: struct.srp_ctx_st */
            	20, 0,
            	98, 8,
            	1415, 16,
            	77, 24,
            	50, 32,
            	792, 40,
            	792, 48,
            	792, 56,
            	792, 64,
            	792, 72,
            	792, 80,
            	792, 88,
            	792, 96,
            	50, 104,
            4097, 8, 0, /* 1415: pointer.func */
            0, 888, 7, /* 1418: struct.dtls1_state_st */
            	288, 576,
            	288, 592,
            	293, 608,
            	293, 616,
            	288, 624,
            	1364, 648,
            	1364, 736,
            1, 8, 1, /* 1435: pointer.struct.stack_st_X509_LOOKUP */
            	1440, 0,
            0, 32, 1, /* 1440: struct.stack_st_X509_LOOKUP */
            	38, 0,
            1, 8, 1, /* 1445: pointer.struct.ssl3_buf_freelist_st */
            	90, 0,
            4097, 8, 0, /* 1450: pointer.func */
            4097, 8, 0, /* 1453: pointer.func */
            0, 1, 0, /* 1456: char */
            4097, 8, 0, /* 1459: pointer.func */
            0, 112, 11, /* 1462: struct.ssl3_enc_method */
            	1487, 0,
            	1490, 8,
            	1493, 16,
            	1381, 24,
            	1487, 32,
            	1453, 40,
            	1450, 56,
            	10, 64,
            	10, 80,
            	1496, 96,
            	1499, 104,
            4097, 8, 0, /* 1487: pointer.func */
            4097, 8, 0, /* 1490: pointer.func */
            4097, 8, 0, /* 1493: pointer.func */
            4097, 8, 0, /* 1496: pointer.func */
            4097, 8, 0, /* 1499: pointer.func */
            4097, 8, 0, /* 1502: pointer.func */
            4097, 8, 0, /* 1505: pointer.func */
            1, 8, 1, /* 1508: pointer.struct.ssl2_state_st */
            	1513, 0,
            0, 344, 9, /* 1513: struct.ssl2_state_st */
            	470, 24,
            	436, 56,
            	436, 64,
            	436, 72,
            	436, 104,
            	436, 112,
            	436, 120,
            	436, 128,
            	436, 136,
            4097, 8, 0, /* 1534: pointer.func */
            4097, 8, 0, /* 1537: pointer.func */
            4097, 8, 0, /* 1540: pointer.func */
            4097, 8, 0, /* 1543: pointer.func */
            4097, 8, 0, /* 1546: pointer.func */
            4097, 8, 0, /* 1549: pointer.func */
            0, 232, 28, /* 1552: struct.ssl_method_st */
            	1493, 8,
            	1611, 16,
            	1611, 24,
            	1493, 32,
            	1493, 40,
            	1614, 48,
            	1614, 56,
            	1534, 64,
            	1493, 72,
            	1493, 80,
            	1493, 88,
            	301, 96,
            	1549, 104,
            	1617, 112,
            	1493, 120,
            	1620, 128,
            	1623, 136,
            	1358, 144,
            	1537, 152,
            	1505, 160,
            	1543, 168,
            	1626, 176,
            	310, 184,
            	209, 192,
            	1629, 200,
            	1543, 208,
            	1546, 216,
            	1634, 224,
            4097, 8, 0, /* 1611: pointer.func */
            4097, 8, 0, /* 1614: pointer.func */
            4097, 8, 0, /* 1617: pointer.func */
            4097, 8, 0, /* 1620: pointer.func */
            4097, 8, 0, /* 1623: pointer.func */
            4097, 8, 0, /* 1626: pointer.func */
            1, 8, 1, /* 1629: pointer.struct.ssl3_enc_method */
            	1462, 0,
            4097, 8, 0, /* 1634: pointer.func */
            1, 8, 1, /* 1637: pointer.struct.ssl_st */
            	1642, 0,
            0, 808, 51, /* 1642: struct.ssl_st */
            	1747, 8,
            	1752, 16,
            	1752, 24,
            	1752, 32,
            	1493, 48,
            	620, 80,
            	20, 88,
            	436, 104,
            	1508, 120,
            	1757, 128,
            	1795, 136,
            	1459, 152,
            	20, 160,
            	1800, 176,
            	1302, 184,
            	1302, 192,
            	1014, 208,
            	1019, 216,
            	227, 224,
            	1014, 232,
            	1019, 240,
            	227, 248,
            	1812, 256,
            	1087, 304,
            	1840, 312,
            	1843, 328,
            	1846, 336,
            	1849, 352,
            	304, 360,
            	1852, 368,
            	212, 392,
            	1336, 408,
            	61, 464,
            	20, 472,
            	50, 480,
            	2041, 504,
            	28, 512,
            	436, 520,
            	436, 544,
            	436, 560,
            	20, 568,
            	23, 584,
            	307, 592,
            	20, 600,
            	1361, 608,
            	20, 616,
            	1852, 624,
            	436, 632,
            	64, 648,
            	0, 656,
            	1384, 680,
            1, 8, 1, /* 1747: pointer.struct.ssl_method_st */
            	1552, 0,
            1, 8, 1, /* 1752: pointer.struct.bio_st */
            	337, 0,
            1, 8, 1, /* 1757: pointer.struct.ssl3_state_st */
            	1762, 0,
            0, 1200, 10, /* 1762: struct.ssl3_state_st */
            	1785, 240,
            	1785, 264,
            	1372, 288,
            	1372, 344,
            	470, 432,
            	1752, 440,
            	1790, 448,
            	20, 496,
            	20, 512,
            	1317, 528,
            0, 24, 1, /* 1785: struct.ssl3_buffer_st */
            	436, 0,
            1, 8, 1, /* 1790: pointer.pointer.struct.env_md_ctx_st */
            	1019, 0,
            1, 8, 1, /* 1795: pointer.struct.dtls1_state_st */
            	1418, 0,
            1, 8, 1, /* 1800: pointer.struct.X509_VERIFY_PARAM_st */
            	1805, 0,
            0, 56, 2, /* 1805: struct.X509_VERIFY_PARAM_st */
            	50, 0,
            	1257, 48,
            1, 8, 1, /* 1812: pointer.struct.cert_st */
            	1817, 0,
            0, 296, 7, /* 1817: struct.cert_st */
            	1151, 0,
            	1277, 48,
            	1834, 56,
            	1282, 64,
            	1502, 72,
            	1287, 80,
            	1837, 88,
            4097, 8, 0, /* 1834: pointer.func */
            4097, 8, 0, /* 1837: pointer.func */
            4097, 8, 0, /* 1840: pointer.func */
            4097, 8, 0, /* 1843: pointer.func */
            4097, 8, 0, /* 1846: pointer.func */
            4097, 8, 0, /* 1849: pointer.func */
            1, 8, 1, /* 1852: pointer.struct.ssl_ctx_st */
            	1857, 0,
            0, 736, 50, /* 1857: struct.ssl_ctx_st */
            	1747, 0,
            	1302, 8,
            	1302, 16,
            	1960, 24,
            	135, 32,
            	1312, 48,
            	1312, 56,
            	2032, 80,
            	120, 88,
            	1540, 96,
            	117, 152,
            	20, 160,
            	114, 168,
            	20, 176,
            	1369, 184,
            	323, 192,
            	111, 200,
            	212, 208,
            	1037, 224,
            	1037, 232,
            	1037, 240,
            	1141, 248,
            	106, 256,
            	1846, 264,
            	1336, 272,
            	1812, 304,
            	1459, 320,
            	20, 328,
            	1843, 376,
            	1840, 384,
            	1800, 392,
            	280, 408,
            	98, 416,
            	20, 424,
            	2035, 480,
            	1415, 488,
            	20, 496,
            	95, 504,
            	20, 512,
            	50, 520,
            	1849, 528,
            	304, 536,
            	1445, 552,
            	1445, 560,
            	1384, 568,
            	74, 696,
            	20, 704,
            	2038, 712,
            	20, 720,
            	64, 728,
            1, 8, 1, /* 1960: pointer.struct.x509_store_st */
            	1965, 0,
            0, 144, 15, /* 1965: struct.x509_store_st */
            	1998, 8,
            	1435, 16,
            	1800, 24,
            	2008, 32,
            	1843, 40,
            	2011, 48,
            	2014, 56,
            	2008, 64,
            	2017, 72,
            	2020, 80,
            	2023, 88,
            	2026, 96,
            	2029, 104,
            	2008, 112,
            	212, 120,
            1, 8, 1, /* 1998: pointer.struct.stack_st_X509_OBJECT */
            	2003, 0,
            0, 32, 1, /* 2003: struct.stack_st_X509_OBJECT */
            	38, 0,
            4097, 8, 0, /* 2008: pointer.func */
            4097, 8, 0, /* 2011: pointer.func */
            4097, 8, 0, /* 2014: pointer.func */
            4097, 8, 0, /* 2017: pointer.func */
            4097, 8, 0, /* 2020: pointer.func */
            4097, 8, 0, /* 2023: pointer.func */
            4097, 8, 0, /* 2026: pointer.func */
            4097, 8, 0, /* 2029: pointer.func */
            4097, 8, 0, /* 2032: pointer.func */
            4097, 8, 0, /* 2035: pointer.func */
            4097, 8, 0, /* 2038: pointer.func */
            1, 8, 1, /* 2041: pointer.struct.stack_st_OCSP_RESPID */
            	58, 0,
        },
        .arg_entity_index = { 1637, },
        .ret_entity_index = 50,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL * new_arg_a = *((SSL * *)new_args->args[0]);

    char * *new_ret_ptr = (char * *)new_args->ret;

    char * (*orig_SSL_get_srp_username)(SSL *);
    orig_SSL_get_srp_username = dlsym(RTLD_NEXT, "SSL_get_srp_username");
    *new_ret_ptr = (*orig_SSL_get_srp_username)(new_arg_a);

    syscall(889);

    return ret;
}

