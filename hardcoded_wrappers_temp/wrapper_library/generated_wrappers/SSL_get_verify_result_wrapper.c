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

long bb_SSL_get_verify_result(const SSL * arg_a);

long SSL_get_verify_result(const SSL * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_get_verify_result called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_get_verify_result(arg_a);
    else {
        long (*orig_SSL_get_verify_result)(const SSL *);
        orig_SSL_get_verify_result = dlsym(RTLD_NEXT, "SSL_get_verify_result");
        return orig_SSL_get_verify_result(arg_a);
    }
}

long bb_SSL_get_verify_result(const SSL * arg_a) 
{
    long ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.struct.srtp_protection_profile_st */
            	5, 0,
            0, 16, 1, /* 5: struct.srtp_protection_profile_st */
            	10, 0,
            1, 8, 1, /* 10: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 15: pointer.func */
            1, 8, 1, /* 18: pointer.struct.tls_session_ticket_ext_st */
            	23, 0,
            0, 16, 1, /* 23: struct.tls_session_ticket_ext_st */
            	28, 8,
            0, 8, 0, /* 28: pointer.void */
            0, 32, 1, /* 31: struct.stack_st_OCSP_RESPID */
            	36, 0,
            0, 32, 2, /* 36: struct.stack_st */
            	43, 8,
            	53, 24,
            1, 8, 1, /* 43: pointer.pointer.char */
            	48, 0,
            1, 8, 1, /* 48: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 53: pointer.func */
            1, 8, 1, /* 56: pointer.struct.stack_st_OCSP_RESPID */
            	31, 0,
            4097, 8, 0, /* 61: pointer.func */
            0, 32, 1, /* 64: struct.stack_st_SRTP_PROTECTION_PROFILE */
            	36, 0,
            4097, 8, 0, /* 69: pointer.func */
            0, 128, 14, /* 72: struct.srp_ctx_st */
            	28, 0,
            	103, 8,
            	106, 16,
            	69, 24,
            	48, 32,
            	109, 40,
            	109, 48,
            	109, 56,
            	109, 64,
            	109, 72,
            	109, 80,
            	109, 88,
            	109, 96,
            	48, 104,
            4097, 8, 0, /* 103: pointer.func */
            4097, 8, 0, /* 106: pointer.func */
            1, 8, 1, /* 109: pointer.struct.bignum_st */
            	114, 0,
            0, 24, 1, /* 114: struct.bignum_st */
            	119, 0,
            1, 8, 1, /* 119: pointer.unsigned int */
            	124, 0,
            0, 4, 0, /* 124: unsigned int */
            4097, 8, 0, /* 127: pointer.func */
            0, 32, 1, /* 130: struct.stack_st_SSL_COMP */
            	36, 0,
            1, 8, 1, /* 135: pointer.struct.stack_st_SSL_COMP */
            	130, 0,
            4097, 8, 0, /* 140: pointer.func */
            4097, 8, 0, /* 143: pointer.func */
            4097, 8, 0, /* 146: pointer.func */
            4097, 8, 0, /* 149: pointer.func */
            4097, 8, 0, /* 152: pointer.func */
            4097, 8, 0, /* 155: pointer.func */
            1, 8, 1, /* 158: pointer.struct.lhash_node_st */
            	163, 0,
            0, 24, 2, /* 163: struct.lhash_node_st */
            	28, 0,
            	158, 8,
            1, 8, 1, /* 170: pointer.struct.lhash_st */
            	175, 0,
            0, 176, 3, /* 175: struct.lhash_st */
            	184, 0,
            	53, 8,
            	155, 16,
            1, 8, 1, /* 184: pointer.pointer.struct.lhash_node_st */
            	189, 0,
            1, 8, 1, /* 189: pointer.struct.lhash_node_st */
            	163, 0,
            4097, 8, 0, /* 194: pointer.func */
            4097, 8, 0, /* 197: pointer.func */
            0, 56, 2, /* 200: struct.comp_ctx_st */
            	207, 0,
            	241, 40,
            1, 8, 1, /* 207: pointer.struct.comp_method_st */
            	212, 0,
            0, 64, 7, /* 212: struct.comp_method_st */
            	10, 8,
            	229, 16,
            	232, 24,
            	235, 32,
            	235, 40,
            	238, 48,
            	238, 56,
            4097, 8, 0, /* 229: pointer.func */
            4097, 8, 0, /* 232: pointer.func */
            4097, 8, 0, /* 235: pointer.func */
            4097, 8, 0, /* 238: pointer.func */
            0, 16, 1, /* 241: struct.crypto_ex_data_st */
            	246, 0,
            1, 8, 1, /* 246: pointer.struct.stack_st_void */
            	251, 0,
            0, 32, 1, /* 251: struct.stack_st_void */
            	36, 0,
            4097, 8, 0, /* 256: pointer.func */
            4097, 8, 0, /* 259: pointer.func */
            0, 168, 4, /* 262: struct.evp_cipher_ctx_st */
            	273, 0,
            	307, 8,
            	28, 96,
            	28, 120,
            1, 8, 1, /* 273: pointer.struct.evp_cipher_st */
            	278, 0,
            0, 88, 7, /* 278: struct.evp_cipher_st */
            	295, 24,
            	256, 32,
            	298, 40,
            	301, 56,
            	301, 64,
            	304, 72,
            	28, 80,
            4097, 8, 0, /* 295: pointer.func */
            4097, 8, 0, /* 298: pointer.func */
            4097, 8, 0, /* 301: pointer.func */
            4097, 8, 0, /* 304: pointer.func */
            1, 8, 1, /* 307: pointer.struct.engine_st */
            	312, 0,
            0, 0, 0, /* 312: struct.engine_st */
            1, 8, 1, /* 315: pointer.struct.stack_st_X509_NAME */
            	320, 0,
            0, 32, 1, /* 320: struct.stack_st_X509_NAME */
            	36, 0,
            4097, 8, 0, /* 325: pointer.func */
            4097, 8, 0, /* 328: pointer.func */
            1, 8, 1, /* 331: pointer.struct.evp_pkey_ctx_st */
            	336, 0,
            0, 0, 0, /* 336: struct.evp_pkey_ctx_st */
            1, 8, 1, /* 339: pointer.struct.ssl_st */
            	344, 0,
            0, 808, 51, /* 344: struct.ssl_st */
            	449, 8,
            	615, 16,
            	615, 24,
            	615, 32,
            	513, 48,
            	686, 80,
            	28, 88,
            	696, 104,
            	704, 120,
            	735, 128,
            	973, 136,
            	1778, 152,
            	28, 160,
            	1781, 176,
            	1763, 184,
            	1763, 192,
            	1024, 208,
            	782, 216,
            	1029, 224,
            	1024, 232,
            	782, 240,
            	1029, 248,
            	1793, 256,
            	1034, 304,
            	1824, 312,
            	1827, 328,
            	1830, 336,
            	1833, 352,
            	1836, 360,
            	1839, 368,
            	241, 392,
            	315, 408,
            	61, 464,
            	28, 472,
            	48, 480,
            	56, 504,
            	2066, 512,
            	696, 520,
            	696, 544,
            	696, 560,
            	28, 568,
            	18, 584,
            	2071, 592,
            	28, 600,
            	15, 608,
            	28, 616,
            	1839, 624,
            	696, 632,
            	2061, 648,
            	0, 656,
            	72, 680,
            1, 8, 1, /* 449: pointer.struct.ssl_method_st */
            	454, 0,
            0, 232, 28, /* 454: struct.ssl_method_st */
            	513, 8,
            	516, 16,
            	516, 24,
            	513, 32,
            	513, 40,
            	519, 48,
            	519, 56,
            	522, 64,
            	513, 72,
            	513, 80,
            	513, 88,
            	525, 96,
            	528, 104,
            	531, 112,
            	513, 120,
            	534, 128,
            	537, 136,
            	540, 144,
            	543, 152,
            	546, 160,
            	549, 168,
            	552, 176,
            	555, 184,
            	238, 192,
            	558, 200,
            	549, 208,
            	609, 216,
            	612, 224,
            4097, 8, 0, /* 513: pointer.func */
            4097, 8, 0, /* 516: pointer.func */
            4097, 8, 0, /* 519: pointer.func */
            4097, 8, 0, /* 522: pointer.func */
            4097, 8, 0, /* 525: pointer.func */
            4097, 8, 0, /* 528: pointer.func */
            4097, 8, 0, /* 531: pointer.func */
            4097, 8, 0, /* 534: pointer.func */
            4097, 8, 0, /* 537: pointer.func */
            4097, 8, 0, /* 540: pointer.func */
            4097, 8, 0, /* 543: pointer.func */
            4097, 8, 0, /* 546: pointer.func */
            4097, 8, 0, /* 549: pointer.func */
            4097, 8, 0, /* 552: pointer.func */
            4097, 8, 0, /* 555: pointer.func */
            1, 8, 1, /* 558: pointer.struct.ssl3_enc_method */
            	563, 0,
            0, 112, 11, /* 563: struct.ssl3_enc_method */
            	588, 0,
            	591, 8,
            	513, 16,
            	594, 24,
            	588, 32,
            	597, 40,
            	600, 56,
            	10, 64,
            	10, 80,
            	603, 96,
            	606, 104,
            4097, 8, 0, /* 588: pointer.func */
            4097, 8, 0, /* 591: pointer.func */
            4097, 8, 0, /* 594: pointer.func */
            4097, 8, 0, /* 597: pointer.func */
            4097, 8, 0, /* 600: pointer.func */
            4097, 8, 0, /* 603: pointer.func */
            4097, 8, 0, /* 606: pointer.func */
            4097, 8, 0, /* 609: pointer.func */
            4097, 8, 0, /* 612: pointer.func */
            1, 8, 1, /* 615: pointer.struct.bio_st */
            	620, 0,
            0, 112, 7, /* 620: struct.bio_st */
            	637, 0,
            	678, 8,
            	48, 16,
            	28, 48,
            	681, 56,
            	681, 64,
            	241, 96,
            1, 8, 1, /* 637: pointer.struct.bio_method_st */
            	642, 0,
            0, 80, 9, /* 642: struct.bio_method_st */
            	10, 8,
            	663, 16,
            	666, 24,
            	669, 32,
            	666, 40,
            	259, 48,
            	672, 56,
            	672, 64,
            	675, 72,
            4097, 8, 0, /* 663: pointer.func */
            4097, 8, 0, /* 666: pointer.func */
            4097, 8, 0, /* 669: pointer.func */
            4097, 8, 0, /* 672: pointer.func */
            4097, 8, 0, /* 675: pointer.func */
            4097, 8, 0, /* 678: pointer.func */
            1, 8, 1, /* 681: pointer.struct.bio_st */
            	620, 0,
            1, 8, 1, /* 686: pointer.struct.buf_mem_st */
            	691, 0,
            0, 24, 1, /* 691: struct.buf_mem_st */
            	48, 8,
            1, 8, 1, /* 696: pointer.unsigned char */
            	701, 0,
            0, 1, 0, /* 701: unsigned char */
            1, 8, 1, /* 704: pointer.struct.ssl2_state_st */
            	709, 0,
            0, 344, 9, /* 709: struct.ssl2_state_st */
            	730, 24,
            	696, 56,
            	696, 64,
            	696, 72,
            	696, 104,
            	696, 112,
            	696, 120,
            	696, 128,
            	696, 136,
            1, 8, 1, /* 730: pointer.unsigned char */
            	701, 0,
            1, 8, 1, /* 735: pointer.struct.ssl3_state_st */
            	740, 0,
            0, 1200, 10, /* 740: struct.ssl3_state_st */
            	763, 240,
            	763, 264,
            	768, 288,
            	768, 344,
            	730, 432,
            	615, 440,
            	777, 448,
            	28, 496,
            	28, 512,
            	842, 528,
            0, 24, 1, /* 763: struct.ssl3_buffer_st */
            	696, 0,
            0, 56, 3, /* 768: struct.ssl3_record_st */
            	696, 16,
            	696, 24,
            	696, 32,
            1, 8, 1, /* 777: pointer.pointer.struct.env_md_ctx_st */
            	782, 0,
            1, 8, 1, /* 782: pointer.struct.env_md_ctx_st */
            	787, 0,
            0, 48, 5, /* 787: struct.env_md_ctx_st */
            	800, 0,
            	307, 8,
            	28, 24,
            	331, 32,
            	824, 40,
            1, 8, 1, /* 800: pointer.struct.env_md_st */
            	805, 0,
            0, 120, 8, /* 805: struct.env_md_st */
            	325, 24,
            	824, 32,
            	827, 40,
            	830, 48,
            	325, 56,
            	833, 64,
            	836, 72,
            	839, 112,
            4097, 8, 0, /* 824: pointer.func */
            4097, 8, 0, /* 827: pointer.func */
            4097, 8, 0, /* 830: pointer.func */
            4097, 8, 0, /* 833: pointer.func */
            4097, 8, 0, /* 836: pointer.func */
            4097, 8, 0, /* 839: pointer.func */
            0, 528, 8, /* 842: struct.unknown */
            	861, 408,
            	871, 416,
            	953, 424,
            	315, 464,
            	696, 480,
            	273, 488,
            	800, 496,
            	961, 512,
            1, 8, 1, /* 861: pointer.struct.ssl_cipher_st */
            	866, 0,
            0, 88, 1, /* 866: struct.ssl_cipher_st */
            	10, 8,
            1, 8, 1, /* 871: pointer.struct.dh_st */
            	876, 0,
            0, 144, 12, /* 876: struct.dh_st */
            	109, 8,
            	109, 16,
            	109, 32,
            	109, 40,
            	903, 56,
            	109, 64,
            	109, 72,
            	696, 80,
            	109, 96,
            	241, 112,
            	917, 128,
            	307, 136,
            1, 8, 1, /* 903: pointer.struct.bn_mont_ctx_st */
            	908, 0,
            0, 96, 3, /* 908: struct.bn_mont_ctx_st */
            	114, 8,
            	114, 32,
            	114, 56,
            1, 8, 1, /* 917: pointer.struct.dh_method */
            	922, 0,
            0, 72, 8, /* 922: struct.dh_method */
            	10, 0,
            	941, 8,
            	944, 16,
            	947, 24,
            	941, 32,
            	941, 40,
            	48, 56,
            	950, 64,
            4097, 8, 0, /* 941: pointer.func */
            4097, 8, 0, /* 944: pointer.func */
            4097, 8, 0, /* 947: pointer.func */
            4097, 8, 0, /* 950: pointer.func */
            1, 8, 1, /* 953: pointer.struct.ec_key_st */
            	958, 0,
            0, 0, 0, /* 958: struct.ec_key_st */
            1, 8, 1, /* 961: pointer.struct.ssl_comp_st */
            	966, 0,
            0, 24, 2, /* 966: struct.ssl_comp_st */
            	10, 8,
            	207, 16,
            1, 8, 1, /* 973: pointer.struct.dtls1_state_st */
            	978, 0,
            0, 888, 7, /* 978: struct.dtls1_state_st */
            	995, 576,
            	995, 592,
            	1000, 608,
            	1000, 616,
            	995, 624,
            	1008, 648,
            	1008, 736,
            0, 16, 1, /* 995: struct.record_pqueue_st */
            	1000, 8,
            1, 8, 1, /* 1000: pointer.struct._pqueue */
            	1005, 0,
            0, 0, 0, /* 1005: struct._pqueue */
            0, 88, 1, /* 1008: struct.hm_header_st */
            	1013, 48,
            0, 40, 4, /* 1013: struct.dtls1_retransmit_state */
            	1024, 0,
            	782, 8,
            	1029, 16,
            	1034, 24,
            1, 8, 1, /* 1024: pointer.struct.evp_cipher_ctx_st */
            	262, 0,
            1, 8, 1, /* 1029: pointer.struct.comp_ctx_st */
            	200, 0,
            1, 8, 1, /* 1034: pointer.struct.ssl_session_st */
            	1039, 0,
            0, 352, 14, /* 1039: struct.ssl_session_st */
            	48, 144,
            	48, 152,
            	1070, 168,
            	1112, 176,
            	861, 224,
            	1763, 240,
            	241, 248,
            	1773, 264,
            	1773, 272,
            	48, 280,
            	696, 296,
            	696, 312,
            	696, 320,
            	48, 344,
            1, 8, 1, /* 1070: pointer.struct.sess_cert_st */
            	1075, 0,
            0, 248, 5, /* 1075: struct.sess_cert_st */
            	1088, 0,
            	1098, 16,
            	1758, 216,
            	871, 224,
            	953, 232,
            1, 8, 1, /* 1088: pointer.struct.stack_st_X509 */
            	1093, 0,
            0, 32, 1, /* 1093: struct.stack_st_X509 */
            	36, 0,
            1, 8, 1, /* 1098: pointer.struct.cert_pkey_st */
            	1103, 0,
            0, 24, 3, /* 1103: struct.cert_pkey_st */
            	1112, 0,
            	1396, 8,
            	800, 16,
            1, 8, 1, /* 1112: pointer.struct.x509_st */
            	1117, 0,
            0, 184, 12, /* 1117: struct.x509_st */
            	1144, 0,
            	1184, 8,
            	1273, 16,
            	48, 32,
            	241, 40,
            	1278, 104,
            	1651, 112,
            	1675, 120,
            	1683, 128,
            	1693, 136,
            	1698, 144,
            	1720, 176,
            1, 8, 1, /* 1144: pointer.struct.x509_cinf_st */
            	1149, 0,
            0, 104, 11, /* 1149: struct.x509_cinf_st */
            	1174, 0,
            	1174, 8,
            	1184, 16,
            	1341, 24,
            	1365, 32,
            	1341, 40,
            	1382, 48,
            	1273, 56,
            	1273, 64,
            	1636, 72,
            	1646, 80,
            1, 8, 1, /* 1174: pointer.struct.asn1_string_st */
            	1179, 0,
            0, 24, 1, /* 1179: struct.asn1_string_st */
            	696, 8,
            1, 8, 1, /* 1184: pointer.struct.X509_algor_st */
            	1189, 0,
            0, 16, 2, /* 1189: struct.X509_algor_st */
            	1196, 0,
            	1210, 8,
            1, 8, 1, /* 1196: pointer.struct.asn1_object_st */
            	1201, 0,
            0, 40, 3, /* 1201: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	730, 24,
            1, 8, 1, /* 1210: pointer.struct.asn1_type_st */
            	1215, 0,
            0, 16, 1, /* 1215: struct.asn1_type_st */
            	1220, 8,
            0, 8, 20, /* 1220: union.unknown */
            	48, 0,
            	1263, 0,
            	1196, 0,
            	1174, 0,
            	1268, 0,
            	1273, 0,
            	1278, 0,
            	1283, 0,
            	1288, 0,
            	1293, 0,
            	1298, 0,
            	1303, 0,
            	1308, 0,
            	1313, 0,
            	1318, 0,
            	1323, 0,
            	1328, 0,
            	1263, 0,
            	1263, 0,
            	1333, 0,
            1, 8, 1, /* 1263: pointer.struct.asn1_string_st */
            	1179, 0,
            1, 8, 1, /* 1268: pointer.struct.asn1_string_st */
            	1179, 0,
            1, 8, 1, /* 1273: pointer.struct.asn1_string_st */
            	1179, 0,
            1, 8, 1, /* 1278: pointer.struct.asn1_string_st */
            	1179, 0,
            1, 8, 1, /* 1283: pointer.struct.asn1_string_st */
            	1179, 0,
            1, 8, 1, /* 1288: pointer.struct.asn1_string_st */
            	1179, 0,
            1, 8, 1, /* 1293: pointer.struct.asn1_string_st */
            	1179, 0,
            1, 8, 1, /* 1298: pointer.struct.asn1_string_st */
            	1179, 0,
            1, 8, 1, /* 1303: pointer.struct.asn1_string_st */
            	1179, 0,
            1, 8, 1, /* 1308: pointer.struct.asn1_string_st */
            	1179, 0,
            1, 8, 1, /* 1313: pointer.struct.asn1_string_st */
            	1179, 0,
            1, 8, 1, /* 1318: pointer.struct.asn1_string_st */
            	1179, 0,
            1, 8, 1, /* 1323: pointer.struct.asn1_string_st */
            	1179, 0,
            1, 8, 1, /* 1328: pointer.struct.asn1_string_st */
            	1179, 0,
            1, 8, 1, /* 1333: pointer.struct.ASN1_VALUE_st */
            	1338, 0,
            0, 0, 0, /* 1338: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1341: pointer.struct.X509_name_st */
            	1346, 0,
            0, 40, 3, /* 1346: struct.X509_name_st */
            	1355, 0,
            	686, 16,
            	696, 24,
            1, 8, 1, /* 1355: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1360, 0,
            0, 32, 1, /* 1360: struct.stack_st_X509_NAME_ENTRY */
            	36, 0,
            1, 8, 1, /* 1365: pointer.struct.X509_val_st */
            	1370, 0,
            0, 16, 2, /* 1370: struct.X509_val_st */
            	1377, 0,
            	1377, 8,
            1, 8, 1, /* 1377: pointer.struct.asn1_string_st */
            	1179, 0,
            1, 8, 1, /* 1382: pointer.struct.X509_pubkey_st */
            	1387, 0,
            0, 24, 3, /* 1387: struct.X509_pubkey_st */
            	1184, 0,
            	1273, 8,
            	1396, 16,
            1, 8, 1, /* 1396: pointer.struct.evp_pkey_st */
            	1401, 0,
            0, 56, 4, /* 1401: struct.evp_pkey_st */
            	1412, 16,
            	307, 24,
            	1420, 32,
            	1626, 48,
            1, 8, 1, /* 1412: pointer.struct.evp_pkey_asn1_method_st */
            	1417, 0,
            0, 0, 0, /* 1417: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 1420: union.unknown */
            	48, 0,
            	1433, 0,
            	1538, 0,
            	1616, 0,
            	1621, 0,
            1, 8, 1, /* 1433: pointer.struct.rsa_st */
            	1438, 0,
            0, 168, 17, /* 1438: struct.rsa_st */
            	1475, 16,
            	307, 24,
            	109, 32,
            	109, 40,
            	109, 48,
            	109, 56,
            	109, 64,
            	109, 72,
            	109, 80,
            	109, 88,
            	241, 96,
            	903, 120,
            	903, 128,
            	903, 136,
            	48, 144,
            	1530, 152,
            	1530, 160,
            1, 8, 1, /* 1475: pointer.struct.rsa_meth_st */
            	1480, 0,
            0, 112, 13, /* 1480: struct.rsa_meth_st */
            	10, 0,
            	1509, 8,
            	1509, 16,
            	1509, 24,
            	1509, 32,
            	1512, 40,
            	1515, 48,
            	1518, 56,
            	1518, 64,
            	48, 80,
            	1521, 88,
            	1524, 96,
            	1527, 104,
            4097, 8, 0, /* 1509: pointer.func */
            4097, 8, 0, /* 1512: pointer.func */
            4097, 8, 0, /* 1515: pointer.func */
            4097, 8, 0, /* 1518: pointer.func */
            4097, 8, 0, /* 1521: pointer.func */
            4097, 8, 0, /* 1524: pointer.func */
            4097, 8, 0, /* 1527: pointer.func */
            1, 8, 1, /* 1530: pointer.struct.bn_blinding_st */
            	1535, 0,
            0, 0, 0, /* 1535: struct.bn_blinding_st */
            1, 8, 1, /* 1538: pointer.struct.dsa_st */
            	1543, 0,
            0, 136, 11, /* 1543: struct.dsa_st */
            	109, 24,
            	109, 32,
            	109, 40,
            	109, 48,
            	109, 56,
            	109, 64,
            	109, 72,
            	903, 88,
            	241, 104,
            	1568, 120,
            	307, 128,
            1, 8, 1, /* 1568: pointer.struct.dsa_method */
            	1573, 0,
            0, 96, 11, /* 1573: struct.dsa_method */
            	10, 0,
            	1598, 8,
            	1601, 16,
            	1604, 24,
            	1607, 32,
            	1610, 40,
            	1613, 48,
            	1613, 56,
            	48, 72,
            	328, 80,
            	1613, 88,
            4097, 8, 0, /* 1598: pointer.func */
            4097, 8, 0, /* 1601: pointer.func */
            4097, 8, 0, /* 1604: pointer.func */
            4097, 8, 0, /* 1607: pointer.func */
            4097, 8, 0, /* 1610: pointer.func */
            4097, 8, 0, /* 1613: pointer.func */
            1, 8, 1, /* 1616: pointer.struct.dh_st */
            	876, 0,
            1, 8, 1, /* 1621: pointer.struct.ec_key_st */
            	958, 0,
            1, 8, 1, /* 1626: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1631, 0,
            0, 32, 1, /* 1631: struct.stack_st_X509_ATTRIBUTE */
            	36, 0,
            1, 8, 1, /* 1636: pointer.struct.stack_st_X509_EXTENSION */
            	1641, 0,
            0, 32, 1, /* 1641: struct.stack_st_X509_EXTENSION */
            	36, 0,
            0, 24, 1, /* 1646: struct.ASN1_ENCODING_st */
            	696, 0,
            1, 8, 1, /* 1651: pointer.struct.AUTHORITY_KEYID_st */
            	1656, 0,
            0, 24, 3, /* 1656: struct.AUTHORITY_KEYID_st */
            	1278, 0,
            	1665, 8,
            	1174, 16,
            1, 8, 1, /* 1665: pointer.struct.stack_st_GENERAL_NAME */
            	1670, 0,
            0, 32, 1, /* 1670: struct.stack_st_GENERAL_NAME */
            	36, 0,
            1, 8, 1, /* 1675: pointer.struct.X509_POLICY_CACHE_st */
            	1680, 0,
            0, 0, 0, /* 1680: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1683: pointer.struct.stack_st_DIST_POINT */
            	1688, 0,
            0, 32, 1, /* 1688: struct.stack_st_DIST_POINT */
            	36, 0,
            1, 8, 1, /* 1693: pointer.struct.stack_st_GENERAL_NAME */
            	1670, 0,
            1, 8, 1, /* 1698: pointer.struct.NAME_CONSTRAINTS_st */
            	1703, 0,
            0, 16, 2, /* 1703: struct.NAME_CONSTRAINTS_st */
            	1710, 0,
            	1710, 8,
            1, 8, 1, /* 1710: pointer.struct.stack_st_GENERAL_SUBTREE */
            	1715, 0,
            0, 32, 1, /* 1715: struct.stack_st_GENERAL_SUBTREE */
            	36, 0,
            1, 8, 1, /* 1720: pointer.struct.x509_cert_aux_st */
            	1725, 0,
            0, 40, 5, /* 1725: struct.x509_cert_aux_st */
            	1738, 0,
            	1738, 8,
            	1328, 16,
            	1278, 24,
            	1748, 32,
            1, 8, 1, /* 1738: pointer.struct.stack_st_ASN1_OBJECT */
            	1743, 0,
            0, 32, 1, /* 1743: struct.stack_st_ASN1_OBJECT */
            	36, 0,
            1, 8, 1, /* 1748: pointer.struct.stack_st_X509_ALGOR */
            	1753, 0,
            0, 32, 1, /* 1753: struct.stack_st_X509_ALGOR */
            	36, 0,
            1, 8, 1, /* 1758: pointer.struct.rsa_st */
            	1438, 0,
            1, 8, 1, /* 1763: pointer.struct.stack_st_SSL_CIPHER */
            	1768, 0,
            0, 32, 1, /* 1768: struct.stack_st_SSL_CIPHER */
            	36, 0,
            1, 8, 1, /* 1773: pointer.struct.ssl_session_st */
            	1039, 0,
            4097, 8, 0, /* 1778: pointer.func */
            1, 8, 1, /* 1781: pointer.struct.X509_VERIFY_PARAM_st */
            	1786, 0,
            0, 56, 2, /* 1786: struct.X509_VERIFY_PARAM_st */
            	48, 0,
            	1738, 48,
            1, 8, 1, /* 1793: pointer.struct.cert_st */
            	1798, 0,
            0, 296, 7, /* 1798: struct.cert_st */
            	1098, 0,
            	1758, 48,
            	1815, 56,
            	871, 64,
            	1818, 72,
            	953, 80,
            	1821, 88,
            4097, 8, 0, /* 1815: pointer.func */
            4097, 8, 0, /* 1818: pointer.func */
            4097, 8, 0, /* 1821: pointer.func */
            4097, 8, 0, /* 1824: pointer.func */
            4097, 8, 0, /* 1827: pointer.func */
            4097, 8, 0, /* 1830: pointer.func */
            4097, 8, 0, /* 1833: pointer.func */
            4097, 8, 0, /* 1836: pointer.func */
            1, 8, 1, /* 1839: pointer.struct.ssl_ctx_st */
            	1844, 0,
            0, 736, 50, /* 1844: struct.ssl_ctx_st */
            	449, 0,
            	1763, 8,
            	1763, 16,
            	1947, 24,
            	170, 32,
            	1773, 48,
            	1773, 56,
            	149, 80,
            	146, 88,
            	143, 96,
            	152, 152,
            	28, 160,
            	2023, 168,
            	28, 176,
            	2026, 184,
            	2029, 192,
            	140, 200,
            	241, 208,
            	800, 224,
            	800, 232,
            	800, 240,
            	1088, 248,
            	135, 256,
            	1830, 264,
            	315, 272,
            	1793, 304,
            	1778, 320,
            	28, 328,
            	1827, 376,
            	1824, 384,
            	1781, 392,
            	307, 408,
            	103, 416,
            	28, 424,
            	2032, 480,
            	106, 488,
            	28, 496,
            	127, 504,
            	28, 512,
            	48, 520,
            	1833, 528,
            	1836, 536,
            	2035, 552,
            	2035, 560,
            	72, 568,
            	2055, 696,
            	28, 704,
            	2058, 712,
            	28, 720,
            	2061, 728,
            1, 8, 1, /* 1947: pointer.struct.x509_store_st */
            	1952, 0,
            0, 144, 15, /* 1952: struct.x509_store_st */
            	1985, 8,
            	1995, 16,
            	1781, 24,
            	2005, 32,
            	1827, 40,
            	2008, 48,
            	2011, 56,
            	2005, 64,
            	2014, 72,
            	2017, 80,
            	197, 88,
            	2020, 96,
            	194, 104,
            	2005, 112,
            	241, 120,
            1, 8, 1, /* 1985: pointer.struct.stack_st_X509_OBJECT */
            	1990, 0,
            0, 32, 1, /* 1990: struct.stack_st_X509_OBJECT */
            	36, 0,
            1, 8, 1, /* 1995: pointer.struct.stack_st_X509_LOOKUP */
            	2000, 0,
            0, 32, 1, /* 2000: struct.stack_st_X509_LOOKUP */
            	36, 0,
            4097, 8, 0, /* 2005: pointer.func */
            4097, 8, 0, /* 2008: pointer.func */
            4097, 8, 0, /* 2011: pointer.func */
            4097, 8, 0, /* 2014: pointer.func */
            4097, 8, 0, /* 2017: pointer.func */
            4097, 8, 0, /* 2020: pointer.func */
            4097, 8, 0, /* 2023: pointer.func */
            4097, 8, 0, /* 2026: pointer.func */
            4097, 8, 0, /* 2029: pointer.func */
            4097, 8, 0, /* 2032: pointer.func */
            1, 8, 1, /* 2035: pointer.struct.ssl3_buf_freelist_st */
            	2040, 0,
            0, 24, 1, /* 2040: struct.ssl3_buf_freelist_st */
            	2045, 16,
            1, 8, 1, /* 2045: pointer.struct.ssl3_buf_freelist_entry_st */
            	2050, 0,
            0, 8, 1, /* 2050: struct.ssl3_buf_freelist_entry_st */
            	2045, 0,
            4097, 8, 0, /* 2055: pointer.func */
            4097, 8, 0, /* 2058: pointer.func */
            1, 8, 1, /* 2061: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	64, 0,
            1, 8, 1, /* 2066: pointer.struct.stack_st_X509_EXTENSION */
            	1641, 0,
            4097, 8, 0, /* 2071: pointer.func */
            0, 1, 0, /* 2074: char */
            0, 8, 0, /* 2077: long int */
        },
        .arg_entity_index = { 339, },
        .ret_entity_index = 2077,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL * new_arg_a = *((const SSL * *)new_args->args[0]);

    long *new_ret_ptr = (long *)new_args->ret;

    long (*orig_SSL_get_verify_result)(const SSL *);
    orig_SSL_get_verify_result = dlsym(RTLD_NEXT, "SSL_get_verify_result");
    *new_ret_ptr = (*orig_SSL_get_verify_result)(new_arg_a);

    syscall(889);

    return ret;
}

