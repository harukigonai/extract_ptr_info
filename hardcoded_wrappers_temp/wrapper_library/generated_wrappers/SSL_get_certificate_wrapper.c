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

X509 * bb_SSL_get_certificate(const SSL * arg_a);

X509 * SSL_get_certificate(const SSL * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_get_certificate called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_get_certificate(arg_a);
    else {
        X509 * (*orig_SSL_get_certificate)(const SSL *);
        orig_SSL_get_certificate = dlsym(RTLD_NEXT, "SSL_get_certificate");
        return orig_SSL_get_certificate(arg_a);
    }
}

X509 * bb_SSL_get_certificate(const SSL * arg_a) 
{
    X509 * ret;

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
            4097, 8, 0, /* 72: pointer.func */
            0, 128, 14, /* 75: struct.srp_ctx_st */
            	28, 0,
            	106, 8,
            	109, 16,
            	72, 24,
            	48, 32,
            	112, 40,
            	112, 48,
            	112, 56,
            	112, 64,
            	112, 72,
            	112, 80,
            	112, 88,
            	112, 96,
            	48, 104,
            4097, 8, 0, /* 106: pointer.func */
            4097, 8, 0, /* 109: pointer.func */
            1, 8, 1, /* 112: pointer.struct.bignum_st */
            	117, 0,
            0, 24, 1, /* 117: struct.bignum_st */
            	122, 0,
            1, 8, 1, /* 122: pointer.unsigned int */
            	127, 0,
            0, 4, 0, /* 127: unsigned int */
            4097, 8, 0, /* 130: pointer.func */
            0, 32, 1, /* 133: struct.stack_st_SSL_COMP */
            	36, 0,
            1, 8, 1, /* 138: pointer.struct.stack_st_SSL_COMP */
            	133, 0,
            4097, 8, 0, /* 143: pointer.func */
            4097, 8, 0, /* 146: pointer.func */
            4097, 8, 0, /* 149: pointer.func */
            4097, 8, 0, /* 152: pointer.func */
            4097, 8, 0, /* 155: pointer.func */
            4097, 8, 0, /* 158: pointer.func */
            1, 8, 1, /* 161: pointer.struct.lhash_node_st */
            	166, 0,
            0, 24, 2, /* 166: struct.lhash_node_st */
            	28, 0,
            	161, 8,
            1, 8, 1, /* 173: pointer.struct.lhash_st */
            	178, 0,
            0, 176, 3, /* 178: struct.lhash_st */
            	187, 0,
            	53, 8,
            	158, 16,
            1, 8, 1, /* 187: pointer.pointer.struct.lhash_node_st */
            	192, 0,
            1, 8, 1, /* 192: pointer.struct.lhash_node_st */
            	166, 0,
            4097, 8, 0, /* 197: pointer.func */
            4097, 8, 0, /* 200: pointer.func */
            1, 8, 1, /* 203: pointer.struct.stack_st_X509_EXTENSION */
            	208, 0,
            0, 32, 1, /* 208: struct.stack_st_X509_EXTENSION */
            	36, 0,
            0, 808, 51, /* 213: struct.ssl_st */
            	318, 8,
            	487, 16,
            	487, 24,
            	487, 32,
            	382, 48,
            	576, 80,
            	28, 88,
            	586, 104,
            	594, 120,
            	625, 128,
            	960, 136,
            	1781, 152,
            	28, 160,
            	1784, 176,
            	1766, 184,
            	1766, 192,
            	1011, 208,
            	672, 216,
            	1027, 224,
            	1011, 232,
            	672, 240,
            	1027, 248,
            	1796, 256,
            	1039, 304,
            	1827, 312,
            	1830, 328,
            	1833, 336,
            	1836, 352,
            	1839, 360,
            	1842, 368,
            	561, 392,
            	870, 408,
            	61, 464,
            	28, 472,
            	48, 480,
            	56, 504,
            	203, 512,
            	586, 520,
            	586, 544,
            	586, 560,
            	28, 568,
            	18, 584,
            	2066, 592,
            	28, 600,
            	15, 608,
            	28, 616,
            	1842, 624,
            	586, 632,
            	2061, 648,
            	0, 656,
            	75, 680,
            1, 8, 1, /* 318: pointer.struct.ssl_method_st */
            	323, 0,
            0, 232, 28, /* 323: struct.ssl_method_st */
            	382, 8,
            	385, 16,
            	385, 24,
            	382, 32,
            	382, 40,
            	388, 48,
            	388, 56,
            	391, 64,
            	382, 72,
            	382, 80,
            	382, 88,
            	394, 96,
            	397, 104,
            	400, 112,
            	382, 120,
            	403, 128,
            	406, 136,
            	409, 144,
            	412, 152,
            	415, 160,
            	418, 168,
            	421, 176,
            	424, 184,
            	427, 192,
            	430, 200,
            	418, 208,
            	481, 216,
            	484, 224,
            4097, 8, 0, /* 382: pointer.func */
            4097, 8, 0, /* 385: pointer.func */
            4097, 8, 0, /* 388: pointer.func */
            4097, 8, 0, /* 391: pointer.func */
            4097, 8, 0, /* 394: pointer.func */
            4097, 8, 0, /* 397: pointer.func */
            4097, 8, 0, /* 400: pointer.func */
            4097, 8, 0, /* 403: pointer.func */
            4097, 8, 0, /* 406: pointer.func */
            4097, 8, 0, /* 409: pointer.func */
            4097, 8, 0, /* 412: pointer.func */
            4097, 8, 0, /* 415: pointer.func */
            4097, 8, 0, /* 418: pointer.func */
            4097, 8, 0, /* 421: pointer.func */
            4097, 8, 0, /* 424: pointer.func */
            4097, 8, 0, /* 427: pointer.func */
            1, 8, 1, /* 430: pointer.struct.ssl3_enc_method */
            	435, 0,
            0, 112, 11, /* 435: struct.ssl3_enc_method */
            	460, 0,
            	463, 8,
            	382, 16,
            	466, 24,
            	460, 32,
            	469, 40,
            	472, 56,
            	10, 64,
            	10, 80,
            	475, 96,
            	478, 104,
            4097, 8, 0, /* 460: pointer.func */
            4097, 8, 0, /* 463: pointer.func */
            4097, 8, 0, /* 466: pointer.func */
            4097, 8, 0, /* 469: pointer.func */
            4097, 8, 0, /* 472: pointer.func */
            4097, 8, 0, /* 475: pointer.func */
            4097, 8, 0, /* 478: pointer.func */
            4097, 8, 0, /* 481: pointer.func */
            4097, 8, 0, /* 484: pointer.func */
            1, 8, 1, /* 487: pointer.struct.bio_st */
            	492, 0,
            0, 112, 7, /* 492: struct.bio_st */
            	509, 0,
            	553, 8,
            	48, 16,
            	28, 48,
            	556, 56,
            	556, 64,
            	561, 96,
            1, 8, 1, /* 509: pointer.struct.bio_method_st */
            	514, 0,
            0, 80, 9, /* 514: struct.bio_method_st */
            	10, 8,
            	535, 16,
            	538, 24,
            	541, 32,
            	538, 40,
            	544, 48,
            	547, 56,
            	547, 64,
            	550, 72,
            4097, 8, 0, /* 535: pointer.func */
            4097, 8, 0, /* 538: pointer.func */
            4097, 8, 0, /* 541: pointer.func */
            4097, 8, 0, /* 544: pointer.func */
            4097, 8, 0, /* 547: pointer.func */
            4097, 8, 0, /* 550: pointer.func */
            4097, 8, 0, /* 553: pointer.func */
            1, 8, 1, /* 556: pointer.struct.bio_st */
            	492, 0,
            0, 16, 1, /* 561: struct.crypto_ex_data_st */
            	566, 0,
            1, 8, 1, /* 566: pointer.struct.stack_st_void */
            	571, 0,
            0, 32, 1, /* 571: struct.stack_st_void */
            	36, 0,
            1, 8, 1, /* 576: pointer.struct.buf_mem_st */
            	581, 0,
            0, 24, 1, /* 581: struct.buf_mem_st */
            	48, 8,
            1, 8, 1, /* 586: pointer.unsigned char */
            	591, 0,
            0, 1, 0, /* 591: unsigned char */
            1, 8, 1, /* 594: pointer.struct.ssl2_state_st */
            	599, 0,
            0, 344, 9, /* 599: struct.ssl2_state_st */
            	620, 24,
            	586, 56,
            	586, 64,
            	586, 72,
            	586, 104,
            	586, 112,
            	586, 120,
            	586, 128,
            	586, 136,
            1, 8, 1, /* 620: pointer.unsigned char */
            	591, 0,
            1, 8, 1, /* 625: pointer.struct.ssl3_state_st */
            	630, 0,
            0, 1200, 10, /* 630: struct.ssl3_state_st */
            	653, 240,
            	653, 264,
            	658, 288,
            	658, 344,
            	620, 432,
            	487, 440,
            	667, 448,
            	28, 496,
            	28, 512,
            	751, 528,
            0, 24, 1, /* 653: struct.ssl3_buffer_st */
            	586, 0,
            0, 56, 3, /* 658: struct.ssl3_record_st */
            	586, 16,
            	586, 24,
            	586, 32,
            1, 8, 1, /* 667: pointer.pointer.struct.env_md_ctx_st */
            	672, 0,
            1, 8, 1, /* 672: pointer.struct.env_md_ctx_st */
            	677, 0,
            0, 48, 5, /* 677: struct.env_md_ctx_st */
            	690, 0,
            	735, 8,
            	28, 24,
            	743, 32,
            	717, 40,
            1, 8, 1, /* 690: pointer.struct.env_md_st */
            	695, 0,
            0, 120, 8, /* 695: struct.env_md_st */
            	714, 24,
            	717, 32,
            	720, 40,
            	723, 48,
            	714, 56,
            	726, 64,
            	729, 72,
            	732, 112,
            4097, 8, 0, /* 714: pointer.func */
            4097, 8, 0, /* 717: pointer.func */
            4097, 8, 0, /* 720: pointer.func */
            4097, 8, 0, /* 723: pointer.func */
            4097, 8, 0, /* 726: pointer.func */
            4097, 8, 0, /* 729: pointer.func */
            4097, 8, 0, /* 732: pointer.func */
            1, 8, 1, /* 735: pointer.struct.engine_st */
            	740, 0,
            0, 0, 0, /* 740: struct.engine_st */
            1, 8, 1, /* 743: pointer.struct.evp_pkey_ctx_st */
            	748, 0,
            0, 0, 0, /* 748: struct.evp_pkey_ctx_st */
            0, 528, 8, /* 751: struct.unknown */
            	770, 408,
            	780, 416,
            	862, 424,
            	870, 464,
            	586, 480,
            	880, 488,
            	690, 496,
            	917, 512,
            1, 8, 1, /* 770: pointer.struct.ssl_cipher_st */
            	775, 0,
            0, 88, 1, /* 775: struct.ssl_cipher_st */
            	10, 8,
            1, 8, 1, /* 780: pointer.struct.dh_st */
            	785, 0,
            0, 144, 12, /* 785: struct.dh_st */
            	112, 8,
            	112, 16,
            	112, 32,
            	112, 40,
            	812, 56,
            	112, 64,
            	112, 72,
            	586, 80,
            	112, 96,
            	561, 112,
            	826, 128,
            	735, 136,
            1, 8, 1, /* 812: pointer.struct.bn_mont_ctx_st */
            	817, 0,
            0, 96, 3, /* 817: struct.bn_mont_ctx_st */
            	117, 8,
            	117, 32,
            	117, 56,
            1, 8, 1, /* 826: pointer.struct.dh_method */
            	831, 0,
            0, 72, 8, /* 831: struct.dh_method */
            	10, 0,
            	850, 8,
            	853, 16,
            	856, 24,
            	850, 32,
            	850, 40,
            	48, 56,
            	859, 64,
            4097, 8, 0, /* 850: pointer.func */
            4097, 8, 0, /* 853: pointer.func */
            4097, 8, 0, /* 856: pointer.func */
            4097, 8, 0, /* 859: pointer.func */
            1, 8, 1, /* 862: pointer.struct.ec_key_st */
            	867, 0,
            0, 0, 0, /* 867: struct.ec_key_st */
            1, 8, 1, /* 870: pointer.struct.stack_st_X509_NAME */
            	875, 0,
            0, 32, 1, /* 875: struct.stack_st_X509_NAME */
            	36, 0,
            1, 8, 1, /* 880: pointer.struct.evp_cipher_st */
            	885, 0,
            0, 88, 7, /* 885: struct.evp_cipher_st */
            	902, 24,
            	905, 32,
            	908, 40,
            	911, 56,
            	911, 64,
            	914, 72,
            	28, 80,
            4097, 8, 0, /* 902: pointer.func */
            4097, 8, 0, /* 905: pointer.func */
            4097, 8, 0, /* 908: pointer.func */
            4097, 8, 0, /* 911: pointer.func */
            4097, 8, 0, /* 914: pointer.func */
            1, 8, 1, /* 917: pointer.struct.ssl_comp_st */
            	922, 0,
            0, 24, 2, /* 922: struct.ssl_comp_st */
            	10, 8,
            	929, 16,
            1, 8, 1, /* 929: pointer.struct.comp_method_st */
            	934, 0,
            0, 64, 7, /* 934: struct.comp_method_st */
            	10, 8,
            	951, 16,
            	954, 24,
            	957, 32,
            	957, 40,
            	427, 48,
            	427, 56,
            4097, 8, 0, /* 951: pointer.func */
            4097, 8, 0, /* 954: pointer.func */
            4097, 8, 0, /* 957: pointer.func */
            1, 8, 1, /* 960: pointer.struct.dtls1_state_st */
            	965, 0,
            0, 888, 7, /* 965: struct.dtls1_state_st */
            	982, 576,
            	982, 592,
            	987, 608,
            	987, 616,
            	982, 624,
            	995, 648,
            	995, 736,
            0, 16, 1, /* 982: struct.record_pqueue_st */
            	987, 8,
            1, 8, 1, /* 987: pointer.struct._pqueue */
            	992, 0,
            0, 0, 0, /* 992: struct._pqueue */
            0, 88, 1, /* 995: struct.hm_header_st */
            	1000, 48,
            0, 40, 4, /* 1000: struct.dtls1_retransmit_state */
            	1011, 0,
            	672, 8,
            	1027, 16,
            	1039, 24,
            1, 8, 1, /* 1011: pointer.struct.evp_cipher_ctx_st */
            	1016, 0,
            0, 168, 4, /* 1016: struct.evp_cipher_ctx_st */
            	880, 0,
            	735, 8,
            	28, 96,
            	28, 120,
            1, 8, 1, /* 1027: pointer.struct.comp_ctx_st */
            	1032, 0,
            0, 56, 2, /* 1032: struct.comp_ctx_st */
            	929, 0,
            	561, 40,
            1, 8, 1, /* 1039: pointer.struct.ssl_session_st */
            	1044, 0,
            0, 352, 14, /* 1044: struct.ssl_session_st */
            	48, 144,
            	48, 152,
            	1075, 168,
            	1117, 176,
            	770, 224,
            	1766, 240,
            	561, 248,
            	1776, 264,
            	1776, 272,
            	48, 280,
            	586, 296,
            	586, 312,
            	586, 320,
            	48, 344,
            1, 8, 1, /* 1075: pointer.struct.sess_cert_st */
            	1080, 0,
            0, 248, 5, /* 1080: struct.sess_cert_st */
            	1093, 0,
            	1103, 16,
            	1761, 216,
            	780, 224,
            	862, 232,
            1, 8, 1, /* 1093: pointer.struct.stack_st_X509 */
            	1098, 0,
            0, 32, 1, /* 1098: struct.stack_st_X509 */
            	36, 0,
            1, 8, 1, /* 1103: pointer.struct.cert_pkey_st */
            	1108, 0,
            0, 24, 3, /* 1108: struct.cert_pkey_st */
            	1117, 0,
            	1401, 8,
            	690, 16,
            1, 8, 1, /* 1117: pointer.struct.x509_st */
            	1122, 0,
            0, 184, 12, /* 1122: struct.x509_st */
            	1149, 0,
            	1189, 8,
            	1278, 16,
            	48, 32,
            	561, 40,
            	1283, 104,
            	1654, 112,
            	1678, 120,
            	1686, 128,
            	1696, 136,
            	1701, 144,
            	1723, 176,
            1, 8, 1, /* 1149: pointer.struct.x509_cinf_st */
            	1154, 0,
            0, 104, 11, /* 1154: struct.x509_cinf_st */
            	1179, 0,
            	1179, 8,
            	1189, 16,
            	1346, 24,
            	1370, 32,
            	1346, 40,
            	1387, 48,
            	1278, 56,
            	1278, 64,
            	1644, 72,
            	1649, 80,
            1, 8, 1, /* 1179: pointer.struct.asn1_string_st */
            	1184, 0,
            0, 24, 1, /* 1184: struct.asn1_string_st */
            	586, 8,
            1, 8, 1, /* 1189: pointer.struct.X509_algor_st */
            	1194, 0,
            0, 16, 2, /* 1194: struct.X509_algor_st */
            	1201, 0,
            	1215, 8,
            1, 8, 1, /* 1201: pointer.struct.asn1_object_st */
            	1206, 0,
            0, 40, 3, /* 1206: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	620, 24,
            1, 8, 1, /* 1215: pointer.struct.asn1_type_st */
            	1220, 0,
            0, 16, 1, /* 1220: struct.asn1_type_st */
            	1225, 8,
            0, 8, 20, /* 1225: union.unknown */
            	48, 0,
            	1268, 0,
            	1201, 0,
            	1179, 0,
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
            	1333, 0,
            	1268, 0,
            	1268, 0,
            	1338, 0,
            1, 8, 1, /* 1268: pointer.struct.asn1_string_st */
            	1184, 0,
            1, 8, 1, /* 1273: pointer.struct.asn1_string_st */
            	1184, 0,
            1, 8, 1, /* 1278: pointer.struct.asn1_string_st */
            	1184, 0,
            1, 8, 1, /* 1283: pointer.struct.asn1_string_st */
            	1184, 0,
            1, 8, 1, /* 1288: pointer.struct.asn1_string_st */
            	1184, 0,
            1, 8, 1, /* 1293: pointer.struct.asn1_string_st */
            	1184, 0,
            1, 8, 1, /* 1298: pointer.struct.asn1_string_st */
            	1184, 0,
            1, 8, 1, /* 1303: pointer.struct.asn1_string_st */
            	1184, 0,
            1, 8, 1, /* 1308: pointer.struct.asn1_string_st */
            	1184, 0,
            1, 8, 1, /* 1313: pointer.struct.asn1_string_st */
            	1184, 0,
            1, 8, 1, /* 1318: pointer.struct.asn1_string_st */
            	1184, 0,
            1, 8, 1, /* 1323: pointer.struct.asn1_string_st */
            	1184, 0,
            1, 8, 1, /* 1328: pointer.struct.asn1_string_st */
            	1184, 0,
            1, 8, 1, /* 1333: pointer.struct.asn1_string_st */
            	1184, 0,
            1, 8, 1, /* 1338: pointer.struct.ASN1_VALUE_st */
            	1343, 0,
            0, 0, 0, /* 1343: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1346: pointer.struct.X509_name_st */
            	1351, 0,
            0, 40, 3, /* 1351: struct.X509_name_st */
            	1360, 0,
            	576, 16,
            	586, 24,
            1, 8, 1, /* 1360: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1365, 0,
            0, 32, 1, /* 1365: struct.stack_st_X509_NAME_ENTRY */
            	36, 0,
            1, 8, 1, /* 1370: pointer.struct.X509_val_st */
            	1375, 0,
            0, 16, 2, /* 1375: struct.X509_val_st */
            	1382, 0,
            	1382, 8,
            1, 8, 1, /* 1382: pointer.struct.asn1_string_st */
            	1184, 0,
            1, 8, 1, /* 1387: pointer.struct.X509_pubkey_st */
            	1392, 0,
            0, 24, 3, /* 1392: struct.X509_pubkey_st */
            	1189, 0,
            	1278, 8,
            	1401, 16,
            1, 8, 1, /* 1401: pointer.struct.evp_pkey_st */
            	1406, 0,
            0, 56, 4, /* 1406: struct.evp_pkey_st */
            	1417, 16,
            	735, 24,
            	1425, 32,
            	1634, 48,
            1, 8, 1, /* 1417: pointer.struct.evp_pkey_asn1_method_st */
            	1422, 0,
            0, 0, 0, /* 1422: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 1425: union.unknown */
            	48, 0,
            	1438, 0,
            	1543, 0,
            	1624, 0,
            	1629, 0,
            1, 8, 1, /* 1438: pointer.struct.rsa_st */
            	1443, 0,
            0, 168, 17, /* 1443: struct.rsa_st */
            	1480, 16,
            	735, 24,
            	112, 32,
            	112, 40,
            	112, 48,
            	112, 56,
            	112, 64,
            	112, 72,
            	112, 80,
            	112, 88,
            	561, 96,
            	812, 120,
            	812, 128,
            	812, 136,
            	48, 144,
            	1535, 152,
            	1535, 160,
            1, 8, 1, /* 1480: pointer.struct.rsa_meth_st */
            	1485, 0,
            0, 112, 13, /* 1485: struct.rsa_meth_st */
            	10, 0,
            	1514, 8,
            	1514, 16,
            	1514, 24,
            	1514, 32,
            	1517, 40,
            	1520, 48,
            	1523, 56,
            	1523, 64,
            	48, 80,
            	1526, 88,
            	1529, 96,
            	1532, 104,
            4097, 8, 0, /* 1514: pointer.func */
            4097, 8, 0, /* 1517: pointer.func */
            4097, 8, 0, /* 1520: pointer.func */
            4097, 8, 0, /* 1523: pointer.func */
            4097, 8, 0, /* 1526: pointer.func */
            4097, 8, 0, /* 1529: pointer.func */
            4097, 8, 0, /* 1532: pointer.func */
            1, 8, 1, /* 1535: pointer.struct.bn_blinding_st */
            	1540, 0,
            0, 0, 0, /* 1540: struct.bn_blinding_st */
            1, 8, 1, /* 1543: pointer.struct.dsa_st */
            	1548, 0,
            0, 136, 11, /* 1548: struct.dsa_st */
            	112, 24,
            	112, 32,
            	112, 40,
            	112, 48,
            	112, 56,
            	112, 64,
            	112, 72,
            	812, 88,
            	561, 104,
            	1573, 120,
            	735, 128,
            1, 8, 1, /* 1573: pointer.struct.dsa_method */
            	1578, 0,
            0, 96, 11, /* 1578: struct.dsa_method */
            	10, 0,
            	1603, 8,
            	1606, 16,
            	1609, 24,
            	1612, 32,
            	1615, 40,
            	1618, 48,
            	1618, 56,
            	48, 72,
            	1621, 80,
            	1618, 88,
            4097, 8, 0, /* 1603: pointer.func */
            4097, 8, 0, /* 1606: pointer.func */
            4097, 8, 0, /* 1609: pointer.func */
            4097, 8, 0, /* 1612: pointer.func */
            4097, 8, 0, /* 1615: pointer.func */
            4097, 8, 0, /* 1618: pointer.func */
            4097, 8, 0, /* 1621: pointer.func */
            1, 8, 1, /* 1624: pointer.struct.dh_st */
            	785, 0,
            1, 8, 1, /* 1629: pointer.struct.ec_key_st */
            	867, 0,
            1, 8, 1, /* 1634: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1639, 0,
            0, 32, 1, /* 1639: struct.stack_st_X509_ATTRIBUTE */
            	36, 0,
            1, 8, 1, /* 1644: pointer.struct.stack_st_X509_EXTENSION */
            	208, 0,
            0, 24, 1, /* 1649: struct.ASN1_ENCODING_st */
            	586, 0,
            1, 8, 1, /* 1654: pointer.struct.AUTHORITY_KEYID_st */
            	1659, 0,
            0, 24, 3, /* 1659: struct.AUTHORITY_KEYID_st */
            	1283, 0,
            	1668, 8,
            	1179, 16,
            1, 8, 1, /* 1668: pointer.struct.stack_st_GENERAL_NAME */
            	1673, 0,
            0, 32, 1, /* 1673: struct.stack_st_GENERAL_NAME */
            	36, 0,
            1, 8, 1, /* 1678: pointer.struct.X509_POLICY_CACHE_st */
            	1683, 0,
            0, 0, 0, /* 1683: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1686: pointer.struct.stack_st_DIST_POINT */
            	1691, 0,
            0, 32, 1, /* 1691: struct.stack_st_DIST_POINT */
            	36, 0,
            1, 8, 1, /* 1696: pointer.struct.stack_st_GENERAL_NAME */
            	1673, 0,
            1, 8, 1, /* 1701: pointer.struct.NAME_CONSTRAINTS_st */
            	1706, 0,
            0, 16, 2, /* 1706: struct.NAME_CONSTRAINTS_st */
            	1713, 0,
            	1713, 8,
            1, 8, 1, /* 1713: pointer.struct.stack_st_GENERAL_SUBTREE */
            	1718, 0,
            0, 32, 1, /* 1718: struct.stack_st_GENERAL_SUBTREE */
            	36, 0,
            1, 8, 1, /* 1723: pointer.struct.x509_cert_aux_st */
            	1728, 0,
            0, 40, 5, /* 1728: struct.x509_cert_aux_st */
            	1741, 0,
            	1741, 8,
            	1333, 16,
            	1283, 24,
            	1751, 32,
            1, 8, 1, /* 1741: pointer.struct.stack_st_ASN1_OBJECT */
            	1746, 0,
            0, 32, 1, /* 1746: struct.stack_st_ASN1_OBJECT */
            	36, 0,
            1, 8, 1, /* 1751: pointer.struct.stack_st_X509_ALGOR */
            	1756, 0,
            0, 32, 1, /* 1756: struct.stack_st_X509_ALGOR */
            	36, 0,
            1, 8, 1, /* 1761: pointer.struct.rsa_st */
            	1443, 0,
            1, 8, 1, /* 1766: pointer.struct.stack_st_SSL_CIPHER */
            	1771, 0,
            0, 32, 1, /* 1771: struct.stack_st_SSL_CIPHER */
            	36, 0,
            1, 8, 1, /* 1776: pointer.struct.ssl_session_st */
            	1044, 0,
            4097, 8, 0, /* 1781: pointer.func */
            1, 8, 1, /* 1784: pointer.struct.X509_VERIFY_PARAM_st */
            	1789, 0,
            0, 56, 2, /* 1789: struct.X509_VERIFY_PARAM_st */
            	48, 0,
            	1741, 48,
            1, 8, 1, /* 1796: pointer.struct.cert_st */
            	1801, 0,
            0, 296, 7, /* 1801: struct.cert_st */
            	1103, 0,
            	1761, 48,
            	1818, 56,
            	780, 64,
            	1821, 72,
            	862, 80,
            	1824, 88,
            4097, 8, 0, /* 1818: pointer.func */
            4097, 8, 0, /* 1821: pointer.func */
            4097, 8, 0, /* 1824: pointer.func */
            4097, 8, 0, /* 1827: pointer.func */
            4097, 8, 0, /* 1830: pointer.func */
            4097, 8, 0, /* 1833: pointer.func */
            4097, 8, 0, /* 1836: pointer.func */
            4097, 8, 0, /* 1839: pointer.func */
            1, 8, 1, /* 1842: pointer.struct.ssl_ctx_st */
            	1847, 0,
            0, 736, 50, /* 1847: struct.ssl_ctx_st */
            	318, 0,
            	1766, 8,
            	1766, 16,
            	1950, 24,
            	173, 32,
            	1776, 48,
            	1776, 56,
            	152, 80,
            	149, 88,
            	146, 96,
            	155, 152,
            	28, 160,
            	2026, 168,
            	28, 176,
            	2029, 184,
            	2032, 192,
            	143, 200,
            	561, 208,
            	690, 224,
            	690, 232,
            	690, 240,
            	1093, 248,
            	138, 256,
            	1833, 264,
            	870, 272,
            	1796, 304,
            	1781, 320,
            	28, 328,
            	1830, 376,
            	1827, 384,
            	1784, 392,
            	735, 408,
            	106, 416,
            	28, 424,
            	2035, 480,
            	109, 488,
            	28, 496,
            	130, 504,
            	28, 512,
            	48, 520,
            	1836, 528,
            	1839, 536,
            	2038, 552,
            	2038, 560,
            	75, 568,
            	2058, 696,
            	28, 704,
            	69, 712,
            	28, 720,
            	2061, 728,
            1, 8, 1, /* 1950: pointer.struct.x509_store_st */
            	1955, 0,
            0, 144, 15, /* 1955: struct.x509_store_st */
            	1988, 8,
            	1998, 16,
            	1784, 24,
            	2008, 32,
            	1830, 40,
            	2011, 48,
            	2014, 56,
            	2008, 64,
            	2017, 72,
            	2020, 80,
            	200, 88,
            	2023, 96,
            	197, 104,
            	2008, 112,
            	561, 120,
            1, 8, 1, /* 1988: pointer.struct.stack_st_X509_OBJECT */
            	1993, 0,
            0, 32, 1, /* 1993: struct.stack_st_X509_OBJECT */
            	36, 0,
            1, 8, 1, /* 1998: pointer.struct.stack_st_X509_LOOKUP */
            	2003, 0,
            0, 32, 1, /* 2003: struct.stack_st_X509_LOOKUP */
            	36, 0,
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
            1, 8, 1, /* 2038: pointer.struct.ssl3_buf_freelist_st */
            	2043, 0,
            0, 24, 1, /* 2043: struct.ssl3_buf_freelist_st */
            	2048, 16,
            1, 8, 1, /* 2048: pointer.struct.ssl3_buf_freelist_entry_st */
            	2053, 0,
            0, 8, 1, /* 2053: struct.ssl3_buf_freelist_entry_st */
            	2048, 0,
            4097, 8, 0, /* 2058: pointer.func */
            1, 8, 1, /* 2061: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	64, 0,
            4097, 8, 0, /* 2066: pointer.func */
            1, 8, 1, /* 2069: pointer.struct.ssl_st */
            	213, 0,
            0, 1, 0, /* 2074: char */
        },
        .arg_entity_index = { 2069, },
        .ret_entity_index = 1117,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL * new_arg_a = *((const SSL * *)new_args->args[0]);

    X509 * *new_ret_ptr = (X509 * *)new_args->ret;

    X509 * (*orig_SSL_get_certificate)(const SSL *);
    orig_SSL_get_certificate = dlsym(RTLD_NEXT, "SSL_get_certificate");
    *new_ret_ptr = (*orig_SSL_get_certificate)(new_arg_a);

    syscall(889);

    return ret;
}

