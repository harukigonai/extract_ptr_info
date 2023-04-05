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

SSL_CTX * bb_SSL_get_SSL_CTX(const SSL * arg_a);

SSL_CTX * SSL_get_SSL_CTX(const SSL * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_get_SSL_CTX called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_get_SSL_CTX(arg_a);
    else {
        SSL_CTX * (*orig_SSL_get_SSL_CTX)(const SSL *);
        orig_SSL_get_SSL_CTX = dlsym(RTLD_NEXT, "SSL_get_SSL_CTX");
        return orig_SSL_get_SSL_CTX(arg_a);
    }
}

SSL_CTX * bb_SSL_get_SSL_CTX(const SSL * arg_a) 
{
    SSL_CTX * ret;

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
            1, 8, 1, /* 64: pointer.struct.ssl_session_st */
            	69, 0,
            0, 352, 14, /* 69: struct.ssl_session_st */
            	48, 144,
            	48, 152,
            	100, 168,
            	142, 176,
            	995, 224,
            	1005, 240,
            	609, 248,
            	1015, 264,
            	1015, 272,
            	48, 280,
            	214, 296,
            	214, 312,
            	214, 320,
            	48, 344,
            1, 8, 1, /* 100: pointer.struct.sess_cert_st */
            	105, 0,
            0, 248, 5, /* 105: struct.sess_cert_st */
            	118, 0,
            	128, 16,
            	980, 216,
            	985, 224,
            	990, 232,
            1, 8, 1, /* 118: pointer.struct.stack_st_X509 */
            	123, 0,
            0, 32, 1, /* 123: struct.stack_st_X509 */
            	36, 0,
            1, 8, 1, /* 128: pointer.struct.cert_pkey_st */
            	133, 0,
            0, 24, 3, /* 133: struct.cert_pkey_st */
            	142, 0,
            	449, 8,
            	935, 16,
            1, 8, 1, /* 142: pointer.struct.x509_st */
            	147, 0,
            0, 184, 12, /* 147: struct.x509_st */
            	174, 0,
            	222, 8,
            	316, 16,
            	48, 32,
            	609, 40,
            	321, 104,
            	828, 112,
            	852, 120,
            	860, 128,
            	870, 136,
            	875, 144,
            	897, 176,
            1, 8, 1, /* 174: pointer.struct.x509_cinf_st */
            	179, 0,
            0, 104, 11, /* 179: struct.x509_cinf_st */
            	204, 0,
            	204, 8,
            	222, 16,
            	384, 24,
            	418, 32,
            	384, 40,
            	435, 48,
            	316, 56,
            	316, 64,
            	813, 72,
            	823, 80,
            1, 8, 1, /* 204: pointer.struct.asn1_string_st */
            	209, 0,
            0, 24, 1, /* 209: struct.asn1_string_st */
            	214, 8,
            1, 8, 1, /* 214: pointer.unsigned char */
            	219, 0,
            0, 1, 0, /* 219: unsigned char */
            1, 8, 1, /* 222: pointer.struct.X509_algor_st */
            	227, 0,
            0, 16, 2, /* 227: struct.X509_algor_st */
            	234, 0,
            	253, 8,
            1, 8, 1, /* 234: pointer.struct.asn1_object_st */
            	239, 0,
            0, 40, 3, /* 239: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	248, 24,
            1, 8, 1, /* 248: pointer.unsigned char */
            	219, 0,
            1, 8, 1, /* 253: pointer.struct.asn1_type_st */
            	258, 0,
            0, 16, 1, /* 258: struct.asn1_type_st */
            	263, 8,
            0, 8, 20, /* 263: union.unknown */
            	48, 0,
            	306, 0,
            	234, 0,
            	204, 0,
            	311, 0,
            	316, 0,
            	321, 0,
            	326, 0,
            	331, 0,
            	336, 0,
            	341, 0,
            	346, 0,
            	351, 0,
            	356, 0,
            	361, 0,
            	366, 0,
            	371, 0,
            	306, 0,
            	306, 0,
            	376, 0,
            1, 8, 1, /* 306: pointer.struct.asn1_string_st */
            	209, 0,
            1, 8, 1, /* 311: pointer.struct.asn1_string_st */
            	209, 0,
            1, 8, 1, /* 316: pointer.struct.asn1_string_st */
            	209, 0,
            1, 8, 1, /* 321: pointer.struct.asn1_string_st */
            	209, 0,
            1, 8, 1, /* 326: pointer.struct.asn1_string_st */
            	209, 0,
            1, 8, 1, /* 331: pointer.struct.asn1_string_st */
            	209, 0,
            1, 8, 1, /* 336: pointer.struct.asn1_string_st */
            	209, 0,
            1, 8, 1, /* 341: pointer.struct.asn1_string_st */
            	209, 0,
            1, 8, 1, /* 346: pointer.struct.asn1_string_st */
            	209, 0,
            1, 8, 1, /* 351: pointer.struct.asn1_string_st */
            	209, 0,
            1, 8, 1, /* 356: pointer.struct.asn1_string_st */
            	209, 0,
            1, 8, 1, /* 361: pointer.struct.asn1_string_st */
            	209, 0,
            1, 8, 1, /* 366: pointer.struct.asn1_string_st */
            	209, 0,
            1, 8, 1, /* 371: pointer.struct.asn1_string_st */
            	209, 0,
            1, 8, 1, /* 376: pointer.struct.ASN1_VALUE_st */
            	381, 0,
            0, 0, 0, /* 381: struct.ASN1_VALUE_st */
            1, 8, 1, /* 384: pointer.struct.X509_name_st */
            	389, 0,
            0, 40, 3, /* 389: struct.X509_name_st */
            	398, 0,
            	408, 16,
            	214, 24,
            1, 8, 1, /* 398: pointer.struct.stack_st_X509_NAME_ENTRY */
            	403, 0,
            0, 32, 1, /* 403: struct.stack_st_X509_NAME_ENTRY */
            	36, 0,
            1, 8, 1, /* 408: pointer.struct.buf_mem_st */
            	413, 0,
            0, 24, 1, /* 413: struct.buf_mem_st */
            	48, 8,
            1, 8, 1, /* 418: pointer.struct.X509_val_st */
            	423, 0,
            0, 16, 2, /* 423: struct.X509_val_st */
            	430, 0,
            	430, 8,
            1, 8, 1, /* 430: pointer.struct.asn1_string_st */
            	209, 0,
            1, 8, 1, /* 435: pointer.struct.X509_pubkey_st */
            	440, 0,
            0, 24, 3, /* 440: struct.X509_pubkey_st */
            	222, 0,
            	316, 8,
            	449, 16,
            1, 8, 1, /* 449: pointer.struct.evp_pkey_st */
            	454, 0,
            0, 56, 4, /* 454: struct.evp_pkey_st */
            	465, 16,
            	473, 24,
            	481, 32,
            	803, 48,
            1, 8, 1, /* 465: pointer.struct.evp_pkey_asn1_method_st */
            	470, 0,
            0, 0, 0, /* 470: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 473: pointer.struct.engine_st */
            	478, 0,
            0, 0, 0, /* 478: struct.engine_st */
            0, 8, 5, /* 481: union.unknown */
            	48, 0,
            	494, 0,
            	646, 0,
            	727, 0,
            	795, 0,
            1, 8, 1, /* 494: pointer.struct.rsa_st */
            	499, 0,
            0, 168, 17, /* 499: struct.rsa_st */
            	536, 16,
            	473, 24,
            	591, 32,
            	591, 40,
            	591, 48,
            	591, 56,
            	591, 64,
            	591, 72,
            	591, 80,
            	591, 88,
            	609, 96,
            	624, 120,
            	624, 128,
            	624, 136,
            	48, 144,
            	638, 152,
            	638, 160,
            1, 8, 1, /* 536: pointer.struct.rsa_meth_st */
            	541, 0,
            0, 112, 13, /* 541: struct.rsa_meth_st */
            	10, 0,
            	570, 8,
            	570, 16,
            	570, 24,
            	570, 32,
            	573, 40,
            	576, 48,
            	579, 56,
            	579, 64,
            	48, 80,
            	582, 88,
            	585, 96,
            	588, 104,
            4097, 8, 0, /* 570: pointer.func */
            4097, 8, 0, /* 573: pointer.func */
            4097, 8, 0, /* 576: pointer.func */
            4097, 8, 0, /* 579: pointer.func */
            4097, 8, 0, /* 582: pointer.func */
            4097, 8, 0, /* 585: pointer.func */
            4097, 8, 0, /* 588: pointer.func */
            1, 8, 1, /* 591: pointer.struct.bignum_st */
            	596, 0,
            0, 24, 1, /* 596: struct.bignum_st */
            	601, 0,
            1, 8, 1, /* 601: pointer.unsigned int */
            	606, 0,
            0, 4, 0, /* 606: unsigned int */
            0, 16, 1, /* 609: struct.crypto_ex_data_st */
            	614, 0,
            1, 8, 1, /* 614: pointer.struct.stack_st_void */
            	619, 0,
            0, 32, 1, /* 619: struct.stack_st_void */
            	36, 0,
            1, 8, 1, /* 624: pointer.struct.bn_mont_ctx_st */
            	629, 0,
            0, 96, 3, /* 629: struct.bn_mont_ctx_st */
            	596, 8,
            	596, 32,
            	596, 56,
            1, 8, 1, /* 638: pointer.struct.bn_blinding_st */
            	643, 0,
            0, 0, 0, /* 643: struct.bn_blinding_st */
            1, 8, 1, /* 646: pointer.struct.dsa_st */
            	651, 0,
            0, 136, 11, /* 651: struct.dsa_st */
            	591, 24,
            	591, 32,
            	591, 40,
            	591, 48,
            	591, 56,
            	591, 64,
            	591, 72,
            	624, 88,
            	609, 104,
            	676, 120,
            	473, 128,
            1, 8, 1, /* 676: pointer.struct.dsa_method */
            	681, 0,
            0, 96, 11, /* 681: struct.dsa_method */
            	10, 0,
            	706, 8,
            	709, 16,
            	712, 24,
            	715, 32,
            	718, 40,
            	721, 48,
            	721, 56,
            	48, 72,
            	724, 80,
            	721, 88,
            4097, 8, 0, /* 706: pointer.func */
            4097, 8, 0, /* 709: pointer.func */
            4097, 8, 0, /* 712: pointer.func */
            4097, 8, 0, /* 715: pointer.func */
            4097, 8, 0, /* 718: pointer.func */
            4097, 8, 0, /* 721: pointer.func */
            4097, 8, 0, /* 724: pointer.func */
            1, 8, 1, /* 727: pointer.struct.dh_st */
            	732, 0,
            0, 144, 12, /* 732: struct.dh_st */
            	591, 8,
            	591, 16,
            	591, 32,
            	591, 40,
            	624, 56,
            	591, 64,
            	591, 72,
            	214, 80,
            	591, 96,
            	609, 112,
            	759, 128,
            	473, 136,
            1, 8, 1, /* 759: pointer.struct.dh_method */
            	764, 0,
            0, 72, 8, /* 764: struct.dh_method */
            	10, 0,
            	783, 8,
            	786, 16,
            	789, 24,
            	783, 32,
            	783, 40,
            	48, 56,
            	792, 64,
            4097, 8, 0, /* 783: pointer.func */
            4097, 8, 0, /* 786: pointer.func */
            4097, 8, 0, /* 789: pointer.func */
            4097, 8, 0, /* 792: pointer.func */
            1, 8, 1, /* 795: pointer.struct.ec_key_st */
            	800, 0,
            0, 0, 0, /* 800: struct.ec_key_st */
            1, 8, 1, /* 803: pointer.struct.stack_st_X509_ATTRIBUTE */
            	808, 0,
            0, 32, 1, /* 808: struct.stack_st_X509_ATTRIBUTE */
            	36, 0,
            1, 8, 1, /* 813: pointer.struct.stack_st_X509_EXTENSION */
            	818, 0,
            0, 32, 1, /* 818: struct.stack_st_X509_EXTENSION */
            	36, 0,
            0, 24, 1, /* 823: struct.ASN1_ENCODING_st */
            	214, 0,
            1, 8, 1, /* 828: pointer.struct.AUTHORITY_KEYID_st */
            	833, 0,
            0, 24, 3, /* 833: struct.AUTHORITY_KEYID_st */
            	321, 0,
            	842, 8,
            	204, 16,
            1, 8, 1, /* 842: pointer.struct.stack_st_GENERAL_NAME */
            	847, 0,
            0, 32, 1, /* 847: struct.stack_st_GENERAL_NAME */
            	36, 0,
            1, 8, 1, /* 852: pointer.struct.X509_POLICY_CACHE_st */
            	857, 0,
            0, 0, 0, /* 857: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 860: pointer.struct.stack_st_DIST_POINT */
            	865, 0,
            0, 32, 1, /* 865: struct.stack_st_DIST_POINT */
            	36, 0,
            1, 8, 1, /* 870: pointer.struct.stack_st_GENERAL_NAME */
            	847, 0,
            1, 8, 1, /* 875: pointer.struct.NAME_CONSTRAINTS_st */
            	880, 0,
            0, 16, 2, /* 880: struct.NAME_CONSTRAINTS_st */
            	887, 0,
            	887, 8,
            1, 8, 1, /* 887: pointer.struct.stack_st_GENERAL_SUBTREE */
            	892, 0,
            0, 32, 1, /* 892: struct.stack_st_GENERAL_SUBTREE */
            	36, 0,
            1, 8, 1, /* 897: pointer.struct.x509_cert_aux_st */
            	902, 0,
            0, 40, 5, /* 902: struct.x509_cert_aux_st */
            	915, 0,
            	915, 8,
            	371, 16,
            	321, 24,
            	925, 32,
            1, 8, 1, /* 915: pointer.struct.stack_st_ASN1_OBJECT */
            	920, 0,
            0, 32, 1, /* 920: struct.stack_st_ASN1_OBJECT */
            	36, 0,
            1, 8, 1, /* 925: pointer.struct.stack_st_X509_ALGOR */
            	930, 0,
            0, 32, 1, /* 930: struct.stack_st_X509_ALGOR */
            	36, 0,
            1, 8, 1, /* 935: pointer.struct.env_md_st */
            	940, 0,
            0, 120, 8, /* 940: struct.env_md_st */
            	959, 24,
            	962, 32,
            	965, 40,
            	968, 48,
            	959, 56,
            	971, 64,
            	974, 72,
            	977, 112,
            4097, 8, 0, /* 959: pointer.func */
            4097, 8, 0, /* 962: pointer.func */
            4097, 8, 0, /* 965: pointer.func */
            4097, 8, 0, /* 968: pointer.func */
            4097, 8, 0, /* 971: pointer.func */
            4097, 8, 0, /* 974: pointer.func */
            4097, 8, 0, /* 977: pointer.func */
            1, 8, 1, /* 980: pointer.struct.rsa_st */
            	499, 0,
            1, 8, 1, /* 985: pointer.struct.dh_st */
            	732, 0,
            1, 8, 1, /* 990: pointer.struct.ec_key_st */
            	800, 0,
            1, 8, 1, /* 995: pointer.struct.ssl_cipher_st */
            	1000, 0,
            0, 88, 1, /* 1000: struct.ssl_cipher_st */
            	10, 8,
            1, 8, 1, /* 1005: pointer.struct.stack_st_SSL_CIPHER */
            	1010, 0,
            0, 32, 1, /* 1010: struct.stack_st_SSL_CIPHER */
            	36, 0,
            1, 8, 1, /* 1015: pointer.struct.ssl_session_st */
            	69, 0,
            0, 56, 2, /* 1020: struct.comp_ctx_st */
            	1027, 0,
            	609, 40,
            1, 8, 1, /* 1027: pointer.struct.comp_method_st */
            	1032, 0,
            0, 64, 7, /* 1032: struct.comp_method_st */
            	10, 8,
            	1049, 16,
            	1052, 24,
            	1055, 32,
            	1055, 40,
            	1058, 48,
            	1058, 56,
            4097, 8, 0, /* 1049: pointer.func */
            4097, 8, 0, /* 1052: pointer.func */
            4097, 8, 0, /* 1055: pointer.func */
            4097, 8, 0, /* 1058: pointer.func */
            1, 8, 1, /* 1061: pointer.struct.comp_ctx_st */
            	1020, 0,
            0, 168, 4, /* 1066: struct.evp_cipher_ctx_st */
            	1077, 0,
            	473, 8,
            	28, 96,
            	28, 120,
            1, 8, 1, /* 1077: pointer.struct.evp_cipher_st */
            	1082, 0,
            0, 88, 7, /* 1082: struct.evp_cipher_st */
            	1099, 24,
            	1102, 32,
            	1105, 40,
            	1108, 56,
            	1108, 64,
            	1111, 72,
            	28, 80,
            4097, 8, 0, /* 1099: pointer.func */
            4097, 8, 0, /* 1102: pointer.func */
            4097, 8, 0, /* 1105: pointer.func */
            4097, 8, 0, /* 1108: pointer.func */
            4097, 8, 0, /* 1111: pointer.func */
            0, 40, 4, /* 1114: struct.dtls1_retransmit_state */
            	1125, 0,
            	1130, 8,
            	1061, 16,
            	64, 24,
            1, 8, 1, /* 1125: pointer.struct.evp_cipher_ctx_st */
            	1066, 0,
            1, 8, 1, /* 1130: pointer.struct.env_md_ctx_st */
            	1135, 0,
            0, 48, 5, /* 1135: struct.env_md_ctx_st */
            	935, 0,
            	473, 8,
            	28, 24,
            	1148, 32,
            	962, 40,
            1, 8, 1, /* 1148: pointer.struct.evp_pkey_ctx_st */
            	1153, 0,
            0, 0, 0, /* 1153: struct.evp_pkey_ctx_st */
            1, 8, 1, /* 1156: pointer.struct._pqueue */
            	1161, 0,
            0, 0, 0, /* 1161: struct._pqueue */
            0, 888, 7, /* 1164: struct.dtls1_state_st */
            	1181, 576,
            	1181, 592,
            	1156, 608,
            	1156, 616,
            	1181, 624,
            	1186, 648,
            	1186, 736,
            0, 16, 1, /* 1181: struct.record_pqueue_st */
            	1156, 8,
            0, 88, 1, /* 1186: struct.hm_header_st */
            	1114, 48,
            1, 8, 1, /* 1191: pointer.struct.dtls1_state_st */
            	1164, 0,
            0, 24, 2, /* 1196: struct.ssl_comp_st */
            	10, 8,
            	1027, 16,
            1, 8, 1, /* 1203: pointer.struct.ssl_comp_st */
            	1196, 0,
            1, 8, 1, /* 1208: pointer.pointer.struct.env_md_ctx_st */
            	1130, 0,
            0, 56, 3, /* 1213: struct.ssl3_record_st */
            	214, 16,
            	214, 24,
            	214, 32,
            0, 24, 1, /* 1222: struct.ssl3_buffer_st */
            	214, 0,
            1, 8, 1, /* 1227: pointer.struct.stack_st_X509_LOOKUP */
            	1232, 0,
            0, 32, 1, /* 1232: struct.stack_st_X509_LOOKUP */
            	36, 0,
            4097, 8, 0, /* 1237: pointer.func */
            4097, 8, 0, /* 1240: pointer.func */
            4097, 8, 0, /* 1243: pointer.func */
            0, 232, 28, /* 1246: struct.ssl_method_st */
            	1305, 8,
            	1308, 16,
            	1308, 24,
            	1305, 32,
            	1305, 40,
            	1311, 48,
            	1311, 56,
            	1314, 64,
            	1305, 72,
            	1305, 80,
            	1305, 88,
            	1317, 96,
            	1320, 104,
            	1323, 112,
            	1305, 120,
            	1326, 128,
            	1329, 136,
            	1332, 144,
            	1335, 152,
            	1338, 160,
            	1341, 168,
            	1344, 176,
            	1347, 184,
            	1058, 192,
            	1350, 200,
            	1341, 208,
            	1401, 216,
            	1404, 224,
            4097, 8, 0, /* 1305: pointer.func */
            4097, 8, 0, /* 1308: pointer.func */
            4097, 8, 0, /* 1311: pointer.func */
            4097, 8, 0, /* 1314: pointer.func */
            4097, 8, 0, /* 1317: pointer.func */
            4097, 8, 0, /* 1320: pointer.func */
            4097, 8, 0, /* 1323: pointer.func */
            4097, 8, 0, /* 1326: pointer.func */
            4097, 8, 0, /* 1329: pointer.func */
            4097, 8, 0, /* 1332: pointer.func */
            4097, 8, 0, /* 1335: pointer.func */
            4097, 8, 0, /* 1338: pointer.func */
            4097, 8, 0, /* 1341: pointer.func */
            4097, 8, 0, /* 1344: pointer.func */
            4097, 8, 0, /* 1347: pointer.func */
            1, 8, 1, /* 1350: pointer.struct.ssl3_enc_method */
            	1355, 0,
            0, 112, 11, /* 1355: struct.ssl3_enc_method */
            	1380, 0,
            	1383, 8,
            	1305, 16,
            	1386, 24,
            	1380, 32,
            	1389, 40,
            	1392, 56,
            	10, 64,
            	10, 80,
            	1395, 96,
            	1398, 104,
            4097, 8, 0, /* 1380: pointer.func */
            4097, 8, 0, /* 1383: pointer.func */
            4097, 8, 0, /* 1386: pointer.func */
            4097, 8, 0, /* 1389: pointer.func */
            4097, 8, 0, /* 1392: pointer.func */
            4097, 8, 0, /* 1395: pointer.func */
            4097, 8, 0, /* 1398: pointer.func */
            4097, 8, 0, /* 1401: pointer.func */
            4097, 8, 0, /* 1404: pointer.func */
            1, 8, 1, /* 1407: pointer.struct.lhash_st */
            	1412, 0,
            0, 176, 3, /* 1412: struct.lhash_st */
            	1421, 0,
            	53, 8,
            	1443, 16,
            1, 8, 1, /* 1421: pointer.pointer.struct.lhash_node_st */
            	1426, 0,
            1, 8, 1, /* 1426: pointer.struct.lhash_node_st */
            	1431, 0,
            0, 24, 2, /* 1431: struct.lhash_node_st */
            	28, 0,
            	1438, 8,
            1, 8, 1, /* 1438: pointer.struct.lhash_node_st */
            	1431, 0,
            4097, 8, 0, /* 1443: pointer.func */
            4097, 8, 0, /* 1446: pointer.func */
            4097, 8, 0, /* 1449: pointer.func */
            4097, 8, 0, /* 1452: pointer.func */
            4097, 8, 0, /* 1455: pointer.func */
            1, 8, 1, /* 1458: pointer.struct.x509_store_st */
            	1463, 0,
            0, 144, 15, /* 1463: struct.x509_store_st */
            	1496, 8,
            	1227, 16,
            	1506, 24,
            	1452, 32,
            	1518, 40,
            	1455, 48,
            	1521, 56,
            	1452, 64,
            	1524, 72,
            	1527, 80,
            	1240, 88,
            	1530, 96,
            	1533, 104,
            	1452, 112,
            	609, 120,
            1, 8, 1, /* 1496: pointer.struct.stack_st_X509_OBJECT */
            	1501, 0,
            0, 32, 1, /* 1501: struct.stack_st_X509_OBJECT */
            	36, 0,
            1, 8, 1, /* 1506: pointer.struct.X509_VERIFY_PARAM_st */
            	1511, 0,
            0, 56, 2, /* 1511: struct.X509_VERIFY_PARAM_st */
            	48, 0,
            	915, 48,
            4097, 8, 0, /* 1518: pointer.func */
            4097, 8, 0, /* 1521: pointer.func */
            4097, 8, 0, /* 1524: pointer.func */
            4097, 8, 0, /* 1527: pointer.func */
            4097, 8, 0, /* 1530: pointer.func */
            4097, 8, 0, /* 1533: pointer.func */
            4097, 8, 0, /* 1536: pointer.func */
            0, 112, 7, /* 1539: struct.bio_st */
            	1556, 0,
            	1536, 8,
            	48, 16,
            	28, 48,
            	1597, 56,
            	1597, 64,
            	609, 96,
            1, 8, 1, /* 1556: pointer.struct.bio_method_st */
            	1561, 0,
            0, 80, 9, /* 1561: struct.bio_method_st */
            	10, 8,
            	1582, 16,
            	1585, 24,
            	1588, 32,
            	1585, 40,
            	1591, 48,
            	1594, 56,
            	1594, 64,
            	1243, 72,
            4097, 8, 0, /* 1582: pointer.func */
            4097, 8, 0, /* 1585: pointer.func */
            4097, 8, 0, /* 1588: pointer.func */
            4097, 8, 0, /* 1591: pointer.func */
            4097, 8, 0, /* 1594: pointer.func */
            1, 8, 1, /* 1597: pointer.struct.bio_st */
            	1539, 0,
            0, 736, 50, /* 1602: struct.ssl_ctx_st */
            	1705, 0,
            	1005, 8,
            	1005, 16,
            	1458, 24,
            	1407, 32,
            	1015, 48,
            	1015, 56,
            	1710, 80,
            	1713, 88,
            	1716, 96,
            	1719, 152,
            	28, 160,
            	1722, 168,
            	28, 176,
            	1725, 184,
            	1728, 192,
            	1731, 200,
            	609, 208,
            	935, 224,
            	935, 232,
            	935, 240,
            	118, 248,
            	1734, 256,
            	1237, 264,
            	1744, 272,
            	1754, 304,
            	1785, 320,
            	28, 328,
            	1518, 376,
            	1449, 384,
            	1506, 392,
            	473, 408,
            	1788, 416,
            	28, 424,
            	1791, 480,
            	1794, 488,
            	28, 496,
            	1797, 504,
            	28, 512,
            	48, 520,
            	1800, 528,
            	1803, 536,
            	1806, 552,
            	1806, 560,
            	1826, 568,
            	1857, 696,
            	28, 704,
            	1860, 712,
            	28, 720,
            	1863, 728,
            1, 8, 1, /* 1705: pointer.struct.ssl_method_st */
            	1246, 0,
            4097, 8, 0, /* 1710: pointer.func */
            4097, 8, 0, /* 1713: pointer.func */
            4097, 8, 0, /* 1716: pointer.func */
            4097, 8, 0, /* 1719: pointer.func */
            4097, 8, 0, /* 1722: pointer.func */
            4097, 8, 0, /* 1725: pointer.func */
            4097, 8, 0, /* 1728: pointer.func */
            4097, 8, 0, /* 1731: pointer.func */
            1, 8, 1, /* 1734: pointer.struct.stack_st_SSL_COMP */
            	1739, 0,
            0, 32, 1, /* 1739: struct.stack_st_SSL_COMP */
            	36, 0,
            1, 8, 1, /* 1744: pointer.struct.stack_st_X509_NAME */
            	1749, 0,
            0, 32, 1, /* 1749: struct.stack_st_X509_NAME */
            	36, 0,
            1, 8, 1, /* 1754: pointer.struct.cert_st */
            	1759, 0,
            0, 296, 7, /* 1759: struct.cert_st */
            	128, 0,
            	980, 48,
            	1776, 56,
            	985, 64,
            	1779, 72,
            	990, 80,
            	1782, 88,
            4097, 8, 0, /* 1776: pointer.func */
            4097, 8, 0, /* 1779: pointer.func */
            4097, 8, 0, /* 1782: pointer.func */
            4097, 8, 0, /* 1785: pointer.func */
            4097, 8, 0, /* 1788: pointer.func */
            4097, 8, 0, /* 1791: pointer.func */
            4097, 8, 0, /* 1794: pointer.func */
            4097, 8, 0, /* 1797: pointer.func */
            4097, 8, 0, /* 1800: pointer.func */
            4097, 8, 0, /* 1803: pointer.func */
            1, 8, 1, /* 1806: pointer.struct.ssl3_buf_freelist_st */
            	1811, 0,
            0, 24, 1, /* 1811: struct.ssl3_buf_freelist_st */
            	1816, 16,
            1, 8, 1, /* 1816: pointer.struct.ssl3_buf_freelist_entry_st */
            	1821, 0,
            0, 8, 1, /* 1821: struct.ssl3_buf_freelist_entry_st */
            	1816, 0,
            0, 128, 14, /* 1826: struct.srp_ctx_st */
            	28, 0,
            	1788, 8,
            	1794, 16,
            	1446, 24,
            	48, 32,
            	591, 40,
            	591, 48,
            	591, 56,
            	591, 64,
            	591, 72,
            	591, 80,
            	591, 88,
            	591, 96,
            	48, 104,
            4097, 8, 0, /* 1857: pointer.func */
            4097, 8, 0, /* 1860: pointer.func */
            1, 8, 1, /* 1863: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	1868, 0,
            0, 32, 1, /* 1868: struct.stack_st_SRTP_PROTECTION_PROFILE */
            	36, 0,
            1, 8, 1, /* 1873: pointer.struct.stack_st_X509_EXTENSION */
            	818, 0,
            0, 808, 51, /* 1878: struct.ssl_st */
            	1705, 8,
            	1983, 16,
            	1983, 24,
            	1983, 32,
            	1305, 48,
            	408, 80,
            	28, 88,
            	214, 104,
            	1988, 120,
            	2014, 128,
            	1191, 136,
            	1785, 152,
            	28, 160,
            	1506, 176,
            	1005, 184,
            	1005, 192,
            	1125, 208,
            	1130, 216,
            	1061, 224,
            	1125, 232,
            	1130, 240,
            	1061, 248,
            	1754, 256,
            	64, 304,
            	1449, 312,
            	1518, 328,
            	1237, 336,
            	1800, 352,
            	1803, 360,
            	2061, 368,
            	609, 392,
            	1744, 408,
            	61, 464,
            	28, 472,
            	48, 480,
            	56, 504,
            	1873, 512,
            	214, 520,
            	214, 544,
            	214, 560,
            	28, 568,
            	18, 584,
            	2066, 592,
            	28, 600,
            	15, 608,
            	28, 616,
            	2061, 624,
            	214, 632,
            	1863, 648,
            	0, 656,
            	1826, 680,
            1, 8, 1, /* 1983: pointer.struct.bio_st */
            	1539, 0,
            1, 8, 1, /* 1988: pointer.struct.ssl2_state_st */
            	1993, 0,
            0, 344, 9, /* 1993: struct.ssl2_state_st */
            	248, 24,
            	214, 56,
            	214, 64,
            	214, 72,
            	214, 104,
            	214, 112,
            	214, 120,
            	214, 128,
            	214, 136,
            1, 8, 1, /* 2014: pointer.struct.ssl3_state_st */
            	2019, 0,
            0, 1200, 10, /* 2019: struct.ssl3_state_st */
            	1222, 240,
            	1222, 264,
            	1213, 288,
            	1213, 344,
            	248, 432,
            	1983, 440,
            	1208, 448,
            	28, 496,
            	28, 512,
            	2042, 528,
            0, 528, 8, /* 2042: struct.unknown */
            	995, 408,
            	985, 416,
            	990, 424,
            	1744, 464,
            	214, 480,
            	1077, 488,
            	935, 496,
            	1203, 512,
            1, 8, 1, /* 2061: pointer.struct.ssl_ctx_st */
            	1602, 0,
            4097, 8, 0, /* 2066: pointer.func */
            0, 1, 0, /* 2069: char */
            1, 8, 1, /* 2072: pointer.struct.ssl_st */
            	1878, 0,
        },
        .arg_entity_index = { 2072, },
        .ret_entity_index = 2061,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL * new_arg_a = *((const SSL * *)new_args->args[0]);

    SSL_CTX * *new_ret_ptr = (SSL_CTX * *)new_args->ret;

    SSL_CTX * (*orig_SSL_get_SSL_CTX)(const SSL *);
    orig_SSL_get_SSL_CTX = dlsym(RTLD_NEXT, "SSL_get_SSL_CTX");
    *new_ret_ptr = (*orig_SSL_get_SSL_CTX)(new_arg_a);

    syscall(889);

    return ret;
}

