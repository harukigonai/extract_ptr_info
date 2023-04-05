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

const SSL_CIPHER * bb_SSL_get_current_cipher(const SSL * arg_a);

const SSL_CIPHER * SSL_get_current_cipher(const SSL * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_get_current_cipher called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_get_current_cipher(arg_a);
    else {
        const SSL_CIPHER * (*orig_SSL_get_current_cipher)(const SSL *);
        orig_SSL_get_current_cipher = dlsym(RTLD_NEXT, "SSL_get_current_cipher");
        return orig_SSL_get_current_cipher(arg_a);
    }
}

const SSL_CIPHER * bb_SSL_get_current_cipher(const SSL * arg_a) 
{
    const SSL_CIPHER * ret;

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
            0, 56, 2, /* 203: struct.comp_ctx_st */
            	210, 0,
            	244, 40,
            1, 8, 1, /* 210: pointer.struct.comp_method_st */
            	215, 0,
            0, 64, 7, /* 215: struct.comp_method_st */
            	10, 8,
            	232, 16,
            	235, 24,
            	238, 32,
            	238, 40,
            	241, 48,
            	241, 56,
            4097, 8, 0, /* 232: pointer.func */
            4097, 8, 0, /* 235: pointer.func */
            4097, 8, 0, /* 238: pointer.func */
            4097, 8, 0, /* 241: pointer.func */
            0, 16, 1, /* 244: struct.crypto_ex_data_st */
            	249, 0,
            1, 8, 1, /* 249: pointer.struct.stack_st_void */
            	254, 0,
            0, 32, 1, /* 254: struct.stack_st_void */
            	36, 0,
            4097, 8, 0, /* 259: pointer.func */
            4097, 8, 0, /* 262: pointer.func */
            0, 168, 4, /* 265: struct.evp_cipher_ctx_st */
            	276, 0,
            	310, 8,
            	28, 96,
            	28, 120,
            1, 8, 1, /* 276: pointer.struct.evp_cipher_st */
            	281, 0,
            0, 88, 7, /* 281: struct.evp_cipher_st */
            	298, 24,
            	259, 32,
            	301, 40,
            	304, 56,
            	304, 64,
            	307, 72,
            	28, 80,
            4097, 8, 0, /* 298: pointer.func */
            4097, 8, 0, /* 301: pointer.func */
            4097, 8, 0, /* 304: pointer.func */
            4097, 8, 0, /* 307: pointer.func */
            1, 8, 1, /* 310: pointer.struct.engine_st */
            	315, 0,
            0, 0, 0, /* 315: struct.engine_st */
            1, 8, 1, /* 318: pointer.struct.stack_st_X509_NAME */
            	323, 0,
            0, 32, 1, /* 323: struct.stack_st_X509_NAME */
            	36, 0,
            4097, 8, 0, /* 328: pointer.func */
            4097, 8, 0, /* 331: pointer.func */
            1, 8, 1, /* 334: pointer.struct.evp_pkey_ctx_st */
            	339, 0,
            0, 0, 0, /* 339: struct.evp_pkey_ctx_st */
            1, 8, 1, /* 342: pointer.struct.ssl_st */
            	347, 0,
            0, 808, 51, /* 347: struct.ssl_st */
            	452, 8,
            	618, 16,
            	618, 24,
            	618, 32,
            	516, 48,
            	689, 80,
            	28, 88,
            	699, 104,
            	707, 120,
            	738, 128,
            	976, 136,
            	1781, 152,
            	28, 160,
            	1784, 176,
            	1766, 184,
            	1766, 192,
            	1027, 208,
            	785, 216,
            	1032, 224,
            	1027, 232,
            	785, 240,
            	1032, 248,
            	1796, 256,
            	1037, 304,
            	1827, 312,
            	1830, 328,
            	1833, 336,
            	1836, 352,
            	1839, 360,
            	1842, 368,
            	244, 392,
            	318, 408,
            	61, 464,
            	28, 472,
            	48, 480,
            	56, 504,
            	2066, 512,
            	699, 520,
            	699, 544,
            	699, 560,
            	28, 568,
            	18, 584,
            	2071, 592,
            	28, 600,
            	15, 608,
            	28, 616,
            	1842, 624,
            	699, 632,
            	2061, 648,
            	0, 656,
            	75, 680,
            1, 8, 1, /* 452: pointer.struct.ssl_method_st */
            	457, 0,
            0, 232, 28, /* 457: struct.ssl_method_st */
            	516, 8,
            	519, 16,
            	519, 24,
            	516, 32,
            	516, 40,
            	522, 48,
            	522, 56,
            	525, 64,
            	516, 72,
            	516, 80,
            	516, 88,
            	528, 96,
            	531, 104,
            	534, 112,
            	516, 120,
            	537, 128,
            	540, 136,
            	543, 144,
            	546, 152,
            	549, 160,
            	552, 168,
            	555, 176,
            	558, 184,
            	241, 192,
            	561, 200,
            	552, 208,
            	612, 216,
            	615, 224,
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
            4097, 8, 0, /* 558: pointer.func */
            1, 8, 1, /* 561: pointer.struct.ssl3_enc_method */
            	566, 0,
            0, 112, 11, /* 566: struct.ssl3_enc_method */
            	591, 0,
            	594, 8,
            	516, 16,
            	597, 24,
            	591, 32,
            	600, 40,
            	603, 56,
            	10, 64,
            	10, 80,
            	606, 96,
            	609, 104,
            4097, 8, 0, /* 591: pointer.func */
            4097, 8, 0, /* 594: pointer.func */
            4097, 8, 0, /* 597: pointer.func */
            4097, 8, 0, /* 600: pointer.func */
            4097, 8, 0, /* 603: pointer.func */
            4097, 8, 0, /* 606: pointer.func */
            4097, 8, 0, /* 609: pointer.func */
            4097, 8, 0, /* 612: pointer.func */
            4097, 8, 0, /* 615: pointer.func */
            1, 8, 1, /* 618: pointer.struct.bio_st */
            	623, 0,
            0, 112, 7, /* 623: struct.bio_st */
            	640, 0,
            	681, 8,
            	48, 16,
            	28, 48,
            	684, 56,
            	684, 64,
            	244, 96,
            1, 8, 1, /* 640: pointer.struct.bio_method_st */
            	645, 0,
            0, 80, 9, /* 645: struct.bio_method_st */
            	10, 8,
            	666, 16,
            	669, 24,
            	672, 32,
            	669, 40,
            	262, 48,
            	675, 56,
            	675, 64,
            	678, 72,
            4097, 8, 0, /* 666: pointer.func */
            4097, 8, 0, /* 669: pointer.func */
            4097, 8, 0, /* 672: pointer.func */
            4097, 8, 0, /* 675: pointer.func */
            4097, 8, 0, /* 678: pointer.func */
            4097, 8, 0, /* 681: pointer.func */
            1, 8, 1, /* 684: pointer.struct.bio_st */
            	623, 0,
            1, 8, 1, /* 689: pointer.struct.buf_mem_st */
            	694, 0,
            0, 24, 1, /* 694: struct.buf_mem_st */
            	48, 8,
            1, 8, 1, /* 699: pointer.unsigned char */
            	704, 0,
            0, 1, 0, /* 704: unsigned char */
            1, 8, 1, /* 707: pointer.struct.ssl2_state_st */
            	712, 0,
            0, 344, 9, /* 712: struct.ssl2_state_st */
            	733, 24,
            	699, 56,
            	699, 64,
            	699, 72,
            	699, 104,
            	699, 112,
            	699, 120,
            	699, 128,
            	699, 136,
            1, 8, 1, /* 733: pointer.unsigned char */
            	704, 0,
            1, 8, 1, /* 738: pointer.struct.ssl3_state_st */
            	743, 0,
            0, 1200, 10, /* 743: struct.ssl3_state_st */
            	766, 240,
            	766, 264,
            	771, 288,
            	771, 344,
            	733, 432,
            	618, 440,
            	780, 448,
            	28, 496,
            	28, 512,
            	845, 528,
            0, 24, 1, /* 766: struct.ssl3_buffer_st */
            	699, 0,
            0, 56, 3, /* 771: struct.ssl3_record_st */
            	699, 16,
            	699, 24,
            	699, 32,
            1, 8, 1, /* 780: pointer.pointer.struct.env_md_ctx_st */
            	785, 0,
            1, 8, 1, /* 785: pointer.struct.env_md_ctx_st */
            	790, 0,
            0, 48, 5, /* 790: struct.env_md_ctx_st */
            	803, 0,
            	310, 8,
            	28, 24,
            	334, 32,
            	827, 40,
            1, 8, 1, /* 803: pointer.struct.env_md_st */
            	808, 0,
            0, 120, 8, /* 808: struct.env_md_st */
            	328, 24,
            	827, 32,
            	830, 40,
            	833, 48,
            	328, 56,
            	836, 64,
            	839, 72,
            	842, 112,
            4097, 8, 0, /* 827: pointer.func */
            4097, 8, 0, /* 830: pointer.func */
            4097, 8, 0, /* 833: pointer.func */
            4097, 8, 0, /* 836: pointer.func */
            4097, 8, 0, /* 839: pointer.func */
            4097, 8, 0, /* 842: pointer.func */
            0, 528, 8, /* 845: struct.unknown */
            	864, 408,
            	874, 416,
            	956, 424,
            	318, 464,
            	699, 480,
            	276, 488,
            	803, 496,
            	964, 512,
            1, 8, 1, /* 864: pointer.struct.ssl_cipher_st */
            	869, 0,
            0, 88, 1, /* 869: struct.ssl_cipher_st */
            	10, 8,
            1, 8, 1, /* 874: pointer.struct.dh_st */
            	879, 0,
            0, 144, 12, /* 879: struct.dh_st */
            	112, 8,
            	112, 16,
            	112, 32,
            	112, 40,
            	906, 56,
            	112, 64,
            	112, 72,
            	699, 80,
            	112, 96,
            	244, 112,
            	920, 128,
            	310, 136,
            1, 8, 1, /* 906: pointer.struct.bn_mont_ctx_st */
            	911, 0,
            0, 96, 3, /* 911: struct.bn_mont_ctx_st */
            	117, 8,
            	117, 32,
            	117, 56,
            1, 8, 1, /* 920: pointer.struct.dh_method */
            	925, 0,
            0, 72, 8, /* 925: struct.dh_method */
            	10, 0,
            	944, 8,
            	947, 16,
            	950, 24,
            	944, 32,
            	944, 40,
            	48, 56,
            	953, 64,
            4097, 8, 0, /* 944: pointer.func */
            4097, 8, 0, /* 947: pointer.func */
            4097, 8, 0, /* 950: pointer.func */
            4097, 8, 0, /* 953: pointer.func */
            1, 8, 1, /* 956: pointer.struct.ec_key_st */
            	961, 0,
            0, 0, 0, /* 961: struct.ec_key_st */
            1, 8, 1, /* 964: pointer.struct.ssl_comp_st */
            	969, 0,
            0, 24, 2, /* 969: struct.ssl_comp_st */
            	10, 8,
            	210, 16,
            1, 8, 1, /* 976: pointer.struct.dtls1_state_st */
            	981, 0,
            0, 888, 7, /* 981: struct.dtls1_state_st */
            	998, 576,
            	998, 592,
            	1003, 608,
            	1003, 616,
            	998, 624,
            	1011, 648,
            	1011, 736,
            0, 16, 1, /* 998: struct.record_pqueue_st */
            	1003, 8,
            1, 8, 1, /* 1003: pointer.struct._pqueue */
            	1008, 0,
            0, 0, 0, /* 1008: struct._pqueue */
            0, 88, 1, /* 1011: struct.hm_header_st */
            	1016, 48,
            0, 40, 4, /* 1016: struct.dtls1_retransmit_state */
            	1027, 0,
            	785, 8,
            	1032, 16,
            	1037, 24,
            1, 8, 1, /* 1027: pointer.struct.evp_cipher_ctx_st */
            	265, 0,
            1, 8, 1, /* 1032: pointer.struct.comp_ctx_st */
            	203, 0,
            1, 8, 1, /* 1037: pointer.struct.ssl_session_st */
            	1042, 0,
            0, 352, 14, /* 1042: struct.ssl_session_st */
            	48, 144,
            	48, 152,
            	1073, 168,
            	1115, 176,
            	864, 224,
            	1766, 240,
            	244, 248,
            	1776, 264,
            	1776, 272,
            	48, 280,
            	699, 296,
            	699, 312,
            	699, 320,
            	48, 344,
            1, 8, 1, /* 1073: pointer.struct.sess_cert_st */
            	1078, 0,
            0, 248, 5, /* 1078: struct.sess_cert_st */
            	1091, 0,
            	1101, 16,
            	1761, 216,
            	874, 224,
            	956, 232,
            1, 8, 1, /* 1091: pointer.struct.stack_st_X509 */
            	1096, 0,
            0, 32, 1, /* 1096: struct.stack_st_X509 */
            	36, 0,
            1, 8, 1, /* 1101: pointer.struct.cert_pkey_st */
            	1106, 0,
            0, 24, 3, /* 1106: struct.cert_pkey_st */
            	1115, 0,
            	1399, 8,
            	803, 16,
            1, 8, 1, /* 1115: pointer.struct.x509_st */
            	1120, 0,
            0, 184, 12, /* 1120: struct.x509_st */
            	1147, 0,
            	1187, 8,
            	1276, 16,
            	48, 32,
            	244, 40,
            	1281, 104,
            	1654, 112,
            	1678, 120,
            	1686, 128,
            	1696, 136,
            	1701, 144,
            	1723, 176,
            1, 8, 1, /* 1147: pointer.struct.x509_cinf_st */
            	1152, 0,
            0, 104, 11, /* 1152: struct.x509_cinf_st */
            	1177, 0,
            	1177, 8,
            	1187, 16,
            	1344, 24,
            	1368, 32,
            	1344, 40,
            	1385, 48,
            	1276, 56,
            	1276, 64,
            	1639, 72,
            	1649, 80,
            1, 8, 1, /* 1177: pointer.struct.asn1_string_st */
            	1182, 0,
            0, 24, 1, /* 1182: struct.asn1_string_st */
            	699, 8,
            1, 8, 1, /* 1187: pointer.struct.X509_algor_st */
            	1192, 0,
            0, 16, 2, /* 1192: struct.X509_algor_st */
            	1199, 0,
            	1213, 8,
            1, 8, 1, /* 1199: pointer.struct.asn1_object_st */
            	1204, 0,
            0, 40, 3, /* 1204: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	733, 24,
            1, 8, 1, /* 1213: pointer.struct.asn1_type_st */
            	1218, 0,
            0, 16, 1, /* 1218: struct.asn1_type_st */
            	1223, 8,
            0, 8, 20, /* 1223: union.unknown */
            	48, 0,
            	1266, 0,
            	1199, 0,
            	1177, 0,
            	1271, 0,
            	1276, 0,
            	1281, 0,
            	1286, 0,
            	1291, 0,
            	1296, 0,
            	1301, 0,
            	1306, 0,
            	1311, 0,
            	1316, 0,
            	1321, 0,
            	1326, 0,
            	1331, 0,
            	1266, 0,
            	1266, 0,
            	1336, 0,
            1, 8, 1, /* 1266: pointer.struct.asn1_string_st */
            	1182, 0,
            1, 8, 1, /* 1271: pointer.struct.asn1_string_st */
            	1182, 0,
            1, 8, 1, /* 1276: pointer.struct.asn1_string_st */
            	1182, 0,
            1, 8, 1, /* 1281: pointer.struct.asn1_string_st */
            	1182, 0,
            1, 8, 1, /* 1286: pointer.struct.asn1_string_st */
            	1182, 0,
            1, 8, 1, /* 1291: pointer.struct.asn1_string_st */
            	1182, 0,
            1, 8, 1, /* 1296: pointer.struct.asn1_string_st */
            	1182, 0,
            1, 8, 1, /* 1301: pointer.struct.asn1_string_st */
            	1182, 0,
            1, 8, 1, /* 1306: pointer.struct.asn1_string_st */
            	1182, 0,
            1, 8, 1, /* 1311: pointer.struct.asn1_string_st */
            	1182, 0,
            1, 8, 1, /* 1316: pointer.struct.asn1_string_st */
            	1182, 0,
            1, 8, 1, /* 1321: pointer.struct.asn1_string_st */
            	1182, 0,
            1, 8, 1, /* 1326: pointer.struct.asn1_string_st */
            	1182, 0,
            1, 8, 1, /* 1331: pointer.struct.asn1_string_st */
            	1182, 0,
            1, 8, 1, /* 1336: pointer.struct.ASN1_VALUE_st */
            	1341, 0,
            0, 0, 0, /* 1341: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1344: pointer.struct.X509_name_st */
            	1349, 0,
            0, 40, 3, /* 1349: struct.X509_name_st */
            	1358, 0,
            	689, 16,
            	699, 24,
            1, 8, 1, /* 1358: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1363, 0,
            0, 32, 1, /* 1363: struct.stack_st_X509_NAME_ENTRY */
            	36, 0,
            1, 8, 1, /* 1368: pointer.struct.X509_val_st */
            	1373, 0,
            0, 16, 2, /* 1373: struct.X509_val_st */
            	1380, 0,
            	1380, 8,
            1, 8, 1, /* 1380: pointer.struct.asn1_string_st */
            	1182, 0,
            1, 8, 1, /* 1385: pointer.struct.X509_pubkey_st */
            	1390, 0,
            0, 24, 3, /* 1390: struct.X509_pubkey_st */
            	1187, 0,
            	1276, 8,
            	1399, 16,
            1, 8, 1, /* 1399: pointer.struct.evp_pkey_st */
            	1404, 0,
            0, 56, 4, /* 1404: struct.evp_pkey_st */
            	1415, 16,
            	310, 24,
            	1423, 32,
            	1629, 48,
            1, 8, 1, /* 1415: pointer.struct.evp_pkey_asn1_method_st */
            	1420, 0,
            0, 0, 0, /* 1420: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 1423: union.unknown */
            	48, 0,
            	1436, 0,
            	1541, 0,
            	1619, 0,
            	1624, 0,
            1, 8, 1, /* 1436: pointer.struct.rsa_st */
            	1441, 0,
            0, 168, 17, /* 1441: struct.rsa_st */
            	1478, 16,
            	310, 24,
            	112, 32,
            	112, 40,
            	112, 48,
            	112, 56,
            	112, 64,
            	112, 72,
            	112, 80,
            	112, 88,
            	244, 96,
            	906, 120,
            	906, 128,
            	906, 136,
            	48, 144,
            	1533, 152,
            	1533, 160,
            1, 8, 1, /* 1478: pointer.struct.rsa_meth_st */
            	1483, 0,
            0, 112, 13, /* 1483: struct.rsa_meth_st */
            	10, 0,
            	1512, 8,
            	1512, 16,
            	1512, 24,
            	1512, 32,
            	1515, 40,
            	1518, 48,
            	1521, 56,
            	1521, 64,
            	48, 80,
            	1524, 88,
            	1527, 96,
            	1530, 104,
            4097, 8, 0, /* 1512: pointer.func */
            4097, 8, 0, /* 1515: pointer.func */
            4097, 8, 0, /* 1518: pointer.func */
            4097, 8, 0, /* 1521: pointer.func */
            4097, 8, 0, /* 1524: pointer.func */
            4097, 8, 0, /* 1527: pointer.func */
            4097, 8, 0, /* 1530: pointer.func */
            1, 8, 1, /* 1533: pointer.struct.bn_blinding_st */
            	1538, 0,
            0, 0, 0, /* 1538: struct.bn_blinding_st */
            1, 8, 1, /* 1541: pointer.struct.dsa_st */
            	1546, 0,
            0, 136, 11, /* 1546: struct.dsa_st */
            	112, 24,
            	112, 32,
            	112, 40,
            	112, 48,
            	112, 56,
            	112, 64,
            	112, 72,
            	906, 88,
            	244, 104,
            	1571, 120,
            	310, 128,
            1, 8, 1, /* 1571: pointer.struct.dsa_method */
            	1576, 0,
            0, 96, 11, /* 1576: struct.dsa_method */
            	10, 0,
            	1601, 8,
            	1604, 16,
            	1607, 24,
            	1610, 32,
            	1613, 40,
            	1616, 48,
            	1616, 56,
            	48, 72,
            	331, 80,
            	1616, 88,
            4097, 8, 0, /* 1601: pointer.func */
            4097, 8, 0, /* 1604: pointer.func */
            4097, 8, 0, /* 1607: pointer.func */
            4097, 8, 0, /* 1610: pointer.func */
            4097, 8, 0, /* 1613: pointer.func */
            4097, 8, 0, /* 1616: pointer.func */
            1, 8, 1, /* 1619: pointer.struct.dh_st */
            	879, 0,
            1, 8, 1, /* 1624: pointer.struct.ec_key_st */
            	961, 0,
            1, 8, 1, /* 1629: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1634, 0,
            0, 32, 1, /* 1634: struct.stack_st_X509_ATTRIBUTE */
            	36, 0,
            1, 8, 1, /* 1639: pointer.struct.stack_st_X509_EXTENSION */
            	1644, 0,
            0, 32, 1, /* 1644: struct.stack_st_X509_EXTENSION */
            	36, 0,
            0, 24, 1, /* 1649: struct.ASN1_ENCODING_st */
            	699, 0,
            1, 8, 1, /* 1654: pointer.struct.AUTHORITY_KEYID_st */
            	1659, 0,
            0, 24, 3, /* 1659: struct.AUTHORITY_KEYID_st */
            	1281, 0,
            	1668, 8,
            	1177, 16,
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
            	1331, 16,
            	1281, 24,
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
            	1441, 0,
            1, 8, 1, /* 1766: pointer.struct.stack_st_SSL_CIPHER */
            	1771, 0,
            0, 32, 1, /* 1771: struct.stack_st_SSL_CIPHER */
            	36, 0,
            1, 8, 1, /* 1776: pointer.struct.ssl_session_st */
            	1042, 0,
            4097, 8, 0, /* 1781: pointer.func */
            1, 8, 1, /* 1784: pointer.struct.X509_VERIFY_PARAM_st */
            	1789, 0,
            0, 56, 2, /* 1789: struct.X509_VERIFY_PARAM_st */
            	48, 0,
            	1741, 48,
            1, 8, 1, /* 1796: pointer.struct.cert_st */
            	1801, 0,
            0, 296, 7, /* 1801: struct.cert_st */
            	1101, 0,
            	1761, 48,
            	1818, 56,
            	874, 64,
            	1821, 72,
            	956, 80,
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
            	452, 0,
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
            	244, 208,
            	803, 224,
            	803, 232,
            	803, 240,
            	1091, 248,
            	138, 256,
            	1833, 264,
            	318, 272,
            	1796, 304,
            	1781, 320,
            	28, 328,
            	1830, 376,
            	1827, 384,
            	1784, 392,
            	310, 408,
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
            	244, 120,
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
            1, 8, 1, /* 2066: pointer.struct.stack_st_X509_EXTENSION */
            	1644, 0,
            4097, 8, 0, /* 2071: pointer.func */
            0, 1, 0, /* 2074: char */
        },
        .arg_entity_index = { 342, },
        .ret_entity_index = 864,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL * new_arg_a = *((const SSL * *)new_args->args[0]);

    const SSL_CIPHER * *new_ret_ptr = (const SSL_CIPHER * *)new_args->ret;

    const SSL_CIPHER * (*orig_SSL_get_current_cipher)(const SSL *);
    orig_SSL_get_current_cipher = dlsym(RTLD_NEXT, "SSL_get_current_cipher");
    *new_ret_ptr = (*orig_SSL_get_current_cipher)(new_arg_a);

    syscall(889);

    return ret;
}

