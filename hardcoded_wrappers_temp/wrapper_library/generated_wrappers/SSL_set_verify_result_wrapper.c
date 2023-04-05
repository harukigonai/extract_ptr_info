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

void bb_SSL_set_verify_result(SSL * arg_a,long arg_b);

void SSL_set_verify_result(SSL * arg_a,long arg_b) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_set_verify_result called %lu\n", in_lib);
    if (!in_lib)
        bb_SSL_set_verify_result(arg_a,arg_b);
    else {
        void (*orig_SSL_set_verify_result)(SSL *,long);
        orig_SSL_set_verify_result = dlsym(RTLD_NEXT, "SSL_set_verify_result");
        orig_SSL_set_verify_result(arg_a,arg_b);
    }
}

void bb_SSL_set_verify_result(SSL * arg_a,long arg_b) 
{
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
            0, 32, 1, /* 18: struct.stack_st_OCSP_RESPID */
            	23, 0,
            0, 32, 2, /* 23: struct.stack_st */
            	30, 8,
            	40, 24,
            1, 8, 1, /* 30: pointer.pointer.char */
            	35, 0,
            1, 8, 1, /* 35: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 40: pointer.func */
            1, 8, 1, /* 43: pointer.struct.stack_st_OCSP_RESPID */
            	18, 0,
            4097, 8, 0, /* 48: pointer.func */
            0, 32, 1, /* 51: struct.stack_st_SRTP_PROTECTION_PROFILE */
            	23, 0,
            4097, 8, 0, /* 56: pointer.func */
            0, 128, 14, /* 59: struct.srp_ctx_st */
            	90, 0,
            	93, 8,
            	96, 16,
            	56, 24,
            	35, 32,
            	99, 40,
            	99, 48,
            	99, 56,
            	99, 64,
            	99, 72,
            	99, 80,
            	99, 88,
            	99, 96,
            	35, 104,
            0, 8, 0, /* 90: pointer.void */
            4097, 8, 0, /* 93: pointer.func */
            4097, 8, 0, /* 96: pointer.func */
            1, 8, 1, /* 99: pointer.struct.bignum_st */
            	104, 0,
            0, 24, 1, /* 104: struct.bignum_st */
            	109, 0,
            1, 8, 1, /* 109: pointer.unsigned int */
            	114, 0,
            0, 4, 0, /* 114: unsigned int */
            4097, 8, 0, /* 117: pointer.func */
            0, 32, 1, /* 120: struct.stack_st_SSL_COMP */
            	23, 0,
            1, 8, 1, /* 125: pointer.struct.stack_st_SSL_COMP */
            	120, 0,
            4097, 8, 0, /* 130: pointer.func */
            4097, 8, 0, /* 133: pointer.func */
            4097, 8, 0, /* 136: pointer.func */
            4097, 8, 0, /* 139: pointer.func */
            4097, 8, 0, /* 142: pointer.func */
            4097, 8, 0, /* 145: pointer.func */
            1, 8, 1, /* 148: pointer.struct.lhash_node_st */
            	153, 0,
            0, 24, 2, /* 153: struct.lhash_node_st */
            	90, 0,
            	148, 8,
            1, 8, 1, /* 160: pointer.struct.lhash_st */
            	165, 0,
            0, 176, 3, /* 165: struct.lhash_st */
            	174, 0,
            	40, 8,
            	145, 16,
            1, 8, 1, /* 174: pointer.pointer.struct.lhash_node_st */
            	179, 0,
            1, 8, 1, /* 179: pointer.struct.lhash_node_st */
            	153, 0,
            4097, 8, 0, /* 184: pointer.func */
            4097, 8, 0, /* 187: pointer.func */
            0, 56, 2, /* 190: struct.comp_ctx_st */
            	197, 0,
            	231, 40,
            1, 8, 1, /* 197: pointer.struct.comp_method_st */
            	202, 0,
            0, 64, 7, /* 202: struct.comp_method_st */
            	10, 8,
            	219, 16,
            	222, 24,
            	225, 32,
            	225, 40,
            	228, 48,
            	228, 56,
            4097, 8, 0, /* 219: pointer.func */
            4097, 8, 0, /* 222: pointer.func */
            4097, 8, 0, /* 225: pointer.func */
            4097, 8, 0, /* 228: pointer.func */
            0, 16, 1, /* 231: struct.crypto_ex_data_st */
            	236, 0,
            1, 8, 1, /* 236: pointer.struct.stack_st_void */
            	241, 0,
            0, 32, 1, /* 241: struct.stack_st_void */
            	23, 0,
            4097, 8, 0, /* 246: pointer.func */
            4097, 8, 0, /* 249: pointer.func */
            0, 168, 4, /* 252: struct.evp_cipher_ctx_st */
            	263, 0,
            	297, 8,
            	90, 96,
            	90, 120,
            1, 8, 1, /* 263: pointer.struct.evp_cipher_st */
            	268, 0,
            0, 88, 7, /* 268: struct.evp_cipher_st */
            	285, 24,
            	246, 32,
            	288, 40,
            	291, 56,
            	291, 64,
            	294, 72,
            	90, 80,
            4097, 8, 0, /* 285: pointer.func */
            4097, 8, 0, /* 288: pointer.func */
            4097, 8, 0, /* 291: pointer.func */
            4097, 8, 0, /* 294: pointer.func */
            1, 8, 1, /* 297: pointer.struct.engine_st */
            	302, 0,
            0, 0, 0, /* 302: struct.engine_st */
            1, 8, 1, /* 305: pointer.struct.stack_st_X509_NAME */
            	310, 0,
            0, 32, 1, /* 310: struct.stack_st_X509_NAME */
            	23, 0,
            4097, 8, 0, /* 315: pointer.func */
            4097, 8, 0, /* 318: pointer.func */
            1, 8, 1, /* 321: pointer.struct.evp_pkey_ctx_st */
            	326, 0,
            0, 0, 0, /* 326: struct.evp_pkey_ctx_st */
            0, 0, 0, /* 329: struct.ec_key_st */
            1, 8, 1, /* 332: pointer.struct.dh_method */
            	337, 0,
            0, 72, 8, /* 337: struct.dh_method */
            	10, 0,
            	356, 8,
            	359, 16,
            	362, 24,
            	356, 32,
            	356, 40,
            	35, 56,
            	365, 64,
            4097, 8, 0, /* 356: pointer.func */
            4097, 8, 0, /* 359: pointer.func */
            4097, 8, 0, /* 362: pointer.func */
            4097, 8, 0, /* 365: pointer.func */
            1, 8, 1, /* 368: pointer.struct.NAME_CONSTRAINTS_st */
            	373, 0,
            0, 16, 2, /* 373: struct.NAME_CONSTRAINTS_st */
            	380, 0,
            	380, 8,
            1, 8, 1, /* 380: pointer.struct.stack_st_GENERAL_SUBTREE */
            	385, 0,
            0, 32, 1, /* 385: struct.stack_st_GENERAL_SUBTREE */
            	23, 0,
            1, 8, 1, /* 390: pointer.struct.bn_mont_ctx_st */
            	395, 0,
            0, 96, 3, /* 395: struct.bn_mont_ctx_st */
            	104, 8,
            	104, 32,
            	104, 56,
            1, 8, 1, /* 404: pointer.struct.dh_st */
            	409, 0,
            0, 144, 12, /* 409: struct.dh_st */
            	99, 8,
            	99, 16,
            	99, 32,
            	99, 40,
            	390, 56,
            	99, 64,
            	99, 72,
            	436, 80,
            	99, 96,
            	231, 112,
            	332, 128,
            	297, 136,
            1, 8, 1, /* 436: pointer.unsigned char */
            	441, 0,
            0, 1, 0, /* 441: unsigned char */
            1, 8, 1, /* 444: pointer.struct.comp_ctx_st */
            	190, 0,
            0, 112, 7, /* 449: struct.bio_st */
            	466, 0,
            	507, 8,
            	35, 16,
            	90, 48,
            	510, 56,
            	510, 64,
            	231, 96,
            1, 8, 1, /* 466: pointer.struct.bio_method_st */
            	471, 0,
            0, 80, 9, /* 471: struct.bio_method_st */
            	10, 8,
            	492, 16,
            	495, 24,
            	498, 32,
            	495, 40,
            	249, 48,
            	501, 56,
            	501, 64,
            	504, 72,
            4097, 8, 0, /* 492: pointer.func */
            4097, 8, 0, /* 495: pointer.func */
            4097, 8, 0, /* 498: pointer.func */
            4097, 8, 0, /* 501: pointer.func */
            4097, 8, 0, /* 504: pointer.func */
            4097, 8, 0, /* 507: pointer.func */
            1, 8, 1, /* 510: pointer.struct.bio_st */
            	449, 0,
            4097, 8, 0, /* 515: pointer.func */
            0, 24, 2, /* 518: struct.ssl_comp_st */
            	10, 8,
            	197, 16,
            4097, 8, 0, /* 525: pointer.func */
            4097, 8, 0, /* 528: pointer.func */
            4097, 8, 0, /* 531: pointer.func */
            1, 8, 1, /* 534: pointer.struct.env_md_st */
            	539, 0,
            0, 120, 8, /* 539: struct.env_md_st */
            	315, 24,
            	558, 32,
            	561, 40,
            	531, 48,
            	315, 56,
            	525, 64,
            	564, 72,
            	515, 112,
            4097, 8, 0, /* 558: pointer.func */
            4097, 8, 0, /* 561: pointer.func */
            4097, 8, 0, /* 564: pointer.func */
            4097, 8, 0, /* 567: pointer.func */
            1, 8, 1, /* 570: pointer.struct.ssl_comp_st */
            	518, 0,
            1, 8, 1, /* 575: pointer.struct.bio_st */
            	449, 0,
            1, 8, 1, /* 580: pointer.struct.ssl_cipher_st */
            	585, 0,
            0, 88, 1, /* 585: struct.ssl_cipher_st */
            	10, 8,
            1, 8, 1, /* 590: pointer.pointer.struct.env_md_ctx_st */
            	595, 0,
            1, 8, 1, /* 595: pointer.struct.env_md_ctx_st */
            	600, 0,
            0, 48, 5, /* 600: struct.env_md_ctx_st */
            	534, 0,
            	297, 8,
            	90, 24,
            	321, 32,
            	558, 40,
            4097, 8, 0, /* 613: pointer.func */
            0, 56, 3, /* 616: struct.ssl3_record_st */
            	436, 16,
            	436, 24,
            	436, 32,
            1, 8, 1, /* 625: pointer.struct.ssl3_state_st */
            	630, 0,
            0, 1200, 10, /* 630: struct.ssl3_state_st */
            	653, 240,
            	653, 264,
            	616, 288,
            	616, 344,
            	658, 432,
            	575, 440,
            	590, 448,
            	90, 496,
            	90, 512,
            	663, 528,
            0, 24, 1, /* 653: struct.ssl3_buffer_st */
            	436, 0,
            1, 8, 1, /* 658: pointer.unsigned char */
            	441, 0,
            0, 528, 8, /* 663: struct.unknown */
            	580, 408,
            	404, 416,
            	682, 424,
            	305, 464,
            	436, 480,
            	263, 488,
            	534, 496,
            	570, 512,
            1, 8, 1, /* 682: pointer.struct.ec_key_st */
            	329, 0,
            1, 8, 1, /* 687: pointer.struct.dsa_st */
            	692, 0,
            0, 136, 11, /* 692: struct.dsa_st */
            	99, 24,
            	99, 32,
            	99, 40,
            	99, 48,
            	99, 56,
            	99, 64,
            	99, 72,
            	390, 88,
            	231, 104,
            	717, 120,
            	297, 128,
            1, 8, 1, /* 717: pointer.struct.dsa_method */
            	722, 0,
            0, 96, 11, /* 722: struct.dsa_method */
            	10, 0,
            	747, 8,
            	750, 16,
            	753, 24,
            	756, 32,
            	759, 40,
            	762, 48,
            	762, 56,
            	35, 72,
            	318, 80,
            	762, 88,
            4097, 8, 0, /* 747: pointer.func */
            4097, 8, 0, /* 750: pointer.func */
            4097, 8, 0, /* 753: pointer.func */
            4097, 8, 0, /* 756: pointer.func */
            4097, 8, 0, /* 759: pointer.func */
            4097, 8, 0, /* 762: pointer.func */
            0, 24, 1, /* 765: struct.ASN1_ENCODING_st */
            	436, 0,
            4097, 8, 0, /* 770: pointer.func */
            0, 112, 11, /* 773: struct.ssl3_enc_method */
            	798, 0,
            	801, 8,
            	567, 16,
            	804, 24,
            	798, 32,
            	613, 40,
            	807, 56,
            	10, 64,
            	10, 80,
            	810, 96,
            	813, 104,
            4097, 8, 0, /* 798: pointer.func */
            4097, 8, 0, /* 801: pointer.func */
            4097, 8, 0, /* 804: pointer.func */
            4097, 8, 0, /* 807: pointer.func */
            4097, 8, 0, /* 810: pointer.func */
            4097, 8, 0, /* 813: pointer.func */
            1, 8, 1, /* 816: pointer.struct._pqueue */
            	821, 0,
            0, 0, 0, /* 821: struct._pqueue */
            0, 888, 7, /* 824: struct.dtls1_state_st */
            	841, 576,
            	841, 592,
            	816, 608,
            	816, 616,
            	841, 624,
            	846, 648,
            	846, 736,
            0, 16, 1, /* 841: struct.record_pqueue_st */
            	816, 8,
            0, 88, 1, /* 846: struct.hm_header_st */
            	851, 48,
            0, 40, 4, /* 851: struct.dtls1_retransmit_state */
            	862, 0,
            	595, 8,
            	444, 16,
            	867, 24,
            1, 8, 1, /* 862: pointer.struct.evp_cipher_ctx_st */
            	252, 0,
            1, 8, 1, /* 867: pointer.struct.ssl_session_st */
            	872, 0,
            0, 352, 14, /* 872: struct.ssl_session_st */
            	35, 144,
            	35, 152,
            	903, 168,
            	945, 176,
            	580, 224,
            	1498, 240,
            	231, 248,
            	1508, 264,
            	1508, 272,
            	35, 280,
            	436, 296,
            	436, 312,
            	436, 320,
            	35, 344,
            1, 8, 1, /* 903: pointer.struct.sess_cert_st */
            	908, 0,
            0, 248, 5, /* 908: struct.sess_cert_st */
            	921, 0,
            	931, 16,
            	1493, 216,
            	404, 224,
            	682, 232,
            1, 8, 1, /* 921: pointer.struct.stack_st_X509 */
            	926, 0,
            0, 32, 1, /* 926: struct.stack_st_X509 */
            	23, 0,
            1, 8, 1, /* 931: pointer.struct.cert_pkey_st */
            	936, 0,
            0, 24, 3, /* 936: struct.cert_pkey_st */
            	945, 0,
            	1239, 8,
            	534, 16,
            1, 8, 1, /* 945: pointer.struct.x509_st */
            	950, 0,
            0, 184, 12, /* 950: struct.x509_st */
            	977, 0,
            	1017, 8,
            	1106, 16,
            	35, 32,
            	231, 40,
            	1111, 104,
            	1408, 112,
            	1432, 120,
            	1440, 128,
            	1450, 136,
            	368, 144,
            	1455, 176,
            1, 8, 1, /* 977: pointer.struct.x509_cinf_st */
            	982, 0,
            0, 104, 11, /* 982: struct.x509_cinf_st */
            	1007, 0,
            	1007, 8,
            	1017, 16,
            	1174, 24,
            	1208, 32,
            	1174, 40,
            	1225, 48,
            	1106, 56,
            	1106, 64,
            	1398, 72,
            	765, 80,
            1, 8, 1, /* 1007: pointer.struct.asn1_string_st */
            	1012, 0,
            0, 24, 1, /* 1012: struct.asn1_string_st */
            	436, 8,
            1, 8, 1, /* 1017: pointer.struct.X509_algor_st */
            	1022, 0,
            0, 16, 2, /* 1022: struct.X509_algor_st */
            	1029, 0,
            	1043, 8,
            1, 8, 1, /* 1029: pointer.struct.asn1_object_st */
            	1034, 0,
            0, 40, 3, /* 1034: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	658, 24,
            1, 8, 1, /* 1043: pointer.struct.asn1_type_st */
            	1048, 0,
            0, 16, 1, /* 1048: struct.asn1_type_st */
            	1053, 8,
            0, 8, 20, /* 1053: union.unknown */
            	35, 0,
            	1096, 0,
            	1029, 0,
            	1007, 0,
            	1101, 0,
            	1106, 0,
            	1111, 0,
            	1116, 0,
            	1121, 0,
            	1126, 0,
            	1131, 0,
            	1136, 0,
            	1141, 0,
            	1146, 0,
            	1151, 0,
            	1156, 0,
            	1161, 0,
            	1096, 0,
            	1096, 0,
            	1166, 0,
            1, 8, 1, /* 1096: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 1101: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 1106: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 1111: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 1116: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 1121: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 1126: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 1131: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 1136: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 1141: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 1146: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 1151: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 1156: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 1161: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 1166: pointer.struct.ASN1_VALUE_st */
            	1171, 0,
            0, 0, 0, /* 1171: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1174: pointer.struct.X509_name_st */
            	1179, 0,
            0, 40, 3, /* 1179: struct.X509_name_st */
            	1188, 0,
            	1198, 16,
            	436, 24,
            1, 8, 1, /* 1188: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1193, 0,
            0, 32, 1, /* 1193: struct.stack_st_X509_NAME_ENTRY */
            	23, 0,
            1, 8, 1, /* 1198: pointer.struct.buf_mem_st */
            	1203, 0,
            0, 24, 1, /* 1203: struct.buf_mem_st */
            	35, 8,
            1, 8, 1, /* 1208: pointer.struct.X509_val_st */
            	1213, 0,
            0, 16, 2, /* 1213: struct.X509_val_st */
            	1220, 0,
            	1220, 8,
            1, 8, 1, /* 1220: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 1225: pointer.struct.X509_pubkey_st */
            	1230, 0,
            0, 24, 3, /* 1230: struct.X509_pubkey_st */
            	1017, 0,
            	1106, 8,
            	1239, 16,
            1, 8, 1, /* 1239: pointer.struct.evp_pkey_st */
            	1244, 0,
            0, 56, 4, /* 1244: struct.evp_pkey_st */
            	1255, 16,
            	297, 24,
            	1263, 32,
            	1388, 48,
            1, 8, 1, /* 1255: pointer.struct.evp_pkey_asn1_method_st */
            	1260, 0,
            0, 0, 0, /* 1260: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 1263: union.unknown */
            	35, 0,
            	1276, 0,
            	687, 0,
            	1378, 0,
            	1383, 0,
            1, 8, 1, /* 1276: pointer.struct.rsa_st */
            	1281, 0,
            0, 168, 17, /* 1281: struct.rsa_st */
            	1318, 16,
            	297, 24,
            	99, 32,
            	99, 40,
            	99, 48,
            	99, 56,
            	99, 64,
            	99, 72,
            	99, 80,
            	99, 88,
            	231, 96,
            	390, 120,
            	390, 128,
            	390, 136,
            	35, 144,
            	1370, 152,
            	1370, 160,
            1, 8, 1, /* 1318: pointer.struct.rsa_meth_st */
            	1323, 0,
            0, 112, 13, /* 1323: struct.rsa_meth_st */
            	10, 0,
            	1352, 8,
            	1352, 16,
            	1352, 24,
            	1352, 32,
            	1355, 40,
            	1358, 48,
            	1361, 56,
            	1361, 64,
            	35, 80,
            	1364, 88,
            	1367, 96,
            	770, 104,
            4097, 8, 0, /* 1352: pointer.func */
            4097, 8, 0, /* 1355: pointer.func */
            4097, 8, 0, /* 1358: pointer.func */
            4097, 8, 0, /* 1361: pointer.func */
            4097, 8, 0, /* 1364: pointer.func */
            4097, 8, 0, /* 1367: pointer.func */
            1, 8, 1, /* 1370: pointer.struct.bn_blinding_st */
            	1375, 0,
            0, 0, 0, /* 1375: struct.bn_blinding_st */
            1, 8, 1, /* 1378: pointer.struct.dh_st */
            	409, 0,
            1, 8, 1, /* 1383: pointer.struct.ec_key_st */
            	329, 0,
            1, 8, 1, /* 1388: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1393, 0,
            0, 32, 1, /* 1393: struct.stack_st_X509_ATTRIBUTE */
            	23, 0,
            1, 8, 1, /* 1398: pointer.struct.stack_st_X509_EXTENSION */
            	1403, 0,
            0, 32, 1, /* 1403: struct.stack_st_X509_EXTENSION */
            	23, 0,
            1, 8, 1, /* 1408: pointer.struct.AUTHORITY_KEYID_st */
            	1413, 0,
            0, 24, 3, /* 1413: struct.AUTHORITY_KEYID_st */
            	1111, 0,
            	1422, 8,
            	1007, 16,
            1, 8, 1, /* 1422: pointer.struct.stack_st_GENERAL_NAME */
            	1427, 0,
            0, 32, 1, /* 1427: struct.stack_st_GENERAL_NAME */
            	23, 0,
            1, 8, 1, /* 1432: pointer.struct.X509_POLICY_CACHE_st */
            	1437, 0,
            0, 0, 0, /* 1437: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1440: pointer.struct.stack_st_DIST_POINT */
            	1445, 0,
            0, 32, 1, /* 1445: struct.stack_st_DIST_POINT */
            	23, 0,
            1, 8, 1, /* 1450: pointer.struct.stack_st_GENERAL_NAME */
            	1427, 0,
            1, 8, 1, /* 1455: pointer.struct.x509_cert_aux_st */
            	1460, 0,
            0, 40, 5, /* 1460: struct.x509_cert_aux_st */
            	1473, 0,
            	1473, 8,
            	1161, 16,
            	1111, 24,
            	1483, 32,
            1, 8, 1, /* 1473: pointer.struct.stack_st_ASN1_OBJECT */
            	1478, 0,
            0, 32, 1, /* 1478: struct.stack_st_ASN1_OBJECT */
            	23, 0,
            1, 8, 1, /* 1483: pointer.struct.stack_st_X509_ALGOR */
            	1488, 0,
            0, 32, 1, /* 1488: struct.stack_st_X509_ALGOR */
            	23, 0,
            1, 8, 1, /* 1493: pointer.struct.rsa_st */
            	1281, 0,
            1, 8, 1, /* 1498: pointer.struct.stack_st_SSL_CIPHER */
            	1503, 0,
            0, 32, 1, /* 1503: struct.stack_st_SSL_CIPHER */
            	23, 0,
            1, 8, 1, /* 1508: pointer.struct.ssl_session_st */
            	872, 0,
            4097, 8, 0, /* 1513: pointer.func */
            4097, 8, 0, /* 1516: pointer.func */
            4097, 8, 0, /* 1519: pointer.func */
            1, 8, 1, /* 1522: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	51, 0,
            1, 8, 1, /* 1527: pointer.struct.cert_st */
            	1532, 0,
            0, 296, 7, /* 1532: struct.cert_st */
            	931, 0,
            	1493, 48,
            	1549, 56,
            	404, 64,
            	1552, 72,
            	682, 80,
            	1555, 88,
            4097, 8, 0, /* 1549: pointer.func */
            4097, 8, 0, /* 1552: pointer.func */
            4097, 8, 0, /* 1555: pointer.func */
            4097, 8, 0, /* 1558: pointer.func */
            4097, 8, 0, /* 1561: pointer.func */
            4097, 8, 0, /* 1564: pointer.func */
            0, 1, 0, /* 1567: char */
            1, 8, 1, /* 1570: pointer.struct.stack_st_X509_EXTENSION */
            	1403, 0,
            0, 808, 51, /* 1575: struct.ssl_st */
            	1680, 8,
            	575, 16,
            	575, 24,
            	575, 32,
            	567, 48,
            	1198, 80,
            	90, 88,
            	436, 104,
            	1785, 120,
            	625, 128,
            	1811, 136,
            	1816, 152,
            	90, 160,
            	1819, 176,
            	1498, 184,
            	1498, 192,
            	862, 208,
            	595, 216,
            	444, 224,
            	862, 232,
            	595, 240,
            	444, 248,
            	1527, 256,
            	867, 304,
            	1831, 312,
            	1834, 328,
            	1837, 336,
            	1840, 352,
            	1519, 360,
            	1843, 368,
            	231, 392,
            	305, 408,
            	48, 464,
            	90, 472,
            	35, 480,
            	43, 504,
            	1570, 512,
            	436, 520,
            	436, 544,
            	436, 560,
            	90, 568,
            	2059, 584,
            	2069, 592,
            	90, 600,
            	15, 608,
            	90, 616,
            	1843, 624,
            	436, 632,
            	1522, 648,
            	0, 656,
            	59, 680,
            1, 8, 1, /* 1680: pointer.struct.ssl_method_st */
            	1685, 0,
            0, 232, 28, /* 1685: struct.ssl_method_st */
            	567, 8,
            	528, 16,
            	528, 24,
            	567, 32,
            	567, 40,
            	1744, 48,
            	1744, 56,
            	1747, 64,
            	567, 72,
            	567, 80,
            	567, 88,
            	1750, 96,
            	1753, 104,
            	1756, 112,
            	567, 120,
            	1759, 128,
            	1762, 136,
            	1564, 144,
            	1765, 152,
            	1768, 160,
            	1771, 168,
            	1561, 176,
            	1513, 184,
            	228, 192,
            	1774, 200,
            	1771, 208,
            	1779, 216,
            	1782, 224,
            4097, 8, 0, /* 1744: pointer.func */
            4097, 8, 0, /* 1747: pointer.func */
            4097, 8, 0, /* 1750: pointer.func */
            4097, 8, 0, /* 1753: pointer.func */
            4097, 8, 0, /* 1756: pointer.func */
            4097, 8, 0, /* 1759: pointer.func */
            4097, 8, 0, /* 1762: pointer.func */
            4097, 8, 0, /* 1765: pointer.func */
            4097, 8, 0, /* 1768: pointer.func */
            4097, 8, 0, /* 1771: pointer.func */
            1, 8, 1, /* 1774: pointer.struct.ssl3_enc_method */
            	773, 0,
            4097, 8, 0, /* 1779: pointer.func */
            4097, 8, 0, /* 1782: pointer.func */
            1, 8, 1, /* 1785: pointer.struct.ssl2_state_st */
            	1790, 0,
            0, 344, 9, /* 1790: struct.ssl2_state_st */
            	658, 24,
            	436, 56,
            	436, 64,
            	436, 72,
            	436, 104,
            	436, 112,
            	436, 120,
            	436, 128,
            	436, 136,
            1, 8, 1, /* 1811: pointer.struct.dtls1_state_st */
            	824, 0,
            4097, 8, 0, /* 1816: pointer.func */
            1, 8, 1, /* 1819: pointer.struct.X509_VERIFY_PARAM_st */
            	1824, 0,
            0, 56, 2, /* 1824: struct.X509_VERIFY_PARAM_st */
            	35, 0,
            	1473, 48,
            4097, 8, 0, /* 1831: pointer.func */
            4097, 8, 0, /* 1834: pointer.func */
            4097, 8, 0, /* 1837: pointer.func */
            4097, 8, 0, /* 1840: pointer.func */
            1, 8, 1, /* 1843: pointer.struct.ssl_ctx_st */
            	1848, 0,
            0, 736, 50, /* 1848: struct.ssl_ctx_st */
            	1680, 0,
            	1498, 8,
            	1498, 16,
            	1951, 24,
            	160, 32,
            	1508, 48,
            	1508, 56,
            	139, 80,
            	136, 88,
            	133, 96,
            	142, 152,
            	90, 160,
            	2024, 168,
            	90, 176,
            	2027, 184,
            	2030, 192,
            	130, 200,
            	231, 208,
            	534, 224,
            	534, 232,
            	534, 240,
            	921, 248,
            	125, 256,
            	1837, 264,
            	305, 272,
            	1527, 304,
            	1816, 320,
            	90, 328,
            	1834, 376,
            	1831, 384,
            	1819, 392,
            	297, 408,
            	93, 416,
            	90, 424,
            	2033, 480,
            	96, 488,
            	90, 496,
            	117, 504,
            	90, 512,
            	35, 520,
            	1840, 528,
            	1519, 536,
            	2036, 552,
            	2036, 560,
            	59, 568,
            	1558, 696,
            	90, 704,
            	2056, 712,
            	90, 720,
            	1522, 728,
            1, 8, 1, /* 1951: pointer.struct.x509_store_st */
            	1956, 0,
            0, 144, 15, /* 1956: struct.x509_store_st */
            	1989, 8,
            	1999, 16,
            	1819, 24,
            	2009, 32,
            	1834, 40,
            	2012, 48,
            	2015, 56,
            	2009, 64,
            	2018, 72,
            	2021, 80,
            	187, 88,
            	1516, 96,
            	184, 104,
            	2009, 112,
            	231, 120,
            1, 8, 1, /* 1989: pointer.struct.stack_st_X509_OBJECT */
            	1994, 0,
            0, 32, 1, /* 1994: struct.stack_st_X509_OBJECT */
            	23, 0,
            1, 8, 1, /* 1999: pointer.struct.stack_st_X509_LOOKUP */
            	2004, 0,
            0, 32, 1, /* 2004: struct.stack_st_X509_LOOKUP */
            	23, 0,
            4097, 8, 0, /* 2009: pointer.func */
            4097, 8, 0, /* 2012: pointer.func */
            4097, 8, 0, /* 2015: pointer.func */
            4097, 8, 0, /* 2018: pointer.func */
            4097, 8, 0, /* 2021: pointer.func */
            4097, 8, 0, /* 2024: pointer.func */
            4097, 8, 0, /* 2027: pointer.func */
            4097, 8, 0, /* 2030: pointer.func */
            4097, 8, 0, /* 2033: pointer.func */
            1, 8, 1, /* 2036: pointer.struct.ssl3_buf_freelist_st */
            	2041, 0,
            0, 24, 1, /* 2041: struct.ssl3_buf_freelist_st */
            	2046, 16,
            1, 8, 1, /* 2046: pointer.struct.ssl3_buf_freelist_entry_st */
            	2051, 0,
            0, 8, 1, /* 2051: struct.ssl3_buf_freelist_entry_st */
            	2046, 0,
            4097, 8, 0, /* 2056: pointer.func */
            1, 8, 1, /* 2059: pointer.struct.tls_session_ticket_ext_st */
            	2064, 0,
            0, 16, 1, /* 2064: struct.tls_session_ticket_ext_st */
            	90, 8,
            4097, 8, 0, /* 2069: pointer.func */
            0, 8, 0, /* 2072: long int */
            1, 8, 1, /* 2075: pointer.struct.ssl_st */
            	1575, 0,
        },
        .arg_entity_index = { 2075, 2072, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL * new_arg_a = *((SSL * *)new_args->args[0]);

    long new_arg_b = *((long *)new_args->args[1]);

    void (*orig_SSL_set_verify_result)(SSL *,long);
    orig_SSL_set_verify_result = dlsym(RTLD_NEXT, "SSL_set_verify_result");
    (*orig_SSL_set_verify_result)(new_arg_a,new_arg_b);

    syscall(889);

}

