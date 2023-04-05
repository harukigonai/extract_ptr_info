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

int bb_SSL_accept(SSL * arg_a);

int SSL_accept(SSL * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_accept called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_accept(arg_a);
    else {
        int (*orig_SSL_accept)(SSL *);
        orig_SSL_accept = dlsym(RTLD_NEXT, "SSL_accept");
        return orig_SSL_accept(arg_a);
    }
}

int bb_SSL_accept(SSL * arg_a) 
{
    int ret;

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
            4097, 8, 0, /* 59: pointer.func */
            0, 128, 14, /* 62: struct.srp_ctx_st */
            	93, 0,
            	96, 8,
            	99, 16,
            	59, 24,
            	35, 32,
            	102, 40,
            	102, 48,
            	102, 56,
            	102, 64,
            	102, 72,
            	102, 80,
            	102, 88,
            	102, 96,
            	35, 104,
            0, 8, 0, /* 93: pointer.void */
            4097, 8, 0, /* 96: pointer.func */
            4097, 8, 0, /* 99: pointer.func */
            1, 8, 1, /* 102: pointer.struct.bignum_st */
            	107, 0,
            0, 24, 1, /* 107: struct.bignum_st */
            	112, 0,
            1, 8, 1, /* 112: pointer.unsigned int */
            	117, 0,
            0, 4, 0, /* 117: unsigned int */
            4097, 8, 0, /* 120: pointer.func */
            0, 32, 1, /* 123: struct.stack_st_SSL_COMP */
            	23, 0,
            1, 8, 1, /* 128: pointer.struct.stack_st_SSL_COMP */
            	123, 0,
            4097, 8, 0, /* 133: pointer.func */
            4097, 8, 0, /* 136: pointer.func */
            4097, 8, 0, /* 139: pointer.func */
            4097, 8, 0, /* 142: pointer.func */
            4097, 8, 0, /* 145: pointer.func */
            4097, 8, 0, /* 148: pointer.func */
            1, 8, 1, /* 151: pointer.struct.lhash_node_st */
            	156, 0,
            0, 24, 2, /* 156: struct.lhash_node_st */
            	93, 0,
            	151, 8,
            1, 8, 1, /* 163: pointer.struct.lhash_st */
            	168, 0,
            0, 176, 3, /* 168: struct.lhash_st */
            	177, 0,
            	40, 8,
            	148, 16,
            1, 8, 1, /* 177: pointer.pointer.struct.lhash_node_st */
            	182, 0,
            1, 8, 1, /* 182: pointer.struct.lhash_node_st */
            	156, 0,
            4097, 8, 0, /* 187: pointer.func */
            4097, 8, 0, /* 190: pointer.func */
            0, 56, 2, /* 193: struct.comp_ctx_st */
            	200, 0,
            	234, 40,
            1, 8, 1, /* 200: pointer.struct.comp_method_st */
            	205, 0,
            0, 64, 7, /* 205: struct.comp_method_st */
            	10, 8,
            	222, 16,
            	225, 24,
            	228, 32,
            	228, 40,
            	231, 48,
            	231, 56,
            4097, 8, 0, /* 222: pointer.func */
            4097, 8, 0, /* 225: pointer.func */
            4097, 8, 0, /* 228: pointer.func */
            4097, 8, 0, /* 231: pointer.func */
            0, 16, 1, /* 234: struct.crypto_ex_data_st */
            	239, 0,
            1, 8, 1, /* 239: pointer.struct.stack_st_void */
            	244, 0,
            0, 32, 1, /* 244: struct.stack_st_void */
            	23, 0,
            4097, 8, 0, /* 249: pointer.func */
            4097, 8, 0, /* 252: pointer.func */
            0, 168, 4, /* 255: struct.evp_cipher_ctx_st */
            	266, 0,
            	300, 8,
            	93, 96,
            	93, 120,
            1, 8, 1, /* 266: pointer.struct.evp_cipher_st */
            	271, 0,
            0, 88, 7, /* 271: struct.evp_cipher_st */
            	288, 24,
            	249, 32,
            	291, 40,
            	294, 56,
            	294, 64,
            	297, 72,
            	93, 80,
            4097, 8, 0, /* 288: pointer.func */
            4097, 8, 0, /* 291: pointer.func */
            4097, 8, 0, /* 294: pointer.func */
            4097, 8, 0, /* 297: pointer.func */
            1, 8, 1, /* 300: pointer.struct.engine_st */
            	305, 0,
            0, 0, 0, /* 305: struct.engine_st */
            1, 8, 1, /* 308: pointer.struct.stack_st_X509_NAME */
            	313, 0,
            0, 32, 1, /* 313: struct.stack_st_X509_NAME */
            	23, 0,
            4097, 8, 0, /* 318: pointer.func */
            4097, 8, 0, /* 321: pointer.func */
            1, 8, 1, /* 324: pointer.struct.evp_pkey_ctx_st */
            	329, 0,
            0, 0, 0, /* 329: struct.evp_pkey_ctx_st */
            0, 0, 0, /* 332: struct.ec_key_st */
            1, 8, 1, /* 335: pointer.struct.dh_method */
            	340, 0,
            0, 72, 8, /* 340: struct.dh_method */
            	10, 0,
            	359, 8,
            	362, 16,
            	365, 24,
            	359, 32,
            	359, 40,
            	35, 56,
            	368, 64,
            4097, 8, 0, /* 359: pointer.func */
            4097, 8, 0, /* 362: pointer.func */
            4097, 8, 0, /* 365: pointer.func */
            4097, 8, 0, /* 368: pointer.func */
            1, 8, 1, /* 371: pointer.struct.NAME_CONSTRAINTS_st */
            	376, 0,
            0, 16, 2, /* 376: struct.NAME_CONSTRAINTS_st */
            	383, 0,
            	383, 8,
            1, 8, 1, /* 383: pointer.struct.stack_st_GENERAL_SUBTREE */
            	388, 0,
            0, 32, 1, /* 388: struct.stack_st_GENERAL_SUBTREE */
            	23, 0,
            1, 8, 1, /* 393: pointer.struct.bn_mont_ctx_st */
            	398, 0,
            0, 96, 3, /* 398: struct.bn_mont_ctx_st */
            	107, 8,
            	107, 32,
            	107, 56,
            1, 8, 1, /* 407: pointer.struct.asn1_string_st */
            	412, 0,
            0, 24, 1, /* 412: struct.asn1_string_st */
            	417, 8,
            1, 8, 1, /* 417: pointer.unsigned char */
            	422, 0,
            0, 1, 0, /* 422: unsigned char */
            1, 8, 1, /* 425: pointer.struct.ec_key_st */
            	332, 0,
            4097, 8, 0, /* 430: pointer.func */
            1, 8, 1, /* 433: pointer.struct.stack_st_X509_NAME_ENTRY */
            	438, 0,
            0, 32, 1, /* 438: struct.stack_st_X509_NAME_ENTRY */
            	23, 0,
            1, 8, 1, /* 443: pointer.struct.dh_st */
            	448, 0,
            0, 144, 12, /* 448: struct.dh_st */
            	102, 8,
            	102, 16,
            	102, 32,
            	102, 40,
            	393, 56,
            	102, 64,
            	102, 72,
            	417, 80,
            	102, 96,
            	234, 112,
            	335, 128,
            	300, 136,
            1, 8, 1, /* 475: pointer.struct.comp_ctx_st */
            	193, 0,
            0, 112, 7, /* 480: struct.bio_st */
            	497, 0,
            	538, 8,
            	35, 16,
            	93, 48,
            	541, 56,
            	541, 64,
            	234, 96,
            1, 8, 1, /* 497: pointer.struct.bio_method_st */
            	502, 0,
            0, 80, 9, /* 502: struct.bio_method_st */
            	10, 8,
            	523, 16,
            	526, 24,
            	529, 32,
            	526, 40,
            	252, 48,
            	532, 56,
            	532, 64,
            	535, 72,
            4097, 8, 0, /* 523: pointer.func */
            4097, 8, 0, /* 526: pointer.func */
            4097, 8, 0, /* 529: pointer.func */
            4097, 8, 0, /* 532: pointer.func */
            4097, 8, 0, /* 535: pointer.func */
            4097, 8, 0, /* 538: pointer.func */
            1, 8, 1, /* 541: pointer.struct.bio_st */
            	480, 0,
            4097, 8, 0, /* 546: pointer.func */
            0, 24, 2, /* 549: struct.ssl_comp_st */
            	10, 8,
            	200, 16,
            4097, 8, 0, /* 556: pointer.func */
            4097, 8, 0, /* 559: pointer.func */
            4097, 8, 0, /* 562: pointer.func */
            1, 8, 1, /* 565: pointer.struct.env_md_st */
            	570, 0,
            0, 120, 8, /* 570: struct.env_md_st */
            	318, 24,
            	589, 32,
            	592, 40,
            	562, 48,
            	318, 56,
            	556, 64,
            	595, 72,
            	546, 112,
            4097, 8, 0, /* 589: pointer.func */
            4097, 8, 0, /* 592: pointer.func */
            4097, 8, 0, /* 595: pointer.func */
            4097, 8, 0, /* 598: pointer.func */
            1, 8, 1, /* 601: pointer.struct.ssl_comp_st */
            	549, 0,
            1, 8, 1, /* 606: pointer.struct.bio_st */
            	480, 0,
            1, 8, 1, /* 611: pointer.struct.ssl_cipher_st */
            	616, 0,
            0, 88, 1, /* 616: struct.ssl_cipher_st */
            	10, 8,
            1, 8, 1, /* 621: pointer.pointer.struct.env_md_ctx_st */
            	626, 0,
            1, 8, 1, /* 626: pointer.struct.env_md_ctx_st */
            	631, 0,
            0, 48, 5, /* 631: struct.env_md_ctx_st */
            	565, 0,
            	300, 8,
            	93, 24,
            	324, 32,
            	589, 40,
            4097, 8, 0, /* 644: pointer.func */
            0, 56, 3, /* 647: struct.ssl3_record_st */
            	417, 16,
            	417, 24,
            	417, 32,
            1, 8, 1, /* 656: pointer.struct.ssl3_state_st */
            	661, 0,
            0, 1200, 10, /* 661: struct.ssl3_state_st */
            	684, 240,
            	684, 264,
            	647, 288,
            	647, 344,
            	689, 432,
            	606, 440,
            	621, 448,
            	93, 496,
            	93, 512,
            	694, 528,
            0, 24, 1, /* 684: struct.ssl3_buffer_st */
            	417, 0,
            1, 8, 1, /* 689: pointer.unsigned char */
            	422, 0,
            0, 528, 8, /* 694: struct.unknown */
            	611, 408,
            	443, 416,
            	425, 424,
            	308, 464,
            	417, 480,
            	266, 488,
            	565, 496,
            	601, 512,
            1, 8, 1, /* 713: pointer.struct.dsa_st */
            	718, 0,
            0, 136, 11, /* 718: struct.dsa_st */
            	102, 24,
            	102, 32,
            	102, 40,
            	102, 48,
            	102, 56,
            	102, 64,
            	102, 72,
            	393, 88,
            	234, 104,
            	743, 120,
            	300, 128,
            1, 8, 1, /* 743: pointer.struct.dsa_method */
            	748, 0,
            0, 96, 11, /* 748: struct.dsa_method */
            	10, 0,
            	773, 8,
            	776, 16,
            	779, 24,
            	782, 32,
            	785, 40,
            	788, 48,
            	788, 56,
            	35, 72,
            	321, 80,
            	788, 88,
            4097, 8, 0, /* 773: pointer.func */
            4097, 8, 0, /* 776: pointer.func */
            4097, 8, 0, /* 779: pointer.func */
            4097, 8, 0, /* 782: pointer.func */
            4097, 8, 0, /* 785: pointer.func */
            4097, 8, 0, /* 788: pointer.func */
            0, 24, 1, /* 791: struct.ASN1_ENCODING_st */
            	417, 0,
            4097, 8, 0, /* 796: pointer.func */
            0, 112, 11, /* 799: struct.ssl3_enc_method */
            	824, 0,
            	827, 8,
            	598, 16,
            	830, 24,
            	824, 32,
            	644, 40,
            	833, 56,
            	10, 64,
            	10, 80,
            	836, 96,
            	839, 104,
            4097, 8, 0, /* 824: pointer.func */
            4097, 8, 0, /* 827: pointer.func */
            4097, 8, 0, /* 830: pointer.func */
            4097, 8, 0, /* 833: pointer.func */
            4097, 8, 0, /* 836: pointer.func */
            4097, 8, 0, /* 839: pointer.func */
            1, 8, 1, /* 842: pointer.struct._pqueue */
            	847, 0,
            0, 0, 0, /* 847: struct._pqueue */
            0, 888, 7, /* 850: struct.dtls1_state_st */
            	867, 576,
            	867, 592,
            	842, 608,
            	842, 616,
            	867, 624,
            	872, 648,
            	872, 736,
            0, 16, 1, /* 867: struct.record_pqueue_st */
            	842, 8,
            0, 88, 1, /* 872: struct.hm_header_st */
            	877, 48,
            0, 40, 4, /* 877: struct.dtls1_retransmit_state */
            	888, 0,
            	626, 8,
            	475, 16,
            	893, 24,
            1, 8, 1, /* 888: pointer.struct.evp_cipher_ctx_st */
            	255, 0,
            1, 8, 1, /* 893: pointer.struct.ssl_session_st */
            	898, 0,
            0, 352, 14, /* 898: struct.ssl_session_st */
            	35, 144,
            	35, 152,
            	929, 168,
            	971, 176,
            	611, 224,
            	1504, 240,
            	234, 248,
            	1514, 264,
            	1514, 272,
            	35, 280,
            	417, 296,
            	417, 312,
            	417, 320,
            	35, 344,
            1, 8, 1, /* 929: pointer.struct.sess_cert_st */
            	934, 0,
            0, 248, 5, /* 934: struct.sess_cert_st */
            	947, 0,
            	957, 16,
            	1499, 216,
            	443, 224,
            	425, 232,
            1, 8, 1, /* 947: pointer.struct.stack_st_X509 */
            	952, 0,
            0, 32, 1, /* 952: struct.stack_st_X509 */
            	23, 0,
            1, 8, 1, /* 957: pointer.struct.cert_pkey_st */
            	962, 0,
            0, 24, 3, /* 962: struct.cert_pkey_st */
            	971, 0,
            	1245, 8,
            	565, 16,
            1, 8, 1, /* 971: pointer.struct.x509_st */
            	976, 0,
            0, 184, 12, /* 976: struct.x509_st */
            	1003, 0,
            	1038, 8,
            	1127, 16,
            	35, 32,
            	234, 40,
            	1132, 104,
            	1414, 112,
            	1438, 120,
            	1446, 128,
            	1456, 136,
            	371, 144,
            	1461, 176,
            1, 8, 1, /* 1003: pointer.struct.x509_cinf_st */
            	1008, 0,
            0, 104, 11, /* 1008: struct.x509_cinf_st */
            	1033, 0,
            	1033, 8,
            	1038, 16,
            	1190, 24,
            	1214, 32,
            	1190, 40,
            	1231, 48,
            	1127, 56,
            	1127, 64,
            	1404, 72,
            	791, 80,
            1, 8, 1, /* 1033: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1038: pointer.struct.X509_algor_st */
            	1043, 0,
            0, 16, 2, /* 1043: struct.X509_algor_st */
            	1050, 0,
            	1064, 8,
            1, 8, 1, /* 1050: pointer.struct.asn1_object_st */
            	1055, 0,
            0, 40, 3, /* 1055: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	689, 24,
            1, 8, 1, /* 1064: pointer.struct.asn1_type_st */
            	1069, 0,
            0, 16, 1, /* 1069: struct.asn1_type_st */
            	1074, 8,
            0, 8, 20, /* 1074: union.unknown */
            	35, 0,
            	1117, 0,
            	1050, 0,
            	1033, 0,
            	1122, 0,
            	1127, 0,
            	1132, 0,
            	1137, 0,
            	1142, 0,
            	407, 0,
            	1147, 0,
            	1152, 0,
            	1157, 0,
            	1162, 0,
            	1167, 0,
            	1172, 0,
            	1177, 0,
            	1117, 0,
            	1117, 0,
            	1182, 0,
            1, 8, 1, /* 1117: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1122: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1127: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1132: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1137: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1142: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1147: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1152: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1157: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1162: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1167: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1172: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1177: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1182: pointer.struct.ASN1_VALUE_st */
            	1187, 0,
            0, 0, 0, /* 1187: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1190: pointer.struct.X509_name_st */
            	1195, 0,
            0, 40, 3, /* 1195: struct.X509_name_st */
            	433, 0,
            	1204, 16,
            	417, 24,
            1, 8, 1, /* 1204: pointer.struct.buf_mem_st */
            	1209, 0,
            0, 24, 1, /* 1209: struct.buf_mem_st */
            	35, 8,
            1, 8, 1, /* 1214: pointer.struct.X509_val_st */
            	1219, 0,
            0, 16, 2, /* 1219: struct.X509_val_st */
            	1226, 0,
            	1226, 8,
            1, 8, 1, /* 1226: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1231: pointer.struct.X509_pubkey_st */
            	1236, 0,
            0, 24, 3, /* 1236: struct.X509_pubkey_st */
            	1038, 0,
            	1127, 8,
            	1245, 16,
            1, 8, 1, /* 1245: pointer.struct.evp_pkey_st */
            	1250, 0,
            0, 56, 4, /* 1250: struct.evp_pkey_st */
            	1261, 16,
            	300, 24,
            	1269, 32,
            	1394, 48,
            1, 8, 1, /* 1261: pointer.struct.evp_pkey_asn1_method_st */
            	1266, 0,
            0, 0, 0, /* 1266: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 1269: union.unknown */
            	35, 0,
            	1282, 0,
            	713, 0,
            	1384, 0,
            	1389, 0,
            1, 8, 1, /* 1282: pointer.struct.rsa_st */
            	1287, 0,
            0, 168, 17, /* 1287: struct.rsa_st */
            	1324, 16,
            	300, 24,
            	102, 32,
            	102, 40,
            	102, 48,
            	102, 56,
            	102, 64,
            	102, 72,
            	102, 80,
            	102, 88,
            	234, 96,
            	393, 120,
            	393, 128,
            	393, 136,
            	35, 144,
            	1376, 152,
            	1376, 160,
            1, 8, 1, /* 1324: pointer.struct.rsa_meth_st */
            	1329, 0,
            0, 112, 13, /* 1329: struct.rsa_meth_st */
            	10, 0,
            	1358, 8,
            	1358, 16,
            	1358, 24,
            	1358, 32,
            	1361, 40,
            	1364, 48,
            	1367, 56,
            	1367, 64,
            	35, 80,
            	1370, 88,
            	1373, 96,
            	796, 104,
            4097, 8, 0, /* 1358: pointer.func */
            4097, 8, 0, /* 1361: pointer.func */
            4097, 8, 0, /* 1364: pointer.func */
            4097, 8, 0, /* 1367: pointer.func */
            4097, 8, 0, /* 1370: pointer.func */
            4097, 8, 0, /* 1373: pointer.func */
            1, 8, 1, /* 1376: pointer.struct.bn_blinding_st */
            	1381, 0,
            0, 0, 0, /* 1381: struct.bn_blinding_st */
            1, 8, 1, /* 1384: pointer.struct.dh_st */
            	448, 0,
            1, 8, 1, /* 1389: pointer.struct.ec_key_st */
            	332, 0,
            1, 8, 1, /* 1394: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1399, 0,
            0, 32, 1, /* 1399: struct.stack_st_X509_ATTRIBUTE */
            	23, 0,
            1, 8, 1, /* 1404: pointer.struct.stack_st_X509_EXTENSION */
            	1409, 0,
            0, 32, 1, /* 1409: struct.stack_st_X509_EXTENSION */
            	23, 0,
            1, 8, 1, /* 1414: pointer.struct.AUTHORITY_KEYID_st */
            	1419, 0,
            0, 24, 3, /* 1419: struct.AUTHORITY_KEYID_st */
            	1132, 0,
            	1428, 8,
            	1033, 16,
            1, 8, 1, /* 1428: pointer.struct.stack_st_GENERAL_NAME */
            	1433, 0,
            0, 32, 1, /* 1433: struct.stack_st_GENERAL_NAME */
            	23, 0,
            1, 8, 1, /* 1438: pointer.struct.X509_POLICY_CACHE_st */
            	1443, 0,
            0, 0, 0, /* 1443: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1446: pointer.struct.stack_st_DIST_POINT */
            	1451, 0,
            0, 32, 1, /* 1451: struct.stack_st_DIST_POINT */
            	23, 0,
            1, 8, 1, /* 1456: pointer.struct.stack_st_GENERAL_NAME */
            	1433, 0,
            1, 8, 1, /* 1461: pointer.struct.x509_cert_aux_st */
            	1466, 0,
            0, 40, 5, /* 1466: struct.x509_cert_aux_st */
            	1479, 0,
            	1479, 8,
            	1177, 16,
            	1132, 24,
            	1489, 32,
            1, 8, 1, /* 1479: pointer.struct.stack_st_ASN1_OBJECT */
            	1484, 0,
            0, 32, 1, /* 1484: struct.stack_st_ASN1_OBJECT */
            	23, 0,
            1, 8, 1, /* 1489: pointer.struct.stack_st_X509_ALGOR */
            	1494, 0,
            0, 32, 1, /* 1494: struct.stack_st_X509_ALGOR */
            	23, 0,
            1, 8, 1, /* 1499: pointer.struct.rsa_st */
            	1287, 0,
            1, 8, 1, /* 1504: pointer.struct.stack_st_SSL_CIPHER */
            	1509, 0,
            0, 32, 1, /* 1509: struct.stack_st_SSL_CIPHER */
            	23, 0,
            1, 8, 1, /* 1514: pointer.struct.ssl_session_st */
            	898, 0,
            4097, 8, 0, /* 1519: pointer.func */
            4097, 8, 0, /* 1522: pointer.func */
            1, 8, 1, /* 1525: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	51, 0,
            1, 8, 1, /* 1530: pointer.struct.cert_st */
            	1535, 0,
            0, 296, 7, /* 1535: struct.cert_st */
            	957, 0,
            	1499, 48,
            	1552, 56,
            	443, 64,
            	1555, 72,
            	425, 80,
            	1558, 88,
            4097, 8, 0, /* 1552: pointer.func */
            4097, 8, 0, /* 1555: pointer.func */
            4097, 8, 0, /* 1558: pointer.func */
            4097, 8, 0, /* 1561: pointer.func */
            4097, 8, 0, /* 1564: pointer.func */
            4097, 8, 0, /* 1567: pointer.func */
            0, 1, 0, /* 1570: char */
            1, 8, 1, /* 1573: pointer.struct.stack_st_X509_EXTENSION */
            	1409, 0,
            0, 808, 51, /* 1578: struct.ssl_st */
            	1683, 8,
            	606, 16,
            	606, 24,
            	606, 32,
            	598, 48,
            	1204, 80,
            	93, 88,
            	417, 104,
            	1788, 120,
            	656, 128,
            	1814, 136,
            	1819, 152,
            	93, 160,
            	1822, 176,
            	1504, 184,
            	1504, 192,
            	888, 208,
            	626, 216,
            	475, 224,
            	888, 232,
            	626, 240,
            	475, 248,
            	1530, 256,
            	893, 304,
            	1834, 312,
            	1837, 328,
            	1840, 336,
            	1843, 352,
            	1522, 360,
            	1846, 368,
            	234, 392,
            	308, 408,
            	48, 464,
            	93, 472,
            	35, 480,
            	43, 504,
            	1573, 512,
            	417, 520,
            	417, 544,
            	417, 560,
            	93, 568,
            	2059, 584,
            	2069, 592,
            	93, 600,
            	15, 608,
            	93, 616,
            	1846, 624,
            	417, 632,
            	1525, 648,
            	0, 656,
            	62, 680,
            1, 8, 1, /* 1683: pointer.struct.ssl_method_st */
            	1688, 0,
            0, 232, 28, /* 1688: struct.ssl_method_st */
            	598, 8,
            	559, 16,
            	559, 24,
            	598, 32,
            	598, 40,
            	1747, 48,
            	1747, 56,
            	1750, 64,
            	598, 72,
            	598, 80,
            	598, 88,
            	1753, 96,
            	1756, 104,
            	1759, 112,
            	598, 120,
            	1762, 128,
            	1765, 136,
            	1567, 144,
            	1768, 152,
            	1771, 160,
            	1774, 168,
            	1564, 176,
            	430, 184,
            	231, 192,
            	1777, 200,
            	1774, 208,
            	1782, 216,
            	1785, 224,
            4097, 8, 0, /* 1747: pointer.func */
            4097, 8, 0, /* 1750: pointer.func */
            4097, 8, 0, /* 1753: pointer.func */
            4097, 8, 0, /* 1756: pointer.func */
            4097, 8, 0, /* 1759: pointer.func */
            4097, 8, 0, /* 1762: pointer.func */
            4097, 8, 0, /* 1765: pointer.func */
            4097, 8, 0, /* 1768: pointer.func */
            4097, 8, 0, /* 1771: pointer.func */
            4097, 8, 0, /* 1774: pointer.func */
            1, 8, 1, /* 1777: pointer.struct.ssl3_enc_method */
            	799, 0,
            4097, 8, 0, /* 1782: pointer.func */
            4097, 8, 0, /* 1785: pointer.func */
            1, 8, 1, /* 1788: pointer.struct.ssl2_state_st */
            	1793, 0,
            0, 344, 9, /* 1793: struct.ssl2_state_st */
            	689, 24,
            	417, 56,
            	417, 64,
            	417, 72,
            	417, 104,
            	417, 112,
            	417, 120,
            	417, 128,
            	417, 136,
            1, 8, 1, /* 1814: pointer.struct.dtls1_state_st */
            	850, 0,
            4097, 8, 0, /* 1819: pointer.func */
            1, 8, 1, /* 1822: pointer.struct.X509_VERIFY_PARAM_st */
            	1827, 0,
            0, 56, 2, /* 1827: struct.X509_VERIFY_PARAM_st */
            	35, 0,
            	1479, 48,
            4097, 8, 0, /* 1834: pointer.func */
            4097, 8, 0, /* 1837: pointer.func */
            4097, 8, 0, /* 1840: pointer.func */
            4097, 8, 0, /* 1843: pointer.func */
            1, 8, 1, /* 1846: pointer.struct.ssl_ctx_st */
            	1851, 0,
            0, 736, 50, /* 1851: struct.ssl_ctx_st */
            	1683, 0,
            	1504, 8,
            	1504, 16,
            	1954, 24,
            	163, 32,
            	1514, 48,
            	1514, 56,
            	142, 80,
            	139, 88,
            	136, 96,
            	145, 152,
            	93, 160,
            	2027, 168,
            	93, 176,
            	2030, 184,
            	2033, 192,
            	133, 200,
            	234, 208,
            	565, 224,
            	565, 232,
            	565, 240,
            	947, 248,
            	128, 256,
            	1840, 264,
            	308, 272,
            	1530, 304,
            	1819, 320,
            	93, 328,
            	1837, 376,
            	1834, 384,
            	1822, 392,
            	300, 408,
            	96, 416,
            	93, 424,
            	2036, 480,
            	99, 488,
            	93, 496,
            	120, 504,
            	93, 512,
            	35, 520,
            	1843, 528,
            	1522, 536,
            	2039, 552,
            	2039, 560,
            	62, 568,
            	1561, 696,
            	93, 704,
            	56, 712,
            	93, 720,
            	1525, 728,
            1, 8, 1, /* 1954: pointer.struct.x509_store_st */
            	1959, 0,
            0, 144, 15, /* 1959: struct.x509_store_st */
            	1992, 8,
            	2002, 16,
            	1822, 24,
            	2012, 32,
            	1837, 40,
            	2015, 48,
            	2018, 56,
            	2012, 64,
            	2021, 72,
            	2024, 80,
            	190, 88,
            	1519, 96,
            	187, 104,
            	2012, 112,
            	234, 120,
            1, 8, 1, /* 1992: pointer.struct.stack_st_X509_OBJECT */
            	1997, 0,
            0, 32, 1, /* 1997: struct.stack_st_X509_OBJECT */
            	23, 0,
            1, 8, 1, /* 2002: pointer.struct.stack_st_X509_LOOKUP */
            	2007, 0,
            0, 32, 1, /* 2007: struct.stack_st_X509_LOOKUP */
            	23, 0,
            4097, 8, 0, /* 2012: pointer.func */
            4097, 8, 0, /* 2015: pointer.func */
            4097, 8, 0, /* 2018: pointer.func */
            4097, 8, 0, /* 2021: pointer.func */
            4097, 8, 0, /* 2024: pointer.func */
            4097, 8, 0, /* 2027: pointer.func */
            4097, 8, 0, /* 2030: pointer.func */
            4097, 8, 0, /* 2033: pointer.func */
            4097, 8, 0, /* 2036: pointer.func */
            1, 8, 1, /* 2039: pointer.struct.ssl3_buf_freelist_st */
            	2044, 0,
            0, 24, 1, /* 2044: struct.ssl3_buf_freelist_st */
            	2049, 16,
            1, 8, 1, /* 2049: pointer.struct.ssl3_buf_freelist_entry_st */
            	2054, 0,
            0, 8, 1, /* 2054: struct.ssl3_buf_freelist_entry_st */
            	2049, 0,
            1, 8, 1, /* 2059: pointer.struct.tls_session_ticket_ext_st */
            	2064, 0,
            0, 16, 1, /* 2064: struct.tls_session_ticket_ext_st */
            	93, 8,
            4097, 8, 0, /* 2069: pointer.func */
            1, 8, 1, /* 2072: pointer.struct.ssl_st */
            	1578, 0,
            0, 4, 0, /* 2077: int */
        },
        .arg_entity_index = { 2072, },
        .ret_entity_index = 2077,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL * new_arg_a = *((SSL * *)new_args->args[0]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_SSL_accept)(SSL *);
    orig_SSL_accept = dlsym(RTLD_NEXT, "SSL_accept");
    *new_ret_ptr = (*orig_SSL_accept)(new_arg_a);

    syscall(889);

    return ret;
}

