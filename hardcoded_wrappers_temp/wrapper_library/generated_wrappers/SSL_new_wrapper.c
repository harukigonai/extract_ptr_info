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

SSL * bb_SSL_new(SSL_CTX * arg_a);

SSL * SSL_new(SSL_CTX * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_new called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_new(arg_a);
    else {
        SSL * (*orig_SSL_new)(SSL_CTX *);
        orig_SSL_new = dlsym(RTLD_NEXT, "SSL_new");
        return orig_SSL_new(arg_a);
    }
}

SSL * bb_SSL_new(SSL_CTX * arg_a) 
{
    SSL * ret;

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
            0, 40, 4, /* 796: struct.dtls1_retransmit_state */
            	807, 0,
            	626, 8,
            	475, 16,
            	812, 24,
            1, 8, 1, /* 807: pointer.struct.evp_cipher_ctx_st */
            	255, 0,
            1, 8, 1, /* 812: pointer.struct.ssl_session_st */
            	817, 0,
            0, 352, 14, /* 817: struct.ssl_session_st */
            	35, 144,
            	35, 152,
            	848, 168,
            	890, 176,
            	611, 224,
            	1426, 240,
            	234, 248,
            	1436, 264,
            	1436, 272,
            	35, 280,
            	417, 296,
            	417, 312,
            	417, 320,
            	35, 344,
            1, 8, 1, /* 848: pointer.struct.sess_cert_st */
            	853, 0,
            0, 248, 5, /* 853: struct.sess_cert_st */
            	866, 0,
            	876, 16,
            	1421, 216,
            	443, 224,
            	425, 232,
            1, 8, 1, /* 866: pointer.struct.stack_st_X509 */
            	871, 0,
            0, 32, 1, /* 871: struct.stack_st_X509 */
            	23, 0,
            1, 8, 1, /* 876: pointer.struct.cert_pkey_st */
            	881, 0,
            0, 24, 3, /* 881: struct.cert_pkey_st */
            	890, 0,
            	1164, 8,
            	565, 16,
            1, 8, 1, /* 890: pointer.struct.x509_st */
            	895, 0,
            0, 184, 12, /* 895: struct.x509_st */
            	922, 0,
            	957, 8,
            	1046, 16,
            	35, 32,
            	234, 40,
            	1051, 104,
            	1336, 112,
            	1360, 120,
            	1368, 128,
            	1378, 136,
            	371, 144,
            	1383, 176,
            1, 8, 1, /* 922: pointer.struct.x509_cinf_st */
            	927, 0,
            0, 104, 11, /* 927: struct.x509_cinf_st */
            	952, 0,
            	952, 8,
            	957, 16,
            	1109, 24,
            	1133, 32,
            	1109, 40,
            	1150, 48,
            	1046, 56,
            	1046, 64,
            	1326, 72,
            	791, 80,
            1, 8, 1, /* 952: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 957: pointer.struct.X509_algor_st */
            	962, 0,
            0, 16, 2, /* 962: struct.X509_algor_st */
            	969, 0,
            	983, 8,
            1, 8, 1, /* 969: pointer.struct.asn1_object_st */
            	974, 0,
            0, 40, 3, /* 974: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	689, 24,
            1, 8, 1, /* 983: pointer.struct.asn1_type_st */
            	988, 0,
            0, 16, 1, /* 988: struct.asn1_type_st */
            	993, 8,
            0, 8, 20, /* 993: union.unknown */
            	35, 0,
            	1036, 0,
            	969, 0,
            	952, 0,
            	1041, 0,
            	1046, 0,
            	1051, 0,
            	1056, 0,
            	1061, 0,
            	407, 0,
            	1066, 0,
            	1071, 0,
            	1076, 0,
            	1081, 0,
            	1086, 0,
            	1091, 0,
            	1096, 0,
            	1036, 0,
            	1036, 0,
            	1101, 0,
            1, 8, 1, /* 1036: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1041: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1046: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1051: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1056: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1061: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1066: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1071: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1076: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1081: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1086: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1091: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1096: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1101: pointer.struct.ASN1_VALUE_st */
            	1106, 0,
            0, 0, 0, /* 1106: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1109: pointer.struct.X509_name_st */
            	1114, 0,
            0, 40, 3, /* 1114: struct.X509_name_st */
            	433, 0,
            	1123, 16,
            	417, 24,
            1, 8, 1, /* 1123: pointer.struct.buf_mem_st */
            	1128, 0,
            0, 24, 1, /* 1128: struct.buf_mem_st */
            	35, 8,
            1, 8, 1, /* 1133: pointer.struct.X509_val_st */
            	1138, 0,
            0, 16, 2, /* 1138: struct.X509_val_st */
            	1145, 0,
            	1145, 8,
            1, 8, 1, /* 1145: pointer.struct.asn1_string_st */
            	412, 0,
            1, 8, 1, /* 1150: pointer.struct.X509_pubkey_st */
            	1155, 0,
            0, 24, 3, /* 1155: struct.X509_pubkey_st */
            	957, 0,
            	1046, 8,
            	1164, 16,
            1, 8, 1, /* 1164: pointer.struct.evp_pkey_st */
            	1169, 0,
            0, 56, 4, /* 1169: struct.evp_pkey_st */
            	1180, 16,
            	300, 24,
            	1188, 32,
            	1316, 48,
            1, 8, 1, /* 1180: pointer.struct.evp_pkey_asn1_method_st */
            	1185, 0,
            0, 0, 0, /* 1185: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 1188: union.unknown */
            	35, 0,
            	1201, 0,
            	713, 0,
            	1306, 0,
            	1311, 0,
            1, 8, 1, /* 1201: pointer.struct.rsa_st */
            	1206, 0,
            0, 168, 17, /* 1206: struct.rsa_st */
            	1243, 16,
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
            	1298, 152,
            	1298, 160,
            1, 8, 1, /* 1243: pointer.struct.rsa_meth_st */
            	1248, 0,
            0, 112, 13, /* 1248: struct.rsa_meth_st */
            	10, 0,
            	1277, 8,
            	1277, 16,
            	1277, 24,
            	1277, 32,
            	1280, 40,
            	1283, 48,
            	1286, 56,
            	1286, 64,
            	35, 80,
            	1289, 88,
            	1292, 96,
            	1295, 104,
            4097, 8, 0, /* 1277: pointer.func */
            4097, 8, 0, /* 1280: pointer.func */
            4097, 8, 0, /* 1283: pointer.func */
            4097, 8, 0, /* 1286: pointer.func */
            4097, 8, 0, /* 1289: pointer.func */
            4097, 8, 0, /* 1292: pointer.func */
            4097, 8, 0, /* 1295: pointer.func */
            1, 8, 1, /* 1298: pointer.struct.bn_blinding_st */
            	1303, 0,
            0, 0, 0, /* 1303: struct.bn_blinding_st */
            1, 8, 1, /* 1306: pointer.struct.dh_st */
            	448, 0,
            1, 8, 1, /* 1311: pointer.struct.ec_key_st */
            	332, 0,
            1, 8, 1, /* 1316: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1321, 0,
            0, 32, 1, /* 1321: struct.stack_st_X509_ATTRIBUTE */
            	23, 0,
            1, 8, 1, /* 1326: pointer.struct.stack_st_X509_EXTENSION */
            	1331, 0,
            0, 32, 1, /* 1331: struct.stack_st_X509_EXTENSION */
            	23, 0,
            1, 8, 1, /* 1336: pointer.struct.AUTHORITY_KEYID_st */
            	1341, 0,
            0, 24, 3, /* 1341: struct.AUTHORITY_KEYID_st */
            	1051, 0,
            	1350, 8,
            	952, 16,
            1, 8, 1, /* 1350: pointer.struct.stack_st_GENERAL_NAME */
            	1355, 0,
            0, 32, 1, /* 1355: struct.stack_st_GENERAL_NAME */
            	23, 0,
            1, 8, 1, /* 1360: pointer.struct.X509_POLICY_CACHE_st */
            	1365, 0,
            0, 0, 0, /* 1365: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1368: pointer.struct.stack_st_DIST_POINT */
            	1373, 0,
            0, 32, 1, /* 1373: struct.stack_st_DIST_POINT */
            	23, 0,
            1, 8, 1, /* 1378: pointer.struct.stack_st_GENERAL_NAME */
            	1355, 0,
            1, 8, 1, /* 1383: pointer.struct.x509_cert_aux_st */
            	1388, 0,
            0, 40, 5, /* 1388: struct.x509_cert_aux_st */
            	1401, 0,
            	1401, 8,
            	1096, 16,
            	1051, 24,
            	1411, 32,
            1, 8, 1, /* 1401: pointer.struct.stack_st_ASN1_OBJECT */
            	1406, 0,
            0, 32, 1, /* 1406: struct.stack_st_ASN1_OBJECT */
            	23, 0,
            1, 8, 1, /* 1411: pointer.struct.stack_st_X509_ALGOR */
            	1416, 0,
            0, 32, 1, /* 1416: struct.stack_st_X509_ALGOR */
            	23, 0,
            1, 8, 1, /* 1421: pointer.struct.rsa_st */
            	1206, 0,
            1, 8, 1, /* 1426: pointer.struct.stack_st_SSL_CIPHER */
            	1431, 0,
            0, 32, 1, /* 1431: struct.stack_st_SSL_CIPHER */
            	23, 0,
            1, 8, 1, /* 1436: pointer.struct.ssl_session_st */
            	817, 0,
            0, 1, 0, /* 1441: char */
            0, 232, 28, /* 1444: struct.ssl_method_st */
            	598, 8,
            	559, 16,
            	559, 24,
            	598, 32,
            	598, 40,
            	1503, 48,
            	1503, 56,
            	1506, 64,
            	598, 72,
            	598, 80,
            	598, 88,
            	1509, 96,
            	1512, 104,
            	1515, 112,
            	598, 120,
            	1518, 128,
            	1521, 136,
            	1524, 144,
            	1527, 152,
            	1530, 160,
            	1533, 168,
            	1536, 176,
            	430, 184,
            	231, 192,
            	1539, 200,
            	1533, 208,
            	1587, 216,
            	1590, 224,
            4097, 8, 0, /* 1503: pointer.func */
            4097, 8, 0, /* 1506: pointer.func */
            4097, 8, 0, /* 1509: pointer.func */
            4097, 8, 0, /* 1512: pointer.func */
            4097, 8, 0, /* 1515: pointer.func */
            4097, 8, 0, /* 1518: pointer.func */
            4097, 8, 0, /* 1521: pointer.func */
            4097, 8, 0, /* 1524: pointer.func */
            4097, 8, 0, /* 1527: pointer.func */
            4097, 8, 0, /* 1530: pointer.func */
            4097, 8, 0, /* 1533: pointer.func */
            4097, 8, 0, /* 1536: pointer.func */
            1, 8, 1, /* 1539: pointer.struct.ssl3_enc_method */
            	1544, 0,
            0, 112, 11, /* 1544: struct.ssl3_enc_method */
            	1569, 0,
            	1572, 8,
            	598, 16,
            	1575, 24,
            	1569, 32,
            	644, 40,
            	1578, 56,
            	10, 64,
            	10, 80,
            	1581, 96,
            	1584, 104,
            4097, 8, 0, /* 1569: pointer.func */
            4097, 8, 0, /* 1572: pointer.func */
            4097, 8, 0, /* 1575: pointer.func */
            4097, 8, 0, /* 1578: pointer.func */
            4097, 8, 0, /* 1581: pointer.func */
            4097, 8, 0, /* 1584: pointer.func */
            4097, 8, 0, /* 1587: pointer.func */
            4097, 8, 0, /* 1590: pointer.func */
            4097, 8, 0, /* 1593: pointer.func */
            1, 8, 1, /* 1596: pointer.struct._pqueue */
            	1601, 0,
            0, 0, 0, /* 1601: struct._pqueue */
            0, 888, 7, /* 1604: struct.dtls1_state_st */
            	1621, 576,
            	1621, 592,
            	1596, 608,
            	1596, 616,
            	1621, 624,
            	1626, 648,
            	1626, 736,
            0, 16, 1, /* 1621: struct.record_pqueue_st */
            	1596, 8,
            0, 88, 1, /* 1626: struct.hm_header_st */
            	796, 48,
            4097, 8, 0, /* 1631: pointer.func */
            4097, 8, 0, /* 1634: pointer.func */
            1, 8, 1, /* 1637: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	51, 0,
            1, 8, 1, /* 1642: pointer.struct.cert_st */
            	1647, 0,
            0, 296, 7, /* 1647: struct.cert_st */
            	876, 0,
            	1421, 48,
            	1664, 56,
            	443, 64,
            	1667, 72,
            	425, 80,
            	1670, 88,
            4097, 8, 0, /* 1664: pointer.func */
            4097, 8, 0, /* 1667: pointer.func */
            4097, 8, 0, /* 1670: pointer.func */
            4097, 8, 0, /* 1673: pointer.func */
            1, 8, 1, /* 1676: pointer.struct.stack_st_X509_EXTENSION */
            	1331, 0,
            0, 808, 51, /* 1681: struct.ssl_st */
            	1786, 8,
            	606, 16,
            	606, 24,
            	606, 32,
            	598, 48,
            	1123, 80,
            	93, 88,
            	417, 104,
            	1791, 120,
            	656, 128,
            	1817, 136,
            	1822, 152,
            	93, 160,
            	1825, 176,
            	1426, 184,
            	1426, 192,
            	807, 208,
            	626, 216,
            	475, 224,
            	807, 232,
            	626, 240,
            	475, 248,
            	1642, 256,
            	812, 304,
            	1837, 312,
            	1840, 328,
            	1843, 336,
            	1846, 352,
            	1634, 360,
            	1849, 368,
            	234, 392,
            	308, 408,
            	48, 464,
            	93, 472,
            	35, 480,
            	43, 504,
            	1676, 512,
            	417, 520,
            	417, 544,
            	417, 560,
            	93, 568,
            	2059, 584,
            	2069, 592,
            	93, 600,
            	15, 608,
            	93, 616,
            	1849, 624,
            	417, 632,
            	1637, 648,
            	0, 656,
            	62, 680,
            1, 8, 1, /* 1786: pointer.struct.ssl_method_st */
            	1444, 0,
            1, 8, 1, /* 1791: pointer.struct.ssl2_state_st */
            	1796, 0,
            0, 344, 9, /* 1796: struct.ssl2_state_st */
            	689, 24,
            	417, 56,
            	417, 64,
            	417, 72,
            	417, 104,
            	417, 112,
            	417, 120,
            	417, 128,
            	417, 136,
            1, 8, 1, /* 1817: pointer.struct.dtls1_state_st */
            	1604, 0,
            4097, 8, 0, /* 1822: pointer.func */
            1, 8, 1, /* 1825: pointer.struct.X509_VERIFY_PARAM_st */
            	1830, 0,
            0, 56, 2, /* 1830: struct.X509_VERIFY_PARAM_st */
            	35, 0,
            	1401, 48,
            4097, 8, 0, /* 1837: pointer.func */
            4097, 8, 0, /* 1840: pointer.func */
            4097, 8, 0, /* 1843: pointer.func */
            4097, 8, 0, /* 1846: pointer.func */
            1, 8, 1, /* 1849: pointer.struct.ssl_ctx_st */
            	1854, 0,
            0, 736, 50, /* 1854: struct.ssl_ctx_st */
            	1786, 0,
            	1426, 8,
            	1426, 16,
            	1957, 24,
            	163, 32,
            	1436, 48,
            	1436, 56,
            	142, 80,
            	139, 88,
            	136, 96,
            	145, 152,
            	93, 160,
            	2030, 168,
            	93, 176,
            	2033, 184,
            	2036, 192,
            	133, 200,
            	234, 208,
            	565, 224,
            	565, 232,
            	565, 240,
            	866, 248,
            	128, 256,
            	1843, 264,
            	308, 272,
            	1642, 304,
            	1822, 320,
            	93, 328,
            	1840, 376,
            	1837, 384,
            	1825, 392,
            	300, 408,
            	96, 416,
            	93, 424,
            	1593, 480,
            	99, 488,
            	93, 496,
            	120, 504,
            	93, 512,
            	35, 520,
            	1846, 528,
            	1634, 536,
            	2039, 552,
            	2039, 560,
            	62, 568,
            	1673, 696,
            	93, 704,
            	56, 712,
            	93, 720,
            	1637, 728,
            1, 8, 1, /* 1957: pointer.struct.x509_store_st */
            	1962, 0,
            0, 144, 15, /* 1962: struct.x509_store_st */
            	1995, 8,
            	2005, 16,
            	1825, 24,
            	2015, 32,
            	1840, 40,
            	2018, 48,
            	2021, 56,
            	2015, 64,
            	2024, 72,
            	2027, 80,
            	190, 88,
            	1631, 96,
            	187, 104,
            	2015, 112,
            	234, 120,
            1, 8, 1, /* 1995: pointer.struct.stack_st_X509_OBJECT */
            	2000, 0,
            0, 32, 1, /* 2000: struct.stack_st_X509_OBJECT */
            	23, 0,
            1, 8, 1, /* 2005: pointer.struct.stack_st_X509_LOOKUP */
            	2010, 0,
            0, 32, 1, /* 2010: struct.stack_st_X509_LOOKUP */
            	23, 0,
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
            	1681, 0,
        },
        .arg_entity_index = { 1849, },
        .ret_entity_index = 2072,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    SSL * *new_ret_ptr = (SSL * *)new_args->ret;

    SSL * (*orig_SSL_new)(SSL_CTX *);
    orig_SSL_new = dlsym(RTLD_NEXT, "SSL_new");
    *new_ret_ptr = (*orig_SSL_new)(new_arg_a);

    syscall(889);

    return ret;
}

