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
    printf("SSL_get_SSL_CTX called\n");
    if (!syscall(890))
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
            0, 0, 0, /* 0: func */
            1, 8, 1, /* 3: pointer.func */
            	0, 0,
            0, 16, 1, /* 8: struct.tls_session_ticket_ext_st */
            	13, 8,
            1, 8, 1, /* 13: pointer.char */
            	18, 0,
            0, 1, 0, /* 18: char */
            1, 8, 1, /* 21: pointer.func */
            	26, 0,
            0, 0, 0, /* 26: func */
            0, 12, 0, /* 29: struct.ap_unix_identity_t */
            0, 56, 2, /* 32: struct.comp_ctx_st */
            	39, 0,
            	93, 40,
            1, 8, 1, /* 39: pointer.struct.comp_method_st */
            	44, 0,
            0, 64, 7, /* 44: struct.comp_method_st */
            	13, 8,
            	61, 16,
            	69, 24,
            	77, 32,
            	77, 40,
            	85, 48,
            	85, 56,
            1, 8, 1, /* 61: pointer.func */
            	66, 0,
            0, 0, 0, /* 66: func */
            1, 8, 1, /* 69: pointer.func */
            	74, 0,
            0, 0, 0, /* 74: func */
            1, 8, 1, /* 77: pointer.func */
            	82, 0,
            0, 0, 0, /* 82: func */
            1, 8, 1, /* 85: pointer.func */
            	90, 0,
            0, 0, 0, /* 90: func */
            0, 16, 1, /* 93: struct.crypto_ex_data_st */
            	98, 0,
            1, 8, 1, /* 98: pointer.struct.stack_st_OPENSSL_STRING */
            	103, 0,
            0, 32, 1, /* 103: struct.stack_st_OPENSSL_STRING */
            	108, 0,
            0, 32, 2, /* 108: struct.stack_st */
            	115, 8,
            	120, 24,
            1, 8, 1, /* 115: pointer.pointer.char */
            	13, 0,
            1, 8, 1, /* 120: pointer.func */
            	125, 0,
            0, 0, 0, /* 125: func */
            0, 168, 4, /* 128: struct.evp_cipher_ctx_st */
            	139, 0,
            	201, 8,
            	13, 96,
            	13, 120,
            1, 8, 1, /* 139: pointer.struct.evp_cipher_st */
            	144, 0,
            0, 88, 7, /* 144: struct.evp_cipher_st */
            	161, 24,
            	169, 32,
            	177, 40,
            	185, 56,
            	185, 64,
            	193, 72,
            	13, 80,
            1, 8, 1, /* 161: pointer.func */
            	166, 0,
            0, 0, 0, /* 166: func */
            1, 8, 1, /* 169: pointer.func */
            	174, 0,
            0, 0, 0, /* 174: func */
            1, 8, 1, /* 177: pointer.func */
            	182, 0,
            0, 0, 0, /* 182: func */
            1, 8, 1, /* 185: pointer.func */
            	190, 0,
            0, 0, 0, /* 190: func */
            1, 8, 1, /* 193: pointer.func */
            	198, 0,
            0, 0, 0, /* 198: func */
            1, 8, 1, /* 201: pointer.struct.engine_st */
            	206, 0,
            0, 216, 24, /* 206: struct.engine_st */
            	13, 0,
            	13, 8,
            	257, 16,
            	347, 24,
            	433, 32,
            	489, 40,
            	511, 48,
            	553, 56,
            	613, 64,
            	621, 72,
            	629, 80,
            	637, 88,
            	645, 96,
            	653, 104,
            	653, 112,
            	653, 120,
            	661, 128,
            	669, 136,
            	669, 144,
            	677, 152,
            	685, 160,
            	93, 184,
            	201, 200,
            	201, 208,
            1, 8, 1, /* 257: pointer.struct.rsa_meth_st */
            	262, 0,
            0, 112, 13, /* 262: struct.rsa_meth_st */
            	13, 0,
            	291, 8,
            	291, 16,
            	291, 24,
            	291, 32,
            	299, 40,
            	307, 48,
            	315, 56,
            	315, 64,
            	13, 80,
            	323, 88,
            	331, 96,
            	339, 104,
            1, 8, 1, /* 291: pointer.func */
            	296, 0,
            0, 0, 0, /* 296: func */
            1, 8, 1, /* 299: pointer.func */
            	304, 0,
            0, 0, 0, /* 304: func */
            1, 8, 1, /* 307: pointer.func */
            	312, 0,
            0, 0, 0, /* 312: func */
            1, 8, 1, /* 315: pointer.func */
            	320, 0,
            0, 0, 0, /* 320: func */
            1, 8, 1, /* 323: pointer.func */
            	328, 0,
            0, 0, 0, /* 328: func */
            1, 8, 1, /* 331: pointer.func */
            	336, 0,
            0, 0, 0, /* 336: func */
            1, 8, 1, /* 339: pointer.func */
            	344, 0,
            0, 0, 0, /* 344: func */
            1, 8, 1, /* 347: pointer.struct.dsa_method.1040 */
            	352, 0,
            0, 96, 11, /* 352: struct.dsa_method.1040 */
            	13, 0,
            	377, 8,
            	385, 16,
            	393, 24,
            	401, 32,
            	409, 40,
            	417, 48,
            	417, 56,
            	13, 72,
            	425, 80,
            	417, 88,
            1, 8, 1, /* 377: pointer.func */
            	382, 0,
            0, 0, 0, /* 382: func */
            1, 8, 1, /* 385: pointer.func */
            	390, 0,
            0, 0, 0, /* 390: func */
            1, 8, 1, /* 393: pointer.func */
            	398, 0,
            0, 0, 0, /* 398: func */
            1, 8, 1, /* 401: pointer.func */
            	406, 0,
            0, 0, 0, /* 406: func */
            1, 8, 1, /* 409: pointer.func */
            	414, 0,
            0, 0, 0, /* 414: func */
            1, 8, 1, /* 417: pointer.func */
            	422, 0,
            0, 0, 0, /* 422: func */
            1, 8, 1, /* 425: pointer.func */
            	430, 0,
            0, 0, 0, /* 430: func */
            1, 8, 1, /* 433: pointer.struct.dh_method */
            	438, 0,
            0, 72, 8, /* 438: struct.dh_method */
            	13, 0,
            	457, 8,
            	465, 16,
            	473, 24,
            	457, 32,
            	457, 40,
            	13, 56,
            	481, 64,
            1, 8, 1, /* 457: pointer.func */
            	462, 0,
            0, 0, 0, /* 462: func */
            1, 8, 1, /* 465: pointer.func */
            	470, 0,
            0, 0, 0, /* 470: func */
            1, 8, 1, /* 473: pointer.func */
            	478, 0,
            0, 0, 0, /* 478: func */
            1, 8, 1, /* 481: pointer.func */
            	486, 0,
            0, 0, 0, /* 486: func */
            1, 8, 1, /* 489: pointer.struct.ecdh_method */
            	494, 0,
            0, 32, 3, /* 494: struct.ecdh_method */
            	13, 0,
            	503, 8,
            	13, 24,
            1, 8, 1, /* 503: pointer.func */
            	508, 0,
            0, 0, 0, /* 508: func */
            1, 8, 1, /* 511: pointer.struct.ecdsa_method */
            	516, 0,
            0, 48, 5, /* 516: struct.ecdsa_method */
            	13, 0,
            	529, 8,
            	537, 16,
            	545, 24,
            	13, 40,
            1, 8, 1, /* 529: pointer.func */
            	534, 0,
            0, 0, 0, /* 534: func */
            1, 8, 1, /* 537: pointer.func */
            	542, 0,
            0, 0, 0, /* 542: func */
            1, 8, 1, /* 545: pointer.func */
            	550, 0,
            0, 0, 0, /* 550: func */
            1, 8, 1, /* 553: pointer.struct.rand_meth_st */
            	558, 0,
            0, 48, 6, /* 558: struct.rand_meth_st */
            	573, 0,
            	581, 8,
            	589, 16,
            	597, 24,
            	581, 32,
            	605, 40,
            1, 8, 1, /* 573: pointer.func */
            	578, 0,
            0, 0, 0, /* 578: func */
            1, 8, 1, /* 581: pointer.func */
            	586, 0,
            0, 0, 0, /* 586: func */
            1, 8, 1, /* 589: pointer.func */
            	594, 0,
            0, 0, 0, /* 594: func */
            1, 8, 1, /* 597: pointer.func */
            	602, 0,
            0, 0, 0, /* 602: func */
            1, 8, 1, /* 605: pointer.func */
            	610, 0,
            0, 0, 0, /* 610: func */
            1, 8, 1, /* 613: pointer.struct.store_method_st */
            	618, 0,
            0, 0, 0, /* 618: struct.store_method_st */
            1, 8, 1, /* 621: pointer.func */
            	626, 0,
            0, 0, 0, /* 626: func */
            1, 8, 1, /* 629: pointer.func */
            	634, 0,
            0, 0, 0, /* 634: func */
            1, 8, 1, /* 637: pointer.func */
            	642, 0,
            0, 0, 0, /* 642: func */
            1, 8, 1, /* 645: pointer.func */
            	650, 0,
            0, 0, 0, /* 650: func */
            1, 8, 1, /* 653: pointer.func */
            	658, 0,
            0, 0, 0, /* 658: func */
            1, 8, 1, /* 661: pointer.func */
            	666, 0,
            0, 0, 0, /* 666: func */
            1, 8, 1, /* 669: pointer.func */
            	674, 0,
            0, 0, 0, /* 674: func */
            1, 8, 1, /* 677: pointer.func */
            	682, 0,
            0, 0, 0, /* 682: func */
            1, 8, 1, /* 685: pointer.struct.ENGINE_CMD_DEFN_st */
            	690, 0,
            0, 32, 2, /* 690: struct.ENGINE_CMD_DEFN_st */
            	13, 8,
            	13, 16,
            1, 8, 1, /* 697: pointer.struct.evp_cipher_ctx_st */
            	128, 0,
            0, 40, 4, /* 702: struct.dtls1_retransmit_state */
            	697, 0,
            	713, 8,
            	1178, 16,
            	1183, 24,
            1, 8, 1, /* 713: pointer.struct.env_md_ctx_st */
            	718, 0,
            0, 48, 5, /* 718: struct.env_md_ctx_st */
            	731, 0,
            	201, 8,
            	13, 24,
            	811, 32,
            	763, 40,
            1, 8, 1, /* 731: pointer.struct.env_md_st */
            	736, 0,
            0, 120, 8, /* 736: struct.env_md_st */
            	755, 24,
            	763, 32,
            	771, 40,
            	779, 48,
            	755, 56,
            	787, 64,
            	795, 72,
            	803, 112,
            1, 8, 1, /* 755: pointer.func */
            	760, 0,
            0, 0, 0, /* 760: func */
            1, 8, 1, /* 763: pointer.func */
            	768, 0,
            0, 0, 0, /* 768: func */
            1, 8, 1, /* 771: pointer.func */
            	776, 0,
            0, 0, 0, /* 776: func */
            1, 8, 1, /* 779: pointer.func */
            	784, 0,
            0, 0, 0, /* 784: func */
            1, 8, 1, /* 787: pointer.func */
            	792, 0,
            0, 0, 0, /* 792: func */
            1, 8, 1, /* 795: pointer.func */
            	800, 0,
            0, 0, 0, /* 800: func */
            1, 8, 1, /* 803: pointer.func */
            	808, 0,
            0, 0, 0, /* 808: func */
            1, 8, 1, /* 811: pointer.struct.evp_pkey_ctx_st */
            	816, 0,
            0, 80, 8, /* 816: struct.evp_pkey_ctx_st */
            	835, 0,
            	201, 8,
            	989, 16,
            	989, 24,
            	13, 40,
            	13, 48,
            	893, 56,
            	1170, 64,
            1, 8, 1, /* 835: pointer.struct.evp_pkey_method_st */
            	840, 0,
            0, 208, 25, /* 840: struct.evp_pkey_method_st */
            	893, 8,
            	901, 16,
            	909, 24,
            	893, 32,
            	917, 40,
            	893, 48,
            	917, 56,
            	893, 64,
            	925, 72,
            	893, 80,
            	933, 88,
            	893, 96,
            	925, 104,
            	941, 112,
            	949, 120,
            	941, 128,
            	957, 136,
            	893, 144,
            	925, 152,
            	893, 160,
            	925, 168,
            	893, 176,
            	965, 184,
            	973, 192,
            	981, 200,
            1, 8, 1, /* 893: pointer.struct.unnamed */
            	898, 0,
            0, 0, 0, /* 898: struct.unnamed */
            1, 8, 1, /* 901: pointer.func */
            	906, 0,
            0, 0, 0, /* 906: func */
            1, 8, 1, /* 909: pointer.func */
            	914, 0,
            0, 0, 0, /* 914: func */
            1, 8, 1, /* 917: pointer.func */
            	922, 0,
            0, 0, 0, /* 922: func */
            1, 8, 1, /* 925: pointer.func */
            	930, 0,
            0, 0, 0, /* 930: func */
            1, 8, 1, /* 933: pointer.func */
            	938, 0,
            0, 0, 0, /* 938: func */
            1, 8, 1, /* 941: pointer.func */
            	946, 0,
            0, 0, 0, /* 946: func */
            1, 8, 1, /* 949: pointer.func */
            	954, 0,
            0, 0, 0, /* 954: func */
            1, 8, 1, /* 957: pointer.func */
            	962, 0,
            0, 0, 0, /* 962: func */
            1, 8, 1, /* 965: pointer.func */
            	970, 0,
            0, 0, 0, /* 970: func */
            1, 8, 1, /* 973: pointer.func */
            	978, 0,
            0, 0, 0, /* 978: func */
            1, 8, 1, /* 981: pointer.func */
            	986, 0,
            0, 0, 0, /* 986: func */
            1, 8, 1, /* 989: pointer.struct.evp_pkey_st */
            	994, 0,
            0, 56, 4, /* 994: struct.evp_pkey_st */
            	1005, 16,
            	201, 24,
            	1165, 32,
            	98, 48,
            1, 8, 1, /* 1005: pointer.struct.evp_pkey_asn1_method_st */
            	1010, 0,
            0, 208, 24, /* 1010: struct.evp_pkey_asn1_method_st */
            	13, 16,
            	13, 24,
            	893, 32,
            	1061, 40,
            	1069, 48,
            	1077, 56,
            	1085, 64,
            	1093, 72,
            	1077, 80,
            	1101, 88,
            	1101, 96,
            	1109, 104,
            	1117, 112,
            	1101, 120,
            	1069, 128,
            	1069, 136,
            	1077, 144,
            	1125, 152,
            	1133, 160,
            	1141, 168,
            	1109, 176,
            	1117, 184,
            	1149, 192,
            	1157, 200,
            1, 8, 1, /* 1061: pointer.func */
            	1066, 0,
            0, 0, 0, /* 1066: func */
            1, 8, 1, /* 1069: pointer.func */
            	1074, 0,
            0, 0, 0, /* 1074: func */
            1, 8, 1, /* 1077: pointer.func */
            	1082, 0,
            0, 0, 0, /* 1082: func */
            1, 8, 1, /* 1085: pointer.func */
            	1090, 0,
            0, 0, 0, /* 1090: func */
            1, 8, 1, /* 1093: pointer.func */
            	1098, 0,
            0, 0, 0, /* 1098: func */
            1, 8, 1, /* 1101: pointer.func */
            	1106, 0,
            0, 0, 0, /* 1106: func */
            1, 8, 1, /* 1109: pointer.func */
            	1114, 0,
            0, 0, 0, /* 1114: func */
            1, 8, 1, /* 1117: pointer.func */
            	1122, 0,
            0, 0, 0, /* 1122: func */
            1, 8, 1, /* 1125: pointer.func */
            	1130, 0,
            0, 0, 0, /* 1130: func */
            1, 8, 1, /* 1133: pointer.func */
            	1138, 0,
            0, 0, 0, /* 1138: func */
            1, 8, 1, /* 1141: pointer.func */
            	1146, 0,
            0, 0, 0, /* 1146: func */
            1, 8, 1, /* 1149: pointer.func */
            	1154, 0,
            0, 0, 0, /* 1154: func */
            1, 8, 1, /* 1157: pointer.func */
            	1162, 0,
            0, 0, 0, /* 1162: func */
            0, 8, 1, /* 1165: struct.fnames */
            	13, 0,
            1, 8, 1, /* 1170: pointer.int */
            	1175, 0,
            0, 4, 0, /* 1175: int */
            1, 8, 1, /* 1178: pointer.struct.comp_ctx_st */
            	32, 0,
            1, 8, 1, /* 1183: pointer.struct.ssl_session_st */
            	1188, 0,
            0, 352, 14, /* 1188: struct.ssl_session_st */
            	13, 144,
            	13, 152,
            	1219, 168,
            	1253, 176,
            	1986, 224,
            	98, 240,
            	93, 248,
            	1183, 264,
            	1183, 272,
            	13, 280,
            	13, 296,
            	13, 312,
            	13, 320,
            	13, 344,
            1, 8, 1, /* 1219: pointer.struct.sess_cert_st */
            	1224, 0,
            0, 248, 6, /* 1224: struct.sess_cert_st */
            	98, 0,
            	1239, 16,
            	1486, 24,
            	1505, 216,
            	1598, 224,
            	1630, 232,
            1, 8, 1, /* 1239: pointer.struct.cert_pkey_st */
            	1244, 0,
            0, 24, 3, /* 1244: struct.cert_pkey_st */
            	1253, 0,
            	989, 8,
            	731, 16,
            1, 8, 1, /* 1253: pointer.struct.x509_st */
            	1258, 0,
            0, 184, 12, /* 1258: struct.x509_st */
            	1285, 0,
            	1325, 8,
            	1315, 16,
            	13, 32,
            	93, 40,
            	1315, 104,
            	1416, 112,
            	1430, 120,
            	98, 128,
            	98, 136,
            	1456, 144,
            	1468, 176,
            1, 8, 1, /* 1285: pointer.struct.x509_cinf_st */
            	1290, 0,
            0, 104, 11, /* 1290: struct.x509_cinf_st */
            	1315, 0,
            	1315, 8,
            	1325, 16,
            	1361, 24,
            	1385, 32,
            	1361, 40,
            	1397, 48,
            	1315, 56,
            	1315, 64,
            	98, 72,
            	1411, 80,
            1, 8, 1, /* 1315: pointer.struct.asn1_string_st */
            	1320, 0,
            0, 24, 1, /* 1320: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 1325: pointer.struct.X509_algor_st */
            	1330, 0,
            0, 16, 2, /* 1330: struct.X509_algor_st */
            	1337, 0,
            	1351, 8,
            1, 8, 1, /* 1337: pointer.struct.asn1_object_st */
            	1342, 0,
            0, 40, 3, /* 1342: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	13, 24,
            1, 8, 1, /* 1351: pointer.struct.asn1_type_st */
            	1356, 0,
            0, 16, 1, /* 1356: struct.asn1_type_st */
            	1165, 8,
            1, 8, 1, /* 1361: pointer.struct.X509_name_st */
            	1366, 0,
            0, 40, 3, /* 1366: struct.X509_name_st */
            	98, 0,
            	1375, 16,
            	13, 24,
            1, 8, 1, /* 1375: pointer.struct.buf_mem_st */
            	1380, 0,
            0, 24, 1, /* 1380: struct.buf_mem_st */
            	13, 8,
            1, 8, 1, /* 1385: pointer.struct.X509_val_st */
            	1390, 0,
            0, 16, 2, /* 1390: struct.X509_val_st */
            	1315, 0,
            	1315, 8,
            1, 8, 1, /* 1397: pointer.struct.X509_pubkey_st */
            	1402, 0,
            0, 24, 3, /* 1402: struct.X509_pubkey_st */
            	1325, 0,
            	1315, 8,
            	989, 16,
            0, 24, 1, /* 1411: struct.ASN1_ENCODING_st */
            	13, 0,
            1, 8, 1, /* 1416: pointer.struct.AUTHORITY_KEYID_st */
            	1421, 0,
            0, 24, 3, /* 1421: struct.AUTHORITY_KEYID_st */
            	1315, 0,
            	98, 8,
            	1315, 16,
            1, 8, 1, /* 1430: pointer.struct.X509_POLICY_CACHE_st */
            	1435, 0,
            0, 40, 2, /* 1435: struct.X509_POLICY_CACHE_st */
            	1442, 0,
            	98, 8,
            1, 8, 1, /* 1442: pointer.struct.X509_POLICY_DATA_st */
            	1447, 0,
            0, 32, 3, /* 1447: struct.X509_POLICY_DATA_st */
            	1337, 8,
            	98, 16,
            	98, 24,
            1, 8, 1, /* 1456: pointer.struct.NAME_CONSTRAINTS_st */
            	1461, 0,
            0, 16, 2, /* 1461: struct.NAME_CONSTRAINTS_st */
            	98, 0,
            	98, 8,
            1, 8, 1, /* 1468: pointer.struct.x509_cert_aux_st */
            	1473, 0,
            0, 40, 5, /* 1473: struct.x509_cert_aux_st */
            	98, 0,
            	98, 8,
            	1315, 16,
            	1315, 24,
            	98, 32,
            0, 192, 8, /* 1486: array[8].struct.cert_pkey_st */
            	1244, 0,
            	1244, 24,
            	1244, 48,
            	1244, 72,
            	1244, 96,
            	1244, 120,
            	1244, 144,
            	1244, 168,
            1, 8, 1, /* 1505: pointer.struct.rsa_st */
            	1510, 0,
            0, 168, 17, /* 1510: struct.rsa_st */
            	257, 16,
            	201, 24,
            	1547, 32,
            	1547, 40,
            	1547, 48,
            	1547, 56,
            	1547, 64,
            	1547, 72,
            	1547, 80,
            	1547, 88,
            	93, 96,
            	1557, 120,
            	1557, 128,
            	1557, 136,
            	13, 144,
            	1571, 152,
            	1571, 160,
            1, 8, 1, /* 1547: pointer.struct.bignum_st */
            	1552, 0,
            0, 24, 1, /* 1552: struct.bignum_st */
            	1170, 0,
            1, 8, 1, /* 1557: pointer.struct.bn_mont_ctx_st */
            	1562, 0,
            0, 96, 3, /* 1562: struct.bn_mont_ctx_st */
            	1552, 8,
            	1552, 32,
            	1552, 56,
            1, 8, 1, /* 1571: pointer.struct.bn_blinding_st */
            	1576, 0,
            0, 88, 7, /* 1576: struct.bn_blinding_st */
            	1547, 0,
            	1547, 8,
            	1547, 16,
            	1547, 24,
            	1593, 40,
            	1557, 72,
            	307, 80,
            0, 16, 1, /* 1593: struct.iovec */
            	13, 0,
            1, 8, 1, /* 1598: pointer.struct.dh_st */
            	1603, 0,
            0, 144, 12, /* 1603: struct.dh_st */
            	1547, 8,
            	1547, 16,
            	1547, 32,
            	1547, 40,
            	1557, 56,
            	1547, 64,
            	1547, 72,
            	13, 80,
            	1547, 96,
            	93, 112,
            	433, 128,
            	201, 136,
            1, 8, 1, /* 1630: pointer.struct.ec_key_st.284 */
            	1635, 0,
            0, 56, 4, /* 1635: struct.ec_key_st.284 */
            	1646, 8,
            	1928, 16,
            	1547, 24,
            	1944, 48,
            1, 8, 1, /* 1646: pointer.struct.ec_group_st */
            	1651, 0,
            0, 232, 12, /* 1651: struct.ec_group_st */
            	1678, 0,
            	1928, 8,
            	1552, 16,
            	1552, 40,
            	13, 80,
            	1944, 96,
            	1552, 104,
            	1552, 152,
            	1552, 176,
            	13, 208,
            	13, 216,
            	1978, 224,
            1, 8, 1, /* 1678: pointer.struct.ec_method_st */
            	1683, 0,
            0, 304, 37, /* 1683: struct.ec_method_st */
            	1760, 8,
            	1768, 16,
            	1768, 24,
            	1776, 32,
            	1784, 40,
            	1784, 48,
            	1760, 56,
            	1792, 64,
            	1800, 72,
            	1808, 80,
            	1808, 88,
            	1816, 96,
            	1824, 104,
            	1832, 112,
            	1832, 120,
            	1840, 128,
            	1840, 136,
            	1848, 144,
            	1856, 152,
            	1864, 160,
            	1872, 168,
            	1880, 176,
            	1888, 184,
            	1824, 192,
            	1888, 200,
            	1880, 208,
            	1888, 216,
            	1896, 224,
            	1904, 232,
            	1792, 240,
            	1760, 248,
            	1784, 256,
            	1912, 264,
            	1784, 272,
            	1912, 280,
            	1912, 288,
            	1920, 296,
            1, 8, 1, /* 1760: pointer.func */
            	1765, 0,
            0, 0, 0, /* 1765: func */
            1, 8, 1, /* 1768: pointer.func */
            	1773, 0,
            0, 0, 0, /* 1773: func */
            1, 8, 1, /* 1776: pointer.func */
            	1781, 0,
            0, 0, 0, /* 1781: func */
            1, 8, 1, /* 1784: pointer.func */
            	1789, 0,
            0, 0, 0, /* 1789: func */
            1, 8, 1, /* 1792: pointer.func */
            	1797, 0,
            0, 0, 0, /* 1797: func */
            1, 8, 1, /* 1800: pointer.func */
            	1805, 0,
            0, 0, 0, /* 1805: func */
            1, 8, 1, /* 1808: pointer.func */
            	1813, 0,
            0, 0, 0, /* 1813: func */
            1, 8, 1, /* 1816: pointer.func */
            	1821, 0,
            0, 0, 0, /* 1821: func */
            1, 8, 1, /* 1824: pointer.func */
            	1829, 0,
            0, 0, 0, /* 1829: func */
            1, 8, 1, /* 1832: pointer.func */
            	1837, 0,
            0, 0, 0, /* 1837: func */
            1, 8, 1, /* 1840: pointer.func */
            	1845, 0,
            0, 0, 0, /* 1845: func */
            1, 8, 1, /* 1848: pointer.func */
            	1853, 0,
            0, 0, 0, /* 1853: func */
            1, 8, 1, /* 1856: pointer.func */
            	1861, 0,
            0, 0, 0, /* 1861: func */
            1, 8, 1, /* 1864: pointer.func */
            	1869, 0,
            0, 0, 0, /* 1869: func */
            1, 8, 1, /* 1872: pointer.func */
            	1877, 0,
            0, 0, 0, /* 1877: func */
            1, 8, 1, /* 1880: pointer.func */
            	1885, 0,
            0, 0, 0, /* 1885: func */
            1, 8, 1, /* 1888: pointer.func */
            	1893, 0,
            0, 0, 0, /* 1893: func */
            1, 8, 1, /* 1896: pointer.func */
            	1901, 0,
            0, 0, 0, /* 1901: func */
            1, 8, 1, /* 1904: pointer.func */
            	1909, 0,
            0, 0, 0, /* 1909: func */
            1, 8, 1, /* 1912: pointer.func */
            	1917, 0,
            0, 0, 0, /* 1917: func */
            1, 8, 1, /* 1920: pointer.func */
            	1925, 0,
            0, 0, 0, /* 1925: func */
            1, 8, 1, /* 1928: pointer.struct.ec_point_st */
            	1933, 0,
            0, 88, 4, /* 1933: struct.ec_point_st */
            	1678, 0,
            	1552, 8,
            	1552, 32,
            	1552, 56,
            1, 8, 1, /* 1944: pointer.struct.ec_extra_data_st */
            	1949, 0,
            0, 40, 5, /* 1949: struct.ec_extra_data_st */
            	1944, 0,
            	13, 8,
            	1962, 16,
            	1970, 24,
            	1970, 32,
            1, 8, 1, /* 1962: pointer.func */
            	1967, 0,
            0, 0, 0, /* 1967: func */
            1, 8, 1, /* 1970: pointer.func */
            	1975, 0,
            0, 0, 0, /* 1975: func */
            1, 8, 1, /* 1978: pointer.func */
            	1983, 0,
            0, 0, 0, /* 1983: func */
            1, 8, 1, /* 1986: pointer.struct.ssl_cipher_st */
            	1991, 0,
            0, 88, 1, /* 1991: struct.ssl_cipher_st */
            	13, 8,
            0, 88, 1, /* 1996: struct.hm_header_st */
            	702, 48,
            0, 24, 2, /* 2001: struct._pitem */
            	13, 8,
            	2008, 16,
            1, 8, 1, /* 2008: pointer.struct._pitem */
            	2001, 0,
            0, 16, 1, /* 2013: struct.record_pqueue_st */
            	2018, 8,
            1, 8, 1, /* 2018: pointer.struct._pqueue */
            	2023, 0,
            0, 16, 1, /* 2023: struct._pqueue */
            	2008, 0,
            0, 16, 0, /* 2028: union.anon.142 */
            1, 8, 1, /* 2031: pointer.struct.dtls1_state_st */
            	2036, 0,
            0, 888, 7, /* 2036: struct.dtls1_state_st */
            	2013, 576,
            	2013, 592,
            	2018, 608,
            	2018, 616,
            	2013, 624,
            	1996, 648,
            	1996, 736,
            0, 24, 2, /* 2053: struct.ssl_comp_st */
            	13, 8,
            	39, 16,
            0, 9, 0, /* 2060: array[9].char */
            0, 128, 0, /* 2063: array[128].char */
            0, 4, 0, /* 2066: array[4].char */
            0, 56, 3, /* 2069: struct.ssl3_record_st */
            	13, 16,
            	13, 24,
            	13, 32,
            0, 64, 0, /* 2078: array[64].char */
            0, 1200, 10, /* 2081: struct.ssl3_state_st */
            	2104, 240,
            	2104, 264,
            	2069, 288,
            	2069, 344,
            	13, 432,
            	2109, 440,
            	2205, 448,
            	13, 496,
            	13, 512,
            	2210, 528,
            0, 24, 1, /* 2104: struct.ssl3_buffer_st */
            	13, 0,
            1, 8, 1, /* 2109: pointer.struct.bio_st */
            	2114, 0,
            0, 112, 7, /* 2114: struct.bio_st */
            	2131, 0,
            	2197, 8,
            	13, 16,
            	13, 48,
            	2109, 56,
            	2109, 64,
            	93, 96,
            1, 8, 1, /* 2131: pointer.struct.bio_method_st */
            	2136, 0,
            0, 80, 9, /* 2136: struct.bio_method_st */
            	13, 8,
            	2157, 16,
            	2157, 24,
            	2165, 32,
            	2157, 40,
            	2173, 48,
            	2181, 56,
            	2181, 64,
            	2189, 72,
            1, 8, 1, /* 2157: pointer.func */
            	2162, 0,
            0, 0, 0, /* 2162: func */
            1, 8, 1, /* 2165: pointer.func */
            	2170, 0,
            0, 0, 0, /* 2170: func */
            1, 8, 1, /* 2173: pointer.func */
            	2178, 0,
            0, 0, 0, /* 2178: func */
            1, 8, 1, /* 2181: pointer.func */
            	2186, 0,
            0, 0, 0, /* 2186: func */
            1, 8, 1, /* 2189: pointer.func */
            	2194, 0,
            0, 0, 0, /* 2194: func */
            1, 8, 1, /* 2197: pointer.func */
            	2202, 0,
            0, 0, 0, /* 2202: func */
            1, 8, 1, /* 2205: pointer.pointer.struct.env_md_ctx_st */
            	713, 0,
            0, 528, 8, /* 2210: struct.anon.0 */
            	1986, 408,
            	1598, 416,
            	1630, 424,
            	98, 464,
            	13, 480,
            	139, 488,
            	731, 496,
            	2229, 512,
            1, 8, 1, /* 2229: pointer.struct.ssl_comp_st */
            	2053, 0,
            1, 8, 1, /* 2234: pointer.struct.ssl3_state_st */
            	2081, 0,
            0, 344, 9, /* 2239: struct.ssl2_state_st */
            	13, 24,
            	13, 56,
            	13, 64,
            	13, 72,
            	13, 104,
            	13, 112,
            	13, 120,
            	13, 128,
            	13, 136,
            0, 0, 0, /* 2260: func */
            1, 8, 1, /* 2263: pointer.func */
            	2260, 0,
            0, 0, 0, /* 2268: func */
            1, 8, 1, /* 2271: pointer.func */
            	2276, 0,
            0, 0, 0, /* 2276: func */
            0, 0, 0, /* 2279: func */
            1, 8, 1, /* 2282: pointer.func */
            	2279, 0,
            0, 0, 0, /* 2287: func */
            1, 8, 1, /* 2290: pointer.func */
            	2287, 0,
            0, 0, 0, /* 2295: func */
            1, 8, 1, /* 2298: pointer.func */
            	2295, 0,
            0, 0, 0, /* 2303: func */
            1, 8, 1, /* 2306: pointer.func */
            	2303, 0,
            0, 16, 0, /* 2311: array[16].char */
            0, 0, 0, /* 2314: func */
            0, 0, 0, /* 2317: func */
            1, 8, 1, /* 2320: pointer.func */
            	2317, 0,
            0, 0, 0, /* 2325: func */
            1, 8, 1, /* 2328: pointer.func */
            	2325, 0,
            1, 8, 1, /* 2333: pointer.struct.ssl3_buf_freelist_entry_st */
            	2338, 0,
            0, 8, 1, /* 2338: struct.ssl3_buf_freelist_entry_st */
            	2333, 0,
            0, 0, 0, /* 2343: func */
            1, 8, 1, /* 2346: pointer.func */
            	2343, 0,
            0, 296, 8, /* 2351: struct.cert_st.745 */
            	1239, 0,
            	1505, 48,
            	2370, 56,
            	1598, 64,
            	2346, 72,
            	1630, 80,
            	2328, 88,
            	1486, 96,
            1, 8, 1, /* 2370: pointer.func */
            	2375, 0,
            0, 0, 0, /* 2375: func */
            1, 8, 1, /* 2378: pointer.struct.cert_st.745 */
            	2351, 0,
            0, 0, 0, /* 2383: func */
            1, 8, 1, /* 2386: pointer.func */
            	2383, 0,
            0, 0, 0, /* 2391: func */
            1, 8, 1, /* 2394: pointer.func */
            	2391, 0,
            0, 44, 0, /* 2399: struct.apr_time_exp_t */
            0, 0, 0, /* 2402: func */
            1, 8, 1, /* 2405: pointer.func */
            	2402, 0,
            0, 24, 0, /* 2410: array[6].int */
            1, 8, 1, /* 2413: pointer.struct.ssl_st.776 */
            	2418, 0,
            0, 808, 51, /* 2418: struct.ssl_st.776 */
            	2523, 8,
            	2109, 16,
            	2109, 24,
            	2109, 32,
            	2587, 48,
            	1375, 80,
            	13, 88,
            	13, 104,
            	2769, 120,
            	2234, 128,
            	2031, 136,
            	2320, 152,
            	13, 160,
            	2774, 176,
            	98, 184,
            	98, 192,
            	697, 208,
            	713, 216,
            	1178, 224,
            	697, 232,
            	713, 240,
            	1178, 248,
            	2378, 256,
            	1183, 304,
            	2786, 312,
            	2794, 328,
            	2802, 336,
            	2282, 352,
            	2713, 360,
            	2810, 368,
            	93, 392,
            	98, 408,
            	21, 464,
            	13, 472,
            	13, 480,
            	98, 504,
            	98, 512,
            	13, 520,
            	13, 544,
            	13, 560,
            	13, 568,
            	3095, 584,
            	2721, 592,
            	13, 600,
            	3, 608,
            	13, 616,
            	2810, 624,
            	13, 632,
            	98, 648,
            	3100, 656,
            	3059, 680,
            1, 8, 1, /* 2523: pointer.struct.ssl_method_st.754 */
            	2528, 0,
            0, 232, 28, /* 2528: struct.ssl_method_st.754 */
            	2587, 8,
            	2595, 16,
            	2595, 24,
            	2587, 32,
            	2587, 40,
            	2603, 48,
            	2603, 56,
            	2603, 64,
            	2587, 72,
            	2587, 80,
            	2587, 88,
            	2611, 96,
            	2619, 104,
            	2627, 112,
            	2587, 120,
            	2635, 128,
            	2643, 136,
            	2651, 144,
            	2659, 152,
            	2587, 160,
            	605, 168,
            	2667, 176,
            	2675, 184,
            	85, 192,
            	2683, 200,
            	605, 208,
            	2753, 216,
            	2761, 224,
            1, 8, 1, /* 2587: pointer.func */
            	2592, 0,
            0, 0, 0, /* 2592: func */
            1, 8, 1, /* 2595: pointer.func */
            	2600, 0,
            0, 0, 0, /* 2600: func */
            1, 8, 1, /* 2603: pointer.func */
            	2608, 0,
            0, 0, 0, /* 2608: func */
            1, 8, 1, /* 2611: pointer.func */
            	2616, 0,
            0, 0, 0, /* 2616: func */
            1, 8, 1, /* 2619: pointer.func */
            	2624, 0,
            0, 0, 0, /* 2624: func */
            1, 8, 1, /* 2627: pointer.func */
            	2632, 0,
            0, 0, 0, /* 2632: func */
            1, 8, 1, /* 2635: pointer.func */
            	2640, 0,
            0, 0, 0, /* 2640: func */
            1, 8, 1, /* 2643: pointer.func */
            	2648, 0,
            0, 0, 0, /* 2648: func */
            1, 8, 1, /* 2651: pointer.func */
            	2656, 0,
            0, 0, 0, /* 2656: func */
            1, 8, 1, /* 2659: pointer.func */
            	2664, 0,
            0, 0, 0, /* 2664: func */
            1, 8, 1, /* 2667: pointer.func */
            	2672, 0,
            0, 0, 0, /* 2672: func */
            1, 8, 1, /* 2675: pointer.func */
            	2680, 0,
            0, 0, 0, /* 2680: func */
            1, 8, 1, /* 2683: pointer.struct.ssl3_enc_method.753 */
            	2688, 0,
            0, 112, 11, /* 2688: struct.ssl3_enc_method.753 */
            	893, 0,
            	2603, 8,
            	2587, 16,
            	2713, 24,
            	893, 32,
            	2721, 40,
            	2729, 56,
            	13, 64,
            	13, 80,
            	2737, 96,
            	2745, 104,
            1, 8, 1, /* 2713: pointer.func */
            	2718, 0,
            0, 0, 0, /* 2718: func */
            1, 8, 1, /* 2721: pointer.func */
            	2726, 0,
            0, 0, 0, /* 2726: func */
            1, 8, 1, /* 2729: pointer.func */
            	2734, 0,
            0, 0, 0, /* 2734: func */
            1, 8, 1, /* 2737: pointer.func */
            	2742, 0,
            0, 0, 0, /* 2742: func */
            1, 8, 1, /* 2745: pointer.func */
            	2750, 0,
            0, 0, 0, /* 2750: func */
            1, 8, 1, /* 2753: pointer.func */
            	2758, 0,
            0, 0, 0, /* 2758: func */
            1, 8, 1, /* 2761: pointer.func */
            	2766, 0,
            0, 0, 0, /* 2766: func */
            1, 8, 1, /* 2769: pointer.struct.ssl2_state_st */
            	2239, 0,
            1, 8, 1, /* 2774: pointer.struct.X509_VERIFY_PARAM_st */
            	2779, 0,
            0, 56, 2, /* 2779: struct.X509_VERIFY_PARAM_st */
            	13, 0,
            	98, 48,
            1, 8, 1, /* 2786: pointer.func */
            	2791, 0,
            0, 0, 0, /* 2791: func */
            1, 8, 1, /* 2794: pointer.func */
            	2799, 0,
            0, 0, 0, /* 2799: func */
            1, 8, 1, /* 2802: pointer.func */
            	2807, 0,
            0, 0, 0, /* 2807: func */
            1, 8, 1, /* 2810: pointer.struct.ssl_ctx_st.752 */
            	2815, 0,
            0, 736, 50, /* 2815: struct.ssl_ctx_st.752 */
            	2523, 0,
            	98, 8,
            	98, 16,
            	2918, 24,
            	3012, 32,
            	1183, 48,
            	1183, 56,
            	2405, 80,
            	3020, 88,
            	3028, 96,
            	3036, 152,
            	13, 160,
            	2394, 168,
            	13, 176,
            	2386, 184,
            	2786, 192,
            	2603, 200,
            	93, 208,
            	731, 224,
            	731, 232,
            	731, 240,
            	98, 248,
            	98, 256,
            	2802, 264,
            	98, 272,
            	2378, 304,
            	2320, 320,
            	13, 328,
            	2794, 376,
            	2786, 384,
            	2774, 392,
            	201, 408,
            	3044, 416,
            	13, 424,
            	2306, 480,
            	2298, 488,
            	13, 496,
            	2290, 504,
            	13, 512,
            	13, 520,
            	2282, 528,
            	2713, 536,
            	3049, 552,
            	3049, 560,
            	3059, 568,
            	3090, 696,
            	13, 704,
            	2263, 712,
            	13, 720,
            	98, 728,
            1, 8, 1, /* 2918: pointer.struct.x509_store_st */
            	2923, 0,
            0, 144, 15, /* 2923: struct.x509_store_st */
            	98, 8,
            	98, 16,
            	2774, 24,
            	2956, 32,
            	2794, 40,
            	2964, 48,
            	2972, 56,
            	2956, 64,
            	2980, 72,
            	2988, 80,
            	2996, 88,
            	3004, 96,
            	3004, 104,
            	2956, 112,
            	93, 120,
            1, 8, 1, /* 2956: pointer.func */
            	2961, 0,
            0, 0, 0, /* 2961: func */
            1, 8, 1, /* 2964: pointer.func */
            	2969, 0,
            0, 0, 0, /* 2969: func */
            1, 8, 1, /* 2972: pointer.func */
            	2977, 0,
            0, 0, 0, /* 2977: func */
            1, 8, 1, /* 2980: pointer.func */
            	2985, 0,
            0, 0, 0, /* 2985: func */
            1, 8, 1, /* 2988: pointer.func */
            	2993, 0,
            0, 0, 0, /* 2993: func */
            1, 8, 1, /* 2996: pointer.func */
            	3001, 0,
            0, 0, 0, /* 3001: func */
            1, 8, 1, /* 3004: pointer.func */
            	3009, 0,
            0, 0, 0, /* 3009: func */
            1, 8, 1, /* 3012: pointer.struct.in_addr */
            	3017, 0,
            0, 4, 0, /* 3017: struct.in_addr */
            1, 8, 1, /* 3020: pointer.func */
            	3025, 0,
            0, 0, 0, /* 3025: func */
            1, 8, 1, /* 3028: pointer.func */
            	3033, 0,
            0, 0, 0, /* 3033: func */
            1, 8, 1, /* 3036: pointer.func */
            	3041, 0,
            0, 0, 0, /* 3041: func */
            1, 8, 1, /* 3044: pointer.func */
            	2314, 0,
            1, 8, 1, /* 3049: pointer.struct.ssl3_buf_freelist_st */
            	3054, 0,
            0, 24, 1, /* 3054: struct.ssl3_buf_freelist_st */
            	2333, 16,
            0, 128, 14, /* 3059: struct.srp_ctx_st.751 */
            	13, 0,
            	3044, 8,
            	2298, 16,
            	2271, 24,
            	13, 32,
            	1547, 40,
            	1547, 48,
            	1547, 56,
            	1547, 64,
            	1547, 72,
            	1547, 80,
            	1547, 88,
            	1547, 96,
            	13, 104,
            1, 8, 1, /* 3090: pointer.func */
            	2268, 0,
            1, 8, 1, /* 3095: pointer.struct.tls_session_ticket_ext_st */
            	8, 0,
            1, 8, 1, /* 3100: pointer.struct.iovec */
            	1593, 0,
            0, 8, 0, /* 3105: array[2].int */
            0, 8, 0, /* 3108: long */
            0, 12, 0, /* 3111: array[12].char */
            0, 20, 0, /* 3114: array[5].int */
            0, 16, 0, /* 3117: struct.rlimit */
            0, 2, 0, /* 3120: short */
            0, 72, 0, /* 3123: struct.anon.25 */
            0, 8, 0, /* 3126: array[8].char */
            0, 32, 0, /* 3129: array[32].char */
            0, 2, 0, /* 3132: array[2].char */
            0, 48, 0, /* 3135: array[48].char */
            0, 256, 0, /* 3138: array[256].char */
            0, 20, 0, /* 3141: array[20].char */
        },
        .arg_entity_index = { 2413, },
        .ret_entity_index = 2810,
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

