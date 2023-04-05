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
            0, 16, 1, /* 0: struct.srtp_protection_profile_st */
            	5, 0,
            1, 8, 1, /* 5: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 10: pointer.struct.stack_st_X509_EXTENSION */
            	15, 0,
            0, 32, 2, /* 15: struct.stack_st_fake_X509_EXTENSION */
            	22, 8,
            	86, 24,
            8884099, 8, 2, /* 22: pointer_to_array_of_pointers_to_stack */
            	29, 0,
            	83, 20,
            0, 8, 1, /* 29: pointer.X509_EXTENSION */
            	34, 0,
            0, 0, 1, /* 34: X509_EXTENSION */
            	39, 0,
            0, 24, 2, /* 39: struct.X509_extension_st */
            	46, 0,
            	68, 16,
            1, 8, 1, /* 46: pointer.struct.asn1_object_st */
            	51, 0,
            0, 40, 3, /* 51: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 60: pointer.unsigned char */
            	65, 0,
            0, 1, 0, /* 65: unsigned char */
            1, 8, 1, /* 68: pointer.struct.asn1_string_st */
            	73, 0,
            0, 24, 1, /* 73: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 78: pointer.unsigned char */
            	65, 0,
            0, 4, 0, /* 83: int */
            8884097, 8, 0, /* 86: pointer.func */
            0, 24, 1, /* 89: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 94: pointer.struct.asn1_string_st */
            	89, 0,
            0, 40, 3, /* 99: struct.X509_name_st */
            	108, 0,
            	168, 16,
            	78, 24,
            1, 8, 1, /* 108: pointer.struct.stack_st_X509_NAME_ENTRY */
            	113, 0,
            0, 32, 2, /* 113: struct.stack_st_fake_X509_NAME_ENTRY */
            	120, 8,
            	86, 24,
            8884099, 8, 2, /* 120: pointer_to_array_of_pointers_to_stack */
            	127, 0,
            	83, 20,
            0, 8, 1, /* 127: pointer.X509_NAME_ENTRY */
            	132, 0,
            0, 0, 1, /* 132: X509_NAME_ENTRY */
            	137, 0,
            0, 24, 2, /* 137: struct.X509_name_entry_st */
            	144, 0,
            	158, 8,
            1, 8, 1, /* 144: pointer.struct.asn1_object_st */
            	149, 0,
            0, 40, 3, /* 149: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 158: pointer.struct.asn1_string_st */
            	163, 0,
            0, 24, 1, /* 163: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 168: pointer.struct.buf_mem_st */
            	173, 0,
            0, 24, 1, /* 173: struct.buf_mem_st */
            	178, 8,
            1, 8, 1, /* 178: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 183: pointer.struct.X509_name_st */
            	99, 0,
            0, 16, 1, /* 188: struct.ocsp_responder_id_st */
            	193, 8,
            0, 8, 2, /* 193: union.unknown */
            	183, 0,
            	94, 0,
            1, 8, 1, /* 200: pointer.struct.stack_st_OCSP_RESPID */
            	205, 0,
            0, 32, 2, /* 205: struct.stack_st_fake_OCSP_RESPID */
            	212, 8,
            	86, 24,
            8884099, 8, 2, /* 212: pointer_to_array_of_pointers_to_stack */
            	219, 0,
            	83, 20,
            0, 8, 1, /* 219: pointer.OCSP_RESPID */
            	224, 0,
            0, 0, 1, /* 224: OCSP_RESPID */
            	188, 0,
            1, 8, 1, /* 229: pointer.struct.ssl_session_st */
            	234, 0,
            0, 352, 14, /* 234: struct.ssl_session_st */
            	178, 144,
            	178, 152,
            	265, 168,
            	2090, 176,
            	3079, 224,
            	3089, 240,
            	2550, 248,
            	3123, 264,
            	3123, 272,
            	178, 280,
            	78, 296,
            	78, 312,
            	78, 320,
            	178, 344,
            1, 8, 1, /* 265: pointer.struct.sess_cert_st */
            	270, 0,
            0, 248, 5, /* 270: struct.sess_cert_st */
            	283, 0,
            	2076, 16,
            	3064, 216,
            	3069, 224,
            	3074, 232,
            1, 8, 1, /* 283: pointer.struct.stack_st_X509 */
            	288, 0,
            0, 32, 2, /* 288: struct.stack_st_fake_X509 */
            	295, 8,
            	86, 24,
            8884099, 8, 2, /* 295: pointer_to_array_of_pointers_to_stack */
            	302, 0,
            	83, 20,
            0, 8, 1, /* 302: pointer.X509 */
            	307, 0,
            0, 0, 1, /* 307: X509 */
            	312, 0,
            0, 184, 12, /* 312: struct.x509_st */
            	339, 0,
            	379, 8,
            	468, 16,
            	178, 32,
            	775, 40,
            	473, 104,
            	1389, 112,
            	1397, 120,
            	1405, 128,
            	1814, 136,
            	1838, 144,
            	1846, 176,
            1, 8, 1, /* 339: pointer.struct.x509_cinf_st */
            	344, 0,
            0, 104, 11, /* 344: struct.x509_cinf_st */
            	369, 0,
            	369, 8,
            	379, 16,
            	536, 24,
            	584, 32,
            	536, 40,
            	601, 48,
            	468, 56,
            	468, 64,
            	1360, 72,
            	1384, 80,
            1, 8, 1, /* 369: pointer.struct.asn1_string_st */
            	374, 0,
            0, 24, 1, /* 374: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 379: pointer.struct.X509_algor_st */
            	384, 0,
            0, 16, 2, /* 384: struct.X509_algor_st */
            	391, 0,
            	405, 8,
            1, 8, 1, /* 391: pointer.struct.asn1_object_st */
            	396, 0,
            0, 40, 3, /* 396: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 405: pointer.struct.asn1_type_st */
            	410, 0,
            0, 16, 1, /* 410: struct.asn1_type_st */
            	415, 8,
            0, 8, 20, /* 415: union.unknown */
            	178, 0,
            	458, 0,
            	391, 0,
            	369, 0,
            	463, 0,
            	468, 0,
            	473, 0,
            	478, 0,
            	483, 0,
            	488, 0,
            	493, 0,
            	498, 0,
            	503, 0,
            	508, 0,
            	513, 0,
            	518, 0,
            	523, 0,
            	458, 0,
            	458, 0,
            	528, 0,
            1, 8, 1, /* 458: pointer.struct.asn1_string_st */
            	374, 0,
            1, 8, 1, /* 463: pointer.struct.asn1_string_st */
            	374, 0,
            1, 8, 1, /* 468: pointer.struct.asn1_string_st */
            	374, 0,
            1, 8, 1, /* 473: pointer.struct.asn1_string_st */
            	374, 0,
            1, 8, 1, /* 478: pointer.struct.asn1_string_st */
            	374, 0,
            1, 8, 1, /* 483: pointer.struct.asn1_string_st */
            	374, 0,
            1, 8, 1, /* 488: pointer.struct.asn1_string_st */
            	374, 0,
            1, 8, 1, /* 493: pointer.struct.asn1_string_st */
            	374, 0,
            1, 8, 1, /* 498: pointer.struct.asn1_string_st */
            	374, 0,
            1, 8, 1, /* 503: pointer.struct.asn1_string_st */
            	374, 0,
            1, 8, 1, /* 508: pointer.struct.asn1_string_st */
            	374, 0,
            1, 8, 1, /* 513: pointer.struct.asn1_string_st */
            	374, 0,
            1, 8, 1, /* 518: pointer.struct.asn1_string_st */
            	374, 0,
            1, 8, 1, /* 523: pointer.struct.asn1_string_st */
            	374, 0,
            1, 8, 1, /* 528: pointer.struct.ASN1_VALUE_st */
            	533, 0,
            0, 0, 0, /* 533: struct.ASN1_VALUE_st */
            1, 8, 1, /* 536: pointer.struct.X509_name_st */
            	541, 0,
            0, 40, 3, /* 541: struct.X509_name_st */
            	550, 0,
            	574, 16,
            	78, 24,
            1, 8, 1, /* 550: pointer.struct.stack_st_X509_NAME_ENTRY */
            	555, 0,
            0, 32, 2, /* 555: struct.stack_st_fake_X509_NAME_ENTRY */
            	562, 8,
            	86, 24,
            8884099, 8, 2, /* 562: pointer_to_array_of_pointers_to_stack */
            	569, 0,
            	83, 20,
            0, 8, 1, /* 569: pointer.X509_NAME_ENTRY */
            	132, 0,
            1, 8, 1, /* 574: pointer.struct.buf_mem_st */
            	579, 0,
            0, 24, 1, /* 579: struct.buf_mem_st */
            	178, 8,
            1, 8, 1, /* 584: pointer.struct.X509_val_st */
            	589, 0,
            0, 16, 2, /* 589: struct.X509_val_st */
            	596, 0,
            	596, 8,
            1, 8, 1, /* 596: pointer.struct.asn1_string_st */
            	374, 0,
            1, 8, 1, /* 601: pointer.struct.X509_pubkey_st */
            	606, 0,
            0, 24, 3, /* 606: struct.X509_pubkey_st */
            	379, 0,
            	468, 8,
            	615, 16,
            1, 8, 1, /* 615: pointer.struct.evp_pkey_st */
            	620, 0,
            0, 56, 4, /* 620: struct.evp_pkey_st */
            	631, 16,
            	639, 24,
            	647, 32,
            	981, 48,
            1, 8, 1, /* 631: pointer.struct.evp_pkey_asn1_method_st */
            	636, 0,
            0, 0, 0, /* 636: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 639: pointer.struct.engine_st */
            	644, 0,
            0, 0, 0, /* 644: struct.engine_st */
            0, 8, 5, /* 647: union.unknown */
            	178, 0,
            	660, 0,
            	824, 0,
            	905, 0,
            	973, 0,
            1, 8, 1, /* 660: pointer.struct.rsa_st */
            	665, 0,
            0, 168, 17, /* 665: struct.rsa_st */
            	702, 16,
            	639, 24,
            	757, 32,
            	757, 40,
            	757, 48,
            	757, 56,
            	757, 64,
            	757, 72,
            	757, 80,
            	757, 88,
            	775, 96,
            	802, 120,
            	802, 128,
            	802, 136,
            	178, 144,
            	816, 152,
            	816, 160,
            1, 8, 1, /* 702: pointer.struct.rsa_meth_st */
            	707, 0,
            0, 112, 13, /* 707: struct.rsa_meth_st */
            	5, 0,
            	736, 8,
            	736, 16,
            	736, 24,
            	736, 32,
            	739, 40,
            	742, 48,
            	745, 56,
            	745, 64,
            	178, 80,
            	748, 88,
            	751, 96,
            	754, 104,
            8884097, 8, 0, /* 736: pointer.func */
            8884097, 8, 0, /* 739: pointer.func */
            8884097, 8, 0, /* 742: pointer.func */
            8884097, 8, 0, /* 745: pointer.func */
            8884097, 8, 0, /* 748: pointer.func */
            8884097, 8, 0, /* 751: pointer.func */
            8884097, 8, 0, /* 754: pointer.func */
            1, 8, 1, /* 757: pointer.struct.bignum_st */
            	762, 0,
            0, 24, 1, /* 762: struct.bignum_st */
            	767, 0,
            1, 8, 1, /* 767: pointer.unsigned int */
            	772, 0,
            0, 4, 0, /* 772: unsigned int */
            0, 16, 1, /* 775: struct.crypto_ex_data_st */
            	780, 0,
            1, 8, 1, /* 780: pointer.struct.stack_st_void */
            	785, 0,
            0, 32, 1, /* 785: struct.stack_st_void */
            	790, 0,
            0, 32, 2, /* 790: struct.stack_st */
            	797, 8,
            	86, 24,
            1, 8, 1, /* 797: pointer.pointer.char */
            	178, 0,
            1, 8, 1, /* 802: pointer.struct.bn_mont_ctx_st */
            	807, 0,
            0, 96, 3, /* 807: struct.bn_mont_ctx_st */
            	762, 8,
            	762, 32,
            	762, 56,
            1, 8, 1, /* 816: pointer.struct.bn_blinding_st */
            	821, 0,
            0, 0, 0, /* 821: struct.bn_blinding_st */
            1, 8, 1, /* 824: pointer.struct.dsa_st */
            	829, 0,
            0, 136, 11, /* 829: struct.dsa_st */
            	757, 24,
            	757, 32,
            	757, 40,
            	757, 48,
            	757, 56,
            	757, 64,
            	757, 72,
            	802, 88,
            	775, 104,
            	854, 120,
            	639, 128,
            1, 8, 1, /* 854: pointer.struct.dsa_method */
            	859, 0,
            0, 96, 11, /* 859: struct.dsa_method */
            	5, 0,
            	884, 8,
            	887, 16,
            	890, 24,
            	893, 32,
            	896, 40,
            	899, 48,
            	899, 56,
            	178, 72,
            	902, 80,
            	899, 88,
            8884097, 8, 0, /* 884: pointer.func */
            8884097, 8, 0, /* 887: pointer.func */
            8884097, 8, 0, /* 890: pointer.func */
            8884097, 8, 0, /* 893: pointer.func */
            8884097, 8, 0, /* 896: pointer.func */
            8884097, 8, 0, /* 899: pointer.func */
            8884097, 8, 0, /* 902: pointer.func */
            1, 8, 1, /* 905: pointer.struct.dh_st */
            	910, 0,
            0, 144, 12, /* 910: struct.dh_st */
            	757, 8,
            	757, 16,
            	757, 32,
            	757, 40,
            	802, 56,
            	757, 64,
            	757, 72,
            	78, 80,
            	757, 96,
            	775, 112,
            	937, 128,
            	639, 136,
            1, 8, 1, /* 937: pointer.struct.dh_method */
            	942, 0,
            0, 72, 8, /* 942: struct.dh_method */
            	5, 0,
            	961, 8,
            	964, 16,
            	967, 24,
            	961, 32,
            	961, 40,
            	178, 56,
            	970, 64,
            8884097, 8, 0, /* 961: pointer.func */
            8884097, 8, 0, /* 964: pointer.func */
            8884097, 8, 0, /* 967: pointer.func */
            8884097, 8, 0, /* 970: pointer.func */
            1, 8, 1, /* 973: pointer.struct.ec_key_st */
            	978, 0,
            0, 0, 0, /* 978: struct.ec_key_st */
            1, 8, 1, /* 981: pointer.struct.stack_st_X509_ATTRIBUTE */
            	986, 0,
            0, 32, 2, /* 986: struct.stack_st_fake_X509_ATTRIBUTE */
            	993, 8,
            	86, 24,
            8884099, 8, 2, /* 993: pointer_to_array_of_pointers_to_stack */
            	1000, 0,
            	83, 20,
            0, 8, 1, /* 1000: pointer.X509_ATTRIBUTE */
            	1005, 0,
            0, 0, 1, /* 1005: X509_ATTRIBUTE */
            	1010, 0,
            0, 24, 2, /* 1010: struct.x509_attributes_st */
            	1017, 0,
            	1031, 16,
            1, 8, 1, /* 1017: pointer.struct.asn1_object_st */
            	1022, 0,
            0, 40, 3, /* 1022: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            0, 8, 3, /* 1031: union.unknown */
            	178, 0,
            	1040, 0,
            	1219, 0,
            1, 8, 1, /* 1040: pointer.struct.stack_st_ASN1_TYPE */
            	1045, 0,
            0, 32, 2, /* 1045: struct.stack_st_fake_ASN1_TYPE */
            	1052, 8,
            	86, 24,
            8884099, 8, 2, /* 1052: pointer_to_array_of_pointers_to_stack */
            	1059, 0,
            	83, 20,
            0, 8, 1, /* 1059: pointer.ASN1_TYPE */
            	1064, 0,
            0, 0, 1, /* 1064: ASN1_TYPE */
            	1069, 0,
            0, 16, 1, /* 1069: struct.asn1_type_st */
            	1074, 8,
            0, 8, 20, /* 1074: union.unknown */
            	178, 0,
            	1117, 0,
            	1127, 0,
            	1141, 0,
            	1146, 0,
            	1151, 0,
            	1156, 0,
            	1161, 0,
            	1166, 0,
            	1171, 0,
            	1176, 0,
            	1181, 0,
            	1186, 0,
            	1191, 0,
            	1196, 0,
            	1201, 0,
            	1206, 0,
            	1117, 0,
            	1117, 0,
            	1211, 0,
            1, 8, 1, /* 1117: pointer.struct.asn1_string_st */
            	1122, 0,
            0, 24, 1, /* 1122: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 1127: pointer.struct.asn1_object_st */
            	1132, 0,
            0, 40, 3, /* 1132: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 1141: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1146: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1151: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1156: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1161: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1166: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1171: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1176: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1181: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1186: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1191: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1196: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1201: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1206: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1211: pointer.struct.ASN1_VALUE_st */
            	1216, 0,
            0, 0, 0, /* 1216: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1219: pointer.struct.asn1_type_st */
            	1224, 0,
            0, 16, 1, /* 1224: struct.asn1_type_st */
            	1229, 8,
            0, 8, 20, /* 1229: union.unknown */
            	178, 0,
            	1272, 0,
            	1017, 0,
            	1282, 0,
            	1287, 0,
            	1292, 0,
            	1297, 0,
            	1302, 0,
            	1307, 0,
            	1312, 0,
            	1317, 0,
            	1322, 0,
            	1327, 0,
            	1332, 0,
            	1337, 0,
            	1342, 0,
            	1347, 0,
            	1272, 0,
            	1272, 0,
            	1352, 0,
            1, 8, 1, /* 1272: pointer.struct.asn1_string_st */
            	1277, 0,
            0, 24, 1, /* 1277: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 1282: pointer.struct.asn1_string_st */
            	1277, 0,
            1, 8, 1, /* 1287: pointer.struct.asn1_string_st */
            	1277, 0,
            1, 8, 1, /* 1292: pointer.struct.asn1_string_st */
            	1277, 0,
            1, 8, 1, /* 1297: pointer.struct.asn1_string_st */
            	1277, 0,
            1, 8, 1, /* 1302: pointer.struct.asn1_string_st */
            	1277, 0,
            1, 8, 1, /* 1307: pointer.struct.asn1_string_st */
            	1277, 0,
            1, 8, 1, /* 1312: pointer.struct.asn1_string_st */
            	1277, 0,
            1, 8, 1, /* 1317: pointer.struct.asn1_string_st */
            	1277, 0,
            1, 8, 1, /* 1322: pointer.struct.asn1_string_st */
            	1277, 0,
            1, 8, 1, /* 1327: pointer.struct.asn1_string_st */
            	1277, 0,
            1, 8, 1, /* 1332: pointer.struct.asn1_string_st */
            	1277, 0,
            1, 8, 1, /* 1337: pointer.struct.asn1_string_st */
            	1277, 0,
            1, 8, 1, /* 1342: pointer.struct.asn1_string_st */
            	1277, 0,
            1, 8, 1, /* 1347: pointer.struct.asn1_string_st */
            	1277, 0,
            1, 8, 1, /* 1352: pointer.struct.ASN1_VALUE_st */
            	1357, 0,
            0, 0, 0, /* 1357: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1360: pointer.struct.stack_st_X509_EXTENSION */
            	1365, 0,
            0, 32, 2, /* 1365: struct.stack_st_fake_X509_EXTENSION */
            	1372, 8,
            	86, 24,
            8884099, 8, 2, /* 1372: pointer_to_array_of_pointers_to_stack */
            	1379, 0,
            	83, 20,
            0, 8, 1, /* 1379: pointer.X509_EXTENSION */
            	34, 0,
            0, 24, 1, /* 1384: struct.ASN1_ENCODING_st */
            	78, 0,
            1, 8, 1, /* 1389: pointer.struct.AUTHORITY_KEYID_st */
            	1394, 0,
            0, 0, 0, /* 1394: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 1397: pointer.struct.X509_POLICY_CACHE_st */
            	1402, 0,
            0, 0, 0, /* 1402: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1405: pointer.struct.stack_st_DIST_POINT */
            	1410, 0,
            0, 32, 2, /* 1410: struct.stack_st_fake_DIST_POINT */
            	1417, 8,
            	86, 24,
            8884099, 8, 2, /* 1417: pointer_to_array_of_pointers_to_stack */
            	1424, 0,
            	83, 20,
            0, 8, 1, /* 1424: pointer.DIST_POINT */
            	1429, 0,
            0, 0, 1, /* 1429: DIST_POINT */
            	1434, 0,
            0, 32, 3, /* 1434: struct.DIST_POINT_st */
            	1443, 0,
            	1804, 8,
            	1462, 16,
            1, 8, 1, /* 1443: pointer.struct.DIST_POINT_NAME_st */
            	1448, 0,
            0, 24, 2, /* 1448: struct.DIST_POINT_NAME_st */
            	1455, 8,
            	1780, 16,
            0, 8, 2, /* 1455: union.unknown */
            	1462, 0,
            	1756, 0,
            1, 8, 1, /* 1462: pointer.struct.stack_st_GENERAL_NAME */
            	1467, 0,
            0, 32, 2, /* 1467: struct.stack_st_fake_GENERAL_NAME */
            	1474, 8,
            	86, 24,
            8884099, 8, 2, /* 1474: pointer_to_array_of_pointers_to_stack */
            	1481, 0,
            	83, 20,
            0, 8, 1, /* 1481: pointer.GENERAL_NAME */
            	1486, 0,
            0, 0, 1, /* 1486: GENERAL_NAME */
            	1491, 0,
            0, 16, 1, /* 1491: struct.GENERAL_NAME_st */
            	1496, 8,
            0, 8, 15, /* 1496: union.unknown */
            	178, 0,
            	1529, 0,
            	1648, 0,
            	1648, 0,
            	1555, 0,
            	1696, 0,
            	1744, 0,
            	1648, 0,
            	1633, 0,
            	1541, 0,
            	1633, 0,
            	1696, 0,
            	1648, 0,
            	1541, 0,
            	1555, 0,
            1, 8, 1, /* 1529: pointer.struct.otherName_st */
            	1534, 0,
            0, 16, 2, /* 1534: struct.otherName_st */
            	1541, 0,
            	1555, 8,
            1, 8, 1, /* 1541: pointer.struct.asn1_object_st */
            	1546, 0,
            0, 40, 3, /* 1546: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 1555: pointer.struct.asn1_type_st */
            	1560, 0,
            0, 16, 1, /* 1560: struct.asn1_type_st */
            	1565, 8,
            0, 8, 20, /* 1565: union.unknown */
            	178, 0,
            	1608, 0,
            	1541, 0,
            	1618, 0,
            	1623, 0,
            	1628, 0,
            	1633, 0,
            	1638, 0,
            	1643, 0,
            	1648, 0,
            	1653, 0,
            	1658, 0,
            	1663, 0,
            	1668, 0,
            	1673, 0,
            	1678, 0,
            	1683, 0,
            	1608, 0,
            	1608, 0,
            	1688, 0,
            1, 8, 1, /* 1608: pointer.struct.asn1_string_st */
            	1613, 0,
            0, 24, 1, /* 1613: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 1618: pointer.struct.asn1_string_st */
            	1613, 0,
            1, 8, 1, /* 1623: pointer.struct.asn1_string_st */
            	1613, 0,
            1, 8, 1, /* 1628: pointer.struct.asn1_string_st */
            	1613, 0,
            1, 8, 1, /* 1633: pointer.struct.asn1_string_st */
            	1613, 0,
            1, 8, 1, /* 1638: pointer.struct.asn1_string_st */
            	1613, 0,
            1, 8, 1, /* 1643: pointer.struct.asn1_string_st */
            	1613, 0,
            1, 8, 1, /* 1648: pointer.struct.asn1_string_st */
            	1613, 0,
            1, 8, 1, /* 1653: pointer.struct.asn1_string_st */
            	1613, 0,
            1, 8, 1, /* 1658: pointer.struct.asn1_string_st */
            	1613, 0,
            1, 8, 1, /* 1663: pointer.struct.asn1_string_st */
            	1613, 0,
            1, 8, 1, /* 1668: pointer.struct.asn1_string_st */
            	1613, 0,
            1, 8, 1, /* 1673: pointer.struct.asn1_string_st */
            	1613, 0,
            1, 8, 1, /* 1678: pointer.struct.asn1_string_st */
            	1613, 0,
            1, 8, 1, /* 1683: pointer.struct.asn1_string_st */
            	1613, 0,
            1, 8, 1, /* 1688: pointer.struct.ASN1_VALUE_st */
            	1693, 0,
            0, 0, 0, /* 1693: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1696: pointer.struct.X509_name_st */
            	1701, 0,
            0, 40, 3, /* 1701: struct.X509_name_st */
            	1710, 0,
            	1734, 16,
            	78, 24,
            1, 8, 1, /* 1710: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1715, 0,
            0, 32, 2, /* 1715: struct.stack_st_fake_X509_NAME_ENTRY */
            	1722, 8,
            	86, 24,
            8884099, 8, 2, /* 1722: pointer_to_array_of_pointers_to_stack */
            	1729, 0,
            	83, 20,
            0, 8, 1, /* 1729: pointer.X509_NAME_ENTRY */
            	132, 0,
            1, 8, 1, /* 1734: pointer.struct.buf_mem_st */
            	1739, 0,
            0, 24, 1, /* 1739: struct.buf_mem_st */
            	178, 8,
            1, 8, 1, /* 1744: pointer.struct.EDIPartyName_st */
            	1749, 0,
            0, 16, 2, /* 1749: struct.EDIPartyName_st */
            	1608, 0,
            	1608, 8,
            1, 8, 1, /* 1756: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1761, 0,
            0, 32, 2, /* 1761: struct.stack_st_fake_X509_NAME_ENTRY */
            	1768, 8,
            	86, 24,
            8884099, 8, 2, /* 1768: pointer_to_array_of_pointers_to_stack */
            	1775, 0,
            	83, 20,
            0, 8, 1, /* 1775: pointer.X509_NAME_ENTRY */
            	132, 0,
            1, 8, 1, /* 1780: pointer.struct.X509_name_st */
            	1785, 0,
            0, 40, 3, /* 1785: struct.X509_name_st */
            	1756, 0,
            	1794, 16,
            	78, 24,
            1, 8, 1, /* 1794: pointer.struct.buf_mem_st */
            	1799, 0,
            0, 24, 1, /* 1799: struct.buf_mem_st */
            	178, 8,
            1, 8, 1, /* 1804: pointer.struct.asn1_string_st */
            	1809, 0,
            0, 24, 1, /* 1809: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 1814: pointer.struct.stack_st_GENERAL_NAME */
            	1819, 0,
            0, 32, 2, /* 1819: struct.stack_st_fake_GENERAL_NAME */
            	1826, 8,
            	86, 24,
            8884099, 8, 2, /* 1826: pointer_to_array_of_pointers_to_stack */
            	1833, 0,
            	83, 20,
            0, 8, 1, /* 1833: pointer.GENERAL_NAME */
            	1486, 0,
            1, 8, 1, /* 1838: pointer.struct.NAME_CONSTRAINTS_st */
            	1843, 0,
            0, 0, 0, /* 1843: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 1846: pointer.struct.x509_cert_aux_st */
            	1851, 0,
            0, 40, 5, /* 1851: struct.x509_cert_aux_st */
            	1864, 0,
            	1864, 8,
            	523, 16,
            	473, 24,
            	1893, 32,
            1, 8, 1, /* 1864: pointer.struct.stack_st_ASN1_OBJECT */
            	1869, 0,
            0, 32, 2, /* 1869: struct.stack_st_fake_ASN1_OBJECT */
            	1876, 8,
            	86, 24,
            8884099, 8, 2, /* 1876: pointer_to_array_of_pointers_to_stack */
            	1883, 0,
            	83, 20,
            0, 8, 1, /* 1883: pointer.ASN1_OBJECT */
            	1888, 0,
            0, 0, 1, /* 1888: ASN1_OBJECT */
            	1132, 0,
            1, 8, 1, /* 1893: pointer.struct.stack_st_X509_ALGOR */
            	1898, 0,
            0, 32, 2, /* 1898: struct.stack_st_fake_X509_ALGOR */
            	1905, 8,
            	86, 24,
            8884099, 8, 2, /* 1905: pointer_to_array_of_pointers_to_stack */
            	1912, 0,
            	83, 20,
            0, 8, 1, /* 1912: pointer.X509_ALGOR */
            	1917, 0,
            0, 0, 1, /* 1917: X509_ALGOR */
            	1922, 0,
            0, 16, 2, /* 1922: struct.X509_algor_st */
            	1929, 0,
            	1943, 8,
            1, 8, 1, /* 1929: pointer.struct.asn1_object_st */
            	1934, 0,
            0, 40, 3, /* 1934: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 1943: pointer.struct.asn1_type_st */
            	1948, 0,
            0, 16, 1, /* 1948: struct.asn1_type_st */
            	1953, 8,
            0, 8, 20, /* 1953: union.unknown */
            	178, 0,
            	1996, 0,
            	1929, 0,
            	2006, 0,
            	2011, 0,
            	2016, 0,
            	2021, 0,
            	2026, 0,
            	2031, 0,
            	2036, 0,
            	2041, 0,
            	2046, 0,
            	2051, 0,
            	2056, 0,
            	2061, 0,
            	2066, 0,
            	2071, 0,
            	1996, 0,
            	1996, 0,
            	1352, 0,
            1, 8, 1, /* 1996: pointer.struct.asn1_string_st */
            	2001, 0,
            0, 24, 1, /* 2001: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 2006: pointer.struct.asn1_string_st */
            	2001, 0,
            1, 8, 1, /* 2011: pointer.struct.asn1_string_st */
            	2001, 0,
            1, 8, 1, /* 2016: pointer.struct.asn1_string_st */
            	2001, 0,
            1, 8, 1, /* 2021: pointer.struct.asn1_string_st */
            	2001, 0,
            1, 8, 1, /* 2026: pointer.struct.asn1_string_st */
            	2001, 0,
            1, 8, 1, /* 2031: pointer.struct.asn1_string_st */
            	2001, 0,
            1, 8, 1, /* 2036: pointer.struct.asn1_string_st */
            	2001, 0,
            1, 8, 1, /* 2041: pointer.struct.asn1_string_st */
            	2001, 0,
            1, 8, 1, /* 2046: pointer.struct.asn1_string_st */
            	2001, 0,
            1, 8, 1, /* 2051: pointer.struct.asn1_string_st */
            	2001, 0,
            1, 8, 1, /* 2056: pointer.struct.asn1_string_st */
            	2001, 0,
            1, 8, 1, /* 2061: pointer.struct.asn1_string_st */
            	2001, 0,
            1, 8, 1, /* 2066: pointer.struct.asn1_string_st */
            	2001, 0,
            1, 8, 1, /* 2071: pointer.struct.asn1_string_st */
            	2001, 0,
            1, 8, 1, /* 2076: pointer.struct.cert_pkey_st */
            	2081, 0,
            0, 24, 3, /* 2081: struct.cert_pkey_st */
            	2090, 0,
            	2398, 8,
            	3019, 16,
            1, 8, 1, /* 2090: pointer.struct.x509_st */
            	2095, 0,
            0, 184, 12, /* 2095: struct.x509_st */
            	2122, 0,
            	2162, 8,
            	2251, 16,
            	178, 32,
            	2550, 40,
            	2256, 104,
            	2804, 112,
            	2842, 120,
            	2850, 128,
            	2874, 136,
            	2898, 144,
            	2953, 176,
            1, 8, 1, /* 2122: pointer.struct.x509_cinf_st */
            	2127, 0,
            0, 104, 11, /* 2127: struct.x509_cinf_st */
            	2152, 0,
            	2152, 8,
            	2162, 16,
            	2319, 24,
            	2367, 32,
            	2319, 40,
            	2384, 48,
            	2251, 56,
            	2251, 64,
            	2775, 72,
            	2799, 80,
            1, 8, 1, /* 2152: pointer.struct.asn1_string_st */
            	2157, 0,
            0, 24, 1, /* 2157: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 2162: pointer.struct.X509_algor_st */
            	2167, 0,
            0, 16, 2, /* 2167: struct.X509_algor_st */
            	2174, 0,
            	2188, 8,
            1, 8, 1, /* 2174: pointer.struct.asn1_object_st */
            	2179, 0,
            0, 40, 3, /* 2179: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 2188: pointer.struct.asn1_type_st */
            	2193, 0,
            0, 16, 1, /* 2193: struct.asn1_type_st */
            	2198, 8,
            0, 8, 20, /* 2198: union.unknown */
            	178, 0,
            	2241, 0,
            	2174, 0,
            	2152, 0,
            	2246, 0,
            	2251, 0,
            	2256, 0,
            	2261, 0,
            	2266, 0,
            	2271, 0,
            	2276, 0,
            	2281, 0,
            	2286, 0,
            	2291, 0,
            	2296, 0,
            	2301, 0,
            	2306, 0,
            	2241, 0,
            	2241, 0,
            	2311, 0,
            1, 8, 1, /* 2241: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2246: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2251: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2256: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2261: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2266: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2271: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2276: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2281: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2286: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2291: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2296: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2301: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2306: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2311: pointer.struct.ASN1_VALUE_st */
            	2316, 0,
            0, 0, 0, /* 2316: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2319: pointer.struct.X509_name_st */
            	2324, 0,
            0, 40, 3, /* 2324: struct.X509_name_st */
            	2333, 0,
            	2357, 16,
            	78, 24,
            1, 8, 1, /* 2333: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2338, 0,
            0, 32, 2, /* 2338: struct.stack_st_fake_X509_NAME_ENTRY */
            	2345, 8,
            	86, 24,
            8884099, 8, 2, /* 2345: pointer_to_array_of_pointers_to_stack */
            	2352, 0,
            	83, 20,
            0, 8, 1, /* 2352: pointer.X509_NAME_ENTRY */
            	132, 0,
            1, 8, 1, /* 2357: pointer.struct.buf_mem_st */
            	2362, 0,
            0, 24, 1, /* 2362: struct.buf_mem_st */
            	178, 8,
            1, 8, 1, /* 2367: pointer.struct.X509_val_st */
            	2372, 0,
            0, 16, 2, /* 2372: struct.X509_val_st */
            	2379, 0,
            	2379, 8,
            1, 8, 1, /* 2379: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2384: pointer.struct.X509_pubkey_st */
            	2389, 0,
            0, 24, 3, /* 2389: struct.X509_pubkey_st */
            	2162, 0,
            	2251, 8,
            	2398, 16,
            1, 8, 1, /* 2398: pointer.struct.evp_pkey_st */
            	2403, 0,
            0, 56, 4, /* 2403: struct.evp_pkey_st */
            	2414, 16,
            	2422, 24,
            	2430, 32,
            	2751, 48,
            1, 8, 1, /* 2414: pointer.struct.evp_pkey_asn1_method_st */
            	2419, 0,
            0, 0, 0, /* 2419: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 2422: pointer.struct.engine_st */
            	2427, 0,
            0, 0, 0, /* 2427: struct.engine_st */
            0, 8, 5, /* 2430: union.unknown */
            	178, 0,
            	2443, 0,
            	2594, 0,
            	2675, 0,
            	2743, 0,
            1, 8, 1, /* 2443: pointer.struct.rsa_st */
            	2448, 0,
            0, 168, 17, /* 2448: struct.rsa_st */
            	2485, 16,
            	2422, 24,
            	2540, 32,
            	2540, 40,
            	2540, 48,
            	2540, 56,
            	2540, 64,
            	2540, 72,
            	2540, 80,
            	2540, 88,
            	2550, 96,
            	2572, 120,
            	2572, 128,
            	2572, 136,
            	178, 144,
            	2586, 152,
            	2586, 160,
            1, 8, 1, /* 2485: pointer.struct.rsa_meth_st */
            	2490, 0,
            0, 112, 13, /* 2490: struct.rsa_meth_st */
            	5, 0,
            	2519, 8,
            	2519, 16,
            	2519, 24,
            	2519, 32,
            	2522, 40,
            	2525, 48,
            	2528, 56,
            	2528, 64,
            	178, 80,
            	2531, 88,
            	2534, 96,
            	2537, 104,
            8884097, 8, 0, /* 2519: pointer.func */
            8884097, 8, 0, /* 2522: pointer.func */
            8884097, 8, 0, /* 2525: pointer.func */
            8884097, 8, 0, /* 2528: pointer.func */
            8884097, 8, 0, /* 2531: pointer.func */
            8884097, 8, 0, /* 2534: pointer.func */
            8884097, 8, 0, /* 2537: pointer.func */
            1, 8, 1, /* 2540: pointer.struct.bignum_st */
            	2545, 0,
            0, 24, 1, /* 2545: struct.bignum_st */
            	767, 0,
            0, 16, 1, /* 2550: struct.crypto_ex_data_st */
            	2555, 0,
            1, 8, 1, /* 2555: pointer.struct.stack_st_void */
            	2560, 0,
            0, 32, 1, /* 2560: struct.stack_st_void */
            	2565, 0,
            0, 32, 2, /* 2565: struct.stack_st */
            	797, 8,
            	86, 24,
            1, 8, 1, /* 2572: pointer.struct.bn_mont_ctx_st */
            	2577, 0,
            0, 96, 3, /* 2577: struct.bn_mont_ctx_st */
            	2545, 8,
            	2545, 32,
            	2545, 56,
            1, 8, 1, /* 2586: pointer.struct.bn_blinding_st */
            	2591, 0,
            0, 0, 0, /* 2591: struct.bn_blinding_st */
            1, 8, 1, /* 2594: pointer.struct.dsa_st */
            	2599, 0,
            0, 136, 11, /* 2599: struct.dsa_st */
            	2540, 24,
            	2540, 32,
            	2540, 40,
            	2540, 48,
            	2540, 56,
            	2540, 64,
            	2540, 72,
            	2572, 88,
            	2550, 104,
            	2624, 120,
            	2422, 128,
            1, 8, 1, /* 2624: pointer.struct.dsa_method */
            	2629, 0,
            0, 96, 11, /* 2629: struct.dsa_method */
            	5, 0,
            	2654, 8,
            	2657, 16,
            	2660, 24,
            	2663, 32,
            	2666, 40,
            	2669, 48,
            	2669, 56,
            	178, 72,
            	2672, 80,
            	2669, 88,
            8884097, 8, 0, /* 2654: pointer.func */
            8884097, 8, 0, /* 2657: pointer.func */
            8884097, 8, 0, /* 2660: pointer.func */
            8884097, 8, 0, /* 2663: pointer.func */
            8884097, 8, 0, /* 2666: pointer.func */
            8884097, 8, 0, /* 2669: pointer.func */
            8884097, 8, 0, /* 2672: pointer.func */
            1, 8, 1, /* 2675: pointer.struct.dh_st */
            	2680, 0,
            0, 144, 12, /* 2680: struct.dh_st */
            	2540, 8,
            	2540, 16,
            	2540, 32,
            	2540, 40,
            	2572, 56,
            	2540, 64,
            	2540, 72,
            	78, 80,
            	2540, 96,
            	2550, 112,
            	2707, 128,
            	2422, 136,
            1, 8, 1, /* 2707: pointer.struct.dh_method */
            	2712, 0,
            0, 72, 8, /* 2712: struct.dh_method */
            	5, 0,
            	2731, 8,
            	2734, 16,
            	2737, 24,
            	2731, 32,
            	2731, 40,
            	178, 56,
            	2740, 64,
            8884097, 8, 0, /* 2731: pointer.func */
            8884097, 8, 0, /* 2734: pointer.func */
            8884097, 8, 0, /* 2737: pointer.func */
            8884097, 8, 0, /* 2740: pointer.func */
            1, 8, 1, /* 2743: pointer.struct.ec_key_st */
            	2748, 0,
            0, 0, 0, /* 2748: struct.ec_key_st */
            1, 8, 1, /* 2751: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2756, 0,
            0, 32, 2, /* 2756: struct.stack_st_fake_X509_ATTRIBUTE */
            	2763, 8,
            	86, 24,
            8884099, 8, 2, /* 2763: pointer_to_array_of_pointers_to_stack */
            	2770, 0,
            	83, 20,
            0, 8, 1, /* 2770: pointer.X509_ATTRIBUTE */
            	1005, 0,
            1, 8, 1, /* 2775: pointer.struct.stack_st_X509_EXTENSION */
            	2780, 0,
            0, 32, 2, /* 2780: struct.stack_st_fake_X509_EXTENSION */
            	2787, 8,
            	86, 24,
            8884099, 8, 2, /* 2787: pointer_to_array_of_pointers_to_stack */
            	2794, 0,
            	83, 20,
            0, 8, 1, /* 2794: pointer.X509_EXTENSION */
            	34, 0,
            0, 24, 1, /* 2799: struct.ASN1_ENCODING_st */
            	78, 0,
            1, 8, 1, /* 2804: pointer.struct.AUTHORITY_KEYID_st */
            	2809, 0,
            0, 24, 3, /* 2809: struct.AUTHORITY_KEYID_st */
            	2256, 0,
            	2818, 8,
            	2152, 16,
            1, 8, 1, /* 2818: pointer.struct.stack_st_GENERAL_NAME */
            	2823, 0,
            0, 32, 2, /* 2823: struct.stack_st_fake_GENERAL_NAME */
            	2830, 8,
            	86, 24,
            8884099, 8, 2, /* 2830: pointer_to_array_of_pointers_to_stack */
            	2837, 0,
            	83, 20,
            0, 8, 1, /* 2837: pointer.GENERAL_NAME */
            	1486, 0,
            1, 8, 1, /* 2842: pointer.struct.X509_POLICY_CACHE_st */
            	2847, 0,
            0, 0, 0, /* 2847: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 2850: pointer.struct.stack_st_DIST_POINT */
            	2855, 0,
            0, 32, 2, /* 2855: struct.stack_st_fake_DIST_POINT */
            	2862, 8,
            	86, 24,
            8884099, 8, 2, /* 2862: pointer_to_array_of_pointers_to_stack */
            	2869, 0,
            	83, 20,
            0, 8, 1, /* 2869: pointer.DIST_POINT */
            	1429, 0,
            1, 8, 1, /* 2874: pointer.struct.stack_st_GENERAL_NAME */
            	2879, 0,
            0, 32, 2, /* 2879: struct.stack_st_fake_GENERAL_NAME */
            	2886, 8,
            	86, 24,
            8884099, 8, 2, /* 2886: pointer_to_array_of_pointers_to_stack */
            	2893, 0,
            	83, 20,
            0, 8, 1, /* 2893: pointer.GENERAL_NAME */
            	1486, 0,
            1, 8, 1, /* 2898: pointer.struct.NAME_CONSTRAINTS_st */
            	2903, 0,
            0, 16, 2, /* 2903: struct.NAME_CONSTRAINTS_st */
            	2910, 0,
            	2910, 8,
            1, 8, 1, /* 2910: pointer.struct.stack_st_GENERAL_SUBTREE */
            	2915, 0,
            0, 32, 2, /* 2915: struct.stack_st_fake_GENERAL_SUBTREE */
            	2922, 8,
            	86, 24,
            8884099, 8, 2, /* 2922: pointer_to_array_of_pointers_to_stack */
            	2929, 0,
            	83, 20,
            0, 8, 1, /* 2929: pointer.GENERAL_SUBTREE */
            	2934, 0,
            0, 0, 1, /* 2934: GENERAL_SUBTREE */
            	2939, 0,
            0, 24, 3, /* 2939: struct.GENERAL_SUBTREE_st */
            	2948, 0,
            	1618, 8,
            	1618, 16,
            1, 8, 1, /* 2948: pointer.struct.GENERAL_NAME_st */
            	1491, 0,
            1, 8, 1, /* 2953: pointer.struct.x509_cert_aux_st */
            	2958, 0,
            0, 40, 5, /* 2958: struct.x509_cert_aux_st */
            	2971, 0,
            	2971, 8,
            	2306, 16,
            	2256, 24,
            	2995, 32,
            1, 8, 1, /* 2971: pointer.struct.stack_st_ASN1_OBJECT */
            	2976, 0,
            0, 32, 2, /* 2976: struct.stack_st_fake_ASN1_OBJECT */
            	2983, 8,
            	86, 24,
            8884099, 8, 2, /* 2983: pointer_to_array_of_pointers_to_stack */
            	2990, 0,
            	83, 20,
            0, 8, 1, /* 2990: pointer.ASN1_OBJECT */
            	1888, 0,
            1, 8, 1, /* 2995: pointer.struct.stack_st_X509_ALGOR */
            	3000, 0,
            0, 32, 2, /* 3000: struct.stack_st_fake_X509_ALGOR */
            	3007, 8,
            	86, 24,
            8884099, 8, 2, /* 3007: pointer_to_array_of_pointers_to_stack */
            	3014, 0,
            	83, 20,
            0, 8, 1, /* 3014: pointer.X509_ALGOR */
            	1917, 0,
            1, 8, 1, /* 3019: pointer.struct.env_md_st */
            	3024, 0,
            0, 120, 8, /* 3024: struct.env_md_st */
            	3043, 24,
            	3046, 32,
            	3049, 40,
            	3052, 48,
            	3043, 56,
            	3055, 64,
            	3058, 72,
            	3061, 112,
            8884097, 8, 0, /* 3043: pointer.func */
            8884097, 8, 0, /* 3046: pointer.func */
            8884097, 8, 0, /* 3049: pointer.func */
            8884097, 8, 0, /* 3052: pointer.func */
            8884097, 8, 0, /* 3055: pointer.func */
            8884097, 8, 0, /* 3058: pointer.func */
            8884097, 8, 0, /* 3061: pointer.func */
            1, 8, 1, /* 3064: pointer.struct.rsa_st */
            	2448, 0,
            1, 8, 1, /* 3069: pointer.struct.dh_st */
            	2680, 0,
            1, 8, 1, /* 3074: pointer.struct.ec_key_st */
            	2748, 0,
            1, 8, 1, /* 3079: pointer.struct.ssl_cipher_st */
            	3084, 0,
            0, 88, 1, /* 3084: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 3089: pointer.struct.stack_st_SSL_CIPHER */
            	3094, 0,
            0, 32, 2, /* 3094: struct.stack_st_fake_SSL_CIPHER */
            	3101, 8,
            	86, 24,
            8884099, 8, 2, /* 3101: pointer_to_array_of_pointers_to_stack */
            	3108, 0,
            	83, 20,
            0, 8, 1, /* 3108: pointer.SSL_CIPHER */
            	3113, 0,
            0, 0, 1, /* 3113: SSL_CIPHER */
            	3118, 0,
            0, 88, 1, /* 3118: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 3123: pointer.struct.ssl_session_st */
            	234, 0,
            0, 56, 2, /* 3128: struct.comp_ctx_st */
            	3135, 0,
            	2550, 40,
            1, 8, 1, /* 3135: pointer.struct.comp_method_st */
            	3140, 0,
            0, 64, 7, /* 3140: struct.comp_method_st */
            	5, 8,
            	3157, 16,
            	3160, 24,
            	3163, 32,
            	3163, 40,
            	3166, 48,
            	3166, 56,
            8884097, 8, 0, /* 3157: pointer.func */
            8884097, 8, 0, /* 3160: pointer.func */
            8884097, 8, 0, /* 3163: pointer.func */
            8884097, 8, 0, /* 3166: pointer.func */
            1, 8, 1, /* 3169: pointer.struct.comp_ctx_st */
            	3128, 0,
            0, 0, 0, /* 3174: struct._pqueue */
            1, 8, 1, /* 3177: pointer.struct._pqueue */
            	3174, 0,
            0, 16, 1, /* 3182: struct.record_pqueue_st */
            	3177, 8,
            0, 888, 7, /* 3187: struct.dtls1_state_st */
            	3182, 576,
            	3182, 592,
            	3177, 608,
            	3177, 616,
            	3182, 624,
            	3204, 648,
            	3204, 736,
            0, 88, 1, /* 3204: struct.hm_header_st */
            	3209, 48,
            0, 40, 4, /* 3209: struct.dtls1_retransmit_state */
            	3220, 0,
            	3276, 8,
            	3169, 16,
            	229, 24,
            1, 8, 1, /* 3220: pointer.struct.evp_cipher_ctx_st */
            	3225, 0,
            0, 168, 4, /* 3225: struct.evp_cipher_ctx_st */
            	3236, 0,
            	2422, 8,
            	3273, 96,
            	3273, 120,
            1, 8, 1, /* 3236: pointer.struct.evp_cipher_st */
            	3241, 0,
            0, 88, 7, /* 3241: struct.evp_cipher_st */
            	3258, 24,
            	3261, 32,
            	3264, 40,
            	3267, 56,
            	3267, 64,
            	3270, 72,
            	3273, 80,
            8884097, 8, 0, /* 3258: pointer.func */
            8884097, 8, 0, /* 3261: pointer.func */
            8884097, 8, 0, /* 3264: pointer.func */
            8884097, 8, 0, /* 3267: pointer.func */
            8884097, 8, 0, /* 3270: pointer.func */
            0, 8, 0, /* 3273: pointer.void */
            1, 8, 1, /* 3276: pointer.struct.env_md_ctx_st */
            	3281, 0,
            0, 48, 5, /* 3281: struct.env_md_ctx_st */
            	3019, 0,
            	2422, 8,
            	3273, 24,
            	3294, 32,
            	3046, 40,
            1, 8, 1, /* 3294: pointer.struct.evp_pkey_ctx_st */
            	3299, 0,
            0, 0, 0, /* 3299: struct.evp_pkey_ctx_st */
            0, 24, 2, /* 3302: struct.ssl_comp_st */
            	5, 8,
            	3135, 16,
            1, 8, 1, /* 3309: pointer.pointer.struct.env_md_ctx_st */
            	3276, 0,
            0, 24, 1, /* 3314: struct.ssl3_buffer_st */
            	78, 0,
            0, 1200, 10, /* 3319: struct.ssl3_state_st */
            	3314, 240,
            	3314, 264,
            	3342, 288,
            	3342, 344,
            	60, 432,
            	3351, 440,
            	3309, 448,
            	3273, 496,
            	3273, 512,
            	3425, 528,
            0, 56, 3, /* 3342: struct.ssl3_record_st */
            	78, 16,
            	78, 24,
            	78, 32,
            1, 8, 1, /* 3351: pointer.struct.bio_st */
            	3356, 0,
            0, 112, 7, /* 3356: struct.bio_st */
            	3373, 0,
            	3417, 8,
            	178, 16,
            	3273, 48,
            	3420, 56,
            	3420, 64,
            	2550, 96,
            1, 8, 1, /* 3373: pointer.struct.bio_method_st */
            	3378, 0,
            0, 80, 9, /* 3378: struct.bio_method_st */
            	5, 8,
            	3399, 16,
            	3402, 24,
            	3405, 32,
            	3402, 40,
            	3408, 48,
            	3411, 56,
            	3411, 64,
            	3414, 72,
            8884097, 8, 0, /* 3399: pointer.func */
            8884097, 8, 0, /* 3402: pointer.func */
            8884097, 8, 0, /* 3405: pointer.func */
            8884097, 8, 0, /* 3408: pointer.func */
            8884097, 8, 0, /* 3411: pointer.func */
            8884097, 8, 0, /* 3414: pointer.func */
            8884097, 8, 0, /* 3417: pointer.func */
            1, 8, 1, /* 3420: pointer.struct.bio_st */
            	3356, 0,
            0, 528, 8, /* 3425: struct.unknown */
            	3079, 408,
            	3069, 416,
            	3074, 424,
            	3444, 464,
            	78, 480,
            	3236, 488,
            	3019, 496,
            	3516, 512,
            1, 8, 1, /* 3444: pointer.struct.stack_st_X509_NAME */
            	3449, 0,
            0, 32, 2, /* 3449: struct.stack_st_fake_X509_NAME */
            	3456, 8,
            	86, 24,
            8884099, 8, 2, /* 3456: pointer_to_array_of_pointers_to_stack */
            	3463, 0,
            	83, 20,
            0, 8, 1, /* 3463: pointer.X509_NAME */
            	3468, 0,
            0, 0, 1, /* 3468: X509_NAME */
            	3473, 0,
            0, 40, 3, /* 3473: struct.X509_name_st */
            	3482, 0,
            	3506, 16,
            	78, 24,
            1, 8, 1, /* 3482: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3487, 0,
            0, 32, 2, /* 3487: struct.stack_st_fake_X509_NAME_ENTRY */
            	3494, 8,
            	86, 24,
            8884099, 8, 2, /* 3494: pointer_to_array_of_pointers_to_stack */
            	3501, 0,
            	83, 20,
            0, 8, 1, /* 3501: pointer.X509_NAME_ENTRY */
            	132, 0,
            1, 8, 1, /* 3506: pointer.struct.buf_mem_st */
            	3511, 0,
            0, 24, 1, /* 3511: struct.buf_mem_st */
            	178, 8,
            1, 8, 1, /* 3516: pointer.struct.ssl_comp_st */
            	3302, 0,
            1, 8, 1, /* 3521: pointer.struct.ssl3_state_st */
            	3319, 0,
            1, 8, 1, /* 3526: pointer.struct.ssl2_state_st */
            	3531, 0,
            0, 344, 9, /* 3531: struct.ssl2_state_st */
            	60, 24,
            	78, 56,
            	78, 64,
            	78, 72,
            	78, 104,
            	78, 112,
            	78, 120,
            	78, 128,
            	78, 136,
            1, 8, 1, /* 3552: pointer.struct.ssl_st */
            	3557, 0,
            0, 808, 51, /* 3557: struct.ssl_st */
            	3662, 8,
            	3351, 16,
            	3351, 24,
            	3351, 32,
            	3726, 48,
            	2357, 80,
            	3273, 88,
            	78, 104,
            	3526, 120,
            	3521, 128,
            	3828, 136,
            	3833, 152,
            	3273, 160,
            	3836, 176,
            	3089, 184,
            	3089, 192,
            	3220, 208,
            	3276, 216,
            	3169, 224,
            	3220, 232,
            	3276, 240,
            	3169, 248,
            	3848, 256,
            	229, 304,
            	3879, 312,
            	3882, 328,
            	3885, 336,
            	3888, 352,
            	3891, 360,
            	3894, 368,
            	2550, 392,
            	3444, 408,
            	5610, 464,
            	3273, 472,
            	178, 480,
            	200, 504,
            	10, 512,
            	78, 520,
            	78, 544,
            	78, 560,
            	3273, 568,
            	5613, 584,
            	5623, 592,
            	3273, 600,
            	5626, 608,
            	3273, 616,
            	3894, 624,
            	78, 632,
            	5576, 648,
            	5629, 656,
            	5536, 680,
            1, 8, 1, /* 3662: pointer.struct.ssl_method_st */
            	3667, 0,
            0, 232, 28, /* 3667: struct.ssl_method_st */
            	3726, 8,
            	3729, 16,
            	3729, 24,
            	3726, 32,
            	3726, 40,
            	3732, 48,
            	3732, 56,
            	3735, 64,
            	3726, 72,
            	3726, 80,
            	3726, 88,
            	3738, 96,
            	3741, 104,
            	3744, 112,
            	3726, 120,
            	3747, 128,
            	3750, 136,
            	3753, 144,
            	3756, 152,
            	3759, 160,
            	3762, 168,
            	3765, 176,
            	3768, 184,
            	3166, 192,
            	3771, 200,
            	3762, 208,
            	3822, 216,
            	3825, 224,
            8884097, 8, 0, /* 3726: pointer.func */
            8884097, 8, 0, /* 3729: pointer.func */
            8884097, 8, 0, /* 3732: pointer.func */
            8884097, 8, 0, /* 3735: pointer.func */
            8884097, 8, 0, /* 3738: pointer.func */
            8884097, 8, 0, /* 3741: pointer.func */
            8884097, 8, 0, /* 3744: pointer.func */
            8884097, 8, 0, /* 3747: pointer.func */
            8884097, 8, 0, /* 3750: pointer.func */
            8884097, 8, 0, /* 3753: pointer.func */
            8884097, 8, 0, /* 3756: pointer.func */
            8884097, 8, 0, /* 3759: pointer.func */
            8884097, 8, 0, /* 3762: pointer.func */
            8884097, 8, 0, /* 3765: pointer.func */
            8884097, 8, 0, /* 3768: pointer.func */
            1, 8, 1, /* 3771: pointer.struct.ssl3_enc_method */
            	3776, 0,
            0, 112, 11, /* 3776: struct.ssl3_enc_method */
            	3801, 0,
            	3804, 8,
            	3726, 16,
            	3807, 24,
            	3801, 32,
            	3810, 40,
            	3813, 56,
            	5, 64,
            	5, 80,
            	3816, 96,
            	3819, 104,
            8884097, 8, 0, /* 3801: pointer.func */
            8884097, 8, 0, /* 3804: pointer.func */
            8884097, 8, 0, /* 3807: pointer.func */
            8884097, 8, 0, /* 3810: pointer.func */
            8884097, 8, 0, /* 3813: pointer.func */
            8884097, 8, 0, /* 3816: pointer.func */
            8884097, 8, 0, /* 3819: pointer.func */
            8884097, 8, 0, /* 3822: pointer.func */
            8884097, 8, 0, /* 3825: pointer.func */
            1, 8, 1, /* 3828: pointer.struct.dtls1_state_st */
            	3187, 0,
            8884097, 8, 0, /* 3833: pointer.func */
            1, 8, 1, /* 3836: pointer.struct.X509_VERIFY_PARAM_st */
            	3841, 0,
            0, 56, 2, /* 3841: struct.X509_VERIFY_PARAM_st */
            	178, 0,
            	2971, 48,
            1, 8, 1, /* 3848: pointer.struct.cert_st */
            	3853, 0,
            0, 296, 7, /* 3853: struct.cert_st */
            	2076, 0,
            	3064, 48,
            	3870, 56,
            	3069, 64,
            	3873, 72,
            	3074, 80,
            	3876, 88,
            8884097, 8, 0, /* 3870: pointer.func */
            8884097, 8, 0, /* 3873: pointer.func */
            8884097, 8, 0, /* 3876: pointer.func */
            8884097, 8, 0, /* 3879: pointer.func */
            8884097, 8, 0, /* 3882: pointer.func */
            8884097, 8, 0, /* 3885: pointer.func */
            8884097, 8, 0, /* 3888: pointer.func */
            8884097, 8, 0, /* 3891: pointer.func */
            1, 8, 1, /* 3894: pointer.struct.ssl_ctx_st */
            	3899, 0,
            0, 736, 50, /* 3899: struct.ssl_ctx_st */
            	3662, 0,
            	3089, 8,
            	3089, 16,
            	4002, 24,
            	5377, 32,
            	3123, 48,
            	3123, 56,
            	5413, 80,
            	5416, 88,
            	5419, 96,
            	5422, 152,
            	3273, 160,
            	5425, 168,
            	3273, 176,
            	5428, 184,
            	5431, 192,
            	5434, 200,
            	2550, 208,
            	3019, 224,
            	3019, 232,
            	3019, 240,
            	283, 248,
            	5437, 256,
            	3885, 264,
            	3444, 272,
            	3848, 304,
            	3833, 320,
            	3273, 328,
            	3882, 376,
            	3879, 384,
            	3836, 392,
            	2422, 408,
            	5504, 416,
            	3273, 424,
            	5507, 480,
            	5510, 488,
            	3273, 496,
            	5513, 504,
            	3273, 512,
            	178, 520,
            	3888, 528,
            	3891, 536,
            	5516, 552,
            	5516, 560,
            	5536, 568,
            	5570, 696,
            	3273, 704,
            	5573, 712,
            	3273, 720,
            	5576, 728,
            1, 8, 1, /* 4002: pointer.struct.x509_store_st */
            	4007, 0,
            0, 144, 15, /* 4007: struct.x509_store_st */
            	4040, 8,
            	5141, 16,
            	3836, 24,
            	5353, 32,
            	3882, 40,
            	5356, 48,
            	5359, 56,
            	5353, 64,
            	5362, 72,
            	5365, 80,
            	5368, 88,
            	5371, 96,
            	5374, 104,
            	5353, 112,
            	2550, 120,
            1, 8, 1, /* 4040: pointer.struct.stack_st_X509_OBJECT */
            	4045, 0,
            0, 32, 2, /* 4045: struct.stack_st_fake_X509_OBJECT */
            	4052, 8,
            	86, 24,
            8884099, 8, 2, /* 4052: pointer_to_array_of_pointers_to_stack */
            	4059, 0,
            	83, 20,
            0, 8, 1, /* 4059: pointer.X509_OBJECT */
            	4064, 0,
            0, 0, 1, /* 4064: X509_OBJECT */
            	4069, 0,
            0, 16, 1, /* 4069: struct.x509_object_st */
            	4074, 8,
            0, 8, 4, /* 4074: union.unknown */
            	178, 0,
            	4085, 0,
            	4929, 0,
            	4385, 0,
            1, 8, 1, /* 4085: pointer.struct.x509_st */
            	4090, 0,
            0, 184, 12, /* 4090: struct.x509_st */
            	4117, 0,
            	4157, 8,
            	4246, 16,
            	178, 32,
            	4537, 40,
            	4251, 104,
            	4791, 112,
            	4799, 120,
            	4807, 128,
            	4831, 136,
            	4855, 144,
            	4863, 176,
            1, 8, 1, /* 4117: pointer.struct.x509_cinf_st */
            	4122, 0,
            0, 104, 11, /* 4122: struct.x509_cinf_st */
            	4147, 0,
            	4147, 8,
            	4157, 16,
            	4306, 24,
            	4354, 32,
            	4306, 40,
            	4371, 48,
            	4246, 56,
            	4246, 64,
            	4762, 72,
            	4786, 80,
            1, 8, 1, /* 4147: pointer.struct.asn1_string_st */
            	4152, 0,
            0, 24, 1, /* 4152: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 4157: pointer.struct.X509_algor_st */
            	4162, 0,
            0, 16, 2, /* 4162: struct.X509_algor_st */
            	4169, 0,
            	4183, 8,
            1, 8, 1, /* 4169: pointer.struct.asn1_object_st */
            	4174, 0,
            0, 40, 3, /* 4174: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 4183: pointer.struct.asn1_type_st */
            	4188, 0,
            0, 16, 1, /* 4188: struct.asn1_type_st */
            	4193, 8,
            0, 8, 20, /* 4193: union.unknown */
            	178, 0,
            	4236, 0,
            	4169, 0,
            	4147, 0,
            	4241, 0,
            	4246, 0,
            	4251, 0,
            	4256, 0,
            	4261, 0,
            	4266, 0,
            	4271, 0,
            	4276, 0,
            	4281, 0,
            	4286, 0,
            	4291, 0,
            	4296, 0,
            	4301, 0,
            	4236, 0,
            	4236, 0,
            	1352, 0,
            1, 8, 1, /* 4236: pointer.struct.asn1_string_st */
            	4152, 0,
            1, 8, 1, /* 4241: pointer.struct.asn1_string_st */
            	4152, 0,
            1, 8, 1, /* 4246: pointer.struct.asn1_string_st */
            	4152, 0,
            1, 8, 1, /* 4251: pointer.struct.asn1_string_st */
            	4152, 0,
            1, 8, 1, /* 4256: pointer.struct.asn1_string_st */
            	4152, 0,
            1, 8, 1, /* 4261: pointer.struct.asn1_string_st */
            	4152, 0,
            1, 8, 1, /* 4266: pointer.struct.asn1_string_st */
            	4152, 0,
            1, 8, 1, /* 4271: pointer.struct.asn1_string_st */
            	4152, 0,
            1, 8, 1, /* 4276: pointer.struct.asn1_string_st */
            	4152, 0,
            1, 8, 1, /* 4281: pointer.struct.asn1_string_st */
            	4152, 0,
            1, 8, 1, /* 4286: pointer.struct.asn1_string_st */
            	4152, 0,
            1, 8, 1, /* 4291: pointer.struct.asn1_string_st */
            	4152, 0,
            1, 8, 1, /* 4296: pointer.struct.asn1_string_st */
            	4152, 0,
            1, 8, 1, /* 4301: pointer.struct.asn1_string_st */
            	4152, 0,
            1, 8, 1, /* 4306: pointer.struct.X509_name_st */
            	4311, 0,
            0, 40, 3, /* 4311: struct.X509_name_st */
            	4320, 0,
            	4344, 16,
            	78, 24,
            1, 8, 1, /* 4320: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4325, 0,
            0, 32, 2, /* 4325: struct.stack_st_fake_X509_NAME_ENTRY */
            	4332, 8,
            	86, 24,
            8884099, 8, 2, /* 4332: pointer_to_array_of_pointers_to_stack */
            	4339, 0,
            	83, 20,
            0, 8, 1, /* 4339: pointer.X509_NAME_ENTRY */
            	132, 0,
            1, 8, 1, /* 4344: pointer.struct.buf_mem_st */
            	4349, 0,
            0, 24, 1, /* 4349: struct.buf_mem_st */
            	178, 8,
            1, 8, 1, /* 4354: pointer.struct.X509_val_st */
            	4359, 0,
            0, 16, 2, /* 4359: struct.X509_val_st */
            	4366, 0,
            	4366, 8,
            1, 8, 1, /* 4366: pointer.struct.asn1_string_st */
            	4152, 0,
            1, 8, 1, /* 4371: pointer.struct.X509_pubkey_st */
            	4376, 0,
            0, 24, 3, /* 4376: struct.X509_pubkey_st */
            	4157, 0,
            	4246, 8,
            	4385, 16,
            1, 8, 1, /* 4385: pointer.struct.evp_pkey_st */
            	4390, 0,
            0, 56, 4, /* 4390: struct.evp_pkey_st */
            	4401, 16,
            	4409, 24,
            	4417, 32,
            	4738, 48,
            1, 8, 1, /* 4401: pointer.struct.evp_pkey_asn1_method_st */
            	4406, 0,
            0, 0, 0, /* 4406: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 4409: pointer.struct.engine_st */
            	4414, 0,
            0, 0, 0, /* 4414: struct.engine_st */
            0, 8, 5, /* 4417: union.unknown */
            	178, 0,
            	4430, 0,
            	4581, 0,
            	4662, 0,
            	4730, 0,
            1, 8, 1, /* 4430: pointer.struct.rsa_st */
            	4435, 0,
            0, 168, 17, /* 4435: struct.rsa_st */
            	4472, 16,
            	4409, 24,
            	4527, 32,
            	4527, 40,
            	4527, 48,
            	4527, 56,
            	4527, 64,
            	4527, 72,
            	4527, 80,
            	4527, 88,
            	4537, 96,
            	4559, 120,
            	4559, 128,
            	4559, 136,
            	178, 144,
            	4573, 152,
            	4573, 160,
            1, 8, 1, /* 4472: pointer.struct.rsa_meth_st */
            	4477, 0,
            0, 112, 13, /* 4477: struct.rsa_meth_st */
            	5, 0,
            	4506, 8,
            	4506, 16,
            	4506, 24,
            	4506, 32,
            	4509, 40,
            	4512, 48,
            	4515, 56,
            	4515, 64,
            	178, 80,
            	4518, 88,
            	4521, 96,
            	4524, 104,
            8884097, 8, 0, /* 4506: pointer.func */
            8884097, 8, 0, /* 4509: pointer.func */
            8884097, 8, 0, /* 4512: pointer.func */
            8884097, 8, 0, /* 4515: pointer.func */
            8884097, 8, 0, /* 4518: pointer.func */
            8884097, 8, 0, /* 4521: pointer.func */
            8884097, 8, 0, /* 4524: pointer.func */
            1, 8, 1, /* 4527: pointer.struct.bignum_st */
            	4532, 0,
            0, 24, 1, /* 4532: struct.bignum_st */
            	767, 0,
            0, 16, 1, /* 4537: struct.crypto_ex_data_st */
            	4542, 0,
            1, 8, 1, /* 4542: pointer.struct.stack_st_void */
            	4547, 0,
            0, 32, 1, /* 4547: struct.stack_st_void */
            	4552, 0,
            0, 32, 2, /* 4552: struct.stack_st */
            	797, 8,
            	86, 24,
            1, 8, 1, /* 4559: pointer.struct.bn_mont_ctx_st */
            	4564, 0,
            0, 96, 3, /* 4564: struct.bn_mont_ctx_st */
            	4532, 8,
            	4532, 32,
            	4532, 56,
            1, 8, 1, /* 4573: pointer.struct.bn_blinding_st */
            	4578, 0,
            0, 0, 0, /* 4578: struct.bn_blinding_st */
            1, 8, 1, /* 4581: pointer.struct.dsa_st */
            	4586, 0,
            0, 136, 11, /* 4586: struct.dsa_st */
            	4527, 24,
            	4527, 32,
            	4527, 40,
            	4527, 48,
            	4527, 56,
            	4527, 64,
            	4527, 72,
            	4559, 88,
            	4537, 104,
            	4611, 120,
            	4409, 128,
            1, 8, 1, /* 4611: pointer.struct.dsa_method */
            	4616, 0,
            0, 96, 11, /* 4616: struct.dsa_method */
            	5, 0,
            	4641, 8,
            	4644, 16,
            	4647, 24,
            	4650, 32,
            	4653, 40,
            	4656, 48,
            	4656, 56,
            	178, 72,
            	4659, 80,
            	4656, 88,
            8884097, 8, 0, /* 4641: pointer.func */
            8884097, 8, 0, /* 4644: pointer.func */
            8884097, 8, 0, /* 4647: pointer.func */
            8884097, 8, 0, /* 4650: pointer.func */
            8884097, 8, 0, /* 4653: pointer.func */
            8884097, 8, 0, /* 4656: pointer.func */
            8884097, 8, 0, /* 4659: pointer.func */
            1, 8, 1, /* 4662: pointer.struct.dh_st */
            	4667, 0,
            0, 144, 12, /* 4667: struct.dh_st */
            	4527, 8,
            	4527, 16,
            	4527, 32,
            	4527, 40,
            	4559, 56,
            	4527, 64,
            	4527, 72,
            	78, 80,
            	4527, 96,
            	4537, 112,
            	4694, 128,
            	4409, 136,
            1, 8, 1, /* 4694: pointer.struct.dh_method */
            	4699, 0,
            0, 72, 8, /* 4699: struct.dh_method */
            	5, 0,
            	4718, 8,
            	4721, 16,
            	4724, 24,
            	4718, 32,
            	4718, 40,
            	178, 56,
            	4727, 64,
            8884097, 8, 0, /* 4718: pointer.func */
            8884097, 8, 0, /* 4721: pointer.func */
            8884097, 8, 0, /* 4724: pointer.func */
            8884097, 8, 0, /* 4727: pointer.func */
            1, 8, 1, /* 4730: pointer.struct.ec_key_st */
            	4735, 0,
            0, 0, 0, /* 4735: struct.ec_key_st */
            1, 8, 1, /* 4738: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4743, 0,
            0, 32, 2, /* 4743: struct.stack_st_fake_X509_ATTRIBUTE */
            	4750, 8,
            	86, 24,
            8884099, 8, 2, /* 4750: pointer_to_array_of_pointers_to_stack */
            	4757, 0,
            	83, 20,
            0, 8, 1, /* 4757: pointer.X509_ATTRIBUTE */
            	1005, 0,
            1, 8, 1, /* 4762: pointer.struct.stack_st_X509_EXTENSION */
            	4767, 0,
            0, 32, 2, /* 4767: struct.stack_st_fake_X509_EXTENSION */
            	4774, 8,
            	86, 24,
            8884099, 8, 2, /* 4774: pointer_to_array_of_pointers_to_stack */
            	4781, 0,
            	83, 20,
            0, 8, 1, /* 4781: pointer.X509_EXTENSION */
            	34, 0,
            0, 24, 1, /* 4786: struct.ASN1_ENCODING_st */
            	78, 0,
            1, 8, 1, /* 4791: pointer.struct.AUTHORITY_KEYID_st */
            	4796, 0,
            0, 0, 0, /* 4796: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4799: pointer.struct.X509_POLICY_CACHE_st */
            	4804, 0,
            0, 0, 0, /* 4804: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 4807: pointer.struct.stack_st_DIST_POINT */
            	4812, 0,
            0, 32, 2, /* 4812: struct.stack_st_fake_DIST_POINT */
            	4819, 8,
            	86, 24,
            8884099, 8, 2, /* 4819: pointer_to_array_of_pointers_to_stack */
            	4826, 0,
            	83, 20,
            0, 8, 1, /* 4826: pointer.DIST_POINT */
            	1429, 0,
            1, 8, 1, /* 4831: pointer.struct.stack_st_GENERAL_NAME */
            	4836, 0,
            0, 32, 2, /* 4836: struct.stack_st_fake_GENERAL_NAME */
            	4843, 8,
            	86, 24,
            8884099, 8, 2, /* 4843: pointer_to_array_of_pointers_to_stack */
            	4850, 0,
            	83, 20,
            0, 8, 1, /* 4850: pointer.GENERAL_NAME */
            	1486, 0,
            1, 8, 1, /* 4855: pointer.struct.NAME_CONSTRAINTS_st */
            	4860, 0,
            0, 0, 0, /* 4860: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4863: pointer.struct.x509_cert_aux_st */
            	4868, 0,
            0, 40, 5, /* 4868: struct.x509_cert_aux_st */
            	4881, 0,
            	4881, 8,
            	4301, 16,
            	4251, 24,
            	4905, 32,
            1, 8, 1, /* 4881: pointer.struct.stack_st_ASN1_OBJECT */
            	4886, 0,
            0, 32, 2, /* 4886: struct.stack_st_fake_ASN1_OBJECT */
            	4893, 8,
            	86, 24,
            8884099, 8, 2, /* 4893: pointer_to_array_of_pointers_to_stack */
            	4900, 0,
            	83, 20,
            0, 8, 1, /* 4900: pointer.ASN1_OBJECT */
            	1888, 0,
            1, 8, 1, /* 4905: pointer.struct.stack_st_X509_ALGOR */
            	4910, 0,
            0, 32, 2, /* 4910: struct.stack_st_fake_X509_ALGOR */
            	4917, 8,
            	86, 24,
            8884099, 8, 2, /* 4917: pointer_to_array_of_pointers_to_stack */
            	4924, 0,
            	83, 20,
            0, 8, 1, /* 4924: pointer.X509_ALGOR */
            	1917, 0,
            1, 8, 1, /* 4929: pointer.struct.X509_crl_st */
            	4934, 0,
            0, 120, 10, /* 4934: struct.X509_crl_st */
            	4957, 0,
            	4157, 8,
            	4246, 16,
            	4791, 32,
            	5084, 40,
            	4147, 56,
            	4147, 64,
            	5092, 96,
            	5133, 104,
            	3273, 112,
            1, 8, 1, /* 4957: pointer.struct.X509_crl_info_st */
            	4962, 0,
            0, 80, 8, /* 4962: struct.X509_crl_info_st */
            	4147, 0,
            	4157, 8,
            	4306, 16,
            	4366, 24,
            	4366, 32,
            	4981, 40,
            	4762, 48,
            	4786, 56,
            1, 8, 1, /* 4981: pointer.struct.stack_st_X509_REVOKED */
            	4986, 0,
            0, 32, 2, /* 4986: struct.stack_st_fake_X509_REVOKED */
            	4993, 8,
            	86, 24,
            8884099, 8, 2, /* 4993: pointer_to_array_of_pointers_to_stack */
            	5000, 0,
            	83, 20,
            0, 8, 1, /* 5000: pointer.X509_REVOKED */
            	5005, 0,
            0, 0, 1, /* 5005: X509_REVOKED */
            	5010, 0,
            0, 40, 4, /* 5010: struct.x509_revoked_st */
            	5021, 0,
            	5031, 8,
            	5036, 16,
            	5060, 24,
            1, 8, 1, /* 5021: pointer.struct.asn1_string_st */
            	5026, 0,
            0, 24, 1, /* 5026: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 5031: pointer.struct.asn1_string_st */
            	5026, 0,
            1, 8, 1, /* 5036: pointer.struct.stack_st_X509_EXTENSION */
            	5041, 0,
            0, 32, 2, /* 5041: struct.stack_st_fake_X509_EXTENSION */
            	5048, 8,
            	86, 24,
            8884099, 8, 2, /* 5048: pointer_to_array_of_pointers_to_stack */
            	5055, 0,
            	83, 20,
            0, 8, 1, /* 5055: pointer.X509_EXTENSION */
            	34, 0,
            1, 8, 1, /* 5060: pointer.struct.stack_st_GENERAL_NAME */
            	5065, 0,
            0, 32, 2, /* 5065: struct.stack_st_fake_GENERAL_NAME */
            	5072, 8,
            	86, 24,
            8884099, 8, 2, /* 5072: pointer_to_array_of_pointers_to_stack */
            	5079, 0,
            	83, 20,
            0, 8, 1, /* 5079: pointer.GENERAL_NAME */
            	1486, 0,
            1, 8, 1, /* 5084: pointer.struct.ISSUING_DIST_POINT_st */
            	5089, 0,
            0, 0, 0, /* 5089: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 5092: pointer.struct.stack_st_GENERAL_NAMES */
            	5097, 0,
            0, 32, 2, /* 5097: struct.stack_st_fake_GENERAL_NAMES */
            	5104, 8,
            	86, 24,
            8884099, 8, 2, /* 5104: pointer_to_array_of_pointers_to_stack */
            	5111, 0,
            	83, 20,
            0, 8, 1, /* 5111: pointer.GENERAL_NAMES */
            	5116, 0,
            0, 0, 1, /* 5116: GENERAL_NAMES */
            	5121, 0,
            0, 32, 1, /* 5121: struct.stack_st_GENERAL_NAME */
            	5126, 0,
            0, 32, 2, /* 5126: struct.stack_st */
            	797, 8,
            	86, 24,
            1, 8, 1, /* 5133: pointer.struct.x509_crl_method_st */
            	5138, 0,
            0, 0, 0, /* 5138: struct.x509_crl_method_st */
            1, 8, 1, /* 5141: pointer.struct.stack_st_X509_LOOKUP */
            	5146, 0,
            0, 32, 2, /* 5146: struct.stack_st_fake_X509_LOOKUP */
            	5153, 8,
            	86, 24,
            8884099, 8, 2, /* 5153: pointer_to_array_of_pointers_to_stack */
            	5160, 0,
            	83, 20,
            0, 8, 1, /* 5160: pointer.X509_LOOKUP */
            	5165, 0,
            0, 0, 1, /* 5165: X509_LOOKUP */
            	5170, 0,
            0, 32, 3, /* 5170: struct.x509_lookup_st */
            	5179, 8,
            	178, 16,
            	5228, 24,
            1, 8, 1, /* 5179: pointer.struct.x509_lookup_method_st */
            	5184, 0,
            0, 80, 10, /* 5184: struct.x509_lookup_method_st */
            	5, 0,
            	5207, 8,
            	5210, 16,
            	5207, 24,
            	5207, 32,
            	5213, 40,
            	5216, 48,
            	5219, 56,
            	5222, 64,
            	5225, 72,
            8884097, 8, 0, /* 5207: pointer.func */
            8884097, 8, 0, /* 5210: pointer.func */
            8884097, 8, 0, /* 5213: pointer.func */
            8884097, 8, 0, /* 5216: pointer.func */
            8884097, 8, 0, /* 5219: pointer.func */
            8884097, 8, 0, /* 5222: pointer.func */
            8884097, 8, 0, /* 5225: pointer.func */
            1, 8, 1, /* 5228: pointer.struct.x509_store_st */
            	5233, 0,
            0, 144, 15, /* 5233: struct.x509_store_st */
            	5266, 8,
            	5290, 16,
            	5314, 24,
            	5326, 32,
            	5329, 40,
            	5332, 48,
            	5335, 56,
            	5326, 64,
            	5338, 72,
            	5341, 80,
            	5344, 88,
            	5347, 96,
            	5350, 104,
            	5326, 112,
            	4537, 120,
            1, 8, 1, /* 5266: pointer.struct.stack_st_X509_OBJECT */
            	5271, 0,
            0, 32, 2, /* 5271: struct.stack_st_fake_X509_OBJECT */
            	5278, 8,
            	86, 24,
            8884099, 8, 2, /* 5278: pointer_to_array_of_pointers_to_stack */
            	5285, 0,
            	83, 20,
            0, 8, 1, /* 5285: pointer.X509_OBJECT */
            	4064, 0,
            1, 8, 1, /* 5290: pointer.struct.stack_st_X509_LOOKUP */
            	5295, 0,
            0, 32, 2, /* 5295: struct.stack_st_fake_X509_LOOKUP */
            	5302, 8,
            	86, 24,
            8884099, 8, 2, /* 5302: pointer_to_array_of_pointers_to_stack */
            	5309, 0,
            	83, 20,
            0, 8, 1, /* 5309: pointer.X509_LOOKUP */
            	5165, 0,
            1, 8, 1, /* 5314: pointer.struct.X509_VERIFY_PARAM_st */
            	5319, 0,
            0, 56, 2, /* 5319: struct.X509_VERIFY_PARAM_st */
            	178, 0,
            	4881, 48,
            8884097, 8, 0, /* 5326: pointer.func */
            8884097, 8, 0, /* 5329: pointer.func */
            8884097, 8, 0, /* 5332: pointer.func */
            8884097, 8, 0, /* 5335: pointer.func */
            8884097, 8, 0, /* 5338: pointer.func */
            8884097, 8, 0, /* 5341: pointer.func */
            8884097, 8, 0, /* 5344: pointer.func */
            8884097, 8, 0, /* 5347: pointer.func */
            8884097, 8, 0, /* 5350: pointer.func */
            8884097, 8, 0, /* 5353: pointer.func */
            8884097, 8, 0, /* 5356: pointer.func */
            8884097, 8, 0, /* 5359: pointer.func */
            8884097, 8, 0, /* 5362: pointer.func */
            8884097, 8, 0, /* 5365: pointer.func */
            8884097, 8, 0, /* 5368: pointer.func */
            8884097, 8, 0, /* 5371: pointer.func */
            8884097, 8, 0, /* 5374: pointer.func */
            1, 8, 1, /* 5377: pointer.struct.lhash_st */
            	5382, 0,
            0, 176, 3, /* 5382: struct.lhash_st */
            	5391, 0,
            	86, 8,
            	5410, 16,
            8884099, 8, 2, /* 5391: pointer_to_array_of_pointers_to_stack */
            	5398, 0,
            	772, 28,
            1, 8, 1, /* 5398: pointer.struct.lhash_node_st */
            	5403, 0,
            0, 24, 2, /* 5403: struct.lhash_node_st */
            	3273, 0,
            	5398, 8,
            8884097, 8, 0, /* 5410: pointer.func */
            8884097, 8, 0, /* 5413: pointer.func */
            8884097, 8, 0, /* 5416: pointer.func */
            8884097, 8, 0, /* 5419: pointer.func */
            8884097, 8, 0, /* 5422: pointer.func */
            8884097, 8, 0, /* 5425: pointer.func */
            8884097, 8, 0, /* 5428: pointer.func */
            8884097, 8, 0, /* 5431: pointer.func */
            8884097, 8, 0, /* 5434: pointer.func */
            1, 8, 1, /* 5437: pointer.struct.stack_st_SSL_COMP */
            	5442, 0,
            0, 32, 2, /* 5442: struct.stack_st_fake_SSL_COMP */
            	5449, 8,
            	86, 24,
            8884099, 8, 2, /* 5449: pointer_to_array_of_pointers_to_stack */
            	5456, 0,
            	83, 20,
            0, 8, 1, /* 5456: pointer.SSL_COMP */
            	5461, 0,
            0, 0, 1, /* 5461: SSL_COMP */
            	5466, 0,
            0, 24, 2, /* 5466: struct.ssl_comp_st */
            	5, 8,
            	5473, 16,
            1, 8, 1, /* 5473: pointer.struct.comp_method_st */
            	5478, 0,
            0, 64, 7, /* 5478: struct.comp_method_st */
            	5, 8,
            	5495, 16,
            	5498, 24,
            	5501, 32,
            	5501, 40,
            	3166, 48,
            	3166, 56,
            8884097, 8, 0, /* 5495: pointer.func */
            8884097, 8, 0, /* 5498: pointer.func */
            8884097, 8, 0, /* 5501: pointer.func */
            8884097, 8, 0, /* 5504: pointer.func */
            8884097, 8, 0, /* 5507: pointer.func */
            8884097, 8, 0, /* 5510: pointer.func */
            8884097, 8, 0, /* 5513: pointer.func */
            1, 8, 1, /* 5516: pointer.struct.ssl3_buf_freelist_st */
            	5521, 0,
            0, 24, 1, /* 5521: struct.ssl3_buf_freelist_st */
            	5526, 16,
            1, 8, 1, /* 5526: pointer.struct.ssl3_buf_freelist_entry_st */
            	5531, 0,
            0, 8, 1, /* 5531: struct.ssl3_buf_freelist_entry_st */
            	5526, 0,
            0, 128, 14, /* 5536: struct.srp_ctx_st */
            	3273, 0,
            	5504, 8,
            	5510, 16,
            	5567, 24,
            	178, 32,
            	2540, 40,
            	2540, 48,
            	2540, 56,
            	2540, 64,
            	2540, 72,
            	2540, 80,
            	2540, 88,
            	2540, 96,
            	178, 104,
            8884097, 8, 0, /* 5567: pointer.func */
            8884097, 8, 0, /* 5570: pointer.func */
            8884097, 8, 0, /* 5573: pointer.func */
            1, 8, 1, /* 5576: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	5581, 0,
            0, 32, 2, /* 5581: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	5588, 8,
            	86, 24,
            8884099, 8, 2, /* 5588: pointer_to_array_of_pointers_to_stack */
            	5595, 0,
            	83, 20,
            0, 8, 1, /* 5595: pointer.SRTP_PROTECTION_PROFILE */
            	5600, 0,
            0, 0, 1, /* 5600: SRTP_PROTECTION_PROFILE */
            	5605, 0,
            0, 16, 1, /* 5605: struct.srtp_protection_profile_st */
            	5, 0,
            8884097, 8, 0, /* 5610: pointer.func */
            1, 8, 1, /* 5613: pointer.struct.tls_session_ticket_ext_st */
            	5618, 0,
            0, 16, 1, /* 5618: struct.tls_session_ticket_ext_st */
            	3273, 8,
            8884097, 8, 0, /* 5623: pointer.func */
            8884097, 8, 0, /* 5626: pointer.func */
            1, 8, 1, /* 5629: pointer.struct.srtp_protection_profile_st */
            	0, 0,
            0, 1, 0, /* 5634: char */
        },
        .arg_entity_index = { 3552, },
        .ret_entity_index = 3894,
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

