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
            0, 24, 1, /* 94: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 99: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 104: pointer.struct.stack_st_X509_NAME_ENTRY */
            	109, 0,
            0, 32, 2, /* 109: struct.stack_st_fake_X509_NAME_ENTRY */
            	116, 8,
            	86, 24,
            8884099, 8, 2, /* 116: pointer_to_array_of_pointers_to_stack */
            	123, 0,
            	83, 20,
            0, 8, 1, /* 123: pointer.X509_NAME_ENTRY */
            	128, 0,
            0, 0, 1, /* 128: X509_NAME_ENTRY */
            	133, 0,
            0, 24, 2, /* 133: struct.X509_name_entry_st */
            	140, 0,
            	154, 8,
            1, 8, 1, /* 140: pointer.struct.asn1_object_st */
            	145, 0,
            0, 40, 3, /* 145: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 154: pointer.struct.asn1_string_st */
            	159, 0,
            0, 24, 1, /* 159: struct.asn1_string_st */
            	78, 8,
            0, 40, 3, /* 164: struct.X509_name_st */
            	104, 0,
            	173, 16,
            	78, 24,
            1, 8, 1, /* 173: pointer.struct.buf_mem_st */
            	94, 0,
            1, 8, 1, /* 178: pointer.struct.X509_name_st */
            	164, 0,
            0, 8, 2, /* 183: union.unknown */
            	178, 0,
            	190, 0,
            1, 8, 1, /* 190: pointer.struct.asn1_string_st */
            	89, 0,
            1, 8, 1, /* 195: pointer.struct.stack_st_OCSP_RESPID */
            	200, 0,
            0, 32, 2, /* 200: struct.stack_st_fake_OCSP_RESPID */
            	207, 8,
            	86, 24,
            8884099, 8, 2, /* 207: pointer_to_array_of_pointers_to_stack */
            	214, 0,
            	83, 20,
            0, 8, 1, /* 214: pointer.OCSP_RESPID */
            	219, 0,
            0, 0, 1, /* 219: OCSP_RESPID */
            	224, 0,
            0, 16, 1, /* 224: struct.ocsp_responder_id_st */
            	183, 8,
            1, 8, 1, /* 229: pointer.struct.ssl_session_st */
            	234, 0,
            0, 352, 14, /* 234: struct.ssl_session_st */
            	99, 144,
            	99, 152,
            	265, 168,
            	1957, 176,
            	3211, 224,
            	3221, 240,
            	2417, 248,
            	3255, 264,
            	3255, 272,
            	99, 280,
            	78, 296,
            	78, 312,
            	78, 320,
            	99, 344,
            1, 8, 1, /* 265: pointer.struct.sess_cert_st */
            	270, 0,
            0, 248, 5, /* 270: struct.sess_cert_st */
            	283, 0,
            	1943, 16,
            	3196, 216,
            	3201, 224,
            	3206, 232,
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
            	99, 32,
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
            	99, 0,
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
            	128, 0,
            1, 8, 1, /* 574: pointer.struct.buf_mem_st */
            	579, 0,
            0, 24, 1, /* 579: struct.buf_mem_st */
            	99, 8,
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
            	99, 0,
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
            	99, 144,
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
            	99, 80,
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
            	99, 0,
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
            	99, 72,
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
            	99, 56,
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
            	99, 0,
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
            	99, 0,
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
            	99, 0,
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
            	99, 0,
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
            	99, 0,
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
            	128, 0,
            1, 8, 1, /* 1734: pointer.struct.buf_mem_st */
            	1739, 0,
            0, 24, 1, /* 1739: struct.buf_mem_st */
            	99, 8,
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
            	128, 0,
            1, 8, 1, /* 1780: pointer.struct.X509_name_st */
            	1785, 0,
            0, 40, 3, /* 1785: struct.X509_name_st */
            	1756, 0,
            	1794, 16,
            	78, 24,
            1, 8, 1, /* 1794: pointer.struct.buf_mem_st */
            	1799, 0,
            0, 24, 1, /* 1799: struct.buf_mem_st */
            	99, 8,
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
            	1902, 32,
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
            	1893, 0,
            0, 40, 3, /* 1893: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 1902: pointer.struct.stack_st_X509_ALGOR */
            	1907, 0,
            0, 32, 2, /* 1907: struct.stack_st_fake_X509_ALGOR */
            	1914, 8,
            	86, 24,
            8884099, 8, 2, /* 1914: pointer_to_array_of_pointers_to_stack */
            	1921, 0,
            	83, 20,
            0, 8, 1, /* 1921: pointer.X509_ALGOR */
            	1926, 0,
            0, 0, 1, /* 1926: X509_ALGOR */
            	1931, 0,
            0, 16, 2, /* 1931: struct.X509_algor_st */
            	1127, 0,
            	1938, 8,
            1, 8, 1, /* 1938: pointer.struct.asn1_type_st */
            	1069, 0,
            1, 8, 1, /* 1943: pointer.struct.cert_pkey_st */
            	1948, 0,
            0, 24, 3, /* 1948: struct.cert_pkey_st */
            	1957, 0,
            	2265, 8,
            	3151, 16,
            1, 8, 1, /* 1957: pointer.struct.x509_st */
            	1962, 0,
            0, 184, 12, /* 1962: struct.x509_st */
            	1989, 0,
            	2029, 8,
            	2118, 16,
            	99, 32,
            	2417, 40,
            	2123, 104,
            	2671, 112,
            	2709, 120,
            	2717, 128,
            	2741, 136,
            	2765, 144,
            	3085, 176,
            1, 8, 1, /* 1989: pointer.struct.x509_cinf_st */
            	1994, 0,
            0, 104, 11, /* 1994: struct.x509_cinf_st */
            	2019, 0,
            	2019, 8,
            	2029, 16,
            	2186, 24,
            	2234, 32,
            	2186, 40,
            	2251, 48,
            	2118, 56,
            	2118, 64,
            	2642, 72,
            	2666, 80,
            1, 8, 1, /* 2019: pointer.struct.asn1_string_st */
            	2024, 0,
            0, 24, 1, /* 2024: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 2029: pointer.struct.X509_algor_st */
            	2034, 0,
            0, 16, 2, /* 2034: struct.X509_algor_st */
            	2041, 0,
            	2055, 8,
            1, 8, 1, /* 2041: pointer.struct.asn1_object_st */
            	2046, 0,
            0, 40, 3, /* 2046: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 2055: pointer.struct.asn1_type_st */
            	2060, 0,
            0, 16, 1, /* 2060: struct.asn1_type_st */
            	2065, 8,
            0, 8, 20, /* 2065: union.unknown */
            	99, 0,
            	2108, 0,
            	2041, 0,
            	2019, 0,
            	2113, 0,
            	2118, 0,
            	2123, 0,
            	2128, 0,
            	2133, 0,
            	2138, 0,
            	2143, 0,
            	2148, 0,
            	2153, 0,
            	2158, 0,
            	2163, 0,
            	2168, 0,
            	2173, 0,
            	2108, 0,
            	2108, 0,
            	2178, 0,
            1, 8, 1, /* 2108: pointer.struct.asn1_string_st */
            	2024, 0,
            1, 8, 1, /* 2113: pointer.struct.asn1_string_st */
            	2024, 0,
            1, 8, 1, /* 2118: pointer.struct.asn1_string_st */
            	2024, 0,
            1, 8, 1, /* 2123: pointer.struct.asn1_string_st */
            	2024, 0,
            1, 8, 1, /* 2128: pointer.struct.asn1_string_st */
            	2024, 0,
            1, 8, 1, /* 2133: pointer.struct.asn1_string_st */
            	2024, 0,
            1, 8, 1, /* 2138: pointer.struct.asn1_string_st */
            	2024, 0,
            1, 8, 1, /* 2143: pointer.struct.asn1_string_st */
            	2024, 0,
            1, 8, 1, /* 2148: pointer.struct.asn1_string_st */
            	2024, 0,
            1, 8, 1, /* 2153: pointer.struct.asn1_string_st */
            	2024, 0,
            1, 8, 1, /* 2158: pointer.struct.asn1_string_st */
            	2024, 0,
            1, 8, 1, /* 2163: pointer.struct.asn1_string_st */
            	2024, 0,
            1, 8, 1, /* 2168: pointer.struct.asn1_string_st */
            	2024, 0,
            1, 8, 1, /* 2173: pointer.struct.asn1_string_st */
            	2024, 0,
            1, 8, 1, /* 2178: pointer.struct.ASN1_VALUE_st */
            	2183, 0,
            0, 0, 0, /* 2183: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2186: pointer.struct.X509_name_st */
            	2191, 0,
            0, 40, 3, /* 2191: struct.X509_name_st */
            	2200, 0,
            	2224, 16,
            	78, 24,
            1, 8, 1, /* 2200: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2205, 0,
            0, 32, 2, /* 2205: struct.stack_st_fake_X509_NAME_ENTRY */
            	2212, 8,
            	86, 24,
            8884099, 8, 2, /* 2212: pointer_to_array_of_pointers_to_stack */
            	2219, 0,
            	83, 20,
            0, 8, 1, /* 2219: pointer.X509_NAME_ENTRY */
            	128, 0,
            1, 8, 1, /* 2224: pointer.struct.buf_mem_st */
            	2229, 0,
            0, 24, 1, /* 2229: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 2234: pointer.struct.X509_val_st */
            	2239, 0,
            0, 16, 2, /* 2239: struct.X509_val_st */
            	2246, 0,
            	2246, 8,
            1, 8, 1, /* 2246: pointer.struct.asn1_string_st */
            	2024, 0,
            1, 8, 1, /* 2251: pointer.struct.X509_pubkey_st */
            	2256, 0,
            0, 24, 3, /* 2256: struct.X509_pubkey_st */
            	2029, 0,
            	2118, 8,
            	2265, 16,
            1, 8, 1, /* 2265: pointer.struct.evp_pkey_st */
            	2270, 0,
            0, 56, 4, /* 2270: struct.evp_pkey_st */
            	2281, 16,
            	2289, 24,
            	2297, 32,
            	2618, 48,
            1, 8, 1, /* 2281: pointer.struct.evp_pkey_asn1_method_st */
            	2286, 0,
            0, 0, 0, /* 2286: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 2289: pointer.struct.engine_st */
            	2294, 0,
            0, 0, 0, /* 2294: struct.engine_st */
            0, 8, 5, /* 2297: union.unknown */
            	99, 0,
            	2310, 0,
            	2461, 0,
            	2542, 0,
            	2610, 0,
            1, 8, 1, /* 2310: pointer.struct.rsa_st */
            	2315, 0,
            0, 168, 17, /* 2315: struct.rsa_st */
            	2352, 16,
            	2289, 24,
            	2407, 32,
            	2407, 40,
            	2407, 48,
            	2407, 56,
            	2407, 64,
            	2407, 72,
            	2407, 80,
            	2407, 88,
            	2417, 96,
            	2439, 120,
            	2439, 128,
            	2439, 136,
            	99, 144,
            	2453, 152,
            	2453, 160,
            1, 8, 1, /* 2352: pointer.struct.rsa_meth_st */
            	2357, 0,
            0, 112, 13, /* 2357: struct.rsa_meth_st */
            	5, 0,
            	2386, 8,
            	2386, 16,
            	2386, 24,
            	2386, 32,
            	2389, 40,
            	2392, 48,
            	2395, 56,
            	2395, 64,
            	99, 80,
            	2398, 88,
            	2401, 96,
            	2404, 104,
            8884097, 8, 0, /* 2386: pointer.func */
            8884097, 8, 0, /* 2389: pointer.func */
            8884097, 8, 0, /* 2392: pointer.func */
            8884097, 8, 0, /* 2395: pointer.func */
            8884097, 8, 0, /* 2398: pointer.func */
            8884097, 8, 0, /* 2401: pointer.func */
            8884097, 8, 0, /* 2404: pointer.func */
            1, 8, 1, /* 2407: pointer.struct.bignum_st */
            	2412, 0,
            0, 24, 1, /* 2412: struct.bignum_st */
            	767, 0,
            0, 16, 1, /* 2417: struct.crypto_ex_data_st */
            	2422, 0,
            1, 8, 1, /* 2422: pointer.struct.stack_st_void */
            	2427, 0,
            0, 32, 1, /* 2427: struct.stack_st_void */
            	2432, 0,
            0, 32, 2, /* 2432: struct.stack_st */
            	797, 8,
            	86, 24,
            1, 8, 1, /* 2439: pointer.struct.bn_mont_ctx_st */
            	2444, 0,
            0, 96, 3, /* 2444: struct.bn_mont_ctx_st */
            	2412, 8,
            	2412, 32,
            	2412, 56,
            1, 8, 1, /* 2453: pointer.struct.bn_blinding_st */
            	2458, 0,
            0, 0, 0, /* 2458: struct.bn_blinding_st */
            1, 8, 1, /* 2461: pointer.struct.dsa_st */
            	2466, 0,
            0, 136, 11, /* 2466: struct.dsa_st */
            	2407, 24,
            	2407, 32,
            	2407, 40,
            	2407, 48,
            	2407, 56,
            	2407, 64,
            	2407, 72,
            	2439, 88,
            	2417, 104,
            	2491, 120,
            	2289, 128,
            1, 8, 1, /* 2491: pointer.struct.dsa_method */
            	2496, 0,
            0, 96, 11, /* 2496: struct.dsa_method */
            	5, 0,
            	2521, 8,
            	2524, 16,
            	2527, 24,
            	2530, 32,
            	2533, 40,
            	2536, 48,
            	2536, 56,
            	99, 72,
            	2539, 80,
            	2536, 88,
            8884097, 8, 0, /* 2521: pointer.func */
            8884097, 8, 0, /* 2524: pointer.func */
            8884097, 8, 0, /* 2527: pointer.func */
            8884097, 8, 0, /* 2530: pointer.func */
            8884097, 8, 0, /* 2533: pointer.func */
            8884097, 8, 0, /* 2536: pointer.func */
            8884097, 8, 0, /* 2539: pointer.func */
            1, 8, 1, /* 2542: pointer.struct.dh_st */
            	2547, 0,
            0, 144, 12, /* 2547: struct.dh_st */
            	2407, 8,
            	2407, 16,
            	2407, 32,
            	2407, 40,
            	2439, 56,
            	2407, 64,
            	2407, 72,
            	78, 80,
            	2407, 96,
            	2417, 112,
            	2574, 128,
            	2289, 136,
            1, 8, 1, /* 2574: pointer.struct.dh_method */
            	2579, 0,
            0, 72, 8, /* 2579: struct.dh_method */
            	5, 0,
            	2598, 8,
            	2601, 16,
            	2604, 24,
            	2598, 32,
            	2598, 40,
            	99, 56,
            	2607, 64,
            8884097, 8, 0, /* 2598: pointer.func */
            8884097, 8, 0, /* 2601: pointer.func */
            8884097, 8, 0, /* 2604: pointer.func */
            8884097, 8, 0, /* 2607: pointer.func */
            1, 8, 1, /* 2610: pointer.struct.ec_key_st */
            	2615, 0,
            0, 0, 0, /* 2615: struct.ec_key_st */
            1, 8, 1, /* 2618: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2623, 0,
            0, 32, 2, /* 2623: struct.stack_st_fake_X509_ATTRIBUTE */
            	2630, 8,
            	86, 24,
            8884099, 8, 2, /* 2630: pointer_to_array_of_pointers_to_stack */
            	2637, 0,
            	83, 20,
            0, 8, 1, /* 2637: pointer.X509_ATTRIBUTE */
            	1005, 0,
            1, 8, 1, /* 2642: pointer.struct.stack_st_X509_EXTENSION */
            	2647, 0,
            0, 32, 2, /* 2647: struct.stack_st_fake_X509_EXTENSION */
            	2654, 8,
            	86, 24,
            8884099, 8, 2, /* 2654: pointer_to_array_of_pointers_to_stack */
            	2661, 0,
            	83, 20,
            0, 8, 1, /* 2661: pointer.X509_EXTENSION */
            	34, 0,
            0, 24, 1, /* 2666: struct.ASN1_ENCODING_st */
            	78, 0,
            1, 8, 1, /* 2671: pointer.struct.AUTHORITY_KEYID_st */
            	2676, 0,
            0, 24, 3, /* 2676: struct.AUTHORITY_KEYID_st */
            	2123, 0,
            	2685, 8,
            	2019, 16,
            1, 8, 1, /* 2685: pointer.struct.stack_st_GENERAL_NAME */
            	2690, 0,
            0, 32, 2, /* 2690: struct.stack_st_fake_GENERAL_NAME */
            	2697, 8,
            	86, 24,
            8884099, 8, 2, /* 2697: pointer_to_array_of_pointers_to_stack */
            	2704, 0,
            	83, 20,
            0, 8, 1, /* 2704: pointer.GENERAL_NAME */
            	1486, 0,
            1, 8, 1, /* 2709: pointer.struct.X509_POLICY_CACHE_st */
            	2714, 0,
            0, 0, 0, /* 2714: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 2717: pointer.struct.stack_st_DIST_POINT */
            	2722, 0,
            0, 32, 2, /* 2722: struct.stack_st_fake_DIST_POINT */
            	2729, 8,
            	86, 24,
            8884099, 8, 2, /* 2729: pointer_to_array_of_pointers_to_stack */
            	2736, 0,
            	83, 20,
            0, 8, 1, /* 2736: pointer.DIST_POINT */
            	1429, 0,
            1, 8, 1, /* 2741: pointer.struct.stack_st_GENERAL_NAME */
            	2746, 0,
            0, 32, 2, /* 2746: struct.stack_st_fake_GENERAL_NAME */
            	2753, 8,
            	86, 24,
            8884099, 8, 2, /* 2753: pointer_to_array_of_pointers_to_stack */
            	2760, 0,
            	83, 20,
            0, 8, 1, /* 2760: pointer.GENERAL_NAME */
            	1486, 0,
            1, 8, 1, /* 2765: pointer.struct.NAME_CONSTRAINTS_st */
            	2770, 0,
            0, 16, 2, /* 2770: struct.NAME_CONSTRAINTS_st */
            	2777, 0,
            	2777, 8,
            1, 8, 1, /* 2777: pointer.struct.stack_st_GENERAL_SUBTREE */
            	2782, 0,
            0, 32, 2, /* 2782: struct.stack_st_fake_GENERAL_SUBTREE */
            	2789, 8,
            	86, 24,
            8884099, 8, 2, /* 2789: pointer_to_array_of_pointers_to_stack */
            	2796, 0,
            	83, 20,
            0, 8, 1, /* 2796: pointer.GENERAL_SUBTREE */
            	2801, 0,
            0, 0, 1, /* 2801: GENERAL_SUBTREE */
            	2806, 0,
            0, 24, 3, /* 2806: struct.GENERAL_SUBTREE_st */
            	2815, 0,
            	2947, 8,
            	2947, 16,
            1, 8, 1, /* 2815: pointer.struct.GENERAL_NAME_st */
            	2820, 0,
            0, 16, 1, /* 2820: struct.GENERAL_NAME_st */
            	2825, 8,
            0, 8, 15, /* 2825: union.unknown */
            	99, 0,
            	2858, 0,
            	2977, 0,
            	2977, 0,
            	2884, 0,
            	3025, 0,
            	3073, 0,
            	2977, 0,
            	2962, 0,
            	2870, 0,
            	2962, 0,
            	3025, 0,
            	2977, 0,
            	2870, 0,
            	2884, 0,
            1, 8, 1, /* 2858: pointer.struct.otherName_st */
            	2863, 0,
            0, 16, 2, /* 2863: struct.otherName_st */
            	2870, 0,
            	2884, 8,
            1, 8, 1, /* 2870: pointer.struct.asn1_object_st */
            	2875, 0,
            0, 40, 3, /* 2875: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 2884: pointer.struct.asn1_type_st */
            	2889, 0,
            0, 16, 1, /* 2889: struct.asn1_type_st */
            	2894, 8,
            0, 8, 20, /* 2894: union.unknown */
            	99, 0,
            	2937, 0,
            	2870, 0,
            	2947, 0,
            	2952, 0,
            	2957, 0,
            	2962, 0,
            	2967, 0,
            	2972, 0,
            	2977, 0,
            	2982, 0,
            	2987, 0,
            	2992, 0,
            	2997, 0,
            	3002, 0,
            	3007, 0,
            	3012, 0,
            	2937, 0,
            	2937, 0,
            	3017, 0,
            1, 8, 1, /* 2937: pointer.struct.asn1_string_st */
            	2942, 0,
            0, 24, 1, /* 2942: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 2947: pointer.struct.asn1_string_st */
            	2942, 0,
            1, 8, 1, /* 2952: pointer.struct.asn1_string_st */
            	2942, 0,
            1, 8, 1, /* 2957: pointer.struct.asn1_string_st */
            	2942, 0,
            1, 8, 1, /* 2962: pointer.struct.asn1_string_st */
            	2942, 0,
            1, 8, 1, /* 2967: pointer.struct.asn1_string_st */
            	2942, 0,
            1, 8, 1, /* 2972: pointer.struct.asn1_string_st */
            	2942, 0,
            1, 8, 1, /* 2977: pointer.struct.asn1_string_st */
            	2942, 0,
            1, 8, 1, /* 2982: pointer.struct.asn1_string_st */
            	2942, 0,
            1, 8, 1, /* 2987: pointer.struct.asn1_string_st */
            	2942, 0,
            1, 8, 1, /* 2992: pointer.struct.asn1_string_st */
            	2942, 0,
            1, 8, 1, /* 2997: pointer.struct.asn1_string_st */
            	2942, 0,
            1, 8, 1, /* 3002: pointer.struct.asn1_string_st */
            	2942, 0,
            1, 8, 1, /* 3007: pointer.struct.asn1_string_st */
            	2942, 0,
            1, 8, 1, /* 3012: pointer.struct.asn1_string_st */
            	2942, 0,
            1, 8, 1, /* 3017: pointer.struct.ASN1_VALUE_st */
            	3022, 0,
            0, 0, 0, /* 3022: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3025: pointer.struct.X509_name_st */
            	3030, 0,
            0, 40, 3, /* 3030: struct.X509_name_st */
            	3039, 0,
            	3063, 16,
            	78, 24,
            1, 8, 1, /* 3039: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3044, 0,
            0, 32, 2, /* 3044: struct.stack_st_fake_X509_NAME_ENTRY */
            	3051, 8,
            	86, 24,
            8884099, 8, 2, /* 3051: pointer_to_array_of_pointers_to_stack */
            	3058, 0,
            	83, 20,
            0, 8, 1, /* 3058: pointer.X509_NAME_ENTRY */
            	128, 0,
            1, 8, 1, /* 3063: pointer.struct.buf_mem_st */
            	3068, 0,
            0, 24, 1, /* 3068: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 3073: pointer.struct.EDIPartyName_st */
            	3078, 0,
            0, 16, 2, /* 3078: struct.EDIPartyName_st */
            	2937, 0,
            	2937, 8,
            1, 8, 1, /* 3085: pointer.struct.x509_cert_aux_st */
            	3090, 0,
            0, 40, 5, /* 3090: struct.x509_cert_aux_st */
            	3103, 0,
            	3103, 8,
            	2173, 16,
            	2123, 24,
            	3127, 32,
            1, 8, 1, /* 3103: pointer.struct.stack_st_ASN1_OBJECT */
            	3108, 0,
            0, 32, 2, /* 3108: struct.stack_st_fake_ASN1_OBJECT */
            	3115, 8,
            	86, 24,
            8884099, 8, 2, /* 3115: pointer_to_array_of_pointers_to_stack */
            	3122, 0,
            	83, 20,
            0, 8, 1, /* 3122: pointer.ASN1_OBJECT */
            	1888, 0,
            1, 8, 1, /* 3127: pointer.struct.stack_st_X509_ALGOR */
            	3132, 0,
            0, 32, 2, /* 3132: struct.stack_st_fake_X509_ALGOR */
            	3139, 8,
            	86, 24,
            8884099, 8, 2, /* 3139: pointer_to_array_of_pointers_to_stack */
            	3146, 0,
            	83, 20,
            0, 8, 1, /* 3146: pointer.X509_ALGOR */
            	1926, 0,
            1, 8, 1, /* 3151: pointer.struct.env_md_st */
            	3156, 0,
            0, 120, 8, /* 3156: struct.env_md_st */
            	3175, 24,
            	3178, 32,
            	3181, 40,
            	3184, 48,
            	3175, 56,
            	3187, 64,
            	3190, 72,
            	3193, 112,
            8884097, 8, 0, /* 3175: pointer.func */
            8884097, 8, 0, /* 3178: pointer.func */
            8884097, 8, 0, /* 3181: pointer.func */
            8884097, 8, 0, /* 3184: pointer.func */
            8884097, 8, 0, /* 3187: pointer.func */
            8884097, 8, 0, /* 3190: pointer.func */
            8884097, 8, 0, /* 3193: pointer.func */
            1, 8, 1, /* 3196: pointer.struct.rsa_st */
            	2315, 0,
            1, 8, 1, /* 3201: pointer.struct.dh_st */
            	2547, 0,
            1, 8, 1, /* 3206: pointer.struct.ec_key_st */
            	2615, 0,
            1, 8, 1, /* 3211: pointer.struct.ssl_cipher_st */
            	3216, 0,
            0, 88, 1, /* 3216: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 3221: pointer.struct.stack_st_SSL_CIPHER */
            	3226, 0,
            0, 32, 2, /* 3226: struct.stack_st_fake_SSL_CIPHER */
            	3233, 8,
            	86, 24,
            8884099, 8, 2, /* 3233: pointer_to_array_of_pointers_to_stack */
            	3240, 0,
            	83, 20,
            0, 8, 1, /* 3240: pointer.SSL_CIPHER */
            	3245, 0,
            0, 0, 1, /* 3245: SSL_CIPHER */
            	3250, 0,
            0, 88, 1, /* 3250: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 3255: pointer.struct.ssl_session_st */
            	234, 0,
            0, 56, 2, /* 3260: struct.comp_ctx_st */
            	3267, 0,
            	2417, 40,
            1, 8, 1, /* 3267: pointer.struct.comp_method_st */
            	3272, 0,
            0, 64, 7, /* 3272: struct.comp_method_st */
            	5, 8,
            	3289, 16,
            	3292, 24,
            	3295, 32,
            	3295, 40,
            	3298, 48,
            	3298, 56,
            8884097, 8, 0, /* 3289: pointer.func */
            8884097, 8, 0, /* 3292: pointer.func */
            8884097, 8, 0, /* 3295: pointer.func */
            8884097, 8, 0, /* 3298: pointer.func */
            1, 8, 1, /* 3301: pointer.struct.comp_ctx_st */
            	3260, 0,
            1, 8, 1, /* 3306: pointer.struct._pqueue */
            	3311, 0,
            0, 0, 0, /* 3311: struct._pqueue */
            0, 16, 1, /* 3314: struct.record_pqueue_st */
            	3306, 8,
            0, 888, 7, /* 3319: struct.dtls1_state_st */
            	3314, 576,
            	3314, 592,
            	3306, 608,
            	3306, 616,
            	3314, 624,
            	3336, 648,
            	3336, 736,
            0, 88, 1, /* 3336: struct.hm_header_st */
            	3341, 48,
            0, 40, 4, /* 3341: struct.dtls1_retransmit_state */
            	3352, 0,
            	3408, 8,
            	3301, 16,
            	229, 24,
            1, 8, 1, /* 3352: pointer.struct.evp_cipher_ctx_st */
            	3357, 0,
            0, 168, 4, /* 3357: struct.evp_cipher_ctx_st */
            	3368, 0,
            	2289, 8,
            	3405, 96,
            	3405, 120,
            1, 8, 1, /* 3368: pointer.struct.evp_cipher_st */
            	3373, 0,
            0, 88, 7, /* 3373: struct.evp_cipher_st */
            	3390, 24,
            	3393, 32,
            	3396, 40,
            	3399, 56,
            	3399, 64,
            	3402, 72,
            	3405, 80,
            8884097, 8, 0, /* 3390: pointer.func */
            8884097, 8, 0, /* 3393: pointer.func */
            8884097, 8, 0, /* 3396: pointer.func */
            8884097, 8, 0, /* 3399: pointer.func */
            8884097, 8, 0, /* 3402: pointer.func */
            0, 8, 0, /* 3405: pointer.void */
            1, 8, 1, /* 3408: pointer.struct.env_md_ctx_st */
            	3413, 0,
            0, 48, 5, /* 3413: struct.env_md_ctx_st */
            	3151, 0,
            	2289, 8,
            	3405, 24,
            	3426, 32,
            	3178, 40,
            1, 8, 1, /* 3426: pointer.struct.evp_pkey_ctx_st */
            	3431, 0,
            0, 0, 0, /* 3431: struct.evp_pkey_ctx_st */
            0, 24, 2, /* 3434: struct.ssl_comp_st */
            	5, 8,
            	3267, 16,
            1, 8, 1, /* 3441: pointer.pointer.struct.env_md_ctx_st */
            	3408, 0,
            0, 24, 1, /* 3446: struct.ssl3_buffer_st */
            	78, 0,
            0, 1200, 10, /* 3451: struct.ssl3_state_st */
            	3446, 240,
            	3446, 264,
            	3474, 288,
            	3474, 344,
            	60, 432,
            	3483, 440,
            	3441, 448,
            	3405, 496,
            	3405, 512,
            	3557, 528,
            0, 56, 3, /* 3474: struct.ssl3_record_st */
            	78, 16,
            	78, 24,
            	78, 32,
            1, 8, 1, /* 3483: pointer.struct.bio_st */
            	3488, 0,
            0, 112, 7, /* 3488: struct.bio_st */
            	3505, 0,
            	3549, 8,
            	99, 16,
            	3405, 48,
            	3552, 56,
            	3552, 64,
            	2417, 96,
            1, 8, 1, /* 3505: pointer.struct.bio_method_st */
            	3510, 0,
            0, 80, 9, /* 3510: struct.bio_method_st */
            	5, 8,
            	3531, 16,
            	3534, 24,
            	3537, 32,
            	3534, 40,
            	3540, 48,
            	3543, 56,
            	3543, 64,
            	3546, 72,
            8884097, 8, 0, /* 3531: pointer.func */
            8884097, 8, 0, /* 3534: pointer.func */
            8884097, 8, 0, /* 3537: pointer.func */
            8884097, 8, 0, /* 3540: pointer.func */
            8884097, 8, 0, /* 3543: pointer.func */
            8884097, 8, 0, /* 3546: pointer.func */
            8884097, 8, 0, /* 3549: pointer.func */
            1, 8, 1, /* 3552: pointer.struct.bio_st */
            	3488, 0,
            0, 528, 8, /* 3557: struct.unknown */
            	3211, 408,
            	3201, 416,
            	3206, 424,
            	3576, 464,
            	78, 480,
            	3368, 488,
            	3151, 496,
            	3605, 512,
            1, 8, 1, /* 3576: pointer.struct.stack_st_X509_NAME */
            	3581, 0,
            0, 32, 2, /* 3581: struct.stack_st_fake_X509_NAME */
            	3588, 8,
            	86, 24,
            8884099, 8, 2, /* 3588: pointer_to_array_of_pointers_to_stack */
            	3595, 0,
            	83, 20,
            0, 8, 1, /* 3595: pointer.X509_NAME */
            	3600, 0,
            0, 0, 1, /* 3600: X509_NAME */
            	541, 0,
            1, 8, 1, /* 3605: pointer.struct.ssl_comp_st */
            	3434, 0,
            1, 8, 1, /* 3610: pointer.struct.ssl3_state_st */
            	3451, 0,
            1, 8, 1, /* 3615: pointer.struct.ssl_st */
            	3620, 0,
            0, 808, 51, /* 3620: struct.ssl_st */
            	3725, 8,
            	3483, 16,
            	3483, 24,
            	3483, 32,
            	3789, 48,
            	2224, 80,
            	3405, 88,
            	78, 104,
            	3891, 120,
            	3610, 128,
            	3917, 136,
            	3922, 152,
            	3405, 160,
            	3925, 176,
            	3221, 184,
            	3221, 192,
            	3352, 208,
            	3408, 216,
            	3301, 224,
            	3352, 232,
            	3408, 240,
            	3301, 248,
            	3937, 256,
            	229, 304,
            	3968, 312,
            	3971, 328,
            	3974, 336,
            	3977, 352,
            	3980, 360,
            	3983, 368,
            	2417, 392,
            	3576, 408,
            	5702, 464,
            	3405, 472,
            	99, 480,
            	195, 504,
            	10, 512,
            	78, 520,
            	78, 544,
            	78, 560,
            	3405, 568,
            	5705, 584,
            	5715, 592,
            	3405, 600,
            	5718, 608,
            	3405, 616,
            	3983, 624,
            	78, 632,
            	5668, 648,
            	5721, 656,
            	5628, 680,
            1, 8, 1, /* 3725: pointer.struct.ssl_method_st */
            	3730, 0,
            0, 232, 28, /* 3730: struct.ssl_method_st */
            	3789, 8,
            	3792, 16,
            	3792, 24,
            	3789, 32,
            	3789, 40,
            	3795, 48,
            	3795, 56,
            	3798, 64,
            	3789, 72,
            	3789, 80,
            	3789, 88,
            	3801, 96,
            	3804, 104,
            	3807, 112,
            	3789, 120,
            	3810, 128,
            	3813, 136,
            	3816, 144,
            	3819, 152,
            	3822, 160,
            	3825, 168,
            	3828, 176,
            	3831, 184,
            	3298, 192,
            	3834, 200,
            	3825, 208,
            	3885, 216,
            	3888, 224,
            8884097, 8, 0, /* 3789: pointer.func */
            8884097, 8, 0, /* 3792: pointer.func */
            8884097, 8, 0, /* 3795: pointer.func */
            8884097, 8, 0, /* 3798: pointer.func */
            8884097, 8, 0, /* 3801: pointer.func */
            8884097, 8, 0, /* 3804: pointer.func */
            8884097, 8, 0, /* 3807: pointer.func */
            8884097, 8, 0, /* 3810: pointer.func */
            8884097, 8, 0, /* 3813: pointer.func */
            8884097, 8, 0, /* 3816: pointer.func */
            8884097, 8, 0, /* 3819: pointer.func */
            8884097, 8, 0, /* 3822: pointer.func */
            8884097, 8, 0, /* 3825: pointer.func */
            8884097, 8, 0, /* 3828: pointer.func */
            8884097, 8, 0, /* 3831: pointer.func */
            1, 8, 1, /* 3834: pointer.struct.ssl3_enc_method */
            	3839, 0,
            0, 112, 11, /* 3839: struct.ssl3_enc_method */
            	3864, 0,
            	3867, 8,
            	3789, 16,
            	3870, 24,
            	3864, 32,
            	3873, 40,
            	3876, 56,
            	5, 64,
            	5, 80,
            	3879, 96,
            	3882, 104,
            8884097, 8, 0, /* 3864: pointer.func */
            8884097, 8, 0, /* 3867: pointer.func */
            8884097, 8, 0, /* 3870: pointer.func */
            8884097, 8, 0, /* 3873: pointer.func */
            8884097, 8, 0, /* 3876: pointer.func */
            8884097, 8, 0, /* 3879: pointer.func */
            8884097, 8, 0, /* 3882: pointer.func */
            8884097, 8, 0, /* 3885: pointer.func */
            8884097, 8, 0, /* 3888: pointer.func */
            1, 8, 1, /* 3891: pointer.struct.ssl2_state_st */
            	3896, 0,
            0, 344, 9, /* 3896: struct.ssl2_state_st */
            	60, 24,
            	78, 56,
            	78, 64,
            	78, 72,
            	78, 104,
            	78, 112,
            	78, 120,
            	78, 128,
            	78, 136,
            1, 8, 1, /* 3917: pointer.struct.dtls1_state_st */
            	3319, 0,
            8884097, 8, 0, /* 3922: pointer.func */
            1, 8, 1, /* 3925: pointer.struct.X509_VERIFY_PARAM_st */
            	3930, 0,
            0, 56, 2, /* 3930: struct.X509_VERIFY_PARAM_st */
            	99, 0,
            	3103, 48,
            1, 8, 1, /* 3937: pointer.struct.cert_st */
            	3942, 0,
            0, 296, 7, /* 3942: struct.cert_st */
            	1943, 0,
            	3196, 48,
            	3959, 56,
            	3201, 64,
            	3962, 72,
            	3206, 80,
            	3965, 88,
            8884097, 8, 0, /* 3959: pointer.func */
            8884097, 8, 0, /* 3962: pointer.func */
            8884097, 8, 0, /* 3965: pointer.func */
            8884097, 8, 0, /* 3968: pointer.func */
            8884097, 8, 0, /* 3971: pointer.func */
            8884097, 8, 0, /* 3974: pointer.func */
            8884097, 8, 0, /* 3977: pointer.func */
            8884097, 8, 0, /* 3980: pointer.func */
            1, 8, 1, /* 3983: pointer.struct.ssl_ctx_st */
            	3988, 0,
            0, 736, 50, /* 3988: struct.ssl_ctx_st */
            	3725, 0,
            	3221, 8,
            	3221, 16,
            	4091, 24,
            	5466, 32,
            	3255, 48,
            	3255, 56,
            	5505, 80,
            	5508, 88,
            	5511, 96,
            	5514, 152,
            	3405, 160,
            	5517, 168,
            	3405, 176,
            	5520, 184,
            	5523, 192,
            	5526, 200,
            	2417, 208,
            	3151, 224,
            	3151, 232,
            	3151, 240,
            	283, 248,
            	5529, 256,
            	3974, 264,
            	3576, 272,
            	3937, 304,
            	3922, 320,
            	3405, 328,
            	3971, 376,
            	3968, 384,
            	3925, 392,
            	2289, 408,
            	5596, 416,
            	3405, 424,
            	5599, 480,
            	5602, 488,
            	3405, 496,
            	5605, 504,
            	3405, 512,
            	99, 520,
            	3977, 528,
            	3980, 536,
            	5608, 552,
            	5608, 560,
            	5628, 568,
            	5662, 696,
            	3405, 704,
            	5665, 712,
            	3405, 720,
            	5668, 728,
            1, 8, 1, /* 4091: pointer.struct.x509_store_st */
            	4096, 0,
            0, 144, 15, /* 4096: struct.x509_store_st */
            	4129, 8,
            	5230, 16,
            	3925, 24,
            	5442, 32,
            	3971, 40,
            	5445, 48,
            	5448, 56,
            	5442, 64,
            	5451, 72,
            	5454, 80,
            	5457, 88,
            	5460, 96,
            	5463, 104,
            	5442, 112,
            	2417, 120,
            1, 8, 1, /* 4129: pointer.struct.stack_st_X509_OBJECT */
            	4134, 0,
            0, 32, 2, /* 4134: struct.stack_st_fake_X509_OBJECT */
            	4141, 8,
            	86, 24,
            8884099, 8, 2, /* 4141: pointer_to_array_of_pointers_to_stack */
            	4148, 0,
            	83, 20,
            0, 8, 1, /* 4148: pointer.X509_OBJECT */
            	4153, 0,
            0, 0, 1, /* 4153: X509_OBJECT */
            	4158, 0,
            0, 16, 1, /* 4158: struct.x509_object_st */
            	4163, 8,
            0, 8, 4, /* 4163: union.unknown */
            	99, 0,
            	4174, 0,
            	5018, 0,
            	4474, 0,
            1, 8, 1, /* 4174: pointer.struct.x509_st */
            	4179, 0,
            0, 184, 12, /* 4179: struct.x509_st */
            	4206, 0,
            	4246, 8,
            	4335, 16,
            	99, 32,
            	4626, 40,
            	4340, 104,
            	4880, 112,
            	4888, 120,
            	4896, 128,
            	4920, 136,
            	4944, 144,
            	4952, 176,
            1, 8, 1, /* 4206: pointer.struct.x509_cinf_st */
            	4211, 0,
            0, 104, 11, /* 4211: struct.x509_cinf_st */
            	4236, 0,
            	4236, 8,
            	4246, 16,
            	4395, 24,
            	4443, 32,
            	4395, 40,
            	4460, 48,
            	4335, 56,
            	4335, 64,
            	4851, 72,
            	4875, 80,
            1, 8, 1, /* 4236: pointer.struct.asn1_string_st */
            	4241, 0,
            0, 24, 1, /* 4241: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 4246: pointer.struct.X509_algor_st */
            	4251, 0,
            0, 16, 2, /* 4251: struct.X509_algor_st */
            	4258, 0,
            	4272, 8,
            1, 8, 1, /* 4258: pointer.struct.asn1_object_st */
            	4263, 0,
            0, 40, 3, /* 4263: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 4272: pointer.struct.asn1_type_st */
            	4277, 0,
            0, 16, 1, /* 4277: struct.asn1_type_st */
            	4282, 8,
            0, 8, 20, /* 4282: union.unknown */
            	99, 0,
            	4325, 0,
            	4258, 0,
            	4236, 0,
            	4330, 0,
            	4335, 0,
            	4340, 0,
            	4345, 0,
            	4350, 0,
            	4355, 0,
            	4360, 0,
            	4365, 0,
            	4370, 0,
            	4375, 0,
            	4380, 0,
            	4385, 0,
            	4390, 0,
            	4325, 0,
            	4325, 0,
            	1352, 0,
            1, 8, 1, /* 4325: pointer.struct.asn1_string_st */
            	4241, 0,
            1, 8, 1, /* 4330: pointer.struct.asn1_string_st */
            	4241, 0,
            1, 8, 1, /* 4335: pointer.struct.asn1_string_st */
            	4241, 0,
            1, 8, 1, /* 4340: pointer.struct.asn1_string_st */
            	4241, 0,
            1, 8, 1, /* 4345: pointer.struct.asn1_string_st */
            	4241, 0,
            1, 8, 1, /* 4350: pointer.struct.asn1_string_st */
            	4241, 0,
            1, 8, 1, /* 4355: pointer.struct.asn1_string_st */
            	4241, 0,
            1, 8, 1, /* 4360: pointer.struct.asn1_string_st */
            	4241, 0,
            1, 8, 1, /* 4365: pointer.struct.asn1_string_st */
            	4241, 0,
            1, 8, 1, /* 4370: pointer.struct.asn1_string_st */
            	4241, 0,
            1, 8, 1, /* 4375: pointer.struct.asn1_string_st */
            	4241, 0,
            1, 8, 1, /* 4380: pointer.struct.asn1_string_st */
            	4241, 0,
            1, 8, 1, /* 4385: pointer.struct.asn1_string_st */
            	4241, 0,
            1, 8, 1, /* 4390: pointer.struct.asn1_string_st */
            	4241, 0,
            1, 8, 1, /* 4395: pointer.struct.X509_name_st */
            	4400, 0,
            0, 40, 3, /* 4400: struct.X509_name_st */
            	4409, 0,
            	4433, 16,
            	78, 24,
            1, 8, 1, /* 4409: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4414, 0,
            0, 32, 2, /* 4414: struct.stack_st_fake_X509_NAME_ENTRY */
            	4421, 8,
            	86, 24,
            8884099, 8, 2, /* 4421: pointer_to_array_of_pointers_to_stack */
            	4428, 0,
            	83, 20,
            0, 8, 1, /* 4428: pointer.X509_NAME_ENTRY */
            	128, 0,
            1, 8, 1, /* 4433: pointer.struct.buf_mem_st */
            	4438, 0,
            0, 24, 1, /* 4438: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 4443: pointer.struct.X509_val_st */
            	4448, 0,
            0, 16, 2, /* 4448: struct.X509_val_st */
            	4455, 0,
            	4455, 8,
            1, 8, 1, /* 4455: pointer.struct.asn1_string_st */
            	4241, 0,
            1, 8, 1, /* 4460: pointer.struct.X509_pubkey_st */
            	4465, 0,
            0, 24, 3, /* 4465: struct.X509_pubkey_st */
            	4246, 0,
            	4335, 8,
            	4474, 16,
            1, 8, 1, /* 4474: pointer.struct.evp_pkey_st */
            	4479, 0,
            0, 56, 4, /* 4479: struct.evp_pkey_st */
            	4490, 16,
            	4498, 24,
            	4506, 32,
            	4827, 48,
            1, 8, 1, /* 4490: pointer.struct.evp_pkey_asn1_method_st */
            	4495, 0,
            0, 0, 0, /* 4495: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 4498: pointer.struct.engine_st */
            	4503, 0,
            0, 0, 0, /* 4503: struct.engine_st */
            0, 8, 5, /* 4506: union.unknown */
            	99, 0,
            	4519, 0,
            	4670, 0,
            	4751, 0,
            	4819, 0,
            1, 8, 1, /* 4519: pointer.struct.rsa_st */
            	4524, 0,
            0, 168, 17, /* 4524: struct.rsa_st */
            	4561, 16,
            	4498, 24,
            	4616, 32,
            	4616, 40,
            	4616, 48,
            	4616, 56,
            	4616, 64,
            	4616, 72,
            	4616, 80,
            	4616, 88,
            	4626, 96,
            	4648, 120,
            	4648, 128,
            	4648, 136,
            	99, 144,
            	4662, 152,
            	4662, 160,
            1, 8, 1, /* 4561: pointer.struct.rsa_meth_st */
            	4566, 0,
            0, 112, 13, /* 4566: struct.rsa_meth_st */
            	5, 0,
            	4595, 8,
            	4595, 16,
            	4595, 24,
            	4595, 32,
            	4598, 40,
            	4601, 48,
            	4604, 56,
            	4604, 64,
            	99, 80,
            	4607, 88,
            	4610, 96,
            	4613, 104,
            8884097, 8, 0, /* 4595: pointer.func */
            8884097, 8, 0, /* 4598: pointer.func */
            8884097, 8, 0, /* 4601: pointer.func */
            8884097, 8, 0, /* 4604: pointer.func */
            8884097, 8, 0, /* 4607: pointer.func */
            8884097, 8, 0, /* 4610: pointer.func */
            8884097, 8, 0, /* 4613: pointer.func */
            1, 8, 1, /* 4616: pointer.struct.bignum_st */
            	4621, 0,
            0, 24, 1, /* 4621: struct.bignum_st */
            	767, 0,
            0, 16, 1, /* 4626: struct.crypto_ex_data_st */
            	4631, 0,
            1, 8, 1, /* 4631: pointer.struct.stack_st_void */
            	4636, 0,
            0, 32, 1, /* 4636: struct.stack_st_void */
            	4641, 0,
            0, 32, 2, /* 4641: struct.stack_st */
            	797, 8,
            	86, 24,
            1, 8, 1, /* 4648: pointer.struct.bn_mont_ctx_st */
            	4653, 0,
            0, 96, 3, /* 4653: struct.bn_mont_ctx_st */
            	4621, 8,
            	4621, 32,
            	4621, 56,
            1, 8, 1, /* 4662: pointer.struct.bn_blinding_st */
            	4667, 0,
            0, 0, 0, /* 4667: struct.bn_blinding_st */
            1, 8, 1, /* 4670: pointer.struct.dsa_st */
            	4675, 0,
            0, 136, 11, /* 4675: struct.dsa_st */
            	4616, 24,
            	4616, 32,
            	4616, 40,
            	4616, 48,
            	4616, 56,
            	4616, 64,
            	4616, 72,
            	4648, 88,
            	4626, 104,
            	4700, 120,
            	4498, 128,
            1, 8, 1, /* 4700: pointer.struct.dsa_method */
            	4705, 0,
            0, 96, 11, /* 4705: struct.dsa_method */
            	5, 0,
            	4730, 8,
            	4733, 16,
            	4736, 24,
            	4739, 32,
            	4742, 40,
            	4745, 48,
            	4745, 56,
            	99, 72,
            	4748, 80,
            	4745, 88,
            8884097, 8, 0, /* 4730: pointer.func */
            8884097, 8, 0, /* 4733: pointer.func */
            8884097, 8, 0, /* 4736: pointer.func */
            8884097, 8, 0, /* 4739: pointer.func */
            8884097, 8, 0, /* 4742: pointer.func */
            8884097, 8, 0, /* 4745: pointer.func */
            8884097, 8, 0, /* 4748: pointer.func */
            1, 8, 1, /* 4751: pointer.struct.dh_st */
            	4756, 0,
            0, 144, 12, /* 4756: struct.dh_st */
            	4616, 8,
            	4616, 16,
            	4616, 32,
            	4616, 40,
            	4648, 56,
            	4616, 64,
            	4616, 72,
            	78, 80,
            	4616, 96,
            	4626, 112,
            	4783, 128,
            	4498, 136,
            1, 8, 1, /* 4783: pointer.struct.dh_method */
            	4788, 0,
            0, 72, 8, /* 4788: struct.dh_method */
            	5, 0,
            	4807, 8,
            	4810, 16,
            	4813, 24,
            	4807, 32,
            	4807, 40,
            	99, 56,
            	4816, 64,
            8884097, 8, 0, /* 4807: pointer.func */
            8884097, 8, 0, /* 4810: pointer.func */
            8884097, 8, 0, /* 4813: pointer.func */
            8884097, 8, 0, /* 4816: pointer.func */
            1, 8, 1, /* 4819: pointer.struct.ec_key_st */
            	4824, 0,
            0, 0, 0, /* 4824: struct.ec_key_st */
            1, 8, 1, /* 4827: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4832, 0,
            0, 32, 2, /* 4832: struct.stack_st_fake_X509_ATTRIBUTE */
            	4839, 8,
            	86, 24,
            8884099, 8, 2, /* 4839: pointer_to_array_of_pointers_to_stack */
            	4846, 0,
            	83, 20,
            0, 8, 1, /* 4846: pointer.X509_ATTRIBUTE */
            	1005, 0,
            1, 8, 1, /* 4851: pointer.struct.stack_st_X509_EXTENSION */
            	4856, 0,
            0, 32, 2, /* 4856: struct.stack_st_fake_X509_EXTENSION */
            	4863, 8,
            	86, 24,
            8884099, 8, 2, /* 4863: pointer_to_array_of_pointers_to_stack */
            	4870, 0,
            	83, 20,
            0, 8, 1, /* 4870: pointer.X509_EXTENSION */
            	34, 0,
            0, 24, 1, /* 4875: struct.ASN1_ENCODING_st */
            	78, 0,
            1, 8, 1, /* 4880: pointer.struct.AUTHORITY_KEYID_st */
            	4885, 0,
            0, 0, 0, /* 4885: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4888: pointer.struct.X509_POLICY_CACHE_st */
            	4893, 0,
            0, 0, 0, /* 4893: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 4896: pointer.struct.stack_st_DIST_POINT */
            	4901, 0,
            0, 32, 2, /* 4901: struct.stack_st_fake_DIST_POINT */
            	4908, 8,
            	86, 24,
            8884099, 8, 2, /* 4908: pointer_to_array_of_pointers_to_stack */
            	4915, 0,
            	83, 20,
            0, 8, 1, /* 4915: pointer.DIST_POINT */
            	1429, 0,
            1, 8, 1, /* 4920: pointer.struct.stack_st_GENERAL_NAME */
            	4925, 0,
            0, 32, 2, /* 4925: struct.stack_st_fake_GENERAL_NAME */
            	4932, 8,
            	86, 24,
            8884099, 8, 2, /* 4932: pointer_to_array_of_pointers_to_stack */
            	4939, 0,
            	83, 20,
            0, 8, 1, /* 4939: pointer.GENERAL_NAME */
            	1486, 0,
            1, 8, 1, /* 4944: pointer.struct.NAME_CONSTRAINTS_st */
            	4949, 0,
            0, 0, 0, /* 4949: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4952: pointer.struct.x509_cert_aux_st */
            	4957, 0,
            0, 40, 5, /* 4957: struct.x509_cert_aux_st */
            	4970, 0,
            	4970, 8,
            	4390, 16,
            	4340, 24,
            	4994, 32,
            1, 8, 1, /* 4970: pointer.struct.stack_st_ASN1_OBJECT */
            	4975, 0,
            0, 32, 2, /* 4975: struct.stack_st_fake_ASN1_OBJECT */
            	4982, 8,
            	86, 24,
            8884099, 8, 2, /* 4982: pointer_to_array_of_pointers_to_stack */
            	4989, 0,
            	83, 20,
            0, 8, 1, /* 4989: pointer.ASN1_OBJECT */
            	1888, 0,
            1, 8, 1, /* 4994: pointer.struct.stack_st_X509_ALGOR */
            	4999, 0,
            0, 32, 2, /* 4999: struct.stack_st_fake_X509_ALGOR */
            	5006, 8,
            	86, 24,
            8884099, 8, 2, /* 5006: pointer_to_array_of_pointers_to_stack */
            	5013, 0,
            	83, 20,
            0, 8, 1, /* 5013: pointer.X509_ALGOR */
            	1926, 0,
            1, 8, 1, /* 5018: pointer.struct.X509_crl_st */
            	5023, 0,
            0, 120, 10, /* 5023: struct.X509_crl_st */
            	5046, 0,
            	4246, 8,
            	4335, 16,
            	4880, 32,
            	5173, 40,
            	4236, 56,
            	4236, 64,
            	5181, 96,
            	5222, 104,
            	3405, 112,
            1, 8, 1, /* 5046: pointer.struct.X509_crl_info_st */
            	5051, 0,
            0, 80, 8, /* 5051: struct.X509_crl_info_st */
            	4236, 0,
            	4246, 8,
            	4395, 16,
            	4455, 24,
            	4455, 32,
            	5070, 40,
            	4851, 48,
            	4875, 56,
            1, 8, 1, /* 5070: pointer.struct.stack_st_X509_REVOKED */
            	5075, 0,
            0, 32, 2, /* 5075: struct.stack_st_fake_X509_REVOKED */
            	5082, 8,
            	86, 24,
            8884099, 8, 2, /* 5082: pointer_to_array_of_pointers_to_stack */
            	5089, 0,
            	83, 20,
            0, 8, 1, /* 5089: pointer.X509_REVOKED */
            	5094, 0,
            0, 0, 1, /* 5094: X509_REVOKED */
            	5099, 0,
            0, 40, 4, /* 5099: struct.x509_revoked_st */
            	5110, 0,
            	5120, 8,
            	5125, 16,
            	5149, 24,
            1, 8, 1, /* 5110: pointer.struct.asn1_string_st */
            	5115, 0,
            0, 24, 1, /* 5115: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 5120: pointer.struct.asn1_string_st */
            	5115, 0,
            1, 8, 1, /* 5125: pointer.struct.stack_st_X509_EXTENSION */
            	5130, 0,
            0, 32, 2, /* 5130: struct.stack_st_fake_X509_EXTENSION */
            	5137, 8,
            	86, 24,
            8884099, 8, 2, /* 5137: pointer_to_array_of_pointers_to_stack */
            	5144, 0,
            	83, 20,
            0, 8, 1, /* 5144: pointer.X509_EXTENSION */
            	34, 0,
            1, 8, 1, /* 5149: pointer.struct.stack_st_GENERAL_NAME */
            	5154, 0,
            0, 32, 2, /* 5154: struct.stack_st_fake_GENERAL_NAME */
            	5161, 8,
            	86, 24,
            8884099, 8, 2, /* 5161: pointer_to_array_of_pointers_to_stack */
            	5168, 0,
            	83, 20,
            0, 8, 1, /* 5168: pointer.GENERAL_NAME */
            	1486, 0,
            1, 8, 1, /* 5173: pointer.struct.ISSUING_DIST_POINT_st */
            	5178, 0,
            0, 0, 0, /* 5178: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 5181: pointer.struct.stack_st_GENERAL_NAMES */
            	5186, 0,
            0, 32, 2, /* 5186: struct.stack_st_fake_GENERAL_NAMES */
            	5193, 8,
            	86, 24,
            8884099, 8, 2, /* 5193: pointer_to_array_of_pointers_to_stack */
            	5200, 0,
            	83, 20,
            0, 8, 1, /* 5200: pointer.GENERAL_NAMES */
            	5205, 0,
            0, 0, 1, /* 5205: GENERAL_NAMES */
            	5210, 0,
            0, 32, 1, /* 5210: struct.stack_st_GENERAL_NAME */
            	5215, 0,
            0, 32, 2, /* 5215: struct.stack_st */
            	797, 8,
            	86, 24,
            1, 8, 1, /* 5222: pointer.struct.x509_crl_method_st */
            	5227, 0,
            0, 0, 0, /* 5227: struct.x509_crl_method_st */
            1, 8, 1, /* 5230: pointer.struct.stack_st_X509_LOOKUP */
            	5235, 0,
            0, 32, 2, /* 5235: struct.stack_st_fake_X509_LOOKUP */
            	5242, 8,
            	86, 24,
            8884099, 8, 2, /* 5242: pointer_to_array_of_pointers_to_stack */
            	5249, 0,
            	83, 20,
            0, 8, 1, /* 5249: pointer.X509_LOOKUP */
            	5254, 0,
            0, 0, 1, /* 5254: X509_LOOKUP */
            	5259, 0,
            0, 32, 3, /* 5259: struct.x509_lookup_st */
            	5268, 8,
            	99, 16,
            	5317, 24,
            1, 8, 1, /* 5268: pointer.struct.x509_lookup_method_st */
            	5273, 0,
            0, 80, 10, /* 5273: struct.x509_lookup_method_st */
            	5, 0,
            	5296, 8,
            	5299, 16,
            	5296, 24,
            	5296, 32,
            	5302, 40,
            	5305, 48,
            	5308, 56,
            	5311, 64,
            	5314, 72,
            8884097, 8, 0, /* 5296: pointer.func */
            8884097, 8, 0, /* 5299: pointer.func */
            8884097, 8, 0, /* 5302: pointer.func */
            8884097, 8, 0, /* 5305: pointer.func */
            8884097, 8, 0, /* 5308: pointer.func */
            8884097, 8, 0, /* 5311: pointer.func */
            8884097, 8, 0, /* 5314: pointer.func */
            1, 8, 1, /* 5317: pointer.struct.x509_store_st */
            	5322, 0,
            0, 144, 15, /* 5322: struct.x509_store_st */
            	5355, 8,
            	5379, 16,
            	5403, 24,
            	5415, 32,
            	5418, 40,
            	5421, 48,
            	5424, 56,
            	5415, 64,
            	5427, 72,
            	5430, 80,
            	5433, 88,
            	5436, 96,
            	5439, 104,
            	5415, 112,
            	4626, 120,
            1, 8, 1, /* 5355: pointer.struct.stack_st_X509_OBJECT */
            	5360, 0,
            0, 32, 2, /* 5360: struct.stack_st_fake_X509_OBJECT */
            	5367, 8,
            	86, 24,
            8884099, 8, 2, /* 5367: pointer_to_array_of_pointers_to_stack */
            	5374, 0,
            	83, 20,
            0, 8, 1, /* 5374: pointer.X509_OBJECT */
            	4153, 0,
            1, 8, 1, /* 5379: pointer.struct.stack_st_X509_LOOKUP */
            	5384, 0,
            0, 32, 2, /* 5384: struct.stack_st_fake_X509_LOOKUP */
            	5391, 8,
            	86, 24,
            8884099, 8, 2, /* 5391: pointer_to_array_of_pointers_to_stack */
            	5398, 0,
            	83, 20,
            0, 8, 1, /* 5398: pointer.X509_LOOKUP */
            	5254, 0,
            1, 8, 1, /* 5403: pointer.struct.X509_VERIFY_PARAM_st */
            	5408, 0,
            0, 56, 2, /* 5408: struct.X509_VERIFY_PARAM_st */
            	99, 0,
            	4970, 48,
            8884097, 8, 0, /* 5415: pointer.func */
            8884097, 8, 0, /* 5418: pointer.func */
            8884097, 8, 0, /* 5421: pointer.func */
            8884097, 8, 0, /* 5424: pointer.func */
            8884097, 8, 0, /* 5427: pointer.func */
            8884097, 8, 0, /* 5430: pointer.func */
            8884097, 8, 0, /* 5433: pointer.func */
            8884097, 8, 0, /* 5436: pointer.func */
            8884097, 8, 0, /* 5439: pointer.func */
            8884097, 8, 0, /* 5442: pointer.func */
            8884097, 8, 0, /* 5445: pointer.func */
            8884097, 8, 0, /* 5448: pointer.func */
            8884097, 8, 0, /* 5451: pointer.func */
            8884097, 8, 0, /* 5454: pointer.func */
            8884097, 8, 0, /* 5457: pointer.func */
            8884097, 8, 0, /* 5460: pointer.func */
            8884097, 8, 0, /* 5463: pointer.func */
            1, 8, 1, /* 5466: pointer.struct.lhash_st */
            	5471, 0,
            0, 176, 3, /* 5471: struct.lhash_st */
            	5480, 0,
            	86, 8,
            	5502, 16,
            1, 8, 1, /* 5480: pointer.pointer.struct.lhash_node_st */
            	5485, 0,
            1, 8, 1, /* 5485: pointer.struct.lhash_node_st */
            	5490, 0,
            0, 24, 2, /* 5490: struct.lhash_node_st */
            	3405, 0,
            	5497, 8,
            1, 8, 1, /* 5497: pointer.struct.lhash_node_st */
            	5490, 0,
            8884097, 8, 0, /* 5502: pointer.func */
            8884097, 8, 0, /* 5505: pointer.func */
            8884097, 8, 0, /* 5508: pointer.func */
            8884097, 8, 0, /* 5511: pointer.func */
            8884097, 8, 0, /* 5514: pointer.func */
            8884097, 8, 0, /* 5517: pointer.func */
            8884097, 8, 0, /* 5520: pointer.func */
            8884097, 8, 0, /* 5523: pointer.func */
            8884097, 8, 0, /* 5526: pointer.func */
            1, 8, 1, /* 5529: pointer.struct.stack_st_SSL_COMP */
            	5534, 0,
            0, 32, 2, /* 5534: struct.stack_st_fake_SSL_COMP */
            	5541, 8,
            	86, 24,
            8884099, 8, 2, /* 5541: pointer_to_array_of_pointers_to_stack */
            	5548, 0,
            	83, 20,
            0, 8, 1, /* 5548: pointer.SSL_COMP */
            	5553, 0,
            0, 0, 1, /* 5553: SSL_COMP */
            	5558, 0,
            0, 24, 2, /* 5558: struct.ssl_comp_st */
            	5, 8,
            	5565, 16,
            1, 8, 1, /* 5565: pointer.struct.comp_method_st */
            	5570, 0,
            0, 64, 7, /* 5570: struct.comp_method_st */
            	5, 8,
            	5587, 16,
            	5590, 24,
            	5593, 32,
            	5593, 40,
            	3298, 48,
            	3298, 56,
            8884097, 8, 0, /* 5587: pointer.func */
            8884097, 8, 0, /* 5590: pointer.func */
            8884097, 8, 0, /* 5593: pointer.func */
            8884097, 8, 0, /* 5596: pointer.func */
            8884097, 8, 0, /* 5599: pointer.func */
            8884097, 8, 0, /* 5602: pointer.func */
            8884097, 8, 0, /* 5605: pointer.func */
            1, 8, 1, /* 5608: pointer.struct.ssl3_buf_freelist_st */
            	5613, 0,
            0, 24, 1, /* 5613: struct.ssl3_buf_freelist_st */
            	5618, 16,
            1, 8, 1, /* 5618: pointer.struct.ssl3_buf_freelist_entry_st */
            	5623, 0,
            0, 8, 1, /* 5623: struct.ssl3_buf_freelist_entry_st */
            	5618, 0,
            0, 128, 14, /* 5628: struct.srp_ctx_st */
            	3405, 0,
            	5596, 8,
            	5602, 16,
            	5659, 24,
            	99, 32,
            	2407, 40,
            	2407, 48,
            	2407, 56,
            	2407, 64,
            	2407, 72,
            	2407, 80,
            	2407, 88,
            	2407, 96,
            	99, 104,
            8884097, 8, 0, /* 5659: pointer.func */
            8884097, 8, 0, /* 5662: pointer.func */
            8884097, 8, 0, /* 5665: pointer.func */
            1, 8, 1, /* 5668: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	5673, 0,
            0, 32, 2, /* 5673: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	5680, 8,
            	86, 24,
            8884099, 8, 2, /* 5680: pointer_to_array_of_pointers_to_stack */
            	5687, 0,
            	83, 20,
            0, 8, 1, /* 5687: pointer.SRTP_PROTECTION_PROFILE */
            	5692, 0,
            0, 0, 1, /* 5692: SRTP_PROTECTION_PROFILE */
            	5697, 0,
            0, 16, 1, /* 5697: struct.srtp_protection_profile_st */
            	5, 0,
            8884097, 8, 0, /* 5702: pointer.func */
            1, 8, 1, /* 5705: pointer.struct.tls_session_ticket_ext_st */
            	5710, 0,
            0, 16, 1, /* 5710: struct.tls_session_ticket_ext_st */
            	3405, 8,
            8884097, 8, 0, /* 5715: pointer.func */
            8884097, 8, 0, /* 5718: pointer.func */
            1, 8, 1, /* 5721: pointer.struct.srtp_protection_profile_st */
            	0, 0,
            0, 1, 0, /* 5726: char */
        },
        .arg_entity_index = { 3615, },
        .ret_entity_index = 3983,
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

