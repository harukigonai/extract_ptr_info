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
            	64096, 0,
            1, 8, 1, /* 10: pointer.struct.stack_st_X509_EXTENSION */
            	15, 0,
            0, 32, 2, /* 15: struct.stack_st_fake_X509_EXTENSION */
            	22, 8,
            	86, 24,
            64099, 8, 2, /* 22: pointer_to_array_of_pointers_to_stack */
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
            64097, 8, 0, /* 86: pointer.func */
            0, 24, 1, /* 89: struct.asn1_string_st */
            	78, 8,
            0, 24, 1, /* 94: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 99: pointer.char */
            	64096, 0,
            1, 8, 1, /* 104: pointer.struct.stack_st_X509_NAME_ENTRY */
            	109, 0,
            0, 32, 2, /* 109: struct.stack_st_fake_X509_NAME_ENTRY */
            	116, 8,
            	86, 24,
            64099, 8, 2, /* 116: pointer_to_array_of_pointers_to_stack */
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
            64099, 8, 2, /* 207: pointer_to_array_of_pointers_to_stack */
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
            	2099, 176,
            	3345, 224,
            	3355, 240,
            	2559, 248,
            	3389, 264,
            	3389, 272,
            	99, 280,
            	78, 296,
            	78, 312,
            	78, 320,
            	99, 344,
            1, 8, 1, /* 265: pointer.struct.sess_cert_st */
            	270, 0,
            0, 248, 5, /* 270: struct.sess_cert_st */
            	283, 0,
            	2085, 16,
            	3330, 216,
            	3335, 224,
            	3340, 232,
            1, 8, 1, /* 283: pointer.struct.stack_st_X509 */
            	288, 0,
            0, 32, 2, /* 288: struct.stack_st_fake_X509 */
            	295, 8,
            	86, 24,
            64099, 8, 2, /* 295: pointer_to_array_of_pointers_to_stack */
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
            64099, 8, 2, /* 562: pointer_to_array_of_pointers_to_stack */
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
            64097, 8, 0, /* 736: pointer.func */
            64097, 8, 0, /* 739: pointer.func */
            64097, 8, 0, /* 742: pointer.func */
            64097, 8, 0, /* 745: pointer.func */
            64097, 8, 0, /* 748: pointer.func */
            64097, 8, 0, /* 751: pointer.func */
            64097, 8, 0, /* 754: pointer.func */
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
            64097, 8, 0, /* 884: pointer.func */
            64097, 8, 0, /* 887: pointer.func */
            64097, 8, 0, /* 890: pointer.func */
            64097, 8, 0, /* 893: pointer.func */
            64097, 8, 0, /* 896: pointer.func */
            64097, 8, 0, /* 899: pointer.func */
            64097, 8, 0, /* 902: pointer.func */
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
            64097, 8, 0, /* 961: pointer.func */
            64097, 8, 0, /* 964: pointer.func */
            64097, 8, 0, /* 967: pointer.func */
            64097, 8, 0, /* 970: pointer.func */
            1, 8, 1, /* 973: pointer.struct.ec_key_st */
            	978, 0,
            0, 0, 0, /* 978: struct.ec_key_st */
            1, 8, 1, /* 981: pointer.struct.stack_st_X509_ATTRIBUTE */
            	986, 0,
            0, 32, 2, /* 986: struct.stack_st_fake_X509_ATTRIBUTE */
            	993, 8,
            	86, 24,
            64099, 8, 2, /* 993: pointer_to_array_of_pointers_to_stack */
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
            64099, 8, 2, /* 1052: pointer_to_array_of_pointers_to_stack */
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
            64099, 8, 2, /* 1372: pointer_to_array_of_pointers_to_stack */
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
            64099, 8, 2, /* 1417: pointer_to_array_of_pointers_to_stack */
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
            64099, 8, 2, /* 1474: pointer_to_array_of_pointers_to_stack */
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
            64099, 8, 2, /* 1722: pointer_to_array_of_pointers_to_stack */
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
            64099, 8, 2, /* 1768: pointer_to_array_of_pointers_to_stack */
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
            64099, 8, 2, /* 1826: pointer_to_array_of_pointers_to_stack */
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
            64099, 8, 2, /* 1876: pointer_to_array_of_pointers_to_stack */
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
            64099, 8, 2, /* 1914: pointer_to_array_of_pointers_to_stack */
            	1921, 0,
            	83, 20,
            0, 8, 1, /* 1921: pointer.X509_ALGOR */
            	1926, 0,
            0, 0, 1, /* 1926: X509_ALGOR */
            	1931, 0,
            0, 16, 2, /* 1931: struct.X509_algor_st */
            	1938, 0,
            	1952, 8,
            1, 8, 1, /* 1938: pointer.struct.asn1_object_st */
            	1943, 0,
            0, 40, 3, /* 1943: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 1952: pointer.struct.asn1_type_st */
            	1957, 0,
            0, 16, 1, /* 1957: struct.asn1_type_st */
            	1962, 8,
            0, 8, 20, /* 1962: union.unknown */
            	99, 0,
            	2005, 0,
            	1938, 0,
            	2015, 0,
            	2020, 0,
            	2025, 0,
            	2030, 0,
            	2035, 0,
            	2040, 0,
            	2045, 0,
            	2050, 0,
            	2055, 0,
            	2060, 0,
            	2065, 0,
            	2070, 0,
            	2075, 0,
            	2080, 0,
            	2005, 0,
            	2005, 0,
            	1352, 0,
            1, 8, 1, /* 2005: pointer.struct.asn1_string_st */
            	2010, 0,
            0, 24, 1, /* 2010: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 2015: pointer.struct.asn1_string_st */
            	2010, 0,
            1, 8, 1, /* 2020: pointer.struct.asn1_string_st */
            	2010, 0,
            1, 8, 1, /* 2025: pointer.struct.asn1_string_st */
            	2010, 0,
            1, 8, 1, /* 2030: pointer.struct.asn1_string_st */
            	2010, 0,
            1, 8, 1, /* 2035: pointer.struct.asn1_string_st */
            	2010, 0,
            1, 8, 1, /* 2040: pointer.struct.asn1_string_st */
            	2010, 0,
            1, 8, 1, /* 2045: pointer.struct.asn1_string_st */
            	2010, 0,
            1, 8, 1, /* 2050: pointer.struct.asn1_string_st */
            	2010, 0,
            1, 8, 1, /* 2055: pointer.struct.asn1_string_st */
            	2010, 0,
            1, 8, 1, /* 2060: pointer.struct.asn1_string_st */
            	2010, 0,
            1, 8, 1, /* 2065: pointer.struct.asn1_string_st */
            	2010, 0,
            1, 8, 1, /* 2070: pointer.struct.asn1_string_st */
            	2010, 0,
            1, 8, 1, /* 2075: pointer.struct.asn1_string_st */
            	2010, 0,
            1, 8, 1, /* 2080: pointer.struct.asn1_string_st */
            	2010, 0,
            1, 8, 1, /* 2085: pointer.struct.cert_pkey_st */
            	2090, 0,
            0, 24, 3, /* 2090: struct.cert_pkey_st */
            	2099, 0,
            	2407, 8,
            	3285, 16,
            1, 8, 1, /* 2099: pointer.struct.x509_st */
            	2104, 0,
            0, 184, 12, /* 2104: struct.x509_st */
            	2131, 0,
            	2171, 8,
            	2260, 16,
            	99, 32,
            	2559, 40,
            	2265, 104,
            	2813, 112,
            	2851, 120,
            	2859, 128,
            	2883, 136,
            	2907, 144,
            	3219, 176,
            1, 8, 1, /* 2131: pointer.struct.x509_cinf_st */
            	2136, 0,
            0, 104, 11, /* 2136: struct.x509_cinf_st */
            	2161, 0,
            	2161, 8,
            	2171, 16,
            	2328, 24,
            	2376, 32,
            	2328, 40,
            	2393, 48,
            	2260, 56,
            	2260, 64,
            	2784, 72,
            	2808, 80,
            1, 8, 1, /* 2161: pointer.struct.asn1_string_st */
            	2166, 0,
            0, 24, 1, /* 2166: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 2171: pointer.struct.X509_algor_st */
            	2176, 0,
            0, 16, 2, /* 2176: struct.X509_algor_st */
            	2183, 0,
            	2197, 8,
            1, 8, 1, /* 2183: pointer.struct.asn1_object_st */
            	2188, 0,
            0, 40, 3, /* 2188: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 2197: pointer.struct.asn1_type_st */
            	2202, 0,
            0, 16, 1, /* 2202: struct.asn1_type_st */
            	2207, 8,
            0, 8, 20, /* 2207: union.unknown */
            	99, 0,
            	2250, 0,
            	2183, 0,
            	2161, 0,
            	2255, 0,
            	2260, 0,
            	2265, 0,
            	2270, 0,
            	2275, 0,
            	2280, 0,
            	2285, 0,
            	2290, 0,
            	2295, 0,
            	2300, 0,
            	2305, 0,
            	2310, 0,
            	2315, 0,
            	2250, 0,
            	2250, 0,
            	2320, 0,
            1, 8, 1, /* 2250: pointer.struct.asn1_string_st */
            	2166, 0,
            1, 8, 1, /* 2255: pointer.struct.asn1_string_st */
            	2166, 0,
            1, 8, 1, /* 2260: pointer.struct.asn1_string_st */
            	2166, 0,
            1, 8, 1, /* 2265: pointer.struct.asn1_string_st */
            	2166, 0,
            1, 8, 1, /* 2270: pointer.struct.asn1_string_st */
            	2166, 0,
            1, 8, 1, /* 2275: pointer.struct.asn1_string_st */
            	2166, 0,
            1, 8, 1, /* 2280: pointer.struct.asn1_string_st */
            	2166, 0,
            1, 8, 1, /* 2285: pointer.struct.asn1_string_st */
            	2166, 0,
            1, 8, 1, /* 2290: pointer.struct.asn1_string_st */
            	2166, 0,
            1, 8, 1, /* 2295: pointer.struct.asn1_string_st */
            	2166, 0,
            1, 8, 1, /* 2300: pointer.struct.asn1_string_st */
            	2166, 0,
            1, 8, 1, /* 2305: pointer.struct.asn1_string_st */
            	2166, 0,
            1, 8, 1, /* 2310: pointer.struct.asn1_string_st */
            	2166, 0,
            1, 8, 1, /* 2315: pointer.struct.asn1_string_st */
            	2166, 0,
            1, 8, 1, /* 2320: pointer.struct.ASN1_VALUE_st */
            	2325, 0,
            0, 0, 0, /* 2325: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2328: pointer.struct.X509_name_st */
            	2333, 0,
            0, 40, 3, /* 2333: struct.X509_name_st */
            	2342, 0,
            	2366, 16,
            	78, 24,
            1, 8, 1, /* 2342: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2347, 0,
            0, 32, 2, /* 2347: struct.stack_st_fake_X509_NAME_ENTRY */
            	2354, 8,
            	86, 24,
            64099, 8, 2, /* 2354: pointer_to_array_of_pointers_to_stack */
            	2361, 0,
            	83, 20,
            0, 8, 1, /* 2361: pointer.X509_NAME_ENTRY */
            	128, 0,
            1, 8, 1, /* 2366: pointer.struct.buf_mem_st */
            	2371, 0,
            0, 24, 1, /* 2371: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 2376: pointer.struct.X509_val_st */
            	2381, 0,
            0, 16, 2, /* 2381: struct.X509_val_st */
            	2388, 0,
            	2388, 8,
            1, 8, 1, /* 2388: pointer.struct.asn1_string_st */
            	2166, 0,
            1, 8, 1, /* 2393: pointer.struct.X509_pubkey_st */
            	2398, 0,
            0, 24, 3, /* 2398: struct.X509_pubkey_st */
            	2171, 0,
            	2260, 8,
            	2407, 16,
            1, 8, 1, /* 2407: pointer.struct.evp_pkey_st */
            	2412, 0,
            0, 56, 4, /* 2412: struct.evp_pkey_st */
            	2423, 16,
            	2431, 24,
            	2439, 32,
            	2760, 48,
            1, 8, 1, /* 2423: pointer.struct.evp_pkey_asn1_method_st */
            	2428, 0,
            0, 0, 0, /* 2428: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 2431: pointer.struct.engine_st */
            	2436, 0,
            0, 0, 0, /* 2436: struct.engine_st */
            0, 8, 5, /* 2439: union.unknown */
            	99, 0,
            	2452, 0,
            	2603, 0,
            	2684, 0,
            	2752, 0,
            1, 8, 1, /* 2452: pointer.struct.rsa_st */
            	2457, 0,
            0, 168, 17, /* 2457: struct.rsa_st */
            	2494, 16,
            	2431, 24,
            	2549, 32,
            	2549, 40,
            	2549, 48,
            	2549, 56,
            	2549, 64,
            	2549, 72,
            	2549, 80,
            	2549, 88,
            	2559, 96,
            	2581, 120,
            	2581, 128,
            	2581, 136,
            	99, 144,
            	2595, 152,
            	2595, 160,
            1, 8, 1, /* 2494: pointer.struct.rsa_meth_st */
            	2499, 0,
            0, 112, 13, /* 2499: struct.rsa_meth_st */
            	5, 0,
            	2528, 8,
            	2528, 16,
            	2528, 24,
            	2528, 32,
            	2531, 40,
            	2534, 48,
            	2537, 56,
            	2537, 64,
            	99, 80,
            	2540, 88,
            	2543, 96,
            	2546, 104,
            64097, 8, 0, /* 2528: pointer.func */
            64097, 8, 0, /* 2531: pointer.func */
            64097, 8, 0, /* 2534: pointer.func */
            64097, 8, 0, /* 2537: pointer.func */
            64097, 8, 0, /* 2540: pointer.func */
            64097, 8, 0, /* 2543: pointer.func */
            64097, 8, 0, /* 2546: pointer.func */
            1, 8, 1, /* 2549: pointer.struct.bignum_st */
            	2554, 0,
            0, 24, 1, /* 2554: struct.bignum_st */
            	767, 0,
            0, 16, 1, /* 2559: struct.crypto_ex_data_st */
            	2564, 0,
            1, 8, 1, /* 2564: pointer.struct.stack_st_void */
            	2569, 0,
            0, 32, 1, /* 2569: struct.stack_st_void */
            	2574, 0,
            0, 32, 2, /* 2574: struct.stack_st */
            	797, 8,
            	86, 24,
            1, 8, 1, /* 2581: pointer.struct.bn_mont_ctx_st */
            	2586, 0,
            0, 96, 3, /* 2586: struct.bn_mont_ctx_st */
            	2554, 8,
            	2554, 32,
            	2554, 56,
            1, 8, 1, /* 2595: pointer.struct.bn_blinding_st */
            	2600, 0,
            0, 0, 0, /* 2600: struct.bn_blinding_st */
            1, 8, 1, /* 2603: pointer.struct.dsa_st */
            	2608, 0,
            0, 136, 11, /* 2608: struct.dsa_st */
            	2549, 24,
            	2549, 32,
            	2549, 40,
            	2549, 48,
            	2549, 56,
            	2549, 64,
            	2549, 72,
            	2581, 88,
            	2559, 104,
            	2633, 120,
            	2431, 128,
            1, 8, 1, /* 2633: pointer.struct.dsa_method */
            	2638, 0,
            0, 96, 11, /* 2638: struct.dsa_method */
            	5, 0,
            	2663, 8,
            	2666, 16,
            	2669, 24,
            	2672, 32,
            	2675, 40,
            	2678, 48,
            	2678, 56,
            	99, 72,
            	2681, 80,
            	2678, 88,
            64097, 8, 0, /* 2663: pointer.func */
            64097, 8, 0, /* 2666: pointer.func */
            64097, 8, 0, /* 2669: pointer.func */
            64097, 8, 0, /* 2672: pointer.func */
            64097, 8, 0, /* 2675: pointer.func */
            64097, 8, 0, /* 2678: pointer.func */
            64097, 8, 0, /* 2681: pointer.func */
            1, 8, 1, /* 2684: pointer.struct.dh_st */
            	2689, 0,
            0, 144, 12, /* 2689: struct.dh_st */
            	2549, 8,
            	2549, 16,
            	2549, 32,
            	2549, 40,
            	2581, 56,
            	2549, 64,
            	2549, 72,
            	78, 80,
            	2549, 96,
            	2559, 112,
            	2716, 128,
            	2431, 136,
            1, 8, 1, /* 2716: pointer.struct.dh_method */
            	2721, 0,
            0, 72, 8, /* 2721: struct.dh_method */
            	5, 0,
            	2740, 8,
            	2743, 16,
            	2746, 24,
            	2740, 32,
            	2740, 40,
            	99, 56,
            	2749, 64,
            64097, 8, 0, /* 2740: pointer.func */
            64097, 8, 0, /* 2743: pointer.func */
            64097, 8, 0, /* 2746: pointer.func */
            64097, 8, 0, /* 2749: pointer.func */
            1, 8, 1, /* 2752: pointer.struct.ec_key_st */
            	2757, 0,
            0, 0, 0, /* 2757: struct.ec_key_st */
            1, 8, 1, /* 2760: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2765, 0,
            0, 32, 2, /* 2765: struct.stack_st_fake_X509_ATTRIBUTE */
            	2772, 8,
            	86, 24,
            64099, 8, 2, /* 2772: pointer_to_array_of_pointers_to_stack */
            	2779, 0,
            	83, 20,
            0, 8, 1, /* 2779: pointer.X509_ATTRIBUTE */
            	1005, 0,
            1, 8, 1, /* 2784: pointer.struct.stack_st_X509_EXTENSION */
            	2789, 0,
            0, 32, 2, /* 2789: struct.stack_st_fake_X509_EXTENSION */
            	2796, 8,
            	86, 24,
            64099, 8, 2, /* 2796: pointer_to_array_of_pointers_to_stack */
            	2803, 0,
            	83, 20,
            0, 8, 1, /* 2803: pointer.X509_EXTENSION */
            	34, 0,
            0, 24, 1, /* 2808: struct.ASN1_ENCODING_st */
            	78, 0,
            1, 8, 1, /* 2813: pointer.struct.AUTHORITY_KEYID_st */
            	2818, 0,
            0, 24, 3, /* 2818: struct.AUTHORITY_KEYID_st */
            	2265, 0,
            	2827, 8,
            	2161, 16,
            1, 8, 1, /* 2827: pointer.struct.stack_st_GENERAL_NAME */
            	2832, 0,
            0, 32, 2, /* 2832: struct.stack_st_fake_GENERAL_NAME */
            	2839, 8,
            	86, 24,
            64099, 8, 2, /* 2839: pointer_to_array_of_pointers_to_stack */
            	2846, 0,
            	83, 20,
            0, 8, 1, /* 2846: pointer.GENERAL_NAME */
            	1486, 0,
            1, 8, 1, /* 2851: pointer.struct.X509_POLICY_CACHE_st */
            	2856, 0,
            0, 0, 0, /* 2856: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 2859: pointer.struct.stack_st_DIST_POINT */
            	2864, 0,
            0, 32, 2, /* 2864: struct.stack_st_fake_DIST_POINT */
            	2871, 8,
            	86, 24,
            64099, 8, 2, /* 2871: pointer_to_array_of_pointers_to_stack */
            	2878, 0,
            	83, 20,
            0, 8, 1, /* 2878: pointer.DIST_POINT */
            	1429, 0,
            1, 8, 1, /* 2883: pointer.struct.stack_st_GENERAL_NAME */
            	2888, 0,
            0, 32, 2, /* 2888: struct.stack_st_fake_GENERAL_NAME */
            	2895, 8,
            	86, 24,
            64099, 8, 2, /* 2895: pointer_to_array_of_pointers_to_stack */
            	2902, 0,
            	83, 20,
            0, 8, 1, /* 2902: pointer.GENERAL_NAME */
            	1486, 0,
            1, 8, 1, /* 2907: pointer.struct.NAME_CONSTRAINTS_st */
            	2912, 0,
            0, 16, 2, /* 2912: struct.NAME_CONSTRAINTS_st */
            	2919, 0,
            	2919, 8,
            1, 8, 1, /* 2919: pointer.struct.stack_st_GENERAL_SUBTREE */
            	2924, 0,
            0, 32, 2, /* 2924: struct.stack_st_fake_GENERAL_SUBTREE */
            	2931, 8,
            	86, 24,
            64099, 8, 2, /* 2931: pointer_to_array_of_pointers_to_stack */
            	2938, 0,
            	83, 20,
            0, 8, 1, /* 2938: pointer.GENERAL_SUBTREE */
            	2943, 0,
            0, 0, 1, /* 2943: GENERAL_SUBTREE */
            	2948, 0,
            0, 24, 3, /* 2948: struct.GENERAL_SUBTREE_st */
            	2957, 0,
            	3089, 8,
            	3089, 16,
            1, 8, 1, /* 2957: pointer.struct.GENERAL_NAME_st */
            	2962, 0,
            0, 16, 1, /* 2962: struct.GENERAL_NAME_st */
            	2967, 8,
            0, 8, 15, /* 2967: union.unknown */
            	99, 0,
            	3000, 0,
            	3119, 0,
            	3119, 0,
            	3026, 0,
            	3159, 0,
            	3207, 0,
            	3119, 0,
            	3104, 0,
            	3012, 0,
            	3104, 0,
            	3159, 0,
            	3119, 0,
            	3012, 0,
            	3026, 0,
            1, 8, 1, /* 3000: pointer.struct.otherName_st */
            	3005, 0,
            0, 16, 2, /* 3005: struct.otherName_st */
            	3012, 0,
            	3026, 8,
            1, 8, 1, /* 3012: pointer.struct.asn1_object_st */
            	3017, 0,
            0, 40, 3, /* 3017: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 3026: pointer.struct.asn1_type_st */
            	3031, 0,
            0, 16, 1, /* 3031: struct.asn1_type_st */
            	3036, 8,
            0, 8, 20, /* 3036: union.unknown */
            	99, 0,
            	3079, 0,
            	3012, 0,
            	3089, 0,
            	3094, 0,
            	3099, 0,
            	3104, 0,
            	3109, 0,
            	3114, 0,
            	3119, 0,
            	3124, 0,
            	3129, 0,
            	3134, 0,
            	3139, 0,
            	3144, 0,
            	3149, 0,
            	3154, 0,
            	3079, 0,
            	3079, 0,
            	1688, 0,
            1, 8, 1, /* 3079: pointer.struct.asn1_string_st */
            	3084, 0,
            0, 24, 1, /* 3084: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 3089: pointer.struct.asn1_string_st */
            	3084, 0,
            1, 8, 1, /* 3094: pointer.struct.asn1_string_st */
            	3084, 0,
            1, 8, 1, /* 3099: pointer.struct.asn1_string_st */
            	3084, 0,
            1, 8, 1, /* 3104: pointer.struct.asn1_string_st */
            	3084, 0,
            1, 8, 1, /* 3109: pointer.struct.asn1_string_st */
            	3084, 0,
            1, 8, 1, /* 3114: pointer.struct.asn1_string_st */
            	3084, 0,
            1, 8, 1, /* 3119: pointer.struct.asn1_string_st */
            	3084, 0,
            1, 8, 1, /* 3124: pointer.struct.asn1_string_st */
            	3084, 0,
            1, 8, 1, /* 3129: pointer.struct.asn1_string_st */
            	3084, 0,
            1, 8, 1, /* 3134: pointer.struct.asn1_string_st */
            	3084, 0,
            1, 8, 1, /* 3139: pointer.struct.asn1_string_st */
            	3084, 0,
            1, 8, 1, /* 3144: pointer.struct.asn1_string_st */
            	3084, 0,
            1, 8, 1, /* 3149: pointer.struct.asn1_string_st */
            	3084, 0,
            1, 8, 1, /* 3154: pointer.struct.asn1_string_st */
            	3084, 0,
            1, 8, 1, /* 3159: pointer.struct.X509_name_st */
            	3164, 0,
            0, 40, 3, /* 3164: struct.X509_name_st */
            	3173, 0,
            	3197, 16,
            	78, 24,
            1, 8, 1, /* 3173: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3178, 0,
            0, 32, 2, /* 3178: struct.stack_st_fake_X509_NAME_ENTRY */
            	3185, 8,
            	86, 24,
            64099, 8, 2, /* 3185: pointer_to_array_of_pointers_to_stack */
            	3192, 0,
            	83, 20,
            0, 8, 1, /* 3192: pointer.X509_NAME_ENTRY */
            	128, 0,
            1, 8, 1, /* 3197: pointer.struct.buf_mem_st */
            	3202, 0,
            0, 24, 1, /* 3202: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 3207: pointer.struct.EDIPartyName_st */
            	3212, 0,
            0, 16, 2, /* 3212: struct.EDIPartyName_st */
            	3079, 0,
            	3079, 8,
            1, 8, 1, /* 3219: pointer.struct.x509_cert_aux_st */
            	3224, 0,
            0, 40, 5, /* 3224: struct.x509_cert_aux_st */
            	3237, 0,
            	3237, 8,
            	2315, 16,
            	2265, 24,
            	3261, 32,
            1, 8, 1, /* 3237: pointer.struct.stack_st_ASN1_OBJECT */
            	3242, 0,
            0, 32, 2, /* 3242: struct.stack_st_fake_ASN1_OBJECT */
            	3249, 8,
            	86, 24,
            64099, 8, 2, /* 3249: pointer_to_array_of_pointers_to_stack */
            	3256, 0,
            	83, 20,
            0, 8, 1, /* 3256: pointer.ASN1_OBJECT */
            	1888, 0,
            1, 8, 1, /* 3261: pointer.struct.stack_st_X509_ALGOR */
            	3266, 0,
            0, 32, 2, /* 3266: struct.stack_st_fake_X509_ALGOR */
            	3273, 8,
            	86, 24,
            64099, 8, 2, /* 3273: pointer_to_array_of_pointers_to_stack */
            	3280, 0,
            	83, 20,
            0, 8, 1, /* 3280: pointer.X509_ALGOR */
            	1926, 0,
            1, 8, 1, /* 3285: pointer.struct.env_md_st */
            	3290, 0,
            0, 120, 8, /* 3290: struct.env_md_st */
            	3309, 24,
            	3312, 32,
            	3315, 40,
            	3318, 48,
            	3309, 56,
            	3321, 64,
            	3324, 72,
            	3327, 112,
            64097, 8, 0, /* 3309: pointer.func */
            64097, 8, 0, /* 3312: pointer.func */
            64097, 8, 0, /* 3315: pointer.func */
            64097, 8, 0, /* 3318: pointer.func */
            64097, 8, 0, /* 3321: pointer.func */
            64097, 8, 0, /* 3324: pointer.func */
            64097, 8, 0, /* 3327: pointer.func */
            1, 8, 1, /* 3330: pointer.struct.rsa_st */
            	2457, 0,
            1, 8, 1, /* 3335: pointer.struct.dh_st */
            	2689, 0,
            1, 8, 1, /* 3340: pointer.struct.ec_key_st */
            	2757, 0,
            1, 8, 1, /* 3345: pointer.struct.ssl_cipher_st */
            	3350, 0,
            0, 88, 1, /* 3350: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 3355: pointer.struct.stack_st_SSL_CIPHER */
            	3360, 0,
            0, 32, 2, /* 3360: struct.stack_st_fake_SSL_CIPHER */
            	3367, 8,
            	86, 24,
            64099, 8, 2, /* 3367: pointer_to_array_of_pointers_to_stack */
            	3374, 0,
            	83, 20,
            0, 8, 1, /* 3374: pointer.SSL_CIPHER */
            	3379, 0,
            0, 0, 1, /* 3379: SSL_CIPHER */
            	3384, 0,
            0, 88, 1, /* 3384: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 3389: pointer.struct.ssl_session_st */
            	234, 0,
            0, 56, 2, /* 3394: struct.comp_ctx_st */
            	3401, 0,
            	2559, 40,
            1, 8, 1, /* 3401: pointer.struct.comp_method_st */
            	3406, 0,
            0, 64, 7, /* 3406: struct.comp_method_st */
            	5, 8,
            	3423, 16,
            	3426, 24,
            	3429, 32,
            	3429, 40,
            	3432, 48,
            	3432, 56,
            64097, 8, 0, /* 3423: pointer.func */
            64097, 8, 0, /* 3426: pointer.func */
            64097, 8, 0, /* 3429: pointer.func */
            64097, 8, 0, /* 3432: pointer.func */
            1, 8, 1, /* 3435: pointer.struct.comp_ctx_st */
            	3394, 0,
            1, 8, 1, /* 3440: pointer.struct._pqueue */
            	3445, 0,
            0, 0, 0, /* 3445: struct._pqueue */
            0, 888, 7, /* 3448: struct.dtls1_state_st */
            	3465, 576,
            	3465, 592,
            	3440, 608,
            	3440, 616,
            	3465, 624,
            	3470, 648,
            	3470, 736,
            0, 16, 1, /* 3465: struct.record_pqueue_st */
            	3440, 8,
            0, 88, 1, /* 3470: struct.hm_header_st */
            	3475, 48,
            0, 40, 4, /* 3475: struct.dtls1_retransmit_state */
            	3486, 0,
            	3542, 8,
            	3435, 16,
            	229, 24,
            1, 8, 1, /* 3486: pointer.struct.evp_cipher_ctx_st */
            	3491, 0,
            0, 168, 4, /* 3491: struct.evp_cipher_ctx_st */
            	3502, 0,
            	2431, 8,
            	3539, 96,
            	3539, 120,
            1, 8, 1, /* 3502: pointer.struct.evp_cipher_st */
            	3507, 0,
            0, 88, 7, /* 3507: struct.evp_cipher_st */
            	3524, 24,
            	3527, 32,
            	3530, 40,
            	3533, 56,
            	3533, 64,
            	3536, 72,
            	3539, 80,
            64097, 8, 0, /* 3524: pointer.func */
            64097, 8, 0, /* 3527: pointer.func */
            64097, 8, 0, /* 3530: pointer.func */
            64097, 8, 0, /* 3533: pointer.func */
            64097, 8, 0, /* 3536: pointer.func */
            0, 8, 0, /* 3539: pointer.void */
            1, 8, 1, /* 3542: pointer.struct.env_md_ctx_st */
            	3547, 0,
            0, 48, 5, /* 3547: struct.env_md_ctx_st */
            	3285, 0,
            	2431, 8,
            	3539, 24,
            	3560, 32,
            	3312, 40,
            1, 8, 1, /* 3560: pointer.struct.evp_pkey_ctx_st */
            	3565, 0,
            0, 0, 0, /* 3565: struct.evp_pkey_ctx_st */
            0, 24, 2, /* 3568: struct.ssl_comp_st */
            	5, 8,
            	3401, 16,
            1, 8, 1, /* 3575: pointer.pointer.struct.env_md_ctx_st */
            	3542, 0,
            0, 24, 1, /* 3580: struct.ssl3_buffer_st */
            	78, 0,
            0, 1200, 10, /* 3585: struct.ssl3_state_st */
            	3580, 240,
            	3580, 264,
            	3608, 288,
            	3608, 344,
            	60, 432,
            	3617, 440,
            	3575, 448,
            	3539, 496,
            	3539, 512,
            	3691, 528,
            0, 56, 3, /* 3608: struct.ssl3_record_st */
            	78, 16,
            	78, 24,
            	78, 32,
            1, 8, 1, /* 3617: pointer.struct.bio_st */
            	3622, 0,
            0, 112, 7, /* 3622: struct.bio_st */
            	3639, 0,
            	3683, 8,
            	99, 16,
            	3539, 48,
            	3686, 56,
            	3686, 64,
            	2559, 96,
            1, 8, 1, /* 3639: pointer.struct.bio_method_st */
            	3644, 0,
            0, 80, 9, /* 3644: struct.bio_method_st */
            	5, 8,
            	3665, 16,
            	3668, 24,
            	3671, 32,
            	3668, 40,
            	3674, 48,
            	3677, 56,
            	3677, 64,
            	3680, 72,
            64097, 8, 0, /* 3665: pointer.func */
            64097, 8, 0, /* 3668: pointer.func */
            64097, 8, 0, /* 3671: pointer.func */
            64097, 8, 0, /* 3674: pointer.func */
            64097, 8, 0, /* 3677: pointer.func */
            64097, 8, 0, /* 3680: pointer.func */
            64097, 8, 0, /* 3683: pointer.func */
            1, 8, 1, /* 3686: pointer.struct.bio_st */
            	3622, 0,
            0, 528, 8, /* 3691: struct.unknown */
            	3345, 408,
            	3335, 416,
            	3340, 424,
            	3710, 464,
            	78, 480,
            	3502, 488,
            	3285, 496,
            	3782, 512,
            1, 8, 1, /* 3710: pointer.struct.stack_st_X509_NAME */
            	3715, 0,
            0, 32, 2, /* 3715: struct.stack_st_fake_X509_NAME */
            	3722, 8,
            	86, 24,
            64099, 8, 2, /* 3722: pointer_to_array_of_pointers_to_stack */
            	3729, 0,
            	83, 20,
            0, 8, 1, /* 3729: pointer.X509_NAME */
            	3734, 0,
            0, 0, 1, /* 3734: X509_NAME */
            	3739, 0,
            0, 40, 3, /* 3739: struct.X509_name_st */
            	3748, 0,
            	3772, 16,
            	78, 24,
            1, 8, 1, /* 3748: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3753, 0,
            0, 32, 2, /* 3753: struct.stack_st_fake_X509_NAME_ENTRY */
            	3760, 8,
            	86, 24,
            64099, 8, 2, /* 3760: pointer_to_array_of_pointers_to_stack */
            	3767, 0,
            	83, 20,
            0, 8, 1, /* 3767: pointer.X509_NAME_ENTRY */
            	128, 0,
            1, 8, 1, /* 3772: pointer.struct.buf_mem_st */
            	3777, 0,
            0, 24, 1, /* 3777: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 3782: pointer.struct.ssl_comp_st */
            	3568, 0,
            1, 8, 1, /* 3787: pointer.struct.ssl3_state_st */
            	3585, 0,
            1, 8, 1, /* 3792: pointer.struct.ssl2_state_st */
            	3797, 0,
            0, 344, 9, /* 3797: struct.ssl2_state_st */
            	60, 24,
            	78, 56,
            	78, 64,
            	78, 72,
            	78, 104,
            	78, 112,
            	78, 120,
            	78, 128,
            	78, 136,
            1, 8, 1, /* 3818: pointer.struct.ssl_st */
            	3823, 0,
            0, 808, 51, /* 3823: struct.ssl_st */
            	3928, 8,
            	3617, 16,
            	3617, 24,
            	3617, 32,
            	3992, 48,
            	2366, 80,
            	3539, 88,
            	78, 104,
            	3792, 120,
            	3787, 128,
            	4094, 136,
            	4099, 152,
            	3539, 160,
            	4102, 176,
            	3355, 184,
            	3355, 192,
            	3486, 208,
            	3542, 216,
            	3435, 224,
            	3486, 232,
            	3542, 240,
            	3435, 248,
            	4114, 256,
            	229, 304,
            	4145, 312,
            	4148, 328,
            	4151, 336,
            	4154, 352,
            	4157, 360,
            	4160, 368,
            	2559, 392,
            	3710, 408,
            	5879, 464,
            	3539, 472,
            	99, 480,
            	195, 504,
            	10, 512,
            	78, 520,
            	78, 544,
            	78, 560,
            	3539, 568,
            	5882, 584,
            	5892, 592,
            	3539, 600,
            	5895, 608,
            	3539, 616,
            	4160, 624,
            	78, 632,
            	5845, 648,
            	5898, 656,
            	5805, 680,
            1, 8, 1, /* 3928: pointer.struct.ssl_method_st */
            	3933, 0,
            0, 232, 28, /* 3933: struct.ssl_method_st */
            	3992, 8,
            	3995, 16,
            	3995, 24,
            	3992, 32,
            	3992, 40,
            	3998, 48,
            	3998, 56,
            	4001, 64,
            	3992, 72,
            	3992, 80,
            	3992, 88,
            	4004, 96,
            	4007, 104,
            	4010, 112,
            	3992, 120,
            	4013, 128,
            	4016, 136,
            	4019, 144,
            	4022, 152,
            	4025, 160,
            	4028, 168,
            	4031, 176,
            	4034, 184,
            	3432, 192,
            	4037, 200,
            	4028, 208,
            	4088, 216,
            	4091, 224,
            64097, 8, 0, /* 3992: pointer.func */
            64097, 8, 0, /* 3995: pointer.func */
            64097, 8, 0, /* 3998: pointer.func */
            64097, 8, 0, /* 4001: pointer.func */
            64097, 8, 0, /* 4004: pointer.func */
            64097, 8, 0, /* 4007: pointer.func */
            64097, 8, 0, /* 4010: pointer.func */
            64097, 8, 0, /* 4013: pointer.func */
            64097, 8, 0, /* 4016: pointer.func */
            64097, 8, 0, /* 4019: pointer.func */
            64097, 8, 0, /* 4022: pointer.func */
            64097, 8, 0, /* 4025: pointer.func */
            64097, 8, 0, /* 4028: pointer.func */
            64097, 8, 0, /* 4031: pointer.func */
            64097, 8, 0, /* 4034: pointer.func */
            1, 8, 1, /* 4037: pointer.struct.ssl3_enc_method */
            	4042, 0,
            0, 112, 11, /* 4042: struct.ssl3_enc_method */
            	4067, 0,
            	4070, 8,
            	3992, 16,
            	4073, 24,
            	4067, 32,
            	4076, 40,
            	4079, 56,
            	5, 64,
            	5, 80,
            	4082, 96,
            	4085, 104,
            64097, 8, 0, /* 4067: pointer.func */
            64097, 8, 0, /* 4070: pointer.func */
            64097, 8, 0, /* 4073: pointer.func */
            64097, 8, 0, /* 4076: pointer.func */
            64097, 8, 0, /* 4079: pointer.func */
            64097, 8, 0, /* 4082: pointer.func */
            64097, 8, 0, /* 4085: pointer.func */
            64097, 8, 0, /* 4088: pointer.func */
            64097, 8, 0, /* 4091: pointer.func */
            1, 8, 1, /* 4094: pointer.struct.dtls1_state_st */
            	3448, 0,
            64097, 8, 0, /* 4099: pointer.func */
            1, 8, 1, /* 4102: pointer.struct.X509_VERIFY_PARAM_st */
            	4107, 0,
            0, 56, 2, /* 4107: struct.X509_VERIFY_PARAM_st */
            	99, 0,
            	3237, 48,
            1, 8, 1, /* 4114: pointer.struct.cert_st */
            	4119, 0,
            0, 296, 7, /* 4119: struct.cert_st */
            	2085, 0,
            	3330, 48,
            	4136, 56,
            	3335, 64,
            	4139, 72,
            	3340, 80,
            	4142, 88,
            64097, 8, 0, /* 4136: pointer.func */
            64097, 8, 0, /* 4139: pointer.func */
            64097, 8, 0, /* 4142: pointer.func */
            64097, 8, 0, /* 4145: pointer.func */
            64097, 8, 0, /* 4148: pointer.func */
            64097, 8, 0, /* 4151: pointer.func */
            64097, 8, 0, /* 4154: pointer.func */
            64097, 8, 0, /* 4157: pointer.func */
            1, 8, 1, /* 4160: pointer.struct.ssl_ctx_st */
            	4165, 0,
            0, 736, 50, /* 4165: struct.ssl_ctx_st */
            	3928, 0,
            	3355, 8,
            	3355, 16,
            	4268, 24,
            	5643, 32,
            	3389, 48,
            	3389, 56,
            	5682, 80,
            	5685, 88,
            	5688, 96,
            	5691, 152,
            	3539, 160,
            	5694, 168,
            	3539, 176,
            	5697, 184,
            	5700, 192,
            	5703, 200,
            	2559, 208,
            	3285, 224,
            	3285, 232,
            	3285, 240,
            	283, 248,
            	5706, 256,
            	4151, 264,
            	3710, 272,
            	4114, 304,
            	4099, 320,
            	3539, 328,
            	4148, 376,
            	4145, 384,
            	4102, 392,
            	2431, 408,
            	5773, 416,
            	3539, 424,
            	5776, 480,
            	5779, 488,
            	3539, 496,
            	5782, 504,
            	3539, 512,
            	99, 520,
            	4154, 528,
            	4157, 536,
            	5785, 552,
            	5785, 560,
            	5805, 568,
            	5839, 696,
            	3539, 704,
            	5842, 712,
            	3539, 720,
            	5845, 728,
            1, 8, 1, /* 4268: pointer.struct.x509_store_st */
            	4273, 0,
            0, 144, 15, /* 4273: struct.x509_store_st */
            	4306, 8,
            	5407, 16,
            	4102, 24,
            	5619, 32,
            	4148, 40,
            	5622, 48,
            	5625, 56,
            	5619, 64,
            	5628, 72,
            	5631, 80,
            	5634, 88,
            	5637, 96,
            	5640, 104,
            	5619, 112,
            	2559, 120,
            1, 8, 1, /* 4306: pointer.struct.stack_st_X509_OBJECT */
            	4311, 0,
            0, 32, 2, /* 4311: struct.stack_st_fake_X509_OBJECT */
            	4318, 8,
            	86, 24,
            64099, 8, 2, /* 4318: pointer_to_array_of_pointers_to_stack */
            	4325, 0,
            	83, 20,
            0, 8, 1, /* 4325: pointer.X509_OBJECT */
            	4330, 0,
            0, 0, 1, /* 4330: X509_OBJECT */
            	4335, 0,
            0, 16, 1, /* 4335: struct.x509_object_st */
            	4340, 8,
            0, 8, 4, /* 4340: union.unknown */
            	99, 0,
            	4351, 0,
            	5195, 0,
            	4651, 0,
            1, 8, 1, /* 4351: pointer.struct.x509_st */
            	4356, 0,
            0, 184, 12, /* 4356: struct.x509_st */
            	4383, 0,
            	4423, 8,
            	4512, 16,
            	99, 32,
            	4803, 40,
            	4517, 104,
            	5057, 112,
            	5065, 120,
            	5073, 128,
            	5097, 136,
            	5121, 144,
            	5129, 176,
            1, 8, 1, /* 4383: pointer.struct.x509_cinf_st */
            	4388, 0,
            0, 104, 11, /* 4388: struct.x509_cinf_st */
            	4413, 0,
            	4413, 8,
            	4423, 16,
            	4572, 24,
            	4620, 32,
            	4572, 40,
            	4637, 48,
            	4512, 56,
            	4512, 64,
            	5028, 72,
            	5052, 80,
            1, 8, 1, /* 4413: pointer.struct.asn1_string_st */
            	4418, 0,
            0, 24, 1, /* 4418: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 4423: pointer.struct.X509_algor_st */
            	4428, 0,
            0, 16, 2, /* 4428: struct.X509_algor_st */
            	4435, 0,
            	4449, 8,
            1, 8, 1, /* 4435: pointer.struct.asn1_object_st */
            	4440, 0,
            0, 40, 3, /* 4440: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 4449: pointer.struct.asn1_type_st */
            	4454, 0,
            0, 16, 1, /* 4454: struct.asn1_type_st */
            	4459, 8,
            0, 8, 20, /* 4459: union.unknown */
            	99, 0,
            	4502, 0,
            	4435, 0,
            	4413, 0,
            	4507, 0,
            	4512, 0,
            	4517, 0,
            	4522, 0,
            	4527, 0,
            	4532, 0,
            	4537, 0,
            	4542, 0,
            	4547, 0,
            	4552, 0,
            	4557, 0,
            	4562, 0,
            	4567, 0,
            	4502, 0,
            	4502, 0,
            	1352, 0,
            1, 8, 1, /* 4502: pointer.struct.asn1_string_st */
            	4418, 0,
            1, 8, 1, /* 4507: pointer.struct.asn1_string_st */
            	4418, 0,
            1, 8, 1, /* 4512: pointer.struct.asn1_string_st */
            	4418, 0,
            1, 8, 1, /* 4517: pointer.struct.asn1_string_st */
            	4418, 0,
            1, 8, 1, /* 4522: pointer.struct.asn1_string_st */
            	4418, 0,
            1, 8, 1, /* 4527: pointer.struct.asn1_string_st */
            	4418, 0,
            1, 8, 1, /* 4532: pointer.struct.asn1_string_st */
            	4418, 0,
            1, 8, 1, /* 4537: pointer.struct.asn1_string_st */
            	4418, 0,
            1, 8, 1, /* 4542: pointer.struct.asn1_string_st */
            	4418, 0,
            1, 8, 1, /* 4547: pointer.struct.asn1_string_st */
            	4418, 0,
            1, 8, 1, /* 4552: pointer.struct.asn1_string_st */
            	4418, 0,
            1, 8, 1, /* 4557: pointer.struct.asn1_string_st */
            	4418, 0,
            1, 8, 1, /* 4562: pointer.struct.asn1_string_st */
            	4418, 0,
            1, 8, 1, /* 4567: pointer.struct.asn1_string_st */
            	4418, 0,
            1, 8, 1, /* 4572: pointer.struct.X509_name_st */
            	4577, 0,
            0, 40, 3, /* 4577: struct.X509_name_st */
            	4586, 0,
            	4610, 16,
            	78, 24,
            1, 8, 1, /* 4586: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4591, 0,
            0, 32, 2, /* 4591: struct.stack_st_fake_X509_NAME_ENTRY */
            	4598, 8,
            	86, 24,
            64099, 8, 2, /* 4598: pointer_to_array_of_pointers_to_stack */
            	4605, 0,
            	83, 20,
            0, 8, 1, /* 4605: pointer.X509_NAME_ENTRY */
            	128, 0,
            1, 8, 1, /* 4610: pointer.struct.buf_mem_st */
            	4615, 0,
            0, 24, 1, /* 4615: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 4620: pointer.struct.X509_val_st */
            	4625, 0,
            0, 16, 2, /* 4625: struct.X509_val_st */
            	4632, 0,
            	4632, 8,
            1, 8, 1, /* 4632: pointer.struct.asn1_string_st */
            	4418, 0,
            1, 8, 1, /* 4637: pointer.struct.X509_pubkey_st */
            	4642, 0,
            0, 24, 3, /* 4642: struct.X509_pubkey_st */
            	4423, 0,
            	4512, 8,
            	4651, 16,
            1, 8, 1, /* 4651: pointer.struct.evp_pkey_st */
            	4656, 0,
            0, 56, 4, /* 4656: struct.evp_pkey_st */
            	4667, 16,
            	4675, 24,
            	4683, 32,
            	5004, 48,
            1, 8, 1, /* 4667: pointer.struct.evp_pkey_asn1_method_st */
            	4672, 0,
            0, 0, 0, /* 4672: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 4675: pointer.struct.engine_st */
            	4680, 0,
            0, 0, 0, /* 4680: struct.engine_st */
            0, 8, 5, /* 4683: union.unknown */
            	99, 0,
            	4696, 0,
            	4847, 0,
            	4928, 0,
            	4996, 0,
            1, 8, 1, /* 4696: pointer.struct.rsa_st */
            	4701, 0,
            0, 168, 17, /* 4701: struct.rsa_st */
            	4738, 16,
            	4675, 24,
            	4793, 32,
            	4793, 40,
            	4793, 48,
            	4793, 56,
            	4793, 64,
            	4793, 72,
            	4793, 80,
            	4793, 88,
            	4803, 96,
            	4825, 120,
            	4825, 128,
            	4825, 136,
            	99, 144,
            	4839, 152,
            	4839, 160,
            1, 8, 1, /* 4738: pointer.struct.rsa_meth_st */
            	4743, 0,
            0, 112, 13, /* 4743: struct.rsa_meth_st */
            	5, 0,
            	4772, 8,
            	4772, 16,
            	4772, 24,
            	4772, 32,
            	4775, 40,
            	4778, 48,
            	4781, 56,
            	4781, 64,
            	99, 80,
            	4784, 88,
            	4787, 96,
            	4790, 104,
            64097, 8, 0, /* 4772: pointer.func */
            64097, 8, 0, /* 4775: pointer.func */
            64097, 8, 0, /* 4778: pointer.func */
            64097, 8, 0, /* 4781: pointer.func */
            64097, 8, 0, /* 4784: pointer.func */
            64097, 8, 0, /* 4787: pointer.func */
            64097, 8, 0, /* 4790: pointer.func */
            1, 8, 1, /* 4793: pointer.struct.bignum_st */
            	4798, 0,
            0, 24, 1, /* 4798: struct.bignum_st */
            	767, 0,
            0, 16, 1, /* 4803: struct.crypto_ex_data_st */
            	4808, 0,
            1, 8, 1, /* 4808: pointer.struct.stack_st_void */
            	4813, 0,
            0, 32, 1, /* 4813: struct.stack_st_void */
            	4818, 0,
            0, 32, 2, /* 4818: struct.stack_st */
            	797, 8,
            	86, 24,
            1, 8, 1, /* 4825: pointer.struct.bn_mont_ctx_st */
            	4830, 0,
            0, 96, 3, /* 4830: struct.bn_mont_ctx_st */
            	4798, 8,
            	4798, 32,
            	4798, 56,
            1, 8, 1, /* 4839: pointer.struct.bn_blinding_st */
            	4844, 0,
            0, 0, 0, /* 4844: struct.bn_blinding_st */
            1, 8, 1, /* 4847: pointer.struct.dsa_st */
            	4852, 0,
            0, 136, 11, /* 4852: struct.dsa_st */
            	4793, 24,
            	4793, 32,
            	4793, 40,
            	4793, 48,
            	4793, 56,
            	4793, 64,
            	4793, 72,
            	4825, 88,
            	4803, 104,
            	4877, 120,
            	4675, 128,
            1, 8, 1, /* 4877: pointer.struct.dsa_method */
            	4882, 0,
            0, 96, 11, /* 4882: struct.dsa_method */
            	5, 0,
            	4907, 8,
            	4910, 16,
            	4913, 24,
            	4916, 32,
            	4919, 40,
            	4922, 48,
            	4922, 56,
            	99, 72,
            	4925, 80,
            	4922, 88,
            64097, 8, 0, /* 4907: pointer.func */
            64097, 8, 0, /* 4910: pointer.func */
            64097, 8, 0, /* 4913: pointer.func */
            64097, 8, 0, /* 4916: pointer.func */
            64097, 8, 0, /* 4919: pointer.func */
            64097, 8, 0, /* 4922: pointer.func */
            64097, 8, 0, /* 4925: pointer.func */
            1, 8, 1, /* 4928: pointer.struct.dh_st */
            	4933, 0,
            0, 144, 12, /* 4933: struct.dh_st */
            	4793, 8,
            	4793, 16,
            	4793, 32,
            	4793, 40,
            	4825, 56,
            	4793, 64,
            	4793, 72,
            	78, 80,
            	4793, 96,
            	4803, 112,
            	4960, 128,
            	4675, 136,
            1, 8, 1, /* 4960: pointer.struct.dh_method */
            	4965, 0,
            0, 72, 8, /* 4965: struct.dh_method */
            	5, 0,
            	4984, 8,
            	4987, 16,
            	4990, 24,
            	4984, 32,
            	4984, 40,
            	99, 56,
            	4993, 64,
            64097, 8, 0, /* 4984: pointer.func */
            64097, 8, 0, /* 4987: pointer.func */
            64097, 8, 0, /* 4990: pointer.func */
            64097, 8, 0, /* 4993: pointer.func */
            1, 8, 1, /* 4996: pointer.struct.ec_key_st */
            	5001, 0,
            0, 0, 0, /* 5001: struct.ec_key_st */
            1, 8, 1, /* 5004: pointer.struct.stack_st_X509_ATTRIBUTE */
            	5009, 0,
            0, 32, 2, /* 5009: struct.stack_st_fake_X509_ATTRIBUTE */
            	5016, 8,
            	86, 24,
            64099, 8, 2, /* 5016: pointer_to_array_of_pointers_to_stack */
            	5023, 0,
            	83, 20,
            0, 8, 1, /* 5023: pointer.X509_ATTRIBUTE */
            	1005, 0,
            1, 8, 1, /* 5028: pointer.struct.stack_st_X509_EXTENSION */
            	5033, 0,
            0, 32, 2, /* 5033: struct.stack_st_fake_X509_EXTENSION */
            	5040, 8,
            	86, 24,
            64099, 8, 2, /* 5040: pointer_to_array_of_pointers_to_stack */
            	5047, 0,
            	83, 20,
            0, 8, 1, /* 5047: pointer.X509_EXTENSION */
            	34, 0,
            0, 24, 1, /* 5052: struct.ASN1_ENCODING_st */
            	78, 0,
            1, 8, 1, /* 5057: pointer.struct.AUTHORITY_KEYID_st */
            	5062, 0,
            0, 0, 0, /* 5062: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 5065: pointer.struct.X509_POLICY_CACHE_st */
            	5070, 0,
            0, 0, 0, /* 5070: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 5073: pointer.struct.stack_st_DIST_POINT */
            	5078, 0,
            0, 32, 2, /* 5078: struct.stack_st_fake_DIST_POINT */
            	5085, 8,
            	86, 24,
            64099, 8, 2, /* 5085: pointer_to_array_of_pointers_to_stack */
            	5092, 0,
            	83, 20,
            0, 8, 1, /* 5092: pointer.DIST_POINT */
            	1429, 0,
            1, 8, 1, /* 5097: pointer.struct.stack_st_GENERAL_NAME */
            	5102, 0,
            0, 32, 2, /* 5102: struct.stack_st_fake_GENERAL_NAME */
            	5109, 8,
            	86, 24,
            64099, 8, 2, /* 5109: pointer_to_array_of_pointers_to_stack */
            	5116, 0,
            	83, 20,
            0, 8, 1, /* 5116: pointer.GENERAL_NAME */
            	1486, 0,
            1, 8, 1, /* 5121: pointer.struct.NAME_CONSTRAINTS_st */
            	5126, 0,
            0, 0, 0, /* 5126: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 5129: pointer.struct.x509_cert_aux_st */
            	5134, 0,
            0, 40, 5, /* 5134: struct.x509_cert_aux_st */
            	5147, 0,
            	5147, 8,
            	4567, 16,
            	4517, 24,
            	5171, 32,
            1, 8, 1, /* 5147: pointer.struct.stack_st_ASN1_OBJECT */
            	5152, 0,
            0, 32, 2, /* 5152: struct.stack_st_fake_ASN1_OBJECT */
            	5159, 8,
            	86, 24,
            64099, 8, 2, /* 5159: pointer_to_array_of_pointers_to_stack */
            	5166, 0,
            	83, 20,
            0, 8, 1, /* 5166: pointer.ASN1_OBJECT */
            	1888, 0,
            1, 8, 1, /* 5171: pointer.struct.stack_st_X509_ALGOR */
            	5176, 0,
            0, 32, 2, /* 5176: struct.stack_st_fake_X509_ALGOR */
            	5183, 8,
            	86, 24,
            64099, 8, 2, /* 5183: pointer_to_array_of_pointers_to_stack */
            	5190, 0,
            	83, 20,
            0, 8, 1, /* 5190: pointer.X509_ALGOR */
            	1926, 0,
            1, 8, 1, /* 5195: pointer.struct.X509_crl_st */
            	5200, 0,
            0, 120, 10, /* 5200: struct.X509_crl_st */
            	5223, 0,
            	4423, 8,
            	4512, 16,
            	5057, 32,
            	5350, 40,
            	4413, 56,
            	4413, 64,
            	5358, 96,
            	5399, 104,
            	3539, 112,
            1, 8, 1, /* 5223: pointer.struct.X509_crl_info_st */
            	5228, 0,
            0, 80, 8, /* 5228: struct.X509_crl_info_st */
            	4413, 0,
            	4423, 8,
            	4572, 16,
            	4632, 24,
            	4632, 32,
            	5247, 40,
            	5028, 48,
            	5052, 56,
            1, 8, 1, /* 5247: pointer.struct.stack_st_X509_REVOKED */
            	5252, 0,
            0, 32, 2, /* 5252: struct.stack_st_fake_X509_REVOKED */
            	5259, 8,
            	86, 24,
            64099, 8, 2, /* 5259: pointer_to_array_of_pointers_to_stack */
            	5266, 0,
            	83, 20,
            0, 8, 1, /* 5266: pointer.X509_REVOKED */
            	5271, 0,
            0, 0, 1, /* 5271: X509_REVOKED */
            	5276, 0,
            0, 40, 4, /* 5276: struct.x509_revoked_st */
            	5287, 0,
            	5297, 8,
            	5302, 16,
            	5326, 24,
            1, 8, 1, /* 5287: pointer.struct.asn1_string_st */
            	5292, 0,
            0, 24, 1, /* 5292: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 5297: pointer.struct.asn1_string_st */
            	5292, 0,
            1, 8, 1, /* 5302: pointer.struct.stack_st_X509_EXTENSION */
            	5307, 0,
            0, 32, 2, /* 5307: struct.stack_st_fake_X509_EXTENSION */
            	5314, 8,
            	86, 24,
            64099, 8, 2, /* 5314: pointer_to_array_of_pointers_to_stack */
            	5321, 0,
            	83, 20,
            0, 8, 1, /* 5321: pointer.X509_EXTENSION */
            	34, 0,
            1, 8, 1, /* 5326: pointer.struct.stack_st_GENERAL_NAME */
            	5331, 0,
            0, 32, 2, /* 5331: struct.stack_st_fake_GENERAL_NAME */
            	5338, 8,
            	86, 24,
            64099, 8, 2, /* 5338: pointer_to_array_of_pointers_to_stack */
            	5345, 0,
            	83, 20,
            0, 8, 1, /* 5345: pointer.GENERAL_NAME */
            	1486, 0,
            1, 8, 1, /* 5350: pointer.struct.ISSUING_DIST_POINT_st */
            	5355, 0,
            0, 0, 0, /* 5355: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 5358: pointer.struct.stack_st_GENERAL_NAMES */
            	5363, 0,
            0, 32, 2, /* 5363: struct.stack_st_fake_GENERAL_NAMES */
            	5370, 8,
            	86, 24,
            64099, 8, 2, /* 5370: pointer_to_array_of_pointers_to_stack */
            	5377, 0,
            	83, 20,
            0, 8, 1, /* 5377: pointer.GENERAL_NAMES */
            	5382, 0,
            0, 0, 1, /* 5382: GENERAL_NAMES */
            	5387, 0,
            0, 32, 1, /* 5387: struct.stack_st_GENERAL_NAME */
            	5392, 0,
            0, 32, 2, /* 5392: struct.stack_st */
            	797, 8,
            	86, 24,
            1, 8, 1, /* 5399: pointer.struct.x509_crl_method_st */
            	5404, 0,
            0, 0, 0, /* 5404: struct.x509_crl_method_st */
            1, 8, 1, /* 5407: pointer.struct.stack_st_X509_LOOKUP */
            	5412, 0,
            0, 32, 2, /* 5412: struct.stack_st_fake_X509_LOOKUP */
            	5419, 8,
            	86, 24,
            64099, 8, 2, /* 5419: pointer_to_array_of_pointers_to_stack */
            	5426, 0,
            	83, 20,
            0, 8, 1, /* 5426: pointer.X509_LOOKUP */
            	5431, 0,
            0, 0, 1, /* 5431: X509_LOOKUP */
            	5436, 0,
            0, 32, 3, /* 5436: struct.x509_lookup_st */
            	5445, 8,
            	99, 16,
            	5494, 24,
            1, 8, 1, /* 5445: pointer.struct.x509_lookup_method_st */
            	5450, 0,
            0, 80, 10, /* 5450: struct.x509_lookup_method_st */
            	5, 0,
            	5473, 8,
            	5476, 16,
            	5473, 24,
            	5473, 32,
            	5479, 40,
            	5482, 48,
            	5485, 56,
            	5488, 64,
            	5491, 72,
            64097, 8, 0, /* 5473: pointer.func */
            64097, 8, 0, /* 5476: pointer.func */
            64097, 8, 0, /* 5479: pointer.func */
            64097, 8, 0, /* 5482: pointer.func */
            64097, 8, 0, /* 5485: pointer.func */
            64097, 8, 0, /* 5488: pointer.func */
            64097, 8, 0, /* 5491: pointer.func */
            1, 8, 1, /* 5494: pointer.struct.x509_store_st */
            	5499, 0,
            0, 144, 15, /* 5499: struct.x509_store_st */
            	5532, 8,
            	5556, 16,
            	5580, 24,
            	5592, 32,
            	5595, 40,
            	5598, 48,
            	5601, 56,
            	5592, 64,
            	5604, 72,
            	5607, 80,
            	5610, 88,
            	5613, 96,
            	5616, 104,
            	5592, 112,
            	4803, 120,
            1, 8, 1, /* 5532: pointer.struct.stack_st_X509_OBJECT */
            	5537, 0,
            0, 32, 2, /* 5537: struct.stack_st_fake_X509_OBJECT */
            	5544, 8,
            	86, 24,
            64099, 8, 2, /* 5544: pointer_to_array_of_pointers_to_stack */
            	5551, 0,
            	83, 20,
            0, 8, 1, /* 5551: pointer.X509_OBJECT */
            	4330, 0,
            1, 8, 1, /* 5556: pointer.struct.stack_st_X509_LOOKUP */
            	5561, 0,
            0, 32, 2, /* 5561: struct.stack_st_fake_X509_LOOKUP */
            	5568, 8,
            	86, 24,
            64099, 8, 2, /* 5568: pointer_to_array_of_pointers_to_stack */
            	5575, 0,
            	83, 20,
            0, 8, 1, /* 5575: pointer.X509_LOOKUP */
            	5431, 0,
            1, 8, 1, /* 5580: pointer.struct.X509_VERIFY_PARAM_st */
            	5585, 0,
            0, 56, 2, /* 5585: struct.X509_VERIFY_PARAM_st */
            	99, 0,
            	5147, 48,
            64097, 8, 0, /* 5592: pointer.func */
            64097, 8, 0, /* 5595: pointer.func */
            64097, 8, 0, /* 5598: pointer.func */
            64097, 8, 0, /* 5601: pointer.func */
            64097, 8, 0, /* 5604: pointer.func */
            64097, 8, 0, /* 5607: pointer.func */
            64097, 8, 0, /* 5610: pointer.func */
            64097, 8, 0, /* 5613: pointer.func */
            64097, 8, 0, /* 5616: pointer.func */
            64097, 8, 0, /* 5619: pointer.func */
            64097, 8, 0, /* 5622: pointer.func */
            64097, 8, 0, /* 5625: pointer.func */
            64097, 8, 0, /* 5628: pointer.func */
            64097, 8, 0, /* 5631: pointer.func */
            64097, 8, 0, /* 5634: pointer.func */
            64097, 8, 0, /* 5637: pointer.func */
            64097, 8, 0, /* 5640: pointer.func */
            1, 8, 1, /* 5643: pointer.struct.lhash_st */
            	5648, 0,
            0, 176, 3, /* 5648: struct.lhash_st */
            	5657, 0,
            	86, 8,
            	5679, 16,
            1, 8, 1, /* 5657: pointer.pointer.struct.lhash_node_st */
            	5662, 0,
            1, 8, 1, /* 5662: pointer.struct.lhash_node_st */
            	5667, 0,
            0, 24, 2, /* 5667: struct.lhash_node_st */
            	3539, 0,
            	5674, 8,
            1, 8, 1, /* 5674: pointer.struct.lhash_node_st */
            	5667, 0,
            64097, 8, 0, /* 5679: pointer.func */
            64097, 8, 0, /* 5682: pointer.func */
            64097, 8, 0, /* 5685: pointer.func */
            64097, 8, 0, /* 5688: pointer.func */
            64097, 8, 0, /* 5691: pointer.func */
            64097, 8, 0, /* 5694: pointer.func */
            64097, 8, 0, /* 5697: pointer.func */
            64097, 8, 0, /* 5700: pointer.func */
            64097, 8, 0, /* 5703: pointer.func */
            1, 8, 1, /* 5706: pointer.struct.stack_st_SSL_COMP */
            	5711, 0,
            0, 32, 2, /* 5711: struct.stack_st_fake_SSL_COMP */
            	5718, 8,
            	86, 24,
            64099, 8, 2, /* 5718: pointer_to_array_of_pointers_to_stack */
            	5725, 0,
            	83, 20,
            0, 8, 1, /* 5725: pointer.SSL_COMP */
            	5730, 0,
            0, 0, 1, /* 5730: SSL_COMP */
            	5735, 0,
            0, 24, 2, /* 5735: struct.ssl_comp_st */
            	5, 8,
            	5742, 16,
            1, 8, 1, /* 5742: pointer.struct.comp_method_st */
            	5747, 0,
            0, 64, 7, /* 5747: struct.comp_method_st */
            	5, 8,
            	5764, 16,
            	5767, 24,
            	5770, 32,
            	5770, 40,
            	3432, 48,
            	3432, 56,
            64097, 8, 0, /* 5764: pointer.func */
            64097, 8, 0, /* 5767: pointer.func */
            64097, 8, 0, /* 5770: pointer.func */
            64097, 8, 0, /* 5773: pointer.func */
            64097, 8, 0, /* 5776: pointer.func */
            64097, 8, 0, /* 5779: pointer.func */
            64097, 8, 0, /* 5782: pointer.func */
            1, 8, 1, /* 5785: pointer.struct.ssl3_buf_freelist_st */
            	5790, 0,
            0, 24, 1, /* 5790: struct.ssl3_buf_freelist_st */
            	5795, 16,
            1, 8, 1, /* 5795: pointer.struct.ssl3_buf_freelist_entry_st */
            	5800, 0,
            0, 8, 1, /* 5800: struct.ssl3_buf_freelist_entry_st */
            	5795, 0,
            0, 128, 14, /* 5805: struct.srp_ctx_st */
            	3539, 0,
            	5773, 8,
            	5779, 16,
            	5836, 24,
            	99, 32,
            	2549, 40,
            	2549, 48,
            	2549, 56,
            	2549, 64,
            	2549, 72,
            	2549, 80,
            	2549, 88,
            	2549, 96,
            	99, 104,
            64097, 8, 0, /* 5836: pointer.func */
            64097, 8, 0, /* 5839: pointer.func */
            64097, 8, 0, /* 5842: pointer.func */
            1, 8, 1, /* 5845: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	5850, 0,
            0, 32, 2, /* 5850: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	5857, 8,
            	86, 24,
            64099, 8, 2, /* 5857: pointer_to_array_of_pointers_to_stack */
            	5864, 0,
            	83, 20,
            0, 8, 1, /* 5864: pointer.SRTP_PROTECTION_PROFILE */
            	5869, 0,
            0, 0, 1, /* 5869: SRTP_PROTECTION_PROFILE */
            	5874, 0,
            0, 16, 1, /* 5874: struct.srtp_protection_profile_st */
            	5, 0,
            64097, 8, 0, /* 5879: pointer.func */
            1, 8, 1, /* 5882: pointer.struct.tls_session_ticket_ext_st */
            	5887, 0,
            0, 16, 1, /* 5887: struct.tls_session_ticket_ext_st */
            	3539, 8,
            64097, 8, 0, /* 5892: pointer.func */
            64097, 8, 0, /* 5895: pointer.func */
            1, 8, 1, /* 5898: pointer.struct.srtp_protection_profile_st */
            	0, 0,
            0, 1, 0, /* 5903: char */
        },
        .arg_entity_index = { 3818, },
        .ret_entity_index = 4160,
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

