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
            0, 0, 1, /* 229: SRTP_PROTECTION_PROFILE */
            	234, 0,
            0, 16, 1, /* 234: struct.srtp_protection_profile_st */
            	5, 0,
            8884097, 8, 0, /* 239: pointer.func */
            0, 128, 14, /* 242: struct.srp_ctx_st */
            	273, 0,
            	276, 8,
            	279, 16,
            	282, 24,
            	178, 32,
            	285, 40,
            	285, 48,
            	285, 56,
            	285, 64,
            	285, 72,
            	285, 80,
            	285, 88,
            	285, 96,
            	178, 104,
            0, 8, 0, /* 273: pointer.void */
            8884097, 8, 0, /* 276: pointer.func */
            8884097, 8, 0, /* 279: pointer.func */
            8884097, 8, 0, /* 282: pointer.func */
            1, 8, 1, /* 285: pointer.struct.bignum_st */
            	290, 0,
            0, 24, 1, /* 290: struct.bignum_st */
            	295, 0,
            1, 8, 1, /* 295: pointer.unsigned int */
            	300, 0,
            0, 4, 0, /* 300: unsigned int */
            1, 8, 1, /* 303: pointer.struct.ssl3_buf_freelist_entry_st */
            	308, 0,
            0, 8, 1, /* 308: struct.ssl3_buf_freelist_entry_st */
            	303, 0,
            8884097, 8, 0, /* 313: pointer.func */
            8884097, 8, 0, /* 316: pointer.func */
            8884097, 8, 0, /* 319: pointer.func */
            8884097, 8, 0, /* 322: pointer.func */
            0, 64, 7, /* 325: struct.comp_method_st */
            	5, 8,
            	322, 16,
            	319, 24,
            	316, 32,
            	316, 40,
            	342, 48,
            	342, 56,
            8884097, 8, 0, /* 342: pointer.func */
            1, 8, 1, /* 345: pointer.struct.comp_method_st */
            	325, 0,
            1, 8, 1, /* 350: pointer.struct.stack_st_SSL_COMP */
            	355, 0,
            0, 32, 2, /* 355: struct.stack_st_fake_SSL_COMP */
            	362, 8,
            	86, 24,
            8884099, 8, 2, /* 362: pointer_to_array_of_pointers_to_stack */
            	369, 0,
            	83, 20,
            0, 8, 1, /* 369: pointer.SSL_COMP */
            	374, 0,
            0, 0, 1, /* 374: SSL_COMP */
            	379, 0,
            0, 24, 2, /* 379: struct.ssl_comp_st */
            	5, 8,
            	345, 16,
            8884097, 8, 0, /* 386: pointer.func */
            8884097, 8, 0, /* 389: pointer.func */
            8884097, 8, 0, /* 392: pointer.func */
            1, 8, 1, /* 395: pointer.struct.lhash_node_st */
            	400, 0,
            0, 24, 2, /* 400: struct.lhash_node_st */
            	273, 0,
            	395, 8,
            1, 8, 1, /* 407: pointer.struct.lhash_node_st */
            	400, 0,
            1, 8, 1, /* 412: pointer.pointer.struct.lhash_node_st */
            	407, 0,
            0, 176, 3, /* 417: struct.lhash_st */
            	412, 0,
            	86, 8,
            	426, 16,
            8884097, 8, 0, /* 426: pointer.func */
            8884097, 8, 0, /* 429: pointer.func */
            8884097, 8, 0, /* 432: pointer.func */
            8884097, 8, 0, /* 435: pointer.func */
            8884097, 8, 0, /* 438: pointer.func */
            8884097, 8, 0, /* 441: pointer.func */
            8884097, 8, 0, /* 444: pointer.func */
            8884097, 8, 0, /* 447: pointer.func */
            8884097, 8, 0, /* 450: pointer.func */
            8884097, 8, 0, /* 453: pointer.func */
            8884097, 8, 0, /* 456: pointer.func */
            8884097, 8, 0, /* 459: pointer.func */
            1, 8, 1, /* 462: pointer.struct.stack_st_X509_LOOKUP */
            	467, 0,
            0, 32, 2, /* 467: struct.stack_st_fake_X509_LOOKUP */
            	474, 8,
            	86, 24,
            8884099, 8, 2, /* 474: pointer_to_array_of_pointers_to_stack */
            	481, 0,
            	83, 20,
            0, 8, 1, /* 481: pointer.X509_LOOKUP */
            	486, 0,
            0, 0, 1, /* 486: X509_LOOKUP */
            	491, 0,
            0, 32, 3, /* 491: struct.x509_lookup_st */
            	500, 8,
            	178, 16,
            	549, 24,
            1, 8, 1, /* 500: pointer.struct.x509_lookup_method_st */
            	505, 0,
            0, 80, 10, /* 505: struct.x509_lookup_method_st */
            	5, 0,
            	528, 8,
            	531, 16,
            	528, 24,
            	528, 32,
            	534, 40,
            	537, 48,
            	540, 56,
            	543, 64,
            	546, 72,
            8884097, 8, 0, /* 528: pointer.func */
            8884097, 8, 0, /* 531: pointer.func */
            8884097, 8, 0, /* 534: pointer.func */
            8884097, 8, 0, /* 537: pointer.func */
            8884097, 8, 0, /* 540: pointer.func */
            8884097, 8, 0, /* 543: pointer.func */
            8884097, 8, 0, /* 546: pointer.func */
            1, 8, 1, /* 549: pointer.struct.x509_store_st */
            	554, 0,
            0, 144, 15, /* 554: struct.x509_store_st */
            	587, 8,
            	462, 16,
            	2606, 24,
            	456, 32,
            	453, 40,
            	450, 48,
            	447, 56,
            	456, 64,
            	444, 72,
            	2618, 80,
            	2621, 88,
            	441, 96,
            	438, 104,
            	456, 112,
            	1092, 120,
            1, 8, 1, /* 587: pointer.struct.stack_st_X509_OBJECT */
            	592, 0,
            0, 32, 2, /* 592: struct.stack_st_fake_X509_OBJECT */
            	599, 8,
            	86, 24,
            8884099, 8, 2, /* 599: pointer_to_array_of_pointers_to_stack */
            	606, 0,
            	83, 20,
            0, 8, 1, /* 606: pointer.X509_OBJECT */
            	611, 0,
            0, 0, 1, /* 611: X509_OBJECT */
            	616, 0,
            0, 16, 1, /* 616: struct.x509_object_st */
            	621, 8,
            0, 8, 4, /* 621: union.unknown */
            	178, 0,
            	632, 0,
            	2394, 0,
            	940, 0,
            1, 8, 1, /* 632: pointer.struct.x509_st */
            	637, 0,
            0, 184, 12, /* 637: struct.x509_st */
            	664, 0,
            	704, 8,
            	793, 16,
            	178, 32,
            	1092, 40,
            	798, 104,
            	1698, 112,
            	1706, 120,
            	1714, 128,
            	2123, 136,
            	2147, 144,
            	2155, 176,
            1, 8, 1, /* 664: pointer.struct.x509_cinf_st */
            	669, 0,
            0, 104, 11, /* 669: struct.x509_cinf_st */
            	694, 0,
            	694, 8,
            	704, 16,
            	861, 24,
            	909, 32,
            	861, 40,
            	926, 48,
            	793, 56,
            	793, 64,
            	1669, 72,
            	1693, 80,
            1, 8, 1, /* 694: pointer.struct.asn1_string_st */
            	699, 0,
            0, 24, 1, /* 699: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 704: pointer.struct.X509_algor_st */
            	709, 0,
            0, 16, 2, /* 709: struct.X509_algor_st */
            	716, 0,
            	730, 8,
            1, 8, 1, /* 716: pointer.struct.asn1_object_st */
            	721, 0,
            0, 40, 3, /* 721: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 730: pointer.struct.asn1_type_st */
            	735, 0,
            0, 16, 1, /* 735: struct.asn1_type_st */
            	740, 8,
            0, 8, 20, /* 740: union.unknown */
            	178, 0,
            	783, 0,
            	716, 0,
            	694, 0,
            	788, 0,
            	793, 0,
            	798, 0,
            	803, 0,
            	808, 0,
            	813, 0,
            	818, 0,
            	823, 0,
            	828, 0,
            	833, 0,
            	838, 0,
            	843, 0,
            	848, 0,
            	783, 0,
            	783, 0,
            	853, 0,
            1, 8, 1, /* 783: pointer.struct.asn1_string_st */
            	699, 0,
            1, 8, 1, /* 788: pointer.struct.asn1_string_st */
            	699, 0,
            1, 8, 1, /* 793: pointer.struct.asn1_string_st */
            	699, 0,
            1, 8, 1, /* 798: pointer.struct.asn1_string_st */
            	699, 0,
            1, 8, 1, /* 803: pointer.struct.asn1_string_st */
            	699, 0,
            1, 8, 1, /* 808: pointer.struct.asn1_string_st */
            	699, 0,
            1, 8, 1, /* 813: pointer.struct.asn1_string_st */
            	699, 0,
            1, 8, 1, /* 818: pointer.struct.asn1_string_st */
            	699, 0,
            1, 8, 1, /* 823: pointer.struct.asn1_string_st */
            	699, 0,
            1, 8, 1, /* 828: pointer.struct.asn1_string_st */
            	699, 0,
            1, 8, 1, /* 833: pointer.struct.asn1_string_st */
            	699, 0,
            1, 8, 1, /* 838: pointer.struct.asn1_string_st */
            	699, 0,
            1, 8, 1, /* 843: pointer.struct.asn1_string_st */
            	699, 0,
            1, 8, 1, /* 848: pointer.struct.asn1_string_st */
            	699, 0,
            1, 8, 1, /* 853: pointer.struct.ASN1_VALUE_st */
            	858, 0,
            0, 0, 0, /* 858: struct.ASN1_VALUE_st */
            1, 8, 1, /* 861: pointer.struct.X509_name_st */
            	866, 0,
            0, 40, 3, /* 866: struct.X509_name_st */
            	875, 0,
            	899, 16,
            	78, 24,
            1, 8, 1, /* 875: pointer.struct.stack_st_X509_NAME_ENTRY */
            	880, 0,
            0, 32, 2, /* 880: struct.stack_st_fake_X509_NAME_ENTRY */
            	887, 8,
            	86, 24,
            8884099, 8, 2, /* 887: pointer_to_array_of_pointers_to_stack */
            	894, 0,
            	83, 20,
            0, 8, 1, /* 894: pointer.X509_NAME_ENTRY */
            	132, 0,
            1, 8, 1, /* 899: pointer.struct.buf_mem_st */
            	904, 0,
            0, 24, 1, /* 904: struct.buf_mem_st */
            	178, 8,
            1, 8, 1, /* 909: pointer.struct.X509_val_st */
            	914, 0,
            0, 16, 2, /* 914: struct.X509_val_st */
            	921, 0,
            	921, 8,
            1, 8, 1, /* 921: pointer.struct.asn1_string_st */
            	699, 0,
            1, 8, 1, /* 926: pointer.struct.X509_pubkey_st */
            	931, 0,
            0, 24, 3, /* 931: struct.X509_pubkey_st */
            	704, 0,
            	793, 8,
            	940, 16,
            1, 8, 1, /* 940: pointer.struct.evp_pkey_st */
            	945, 0,
            0, 56, 4, /* 945: struct.evp_pkey_st */
            	956, 16,
            	964, 24,
            	972, 32,
            	1298, 48,
            1, 8, 1, /* 956: pointer.struct.evp_pkey_asn1_method_st */
            	961, 0,
            0, 0, 0, /* 961: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 964: pointer.struct.engine_st */
            	969, 0,
            0, 0, 0, /* 969: struct.engine_st */
            0, 8, 5, /* 972: union.unknown */
            	178, 0,
            	985, 0,
            	1141, 0,
            	1222, 0,
            	1290, 0,
            1, 8, 1, /* 985: pointer.struct.rsa_st */
            	990, 0,
            0, 168, 17, /* 990: struct.rsa_st */
            	1027, 16,
            	964, 24,
            	1082, 32,
            	1082, 40,
            	1082, 48,
            	1082, 56,
            	1082, 64,
            	1082, 72,
            	1082, 80,
            	1082, 88,
            	1092, 96,
            	1119, 120,
            	1119, 128,
            	1119, 136,
            	178, 144,
            	1133, 152,
            	1133, 160,
            1, 8, 1, /* 1027: pointer.struct.rsa_meth_st */
            	1032, 0,
            0, 112, 13, /* 1032: struct.rsa_meth_st */
            	5, 0,
            	1061, 8,
            	1061, 16,
            	1061, 24,
            	1061, 32,
            	1064, 40,
            	1067, 48,
            	1070, 56,
            	1070, 64,
            	178, 80,
            	1073, 88,
            	1076, 96,
            	1079, 104,
            8884097, 8, 0, /* 1061: pointer.func */
            8884097, 8, 0, /* 1064: pointer.func */
            8884097, 8, 0, /* 1067: pointer.func */
            8884097, 8, 0, /* 1070: pointer.func */
            8884097, 8, 0, /* 1073: pointer.func */
            8884097, 8, 0, /* 1076: pointer.func */
            8884097, 8, 0, /* 1079: pointer.func */
            1, 8, 1, /* 1082: pointer.struct.bignum_st */
            	1087, 0,
            0, 24, 1, /* 1087: struct.bignum_st */
            	295, 0,
            0, 16, 1, /* 1092: struct.crypto_ex_data_st */
            	1097, 0,
            1, 8, 1, /* 1097: pointer.struct.stack_st_void */
            	1102, 0,
            0, 32, 1, /* 1102: struct.stack_st_void */
            	1107, 0,
            0, 32, 2, /* 1107: struct.stack_st */
            	1114, 8,
            	86, 24,
            1, 8, 1, /* 1114: pointer.pointer.char */
            	178, 0,
            1, 8, 1, /* 1119: pointer.struct.bn_mont_ctx_st */
            	1124, 0,
            0, 96, 3, /* 1124: struct.bn_mont_ctx_st */
            	1087, 8,
            	1087, 32,
            	1087, 56,
            1, 8, 1, /* 1133: pointer.struct.bn_blinding_st */
            	1138, 0,
            0, 0, 0, /* 1138: struct.bn_blinding_st */
            1, 8, 1, /* 1141: pointer.struct.dsa_st */
            	1146, 0,
            0, 136, 11, /* 1146: struct.dsa_st */
            	1082, 24,
            	1082, 32,
            	1082, 40,
            	1082, 48,
            	1082, 56,
            	1082, 64,
            	1082, 72,
            	1119, 88,
            	1092, 104,
            	1171, 120,
            	964, 128,
            1, 8, 1, /* 1171: pointer.struct.dsa_method */
            	1176, 0,
            0, 96, 11, /* 1176: struct.dsa_method */
            	5, 0,
            	1201, 8,
            	1204, 16,
            	1207, 24,
            	1210, 32,
            	1213, 40,
            	1216, 48,
            	1216, 56,
            	178, 72,
            	1219, 80,
            	1216, 88,
            8884097, 8, 0, /* 1201: pointer.func */
            8884097, 8, 0, /* 1204: pointer.func */
            8884097, 8, 0, /* 1207: pointer.func */
            8884097, 8, 0, /* 1210: pointer.func */
            8884097, 8, 0, /* 1213: pointer.func */
            8884097, 8, 0, /* 1216: pointer.func */
            8884097, 8, 0, /* 1219: pointer.func */
            1, 8, 1, /* 1222: pointer.struct.dh_st */
            	1227, 0,
            0, 144, 12, /* 1227: struct.dh_st */
            	1082, 8,
            	1082, 16,
            	1082, 32,
            	1082, 40,
            	1119, 56,
            	1082, 64,
            	1082, 72,
            	78, 80,
            	1082, 96,
            	1092, 112,
            	1254, 128,
            	964, 136,
            1, 8, 1, /* 1254: pointer.struct.dh_method */
            	1259, 0,
            0, 72, 8, /* 1259: struct.dh_method */
            	5, 0,
            	1278, 8,
            	1281, 16,
            	1284, 24,
            	1278, 32,
            	1278, 40,
            	178, 56,
            	1287, 64,
            8884097, 8, 0, /* 1278: pointer.func */
            8884097, 8, 0, /* 1281: pointer.func */
            8884097, 8, 0, /* 1284: pointer.func */
            8884097, 8, 0, /* 1287: pointer.func */
            1, 8, 1, /* 1290: pointer.struct.ec_key_st */
            	1295, 0,
            0, 0, 0, /* 1295: struct.ec_key_st */
            1, 8, 1, /* 1298: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1303, 0,
            0, 32, 2, /* 1303: struct.stack_st_fake_X509_ATTRIBUTE */
            	1310, 8,
            	86, 24,
            8884099, 8, 2, /* 1310: pointer_to_array_of_pointers_to_stack */
            	1317, 0,
            	83, 20,
            0, 8, 1, /* 1317: pointer.X509_ATTRIBUTE */
            	1322, 0,
            0, 0, 1, /* 1322: X509_ATTRIBUTE */
            	1327, 0,
            0, 24, 2, /* 1327: struct.x509_attributes_st */
            	1334, 0,
            	1348, 16,
            1, 8, 1, /* 1334: pointer.struct.asn1_object_st */
            	1339, 0,
            0, 40, 3, /* 1339: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            0, 8, 3, /* 1348: union.unknown */
            	178, 0,
            	1357, 0,
            	1536, 0,
            1, 8, 1, /* 1357: pointer.struct.stack_st_ASN1_TYPE */
            	1362, 0,
            0, 32, 2, /* 1362: struct.stack_st_fake_ASN1_TYPE */
            	1369, 8,
            	86, 24,
            8884099, 8, 2, /* 1369: pointer_to_array_of_pointers_to_stack */
            	1376, 0,
            	83, 20,
            0, 8, 1, /* 1376: pointer.ASN1_TYPE */
            	1381, 0,
            0, 0, 1, /* 1381: ASN1_TYPE */
            	1386, 0,
            0, 16, 1, /* 1386: struct.asn1_type_st */
            	1391, 8,
            0, 8, 20, /* 1391: union.unknown */
            	178, 0,
            	1434, 0,
            	1444, 0,
            	1458, 0,
            	1463, 0,
            	1468, 0,
            	1473, 0,
            	1478, 0,
            	1483, 0,
            	1488, 0,
            	1493, 0,
            	1498, 0,
            	1503, 0,
            	1508, 0,
            	1513, 0,
            	1518, 0,
            	1523, 0,
            	1434, 0,
            	1434, 0,
            	1528, 0,
            1, 8, 1, /* 1434: pointer.struct.asn1_string_st */
            	1439, 0,
            0, 24, 1, /* 1439: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 1444: pointer.struct.asn1_object_st */
            	1449, 0,
            0, 40, 3, /* 1449: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 1458: pointer.struct.asn1_string_st */
            	1439, 0,
            1, 8, 1, /* 1463: pointer.struct.asn1_string_st */
            	1439, 0,
            1, 8, 1, /* 1468: pointer.struct.asn1_string_st */
            	1439, 0,
            1, 8, 1, /* 1473: pointer.struct.asn1_string_st */
            	1439, 0,
            1, 8, 1, /* 1478: pointer.struct.asn1_string_st */
            	1439, 0,
            1, 8, 1, /* 1483: pointer.struct.asn1_string_st */
            	1439, 0,
            1, 8, 1, /* 1488: pointer.struct.asn1_string_st */
            	1439, 0,
            1, 8, 1, /* 1493: pointer.struct.asn1_string_st */
            	1439, 0,
            1, 8, 1, /* 1498: pointer.struct.asn1_string_st */
            	1439, 0,
            1, 8, 1, /* 1503: pointer.struct.asn1_string_st */
            	1439, 0,
            1, 8, 1, /* 1508: pointer.struct.asn1_string_st */
            	1439, 0,
            1, 8, 1, /* 1513: pointer.struct.asn1_string_st */
            	1439, 0,
            1, 8, 1, /* 1518: pointer.struct.asn1_string_st */
            	1439, 0,
            1, 8, 1, /* 1523: pointer.struct.asn1_string_st */
            	1439, 0,
            1, 8, 1, /* 1528: pointer.struct.ASN1_VALUE_st */
            	1533, 0,
            0, 0, 0, /* 1533: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1536: pointer.struct.asn1_type_st */
            	1541, 0,
            0, 16, 1, /* 1541: struct.asn1_type_st */
            	1546, 8,
            0, 8, 20, /* 1546: union.unknown */
            	178, 0,
            	1589, 0,
            	1334, 0,
            	1599, 0,
            	1604, 0,
            	1609, 0,
            	1614, 0,
            	1619, 0,
            	1624, 0,
            	1629, 0,
            	1634, 0,
            	1639, 0,
            	1644, 0,
            	1649, 0,
            	1654, 0,
            	1659, 0,
            	1664, 0,
            	1589, 0,
            	1589, 0,
            	853, 0,
            1, 8, 1, /* 1589: pointer.struct.asn1_string_st */
            	1594, 0,
            0, 24, 1, /* 1594: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 1599: pointer.struct.asn1_string_st */
            	1594, 0,
            1, 8, 1, /* 1604: pointer.struct.asn1_string_st */
            	1594, 0,
            1, 8, 1, /* 1609: pointer.struct.asn1_string_st */
            	1594, 0,
            1, 8, 1, /* 1614: pointer.struct.asn1_string_st */
            	1594, 0,
            1, 8, 1, /* 1619: pointer.struct.asn1_string_st */
            	1594, 0,
            1, 8, 1, /* 1624: pointer.struct.asn1_string_st */
            	1594, 0,
            1, 8, 1, /* 1629: pointer.struct.asn1_string_st */
            	1594, 0,
            1, 8, 1, /* 1634: pointer.struct.asn1_string_st */
            	1594, 0,
            1, 8, 1, /* 1639: pointer.struct.asn1_string_st */
            	1594, 0,
            1, 8, 1, /* 1644: pointer.struct.asn1_string_st */
            	1594, 0,
            1, 8, 1, /* 1649: pointer.struct.asn1_string_st */
            	1594, 0,
            1, 8, 1, /* 1654: pointer.struct.asn1_string_st */
            	1594, 0,
            1, 8, 1, /* 1659: pointer.struct.asn1_string_st */
            	1594, 0,
            1, 8, 1, /* 1664: pointer.struct.asn1_string_st */
            	1594, 0,
            1, 8, 1, /* 1669: pointer.struct.stack_st_X509_EXTENSION */
            	1674, 0,
            0, 32, 2, /* 1674: struct.stack_st_fake_X509_EXTENSION */
            	1681, 8,
            	86, 24,
            8884099, 8, 2, /* 1681: pointer_to_array_of_pointers_to_stack */
            	1688, 0,
            	83, 20,
            0, 8, 1, /* 1688: pointer.X509_EXTENSION */
            	34, 0,
            0, 24, 1, /* 1693: struct.ASN1_ENCODING_st */
            	78, 0,
            1, 8, 1, /* 1698: pointer.struct.AUTHORITY_KEYID_st */
            	1703, 0,
            0, 0, 0, /* 1703: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 1706: pointer.struct.X509_POLICY_CACHE_st */
            	1711, 0,
            0, 0, 0, /* 1711: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1714: pointer.struct.stack_st_DIST_POINT */
            	1719, 0,
            0, 32, 2, /* 1719: struct.stack_st_fake_DIST_POINT */
            	1726, 8,
            	86, 24,
            8884099, 8, 2, /* 1726: pointer_to_array_of_pointers_to_stack */
            	1733, 0,
            	83, 20,
            0, 8, 1, /* 1733: pointer.DIST_POINT */
            	1738, 0,
            0, 0, 1, /* 1738: DIST_POINT */
            	1743, 0,
            0, 32, 3, /* 1743: struct.DIST_POINT_st */
            	1752, 0,
            	2113, 8,
            	1771, 16,
            1, 8, 1, /* 1752: pointer.struct.DIST_POINT_NAME_st */
            	1757, 0,
            0, 24, 2, /* 1757: struct.DIST_POINT_NAME_st */
            	1764, 8,
            	2089, 16,
            0, 8, 2, /* 1764: union.unknown */
            	1771, 0,
            	2065, 0,
            1, 8, 1, /* 1771: pointer.struct.stack_st_GENERAL_NAME */
            	1776, 0,
            0, 32, 2, /* 1776: struct.stack_st_fake_GENERAL_NAME */
            	1783, 8,
            	86, 24,
            8884099, 8, 2, /* 1783: pointer_to_array_of_pointers_to_stack */
            	1790, 0,
            	83, 20,
            0, 8, 1, /* 1790: pointer.GENERAL_NAME */
            	1795, 0,
            0, 0, 1, /* 1795: GENERAL_NAME */
            	1800, 0,
            0, 16, 1, /* 1800: struct.GENERAL_NAME_st */
            	1805, 8,
            0, 8, 15, /* 1805: union.unknown */
            	178, 0,
            	1838, 0,
            	1957, 0,
            	1957, 0,
            	1864, 0,
            	2005, 0,
            	2053, 0,
            	1957, 0,
            	1942, 0,
            	1850, 0,
            	1942, 0,
            	2005, 0,
            	1957, 0,
            	1850, 0,
            	1864, 0,
            1, 8, 1, /* 1838: pointer.struct.otherName_st */
            	1843, 0,
            0, 16, 2, /* 1843: struct.otherName_st */
            	1850, 0,
            	1864, 8,
            1, 8, 1, /* 1850: pointer.struct.asn1_object_st */
            	1855, 0,
            0, 40, 3, /* 1855: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 1864: pointer.struct.asn1_type_st */
            	1869, 0,
            0, 16, 1, /* 1869: struct.asn1_type_st */
            	1874, 8,
            0, 8, 20, /* 1874: union.unknown */
            	178, 0,
            	1917, 0,
            	1850, 0,
            	1927, 0,
            	1932, 0,
            	1937, 0,
            	1942, 0,
            	1947, 0,
            	1952, 0,
            	1957, 0,
            	1962, 0,
            	1967, 0,
            	1972, 0,
            	1977, 0,
            	1982, 0,
            	1987, 0,
            	1992, 0,
            	1917, 0,
            	1917, 0,
            	1997, 0,
            1, 8, 1, /* 1917: pointer.struct.asn1_string_st */
            	1922, 0,
            0, 24, 1, /* 1922: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 1927: pointer.struct.asn1_string_st */
            	1922, 0,
            1, 8, 1, /* 1932: pointer.struct.asn1_string_st */
            	1922, 0,
            1, 8, 1, /* 1937: pointer.struct.asn1_string_st */
            	1922, 0,
            1, 8, 1, /* 1942: pointer.struct.asn1_string_st */
            	1922, 0,
            1, 8, 1, /* 1947: pointer.struct.asn1_string_st */
            	1922, 0,
            1, 8, 1, /* 1952: pointer.struct.asn1_string_st */
            	1922, 0,
            1, 8, 1, /* 1957: pointer.struct.asn1_string_st */
            	1922, 0,
            1, 8, 1, /* 1962: pointer.struct.asn1_string_st */
            	1922, 0,
            1, 8, 1, /* 1967: pointer.struct.asn1_string_st */
            	1922, 0,
            1, 8, 1, /* 1972: pointer.struct.asn1_string_st */
            	1922, 0,
            1, 8, 1, /* 1977: pointer.struct.asn1_string_st */
            	1922, 0,
            1, 8, 1, /* 1982: pointer.struct.asn1_string_st */
            	1922, 0,
            1, 8, 1, /* 1987: pointer.struct.asn1_string_st */
            	1922, 0,
            1, 8, 1, /* 1992: pointer.struct.asn1_string_st */
            	1922, 0,
            1, 8, 1, /* 1997: pointer.struct.ASN1_VALUE_st */
            	2002, 0,
            0, 0, 0, /* 2002: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2005: pointer.struct.X509_name_st */
            	2010, 0,
            0, 40, 3, /* 2010: struct.X509_name_st */
            	2019, 0,
            	2043, 16,
            	78, 24,
            1, 8, 1, /* 2019: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2024, 0,
            0, 32, 2, /* 2024: struct.stack_st_fake_X509_NAME_ENTRY */
            	2031, 8,
            	86, 24,
            8884099, 8, 2, /* 2031: pointer_to_array_of_pointers_to_stack */
            	2038, 0,
            	83, 20,
            0, 8, 1, /* 2038: pointer.X509_NAME_ENTRY */
            	132, 0,
            1, 8, 1, /* 2043: pointer.struct.buf_mem_st */
            	2048, 0,
            0, 24, 1, /* 2048: struct.buf_mem_st */
            	178, 8,
            1, 8, 1, /* 2053: pointer.struct.EDIPartyName_st */
            	2058, 0,
            0, 16, 2, /* 2058: struct.EDIPartyName_st */
            	1917, 0,
            	1917, 8,
            1, 8, 1, /* 2065: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2070, 0,
            0, 32, 2, /* 2070: struct.stack_st_fake_X509_NAME_ENTRY */
            	2077, 8,
            	86, 24,
            8884099, 8, 2, /* 2077: pointer_to_array_of_pointers_to_stack */
            	2084, 0,
            	83, 20,
            0, 8, 1, /* 2084: pointer.X509_NAME_ENTRY */
            	132, 0,
            1, 8, 1, /* 2089: pointer.struct.X509_name_st */
            	2094, 0,
            0, 40, 3, /* 2094: struct.X509_name_st */
            	2065, 0,
            	2103, 16,
            	78, 24,
            1, 8, 1, /* 2103: pointer.struct.buf_mem_st */
            	2108, 0,
            0, 24, 1, /* 2108: struct.buf_mem_st */
            	178, 8,
            1, 8, 1, /* 2113: pointer.struct.asn1_string_st */
            	2118, 0,
            0, 24, 1, /* 2118: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 2123: pointer.struct.stack_st_GENERAL_NAME */
            	2128, 0,
            0, 32, 2, /* 2128: struct.stack_st_fake_GENERAL_NAME */
            	2135, 8,
            	86, 24,
            8884099, 8, 2, /* 2135: pointer_to_array_of_pointers_to_stack */
            	2142, 0,
            	83, 20,
            0, 8, 1, /* 2142: pointer.GENERAL_NAME */
            	1795, 0,
            1, 8, 1, /* 2147: pointer.struct.NAME_CONSTRAINTS_st */
            	2152, 0,
            0, 0, 0, /* 2152: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 2155: pointer.struct.x509_cert_aux_st */
            	2160, 0,
            0, 40, 5, /* 2160: struct.x509_cert_aux_st */
            	2173, 0,
            	2173, 8,
            	848, 16,
            	798, 24,
            	2211, 32,
            1, 8, 1, /* 2173: pointer.struct.stack_st_ASN1_OBJECT */
            	2178, 0,
            0, 32, 2, /* 2178: struct.stack_st_fake_ASN1_OBJECT */
            	2185, 8,
            	86, 24,
            8884099, 8, 2, /* 2185: pointer_to_array_of_pointers_to_stack */
            	2192, 0,
            	83, 20,
            0, 8, 1, /* 2192: pointer.ASN1_OBJECT */
            	2197, 0,
            0, 0, 1, /* 2197: ASN1_OBJECT */
            	2202, 0,
            0, 40, 3, /* 2202: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 2211: pointer.struct.stack_st_X509_ALGOR */
            	2216, 0,
            0, 32, 2, /* 2216: struct.stack_st_fake_X509_ALGOR */
            	2223, 8,
            	86, 24,
            8884099, 8, 2, /* 2223: pointer_to_array_of_pointers_to_stack */
            	2230, 0,
            	83, 20,
            0, 8, 1, /* 2230: pointer.X509_ALGOR */
            	2235, 0,
            0, 0, 1, /* 2235: X509_ALGOR */
            	2240, 0,
            0, 16, 2, /* 2240: struct.X509_algor_st */
            	2247, 0,
            	2261, 8,
            1, 8, 1, /* 2247: pointer.struct.asn1_object_st */
            	2252, 0,
            0, 40, 3, /* 2252: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 2261: pointer.struct.asn1_type_st */
            	2266, 0,
            0, 16, 1, /* 2266: struct.asn1_type_st */
            	2271, 8,
            0, 8, 20, /* 2271: union.unknown */
            	178, 0,
            	2314, 0,
            	2247, 0,
            	2324, 0,
            	2329, 0,
            	2334, 0,
            	2339, 0,
            	2344, 0,
            	2349, 0,
            	2354, 0,
            	2359, 0,
            	2364, 0,
            	2369, 0,
            	2374, 0,
            	2379, 0,
            	2384, 0,
            	2389, 0,
            	2314, 0,
            	2314, 0,
            	853, 0,
            1, 8, 1, /* 2314: pointer.struct.asn1_string_st */
            	2319, 0,
            0, 24, 1, /* 2319: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 2324: pointer.struct.asn1_string_st */
            	2319, 0,
            1, 8, 1, /* 2329: pointer.struct.asn1_string_st */
            	2319, 0,
            1, 8, 1, /* 2334: pointer.struct.asn1_string_st */
            	2319, 0,
            1, 8, 1, /* 2339: pointer.struct.asn1_string_st */
            	2319, 0,
            1, 8, 1, /* 2344: pointer.struct.asn1_string_st */
            	2319, 0,
            1, 8, 1, /* 2349: pointer.struct.asn1_string_st */
            	2319, 0,
            1, 8, 1, /* 2354: pointer.struct.asn1_string_st */
            	2319, 0,
            1, 8, 1, /* 2359: pointer.struct.asn1_string_st */
            	2319, 0,
            1, 8, 1, /* 2364: pointer.struct.asn1_string_st */
            	2319, 0,
            1, 8, 1, /* 2369: pointer.struct.asn1_string_st */
            	2319, 0,
            1, 8, 1, /* 2374: pointer.struct.asn1_string_st */
            	2319, 0,
            1, 8, 1, /* 2379: pointer.struct.asn1_string_st */
            	2319, 0,
            1, 8, 1, /* 2384: pointer.struct.asn1_string_st */
            	2319, 0,
            1, 8, 1, /* 2389: pointer.struct.asn1_string_st */
            	2319, 0,
            1, 8, 1, /* 2394: pointer.struct.X509_crl_st */
            	2399, 0,
            0, 120, 10, /* 2399: struct.X509_crl_st */
            	2422, 0,
            	704, 8,
            	793, 16,
            	1698, 32,
            	2549, 40,
            	694, 56,
            	694, 64,
            	2557, 96,
            	2598, 104,
            	273, 112,
            1, 8, 1, /* 2422: pointer.struct.X509_crl_info_st */
            	2427, 0,
            0, 80, 8, /* 2427: struct.X509_crl_info_st */
            	694, 0,
            	704, 8,
            	861, 16,
            	921, 24,
            	921, 32,
            	2446, 40,
            	1669, 48,
            	1693, 56,
            1, 8, 1, /* 2446: pointer.struct.stack_st_X509_REVOKED */
            	2451, 0,
            0, 32, 2, /* 2451: struct.stack_st_fake_X509_REVOKED */
            	2458, 8,
            	86, 24,
            8884099, 8, 2, /* 2458: pointer_to_array_of_pointers_to_stack */
            	2465, 0,
            	83, 20,
            0, 8, 1, /* 2465: pointer.X509_REVOKED */
            	2470, 0,
            0, 0, 1, /* 2470: X509_REVOKED */
            	2475, 0,
            0, 40, 4, /* 2475: struct.x509_revoked_st */
            	2486, 0,
            	2496, 8,
            	2501, 16,
            	2525, 24,
            1, 8, 1, /* 2486: pointer.struct.asn1_string_st */
            	2491, 0,
            0, 24, 1, /* 2491: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 2496: pointer.struct.asn1_string_st */
            	2491, 0,
            1, 8, 1, /* 2501: pointer.struct.stack_st_X509_EXTENSION */
            	2506, 0,
            0, 32, 2, /* 2506: struct.stack_st_fake_X509_EXTENSION */
            	2513, 8,
            	86, 24,
            8884099, 8, 2, /* 2513: pointer_to_array_of_pointers_to_stack */
            	2520, 0,
            	83, 20,
            0, 8, 1, /* 2520: pointer.X509_EXTENSION */
            	34, 0,
            1, 8, 1, /* 2525: pointer.struct.stack_st_GENERAL_NAME */
            	2530, 0,
            0, 32, 2, /* 2530: struct.stack_st_fake_GENERAL_NAME */
            	2537, 8,
            	86, 24,
            8884099, 8, 2, /* 2537: pointer_to_array_of_pointers_to_stack */
            	2544, 0,
            	83, 20,
            0, 8, 1, /* 2544: pointer.GENERAL_NAME */
            	1795, 0,
            1, 8, 1, /* 2549: pointer.struct.ISSUING_DIST_POINT_st */
            	2554, 0,
            0, 0, 0, /* 2554: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 2557: pointer.struct.stack_st_GENERAL_NAMES */
            	2562, 0,
            0, 32, 2, /* 2562: struct.stack_st_fake_GENERAL_NAMES */
            	2569, 8,
            	86, 24,
            8884099, 8, 2, /* 2569: pointer_to_array_of_pointers_to_stack */
            	2576, 0,
            	83, 20,
            0, 8, 1, /* 2576: pointer.GENERAL_NAMES */
            	2581, 0,
            0, 0, 1, /* 2581: GENERAL_NAMES */
            	2586, 0,
            0, 32, 1, /* 2586: struct.stack_st_GENERAL_NAME */
            	2591, 0,
            0, 32, 2, /* 2591: struct.stack_st */
            	1114, 8,
            	86, 24,
            1, 8, 1, /* 2598: pointer.struct.x509_crl_method_st */
            	2603, 0,
            0, 0, 0, /* 2603: struct.x509_crl_method_st */
            1, 8, 1, /* 2606: pointer.struct.X509_VERIFY_PARAM_st */
            	2611, 0,
            0, 56, 2, /* 2611: struct.X509_VERIFY_PARAM_st */
            	178, 0,
            	2173, 48,
            8884097, 8, 0, /* 2618: pointer.func */
            8884097, 8, 0, /* 2621: pointer.func */
            0, 16, 1, /* 2624: struct.tls_session_ticket_ext_st */
            	273, 8,
            1, 8, 1, /* 2629: pointer.struct.tls_session_ticket_ext_st */
            	2624, 0,
            8884097, 8, 0, /* 2634: pointer.func */
            8884097, 8, 0, /* 2637: pointer.func */
            1, 8, 1, /* 2640: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2645, 0,
            0, 32, 2, /* 2645: struct.stack_st_fake_X509_NAME_ENTRY */
            	2652, 8,
            	86, 24,
            8884099, 8, 2, /* 2652: pointer_to_array_of_pointers_to_stack */
            	2659, 0,
            	83, 20,
            0, 8, 1, /* 2659: pointer.X509_NAME_ENTRY */
            	132, 0,
            1, 8, 1, /* 2664: pointer.struct.asn1_string_st */
            	2669, 0,
            0, 24, 1, /* 2669: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 2674: pointer.struct.asn1_string_st */
            	2669, 0,
            0, 144, 12, /* 2679: struct.dh_st */
            	2706, 8,
            	2706, 16,
            	2706, 32,
            	2706, 40,
            	2716, 56,
            	2706, 64,
            	2706, 72,
            	78, 80,
            	2706, 96,
            	2730, 112,
            	2752, 128,
            	2788, 136,
            1, 8, 1, /* 2706: pointer.struct.bignum_st */
            	2711, 0,
            0, 24, 1, /* 2711: struct.bignum_st */
            	295, 0,
            1, 8, 1, /* 2716: pointer.struct.bn_mont_ctx_st */
            	2721, 0,
            0, 96, 3, /* 2721: struct.bn_mont_ctx_st */
            	2711, 8,
            	2711, 32,
            	2711, 56,
            0, 16, 1, /* 2730: struct.crypto_ex_data_st */
            	2735, 0,
            1, 8, 1, /* 2735: pointer.struct.stack_st_void */
            	2740, 0,
            0, 32, 1, /* 2740: struct.stack_st_void */
            	2745, 0,
            0, 32, 2, /* 2745: struct.stack_st */
            	1114, 8,
            	86, 24,
            1, 8, 1, /* 2752: pointer.struct.dh_method */
            	2757, 0,
            0, 72, 8, /* 2757: struct.dh_method */
            	5, 0,
            	2776, 8,
            	2779, 16,
            	2782, 24,
            	2776, 32,
            	2776, 40,
            	178, 56,
            	2785, 64,
            8884097, 8, 0, /* 2776: pointer.func */
            8884097, 8, 0, /* 2779: pointer.func */
            8884097, 8, 0, /* 2782: pointer.func */
            8884097, 8, 0, /* 2785: pointer.func */
            1, 8, 1, /* 2788: pointer.struct.engine_st */
            	2793, 0,
            0, 0, 0, /* 2793: struct.engine_st */
            1, 8, 1, /* 2796: pointer.struct.asn1_string_st */
            	2669, 0,
            8884097, 8, 0, /* 2801: pointer.func */
            0, 8, 20, /* 2804: union.unknown */
            	178, 0,
            	2847, 0,
            	2852, 0,
            	2866, 0,
            	2871, 0,
            	2876, 0,
            	2881, 0,
            	2886, 0,
            	2891, 0,
            	2796, 0,
            	2674, 0,
            	2896, 0,
            	2901, 0,
            	2906, 0,
            	2664, 0,
            	2911, 0,
            	2916, 0,
            	2847, 0,
            	2847, 0,
            	1997, 0,
            1, 8, 1, /* 2847: pointer.struct.asn1_string_st */
            	2669, 0,
            1, 8, 1, /* 2852: pointer.struct.asn1_object_st */
            	2857, 0,
            0, 40, 3, /* 2857: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 2866: pointer.struct.asn1_string_st */
            	2669, 0,
            1, 8, 1, /* 2871: pointer.struct.asn1_string_st */
            	2669, 0,
            1, 8, 1, /* 2876: pointer.struct.asn1_string_st */
            	2669, 0,
            1, 8, 1, /* 2881: pointer.struct.asn1_string_st */
            	2669, 0,
            1, 8, 1, /* 2886: pointer.struct.asn1_string_st */
            	2669, 0,
            1, 8, 1, /* 2891: pointer.struct.asn1_string_st */
            	2669, 0,
            1, 8, 1, /* 2896: pointer.struct.asn1_string_st */
            	2669, 0,
            1, 8, 1, /* 2901: pointer.struct.asn1_string_st */
            	2669, 0,
            1, 8, 1, /* 2906: pointer.struct.asn1_string_st */
            	2669, 0,
            1, 8, 1, /* 2911: pointer.struct.asn1_string_st */
            	2669, 0,
            1, 8, 1, /* 2916: pointer.struct.asn1_string_st */
            	2669, 0,
            0, 16, 2, /* 2921: struct.otherName_st */
            	2852, 0,
            	2928, 8,
            1, 8, 1, /* 2928: pointer.struct.asn1_type_st */
            	2933, 0,
            0, 16, 1, /* 2933: struct.asn1_type_st */
            	2804, 8,
            0, 296, 7, /* 2938: struct.cert_st */
            	2955, 0,
            	4012, 48,
            	4017, 56,
            	4020, 64,
            	4025, 72,
            	4028, 80,
            	4033, 88,
            1, 8, 1, /* 2955: pointer.struct.cert_pkey_st */
            	2960, 0,
            0, 24, 3, /* 2960: struct.cert_pkey_st */
            	2969, 0,
            	3277, 8,
            	3967, 16,
            1, 8, 1, /* 2969: pointer.struct.x509_st */
            	2974, 0,
            0, 184, 12, /* 2974: struct.x509_st */
            	3001, 0,
            	3041, 8,
            	3130, 16,
            	178, 32,
            	3419, 40,
            	3135, 104,
            	3673, 112,
            	3711, 120,
            	3719, 128,
            	3743, 136,
            	3767, 144,
            	3901, 176,
            1, 8, 1, /* 3001: pointer.struct.x509_cinf_st */
            	3006, 0,
            0, 104, 11, /* 3006: struct.x509_cinf_st */
            	3031, 0,
            	3031, 8,
            	3041, 16,
            	3198, 24,
            	3246, 32,
            	3198, 40,
            	3263, 48,
            	3130, 56,
            	3130, 64,
            	3644, 72,
            	3668, 80,
            1, 8, 1, /* 3031: pointer.struct.asn1_string_st */
            	3036, 0,
            0, 24, 1, /* 3036: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 3041: pointer.struct.X509_algor_st */
            	3046, 0,
            0, 16, 2, /* 3046: struct.X509_algor_st */
            	3053, 0,
            	3067, 8,
            1, 8, 1, /* 3053: pointer.struct.asn1_object_st */
            	3058, 0,
            0, 40, 3, /* 3058: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 3067: pointer.struct.asn1_type_st */
            	3072, 0,
            0, 16, 1, /* 3072: struct.asn1_type_st */
            	3077, 8,
            0, 8, 20, /* 3077: union.unknown */
            	178, 0,
            	3120, 0,
            	3053, 0,
            	3031, 0,
            	3125, 0,
            	3130, 0,
            	3135, 0,
            	3140, 0,
            	3145, 0,
            	3150, 0,
            	3155, 0,
            	3160, 0,
            	3165, 0,
            	3170, 0,
            	3175, 0,
            	3180, 0,
            	3185, 0,
            	3120, 0,
            	3120, 0,
            	3190, 0,
            1, 8, 1, /* 3120: pointer.struct.asn1_string_st */
            	3036, 0,
            1, 8, 1, /* 3125: pointer.struct.asn1_string_st */
            	3036, 0,
            1, 8, 1, /* 3130: pointer.struct.asn1_string_st */
            	3036, 0,
            1, 8, 1, /* 3135: pointer.struct.asn1_string_st */
            	3036, 0,
            1, 8, 1, /* 3140: pointer.struct.asn1_string_st */
            	3036, 0,
            1, 8, 1, /* 3145: pointer.struct.asn1_string_st */
            	3036, 0,
            1, 8, 1, /* 3150: pointer.struct.asn1_string_st */
            	3036, 0,
            1, 8, 1, /* 3155: pointer.struct.asn1_string_st */
            	3036, 0,
            1, 8, 1, /* 3160: pointer.struct.asn1_string_st */
            	3036, 0,
            1, 8, 1, /* 3165: pointer.struct.asn1_string_st */
            	3036, 0,
            1, 8, 1, /* 3170: pointer.struct.asn1_string_st */
            	3036, 0,
            1, 8, 1, /* 3175: pointer.struct.asn1_string_st */
            	3036, 0,
            1, 8, 1, /* 3180: pointer.struct.asn1_string_st */
            	3036, 0,
            1, 8, 1, /* 3185: pointer.struct.asn1_string_st */
            	3036, 0,
            1, 8, 1, /* 3190: pointer.struct.ASN1_VALUE_st */
            	3195, 0,
            0, 0, 0, /* 3195: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3198: pointer.struct.X509_name_st */
            	3203, 0,
            0, 40, 3, /* 3203: struct.X509_name_st */
            	3212, 0,
            	3236, 16,
            	78, 24,
            1, 8, 1, /* 3212: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3217, 0,
            0, 32, 2, /* 3217: struct.stack_st_fake_X509_NAME_ENTRY */
            	3224, 8,
            	86, 24,
            8884099, 8, 2, /* 3224: pointer_to_array_of_pointers_to_stack */
            	3231, 0,
            	83, 20,
            0, 8, 1, /* 3231: pointer.X509_NAME_ENTRY */
            	132, 0,
            1, 8, 1, /* 3236: pointer.struct.buf_mem_st */
            	3241, 0,
            0, 24, 1, /* 3241: struct.buf_mem_st */
            	178, 8,
            1, 8, 1, /* 3246: pointer.struct.X509_val_st */
            	3251, 0,
            0, 16, 2, /* 3251: struct.X509_val_st */
            	3258, 0,
            	3258, 8,
            1, 8, 1, /* 3258: pointer.struct.asn1_string_st */
            	3036, 0,
            1, 8, 1, /* 3263: pointer.struct.X509_pubkey_st */
            	3268, 0,
            0, 24, 3, /* 3268: struct.X509_pubkey_st */
            	3041, 0,
            	3130, 8,
            	3277, 16,
            1, 8, 1, /* 3277: pointer.struct.evp_pkey_st */
            	3282, 0,
            0, 56, 4, /* 3282: struct.evp_pkey_st */
            	3293, 16,
            	3301, 24,
            	3309, 32,
            	3620, 48,
            1, 8, 1, /* 3293: pointer.struct.evp_pkey_asn1_method_st */
            	3298, 0,
            0, 0, 0, /* 3298: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 3301: pointer.struct.engine_st */
            	3306, 0,
            0, 0, 0, /* 3306: struct.engine_st */
            0, 8, 5, /* 3309: union.unknown */
            	178, 0,
            	3322, 0,
            	3463, 0,
            	3544, 0,
            	3612, 0,
            1, 8, 1, /* 3322: pointer.struct.rsa_st */
            	3327, 0,
            0, 168, 17, /* 3327: struct.rsa_st */
            	3364, 16,
            	3301, 24,
            	285, 32,
            	285, 40,
            	285, 48,
            	285, 56,
            	285, 64,
            	285, 72,
            	285, 80,
            	285, 88,
            	3419, 96,
            	3441, 120,
            	3441, 128,
            	3441, 136,
            	178, 144,
            	3455, 152,
            	3455, 160,
            1, 8, 1, /* 3364: pointer.struct.rsa_meth_st */
            	3369, 0,
            0, 112, 13, /* 3369: struct.rsa_meth_st */
            	5, 0,
            	3398, 8,
            	3398, 16,
            	3398, 24,
            	3398, 32,
            	3401, 40,
            	3404, 48,
            	3407, 56,
            	3407, 64,
            	178, 80,
            	3410, 88,
            	3413, 96,
            	3416, 104,
            8884097, 8, 0, /* 3398: pointer.func */
            8884097, 8, 0, /* 3401: pointer.func */
            8884097, 8, 0, /* 3404: pointer.func */
            8884097, 8, 0, /* 3407: pointer.func */
            8884097, 8, 0, /* 3410: pointer.func */
            8884097, 8, 0, /* 3413: pointer.func */
            8884097, 8, 0, /* 3416: pointer.func */
            0, 16, 1, /* 3419: struct.crypto_ex_data_st */
            	3424, 0,
            1, 8, 1, /* 3424: pointer.struct.stack_st_void */
            	3429, 0,
            0, 32, 1, /* 3429: struct.stack_st_void */
            	3434, 0,
            0, 32, 2, /* 3434: struct.stack_st */
            	1114, 8,
            	86, 24,
            1, 8, 1, /* 3441: pointer.struct.bn_mont_ctx_st */
            	3446, 0,
            0, 96, 3, /* 3446: struct.bn_mont_ctx_st */
            	290, 8,
            	290, 32,
            	290, 56,
            1, 8, 1, /* 3455: pointer.struct.bn_blinding_st */
            	3460, 0,
            0, 0, 0, /* 3460: struct.bn_blinding_st */
            1, 8, 1, /* 3463: pointer.struct.dsa_st */
            	3468, 0,
            0, 136, 11, /* 3468: struct.dsa_st */
            	285, 24,
            	285, 32,
            	285, 40,
            	285, 48,
            	285, 56,
            	285, 64,
            	285, 72,
            	3441, 88,
            	3419, 104,
            	3493, 120,
            	3301, 128,
            1, 8, 1, /* 3493: pointer.struct.dsa_method */
            	3498, 0,
            0, 96, 11, /* 3498: struct.dsa_method */
            	5, 0,
            	3523, 8,
            	3526, 16,
            	3529, 24,
            	3532, 32,
            	3535, 40,
            	3538, 48,
            	3538, 56,
            	178, 72,
            	3541, 80,
            	3538, 88,
            8884097, 8, 0, /* 3523: pointer.func */
            8884097, 8, 0, /* 3526: pointer.func */
            8884097, 8, 0, /* 3529: pointer.func */
            8884097, 8, 0, /* 3532: pointer.func */
            8884097, 8, 0, /* 3535: pointer.func */
            8884097, 8, 0, /* 3538: pointer.func */
            8884097, 8, 0, /* 3541: pointer.func */
            1, 8, 1, /* 3544: pointer.struct.dh_st */
            	3549, 0,
            0, 144, 12, /* 3549: struct.dh_st */
            	285, 8,
            	285, 16,
            	285, 32,
            	285, 40,
            	3441, 56,
            	285, 64,
            	285, 72,
            	78, 80,
            	285, 96,
            	3419, 112,
            	3576, 128,
            	3301, 136,
            1, 8, 1, /* 3576: pointer.struct.dh_method */
            	3581, 0,
            0, 72, 8, /* 3581: struct.dh_method */
            	5, 0,
            	3600, 8,
            	3603, 16,
            	3606, 24,
            	3600, 32,
            	3600, 40,
            	178, 56,
            	3609, 64,
            8884097, 8, 0, /* 3600: pointer.func */
            8884097, 8, 0, /* 3603: pointer.func */
            8884097, 8, 0, /* 3606: pointer.func */
            8884097, 8, 0, /* 3609: pointer.func */
            1, 8, 1, /* 3612: pointer.struct.ec_key_st */
            	3617, 0,
            0, 0, 0, /* 3617: struct.ec_key_st */
            1, 8, 1, /* 3620: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3625, 0,
            0, 32, 2, /* 3625: struct.stack_st_fake_X509_ATTRIBUTE */
            	3632, 8,
            	86, 24,
            8884099, 8, 2, /* 3632: pointer_to_array_of_pointers_to_stack */
            	3639, 0,
            	83, 20,
            0, 8, 1, /* 3639: pointer.X509_ATTRIBUTE */
            	1322, 0,
            1, 8, 1, /* 3644: pointer.struct.stack_st_X509_EXTENSION */
            	3649, 0,
            0, 32, 2, /* 3649: struct.stack_st_fake_X509_EXTENSION */
            	3656, 8,
            	86, 24,
            8884099, 8, 2, /* 3656: pointer_to_array_of_pointers_to_stack */
            	3663, 0,
            	83, 20,
            0, 8, 1, /* 3663: pointer.X509_EXTENSION */
            	34, 0,
            0, 24, 1, /* 3668: struct.ASN1_ENCODING_st */
            	78, 0,
            1, 8, 1, /* 3673: pointer.struct.AUTHORITY_KEYID_st */
            	3678, 0,
            0, 24, 3, /* 3678: struct.AUTHORITY_KEYID_st */
            	3135, 0,
            	3687, 8,
            	3031, 16,
            1, 8, 1, /* 3687: pointer.struct.stack_st_GENERAL_NAME */
            	3692, 0,
            0, 32, 2, /* 3692: struct.stack_st_fake_GENERAL_NAME */
            	3699, 8,
            	86, 24,
            8884099, 8, 2, /* 3699: pointer_to_array_of_pointers_to_stack */
            	3706, 0,
            	83, 20,
            0, 8, 1, /* 3706: pointer.GENERAL_NAME */
            	1795, 0,
            1, 8, 1, /* 3711: pointer.struct.X509_POLICY_CACHE_st */
            	3716, 0,
            0, 0, 0, /* 3716: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 3719: pointer.struct.stack_st_DIST_POINT */
            	3724, 0,
            0, 32, 2, /* 3724: struct.stack_st_fake_DIST_POINT */
            	3731, 8,
            	86, 24,
            8884099, 8, 2, /* 3731: pointer_to_array_of_pointers_to_stack */
            	3738, 0,
            	83, 20,
            0, 8, 1, /* 3738: pointer.DIST_POINT */
            	1738, 0,
            1, 8, 1, /* 3743: pointer.struct.stack_st_GENERAL_NAME */
            	3748, 0,
            0, 32, 2, /* 3748: struct.stack_st_fake_GENERAL_NAME */
            	3755, 8,
            	86, 24,
            8884099, 8, 2, /* 3755: pointer_to_array_of_pointers_to_stack */
            	3762, 0,
            	83, 20,
            0, 8, 1, /* 3762: pointer.GENERAL_NAME */
            	1795, 0,
            1, 8, 1, /* 3767: pointer.struct.NAME_CONSTRAINTS_st */
            	3772, 0,
            0, 16, 2, /* 3772: struct.NAME_CONSTRAINTS_st */
            	3779, 0,
            	3779, 8,
            1, 8, 1, /* 3779: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3784, 0,
            0, 32, 2, /* 3784: struct.stack_st_fake_GENERAL_SUBTREE */
            	3791, 8,
            	86, 24,
            8884099, 8, 2, /* 3791: pointer_to_array_of_pointers_to_stack */
            	3798, 0,
            	83, 20,
            0, 8, 1, /* 3798: pointer.GENERAL_SUBTREE */
            	3803, 0,
            0, 0, 1, /* 3803: GENERAL_SUBTREE */
            	3808, 0,
            0, 24, 3, /* 3808: struct.GENERAL_SUBTREE_st */
            	3817, 0,
            	2866, 8,
            	2866, 16,
            1, 8, 1, /* 3817: pointer.struct.GENERAL_NAME_st */
            	3822, 0,
            0, 16, 1, /* 3822: struct.GENERAL_NAME_st */
            	3827, 8,
            0, 8, 15, /* 3827: union.unknown */
            	178, 0,
            	3860, 0,
            	2796, 0,
            	2796, 0,
            	2928, 0,
            	3865, 0,
            	3889, 0,
            	2796, 0,
            	2881, 0,
            	2852, 0,
            	2881, 0,
            	3865, 0,
            	2796, 0,
            	2852, 0,
            	2928, 0,
            1, 8, 1, /* 3860: pointer.struct.otherName_st */
            	2921, 0,
            1, 8, 1, /* 3865: pointer.struct.X509_name_st */
            	3870, 0,
            0, 40, 3, /* 3870: struct.X509_name_st */
            	2640, 0,
            	3879, 16,
            	78, 24,
            1, 8, 1, /* 3879: pointer.struct.buf_mem_st */
            	3884, 0,
            0, 24, 1, /* 3884: struct.buf_mem_st */
            	178, 8,
            1, 8, 1, /* 3889: pointer.struct.EDIPartyName_st */
            	3894, 0,
            0, 16, 2, /* 3894: struct.EDIPartyName_st */
            	2847, 0,
            	2847, 8,
            1, 8, 1, /* 3901: pointer.struct.x509_cert_aux_st */
            	3906, 0,
            0, 40, 5, /* 3906: struct.x509_cert_aux_st */
            	3919, 0,
            	3919, 8,
            	3185, 16,
            	3135, 24,
            	3943, 32,
            1, 8, 1, /* 3919: pointer.struct.stack_st_ASN1_OBJECT */
            	3924, 0,
            0, 32, 2, /* 3924: struct.stack_st_fake_ASN1_OBJECT */
            	3931, 8,
            	86, 24,
            8884099, 8, 2, /* 3931: pointer_to_array_of_pointers_to_stack */
            	3938, 0,
            	83, 20,
            0, 8, 1, /* 3938: pointer.ASN1_OBJECT */
            	2197, 0,
            1, 8, 1, /* 3943: pointer.struct.stack_st_X509_ALGOR */
            	3948, 0,
            0, 32, 2, /* 3948: struct.stack_st_fake_X509_ALGOR */
            	3955, 8,
            	86, 24,
            8884099, 8, 2, /* 3955: pointer_to_array_of_pointers_to_stack */
            	3962, 0,
            	83, 20,
            0, 8, 1, /* 3962: pointer.X509_ALGOR */
            	2235, 0,
            1, 8, 1, /* 3967: pointer.struct.env_md_st */
            	3972, 0,
            0, 120, 8, /* 3972: struct.env_md_st */
            	3991, 24,
            	3994, 32,
            	3997, 40,
            	4000, 48,
            	3991, 56,
            	4003, 64,
            	4006, 72,
            	4009, 112,
            8884097, 8, 0, /* 3991: pointer.func */
            8884097, 8, 0, /* 3994: pointer.func */
            8884097, 8, 0, /* 3997: pointer.func */
            8884097, 8, 0, /* 4000: pointer.func */
            8884097, 8, 0, /* 4003: pointer.func */
            8884097, 8, 0, /* 4006: pointer.func */
            8884097, 8, 0, /* 4009: pointer.func */
            1, 8, 1, /* 4012: pointer.struct.rsa_st */
            	3327, 0,
            8884097, 8, 0, /* 4017: pointer.func */
            1, 8, 1, /* 4020: pointer.struct.dh_st */
            	3549, 0,
            8884097, 8, 0, /* 4025: pointer.func */
            1, 8, 1, /* 4028: pointer.struct.ec_key_st */
            	3617, 0,
            8884097, 8, 0, /* 4033: pointer.func */
            1, 8, 1, /* 4036: pointer.struct.ASN1_VALUE_st */
            	4041, 0,
            0, 0, 0, /* 4041: struct.ASN1_VALUE_st */
            8884097, 8, 0, /* 4044: pointer.func */
            1, 8, 1, /* 4047: pointer.struct.stack_st_ASN1_OBJECT */
            	4052, 0,
            0, 32, 2, /* 4052: struct.stack_st_fake_ASN1_OBJECT */
            	4059, 8,
            	86, 24,
            8884099, 8, 2, /* 4059: pointer_to_array_of_pointers_to_stack */
            	4066, 0,
            	83, 20,
            0, 8, 1, /* 4066: pointer.ASN1_OBJECT */
            	2197, 0,
            0, 24, 1, /* 4071: struct.ssl3_buffer_st */
            	78, 0,
            0, 0, 0, /* 4076: struct.evp_pkey_ctx_st */
            8884097, 8, 0, /* 4079: pointer.func */
            0, 24, 1, /* 4082: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 4087: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	4092, 0,
            0, 32, 2, /* 4092: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	4099, 8,
            	86, 24,
            8884099, 8, 2, /* 4099: pointer_to_array_of_pointers_to_stack */
            	4106, 0,
            	83, 20,
            0, 8, 1, /* 4106: pointer.SRTP_PROTECTION_PROFILE */
            	229, 0,
            8884097, 8, 0, /* 4111: pointer.func */
            8884097, 8, 0, /* 4114: pointer.func */
            8884097, 8, 0, /* 4117: pointer.func */
            1, 8, 1, /* 4120: pointer.struct.X509_pubkey_st */
            	4125, 0,
            0, 24, 3, /* 4125: struct.X509_pubkey_st */
            	4134, 0,
            	4228, 8,
            	4288, 16,
            1, 8, 1, /* 4134: pointer.struct.X509_algor_st */
            	4139, 0,
            0, 16, 2, /* 4139: struct.X509_algor_st */
            	4146, 0,
            	4160, 8,
            1, 8, 1, /* 4146: pointer.struct.asn1_object_st */
            	4151, 0,
            0, 40, 3, /* 4151: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 4160: pointer.struct.asn1_type_st */
            	4165, 0,
            0, 16, 1, /* 4165: struct.asn1_type_st */
            	4170, 8,
            0, 8, 20, /* 4170: union.unknown */
            	178, 0,
            	4213, 0,
            	4146, 0,
            	4218, 0,
            	4223, 0,
            	4228, 0,
            	4233, 0,
            	4238, 0,
            	4243, 0,
            	4248, 0,
            	4253, 0,
            	4258, 0,
            	4263, 0,
            	4268, 0,
            	4273, 0,
            	4278, 0,
            	4283, 0,
            	4213, 0,
            	4213, 0,
            	4036, 0,
            1, 8, 1, /* 4213: pointer.struct.asn1_string_st */
            	4082, 0,
            1, 8, 1, /* 4218: pointer.struct.asn1_string_st */
            	4082, 0,
            1, 8, 1, /* 4223: pointer.struct.asn1_string_st */
            	4082, 0,
            1, 8, 1, /* 4228: pointer.struct.asn1_string_st */
            	4082, 0,
            1, 8, 1, /* 4233: pointer.struct.asn1_string_st */
            	4082, 0,
            1, 8, 1, /* 4238: pointer.struct.asn1_string_st */
            	4082, 0,
            1, 8, 1, /* 4243: pointer.struct.asn1_string_st */
            	4082, 0,
            1, 8, 1, /* 4248: pointer.struct.asn1_string_st */
            	4082, 0,
            1, 8, 1, /* 4253: pointer.struct.asn1_string_st */
            	4082, 0,
            1, 8, 1, /* 4258: pointer.struct.asn1_string_st */
            	4082, 0,
            1, 8, 1, /* 4263: pointer.struct.asn1_string_st */
            	4082, 0,
            1, 8, 1, /* 4268: pointer.struct.asn1_string_st */
            	4082, 0,
            1, 8, 1, /* 4273: pointer.struct.asn1_string_st */
            	4082, 0,
            1, 8, 1, /* 4278: pointer.struct.asn1_string_st */
            	4082, 0,
            1, 8, 1, /* 4283: pointer.struct.asn1_string_st */
            	4082, 0,
            1, 8, 1, /* 4288: pointer.struct.evp_pkey_st */
            	4293, 0,
            0, 56, 4, /* 4293: struct.evp_pkey_st */
            	4304, 16,
            	2788, 24,
            	4312, 32,
            	4521, 48,
            1, 8, 1, /* 4304: pointer.struct.evp_pkey_asn1_method_st */
            	4309, 0,
            0, 0, 0, /* 4309: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 4312: union.unknown */
            	178, 0,
            	4325, 0,
            	4430, 0,
            	4508, 0,
            	4513, 0,
            1, 8, 1, /* 4325: pointer.struct.rsa_st */
            	4330, 0,
            0, 168, 17, /* 4330: struct.rsa_st */
            	4367, 16,
            	2788, 24,
            	2706, 32,
            	2706, 40,
            	2706, 48,
            	2706, 56,
            	2706, 64,
            	2706, 72,
            	2706, 80,
            	2706, 88,
            	2730, 96,
            	2716, 120,
            	2716, 128,
            	2716, 136,
            	178, 144,
            	4422, 152,
            	4422, 160,
            1, 8, 1, /* 4367: pointer.struct.rsa_meth_st */
            	4372, 0,
            0, 112, 13, /* 4372: struct.rsa_meth_st */
            	5, 0,
            	4401, 8,
            	4401, 16,
            	4401, 24,
            	4401, 32,
            	4404, 40,
            	4407, 48,
            	4410, 56,
            	4410, 64,
            	178, 80,
            	4413, 88,
            	4416, 96,
            	4419, 104,
            8884097, 8, 0, /* 4401: pointer.func */
            8884097, 8, 0, /* 4404: pointer.func */
            8884097, 8, 0, /* 4407: pointer.func */
            8884097, 8, 0, /* 4410: pointer.func */
            8884097, 8, 0, /* 4413: pointer.func */
            8884097, 8, 0, /* 4416: pointer.func */
            8884097, 8, 0, /* 4419: pointer.func */
            1, 8, 1, /* 4422: pointer.struct.bn_blinding_st */
            	4427, 0,
            0, 0, 0, /* 4427: struct.bn_blinding_st */
            1, 8, 1, /* 4430: pointer.struct.dsa_st */
            	4435, 0,
            0, 136, 11, /* 4435: struct.dsa_st */
            	2706, 24,
            	2706, 32,
            	2706, 40,
            	2706, 48,
            	2706, 56,
            	2706, 64,
            	2706, 72,
            	2716, 88,
            	2730, 104,
            	4460, 120,
            	2788, 128,
            1, 8, 1, /* 4460: pointer.struct.dsa_method */
            	4465, 0,
            0, 96, 11, /* 4465: struct.dsa_method */
            	5, 0,
            	4490, 8,
            	4493, 16,
            	4496, 24,
            	4079, 32,
            	4499, 40,
            	4502, 48,
            	4502, 56,
            	178, 72,
            	4505, 80,
            	4502, 88,
            8884097, 8, 0, /* 4490: pointer.func */
            8884097, 8, 0, /* 4493: pointer.func */
            8884097, 8, 0, /* 4496: pointer.func */
            8884097, 8, 0, /* 4499: pointer.func */
            8884097, 8, 0, /* 4502: pointer.func */
            8884097, 8, 0, /* 4505: pointer.func */
            1, 8, 1, /* 4508: pointer.struct.dh_st */
            	2679, 0,
            1, 8, 1, /* 4513: pointer.struct.ec_key_st */
            	4518, 0,
            0, 0, 0, /* 4518: struct.ec_key_st */
            1, 8, 1, /* 4521: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4526, 0,
            0, 32, 2, /* 4526: struct.stack_st_fake_X509_ATTRIBUTE */
            	4533, 8,
            	86, 24,
            8884099, 8, 2, /* 4533: pointer_to_array_of_pointers_to_stack */
            	4540, 0,
            	83, 20,
            0, 8, 1, /* 4540: pointer.X509_ATTRIBUTE */
            	1322, 0,
            0, 112, 7, /* 4545: struct.bio_st */
            	4562, 0,
            	4603, 8,
            	178, 16,
            	273, 48,
            	4606, 56,
            	4606, 64,
            	3419, 96,
            1, 8, 1, /* 4562: pointer.struct.bio_method_st */
            	4567, 0,
            0, 80, 9, /* 4567: struct.bio_method_st */
            	5, 8,
            	4588, 16,
            	4117, 24,
            	4591, 32,
            	4117, 40,
            	4594, 48,
            	4597, 56,
            	4597, 64,
            	4600, 72,
            8884097, 8, 0, /* 4588: pointer.func */
            8884097, 8, 0, /* 4591: pointer.func */
            8884097, 8, 0, /* 4594: pointer.func */
            8884097, 8, 0, /* 4597: pointer.func */
            8884097, 8, 0, /* 4600: pointer.func */
            8884097, 8, 0, /* 4603: pointer.func */
            1, 8, 1, /* 4606: pointer.struct.bio_st */
            	4545, 0,
            8884097, 8, 0, /* 4611: pointer.func */
            1, 8, 1, /* 4614: pointer.struct.lhash_st */
            	417, 0,
            0, 0, 0, /* 4619: struct._pqueue */
            8884097, 8, 0, /* 4622: pointer.func */
            1, 8, 1, /* 4625: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4630, 0,
            0, 32, 2, /* 4630: struct.stack_st_fake_X509_NAME_ENTRY */
            	4637, 8,
            	86, 24,
            8884099, 8, 2, /* 4637: pointer_to_array_of_pointers_to_stack */
            	4644, 0,
            	83, 20,
            0, 8, 1, /* 4644: pointer.X509_NAME_ENTRY */
            	132, 0,
            8884097, 8, 0, /* 4649: pointer.func */
            0, 0, 0, /* 4652: struct.X509_POLICY_CACHE_st */
            0, 104, 11, /* 4655: struct.x509_cinf_st */
            	4218, 0,
            	4218, 8,
            	4134, 16,
            	4680, 24,
            	4728, 32,
            	4680, 40,
            	4120, 48,
            	4228, 56,
            	4228, 64,
            	4745, 72,
            	4769, 80,
            1, 8, 1, /* 4680: pointer.struct.X509_name_st */
            	4685, 0,
            0, 40, 3, /* 4685: struct.X509_name_st */
            	4694, 0,
            	4718, 16,
            	78, 24,
            1, 8, 1, /* 4694: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4699, 0,
            0, 32, 2, /* 4699: struct.stack_st_fake_X509_NAME_ENTRY */
            	4706, 8,
            	86, 24,
            8884099, 8, 2, /* 4706: pointer_to_array_of_pointers_to_stack */
            	4713, 0,
            	83, 20,
            0, 8, 1, /* 4713: pointer.X509_NAME_ENTRY */
            	132, 0,
            1, 8, 1, /* 4718: pointer.struct.buf_mem_st */
            	4723, 0,
            0, 24, 1, /* 4723: struct.buf_mem_st */
            	178, 8,
            1, 8, 1, /* 4728: pointer.struct.X509_val_st */
            	4733, 0,
            0, 16, 2, /* 4733: struct.X509_val_st */
            	4740, 0,
            	4740, 8,
            1, 8, 1, /* 4740: pointer.struct.asn1_string_st */
            	4082, 0,
            1, 8, 1, /* 4745: pointer.struct.stack_st_X509_EXTENSION */
            	4750, 0,
            0, 32, 2, /* 4750: struct.stack_st_fake_X509_EXTENSION */
            	4757, 8,
            	86, 24,
            8884099, 8, 2, /* 4757: pointer_to_array_of_pointers_to_stack */
            	4764, 0,
            	83, 20,
            0, 8, 1, /* 4764: pointer.X509_EXTENSION */
            	34, 0,
            0, 24, 1, /* 4769: struct.ASN1_ENCODING_st */
            	78, 0,
            1, 8, 1, /* 4774: pointer.struct.ssl_session_st */
            	4779, 0,
            0, 352, 14, /* 4779: struct.ssl_session_st */
            	178, 144,
            	178, 152,
            	4810, 168,
            	2969, 176,
            	5000, 224,
            	5010, 240,
            	3419, 248,
            	4774, 264,
            	4774, 272,
            	178, 280,
            	78, 296,
            	78, 312,
            	78, 320,
            	178, 344,
            1, 8, 1, /* 4810: pointer.struct.sess_cert_st */
            	4815, 0,
            0, 248, 5, /* 4815: struct.sess_cert_st */
            	4828, 0,
            	2955, 16,
            	4012, 216,
            	4020, 224,
            	4028, 232,
            1, 8, 1, /* 4828: pointer.struct.stack_st_X509 */
            	4833, 0,
            0, 32, 2, /* 4833: struct.stack_st_fake_X509 */
            	4840, 8,
            	86, 24,
            8884099, 8, 2, /* 4840: pointer_to_array_of_pointers_to_stack */
            	4847, 0,
            	83, 20,
            0, 8, 1, /* 4847: pointer.X509 */
            	4852, 0,
            0, 0, 1, /* 4852: X509 */
            	4857, 0,
            0, 184, 12, /* 4857: struct.x509_st */
            	4884, 0,
            	4134, 8,
            	4228, 16,
            	178, 32,
            	2730, 40,
            	4233, 104,
            	4889, 112,
            	4897, 120,
            	4902, 128,
            	4926, 136,
            	4950, 144,
            	4958, 176,
            1, 8, 1, /* 4884: pointer.struct.x509_cinf_st */
            	4655, 0,
            1, 8, 1, /* 4889: pointer.struct.AUTHORITY_KEYID_st */
            	4894, 0,
            0, 0, 0, /* 4894: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4897: pointer.struct.X509_POLICY_CACHE_st */
            	4652, 0,
            1, 8, 1, /* 4902: pointer.struct.stack_st_DIST_POINT */
            	4907, 0,
            0, 32, 2, /* 4907: struct.stack_st_fake_DIST_POINT */
            	4914, 8,
            	86, 24,
            8884099, 8, 2, /* 4914: pointer_to_array_of_pointers_to_stack */
            	4921, 0,
            	83, 20,
            0, 8, 1, /* 4921: pointer.DIST_POINT */
            	1738, 0,
            1, 8, 1, /* 4926: pointer.struct.stack_st_GENERAL_NAME */
            	4931, 0,
            0, 32, 2, /* 4931: struct.stack_st_fake_GENERAL_NAME */
            	4938, 8,
            	86, 24,
            8884099, 8, 2, /* 4938: pointer_to_array_of_pointers_to_stack */
            	4945, 0,
            	83, 20,
            0, 8, 1, /* 4945: pointer.GENERAL_NAME */
            	1795, 0,
            1, 8, 1, /* 4950: pointer.struct.NAME_CONSTRAINTS_st */
            	4955, 0,
            0, 0, 0, /* 4955: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4958: pointer.struct.x509_cert_aux_st */
            	4963, 0,
            0, 40, 5, /* 4963: struct.x509_cert_aux_st */
            	4047, 0,
            	4047, 8,
            	4283, 16,
            	4233, 24,
            	4976, 32,
            1, 8, 1, /* 4976: pointer.struct.stack_st_X509_ALGOR */
            	4981, 0,
            0, 32, 2, /* 4981: struct.stack_st_fake_X509_ALGOR */
            	4988, 8,
            	86, 24,
            8884099, 8, 2, /* 4988: pointer_to_array_of_pointers_to_stack */
            	4995, 0,
            	83, 20,
            0, 8, 1, /* 4995: pointer.X509_ALGOR */
            	2235, 0,
            1, 8, 1, /* 5000: pointer.struct.ssl_cipher_st */
            	5005, 0,
            0, 88, 1, /* 5005: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 5010: pointer.struct.stack_st_SSL_CIPHER */
            	5015, 0,
            0, 32, 2, /* 5015: struct.stack_st_fake_SSL_CIPHER */
            	5022, 8,
            	86, 24,
            8884099, 8, 2, /* 5022: pointer_to_array_of_pointers_to_stack */
            	5029, 0,
            	83, 20,
            0, 8, 1, /* 5029: pointer.SSL_CIPHER */
            	5034, 0,
            0, 0, 1, /* 5034: SSL_CIPHER */
            	5039, 0,
            0, 88, 1, /* 5039: struct.ssl_cipher_st */
            	5, 8,
            0, 1, 0, /* 5044: char */
            8884097, 8, 0, /* 5047: pointer.func */
            8884097, 8, 0, /* 5050: pointer.func */
            0, 16, 1, /* 5053: struct.record_pqueue_st */
            	5058, 8,
            1, 8, 1, /* 5058: pointer.struct._pqueue */
            	4619, 0,
            1, 8, 1, /* 5063: pointer.struct.ssl_session_st */
            	4779, 0,
            1, 8, 1, /* 5068: pointer.struct.X509_VERIFY_PARAM_st */
            	5073, 0,
            0, 56, 2, /* 5073: struct.X509_VERIFY_PARAM_st */
            	178, 0,
            	3919, 48,
            8884097, 8, 0, /* 5080: pointer.func */
            8884097, 8, 0, /* 5083: pointer.func */
            1, 8, 1, /* 5086: pointer.struct.ssl2_state_st */
            	5091, 0,
            0, 344, 9, /* 5091: struct.ssl2_state_st */
            	60, 24,
            	78, 56,
            	78, 64,
            	78, 72,
            	78, 104,
            	78, 112,
            	78, 120,
            	78, 128,
            	78, 136,
            8884097, 8, 0, /* 5112: pointer.func */
            1, 8, 1, /* 5115: pointer.struct.ssl3_buf_freelist_st */
            	5120, 0,
            0, 24, 1, /* 5120: struct.ssl3_buf_freelist_st */
            	303, 16,
            1, 8, 1, /* 5125: pointer.struct.ssl_st */
            	5130, 0,
            0, 808, 51, /* 5130: struct.ssl_st */
            	5235, 8,
            	5383, 16,
            	5383, 24,
            	5383, 32,
            	5299, 48,
            	3236, 80,
            	273, 88,
            	78, 104,
            	5086, 120,
            	5388, 128,
            	5600, 136,
            	5666, 152,
            	273, 160,
            	5068, 176,
            	5010, 184,
            	5010, 192,
            	5638, 208,
            	5430, 216,
            	5654, 224,
            	5638, 232,
            	5430, 240,
            	5654, 248,
            	5669, 256,
            	5063, 304,
            	5674, 312,
            	5677, 328,
            	5680, 336,
            	5683, 352,
            	5686, 360,
            	5689, 368,
            	3419, 392,
            	5472, 408,
            	4611, 464,
            	273, 472,
            	178, 480,
            	200, 504,
            	10, 512,
            	78, 520,
            	78, 544,
            	78, 560,
            	273, 568,
            	2629, 584,
            	2801, 592,
            	273, 600,
            	5050, 608,
            	273, 616,
            	5689, 624,
            	78, 632,
            	4087, 648,
            	5901, 656,
            	242, 680,
            1, 8, 1, /* 5235: pointer.struct.ssl_method_st */
            	5240, 0,
            0, 232, 28, /* 5240: struct.ssl_method_st */
            	5299, 8,
            	5302, 16,
            	5302, 24,
            	5299, 32,
            	5299, 40,
            	5305, 48,
            	5305, 56,
            	4044, 64,
            	5299, 72,
            	5299, 80,
            	5299, 88,
            	5308, 96,
            	5311, 104,
            	5314, 112,
            	5299, 120,
            	5317, 128,
            	5112, 136,
            	5320, 144,
            	5323, 152,
            	5326, 160,
            	5329, 168,
            	4111, 176,
            	5332, 184,
            	342, 192,
            	5335, 200,
            	5329, 208,
            	5377, 216,
            	5380, 224,
            8884097, 8, 0, /* 5299: pointer.func */
            8884097, 8, 0, /* 5302: pointer.func */
            8884097, 8, 0, /* 5305: pointer.func */
            8884097, 8, 0, /* 5308: pointer.func */
            8884097, 8, 0, /* 5311: pointer.func */
            8884097, 8, 0, /* 5314: pointer.func */
            8884097, 8, 0, /* 5317: pointer.func */
            8884097, 8, 0, /* 5320: pointer.func */
            8884097, 8, 0, /* 5323: pointer.func */
            8884097, 8, 0, /* 5326: pointer.func */
            8884097, 8, 0, /* 5329: pointer.func */
            8884097, 8, 0, /* 5332: pointer.func */
            1, 8, 1, /* 5335: pointer.struct.ssl3_enc_method */
            	5340, 0,
            0, 112, 11, /* 5340: struct.ssl3_enc_method */
            	5365, 0,
            	5368, 8,
            	5299, 16,
            	5371, 24,
            	5365, 32,
            	5374, 40,
            	4649, 56,
            	5, 64,
            	5, 80,
            	5080, 96,
            	5083, 104,
            8884097, 8, 0, /* 5365: pointer.func */
            8884097, 8, 0, /* 5368: pointer.func */
            8884097, 8, 0, /* 5371: pointer.func */
            8884097, 8, 0, /* 5374: pointer.func */
            8884097, 8, 0, /* 5377: pointer.func */
            8884097, 8, 0, /* 5380: pointer.func */
            1, 8, 1, /* 5383: pointer.struct.bio_st */
            	4545, 0,
            1, 8, 1, /* 5388: pointer.struct.ssl3_state_st */
            	5393, 0,
            0, 1200, 10, /* 5393: struct.ssl3_state_st */
            	4071, 240,
            	4071, 264,
            	5416, 288,
            	5416, 344,
            	60, 432,
            	5383, 440,
            	5425, 448,
            	273, 496,
            	273, 512,
            	5453, 528,
            0, 56, 3, /* 5416: struct.ssl3_record_st */
            	78, 16,
            	78, 24,
            	78, 32,
            1, 8, 1, /* 5425: pointer.pointer.struct.env_md_ctx_st */
            	5430, 0,
            1, 8, 1, /* 5430: pointer.struct.env_md_ctx_st */
            	5435, 0,
            0, 48, 5, /* 5435: struct.env_md_ctx_st */
            	3967, 0,
            	3301, 8,
            	273, 24,
            	5448, 32,
            	3994, 40,
            1, 8, 1, /* 5448: pointer.struct.evp_pkey_ctx_st */
            	4076, 0,
            0, 528, 8, /* 5453: struct.unknown */
            	5000, 408,
            	4020, 416,
            	4028, 424,
            	5472, 464,
            	78, 480,
            	5520, 488,
            	3967, 496,
            	5557, 512,
            1, 8, 1, /* 5472: pointer.struct.stack_st_X509_NAME */
            	5477, 0,
            0, 32, 2, /* 5477: struct.stack_st_fake_X509_NAME */
            	5484, 8,
            	86, 24,
            8884099, 8, 2, /* 5484: pointer_to_array_of_pointers_to_stack */
            	5491, 0,
            	83, 20,
            0, 8, 1, /* 5491: pointer.X509_NAME */
            	5496, 0,
            0, 0, 1, /* 5496: X509_NAME */
            	5501, 0,
            0, 40, 3, /* 5501: struct.X509_name_st */
            	4625, 0,
            	5510, 16,
            	78, 24,
            1, 8, 1, /* 5510: pointer.struct.buf_mem_st */
            	5515, 0,
            0, 24, 1, /* 5515: struct.buf_mem_st */
            	178, 8,
            1, 8, 1, /* 5520: pointer.struct.evp_cipher_st */
            	5525, 0,
            0, 88, 7, /* 5525: struct.evp_cipher_st */
            	5542, 24,
            	5545, 32,
            	5548, 40,
            	5551, 56,
            	5551, 64,
            	5554, 72,
            	273, 80,
            8884097, 8, 0, /* 5542: pointer.func */
            8884097, 8, 0, /* 5545: pointer.func */
            8884097, 8, 0, /* 5548: pointer.func */
            8884097, 8, 0, /* 5551: pointer.func */
            8884097, 8, 0, /* 5554: pointer.func */
            1, 8, 1, /* 5557: pointer.struct.ssl_comp_st */
            	5562, 0,
            0, 24, 2, /* 5562: struct.ssl_comp_st */
            	5, 8,
            	5569, 16,
            1, 8, 1, /* 5569: pointer.struct.comp_method_st */
            	5574, 0,
            0, 64, 7, /* 5574: struct.comp_method_st */
            	5, 8,
            	5591, 16,
            	5594, 24,
            	5597, 32,
            	5597, 40,
            	342, 48,
            	342, 56,
            8884097, 8, 0, /* 5591: pointer.func */
            8884097, 8, 0, /* 5594: pointer.func */
            8884097, 8, 0, /* 5597: pointer.func */
            1, 8, 1, /* 5600: pointer.struct.dtls1_state_st */
            	5605, 0,
            0, 888, 7, /* 5605: struct.dtls1_state_st */
            	5053, 576,
            	5053, 592,
            	5058, 608,
            	5058, 616,
            	5053, 624,
            	5622, 648,
            	5622, 736,
            0, 88, 1, /* 5622: struct.hm_header_st */
            	5627, 48,
            0, 40, 4, /* 5627: struct.dtls1_retransmit_state */
            	5638, 0,
            	5430, 8,
            	5654, 16,
            	5063, 24,
            1, 8, 1, /* 5638: pointer.struct.evp_cipher_ctx_st */
            	5643, 0,
            0, 168, 4, /* 5643: struct.evp_cipher_ctx_st */
            	5520, 0,
            	3301, 8,
            	273, 96,
            	273, 120,
            1, 8, 1, /* 5654: pointer.struct.comp_ctx_st */
            	5659, 0,
            0, 56, 2, /* 5659: struct.comp_ctx_st */
            	5569, 0,
            	3419, 40,
            8884097, 8, 0, /* 5666: pointer.func */
            1, 8, 1, /* 5669: pointer.struct.cert_st */
            	2938, 0,
            8884097, 8, 0, /* 5674: pointer.func */
            8884097, 8, 0, /* 5677: pointer.func */
            8884097, 8, 0, /* 5680: pointer.func */
            8884097, 8, 0, /* 5683: pointer.func */
            8884097, 8, 0, /* 5686: pointer.func */
            1, 8, 1, /* 5689: pointer.struct.ssl_ctx_st */
            	5694, 0,
            0, 736, 50, /* 5694: struct.ssl_ctx_st */
            	5235, 0,
            	5010, 8,
            	5010, 16,
            	5797, 24,
            	4614, 32,
            	4774, 48,
            	4774, 56,
            	459, 80,
            	5892, 88,
            	392, 96,
            	2634, 152,
            	273, 160,
            	5895, 168,
            	273, 176,
            	389, 184,
            	5898, 192,
            	386, 200,
            	3419, 208,
            	3967, 224,
            	3967, 232,
            	3967, 240,
            	4828, 248,
            	350, 256,
            	5680, 264,
            	5472, 272,
            	5669, 304,
            	5666, 320,
            	273, 328,
            	5677, 376,
            	5674, 384,
            	5068, 392,
            	3301, 408,
            	276, 416,
            	273, 424,
            	2637, 480,
            	279, 488,
            	273, 496,
            	313, 504,
            	273, 512,
            	178, 520,
            	5683, 528,
            	5686, 536,
            	5115, 552,
            	5115, 560,
            	242, 568,
            	239, 696,
            	273, 704,
            	4114, 712,
            	273, 720,
            	4087, 728,
            1, 8, 1, /* 5797: pointer.struct.x509_store_st */
            	5802, 0,
            0, 144, 15, /* 5802: struct.x509_store_st */
            	5835, 8,
            	5859, 16,
            	5068, 24,
            	435, 32,
            	5677, 40,
            	4622, 48,
            	5883, 56,
            	435, 64,
            	5886, 72,
            	432, 80,
            	5047, 88,
            	429, 96,
            	5889, 104,
            	435, 112,
            	3419, 120,
            1, 8, 1, /* 5835: pointer.struct.stack_st_X509_OBJECT */
            	5840, 0,
            0, 32, 2, /* 5840: struct.stack_st_fake_X509_OBJECT */
            	5847, 8,
            	86, 24,
            8884099, 8, 2, /* 5847: pointer_to_array_of_pointers_to_stack */
            	5854, 0,
            	83, 20,
            0, 8, 1, /* 5854: pointer.X509_OBJECT */
            	611, 0,
            1, 8, 1, /* 5859: pointer.struct.stack_st_X509_LOOKUP */
            	5864, 0,
            0, 32, 2, /* 5864: struct.stack_st_fake_X509_LOOKUP */
            	5871, 8,
            	86, 24,
            8884099, 8, 2, /* 5871: pointer_to_array_of_pointers_to_stack */
            	5878, 0,
            	83, 20,
            0, 8, 1, /* 5878: pointer.X509_LOOKUP */
            	486, 0,
            8884097, 8, 0, /* 5883: pointer.func */
            8884097, 8, 0, /* 5886: pointer.func */
            8884097, 8, 0, /* 5889: pointer.func */
            8884097, 8, 0, /* 5892: pointer.func */
            8884097, 8, 0, /* 5895: pointer.func */
            8884097, 8, 0, /* 5898: pointer.func */
            1, 8, 1, /* 5901: pointer.struct.srtp_protection_profile_st */
            	0, 0,
        },
        .arg_entity_index = { 5125, },
        .ret_entity_index = 2969,
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

