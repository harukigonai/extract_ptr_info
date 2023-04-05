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

int bb_SSL_set_session_id_context(SSL * arg_a,const unsigned char * arg_b,unsigned int arg_c);

int SSL_set_session_id_context(SSL * arg_a,const unsigned char * arg_b,unsigned int arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_set_session_id_context called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_set_session_id_context(arg_a,arg_b,arg_c);
    else {
        int (*orig_SSL_set_session_id_context)(SSL *,const unsigned char *,unsigned int);
        orig_SSL_set_session_id_context = dlsym(RTLD_NEXT, "SSL_set_session_id_context");
        return orig_SSL_set_session_id_context(arg_a,arg_b,arg_c);
    }
}

int bb_SSL_set_session_id_context(SSL * arg_a,const unsigned char * arg_b,unsigned int arg_c) 
{
    int ret;

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
            1, 8, 1, /* 2640: pointer.struct.dh_st */
            	2645, 0,
            0, 144, 12, /* 2645: struct.dh_st */
            	285, 8,
            	285, 16,
            	285, 32,
            	285, 40,
            	2672, 56,
            	285, 64,
            	285, 72,
            	78, 80,
            	285, 96,
            	2686, 112,
            	2708, 128,
            	2744, 136,
            1, 8, 1, /* 2672: pointer.struct.bn_mont_ctx_st */
            	2677, 0,
            0, 96, 3, /* 2677: struct.bn_mont_ctx_st */
            	290, 8,
            	290, 32,
            	290, 56,
            0, 16, 1, /* 2686: struct.crypto_ex_data_st */
            	2691, 0,
            1, 8, 1, /* 2691: pointer.struct.stack_st_void */
            	2696, 0,
            0, 32, 1, /* 2696: struct.stack_st_void */
            	2701, 0,
            0, 32, 2, /* 2701: struct.stack_st */
            	1114, 8,
            	86, 24,
            1, 8, 1, /* 2708: pointer.struct.dh_method */
            	2713, 0,
            0, 72, 8, /* 2713: struct.dh_method */
            	5, 0,
            	2732, 8,
            	2735, 16,
            	2738, 24,
            	2732, 32,
            	2732, 40,
            	178, 56,
            	2741, 64,
            8884097, 8, 0, /* 2732: pointer.func */
            8884097, 8, 0, /* 2735: pointer.func */
            8884097, 8, 0, /* 2738: pointer.func */
            8884097, 8, 0, /* 2741: pointer.func */
            1, 8, 1, /* 2744: pointer.struct.engine_st */
            	2749, 0,
            0, 0, 0, /* 2749: struct.engine_st */
            8884097, 8, 0, /* 2752: pointer.func */
            8884097, 8, 0, /* 2755: pointer.func */
            1, 8, 1, /* 2758: pointer.struct.asn1_string_st */
            	2763, 0,
            0, 24, 1, /* 2763: struct.asn1_string_st */
            	78, 8,
            8884097, 8, 0, /* 2768: pointer.func */
            0, 184, 12, /* 2771: struct.x509_st */
            	2798, 0,
            	2838, 8,
            	2927, 16,
            	178, 32,
            	2686, 40,
            	2932, 104,
            	3363, 112,
            	3401, 120,
            	3409, 128,
            	3433, 136,
            	3457, 144,
            	3759, 176,
            1, 8, 1, /* 2798: pointer.struct.x509_cinf_st */
            	2803, 0,
            0, 104, 11, /* 2803: struct.x509_cinf_st */
            	2828, 0,
            	2828, 8,
            	2838, 16,
            	2995, 24,
            	3043, 32,
            	2995, 40,
            	3060, 48,
            	2927, 56,
            	2927, 64,
            	3334, 72,
            	3358, 80,
            1, 8, 1, /* 2828: pointer.struct.asn1_string_st */
            	2833, 0,
            0, 24, 1, /* 2833: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 2838: pointer.struct.X509_algor_st */
            	2843, 0,
            0, 16, 2, /* 2843: struct.X509_algor_st */
            	2850, 0,
            	2864, 8,
            1, 8, 1, /* 2850: pointer.struct.asn1_object_st */
            	2855, 0,
            0, 40, 3, /* 2855: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 2864: pointer.struct.asn1_type_st */
            	2869, 0,
            0, 16, 1, /* 2869: struct.asn1_type_st */
            	2874, 8,
            0, 8, 20, /* 2874: union.unknown */
            	178, 0,
            	2917, 0,
            	2850, 0,
            	2828, 0,
            	2922, 0,
            	2927, 0,
            	2932, 0,
            	2937, 0,
            	2942, 0,
            	2947, 0,
            	2952, 0,
            	2957, 0,
            	2962, 0,
            	2967, 0,
            	2972, 0,
            	2977, 0,
            	2982, 0,
            	2917, 0,
            	2917, 0,
            	2987, 0,
            1, 8, 1, /* 2917: pointer.struct.asn1_string_st */
            	2833, 0,
            1, 8, 1, /* 2922: pointer.struct.asn1_string_st */
            	2833, 0,
            1, 8, 1, /* 2927: pointer.struct.asn1_string_st */
            	2833, 0,
            1, 8, 1, /* 2932: pointer.struct.asn1_string_st */
            	2833, 0,
            1, 8, 1, /* 2937: pointer.struct.asn1_string_st */
            	2833, 0,
            1, 8, 1, /* 2942: pointer.struct.asn1_string_st */
            	2833, 0,
            1, 8, 1, /* 2947: pointer.struct.asn1_string_st */
            	2833, 0,
            1, 8, 1, /* 2952: pointer.struct.asn1_string_st */
            	2833, 0,
            1, 8, 1, /* 2957: pointer.struct.asn1_string_st */
            	2833, 0,
            1, 8, 1, /* 2962: pointer.struct.asn1_string_st */
            	2833, 0,
            1, 8, 1, /* 2967: pointer.struct.asn1_string_st */
            	2833, 0,
            1, 8, 1, /* 2972: pointer.struct.asn1_string_st */
            	2833, 0,
            1, 8, 1, /* 2977: pointer.struct.asn1_string_st */
            	2833, 0,
            1, 8, 1, /* 2982: pointer.struct.asn1_string_st */
            	2833, 0,
            1, 8, 1, /* 2987: pointer.struct.ASN1_VALUE_st */
            	2992, 0,
            0, 0, 0, /* 2992: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2995: pointer.struct.X509_name_st */
            	3000, 0,
            0, 40, 3, /* 3000: struct.X509_name_st */
            	3009, 0,
            	3033, 16,
            	78, 24,
            1, 8, 1, /* 3009: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3014, 0,
            0, 32, 2, /* 3014: struct.stack_st_fake_X509_NAME_ENTRY */
            	3021, 8,
            	86, 24,
            8884099, 8, 2, /* 3021: pointer_to_array_of_pointers_to_stack */
            	3028, 0,
            	83, 20,
            0, 8, 1, /* 3028: pointer.X509_NAME_ENTRY */
            	132, 0,
            1, 8, 1, /* 3033: pointer.struct.buf_mem_st */
            	3038, 0,
            0, 24, 1, /* 3038: struct.buf_mem_st */
            	178, 8,
            1, 8, 1, /* 3043: pointer.struct.X509_val_st */
            	3048, 0,
            0, 16, 2, /* 3048: struct.X509_val_st */
            	3055, 0,
            	3055, 8,
            1, 8, 1, /* 3055: pointer.struct.asn1_string_st */
            	2833, 0,
            1, 8, 1, /* 3060: pointer.struct.X509_pubkey_st */
            	3065, 0,
            0, 24, 3, /* 3065: struct.X509_pubkey_st */
            	2838, 0,
            	2927, 8,
            	3074, 16,
            1, 8, 1, /* 3074: pointer.struct.evp_pkey_st */
            	3079, 0,
            0, 56, 4, /* 3079: struct.evp_pkey_st */
            	3090, 16,
            	2744, 24,
            	3098, 32,
            	3310, 48,
            1, 8, 1, /* 3090: pointer.struct.evp_pkey_asn1_method_st */
            	3095, 0,
            0, 0, 0, /* 3095: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 3098: union.unknown */
            	178, 0,
            	3111, 0,
            	3216, 0,
            	3297, 0,
            	3302, 0,
            1, 8, 1, /* 3111: pointer.struct.rsa_st */
            	3116, 0,
            0, 168, 17, /* 3116: struct.rsa_st */
            	3153, 16,
            	2744, 24,
            	285, 32,
            	285, 40,
            	285, 48,
            	285, 56,
            	285, 64,
            	285, 72,
            	285, 80,
            	285, 88,
            	2686, 96,
            	2672, 120,
            	2672, 128,
            	2672, 136,
            	178, 144,
            	3208, 152,
            	3208, 160,
            1, 8, 1, /* 3153: pointer.struct.rsa_meth_st */
            	3158, 0,
            0, 112, 13, /* 3158: struct.rsa_meth_st */
            	5, 0,
            	3187, 8,
            	3187, 16,
            	3187, 24,
            	3187, 32,
            	3190, 40,
            	3193, 48,
            	3196, 56,
            	3196, 64,
            	178, 80,
            	3199, 88,
            	3202, 96,
            	3205, 104,
            8884097, 8, 0, /* 3187: pointer.func */
            8884097, 8, 0, /* 3190: pointer.func */
            8884097, 8, 0, /* 3193: pointer.func */
            8884097, 8, 0, /* 3196: pointer.func */
            8884097, 8, 0, /* 3199: pointer.func */
            8884097, 8, 0, /* 3202: pointer.func */
            8884097, 8, 0, /* 3205: pointer.func */
            1, 8, 1, /* 3208: pointer.struct.bn_blinding_st */
            	3213, 0,
            0, 0, 0, /* 3213: struct.bn_blinding_st */
            1, 8, 1, /* 3216: pointer.struct.dsa_st */
            	3221, 0,
            0, 136, 11, /* 3221: struct.dsa_st */
            	285, 24,
            	285, 32,
            	285, 40,
            	285, 48,
            	285, 56,
            	285, 64,
            	285, 72,
            	2672, 88,
            	2686, 104,
            	3246, 120,
            	2744, 128,
            1, 8, 1, /* 3246: pointer.struct.dsa_method */
            	3251, 0,
            0, 96, 11, /* 3251: struct.dsa_method */
            	5, 0,
            	3276, 8,
            	3279, 16,
            	3282, 24,
            	3285, 32,
            	3288, 40,
            	3291, 48,
            	3291, 56,
            	178, 72,
            	3294, 80,
            	3291, 88,
            8884097, 8, 0, /* 3276: pointer.func */
            8884097, 8, 0, /* 3279: pointer.func */
            8884097, 8, 0, /* 3282: pointer.func */
            8884097, 8, 0, /* 3285: pointer.func */
            8884097, 8, 0, /* 3288: pointer.func */
            8884097, 8, 0, /* 3291: pointer.func */
            8884097, 8, 0, /* 3294: pointer.func */
            1, 8, 1, /* 3297: pointer.struct.dh_st */
            	2645, 0,
            1, 8, 1, /* 3302: pointer.struct.ec_key_st */
            	3307, 0,
            0, 0, 0, /* 3307: struct.ec_key_st */
            1, 8, 1, /* 3310: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3315, 0,
            0, 32, 2, /* 3315: struct.stack_st_fake_X509_ATTRIBUTE */
            	3322, 8,
            	86, 24,
            8884099, 8, 2, /* 3322: pointer_to_array_of_pointers_to_stack */
            	3329, 0,
            	83, 20,
            0, 8, 1, /* 3329: pointer.X509_ATTRIBUTE */
            	1322, 0,
            1, 8, 1, /* 3334: pointer.struct.stack_st_X509_EXTENSION */
            	3339, 0,
            0, 32, 2, /* 3339: struct.stack_st_fake_X509_EXTENSION */
            	3346, 8,
            	86, 24,
            8884099, 8, 2, /* 3346: pointer_to_array_of_pointers_to_stack */
            	3353, 0,
            	83, 20,
            0, 8, 1, /* 3353: pointer.X509_EXTENSION */
            	34, 0,
            0, 24, 1, /* 3358: struct.ASN1_ENCODING_st */
            	78, 0,
            1, 8, 1, /* 3363: pointer.struct.AUTHORITY_KEYID_st */
            	3368, 0,
            0, 24, 3, /* 3368: struct.AUTHORITY_KEYID_st */
            	2932, 0,
            	3377, 8,
            	2828, 16,
            1, 8, 1, /* 3377: pointer.struct.stack_st_GENERAL_NAME */
            	3382, 0,
            0, 32, 2, /* 3382: struct.stack_st_fake_GENERAL_NAME */
            	3389, 8,
            	86, 24,
            8884099, 8, 2, /* 3389: pointer_to_array_of_pointers_to_stack */
            	3396, 0,
            	83, 20,
            0, 8, 1, /* 3396: pointer.GENERAL_NAME */
            	1795, 0,
            1, 8, 1, /* 3401: pointer.struct.X509_POLICY_CACHE_st */
            	3406, 0,
            0, 0, 0, /* 3406: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 3409: pointer.struct.stack_st_DIST_POINT */
            	3414, 0,
            0, 32, 2, /* 3414: struct.stack_st_fake_DIST_POINT */
            	3421, 8,
            	86, 24,
            8884099, 8, 2, /* 3421: pointer_to_array_of_pointers_to_stack */
            	3428, 0,
            	83, 20,
            0, 8, 1, /* 3428: pointer.DIST_POINT */
            	1738, 0,
            1, 8, 1, /* 3433: pointer.struct.stack_st_GENERAL_NAME */
            	3438, 0,
            0, 32, 2, /* 3438: struct.stack_st_fake_GENERAL_NAME */
            	3445, 8,
            	86, 24,
            8884099, 8, 2, /* 3445: pointer_to_array_of_pointers_to_stack */
            	3452, 0,
            	83, 20,
            0, 8, 1, /* 3452: pointer.GENERAL_NAME */
            	1795, 0,
            1, 8, 1, /* 3457: pointer.struct.NAME_CONSTRAINTS_st */
            	3462, 0,
            0, 16, 2, /* 3462: struct.NAME_CONSTRAINTS_st */
            	3469, 0,
            	3469, 8,
            1, 8, 1, /* 3469: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3474, 0,
            0, 32, 2, /* 3474: struct.stack_st_fake_GENERAL_SUBTREE */
            	3481, 8,
            	86, 24,
            8884099, 8, 2, /* 3481: pointer_to_array_of_pointers_to_stack */
            	3488, 0,
            	83, 20,
            0, 8, 1, /* 3488: pointer.GENERAL_SUBTREE */
            	3493, 0,
            0, 0, 1, /* 3493: GENERAL_SUBTREE */
            	3498, 0,
            0, 24, 3, /* 3498: struct.GENERAL_SUBTREE_st */
            	3507, 0,
            	3634, 8,
            	3634, 16,
            1, 8, 1, /* 3507: pointer.struct.GENERAL_NAME_st */
            	3512, 0,
            0, 16, 1, /* 3512: struct.GENERAL_NAME_st */
            	3517, 8,
            0, 8, 15, /* 3517: union.unknown */
            	178, 0,
            	3550, 0,
            	3659, 0,
            	3659, 0,
            	3576, 0,
            	3699, 0,
            	3747, 0,
            	3659, 0,
            	3644, 0,
            	3562, 0,
            	3644, 0,
            	3699, 0,
            	3659, 0,
            	3562, 0,
            	3576, 0,
            1, 8, 1, /* 3550: pointer.struct.otherName_st */
            	3555, 0,
            0, 16, 2, /* 3555: struct.otherName_st */
            	3562, 0,
            	3576, 8,
            1, 8, 1, /* 3562: pointer.struct.asn1_object_st */
            	3567, 0,
            0, 40, 3, /* 3567: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 3576: pointer.struct.asn1_type_st */
            	3581, 0,
            0, 16, 1, /* 3581: struct.asn1_type_st */
            	3586, 8,
            0, 8, 20, /* 3586: union.unknown */
            	178, 0,
            	3629, 0,
            	3562, 0,
            	3634, 0,
            	3639, 0,
            	2758, 0,
            	3644, 0,
            	3649, 0,
            	3654, 0,
            	3659, 0,
            	3664, 0,
            	3669, 0,
            	3674, 0,
            	3679, 0,
            	3684, 0,
            	3689, 0,
            	3694, 0,
            	3629, 0,
            	3629, 0,
            	1997, 0,
            1, 8, 1, /* 3629: pointer.struct.asn1_string_st */
            	2763, 0,
            1, 8, 1, /* 3634: pointer.struct.asn1_string_st */
            	2763, 0,
            1, 8, 1, /* 3639: pointer.struct.asn1_string_st */
            	2763, 0,
            1, 8, 1, /* 3644: pointer.struct.asn1_string_st */
            	2763, 0,
            1, 8, 1, /* 3649: pointer.struct.asn1_string_st */
            	2763, 0,
            1, 8, 1, /* 3654: pointer.struct.asn1_string_st */
            	2763, 0,
            1, 8, 1, /* 3659: pointer.struct.asn1_string_st */
            	2763, 0,
            1, 8, 1, /* 3664: pointer.struct.asn1_string_st */
            	2763, 0,
            1, 8, 1, /* 3669: pointer.struct.asn1_string_st */
            	2763, 0,
            1, 8, 1, /* 3674: pointer.struct.asn1_string_st */
            	2763, 0,
            1, 8, 1, /* 3679: pointer.struct.asn1_string_st */
            	2763, 0,
            1, 8, 1, /* 3684: pointer.struct.asn1_string_st */
            	2763, 0,
            1, 8, 1, /* 3689: pointer.struct.asn1_string_st */
            	2763, 0,
            1, 8, 1, /* 3694: pointer.struct.asn1_string_st */
            	2763, 0,
            1, 8, 1, /* 3699: pointer.struct.X509_name_st */
            	3704, 0,
            0, 40, 3, /* 3704: struct.X509_name_st */
            	3713, 0,
            	3737, 16,
            	78, 24,
            1, 8, 1, /* 3713: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3718, 0,
            0, 32, 2, /* 3718: struct.stack_st_fake_X509_NAME_ENTRY */
            	3725, 8,
            	86, 24,
            8884099, 8, 2, /* 3725: pointer_to_array_of_pointers_to_stack */
            	3732, 0,
            	83, 20,
            0, 8, 1, /* 3732: pointer.X509_NAME_ENTRY */
            	132, 0,
            1, 8, 1, /* 3737: pointer.struct.buf_mem_st */
            	3742, 0,
            0, 24, 1, /* 3742: struct.buf_mem_st */
            	178, 8,
            1, 8, 1, /* 3747: pointer.struct.EDIPartyName_st */
            	3752, 0,
            0, 16, 2, /* 3752: struct.EDIPartyName_st */
            	3629, 0,
            	3629, 8,
            1, 8, 1, /* 3759: pointer.struct.x509_cert_aux_st */
            	3764, 0,
            0, 40, 5, /* 3764: struct.x509_cert_aux_st */
            	3777, 0,
            	3777, 8,
            	2982, 16,
            	2932, 24,
            	3801, 32,
            1, 8, 1, /* 3777: pointer.struct.stack_st_ASN1_OBJECT */
            	3782, 0,
            0, 32, 2, /* 3782: struct.stack_st_fake_ASN1_OBJECT */
            	3789, 8,
            	86, 24,
            8884099, 8, 2, /* 3789: pointer_to_array_of_pointers_to_stack */
            	3796, 0,
            	83, 20,
            0, 8, 1, /* 3796: pointer.ASN1_OBJECT */
            	2197, 0,
            1, 8, 1, /* 3801: pointer.struct.stack_st_X509_ALGOR */
            	3806, 0,
            0, 32, 2, /* 3806: struct.stack_st_fake_X509_ALGOR */
            	3813, 8,
            	86, 24,
            8884099, 8, 2, /* 3813: pointer_to_array_of_pointers_to_stack */
            	3820, 0,
            	83, 20,
            0, 8, 1, /* 3820: pointer.X509_ALGOR */
            	2235, 0,
            1, 8, 1, /* 3825: pointer.struct.ssl_session_st */
            	3830, 0,
            0, 352, 14, /* 3830: struct.ssl_session_st */
            	178, 144,
            	178, 152,
            	3861, 168,
            	4769, 176,
            	4829, 224,
            	4839, 240,
            	2686, 248,
            	4873, 264,
            	4873, 272,
            	178, 280,
            	78, 296,
            	78, 312,
            	78, 320,
            	178, 344,
            1, 8, 1, /* 3861: pointer.struct.sess_cert_st */
            	3866, 0,
            0, 248, 5, /* 3866: struct.sess_cert_st */
            	3879, 0,
            	4755, 16,
            	4819, 216,
            	2640, 224,
            	4824, 232,
            1, 8, 1, /* 3879: pointer.struct.stack_st_X509 */
            	3884, 0,
            0, 32, 2, /* 3884: struct.stack_st_fake_X509 */
            	3891, 8,
            	86, 24,
            8884099, 8, 2, /* 3891: pointer_to_array_of_pointers_to_stack */
            	3898, 0,
            	83, 20,
            0, 8, 1, /* 3898: pointer.X509 */
            	3903, 0,
            0, 0, 1, /* 3903: X509 */
            	3908, 0,
            0, 184, 12, /* 3908: struct.x509_st */
            	3935, 0,
            	3975, 8,
            	4064, 16,
            	178, 32,
            	4363, 40,
            	4069, 104,
            	4617, 112,
            	4625, 120,
            	4633, 128,
            	4657, 136,
            	4681, 144,
            	4689, 176,
            1, 8, 1, /* 3935: pointer.struct.x509_cinf_st */
            	3940, 0,
            0, 104, 11, /* 3940: struct.x509_cinf_st */
            	3965, 0,
            	3965, 8,
            	3975, 16,
            	4132, 24,
            	4180, 32,
            	4132, 40,
            	4197, 48,
            	4064, 56,
            	4064, 64,
            	4588, 72,
            	4612, 80,
            1, 8, 1, /* 3965: pointer.struct.asn1_string_st */
            	3970, 0,
            0, 24, 1, /* 3970: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 3975: pointer.struct.X509_algor_st */
            	3980, 0,
            0, 16, 2, /* 3980: struct.X509_algor_st */
            	3987, 0,
            	4001, 8,
            1, 8, 1, /* 3987: pointer.struct.asn1_object_st */
            	3992, 0,
            0, 40, 3, /* 3992: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 4001: pointer.struct.asn1_type_st */
            	4006, 0,
            0, 16, 1, /* 4006: struct.asn1_type_st */
            	4011, 8,
            0, 8, 20, /* 4011: union.unknown */
            	178, 0,
            	4054, 0,
            	3987, 0,
            	3965, 0,
            	4059, 0,
            	4064, 0,
            	4069, 0,
            	4074, 0,
            	4079, 0,
            	4084, 0,
            	4089, 0,
            	4094, 0,
            	4099, 0,
            	4104, 0,
            	4109, 0,
            	4114, 0,
            	4119, 0,
            	4054, 0,
            	4054, 0,
            	4124, 0,
            1, 8, 1, /* 4054: pointer.struct.asn1_string_st */
            	3970, 0,
            1, 8, 1, /* 4059: pointer.struct.asn1_string_st */
            	3970, 0,
            1, 8, 1, /* 4064: pointer.struct.asn1_string_st */
            	3970, 0,
            1, 8, 1, /* 4069: pointer.struct.asn1_string_st */
            	3970, 0,
            1, 8, 1, /* 4074: pointer.struct.asn1_string_st */
            	3970, 0,
            1, 8, 1, /* 4079: pointer.struct.asn1_string_st */
            	3970, 0,
            1, 8, 1, /* 4084: pointer.struct.asn1_string_st */
            	3970, 0,
            1, 8, 1, /* 4089: pointer.struct.asn1_string_st */
            	3970, 0,
            1, 8, 1, /* 4094: pointer.struct.asn1_string_st */
            	3970, 0,
            1, 8, 1, /* 4099: pointer.struct.asn1_string_st */
            	3970, 0,
            1, 8, 1, /* 4104: pointer.struct.asn1_string_st */
            	3970, 0,
            1, 8, 1, /* 4109: pointer.struct.asn1_string_st */
            	3970, 0,
            1, 8, 1, /* 4114: pointer.struct.asn1_string_st */
            	3970, 0,
            1, 8, 1, /* 4119: pointer.struct.asn1_string_st */
            	3970, 0,
            1, 8, 1, /* 4124: pointer.struct.ASN1_VALUE_st */
            	4129, 0,
            0, 0, 0, /* 4129: struct.ASN1_VALUE_st */
            1, 8, 1, /* 4132: pointer.struct.X509_name_st */
            	4137, 0,
            0, 40, 3, /* 4137: struct.X509_name_st */
            	4146, 0,
            	4170, 16,
            	78, 24,
            1, 8, 1, /* 4146: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4151, 0,
            0, 32, 2, /* 4151: struct.stack_st_fake_X509_NAME_ENTRY */
            	4158, 8,
            	86, 24,
            8884099, 8, 2, /* 4158: pointer_to_array_of_pointers_to_stack */
            	4165, 0,
            	83, 20,
            0, 8, 1, /* 4165: pointer.X509_NAME_ENTRY */
            	132, 0,
            1, 8, 1, /* 4170: pointer.struct.buf_mem_st */
            	4175, 0,
            0, 24, 1, /* 4175: struct.buf_mem_st */
            	178, 8,
            1, 8, 1, /* 4180: pointer.struct.X509_val_st */
            	4185, 0,
            0, 16, 2, /* 4185: struct.X509_val_st */
            	4192, 0,
            	4192, 8,
            1, 8, 1, /* 4192: pointer.struct.asn1_string_st */
            	3970, 0,
            1, 8, 1, /* 4197: pointer.struct.X509_pubkey_st */
            	4202, 0,
            0, 24, 3, /* 4202: struct.X509_pubkey_st */
            	3975, 0,
            	4064, 8,
            	4211, 16,
            1, 8, 1, /* 4211: pointer.struct.evp_pkey_st */
            	4216, 0,
            0, 56, 4, /* 4216: struct.evp_pkey_st */
            	4227, 16,
            	4235, 24,
            	4243, 32,
            	4564, 48,
            1, 8, 1, /* 4227: pointer.struct.evp_pkey_asn1_method_st */
            	4232, 0,
            0, 0, 0, /* 4232: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 4235: pointer.struct.engine_st */
            	4240, 0,
            0, 0, 0, /* 4240: struct.engine_st */
            0, 8, 5, /* 4243: union.unknown */
            	178, 0,
            	4256, 0,
            	4407, 0,
            	4488, 0,
            	4556, 0,
            1, 8, 1, /* 4256: pointer.struct.rsa_st */
            	4261, 0,
            0, 168, 17, /* 4261: struct.rsa_st */
            	4298, 16,
            	4235, 24,
            	4353, 32,
            	4353, 40,
            	4353, 48,
            	4353, 56,
            	4353, 64,
            	4353, 72,
            	4353, 80,
            	4353, 88,
            	4363, 96,
            	4385, 120,
            	4385, 128,
            	4385, 136,
            	178, 144,
            	4399, 152,
            	4399, 160,
            1, 8, 1, /* 4298: pointer.struct.rsa_meth_st */
            	4303, 0,
            0, 112, 13, /* 4303: struct.rsa_meth_st */
            	5, 0,
            	4332, 8,
            	4332, 16,
            	4332, 24,
            	4332, 32,
            	4335, 40,
            	4338, 48,
            	4341, 56,
            	4341, 64,
            	178, 80,
            	4344, 88,
            	4347, 96,
            	4350, 104,
            8884097, 8, 0, /* 4332: pointer.func */
            8884097, 8, 0, /* 4335: pointer.func */
            8884097, 8, 0, /* 4338: pointer.func */
            8884097, 8, 0, /* 4341: pointer.func */
            8884097, 8, 0, /* 4344: pointer.func */
            8884097, 8, 0, /* 4347: pointer.func */
            8884097, 8, 0, /* 4350: pointer.func */
            1, 8, 1, /* 4353: pointer.struct.bignum_st */
            	4358, 0,
            0, 24, 1, /* 4358: struct.bignum_st */
            	295, 0,
            0, 16, 1, /* 4363: struct.crypto_ex_data_st */
            	4368, 0,
            1, 8, 1, /* 4368: pointer.struct.stack_st_void */
            	4373, 0,
            0, 32, 1, /* 4373: struct.stack_st_void */
            	4378, 0,
            0, 32, 2, /* 4378: struct.stack_st */
            	1114, 8,
            	86, 24,
            1, 8, 1, /* 4385: pointer.struct.bn_mont_ctx_st */
            	4390, 0,
            0, 96, 3, /* 4390: struct.bn_mont_ctx_st */
            	4358, 8,
            	4358, 32,
            	4358, 56,
            1, 8, 1, /* 4399: pointer.struct.bn_blinding_st */
            	4404, 0,
            0, 0, 0, /* 4404: struct.bn_blinding_st */
            1, 8, 1, /* 4407: pointer.struct.dsa_st */
            	4412, 0,
            0, 136, 11, /* 4412: struct.dsa_st */
            	4353, 24,
            	4353, 32,
            	4353, 40,
            	4353, 48,
            	4353, 56,
            	4353, 64,
            	4353, 72,
            	4385, 88,
            	4363, 104,
            	4437, 120,
            	4235, 128,
            1, 8, 1, /* 4437: pointer.struct.dsa_method */
            	4442, 0,
            0, 96, 11, /* 4442: struct.dsa_method */
            	5, 0,
            	4467, 8,
            	4470, 16,
            	4473, 24,
            	4476, 32,
            	4479, 40,
            	4482, 48,
            	4482, 56,
            	178, 72,
            	4485, 80,
            	4482, 88,
            8884097, 8, 0, /* 4467: pointer.func */
            8884097, 8, 0, /* 4470: pointer.func */
            8884097, 8, 0, /* 4473: pointer.func */
            8884097, 8, 0, /* 4476: pointer.func */
            8884097, 8, 0, /* 4479: pointer.func */
            8884097, 8, 0, /* 4482: pointer.func */
            8884097, 8, 0, /* 4485: pointer.func */
            1, 8, 1, /* 4488: pointer.struct.dh_st */
            	4493, 0,
            0, 144, 12, /* 4493: struct.dh_st */
            	4353, 8,
            	4353, 16,
            	4353, 32,
            	4353, 40,
            	4385, 56,
            	4353, 64,
            	4353, 72,
            	78, 80,
            	4353, 96,
            	4363, 112,
            	4520, 128,
            	4235, 136,
            1, 8, 1, /* 4520: pointer.struct.dh_method */
            	4525, 0,
            0, 72, 8, /* 4525: struct.dh_method */
            	5, 0,
            	4544, 8,
            	4547, 16,
            	4550, 24,
            	4544, 32,
            	4544, 40,
            	178, 56,
            	4553, 64,
            8884097, 8, 0, /* 4544: pointer.func */
            8884097, 8, 0, /* 4547: pointer.func */
            8884097, 8, 0, /* 4550: pointer.func */
            8884097, 8, 0, /* 4553: pointer.func */
            1, 8, 1, /* 4556: pointer.struct.ec_key_st */
            	4561, 0,
            0, 0, 0, /* 4561: struct.ec_key_st */
            1, 8, 1, /* 4564: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4569, 0,
            0, 32, 2, /* 4569: struct.stack_st_fake_X509_ATTRIBUTE */
            	4576, 8,
            	86, 24,
            8884099, 8, 2, /* 4576: pointer_to_array_of_pointers_to_stack */
            	4583, 0,
            	83, 20,
            0, 8, 1, /* 4583: pointer.X509_ATTRIBUTE */
            	1322, 0,
            1, 8, 1, /* 4588: pointer.struct.stack_st_X509_EXTENSION */
            	4593, 0,
            0, 32, 2, /* 4593: struct.stack_st_fake_X509_EXTENSION */
            	4600, 8,
            	86, 24,
            8884099, 8, 2, /* 4600: pointer_to_array_of_pointers_to_stack */
            	4607, 0,
            	83, 20,
            0, 8, 1, /* 4607: pointer.X509_EXTENSION */
            	34, 0,
            0, 24, 1, /* 4612: struct.ASN1_ENCODING_st */
            	78, 0,
            1, 8, 1, /* 4617: pointer.struct.AUTHORITY_KEYID_st */
            	4622, 0,
            0, 0, 0, /* 4622: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4625: pointer.struct.X509_POLICY_CACHE_st */
            	4630, 0,
            0, 0, 0, /* 4630: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 4633: pointer.struct.stack_st_DIST_POINT */
            	4638, 0,
            0, 32, 2, /* 4638: struct.stack_st_fake_DIST_POINT */
            	4645, 8,
            	86, 24,
            8884099, 8, 2, /* 4645: pointer_to_array_of_pointers_to_stack */
            	4652, 0,
            	83, 20,
            0, 8, 1, /* 4652: pointer.DIST_POINT */
            	1738, 0,
            1, 8, 1, /* 4657: pointer.struct.stack_st_GENERAL_NAME */
            	4662, 0,
            0, 32, 2, /* 4662: struct.stack_st_fake_GENERAL_NAME */
            	4669, 8,
            	86, 24,
            8884099, 8, 2, /* 4669: pointer_to_array_of_pointers_to_stack */
            	4676, 0,
            	83, 20,
            0, 8, 1, /* 4676: pointer.GENERAL_NAME */
            	1795, 0,
            1, 8, 1, /* 4681: pointer.struct.NAME_CONSTRAINTS_st */
            	4686, 0,
            0, 0, 0, /* 4686: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4689: pointer.struct.x509_cert_aux_st */
            	4694, 0,
            0, 40, 5, /* 4694: struct.x509_cert_aux_st */
            	4707, 0,
            	4707, 8,
            	4119, 16,
            	4069, 24,
            	4731, 32,
            1, 8, 1, /* 4707: pointer.struct.stack_st_ASN1_OBJECT */
            	4712, 0,
            0, 32, 2, /* 4712: struct.stack_st_fake_ASN1_OBJECT */
            	4719, 8,
            	86, 24,
            8884099, 8, 2, /* 4719: pointer_to_array_of_pointers_to_stack */
            	4726, 0,
            	83, 20,
            0, 8, 1, /* 4726: pointer.ASN1_OBJECT */
            	2197, 0,
            1, 8, 1, /* 4731: pointer.struct.stack_st_X509_ALGOR */
            	4736, 0,
            0, 32, 2, /* 4736: struct.stack_st_fake_X509_ALGOR */
            	4743, 8,
            	86, 24,
            8884099, 8, 2, /* 4743: pointer_to_array_of_pointers_to_stack */
            	4750, 0,
            	83, 20,
            0, 8, 1, /* 4750: pointer.X509_ALGOR */
            	2235, 0,
            1, 8, 1, /* 4755: pointer.struct.cert_pkey_st */
            	4760, 0,
            0, 24, 3, /* 4760: struct.cert_pkey_st */
            	4769, 0,
            	3074, 8,
            	4774, 16,
            1, 8, 1, /* 4769: pointer.struct.x509_st */
            	2771, 0,
            1, 8, 1, /* 4774: pointer.struct.env_md_st */
            	4779, 0,
            0, 120, 8, /* 4779: struct.env_md_st */
            	4798, 24,
            	4801, 32,
            	4804, 40,
            	4807, 48,
            	4798, 56,
            	4810, 64,
            	4813, 72,
            	4816, 112,
            8884097, 8, 0, /* 4798: pointer.func */
            8884097, 8, 0, /* 4801: pointer.func */
            8884097, 8, 0, /* 4804: pointer.func */
            8884097, 8, 0, /* 4807: pointer.func */
            8884097, 8, 0, /* 4810: pointer.func */
            8884097, 8, 0, /* 4813: pointer.func */
            8884097, 8, 0, /* 4816: pointer.func */
            1, 8, 1, /* 4819: pointer.struct.rsa_st */
            	3116, 0,
            1, 8, 1, /* 4824: pointer.struct.ec_key_st */
            	3307, 0,
            1, 8, 1, /* 4829: pointer.struct.ssl_cipher_st */
            	4834, 0,
            0, 88, 1, /* 4834: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 4839: pointer.struct.stack_st_SSL_CIPHER */
            	4844, 0,
            0, 32, 2, /* 4844: struct.stack_st_fake_SSL_CIPHER */
            	4851, 8,
            	86, 24,
            8884099, 8, 2, /* 4851: pointer_to_array_of_pointers_to_stack */
            	4858, 0,
            	83, 20,
            0, 8, 1, /* 4858: pointer.SSL_CIPHER */
            	4863, 0,
            0, 0, 1, /* 4863: SSL_CIPHER */
            	4868, 0,
            0, 88, 1, /* 4868: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 4873: pointer.struct.ssl_session_st */
            	3830, 0,
            8884097, 8, 0, /* 4878: pointer.func */
            0, 24, 2, /* 4881: struct.ssl_comp_st */
            	5, 8,
            	4888, 16,
            1, 8, 1, /* 4888: pointer.struct.comp_method_st */
            	4893, 0,
            0, 64, 7, /* 4893: struct.comp_method_st */
            	5, 8,
            	4910, 16,
            	4913, 24,
            	4916, 32,
            	4916, 40,
            	342, 48,
            	342, 56,
            8884097, 8, 0, /* 4910: pointer.func */
            8884097, 8, 0, /* 4913: pointer.func */
            8884097, 8, 0, /* 4916: pointer.func */
            8884097, 8, 0, /* 4919: pointer.func */
            8884097, 8, 0, /* 4922: pointer.func */
            8884097, 8, 0, /* 4925: pointer.func */
            8884097, 8, 0, /* 4928: pointer.func */
            8884097, 8, 0, /* 4931: pointer.func */
            8884097, 8, 0, /* 4934: pointer.func */
            8884097, 8, 0, /* 4937: pointer.func */
            1, 8, 1, /* 4940: pointer.struct.comp_ctx_st */
            	4945, 0,
            0, 56, 2, /* 4945: struct.comp_ctx_st */
            	4888, 0,
            	2686, 40,
            0, 168, 4, /* 4952: struct.evp_cipher_ctx_st */
            	4963, 0,
            	2744, 8,
            	273, 96,
            	273, 120,
            1, 8, 1, /* 4963: pointer.struct.evp_cipher_st */
            	4968, 0,
            0, 88, 7, /* 4968: struct.evp_cipher_st */
            	4985, 24,
            	4988, 32,
            	4931, 40,
            	4991, 56,
            	4991, 64,
            	4994, 72,
            	273, 80,
            8884097, 8, 0, /* 4985: pointer.func */
            8884097, 8, 0, /* 4988: pointer.func */
            8884097, 8, 0, /* 4991: pointer.func */
            8884097, 8, 0, /* 4994: pointer.func */
            0, 40, 4, /* 4997: struct.dtls1_retransmit_state */
            	5008, 0,
            	5013, 8,
            	4940, 16,
            	3825, 24,
            1, 8, 1, /* 5008: pointer.struct.evp_cipher_ctx_st */
            	4952, 0,
            1, 8, 1, /* 5013: pointer.struct.env_md_ctx_st */
            	5018, 0,
            0, 48, 5, /* 5018: struct.env_md_ctx_st */
            	4774, 0,
            	2744, 8,
            	273, 24,
            	5031, 32,
            	4801, 40,
            1, 8, 1, /* 5031: pointer.struct.evp_pkey_ctx_st */
            	5036, 0,
            0, 0, 0, /* 5036: struct.evp_pkey_ctx_st */
            1, 8, 1, /* 5039: pointer.struct._pqueue */
            	5044, 0,
            0, 0, 0, /* 5044: struct._pqueue */
            0, 16, 1, /* 5047: struct.record_pqueue_st */
            	5039, 8,
            8884097, 8, 0, /* 5052: pointer.func */
            8884097, 8, 0, /* 5055: pointer.func */
            8884097, 8, 0, /* 5058: pointer.func */
            0, 0, 1, /* 5061: X509_NAME */
            	5066, 0,
            0, 40, 3, /* 5066: struct.X509_name_st */
            	5075, 0,
            	5099, 16,
            	78, 24,
            1, 8, 1, /* 5075: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5080, 0,
            0, 32, 2, /* 5080: struct.stack_st_fake_X509_NAME_ENTRY */
            	5087, 8,
            	86, 24,
            8884099, 8, 2, /* 5087: pointer_to_array_of_pointers_to_stack */
            	5094, 0,
            	83, 20,
            0, 8, 1, /* 5094: pointer.X509_NAME_ENTRY */
            	132, 0,
            1, 8, 1, /* 5099: pointer.struct.buf_mem_st */
            	5104, 0,
            0, 24, 1, /* 5104: struct.buf_mem_st */
            	178, 8,
            0, 80, 9, /* 5109: struct.bio_method_st */
            	5, 8,
            	5130, 16,
            	5133, 24,
            	5136, 32,
            	5133, 40,
            	5139, 48,
            	5142, 56,
            	5142, 64,
            	5145, 72,
            8884097, 8, 0, /* 5130: pointer.func */
            8884097, 8, 0, /* 5133: pointer.func */
            8884097, 8, 0, /* 5136: pointer.func */
            8884097, 8, 0, /* 5139: pointer.func */
            8884097, 8, 0, /* 5142: pointer.func */
            8884097, 8, 0, /* 5145: pointer.func */
            8884097, 8, 0, /* 5148: pointer.func */
            1, 8, 1, /* 5151: pointer.struct.bio_st */
            	5156, 0,
            0, 112, 7, /* 5156: struct.bio_st */
            	5173, 0,
            	5178, 8,
            	178, 16,
            	273, 48,
            	5151, 56,
            	5151, 64,
            	2686, 96,
            1, 8, 1, /* 5173: pointer.struct.bio_method_st */
            	5109, 0,
            8884097, 8, 0, /* 5178: pointer.func */
            0, 1200, 10, /* 5181: struct.ssl3_state_st */
            	5204, 240,
            	5204, 264,
            	5209, 288,
            	5209, 344,
            	60, 432,
            	5218, 440,
            	5223, 448,
            	273, 496,
            	273, 512,
            	5228, 528,
            0, 24, 1, /* 5204: struct.ssl3_buffer_st */
            	78, 0,
            0, 56, 3, /* 5209: struct.ssl3_record_st */
            	78, 16,
            	78, 24,
            	78, 32,
            1, 8, 1, /* 5218: pointer.struct.bio_st */
            	5156, 0,
            1, 8, 1, /* 5223: pointer.pointer.struct.env_md_ctx_st */
            	5013, 0,
            0, 528, 8, /* 5228: struct.unknown */
            	4829, 408,
            	2640, 416,
            	4824, 424,
            	5247, 464,
            	78, 480,
            	4963, 488,
            	4774, 496,
            	5271, 512,
            1, 8, 1, /* 5247: pointer.struct.stack_st_X509_NAME */
            	5252, 0,
            0, 32, 2, /* 5252: struct.stack_st_fake_X509_NAME */
            	5259, 8,
            	86, 24,
            8884099, 8, 2, /* 5259: pointer_to_array_of_pointers_to_stack */
            	5266, 0,
            	83, 20,
            0, 8, 1, /* 5266: pointer.X509_NAME */
            	5061, 0,
            1, 8, 1, /* 5271: pointer.struct.ssl_comp_st */
            	4881, 0,
            1, 8, 1, /* 5276: pointer.struct.ssl3_enc_method */
            	5281, 0,
            0, 112, 11, /* 5281: struct.ssl3_enc_method */
            	5306, 0,
            	5309, 8,
            	5312, 16,
            	5055, 24,
            	5306, 32,
            	5315, 40,
            	5318, 56,
            	5, 64,
            	5, 80,
            	5148, 96,
            	5058, 104,
            8884097, 8, 0, /* 5306: pointer.func */
            8884097, 8, 0, /* 5309: pointer.func */
            8884097, 8, 0, /* 5312: pointer.func */
            8884097, 8, 0, /* 5315: pointer.func */
            8884097, 8, 0, /* 5318: pointer.func */
            0, 232, 28, /* 5321: struct.ssl_method_st */
            	5312, 8,
            	2755, 16,
            	2755, 24,
            	5312, 32,
            	5312, 40,
            	5380, 48,
            	5380, 56,
            	5383, 64,
            	5312, 72,
            	5312, 80,
            	5312, 88,
            	5386, 96,
            	5389, 104,
            	5392, 112,
            	5312, 120,
            	5395, 128,
            	5398, 136,
            	4937, 144,
            	5401, 152,
            	5404, 160,
            	5407, 168,
            	5410, 176,
            	5413, 184,
            	342, 192,
            	5276, 200,
            	5407, 208,
            	4922, 216,
            	5416, 224,
            8884097, 8, 0, /* 5380: pointer.func */
            8884097, 8, 0, /* 5383: pointer.func */
            8884097, 8, 0, /* 5386: pointer.func */
            8884097, 8, 0, /* 5389: pointer.func */
            8884097, 8, 0, /* 5392: pointer.func */
            8884097, 8, 0, /* 5395: pointer.func */
            8884097, 8, 0, /* 5398: pointer.func */
            8884097, 8, 0, /* 5401: pointer.func */
            8884097, 8, 0, /* 5404: pointer.func */
            8884097, 8, 0, /* 5407: pointer.func */
            8884097, 8, 0, /* 5410: pointer.func */
            8884097, 8, 0, /* 5413: pointer.func */
            8884097, 8, 0, /* 5416: pointer.func */
            8884097, 8, 0, /* 5419: pointer.func */
            0, 88, 1, /* 5422: struct.hm_header_st */
            	4997, 48,
            0, 888, 7, /* 5427: struct.dtls1_state_st */
            	5047, 576,
            	5047, 592,
            	5039, 608,
            	5039, 616,
            	5047, 624,
            	5422, 648,
            	5422, 736,
            0, 736, 50, /* 5444: struct.ssl_ctx_st */
            	5547, 0,
            	4839, 8,
            	4839, 16,
            	5552, 24,
            	5662, 32,
            	4873, 48,
            	4873, 56,
            	459, 80,
            	4878, 88,
            	392, 96,
            	2634, 152,
            	273, 160,
            	4928, 168,
            	273, 176,
            	389, 184,
            	4925, 192,
            	386, 200,
            	2686, 208,
            	4774, 224,
            	4774, 232,
            	4774, 240,
            	3879, 248,
            	350, 256,
            	5052, 264,
            	5247, 272,
            	5667, 304,
            	5692, 320,
            	273, 328,
            	5650, 376,
            	5695, 384,
            	5638, 392,
            	2744, 408,
            	276, 416,
            	273, 424,
            	2637, 480,
            	279, 488,
            	273, 496,
            	313, 504,
            	273, 512,
            	178, 520,
            	5698, 528,
            	5701, 536,
            	5704, 552,
            	5704, 560,
            	242, 568,
            	239, 696,
            	273, 704,
            	5714, 712,
            	273, 720,
            	5717, 728,
            1, 8, 1, /* 5547: pointer.struct.ssl_method_st */
            	5321, 0,
            1, 8, 1, /* 5552: pointer.struct.x509_store_st */
            	5557, 0,
            0, 144, 15, /* 5557: struct.x509_store_st */
            	5590, 8,
            	5614, 16,
            	5638, 24,
            	435, 32,
            	5650, 40,
            	5653, 48,
            	5656, 56,
            	435, 64,
            	4934, 72,
            	432, 80,
            	5659, 88,
            	429, 96,
            	4919, 104,
            	435, 112,
            	2686, 120,
            1, 8, 1, /* 5590: pointer.struct.stack_st_X509_OBJECT */
            	5595, 0,
            0, 32, 2, /* 5595: struct.stack_st_fake_X509_OBJECT */
            	5602, 8,
            	86, 24,
            8884099, 8, 2, /* 5602: pointer_to_array_of_pointers_to_stack */
            	5609, 0,
            	83, 20,
            0, 8, 1, /* 5609: pointer.X509_OBJECT */
            	611, 0,
            1, 8, 1, /* 5614: pointer.struct.stack_st_X509_LOOKUP */
            	5619, 0,
            0, 32, 2, /* 5619: struct.stack_st_fake_X509_LOOKUP */
            	5626, 8,
            	86, 24,
            8884099, 8, 2, /* 5626: pointer_to_array_of_pointers_to_stack */
            	5633, 0,
            	83, 20,
            0, 8, 1, /* 5633: pointer.X509_LOOKUP */
            	486, 0,
            1, 8, 1, /* 5638: pointer.struct.X509_VERIFY_PARAM_st */
            	5643, 0,
            0, 56, 2, /* 5643: struct.X509_VERIFY_PARAM_st */
            	178, 0,
            	3777, 48,
            8884097, 8, 0, /* 5650: pointer.func */
            8884097, 8, 0, /* 5653: pointer.func */
            8884097, 8, 0, /* 5656: pointer.func */
            8884097, 8, 0, /* 5659: pointer.func */
            1, 8, 1, /* 5662: pointer.struct.lhash_st */
            	417, 0,
            1, 8, 1, /* 5667: pointer.struct.cert_st */
            	5672, 0,
            0, 296, 7, /* 5672: struct.cert_st */
            	4755, 0,
            	4819, 48,
            	2752, 56,
            	2640, 64,
            	5419, 72,
            	4824, 80,
            	5689, 88,
            8884097, 8, 0, /* 5689: pointer.func */
            8884097, 8, 0, /* 5692: pointer.func */
            8884097, 8, 0, /* 5695: pointer.func */
            8884097, 8, 0, /* 5698: pointer.func */
            8884097, 8, 0, /* 5701: pointer.func */
            1, 8, 1, /* 5704: pointer.struct.ssl3_buf_freelist_st */
            	5709, 0,
            0, 24, 1, /* 5709: struct.ssl3_buf_freelist_st */
            	303, 16,
            8884097, 8, 0, /* 5714: pointer.func */
            1, 8, 1, /* 5717: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	5722, 0,
            0, 32, 2, /* 5722: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	5729, 8,
            	86, 24,
            8884099, 8, 2, /* 5729: pointer_to_array_of_pointers_to_stack */
            	5736, 0,
            	83, 20,
            0, 8, 1, /* 5736: pointer.SRTP_PROTECTION_PROFILE */
            	229, 0,
            1, 8, 1, /* 5741: pointer.struct.ssl2_state_st */
            	5746, 0,
            0, 344, 9, /* 5746: struct.ssl2_state_st */
            	60, 24,
            	78, 56,
            	78, 64,
            	78, 72,
            	78, 104,
            	78, 112,
            	78, 120,
            	78, 128,
            	78, 136,
            0, 808, 51, /* 5767: struct.ssl_st */
            	5547, 8,
            	5218, 16,
            	5218, 24,
            	5218, 32,
            	5312, 48,
            	3033, 80,
            	273, 88,
            	78, 104,
            	5741, 120,
            	5872, 128,
            	5877, 136,
            	5692, 152,
            	273, 160,
            	5638, 176,
            	4839, 184,
            	4839, 192,
            	5008, 208,
            	5013, 216,
            	4940, 224,
            	5008, 232,
            	5013, 240,
            	4940, 248,
            	5667, 256,
            	3825, 304,
            	5695, 312,
            	5650, 328,
            	5052, 336,
            	5698, 352,
            	5701, 360,
            	5882, 368,
            	2686, 392,
            	5247, 408,
            	5887, 464,
            	273, 472,
            	178, 480,
            	200, 504,
            	10, 512,
            	78, 520,
            	78, 544,
            	78, 560,
            	273, 568,
            	2629, 584,
            	5890, 592,
            	273, 600,
            	2768, 608,
            	273, 616,
            	5882, 624,
            	78, 632,
            	5717, 648,
            	5893, 656,
            	242, 680,
            1, 8, 1, /* 5872: pointer.struct.ssl3_state_st */
            	5181, 0,
            1, 8, 1, /* 5877: pointer.struct.dtls1_state_st */
            	5427, 0,
            1, 8, 1, /* 5882: pointer.struct.ssl_ctx_st */
            	5444, 0,
            8884097, 8, 0, /* 5887: pointer.func */
            8884097, 8, 0, /* 5890: pointer.func */
            1, 8, 1, /* 5893: pointer.struct.srtp_protection_profile_st */
            	0, 0,
            0, 1, 0, /* 5898: char */
            1, 8, 1, /* 5901: pointer.struct.ssl_st */
            	5767, 0,
        },
        .arg_entity_index = { 5901, 60, 300, },
        .ret_entity_index = 83,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL * new_arg_a = *((SSL * *)new_args->args[0]);

    const unsigned char * new_arg_b = *((const unsigned char * *)new_args->args[1]);

    unsigned int new_arg_c = *((unsigned int *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_SSL_set_session_id_context)(SSL *,const unsigned char *,unsigned int);
    orig_SSL_set_session_id_context = dlsym(RTLD_NEXT, "SSL_set_session_id_context");
    *new_ret_ptr = (*orig_SSL_set_session_id_context)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    return ret;
}

