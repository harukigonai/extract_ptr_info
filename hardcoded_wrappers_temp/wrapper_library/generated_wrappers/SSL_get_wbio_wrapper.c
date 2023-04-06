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

BIO * bb_SSL_get_wbio(const SSL * arg_a);

BIO * SSL_get_wbio(const SSL * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_get_wbio called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_get_wbio(arg_a);
    else {
        BIO * (*orig_SSL_get_wbio)(const SSL *);
        orig_SSL_get_wbio = dlsym(RTLD_NEXT, "SSL_get_wbio");
        return orig_SSL_get_wbio(arg_a);
    }
}

BIO * bb_SSL_get_wbio(const SSL * arg_a) 
{
    BIO * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 32, 1, /* 0: struct.stack_st_void */
            	5, 0,
            0, 32, 2, /* 5: struct.stack_st */
            	12, 8,
            	22, 24,
            1, 8, 1, /* 12: pointer.pointer.char */
            	17, 0,
            1, 8, 1, /* 17: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 22: pointer.func */
            0, 16, 1, /* 25: struct.crypto_ex_data_st */
            	30, 0,
            1, 8, 1, /* 30: pointer.struct.stack_st_void */
            	0, 0,
            8884097, 8, 0, /* 35: pointer.func */
            8884097, 8, 0, /* 38: pointer.func */
            0, 80, 9, /* 41: struct.bio_method_st */
            	62, 8,
            	67, 16,
            	70, 24,
            	38, 32,
            	70, 40,
            	73, 48,
            	76, 56,
            	76, 64,
            	79, 72,
            1, 8, 1, /* 62: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 67: pointer.func */
            8884097, 8, 0, /* 70: pointer.func */
            8884097, 8, 0, /* 73: pointer.func */
            8884097, 8, 0, /* 76: pointer.func */
            8884097, 8, 0, /* 79: pointer.func */
            0, 112, 7, /* 82: struct.bio_st */
            	99, 0,
            	35, 8,
            	17, 16,
            	104, 48,
            	107, 56,
            	107, 64,
            	25, 96,
            1, 8, 1, /* 99: pointer.struct.bio_method_st */
            	41, 0,
            0, 8, 0, /* 104: pointer.void */
            1, 8, 1, /* 107: pointer.struct.bio_st */
            	82, 0,
            1, 8, 1, /* 112: pointer.struct.bio_st */
            	82, 0,
            0, 16, 1, /* 117: struct.tls_session_ticket_ext_st */
            	104, 8,
            0, 24, 1, /* 122: struct.asn1_string_st */
            	127, 8,
            1, 8, 1, /* 127: pointer.unsigned char */
            	132, 0,
            0, 1, 0, /* 132: unsigned char */
            0, 24, 1, /* 135: struct.buf_mem_st */
            	17, 8,
            0, 8, 2, /* 140: union.unknown */
            	147, 0,
            	234, 0,
            1, 8, 1, /* 147: pointer.struct.X509_name_st */
            	152, 0,
            0, 40, 3, /* 152: struct.X509_name_st */
            	161, 0,
            	229, 16,
            	127, 24,
            1, 8, 1, /* 161: pointer.struct.stack_st_X509_NAME_ENTRY */
            	166, 0,
            0, 32, 2, /* 166: struct.stack_st_fake_X509_NAME_ENTRY */
            	173, 8,
            	22, 24,
            8884099, 8, 2, /* 173: pointer_to_array_of_pointers_to_stack */
            	180, 0,
            	226, 20,
            0, 8, 1, /* 180: pointer.X509_NAME_ENTRY */
            	185, 0,
            0, 0, 1, /* 185: X509_NAME_ENTRY */
            	190, 0,
            0, 24, 2, /* 190: struct.X509_name_entry_st */
            	197, 0,
            	216, 8,
            1, 8, 1, /* 197: pointer.struct.asn1_object_st */
            	202, 0,
            0, 40, 3, /* 202: struct.asn1_object_st */
            	62, 0,
            	62, 8,
            	211, 24,
            1, 8, 1, /* 211: pointer.unsigned char */
            	132, 0,
            1, 8, 1, /* 216: pointer.struct.asn1_string_st */
            	221, 0,
            0, 24, 1, /* 221: struct.asn1_string_st */
            	127, 8,
            0, 4, 0, /* 226: int */
            1, 8, 1, /* 229: pointer.struct.buf_mem_st */
            	135, 0,
            1, 8, 1, /* 234: pointer.struct.asn1_string_st */
            	122, 0,
            0, 0, 1, /* 239: OCSP_RESPID */
            	244, 0,
            0, 16, 1, /* 244: struct.ocsp_responder_id_st */
            	140, 8,
            0, 16, 1, /* 249: struct.srtp_protection_profile_st */
            	62, 0,
            8884097, 8, 0, /* 254: pointer.func */
            8884097, 8, 0, /* 257: pointer.func */
            1, 8, 1, /* 260: pointer.struct.bignum_st */
            	265, 0,
            0, 24, 1, /* 265: struct.bignum_st */
            	270, 0,
            1, 8, 1, /* 270: pointer.unsigned int */
            	275, 0,
            0, 4, 0, /* 275: unsigned int */
            0, 8, 1, /* 278: struct.ssl3_buf_freelist_entry_st */
            	283, 0,
            1, 8, 1, /* 283: pointer.struct.ssl3_buf_freelist_entry_st */
            	278, 0,
            0, 24, 1, /* 288: struct.ssl3_buf_freelist_st */
            	283, 16,
            1, 8, 1, /* 293: pointer.struct.ssl3_buf_freelist_st */
            	288, 0,
            8884097, 8, 0, /* 298: pointer.func */
            8884097, 8, 0, /* 301: pointer.func */
            0, 64, 7, /* 304: struct.comp_method_st */
            	62, 8,
            	321, 16,
            	301, 24,
            	324, 32,
            	324, 40,
            	327, 48,
            	327, 56,
            8884097, 8, 0, /* 321: pointer.func */
            8884097, 8, 0, /* 324: pointer.func */
            8884097, 8, 0, /* 327: pointer.func */
            0, 0, 1, /* 330: SSL_COMP */
            	335, 0,
            0, 24, 2, /* 335: struct.ssl_comp_st */
            	62, 8,
            	342, 16,
            1, 8, 1, /* 342: pointer.struct.comp_method_st */
            	304, 0,
            1, 8, 1, /* 347: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	352, 0,
            0, 32, 2, /* 352: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	359, 8,
            	22, 24,
            8884099, 8, 2, /* 359: pointer_to_array_of_pointers_to_stack */
            	366, 0,
            	226, 20,
            0, 8, 1, /* 366: pointer.SRTP_PROTECTION_PROFILE */
            	371, 0,
            0, 0, 1, /* 371: SRTP_PROTECTION_PROFILE */
            	249, 0,
            1, 8, 1, /* 376: pointer.struct.stack_st_SSL_COMP */
            	381, 0,
            0, 32, 2, /* 381: struct.stack_st_fake_SSL_COMP */
            	388, 8,
            	22, 24,
            8884099, 8, 2, /* 388: pointer_to_array_of_pointers_to_stack */
            	395, 0,
            	226, 20,
            0, 8, 1, /* 395: pointer.SSL_COMP */
            	330, 0,
            8884097, 8, 0, /* 400: pointer.func */
            8884097, 8, 0, /* 403: pointer.func */
            8884097, 8, 0, /* 406: pointer.func */
            8884097, 8, 0, /* 409: pointer.func */
            8884097, 8, 0, /* 412: pointer.func */
            1, 8, 1, /* 415: pointer.struct.lhash_node_st */
            	420, 0,
            0, 24, 2, /* 420: struct.lhash_node_st */
            	104, 0,
            	415, 8,
            1, 8, 1, /* 427: pointer.struct.lhash_st */
            	432, 0,
            0, 176, 3, /* 432: struct.lhash_st */
            	441, 0,
            	22, 8,
            	448, 16,
            8884099, 8, 2, /* 441: pointer_to_array_of_pointers_to_stack */
            	415, 0,
            	275, 28,
            8884097, 8, 0, /* 448: pointer.func */
            8884097, 8, 0, /* 451: pointer.func */
            8884097, 8, 0, /* 454: pointer.func */
            8884097, 8, 0, /* 457: pointer.func */
            8884097, 8, 0, /* 460: pointer.func */
            8884097, 8, 0, /* 463: pointer.func */
            8884097, 8, 0, /* 466: pointer.func */
            8884097, 8, 0, /* 469: pointer.func */
            8884097, 8, 0, /* 472: pointer.func */
            1, 8, 1, /* 475: pointer.struct.X509_VERIFY_PARAM_st */
            	480, 0,
            0, 56, 2, /* 480: struct.X509_VERIFY_PARAM_st */
            	17, 0,
            	487, 48,
            1, 8, 1, /* 487: pointer.struct.stack_st_ASN1_OBJECT */
            	492, 0,
            0, 32, 2, /* 492: struct.stack_st_fake_ASN1_OBJECT */
            	499, 8,
            	22, 24,
            8884099, 8, 2, /* 499: pointer_to_array_of_pointers_to_stack */
            	506, 0,
            	226, 20,
            0, 8, 1, /* 506: pointer.ASN1_OBJECT */
            	511, 0,
            0, 0, 1, /* 511: ASN1_OBJECT */
            	516, 0,
            0, 40, 3, /* 516: struct.asn1_object_st */
            	62, 0,
            	62, 8,
            	211, 24,
            1, 8, 1, /* 525: pointer.struct.stack_st_X509_OBJECT */
            	530, 0,
            0, 32, 2, /* 530: struct.stack_st_fake_X509_OBJECT */
            	537, 8,
            	22, 24,
            8884099, 8, 2, /* 537: pointer_to_array_of_pointers_to_stack */
            	544, 0,
            	226, 20,
            0, 8, 1, /* 544: pointer.X509_OBJECT */
            	549, 0,
            0, 0, 1, /* 549: X509_OBJECT */
            	554, 0,
            0, 16, 1, /* 554: struct.x509_object_st */
            	559, 8,
            0, 8, 4, /* 559: union.unknown */
            	17, 0,
            	570, 0,
            	4060, 0,
            	4293, 0,
            1, 8, 1, /* 570: pointer.struct.x509_st */
            	575, 0,
            0, 184, 12, /* 575: struct.x509_st */
            	602, 0,
            	642, 8,
            	2691, 16,
            	17, 32,
            	2761, 40,
            	2783, 104,
            	2788, 112,
            	3111, 120,
            	3533, 128,
            	3672, 136,
            	3696, 144,
            	4008, 176,
            1, 8, 1, /* 602: pointer.struct.x509_cinf_st */
            	607, 0,
            0, 104, 11, /* 607: struct.x509_cinf_st */
            	632, 0,
            	632, 8,
            	642, 16,
            	809, 24,
            	857, 32,
            	809, 40,
            	874, 48,
            	2691, 56,
            	2691, 64,
            	2696, 72,
            	2756, 80,
            1, 8, 1, /* 632: pointer.struct.asn1_string_st */
            	637, 0,
            0, 24, 1, /* 637: struct.asn1_string_st */
            	127, 8,
            1, 8, 1, /* 642: pointer.struct.X509_algor_st */
            	647, 0,
            0, 16, 2, /* 647: struct.X509_algor_st */
            	654, 0,
            	668, 8,
            1, 8, 1, /* 654: pointer.struct.asn1_object_st */
            	659, 0,
            0, 40, 3, /* 659: struct.asn1_object_st */
            	62, 0,
            	62, 8,
            	211, 24,
            1, 8, 1, /* 668: pointer.struct.asn1_type_st */
            	673, 0,
            0, 16, 1, /* 673: struct.asn1_type_st */
            	678, 8,
            0, 8, 20, /* 678: union.unknown */
            	17, 0,
            	721, 0,
            	654, 0,
            	731, 0,
            	736, 0,
            	741, 0,
            	746, 0,
            	751, 0,
            	756, 0,
            	761, 0,
            	766, 0,
            	771, 0,
            	776, 0,
            	781, 0,
            	786, 0,
            	791, 0,
            	796, 0,
            	721, 0,
            	721, 0,
            	801, 0,
            1, 8, 1, /* 721: pointer.struct.asn1_string_st */
            	726, 0,
            0, 24, 1, /* 726: struct.asn1_string_st */
            	127, 8,
            1, 8, 1, /* 731: pointer.struct.asn1_string_st */
            	726, 0,
            1, 8, 1, /* 736: pointer.struct.asn1_string_st */
            	726, 0,
            1, 8, 1, /* 741: pointer.struct.asn1_string_st */
            	726, 0,
            1, 8, 1, /* 746: pointer.struct.asn1_string_st */
            	726, 0,
            1, 8, 1, /* 751: pointer.struct.asn1_string_st */
            	726, 0,
            1, 8, 1, /* 756: pointer.struct.asn1_string_st */
            	726, 0,
            1, 8, 1, /* 761: pointer.struct.asn1_string_st */
            	726, 0,
            1, 8, 1, /* 766: pointer.struct.asn1_string_st */
            	726, 0,
            1, 8, 1, /* 771: pointer.struct.asn1_string_st */
            	726, 0,
            1, 8, 1, /* 776: pointer.struct.asn1_string_st */
            	726, 0,
            1, 8, 1, /* 781: pointer.struct.asn1_string_st */
            	726, 0,
            1, 8, 1, /* 786: pointer.struct.asn1_string_st */
            	726, 0,
            1, 8, 1, /* 791: pointer.struct.asn1_string_st */
            	726, 0,
            1, 8, 1, /* 796: pointer.struct.asn1_string_st */
            	726, 0,
            1, 8, 1, /* 801: pointer.struct.ASN1_VALUE_st */
            	806, 0,
            0, 0, 0, /* 806: struct.ASN1_VALUE_st */
            1, 8, 1, /* 809: pointer.struct.X509_name_st */
            	814, 0,
            0, 40, 3, /* 814: struct.X509_name_st */
            	823, 0,
            	847, 16,
            	127, 24,
            1, 8, 1, /* 823: pointer.struct.stack_st_X509_NAME_ENTRY */
            	828, 0,
            0, 32, 2, /* 828: struct.stack_st_fake_X509_NAME_ENTRY */
            	835, 8,
            	22, 24,
            8884099, 8, 2, /* 835: pointer_to_array_of_pointers_to_stack */
            	842, 0,
            	226, 20,
            0, 8, 1, /* 842: pointer.X509_NAME_ENTRY */
            	185, 0,
            1, 8, 1, /* 847: pointer.struct.buf_mem_st */
            	852, 0,
            0, 24, 1, /* 852: struct.buf_mem_st */
            	17, 8,
            1, 8, 1, /* 857: pointer.struct.X509_val_st */
            	862, 0,
            0, 16, 2, /* 862: struct.X509_val_st */
            	869, 0,
            	869, 8,
            1, 8, 1, /* 869: pointer.struct.asn1_string_st */
            	637, 0,
            1, 8, 1, /* 874: pointer.struct.X509_pubkey_st */
            	879, 0,
            0, 24, 3, /* 879: struct.X509_pubkey_st */
            	888, 0,
            	893, 8,
            	903, 16,
            1, 8, 1, /* 888: pointer.struct.X509_algor_st */
            	647, 0,
            1, 8, 1, /* 893: pointer.struct.asn1_string_st */
            	898, 0,
            0, 24, 1, /* 898: struct.asn1_string_st */
            	127, 8,
            1, 8, 1, /* 903: pointer.struct.evp_pkey_st */
            	908, 0,
            0, 56, 4, /* 908: struct.evp_pkey_st */
            	919, 16,
            	1020, 24,
            	1368, 32,
            	2312, 48,
            1, 8, 1, /* 919: pointer.struct.evp_pkey_asn1_method_st */
            	924, 0,
            0, 208, 24, /* 924: struct.evp_pkey_asn1_method_st */
            	17, 16,
            	17, 24,
            	975, 32,
            	978, 40,
            	981, 48,
            	984, 56,
            	987, 64,
            	990, 72,
            	984, 80,
            	993, 88,
            	993, 96,
            	996, 104,
            	999, 112,
            	993, 120,
            	1002, 128,
            	981, 136,
            	984, 144,
            	1005, 152,
            	1008, 160,
            	1011, 168,
            	996, 176,
            	999, 184,
            	1014, 192,
            	1017, 200,
            8884097, 8, 0, /* 975: pointer.func */
            8884097, 8, 0, /* 978: pointer.func */
            8884097, 8, 0, /* 981: pointer.func */
            8884097, 8, 0, /* 984: pointer.func */
            8884097, 8, 0, /* 987: pointer.func */
            8884097, 8, 0, /* 990: pointer.func */
            8884097, 8, 0, /* 993: pointer.func */
            8884097, 8, 0, /* 996: pointer.func */
            8884097, 8, 0, /* 999: pointer.func */
            8884097, 8, 0, /* 1002: pointer.func */
            8884097, 8, 0, /* 1005: pointer.func */
            8884097, 8, 0, /* 1008: pointer.func */
            8884097, 8, 0, /* 1011: pointer.func */
            8884097, 8, 0, /* 1014: pointer.func */
            8884097, 8, 0, /* 1017: pointer.func */
            1, 8, 1, /* 1020: pointer.struct.engine_st */
            	1025, 0,
            0, 216, 24, /* 1025: struct.engine_st */
            	62, 0,
            	62, 8,
            	1076, 16,
            	1131, 24,
            	1182, 32,
            	1218, 40,
            	1235, 48,
            	1262, 56,
            	1297, 64,
            	1305, 72,
            	1308, 80,
            	1311, 88,
            	1314, 96,
            	1317, 104,
            	1317, 112,
            	1317, 120,
            	1320, 128,
            	1323, 136,
            	1323, 144,
            	1326, 152,
            	1329, 160,
            	1341, 184,
            	1363, 200,
            	1363, 208,
            1, 8, 1, /* 1076: pointer.struct.rsa_meth_st */
            	1081, 0,
            0, 112, 13, /* 1081: struct.rsa_meth_st */
            	62, 0,
            	1110, 8,
            	1110, 16,
            	1110, 24,
            	1110, 32,
            	1113, 40,
            	1116, 48,
            	1119, 56,
            	1119, 64,
            	17, 80,
            	1122, 88,
            	1125, 96,
            	1128, 104,
            8884097, 8, 0, /* 1110: pointer.func */
            8884097, 8, 0, /* 1113: pointer.func */
            8884097, 8, 0, /* 1116: pointer.func */
            8884097, 8, 0, /* 1119: pointer.func */
            8884097, 8, 0, /* 1122: pointer.func */
            8884097, 8, 0, /* 1125: pointer.func */
            8884097, 8, 0, /* 1128: pointer.func */
            1, 8, 1, /* 1131: pointer.struct.dsa_method */
            	1136, 0,
            0, 96, 11, /* 1136: struct.dsa_method */
            	62, 0,
            	1161, 8,
            	1164, 16,
            	1167, 24,
            	1170, 32,
            	1173, 40,
            	1176, 48,
            	1176, 56,
            	17, 72,
            	1179, 80,
            	1176, 88,
            8884097, 8, 0, /* 1161: pointer.func */
            8884097, 8, 0, /* 1164: pointer.func */
            8884097, 8, 0, /* 1167: pointer.func */
            8884097, 8, 0, /* 1170: pointer.func */
            8884097, 8, 0, /* 1173: pointer.func */
            8884097, 8, 0, /* 1176: pointer.func */
            8884097, 8, 0, /* 1179: pointer.func */
            1, 8, 1, /* 1182: pointer.struct.dh_method */
            	1187, 0,
            0, 72, 8, /* 1187: struct.dh_method */
            	62, 0,
            	1206, 8,
            	1209, 16,
            	1212, 24,
            	1206, 32,
            	1206, 40,
            	17, 56,
            	1215, 64,
            8884097, 8, 0, /* 1206: pointer.func */
            8884097, 8, 0, /* 1209: pointer.func */
            8884097, 8, 0, /* 1212: pointer.func */
            8884097, 8, 0, /* 1215: pointer.func */
            1, 8, 1, /* 1218: pointer.struct.ecdh_method */
            	1223, 0,
            0, 32, 3, /* 1223: struct.ecdh_method */
            	62, 0,
            	1232, 8,
            	17, 24,
            8884097, 8, 0, /* 1232: pointer.func */
            1, 8, 1, /* 1235: pointer.struct.ecdsa_method */
            	1240, 0,
            0, 48, 5, /* 1240: struct.ecdsa_method */
            	62, 0,
            	1253, 8,
            	1256, 16,
            	1259, 24,
            	17, 40,
            8884097, 8, 0, /* 1253: pointer.func */
            8884097, 8, 0, /* 1256: pointer.func */
            8884097, 8, 0, /* 1259: pointer.func */
            1, 8, 1, /* 1262: pointer.struct.rand_meth_st */
            	1267, 0,
            0, 48, 6, /* 1267: struct.rand_meth_st */
            	1282, 0,
            	1285, 8,
            	1288, 16,
            	1291, 24,
            	1285, 32,
            	1294, 40,
            8884097, 8, 0, /* 1282: pointer.func */
            8884097, 8, 0, /* 1285: pointer.func */
            8884097, 8, 0, /* 1288: pointer.func */
            8884097, 8, 0, /* 1291: pointer.func */
            8884097, 8, 0, /* 1294: pointer.func */
            1, 8, 1, /* 1297: pointer.struct.store_method_st */
            	1302, 0,
            0, 0, 0, /* 1302: struct.store_method_st */
            8884097, 8, 0, /* 1305: pointer.func */
            8884097, 8, 0, /* 1308: pointer.func */
            8884097, 8, 0, /* 1311: pointer.func */
            8884097, 8, 0, /* 1314: pointer.func */
            8884097, 8, 0, /* 1317: pointer.func */
            8884097, 8, 0, /* 1320: pointer.func */
            8884097, 8, 0, /* 1323: pointer.func */
            8884097, 8, 0, /* 1326: pointer.func */
            1, 8, 1, /* 1329: pointer.struct.ENGINE_CMD_DEFN_st */
            	1334, 0,
            0, 32, 2, /* 1334: struct.ENGINE_CMD_DEFN_st */
            	62, 8,
            	62, 16,
            0, 16, 1, /* 1341: struct.crypto_ex_data_st */
            	1346, 0,
            1, 8, 1, /* 1346: pointer.struct.stack_st_void */
            	1351, 0,
            0, 32, 1, /* 1351: struct.stack_st_void */
            	1356, 0,
            0, 32, 2, /* 1356: struct.stack_st */
            	12, 8,
            	22, 24,
            1, 8, 1, /* 1363: pointer.struct.engine_st */
            	1025, 0,
            0, 8, 5, /* 1368: union.unknown */
            	17, 0,
            	1381, 0,
            	1583, 0,
            	1710, 0,
            	1824, 0,
            1, 8, 1, /* 1381: pointer.struct.rsa_st */
            	1386, 0,
            0, 168, 17, /* 1386: struct.rsa_st */
            	1423, 16,
            	1478, 24,
            	1483, 32,
            	1483, 40,
            	1483, 48,
            	1483, 56,
            	1483, 64,
            	1483, 72,
            	1483, 80,
            	1483, 88,
            	1493, 96,
            	1515, 120,
            	1515, 128,
            	1515, 136,
            	17, 144,
            	1529, 152,
            	1529, 160,
            1, 8, 1, /* 1423: pointer.struct.rsa_meth_st */
            	1428, 0,
            0, 112, 13, /* 1428: struct.rsa_meth_st */
            	62, 0,
            	1457, 8,
            	1457, 16,
            	1457, 24,
            	1457, 32,
            	1460, 40,
            	1463, 48,
            	1466, 56,
            	1466, 64,
            	17, 80,
            	1469, 88,
            	1472, 96,
            	1475, 104,
            8884097, 8, 0, /* 1457: pointer.func */
            8884097, 8, 0, /* 1460: pointer.func */
            8884097, 8, 0, /* 1463: pointer.func */
            8884097, 8, 0, /* 1466: pointer.func */
            8884097, 8, 0, /* 1469: pointer.func */
            8884097, 8, 0, /* 1472: pointer.func */
            8884097, 8, 0, /* 1475: pointer.func */
            1, 8, 1, /* 1478: pointer.struct.engine_st */
            	1025, 0,
            1, 8, 1, /* 1483: pointer.struct.bignum_st */
            	1488, 0,
            0, 24, 1, /* 1488: struct.bignum_st */
            	270, 0,
            0, 16, 1, /* 1493: struct.crypto_ex_data_st */
            	1498, 0,
            1, 8, 1, /* 1498: pointer.struct.stack_st_void */
            	1503, 0,
            0, 32, 1, /* 1503: struct.stack_st_void */
            	1508, 0,
            0, 32, 2, /* 1508: struct.stack_st */
            	12, 8,
            	22, 24,
            1, 8, 1, /* 1515: pointer.struct.bn_mont_ctx_st */
            	1520, 0,
            0, 96, 3, /* 1520: struct.bn_mont_ctx_st */
            	1488, 8,
            	1488, 32,
            	1488, 56,
            1, 8, 1, /* 1529: pointer.struct.bn_blinding_st */
            	1534, 0,
            0, 88, 7, /* 1534: struct.bn_blinding_st */
            	1551, 0,
            	1551, 8,
            	1551, 16,
            	1551, 24,
            	1561, 40,
            	1566, 72,
            	1580, 80,
            1, 8, 1, /* 1551: pointer.struct.bignum_st */
            	1556, 0,
            0, 24, 1, /* 1556: struct.bignum_st */
            	270, 0,
            0, 16, 1, /* 1561: struct.crypto_threadid_st */
            	104, 0,
            1, 8, 1, /* 1566: pointer.struct.bn_mont_ctx_st */
            	1571, 0,
            0, 96, 3, /* 1571: struct.bn_mont_ctx_st */
            	1556, 8,
            	1556, 32,
            	1556, 56,
            8884097, 8, 0, /* 1580: pointer.func */
            1, 8, 1, /* 1583: pointer.struct.dsa_st */
            	1588, 0,
            0, 136, 11, /* 1588: struct.dsa_st */
            	1613, 24,
            	1613, 32,
            	1613, 40,
            	1613, 48,
            	1613, 56,
            	1613, 64,
            	1613, 72,
            	1623, 88,
            	1637, 104,
            	1659, 120,
            	1020, 128,
            1, 8, 1, /* 1613: pointer.struct.bignum_st */
            	1618, 0,
            0, 24, 1, /* 1618: struct.bignum_st */
            	270, 0,
            1, 8, 1, /* 1623: pointer.struct.bn_mont_ctx_st */
            	1628, 0,
            0, 96, 3, /* 1628: struct.bn_mont_ctx_st */
            	1618, 8,
            	1618, 32,
            	1618, 56,
            0, 16, 1, /* 1637: struct.crypto_ex_data_st */
            	1642, 0,
            1, 8, 1, /* 1642: pointer.struct.stack_st_void */
            	1647, 0,
            0, 32, 1, /* 1647: struct.stack_st_void */
            	1652, 0,
            0, 32, 2, /* 1652: struct.stack_st */
            	12, 8,
            	22, 24,
            1, 8, 1, /* 1659: pointer.struct.dsa_method */
            	1664, 0,
            0, 96, 11, /* 1664: struct.dsa_method */
            	62, 0,
            	1689, 8,
            	1692, 16,
            	1695, 24,
            	1698, 32,
            	1701, 40,
            	1704, 48,
            	1704, 56,
            	17, 72,
            	1707, 80,
            	1704, 88,
            8884097, 8, 0, /* 1689: pointer.func */
            8884097, 8, 0, /* 1692: pointer.func */
            8884097, 8, 0, /* 1695: pointer.func */
            8884097, 8, 0, /* 1698: pointer.func */
            8884097, 8, 0, /* 1701: pointer.func */
            8884097, 8, 0, /* 1704: pointer.func */
            8884097, 8, 0, /* 1707: pointer.func */
            1, 8, 1, /* 1710: pointer.struct.dh_st */
            	1715, 0,
            0, 144, 12, /* 1715: struct.dh_st */
            	1742, 8,
            	1742, 16,
            	1742, 32,
            	1742, 40,
            	1752, 56,
            	1742, 64,
            	1742, 72,
            	127, 80,
            	1742, 96,
            	1766, 112,
            	1788, 128,
            	1478, 136,
            1, 8, 1, /* 1742: pointer.struct.bignum_st */
            	1747, 0,
            0, 24, 1, /* 1747: struct.bignum_st */
            	270, 0,
            1, 8, 1, /* 1752: pointer.struct.bn_mont_ctx_st */
            	1757, 0,
            0, 96, 3, /* 1757: struct.bn_mont_ctx_st */
            	1747, 8,
            	1747, 32,
            	1747, 56,
            0, 16, 1, /* 1766: struct.crypto_ex_data_st */
            	1771, 0,
            1, 8, 1, /* 1771: pointer.struct.stack_st_void */
            	1776, 0,
            0, 32, 1, /* 1776: struct.stack_st_void */
            	1781, 0,
            0, 32, 2, /* 1781: struct.stack_st */
            	12, 8,
            	22, 24,
            1, 8, 1, /* 1788: pointer.struct.dh_method */
            	1793, 0,
            0, 72, 8, /* 1793: struct.dh_method */
            	62, 0,
            	1812, 8,
            	1815, 16,
            	1818, 24,
            	1812, 32,
            	1812, 40,
            	17, 56,
            	1821, 64,
            8884097, 8, 0, /* 1812: pointer.func */
            8884097, 8, 0, /* 1815: pointer.func */
            8884097, 8, 0, /* 1818: pointer.func */
            8884097, 8, 0, /* 1821: pointer.func */
            1, 8, 1, /* 1824: pointer.struct.ec_key_st */
            	1829, 0,
            0, 56, 4, /* 1829: struct.ec_key_st */
            	1840, 8,
            	2274, 16,
            	2279, 24,
            	2289, 48,
            1, 8, 1, /* 1840: pointer.struct.ec_group_st */
            	1845, 0,
            0, 232, 12, /* 1845: struct.ec_group_st */
            	1872, 0,
            	2044, 8,
            	2237, 16,
            	2237, 40,
            	127, 80,
            	2242, 96,
            	2237, 104,
            	2237, 152,
            	2237, 176,
            	104, 208,
            	104, 216,
            	2271, 224,
            1, 8, 1, /* 1872: pointer.struct.ec_method_st */
            	1877, 0,
            0, 304, 37, /* 1877: struct.ec_method_st */
            	1954, 8,
            	1957, 16,
            	1957, 24,
            	1960, 32,
            	1963, 40,
            	1966, 48,
            	1969, 56,
            	1972, 64,
            	1975, 72,
            	1978, 80,
            	1978, 88,
            	1981, 96,
            	1984, 104,
            	1987, 112,
            	1990, 120,
            	1993, 128,
            	1996, 136,
            	1999, 144,
            	2002, 152,
            	2005, 160,
            	2008, 168,
            	2011, 176,
            	2014, 184,
            	2017, 192,
            	2020, 200,
            	2023, 208,
            	2014, 216,
            	2026, 224,
            	2029, 232,
            	2032, 240,
            	1969, 248,
            	2035, 256,
            	2038, 264,
            	2035, 272,
            	2038, 280,
            	2038, 288,
            	2041, 296,
            8884097, 8, 0, /* 1954: pointer.func */
            8884097, 8, 0, /* 1957: pointer.func */
            8884097, 8, 0, /* 1960: pointer.func */
            8884097, 8, 0, /* 1963: pointer.func */
            8884097, 8, 0, /* 1966: pointer.func */
            8884097, 8, 0, /* 1969: pointer.func */
            8884097, 8, 0, /* 1972: pointer.func */
            8884097, 8, 0, /* 1975: pointer.func */
            8884097, 8, 0, /* 1978: pointer.func */
            8884097, 8, 0, /* 1981: pointer.func */
            8884097, 8, 0, /* 1984: pointer.func */
            8884097, 8, 0, /* 1987: pointer.func */
            8884097, 8, 0, /* 1990: pointer.func */
            8884097, 8, 0, /* 1993: pointer.func */
            8884097, 8, 0, /* 1996: pointer.func */
            8884097, 8, 0, /* 1999: pointer.func */
            8884097, 8, 0, /* 2002: pointer.func */
            8884097, 8, 0, /* 2005: pointer.func */
            8884097, 8, 0, /* 2008: pointer.func */
            8884097, 8, 0, /* 2011: pointer.func */
            8884097, 8, 0, /* 2014: pointer.func */
            8884097, 8, 0, /* 2017: pointer.func */
            8884097, 8, 0, /* 2020: pointer.func */
            8884097, 8, 0, /* 2023: pointer.func */
            8884097, 8, 0, /* 2026: pointer.func */
            8884097, 8, 0, /* 2029: pointer.func */
            8884097, 8, 0, /* 2032: pointer.func */
            8884097, 8, 0, /* 2035: pointer.func */
            8884097, 8, 0, /* 2038: pointer.func */
            8884097, 8, 0, /* 2041: pointer.func */
            1, 8, 1, /* 2044: pointer.struct.ec_point_st */
            	2049, 0,
            0, 88, 4, /* 2049: struct.ec_point_st */
            	2060, 0,
            	2232, 8,
            	2232, 32,
            	2232, 56,
            1, 8, 1, /* 2060: pointer.struct.ec_method_st */
            	2065, 0,
            0, 304, 37, /* 2065: struct.ec_method_st */
            	2142, 8,
            	2145, 16,
            	2145, 24,
            	2148, 32,
            	2151, 40,
            	2154, 48,
            	2157, 56,
            	2160, 64,
            	2163, 72,
            	2166, 80,
            	2166, 88,
            	2169, 96,
            	2172, 104,
            	2175, 112,
            	2178, 120,
            	2181, 128,
            	2184, 136,
            	2187, 144,
            	2190, 152,
            	2193, 160,
            	2196, 168,
            	2199, 176,
            	2202, 184,
            	2205, 192,
            	2208, 200,
            	2211, 208,
            	2202, 216,
            	2214, 224,
            	2217, 232,
            	2220, 240,
            	2157, 248,
            	2223, 256,
            	2226, 264,
            	2223, 272,
            	2226, 280,
            	2226, 288,
            	2229, 296,
            8884097, 8, 0, /* 2142: pointer.func */
            8884097, 8, 0, /* 2145: pointer.func */
            8884097, 8, 0, /* 2148: pointer.func */
            8884097, 8, 0, /* 2151: pointer.func */
            8884097, 8, 0, /* 2154: pointer.func */
            8884097, 8, 0, /* 2157: pointer.func */
            8884097, 8, 0, /* 2160: pointer.func */
            8884097, 8, 0, /* 2163: pointer.func */
            8884097, 8, 0, /* 2166: pointer.func */
            8884097, 8, 0, /* 2169: pointer.func */
            8884097, 8, 0, /* 2172: pointer.func */
            8884097, 8, 0, /* 2175: pointer.func */
            8884097, 8, 0, /* 2178: pointer.func */
            8884097, 8, 0, /* 2181: pointer.func */
            8884097, 8, 0, /* 2184: pointer.func */
            8884097, 8, 0, /* 2187: pointer.func */
            8884097, 8, 0, /* 2190: pointer.func */
            8884097, 8, 0, /* 2193: pointer.func */
            8884097, 8, 0, /* 2196: pointer.func */
            8884097, 8, 0, /* 2199: pointer.func */
            8884097, 8, 0, /* 2202: pointer.func */
            8884097, 8, 0, /* 2205: pointer.func */
            8884097, 8, 0, /* 2208: pointer.func */
            8884097, 8, 0, /* 2211: pointer.func */
            8884097, 8, 0, /* 2214: pointer.func */
            8884097, 8, 0, /* 2217: pointer.func */
            8884097, 8, 0, /* 2220: pointer.func */
            8884097, 8, 0, /* 2223: pointer.func */
            8884097, 8, 0, /* 2226: pointer.func */
            8884097, 8, 0, /* 2229: pointer.func */
            0, 24, 1, /* 2232: struct.bignum_st */
            	270, 0,
            0, 24, 1, /* 2237: struct.bignum_st */
            	270, 0,
            1, 8, 1, /* 2242: pointer.struct.ec_extra_data_st */
            	2247, 0,
            0, 40, 5, /* 2247: struct.ec_extra_data_st */
            	2260, 0,
            	104, 8,
            	2265, 16,
            	2268, 24,
            	2268, 32,
            1, 8, 1, /* 2260: pointer.struct.ec_extra_data_st */
            	2247, 0,
            8884097, 8, 0, /* 2265: pointer.func */
            8884097, 8, 0, /* 2268: pointer.func */
            8884097, 8, 0, /* 2271: pointer.func */
            1, 8, 1, /* 2274: pointer.struct.ec_point_st */
            	2049, 0,
            1, 8, 1, /* 2279: pointer.struct.bignum_st */
            	2284, 0,
            0, 24, 1, /* 2284: struct.bignum_st */
            	270, 0,
            1, 8, 1, /* 2289: pointer.struct.ec_extra_data_st */
            	2294, 0,
            0, 40, 5, /* 2294: struct.ec_extra_data_st */
            	2307, 0,
            	104, 8,
            	2265, 16,
            	2268, 24,
            	2268, 32,
            1, 8, 1, /* 2307: pointer.struct.ec_extra_data_st */
            	2294, 0,
            1, 8, 1, /* 2312: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2317, 0,
            0, 32, 2, /* 2317: struct.stack_st_fake_X509_ATTRIBUTE */
            	2324, 8,
            	22, 24,
            8884099, 8, 2, /* 2324: pointer_to_array_of_pointers_to_stack */
            	2331, 0,
            	226, 20,
            0, 8, 1, /* 2331: pointer.X509_ATTRIBUTE */
            	2336, 0,
            0, 0, 1, /* 2336: X509_ATTRIBUTE */
            	2341, 0,
            0, 24, 2, /* 2341: struct.x509_attributes_st */
            	2348, 0,
            	2362, 16,
            1, 8, 1, /* 2348: pointer.struct.asn1_object_st */
            	2353, 0,
            0, 40, 3, /* 2353: struct.asn1_object_st */
            	62, 0,
            	62, 8,
            	211, 24,
            0, 8, 3, /* 2362: union.unknown */
            	17, 0,
            	2371, 0,
            	2550, 0,
            1, 8, 1, /* 2371: pointer.struct.stack_st_ASN1_TYPE */
            	2376, 0,
            0, 32, 2, /* 2376: struct.stack_st_fake_ASN1_TYPE */
            	2383, 8,
            	22, 24,
            8884099, 8, 2, /* 2383: pointer_to_array_of_pointers_to_stack */
            	2390, 0,
            	226, 20,
            0, 8, 1, /* 2390: pointer.ASN1_TYPE */
            	2395, 0,
            0, 0, 1, /* 2395: ASN1_TYPE */
            	2400, 0,
            0, 16, 1, /* 2400: struct.asn1_type_st */
            	2405, 8,
            0, 8, 20, /* 2405: union.unknown */
            	17, 0,
            	2448, 0,
            	2458, 0,
            	2472, 0,
            	2477, 0,
            	2482, 0,
            	2487, 0,
            	2492, 0,
            	2497, 0,
            	2502, 0,
            	2507, 0,
            	2512, 0,
            	2517, 0,
            	2522, 0,
            	2527, 0,
            	2532, 0,
            	2537, 0,
            	2448, 0,
            	2448, 0,
            	2542, 0,
            1, 8, 1, /* 2448: pointer.struct.asn1_string_st */
            	2453, 0,
            0, 24, 1, /* 2453: struct.asn1_string_st */
            	127, 8,
            1, 8, 1, /* 2458: pointer.struct.asn1_object_st */
            	2463, 0,
            0, 40, 3, /* 2463: struct.asn1_object_st */
            	62, 0,
            	62, 8,
            	211, 24,
            1, 8, 1, /* 2472: pointer.struct.asn1_string_st */
            	2453, 0,
            1, 8, 1, /* 2477: pointer.struct.asn1_string_st */
            	2453, 0,
            1, 8, 1, /* 2482: pointer.struct.asn1_string_st */
            	2453, 0,
            1, 8, 1, /* 2487: pointer.struct.asn1_string_st */
            	2453, 0,
            1, 8, 1, /* 2492: pointer.struct.asn1_string_st */
            	2453, 0,
            1, 8, 1, /* 2497: pointer.struct.asn1_string_st */
            	2453, 0,
            1, 8, 1, /* 2502: pointer.struct.asn1_string_st */
            	2453, 0,
            1, 8, 1, /* 2507: pointer.struct.asn1_string_st */
            	2453, 0,
            1, 8, 1, /* 2512: pointer.struct.asn1_string_st */
            	2453, 0,
            1, 8, 1, /* 2517: pointer.struct.asn1_string_st */
            	2453, 0,
            1, 8, 1, /* 2522: pointer.struct.asn1_string_st */
            	2453, 0,
            1, 8, 1, /* 2527: pointer.struct.asn1_string_st */
            	2453, 0,
            1, 8, 1, /* 2532: pointer.struct.asn1_string_st */
            	2453, 0,
            1, 8, 1, /* 2537: pointer.struct.asn1_string_st */
            	2453, 0,
            1, 8, 1, /* 2542: pointer.struct.ASN1_VALUE_st */
            	2547, 0,
            0, 0, 0, /* 2547: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2550: pointer.struct.asn1_type_st */
            	2555, 0,
            0, 16, 1, /* 2555: struct.asn1_type_st */
            	2560, 8,
            0, 8, 20, /* 2560: union.unknown */
            	17, 0,
            	2603, 0,
            	2348, 0,
            	2613, 0,
            	2618, 0,
            	2623, 0,
            	2628, 0,
            	2633, 0,
            	2638, 0,
            	2643, 0,
            	2648, 0,
            	2653, 0,
            	2658, 0,
            	2663, 0,
            	2668, 0,
            	2673, 0,
            	2678, 0,
            	2603, 0,
            	2603, 0,
            	2683, 0,
            1, 8, 1, /* 2603: pointer.struct.asn1_string_st */
            	2608, 0,
            0, 24, 1, /* 2608: struct.asn1_string_st */
            	127, 8,
            1, 8, 1, /* 2613: pointer.struct.asn1_string_st */
            	2608, 0,
            1, 8, 1, /* 2618: pointer.struct.asn1_string_st */
            	2608, 0,
            1, 8, 1, /* 2623: pointer.struct.asn1_string_st */
            	2608, 0,
            1, 8, 1, /* 2628: pointer.struct.asn1_string_st */
            	2608, 0,
            1, 8, 1, /* 2633: pointer.struct.asn1_string_st */
            	2608, 0,
            1, 8, 1, /* 2638: pointer.struct.asn1_string_st */
            	2608, 0,
            1, 8, 1, /* 2643: pointer.struct.asn1_string_st */
            	2608, 0,
            1, 8, 1, /* 2648: pointer.struct.asn1_string_st */
            	2608, 0,
            1, 8, 1, /* 2653: pointer.struct.asn1_string_st */
            	2608, 0,
            1, 8, 1, /* 2658: pointer.struct.asn1_string_st */
            	2608, 0,
            1, 8, 1, /* 2663: pointer.struct.asn1_string_st */
            	2608, 0,
            1, 8, 1, /* 2668: pointer.struct.asn1_string_st */
            	2608, 0,
            1, 8, 1, /* 2673: pointer.struct.asn1_string_st */
            	2608, 0,
            1, 8, 1, /* 2678: pointer.struct.asn1_string_st */
            	2608, 0,
            1, 8, 1, /* 2683: pointer.struct.ASN1_VALUE_st */
            	2688, 0,
            0, 0, 0, /* 2688: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2691: pointer.struct.asn1_string_st */
            	637, 0,
            1, 8, 1, /* 2696: pointer.struct.stack_st_X509_EXTENSION */
            	2701, 0,
            0, 32, 2, /* 2701: struct.stack_st_fake_X509_EXTENSION */
            	2708, 8,
            	22, 24,
            8884099, 8, 2, /* 2708: pointer_to_array_of_pointers_to_stack */
            	2715, 0,
            	226, 20,
            0, 8, 1, /* 2715: pointer.X509_EXTENSION */
            	2720, 0,
            0, 0, 1, /* 2720: X509_EXTENSION */
            	2725, 0,
            0, 24, 2, /* 2725: struct.X509_extension_st */
            	2732, 0,
            	2746, 16,
            1, 8, 1, /* 2732: pointer.struct.asn1_object_st */
            	2737, 0,
            0, 40, 3, /* 2737: struct.asn1_object_st */
            	62, 0,
            	62, 8,
            	211, 24,
            1, 8, 1, /* 2746: pointer.struct.asn1_string_st */
            	2751, 0,
            0, 24, 1, /* 2751: struct.asn1_string_st */
            	127, 8,
            0, 24, 1, /* 2756: struct.ASN1_ENCODING_st */
            	127, 0,
            0, 16, 1, /* 2761: struct.crypto_ex_data_st */
            	2766, 0,
            1, 8, 1, /* 2766: pointer.struct.stack_st_void */
            	2771, 0,
            0, 32, 1, /* 2771: struct.stack_st_void */
            	2776, 0,
            0, 32, 2, /* 2776: struct.stack_st */
            	12, 8,
            	22, 24,
            1, 8, 1, /* 2783: pointer.struct.asn1_string_st */
            	637, 0,
            1, 8, 1, /* 2788: pointer.struct.AUTHORITY_KEYID_st */
            	2793, 0,
            0, 24, 3, /* 2793: struct.AUTHORITY_KEYID_st */
            	2802, 0,
            	2812, 8,
            	3106, 16,
            1, 8, 1, /* 2802: pointer.struct.asn1_string_st */
            	2807, 0,
            0, 24, 1, /* 2807: struct.asn1_string_st */
            	127, 8,
            1, 8, 1, /* 2812: pointer.struct.stack_st_GENERAL_NAME */
            	2817, 0,
            0, 32, 2, /* 2817: struct.stack_st_fake_GENERAL_NAME */
            	2824, 8,
            	22, 24,
            8884099, 8, 2, /* 2824: pointer_to_array_of_pointers_to_stack */
            	2831, 0,
            	226, 20,
            0, 8, 1, /* 2831: pointer.GENERAL_NAME */
            	2836, 0,
            0, 0, 1, /* 2836: GENERAL_NAME */
            	2841, 0,
            0, 16, 1, /* 2841: struct.GENERAL_NAME_st */
            	2846, 8,
            0, 8, 15, /* 2846: union.unknown */
            	17, 0,
            	2879, 0,
            	2998, 0,
            	2998, 0,
            	2905, 0,
            	3046, 0,
            	3094, 0,
            	2998, 0,
            	2983, 0,
            	2891, 0,
            	2983, 0,
            	3046, 0,
            	2998, 0,
            	2891, 0,
            	2905, 0,
            1, 8, 1, /* 2879: pointer.struct.otherName_st */
            	2884, 0,
            0, 16, 2, /* 2884: struct.otherName_st */
            	2891, 0,
            	2905, 8,
            1, 8, 1, /* 2891: pointer.struct.asn1_object_st */
            	2896, 0,
            0, 40, 3, /* 2896: struct.asn1_object_st */
            	62, 0,
            	62, 8,
            	211, 24,
            1, 8, 1, /* 2905: pointer.struct.asn1_type_st */
            	2910, 0,
            0, 16, 1, /* 2910: struct.asn1_type_st */
            	2915, 8,
            0, 8, 20, /* 2915: union.unknown */
            	17, 0,
            	2958, 0,
            	2891, 0,
            	2968, 0,
            	2973, 0,
            	2978, 0,
            	2983, 0,
            	2988, 0,
            	2993, 0,
            	2998, 0,
            	3003, 0,
            	3008, 0,
            	3013, 0,
            	3018, 0,
            	3023, 0,
            	3028, 0,
            	3033, 0,
            	2958, 0,
            	2958, 0,
            	3038, 0,
            1, 8, 1, /* 2958: pointer.struct.asn1_string_st */
            	2963, 0,
            0, 24, 1, /* 2963: struct.asn1_string_st */
            	127, 8,
            1, 8, 1, /* 2968: pointer.struct.asn1_string_st */
            	2963, 0,
            1, 8, 1, /* 2973: pointer.struct.asn1_string_st */
            	2963, 0,
            1, 8, 1, /* 2978: pointer.struct.asn1_string_st */
            	2963, 0,
            1, 8, 1, /* 2983: pointer.struct.asn1_string_st */
            	2963, 0,
            1, 8, 1, /* 2988: pointer.struct.asn1_string_st */
            	2963, 0,
            1, 8, 1, /* 2993: pointer.struct.asn1_string_st */
            	2963, 0,
            1, 8, 1, /* 2998: pointer.struct.asn1_string_st */
            	2963, 0,
            1, 8, 1, /* 3003: pointer.struct.asn1_string_st */
            	2963, 0,
            1, 8, 1, /* 3008: pointer.struct.asn1_string_st */
            	2963, 0,
            1, 8, 1, /* 3013: pointer.struct.asn1_string_st */
            	2963, 0,
            1, 8, 1, /* 3018: pointer.struct.asn1_string_st */
            	2963, 0,
            1, 8, 1, /* 3023: pointer.struct.asn1_string_st */
            	2963, 0,
            1, 8, 1, /* 3028: pointer.struct.asn1_string_st */
            	2963, 0,
            1, 8, 1, /* 3033: pointer.struct.asn1_string_st */
            	2963, 0,
            1, 8, 1, /* 3038: pointer.struct.ASN1_VALUE_st */
            	3043, 0,
            0, 0, 0, /* 3043: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3046: pointer.struct.X509_name_st */
            	3051, 0,
            0, 40, 3, /* 3051: struct.X509_name_st */
            	3060, 0,
            	3084, 16,
            	127, 24,
            1, 8, 1, /* 3060: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3065, 0,
            0, 32, 2, /* 3065: struct.stack_st_fake_X509_NAME_ENTRY */
            	3072, 8,
            	22, 24,
            8884099, 8, 2, /* 3072: pointer_to_array_of_pointers_to_stack */
            	3079, 0,
            	226, 20,
            0, 8, 1, /* 3079: pointer.X509_NAME_ENTRY */
            	185, 0,
            1, 8, 1, /* 3084: pointer.struct.buf_mem_st */
            	3089, 0,
            0, 24, 1, /* 3089: struct.buf_mem_st */
            	17, 8,
            1, 8, 1, /* 3094: pointer.struct.EDIPartyName_st */
            	3099, 0,
            0, 16, 2, /* 3099: struct.EDIPartyName_st */
            	2958, 0,
            	2958, 8,
            1, 8, 1, /* 3106: pointer.struct.asn1_string_st */
            	2807, 0,
            1, 8, 1, /* 3111: pointer.struct.X509_POLICY_CACHE_st */
            	3116, 0,
            0, 40, 2, /* 3116: struct.X509_POLICY_CACHE_st */
            	3123, 0,
            	3433, 8,
            1, 8, 1, /* 3123: pointer.struct.X509_POLICY_DATA_st */
            	3128, 0,
            0, 32, 3, /* 3128: struct.X509_POLICY_DATA_st */
            	3137, 8,
            	3151, 16,
            	3409, 24,
            1, 8, 1, /* 3137: pointer.struct.asn1_object_st */
            	3142, 0,
            0, 40, 3, /* 3142: struct.asn1_object_st */
            	62, 0,
            	62, 8,
            	211, 24,
            1, 8, 1, /* 3151: pointer.struct.stack_st_POLICYQUALINFO */
            	3156, 0,
            0, 32, 2, /* 3156: struct.stack_st_fake_POLICYQUALINFO */
            	3163, 8,
            	22, 24,
            8884099, 8, 2, /* 3163: pointer_to_array_of_pointers_to_stack */
            	3170, 0,
            	226, 20,
            0, 8, 1, /* 3170: pointer.POLICYQUALINFO */
            	3175, 0,
            0, 0, 1, /* 3175: POLICYQUALINFO */
            	3180, 0,
            0, 16, 2, /* 3180: struct.POLICYQUALINFO_st */
            	3187, 0,
            	3201, 8,
            1, 8, 1, /* 3187: pointer.struct.asn1_object_st */
            	3192, 0,
            0, 40, 3, /* 3192: struct.asn1_object_st */
            	62, 0,
            	62, 8,
            	211, 24,
            0, 8, 3, /* 3201: union.unknown */
            	3210, 0,
            	3220, 0,
            	3283, 0,
            1, 8, 1, /* 3210: pointer.struct.asn1_string_st */
            	3215, 0,
            0, 24, 1, /* 3215: struct.asn1_string_st */
            	127, 8,
            1, 8, 1, /* 3220: pointer.struct.USERNOTICE_st */
            	3225, 0,
            0, 16, 2, /* 3225: struct.USERNOTICE_st */
            	3232, 0,
            	3244, 8,
            1, 8, 1, /* 3232: pointer.struct.NOTICEREF_st */
            	3237, 0,
            0, 16, 2, /* 3237: struct.NOTICEREF_st */
            	3244, 0,
            	3249, 8,
            1, 8, 1, /* 3244: pointer.struct.asn1_string_st */
            	3215, 0,
            1, 8, 1, /* 3249: pointer.struct.stack_st_ASN1_INTEGER */
            	3254, 0,
            0, 32, 2, /* 3254: struct.stack_st_fake_ASN1_INTEGER */
            	3261, 8,
            	22, 24,
            8884099, 8, 2, /* 3261: pointer_to_array_of_pointers_to_stack */
            	3268, 0,
            	226, 20,
            0, 8, 1, /* 3268: pointer.ASN1_INTEGER */
            	3273, 0,
            0, 0, 1, /* 3273: ASN1_INTEGER */
            	3278, 0,
            0, 24, 1, /* 3278: struct.asn1_string_st */
            	127, 8,
            1, 8, 1, /* 3283: pointer.struct.asn1_type_st */
            	3288, 0,
            0, 16, 1, /* 3288: struct.asn1_type_st */
            	3293, 8,
            0, 8, 20, /* 3293: union.unknown */
            	17, 0,
            	3244, 0,
            	3187, 0,
            	3336, 0,
            	3341, 0,
            	3346, 0,
            	3351, 0,
            	3356, 0,
            	3361, 0,
            	3210, 0,
            	3366, 0,
            	3371, 0,
            	3376, 0,
            	3381, 0,
            	3386, 0,
            	3391, 0,
            	3396, 0,
            	3244, 0,
            	3244, 0,
            	3401, 0,
            1, 8, 1, /* 3336: pointer.struct.asn1_string_st */
            	3215, 0,
            1, 8, 1, /* 3341: pointer.struct.asn1_string_st */
            	3215, 0,
            1, 8, 1, /* 3346: pointer.struct.asn1_string_st */
            	3215, 0,
            1, 8, 1, /* 3351: pointer.struct.asn1_string_st */
            	3215, 0,
            1, 8, 1, /* 3356: pointer.struct.asn1_string_st */
            	3215, 0,
            1, 8, 1, /* 3361: pointer.struct.asn1_string_st */
            	3215, 0,
            1, 8, 1, /* 3366: pointer.struct.asn1_string_st */
            	3215, 0,
            1, 8, 1, /* 3371: pointer.struct.asn1_string_st */
            	3215, 0,
            1, 8, 1, /* 3376: pointer.struct.asn1_string_st */
            	3215, 0,
            1, 8, 1, /* 3381: pointer.struct.asn1_string_st */
            	3215, 0,
            1, 8, 1, /* 3386: pointer.struct.asn1_string_st */
            	3215, 0,
            1, 8, 1, /* 3391: pointer.struct.asn1_string_st */
            	3215, 0,
            1, 8, 1, /* 3396: pointer.struct.asn1_string_st */
            	3215, 0,
            1, 8, 1, /* 3401: pointer.struct.ASN1_VALUE_st */
            	3406, 0,
            0, 0, 0, /* 3406: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3409: pointer.struct.stack_st_ASN1_OBJECT */
            	3414, 0,
            0, 32, 2, /* 3414: struct.stack_st_fake_ASN1_OBJECT */
            	3421, 8,
            	22, 24,
            8884099, 8, 2, /* 3421: pointer_to_array_of_pointers_to_stack */
            	3428, 0,
            	226, 20,
            0, 8, 1, /* 3428: pointer.ASN1_OBJECT */
            	511, 0,
            1, 8, 1, /* 3433: pointer.struct.stack_st_X509_POLICY_DATA */
            	3438, 0,
            0, 32, 2, /* 3438: struct.stack_st_fake_X509_POLICY_DATA */
            	3445, 8,
            	22, 24,
            8884099, 8, 2, /* 3445: pointer_to_array_of_pointers_to_stack */
            	3452, 0,
            	226, 20,
            0, 8, 1, /* 3452: pointer.X509_POLICY_DATA */
            	3457, 0,
            0, 0, 1, /* 3457: X509_POLICY_DATA */
            	3462, 0,
            0, 32, 3, /* 3462: struct.X509_POLICY_DATA_st */
            	3471, 8,
            	3485, 16,
            	3509, 24,
            1, 8, 1, /* 3471: pointer.struct.asn1_object_st */
            	3476, 0,
            0, 40, 3, /* 3476: struct.asn1_object_st */
            	62, 0,
            	62, 8,
            	211, 24,
            1, 8, 1, /* 3485: pointer.struct.stack_st_POLICYQUALINFO */
            	3490, 0,
            0, 32, 2, /* 3490: struct.stack_st_fake_POLICYQUALINFO */
            	3497, 8,
            	22, 24,
            8884099, 8, 2, /* 3497: pointer_to_array_of_pointers_to_stack */
            	3504, 0,
            	226, 20,
            0, 8, 1, /* 3504: pointer.POLICYQUALINFO */
            	3175, 0,
            1, 8, 1, /* 3509: pointer.struct.stack_st_ASN1_OBJECT */
            	3514, 0,
            0, 32, 2, /* 3514: struct.stack_st_fake_ASN1_OBJECT */
            	3521, 8,
            	22, 24,
            8884099, 8, 2, /* 3521: pointer_to_array_of_pointers_to_stack */
            	3528, 0,
            	226, 20,
            0, 8, 1, /* 3528: pointer.ASN1_OBJECT */
            	511, 0,
            1, 8, 1, /* 3533: pointer.struct.stack_st_DIST_POINT */
            	3538, 0,
            0, 32, 2, /* 3538: struct.stack_st_fake_DIST_POINT */
            	3545, 8,
            	22, 24,
            8884099, 8, 2, /* 3545: pointer_to_array_of_pointers_to_stack */
            	3552, 0,
            	226, 20,
            0, 8, 1, /* 3552: pointer.DIST_POINT */
            	3557, 0,
            0, 0, 1, /* 3557: DIST_POINT */
            	3562, 0,
            0, 32, 3, /* 3562: struct.DIST_POINT_st */
            	3571, 0,
            	3662, 8,
            	3590, 16,
            1, 8, 1, /* 3571: pointer.struct.DIST_POINT_NAME_st */
            	3576, 0,
            0, 24, 2, /* 3576: struct.DIST_POINT_NAME_st */
            	3583, 8,
            	3638, 16,
            0, 8, 2, /* 3583: union.unknown */
            	3590, 0,
            	3614, 0,
            1, 8, 1, /* 3590: pointer.struct.stack_st_GENERAL_NAME */
            	3595, 0,
            0, 32, 2, /* 3595: struct.stack_st_fake_GENERAL_NAME */
            	3602, 8,
            	22, 24,
            8884099, 8, 2, /* 3602: pointer_to_array_of_pointers_to_stack */
            	3609, 0,
            	226, 20,
            0, 8, 1, /* 3609: pointer.GENERAL_NAME */
            	2836, 0,
            1, 8, 1, /* 3614: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3619, 0,
            0, 32, 2, /* 3619: struct.stack_st_fake_X509_NAME_ENTRY */
            	3626, 8,
            	22, 24,
            8884099, 8, 2, /* 3626: pointer_to_array_of_pointers_to_stack */
            	3633, 0,
            	226, 20,
            0, 8, 1, /* 3633: pointer.X509_NAME_ENTRY */
            	185, 0,
            1, 8, 1, /* 3638: pointer.struct.X509_name_st */
            	3643, 0,
            0, 40, 3, /* 3643: struct.X509_name_st */
            	3614, 0,
            	3652, 16,
            	127, 24,
            1, 8, 1, /* 3652: pointer.struct.buf_mem_st */
            	3657, 0,
            0, 24, 1, /* 3657: struct.buf_mem_st */
            	17, 8,
            1, 8, 1, /* 3662: pointer.struct.asn1_string_st */
            	3667, 0,
            0, 24, 1, /* 3667: struct.asn1_string_st */
            	127, 8,
            1, 8, 1, /* 3672: pointer.struct.stack_st_GENERAL_NAME */
            	3677, 0,
            0, 32, 2, /* 3677: struct.stack_st_fake_GENERAL_NAME */
            	3684, 8,
            	22, 24,
            8884099, 8, 2, /* 3684: pointer_to_array_of_pointers_to_stack */
            	3691, 0,
            	226, 20,
            0, 8, 1, /* 3691: pointer.GENERAL_NAME */
            	2836, 0,
            1, 8, 1, /* 3696: pointer.struct.NAME_CONSTRAINTS_st */
            	3701, 0,
            0, 16, 2, /* 3701: struct.NAME_CONSTRAINTS_st */
            	3708, 0,
            	3708, 8,
            1, 8, 1, /* 3708: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3713, 0,
            0, 32, 2, /* 3713: struct.stack_st_fake_GENERAL_SUBTREE */
            	3720, 8,
            	22, 24,
            8884099, 8, 2, /* 3720: pointer_to_array_of_pointers_to_stack */
            	3727, 0,
            	226, 20,
            0, 8, 1, /* 3727: pointer.GENERAL_SUBTREE */
            	3732, 0,
            0, 0, 1, /* 3732: GENERAL_SUBTREE */
            	3737, 0,
            0, 24, 3, /* 3737: struct.GENERAL_SUBTREE_st */
            	3746, 0,
            	3878, 8,
            	3878, 16,
            1, 8, 1, /* 3746: pointer.struct.GENERAL_NAME_st */
            	3751, 0,
            0, 16, 1, /* 3751: struct.GENERAL_NAME_st */
            	3756, 8,
            0, 8, 15, /* 3756: union.unknown */
            	17, 0,
            	3789, 0,
            	3908, 0,
            	3908, 0,
            	3815, 0,
            	3948, 0,
            	3996, 0,
            	3908, 0,
            	3893, 0,
            	3801, 0,
            	3893, 0,
            	3948, 0,
            	3908, 0,
            	3801, 0,
            	3815, 0,
            1, 8, 1, /* 3789: pointer.struct.otherName_st */
            	3794, 0,
            0, 16, 2, /* 3794: struct.otherName_st */
            	3801, 0,
            	3815, 8,
            1, 8, 1, /* 3801: pointer.struct.asn1_object_st */
            	3806, 0,
            0, 40, 3, /* 3806: struct.asn1_object_st */
            	62, 0,
            	62, 8,
            	211, 24,
            1, 8, 1, /* 3815: pointer.struct.asn1_type_st */
            	3820, 0,
            0, 16, 1, /* 3820: struct.asn1_type_st */
            	3825, 8,
            0, 8, 20, /* 3825: union.unknown */
            	17, 0,
            	3868, 0,
            	3801, 0,
            	3878, 0,
            	3883, 0,
            	3888, 0,
            	3893, 0,
            	3898, 0,
            	3903, 0,
            	3908, 0,
            	3913, 0,
            	3918, 0,
            	3923, 0,
            	3928, 0,
            	3933, 0,
            	3938, 0,
            	3943, 0,
            	3868, 0,
            	3868, 0,
            	3401, 0,
            1, 8, 1, /* 3868: pointer.struct.asn1_string_st */
            	3873, 0,
            0, 24, 1, /* 3873: struct.asn1_string_st */
            	127, 8,
            1, 8, 1, /* 3878: pointer.struct.asn1_string_st */
            	3873, 0,
            1, 8, 1, /* 3883: pointer.struct.asn1_string_st */
            	3873, 0,
            1, 8, 1, /* 3888: pointer.struct.asn1_string_st */
            	3873, 0,
            1, 8, 1, /* 3893: pointer.struct.asn1_string_st */
            	3873, 0,
            1, 8, 1, /* 3898: pointer.struct.asn1_string_st */
            	3873, 0,
            1, 8, 1, /* 3903: pointer.struct.asn1_string_st */
            	3873, 0,
            1, 8, 1, /* 3908: pointer.struct.asn1_string_st */
            	3873, 0,
            1, 8, 1, /* 3913: pointer.struct.asn1_string_st */
            	3873, 0,
            1, 8, 1, /* 3918: pointer.struct.asn1_string_st */
            	3873, 0,
            1, 8, 1, /* 3923: pointer.struct.asn1_string_st */
            	3873, 0,
            1, 8, 1, /* 3928: pointer.struct.asn1_string_st */
            	3873, 0,
            1, 8, 1, /* 3933: pointer.struct.asn1_string_st */
            	3873, 0,
            1, 8, 1, /* 3938: pointer.struct.asn1_string_st */
            	3873, 0,
            1, 8, 1, /* 3943: pointer.struct.asn1_string_st */
            	3873, 0,
            1, 8, 1, /* 3948: pointer.struct.X509_name_st */
            	3953, 0,
            0, 40, 3, /* 3953: struct.X509_name_st */
            	3962, 0,
            	3986, 16,
            	127, 24,
            1, 8, 1, /* 3962: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3967, 0,
            0, 32, 2, /* 3967: struct.stack_st_fake_X509_NAME_ENTRY */
            	3974, 8,
            	22, 24,
            8884099, 8, 2, /* 3974: pointer_to_array_of_pointers_to_stack */
            	3981, 0,
            	226, 20,
            0, 8, 1, /* 3981: pointer.X509_NAME_ENTRY */
            	185, 0,
            1, 8, 1, /* 3986: pointer.struct.buf_mem_st */
            	3991, 0,
            0, 24, 1, /* 3991: struct.buf_mem_st */
            	17, 8,
            1, 8, 1, /* 3996: pointer.struct.EDIPartyName_st */
            	4001, 0,
            0, 16, 2, /* 4001: struct.EDIPartyName_st */
            	3868, 0,
            	3868, 8,
            1, 8, 1, /* 4008: pointer.struct.x509_cert_aux_st */
            	4013, 0,
            0, 40, 5, /* 4013: struct.x509_cert_aux_st */
            	487, 0,
            	487, 8,
            	4026, 16,
            	2783, 24,
            	4031, 32,
            1, 8, 1, /* 4026: pointer.struct.asn1_string_st */
            	637, 0,
            1, 8, 1, /* 4031: pointer.struct.stack_st_X509_ALGOR */
            	4036, 0,
            0, 32, 2, /* 4036: struct.stack_st_fake_X509_ALGOR */
            	4043, 8,
            	22, 24,
            8884099, 8, 2, /* 4043: pointer_to_array_of_pointers_to_stack */
            	4050, 0,
            	226, 20,
            0, 8, 1, /* 4050: pointer.X509_ALGOR */
            	4055, 0,
            0, 0, 1, /* 4055: X509_ALGOR */
            	647, 0,
            1, 8, 1, /* 4060: pointer.struct.X509_crl_st */
            	4065, 0,
            0, 120, 10, /* 4065: struct.X509_crl_st */
            	4088, 0,
            	642, 8,
            	2691, 16,
            	2788, 32,
            	4215, 40,
            	632, 56,
            	632, 64,
            	4227, 96,
            	4268, 104,
            	104, 112,
            1, 8, 1, /* 4088: pointer.struct.X509_crl_info_st */
            	4093, 0,
            0, 80, 8, /* 4093: struct.X509_crl_info_st */
            	632, 0,
            	642, 8,
            	809, 16,
            	869, 24,
            	869, 32,
            	4112, 40,
            	2696, 48,
            	2756, 56,
            1, 8, 1, /* 4112: pointer.struct.stack_st_X509_REVOKED */
            	4117, 0,
            0, 32, 2, /* 4117: struct.stack_st_fake_X509_REVOKED */
            	4124, 8,
            	22, 24,
            8884099, 8, 2, /* 4124: pointer_to_array_of_pointers_to_stack */
            	4131, 0,
            	226, 20,
            0, 8, 1, /* 4131: pointer.X509_REVOKED */
            	4136, 0,
            0, 0, 1, /* 4136: X509_REVOKED */
            	4141, 0,
            0, 40, 4, /* 4141: struct.x509_revoked_st */
            	4152, 0,
            	4162, 8,
            	4167, 16,
            	4191, 24,
            1, 8, 1, /* 4152: pointer.struct.asn1_string_st */
            	4157, 0,
            0, 24, 1, /* 4157: struct.asn1_string_st */
            	127, 8,
            1, 8, 1, /* 4162: pointer.struct.asn1_string_st */
            	4157, 0,
            1, 8, 1, /* 4167: pointer.struct.stack_st_X509_EXTENSION */
            	4172, 0,
            0, 32, 2, /* 4172: struct.stack_st_fake_X509_EXTENSION */
            	4179, 8,
            	22, 24,
            8884099, 8, 2, /* 4179: pointer_to_array_of_pointers_to_stack */
            	4186, 0,
            	226, 20,
            0, 8, 1, /* 4186: pointer.X509_EXTENSION */
            	2720, 0,
            1, 8, 1, /* 4191: pointer.struct.stack_st_GENERAL_NAME */
            	4196, 0,
            0, 32, 2, /* 4196: struct.stack_st_fake_GENERAL_NAME */
            	4203, 8,
            	22, 24,
            8884099, 8, 2, /* 4203: pointer_to_array_of_pointers_to_stack */
            	4210, 0,
            	226, 20,
            0, 8, 1, /* 4210: pointer.GENERAL_NAME */
            	2836, 0,
            1, 8, 1, /* 4215: pointer.struct.ISSUING_DIST_POINT_st */
            	4220, 0,
            0, 32, 2, /* 4220: struct.ISSUING_DIST_POINT_st */
            	3571, 0,
            	3662, 16,
            1, 8, 1, /* 4227: pointer.struct.stack_st_GENERAL_NAMES */
            	4232, 0,
            0, 32, 2, /* 4232: struct.stack_st_fake_GENERAL_NAMES */
            	4239, 8,
            	22, 24,
            8884099, 8, 2, /* 4239: pointer_to_array_of_pointers_to_stack */
            	4246, 0,
            	226, 20,
            0, 8, 1, /* 4246: pointer.GENERAL_NAMES */
            	4251, 0,
            0, 0, 1, /* 4251: GENERAL_NAMES */
            	4256, 0,
            0, 32, 1, /* 4256: struct.stack_st_GENERAL_NAME */
            	4261, 0,
            0, 32, 2, /* 4261: struct.stack_st */
            	12, 8,
            	22, 24,
            1, 8, 1, /* 4268: pointer.struct.x509_crl_method_st */
            	4273, 0,
            0, 40, 4, /* 4273: struct.x509_crl_method_st */
            	4284, 8,
            	4284, 16,
            	4287, 24,
            	4290, 32,
            8884097, 8, 0, /* 4284: pointer.func */
            8884097, 8, 0, /* 4287: pointer.func */
            8884097, 8, 0, /* 4290: pointer.func */
            1, 8, 1, /* 4293: pointer.struct.evp_pkey_st */
            	4298, 0,
            0, 56, 4, /* 4298: struct.evp_pkey_st */
            	4309, 16,
            	1478, 24,
            	4314, 32,
            	4347, 48,
            1, 8, 1, /* 4309: pointer.struct.evp_pkey_asn1_method_st */
            	924, 0,
            0, 8, 5, /* 4314: union.unknown */
            	17, 0,
            	4327, 0,
            	4332, 0,
            	4337, 0,
            	4342, 0,
            1, 8, 1, /* 4327: pointer.struct.rsa_st */
            	1386, 0,
            1, 8, 1, /* 4332: pointer.struct.dsa_st */
            	1588, 0,
            1, 8, 1, /* 4337: pointer.struct.dh_st */
            	1715, 0,
            1, 8, 1, /* 4342: pointer.struct.ec_key_st */
            	1829, 0,
            1, 8, 1, /* 4347: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4352, 0,
            0, 32, 2, /* 4352: struct.stack_st_fake_X509_ATTRIBUTE */
            	4359, 8,
            	22, 24,
            8884099, 8, 2, /* 4359: pointer_to_array_of_pointers_to_stack */
            	4366, 0,
            	226, 20,
            0, 8, 1, /* 4366: pointer.X509_ATTRIBUTE */
            	2336, 0,
            8884097, 8, 0, /* 4371: pointer.func */
            8884097, 8, 0, /* 4374: pointer.func */
            8884097, 8, 0, /* 4377: pointer.func */
            0, 0, 1, /* 4380: X509_LOOKUP */
            	4385, 0,
            0, 32, 3, /* 4385: struct.x509_lookup_st */
            	4394, 8,
            	17, 16,
            	4437, 24,
            1, 8, 1, /* 4394: pointer.struct.x509_lookup_method_st */
            	4399, 0,
            0, 80, 10, /* 4399: struct.x509_lookup_method_st */
            	62, 0,
            	4422, 8,
            	4377, 16,
            	4422, 24,
            	4422, 32,
            	4425, 40,
            	4428, 48,
            	4371, 56,
            	4431, 64,
            	4434, 72,
            8884097, 8, 0, /* 4422: pointer.func */
            8884097, 8, 0, /* 4425: pointer.func */
            8884097, 8, 0, /* 4428: pointer.func */
            8884097, 8, 0, /* 4431: pointer.func */
            8884097, 8, 0, /* 4434: pointer.func */
            1, 8, 1, /* 4437: pointer.struct.x509_store_st */
            	4442, 0,
            0, 144, 15, /* 4442: struct.x509_store_st */
            	525, 8,
            	4475, 16,
            	475, 24,
            	472, 32,
            	4499, 40,
            	4502, 48,
            	469, 56,
            	472, 64,
            	4505, 72,
            	466, 80,
            	4508, 88,
            	463, 96,
            	460, 104,
            	472, 112,
            	2761, 120,
            1, 8, 1, /* 4475: pointer.struct.stack_st_X509_LOOKUP */
            	4480, 0,
            0, 32, 2, /* 4480: struct.stack_st_fake_X509_LOOKUP */
            	4487, 8,
            	22, 24,
            8884099, 8, 2, /* 4487: pointer_to_array_of_pointers_to_stack */
            	4494, 0,
            	226, 20,
            0, 8, 1, /* 4494: pointer.X509_LOOKUP */
            	4380, 0,
            8884097, 8, 0, /* 4499: pointer.func */
            8884097, 8, 0, /* 4502: pointer.func */
            8884097, 8, 0, /* 4505: pointer.func */
            8884097, 8, 0, /* 4508: pointer.func */
            1, 8, 1, /* 4511: pointer.struct.stack_st_X509_LOOKUP */
            	4516, 0,
            0, 32, 2, /* 4516: struct.stack_st_fake_X509_LOOKUP */
            	4523, 8,
            	22, 24,
            8884099, 8, 2, /* 4523: pointer_to_array_of_pointers_to_stack */
            	4530, 0,
            	226, 20,
            0, 8, 1, /* 4530: pointer.X509_LOOKUP */
            	4380, 0,
            8884097, 8, 0, /* 4535: pointer.func */
            8884097, 8, 0, /* 4538: pointer.func */
            0, 16, 1, /* 4541: struct.srtp_protection_profile_st */
            	62, 0,
            1, 8, 1, /* 4546: pointer.struct.stack_st_X509 */
            	4551, 0,
            0, 32, 2, /* 4551: struct.stack_st_fake_X509 */
            	4558, 8,
            	22, 24,
            8884099, 8, 2, /* 4558: pointer_to_array_of_pointers_to_stack */
            	4565, 0,
            	226, 20,
            0, 8, 1, /* 4565: pointer.X509 */
            	4570, 0,
            0, 0, 1, /* 4570: X509 */
            	4575, 0,
            0, 184, 12, /* 4575: struct.x509_st */
            	4602, 0,
            	4642, 8,
            	4717, 16,
            	17, 32,
            	1637, 40,
            	4751, 104,
            	4756, 112,
            	4761, 120,
            	4766, 128,
            	4191, 136,
            	4790, 144,
            	4795, 176,
            1, 8, 1, /* 4602: pointer.struct.x509_cinf_st */
            	4607, 0,
            0, 104, 11, /* 4607: struct.x509_cinf_st */
            	4632, 0,
            	4632, 8,
            	4642, 16,
            	4647, 24,
            	4695, 32,
            	4647, 40,
            	4712, 48,
            	4717, 56,
            	4717, 64,
            	4722, 72,
            	4746, 80,
            1, 8, 1, /* 4632: pointer.struct.asn1_string_st */
            	4637, 0,
            0, 24, 1, /* 4637: struct.asn1_string_st */
            	127, 8,
            1, 8, 1, /* 4642: pointer.struct.X509_algor_st */
            	647, 0,
            1, 8, 1, /* 4647: pointer.struct.X509_name_st */
            	4652, 0,
            0, 40, 3, /* 4652: struct.X509_name_st */
            	4661, 0,
            	4685, 16,
            	127, 24,
            1, 8, 1, /* 4661: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4666, 0,
            0, 32, 2, /* 4666: struct.stack_st_fake_X509_NAME_ENTRY */
            	4673, 8,
            	22, 24,
            8884099, 8, 2, /* 4673: pointer_to_array_of_pointers_to_stack */
            	4680, 0,
            	226, 20,
            0, 8, 1, /* 4680: pointer.X509_NAME_ENTRY */
            	185, 0,
            1, 8, 1, /* 4685: pointer.struct.buf_mem_st */
            	4690, 0,
            0, 24, 1, /* 4690: struct.buf_mem_st */
            	17, 8,
            1, 8, 1, /* 4695: pointer.struct.X509_val_st */
            	4700, 0,
            0, 16, 2, /* 4700: struct.X509_val_st */
            	4707, 0,
            	4707, 8,
            1, 8, 1, /* 4707: pointer.struct.asn1_string_st */
            	4637, 0,
            1, 8, 1, /* 4712: pointer.struct.X509_pubkey_st */
            	879, 0,
            1, 8, 1, /* 4717: pointer.struct.asn1_string_st */
            	4637, 0,
            1, 8, 1, /* 4722: pointer.struct.stack_st_X509_EXTENSION */
            	4727, 0,
            0, 32, 2, /* 4727: struct.stack_st_fake_X509_EXTENSION */
            	4734, 8,
            	22, 24,
            8884099, 8, 2, /* 4734: pointer_to_array_of_pointers_to_stack */
            	4741, 0,
            	226, 20,
            0, 8, 1, /* 4741: pointer.X509_EXTENSION */
            	2720, 0,
            0, 24, 1, /* 4746: struct.ASN1_ENCODING_st */
            	127, 0,
            1, 8, 1, /* 4751: pointer.struct.asn1_string_st */
            	4637, 0,
            1, 8, 1, /* 4756: pointer.struct.AUTHORITY_KEYID_st */
            	2793, 0,
            1, 8, 1, /* 4761: pointer.struct.X509_POLICY_CACHE_st */
            	3116, 0,
            1, 8, 1, /* 4766: pointer.struct.stack_st_DIST_POINT */
            	4771, 0,
            0, 32, 2, /* 4771: struct.stack_st_fake_DIST_POINT */
            	4778, 8,
            	22, 24,
            8884099, 8, 2, /* 4778: pointer_to_array_of_pointers_to_stack */
            	4785, 0,
            	226, 20,
            0, 8, 1, /* 4785: pointer.DIST_POINT */
            	3557, 0,
            1, 8, 1, /* 4790: pointer.struct.NAME_CONSTRAINTS_st */
            	3701, 0,
            1, 8, 1, /* 4795: pointer.struct.x509_cert_aux_st */
            	4800, 0,
            0, 40, 5, /* 4800: struct.x509_cert_aux_st */
            	4813, 0,
            	4813, 8,
            	4837, 16,
            	4751, 24,
            	4842, 32,
            1, 8, 1, /* 4813: pointer.struct.stack_st_ASN1_OBJECT */
            	4818, 0,
            0, 32, 2, /* 4818: struct.stack_st_fake_ASN1_OBJECT */
            	4825, 8,
            	22, 24,
            8884099, 8, 2, /* 4825: pointer_to_array_of_pointers_to_stack */
            	4832, 0,
            	226, 20,
            0, 8, 1, /* 4832: pointer.ASN1_OBJECT */
            	511, 0,
            1, 8, 1, /* 4837: pointer.struct.asn1_string_st */
            	4637, 0,
            1, 8, 1, /* 4842: pointer.struct.stack_st_X509_ALGOR */
            	4847, 0,
            0, 32, 2, /* 4847: struct.stack_st_fake_X509_ALGOR */
            	4854, 8,
            	22, 24,
            8884099, 8, 2, /* 4854: pointer_to_array_of_pointers_to_stack */
            	4861, 0,
            	226, 20,
            0, 8, 1, /* 4861: pointer.X509_ALGOR */
            	4055, 0,
            8884097, 8, 0, /* 4866: pointer.func */
            1, 8, 1, /* 4869: pointer.struct.x509_store_st */
            	4874, 0,
            0, 144, 15, /* 4874: struct.x509_store_st */
            	4907, 8,
            	4511, 16,
            	4931, 24,
            	457, 32,
            	4967, 40,
            	4970, 48,
            	4374, 56,
            	457, 64,
            	4973, 72,
            	4866, 80,
            	4976, 88,
            	454, 96,
            	451, 104,
            	457, 112,
            	4979, 120,
            1, 8, 1, /* 4907: pointer.struct.stack_st_X509_OBJECT */
            	4912, 0,
            0, 32, 2, /* 4912: struct.stack_st_fake_X509_OBJECT */
            	4919, 8,
            	22, 24,
            8884099, 8, 2, /* 4919: pointer_to_array_of_pointers_to_stack */
            	4926, 0,
            	226, 20,
            0, 8, 1, /* 4926: pointer.X509_OBJECT */
            	549, 0,
            1, 8, 1, /* 4931: pointer.struct.X509_VERIFY_PARAM_st */
            	4936, 0,
            0, 56, 2, /* 4936: struct.X509_VERIFY_PARAM_st */
            	17, 0,
            	4943, 48,
            1, 8, 1, /* 4943: pointer.struct.stack_st_ASN1_OBJECT */
            	4948, 0,
            0, 32, 2, /* 4948: struct.stack_st_fake_ASN1_OBJECT */
            	4955, 8,
            	22, 24,
            8884099, 8, 2, /* 4955: pointer_to_array_of_pointers_to_stack */
            	4962, 0,
            	226, 20,
            0, 8, 1, /* 4962: pointer.ASN1_OBJECT */
            	511, 0,
            8884097, 8, 0, /* 4967: pointer.func */
            8884097, 8, 0, /* 4970: pointer.func */
            8884097, 8, 0, /* 4973: pointer.func */
            8884097, 8, 0, /* 4976: pointer.func */
            0, 16, 1, /* 4979: struct.crypto_ex_data_st */
            	4984, 0,
            1, 8, 1, /* 4984: pointer.struct.stack_st_void */
            	4989, 0,
            0, 32, 1, /* 4989: struct.stack_st_void */
            	4994, 0,
            0, 32, 2, /* 4994: struct.stack_st */
            	12, 8,
            	22, 24,
            0, 736, 50, /* 5001: struct.ssl_ctx_st */
            	5104, 0,
            	5270, 8,
            	5270, 16,
            	4869, 24,
            	427, 32,
            	5304, 48,
            	5304, 56,
            	6124, 80,
            	412, 88,
            	6127, 96,
            	409, 152,
            	104, 160,
            	406, 168,
            	104, 176,
            	6130, 184,
            	403, 192,
            	400, 200,
            	4979, 208,
            	6133, 224,
            	6133, 232,
            	6133, 240,
            	4546, 248,
            	376, 256,
            	6172, 264,
            	6175, 272,
            	6204, 304,
            	6645, 320,
            	104, 328,
            	4967, 376,
            	6648, 384,
            	4931, 392,
            	5759, 408,
            	298, 416,
            	104, 424,
            	4538, 480,
            	4535, 488,
            	104, 496,
            	6651, 504,
            	104, 512,
            	17, 520,
            	6654, 528,
            	6657, 536,
            	293, 552,
            	293, 560,
            	6660, 568,
            	257, 696,
            	104, 704,
            	254, 712,
            	104, 720,
            	347, 728,
            1, 8, 1, /* 5104: pointer.struct.ssl_method_st */
            	5109, 0,
            0, 232, 28, /* 5109: struct.ssl_method_st */
            	5168, 8,
            	5171, 16,
            	5171, 24,
            	5168, 32,
            	5168, 40,
            	5174, 48,
            	5174, 56,
            	5177, 64,
            	5168, 72,
            	5168, 80,
            	5168, 88,
            	5180, 96,
            	5183, 104,
            	5186, 112,
            	5168, 120,
            	5189, 128,
            	5192, 136,
            	5195, 144,
            	5198, 152,
            	5201, 160,
            	1294, 168,
            	5204, 176,
            	5207, 184,
            	327, 192,
            	5210, 200,
            	1294, 208,
            	5264, 216,
            	5267, 224,
            8884097, 8, 0, /* 5168: pointer.func */
            8884097, 8, 0, /* 5171: pointer.func */
            8884097, 8, 0, /* 5174: pointer.func */
            8884097, 8, 0, /* 5177: pointer.func */
            8884097, 8, 0, /* 5180: pointer.func */
            8884097, 8, 0, /* 5183: pointer.func */
            8884097, 8, 0, /* 5186: pointer.func */
            8884097, 8, 0, /* 5189: pointer.func */
            8884097, 8, 0, /* 5192: pointer.func */
            8884097, 8, 0, /* 5195: pointer.func */
            8884097, 8, 0, /* 5198: pointer.func */
            8884097, 8, 0, /* 5201: pointer.func */
            8884097, 8, 0, /* 5204: pointer.func */
            8884097, 8, 0, /* 5207: pointer.func */
            1, 8, 1, /* 5210: pointer.struct.ssl3_enc_method */
            	5215, 0,
            0, 112, 11, /* 5215: struct.ssl3_enc_method */
            	5240, 0,
            	5243, 8,
            	5246, 16,
            	5249, 24,
            	5240, 32,
            	5252, 40,
            	5255, 56,
            	62, 64,
            	62, 80,
            	5258, 96,
            	5261, 104,
            8884097, 8, 0, /* 5240: pointer.func */
            8884097, 8, 0, /* 5243: pointer.func */
            8884097, 8, 0, /* 5246: pointer.func */
            8884097, 8, 0, /* 5249: pointer.func */
            8884097, 8, 0, /* 5252: pointer.func */
            8884097, 8, 0, /* 5255: pointer.func */
            8884097, 8, 0, /* 5258: pointer.func */
            8884097, 8, 0, /* 5261: pointer.func */
            8884097, 8, 0, /* 5264: pointer.func */
            8884097, 8, 0, /* 5267: pointer.func */
            1, 8, 1, /* 5270: pointer.struct.stack_st_SSL_CIPHER */
            	5275, 0,
            0, 32, 2, /* 5275: struct.stack_st_fake_SSL_CIPHER */
            	5282, 8,
            	22, 24,
            8884099, 8, 2, /* 5282: pointer_to_array_of_pointers_to_stack */
            	5289, 0,
            	226, 20,
            0, 8, 1, /* 5289: pointer.SSL_CIPHER */
            	5294, 0,
            0, 0, 1, /* 5294: SSL_CIPHER */
            	5299, 0,
            0, 88, 1, /* 5299: struct.ssl_cipher_st */
            	62, 8,
            1, 8, 1, /* 5304: pointer.struct.ssl_session_st */
            	5309, 0,
            0, 352, 14, /* 5309: struct.ssl_session_st */
            	17, 144,
            	17, 152,
            	5340, 168,
            	5881, 176,
            	6114, 224,
            	5270, 240,
            	4979, 248,
            	5304, 264,
            	5304, 272,
            	17, 280,
            	127, 296,
            	127, 312,
            	127, 320,
            	17, 344,
            1, 8, 1, /* 5340: pointer.struct.sess_cert_st */
            	5345, 0,
            0, 248, 5, /* 5345: struct.sess_cert_st */
            	5358, 0,
            	5382, 16,
            	5866, 216,
            	5871, 224,
            	5876, 232,
            1, 8, 1, /* 5358: pointer.struct.stack_st_X509 */
            	5363, 0,
            0, 32, 2, /* 5363: struct.stack_st_fake_X509 */
            	5370, 8,
            	22, 24,
            8884099, 8, 2, /* 5370: pointer_to_array_of_pointers_to_stack */
            	5377, 0,
            	226, 20,
            0, 8, 1, /* 5377: pointer.X509 */
            	4570, 0,
            1, 8, 1, /* 5382: pointer.struct.cert_pkey_st */
            	5387, 0,
            0, 24, 3, /* 5387: struct.cert_pkey_st */
            	5396, 0,
            	5738, 8,
            	5821, 16,
            1, 8, 1, /* 5396: pointer.struct.x509_st */
            	5401, 0,
            0, 184, 12, /* 5401: struct.x509_st */
            	5428, 0,
            	5468, 8,
            	5543, 16,
            	17, 32,
            	5577, 40,
            	5599, 104,
            	5604, 112,
            	5609, 120,
            	5614, 128,
            	5638, 136,
            	5662, 144,
            	5667, 176,
            1, 8, 1, /* 5428: pointer.struct.x509_cinf_st */
            	5433, 0,
            0, 104, 11, /* 5433: struct.x509_cinf_st */
            	5458, 0,
            	5458, 8,
            	5468, 16,
            	5473, 24,
            	5521, 32,
            	5473, 40,
            	5538, 48,
            	5543, 56,
            	5543, 64,
            	5548, 72,
            	5572, 80,
            1, 8, 1, /* 5458: pointer.struct.asn1_string_st */
            	5463, 0,
            0, 24, 1, /* 5463: struct.asn1_string_st */
            	127, 8,
            1, 8, 1, /* 5468: pointer.struct.X509_algor_st */
            	647, 0,
            1, 8, 1, /* 5473: pointer.struct.X509_name_st */
            	5478, 0,
            0, 40, 3, /* 5478: struct.X509_name_st */
            	5487, 0,
            	5511, 16,
            	127, 24,
            1, 8, 1, /* 5487: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5492, 0,
            0, 32, 2, /* 5492: struct.stack_st_fake_X509_NAME_ENTRY */
            	5499, 8,
            	22, 24,
            8884099, 8, 2, /* 5499: pointer_to_array_of_pointers_to_stack */
            	5506, 0,
            	226, 20,
            0, 8, 1, /* 5506: pointer.X509_NAME_ENTRY */
            	185, 0,
            1, 8, 1, /* 5511: pointer.struct.buf_mem_st */
            	5516, 0,
            0, 24, 1, /* 5516: struct.buf_mem_st */
            	17, 8,
            1, 8, 1, /* 5521: pointer.struct.X509_val_st */
            	5526, 0,
            0, 16, 2, /* 5526: struct.X509_val_st */
            	5533, 0,
            	5533, 8,
            1, 8, 1, /* 5533: pointer.struct.asn1_string_st */
            	5463, 0,
            1, 8, 1, /* 5538: pointer.struct.X509_pubkey_st */
            	879, 0,
            1, 8, 1, /* 5543: pointer.struct.asn1_string_st */
            	5463, 0,
            1, 8, 1, /* 5548: pointer.struct.stack_st_X509_EXTENSION */
            	5553, 0,
            0, 32, 2, /* 5553: struct.stack_st_fake_X509_EXTENSION */
            	5560, 8,
            	22, 24,
            8884099, 8, 2, /* 5560: pointer_to_array_of_pointers_to_stack */
            	5567, 0,
            	226, 20,
            0, 8, 1, /* 5567: pointer.X509_EXTENSION */
            	2720, 0,
            0, 24, 1, /* 5572: struct.ASN1_ENCODING_st */
            	127, 0,
            0, 16, 1, /* 5577: struct.crypto_ex_data_st */
            	5582, 0,
            1, 8, 1, /* 5582: pointer.struct.stack_st_void */
            	5587, 0,
            0, 32, 1, /* 5587: struct.stack_st_void */
            	5592, 0,
            0, 32, 2, /* 5592: struct.stack_st */
            	12, 8,
            	22, 24,
            1, 8, 1, /* 5599: pointer.struct.asn1_string_st */
            	5463, 0,
            1, 8, 1, /* 5604: pointer.struct.AUTHORITY_KEYID_st */
            	2793, 0,
            1, 8, 1, /* 5609: pointer.struct.X509_POLICY_CACHE_st */
            	3116, 0,
            1, 8, 1, /* 5614: pointer.struct.stack_st_DIST_POINT */
            	5619, 0,
            0, 32, 2, /* 5619: struct.stack_st_fake_DIST_POINT */
            	5626, 8,
            	22, 24,
            8884099, 8, 2, /* 5626: pointer_to_array_of_pointers_to_stack */
            	5633, 0,
            	226, 20,
            0, 8, 1, /* 5633: pointer.DIST_POINT */
            	3557, 0,
            1, 8, 1, /* 5638: pointer.struct.stack_st_GENERAL_NAME */
            	5643, 0,
            0, 32, 2, /* 5643: struct.stack_st_fake_GENERAL_NAME */
            	5650, 8,
            	22, 24,
            8884099, 8, 2, /* 5650: pointer_to_array_of_pointers_to_stack */
            	5657, 0,
            	226, 20,
            0, 8, 1, /* 5657: pointer.GENERAL_NAME */
            	2836, 0,
            1, 8, 1, /* 5662: pointer.struct.NAME_CONSTRAINTS_st */
            	3701, 0,
            1, 8, 1, /* 5667: pointer.struct.x509_cert_aux_st */
            	5672, 0,
            0, 40, 5, /* 5672: struct.x509_cert_aux_st */
            	5685, 0,
            	5685, 8,
            	5709, 16,
            	5599, 24,
            	5714, 32,
            1, 8, 1, /* 5685: pointer.struct.stack_st_ASN1_OBJECT */
            	5690, 0,
            0, 32, 2, /* 5690: struct.stack_st_fake_ASN1_OBJECT */
            	5697, 8,
            	22, 24,
            8884099, 8, 2, /* 5697: pointer_to_array_of_pointers_to_stack */
            	5704, 0,
            	226, 20,
            0, 8, 1, /* 5704: pointer.ASN1_OBJECT */
            	511, 0,
            1, 8, 1, /* 5709: pointer.struct.asn1_string_st */
            	5463, 0,
            1, 8, 1, /* 5714: pointer.struct.stack_st_X509_ALGOR */
            	5719, 0,
            0, 32, 2, /* 5719: struct.stack_st_fake_X509_ALGOR */
            	5726, 8,
            	22, 24,
            8884099, 8, 2, /* 5726: pointer_to_array_of_pointers_to_stack */
            	5733, 0,
            	226, 20,
            0, 8, 1, /* 5733: pointer.X509_ALGOR */
            	4055, 0,
            1, 8, 1, /* 5738: pointer.struct.evp_pkey_st */
            	5743, 0,
            0, 56, 4, /* 5743: struct.evp_pkey_st */
            	5754, 16,
            	5759, 24,
            	5764, 32,
            	5797, 48,
            1, 8, 1, /* 5754: pointer.struct.evp_pkey_asn1_method_st */
            	924, 0,
            1, 8, 1, /* 5759: pointer.struct.engine_st */
            	1025, 0,
            0, 8, 5, /* 5764: union.unknown */
            	17, 0,
            	5777, 0,
            	5782, 0,
            	5787, 0,
            	5792, 0,
            1, 8, 1, /* 5777: pointer.struct.rsa_st */
            	1386, 0,
            1, 8, 1, /* 5782: pointer.struct.dsa_st */
            	1588, 0,
            1, 8, 1, /* 5787: pointer.struct.dh_st */
            	1715, 0,
            1, 8, 1, /* 5792: pointer.struct.ec_key_st */
            	1829, 0,
            1, 8, 1, /* 5797: pointer.struct.stack_st_X509_ATTRIBUTE */
            	5802, 0,
            0, 32, 2, /* 5802: struct.stack_st_fake_X509_ATTRIBUTE */
            	5809, 8,
            	22, 24,
            8884099, 8, 2, /* 5809: pointer_to_array_of_pointers_to_stack */
            	5816, 0,
            	226, 20,
            0, 8, 1, /* 5816: pointer.X509_ATTRIBUTE */
            	2336, 0,
            1, 8, 1, /* 5821: pointer.struct.env_md_st */
            	5826, 0,
            0, 120, 8, /* 5826: struct.env_md_st */
            	5845, 24,
            	5848, 32,
            	5851, 40,
            	5854, 48,
            	5845, 56,
            	5857, 64,
            	5860, 72,
            	5863, 112,
            8884097, 8, 0, /* 5845: pointer.func */
            8884097, 8, 0, /* 5848: pointer.func */
            8884097, 8, 0, /* 5851: pointer.func */
            8884097, 8, 0, /* 5854: pointer.func */
            8884097, 8, 0, /* 5857: pointer.func */
            8884097, 8, 0, /* 5860: pointer.func */
            8884097, 8, 0, /* 5863: pointer.func */
            1, 8, 1, /* 5866: pointer.struct.rsa_st */
            	1386, 0,
            1, 8, 1, /* 5871: pointer.struct.dh_st */
            	1715, 0,
            1, 8, 1, /* 5876: pointer.struct.ec_key_st */
            	1829, 0,
            1, 8, 1, /* 5881: pointer.struct.x509_st */
            	5886, 0,
            0, 184, 12, /* 5886: struct.x509_st */
            	5913, 0,
            	5953, 8,
            	6028, 16,
            	17, 32,
            	4979, 40,
            	6062, 104,
            	5604, 112,
            	5609, 120,
            	5614, 128,
            	5638, 136,
            	5662, 144,
            	6067, 176,
            1, 8, 1, /* 5913: pointer.struct.x509_cinf_st */
            	5918, 0,
            0, 104, 11, /* 5918: struct.x509_cinf_st */
            	5943, 0,
            	5943, 8,
            	5953, 16,
            	5958, 24,
            	6006, 32,
            	5958, 40,
            	6023, 48,
            	6028, 56,
            	6028, 64,
            	6033, 72,
            	6057, 80,
            1, 8, 1, /* 5943: pointer.struct.asn1_string_st */
            	5948, 0,
            0, 24, 1, /* 5948: struct.asn1_string_st */
            	127, 8,
            1, 8, 1, /* 5953: pointer.struct.X509_algor_st */
            	647, 0,
            1, 8, 1, /* 5958: pointer.struct.X509_name_st */
            	5963, 0,
            0, 40, 3, /* 5963: struct.X509_name_st */
            	5972, 0,
            	5996, 16,
            	127, 24,
            1, 8, 1, /* 5972: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5977, 0,
            0, 32, 2, /* 5977: struct.stack_st_fake_X509_NAME_ENTRY */
            	5984, 8,
            	22, 24,
            8884099, 8, 2, /* 5984: pointer_to_array_of_pointers_to_stack */
            	5991, 0,
            	226, 20,
            0, 8, 1, /* 5991: pointer.X509_NAME_ENTRY */
            	185, 0,
            1, 8, 1, /* 5996: pointer.struct.buf_mem_st */
            	6001, 0,
            0, 24, 1, /* 6001: struct.buf_mem_st */
            	17, 8,
            1, 8, 1, /* 6006: pointer.struct.X509_val_st */
            	6011, 0,
            0, 16, 2, /* 6011: struct.X509_val_st */
            	6018, 0,
            	6018, 8,
            1, 8, 1, /* 6018: pointer.struct.asn1_string_st */
            	5948, 0,
            1, 8, 1, /* 6023: pointer.struct.X509_pubkey_st */
            	879, 0,
            1, 8, 1, /* 6028: pointer.struct.asn1_string_st */
            	5948, 0,
            1, 8, 1, /* 6033: pointer.struct.stack_st_X509_EXTENSION */
            	6038, 0,
            0, 32, 2, /* 6038: struct.stack_st_fake_X509_EXTENSION */
            	6045, 8,
            	22, 24,
            8884099, 8, 2, /* 6045: pointer_to_array_of_pointers_to_stack */
            	6052, 0,
            	226, 20,
            0, 8, 1, /* 6052: pointer.X509_EXTENSION */
            	2720, 0,
            0, 24, 1, /* 6057: struct.ASN1_ENCODING_st */
            	127, 0,
            1, 8, 1, /* 6062: pointer.struct.asn1_string_st */
            	5948, 0,
            1, 8, 1, /* 6067: pointer.struct.x509_cert_aux_st */
            	6072, 0,
            0, 40, 5, /* 6072: struct.x509_cert_aux_st */
            	4943, 0,
            	4943, 8,
            	6085, 16,
            	6062, 24,
            	6090, 32,
            1, 8, 1, /* 6085: pointer.struct.asn1_string_st */
            	5948, 0,
            1, 8, 1, /* 6090: pointer.struct.stack_st_X509_ALGOR */
            	6095, 0,
            0, 32, 2, /* 6095: struct.stack_st_fake_X509_ALGOR */
            	6102, 8,
            	22, 24,
            8884099, 8, 2, /* 6102: pointer_to_array_of_pointers_to_stack */
            	6109, 0,
            	226, 20,
            0, 8, 1, /* 6109: pointer.X509_ALGOR */
            	4055, 0,
            1, 8, 1, /* 6114: pointer.struct.ssl_cipher_st */
            	6119, 0,
            0, 88, 1, /* 6119: struct.ssl_cipher_st */
            	62, 8,
            8884097, 8, 0, /* 6124: pointer.func */
            8884097, 8, 0, /* 6127: pointer.func */
            8884097, 8, 0, /* 6130: pointer.func */
            1, 8, 1, /* 6133: pointer.struct.env_md_st */
            	6138, 0,
            0, 120, 8, /* 6138: struct.env_md_st */
            	6157, 24,
            	6160, 32,
            	6163, 40,
            	6166, 48,
            	6157, 56,
            	5857, 64,
            	5860, 72,
            	6169, 112,
            8884097, 8, 0, /* 6157: pointer.func */
            8884097, 8, 0, /* 6160: pointer.func */
            8884097, 8, 0, /* 6163: pointer.func */
            8884097, 8, 0, /* 6166: pointer.func */
            8884097, 8, 0, /* 6169: pointer.func */
            8884097, 8, 0, /* 6172: pointer.func */
            1, 8, 1, /* 6175: pointer.struct.stack_st_X509_NAME */
            	6180, 0,
            0, 32, 2, /* 6180: struct.stack_st_fake_X509_NAME */
            	6187, 8,
            	22, 24,
            8884099, 8, 2, /* 6187: pointer_to_array_of_pointers_to_stack */
            	6194, 0,
            	226, 20,
            0, 8, 1, /* 6194: pointer.X509_NAME */
            	6199, 0,
            0, 0, 1, /* 6199: X509_NAME */
            	4652, 0,
            1, 8, 1, /* 6204: pointer.struct.cert_st */
            	6209, 0,
            0, 296, 7, /* 6209: struct.cert_st */
            	6226, 0,
            	6626, 48,
            	6631, 56,
            	6634, 64,
            	6639, 72,
            	5876, 80,
            	6642, 88,
            1, 8, 1, /* 6226: pointer.struct.cert_pkey_st */
            	6231, 0,
            0, 24, 3, /* 6231: struct.cert_pkey_st */
            	6240, 0,
            	6519, 8,
            	6587, 16,
            1, 8, 1, /* 6240: pointer.struct.x509_st */
            	6245, 0,
            0, 184, 12, /* 6245: struct.x509_st */
            	6272, 0,
            	6312, 8,
            	6387, 16,
            	17, 32,
            	6421, 40,
            	6443, 104,
            	5604, 112,
            	5609, 120,
            	5614, 128,
            	5638, 136,
            	5662, 144,
            	6448, 176,
            1, 8, 1, /* 6272: pointer.struct.x509_cinf_st */
            	6277, 0,
            0, 104, 11, /* 6277: struct.x509_cinf_st */
            	6302, 0,
            	6302, 8,
            	6312, 16,
            	6317, 24,
            	6365, 32,
            	6317, 40,
            	6382, 48,
            	6387, 56,
            	6387, 64,
            	6392, 72,
            	6416, 80,
            1, 8, 1, /* 6302: pointer.struct.asn1_string_st */
            	6307, 0,
            0, 24, 1, /* 6307: struct.asn1_string_st */
            	127, 8,
            1, 8, 1, /* 6312: pointer.struct.X509_algor_st */
            	647, 0,
            1, 8, 1, /* 6317: pointer.struct.X509_name_st */
            	6322, 0,
            0, 40, 3, /* 6322: struct.X509_name_st */
            	6331, 0,
            	6355, 16,
            	127, 24,
            1, 8, 1, /* 6331: pointer.struct.stack_st_X509_NAME_ENTRY */
            	6336, 0,
            0, 32, 2, /* 6336: struct.stack_st_fake_X509_NAME_ENTRY */
            	6343, 8,
            	22, 24,
            8884099, 8, 2, /* 6343: pointer_to_array_of_pointers_to_stack */
            	6350, 0,
            	226, 20,
            0, 8, 1, /* 6350: pointer.X509_NAME_ENTRY */
            	185, 0,
            1, 8, 1, /* 6355: pointer.struct.buf_mem_st */
            	6360, 0,
            0, 24, 1, /* 6360: struct.buf_mem_st */
            	17, 8,
            1, 8, 1, /* 6365: pointer.struct.X509_val_st */
            	6370, 0,
            0, 16, 2, /* 6370: struct.X509_val_st */
            	6377, 0,
            	6377, 8,
            1, 8, 1, /* 6377: pointer.struct.asn1_string_st */
            	6307, 0,
            1, 8, 1, /* 6382: pointer.struct.X509_pubkey_st */
            	879, 0,
            1, 8, 1, /* 6387: pointer.struct.asn1_string_st */
            	6307, 0,
            1, 8, 1, /* 6392: pointer.struct.stack_st_X509_EXTENSION */
            	6397, 0,
            0, 32, 2, /* 6397: struct.stack_st_fake_X509_EXTENSION */
            	6404, 8,
            	22, 24,
            8884099, 8, 2, /* 6404: pointer_to_array_of_pointers_to_stack */
            	6411, 0,
            	226, 20,
            0, 8, 1, /* 6411: pointer.X509_EXTENSION */
            	2720, 0,
            0, 24, 1, /* 6416: struct.ASN1_ENCODING_st */
            	127, 0,
            0, 16, 1, /* 6421: struct.crypto_ex_data_st */
            	6426, 0,
            1, 8, 1, /* 6426: pointer.struct.stack_st_void */
            	6431, 0,
            0, 32, 1, /* 6431: struct.stack_st_void */
            	6436, 0,
            0, 32, 2, /* 6436: struct.stack_st */
            	12, 8,
            	22, 24,
            1, 8, 1, /* 6443: pointer.struct.asn1_string_st */
            	6307, 0,
            1, 8, 1, /* 6448: pointer.struct.x509_cert_aux_st */
            	6453, 0,
            0, 40, 5, /* 6453: struct.x509_cert_aux_st */
            	6466, 0,
            	6466, 8,
            	6490, 16,
            	6443, 24,
            	6495, 32,
            1, 8, 1, /* 6466: pointer.struct.stack_st_ASN1_OBJECT */
            	6471, 0,
            0, 32, 2, /* 6471: struct.stack_st_fake_ASN1_OBJECT */
            	6478, 8,
            	22, 24,
            8884099, 8, 2, /* 6478: pointer_to_array_of_pointers_to_stack */
            	6485, 0,
            	226, 20,
            0, 8, 1, /* 6485: pointer.ASN1_OBJECT */
            	511, 0,
            1, 8, 1, /* 6490: pointer.struct.asn1_string_st */
            	6307, 0,
            1, 8, 1, /* 6495: pointer.struct.stack_st_X509_ALGOR */
            	6500, 0,
            0, 32, 2, /* 6500: struct.stack_st_fake_X509_ALGOR */
            	6507, 8,
            	22, 24,
            8884099, 8, 2, /* 6507: pointer_to_array_of_pointers_to_stack */
            	6514, 0,
            	226, 20,
            0, 8, 1, /* 6514: pointer.X509_ALGOR */
            	4055, 0,
            1, 8, 1, /* 6519: pointer.struct.evp_pkey_st */
            	6524, 0,
            0, 56, 4, /* 6524: struct.evp_pkey_st */
            	5754, 16,
            	5759, 24,
            	6535, 32,
            	6563, 48,
            0, 8, 5, /* 6535: union.unknown */
            	17, 0,
            	6548, 0,
            	6553, 0,
            	6558, 0,
            	5792, 0,
            1, 8, 1, /* 6548: pointer.struct.rsa_st */
            	1386, 0,
            1, 8, 1, /* 6553: pointer.struct.dsa_st */
            	1588, 0,
            1, 8, 1, /* 6558: pointer.struct.dh_st */
            	1715, 0,
            1, 8, 1, /* 6563: pointer.struct.stack_st_X509_ATTRIBUTE */
            	6568, 0,
            0, 32, 2, /* 6568: struct.stack_st_fake_X509_ATTRIBUTE */
            	6575, 8,
            	22, 24,
            8884099, 8, 2, /* 6575: pointer_to_array_of_pointers_to_stack */
            	6582, 0,
            	226, 20,
            0, 8, 1, /* 6582: pointer.X509_ATTRIBUTE */
            	2336, 0,
            1, 8, 1, /* 6587: pointer.struct.env_md_st */
            	6592, 0,
            0, 120, 8, /* 6592: struct.env_md_st */
            	6611, 24,
            	6614, 32,
            	6617, 40,
            	6620, 48,
            	6611, 56,
            	5857, 64,
            	5860, 72,
            	6623, 112,
            8884097, 8, 0, /* 6611: pointer.func */
            8884097, 8, 0, /* 6614: pointer.func */
            8884097, 8, 0, /* 6617: pointer.func */
            8884097, 8, 0, /* 6620: pointer.func */
            8884097, 8, 0, /* 6623: pointer.func */
            1, 8, 1, /* 6626: pointer.struct.rsa_st */
            	1386, 0,
            8884097, 8, 0, /* 6631: pointer.func */
            1, 8, 1, /* 6634: pointer.struct.dh_st */
            	1715, 0,
            8884097, 8, 0, /* 6639: pointer.func */
            8884097, 8, 0, /* 6642: pointer.func */
            8884097, 8, 0, /* 6645: pointer.func */
            8884097, 8, 0, /* 6648: pointer.func */
            8884097, 8, 0, /* 6651: pointer.func */
            8884097, 8, 0, /* 6654: pointer.func */
            8884097, 8, 0, /* 6657: pointer.func */
            0, 128, 14, /* 6660: struct.srp_ctx_st */
            	104, 0,
            	298, 8,
            	4535, 16,
            	6691, 24,
            	17, 32,
            	260, 40,
            	260, 48,
            	260, 56,
            	260, 64,
            	260, 72,
            	260, 80,
            	260, 88,
            	260, 96,
            	17, 104,
            8884097, 8, 0, /* 6691: pointer.func */
            1, 8, 1, /* 6694: pointer.struct.ssl_ctx_st */
            	5001, 0,
            1, 8, 1, /* 6699: pointer.struct.stack_st_X509_EXTENSION */
            	6704, 0,
            0, 32, 2, /* 6704: struct.stack_st_fake_X509_EXTENSION */
            	6711, 8,
            	22, 24,
            8884099, 8, 2, /* 6711: pointer_to_array_of_pointers_to_stack */
            	6718, 0,
            	226, 20,
            0, 8, 1, /* 6718: pointer.X509_EXTENSION */
            	2720, 0,
            1, 8, 1, /* 6723: pointer.struct.dsa_st */
            	1588, 0,
            1, 8, 1, /* 6728: pointer.struct.engine_st */
            	1025, 0,
            0, 24, 1, /* 6733: struct.ssl3_buffer_st */
            	127, 0,
            8884097, 8, 0, /* 6738: pointer.func */
            0, 8, 5, /* 6741: union.unknown */
            	17, 0,
            	6754, 0,
            	6723, 0,
            	6759, 0,
            	6764, 0,
            1, 8, 1, /* 6754: pointer.struct.rsa_st */
            	1386, 0,
            1, 8, 1, /* 6759: pointer.struct.dh_st */
            	1715, 0,
            1, 8, 1, /* 6764: pointer.struct.ec_key_st */
            	1829, 0,
            8884097, 8, 0, /* 6769: pointer.func */
            8884097, 8, 0, /* 6772: pointer.func */
            8884097, 8, 0, /* 6775: pointer.func */
            0, 56, 3, /* 6778: struct.ssl3_record_st */
            	127, 16,
            	127, 24,
            	127, 32,
            8884097, 8, 0, /* 6787: pointer.func */
            0, 208, 25, /* 6790: struct.evp_pkey_method_st */
            	6843, 8,
            	6787, 16,
            	6846, 24,
            	6843, 32,
            	6849, 40,
            	6843, 48,
            	6849, 56,
            	6843, 64,
            	6852, 72,
            	6843, 80,
            	6855, 88,
            	6843, 96,
            	6852, 104,
            	6772, 112,
            	6769, 120,
            	6772, 128,
            	6858, 136,
            	6843, 144,
            	6852, 152,
            	6843, 160,
            	6852, 168,
            	6843, 176,
            	6861, 184,
            	6864, 192,
            	6867, 200,
            8884097, 8, 0, /* 6843: pointer.func */
            8884097, 8, 0, /* 6846: pointer.func */
            8884097, 8, 0, /* 6849: pointer.func */
            8884097, 8, 0, /* 6852: pointer.func */
            8884097, 8, 0, /* 6855: pointer.func */
            8884097, 8, 0, /* 6858: pointer.func */
            8884097, 8, 0, /* 6861: pointer.func */
            8884097, 8, 0, /* 6864: pointer.func */
            8884097, 8, 0, /* 6867: pointer.func */
            0, 344, 9, /* 6870: struct.ssl2_state_st */
            	211, 24,
            	127, 56,
            	127, 64,
            	127, 72,
            	127, 104,
            	127, 112,
            	127, 120,
            	127, 128,
            	127, 136,
            8884097, 8, 0, /* 6891: pointer.func */
            1, 8, 1, /* 6894: pointer.struct.stack_st_OCSP_RESPID */
            	6899, 0,
            0, 32, 2, /* 6899: struct.stack_st_fake_OCSP_RESPID */
            	6906, 8,
            	22, 24,
            8884099, 8, 2, /* 6906: pointer_to_array_of_pointers_to_stack */
            	6913, 0,
            	226, 20,
            0, 8, 1, /* 6913: pointer.OCSP_RESPID */
            	239, 0,
            8884097, 8, 0, /* 6918: pointer.func */
            1, 8, 1, /* 6921: pointer.struct.bio_method_st */
            	6926, 0,
            0, 80, 9, /* 6926: struct.bio_method_st */
            	62, 8,
            	6891, 16,
            	6918, 24,
            	6775, 32,
            	6918, 40,
            	6947, 48,
            	6950, 56,
            	6950, 64,
            	6953, 72,
            8884097, 8, 0, /* 6947: pointer.func */
            8884097, 8, 0, /* 6950: pointer.func */
            8884097, 8, 0, /* 6953: pointer.func */
            8884097, 8, 0, /* 6956: pointer.func */
            1, 8, 1, /* 6959: pointer.struct.evp_cipher_ctx_st */
            	6964, 0,
            0, 168, 4, /* 6964: struct.evp_cipher_ctx_st */
            	6975, 0,
            	5759, 8,
            	104, 96,
            	104, 120,
            1, 8, 1, /* 6975: pointer.struct.evp_cipher_st */
            	6980, 0,
            0, 88, 7, /* 6980: struct.evp_cipher_st */
            	6997, 24,
            	7000, 32,
            	7003, 40,
            	7006, 56,
            	7006, 64,
            	7009, 72,
            	104, 80,
            8884097, 8, 0, /* 6997: pointer.func */
            8884097, 8, 0, /* 7000: pointer.func */
            8884097, 8, 0, /* 7003: pointer.func */
            8884097, 8, 0, /* 7006: pointer.func */
            8884097, 8, 0, /* 7009: pointer.func */
            0, 112, 7, /* 7012: struct.bio_st */
            	6921, 0,
            	7029, 8,
            	17, 16,
            	104, 48,
            	7032, 56,
            	7032, 64,
            	4979, 96,
            8884097, 8, 0, /* 7029: pointer.func */
            1, 8, 1, /* 7032: pointer.struct.bio_st */
            	7012, 0,
            1, 8, 1, /* 7037: pointer.struct.bio_st */
            	7012, 0,
            1, 8, 1, /* 7042: pointer.struct.ssl_st */
            	7047, 0,
            0, 808, 51, /* 7047: struct.ssl_st */
            	5104, 8,
            	7037, 16,
            	7037, 24,
            	7037, 32,
            	5168, 48,
            	5996, 80,
            	104, 88,
            	127, 104,
            	7152, 120,
            	7157, 128,
            	7351, 136,
            	6645, 152,
            	104, 160,
            	4931, 176,
            	5270, 184,
            	5270, 192,
            	6959, 208,
            	7190, 216,
            	7421, 224,
            	6959, 232,
            	7190, 240,
            	7421, 248,
            	6204, 256,
            	7433, 304,
            	6648, 312,
            	4967, 328,
            	6172, 336,
            	6654, 352,
            	6657, 360,
            	6694, 368,
            	4979, 392,
            	6175, 408,
            	7438, 464,
            	104, 472,
            	17, 480,
            	6894, 504,
            	6699, 512,
            	127, 520,
            	127, 544,
            	127, 560,
            	104, 568,
            	7441, 584,
            	7446, 592,
            	104, 600,
            	7449, 608,
            	104, 616,
            	6694, 624,
            	127, 632,
            	347, 648,
            	7452, 656,
            	6660, 680,
            1, 8, 1, /* 7152: pointer.struct.ssl2_state_st */
            	6870, 0,
            1, 8, 1, /* 7157: pointer.struct.ssl3_state_st */
            	7162, 0,
            0, 1200, 10, /* 7162: struct.ssl3_state_st */
            	6733, 240,
            	6733, 264,
            	6778, 288,
            	6778, 344,
            	211, 432,
            	7037, 440,
            	7185, 448,
            	104, 496,
            	104, 512,
            	7287, 528,
            1, 8, 1, /* 7185: pointer.pointer.struct.env_md_ctx_st */
            	7190, 0,
            1, 8, 1, /* 7190: pointer.struct.env_md_ctx_st */
            	7195, 0,
            0, 48, 5, /* 7195: struct.env_md_ctx_st */
            	6133, 0,
            	5759, 8,
            	104, 24,
            	7208, 32,
            	6160, 40,
            1, 8, 1, /* 7208: pointer.struct.evp_pkey_ctx_st */
            	7213, 0,
            0, 80, 8, /* 7213: struct.evp_pkey_ctx_st */
            	7232, 0,
            	6728, 8,
            	7237, 16,
            	7237, 24,
            	104, 40,
            	104, 48,
            	6956, 56,
            	7282, 64,
            1, 8, 1, /* 7232: pointer.struct.evp_pkey_method_st */
            	6790, 0,
            1, 8, 1, /* 7237: pointer.struct.evp_pkey_st */
            	7242, 0,
            0, 56, 4, /* 7242: struct.evp_pkey_st */
            	7253, 16,
            	6728, 24,
            	6741, 32,
            	7258, 48,
            1, 8, 1, /* 7253: pointer.struct.evp_pkey_asn1_method_st */
            	924, 0,
            1, 8, 1, /* 7258: pointer.struct.stack_st_X509_ATTRIBUTE */
            	7263, 0,
            0, 32, 2, /* 7263: struct.stack_st_fake_X509_ATTRIBUTE */
            	7270, 8,
            	22, 24,
            8884099, 8, 2, /* 7270: pointer_to_array_of_pointers_to_stack */
            	7277, 0,
            	226, 20,
            0, 8, 1, /* 7277: pointer.X509_ATTRIBUTE */
            	2336, 0,
            1, 8, 1, /* 7282: pointer.int */
            	226, 0,
            0, 528, 8, /* 7287: struct.unknown */
            	6114, 408,
            	7306, 416,
            	5876, 424,
            	6175, 464,
            	127, 480,
            	6975, 488,
            	6133, 496,
            	7311, 512,
            1, 8, 1, /* 7306: pointer.struct.dh_st */
            	1715, 0,
            1, 8, 1, /* 7311: pointer.struct.ssl_comp_st */
            	7316, 0,
            0, 24, 2, /* 7316: struct.ssl_comp_st */
            	62, 8,
            	7323, 16,
            1, 8, 1, /* 7323: pointer.struct.comp_method_st */
            	7328, 0,
            0, 64, 7, /* 7328: struct.comp_method_st */
            	62, 8,
            	7345, 16,
            	7348, 24,
            	6738, 32,
            	6738, 40,
            	327, 48,
            	327, 56,
            8884097, 8, 0, /* 7345: pointer.func */
            8884097, 8, 0, /* 7348: pointer.func */
            1, 8, 1, /* 7351: pointer.struct.dtls1_state_st */
            	7356, 0,
            0, 888, 7, /* 7356: struct.dtls1_state_st */
            	7373, 576,
            	7373, 592,
            	7378, 608,
            	7378, 616,
            	7373, 624,
            	7405, 648,
            	7405, 736,
            0, 16, 1, /* 7373: struct.record_pqueue_st */
            	7378, 8,
            1, 8, 1, /* 7378: pointer.struct._pqueue */
            	7383, 0,
            0, 16, 1, /* 7383: struct._pqueue */
            	7388, 0,
            1, 8, 1, /* 7388: pointer.struct._pitem */
            	7393, 0,
            0, 24, 2, /* 7393: struct._pitem */
            	104, 8,
            	7400, 16,
            1, 8, 1, /* 7400: pointer.struct._pitem */
            	7393, 0,
            0, 88, 1, /* 7405: struct.hm_header_st */
            	7410, 48,
            0, 40, 4, /* 7410: struct.dtls1_retransmit_state */
            	6959, 0,
            	7190, 8,
            	7421, 16,
            	7433, 24,
            1, 8, 1, /* 7421: pointer.struct.comp_ctx_st */
            	7426, 0,
            0, 56, 2, /* 7426: struct.comp_ctx_st */
            	7323, 0,
            	4979, 40,
            1, 8, 1, /* 7433: pointer.struct.ssl_session_st */
            	5309, 0,
            8884097, 8, 0, /* 7438: pointer.func */
            1, 8, 1, /* 7441: pointer.struct.tls_session_ticket_ext_st */
            	117, 0,
            8884097, 8, 0, /* 7446: pointer.func */
            8884097, 8, 0, /* 7449: pointer.func */
            1, 8, 1, /* 7452: pointer.struct.srtp_protection_profile_st */
            	4541, 0,
            0, 1, 0, /* 7457: char */
        },
        .arg_entity_index = { 7042, },
        .ret_entity_index = 112,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL * new_arg_a = *((const SSL * *)new_args->args[0]);

    BIO * *new_ret_ptr = (BIO * *)new_args->ret;

    BIO * (*orig_SSL_get_wbio)(const SSL *);
    orig_SSL_get_wbio = dlsym(RTLD_NEXT, "SSL_get_wbio");
    *new_ret_ptr = (*orig_SSL_get_wbio)(new_arg_a);

    syscall(889);

    return ret;
}

