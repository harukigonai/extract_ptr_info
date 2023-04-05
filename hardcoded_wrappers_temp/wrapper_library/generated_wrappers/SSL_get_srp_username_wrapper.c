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

char * bb_SSL_get_srp_username(SSL * arg_a);

char * SSL_get_srp_username(SSL * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_get_srp_username called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_get_srp_username(arg_a);
    else {
        char * (*orig_SSL_get_srp_username)(SSL *);
        orig_SSL_get_srp_username = dlsym(RTLD_NEXT, "SSL_get_srp_username");
        return orig_SSL_get_srp_username(arg_a);
    }
}

char * bb_SSL_get_srp_username(SSL * arg_a) 
{
    char * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 16, 1, /* 0: struct.srtp_protection_profile_st */
            	5, 0,
            1, 8, 1, /* 5: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 10: pointer.struct.srtp_protection_profile_st */
            	0, 0,
            8884097, 8, 0, /* 15: pointer.func */
            8884097, 8, 0, /* 18: pointer.func */
            0, 16, 1, /* 21: struct.tls_session_ticket_ext_st */
            	26, 8,
            0, 8, 0, /* 26: pointer.void */
            1, 8, 1, /* 29: pointer.struct.tls_session_ticket_ext_st */
            	21, 0,
            0, 24, 1, /* 34: struct.asn1_string_st */
            	39, 8,
            1, 8, 1, /* 39: pointer.unsigned char */
            	44, 0,
            0, 1, 0, /* 44: unsigned char */
            0, 24, 1, /* 47: struct.buf_mem_st */
            	52, 8,
            1, 8, 1, /* 52: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 57: pointer.struct.stack_st_X509_NAME_ENTRY */
            	62, 0,
            0, 32, 2, /* 62: struct.stack_st_fake_X509_NAME_ENTRY */
            	69, 8,
            	125, 24,
            8884099, 8, 2, /* 69: pointer_to_array_of_pointers_to_stack */
            	76, 0,
            	122, 20,
            0, 8, 1, /* 76: pointer.X509_NAME_ENTRY */
            	81, 0,
            0, 0, 1, /* 81: X509_NAME_ENTRY */
            	86, 0,
            0, 24, 2, /* 86: struct.X509_name_entry_st */
            	93, 0,
            	112, 8,
            1, 8, 1, /* 93: pointer.struct.asn1_object_st */
            	98, 0,
            0, 40, 3, /* 98: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	107, 24,
            1, 8, 1, /* 107: pointer.unsigned char */
            	44, 0,
            1, 8, 1, /* 112: pointer.struct.asn1_string_st */
            	117, 0,
            0, 24, 1, /* 117: struct.asn1_string_st */
            	39, 8,
            0, 4, 0, /* 122: int */
            8884097, 8, 0, /* 125: pointer.func */
            0, 40, 3, /* 128: struct.X509_name_st */
            	57, 0,
            	137, 16,
            	39, 24,
            1, 8, 1, /* 137: pointer.struct.buf_mem_st */
            	47, 0,
            1, 8, 1, /* 142: pointer.struct.X509_name_st */
            	128, 0,
            0, 8, 2, /* 147: union.unknown */
            	142, 0,
            	154, 0,
            1, 8, 1, /* 154: pointer.struct.asn1_string_st */
            	34, 0,
            8884097, 8, 0, /* 159: pointer.func */
            0, 16, 1, /* 162: struct.srtp_protection_profile_st */
            	5, 0,
            1, 8, 1, /* 167: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	172, 0,
            0, 32, 2, /* 172: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	179, 8,
            	125, 24,
            8884099, 8, 2, /* 179: pointer_to_array_of_pointers_to_stack */
            	186, 0,
            	122, 20,
            0, 8, 1, /* 186: pointer.SRTP_PROTECTION_PROFILE */
            	191, 0,
            0, 0, 1, /* 191: SRTP_PROTECTION_PROFILE */
            	162, 0,
            8884097, 8, 0, /* 196: pointer.func */
            8884097, 8, 0, /* 199: pointer.func */
            8884097, 8, 0, /* 202: pointer.func */
            0, 128, 14, /* 205: struct.srp_ctx_st */
            	26, 0,
            	236, 8,
            	239, 16,
            	202, 24,
            	52, 32,
            	242, 40,
            	242, 48,
            	242, 56,
            	242, 64,
            	242, 72,
            	242, 80,
            	242, 88,
            	242, 96,
            	52, 104,
            8884097, 8, 0, /* 236: pointer.func */
            8884097, 8, 0, /* 239: pointer.func */
            1, 8, 1, /* 242: pointer.struct.bignum_st */
            	247, 0,
            0, 24, 1, /* 247: struct.bignum_st */
            	252, 0,
            1, 8, 1, /* 252: pointer.unsigned int */
            	257, 0,
            0, 4, 0, /* 257: unsigned int */
            0, 8, 1, /* 260: struct.ssl3_buf_freelist_entry_st */
            	265, 0,
            1, 8, 1, /* 265: pointer.struct.ssl3_buf_freelist_entry_st */
            	260, 0,
            8884097, 8, 0, /* 270: pointer.func */
            8884097, 8, 0, /* 273: pointer.func */
            0, 64, 7, /* 276: struct.comp_method_st */
            	5, 8,
            	293, 16,
            	273, 24,
            	296, 32,
            	296, 40,
            	299, 48,
            	299, 56,
            8884097, 8, 0, /* 293: pointer.func */
            8884097, 8, 0, /* 296: pointer.func */
            8884097, 8, 0, /* 299: pointer.func */
            0, 0, 1, /* 302: SSL_COMP */
            	307, 0,
            0, 24, 2, /* 307: struct.ssl_comp_st */
            	5, 8,
            	314, 16,
            1, 8, 1, /* 314: pointer.struct.comp_method_st */
            	276, 0,
            1, 8, 1, /* 319: pointer.struct.stack_st_SSL_COMP */
            	324, 0,
            0, 32, 2, /* 324: struct.stack_st_fake_SSL_COMP */
            	331, 8,
            	125, 24,
            8884099, 8, 2, /* 331: pointer_to_array_of_pointers_to_stack */
            	338, 0,
            	122, 20,
            0, 8, 1, /* 338: pointer.SSL_COMP */
            	302, 0,
            8884097, 8, 0, /* 343: pointer.func */
            8884097, 8, 0, /* 346: pointer.func */
            8884097, 8, 0, /* 349: pointer.func */
            1, 8, 1, /* 352: pointer.struct.lhash_node_st */
            	357, 0,
            0, 24, 2, /* 357: struct.lhash_node_st */
            	26, 0,
            	352, 8,
            1, 8, 1, /* 364: pointer.struct.lhash_node_st */
            	357, 0,
            1, 8, 1, /* 369: pointer.pointer.struct.lhash_node_st */
            	364, 0,
            0, 176, 3, /* 374: struct.lhash_st */
            	369, 0,
            	125, 8,
            	383, 16,
            8884097, 8, 0, /* 383: pointer.func */
            1, 8, 1, /* 386: pointer.struct.lhash_st */
            	374, 0,
            8884097, 8, 0, /* 391: pointer.func */
            8884097, 8, 0, /* 394: pointer.func */
            8884097, 8, 0, /* 397: pointer.func */
            8884097, 8, 0, /* 400: pointer.func */
            8884097, 8, 0, /* 403: pointer.func */
            8884097, 8, 0, /* 406: pointer.func */
            8884097, 8, 0, /* 409: pointer.func */
            8884097, 8, 0, /* 412: pointer.func */
            8884097, 8, 0, /* 415: pointer.func */
            8884097, 8, 0, /* 418: pointer.func */
            8884097, 8, 0, /* 421: pointer.func */
            8884097, 8, 0, /* 424: pointer.func */
            8884097, 8, 0, /* 427: pointer.func */
            1, 8, 1, /* 430: pointer.struct.stack_st_X509_LOOKUP */
            	435, 0,
            0, 32, 2, /* 435: struct.stack_st_fake_X509_LOOKUP */
            	442, 8,
            	125, 24,
            8884099, 8, 2, /* 442: pointer_to_array_of_pointers_to_stack */
            	449, 0,
            	122, 20,
            0, 8, 1, /* 449: pointer.X509_LOOKUP */
            	454, 0,
            0, 0, 1, /* 454: X509_LOOKUP */
            	459, 0,
            0, 32, 3, /* 459: struct.x509_lookup_st */
            	468, 8,
            	52, 16,
            	517, 24,
            1, 8, 1, /* 468: pointer.struct.x509_lookup_method_st */
            	473, 0,
            0, 80, 10, /* 473: struct.x509_lookup_method_st */
            	5, 0,
            	496, 8,
            	499, 16,
            	496, 24,
            	496, 32,
            	502, 40,
            	505, 48,
            	508, 56,
            	511, 64,
            	514, 72,
            8884097, 8, 0, /* 496: pointer.func */
            8884097, 8, 0, /* 499: pointer.func */
            8884097, 8, 0, /* 502: pointer.func */
            8884097, 8, 0, /* 505: pointer.func */
            8884097, 8, 0, /* 508: pointer.func */
            8884097, 8, 0, /* 511: pointer.func */
            8884097, 8, 0, /* 514: pointer.func */
            1, 8, 1, /* 517: pointer.struct.x509_store_st */
            	522, 0,
            0, 144, 15, /* 522: struct.x509_store_st */
            	555, 8,
            	430, 16,
            	2468, 24,
            	427, 32,
            	424, 40,
            	2480, 48,
            	421, 56,
            	427, 64,
            	418, 72,
            	415, 80,
            	2483, 88,
            	412, 96,
            	409, 104,
            	427, 112,
            	1060, 120,
            1, 8, 1, /* 555: pointer.struct.stack_st_X509_OBJECT */
            	560, 0,
            0, 32, 2, /* 560: struct.stack_st_fake_X509_OBJECT */
            	567, 8,
            	125, 24,
            8884099, 8, 2, /* 567: pointer_to_array_of_pointers_to_stack */
            	574, 0,
            	122, 20,
            0, 8, 1, /* 574: pointer.X509_OBJECT */
            	579, 0,
            0, 0, 1, /* 579: X509_OBJECT */
            	584, 0,
            0, 16, 1, /* 584: struct.x509_object_st */
            	589, 8,
            0, 8, 4, /* 589: union.unknown */
            	52, 0,
            	600, 0,
            	2256, 0,
            	908, 0,
            1, 8, 1, /* 600: pointer.struct.x509_st */
            	605, 0,
            0, 184, 12, /* 605: struct.x509_st */
            	632, 0,
            	672, 8,
            	761, 16,
            	52, 32,
            	1060, 40,
            	766, 104,
            	1702, 112,
            	1710, 120,
            	1718, 128,
            	2127, 136,
            	2151, 144,
            	2159, 176,
            1, 8, 1, /* 632: pointer.struct.x509_cinf_st */
            	637, 0,
            0, 104, 11, /* 637: struct.x509_cinf_st */
            	662, 0,
            	662, 8,
            	672, 16,
            	829, 24,
            	877, 32,
            	829, 40,
            	894, 48,
            	761, 56,
            	761, 64,
            	1637, 72,
            	1697, 80,
            1, 8, 1, /* 662: pointer.struct.asn1_string_st */
            	667, 0,
            0, 24, 1, /* 667: struct.asn1_string_st */
            	39, 8,
            1, 8, 1, /* 672: pointer.struct.X509_algor_st */
            	677, 0,
            0, 16, 2, /* 677: struct.X509_algor_st */
            	684, 0,
            	698, 8,
            1, 8, 1, /* 684: pointer.struct.asn1_object_st */
            	689, 0,
            0, 40, 3, /* 689: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	107, 24,
            1, 8, 1, /* 698: pointer.struct.asn1_type_st */
            	703, 0,
            0, 16, 1, /* 703: struct.asn1_type_st */
            	708, 8,
            0, 8, 20, /* 708: union.unknown */
            	52, 0,
            	751, 0,
            	684, 0,
            	662, 0,
            	756, 0,
            	761, 0,
            	766, 0,
            	771, 0,
            	776, 0,
            	781, 0,
            	786, 0,
            	791, 0,
            	796, 0,
            	801, 0,
            	806, 0,
            	811, 0,
            	816, 0,
            	751, 0,
            	751, 0,
            	821, 0,
            1, 8, 1, /* 751: pointer.struct.asn1_string_st */
            	667, 0,
            1, 8, 1, /* 756: pointer.struct.asn1_string_st */
            	667, 0,
            1, 8, 1, /* 761: pointer.struct.asn1_string_st */
            	667, 0,
            1, 8, 1, /* 766: pointer.struct.asn1_string_st */
            	667, 0,
            1, 8, 1, /* 771: pointer.struct.asn1_string_st */
            	667, 0,
            1, 8, 1, /* 776: pointer.struct.asn1_string_st */
            	667, 0,
            1, 8, 1, /* 781: pointer.struct.asn1_string_st */
            	667, 0,
            1, 8, 1, /* 786: pointer.struct.asn1_string_st */
            	667, 0,
            1, 8, 1, /* 791: pointer.struct.asn1_string_st */
            	667, 0,
            1, 8, 1, /* 796: pointer.struct.asn1_string_st */
            	667, 0,
            1, 8, 1, /* 801: pointer.struct.asn1_string_st */
            	667, 0,
            1, 8, 1, /* 806: pointer.struct.asn1_string_st */
            	667, 0,
            1, 8, 1, /* 811: pointer.struct.asn1_string_st */
            	667, 0,
            1, 8, 1, /* 816: pointer.struct.asn1_string_st */
            	667, 0,
            1, 8, 1, /* 821: pointer.struct.ASN1_VALUE_st */
            	826, 0,
            0, 0, 0, /* 826: struct.ASN1_VALUE_st */
            1, 8, 1, /* 829: pointer.struct.X509_name_st */
            	834, 0,
            0, 40, 3, /* 834: struct.X509_name_st */
            	843, 0,
            	867, 16,
            	39, 24,
            1, 8, 1, /* 843: pointer.struct.stack_st_X509_NAME_ENTRY */
            	848, 0,
            0, 32, 2, /* 848: struct.stack_st_fake_X509_NAME_ENTRY */
            	855, 8,
            	125, 24,
            8884099, 8, 2, /* 855: pointer_to_array_of_pointers_to_stack */
            	862, 0,
            	122, 20,
            0, 8, 1, /* 862: pointer.X509_NAME_ENTRY */
            	81, 0,
            1, 8, 1, /* 867: pointer.struct.buf_mem_st */
            	872, 0,
            0, 24, 1, /* 872: struct.buf_mem_st */
            	52, 8,
            1, 8, 1, /* 877: pointer.struct.X509_val_st */
            	882, 0,
            0, 16, 2, /* 882: struct.X509_val_st */
            	889, 0,
            	889, 8,
            1, 8, 1, /* 889: pointer.struct.asn1_string_st */
            	667, 0,
            1, 8, 1, /* 894: pointer.struct.X509_pubkey_st */
            	899, 0,
            0, 24, 3, /* 899: struct.X509_pubkey_st */
            	672, 0,
            	761, 8,
            	908, 16,
            1, 8, 1, /* 908: pointer.struct.evp_pkey_st */
            	913, 0,
            0, 56, 4, /* 913: struct.evp_pkey_st */
            	924, 16,
            	932, 24,
            	940, 32,
            	1266, 48,
            1, 8, 1, /* 924: pointer.struct.evp_pkey_asn1_method_st */
            	929, 0,
            0, 0, 0, /* 929: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 932: pointer.struct.engine_st */
            	937, 0,
            0, 0, 0, /* 937: struct.engine_st */
            0, 8, 5, /* 940: union.unknown */
            	52, 0,
            	953, 0,
            	1109, 0,
            	1190, 0,
            	1258, 0,
            1, 8, 1, /* 953: pointer.struct.rsa_st */
            	958, 0,
            0, 168, 17, /* 958: struct.rsa_st */
            	995, 16,
            	932, 24,
            	1050, 32,
            	1050, 40,
            	1050, 48,
            	1050, 56,
            	1050, 64,
            	1050, 72,
            	1050, 80,
            	1050, 88,
            	1060, 96,
            	1087, 120,
            	1087, 128,
            	1087, 136,
            	52, 144,
            	1101, 152,
            	1101, 160,
            1, 8, 1, /* 995: pointer.struct.rsa_meth_st */
            	1000, 0,
            0, 112, 13, /* 1000: struct.rsa_meth_st */
            	5, 0,
            	1029, 8,
            	1029, 16,
            	1029, 24,
            	1029, 32,
            	1032, 40,
            	1035, 48,
            	1038, 56,
            	1038, 64,
            	52, 80,
            	1041, 88,
            	1044, 96,
            	1047, 104,
            8884097, 8, 0, /* 1029: pointer.func */
            8884097, 8, 0, /* 1032: pointer.func */
            8884097, 8, 0, /* 1035: pointer.func */
            8884097, 8, 0, /* 1038: pointer.func */
            8884097, 8, 0, /* 1041: pointer.func */
            8884097, 8, 0, /* 1044: pointer.func */
            8884097, 8, 0, /* 1047: pointer.func */
            1, 8, 1, /* 1050: pointer.struct.bignum_st */
            	1055, 0,
            0, 24, 1, /* 1055: struct.bignum_st */
            	252, 0,
            0, 16, 1, /* 1060: struct.crypto_ex_data_st */
            	1065, 0,
            1, 8, 1, /* 1065: pointer.struct.stack_st_void */
            	1070, 0,
            0, 32, 1, /* 1070: struct.stack_st_void */
            	1075, 0,
            0, 32, 2, /* 1075: struct.stack_st */
            	1082, 8,
            	125, 24,
            1, 8, 1, /* 1082: pointer.pointer.char */
            	52, 0,
            1, 8, 1, /* 1087: pointer.struct.bn_mont_ctx_st */
            	1092, 0,
            0, 96, 3, /* 1092: struct.bn_mont_ctx_st */
            	1055, 8,
            	1055, 32,
            	1055, 56,
            1, 8, 1, /* 1101: pointer.struct.bn_blinding_st */
            	1106, 0,
            0, 0, 0, /* 1106: struct.bn_blinding_st */
            1, 8, 1, /* 1109: pointer.struct.dsa_st */
            	1114, 0,
            0, 136, 11, /* 1114: struct.dsa_st */
            	1050, 24,
            	1050, 32,
            	1050, 40,
            	1050, 48,
            	1050, 56,
            	1050, 64,
            	1050, 72,
            	1087, 88,
            	1060, 104,
            	1139, 120,
            	932, 128,
            1, 8, 1, /* 1139: pointer.struct.dsa_method */
            	1144, 0,
            0, 96, 11, /* 1144: struct.dsa_method */
            	5, 0,
            	1169, 8,
            	1172, 16,
            	1175, 24,
            	1178, 32,
            	1181, 40,
            	1184, 48,
            	1184, 56,
            	52, 72,
            	1187, 80,
            	1184, 88,
            8884097, 8, 0, /* 1169: pointer.func */
            8884097, 8, 0, /* 1172: pointer.func */
            8884097, 8, 0, /* 1175: pointer.func */
            8884097, 8, 0, /* 1178: pointer.func */
            8884097, 8, 0, /* 1181: pointer.func */
            8884097, 8, 0, /* 1184: pointer.func */
            8884097, 8, 0, /* 1187: pointer.func */
            1, 8, 1, /* 1190: pointer.struct.dh_st */
            	1195, 0,
            0, 144, 12, /* 1195: struct.dh_st */
            	1050, 8,
            	1050, 16,
            	1050, 32,
            	1050, 40,
            	1087, 56,
            	1050, 64,
            	1050, 72,
            	39, 80,
            	1050, 96,
            	1060, 112,
            	1222, 128,
            	932, 136,
            1, 8, 1, /* 1222: pointer.struct.dh_method */
            	1227, 0,
            0, 72, 8, /* 1227: struct.dh_method */
            	5, 0,
            	1246, 8,
            	1249, 16,
            	1252, 24,
            	1246, 32,
            	1246, 40,
            	52, 56,
            	1255, 64,
            8884097, 8, 0, /* 1246: pointer.func */
            8884097, 8, 0, /* 1249: pointer.func */
            8884097, 8, 0, /* 1252: pointer.func */
            8884097, 8, 0, /* 1255: pointer.func */
            1, 8, 1, /* 1258: pointer.struct.ec_key_st */
            	1263, 0,
            0, 0, 0, /* 1263: struct.ec_key_st */
            1, 8, 1, /* 1266: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1271, 0,
            0, 32, 2, /* 1271: struct.stack_st_fake_X509_ATTRIBUTE */
            	1278, 8,
            	125, 24,
            8884099, 8, 2, /* 1278: pointer_to_array_of_pointers_to_stack */
            	1285, 0,
            	122, 20,
            0, 8, 1, /* 1285: pointer.X509_ATTRIBUTE */
            	1290, 0,
            0, 0, 1, /* 1290: X509_ATTRIBUTE */
            	1295, 0,
            0, 24, 2, /* 1295: struct.x509_attributes_st */
            	1302, 0,
            	1316, 16,
            1, 8, 1, /* 1302: pointer.struct.asn1_object_st */
            	1307, 0,
            0, 40, 3, /* 1307: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	107, 24,
            0, 8, 3, /* 1316: union.unknown */
            	52, 0,
            	1325, 0,
            	1504, 0,
            1, 8, 1, /* 1325: pointer.struct.stack_st_ASN1_TYPE */
            	1330, 0,
            0, 32, 2, /* 1330: struct.stack_st_fake_ASN1_TYPE */
            	1337, 8,
            	125, 24,
            8884099, 8, 2, /* 1337: pointer_to_array_of_pointers_to_stack */
            	1344, 0,
            	122, 20,
            0, 8, 1, /* 1344: pointer.ASN1_TYPE */
            	1349, 0,
            0, 0, 1, /* 1349: ASN1_TYPE */
            	1354, 0,
            0, 16, 1, /* 1354: struct.asn1_type_st */
            	1359, 8,
            0, 8, 20, /* 1359: union.unknown */
            	52, 0,
            	1402, 0,
            	1412, 0,
            	1426, 0,
            	1431, 0,
            	1436, 0,
            	1441, 0,
            	1446, 0,
            	1451, 0,
            	1456, 0,
            	1461, 0,
            	1466, 0,
            	1471, 0,
            	1476, 0,
            	1481, 0,
            	1486, 0,
            	1491, 0,
            	1402, 0,
            	1402, 0,
            	1496, 0,
            1, 8, 1, /* 1402: pointer.struct.asn1_string_st */
            	1407, 0,
            0, 24, 1, /* 1407: struct.asn1_string_st */
            	39, 8,
            1, 8, 1, /* 1412: pointer.struct.asn1_object_st */
            	1417, 0,
            0, 40, 3, /* 1417: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	107, 24,
            1, 8, 1, /* 1426: pointer.struct.asn1_string_st */
            	1407, 0,
            1, 8, 1, /* 1431: pointer.struct.asn1_string_st */
            	1407, 0,
            1, 8, 1, /* 1436: pointer.struct.asn1_string_st */
            	1407, 0,
            1, 8, 1, /* 1441: pointer.struct.asn1_string_st */
            	1407, 0,
            1, 8, 1, /* 1446: pointer.struct.asn1_string_st */
            	1407, 0,
            1, 8, 1, /* 1451: pointer.struct.asn1_string_st */
            	1407, 0,
            1, 8, 1, /* 1456: pointer.struct.asn1_string_st */
            	1407, 0,
            1, 8, 1, /* 1461: pointer.struct.asn1_string_st */
            	1407, 0,
            1, 8, 1, /* 1466: pointer.struct.asn1_string_st */
            	1407, 0,
            1, 8, 1, /* 1471: pointer.struct.asn1_string_st */
            	1407, 0,
            1, 8, 1, /* 1476: pointer.struct.asn1_string_st */
            	1407, 0,
            1, 8, 1, /* 1481: pointer.struct.asn1_string_st */
            	1407, 0,
            1, 8, 1, /* 1486: pointer.struct.asn1_string_st */
            	1407, 0,
            1, 8, 1, /* 1491: pointer.struct.asn1_string_st */
            	1407, 0,
            1, 8, 1, /* 1496: pointer.struct.ASN1_VALUE_st */
            	1501, 0,
            0, 0, 0, /* 1501: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1504: pointer.struct.asn1_type_st */
            	1509, 0,
            0, 16, 1, /* 1509: struct.asn1_type_st */
            	1514, 8,
            0, 8, 20, /* 1514: union.unknown */
            	52, 0,
            	1557, 0,
            	1302, 0,
            	1567, 0,
            	1572, 0,
            	1577, 0,
            	1582, 0,
            	1587, 0,
            	1592, 0,
            	1597, 0,
            	1602, 0,
            	1607, 0,
            	1612, 0,
            	1617, 0,
            	1622, 0,
            	1627, 0,
            	1632, 0,
            	1557, 0,
            	1557, 0,
            	821, 0,
            1, 8, 1, /* 1557: pointer.struct.asn1_string_st */
            	1562, 0,
            0, 24, 1, /* 1562: struct.asn1_string_st */
            	39, 8,
            1, 8, 1, /* 1567: pointer.struct.asn1_string_st */
            	1562, 0,
            1, 8, 1, /* 1572: pointer.struct.asn1_string_st */
            	1562, 0,
            1, 8, 1, /* 1577: pointer.struct.asn1_string_st */
            	1562, 0,
            1, 8, 1, /* 1582: pointer.struct.asn1_string_st */
            	1562, 0,
            1, 8, 1, /* 1587: pointer.struct.asn1_string_st */
            	1562, 0,
            1, 8, 1, /* 1592: pointer.struct.asn1_string_st */
            	1562, 0,
            1, 8, 1, /* 1597: pointer.struct.asn1_string_st */
            	1562, 0,
            1, 8, 1, /* 1602: pointer.struct.asn1_string_st */
            	1562, 0,
            1, 8, 1, /* 1607: pointer.struct.asn1_string_st */
            	1562, 0,
            1, 8, 1, /* 1612: pointer.struct.asn1_string_st */
            	1562, 0,
            1, 8, 1, /* 1617: pointer.struct.asn1_string_st */
            	1562, 0,
            1, 8, 1, /* 1622: pointer.struct.asn1_string_st */
            	1562, 0,
            1, 8, 1, /* 1627: pointer.struct.asn1_string_st */
            	1562, 0,
            1, 8, 1, /* 1632: pointer.struct.asn1_string_st */
            	1562, 0,
            1, 8, 1, /* 1637: pointer.struct.stack_st_X509_EXTENSION */
            	1642, 0,
            0, 32, 2, /* 1642: struct.stack_st_fake_X509_EXTENSION */
            	1649, 8,
            	125, 24,
            8884099, 8, 2, /* 1649: pointer_to_array_of_pointers_to_stack */
            	1656, 0,
            	122, 20,
            0, 8, 1, /* 1656: pointer.X509_EXTENSION */
            	1661, 0,
            0, 0, 1, /* 1661: X509_EXTENSION */
            	1666, 0,
            0, 24, 2, /* 1666: struct.X509_extension_st */
            	1673, 0,
            	1687, 16,
            1, 8, 1, /* 1673: pointer.struct.asn1_object_st */
            	1678, 0,
            0, 40, 3, /* 1678: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	107, 24,
            1, 8, 1, /* 1687: pointer.struct.asn1_string_st */
            	1692, 0,
            0, 24, 1, /* 1692: struct.asn1_string_st */
            	39, 8,
            0, 24, 1, /* 1697: struct.ASN1_ENCODING_st */
            	39, 0,
            1, 8, 1, /* 1702: pointer.struct.AUTHORITY_KEYID_st */
            	1707, 0,
            0, 0, 0, /* 1707: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 1710: pointer.struct.X509_POLICY_CACHE_st */
            	1715, 0,
            0, 0, 0, /* 1715: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1718: pointer.struct.stack_st_DIST_POINT */
            	1723, 0,
            0, 32, 2, /* 1723: struct.stack_st_fake_DIST_POINT */
            	1730, 8,
            	125, 24,
            8884099, 8, 2, /* 1730: pointer_to_array_of_pointers_to_stack */
            	1737, 0,
            	122, 20,
            0, 8, 1, /* 1737: pointer.DIST_POINT */
            	1742, 0,
            0, 0, 1, /* 1742: DIST_POINT */
            	1747, 0,
            0, 32, 3, /* 1747: struct.DIST_POINT_st */
            	1756, 0,
            	2117, 8,
            	1775, 16,
            1, 8, 1, /* 1756: pointer.struct.DIST_POINT_NAME_st */
            	1761, 0,
            0, 24, 2, /* 1761: struct.DIST_POINT_NAME_st */
            	1768, 8,
            	2093, 16,
            0, 8, 2, /* 1768: union.unknown */
            	1775, 0,
            	2069, 0,
            1, 8, 1, /* 1775: pointer.struct.stack_st_GENERAL_NAME */
            	1780, 0,
            0, 32, 2, /* 1780: struct.stack_st_fake_GENERAL_NAME */
            	1787, 8,
            	125, 24,
            8884099, 8, 2, /* 1787: pointer_to_array_of_pointers_to_stack */
            	1794, 0,
            	122, 20,
            0, 8, 1, /* 1794: pointer.GENERAL_NAME */
            	1799, 0,
            0, 0, 1, /* 1799: GENERAL_NAME */
            	1804, 0,
            0, 16, 1, /* 1804: struct.GENERAL_NAME_st */
            	1809, 8,
            0, 8, 15, /* 1809: union.unknown */
            	52, 0,
            	1842, 0,
            	1961, 0,
            	1961, 0,
            	1868, 0,
            	2009, 0,
            	2057, 0,
            	1961, 0,
            	1946, 0,
            	1854, 0,
            	1946, 0,
            	2009, 0,
            	1961, 0,
            	1854, 0,
            	1868, 0,
            1, 8, 1, /* 1842: pointer.struct.otherName_st */
            	1847, 0,
            0, 16, 2, /* 1847: struct.otherName_st */
            	1854, 0,
            	1868, 8,
            1, 8, 1, /* 1854: pointer.struct.asn1_object_st */
            	1859, 0,
            0, 40, 3, /* 1859: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	107, 24,
            1, 8, 1, /* 1868: pointer.struct.asn1_type_st */
            	1873, 0,
            0, 16, 1, /* 1873: struct.asn1_type_st */
            	1878, 8,
            0, 8, 20, /* 1878: union.unknown */
            	52, 0,
            	1921, 0,
            	1854, 0,
            	1931, 0,
            	1936, 0,
            	1941, 0,
            	1946, 0,
            	1951, 0,
            	1956, 0,
            	1961, 0,
            	1966, 0,
            	1971, 0,
            	1976, 0,
            	1981, 0,
            	1986, 0,
            	1991, 0,
            	1996, 0,
            	1921, 0,
            	1921, 0,
            	2001, 0,
            1, 8, 1, /* 1921: pointer.struct.asn1_string_st */
            	1926, 0,
            0, 24, 1, /* 1926: struct.asn1_string_st */
            	39, 8,
            1, 8, 1, /* 1931: pointer.struct.asn1_string_st */
            	1926, 0,
            1, 8, 1, /* 1936: pointer.struct.asn1_string_st */
            	1926, 0,
            1, 8, 1, /* 1941: pointer.struct.asn1_string_st */
            	1926, 0,
            1, 8, 1, /* 1946: pointer.struct.asn1_string_st */
            	1926, 0,
            1, 8, 1, /* 1951: pointer.struct.asn1_string_st */
            	1926, 0,
            1, 8, 1, /* 1956: pointer.struct.asn1_string_st */
            	1926, 0,
            1, 8, 1, /* 1961: pointer.struct.asn1_string_st */
            	1926, 0,
            1, 8, 1, /* 1966: pointer.struct.asn1_string_st */
            	1926, 0,
            1, 8, 1, /* 1971: pointer.struct.asn1_string_st */
            	1926, 0,
            1, 8, 1, /* 1976: pointer.struct.asn1_string_st */
            	1926, 0,
            1, 8, 1, /* 1981: pointer.struct.asn1_string_st */
            	1926, 0,
            1, 8, 1, /* 1986: pointer.struct.asn1_string_st */
            	1926, 0,
            1, 8, 1, /* 1991: pointer.struct.asn1_string_st */
            	1926, 0,
            1, 8, 1, /* 1996: pointer.struct.asn1_string_st */
            	1926, 0,
            1, 8, 1, /* 2001: pointer.struct.ASN1_VALUE_st */
            	2006, 0,
            0, 0, 0, /* 2006: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2009: pointer.struct.X509_name_st */
            	2014, 0,
            0, 40, 3, /* 2014: struct.X509_name_st */
            	2023, 0,
            	2047, 16,
            	39, 24,
            1, 8, 1, /* 2023: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2028, 0,
            0, 32, 2, /* 2028: struct.stack_st_fake_X509_NAME_ENTRY */
            	2035, 8,
            	125, 24,
            8884099, 8, 2, /* 2035: pointer_to_array_of_pointers_to_stack */
            	2042, 0,
            	122, 20,
            0, 8, 1, /* 2042: pointer.X509_NAME_ENTRY */
            	81, 0,
            1, 8, 1, /* 2047: pointer.struct.buf_mem_st */
            	2052, 0,
            0, 24, 1, /* 2052: struct.buf_mem_st */
            	52, 8,
            1, 8, 1, /* 2057: pointer.struct.EDIPartyName_st */
            	2062, 0,
            0, 16, 2, /* 2062: struct.EDIPartyName_st */
            	1921, 0,
            	1921, 8,
            1, 8, 1, /* 2069: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2074, 0,
            0, 32, 2, /* 2074: struct.stack_st_fake_X509_NAME_ENTRY */
            	2081, 8,
            	125, 24,
            8884099, 8, 2, /* 2081: pointer_to_array_of_pointers_to_stack */
            	2088, 0,
            	122, 20,
            0, 8, 1, /* 2088: pointer.X509_NAME_ENTRY */
            	81, 0,
            1, 8, 1, /* 2093: pointer.struct.X509_name_st */
            	2098, 0,
            0, 40, 3, /* 2098: struct.X509_name_st */
            	2069, 0,
            	2107, 16,
            	39, 24,
            1, 8, 1, /* 2107: pointer.struct.buf_mem_st */
            	2112, 0,
            0, 24, 1, /* 2112: struct.buf_mem_st */
            	52, 8,
            1, 8, 1, /* 2117: pointer.struct.asn1_string_st */
            	2122, 0,
            0, 24, 1, /* 2122: struct.asn1_string_st */
            	39, 8,
            1, 8, 1, /* 2127: pointer.struct.stack_st_GENERAL_NAME */
            	2132, 0,
            0, 32, 2, /* 2132: struct.stack_st_fake_GENERAL_NAME */
            	2139, 8,
            	125, 24,
            8884099, 8, 2, /* 2139: pointer_to_array_of_pointers_to_stack */
            	2146, 0,
            	122, 20,
            0, 8, 1, /* 2146: pointer.GENERAL_NAME */
            	1799, 0,
            1, 8, 1, /* 2151: pointer.struct.NAME_CONSTRAINTS_st */
            	2156, 0,
            0, 0, 0, /* 2156: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 2159: pointer.struct.x509_cert_aux_st */
            	2164, 0,
            0, 40, 5, /* 2164: struct.x509_cert_aux_st */
            	2177, 0,
            	2177, 8,
            	816, 16,
            	766, 24,
            	2215, 32,
            1, 8, 1, /* 2177: pointer.struct.stack_st_ASN1_OBJECT */
            	2182, 0,
            0, 32, 2, /* 2182: struct.stack_st_fake_ASN1_OBJECT */
            	2189, 8,
            	125, 24,
            8884099, 8, 2, /* 2189: pointer_to_array_of_pointers_to_stack */
            	2196, 0,
            	122, 20,
            0, 8, 1, /* 2196: pointer.ASN1_OBJECT */
            	2201, 0,
            0, 0, 1, /* 2201: ASN1_OBJECT */
            	2206, 0,
            0, 40, 3, /* 2206: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	107, 24,
            1, 8, 1, /* 2215: pointer.struct.stack_st_X509_ALGOR */
            	2220, 0,
            0, 32, 2, /* 2220: struct.stack_st_fake_X509_ALGOR */
            	2227, 8,
            	125, 24,
            8884099, 8, 2, /* 2227: pointer_to_array_of_pointers_to_stack */
            	2234, 0,
            	122, 20,
            0, 8, 1, /* 2234: pointer.X509_ALGOR */
            	2239, 0,
            0, 0, 1, /* 2239: X509_ALGOR */
            	2244, 0,
            0, 16, 2, /* 2244: struct.X509_algor_st */
            	1412, 0,
            	2251, 8,
            1, 8, 1, /* 2251: pointer.struct.asn1_type_st */
            	1354, 0,
            1, 8, 1, /* 2256: pointer.struct.X509_crl_st */
            	2261, 0,
            0, 120, 10, /* 2261: struct.X509_crl_st */
            	2284, 0,
            	672, 8,
            	761, 16,
            	1702, 32,
            	2411, 40,
            	662, 56,
            	662, 64,
            	2419, 96,
            	2460, 104,
            	26, 112,
            1, 8, 1, /* 2284: pointer.struct.X509_crl_info_st */
            	2289, 0,
            0, 80, 8, /* 2289: struct.X509_crl_info_st */
            	662, 0,
            	672, 8,
            	829, 16,
            	889, 24,
            	889, 32,
            	2308, 40,
            	1637, 48,
            	1697, 56,
            1, 8, 1, /* 2308: pointer.struct.stack_st_X509_REVOKED */
            	2313, 0,
            0, 32, 2, /* 2313: struct.stack_st_fake_X509_REVOKED */
            	2320, 8,
            	125, 24,
            8884099, 8, 2, /* 2320: pointer_to_array_of_pointers_to_stack */
            	2327, 0,
            	122, 20,
            0, 8, 1, /* 2327: pointer.X509_REVOKED */
            	2332, 0,
            0, 0, 1, /* 2332: X509_REVOKED */
            	2337, 0,
            0, 40, 4, /* 2337: struct.x509_revoked_st */
            	2348, 0,
            	2358, 8,
            	2363, 16,
            	2387, 24,
            1, 8, 1, /* 2348: pointer.struct.asn1_string_st */
            	2353, 0,
            0, 24, 1, /* 2353: struct.asn1_string_st */
            	39, 8,
            1, 8, 1, /* 2358: pointer.struct.asn1_string_st */
            	2353, 0,
            1, 8, 1, /* 2363: pointer.struct.stack_st_X509_EXTENSION */
            	2368, 0,
            0, 32, 2, /* 2368: struct.stack_st_fake_X509_EXTENSION */
            	2375, 8,
            	125, 24,
            8884099, 8, 2, /* 2375: pointer_to_array_of_pointers_to_stack */
            	2382, 0,
            	122, 20,
            0, 8, 1, /* 2382: pointer.X509_EXTENSION */
            	1661, 0,
            1, 8, 1, /* 2387: pointer.struct.stack_st_GENERAL_NAME */
            	2392, 0,
            0, 32, 2, /* 2392: struct.stack_st_fake_GENERAL_NAME */
            	2399, 8,
            	125, 24,
            8884099, 8, 2, /* 2399: pointer_to_array_of_pointers_to_stack */
            	2406, 0,
            	122, 20,
            0, 8, 1, /* 2406: pointer.GENERAL_NAME */
            	1799, 0,
            1, 8, 1, /* 2411: pointer.struct.ISSUING_DIST_POINT_st */
            	2416, 0,
            0, 0, 0, /* 2416: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 2419: pointer.struct.stack_st_GENERAL_NAMES */
            	2424, 0,
            0, 32, 2, /* 2424: struct.stack_st_fake_GENERAL_NAMES */
            	2431, 8,
            	125, 24,
            8884099, 8, 2, /* 2431: pointer_to_array_of_pointers_to_stack */
            	2438, 0,
            	122, 20,
            0, 8, 1, /* 2438: pointer.GENERAL_NAMES */
            	2443, 0,
            0, 0, 1, /* 2443: GENERAL_NAMES */
            	2448, 0,
            0, 32, 1, /* 2448: struct.stack_st_GENERAL_NAME */
            	2453, 0,
            0, 32, 2, /* 2453: struct.stack_st */
            	1082, 8,
            	125, 24,
            1, 8, 1, /* 2460: pointer.struct.x509_crl_method_st */
            	2465, 0,
            0, 0, 0, /* 2465: struct.x509_crl_method_st */
            1, 8, 1, /* 2468: pointer.struct.X509_VERIFY_PARAM_st */
            	2473, 0,
            0, 56, 2, /* 2473: struct.X509_VERIFY_PARAM_st */
            	52, 0,
            	2177, 48,
            8884097, 8, 0, /* 2480: pointer.func */
            8884097, 8, 0, /* 2483: pointer.func */
            1, 8, 1, /* 2486: pointer.struct.stack_st_X509_LOOKUP */
            	2491, 0,
            0, 32, 2, /* 2491: struct.stack_st_fake_X509_LOOKUP */
            	2498, 8,
            	125, 24,
            8884099, 8, 2, /* 2498: pointer_to_array_of_pointers_to_stack */
            	2505, 0,
            	122, 20,
            0, 8, 1, /* 2505: pointer.X509_LOOKUP */
            	454, 0,
            1, 8, 1, /* 2510: pointer.struct.ssl3_buf_freelist_st */
            	2515, 0,
            0, 24, 1, /* 2515: struct.ssl3_buf_freelist_st */
            	265, 16,
            1, 8, 1, /* 2520: pointer.struct.X509_algor_st */
            	2525, 0,
            0, 16, 2, /* 2525: struct.X509_algor_st */
            	2532, 0,
            	2546, 8,
            1, 8, 1, /* 2532: pointer.struct.asn1_object_st */
            	2537, 0,
            0, 40, 3, /* 2537: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	107, 24,
            1, 8, 1, /* 2546: pointer.struct.asn1_type_st */
            	2551, 0,
            0, 16, 1, /* 2551: struct.asn1_type_st */
            	2556, 8,
            0, 8, 20, /* 2556: union.unknown */
            	52, 0,
            	2599, 0,
            	2532, 0,
            	2609, 0,
            	2614, 0,
            	2619, 0,
            	2624, 0,
            	2629, 0,
            	2634, 0,
            	2639, 0,
            	2644, 0,
            	2649, 0,
            	2654, 0,
            	2659, 0,
            	2664, 0,
            	2669, 0,
            	2674, 0,
            	2599, 0,
            	2599, 0,
            	2679, 0,
            1, 8, 1, /* 2599: pointer.struct.asn1_string_st */
            	2604, 0,
            0, 24, 1, /* 2604: struct.asn1_string_st */
            	39, 8,
            1, 8, 1, /* 2609: pointer.struct.asn1_string_st */
            	2604, 0,
            1, 8, 1, /* 2614: pointer.struct.asn1_string_st */
            	2604, 0,
            1, 8, 1, /* 2619: pointer.struct.asn1_string_st */
            	2604, 0,
            1, 8, 1, /* 2624: pointer.struct.asn1_string_st */
            	2604, 0,
            1, 8, 1, /* 2629: pointer.struct.asn1_string_st */
            	2604, 0,
            1, 8, 1, /* 2634: pointer.struct.asn1_string_st */
            	2604, 0,
            1, 8, 1, /* 2639: pointer.struct.asn1_string_st */
            	2604, 0,
            1, 8, 1, /* 2644: pointer.struct.asn1_string_st */
            	2604, 0,
            1, 8, 1, /* 2649: pointer.struct.asn1_string_st */
            	2604, 0,
            1, 8, 1, /* 2654: pointer.struct.asn1_string_st */
            	2604, 0,
            1, 8, 1, /* 2659: pointer.struct.asn1_string_st */
            	2604, 0,
            1, 8, 1, /* 2664: pointer.struct.asn1_string_st */
            	2604, 0,
            1, 8, 1, /* 2669: pointer.struct.asn1_string_st */
            	2604, 0,
            1, 8, 1, /* 2674: pointer.struct.asn1_string_st */
            	2604, 0,
            1, 8, 1, /* 2679: pointer.struct.ASN1_VALUE_st */
            	2684, 0,
            0, 0, 0, /* 2684: struct.ASN1_VALUE_st */
            8884097, 8, 0, /* 2687: pointer.func */
            8884097, 8, 0, /* 2690: pointer.func */
            8884097, 8, 0, /* 2693: pointer.func */
            0, 0, 0, /* 2696: struct.ec_key_st */
            1, 8, 1, /* 2699: pointer.struct.ec_key_st */
            	2696, 0,
            8884097, 8, 0, /* 2704: pointer.func */
            8884097, 8, 0, /* 2707: pointer.func */
            8884097, 8, 0, /* 2710: pointer.func */
            0, 72, 8, /* 2713: struct.dh_method */
            	5, 0,
            	2710, 8,
            	2732, 16,
            	2704, 24,
            	2710, 32,
            	2710, 40,
            	52, 56,
            	2735, 64,
            8884097, 8, 0, /* 2732: pointer.func */
            8884097, 8, 0, /* 2735: pointer.func */
            1, 8, 1, /* 2738: pointer.struct.stack_st_GENERAL_NAME */
            	2743, 0,
            0, 32, 2, /* 2743: struct.stack_st_fake_GENERAL_NAME */
            	2750, 8,
            	125, 24,
            8884099, 8, 2, /* 2750: pointer_to_array_of_pointers_to_stack */
            	2757, 0,
            	122, 20,
            0, 8, 1, /* 2757: pointer.GENERAL_NAME */
            	1799, 0,
            8884097, 8, 0, /* 2762: pointer.func */
            8884097, 8, 0, /* 2765: pointer.func */
            0, 248, 5, /* 2768: struct.sess_cert_st */
            	2781, 0,
            	3612, 16,
            	4322, 216,
            	4327, 224,
            	4332, 232,
            1, 8, 1, /* 2781: pointer.struct.stack_st_X509 */
            	2786, 0,
            0, 32, 2, /* 2786: struct.stack_st_fake_X509 */
            	2793, 8,
            	125, 24,
            8884099, 8, 2, /* 2793: pointer_to_array_of_pointers_to_stack */
            	2800, 0,
            	122, 20,
            0, 8, 1, /* 2800: pointer.X509 */
            	2805, 0,
            0, 0, 1, /* 2805: X509 */
            	2810, 0,
            0, 184, 12, /* 2810: struct.x509_st */
            	2837, 0,
            	2877, 8,
            	2966, 16,
            	52, 32,
            	3265, 40,
            	2971, 104,
            	3474, 112,
            	3482, 120,
            	3490, 128,
            	3514, 136,
            	3538, 144,
            	3546, 176,
            1, 8, 1, /* 2837: pointer.struct.x509_cinf_st */
            	2842, 0,
            0, 104, 11, /* 2842: struct.x509_cinf_st */
            	2867, 0,
            	2867, 8,
            	2877, 16,
            	3034, 24,
            	3082, 32,
            	3034, 40,
            	3099, 48,
            	2966, 56,
            	2966, 64,
            	3445, 72,
            	3469, 80,
            1, 8, 1, /* 2867: pointer.struct.asn1_string_st */
            	2872, 0,
            0, 24, 1, /* 2872: struct.asn1_string_st */
            	39, 8,
            1, 8, 1, /* 2877: pointer.struct.X509_algor_st */
            	2882, 0,
            0, 16, 2, /* 2882: struct.X509_algor_st */
            	2889, 0,
            	2903, 8,
            1, 8, 1, /* 2889: pointer.struct.asn1_object_st */
            	2894, 0,
            0, 40, 3, /* 2894: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	107, 24,
            1, 8, 1, /* 2903: pointer.struct.asn1_type_st */
            	2908, 0,
            0, 16, 1, /* 2908: struct.asn1_type_st */
            	2913, 8,
            0, 8, 20, /* 2913: union.unknown */
            	52, 0,
            	2956, 0,
            	2889, 0,
            	2867, 0,
            	2961, 0,
            	2966, 0,
            	2971, 0,
            	2976, 0,
            	2981, 0,
            	2986, 0,
            	2991, 0,
            	2996, 0,
            	3001, 0,
            	3006, 0,
            	3011, 0,
            	3016, 0,
            	3021, 0,
            	2956, 0,
            	2956, 0,
            	3026, 0,
            1, 8, 1, /* 2956: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 2961: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 2966: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 2971: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 2976: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 2981: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 2986: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 2991: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 2996: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 3001: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 3006: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 3011: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 3016: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 3021: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 3026: pointer.struct.ASN1_VALUE_st */
            	3031, 0,
            0, 0, 0, /* 3031: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3034: pointer.struct.X509_name_st */
            	3039, 0,
            0, 40, 3, /* 3039: struct.X509_name_st */
            	3048, 0,
            	3072, 16,
            	39, 24,
            1, 8, 1, /* 3048: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3053, 0,
            0, 32, 2, /* 3053: struct.stack_st_fake_X509_NAME_ENTRY */
            	3060, 8,
            	125, 24,
            8884099, 8, 2, /* 3060: pointer_to_array_of_pointers_to_stack */
            	3067, 0,
            	122, 20,
            0, 8, 1, /* 3067: pointer.X509_NAME_ENTRY */
            	81, 0,
            1, 8, 1, /* 3072: pointer.struct.buf_mem_st */
            	3077, 0,
            0, 24, 1, /* 3077: struct.buf_mem_st */
            	52, 8,
            1, 8, 1, /* 3082: pointer.struct.X509_val_st */
            	3087, 0,
            0, 16, 2, /* 3087: struct.X509_val_st */
            	3094, 0,
            	3094, 8,
            1, 8, 1, /* 3094: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 3099: pointer.struct.X509_pubkey_st */
            	3104, 0,
            0, 24, 3, /* 3104: struct.X509_pubkey_st */
            	2877, 0,
            	2966, 8,
            	3113, 16,
            1, 8, 1, /* 3113: pointer.struct.evp_pkey_st */
            	3118, 0,
            0, 56, 4, /* 3118: struct.evp_pkey_st */
            	3129, 16,
            	3137, 24,
            	3145, 32,
            	3421, 48,
            1, 8, 1, /* 3129: pointer.struct.evp_pkey_asn1_method_st */
            	3134, 0,
            0, 0, 0, /* 3134: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 3137: pointer.struct.engine_st */
            	3142, 0,
            0, 0, 0, /* 3142: struct.engine_st */
            0, 8, 5, /* 3145: union.unknown */
            	52, 0,
            	3158, 0,
            	3309, 0,
            	3384, 0,
            	2699, 0,
            1, 8, 1, /* 3158: pointer.struct.rsa_st */
            	3163, 0,
            0, 168, 17, /* 3163: struct.rsa_st */
            	3200, 16,
            	3137, 24,
            	3255, 32,
            	3255, 40,
            	3255, 48,
            	3255, 56,
            	3255, 64,
            	3255, 72,
            	3255, 80,
            	3255, 88,
            	3265, 96,
            	3287, 120,
            	3287, 128,
            	3287, 136,
            	52, 144,
            	3301, 152,
            	3301, 160,
            1, 8, 1, /* 3200: pointer.struct.rsa_meth_st */
            	3205, 0,
            0, 112, 13, /* 3205: struct.rsa_meth_st */
            	5, 0,
            	3234, 8,
            	3234, 16,
            	3234, 24,
            	3234, 32,
            	3237, 40,
            	3240, 48,
            	3243, 56,
            	3243, 64,
            	52, 80,
            	3246, 88,
            	3249, 96,
            	3252, 104,
            8884097, 8, 0, /* 3234: pointer.func */
            8884097, 8, 0, /* 3237: pointer.func */
            8884097, 8, 0, /* 3240: pointer.func */
            8884097, 8, 0, /* 3243: pointer.func */
            8884097, 8, 0, /* 3246: pointer.func */
            8884097, 8, 0, /* 3249: pointer.func */
            8884097, 8, 0, /* 3252: pointer.func */
            1, 8, 1, /* 3255: pointer.struct.bignum_st */
            	3260, 0,
            0, 24, 1, /* 3260: struct.bignum_st */
            	252, 0,
            0, 16, 1, /* 3265: struct.crypto_ex_data_st */
            	3270, 0,
            1, 8, 1, /* 3270: pointer.struct.stack_st_void */
            	3275, 0,
            0, 32, 1, /* 3275: struct.stack_st_void */
            	3280, 0,
            0, 32, 2, /* 3280: struct.stack_st */
            	1082, 8,
            	125, 24,
            1, 8, 1, /* 3287: pointer.struct.bn_mont_ctx_st */
            	3292, 0,
            0, 96, 3, /* 3292: struct.bn_mont_ctx_st */
            	3260, 8,
            	3260, 32,
            	3260, 56,
            1, 8, 1, /* 3301: pointer.struct.bn_blinding_st */
            	3306, 0,
            0, 0, 0, /* 3306: struct.bn_blinding_st */
            1, 8, 1, /* 3309: pointer.struct.dsa_st */
            	3314, 0,
            0, 136, 11, /* 3314: struct.dsa_st */
            	3255, 24,
            	3255, 32,
            	3255, 40,
            	3255, 48,
            	3255, 56,
            	3255, 64,
            	3255, 72,
            	3287, 88,
            	3265, 104,
            	3339, 120,
            	3137, 128,
            1, 8, 1, /* 3339: pointer.struct.dsa_method */
            	3344, 0,
            0, 96, 11, /* 3344: struct.dsa_method */
            	5, 0,
            	3369, 8,
            	2765, 16,
            	2762, 24,
            	3372, 32,
            	3375, 40,
            	3378, 48,
            	3378, 56,
            	52, 72,
            	3381, 80,
            	3378, 88,
            8884097, 8, 0, /* 3369: pointer.func */
            8884097, 8, 0, /* 3372: pointer.func */
            8884097, 8, 0, /* 3375: pointer.func */
            8884097, 8, 0, /* 3378: pointer.func */
            8884097, 8, 0, /* 3381: pointer.func */
            1, 8, 1, /* 3384: pointer.struct.dh_st */
            	3389, 0,
            0, 144, 12, /* 3389: struct.dh_st */
            	3255, 8,
            	3255, 16,
            	3255, 32,
            	3255, 40,
            	3287, 56,
            	3255, 64,
            	3255, 72,
            	39, 80,
            	3255, 96,
            	3265, 112,
            	3416, 128,
            	3137, 136,
            1, 8, 1, /* 3416: pointer.struct.dh_method */
            	2713, 0,
            1, 8, 1, /* 3421: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3426, 0,
            0, 32, 2, /* 3426: struct.stack_st_fake_X509_ATTRIBUTE */
            	3433, 8,
            	125, 24,
            8884099, 8, 2, /* 3433: pointer_to_array_of_pointers_to_stack */
            	3440, 0,
            	122, 20,
            0, 8, 1, /* 3440: pointer.X509_ATTRIBUTE */
            	1290, 0,
            1, 8, 1, /* 3445: pointer.struct.stack_st_X509_EXTENSION */
            	3450, 0,
            0, 32, 2, /* 3450: struct.stack_st_fake_X509_EXTENSION */
            	3457, 8,
            	125, 24,
            8884099, 8, 2, /* 3457: pointer_to_array_of_pointers_to_stack */
            	3464, 0,
            	122, 20,
            0, 8, 1, /* 3464: pointer.X509_EXTENSION */
            	1661, 0,
            0, 24, 1, /* 3469: struct.ASN1_ENCODING_st */
            	39, 0,
            1, 8, 1, /* 3474: pointer.struct.AUTHORITY_KEYID_st */
            	3479, 0,
            0, 0, 0, /* 3479: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 3482: pointer.struct.X509_POLICY_CACHE_st */
            	3487, 0,
            0, 0, 0, /* 3487: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 3490: pointer.struct.stack_st_DIST_POINT */
            	3495, 0,
            0, 32, 2, /* 3495: struct.stack_st_fake_DIST_POINT */
            	3502, 8,
            	125, 24,
            8884099, 8, 2, /* 3502: pointer_to_array_of_pointers_to_stack */
            	3509, 0,
            	122, 20,
            0, 8, 1, /* 3509: pointer.DIST_POINT */
            	1742, 0,
            1, 8, 1, /* 3514: pointer.struct.stack_st_GENERAL_NAME */
            	3519, 0,
            0, 32, 2, /* 3519: struct.stack_st_fake_GENERAL_NAME */
            	3526, 8,
            	125, 24,
            8884099, 8, 2, /* 3526: pointer_to_array_of_pointers_to_stack */
            	3533, 0,
            	122, 20,
            0, 8, 1, /* 3533: pointer.GENERAL_NAME */
            	1799, 0,
            1, 8, 1, /* 3538: pointer.struct.NAME_CONSTRAINTS_st */
            	3543, 0,
            0, 0, 0, /* 3543: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3546: pointer.struct.x509_cert_aux_st */
            	3551, 0,
            0, 40, 5, /* 3551: struct.x509_cert_aux_st */
            	3564, 0,
            	3564, 8,
            	3021, 16,
            	2971, 24,
            	3588, 32,
            1, 8, 1, /* 3564: pointer.struct.stack_st_ASN1_OBJECT */
            	3569, 0,
            0, 32, 2, /* 3569: struct.stack_st_fake_ASN1_OBJECT */
            	3576, 8,
            	125, 24,
            8884099, 8, 2, /* 3576: pointer_to_array_of_pointers_to_stack */
            	3583, 0,
            	122, 20,
            0, 8, 1, /* 3583: pointer.ASN1_OBJECT */
            	2201, 0,
            1, 8, 1, /* 3588: pointer.struct.stack_st_X509_ALGOR */
            	3593, 0,
            0, 32, 2, /* 3593: struct.stack_st_fake_X509_ALGOR */
            	3600, 8,
            	125, 24,
            8884099, 8, 2, /* 3600: pointer_to_array_of_pointers_to_stack */
            	3607, 0,
            	122, 20,
            0, 8, 1, /* 3607: pointer.X509_ALGOR */
            	2239, 0,
            1, 8, 1, /* 3612: pointer.struct.cert_pkey_st */
            	3617, 0,
            0, 24, 3, /* 3617: struct.cert_pkey_st */
            	3626, 0,
            	3767, 8,
            	4277, 16,
            1, 8, 1, /* 3626: pointer.struct.x509_st */
            	3631, 0,
            0, 184, 12, /* 3631: struct.x509_st */
            	3658, 0,
            	2520, 8,
            	2619, 16,
            	52, 32,
            	3909, 40,
            	2624, 104,
            	4163, 112,
            	4171, 120,
            	4179, 128,
            	2738, 136,
            	4203, 144,
            	4211, 176,
            1, 8, 1, /* 3658: pointer.struct.x509_cinf_st */
            	3663, 0,
            0, 104, 11, /* 3663: struct.x509_cinf_st */
            	2609, 0,
            	2609, 8,
            	2520, 16,
            	3688, 24,
            	3736, 32,
            	3688, 40,
            	3753, 48,
            	2619, 56,
            	2619, 64,
            	4134, 72,
            	4158, 80,
            1, 8, 1, /* 3688: pointer.struct.X509_name_st */
            	3693, 0,
            0, 40, 3, /* 3693: struct.X509_name_st */
            	3702, 0,
            	3726, 16,
            	39, 24,
            1, 8, 1, /* 3702: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3707, 0,
            0, 32, 2, /* 3707: struct.stack_st_fake_X509_NAME_ENTRY */
            	3714, 8,
            	125, 24,
            8884099, 8, 2, /* 3714: pointer_to_array_of_pointers_to_stack */
            	3721, 0,
            	122, 20,
            0, 8, 1, /* 3721: pointer.X509_NAME_ENTRY */
            	81, 0,
            1, 8, 1, /* 3726: pointer.struct.buf_mem_st */
            	3731, 0,
            0, 24, 1, /* 3731: struct.buf_mem_st */
            	52, 8,
            1, 8, 1, /* 3736: pointer.struct.X509_val_st */
            	3741, 0,
            0, 16, 2, /* 3741: struct.X509_val_st */
            	3748, 0,
            	3748, 8,
            1, 8, 1, /* 3748: pointer.struct.asn1_string_st */
            	2604, 0,
            1, 8, 1, /* 3753: pointer.struct.X509_pubkey_st */
            	3758, 0,
            0, 24, 3, /* 3758: struct.X509_pubkey_st */
            	2520, 0,
            	2619, 8,
            	3767, 16,
            1, 8, 1, /* 3767: pointer.struct.evp_pkey_st */
            	3772, 0,
            0, 56, 4, /* 3772: struct.evp_pkey_st */
            	3783, 16,
            	3791, 24,
            	3799, 32,
            	4110, 48,
            1, 8, 1, /* 3783: pointer.struct.evp_pkey_asn1_method_st */
            	3788, 0,
            0, 0, 0, /* 3788: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 3791: pointer.struct.engine_st */
            	3796, 0,
            0, 0, 0, /* 3796: struct.engine_st */
            0, 8, 5, /* 3799: union.unknown */
            	52, 0,
            	3812, 0,
            	3953, 0,
            	4034, 0,
            	4102, 0,
            1, 8, 1, /* 3812: pointer.struct.rsa_st */
            	3817, 0,
            0, 168, 17, /* 3817: struct.rsa_st */
            	3854, 16,
            	3791, 24,
            	242, 32,
            	242, 40,
            	242, 48,
            	242, 56,
            	242, 64,
            	242, 72,
            	242, 80,
            	242, 88,
            	3909, 96,
            	3931, 120,
            	3931, 128,
            	3931, 136,
            	52, 144,
            	3945, 152,
            	3945, 160,
            1, 8, 1, /* 3854: pointer.struct.rsa_meth_st */
            	3859, 0,
            0, 112, 13, /* 3859: struct.rsa_meth_st */
            	5, 0,
            	3888, 8,
            	3888, 16,
            	3888, 24,
            	3888, 32,
            	3891, 40,
            	3894, 48,
            	3897, 56,
            	3897, 64,
            	52, 80,
            	3900, 88,
            	3903, 96,
            	3906, 104,
            8884097, 8, 0, /* 3888: pointer.func */
            8884097, 8, 0, /* 3891: pointer.func */
            8884097, 8, 0, /* 3894: pointer.func */
            8884097, 8, 0, /* 3897: pointer.func */
            8884097, 8, 0, /* 3900: pointer.func */
            8884097, 8, 0, /* 3903: pointer.func */
            8884097, 8, 0, /* 3906: pointer.func */
            0, 16, 1, /* 3909: struct.crypto_ex_data_st */
            	3914, 0,
            1, 8, 1, /* 3914: pointer.struct.stack_st_void */
            	3919, 0,
            0, 32, 1, /* 3919: struct.stack_st_void */
            	3924, 0,
            0, 32, 2, /* 3924: struct.stack_st */
            	1082, 8,
            	125, 24,
            1, 8, 1, /* 3931: pointer.struct.bn_mont_ctx_st */
            	3936, 0,
            0, 96, 3, /* 3936: struct.bn_mont_ctx_st */
            	247, 8,
            	247, 32,
            	247, 56,
            1, 8, 1, /* 3945: pointer.struct.bn_blinding_st */
            	3950, 0,
            0, 0, 0, /* 3950: struct.bn_blinding_st */
            1, 8, 1, /* 3953: pointer.struct.dsa_st */
            	3958, 0,
            0, 136, 11, /* 3958: struct.dsa_st */
            	242, 24,
            	242, 32,
            	242, 40,
            	242, 48,
            	242, 56,
            	242, 64,
            	242, 72,
            	3931, 88,
            	3909, 104,
            	3983, 120,
            	3791, 128,
            1, 8, 1, /* 3983: pointer.struct.dsa_method */
            	3988, 0,
            0, 96, 11, /* 3988: struct.dsa_method */
            	5, 0,
            	4013, 8,
            	4016, 16,
            	4019, 24,
            	4022, 32,
            	4025, 40,
            	4028, 48,
            	4028, 56,
            	52, 72,
            	4031, 80,
            	4028, 88,
            8884097, 8, 0, /* 4013: pointer.func */
            8884097, 8, 0, /* 4016: pointer.func */
            8884097, 8, 0, /* 4019: pointer.func */
            8884097, 8, 0, /* 4022: pointer.func */
            8884097, 8, 0, /* 4025: pointer.func */
            8884097, 8, 0, /* 4028: pointer.func */
            8884097, 8, 0, /* 4031: pointer.func */
            1, 8, 1, /* 4034: pointer.struct.dh_st */
            	4039, 0,
            0, 144, 12, /* 4039: struct.dh_st */
            	242, 8,
            	242, 16,
            	242, 32,
            	242, 40,
            	3931, 56,
            	242, 64,
            	242, 72,
            	39, 80,
            	242, 96,
            	3909, 112,
            	4066, 128,
            	3791, 136,
            1, 8, 1, /* 4066: pointer.struct.dh_method */
            	4071, 0,
            0, 72, 8, /* 4071: struct.dh_method */
            	5, 0,
            	4090, 8,
            	4093, 16,
            	4096, 24,
            	4090, 32,
            	4090, 40,
            	52, 56,
            	4099, 64,
            8884097, 8, 0, /* 4090: pointer.func */
            8884097, 8, 0, /* 4093: pointer.func */
            8884097, 8, 0, /* 4096: pointer.func */
            8884097, 8, 0, /* 4099: pointer.func */
            1, 8, 1, /* 4102: pointer.struct.ec_key_st */
            	4107, 0,
            0, 0, 0, /* 4107: struct.ec_key_st */
            1, 8, 1, /* 4110: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4115, 0,
            0, 32, 2, /* 4115: struct.stack_st_fake_X509_ATTRIBUTE */
            	4122, 8,
            	125, 24,
            8884099, 8, 2, /* 4122: pointer_to_array_of_pointers_to_stack */
            	4129, 0,
            	122, 20,
            0, 8, 1, /* 4129: pointer.X509_ATTRIBUTE */
            	1290, 0,
            1, 8, 1, /* 4134: pointer.struct.stack_st_X509_EXTENSION */
            	4139, 0,
            0, 32, 2, /* 4139: struct.stack_st_fake_X509_EXTENSION */
            	4146, 8,
            	125, 24,
            8884099, 8, 2, /* 4146: pointer_to_array_of_pointers_to_stack */
            	4153, 0,
            	122, 20,
            0, 8, 1, /* 4153: pointer.X509_EXTENSION */
            	1661, 0,
            0, 24, 1, /* 4158: struct.ASN1_ENCODING_st */
            	39, 0,
            1, 8, 1, /* 4163: pointer.struct.AUTHORITY_KEYID_st */
            	4168, 0,
            0, 0, 0, /* 4168: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4171: pointer.struct.X509_POLICY_CACHE_st */
            	4176, 0,
            0, 0, 0, /* 4176: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 4179: pointer.struct.stack_st_DIST_POINT */
            	4184, 0,
            0, 32, 2, /* 4184: struct.stack_st_fake_DIST_POINT */
            	4191, 8,
            	125, 24,
            8884099, 8, 2, /* 4191: pointer_to_array_of_pointers_to_stack */
            	4198, 0,
            	122, 20,
            0, 8, 1, /* 4198: pointer.DIST_POINT */
            	1742, 0,
            1, 8, 1, /* 4203: pointer.struct.NAME_CONSTRAINTS_st */
            	4208, 0,
            0, 0, 0, /* 4208: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4211: pointer.struct.x509_cert_aux_st */
            	4216, 0,
            0, 40, 5, /* 4216: struct.x509_cert_aux_st */
            	4229, 0,
            	4229, 8,
            	2674, 16,
            	2624, 24,
            	4253, 32,
            1, 8, 1, /* 4229: pointer.struct.stack_st_ASN1_OBJECT */
            	4234, 0,
            0, 32, 2, /* 4234: struct.stack_st_fake_ASN1_OBJECT */
            	4241, 8,
            	125, 24,
            8884099, 8, 2, /* 4241: pointer_to_array_of_pointers_to_stack */
            	4248, 0,
            	122, 20,
            0, 8, 1, /* 4248: pointer.ASN1_OBJECT */
            	2201, 0,
            1, 8, 1, /* 4253: pointer.struct.stack_st_X509_ALGOR */
            	4258, 0,
            0, 32, 2, /* 4258: struct.stack_st_fake_X509_ALGOR */
            	4265, 8,
            	125, 24,
            8884099, 8, 2, /* 4265: pointer_to_array_of_pointers_to_stack */
            	4272, 0,
            	122, 20,
            0, 8, 1, /* 4272: pointer.X509_ALGOR */
            	2239, 0,
            1, 8, 1, /* 4277: pointer.struct.env_md_st */
            	4282, 0,
            0, 120, 8, /* 4282: struct.env_md_st */
            	4301, 24,
            	4304, 32,
            	4307, 40,
            	4310, 48,
            	4301, 56,
            	4313, 64,
            	4316, 72,
            	4319, 112,
            8884097, 8, 0, /* 4301: pointer.func */
            8884097, 8, 0, /* 4304: pointer.func */
            8884097, 8, 0, /* 4307: pointer.func */
            8884097, 8, 0, /* 4310: pointer.func */
            8884097, 8, 0, /* 4313: pointer.func */
            8884097, 8, 0, /* 4316: pointer.func */
            8884097, 8, 0, /* 4319: pointer.func */
            1, 8, 1, /* 4322: pointer.struct.rsa_st */
            	3817, 0,
            1, 8, 1, /* 4327: pointer.struct.dh_st */
            	4039, 0,
            1, 8, 1, /* 4332: pointer.struct.ec_key_st */
            	4107, 0,
            1, 8, 1, /* 4337: pointer.struct.ssl3_enc_method */
            	4342, 0,
            0, 112, 11, /* 4342: struct.ssl3_enc_method */
            	4367, 0,
            	4370, 8,
            	4373, 16,
            	4376, 24,
            	4367, 32,
            	4379, 40,
            	4382, 56,
            	5, 64,
            	5, 80,
            	4385, 96,
            	2690, 104,
            8884097, 8, 0, /* 4367: pointer.func */
            8884097, 8, 0, /* 4370: pointer.func */
            8884097, 8, 0, /* 4373: pointer.func */
            8884097, 8, 0, /* 4376: pointer.func */
            8884097, 8, 0, /* 4379: pointer.func */
            8884097, 8, 0, /* 4382: pointer.func */
            8884097, 8, 0, /* 4385: pointer.func */
            8884097, 8, 0, /* 4388: pointer.func */
            0, 0, 1, /* 4391: OCSP_RESPID */
            	4396, 0,
            0, 16, 1, /* 4396: struct.ocsp_responder_id_st */
            	147, 8,
            1, 8, 1, /* 4401: pointer.struct.stack_st_X509_OBJECT */
            	4406, 0,
            0, 32, 2, /* 4406: struct.stack_st_fake_X509_OBJECT */
            	4413, 8,
            	125, 24,
            8884099, 8, 2, /* 4413: pointer_to_array_of_pointers_to_stack */
            	4420, 0,
            	122, 20,
            0, 8, 1, /* 4420: pointer.X509_OBJECT */
            	579, 0,
            8884097, 8, 0, /* 4425: pointer.func */
            1, 8, 1, /* 4428: pointer.struct.comp_ctx_st */
            	4433, 0,
            0, 56, 2, /* 4433: struct.comp_ctx_st */
            	4440, 0,
            	3909, 40,
            1, 8, 1, /* 4440: pointer.struct.comp_method_st */
            	4445, 0,
            0, 64, 7, /* 4445: struct.comp_method_st */
            	5, 8,
            	4462, 16,
            	4465, 24,
            	4468, 32,
            	4468, 40,
            	299, 48,
            	299, 56,
            8884097, 8, 0, /* 4462: pointer.func */
            8884097, 8, 0, /* 4465: pointer.func */
            8884097, 8, 0, /* 4468: pointer.func */
            1, 8, 1, /* 4471: pointer.struct.dtls1_state_st */
            	4476, 0,
            0, 888, 7, /* 4476: struct.dtls1_state_st */
            	4493, 576,
            	4493, 592,
            	4498, 608,
            	4498, 616,
            	4493, 624,
            	4506, 648,
            	4506, 736,
            0, 16, 1, /* 4493: struct.record_pqueue_st */
            	4498, 8,
            1, 8, 1, /* 4498: pointer.struct._pqueue */
            	4503, 0,
            0, 0, 0, /* 4503: struct._pqueue */
            0, 88, 1, /* 4506: struct.hm_header_st */
            	4511, 48,
            0, 40, 4, /* 4511: struct.dtls1_retransmit_state */
            	4522, 0,
            	4575, 8,
            	4428, 16,
            	4601, 24,
            1, 8, 1, /* 4522: pointer.struct.evp_cipher_ctx_st */
            	4527, 0,
            0, 168, 4, /* 4527: struct.evp_cipher_ctx_st */
            	4538, 0,
            	3791, 8,
            	26, 96,
            	26, 120,
            1, 8, 1, /* 4538: pointer.struct.evp_cipher_st */
            	4543, 0,
            0, 88, 7, /* 4543: struct.evp_cipher_st */
            	4560, 24,
            	4563, 32,
            	4566, 40,
            	4569, 56,
            	4569, 64,
            	4572, 72,
            	26, 80,
            8884097, 8, 0, /* 4560: pointer.func */
            8884097, 8, 0, /* 4563: pointer.func */
            8884097, 8, 0, /* 4566: pointer.func */
            8884097, 8, 0, /* 4569: pointer.func */
            8884097, 8, 0, /* 4572: pointer.func */
            1, 8, 1, /* 4575: pointer.struct.env_md_ctx_st */
            	4580, 0,
            0, 48, 5, /* 4580: struct.env_md_ctx_st */
            	4277, 0,
            	3791, 8,
            	26, 24,
            	4593, 32,
            	4304, 40,
            1, 8, 1, /* 4593: pointer.struct.evp_pkey_ctx_st */
            	4598, 0,
            0, 0, 0, /* 4598: struct.evp_pkey_ctx_st */
            1, 8, 1, /* 4601: pointer.struct.ssl_session_st */
            	4606, 0,
            0, 352, 14, /* 4606: struct.ssl_session_st */
            	52, 144,
            	52, 152,
            	4637, 168,
            	3626, 176,
            	4642, 224,
            	4652, 240,
            	3909, 248,
            	4686, 264,
            	4686, 272,
            	52, 280,
            	39, 296,
            	39, 312,
            	39, 320,
            	52, 344,
            1, 8, 1, /* 4637: pointer.struct.sess_cert_st */
            	2768, 0,
            1, 8, 1, /* 4642: pointer.struct.ssl_cipher_st */
            	4647, 0,
            0, 88, 1, /* 4647: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 4652: pointer.struct.stack_st_SSL_CIPHER */
            	4657, 0,
            0, 32, 2, /* 4657: struct.stack_st_fake_SSL_CIPHER */
            	4664, 8,
            	125, 24,
            8884099, 8, 2, /* 4664: pointer_to_array_of_pointers_to_stack */
            	4671, 0,
            	122, 20,
            0, 8, 1, /* 4671: pointer.SSL_CIPHER */
            	4676, 0,
            0, 0, 1, /* 4676: SSL_CIPHER */
            	4681, 0,
            0, 88, 1, /* 4681: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 4686: pointer.struct.ssl_session_st */
            	4606, 0,
            8884097, 8, 0, /* 4691: pointer.func */
            8884097, 8, 0, /* 4694: pointer.func */
            0, 344, 9, /* 4697: struct.ssl2_state_st */
            	107, 24,
            	39, 56,
            	39, 64,
            	39, 72,
            	39, 104,
            	39, 112,
            	39, 120,
            	39, 128,
            	39, 136,
            8884097, 8, 0, /* 4718: pointer.func */
            8884097, 8, 0, /* 4721: pointer.func */
            8884097, 8, 0, /* 4724: pointer.func */
            0, 0, 1, /* 4727: X509_NAME */
            	3039, 0,
            1, 8, 1, /* 4732: pointer.pointer.struct.env_md_ctx_st */
            	4575, 0,
            8884097, 8, 0, /* 4737: pointer.func */
            0, 1200, 10, /* 4740: struct.ssl3_state_st */
            	4763, 240,
            	4763, 264,
            	4768, 288,
            	4768, 344,
            	107, 432,
            	4777, 440,
            	4732, 448,
            	26, 496,
            	26, 512,
            	4845, 528,
            0, 24, 1, /* 4763: struct.ssl3_buffer_st */
            	39, 0,
            0, 56, 3, /* 4768: struct.ssl3_record_st */
            	39, 16,
            	39, 24,
            	39, 32,
            1, 8, 1, /* 4777: pointer.struct.bio_st */
            	4782, 0,
            0, 112, 7, /* 4782: struct.bio_st */
            	4799, 0,
            	4837, 8,
            	52, 16,
            	26, 48,
            	4840, 56,
            	4840, 64,
            	3909, 96,
            1, 8, 1, /* 4799: pointer.struct.bio_method_st */
            	4804, 0,
            0, 80, 9, /* 4804: struct.bio_method_st */
            	5, 8,
            	4825, 16,
            	4828, 24,
            	4721, 32,
            	4828, 40,
            	4831, 48,
            	4834, 56,
            	4834, 64,
            	4718, 72,
            8884097, 8, 0, /* 4825: pointer.func */
            8884097, 8, 0, /* 4828: pointer.func */
            8884097, 8, 0, /* 4831: pointer.func */
            8884097, 8, 0, /* 4834: pointer.func */
            8884097, 8, 0, /* 4837: pointer.func */
            1, 8, 1, /* 4840: pointer.struct.bio_st */
            	4782, 0,
            0, 528, 8, /* 4845: struct.unknown */
            	4642, 408,
            	4327, 416,
            	4332, 424,
            	4864, 464,
            	39, 480,
            	4538, 488,
            	4277, 496,
            	4888, 512,
            1, 8, 1, /* 4864: pointer.struct.stack_st_X509_NAME */
            	4869, 0,
            0, 32, 2, /* 4869: struct.stack_st_fake_X509_NAME */
            	4876, 8,
            	125, 24,
            8884099, 8, 2, /* 4876: pointer_to_array_of_pointers_to_stack */
            	4883, 0,
            	122, 20,
            0, 8, 1, /* 4883: pointer.X509_NAME */
            	4727, 0,
            1, 8, 1, /* 4888: pointer.struct.ssl_comp_st */
            	4893, 0,
            0, 24, 2, /* 4893: struct.ssl_comp_st */
            	5, 8,
            	4440, 16,
            8884097, 8, 0, /* 4900: pointer.func */
            0, 808, 51, /* 4903: struct.ssl_st */
            	5008, 8,
            	4777, 16,
            	4777, 24,
            	4777, 32,
            	4373, 48,
            	3726, 80,
            	26, 88,
            	39, 104,
            	5108, 120,
            	5113, 128,
            	4471, 136,
            	5118, 152,
            	26, 160,
            	5121, 176,
            	4652, 184,
            	4652, 192,
            	4522, 208,
            	4575, 216,
            	4428, 224,
            	4522, 232,
            	4575, 240,
            	4428, 248,
            	5133, 256,
            	4601, 304,
            	5161, 312,
            	5164, 328,
            	4388, 336,
            	5167, 352,
            	5170, 360,
            	5173, 368,
            	3909, 392,
            	4864, 408,
            	159, 464,
            	26, 472,
            	52, 480,
            	5331, 504,
            	5355, 512,
            	39, 520,
            	39, 544,
            	39, 560,
            	26, 568,
            	29, 584,
            	18, 592,
            	26, 600,
            	15, 608,
            	26, 616,
            	5173, 624,
            	39, 632,
            	167, 648,
            	10, 656,
            	205, 680,
            1, 8, 1, /* 5008: pointer.struct.ssl_method_st */
            	5013, 0,
            0, 232, 28, /* 5013: struct.ssl_method_st */
            	4373, 8,
            	4694, 16,
            	4694, 24,
            	4373, 32,
            	4373, 40,
            	4900, 48,
            	4900, 56,
            	5072, 64,
            	4373, 72,
            	4373, 80,
            	4373, 88,
            	5075, 96,
            	5078, 104,
            	5081, 112,
            	4373, 120,
            	5084, 128,
            	2707, 136,
            	5087, 144,
            	5090, 152,
            	5093, 160,
            	5096, 168,
            	5099, 176,
            	5102, 184,
            	299, 192,
            	4337, 200,
            	5096, 208,
            	5105, 216,
            	4737, 224,
            8884097, 8, 0, /* 5072: pointer.func */
            8884097, 8, 0, /* 5075: pointer.func */
            8884097, 8, 0, /* 5078: pointer.func */
            8884097, 8, 0, /* 5081: pointer.func */
            8884097, 8, 0, /* 5084: pointer.func */
            8884097, 8, 0, /* 5087: pointer.func */
            8884097, 8, 0, /* 5090: pointer.func */
            8884097, 8, 0, /* 5093: pointer.func */
            8884097, 8, 0, /* 5096: pointer.func */
            8884097, 8, 0, /* 5099: pointer.func */
            8884097, 8, 0, /* 5102: pointer.func */
            8884097, 8, 0, /* 5105: pointer.func */
            1, 8, 1, /* 5108: pointer.struct.ssl2_state_st */
            	4697, 0,
            1, 8, 1, /* 5113: pointer.struct.ssl3_state_st */
            	4740, 0,
            8884097, 8, 0, /* 5118: pointer.func */
            1, 8, 1, /* 5121: pointer.struct.X509_VERIFY_PARAM_st */
            	5126, 0,
            0, 56, 2, /* 5126: struct.X509_VERIFY_PARAM_st */
            	52, 0,
            	4229, 48,
            1, 8, 1, /* 5133: pointer.struct.cert_st */
            	5138, 0,
            0, 296, 7, /* 5138: struct.cert_st */
            	3612, 0,
            	4322, 48,
            	2693, 56,
            	4327, 64,
            	5155, 72,
            	4332, 80,
            	5158, 88,
            8884097, 8, 0, /* 5155: pointer.func */
            8884097, 8, 0, /* 5158: pointer.func */
            8884097, 8, 0, /* 5161: pointer.func */
            8884097, 8, 0, /* 5164: pointer.func */
            8884097, 8, 0, /* 5167: pointer.func */
            8884097, 8, 0, /* 5170: pointer.func */
            1, 8, 1, /* 5173: pointer.struct.ssl_ctx_st */
            	5178, 0,
            0, 736, 50, /* 5178: struct.ssl_ctx_st */
            	5008, 0,
            	4652, 8,
            	4652, 16,
            	5281, 24,
            	386, 32,
            	4686, 48,
            	4686, 56,
            	349, 80,
            	5322, 88,
            	346, 96,
            	4724, 152,
            	26, 160,
            	4425, 168,
            	26, 176,
            	343, 184,
            	5325, 192,
            	5328, 200,
            	3909, 208,
            	4277, 224,
            	4277, 232,
            	4277, 240,
            	2781, 248,
            	319, 256,
            	4388, 264,
            	4864, 272,
            	5133, 304,
            	5118, 320,
            	26, 328,
            	5164, 376,
            	5161, 384,
            	5121, 392,
            	3791, 408,
            	236, 416,
            	26, 424,
            	4691, 480,
            	239, 488,
            	26, 496,
            	270, 504,
            	26, 512,
            	52, 520,
            	5167, 528,
            	5170, 536,
            	2510, 552,
            	2510, 560,
            	205, 568,
            	199, 696,
            	26, 704,
            	196, 712,
            	26, 720,
            	167, 728,
            1, 8, 1, /* 5281: pointer.struct.x509_store_st */
            	5286, 0,
            0, 144, 15, /* 5286: struct.x509_store_st */
            	4401, 8,
            	2486, 16,
            	5121, 24,
            	5319, 32,
            	5164, 40,
            	2687, 48,
            	406, 56,
            	5319, 64,
            	403, 72,
            	400, 80,
            	397, 88,
            	394, 96,
            	391, 104,
            	5319, 112,
            	3909, 120,
            8884097, 8, 0, /* 5319: pointer.func */
            8884097, 8, 0, /* 5322: pointer.func */
            8884097, 8, 0, /* 5325: pointer.func */
            8884097, 8, 0, /* 5328: pointer.func */
            1, 8, 1, /* 5331: pointer.struct.stack_st_OCSP_RESPID */
            	5336, 0,
            0, 32, 2, /* 5336: struct.stack_st_fake_OCSP_RESPID */
            	5343, 8,
            	125, 24,
            8884099, 8, 2, /* 5343: pointer_to_array_of_pointers_to_stack */
            	5350, 0,
            	122, 20,
            0, 8, 1, /* 5350: pointer.OCSP_RESPID */
            	4391, 0,
            1, 8, 1, /* 5355: pointer.struct.stack_st_X509_EXTENSION */
            	5360, 0,
            0, 32, 2, /* 5360: struct.stack_st_fake_X509_EXTENSION */
            	5367, 8,
            	125, 24,
            8884099, 8, 2, /* 5367: pointer_to_array_of_pointers_to_stack */
            	5374, 0,
            	122, 20,
            0, 8, 1, /* 5374: pointer.X509_EXTENSION */
            	1661, 0,
            0, 1, 0, /* 5379: char */
            1, 8, 1, /* 5382: pointer.struct.ssl_st */
            	4903, 0,
        },
        .arg_entity_index = { 5382, },
        .ret_entity_index = 52,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL * new_arg_a = *((SSL * *)new_args->args[0]);

    char * *new_ret_ptr = (char * *)new_args->ret;

    char * (*orig_SSL_get_srp_username)(SSL *);
    orig_SSL_get_srp_username = dlsym(RTLD_NEXT, "SSL_get_srp_username");
    *new_ret_ptr = (*orig_SSL_get_srp_username)(new_arg_a);

    syscall(889);

    return ret;
}

