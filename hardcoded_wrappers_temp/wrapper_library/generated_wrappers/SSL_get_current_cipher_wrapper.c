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

const SSL_CIPHER * bb_SSL_get_current_cipher(const SSL * arg_a);

const SSL_CIPHER * SSL_get_current_cipher(const SSL * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_get_current_cipher called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_get_current_cipher(arg_a);
    else {
        const SSL_CIPHER * (*orig_SSL_get_current_cipher)(const SSL *);
        orig_SSL_get_current_cipher = dlsym(RTLD_NEXT, "SSL_get_current_cipher");
        return orig_SSL_get_current_cipher(arg_a);
    }
}

const SSL_CIPHER * bb_SSL_get_current_cipher(const SSL * arg_a) 
{
    const SSL_CIPHER * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 88, 1, /* 0: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 5: pointer.char */
            	8884096, 0,
            0, 16, 1, /* 10: struct.tls_session_ticket_ext_st */
            	15, 8,
            0, 8, 0, /* 15: pointer.void */
            0, 24, 1, /* 18: struct.asn1_string_st */
            	23, 8,
            1, 8, 1, /* 23: pointer.unsigned char */
            	28, 0,
            0, 1, 0, /* 28: unsigned char */
            0, 24, 1, /* 31: struct.buf_mem_st */
            	36, 8,
            1, 8, 1, /* 36: pointer.char */
            	8884096, 0,
            0, 8, 2, /* 41: union.unknown */
            	48, 0,
            	138, 0,
            1, 8, 1, /* 48: pointer.struct.X509_name_st */
            	53, 0,
            0, 40, 3, /* 53: struct.X509_name_st */
            	62, 0,
            	133, 16,
            	23, 24,
            1, 8, 1, /* 62: pointer.struct.stack_st_X509_NAME_ENTRY */
            	67, 0,
            0, 32, 2, /* 67: struct.stack_st_fake_X509_NAME_ENTRY */
            	74, 8,
            	130, 24,
            8884099, 8, 2, /* 74: pointer_to_array_of_pointers_to_stack */
            	81, 0,
            	127, 20,
            0, 8, 1, /* 81: pointer.X509_NAME_ENTRY */
            	86, 0,
            0, 0, 1, /* 86: X509_NAME_ENTRY */
            	91, 0,
            0, 24, 2, /* 91: struct.X509_name_entry_st */
            	98, 0,
            	117, 8,
            1, 8, 1, /* 98: pointer.struct.asn1_object_st */
            	103, 0,
            0, 40, 3, /* 103: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	112, 24,
            1, 8, 1, /* 112: pointer.unsigned char */
            	28, 0,
            1, 8, 1, /* 117: pointer.struct.asn1_string_st */
            	122, 0,
            0, 24, 1, /* 122: struct.asn1_string_st */
            	23, 8,
            0, 4, 0, /* 127: int */
            8884097, 8, 0, /* 130: pointer.func */
            1, 8, 1, /* 133: pointer.struct.buf_mem_st */
            	31, 0,
            1, 8, 1, /* 138: pointer.struct.asn1_string_st */
            	18, 0,
            0, 0, 1, /* 143: OCSP_RESPID */
            	148, 0,
            0, 16, 1, /* 148: struct.ocsp_responder_id_st */
            	41, 8,
            0, 16, 1, /* 153: struct.srtp_protection_profile_st */
            	5, 0,
            8884097, 8, 0, /* 158: pointer.func */
            8884097, 8, 0, /* 161: pointer.func */
            1, 8, 1, /* 164: pointer.struct.bignum_st */
            	169, 0,
            0, 24, 1, /* 169: struct.bignum_st */
            	174, 0,
            1, 8, 1, /* 174: pointer.unsigned int */
            	179, 0,
            0, 4, 0, /* 179: unsigned int */
            0, 8, 1, /* 182: struct.ssl3_buf_freelist_entry_st */
            	187, 0,
            1, 8, 1, /* 187: pointer.struct.ssl3_buf_freelist_entry_st */
            	182, 0,
            0, 24, 1, /* 192: struct.ssl3_buf_freelist_st */
            	187, 16,
            1, 8, 1, /* 197: pointer.struct.ssl3_buf_freelist_st */
            	192, 0,
            8884097, 8, 0, /* 202: pointer.func */
            8884097, 8, 0, /* 205: pointer.func */
            0, 64, 7, /* 208: struct.comp_method_st */
            	5, 8,
            	225, 16,
            	205, 24,
            	228, 32,
            	228, 40,
            	231, 48,
            	231, 56,
            8884097, 8, 0, /* 225: pointer.func */
            8884097, 8, 0, /* 228: pointer.func */
            8884097, 8, 0, /* 231: pointer.func */
            0, 0, 1, /* 234: SSL_COMP */
            	239, 0,
            0, 24, 2, /* 239: struct.ssl_comp_st */
            	5, 8,
            	246, 16,
            1, 8, 1, /* 246: pointer.struct.comp_method_st */
            	208, 0,
            1, 8, 1, /* 251: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	256, 0,
            0, 32, 2, /* 256: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	263, 8,
            	130, 24,
            8884099, 8, 2, /* 263: pointer_to_array_of_pointers_to_stack */
            	270, 0,
            	127, 20,
            0, 8, 1, /* 270: pointer.SRTP_PROTECTION_PROFILE */
            	275, 0,
            0, 0, 1, /* 275: SRTP_PROTECTION_PROFILE */
            	153, 0,
            1, 8, 1, /* 280: pointer.struct.stack_st_SSL_COMP */
            	285, 0,
            0, 32, 2, /* 285: struct.stack_st_fake_SSL_COMP */
            	292, 8,
            	130, 24,
            8884099, 8, 2, /* 292: pointer_to_array_of_pointers_to_stack */
            	299, 0,
            	127, 20,
            0, 8, 1, /* 299: pointer.SSL_COMP */
            	234, 0,
            8884097, 8, 0, /* 304: pointer.func */
            8884097, 8, 0, /* 307: pointer.func */
            8884097, 8, 0, /* 310: pointer.func */
            8884097, 8, 0, /* 313: pointer.func */
            8884097, 8, 0, /* 316: pointer.func */
            1, 8, 1, /* 319: pointer.struct.lhash_node_st */
            	324, 0,
            0, 24, 2, /* 324: struct.lhash_node_st */
            	15, 0,
            	319, 8,
            1, 8, 1, /* 331: pointer.struct.lhash_st */
            	336, 0,
            0, 176, 3, /* 336: struct.lhash_st */
            	345, 0,
            	130, 8,
            	352, 16,
            8884099, 8, 2, /* 345: pointer_to_array_of_pointers_to_stack */
            	319, 0,
            	179, 28,
            8884097, 8, 0, /* 352: pointer.func */
            8884097, 8, 0, /* 355: pointer.func */
            8884097, 8, 0, /* 358: pointer.func */
            8884097, 8, 0, /* 361: pointer.func */
            8884097, 8, 0, /* 364: pointer.func */
            8884097, 8, 0, /* 367: pointer.func */
            8884097, 8, 0, /* 370: pointer.func */
            8884097, 8, 0, /* 373: pointer.func */
            8884097, 8, 0, /* 376: pointer.func */
            1, 8, 1, /* 379: pointer.struct.X509_VERIFY_PARAM_st */
            	384, 0,
            0, 56, 2, /* 384: struct.X509_VERIFY_PARAM_st */
            	36, 0,
            	391, 48,
            1, 8, 1, /* 391: pointer.struct.stack_st_ASN1_OBJECT */
            	396, 0,
            0, 32, 2, /* 396: struct.stack_st_fake_ASN1_OBJECT */
            	403, 8,
            	130, 24,
            8884099, 8, 2, /* 403: pointer_to_array_of_pointers_to_stack */
            	410, 0,
            	127, 20,
            0, 8, 1, /* 410: pointer.ASN1_OBJECT */
            	415, 0,
            0, 0, 1, /* 415: ASN1_OBJECT */
            	420, 0,
            0, 40, 3, /* 420: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	112, 24,
            1, 8, 1, /* 429: pointer.struct.stack_st_X509_OBJECT */
            	434, 0,
            0, 32, 2, /* 434: struct.stack_st_fake_X509_OBJECT */
            	441, 8,
            	130, 24,
            8884099, 8, 2, /* 441: pointer_to_array_of_pointers_to_stack */
            	448, 0,
            	127, 20,
            0, 8, 1, /* 448: pointer.X509_OBJECT */
            	453, 0,
            0, 0, 1, /* 453: X509_OBJECT */
            	458, 0,
            0, 16, 1, /* 458: struct.x509_object_st */
            	463, 8,
            0, 8, 4, /* 463: union.unknown */
            	36, 0,
            	474, 0,
            	3969, 0,
            	4202, 0,
            1, 8, 1, /* 474: pointer.struct.x509_st */
            	479, 0,
            0, 184, 12, /* 479: struct.x509_st */
            	506, 0,
            	546, 8,
            	2600, 16,
            	36, 32,
            	2670, 40,
            	2692, 104,
            	2697, 112,
            	3020, 120,
            	3442, 128,
            	3581, 136,
            	3605, 144,
            	3917, 176,
            1, 8, 1, /* 506: pointer.struct.x509_cinf_st */
            	511, 0,
            0, 104, 11, /* 511: struct.x509_cinf_st */
            	536, 0,
            	536, 8,
            	546, 16,
            	713, 24,
            	761, 32,
            	713, 40,
            	778, 48,
            	2600, 56,
            	2600, 64,
            	2605, 72,
            	2665, 80,
            1, 8, 1, /* 536: pointer.struct.asn1_string_st */
            	541, 0,
            0, 24, 1, /* 541: struct.asn1_string_st */
            	23, 8,
            1, 8, 1, /* 546: pointer.struct.X509_algor_st */
            	551, 0,
            0, 16, 2, /* 551: struct.X509_algor_st */
            	558, 0,
            	572, 8,
            1, 8, 1, /* 558: pointer.struct.asn1_object_st */
            	563, 0,
            0, 40, 3, /* 563: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	112, 24,
            1, 8, 1, /* 572: pointer.struct.asn1_type_st */
            	577, 0,
            0, 16, 1, /* 577: struct.asn1_type_st */
            	582, 8,
            0, 8, 20, /* 582: union.unknown */
            	36, 0,
            	625, 0,
            	558, 0,
            	635, 0,
            	640, 0,
            	645, 0,
            	650, 0,
            	655, 0,
            	660, 0,
            	665, 0,
            	670, 0,
            	675, 0,
            	680, 0,
            	685, 0,
            	690, 0,
            	695, 0,
            	700, 0,
            	625, 0,
            	625, 0,
            	705, 0,
            1, 8, 1, /* 625: pointer.struct.asn1_string_st */
            	630, 0,
            0, 24, 1, /* 630: struct.asn1_string_st */
            	23, 8,
            1, 8, 1, /* 635: pointer.struct.asn1_string_st */
            	630, 0,
            1, 8, 1, /* 640: pointer.struct.asn1_string_st */
            	630, 0,
            1, 8, 1, /* 645: pointer.struct.asn1_string_st */
            	630, 0,
            1, 8, 1, /* 650: pointer.struct.asn1_string_st */
            	630, 0,
            1, 8, 1, /* 655: pointer.struct.asn1_string_st */
            	630, 0,
            1, 8, 1, /* 660: pointer.struct.asn1_string_st */
            	630, 0,
            1, 8, 1, /* 665: pointer.struct.asn1_string_st */
            	630, 0,
            1, 8, 1, /* 670: pointer.struct.asn1_string_st */
            	630, 0,
            1, 8, 1, /* 675: pointer.struct.asn1_string_st */
            	630, 0,
            1, 8, 1, /* 680: pointer.struct.asn1_string_st */
            	630, 0,
            1, 8, 1, /* 685: pointer.struct.asn1_string_st */
            	630, 0,
            1, 8, 1, /* 690: pointer.struct.asn1_string_st */
            	630, 0,
            1, 8, 1, /* 695: pointer.struct.asn1_string_st */
            	630, 0,
            1, 8, 1, /* 700: pointer.struct.asn1_string_st */
            	630, 0,
            1, 8, 1, /* 705: pointer.struct.ASN1_VALUE_st */
            	710, 0,
            0, 0, 0, /* 710: struct.ASN1_VALUE_st */
            1, 8, 1, /* 713: pointer.struct.X509_name_st */
            	718, 0,
            0, 40, 3, /* 718: struct.X509_name_st */
            	727, 0,
            	751, 16,
            	23, 24,
            1, 8, 1, /* 727: pointer.struct.stack_st_X509_NAME_ENTRY */
            	732, 0,
            0, 32, 2, /* 732: struct.stack_st_fake_X509_NAME_ENTRY */
            	739, 8,
            	130, 24,
            8884099, 8, 2, /* 739: pointer_to_array_of_pointers_to_stack */
            	746, 0,
            	127, 20,
            0, 8, 1, /* 746: pointer.X509_NAME_ENTRY */
            	86, 0,
            1, 8, 1, /* 751: pointer.struct.buf_mem_st */
            	756, 0,
            0, 24, 1, /* 756: struct.buf_mem_st */
            	36, 8,
            1, 8, 1, /* 761: pointer.struct.X509_val_st */
            	766, 0,
            0, 16, 2, /* 766: struct.X509_val_st */
            	773, 0,
            	773, 8,
            1, 8, 1, /* 773: pointer.struct.asn1_string_st */
            	541, 0,
            1, 8, 1, /* 778: pointer.struct.X509_pubkey_st */
            	783, 0,
            0, 24, 3, /* 783: struct.X509_pubkey_st */
            	792, 0,
            	797, 8,
            	807, 16,
            1, 8, 1, /* 792: pointer.struct.X509_algor_st */
            	551, 0,
            1, 8, 1, /* 797: pointer.struct.asn1_string_st */
            	802, 0,
            0, 24, 1, /* 802: struct.asn1_string_st */
            	23, 8,
            1, 8, 1, /* 807: pointer.struct.evp_pkey_st */
            	812, 0,
            0, 56, 4, /* 812: struct.evp_pkey_st */
            	823, 16,
            	924, 24,
            	1277, 32,
            	2221, 48,
            1, 8, 1, /* 823: pointer.struct.evp_pkey_asn1_method_st */
            	828, 0,
            0, 208, 24, /* 828: struct.evp_pkey_asn1_method_st */
            	36, 16,
            	36, 24,
            	879, 32,
            	882, 40,
            	885, 48,
            	888, 56,
            	891, 64,
            	894, 72,
            	888, 80,
            	897, 88,
            	897, 96,
            	900, 104,
            	903, 112,
            	897, 120,
            	906, 128,
            	885, 136,
            	888, 144,
            	909, 152,
            	912, 160,
            	915, 168,
            	900, 176,
            	903, 184,
            	918, 192,
            	921, 200,
            8884097, 8, 0, /* 879: pointer.func */
            8884097, 8, 0, /* 882: pointer.func */
            8884097, 8, 0, /* 885: pointer.func */
            8884097, 8, 0, /* 888: pointer.func */
            8884097, 8, 0, /* 891: pointer.func */
            8884097, 8, 0, /* 894: pointer.func */
            8884097, 8, 0, /* 897: pointer.func */
            8884097, 8, 0, /* 900: pointer.func */
            8884097, 8, 0, /* 903: pointer.func */
            8884097, 8, 0, /* 906: pointer.func */
            8884097, 8, 0, /* 909: pointer.func */
            8884097, 8, 0, /* 912: pointer.func */
            8884097, 8, 0, /* 915: pointer.func */
            8884097, 8, 0, /* 918: pointer.func */
            8884097, 8, 0, /* 921: pointer.func */
            1, 8, 1, /* 924: pointer.struct.engine_st */
            	929, 0,
            0, 216, 24, /* 929: struct.engine_st */
            	5, 0,
            	5, 8,
            	980, 16,
            	1035, 24,
            	1086, 32,
            	1122, 40,
            	1139, 48,
            	1166, 56,
            	1201, 64,
            	1209, 72,
            	1212, 80,
            	1215, 88,
            	1218, 96,
            	1221, 104,
            	1221, 112,
            	1221, 120,
            	1224, 128,
            	1227, 136,
            	1227, 144,
            	1230, 152,
            	1233, 160,
            	1245, 184,
            	1272, 200,
            	1272, 208,
            1, 8, 1, /* 980: pointer.struct.rsa_meth_st */
            	985, 0,
            0, 112, 13, /* 985: struct.rsa_meth_st */
            	5, 0,
            	1014, 8,
            	1014, 16,
            	1014, 24,
            	1014, 32,
            	1017, 40,
            	1020, 48,
            	1023, 56,
            	1023, 64,
            	36, 80,
            	1026, 88,
            	1029, 96,
            	1032, 104,
            8884097, 8, 0, /* 1014: pointer.func */
            8884097, 8, 0, /* 1017: pointer.func */
            8884097, 8, 0, /* 1020: pointer.func */
            8884097, 8, 0, /* 1023: pointer.func */
            8884097, 8, 0, /* 1026: pointer.func */
            8884097, 8, 0, /* 1029: pointer.func */
            8884097, 8, 0, /* 1032: pointer.func */
            1, 8, 1, /* 1035: pointer.struct.dsa_method */
            	1040, 0,
            0, 96, 11, /* 1040: struct.dsa_method */
            	5, 0,
            	1065, 8,
            	1068, 16,
            	1071, 24,
            	1074, 32,
            	1077, 40,
            	1080, 48,
            	1080, 56,
            	36, 72,
            	1083, 80,
            	1080, 88,
            8884097, 8, 0, /* 1065: pointer.func */
            8884097, 8, 0, /* 1068: pointer.func */
            8884097, 8, 0, /* 1071: pointer.func */
            8884097, 8, 0, /* 1074: pointer.func */
            8884097, 8, 0, /* 1077: pointer.func */
            8884097, 8, 0, /* 1080: pointer.func */
            8884097, 8, 0, /* 1083: pointer.func */
            1, 8, 1, /* 1086: pointer.struct.dh_method */
            	1091, 0,
            0, 72, 8, /* 1091: struct.dh_method */
            	5, 0,
            	1110, 8,
            	1113, 16,
            	1116, 24,
            	1110, 32,
            	1110, 40,
            	36, 56,
            	1119, 64,
            8884097, 8, 0, /* 1110: pointer.func */
            8884097, 8, 0, /* 1113: pointer.func */
            8884097, 8, 0, /* 1116: pointer.func */
            8884097, 8, 0, /* 1119: pointer.func */
            1, 8, 1, /* 1122: pointer.struct.ecdh_method */
            	1127, 0,
            0, 32, 3, /* 1127: struct.ecdh_method */
            	5, 0,
            	1136, 8,
            	36, 24,
            8884097, 8, 0, /* 1136: pointer.func */
            1, 8, 1, /* 1139: pointer.struct.ecdsa_method */
            	1144, 0,
            0, 48, 5, /* 1144: struct.ecdsa_method */
            	5, 0,
            	1157, 8,
            	1160, 16,
            	1163, 24,
            	36, 40,
            8884097, 8, 0, /* 1157: pointer.func */
            8884097, 8, 0, /* 1160: pointer.func */
            8884097, 8, 0, /* 1163: pointer.func */
            1, 8, 1, /* 1166: pointer.struct.rand_meth_st */
            	1171, 0,
            0, 48, 6, /* 1171: struct.rand_meth_st */
            	1186, 0,
            	1189, 8,
            	1192, 16,
            	1195, 24,
            	1189, 32,
            	1198, 40,
            8884097, 8, 0, /* 1186: pointer.func */
            8884097, 8, 0, /* 1189: pointer.func */
            8884097, 8, 0, /* 1192: pointer.func */
            8884097, 8, 0, /* 1195: pointer.func */
            8884097, 8, 0, /* 1198: pointer.func */
            1, 8, 1, /* 1201: pointer.struct.store_method_st */
            	1206, 0,
            0, 0, 0, /* 1206: struct.store_method_st */
            8884097, 8, 0, /* 1209: pointer.func */
            8884097, 8, 0, /* 1212: pointer.func */
            8884097, 8, 0, /* 1215: pointer.func */
            8884097, 8, 0, /* 1218: pointer.func */
            8884097, 8, 0, /* 1221: pointer.func */
            8884097, 8, 0, /* 1224: pointer.func */
            8884097, 8, 0, /* 1227: pointer.func */
            8884097, 8, 0, /* 1230: pointer.func */
            1, 8, 1, /* 1233: pointer.struct.ENGINE_CMD_DEFN_st */
            	1238, 0,
            0, 32, 2, /* 1238: struct.ENGINE_CMD_DEFN_st */
            	5, 8,
            	5, 16,
            0, 16, 1, /* 1245: struct.crypto_ex_data_st */
            	1250, 0,
            1, 8, 1, /* 1250: pointer.struct.stack_st_void */
            	1255, 0,
            0, 32, 1, /* 1255: struct.stack_st_void */
            	1260, 0,
            0, 32, 2, /* 1260: struct.stack_st */
            	1267, 8,
            	130, 24,
            1, 8, 1, /* 1267: pointer.pointer.char */
            	36, 0,
            1, 8, 1, /* 1272: pointer.struct.engine_st */
            	929, 0,
            0, 8, 5, /* 1277: union.unknown */
            	36, 0,
            	1290, 0,
            	1492, 0,
            	1619, 0,
            	1733, 0,
            1, 8, 1, /* 1290: pointer.struct.rsa_st */
            	1295, 0,
            0, 168, 17, /* 1295: struct.rsa_st */
            	1332, 16,
            	1387, 24,
            	1392, 32,
            	1392, 40,
            	1392, 48,
            	1392, 56,
            	1392, 64,
            	1392, 72,
            	1392, 80,
            	1392, 88,
            	1402, 96,
            	1424, 120,
            	1424, 128,
            	1424, 136,
            	36, 144,
            	1438, 152,
            	1438, 160,
            1, 8, 1, /* 1332: pointer.struct.rsa_meth_st */
            	1337, 0,
            0, 112, 13, /* 1337: struct.rsa_meth_st */
            	5, 0,
            	1366, 8,
            	1366, 16,
            	1366, 24,
            	1366, 32,
            	1369, 40,
            	1372, 48,
            	1375, 56,
            	1375, 64,
            	36, 80,
            	1378, 88,
            	1381, 96,
            	1384, 104,
            8884097, 8, 0, /* 1366: pointer.func */
            8884097, 8, 0, /* 1369: pointer.func */
            8884097, 8, 0, /* 1372: pointer.func */
            8884097, 8, 0, /* 1375: pointer.func */
            8884097, 8, 0, /* 1378: pointer.func */
            8884097, 8, 0, /* 1381: pointer.func */
            8884097, 8, 0, /* 1384: pointer.func */
            1, 8, 1, /* 1387: pointer.struct.engine_st */
            	929, 0,
            1, 8, 1, /* 1392: pointer.struct.bignum_st */
            	1397, 0,
            0, 24, 1, /* 1397: struct.bignum_st */
            	174, 0,
            0, 16, 1, /* 1402: struct.crypto_ex_data_st */
            	1407, 0,
            1, 8, 1, /* 1407: pointer.struct.stack_st_void */
            	1412, 0,
            0, 32, 1, /* 1412: struct.stack_st_void */
            	1417, 0,
            0, 32, 2, /* 1417: struct.stack_st */
            	1267, 8,
            	130, 24,
            1, 8, 1, /* 1424: pointer.struct.bn_mont_ctx_st */
            	1429, 0,
            0, 96, 3, /* 1429: struct.bn_mont_ctx_st */
            	1397, 8,
            	1397, 32,
            	1397, 56,
            1, 8, 1, /* 1438: pointer.struct.bn_blinding_st */
            	1443, 0,
            0, 88, 7, /* 1443: struct.bn_blinding_st */
            	1460, 0,
            	1460, 8,
            	1460, 16,
            	1460, 24,
            	1470, 40,
            	1475, 72,
            	1489, 80,
            1, 8, 1, /* 1460: pointer.struct.bignum_st */
            	1465, 0,
            0, 24, 1, /* 1465: struct.bignum_st */
            	174, 0,
            0, 16, 1, /* 1470: struct.crypto_threadid_st */
            	15, 0,
            1, 8, 1, /* 1475: pointer.struct.bn_mont_ctx_st */
            	1480, 0,
            0, 96, 3, /* 1480: struct.bn_mont_ctx_st */
            	1465, 8,
            	1465, 32,
            	1465, 56,
            8884097, 8, 0, /* 1489: pointer.func */
            1, 8, 1, /* 1492: pointer.struct.dsa_st */
            	1497, 0,
            0, 136, 11, /* 1497: struct.dsa_st */
            	1522, 24,
            	1522, 32,
            	1522, 40,
            	1522, 48,
            	1522, 56,
            	1522, 64,
            	1522, 72,
            	1532, 88,
            	1546, 104,
            	1568, 120,
            	924, 128,
            1, 8, 1, /* 1522: pointer.struct.bignum_st */
            	1527, 0,
            0, 24, 1, /* 1527: struct.bignum_st */
            	174, 0,
            1, 8, 1, /* 1532: pointer.struct.bn_mont_ctx_st */
            	1537, 0,
            0, 96, 3, /* 1537: struct.bn_mont_ctx_st */
            	1527, 8,
            	1527, 32,
            	1527, 56,
            0, 16, 1, /* 1546: struct.crypto_ex_data_st */
            	1551, 0,
            1, 8, 1, /* 1551: pointer.struct.stack_st_void */
            	1556, 0,
            0, 32, 1, /* 1556: struct.stack_st_void */
            	1561, 0,
            0, 32, 2, /* 1561: struct.stack_st */
            	1267, 8,
            	130, 24,
            1, 8, 1, /* 1568: pointer.struct.dsa_method */
            	1573, 0,
            0, 96, 11, /* 1573: struct.dsa_method */
            	5, 0,
            	1598, 8,
            	1601, 16,
            	1604, 24,
            	1607, 32,
            	1610, 40,
            	1613, 48,
            	1613, 56,
            	36, 72,
            	1616, 80,
            	1613, 88,
            8884097, 8, 0, /* 1598: pointer.func */
            8884097, 8, 0, /* 1601: pointer.func */
            8884097, 8, 0, /* 1604: pointer.func */
            8884097, 8, 0, /* 1607: pointer.func */
            8884097, 8, 0, /* 1610: pointer.func */
            8884097, 8, 0, /* 1613: pointer.func */
            8884097, 8, 0, /* 1616: pointer.func */
            1, 8, 1, /* 1619: pointer.struct.dh_st */
            	1624, 0,
            0, 144, 12, /* 1624: struct.dh_st */
            	1651, 8,
            	1651, 16,
            	1651, 32,
            	1651, 40,
            	1661, 56,
            	1651, 64,
            	1651, 72,
            	23, 80,
            	1651, 96,
            	1675, 112,
            	1697, 128,
            	1387, 136,
            1, 8, 1, /* 1651: pointer.struct.bignum_st */
            	1656, 0,
            0, 24, 1, /* 1656: struct.bignum_st */
            	174, 0,
            1, 8, 1, /* 1661: pointer.struct.bn_mont_ctx_st */
            	1666, 0,
            0, 96, 3, /* 1666: struct.bn_mont_ctx_st */
            	1656, 8,
            	1656, 32,
            	1656, 56,
            0, 16, 1, /* 1675: struct.crypto_ex_data_st */
            	1680, 0,
            1, 8, 1, /* 1680: pointer.struct.stack_st_void */
            	1685, 0,
            0, 32, 1, /* 1685: struct.stack_st_void */
            	1690, 0,
            0, 32, 2, /* 1690: struct.stack_st */
            	1267, 8,
            	130, 24,
            1, 8, 1, /* 1697: pointer.struct.dh_method */
            	1702, 0,
            0, 72, 8, /* 1702: struct.dh_method */
            	5, 0,
            	1721, 8,
            	1724, 16,
            	1727, 24,
            	1721, 32,
            	1721, 40,
            	36, 56,
            	1730, 64,
            8884097, 8, 0, /* 1721: pointer.func */
            8884097, 8, 0, /* 1724: pointer.func */
            8884097, 8, 0, /* 1727: pointer.func */
            8884097, 8, 0, /* 1730: pointer.func */
            1, 8, 1, /* 1733: pointer.struct.ec_key_st */
            	1738, 0,
            0, 56, 4, /* 1738: struct.ec_key_st */
            	1749, 8,
            	2183, 16,
            	2188, 24,
            	2198, 48,
            1, 8, 1, /* 1749: pointer.struct.ec_group_st */
            	1754, 0,
            0, 232, 12, /* 1754: struct.ec_group_st */
            	1781, 0,
            	1953, 8,
            	2146, 16,
            	2146, 40,
            	23, 80,
            	2151, 96,
            	2146, 104,
            	2146, 152,
            	2146, 176,
            	15, 208,
            	15, 216,
            	2180, 224,
            1, 8, 1, /* 1781: pointer.struct.ec_method_st */
            	1786, 0,
            0, 304, 37, /* 1786: struct.ec_method_st */
            	1863, 8,
            	1866, 16,
            	1866, 24,
            	1869, 32,
            	1872, 40,
            	1875, 48,
            	1878, 56,
            	1881, 64,
            	1884, 72,
            	1887, 80,
            	1887, 88,
            	1890, 96,
            	1893, 104,
            	1896, 112,
            	1899, 120,
            	1902, 128,
            	1905, 136,
            	1908, 144,
            	1911, 152,
            	1914, 160,
            	1917, 168,
            	1920, 176,
            	1923, 184,
            	1926, 192,
            	1929, 200,
            	1932, 208,
            	1923, 216,
            	1935, 224,
            	1938, 232,
            	1941, 240,
            	1878, 248,
            	1944, 256,
            	1947, 264,
            	1944, 272,
            	1947, 280,
            	1947, 288,
            	1950, 296,
            8884097, 8, 0, /* 1863: pointer.func */
            8884097, 8, 0, /* 1866: pointer.func */
            8884097, 8, 0, /* 1869: pointer.func */
            8884097, 8, 0, /* 1872: pointer.func */
            8884097, 8, 0, /* 1875: pointer.func */
            8884097, 8, 0, /* 1878: pointer.func */
            8884097, 8, 0, /* 1881: pointer.func */
            8884097, 8, 0, /* 1884: pointer.func */
            8884097, 8, 0, /* 1887: pointer.func */
            8884097, 8, 0, /* 1890: pointer.func */
            8884097, 8, 0, /* 1893: pointer.func */
            8884097, 8, 0, /* 1896: pointer.func */
            8884097, 8, 0, /* 1899: pointer.func */
            8884097, 8, 0, /* 1902: pointer.func */
            8884097, 8, 0, /* 1905: pointer.func */
            8884097, 8, 0, /* 1908: pointer.func */
            8884097, 8, 0, /* 1911: pointer.func */
            8884097, 8, 0, /* 1914: pointer.func */
            8884097, 8, 0, /* 1917: pointer.func */
            8884097, 8, 0, /* 1920: pointer.func */
            8884097, 8, 0, /* 1923: pointer.func */
            8884097, 8, 0, /* 1926: pointer.func */
            8884097, 8, 0, /* 1929: pointer.func */
            8884097, 8, 0, /* 1932: pointer.func */
            8884097, 8, 0, /* 1935: pointer.func */
            8884097, 8, 0, /* 1938: pointer.func */
            8884097, 8, 0, /* 1941: pointer.func */
            8884097, 8, 0, /* 1944: pointer.func */
            8884097, 8, 0, /* 1947: pointer.func */
            8884097, 8, 0, /* 1950: pointer.func */
            1, 8, 1, /* 1953: pointer.struct.ec_point_st */
            	1958, 0,
            0, 88, 4, /* 1958: struct.ec_point_st */
            	1969, 0,
            	2141, 8,
            	2141, 32,
            	2141, 56,
            1, 8, 1, /* 1969: pointer.struct.ec_method_st */
            	1974, 0,
            0, 304, 37, /* 1974: struct.ec_method_st */
            	2051, 8,
            	2054, 16,
            	2054, 24,
            	2057, 32,
            	2060, 40,
            	2063, 48,
            	2066, 56,
            	2069, 64,
            	2072, 72,
            	2075, 80,
            	2075, 88,
            	2078, 96,
            	2081, 104,
            	2084, 112,
            	2087, 120,
            	2090, 128,
            	2093, 136,
            	2096, 144,
            	2099, 152,
            	2102, 160,
            	2105, 168,
            	2108, 176,
            	2111, 184,
            	2114, 192,
            	2117, 200,
            	2120, 208,
            	2111, 216,
            	2123, 224,
            	2126, 232,
            	2129, 240,
            	2066, 248,
            	2132, 256,
            	2135, 264,
            	2132, 272,
            	2135, 280,
            	2135, 288,
            	2138, 296,
            8884097, 8, 0, /* 2051: pointer.func */
            8884097, 8, 0, /* 2054: pointer.func */
            8884097, 8, 0, /* 2057: pointer.func */
            8884097, 8, 0, /* 2060: pointer.func */
            8884097, 8, 0, /* 2063: pointer.func */
            8884097, 8, 0, /* 2066: pointer.func */
            8884097, 8, 0, /* 2069: pointer.func */
            8884097, 8, 0, /* 2072: pointer.func */
            8884097, 8, 0, /* 2075: pointer.func */
            8884097, 8, 0, /* 2078: pointer.func */
            8884097, 8, 0, /* 2081: pointer.func */
            8884097, 8, 0, /* 2084: pointer.func */
            8884097, 8, 0, /* 2087: pointer.func */
            8884097, 8, 0, /* 2090: pointer.func */
            8884097, 8, 0, /* 2093: pointer.func */
            8884097, 8, 0, /* 2096: pointer.func */
            8884097, 8, 0, /* 2099: pointer.func */
            8884097, 8, 0, /* 2102: pointer.func */
            8884097, 8, 0, /* 2105: pointer.func */
            8884097, 8, 0, /* 2108: pointer.func */
            8884097, 8, 0, /* 2111: pointer.func */
            8884097, 8, 0, /* 2114: pointer.func */
            8884097, 8, 0, /* 2117: pointer.func */
            8884097, 8, 0, /* 2120: pointer.func */
            8884097, 8, 0, /* 2123: pointer.func */
            8884097, 8, 0, /* 2126: pointer.func */
            8884097, 8, 0, /* 2129: pointer.func */
            8884097, 8, 0, /* 2132: pointer.func */
            8884097, 8, 0, /* 2135: pointer.func */
            8884097, 8, 0, /* 2138: pointer.func */
            0, 24, 1, /* 2141: struct.bignum_st */
            	174, 0,
            0, 24, 1, /* 2146: struct.bignum_st */
            	174, 0,
            1, 8, 1, /* 2151: pointer.struct.ec_extra_data_st */
            	2156, 0,
            0, 40, 5, /* 2156: struct.ec_extra_data_st */
            	2169, 0,
            	15, 8,
            	2174, 16,
            	2177, 24,
            	2177, 32,
            1, 8, 1, /* 2169: pointer.struct.ec_extra_data_st */
            	2156, 0,
            8884097, 8, 0, /* 2174: pointer.func */
            8884097, 8, 0, /* 2177: pointer.func */
            8884097, 8, 0, /* 2180: pointer.func */
            1, 8, 1, /* 2183: pointer.struct.ec_point_st */
            	1958, 0,
            1, 8, 1, /* 2188: pointer.struct.bignum_st */
            	2193, 0,
            0, 24, 1, /* 2193: struct.bignum_st */
            	174, 0,
            1, 8, 1, /* 2198: pointer.struct.ec_extra_data_st */
            	2203, 0,
            0, 40, 5, /* 2203: struct.ec_extra_data_st */
            	2216, 0,
            	15, 8,
            	2174, 16,
            	2177, 24,
            	2177, 32,
            1, 8, 1, /* 2216: pointer.struct.ec_extra_data_st */
            	2203, 0,
            1, 8, 1, /* 2221: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2226, 0,
            0, 32, 2, /* 2226: struct.stack_st_fake_X509_ATTRIBUTE */
            	2233, 8,
            	130, 24,
            8884099, 8, 2, /* 2233: pointer_to_array_of_pointers_to_stack */
            	2240, 0,
            	127, 20,
            0, 8, 1, /* 2240: pointer.X509_ATTRIBUTE */
            	2245, 0,
            0, 0, 1, /* 2245: X509_ATTRIBUTE */
            	2250, 0,
            0, 24, 2, /* 2250: struct.x509_attributes_st */
            	2257, 0,
            	2271, 16,
            1, 8, 1, /* 2257: pointer.struct.asn1_object_st */
            	2262, 0,
            0, 40, 3, /* 2262: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	112, 24,
            0, 8, 3, /* 2271: union.unknown */
            	36, 0,
            	2280, 0,
            	2459, 0,
            1, 8, 1, /* 2280: pointer.struct.stack_st_ASN1_TYPE */
            	2285, 0,
            0, 32, 2, /* 2285: struct.stack_st_fake_ASN1_TYPE */
            	2292, 8,
            	130, 24,
            8884099, 8, 2, /* 2292: pointer_to_array_of_pointers_to_stack */
            	2299, 0,
            	127, 20,
            0, 8, 1, /* 2299: pointer.ASN1_TYPE */
            	2304, 0,
            0, 0, 1, /* 2304: ASN1_TYPE */
            	2309, 0,
            0, 16, 1, /* 2309: struct.asn1_type_st */
            	2314, 8,
            0, 8, 20, /* 2314: union.unknown */
            	36, 0,
            	2357, 0,
            	2367, 0,
            	2381, 0,
            	2386, 0,
            	2391, 0,
            	2396, 0,
            	2401, 0,
            	2406, 0,
            	2411, 0,
            	2416, 0,
            	2421, 0,
            	2426, 0,
            	2431, 0,
            	2436, 0,
            	2441, 0,
            	2446, 0,
            	2357, 0,
            	2357, 0,
            	2451, 0,
            1, 8, 1, /* 2357: pointer.struct.asn1_string_st */
            	2362, 0,
            0, 24, 1, /* 2362: struct.asn1_string_st */
            	23, 8,
            1, 8, 1, /* 2367: pointer.struct.asn1_object_st */
            	2372, 0,
            0, 40, 3, /* 2372: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	112, 24,
            1, 8, 1, /* 2381: pointer.struct.asn1_string_st */
            	2362, 0,
            1, 8, 1, /* 2386: pointer.struct.asn1_string_st */
            	2362, 0,
            1, 8, 1, /* 2391: pointer.struct.asn1_string_st */
            	2362, 0,
            1, 8, 1, /* 2396: pointer.struct.asn1_string_st */
            	2362, 0,
            1, 8, 1, /* 2401: pointer.struct.asn1_string_st */
            	2362, 0,
            1, 8, 1, /* 2406: pointer.struct.asn1_string_st */
            	2362, 0,
            1, 8, 1, /* 2411: pointer.struct.asn1_string_st */
            	2362, 0,
            1, 8, 1, /* 2416: pointer.struct.asn1_string_st */
            	2362, 0,
            1, 8, 1, /* 2421: pointer.struct.asn1_string_st */
            	2362, 0,
            1, 8, 1, /* 2426: pointer.struct.asn1_string_st */
            	2362, 0,
            1, 8, 1, /* 2431: pointer.struct.asn1_string_st */
            	2362, 0,
            1, 8, 1, /* 2436: pointer.struct.asn1_string_st */
            	2362, 0,
            1, 8, 1, /* 2441: pointer.struct.asn1_string_st */
            	2362, 0,
            1, 8, 1, /* 2446: pointer.struct.asn1_string_st */
            	2362, 0,
            1, 8, 1, /* 2451: pointer.struct.ASN1_VALUE_st */
            	2456, 0,
            0, 0, 0, /* 2456: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2459: pointer.struct.asn1_type_st */
            	2464, 0,
            0, 16, 1, /* 2464: struct.asn1_type_st */
            	2469, 8,
            0, 8, 20, /* 2469: union.unknown */
            	36, 0,
            	2512, 0,
            	2257, 0,
            	2522, 0,
            	2527, 0,
            	2532, 0,
            	2537, 0,
            	2542, 0,
            	2547, 0,
            	2552, 0,
            	2557, 0,
            	2562, 0,
            	2567, 0,
            	2572, 0,
            	2577, 0,
            	2582, 0,
            	2587, 0,
            	2512, 0,
            	2512, 0,
            	2592, 0,
            1, 8, 1, /* 2512: pointer.struct.asn1_string_st */
            	2517, 0,
            0, 24, 1, /* 2517: struct.asn1_string_st */
            	23, 8,
            1, 8, 1, /* 2522: pointer.struct.asn1_string_st */
            	2517, 0,
            1, 8, 1, /* 2527: pointer.struct.asn1_string_st */
            	2517, 0,
            1, 8, 1, /* 2532: pointer.struct.asn1_string_st */
            	2517, 0,
            1, 8, 1, /* 2537: pointer.struct.asn1_string_st */
            	2517, 0,
            1, 8, 1, /* 2542: pointer.struct.asn1_string_st */
            	2517, 0,
            1, 8, 1, /* 2547: pointer.struct.asn1_string_st */
            	2517, 0,
            1, 8, 1, /* 2552: pointer.struct.asn1_string_st */
            	2517, 0,
            1, 8, 1, /* 2557: pointer.struct.asn1_string_st */
            	2517, 0,
            1, 8, 1, /* 2562: pointer.struct.asn1_string_st */
            	2517, 0,
            1, 8, 1, /* 2567: pointer.struct.asn1_string_st */
            	2517, 0,
            1, 8, 1, /* 2572: pointer.struct.asn1_string_st */
            	2517, 0,
            1, 8, 1, /* 2577: pointer.struct.asn1_string_st */
            	2517, 0,
            1, 8, 1, /* 2582: pointer.struct.asn1_string_st */
            	2517, 0,
            1, 8, 1, /* 2587: pointer.struct.asn1_string_st */
            	2517, 0,
            1, 8, 1, /* 2592: pointer.struct.ASN1_VALUE_st */
            	2597, 0,
            0, 0, 0, /* 2597: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2600: pointer.struct.asn1_string_st */
            	541, 0,
            1, 8, 1, /* 2605: pointer.struct.stack_st_X509_EXTENSION */
            	2610, 0,
            0, 32, 2, /* 2610: struct.stack_st_fake_X509_EXTENSION */
            	2617, 8,
            	130, 24,
            8884099, 8, 2, /* 2617: pointer_to_array_of_pointers_to_stack */
            	2624, 0,
            	127, 20,
            0, 8, 1, /* 2624: pointer.X509_EXTENSION */
            	2629, 0,
            0, 0, 1, /* 2629: X509_EXTENSION */
            	2634, 0,
            0, 24, 2, /* 2634: struct.X509_extension_st */
            	2641, 0,
            	2655, 16,
            1, 8, 1, /* 2641: pointer.struct.asn1_object_st */
            	2646, 0,
            0, 40, 3, /* 2646: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	112, 24,
            1, 8, 1, /* 2655: pointer.struct.asn1_string_st */
            	2660, 0,
            0, 24, 1, /* 2660: struct.asn1_string_st */
            	23, 8,
            0, 24, 1, /* 2665: struct.ASN1_ENCODING_st */
            	23, 0,
            0, 16, 1, /* 2670: struct.crypto_ex_data_st */
            	2675, 0,
            1, 8, 1, /* 2675: pointer.struct.stack_st_void */
            	2680, 0,
            0, 32, 1, /* 2680: struct.stack_st_void */
            	2685, 0,
            0, 32, 2, /* 2685: struct.stack_st */
            	1267, 8,
            	130, 24,
            1, 8, 1, /* 2692: pointer.struct.asn1_string_st */
            	541, 0,
            1, 8, 1, /* 2697: pointer.struct.AUTHORITY_KEYID_st */
            	2702, 0,
            0, 24, 3, /* 2702: struct.AUTHORITY_KEYID_st */
            	2711, 0,
            	2721, 8,
            	3015, 16,
            1, 8, 1, /* 2711: pointer.struct.asn1_string_st */
            	2716, 0,
            0, 24, 1, /* 2716: struct.asn1_string_st */
            	23, 8,
            1, 8, 1, /* 2721: pointer.struct.stack_st_GENERAL_NAME */
            	2726, 0,
            0, 32, 2, /* 2726: struct.stack_st_fake_GENERAL_NAME */
            	2733, 8,
            	130, 24,
            8884099, 8, 2, /* 2733: pointer_to_array_of_pointers_to_stack */
            	2740, 0,
            	127, 20,
            0, 8, 1, /* 2740: pointer.GENERAL_NAME */
            	2745, 0,
            0, 0, 1, /* 2745: GENERAL_NAME */
            	2750, 0,
            0, 16, 1, /* 2750: struct.GENERAL_NAME_st */
            	2755, 8,
            0, 8, 15, /* 2755: union.unknown */
            	36, 0,
            	2788, 0,
            	2907, 0,
            	2907, 0,
            	2814, 0,
            	2955, 0,
            	3003, 0,
            	2907, 0,
            	2892, 0,
            	2800, 0,
            	2892, 0,
            	2955, 0,
            	2907, 0,
            	2800, 0,
            	2814, 0,
            1, 8, 1, /* 2788: pointer.struct.otherName_st */
            	2793, 0,
            0, 16, 2, /* 2793: struct.otherName_st */
            	2800, 0,
            	2814, 8,
            1, 8, 1, /* 2800: pointer.struct.asn1_object_st */
            	2805, 0,
            0, 40, 3, /* 2805: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	112, 24,
            1, 8, 1, /* 2814: pointer.struct.asn1_type_st */
            	2819, 0,
            0, 16, 1, /* 2819: struct.asn1_type_st */
            	2824, 8,
            0, 8, 20, /* 2824: union.unknown */
            	36, 0,
            	2867, 0,
            	2800, 0,
            	2877, 0,
            	2882, 0,
            	2887, 0,
            	2892, 0,
            	2897, 0,
            	2902, 0,
            	2907, 0,
            	2912, 0,
            	2917, 0,
            	2922, 0,
            	2927, 0,
            	2932, 0,
            	2937, 0,
            	2942, 0,
            	2867, 0,
            	2867, 0,
            	2947, 0,
            1, 8, 1, /* 2867: pointer.struct.asn1_string_st */
            	2872, 0,
            0, 24, 1, /* 2872: struct.asn1_string_st */
            	23, 8,
            1, 8, 1, /* 2877: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 2882: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 2887: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 2892: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 2897: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 2902: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 2907: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 2912: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 2917: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 2922: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 2927: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 2932: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 2937: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 2942: pointer.struct.asn1_string_st */
            	2872, 0,
            1, 8, 1, /* 2947: pointer.struct.ASN1_VALUE_st */
            	2952, 0,
            0, 0, 0, /* 2952: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2955: pointer.struct.X509_name_st */
            	2960, 0,
            0, 40, 3, /* 2960: struct.X509_name_st */
            	2969, 0,
            	2993, 16,
            	23, 24,
            1, 8, 1, /* 2969: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2974, 0,
            0, 32, 2, /* 2974: struct.stack_st_fake_X509_NAME_ENTRY */
            	2981, 8,
            	130, 24,
            8884099, 8, 2, /* 2981: pointer_to_array_of_pointers_to_stack */
            	2988, 0,
            	127, 20,
            0, 8, 1, /* 2988: pointer.X509_NAME_ENTRY */
            	86, 0,
            1, 8, 1, /* 2993: pointer.struct.buf_mem_st */
            	2998, 0,
            0, 24, 1, /* 2998: struct.buf_mem_st */
            	36, 8,
            1, 8, 1, /* 3003: pointer.struct.EDIPartyName_st */
            	3008, 0,
            0, 16, 2, /* 3008: struct.EDIPartyName_st */
            	2867, 0,
            	2867, 8,
            1, 8, 1, /* 3015: pointer.struct.asn1_string_st */
            	2716, 0,
            1, 8, 1, /* 3020: pointer.struct.X509_POLICY_CACHE_st */
            	3025, 0,
            0, 40, 2, /* 3025: struct.X509_POLICY_CACHE_st */
            	3032, 0,
            	3342, 8,
            1, 8, 1, /* 3032: pointer.struct.X509_POLICY_DATA_st */
            	3037, 0,
            0, 32, 3, /* 3037: struct.X509_POLICY_DATA_st */
            	3046, 8,
            	3060, 16,
            	3318, 24,
            1, 8, 1, /* 3046: pointer.struct.asn1_object_st */
            	3051, 0,
            0, 40, 3, /* 3051: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	112, 24,
            1, 8, 1, /* 3060: pointer.struct.stack_st_POLICYQUALINFO */
            	3065, 0,
            0, 32, 2, /* 3065: struct.stack_st_fake_POLICYQUALINFO */
            	3072, 8,
            	130, 24,
            8884099, 8, 2, /* 3072: pointer_to_array_of_pointers_to_stack */
            	3079, 0,
            	127, 20,
            0, 8, 1, /* 3079: pointer.POLICYQUALINFO */
            	3084, 0,
            0, 0, 1, /* 3084: POLICYQUALINFO */
            	3089, 0,
            0, 16, 2, /* 3089: struct.POLICYQUALINFO_st */
            	3096, 0,
            	3110, 8,
            1, 8, 1, /* 3096: pointer.struct.asn1_object_st */
            	3101, 0,
            0, 40, 3, /* 3101: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	112, 24,
            0, 8, 3, /* 3110: union.unknown */
            	3119, 0,
            	3129, 0,
            	3192, 0,
            1, 8, 1, /* 3119: pointer.struct.asn1_string_st */
            	3124, 0,
            0, 24, 1, /* 3124: struct.asn1_string_st */
            	23, 8,
            1, 8, 1, /* 3129: pointer.struct.USERNOTICE_st */
            	3134, 0,
            0, 16, 2, /* 3134: struct.USERNOTICE_st */
            	3141, 0,
            	3153, 8,
            1, 8, 1, /* 3141: pointer.struct.NOTICEREF_st */
            	3146, 0,
            0, 16, 2, /* 3146: struct.NOTICEREF_st */
            	3153, 0,
            	3158, 8,
            1, 8, 1, /* 3153: pointer.struct.asn1_string_st */
            	3124, 0,
            1, 8, 1, /* 3158: pointer.struct.stack_st_ASN1_INTEGER */
            	3163, 0,
            0, 32, 2, /* 3163: struct.stack_st_fake_ASN1_INTEGER */
            	3170, 8,
            	130, 24,
            8884099, 8, 2, /* 3170: pointer_to_array_of_pointers_to_stack */
            	3177, 0,
            	127, 20,
            0, 8, 1, /* 3177: pointer.ASN1_INTEGER */
            	3182, 0,
            0, 0, 1, /* 3182: ASN1_INTEGER */
            	3187, 0,
            0, 24, 1, /* 3187: struct.asn1_string_st */
            	23, 8,
            1, 8, 1, /* 3192: pointer.struct.asn1_type_st */
            	3197, 0,
            0, 16, 1, /* 3197: struct.asn1_type_st */
            	3202, 8,
            0, 8, 20, /* 3202: union.unknown */
            	36, 0,
            	3153, 0,
            	3096, 0,
            	3245, 0,
            	3250, 0,
            	3255, 0,
            	3260, 0,
            	3265, 0,
            	3270, 0,
            	3119, 0,
            	3275, 0,
            	3280, 0,
            	3285, 0,
            	3290, 0,
            	3295, 0,
            	3300, 0,
            	3305, 0,
            	3153, 0,
            	3153, 0,
            	3310, 0,
            1, 8, 1, /* 3245: pointer.struct.asn1_string_st */
            	3124, 0,
            1, 8, 1, /* 3250: pointer.struct.asn1_string_st */
            	3124, 0,
            1, 8, 1, /* 3255: pointer.struct.asn1_string_st */
            	3124, 0,
            1, 8, 1, /* 3260: pointer.struct.asn1_string_st */
            	3124, 0,
            1, 8, 1, /* 3265: pointer.struct.asn1_string_st */
            	3124, 0,
            1, 8, 1, /* 3270: pointer.struct.asn1_string_st */
            	3124, 0,
            1, 8, 1, /* 3275: pointer.struct.asn1_string_st */
            	3124, 0,
            1, 8, 1, /* 3280: pointer.struct.asn1_string_st */
            	3124, 0,
            1, 8, 1, /* 3285: pointer.struct.asn1_string_st */
            	3124, 0,
            1, 8, 1, /* 3290: pointer.struct.asn1_string_st */
            	3124, 0,
            1, 8, 1, /* 3295: pointer.struct.asn1_string_st */
            	3124, 0,
            1, 8, 1, /* 3300: pointer.struct.asn1_string_st */
            	3124, 0,
            1, 8, 1, /* 3305: pointer.struct.asn1_string_st */
            	3124, 0,
            1, 8, 1, /* 3310: pointer.struct.ASN1_VALUE_st */
            	3315, 0,
            0, 0, 0, /* 3315: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3318: pointer.struct.stack_st_ASN1_OBJECT */
            	3323, 0,
            0, 32, 2, /* 3323: struct.stack_st_fake_ASN1_OBJECT */
            	3330, 8,
            	130, 24,
            8884099, 8, 2, /* 3330: pointer_to_array_of_pointers_to_stack */
            	3337, 0,
            	127, 20,
            0, 8, 1, /* 3337: pointer.ASN1_OBJECT */
            	415, 0,
            1, 8, 1, /* 3342: pointer.struct.stack_st_X509_POLICY_DATA */
            	3347, 0,
            0, 32, 2, /* 3347: struct.stack_st_fake_X509_POLICY_DATA */
            	3354, 8,
            	130, 24,
            8884099, 8, 2, /* 3354: pointer_to_array_of_pointers_to_stack */
            	3361, 0,
            	127, 20,
            0, 8, 1, /* 3361: pointer.X509_POLICY_DATA */
            	3366, 0,
            0, 0, 1, /* 3366: X509_POLICY_DATA */
            	3371, 0,
            0, 32, 3, /* 3371: struct.X509_POLICY_DATA_st */
            	3380, 8,
            	3394, 16,
            	3418, 24,
            1, 8, 1, /* 3380: pointer.struct.asn1_object_st */
            	3385, 0,
            0, 40, 3, /* 3385: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	112, 24,
            1, 8, 1, /* 3394: pointer.struct.stack_st_POLICYQUALINFO */
            	3399, 0,
            0, 32, 2, /* 3399: struct.stack_st_fake_POLICYQUALINFO */
            	3406, 8,
            	130, 24,
            8884099, 8, 2, /* 3406: pointer_to_array_of_pointers_to_stack */
            	3413, 0,
            	127, 20,
            0, 8, 1, /* 3413: pointer.POLICYQUALINFO */
            	3084, 0,
            1, 8, 1, /* 3418: pointer.struct.stack_st_ASN1_OBJECT */
            	3423, 0,
            0, 32, 2, /* 3423: struct.stack_st_fake_ASN1_OBJECT */
            	3430, 8,
            	130, 24,
            8884099, 8, 2, /* 3430: pointer_to_array_of_pointers_to_stack */
            	3437, 0,
            	127, 20,
            0, 8, 1, /* 3437: pointer.ASN1_OBJECT */
            	415, 0,
            1, 8, 1, /* 3442: pointer.struct.stack_st_DIST_POINT */
            	3447, 0,
            0, 32, 2, /* 3447: struct.stack_st_fake_DIST_POINT */
            	3454, 8,
            	130, 24,
            8884099, 8, 2, /* 3454: pointer_to_array_of_pointers_to_stack */
            	3461, 0,
            	127, 20,
            0, 8, 1, /* 3461: pointer.DIST_POINT */
            	3466, 0,
            0, 0, 1, /* 3466: DIST_POINT */
            	3471, 0,
            0, 32, 3, /* 3471: struct.DIST_POINT_st */
            	3480, 0,
            	3571, 8,
            	3499, 16,
            1, 8, 1, /* 3480: pointer.struct.DIST_POINT_NAME_st */
            	3485, 0,
            0, 24, 2, /* 3485: struct.DIST_POINT_NAME_st */
            	3492, 8,
            	3547, 16,
            0, 8, 2, /* 3492: union.unknown */
            	3499, 0,
            	3523, 0,
            1, 8, 1, /* 3499: pointer.struct.stack_st_GENERAL_NAME */
            	3504, 0,
            0, 32, 2, /* 3504: struct.stack_st_fake_GENERAL_NAME */
            	3511, 8,
            	130, 24,
            8884099, 8, 2, /* 3511: pointer_to_array_of_pointers_to_stack */
            	3518, 0,
            	127, 20,
            0, 8, 1, /* 3518: pointer.GENERAL_NAME */
            	2745, 0,
            1, 8, 1, /* 3523: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3528, 0,
            0, 32, 2, /* 3528: struct.stack_st_fake_X509_NAME_ENTRY */
            	3535, 8,
            	130, 24,
            8884099, 8, 2, /* 3535: pointer_to_array_of_pointers_to_stack */
            	3542, 0,
            	127, 20,
            0, 8, 1, /* 3542: pointer.X509_NAME_ENTRY */
            	86, 0,
            1, 8, 1, /* 3547: pointer.struct.X509_name_st */
            	3552, 0,
            0, 40, 3, /* 3552: struct.X509_name_st */
            	3523, 0,
            	3561, 16,
            	23, 24,
            1, 8, 1, /* 3561: pointer.struct.buf_mem_st */
            	3566, 0,
            0, 24, 1, /* 3566: struct.buf_mem_st */
            	36, 8,
            1, 8, 1, /* 3571: pointer.struct.asn1_string_st */
            	3576, 0,
            0, 24, 1, /* 3576: struct.asn1_string_st */
            	23, 8,
            1, 8, 1, /* 3581: pointer.struct.stack_st_GENERAL_NAME */
            	3586, 0,
            0, 32, 2, /* 3586: struct.stack_st_fake_GENERAL_NAME */
            	3593, 8,
            	130, 24,
            8884099, 8, 2, /* 3593: pointer_to_array_of_pointers_to_stack */
            	3600, 0,
            	127, 20,
            0, 8, 1, /* 3600: pointer.GENERAL_NAME */
            	2745, 0,
            1, 8, 1, /* 3605: pointer.struct.NAME_CONSTRAINTS_st */
            	3610, 0,
            0, 16, 2, /* 3610: struct.NAME_CONSTRAINTS_st */
            	3617, 0,
            	3617, 8,
            1, 8, 1, /* 3617: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3622, 0,
            0, 32, 2, /* 3622: struct.stack_st_fake_GENERAL_SUBTREE */
            	3629, 8,
            	130, 24,
            8884099, 8, 2, /* 3629: pointer_to_array_of_pointers_to_stack */
            	3636, 0,
            	127, 20,
            0, 8, 1, /* 3636: pointer.GENERAL_SUBTREE */
            	3641, 0,
            0, 0, 1, /* 3641: GENERAL_SUBTREE */
            	3646, 0,
            0, 24, 3, /* 3646: struct.GENERAL_SUBTREE_st */
            	3655, 0,
            	3787, 8,
            	3787, 16,
            1, 8, 1, /* 3655: pointer.struct.GENERAL_NAME_st */
            	3660, 0,
            0, 16, 1, /* 3660: struct.GENERAL_NAME_st */
            	3665, 8,
            0, 8, 15, /* 3665: union.unknown */
            	36, 0,
            	3698, 0,
            	3817, 0,
            	3817, 0,
            	3724, 0,
            	3857, 0,
            	3905, 0,
            	3817, 0,
            	3802, 0,
            	3710, 0,
            	3802, 0,
            	3857, 0,
            	3817, 0,
            	3710, 0,
            	3724, 0,
            1, 8, 1, /* 3698: pointer.struct.otherName_st */
            	3703, 0,
            0, 16, 2, /* 3703: struct.otherName_st */
            	3710, 0,
            	3724, 8,
            1, 8, 1, /* 3710: pointer.struct.asn1_object_st */
            	3715, 0,
            0, 40, 3, /* 3715: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	112, 24,
            1, 8, 1, /* 3724: pointer.struct.asn1_type_st */
            	3729, 0,
            0, 16, 1, /* 3729: struct.asn1_type_st */
            	3734, 8,
            0, 8, 20, /* 3734: union.unknown */
            	36, 0,
            	3777, 0,
            	3710, 0,
            	3787, 0,
            	3792, 0,
            	3797, 0,
            	3802, 0,
            	3807, 0,
            	3812, 0,
            	3817, 0,
            	3822, 0,
            	3827, 0,
            	3832, 0,
            	3837, 0,
            	3842, 0,
            	3847, 0,
            	3852, 0,
            	3777, 0,
            	3777, 0,
            	3310, 0,
            1, 8, 1, /* 3777: pointer.struct.asn1_string_st */
            	3782, 0,
            0, 24, 1, /* 3782: struct.asn1_string_st */
            	23, 8,
            1, 8, 1, /* 3787: pointer.struct.asn1_string_st */
            	3782, 0,
            1, 8, 1, /* 3792: pointer.struct.asn1_string_st */
            	3782, 0,
            1, 8, 1, /* 3797: pointer.struct.asn1_string_st */
            	3782, 0,
            1, 8, 1, /* 3802: pointer.struct.asn1_string_st */
            	3782, 0,
            1, 8, 1, /* 3807: pointer.struct.asn1_string_st */
            	3782, 0,
            1, 8, 1, /* 3812: pointer.struct.asn1_string_st */
            	3782, 0,
            1, 8, 1, /* 3817: pointer.struct.asn1_string_st */
            	3782, 0,
            1, 8, 1, /* 3822: pointer.struct.asn1_string_st */
            	3782, 0,
            1, 8, 1, /* 3827: pointer.struct.asn1_string_st */
            	3782, 0,
            1, 8, 1, /* 3832: pointer.struct.asn1_string_st */
            	3782, 0,
            1, 8, 1, /* 3837: pointer.struct.asn1_string_st */
            	3782, 0,
            1, 8, 1, /* 3842: pointer.struct.asn1_string_st */
            	3782, 0,
            1, 8, 1, /* 3847: pointer.struct.asn1_string_st */
            	3782, 0,
            1, 8, 1, /* 3852: pointer.struct.asn1_string_st */
            	3782, 0,
            1, 8, 1, /* 3857: pointer.struct.X509_name_st */
            	3862, 0,
            0, 40, 3, /* 3862: struct.X509_name_st */
            	3871, 0,
            	3895, 16,
            	23, 24,
            1, 8, 1, /* 3871: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3876, 0,
            0, 32, 2, /* 3876: struct.stack_st_fake_X509_NAME_ENTRY */
            	3883, 8,
            	130, 24,
            8884099, 8, 2, /* 3883: pointer_to_array_of_pointers_to_stack */
            	3890, 0,
            	127, 20,
            0, 8, 1, /* 3890: pointer.X509_NAME_ENTRY */
            	86, 0,
            1, 8, 1, /* 3895: pointer.struct.buf_mem_st */
            	3900, 0,
            0, 24, 1, /* 3900: struct.buf_mem_st */
            	36, 8,
            1, 8, 1, /* 3905: pointer.struct.EDIPartyName_st */
            	3910, 0,
            0, 16, 2, /* 3910: struct.EDIPartyName_st */
            	3777, 0,
            	3777, 8,
            1, 8, 1, /* 3917: pointer.struct.x509_cert_aux_st */
            	3922, 0,
            0, 40, 5, /* 3922: struct.x509_cert_aux_st */
            	391, 0,
            	391, 8,
            	3935, 16,
            	2692, 24,
            	3940, 32,
            1, 8, 1, /* 3935: pointer.struct.asn1_string_st */
            	541, 0,
            1, 8, 1, /* 3940: pointer.struct.stack_st_X509_ALGOR */
            	3945, 0,
            0, 32, 2, /* 3945: struct.stack_st_fake_X509_ALGOR */
            	3952, 8,
            	130, 24,
            8884099, 8, 2, /* 3952: pointer_to_array_of_pointers_to_stack */
            	3959, 0,
            	127, 20,
            0, 8, 1, /* 3959: pointer.X509_ALGOR */
            	3964, 0,
            0, 0, 1, /* 3964: X509_ALGOR */
            	551, 0,
            1, 8, 1, /* 3969: pointer.struct.X509_crl_st */
            	3974, 0,
            0, 120, 10, /* 3974: struct.X509_crl_st */
            	3997, 0,
            	546, 8,
            	2600, 16,
            	2697, 32,
            	4124, 40,
            	536, 56,
            	536, 64,
            	4136, 96,
            	4177, 104,
            	15, 112,
            1, 8, 1, /* 3997: pointer.struct.X509_crl_info_st */
            	4002, 0,
            0, 80, 8, /* 4002: struct.X509_crl_info_st */
            	536, 0,
            	546, 8,
            	713, 16,
            	773, 24,
            	773, 32,
            	4021, 40,
            	2605, 48,
            	2665, 56,
            1, 8, 1, /* 4021: pointer.struct.stack_st_X509_REVOKED */
            	4026, 0,
            0, 32, 2, /* 4026: struct.stack_st_fake_X509_REVOKED */
            	4033, 8,
            	130, 24,
            8884099, 8, 2, /* 4033: pointer_to_array_of_pointers_to_stack */
            	4040, 0,
            	127, 20,
            0, 8, 1, /* 4040: pointer.X509_REVOKED */
            	4045, 0,
            0, 0, 1, /* 4045: X509_REVOKED */
            	4050, 0,
            0, 40, 4, /* 4050: struct.x509_revoked_st */
            	4061, 0,
            	4071, 8,
            	4076, 16,
            	4100, 24,
            1, 8, 1, /* 4061: pointer.struct.asn1_string_st */
            	4066, 0,
            0, 24, 1, /* 4066: struct.asn1_string_st */
            	23, 8,
            1, 8, 1, /* 4071: pointer.struct.asn1_string_st */
            	4066, 0,
            1, 8, 1, /* 4076: pointer.struct.stack_st_X509_EXTENSION */
            	4081, 0,
            0, 32, 2, /* 4081: struct.stack_st_fake_X509_EXTENSION */
            	4088, 8,
            	130, 24,
            8884099, 8, 2, /* 4088: pointer_to_array_of_pointers_to_stack */
            	4095, 0,
            	127, 20,
            0, 8, 1, /* 4095: pointer.X509_EXTENSION */
            	2629, 0,
            1, 8, 1, /* 4100: pointer.struct.stack_st_GENERAL_NAME */
            	4105, 0,
            0, 32, 2, /* 4105: struct.stack_st_fake_GENERAL_NAME */
            	4112, 8,
            	130, 24,
            8884099, 8, 2, /* 4112: pointer_to_array_of_pointers_to_stack */
            	4119, 0,
            	127, 20,
            0, 8, 1, /* 4119: pointer.GENERAL_NAME */
            	2745, 0,
            1, 8, 1, /* 4124: pointer.struct.ISSUING_DIST_POINT_st */
            	4129, 0,
            0, 32, 2, /* 4129: struct.ISSUING_DIST_POINT_st */
            	3480, 0,
            	3571, 16,
            1, 8, 1, /* 4136: pointer.struct.stack_st_GENERAL_NAMES */
            	4141, 0,
            0, 32, 2, /* 4141: struct.stack_st_fake_GENERAL_NAMES */
            	4148, 8,
            	130, 24,
            8884099, 8, 2, /* 4148: pointer_to_array_of_pointers_to_stack */
            	4155, 0,
            	127, 20,
            0, 8, 1, /* 4155: pointer.GENERAL_NAMES */
            	4160, 0,
            0, 0, 1, /* 4160: GENERAL_NAMES */
            	4165, 0,
            0, 32, 1, /* 4165: struct.stack_st_GENERAL_NAME */
            	4170, 0,
            0, 32, 2, /* 4170: struct.stack_st */
            	1267, 8,
            	130, 24,
            1, 8, 1, /* 4177: pointer.struct.x509_crl_method_st */
            	4182, 0,
            0, 40, 4, /* 4182: struct.x509_crl_method_st */
            	4193, 8,
            	4193, 16,
            	4196, 24,
            	4199, 32,
            8884097, 8, 0, /* 4193: pointer.func */
            8884097, 8, 0, /* 4196: pointer.func */
            8884097, 8, 0, /* 4199: pointer.func */
            1, 8, 1, /* 4202: pointer.struct.evp_pkey_st */
            	4207, 0,
            0, 56, 4, /* 4207: struct.evp_pkey_st */
            	4218, 16,
            	1387, 24,
            	4223, 32,
            	4256, 48,
            1, 8, 1, /* 4218: pointer.struct.evp_pkey_asn1_method_st */
            	828, 0,
            0, 8, 5, /* 4223: union.unknown */
            	36, 0,
            	4236, 0,
            	4241, 0,
            	4246, 0,
            	4251, 0,
            1, 8, 1, /* 4236: pointer.struct.rsa_st */
            	1295, 0,
            1, 8, 1, /* 4241: pointer.struct.dsa_st */
            	1497, 0,
            1, 8, 1, /* 4246: pointer.struct.dh_st */
            	1624, 0,
            1, 8, 1, /* 4251: pointer.struct.ec_key_st */
            	1738, 0,
            1, 8, 1, /* 4256: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4261, 0,
            0, 32, 2, /* 4261: struct.stack_st_fake_X509_ATTRIBUTE */
            	4268, 8,
            	130, 24,
            8884099, 8, 2, /* 4268: pointer_to_array_of_pointers_to_stack */
            	4275, 0,
            	127, 20,
            0, 8, 1, /* 4275: pointer.X509_ATTRIBUTE */
            	2245, 0,
            8884097, 8, 0, /* 4280: pointer.func */
            8884097, 8, 0, /* 4283: pointer.func */
            8884097, 8, 0, /* 4286: pointer.func */
            0, 0, 1, /* 4289: X509_LOOKUP */
            	4294, 0,
            0, 32, 3, /* 4294: struct.x509_lookup_st */
            	4303, 8,
            	36, 16,
            	4346, 24,
            1, 8, 1, /* 4303: pointer.struct.x509_lookup_method_st */
            	4308, 0,
            0, 80, 10, /* 4308: struct.x509_lookup_method_st */
            	5, 0,
            	4331, 8,
            	4286, 16,
            	4331, 24,
            	4331, 32,
            	4334, 40,
            	4337, 48,
            	4280, 56,
            	4340, 64,
            	4343, 72,
            8884097, 8, 0, /* 4331: pointer.func */
            8884097, 8, 0, /* 4334: pointer.func */
            8884097, 8, 0, /* 4337: pointer.func */
            8884097, 8, 0, /* 4340: pointer.func */
            8884097, 8, 0, /* 4343: pointer.func */
            1, 8, 1, /* 4346: pointer.struct.x509_store_st */
            	4351, 0,
            0, 144, 15, /* 4351: struct.x509_store_st */
            	429, 8,
            	4384, 16,
            	379, 24,
            	376, 32,
            	4408, 40,
            	4411, 48,
            	373, 56,
            	376, 64,
            	4414, 72,
            	370, 80,
            	4417, 88,
            	367, 96,
            	364, 104,
            	376, 112,
            	2670, 120,
            1, 8, 1, /* 4384: pointer.struct.stack_st_X509_LOOKUP */
            	4389, 0,
            0, 32, 2, /* 4389: struct.stack_st_fake_X509_LOOKUP */
            	4396, 8,
            	130, 24,
            8884099, 8, 2, /* 4396: pointer_to_array_of_pointers_to_stack */
            	4403, 0,
            	127, 20,
            0, 8, 1, /* 4403: pointer.X509_LOOKUP */
            	4289, 0,
            8884097, 8, 0, /* 4408: pointer.func */
            8884097, 8, 0, /* 4411: pointer.func */
            8884097, 8, 0, /* 4414: pointer.func */
            8884097, 8, 0, /* 4417: pointer.func */
            1, 8, 1, /* 4420: pointer.struct.stack_st_X509_LOOKUP */
            	4425, 0,
            0, 32, 2, /* 4425: struct.stack_st_fake_X509_LOOKUP */
            	4432, 8,
            	130, 24,
            8884099, 8, 2, /* 4432: pointer_to_array_of_pointers_to_stack */
            	4439, 0,
            	127, 20,
            0, 8, 1, /* 4439: pointer.X509_LOOKUP */
            	4289, 0,
            8884097, 8, 0, /* 4444: pointer.func */
            8884097, 8, 0, /* 4447: pointer.func */
            0, 16, 1, /* 4450: struct.srtp_protection_profile_st */
            	5, 0,
            1, 8, 1, /* 4455: pointer.struct.stack_st_X509 */
            	4460, 0,
            0, 32, 2, /* 4460: struct.stack_st_fake_X509 */
            	4467, 8,
            	130, 24,
            8884099, 8, 2, /* 4467: pointer_to_array_of_pointers_to_stack */
            	4474, 0,
            	127, 20,
            0, 8, 1, /* 4474: pointer.X509 */
            	4479, 0,
            0, 0, 1, /* 4479: X509 */
            	4484, 0,
            0, 184, 12, /* 4484: struct.x509_st */
            	4511, 0,
            	4551, 8,
            	4626, 16,
            	36, 32,
            	1546, 40,
            	4660, 104,
            	4665, 112,
            	4670, 120,
            	4675, 128,
            	4100, 136,
            	4699, 144,
            	4704, 176,
            1, 8, 1, /* 4511: pointer.struct.x509_cinf_st */
            	4516, 0,
            0, 104, 11, /* 4516: struct.x509_cinf_st */
            	4541, 0,
            	4541, 8,
            	4551, 16,
            	4556, 24,
            	4604, 32,
            	4556, 40,
            	4621, 48,
            	4626, 56,
            	4626, 64,
            	4631, 72,
            	4655, 80,
            1, 8, 1, /* 4541: pointer.struct.asn1_string_st */
            	4546, 0,
            0, 24, 1, /* 4546: struct.asn1_string_st */
            	23, 8,
            1, 8, 1, /* 4551: pointer.struct.X509_algor_st */
            	551, 0,
            1, 8, 1, /* 4556: pointer.struct.X509_name_st */
            	4561, 0,
            0, 40, 3, /* 4561: struct.X509_name_st */
            	4570, 0,
            	4594, 16,
            	23, 24,
            1, 8, 1, /* 4570: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4575, 0,
            0, 32, 2, /* 4575: struct.stack_st_fake_X509_NAME_ENTRY */
            	4582, 8,
            	130, 24,
            8884099, 8, 2, /* 4582: pointer_to_array_of_pointers_to_stack */
            	4589, 0,
            	127, 20,
            0, 8, 1, /* 4589: pointer.X509_NAME_ENTRY */
            	86, 0,
            1, 8, 1, /* 4594: pointer.struct.buf_mem_st */
            	4599, 0,
            0, 24, 1, /* 4599: struct.buf_mem_st */
            	36, 8,
            1, 8, 1, /* 4604: pointer.struct.X509_val_st */
            	4609, 0,
            0, 16, 2, /* 4609: struct.X509_val_st */
            	4616, 0,
            	4616, 8,
            1, 8, 1, /* 4616: pointer.struct.asn1_string_st */
            	4546, 0,
            1, 8, 1, /* 4621: pointer.struct.X509_pubkey_st */
            	783, 0,
            1, 8, 1, /* 4626: pointer.struct.asn1_string_st */
            	4546, 0,
            1, 8, 1, /* 4631: pointer.struct.stack_st_X509_EXTENSION */
            	4636, 0,
            0, 32, 2, /* 4636: struct.stack_st_fake_X509_EXTENSION */
            	4643, 8,
            	130, 24,
            8884099, 8, 2, /* 4643: pointer_to_array_of_pointers_to_stack */
            	4650, 0,
            	127, 20,
            0, 8, 1, /* 4650: pointer.X509_EXTENSION */
            	2629, 0,
            0, 24, 1, /* 4655: struct.ASN1_ENCODING_st */
            	23, 0,
            1, 8, 1, /* 4660: pointer.struct.asn1_string_st */
            	4546, 0,
            1, 8, 1, /* 4665: pointer.struct.AUTHORITY_KEYID_st */
            	2702, 0,
            1, 8, 1, /* 4670: pointer.struct.X509_POLICY_CACHE_st */
            	3025, 0,
            1, 8, 1, /* 4675: pointer.struct.stack_st_DIST_POINT */
            	4680, 0,
            0, 32, 2, /* 4680: struct.stack_st_fake_DIST_POINT */
            	4687, 8,
            	130, 24,
            8884099, 8, 2, /* 4687: pointer_to_array_of_pointers_to_stack */
            	4694, 0,
            	127, 20,
            0, 8, 1, /* 4694: pointer.DIST_POINT */
            	3466, 0,
            1, 8, 1, /* 4699: pointer.struct.NAME_CONSTRAINTS_st */
            	3610, 0,
            1, 8, 1, /* 4704: pointer.struct.x509_cert_aux_st */
            	4709, 0,
            0, 40, 5, /* 4709: struct.x509_cert_aux_st */
            	4722, 0,
            	4722, 8,
            	4746, 16,
            	4660, 24,
            	4751, 32,
            1, 8, 1, /* 4722: pointer.struct.stack_st_ASN1_OBJECT */
            	4727, 0,
            0, 32, 2, /* 4727: struct.stack_st_fake_ASN1_OBJECT */
            	4734, 8,
            	130, 24,
            8884099, 8, 2, /* 4734: pointer_to_array_of_pointers_to_stack */
            	4741, 0,
            	127, 20,
            0, 8, 1, /* 4741: pointer.ASN1_OBJECT */
            	415, 0,
            1, 8, 1, /* 4746: pointer.struct.asn1_string_st */
            	4546, 0,
            1, 8, 1, /* 4751: pointer.struct.stack_st_X509_ALGOR */
            	4756, 0,
            0, 32, 2, /* 4756: struct.stack_st_fake_X509_ALGOR */
            	4763, 8,
            	130, 24,
            8884099, 8, 2, /* 4763: pointer_to_array_of_pointers_to_stack */
            	4770, 0,
            	127, 20,
            0, 8, 1, /* 4770: pointer.X509_ALGOR */
            	3964, 0,
            8884097, 8, 0, /* 4775: pointer.func */
            1, 8, 1, /* 4778: pointer.struct.x509_store_st */
            	4783, 0,
            0, 144, 15, /* 4783: struct.x509_store_st */
            	4816, 8,
            	4420, 16,
            	4840, 24,
            	361, 32,
            	4876, 40,
            	4879, 48,
            	4283, 56,
            	361, 64,
            	4882, 72,
            	4775, 80,
            	4885, 88,
            	358, 96,
            	355, 104,
            	361, 112,
            	4888, 120,
            1, 8, 1, /* 4816: pointer.struct.stack_st_X509_OBJECT */
            	4821, 0,
            0, 32, 2, /* 4821: struct.stack_st_fake_X509_OBJECT */
            	4828, 8,
            	130, 24,
            8884099, 8, 2, /* 4828: pointer_to_array_of_pointers_to_stack */
            	4835, 0,
            	127, 20,
            0, 8, 1, /* 4835: pointer.X509_OBJECT */
            	453, 0,
            1, 8, 1, /* 4840: pointer.struct.X509_VERIFY_PARAM_st */
            	4845, 0,
            0, 56, 2, /* 4845: struct.X509_VERIFY_PARAM_st */
            	36, 0,
            	4852, 48,
            1, 8, 1, /* 4852: pointer.struct.stack_st_ASN1_OBJECT */
            	4857, 0,
            0, 32, 2, /* 4857: struct.stack_st_fake_ASN1_OBJECT */
            	4864, 8,
            	130, 24,
            8884099, 8, 2, /* 4864: pointer_to_array_of_pointers_to_stack */
            	4871, 0,
            	127, 20,
            0, 8, 1, /* 4871: pointer.ASN1_OBJECT */
            	415, 0,
            8884097, 8, 0, /* 4876: pointer.func */
            8884097, 8, 0, /* 4879: pointer.func */
            8884097, 8, 0, /* 4882: pointer.func */
            8884097, 8, 0, /* 4885: pointer.func */
            0, 16, 1, /* 4888: struct.crypto_ex_data_st */
            	4893, 0,
            1, 8, 1, /* 4893: pointer.struct.stack_st_void */
            	4898, 0,
            0, 32, 1, /* 4898: struct.stack_st_void */
            	4903, 0,
            0, 32, 2, /* 4903: struct.stack_st */
            	1267, 8,
            	130, 24,
            0, 736, 50, /* 4910: struct.ssl_ctx_st */
            	5013, 0,
            	5179, 8,
            	5179, 16,
            	4778, 24,
            	331, 32,
            	5213, 48,
            	5213, 56,
            	6033, 80,
            	316, 88,
            	6036, 96,
            	313, 152,
            	15, 160,
            	310, 168,
            	15, 176,
            	6039, 184,
            	307, 192,
            	304, 200,
            	4888, 208,
            	6042, 224,
            	6042, 232,
            	6042, 240,
            	4455, 248,
            	280, 256,
            	6081, 264,
            	6084, 272,
            	6113, 304,
            	6554, 320,
            	15, 328,
            	4876, 376,
            	6557, 384,
            	4840, 392,
            	5668, 408,
            	202, 416,
            	15, 424,
            	4447, 480,
            	4444, 488,
            	15, 496,
            	6560, 504,
            	15, 512,
            	36, 520,
            	6563, 528,
            	6566, 536,
            	197, 552,
            	197, 560,
            	6569, 568,
            	161, 696,
            	15, 704,
            	158, 712,
            	15, 720,
            	251, 728,
            1, 8, 1, /* 5013: pointer.struct.ssl_method_st */
            	5018, 0,
            0, 232, 28, /* 5018: struct.ssl_method_st */
            	5077, 8,
            	5080, 16,
            	5080, 24,
            	5077, 32,
            	5077, 40,
            	5083, 48,
            	5083, 56,
            	5086, 64,
            	5077, 72,
            	5077, 80,
            	5077, 88,
            	5089, 96,
            	5092, 104,
            	5095, 112,
            	5077, 120,
            	5098, 128,
            	5101, 136,
            	5104, 144,
            	5107, 152,
            	5110, 160,
            	1198, 168,
            	5113, 176,
            	5116, 184,
            	231, 192,
            	5119, 200,
            	1198, 208,
            	5173, 216,
            	5176, 224,
            8884097, 8, 0, /* 5077: pointer.func */
            8884097, 8, 0, /* 5080: pointer.func */
            8884097, 8, 0, /* 5083: pointer.func */
            8884097, 8, 0, /* 5086: pointer.func */
            8884097, 8, 0, /* 5089: pointer.func */
            8884097, 8, 0, /* 5092: pointer.func */
            8884097, 8, 0, /* 5095: pointer.func */
            8884097, 8, 0, /* 5098: pointer.func */
            8884097, 8, 0, /* 5101: pointer.func */
            8884097, 8, 0, /* 5104: pointer.func */
            8884097, 8, 0, /* 5107: pointer.func */
            8884097, 8, 0, /* 5110: pointer.func */
            8884097, 8, 0, /* 5113: pointer.func */
            8884097, 8, 0, /* 5116: pointer.func */
            1, 8, 1, /* 5119: pointer.struct.ssl3_enc_method */
            	5124, 0,
            0, 112, 11, /* 5124: struct.ssl3_enc_method */
            	5149, 0,
            	5152, 8,
            	5155, 16,
            	5158, 24,
            	5149, 32,
            	5161, 40,
            	5164, 56,
            	5, 64,
            	5, 80,
            	5167, 96,
            	5170, 104,
            8884097, 8, 0, /* 5149: pointer.func */
            8884097, 8, 0, /* 5152: pointer.func */
            8884097, 8, 0, /* 5155: pointer.func */
            8884097, 8, 0, /* 5158: pointer.func */
            8884097, 8, 0, /* 5161: pointer.func */
            8884097, 8, 0, /* 5164: pointer.func */
            8884097, 8, 0, /* 5167: pointer.func */
            8884097, 8, 0, /* 5170: pointer.func */
            8884097, 8, 0, /* 5173: pointer.func */
            8884097, 8, 0, /* 5176: pointer.func */
            1, 8, 1, /* 5179: pointer.struct.stack_st_SSL_CIPHER */
            	5184, 0,
            0, 32, 2, /* 5184: struct.stack_st_fake_SSL_CIPHER */
            	5191, 8,
            	130, 24,
            8884099, 8, 2, /* 5191: pointer_to_array_of_pointers_to_stack */
            	5198, 0,
            	127, 20,
            0, 8, 1, /* 5198: pointer.SSL_CIPHER */
            	5203, 0,
            0, 0, 1, /* 5203: SSL_CIPHER */
            	5208, 0,
            0, 88, 1, /* 5208: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 5213: pointer.struct.ssl_session_st */
            	5218, 0,
            0, 352, 14, /* 5218: struct.ssl_session_st */
            	36, 144,
            	36, 152,
            	5249, 168,
            	5790, 176,
            	6023, 224,
            	5179, 240,
            	4888, 248,
            	5213, 264,
            	5213, 272,
            	36, 280,
            	23, 296,
            	23, 312,
            	23, 320,
            	36, 344,
            1, 8, 1, /* 5249: pointer.struct.sess_cert_st */
            	5254, 0,
            0, 248, 5, /* 5254: struct.sess_cert_st */
            	5267, 0,
            	5291, 16,
            	5775, 216,
            	5780, 224,
            	5785, 232,
            1, 8, 1, /* 5267: pointer.struct.stack_st_X509 */
            	5272, 0,
            0, 32, 2, /* 5272: struct.stack_st_fake_X509 */
            	5279, 8,
            	130, 24,
            8884099, 8, 2, /* 5279: pointer_to_array_of_pointers_to_stack */
            	5286, 0,
            	127, 20,
            0, 8, 1, /* 5286: pointer.X509 */
            	4479, 0,
            1, 8, 1, /* 5291: pointer.struct.cert_pkey_st */
            	5296, 0,
            0, 24, 3, /* 5296: struct.cert_pkey_st */
            	5305, 0,
            	5647, 8,
            	5730, 16,
            1, 8, 1, /* 5305: pointer.struct.x509_st */
            	5310, 0,
            0, 184, 12, /* 5310: struct.x509_st */
            	5337, 0,
            	5377, 8,
            	5452, 16,
            	36, 32,
            	5486, 40,
            	5508, 104,
            	5513, 112,
            	5518, 120,
            	5523, 128,
            	5547, 136,
            	5571, 144,
            	5576, 176,
            1, 8, 1, /* 5337: pointer.struct.x509_cinf_st */
            	5342, 0,
            0, 104, 11, /* 5342: struct.x509_cinf_st */
            	5367, 0,
            	5367, 8,
            	5377, 16,
            	5382, 24,
            	5430, 32,
            	5382, 40,
            	5447, 48,
            	5452, 56,
            	5452, 64,
            	5457, 72,
            	5481, 80,
            1, 8, 1, /* 5367: pointer.struct.asn1_string_st */
            	5372, 0,
            0, 24, 1, /* 5372: struct.asn1_string_st */
            	23, 8,
            1, 8, 1, /* 5377: pointer.struct.X509_algor_st */
            	551, 0,
            1, 8, 1, /* 5382: pointer.struct.X509_name_st */
            	5387, 0,
            0, 40, 3, /* 5387: struct.X509_name_st */
            	5396, 0,
            	5420, 16,
            	23, 24,
            1, 8, 1, /* 5396: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5401, 0,
            0, 32, 2, /* 5401: struct.stack_st_fake_X509_NAME_ENTRY */
            	5408, 8,
            	130, 24,
            8884099, 8, 2, /* 5408: pointer_to_array_of_pointers_to_stack */
            	5415, 0,
            	127, 20,
            0, 8, 1, /* 5415: pointer.X509_NAME_ENTRY */
            	86, 0,
            1, 8, 1, /* 5420: pointer.struct.buf_mem_st */
            	5425, 0,
            0, 24, 1, /* 5425: struct.buf_mem_st */
            	36, 8,
            1, 8, 1, /* 5430: pointer.struct.X509_val_st */
            	5435, 0,
            0, 16, 2, /* 5435: struct.X509_val_st */
            	5442, 0,
            	5442, 8,
            1, 8, 1, /* 5442: pointer.struct.asn1_string_st */
            	5372, 0,
            1, 8, 1, /* 5447: pointer.struct.X509_pubkey_st */
            	783, 0,
            1, 8, 1, /* 5452: pointer.struct.asn1_string_st */
            	5372, 0,
            1, 8, 1, /* 5457: pointer.struct.stack_st_X509_EXTENSION */
            	5462, 0,
            0, 32, 2, /* 5462: struct.stack_st_fake_X509_EXTENSION */
            	5469, 8,
            	130, 24,
            8884099, 8, 2, /* 5469: pointer_to_array_of_pointers_to_stack */
            	5476, 0,
            	127, 20,
            0, 8, 1, /* 5476: pointer.X509_EXTENSION */
            	2629, 0,
            0, 24, 1, /* 5481: struct.ASN1_ENCODING_st */
            	23, 0,
            0, 16, 1, /* 5486: struct.crypto_ex_data_st */
            	5491, 0,
            1, 8, 1, /* 5491: pointer.struct.stack_st_void */
            	5496, 0,
            0, 32, 1, /* 5496: struct.stack_st_void */
            	5501, 0,
            0, 32, 2, /* 5501: struct.stack_st */
            	1267, 8,
            	130, 24,
            1, 8, 1, /* 5508: pointer.struct.asn1_string_st */
            	5372, 0,
            1, 8, 1, /* 5513: pointer.struct.AUTHORITY_KEYID_st */
            	2702, 0,
            1, 8, 1, /* 5518: pointer.struct.X509_POLICY_CACHE_st */
            	3025, 0,
            1, 8, 1, /* 5523: pointer.struct.stack_st_DIST_POINT */
            	5528, 0,
            0, 32, 2, /* 5528: struct.stack_st_fake_DIST_POINT */
            	5535, 8,
            	130, 24,
            8884099, 8, 2, /* 5535: pointer_to_array_of_pointers_to_stack */
            	5542, 0,
            	127, 20,
            0, 8, 1, /* 5542: pointer.DIST_POINT */
            	3466, 0,
            1, 8, 1, /* 5547: pointer.struct.stack_st_GENERAL_NAME */
            	5552, 0,
            0, 32, 2, /* 5552: struct.stack_st_fake_GENERAL_NAME */
            	5559, 8,
            	130, 24,
            8884099, 8, 2, /* 5559: pointer_to_array_of_pointers_to_stack */
            	5566, 0,
            	127, 20,
            0, 8, 1, /* 5566: pointer.GENERAL_NAME */
            	2745, 0,
            1, 8, 1, /* 5571: pointer.struct.NAME_CONSTRAINTS_st */
            	3610, 0,
            1, 8, 1, /* 5576: pointer.struct.x509_cert_aux_st */
            	5581, 0,
            0, 40, 5, /* 5581: struct.x509_cert_aux_st */
            	5594, 0,
            	5594, 8,
            	5618, 16,
            	5508, 24,
            	5623, 32,
            1, 8, 1, /* 5594: pointer.struct.stack_st_ASN1_OBJECT */
            	5599, 0,
            0, 32, 2, /* 5599: struct.stack_st_fake_ASN1_OBJECT */
            	5606, 8,
            	130, 24,
            8884099, 8, 2, /* 5606: pointer_to_array_of_pointers_to_stack */
            	5613, 0,
            	127, 20,
            0, 8, 1, /* 5613: pointer.ASN1_OBJECT */
            	415, 0,
            1, 8, 1, /* 5618: pointer.struct.asn1_string_st */
            	5372, 0,
            1, 8, 1, /* 5623: pointer.struct.stack_st_X509_ALGOR */
            	5628, 0,
            0, 32, 2, /* 5628: struct.stack_st_fake_X509_ALGOR */
            	5635, 8,
            	130, 24,
            8884099, 8, 2, /* 5635: pointer_to_array_of_pointers_to_stack */
            	5642, 0,
            	127, 20,
            0, 8, 1, /* 5642: pointer.X509_ALGOR */
            	3964, 0,
            1, 8, 1, /* 5647: pointer.struct.evp_pkey_st */
            	5652, 0,
            0, 56, 4, /* 5652: struct.evp_pkey_st */
            	5663, 16,
            	5668, 24,
            	5673, 32,
            	5706, 48,
            1, 8, 1, /* 5663: pointer.struct.evp_pkey_asn1_method_st */
            	828, 0,
            1, 8, 1, /* 5668: pointer.struct.engine_st */
            	929, 0,
            0, 8, 5, /* 5673: union.unknown */
            	36, 0,
            	5686, 0,
            	5691, 0,
            	5696, 0,
            	5701, 0,
            1, 8, 1, /* 5686: pointer.struct.rsa_st */
            	1295, 0,
            1, 8, 1, /* 5691: pointer.struct.dsa_st */
            	1497, 0,
            1, 8, 1, /* 5696: pointer.struct.dh_st */
            	1624, 0,
            1, 8, 1, /* 5701: pointer.struct.ec_key_st */
            	1738, 0,
            1, 8, 1, /* 5706: pointer.struct.stack_st_X509_ATTRIBUTE */
            	5711, 0,
            0, 32, 2, /* 5711: struct.stack_st_fake_X509_ATTRIBUTE */
            	5718, 8,
            	130, 24,
            8884099, 8, 2, /* 5718: pointer_to_array_of_pointers_to_stack */
            	5725, 0,
            	127, 20,
            0, 8, 1, /* 5725: pointer.X509_ATTRIBUTE */
            	2245, 0,
            1, 8, 1, /* 5730: pointer.struct.env_md_st */
            	5735, 0,
            0, 120, 8, /* 5735: struct.env_md_st */
            	5754, 24,
            	5757, 32,
            	5760, 40,
            	5763, 48,
            	5754, 56,
            	5766, 64,
            	5769, 72,
            	5772, 112,
            8884097, 8, 0, /* 5754: pointer.func */
            8884097, 8, 0, /* 5757: pointer.func */
            8884097, 8, 0, /* 5760: pointer.func */
            8884097, 8, 0, /* 5763: pointer.func */
            8884097, 8, 0, /* 5766: pointer.func */
            8884097, 8, 0, /* 5769: pointer.func */
            8884097, 8, 0, /* 5772: pointer.func */
            1, 8, 1, /* 5775: pointer.struct.rsa_st */
            	1295, 0,
            1, 8, 1, /* 5780: pointer.struct.dh_st */
            	1624, 0,
            1, 8, 1, /* 5785: pointer.struct.ec_key_st */
            	1738, 0,
            1, 8, 1, /* 5790: pointer.struct.x509_st */
            	5795, 0,
            0, 184, 12, /* 5795: struct.x509_st */
            	5822, 0,
            	5862, 8,
            	5937, 16,
            	36, 32,
            	4888, 40,
            	5971, 104,
            	5513, 112,
            	5518, 120,
            	5523, 128,
            	5547, 136,
            	5571, 144,
            	5976, 176,
            1, 8, 1, /* 5822: pointer.struct.x509_cinf_st */
            	5827, 0,
            0, 104, 11, /* 5827: struct.x509_cinf_st */
            	5852, 0,
            	5852, 8,
            	5862, 16,
            	5867, 24,
            	5915, 32,
            	5867, 40,
            	5932, 48,
            	5937, 56,
            	5937, 64,
            	5942, 72,
            	5966, 80,
            1, 8, 1, /* 5852: pointer.struct.asn1_string_st */
            	5857, 0,
            0, 24, 1, /* 5857: struct.asn1_string_st */
            	23, 8,
            1, 8, 1, /* 5862: pointer.struct.X509_algor_st */
            	551, 0,
            1, 8, 1, /* 5867: pointer.struct.X509_name_st */
            	5872, 0,
            0, 40, 3, /* 5872: struct.X509_name_st */
            	5881, 0,
            	5905, 16,
            	23, 24,
            1, 8, 1, /* 5881: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5886, 0,
            0, 32, 2, /* 5886: struct.stack_st_fake_X509_NAME_ENTRY */
            	5893, 8,
            	130, 24,
            8884099, 8, 2, /* 5893: pointer_to_array_of_pointers_to_stack */
            	5900, 0,
            	127, 20,
            0, 8, 1, /* 5900: pointer.X509_NAME_ENTRY */
            	86, 0,
            1, 8, 1, /* 5905: pointer.struct.buf_mem_st */
            	5910, 0,
            0, 24, 1, /* 5910: struct.buf_mem_st */
            	36, 8,
            1, 8, 1, /* 5915: pointer.struct.X509_val_st */
            	5920, 0,
            0, 16, 2, /* 5920: struct.X509_val_st */
            	5927, 0,
            	5927, 8,
            1, 8, 1, /* 5927: pointer.struct.asn1_string_st */
            	5857, 0,
            1, 8, 1, /* 5932: pointer.struct.X509_pubkey_st */
            	783, 0,
            1, 8, 1, /* 5937: pointer.struct.asn1_string_st */
            	5857, 0,
            1, 8, 1, /* 5942: pointer.struct.stack_st_X509_EXTENSION */
            	5947, 0,
            0, 32, 2, /* 5947: struct.stack_st_fake_X509_EXTENSION */
            	5954, 8,
            	130, 24,
            8884099, 8, 2, /* 5954: pointer_to_array_of_pointers_to_stack */
            	5961, 0,
            	127, 20,
            0, 8, 1, /* 5961: pointer.X509_EXTENSION */
            	2629, 0,
            0, 24, 1, /* 5966: struct.ASN1_ENCODING_st */
            	23, 0,
            1, 8, 1, /* 5971: pointer.struct.asn1_string_st */
            	5857, 0,
            1, 8, 1, /* 5976: pointer.struct.x509_cert_aux_st */
            	5981, 0,
            0, 40, 5, /* 5981: struct.x509_cert_aux_st */
            	4852, 0,
            	4852, 8,
            	5994, 16,
            	5971, 24,
            	5999, 32,
            1, 8, 1, /* 5994: pointer.struct.asn1_string_st */
            	5857, 0,
            1, 8, 1, /* 5999: pointer.struct.stack_st_X509_ALGOR */
            	6004, 0,
            0, 32, 2, /* 6004: struct.stack_st_fake_X509_ALGOR */
            	6011, 8,
            	130, 24,
            8884099, 8, 2, /* 6011: pointer_to_array_of_pointers_to_stack */
            	6018, 0,
            	127, 20,
            0, 8, 1, /* 6018: pointer.X509_ALGOR */
            	3964, 0,
            1, 8, 1, /* 6023: pointer.struct.ssl_cipher_st */
            	6028, 0,
            0, 88, 1, /* 6028: struct.ssl_cipher_st */
            	5, 8,
            8884097, 8, 0, /* 6033: pointer.func */
            8884097, 8, 0, /* 6036: pointer.func */
            8884097, 8, 0, /* 6039: pointer.func */
            1, 8, 1, /* 6042: pointer.struct.env_md_st */
            	6047, 0,
            0, 120, 8, /* 6047: struct.env_md_st */
            	6066, 24,
            	6069, 32,
            	6072, 40,
            	6075, 48,
            	6066, 56,
            	5766, 64,
            	5769, 72,
            	6078, 112,
            8884097, 8, 0, /* 6066: pointer.func */
            8884097, 8, 0, /* 6069: pointer.func */
            8884097, 8, 0, /* 6072: pointer.func */
            8884097, 8, 0, /* 6075: pointer.func */
            8884097, 8, 0, /* 6078: pointer.func */
            8884097, 8, 0, /* 6081: pointer.func */
            1, 8, 1, /* 6084: pointer.struct.stack_st_X509_NAME */
            	6089, 0,
            0, 32, 2, /* 6089: struct.stack_st_fake_X509_NAME */
            	6096, 8,
            	130, 24,
            8884099, 8, 2, /* 6096: pointer_to_array_of_pointers_to_stack */
            	6103, 0,
            	127, 20,
            0, 8, 1, /* 6103: pointer.X509_NAME */
            	6108, 0,
            0, 0, 1, /* 6108: X509_NAME */
            	4561, 0,
            1, 8, 1, /* 6113: pointer.struct.cert_st */
            	6118, 0,
            0, 296, 7, /* 6118: struct.cert_st */
            	6135, 0,
            	6535, 48,
            	6540, 56,
            	6543, 64,
            	6548, 72,
            	5785, 80,
            	6551, 88,
            1, 8, 1, /* 6135: pointer.struct.cert_pkey_st */
            	6140, 0,
            0, 24, 3, /* 6140: struct.cert_pkey_st */
            	6149, 0,
            	6428, 8,
            	6496, 16,
            1, 8, 1, /* 6149: pointer.struct.x509_st */
            	6154, 0,
            0, 184, 12, /* 6154: struct.x509_st */
            	6181, 0,
            	6221, 8,
            	6296, 16,
            	36, 32,
            	6330, 40,
            	6352, 104,
            	5513, 112,
            	5518, 120,
            	5523, 128,
            	5547, 136,
            	5571, 144,
            	6357, 176,
            1, 8, 1, /* 6181: pointer.struct.x509_cinf_st */
            	6186, 0,
            0, 104, 11, /* 6186: struct.x509_cinf_st */
            	6211, 0,
            	6211, 8,
            	6221, 16,
            	6226, 24,
            	6274, 32,
            	6226, 40,
            	6291, 48,
            	6296, 56,
            	6296, 64,
            	6301, 72,
            	6325, 80,
            1, 8, 1, /* 6211: pointer.struct.asn1_string_st */
            	6216, 0,
            0, 24, 1, /* 6216: struct.asn1_string_st */
            	23, 8,
            1, 8, 1, /* 6221: pointer.struct.X509_algor_st */
            	551, 0,
            1, 8, 1, /* 6226: pointer.struct.X509_name_st */
            	6231, 0,
            0, 40, 3, /* 6231: struct.X509_name_st */
            	6240, 0,
            	6264, 16,
            	23, 24,
            1, 8, 1, /* 6240: pointer.struct.stack_st_X509_NAME_ENTRY */
            	6245, 0,
            0, 32, 2, /* 6245: struct.stack_st_fake_X509_NAME_ENTRY */
            	6252, 8,
            	130, 24,
            8884099, 8, 2, /* 6252: pointer_to_array_of_pointers_to_stack */
            	6259, 0,
            	127, 20,
            0, 8, 1, /* 6259: pointer.X509_NAME_ENTRY */
            	86, 0,
            1, 8, 1, /* 6264: pointer.struct.buf_mem_st */
            	6269, 0,
            0, 24, 1, /* 6269: struct.buf_mem_st */
            	36, 8,
            1, 8, 1, /* 6274: pointer.struct.X509_val_st */
            	6279, 0,
            0, 16, 2, /* 6279: struct.X509_val_st */
            	6286, 0,
            	6286, 8,
            1, 8, 1, /* 6286: pointer.struct.asn1_string_st */
            	6216, 0,
            1, 8, 1, /* 6291: pointer.struct.X509_pubkey_st */
            	783, 0,
            1, 8, 1, /* 6296: pointer.struct.asn1_string_st */
            	6216, 0,
            1, 8, 1, /* 6301: pointer.struct.stack_st_X509_EXTENSION */
            	6306, 0,
            0, 32, 2, /* 6306: struct.stack_st_fake_X509_EXTENSION */
            	6313, 8,
            	130, 24,
            8884099, 8, 2, /* 6313: pointer_to_array_of_pointers_to_stack */
            	6320, 0,
            	127, 20,
            0, 8, 1, /* 6320: pointer.X509_EXTENSION */
            	2629, 0,
            0, 24, 1, /* 6325: struct.ASN1_ENCODING_st */
            	23, 0,
            0, 16, 1, /* 6330: struct.crypto_ex_data_st */
            	6335, 0,
            1, 8, 1, /* 6335: pointer.struct.stack_st_void */
            	6340, 0,
            0, 32, 1, /* 6340: struct.stack_st_void */
            	6345, 0,
            0, 32, 2, /* 6345: struct.stack_st */
            	1267, 8,
            	130, 24,
            1, 8, 1, /* 6352: pointer.struct.asn1_string_st */
            	6216, 0,
            1, 8, 1, /* 6357: pointer.struct.x509_cert_aux_st */
            	6362, 0,
            0, 40, 5, /* 6362: struct.x509_cert_aux_st */
            	6375, 0,
            	6375, 8,
            	6399, 16,
            	6352, 24,
            	6404, 32,
            1, 8, 1, /* 6375: pointer.struct.stack_st_ASN1_OBJECT */
            	6380, 0,
            0, 32, 2, /* 6380: struct.stack_st_fake_ASN1_OBJECT */
            	6387, 8,
            	130, 24,
            8884099, 8, 2, /* 6387: pointer_to_array_of_pointers_to_stack */
            	6394, 0,
            	127, 20,
            0, 8, 1, /* 6394: pointer.ASN1_OBJECT */
            	415, 0,
            1, 8, 1, /* 6399: pointer.struct.asn1_string_st */
            	6216, 0,
            1, 8, 1, /* 6404: pointer.struct.stack_st_X509_ALGOR */
            	6409, 0,
            0, 32, 2, /* 6409: struct.stack_st_fake_X509_ALGOR */
            	6416, 8,
            	130, 24,
            8884099, 8, 2, /* 6416: pointer_to_array_of_pointers_to_stack */
            	6423, 0,
            	127, 20,
            0, 8, 1, /* 6423: pointer.X509_ALGOR */
            	3964, 0,
            1, 8, 1, /* 6428: pointer.struct.evp_pkey_st */
            	6433, 0,
            0, 56, 4, /* 6433: struct.evp_pkey_st */
            	5663, 16,
            	5668, 24,
            	6444, 32,
            	6472, 48,
            0, 8, 5, /* 6444: union.unknown */
            	36, 0,
            	6457, 0,
            	6462, 0,
            	6467, 0,
            	5701, 0,
            1, 8, 1, /* 6457: pointer.struct.rsa_st */
            	1295, 0,
            1, 8, 1, /* 6462: pointer.struct.dsa_st */
            	1497, 0,
            1, 8, 1, /* 6467: pointer.struct.dh_st */
            	1624, 0,
            1, 8, 1, /* 6472: pointer.struct.stack_st_X509_ATTRIBUTE */
            	6477, 0,
            0, 32, 2, /* 6477: struct.stack_st_fake_X509_ATTRIBUTE */
            	6484, 8,
            	130, 24,
            8884099, 8, 2, /* 6484: pointer_to_array_of_pointers_to_stack */
            	6491, 0,
            	127, 20,
            0, 8, 1, /* 6491: pointer.X509_ATTRIBUTE */
            	2245, 0,
            1, 8, 1, /* 6496: pointer.struct.env_md_st */
            	6501, 0,
            0, 120, 8, /* 6501: struct.env_md_st */
            	6520, 24,
            	6523, 32,
            	6526, 40,
            	6529, 48,
            	6520, 56,
            	5766, 64,
            	5769, 72,
            	6532, 112,
            8884097, 8, 0, /* 6520: pointer.func */
            8884097, 8, 0, /* 6523: pointer.func */
            8884097, 8, 0, /* 6526: pointer.func */
            8884097, 8, 0, /* 6529: pointer.func */
            8884097, 8, 0, /* 6532: pointer.func */
            1, 8, 1, /* 6535: pointer.struct.rsa_st */
            	1295, 0,
            8884097, 8, 0, /* 6540: pointer.func */
            1, 8, 1, /* 6543: pointer.struct.dh_st */
            	1624, 0,
            8884097, 8, 0, /* 6548: pointer.func */
            8884097, 8, 0, /* 6551: pointer.func */
            8884097, 8, 0, /* 6554: pointer.func */
            8884097, 8, 0, /* 6557: pointer.func */
            8884097, 8, 0, /* 6560: pointer.func */
            8884097, 8, 0, /* 6563: pointer.func */
            8884097, 8, 0, /* 6566: pointer.func */
            0, 128, 14, /* 6569: struct.srp_ctx_st */
            	15, 0,
            	202, 8,
            	4444, 16,
            	6600, 24,
            	36, 32,
            	164, 40,
            	164, 48,
            	164, 56,
            	164, 64,
            	164, 72,
            	164, 80,
            	164, 88,
            	164, 96,
            	36, 104,
            8884097, 8, 0, /* 6600: pointer.func */
            1, 8, 1, /* 6603: pointer.struct.ssl_ctx_st */
            	4910, 0,
            1, 8, 1, /* 6608: pointer.struct.stack_st_X509_EXTENSION */
            	6613, 0,
            0, 32, 2, /* 6613: struct.stack_st_fake_X509_EXTENSION */
            	6620, 8,
            	130, 24,
            8884099, 8, 2, /* 6620: pointer_to_array_of_pointers_to_stack */
            	6627, 0,
            	127, 20,
            0, 8, 1, /* 6627: pointer.X509_EXTENSION */
            	2629, 0,
            1, 8, 1, /* 6632: pointer.struct.dsa_st */
            	1497, 0,
            1, 8, 1, /* 6637: pointer.struct.engine_st */
            	929, 0,
            0, 24, 1, /* 6642: struct.ssl3_buffer_st */
            	23, 0,
            8884097, 8, 0, /* 6647: pointer.func */
            0, 8, 5, /* 6650: union.unknown */
            	36, 0,
            	6663, 0,
            	6632, 0,
            	6668, 0,
            	6673, 0,
            1, 8, 1, /* 6663: pointer.struct.rsa_st */
            	1295, 0,
            1, 8, 1, /* 6668: pointer.struct.dh_st */
            	1624, 0,
            1, 8, 1, /* 6673: pointer.struct.ec_key_st */
            	1738, 0,
            8884097, 8, 0, /* 6678: pointer.func */
            8884097, 8, 0, /* 6681: pointer.func */
            8884097, 8, 0, /* 6684: pointer.func */
            0, 56, 3, /* 6687: struct.ssl3_record_st */
            	23, 16,
            	23, 24,
            	23, 32,
            8884097, 8, 0, /* 6696: pointer.func */
            0, 208, 25, /* 6699: struct.evp_pkey_method_st */
            	6752, 8,
            	6696, 16,
            	6755, 24,
            	6752, 32,
            	6758, 40,
            	6752, 48,
            	6758, 56,
            	6752, 64,
            	6761, 72,
            	6752, 80,
            	6764, 88,
            	6752, 96,
            	6761, 104,
            	6681, 112,
            	6678, 120,
            	6681, 128,
            	6767, 136,
            	6752, 144,
            	6761, 152,
            	6752, 160,
            	6761, 168,
            	6752, 176,
            	6770, 184,
            	6773, 192,
            	6776, 200,
            8884097, 8, 0, /* 6752: pointer.func */
            8884097, 8, 0, /* 6755: pointer.func */
            8884097, 8, 0, /* 6758: pointer.func */
            8884097, 8, 0, /* 6761: pointer.func */
            8884097, 8, 0, /* 6764: pointer.func */
            8884097, 8, 0, /* 6767: pointer.func */
            8884097, 8, 0, /* 6770: pointer.func */
            8884097, 8, 0, /* 6773: pointer.func */
            8884097, 8, 0, /* 6776: pointer.func */
            0, 344, 9, /* 6779: struct.ssl2_state_st */
            	112, 24,
            	23, 56,
            	23, 64,
            	23, 72,
            	23, 104,
            	23, 112,
            	23, 120,
            	23, 128,
            	23, 136,
            8884097, 8, 0, /* 6800: pointer.func */
            1, 8, 1, /* 6803: pointer.struct.stack_st_OCSP_RESPID */
            	6808, 0,
            0, 32, 2, /* 6808: struct.stack_st_fake_OCSP_RESPID */
            	6815, 8,
            	130, 24,
            8884099, 8, 2, /* 6815: pointer_to_array_of_pointers_to_stack */
            	6822, 0,
            	127, 20,
            0, 8, 1, /* 6822: pointer.OCSP_RESPID */
            	143, 0,
            8884097, 8, 0, /* 6827: pointer.func */
            1, 8, 1, /* 6830: pointer.struct.bio_method_st */
            	6835, 0,
            0, 80, 9, /* 6835: struct.bio_method_st */
            	5, 8,
            	6800, 16,
            	6827, 24,
            	6684, 32,
            	6827, 40,
            	6856, 48,
            	6859, 56,
            	6859, 64,
            	6862, 72,
            8884097, 8, 0, /* 6856: pointer.func */
            8884097, 8, 0, /* 6859: pointer.func */
            8884097, 8, 0, /* 6862: pointer.func */
            8884097, 8, 0, /* 6865: pointer.func */
            1, 8, 1, /* 6868: pointer.struct.evp_cipher_ctx_st */
            	6873, 0,
            0, 168, 4, /* 6873: struct.evp_cipher_ctx_st */
            	6884, 0,
            	5668, 8,
            	15, 96,
            	15, 120,
            1, 8, 1, /* 6884: pointer.struct.evp_cipher_st */
            	6889, 0,
            0, 88, 7, /* 6889: struct.evp_cipher_st */
            	6906, 24,
            	6909, 32,
            	6912, 40,
            	6915, 56,
            	6915, 64,
            	6918, 72,
            	15, 80,
            8884097, 8, 0, /* 6906: pointer.func */
            8884097, 8, 0, /* 6909: pointer.func */
            8884097, 8, 0, /* 6912: pointer.func */
            8884097, 8, 0, /* 6915: pointer.func */
            8884097, 8, 0, /* 6918: pointer.func */
            0, 112, 7, /* 6921: struct.bio_st */
            	6830, 0,
            	6938, 8,
            	36, 16,
            	15, 48,
            	6941, 56,
            	6941, 64,
            	4888, 96,
            8884097, 8, 0, /* 6938: pointer.func */
            1, 8, 1, /* 6941: pointer.struct.bio_st */
            	6921, 0,
            1, 8, 1, /* 6946: pointer.struct.bio_st */
            	6921, 0,
            1, 8, 1, /* 6951: pointer.struct.ssl_st */
            	6956, 0,
            0, 808, 51, /* 6956: struct.ssl_st */
            	5013, 8,
            	6946, 16,
            	6946, 24,
            	6946, 32,
            	5077, 48,
            	5905, 80,
            	15, 88,
            	23, 104,
            	7061, 120,
            	7066, 128,
            	7260, 136,
            	6554, 152,
            	15, 160,
            	4840, 176,
            	5179, 184,
            	5179, 192,
            	6868, 208,
            	7099, 216,
            	7330, 224,
            	6868, 232,
            	7099, 240,
            	7330, 248,
            	6113, 256,
            	7342, 304,
            	6557, 312,
            	4876, 328,
            	6081, 336,
            	6563, 352,
            	6566, 360,
            	6603, 368,
            	4888, 392,
            	6084, 408,
            	7347, 464,
            	15, 472,
            	36, 480,
            	6803, 504,
            	6608, 512,
            	23, 520,
            	23, 544,
            	23, 560,
            	15, 568,
            	7350, 584,
            	7355, 592,
            	15, 600,
            	7358, 608,
            	15, 616,
            	6603, 624,
            	23, 632,
            	251, 648,
            	7361, 656,
            	6569, 680,
            1, 8, 1, /* 7061: pointer.struct.ssl2_state_st */
            	6779, 0,
            1, 8, 1, /* 7066: pointer.struct.ssl3_state_st */
            	7071, 0,
            0, 1200, 10, /* 7071: struct.ssl3_state_st */
            	6642, 240,
            	6642, 264,
            	6687, 288,
            	6687, 344,
            	112, 432,
            	6946, 440,
            	7094, 448,
            	15, 496,
            	15, 512,
            	7196, 528,
            1, 8, 1, /* 7094: pointer.pointer.struct.env_md_ctx_st */
            	7099, 0,
            1, 8, 1, /* 7099: pointer.struct.env_md_ctx_st */
            	7104, 0,
            0, 48, 5, /* 7104: struct.env_md_ctx_st */
            	6042, 0,
            	5668, 8,
            	15, 24,
            	7117, 32,
            	6069, 40,
            1, 8, 1, /* 7117: pointer.struct.evp_pkey_ctx_st */
            	7122, 0,
            0, 80, 8, /* 7122: struct.evp_pkey_ctx_st */
            	7141, 0,
            	6637, 8,
            	7146, 16,
            	7146, 24,
            	15, 40,
            	15, 48,
            	6865, 56,
            	7191, 64,
            1, 8, 1, /* 7141: pointer.struct.evp_pkey_method_st */
            	6699, 0,
            1, 8, 1, /* 7146: pointer.struct.evp_pkey_st */
            	7151, 0,
            0, 56, 4, /* 7151: struct.evp_pkey_st */
            	7162, 16,
            	6637, 24,
            	6650, 32,
            	7167, 48,
            1, 8, 1, /* 7162: pointer.struct.evp_pkey_asn1_method_st */
            	828, 0,
            1, 8, 1, /* 7167: pointer.struct.stack_st_X509_ATTRIBUTE */
            	7172, 0,
            0, 32, 2, /* 7172: struct.stack_st_fake_X509_ATTRIBUTE */
            	7179, 8,
            	130, 24,
            8884099, 8, 2, /* 7179: pointer_to_array_of_pointers_to_stack */
            	7186, 0,
            	127, 20,
            0, 8, 1, /* 7186: pointer.X509_ATTRIBUTE */
            	2245, 0,
            1, 8, 1, /* 7191: pointer.int */
            	127, 0,
            0, 528, 8, /* 7196: struct.unknown */
            	6023, 408,
            	7215, 416,
            	5785, 424,
            	6084, 464,
            	23, 480,
            	6884, 488,
            	6042, 496,
            	7220, 512,
            1, 8, 1, /* 7215: pointer.struct.dh_st */
            	1624, 0,
            1, 8, 1, /* 7220: pointer.struct.ssl_comp_st */
            	7225, 0,
            0, 24, 2, /* 7225: struct.ssl_comp_st */
            	5, 8,
            	7232, 16,
            1, 8, 1, /* 7232: pointer.struct.comp_method_st */
            	7237, 0,
            0, 64, 7, /* 7237: struct.comp_method_st */
            	5, 8,
            	7254, 16,
            	7257, 24,
            	6647, 32,
            	6647, 40,
            	231, 48,
            	231, 56,
            8884097, 8, 0, /* 7254: pointer.func */
            8884097, 8, 0, /* 7257: pointer.func */
            1, 8, 1, /* 7260: pointer.struct.dtls1_state_st */
            	7265, 0,
            0, 888, 7, /* 7265: struct.dtls1_state_st */
            	7282, 576,
            	7282, 592,
            	7287, 608,
            	7287, 616,
            	7282, 624,
            	7314, 648,
            	7314, 736,
            0, 16, 1, /* 7282: struct.record_pqueue_st */
            	7287, 8,
            1, 8, 1, /* 7287: pointer.struct._pqueue */
            	7292, 0,
            0, 16, 1, /* 7292: struct._pqueue */
            	7297, 0,
            1, 8, 1, /* 7297: pointer.struct._pitem */
            	7302, 0,
            0, 24, 2, /* 7302: struct._pitem */
            	15, 8,
            	7309, 16,
            1, 8, 1, /* 7309: pointer.struct._pitem */
            	7302, 0,
            0, 88, 1, /* 7314: struct.hm_header_st */
            	7319, 48,
            0, 40, 4, /* 7319: struct.dtls1_retransmit_state */
            	6868, 0,
            	7099, 8,
            	7330, 16,
            	7342, 24,
            1, 8, 1, /* 7330: pointer.struct.comp_ctx_st */
            	7335, 0,
            0, 56, 2, /* 7335: struct.comp_ctx_st */
            	7232, 0,
            	4888, 40,
            1, 8, 1, /* 7342: pointer.struct.ssl_session_st */
            	5218, 0,
            8884097, 8, 0, /* 7347: pointer.func */
            1, 8, 1, /* 7350: pointer.struct.tls_session_ticket_ext_st */
            	10, 0,
            8884097, 8, 0, /* 7355: pointer.func */
            8884097, 8, 0, /* 7358: pointer.func */
            1, 8, 1, /* 7361: pointer.struct.srtp_protection_profile_st */
            	4450, 0,
            1, 8, 1, /* 7366: pointer.struct.ssl_cipher_st */
            	0, 0,
            0, 1, 0, /* 7371: char */
        },
        .arg_entity_index = { 6951, },
        .ret_entity_index = 7366,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL * new_arg_a = *((const SSL * *)new_args->args[0]);

    const SSL_CIPHER * *new_ret_ptr = (const SSL_CIPHER * *)new_args->ret;

    const SSL_CIPHER * (*orig_SSL_get_current_cipher)(const SSL *);
    orig_SSL_get_current_cipher = dlsym(RTLD_NEXT, "SSL_get_current_cipher");
    *new_ret_ptr = (*orig_SSL_get_current_cipher)(new_arg_a);

    syscall(889);

    return ret;
}

