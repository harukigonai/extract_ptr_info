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

X509 * bb_SSL_get_peer_certificate(const SSL * arg_a);

X509 * SSL_get_peer_certificate(const SSL * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_get_peer_certificate called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_get_peer_certificate(arg_a);
    else {
        X509 * (*orig_SSL_get_peer_certificate)(const SSL *);
        orig_SSL_get_peer_certificate = dlsym(RTLD_NEXT, "SSL_get_peer_certificate");
        return orig_SSL_get_peer_certificate(arg_a);
    }
}

X509 * bb_SSL_get_peer_certificate(const SSL * arg_a) 
{
    X509 * ret;

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
            0, 0, 1, /* 229: SRTP_PROTECTION_PROFILE */
            	234, 0,
            0, 16, 1, /* 234: struct.srtp_protection_profile_st */
            	5, 0,
            64097, 8, 0, /* 239: pointer.func */
            0, 128, 14, /* 242: struct.srp_ctx_st */
            	273, 0,
            	276, 8,
            	279, 16,
            	282, 24,
            	99, 32,
            	285, 40,
            	285, 48,
            	285, 56,
            	285, 64,
            	285, 72,
            	285, 80,
            	285, 88,
            	285, 96,
            	99, 104,
            0, 8, 0, /* 273: pointer.void */
            64097, 8, 0, /* 276: pointer.func */
            64097, 8, 0, /* 279: pointer.func */
            64097, 8, 0, /* 282: pointer.func */
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
            64097, 8, 0, /* 313: pointer.func */
            64097, 8, 0, /* 316: pointer.func */
            64097, 8, 0, /* 319: pointer.func */
            0, 24, 2, /* 322: struct.ssl_comp_st */
            	5, 8,
            	329, 16,
            1, 8, 1, /* 329: pointer.struct.comp_method_st */
            	334, 0,
            0, 64, 7, /* 334: struct.comp_method_st */
            	5, 8,
            	319, 16,
            	351, 24,
            	316, 32,
            	316, 40,
            	354, 48,
            	354, 56,
            64097, 8, 0, /* 351: pointer.func */
            64097, 8, 0, /* 354: pointer.func */
            1, 8, 1, /* 357: pointer.struct.stack_st_SSL_COMP */
            	362, 0,
            0, 32, 2, /* 362: struct.stack_st_fake_SSL_COMP */
            	369, 8,
            	86, 24,
            64099, 8, 2, /* 369: pointer_to_array_of_pointers_to_stack */
            	376, 0,
            	83, 20,
            0, 8, 1, /* 376: pointer.SSL_COMP */
            	381, 0,
            0, 0, 1, /* 381: SSL_COMP */
            	322, 0,
            64097, 8, 0, /* 386: pointer.func */
            64097, 8, 0, /* 389: pointer.func */
            64097, 8, 0, /* 392: pointer.func */
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
            64097, 8, 0, /* 426: pointer.func */
            64097, 8, 0, /* 429: pointer.func */
            64097, 8, 0, /* 432: pointer.func */
            64097, 8, 0, /* 435: pointer.func */
            64097, 8, 0, /* 438: pointer.func */
            64097, 8, 0, /* 441: pointer.func */
            64097, 8, 0, /* 444: pointer.func */
            64097, 8, 0, /* 447: pointer.func */
            64097, 8, 0, /* 450: pointer.func */
            64097, 8, 0, /* 453: pointer.func */
            64097, 8, 0, /* 456: pointer.func */
            64097, 8, 0, /* 459: pointer.func */
            64097, 8, 0, /* 462: pointer.func */
            64097, 8, 0, /* 465: pointer.func */
            1, 8, 1, /* 468: pointer.struct.stack_st_X509_LOOKUP */
            	473, 0,
            0, 32, 2, /* 473: struct.stack_st_fake_X509_LOOKUP */
            	480, 8,
            	86, 24,
            64099, 8, 2, /* 480: pointer_to_array_of_pointers_to_stack */
            	487, 0,
            	83, 20,
            0, 8, 1, /* 487: pointer.X509_LOOKUP */
            	492, 0,
            0, 0, 1, /* 492: X509_LOOKUP */
            	497, 0,
            0, 32, 3, /* 497: struct.x509_lookup_st */
            	506, 8,
            	99, 16,
            	555, 24,
            1, 8, 1, /* 506: pointer.struct.x509_lookup_method_st */
            	511, 0,
            0, 80, 10, /* 511: struct.x509_lookup_method_st */
            	5, 0,
            	534, 8,
            	537, 16,
            	534, 24,
            	534, 32,
            	540, 40,
            	543, 48,
            	546, 56,
            	549, 64,
            	552, 72,
            64097, 8, 0, /* 534: pointer.func */
            64097, 8, 0, /* 537: pointer.func */
            64097, 8, 0, /* 540: pointer.func */
            64097, 8, 0, /* 543: pointer.func */
            64097, 8, 0, /* 546: pointer.func */
            64097, 8, 0, /* 549: pointer.func */
            64097, 8, 0, /* 552: pointer.func */
            1, 8, 1, /* 555: pointer.struct.x509_store_st */
            	560, 0,
            0, 144, 15, /* 560: struct.x509_store_st */
            	593, 8,
            	468, 16,
            	2612, 24,
            	462, 32,
            	459, 40,
            	456, 48,
            	453, 56,
            	462, 64,
            	450, 72,
            	447, 80,
            	2624, 88,
            	444, 96,
            	441, 104,
            	462, 112,
            	1098, 120,
            1, 8, 1, /* 593: pointer.struct.stack_st_X509_OBJECT */
            	598, 0,
            0, 32, 2, /* 598: struct.stack_st_fake_X509_OBJECT */
            	605, 8,
            	86, 24,
            64099, 8, 2, /* 605: pointer_to_array_of_pointers_to_stack */
            	612, 0,
            	83, 20,
            0, 8, 1, /* 612: pointer.X509_OBJECT */
            	617, 0,
            0, 0, 1, /* 617: X509_OBJECT */
            	622, 0,
            0, 16, 1, /* 622: struct.x509_object_st */
            	627, 8,
            0, 8, 4, /* 627: union.unknown */
            	99, 0,
            	638, 0,
            	2400, 0,
            	946, 0,
            1, 8, 1, /* 638: pointer.struct.x509_st */
            	643, 0,
            0, 184, 12, /* 643: struct.x509_st */
            	670, 0,
            	710, 8,
            	799, 16,
            	99, 32,
            	1098, 40,
            	804, 104,
            	1704, 112,
            	1712, 120,
            	1720, 128,
            	2129, 136,
            	2153, 144,
            	2161, 176,
            1, 8, 1, /* 670: pointer.struct.x509_cinf_st */
            	675, 0,
            0, 104, 11, /* 675: struct.x509_cinf_st */
            	700, 0,
            	700, 8,
            	710, 16,
            	867, 24,
            	915, 32,
            	867, 40,
            	932, 48,
            	799, 56,
            	799, 64,
            	1675, 72,
            	1699, 80,
            1, 8, 1, /* 700: pointer.struct.asn1_string_st */
            	705, 0,
            0, 24, 1, /* 705: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 710: pointer.struct.X509_algor_st */
            	715, 0,
            0, 16, 2, /* 715: struct.X509_algor_st */
            	722, 0,
            	736, 8,
            1, 8, 1, /* 722: pointer.struct.asn1_object_st */
            	727, 0,
            0, 40, 3, /* 727: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 736: pointer.struct.asn1_type_st */
            	741, 0,
            0, 16, 1, /* 741: struct.asn1_type_st */
            	746, 8,
            0, 8, 20, /* 746: union.unknown */
            	99, 0,
            	789, 0,
            	722, 0,
            	700, 0,
            	794, 0,
            	799, 0,
            	804, 0,
            	809, 0,
            	814, 0,
            	819, 0,
            	824, 0,
            	829, 0,
            	834, 0,
            	839, 0,
            	844, 0,
            	849, 0,
            	854, 0,
            	789, 0,
            	789, 0,
            	859, 0,
            1, 8, 1, /* 789: pointer.struct.asn1_string_st */
            	705, 0,
            1, 8, 1, /* 794: pointer.struct.asn1_string_st */
            	705, 0,
            1, 8, 1, /* 799: pointer.struct.asn1_string_st */
            	705, 0,
            1, 8, 1, /* 804: pointer.struct.asn1_string_st */
            	705, 0,
            1, 8, 1, /* 809: pointer.struct.asn1_string_st */
            	705, 0,
            1, 8, 1, /* 814: pointer.struct.asn1_string_st */
            	705, 0,
            1, 8, 1, /* 819: pointer.struct.asn1_string_st */
            	705, 0,
            1, 8, 1, /* 824: pointer.struct.asn1_string_st */
            	705, 0,
            1, 8, 1, /* 829: pointer.struct.asn1_string_st */
            	705, 0,
            1, 8, 1, /* 834: pointer.struct.asn1_string_st */
            	705, 0,
            1, 8, 1, /* 839: pointer.struct.asn1_string_st */
            	705, 0,
            1, 8, 1, /* 844: pointer.struct.asn1_string_st */
            	705, 0,
            1, 8, 1, /* 849: pointer.struct.asn1_string_st */
            	705, 0,
            1, 8, 1, /* 854: pointer.struct.asn1_string_st */
            	705, 0,
            1, 8, 1, /* 859: pointer.struct.ASN1_VALUE_st */
            	864, 0,
            0, 0, 0, /* 864: struct.ASN1_VALUE_st */
            1, 8, 1, /* 867: pointer.struct.X509_name_st */
            	872, 0,
            0, 40, 3, /* 872: struct.X509_name_st */
            	881, 0,
            	905, 16,
            	78, 24,
            1, 8, 1, /* 881: pointer.struct.stack_st_X509_NAME_ENTRY */
            	886, 0,
            0, 32, 2, /* 886: struct.stack_st_fake_X509_NAME_ENTRY */
            	893, 8,
            	86, 24,
            64099, 8, 2, /* 893: pointer_to_array_of_pointers_to_stack */
            	900, 0,
            	83, 20,
            0, 8, 1, /* 900: pointer.X509_NAME_ENTRY */
            	128, 0,
            1, 8, 1, /* 905: pointer.struct.buf_mem_st */
            	910, 0,
            0, 24, 1, /* 910: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 915: pointer.struct.X509_val_st */
            	920, 0,
            0, 16, 2, /* 920: struct.X509_val_st */
            	927, 0,
            	927, 8,
            1, 8, 1, /* 927: pointer.struct.asn1_string_st */
            	705, 0,
            1, 8, 1, /* 932: pointer.struct.X509_pubkey_st */
            	937, 0,
            0, 24, 3, /* 937: struct.X509_pubkey_st */
            	710, 0,
            	799, 8,
            	946, 16,
            1, 8, 1, /* 946: pointer.struct.evp_pkey_st */
            	951, 0,
            0, 56, 4, /* 951: struct.evp_pkey_st */
            	962, 16,
            	970, 24,
            	978, 32,
            	1304, 48,
            1, 8, 1, /* 962: pointer.struct.evp_pkey_asn1_method_st */
            	967, 0,
            0, 0, 0, /* 967: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 970: pointer.struct.engine_st */
            	975, 0,
            0, 0, 0, /* 975: struct.engine_st */
            0, 8, 5, /* 978: union.unknown */
            	99, 0,
            	991, 0,
            	1147, 0,
            	1228, 0,
            	1296, 0,
            1, 8, 1, /* 991: pointer.struct.rsa_st */
            	996, 0,
            0, 168, 17, /* 996: struct.rsa_st */
            	1033, 16,
            	970, 24,
            	1088, 32,
            	1088, 40,
            	1088, 48,
            	1088, 56,
            	1088, 64,
            	1088, 72,
            	1088, 80,
            	1088, 88,
            	1098, 96,
            	1125, 120,
            	1125, 128,
            	1125, 136,
            	99, 144,
            	1139, 152,
            	1139, 160,
            1, 8, 1, /* 1033: pointer.struct.rsa_meth_st */
            	1038, 0,
            0, 112, 13, /* 1038: struct.rsa_meth_st */
            	5, 0,
            	1067, 8,
            	1067, 16,
            	1067, 24,
            	1067, 32,
            	1070, 40,
            	1073, 48,
            	1076, 56,
            	1076, 64,
            	99, 80,
            	1079, 88,
            	1082, 96,
            	1085, 104,
            64097, 8, 0, /* 1067: pointer.func */
            64097, 8, 0, /* 1070: pointer.func */
            64097, 8, 0, /* 1073: pointer.func */
            64097, 8, 0, /* 1076: pointer.func */
            64097, 8, 0, /* 1079: pointer.func */
            64097, 8, 0, /* 1082: pointer.func */
            64097, 8, 0, /* 1085: pointer.func */
            1, 8, 1, /* 1088: pointer.struct.bignum_st */
            	1093, 0,
            0, 24, 1, /* 1093: struct.bignum_st */
            	295, 0,
            0, 16, 1, /* 1098: struct.crypto_ex_data_st */
            	1103, 0,
            1, 8, 1, /* 1103: pointer.struct.stack_st_void */
            	1108, 0,
            0, 32, 1, /* 1108: struct.stack_st_void */
            	1113, 0,
            0, 32, 2, /* 1113: struct.stack_st */
            	1120, 8,
            	86, 24,
            1, 8, 1, /* 1120: pointer.pointer.char */
            	99, 0,
            1, 8, 1, /* 1125: pointer.struct.bn_mont_ctx_st */
            	1130, 0,
            0, 96, 3, /* 1130: struct.bn_mont_ctx_st */
            	1093, 8,
            	1093, 32,
            	1093, 56,
            1, 8, 1, /* 1139: pointer.struct.bn_blinding_st */
            	1144, 0,
            0, 0, 0, /* 1144: struct.bn_blinding_st */
            1, 8, 1, /* 1147: pointer.struct.dsa_st */
            	1152, 0,
            0, 136, 11, /* 1152: struct.dsa_st */
            	1088, 24,
            	1088, 32,
            	1088, 40,
            	1088, 48,
            	1088, 56,
            	1088, 64,
            	1088, 72,
            	1125, 88,
            	1098, 104,
            	1177, 120,
            	970, 128,
            1, 8, 1, /* 1177: pointer.struct.dsa_method */
            	1182, 0,
            0, 96, 11, /* 1182: struct.dsa_method */
            	5, 0,
            	1207, 8,
            	1210, 16,
            	1213, 24,
            	1216, 32,
            	1219, 40,
            	1222, 48,
            	1222, 56,
            	99, 72,
            	1225, 80,
            	1222, 88,
            64097, 8, 0, /* 1207: pointer.func */
            64097, 8, 0, /* 1210: pointer.func */
            64097, 8, 0, /* 1213: pointer.func */
            64097, 8, 0, /* 1216: pointer.func */
            64097, 8, 0, /* 1219: pointer.func */
            64097, 8, 0, /* 1222: pointer.func */
            64097, 8, 0, /* 1225: pointer.func */
            1, 8, 1, /* 1228: pointer.struct.dh_st */
            	1233, 0,
            0, 144, 12, /* 1233: struct.dh_st */
            	1088, 8,
            	1088, 16,
            	1088, 32,
            	1088, 40,
            	1125, 56,
            	1088, 64,
            	1088, 72,
            	78, 80,
            	1088, 96,
            	1098, 112,
            	1260, 128,
            	970, 136,
            1, 8, 1, /* 1260: pointer.struct.dh_method */
            	1265, 0,
            0, 72, 8, /* 1265: struct.dh_method */
            	5, 0,
            	1284, 8,
            	1287, 16,
            	1290, 24,
            	1284, 32,
            	1284, 40,
            	99, 56,
            	1293, 64,
            64097, 8, 0, /* 1284: pointer.func */
            64097, 8, 0, /* 1287: pointer.func */
            64097, 8, 0, /* 1290: pointer.func */
            64097, 8, 0, /* 1293: pointer.func */
            1, 8, 1, /* 1296: pointer.struct.ec_key_st */
            	1301, 0,
            0, 0, 0, /* 1301: struct.ec_key_st */
            1, 8, 1, /* 1304: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1309, 0,
            0, 32, 2, /* 1309: struct.stack_st_fake_X509_ATTRIBUTE */
            	1316, 8,
            	86, 24,
            64099, 8, 2, /* 1316: pointer_to_array_of_pointers_to_stack */
            	1323, 0,
            	83, 20,
            0, 8, 1, /* 1323: pointer.X509_ATTRIBUTE */
            	1328, 0,
            0, 0, 1, /* 1328: X509_ATTRIBUTE */
            	1333, 0,
            0, 24, 2, /* 1333: struct.x509_attributes_st */
            	1340, 0,
            	1354, 16,
            1, 8, 1, /* 1340: pointer.struct.asn1_object_st */
            	1345, 0,
            0, 40, 3, /* 1345: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            0, 8, 3, /* 1354: union.unknown */
            	99, 0,
            	1363, 0,
            	1542, 0,
            1, 8, 1, /* 1363: pointer.struct.stack_st_ASN1_TYPE */
            	1368, 0,
            0, 32, 2, /* 1368: struct.stack_st_fake_ASN1_TYPE */
            	1375, 8,
            	86, 24,
            64099, 8, 2, /* 1375: pointer_to_array_of_pointers_to_stack */
            	1382, 0,
            	83, 20,
            0, 8, 1, /* 1382: pointer.ASN1_TYPE */
            	1387, 0,
            0, 0, 1, /* 1387: ASN1_TYPE */
            	1392, 0,
            0, 16, 1, /* 1392: struct.asn1_type_st */
            	1397, 8,
            0, 8, 20, /* 1397: union.unknown */
            	99, 0,
            	1440, 0,
            	1450, 0,
            	1464, 0,
            	1469, 0,
            	1474, 0,
            	1479, 0,
            	1484, 0,
            	1489, 0,
            	1494, 0,
            	1499, 0,
            	1504, 0,
            	1509, 0,
            	1514, 0,
            	1519, 0,
            	1524, 0,
            	1529, 0,
            	1440, 0,
            	1440, 0,
            	1534, 0,
            1, 8, 1, /* 1440: pointer.struct.asn1_string_st */
            	1445, 0,
            0, 24, 1, /* 1445: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 1450: pointer.struct.asn1_object_st */
            	1455, 0,
            0, 40, 3, /* 1455: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 1464: pointer.struct.asn1_string_st */
            	1445, 0,
            1, 8, 1, /* 1469: pointer.struct.asn1_string_st */
            	1445, 0,
            1, 8, 1, /* 1474: pointer.struct.asn1_string_st */
            	1445, 0,
            1, 8, 1, /* 1479: pointer.struct.asn1_string_st */
            	1445, 0,
            1, 8, 1, /* 1484: pointer.struct.asn1_string_st */
            	1445, 0,
            1, 8, 1, /* 1489: pointer.struct.asn1_string_st */
            	1445, 0,
            1, 8, 1, /* 1494: pointer.struct.asn1_string_st */
            	1445, 0,
            1, 8, 1, /* 1499: pointer.struct.asn1_string_st */
            	1445, 0,
            1, 8, 1, /* 1504: pointer.struct.asn1_string_st */
            	1445, 0,
            1, 8, 1, /* 1509: pointer.struct.asn1_string_st */
            	1445, 0,
            1, 8, 1, /* 1514: pointer.struct.asn1_string_st */
            	1445, 0,
            1, 8, 1, /* 1519: pointer.struct.asn1_string_st */
            	1445, 0,
            1, 8, 1, /* 1524: pointer.struct.asn1_string_st */
            	1445, 0,
            1, 8, 1, /* 1529: pointer.struct.asn1_string_st */
            	1445, 0,
            1, 8, 1, /* 1534: pointer.struct.ASN1_VALUE_st */
            	1539, 0,
            0, 0, 0, /* 1539: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1542: pointer.struct.asn1_type_st */
            	1547, 0,
            0, 16, 1, /* 1547: struct.asn1_type_st */
            	1552, 8,
            0, 8, 20, /* 1552: union.unknown */
            	99, 0,
            	1595, 0,
            	1340, 0,
            	1605, 0,
            	1610, 0,
            	1615, 0,
            	1620, 0,
            	1625, 0,
            	1630, 0,
            	1635, 0,
            	1640, 0,
            	1645, 0,
            	1650, 0,
            	1655, 0,
            	1660, 0,
            	1665, 0,
            	1670, 0,
            	1595, 0,
            	1595, 0,
            	859, 0,
            1, 8, 1, /* 1595: pointer.struct.asn1_string_st */
            	1600, 0,
            0, 24, 1, /* 1600: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 1605: pointer.struct.asn1_string_st */
            	1600, 0,
            1, 8, 1, /* 1610: pointer.struct.asn1_string_st */
            	1600, 0,
            1, 8, 1, /* 1615: pointer.struct.asn1_string_st */
            	1600, 0,
            1, 8, 1, /* 1620: pointer.struct.asn1_string_st */
            	1600, 0,
            1, 8, 1, /* 1625: pointer.struct.asn1_string_st */
            	1600, 0,
            1, 8, 1, /* 1630: pointer.struct.asn1_string_st */
            	1600, 0,
            1, 8, 1, /* 1635: pointer.struct.asn1_string_st */
            	1600, 0,
            1, 8, 1, /* 1640: pointer.struct.asn1_string_st */
            	1600, 0,
            1, 8, 1, /* 1645: pointer.struct.asn1_string_st */
            	1600, 0,
            1, 8, 1, /* 1650: pointer.struct.asn1_string_st */
            	1600, 0,
            1, 8, 1, /* 1655: pointer.struct.asn1_string_st */
            	1600, 0,
            1, 8, 1, /* 1660: pointer.struct.asn1_string_st */
            	1600, 0,
            1, 8, 1, /* 1665: pointer.struct.asn1_string_st */
            	1600, 0,
            1, 8, 1, /* 1670: pointer.struct.asn1_string_st */
            	1600, 0,
            1, 8, 1, /* 1675: pointer.struct.stack_st_X509_EXTENSION */
            	1680, 0,
            0, 32, 2, /* 1680: struct.stack_st_fake_X509_EXTENSION */
            	1687, 8,
            	86, 24,
            64099, 8, 2, /* 1687: pointer_to_array_of_pointers_to_stack */
            	1694, 0,
            	83, 20,
            0, 8, 1, /* 1694: pointer.X509_EXTENSION */
            	34, 0,
            0, 24, 1, /* 1699: struct.ASN1_ENCODING_st */
            	78, 0,
            1, 8, 1, /* 1704: pointer.struct.AUTHORITY_KEYID_st */
            	1709, 0,
            0, 0, 0, /* 1709: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 1712: pointer.struct.X509_POLICY_CACHE_st */
            	1717, 0,
            0, 0, 0, /* 1717: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1720: pointer.struct.stack_st_DIST_POINT */
            	1725, 0,
            0, 32, 2, /* 1725: struct.stack_st_fake_DIST_POINT */
            	1732, 8,
            	86, 24,
            64099, 8, 2, /* 1732: pointer_to_array_of_pointers_to_stack */
            	1739, 0,
            	83, 20,
            0, 8, 1, /* 1739: pointer.DIST_POINT */
            	1744, 0,
            0, 0, 1, /* 1744: DIST_POINT */
            	1749, 0,
            0, 32, 3, /* 1749: struct.DIST_POINT_st */
            	1758, 0,
            	2119, 8,
            	1777, 16,
            1, 8, 1, /* 1758: pointer.struct.DIST_POINT_NAME_st */
            	1763, 0,
            0, 24, 2, /* 1763: struct.DIST_POINT_NAME_st */
            	1770, 8,
            	2095, 16,
            0, 8, 2, /* 1770: union.unknown */
            	1777, 0,
            	2071, 0,
            1, 8, 1, /* 1777: pointer.struct.stack_st_GENERAL_NAME */
            	1782, 0,
            0, 32, 2, /* 1782: struct.stack_st_fake_GENERAL_NAME */
            	1789, 8,
            	86, 24,
            64099, 8, 2, /* 1789: pointer_to_array_of_pointers_to_stack */
            	1796, 0,
            	83, 20,
            0, 8, 1, /* 1796: pointer.GENERAL_NAME */
            	1801, 0,
            0, 0, 1, /* 1801: GENERAL_NAME */
            	1806, 0,
            0, 16, 1, /* 1806: struct.GENERAL_NAME_st */
            	1811, 8,
            0, 8, 15, /* 1811: union.unknown */
            	99, 0,
            	1844, 0,
            	1963, 0,
            	1963, 0,
            	1870, 0,
            	2011, 0,
            	2059, 0,
            	1963, 0,
            	1948, 0,
            	1856, 0,
            	1948, 0,
            	2011, 0,
            	1963, 0,
            	1856, 0,
            	1870, 0,
            1, 8, 1, /* 1844: pointer.struct.otherName_st */
            	1849, 0,
            0, 16, 2, /* 1849: struct.otherName_st */
            	1856, 0,
            	1870, 8,
            1, 8, 1, /* 1856: pointer.struct.asn1_object_st */
            	1861, 0,
            0, 40, 3, /* 1861: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 1870: pointer.struct.asn1_type_st */
            	1875, 0,
            0, 16, 1, /* 1875: struct.asn1_type_st */
            	1880, 8,
            0, 8, 20, /* 1880: union.unknown */
            	99, 0,
            	1923, 0,
            	1856, 0,
            	1933, 0,
            	1938, 0,
            	1943, 0,
            	1948, 0,
            	1953, 0,
            	1958, 0,
            	1963, 0,
            	1968, 0,
            	1973, 0,
            	1978, 0,
            	1983, 0,
            	1988, 0,
            	1993, 0,
            	1998, 0,
            	1923, 0,
            	1923, 0,
            	2003, 0,
            1, 8, 1, /* 1923: pointer.struct.asn1_string_st */
            	1928, 0,
            0, 24, 1, /* 1928: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 1933: pointer.struct.asn1_string_st */
            	1928, 0,
            1, 8, 1, /* 1938: pointer.struct.asn1_string_st */
            	1928, 0,
            1, 8, 1, /* 1943: pointer.struct.asn1_string_st */
            	1928, 0,
            1, 8, 1, /* 1948: pointer.struct.asn1_string_st */
            	1928, 0,
            1, 8, 1, /* 1953: pointer.struct.asn1_string_st */
            	1928, 0,
            1, 8, 1, /* 1958: pointer.struct.asn1_string_st */
            	1928, 0,
            1, 8, 1, /* 1963: pointer.struct.asn1_string_st */
            	1928, 0,
            1, 8, 1, /* 1968: pointer.struct.asn1_string_st */
            	1928, 0,
            1, 8, 1, /* 1973: pointer.struct.asn1_string_st */
            	1928, 0,
            1, 8, 1, /* 1978: pointer.struct.asn1_string_st */
            	1928, 0,
            1, 8, 1, /* 1983: pointer.struct.asn1_string_st */
            	1928, 0,
            1, 8, 1, /* 1988: pointer.struct.asn1_string_st */
            	1928, 0,
            1, 8, 1, /* 1993: pointer.struct.asn1_string_st */
            	1928, 0,
            1, 8, 1, /* 1998: pointer.struct.asn1_string_st */
            	1928, 0,
            1, 8, 1, /* 2003: pointer.struct.ASN1_VALUE_st */
            	2008, 0,
            0, 0, 0, /* 2008: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2011: pointer.struct.X509_name_st */
            	2016, 0,
            0, 40, 3, /* 2016: struct.X509_name_st */
            	2025, 0,
            	2049, 16,
            	78, 24,
            1, 8, 1, /* 2025: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2030, 0,
            0, 32, 2, /* 2030: struct.stack_st_fake_X509_NAME_ENTRY */
            	2037, 8,
            	86, 24,
            64099, 8, 2, /* 2037: pointer_to_array_of_pointers_to_stack */
            	2044, 0,
            	83, 20,
            0, 8, 1, /* 2044: pointer.X509_NAME_ENTRY */
            	128, 0,
            1, 8, 1, /* 2049: pointer.struct.buf_mem_st */
            	2054, 0,
            0, 24, 1, /* 2054: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 2059: pointer.struct.EDIPartyName_st */
            	2064, 0,
            0, 16, 2, /* 2064: struct.EDIPartyName_st */
            	1923, 0,
            	1923, 8,
            1, 8, 1, /* 2071: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2076, 0,
            0, 32, 2, /* 2076: struct.stack_st_fake_X509_NAME_ENTRY */
            	2083, 8,
            	86, 24,
            64099, 8, 2, /* 2083: pointer_to_array_of_pointers_to_stack */
            	2090, 0,
            	83, 20,
            0, 8, 1, /* 2090: pointer.X509_NAME_ENTRY */
            	128, 0,
            1, 8, 1, /* 2095: pointer.struct.X509_name_st */
            	2100, 0,
            0, 40, 3, /* 2100: struct.X509_name_st */
            	2071, 0,
            	2109, 16,
            	78, 24,
            1, 8, 1, /* 2109: pointer.struct.buf_mem_st */
            	2114, 0,
            0, 24, 1, /* 2114: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 2119: pointer.struct.asn1_string_st */
            	2124, 0,
            0, 24, 1, /* 2124: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 2129: pointer.struct.stack_st_GENERAL_NAME */
            	2134, 0,
            0, 32, 2, /* 2134: struct.stack_st_fake_GENERAL_NAME */
            	2141, 8,
            	86, 24,
            64099, 8, 2, /* 2141: pointer_to_array_of_pointers_to_stack */
            	2148, 0,
            	83, 20,
            0, 8, 1, /* 2148: pointer.GENERAL_NAME */
            	1801, 0,
            1, 8, 1, /* 2153: pointer.struct.NAME_CONSTRAINTS_st */
            	2158, 0,
            0, 0, 0, /* 2158: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 2161: pointer.struct.x509_cert_aux_st */
            	2166, 0,
            0, 40, 5, /* 2166: struct.x509_cert_aux_st */
            	2179, 0,
            	2179, 8,
            	854, 16,
            	804, 24,
            	2217, 32,
            1, 8, 1, /* 2179: pointer.struct.stack_st_ASN1_OBJECT */
            	2184, 0,
            0, 32, 2, /* 2184: struct.stack_st_fake_ASN1_OBJECT */
            	2191, 8,
            	86, 24,
            64099, 8, 2, /* 2191: pointer_to_array_of_pointers_to_stack */
            	2198, 0,
            	83, 20,
            0, 8, 1, /* 2198: pointer.ASN1_OBJECT */
            	2203, 0,
            0, 0, 1, /* 2203: ASN1_OBJECT */
            	2208, 0,
            0, 40, 3, /* 2208: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 2217: pointer.struct.stack_st_X509_ALGOR */
            	2222, 0,
            0, 32, 2, /* 2222: struct.stack_st_fake_X509_ALGOR */
            	2229, 8,
            	86, 24,
            64099, 8, 2, /* 2229: pointer_to_array_of_pointers_to_stack */
            	2236, 0,
            	83, 20,
            0, 8, 1, /* 2236: pointer.X509_ALGOR */
            	2241, 0,
            0, 0, 1, /* 2241: X509_ALGOR */
            	2246, 0,
            0, 16, 2, /* 2246: struct.X509_algor_st */
            	2253, 0,
            	2267, 8,
            1, 8, 1, /* 2253: pointer.struct.asn1_object_st */
            	2258, 0,
            0, 40, 3, /* 2258: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 2267: pointer.struct.asn1_type_st */
            	2272, 0,
            0, 16, 1, /* 2272: struct.asn1_type_st */
            	2277, 8,
            0, 8, 20, /* 2277: union.unknown */
            	99, 0,
            	2320, 0,
            	2253, 0,
            	2330, 0,
            	2335, 0,
            	2340, 0,
            	2345, 0,
            	2350, 0,
            	2355, 0,
            	2360, 0,
            	2365, 0,
            	2370, 0,
            	2375, 0,
            	2380, 0,
            	2385, 0,
            	2390, 0,
            	2395, 0,
            	2320, 0,
            	2320, 0,
            	859, 0,
            1, 8, 1, /* 2320: pointer.struct.asn1_string_st */
            	2325, 0,
            0, 24, 1, /* 2325: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 2330: pointer.struct.asn1_string_st */
            	2325, 0,
            1, 8, 1, /* 2335: pointer.struct.asn1_string_st */
            	2325, 0,
            1, 8, 1, /* 2340: pointer.struct.asn1_string_st */
            	2325, 0,
            1, 8, 1, /* 2345: pointer.struct.asn1_string_st */
            	2325, 0,
            1, 8, 1, /* 2350: pointer.struct.asn1_string_st */
            	2325, 0,
            1, 8, 1, /* 2355: pointer.struct.asn1_string_st */
            	2325, 0,
            1, 8, 1, /* 2360: pointer.struct.asn1_string_st */
            	2325, 0,
            1, 8, 1, /* 2365: pointer.struct.asn1_string_st */
            	2325, 0,
            1, 8, 1, /* 2370: pointer.struct.asn1_string_st */
            	2325, 0,
            1, 8, 1, /* 2375: pointer.struct.asn1_string_st */
            	2325, 0,
            1, 8, 1, /* 2380: pointer.struct.asn1_string_st */
            	2325, 0,
            1, 8, 1, /* 2385: pointer.struct.asn1_string_st */
            	2325, 0,
            1, 8, 1, /* 2390: pointer.struct.asn1_string_st */
            	2325, 0,
            1, 8, 1, /* 2395: pointer.struct.asn1_string_st */
            	2325, 0,
            1, 8, 1, /* 2400: pointer.struct.X509_crl_st */
            	2405, 0,
            0, 120, 10, /* 2405: struct.X509_crl_st */
            	2428, 0,
            	710, 8,
            	799, 16,
            	1704, 32,
            	2555, 40,
            	700, 56,
            	700, 64,
            	2563, 96,
            	2604, 104,
            	273, 112,
            1, 8, 1, /* 2428: pointer.struct.X509_crl_info_st */
            	2433, 0,
            0, 80, 8, /* 2433: struct.X509_crl_info_st */
            	700, 0,
            	710, 8,
            	867, 16,
            	927, 24,
            	927, 32,
            	2452, 40,
            	1675, 48,
            	1699, 56,
            1, 8, 1, /* 2452: pointer.struct.stack_st_X509_REVOKED */
            	2457, 0,
            0, 32, 2, /* 2457: struct.stack_st_fake_X509_REVOKED */
            	2464, 8,
            	86, 24,
            64099, 8, 2, /* 2464: pointer_to_array_of_pointers_to_stack */
            	2471, 0,
            	83, 20,
            0, 8, 1, /* 2471: pointer.X509_REVOKED */
            	2476, 0,
            0, 0, 1, /* 2476: X509_REVOKED */
            	2481, 0,
            0, 40, 4, /* 2481: struct.x509_revoked_st */
            	2492, 0,
            	2502, 8,
            	2507, 16,
            	2531, 24,
            1, 8, 1, /* 2492: pointer.struct.asn1_string_st */
            	2497, 0,
            0, 24, 1, /* 2497: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 2502: pointer.struct.asn1_string_st */
            	2497, 0,
            1, 8, 1, /* 2507: pointer.struct.stack_st_X509_EXTENSION */
            	2512, 0,
            0, 32, 2, /* 2512: struct.stack_st_fake_X509_EXTENSION */
            	2519, 8,
            	86, 24,
            64099, 8, 2, /* 2519: pointer_to_array_of_pointers_to_stack */
            	2526, 0,
            	83, 20,
            0, 8, 1, /* 2526: pointer.X509_EXTENSION */
            	34, 0,
            1, 8, 1, /* 2531: pointer.struct.stack_st_GENERAL_NAME */
            	2536, 0,
            0, 32, 2, /* 2536: struct.stack_st_fake_GENERAL_NAME */
            	2543, 8,
            	86, 24,
            64099, 8, 2, /* 2543: pointer_to_array_of_pointers_to_stack */
            	2550, 0,
            	83, 20,
            0, 8, 1, /* 2550: pointer.GENERAL_NAME */
            	1801, 0,
            1, 8, 1, /* 2555: pointer.struct.ISSUING_DIST_POINT_st */
            	2560, 0,
            0, 0, 0, /* 2560: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 2563: pointer.struct.stack_st_GENERAL_NAMES */
            	2568, 0,
            0, 32, 2, /* 2568: struct.stack_st_fake_GENERAL_NAMES */
            	2575, 8,
            	86, 24,
            64099, 8, 2, /* 2575: pointer_to_array_of_pointers_to_stack */
            	2582, 0,
            	83, 20,
            0, 8, 1, /* 2582: pointer.GENERAL_NAMES */
            	2587, 0,
            0, 0, 1, /* 2587: GENERAL_NAMES */
            	2592, 0,
            0, 32, 1, /* 2592: struct.stack_st_GENERAL_NAME */
            	2597, 0,
            0, 32, 2, /* 2597: struct.stack_st */
            	1120, 8,
            	86, 24,
            1, 8, 1, /* 2604: pointer.struct.x509_crl_method_st */
            	2609, 0,
            0, 0, 0, /* 2609: struct.x509_crl_method_st */
            1, 8, 1, /* 2612: pointer.struct.X509_VERIFY_PARAM_st */
            	2617, 0,
            0, 56, 2, /* 2617: struct.X509_VERIFY_PARAM_st */
            	99, 0,
            	2179, 48,
            64097, 8, 0, /* 2624: pointer.func */
            1, 8, 1, /* 2627: pointer.struct.stack_st_X509_LOOKUP */
            	2632, 0,
            0, 32, 2, /* 2632: struct.stack_st_fake_X509_LOOKUP */
            	2639, 8,
            	86, 24,
            64099, 8, 2, /* 2639: pointer_to_array_of_pointers_to_stack */
            	2646, 0,
            	83, 20,
            0, 8, 1, /* 2646: pointer.X509_LOOKUP */
            	492, 0,
            0, 16, 1, /* 2651: struct.tls_session_ticket_ext_st */
            	273, 8,
            1, 8, 1, /* 2656: pointer.struct.tls_session_ticket_ext_st */
            	2651, 0,
            64097, 8, 0, /* 2661: pointer.func */
            64097, 8, 0, /* 2664: pointer.func */
            1, 8, 1, /* 2667: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2672, 0,
            0, 32, 2, /* 2672: struct.stack_st_fake_X509_NAME_ENTRY */
            	2679, 8,
            	86, 24,
            64099, 8, 2, /* 2679: pointer_to_array_of_pointers_to_stack */
            	2686, 0,
            	83, 20,
            0, 8, 1, /* 2686: pointer.X509_NAME_ENTRY */
            	128, 0,
            1, 8, 1, /* 2691: pointer.struct.asn1_string_st */
            	2696, 0,
            0, 24, 1, /* 2696: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 2701: pointer.struct.asn1_string_st */
            	2696, 0,
            0, 144, 12, /* 2706: struct.dh_st */
            	2733, 8,
            	2733, 16,
            	2733, 32,
            	2733, 40,
            	2743, 56,
            	2733, 64,
            	2733, 72,
            	78, 80,
            	2733, 96,
            	2757, 112,
            	2779, 128,
            	2815, 136,
            1, 8, 1, /* 2733: pointer.struct.bignum_st */
            	2738, 0,
            0, 24, 1, /* 2738: struct.bignum_st */
            	295, 0,
            1, 8, 1, /* 2743: pointer.struct.bn_mont_ctx_st */
            	2748, 0,
            0, 96, 3, /* 2748: struct.bn_mont_ctx_st */
            	2738, 8,
            	2738, 32,
            	2738, 56,
            0, 16, 1, /* 2757: struct.crypto_ex_data_st */
            	2762, 0,
            1, 8, 1, /* 2762: pointer.struct.stack_st_void */
            	2767, 0,
            0, 32, 1, /* 2767: struct.stack_st_void */
            	2772, 0,
            0, 32, 2, /* 2772: struct.stack_st */
            	1120, 8,
            	86, 24,
            1, 8, 1, /* 2779: pointer.struct.dh_method */
            	2784, 0,
            0, 72, 8, /* 2784: struct.dh_method */
            	5, 0,
            	2803, 8,
            	2806, 16,
            	2809, 24,
            	2803, 32,
            	2803, 40,
            	99, 56,
            	2812, 64,
            64097, 8, 0, /* 2803: pointer.func */
            64097, 8, 0, /* 2806: pointer.func */
            64097, 8, 0, /* 2809: pointer.func */
            64097, 8, 0, /* 2812: pointer.func */
            1, 8, 1, /* 2815: pointer.struct.engine_st */
            	2820, 0,
            0, 0, 0, /* 2820: struct.engine_st */
            1, 8, 1, /* 2823: pointer.struct.asn1_string_st */
            	2696, 0,
            0, 16, 1, /* 2828: struct.crypto_ex_data_st */
            	2833, 0,
            1, 8, 1, /* 2833: pointer.struct.stack_st_void */
            	2838, 0,
            0, 32, 1, /* 2838: struct.stack_st_void */
            	2843, 0,
            0, 32, 2, /* 2843: struct.stack_st */
            	1120, 8,
            	86, 24,
            0, 168, 17, /* 2850: struct.rsa_st */
            	2887, 16,
            	2942, 24,
            	285, 32,
            	285, 40,
            	285, 48,
            	285, 56,
            	285, 64,
            	285, 72,
            	285, 80,
            	285, 88,
            	2828, 96,
            	2950, 120,
            	2950, 128,
            	2950, 136,
            	99, 144,
            	2964, 152,
            	2964, 160,
            1, 8, 1, /* 2887: pointer.struct.rsa_meth_st */
            	2892, 0,
            0, 112, 13, /* 2892: struct.rsa_meth_st */
            	5, 0,
            	2921, 8,
            	2921, 16,
            	2921, 24,
            	2921, 32,
            	2924, 40,
            	2927, 48,
            	2930, 56,
            	2930, 64,
            	99, 80,
            	2933, 88,
            	2936, 96,
            	2939, 104,
            64097, 8, 0, /* 2921: pointer.func */
            64097, 8, 0, /* 2924: pointer.func */
            64097, 8, 0, /* 2927: pointer.func */
            64097, 8, 0, /* 2930: pointer.func */
            64097, 8, 0, /* 2933: pointer.func */
            64097, 8, 0, /* 2936: pointer.func */
            64097, 8, 0, /* 2939: pointer.func */
            1, 8, 1, /* 2942: pointer.struct.engine_st */
            	2947, 0,
            0, 0, 0, /* 2947: struct.engine_st */
            1, 8, 1, /* 2950: pointer.struct.bn_mont_ctx_st */
            	2955, 0,
            0, 96, 3, /* 2955: struct.bn_mont_ctx_st */
            	290, 8,
            	290, 32,
            	290, 56,
            1, 8, 1, /* 2964: pointer.struct.bn_blinding_st */
            	2969, 0,
            0, 0, 0, /* 2969: struct.bn_blinding_st */
            0, 16, 2, /* 2972: struct.otherName_st */
            	2979, 0,
            	2993, 8,
            1, 8, 1, /* 2979: pointer.struct.asn1_object_st */
            	2984, 0,
            0, 40, 3, /* 2984: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 2993: pointer.struct.asn1_type_st */
            	2998, 0,
            0, 16, 1, /* 2998: struct.asn1_type_st */
            	3003, 8,
            0, 8, 20, /* 3003: union.unknown */
            	99, 0,
            	3046, 0,
            	2979, 0,
            	3051, 0,
            	3056, 0,
            	3061, 0,
            	3066, 0,
            	3071, 0,
            	3076, 0,
            	2823, 0,
            	2701, 0,
            	3081, 0,
            	3086, 0,
            	3091, 0,
            	2691, 0,
            	3096, 0,
            	3101, 0,
            	3046, 0,
            	3046, 0,
            	2003, 0,
            1, 8, 1, /* 3046: pointer.struct.asn1_string_st */
            	2696, 0,
            1, 8, 1, /* 3051: pointer.struct.asn1_string_st */
            	2696, 0,
            1, 8, 1, /* 3056: pointer.struct.asn1_string_st */
            	2696, 0,
            1, 8, 1, /* 3061: pointer.struct.asn1_string_st */
            	2696, 0,
            1, 8, 1, /* 3066: pointer.struct.asn1_string_st */
            	2696, 0,
            1, 8, 1, /* 3071: pointer.struct.asn1_string_st */
            	2696, 0,
            1, 8, 1, /* 3076: pointer.struct.asn1_string_st */
            	2696, 0,
            1, 8, 1, /* 3081: pointer.struct.asn1_string_st */
            	2696, 0,
            1, 8, 1, /* 3086: pointer.struct.asn1_string_st */
            	2696, 0,
            1, 8, 1, /* 3091: pointer.struct.asn1_string_st */
            	2696, 0,
            1, 8, 1, /* 3096: pointer.struct.asn1_string_st */
            	2696, 0,
            1, 8, 1, /* 3101: pointer.struct.asn1_string_st */
            	2696, 0,
            0, 296, 7, /* 3106: struct.cert_st */
            	3123, 0,
            	4036, 48,
            	4041, 56,
            	4044, 64,
            	4049, 72,
            	4052, 80,
            	4057, 88,
            1, 8, 1, /* 3123: pointer.struct.cert_pkey_st */
            	3128, 0,
            0, 24, 3, /* 3128: struct.cert_pkey_st */
            	3137, 0,
            	3445, 8,
            	3991, 16,
            1, 8, 1, /* 3137: pointer.struct.x509_st */
            	3142, 0,
            0, 184, 12, /* 3142: struct.x509_st */
            	3169, 0,
            	3209, 8,
            	3298, 16,
            	99, 32,
            	2828, 40,
            	3303, 104,
            	3697, 112,
            	3735, 120,
            	3743, 128,
            	3767, 136,
            	3791, 144,
            	3925, 176,
            1, 8, 1, /* 3169: pointer.struct.x509_cinf_st */
            	3174, 0,
            0, 104, 11, /* 3174: struct.x509_cinf_st */
            	3199, 0,
            	3199, 8,
            	3209, 16,
            	3366, 24,
            	3414, 32,
            	3366, 40,
            	3431, 48,
            	3298, 56,
            	3298, 64,
            	3668, 72,
            	3692, 80,
            1, 8, 1, /* 3199: pointer.struct.asn1_string_st */
            	3204, 0,
            0, 24, 1, /* 3204: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 3209: pointer.struct.X509_algor_st */
            	3214, 0,
            0, 16, 2, /* 3214: struct.X509_algor_st */
            	3221, 0,
            	3235, 8,
            1, 8, 1, /* 3221: pointer.struct.asn1_object_st */
            	3226, 0,
            0, 40, 3, /* 3226: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 3235: pointer.struct.asn1_type_st */
            	3240, 0,
            0, 16, 1, /* 3240: struct.asn1_type_st */
            	3245, 8,
            0, 8, 20, /* 3245: union.unknown */
            	99, 0,
            	3288, 0,
            	3221, 0,
            	3199, 0,
            	3293, 0,
            	3298, 0,
            	3303, 0,
            	3308, 0,
            	3313, 0,
            	3318, 0,
            	3323, 0,
            	3328, 0,
            	3333, 0,
            	3338, 0,
            	3343, 0,
            	3348, 0,
            	3353, 0,
            	3288, 0,
            	3288, 0,
            	3358, 0,
            1, 8, 1, /* 3288: pointer.struct.asn1_string_st */
            	3204, 0,
            1, 8, 1, /* 3293: pointer.struct.asn1_string_st */
            	3204, 0,
            1, 8, 1, /* 3298: pointer.struct.asn1_string_st */
            	3204, 0,
            1, 8, 1, /* 3303: pointer.struct.asn1_string_st */
            	3204, 0,
            1, 8, 1, /* 3308: pointer.struct.asn1_string_st */
            	3204, 0,
            1, 8, 1, /* 3313: pointer.struct.asn1_string_st */
            	3204, 0,
            1, 8, 1, /* 3318: pointer.struct.asn1_string_st */
            	3204, 0,
            1, 8, 1, /* 3323: pointer.struct.asn1_string_st */
            	3204, 0,
            1, 8, 1, /* 3328: pointer.struct.asn1_string_st */
            	3204, 0,
            1, 8, 1, /* 3333: pointer.struct.asn1_string_st */
            	3204, 0,
            1, 8, 1, /* 3338: pointer.struct.asn1_string_st */
            	3204, 0,
            1, 8, 1, /* 3343: pointer.struct.asn1_string_st */
            	3204, 0,
            1, 8, 1, /* 3348: pointer.struct.asn1_string_st */
            	3204, 0,
            1, 8, 1, /* 3353: pointer.struct.asn1_string_st */
            	3204, 0,
            1, 8, 1, /* 3358: pointer.struct.ASN1_VALUE_st */
            	3363, 0,
            0, 0, 0, /* 3363: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3366: pointer.struct.X509_name_st */
            	3371, 0,
            0, 40, 3, /* 3371: struct.X509_name_st */
            	3380, 0,
            	3404, 16,
            	78, 24,
            1, 8, 1, /* 3380: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3385, 0,
            0, 32, 2, /* 3385: struct.stack_st_fake_X509_NAME_ENTRY */
            	3392, 8,
            	86, 24,
            64099, 8, 2, /* 3392: pointer_to_array_of_pointers_to_stack */
            	3399, 0,
            	83, 20,
            0, 8, 1, /* 3399: pointer.X509_NAME_ENTRY */
            	128, 0,
            1, 8, 1, /* 3404: pointer.struct.buf_mem_st */
            	3409, 0,
            0, 24, 1, /* 3409: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 3414: pointer.struct.X509_val_st */
            	3419, 0,
            0, 16, 2, /* 3419: struct.X509_val_st */
            	3426, 0,
            	3426, 8,
            1, 8, 1, /* 3426: pointer.struct.asn1_string_st */
            	3204, 0,
            1, 8, 1, /* 3431: pointer.struct.X509_pubkey_st */
            	3436, 0,
            0, 24, 3, /* 3436: struct.X509_pubkey_st */
            	3209, 0,
            	3298, 8,
            	3445, 16,
            1, 8, 1, /* 3445: pointer.struct.evp_pkey_st */
            	3450, 0,
            0, 56, 4, /* 3450: struct.evp_pkey_st */
            	3461, 16,
            	2942, 24,
            	3469, 32,
            	3644, 48,
            1, 8, 1, /* 3461: pointer.struct.evp_pkey_asn1_method_st */
            	3466, 0,
            0, 0, 0, /* 3466: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 3469: union.unknown */
            	99, 0,
            	3482, 0,
            	3487, 0,
            	3568, 0,
            	3636, 0,
            1, 8, 1, /* 3482: pointer.struct.rsa_st */
            	2850, 0,
            1, 8, 1, /* 3487: pointer.struct.dsa_st */
            	3492, 0,
            0, 136, 11, /* 3492: struct.dsa_st */
            	285, 24,
            	285, 32,
            	285, 40,
            	285, 48,
            	285, 56,
            	285, 64,
            	285, 72,
            	2950, 88,
            	2828, 104,
            	3517, 120,
            	2942, 128,
            1, 8, 1, /* 3517: pointer.struct.dsa_method */
            	3522, 0,
            0, 96, 11, /* 3522: struct.dsa_method */
            	5, 0,
            	3547, 8,
            	3550, 16,
            	3553, 24,
            	3556, 32,
            	3559, 40,
            	3562, 48,
            	3562, 56,
            	99, 72,
            	3565, 80,
            	3562, 88,
            64097, 8, 0, /* 3547: pointer.func */
            64097, 8, 0, /* 3550: pointer.func */
            64097, 8, 0, /* 3553: pointer.func */
            64097, 8, 0, /* 3556: pointer.func */
            64097, 8, 0, /* 3559: pointer.func */
            64097, 8, 0, /* 3562: pointer.func */
            64097, 8, 0, /* 3565: pointer.func */
            1, 8, 1, /* 3568: pointer.struct.dh_st */
            	3573, 0,
            0, 144, 12, /* 3573: struct.dh_st */
            	285, 8,
            	285, 16,
            	285, 32,
            	285, 40,
            	2950, 56,
            	285, 64,
            	285, 72,
            	78, 80,
            	285, 96,
            	2828, 112,
            	3600, 128,
            	2942, 136,
            1, 8, 1, /* 3600: pointer.struct.dh_method */
            	3605, 0,
            0, 72, 8, /* 3605: struct.dh_method */
            	5, 0,
            	3624, 8,
            	3627, 16,
            	3630, 24,
            	3624, 32,
            	3624, 40,
            	99, 56,
            	3633, 64,
            64097, 8, 0, /* 3624: pointer.func */
            64097, 8, 0, /* 3627: pointer.func */
            64097, 8, 0, /* 3630: pointer.func */
            64097, 8, 0, /* 3633: pointer.func */
            1, 8, 1, /* 3636: pointer.struct.ec_key_st */
            	3641, 0,
            0, 0, 0, /* 3641: struct.ec_key_st */
            1, 8, 1, /* 3644: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3649, 0,
            0, 32, 2, /* 3649: struct.stack_st_fake_X509_ATTRIBUTE */
            	3656, 8,
            	86, 24,
            64099, 8, 2, /* 3656: pointer_to_array_of_pointers_to_stack */
            	3663, 0,
            	83, 20,
            0, 8, 1, /* 3663: pointer.X509_ATTRIBUTE */
            	1328, 0,
            1, 8, 1, /* 3668: pointer.struct.stack_st_X509_EXTENSION */
            	3673, 0,
            0, 32, 2, /* 3673: struct.stack_st_fake_X509_EXTENSION */
            	3680, 8,
            	86, 24,
            64099, 8, 2, /* 3680: pointer_to_array_of_pointers_to_stack */
            	3687, 0,
            	83, 20,
            0, 8, 1, /* 3687: pointer.X509_EXTENSION */
            	34, 0,
            0, 24, 1, /* 3692: struct.ASN1_ENCODING_st */
            	78, 0,
            1, 8, 1, /* 3697: pointer.struct.AUTHORITY_KEYID_st */
            	3702, 0,
            0, 24, 3, /* 3702: struct.AUTHORITY_KEYID_st */
            	3303, 0,
            	3711, 8,
            	3199, 16,
            1, 8, 1, /* 3711: pointer.struct.stack_st_GENERAL_NAME */
            	3716, 0,
            0, 32, 2, /* 3716: struct.stack_st_fake_GENERAL_NAME */
            	3723, 8,
            	86, 24,
            64099, 8, 2, /* 3723: pointer_to_array_of_pointers_to_stack */
            	3730, 0,
            	83, 20,
            0, 8, 1, /* 3730: pointer.GENERAL_NAME */
            	1801, 0,
            1, 8, 1, /* 3735: pointer.struct.X509_POLICY_CACHE_st */
            	3740, 0,
            0, 0, 0, /* 3740: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 3743: pointer.struct.stack_st_DIST_POINT */
            	3748, 0,
            0, 32, 2, /* 3748: struct.stack_st_fake_DIST_POINT */
            	3755, 8,
            	86, 24,
            64099, 8, 2, /* 3755: pointer_to_array_of_pointers_to_stack */
            	3762, 0,
            	83, 20,
            0, 8, 1, /* 3762: pointer.DIST_POINT */
            	1744, 0,
            1, 8, 1, /* 3767: pointer.struct.stack_st_GENERAL_NAME */
            	3772, 0,
            0, 32, 2, /* 3772: struct.stack_st_fake_GENERAL_NAME */
            	3779, 8,
            	86, 24,
            64099, 8, 2, /* 3779: pointer_to_array_of_pointers_to_stack */
            	3786, 0,
            	83, 20,
            0, 8, 1, /* 3786: pointer.GENERAL_NAME */
            	1801, 0,
            1, 8, 1, /* 3791: pointer.struct.NAME_CONSTRAINTS_st */
            	3796, 0,
            0, 16, 2, /* 3796: struct.NAME_CONSTRAINTS_st */
            	3803, 0,
            	3803, 8,
            1, 8, 1, /* 3803: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3808, 0,
            0, 32, 2, /* 3808: struct.stack_st_fake_GENERAL_SUBTREE */
            	3815, 8,
            	86, 24,
            64099, 8, 2, /* 3815: pointer_to_array_of_pointers_to_stack */
            	3822, 0,
            	83, 20,
            0, 8, 1, /* 3822: pointer.GENERAL_SUBTREE */
            	3827, 0,
            0, 0, 1, /* 3827: GENERAL_SUBTREE */
            	3832, 0,
            0, 24, 3, /* 3832: struct.GENERAL_SUBTREE_st */
            	3841, 0,
            	3051, 8,
            	3051, 16,
            1, 8, 1, /* 3841: pointer.struct.GENERAL_NAME_st */
            	3846, 0,
            0, 16, 1, /* 3846: struct.GENERAL_NAME_st */
            	3851, 8,
            0, 8, 15, /* 3851: union.unknown */
            	99, 0,
            	3884, 0,
            	2823, 0,
            	2823, 0,
            	2993, 0,
            	3889, 0,
            	3913, 0,
            	2823, 0,
            	3066, 0,
            	2979, 0,
            	3066, 0,
            	3889, 0,
            	2823, 0,
            	2979, 0,
            	2993, 0,
            1, 8, 1, /* 3884: pointer.struct.otherName_st */
            	2972, 0,
            1, 8, 1, /* 3889: pointer.struct.X509_name_st */
            	3894, 0,
            0, 40, 3, /* 3894: struct.X509_name_st */
            	2667, 0,
            	3903, 16,
            	78, 24,
            1, 8, 1, /* 3903: pointer.struct.buf_mem_st */
            	3908, 0,
            0, 24, 1, /* 3908: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 3913: pointer.struct.EDIPartyName_st */
            	3918, 0,
            0, 16, 2, /* 3918: struct.EDIPartyName_st */
            	3046, 0,
            	3046, 8,
            1, 8, 1, /* 3925: pointer.struct.x509_cert_aux_st */
            	3930, 0,
            0, 40, 5, /* 3930: struct.x509_cert_aux_st */
            	3943, 0,
            	3943, 8,
            	3353, 16,
            	3303, 24,
            	3967, 32,
            1, 8, 1, /* 3943: pointer.struct.stack_st_ASN1_OBJECT */
            	3948, 0,
            0, 32, 2, /* 3948: struct.stack_st_fake_ASN1_OBJECT */
            	3955, 8,
            	86, 24,
            64099, 8, 2, /* 3955: pointer_to_array_of_pointers_to_stack */
            	3962, 0,
            	83, 20,
            0, 8, 1, /* 3962: pointer.ASN1_OBJECT */
            	2203, 0,
            1, 8, 1, /* 3967: pointer.struct.stack_st_X509_ALGOR */
            	3972, 0,
            0, 32, 2, /* 3972: struct.stack_st_fake_X509_ALGOR */
            	3979, 8,
            	86, 24,
            64099, 8, 2, /* 3979: pointer_to_array_of_pointers_to_stack */
            	3986, 0,
            	83, 20,
            0, 8, 1, /* 3986: pointer.X509_ALGOR */
            	2241, 0,
            1, 8, 1, /* 3991: pointer.struct.env_md_st */
            	3996, 0,
            0, 120, 8, /* 3996: struct.env_md_st */
            	4015, 24,
            	4018, 32,
            	4021, 40,
            	4024, 48,
            	4015, 56,
            	4027, 64,
            	4030, 72,
            	4033, 112,
            64097, 8, 0, /* 4015: pointer.func */
            64097, 8, 0, /* 4018: pointer.func */
            64097, 8, 0, /* 4021: pointer.func */
            64097, 8, 0, /* 4024: pointer.func */
            64097, 8, 0, /* 4027: pointer.func */
            64097, 8, 0, /* 4030: pointer.func */
            64097, 8, 0, /* 4033: pointer.func */
            1, 8, 1, /* 4036: pointer.struct.rsa_st */
            	2850, 0,
            64097, 8, 0, /* 4041: pointer.func */
            1, 8, 1, /* 4044: pointer.struct.dh_st */
            	3573, 0,
            64097, 8, 0, /* 4049: pointer.func */
            1, 8, 1, /* 4052: pointer.struct.ec_key_st */
            	3641, 0,
            64097, 8, 0, /* 4057: pointer.func */
            1, 8, 1, /* 4060: pointer.struct.ASN1_VALUE_st */
            	4065, 0,
            0, 0, 0, /* 4065: struct.ASN1_VALUE_st */
            64097, 8, 0, /* 4068: pointer.func */
            1, 8, 1, /* 4071: pointer.struct.stack_st_ASN1_OBJECT */
            	4076, 0,
            0, 32, 2, /* 4076: struct.stack_st_fake_ASN1_OBJECT */
            	4083, 8,
            	86, 24,
            64099, 8, 2, /* 4083: pointer_to_array_of_pointers_to_stack */
            	4090, 0,
            	83, 20,
            0, 8, 1, /* 4090: pointer.ASN1_OBJECT */
            	2203, 0,
            64097, 8, 0, /* 4095: pointer.func */
            0, 0, 0, /* 4098: struct._pqueue */
            64097, 8, 0, /* 4101: pointer.func */
            0, 24, 1, /* 4104: struct.ssl3_buffer_st */
            	78, 0,
            0, 0, 0, /* 4109: struct.evp_pkey_ctx_st */
            64097, 8, 0, /* 4112: pointer.func */
            0, 24, 1, /* 4115: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 4120: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	4125, 0,
            0, 32, 2, /* 4125: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	4132, 8,
            	86, 24,
            64099, 8, 2, /* 4132: pointer_to_array_of_pointers_to_stack */
            	4139, 0,
            	83, 20,
            0, 8, 1, /* 4139: pointer.SRTP_PROTECTION_PROFILE */
            	229, 0,
            64097, 8, 0, /* 4144: pointer.func */
            64097, 8, 0, /* 4147: pointer.func */
            64097, 8, 0, /* 4150: pointer.func */
            1, 8, 1, /* 4153: pointer.struct.X509_pubkey_st */
            	4158, 0,
            0, 24, 3, /* 4158: struct.X509_pubkey_st */
            	4167, 0,
            	4261, 8,
            	4321, 16,
            1, 8, 1, /* 4167: pointer.struct.X509_algor_st */
            	4172, 0,
            0, 16, 2, /* 4172: struct.X509_algor_st */
            	4179, 0,
            	4193, 8,
            1, 8, 1, /* 4179: pointer.struct.asn1_object_st */
            	4184, 0,
            0, 40, 3, /* 4184: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 4193: pointer.struct.asn1_type_st */
            	4198, 0,
            0, 16, 1, /* 4198: struct.asn1_type_st */
            	4203, 8,
            0, 8, 20, /* 4203: union.unknown */
            	99, 0,
            	4246, 0,
            	4179, 0,
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
            	4306, 0,
            	4311, 0,
            	4316, 0,
            	4246, 0,
            	4246, 0,
            	4060, 0,
            1, 8, 1, /* 4246: pointer.struct.asn1_string_st */
            	4115, 0,
            1, 8, 1, /* 4251: pointer.struct.asn1_string_st */
            	4115, 0,
            1, 8, 1, /* 4256: pointer.struct.asn1_string_st */
            	4115, 0,
            1, 8, 1, /* 4261: pointer.struct.asn1_string_st */
            	4115, 0,
            1, 8, 1, /* 4266: pointer.struct.asn1_string_st */
            	4115, 0,
            1, 8, 1, /* 4271: pointer.struct.asn1_string_st */
            	4115, 0,
            1, 8, 1, /* 4276: pointer.struct.asn1_string_st */
            	4115, 0,
            1, 8, 1, /* 4281: pointer.struct.asn1_string_st */
            	4115, 0,
            1, 8, 1, /* 4286: pointer.struct.asn1_string_st */
            	4115, 0,
            1, 8, 1, /* 4291: pointer.struct.asn1_string_st */
            	4115, 0,
            1, 8, 1, /* 4296: pointer.struct.asn1_string_st */
            	4115, 0,
            1, 8, 1, /* 4301: pointer.struct.asn1_string_st */
            	4115, 0,
            1, 8, 1, /* 4306: pointer.struct.asn1_string_st */
            	4115, 0,
            1, 8, 1, /* 4311: pointer.struct.asn1_string_st */
            	4115, 0,
            1, 8, 1, /* 4316: pointer.struct.asn1_string_st */
            	4115, 0,
            1, 8, 1, /* 4321: pointer.struct.evp_pkey_st */
            	4326, 0,
            0, 56, 4, /* 4326: struct.evp_pkey_st */
            	4337, 16,
            	2815, 24,
            	4345, 32,
            	4551, 48,
            1, 8, 1, /* 4337: pointer.struct.evp_pkey_asn1_method_st */
            	4342, 0,
            0, 0, 0, /* 4342: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 4345: union.unknown */
            	99, 0,
            	4358, 0,
            	4460, 0,
            	4538, 0,
            	4543, 0,
            1, 8, 1, /* 4358: pointer.struct.rsa_st */
            	4363, 0,
            0, 168, 17, /* 4363: struct.rsa_st */
            	4400, 16,
            	2815, 24,
            	2733, 32,
            	2733, 40,
            	2733, 48,
            	2733, 56,
            	2733, 64,
            	2733, 72,
            	2733, 80,
            	2733, 88,
            	2757, 96,
            	2743, 120,
            	2743, 128,
            	2743, 136,
            	99, 144,
            	4452, 152,
            	4452, 160,
            1, 8, 1, /* 4400: pointer.struct.rsa_meth_st */
            	4405, 0,
            0, 112, 13, /* 4405: struct.rsa_meth_st */
            	5, 0,
            	4434, 8,
            	4434, 16,
            	4434, 24,
            	4434, 32,
            	4095, 40,
            	4437, 48,
            	4440, 56,
            	4440, 64,
            	99, 80,
            	4443, 88,
            	4446, 96,
            	4449, 104,
            64097, 8, 0, /* 4434: pointer.func */
            64097, 8, 0, /* 4437: pointer.func */
            64097, 8, 0, /* 4440: pointer.func */
            64097, 8, 0, /* 4443: pointer.func */
            64097, 8, 0, /* 4446: pointer.func */
            64097, 8, 0, /* 4449: pointer.func */
            1, 8, 1, /* 4452: pointer.struct.bn_blinding_st */
            	4457, 0,
            0, 0, 0, /* 4457: struct.bn_blinding_st */
            1, 8, 1, /* 4460: pointer.struct.dsa_st */
            	4465, 0,
            0, 136, 11, /* 4465: struct.dsa_st */
            	2733, 24,
            	2733, 32,
            	2733, 40,
            	2733, 48,
            	2733, 56,
            	2733, 64,
            	2733, 72,
            	2743, 88,
            	2757, 104,
            	4490, 120,
            	2815, 128,
            1, 8, 1, /* 4490: pointer.struct.dsa_method */
            	4495, 0,
            0, 96, 11, /* 4495: struct.dsa_method */
            	5, 0,
            	4520, 8,
            	4523, 16,
            	4526, 24,
            	4112, 32,
            	4529, 40,
            	4532, 48,
            	4532, 56,
            	99, 72,
            	4535, 80,
            	4532, 88,
            64097, 8, 0, /* 4520: pointer.func */
            64097, 8, 0, /* 4523: pointer.func */
            64097, 8, 0, /* 4526: pointer.func */
            64097, 8, 0, /* 4529: pointer.func */
            64097, 8, 0, /* 4532: pointer.func */
            64097, 8, 0, /* 4535: pointer.func */
            1, 8, 1, /* 4538: pointer.struct.dh_st */
            	2706, 0,
            1, 8, 1, /* 4543: pointer.struct.ec_key_st */
            	4548, 0,
            0, 0, 0, /* 4548: struct.ec_key_st */
            1, 8, 1, /* 4551: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4556, 0,
            0, 32, 2, /* 4556: struct.stack_st_fake_X509_ATTRIBUTE */
            	4563, 8,
            	86, 24,
            64099, 8, 2, /* 4563: pointer_to_array_of_pointers_to_stack */
            	4570, 0,
            	83, 20,
            0, 8, 1, /* 4570: pointer.X509_ATTRIBUTE */
            	1328, 0,
            0, 112, 7, /* 4575: struct.bio_st */
            	4592, 0,
            	4633, 8,
            	99, 16,
            	273, 48,
            	4636, 56,
            	4636, 64,
            	2828, 96,
            1, 8, 1, /* 4592: pointer.struct.bio_method_st */
            	4597, 0,
            0, 80, 9, /* 4597: struct.bio_method_st */
            	5, 8,
            	4618, 16,
            	4150, 24,
            	4621, 32,
            	4150, 40,
            	4624, 48,
            	4627, 56,
            	4627, 64,
            	4630, 72,
            64097, 8, 0, /* 4618: pointer.func */
            64097, 8, 0, /* 4621: pointer.func */
            64097, 8, 0, /* 4624: pointer.func */
            64097, 8, 0, /* 4627: pointer.func */
            64097, 8, 0, /* 4630: pointer.func */
            64097, 8, 0, /* 4633: pointer.func */
            1, 8, 1, /* 4636: pointer.struct.bio_st */
            	4575, 0,
            64097, 8, 0, /* 4641: pointer.func */
            1, 8, 1, /* 4644: pointer.struct.lhash_st */
            	417, 0,
            64097, 8, 0, /* 4649: pointer.func */
            64097, 8, 0, /* 4652: pointer.func */
            64097, 8, 0, /* 4655: pointer.func */
            64097, 8, 0, /* 4658: pointer.func */
            1, 8, 1, /* 4661: pointer.struct.ssl_session_st */
            	4666, 0,
            0, 352, 14, /* 4666: struct.ssl_session_st */
            	99, 144,
            	99, 152,
            	4697, 168,
            	3137, 176,
            	5009, 224,
            	5019, 240,
            	2828, 248,
            	4661, 264,
            	4661, 272,
            	99, 280,
            	78, 296,
            	78, 312,
            	78, 320,
            	99, 344,
            1, 8, 1, /* 4697: pointer.struct.sess_cert_st */
            	4702, 0,
            0, 248, 5, /* 4702: struct.sess_cert_st */
            	4715, 0,
            	3123, 16,
            	4036, 216,
            	4044, 224,
            	4052, 232,
            1, 8, 1, /* 4715: pointer.struct.stack_st_X509 */
            	4720, 0,
            0, 32, 2, /* 4720: struct.stack_st_fake_X509 */
            	4727, 8,
            	86, 24,
            64099, 8, 2, /* 4727: pointer_to_array_of_pointers_to_stack */
            	4734, 0,
            	83, 20,
            0, 8, 1, /* 4734: pointer.X509 */
            	4739, 0,
            0, 0, 1, /* 4739: X509 */
            	4744, 0,
            0, 184, 12, /* 4744: struct.x509_st */
            	4771, 0,
            	4167, 8,
            	4261, 16,
            	99, 32,
            	2757, 40,
            	4266, 104,
            	4895, 112,
            	4903, 120,
            	4911, 128,
            	4935, 136,
            	4959, 144,
            	4967, 176,
            1, 8, 1, /* 4771: pointer.struct.x509_cinf_st */
            	4776, 0,
            0, 104, 11, /* 4776: struct.x509_cinf_st */
            	4251, 0,
            	4251, 8,
            	4167, 16,
            	4801, 24,
            	4849, 32,
            	4801, 40,
            	4153, 48,
            	4261, 56,
            	4261, 64,
            	4866, 72,
            	4890, 80,
            1, 8, 1, /* 4801: pointer.struct.X509_name_st */
            	4806, 0,
            0, 40, 3, /* 4806: struct.X509_name_st */
            	4815, 0,
            	4839, 16,
            	78, 24,
            1, 8, 1, /* 4815: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4820, 0,
            0, 32, 2, /* 4820: struct.stack_st_fake_X509_NAME_ENTRY */
            	4827, 8,
            	86, 24,
            64099, 8, 2, /* 4827: pointer_to_array_of_pointers_to_stack */
            	4834, 0,
            	83, 20,
            0, 8, 1, /* 4834: pointer.X509_NAME_ENTRY */
            	128, 0,
            1, 8, 1, /* 4839: pointer.struct.buf_mem_st */
            	4844, 0,
            0, 24, 1, /* 4844: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 4849: pointer.struct.X509_val_st */
            	4854, 0,
            0, 16, 2, /* 4854: struct.X509_val_st */
            	4861, 0,
            	4861, 8,
            1, 8, 1, /* 4861: pointer.struct.asn1_string_st */
            	4115, 0,
            1, 8, 1, /* 4866: pointer.struct.stack_st_X509_EXTENSION */
            	4871, 0,
            0, 32, 2, /* 4871: struct.stack_st_fake_X509_EXTENSION */
            	4878, 8,
            	86, 24,
            64099, 8, 2, /* 4878: pointer_to_array_of_pointers_to_stack */
            	4885, 0,
            	83, 20,
            0, 8, 1, /* 4885: pointer.X509_EXTENSION */
            	34, 0,
            0, 24, 1, /* 4890: struct.ASN1_ENCODING_st */
            	78, 0,
            1, 8, 1, /* 4895: pointer.struct.AUTHORITY_KEYID_st */
            	4900, 0,
            0, 0, 0, /* 4900: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4903: pointer.struct.X509_POLICY_CACHE_st */
            	4908, 0,
            0, 0, 0, /* 4908: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 4911: pointer.struct.stack_st_DIST_POINT */
            	4916, 0,
            0, 32, 2, /* 4916: struct.stack_st_fake_DIST_POINT */
            	4923, 8,
            	86, 24,
            64099, 8, 2, /* 4923: pointer_to_array_of_pointers_to_stack */
            	4930, 0,
            	83, 20,
            0, 8, 1, /* 4930: pointer.DIST_POINT */
            	1744, 0,
            1, 8, 1, /* 4935: pointer.struct.stack_st_GENERAL_NAME */
            	4940, 0,
            0, 32, 2, /* 4940: struct.stack_st_fake_GENERAL_NAME */
            	4947, 8,
            	86, 24,
            64099, 8, 2, /* 4947: pointer_to_array_of_pointers_to_stack */
            	4954, 0,
            	83, 20,
            0, 8, 1, /* 4954: pointer.GENERAL_NAME */
            	1801, 0,
            1, 8, 1, /* 4959: pointer.struct.NAME_CONSTRAINTS_st */
            	4964, 0,
            0, 0, 0, /* 4964: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4967: pointer.struct.x509_cert_aux_st */
            	4972, 0,
            0, 40, 5, /* 4972: struct.x509_cert_aux_st */
            	4071, 0,
            	4071, 8,
            	4316, 16,
            	4266, 24,
            	4985, 32,
            1, 8, 1, /* 4985: pointer.struct.stack_st_X509_ALGOR */
            	4990, 0,
            0, 32, 2, /* 4990: struct.stack_st_fake_X509_ALGOR */
            	4997, 8,
            	86, 24,
            64099, 8, 2, /* 4997: pointer_to_array_of_pointers_to_stack */
            	5004, 0,
            	83, 20,
            0, 8, 1, /* 5004: pointer.X509_ALGOR */
            	2241, 0,
            1, 8, 1, /* 5009: pointer.struct.ssl_cipher_st */
            	5014, 0,
            0, 88, 1, /* 5014: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 5019: pointer.struct.stack_st_SSL_CIPHER */
            	5024, 0,
            0, 32, 2, /* 5024: struct.stack_st_fake_SSL_CIPHER */
            	5031, 8,
            	86, 24,
            64099, 8, 2, /* 5031: pointer_to_array_of_pointers_to_stack */
            	5038, 0,
            	83, 20,
            0, 8, 1, /* 5038: pointer.SSL_CIPHER */
            	5043, 0,
            0, 0, 1, /* 5043: SSL_CIPHER */
            	5048, 0,
            0, 88, 1, /* 5048: struct.ssl_cipher_st */
            	5, 8,
            0, 1, 0, /* 5053: char */
            64097, 8, 0, /* 5056: pointer.func */
            1, 8, 1, /* 5059: pointer.struct.X509_VERIFY_PARAM_st */
            	5064, 0,
            0, 56, 2, /* 5064: struct.X509_VERIFY_PARAM_st */
            	99, 0,
            	3943, 48,
            64097, 8, 0, /* 5071: pointer.func */
            1, 8, 1, /* 5074: pointer.struct.ssl2_state_st */
            	5079, 0,
            0, 344, 9, /* 5079: struct.ssl2_state_st */
            	60, 24,
            	78, 56,
            	78, 64,
            	78, 72,
            	78, 104,
            	78, 112,
            	78, 120,
            	78, 128,
            	78, 136,
            64097, 8, 0, /* 5100: pointer.func */
            0, 16, 1, /* 5103: struct.record_pqueue_st */
            	5108, 8,
            1, 8, 1, /* 5108: pointer.struct._pqueue */
            	4098, 0,
            0, 40, 3, /* 5113: struct.X509_name_st */
            	5122, 0,
            	5146, 16,
            	78, 24,
            1, 8, 1, /* 5122: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5127, 0,
            0, 32, 2, /* 5127: struct.stack_st_fake_X509_NAME_ENTRY */
            	5134, 8,
            	86, 24,
            64099, 8, 2, /* 5134: pointer_to_array_of_pointers_to_stack */
            	5141, 0,
            	83, 20,
            0, 8, 1, /* 5141: pointer.X509_NAME_ENTRY */
            	128, 0,
            1, 8, 1, /* 5146: pointer.struct.buf_mem_st */
            	5151, 0,
            0, 24, 1, /* 5151: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 5156: pointer.struct.ssl3_buf_freelist_st */
            	5161, 0,
            0, 24, 1, /* 5161: struct.ssl3_buf_freelist_st */
            	303, 16,
            1, 8, 1, /* 5166: pointer.struct.ssl_st */
            	5171, 0,
            0, 808, 51, /* 5171: struct.ssl_st */
            	5276, 8,
            	5421, 16,
            	5421, 24,
            	5421, 32,
            	5340, 48,
            	3404, 80,
            	273, 88,
            	78, 104,
            	5074, 120,
            	5426, 128,
            	5619, 136,
            	5690, 152,
            	273, 160,
            	5059, 176,
            	5019, 184,
            	5019, 192,
            	5657, 208,
            	5468, 216,
            	5673, 224,
            	5657, 232,
            	5468, 240,
            	5673, 248,
            	5693, 256,
            	5685, 304,
            	5698, 312,
            	5701, 328,
            	5704, 336,
            	5707, 352,
            	5710, 360,
            	5713, 368,
            	2828, 392,
            	5510, 408,
            	4641, 464,
            	273, 472,
            	99, 480,
            	195, 504,
            	10, 512,
            	78, 520,
            	78, 544,
            	78, 560,
            	273, 568,
            	2656, 584,
            	4101, 592,
            	273, 600,
            	4655, 608,
            	273, 616,
            	5713, 624,
            	78, 632,
            	4120, 648,
            	5901, 656,
            	242, 680,
            1, 8, 1, /* 5276: pointer.struct.ssl_method_st */
            	5281, 0,
            0, 232, 28, /* 5281: struct.ssl_method_st */
            	5340, 8,
            	5343, 16,
            	5343, 24,
            	5340, 32,
            	5340, 40,
            	5346, 48,
            	5346, 56,
            	4068, 64,
            	5340, 72,
            	5340, 80,
            	5340, 88,
            	5349, 96,
            	5352, 104,
            	5355, 112,
            	5340, 120,
            	5358, 128,
            	5100, 136,
            	5361, 144,
            	5364, 152,
            	5367, 160,
            	5370, 168,
            	4144, 176,
            	4649, 184,
            	354, 192,
            	5373, 200,
            	5370, 208,
            	5415, 216,
            	5418, 224,
            64097, 8, 0, /* 5340: pointer.func */
            64097, 8, 0, /* 5343: pointer.func */
            64097, 8, 0, /* 5346: pointer.func */
            64097, 8, 0, /* 5349: pointer.func */
            64097, 8, 0, /* 5352: pointer.func */
            64097, 8, 0, /* 5355: pointer.func */
            64097, 8, 0, /* 5358: pointer.func */
            64097, 8, 0, /* 5361: pointer.func */
            64097, 8, 0, /* 5364: pointer.func */
            64097, 8, 0, /* 5367: pointer.func */
            64097, 8, 0, /* 5370: pointer.func */
            1, 8, 1, /* 5373: pointer.struct.ssl3_enc_method */
            	5378, 0,
            0, 112, 11, /* 5378: struct.ssl3_enc_method */
            	5403, 0,
            	5406, 8,
            	5340, 16,
            	5409, 24,
            	5403, 32,
            	5412, 40,
            	4652, 56,
            	5, 64,
            	5, 80,
            	4658, 96,
            	5071, 104,
            64097, 8, 0, /* 5403: pointer.func */
            64097, 8, 0, /* 5406: pointer.func */
            64097, 8, 0, /* 5409: pointer.func */
            64097, 8, 0, /* 5412: pointer.func */
            64097, 8, 0, /* 5415: pointer.func */
            64097, 8, 0, /* 5418: pointer.func */
            1, 8, 1, /* 5421: pointer.struct.bio_st */
            	4575, 0,
            1, 8, 1, /* 5426: pointer.struct.ssl3_state_st */
            	5431, 0,
            0, 1200, 10, /* 5431: struct.ssl3_state_st */
            	4104, 240,
            	4104, 264,
            	5454, 288,
            	5454, 344,
            	60, 432,
            	5421, 440,
            	5463, 448,
            	273, 496,
            	273, 512,
            	5491, 528,
            0, 56, 3, /* 5454: struct.ssl3_record_st */
            	78, 16,
            	78, 24,
            	78, 32,
            1, 8, 1, /* 5463: pointer.pointer.struct.env_md_ctx_st */
            	5468, 0,
            1, 8, 1, /* 5468: pointer.struct.env_md_ctx_st */
            	5473, 0,
            0, 48, 5, /* 5473: struct.env_md_ctx_st */
            	3991, 0,
            	2942, 8,
            	273, 24,
            	5486, 32,
            	4018, 40,
            1, 8, 1, /* 5486: pointer.struct.evp_pkey_ctx_st */
            	4109, 0,
            0, 528, 8, /* 5491: struct.unknown */
            	5009, 408,
            	4044, 416,
            	4052, 424,
            	5510, 464,
            	78, 480,
            	5539, 488,
            	3991, 496,
            	5576, 512,
            1, 8, 1, /* 5510: pointer.struct.stack_st_X509_NAME */
            	5515, 0,
            0, 32, 2, /* 5515: struct.stack_st_fake_X509_NAME */
            	5522, 8,
            	86, 24,
            64099, 8, 2, /* 5522: pointer_to_array_of_pointers_to_stack */
            	5529, 0,
            	83, 20,
            0, 8, 1, /* 5529: pointer.X509_NAME */
            	5534, 0,
            0, 0, 1, /* 5534: X509_NAME */
            	5113, 0,
            1, 8, 1, /* 5539: pointer.struct.evp_cipher_st */
            	5544, 0,
            0, 88, 7, /* 5544: struct.evp_cipher_st */
            	5561, 24,
            	5564, 32,
            	5567, 40,
            	5570, 56,
            	5570, 64,
            	5573, 72,
            	273, 80,
            64097, 8, 0, /* 5561: pointer.func */
            64097, 8, 0, /* 5564: pointer.func */
            64097, 8, 0, /* 5567: pointer.func */
            64097, 8, 0, /* 5570: pointer.func */
            64097, 8, 0, /* 5573: pointer.func */
            1, 8, 1, /* 5576: pointer.struct.ssl_comp_st */
            	5581, 0,
            0, 24, 2, /* 5581: struct.ssl_comp_st */
            	5, 8,
            	5588, 16,
            1, 8, 1, /* 5588: pointer.struct.comp_method_st */
            	5593, 0,
            0, 64, 7, /* 5593: struct.comp_method_st */
            	5, 8,
            	5610, 16,
            	5613, 24,
            	5616, 32,
            	5616, 40,
            	354, 48,
            	354, 56,
            64097, 8, 0, /* 5610: pointer.func */
            64097, 8, 0, /* 5613: pointer.func */
            64097, 8, 0, /* 5616: pointer.func */
            1, 8, 1, /* 5619: pointer.struct.dtls1_state_st */
            	5624, 0,
            0, 888, 7, /* 5624: struct.dtls1_state_st */
            	5103, 576,
            	5103, 592,
            	5108, 608,
            	5108, 616,
            	5103, 624,
            	5641, 648,
            	5641, 736,
            0, 88, 1, /* 5641: struct.hm_header_st */
            	5646, 48,
            0, 40, 4, /* 5646: struct.dtls1_retransmit_state */
            	5657, 0,
            	5468, 8,
            	5673, 16,
            	5685, 24,
            1, 8, 1, /* 5657: pointer.struct.evp_cipher_ctx_st */
            	5662, 0,
            0, 168, 4, /* 5662: struct.evp_cipher_ctx_st */
            	5539, 0,
            	2942, 8,
            	273, 96,
            	273, 120,
            1, 8, 1, /* 5673: pointer.struct.comp_ctx_st */
            	5678, 0,
            0, 56, 2, /* 5678: struct.comp_ctx_st */
            	5588, 0,
            	2828, 40,
            1, 8, 1, /* 5685: pointer.struct.ssl_session_st */
            	4666, 0,
            64097, 8, 0, /* 5690: pointer.func */
            1, 8, 1, /* 5693: pointer.struct.cert_st */
            	3106, 0,
            64097, 8, 0, /* 5698: pointer.func */
            64097, 8, 0, /* 5701: pointer.func */
            64097, 8, 0, /* 5704: pointer.func */
            64097, 8, 0, /* 5707: pointer.func */
            64097, 8, 0, /* 5710: pointer.func */
            1, 8, 1, /* 5713: pointer.struct.ssl_ctx_st */
            	5718, 0,
            0, 736, 50, /* 5718: struct.ssl_ctx_st */
            	5276, 0,
            	5019, 8,
            	5019, 16,
            	5821, 24,
            	4644, 32,
            	4661, 48,
            	4661, 56,
            	465, 80,
            	5892, 88,
            	392, 96,
            	2661, 152,
            	273, 160,
            	5895, 168,
            	273, 176,
            	389, 184,
            	5898, 192,
            	386, 200,
            	2828, 208,
            	3991, 224,
            	3991, 232,
            	3991, 240,
            	4715, 248,
            	357, 256,
            	5704, 264,
            	5510, 272,
            	5693, 304,
            	5690, 320,
            	273, 328,
            	5701, 376,
            	5698, 384,
            	5059, 392,
            	2942, 408,
            	276, 416,
            	273, 424,
            	2664, 480,
            	279, 488,
            	273, 496,
            	313, 504,
            	273, 512,
            	99, 520,
            	5707, 528,
            	5710, 536,
            	5156, 552,
            	5156, 560,
            	242, 568,
            	239, 696,
            	273, 704,
            	4147, 712,
            	273, 720,
            	4120, 728,
            1, 8, 1, /* 5821: pointer.struct.x509_store_st */
            	5826, 0,
            0, 144, 15, /* 5826: struct.x509_store_st */
            	5859, 8,
            	2627, 16,
            	5059, 24,
            	438, 32,
            	5701, 40,
            	435, 48,
            	5883, 56,
            	438, 64,
            	5886, 72,
            	432, 80,
            	5056, 88,
            	429, 96,
            	5889, 104,
            	438, 112,
            	2828, 120,
            1, 8, 1, /* 5859: pointer.struct.stack_st_X509_OBJECT */
            	5864, 0,
            0, 32, 2, /* 5864: struct.stack_st_fake_X509_OBJECT */
            	5871, 8,
            	86, 24,
            64099, 8, 2, /* 5871: pointer_to_array_of_pointers_to_stack */
            	5878, 0,
            	83, 20,
            0, 8, 1, /* 5878: pointer.X509_OBJECT */
            	617, 0,
            64097, 8, 0, /* 5883: pointer.func */
            64097, 8, 0, /* 5886: pointer.func */
            64097, 8, 0, /* 5889: pointer.func */
            64097, 8, 0, /* 5892: pointer.func */
            64097, 8, 0, /* 5895: pointer.func */
            64097, 8, 0, /* 5898: pointer.func */
            1, 8, 1, /* 5901: pointer.struct.srtp_protection_profile_st */
            	0, 0,
        },
        .arg_entity_index = { 5166, },
        .ret_entity_index = 3137,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL * new_arg_a = *((const SSL * *)new_args->args[0]);

    X509 * *new_ret_ptr = (X509 * *)new_args->ret;

    X509 * (*orig_SSL_get_peer_certificate)(const SSL *);
    orig_SSL_get_peer_certificate = dlsym(RTLD_NEXT, "SSL_get_peer_certificate");
    *new_ret_ptr = (*orig_SSL_get_peer_certificate)(new_arg_a);

    syscall(889);

    return ret;
}

