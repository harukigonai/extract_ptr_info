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

int bb_SSL_shutdown(SSL * arg_a);

int SSL_shutdown(SSL * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_shutdown called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_shutdown(arg_a);
    else {
        int (*orig_SSL_shutdown)(SSL *);
        orig_SSL_shutdown = dlsym(RTLD_NEXT, "SSL_shutdown");
        return orig_SSL_shutdown(arg_a);
    }
}

int bb_SSL_shutdown(SSL * arg_a) 
{
    int ret;

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
            0, 136, 11, /* 2667: struct.dsa_st */
            	285, 24,
            	285, 32,
            	285, 40,
            	285, 48,
            	285, 56,
            	285, 64,
            	285, 72,
            	2692, 88,
            	2706, 104,
            	2728, 120,
            	2779, 128,
            1, 8, 1, /* 2692: pointer.struct.bn_mont_ctx_st */
            	2697, 0,
            0, 96, 3, /* 2697: struct.bn_mont_ctx_st */
            	290, 8,
            	290, 32,
            	290, 56,
            0, 16, 1, /* 2706: struct.crypto_ex_data_st */
            	2711, 0,
            1, 8, 1, /* 2711: pointer.struct.stack_st_void */
            	2716, 0,
            0, 32, 1, /* 2716: struct.stack_st_void */
            	2721, 0,
            0, 32, 2, /* 2721: struct.stack_st */
            	1120, 8,
            	86, 24,
            1, 8, 1, /* 2728: pointer.struct.dsa_method */
            	2733, 0,
            0, 96, 11, /* 2733: struct.dsa_method */
            	5, 0,
            	2758, 8,
            	2761, 16,
            	2764, 24,
            	2767, 32,
            	2770, 40,
            	2773, 48,
            	2773, 56,
            	99, 72,
            	2776, 80,
            	2773, 88,
            64097, 8, 0, /* 2758: pointer.func */
            64097, 8, 0, /* 2761: pointer.func */
            64097, 8, 0, /* 2764: pointer.func */
            64097, 8, 0, /* 2767: pointer.func */
            64097, 8, 0, /* 2770: pointer.func */
            64097, 8, 0, /* 2773: pointer.func */
            64097, 8, 0, /* 2776: pointer.func */
            1, 8, 1, /* 2779: pointer.struct.engine_st */
            	2784, 0,
            0, 0, 0, /* 2784: struct.engine_st */
            1, 8, 1, /* 2787: pointer.struct.asn1_string_st */
            	2792, 0,
            0, 24, 1, /* 2792: struct.asn1_string_st */
            	78, 8,
            64097, 8, 0, /* 2797: pointer.func */
            0, 184, 12, /* 2800: struct.x509_st */
            	2827, 0,
            	2867, 8,
            	2956, 16,
            	99, 32,
            	2706, 40,
            	2961, 104,
            	3379, 112,
            	3417, 120,
            	3425, 128,
            	3449, 136,
            	3473, 144,
            	3775, 176,
            1, 8, 1, /* 2827: pointer.struct.x509_cinf_st */
            	2832, 0,
            0, 104, 11, /* 2832: struct.x509_cinf_st */
            	2857, 0,
            	2857, 8,
            	2867, 16,
            	3024, 24,
            	3072, 32,
            	3024, 40,
            	3089, 48,
            	2956, 56,
            	2956, 64,
            	3350, 72,
            	3374, 80,
            1, 8, 1, /* 2857: pointer.struct.asn1_string_st */
            	2862, 0,
            0, 24, 1, /* 2862: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 2867: pointer.struct.X509_algor_st */
            	2872, 0,
            0, 16, 2, /* 2872: struct.X509_algor_st */
            	2879, 0,
            	2893, 8,
            1, 8, 1, /* 2879: pointer.struct.asn1_object_st */
            	2884, 0,
            0, 40, 3, /* 2884: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 2893: pointer.struct.asn1_type_st */
            	2898, 0,
            0, 16, 1, /* 2898: struct.asn1_type_st */
            	2903, 8,
            0, 8, 20, /* 2903: union.unknown */
            	99, 0,
            	2946, 0,
            	2879, 0,
            	2857, 0,
            	2951, 0,
            	2956, 0,
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
            	2946, 0,
            	2946, 0,
            	3016, 0,
            1, 8, 1, /* 2946: pointer.struct.asn1_string_st */
            	2862, 0,
            1, 8, 1, /* 2951: pointer.struct.asn1_string_st */
            	2862, 0,
            1, 8, 1, /* 2956: pointer.struct.asn1_string_st */
            	2862, 0,
            1, 8, 1, /* 2961: pointer.struct.asn1_string_st */
            	2862, 0,
            1, 8, 1, /* 2966: pointer.struct.asn1_string_st */
            	2862, 0,
            1, 8, 1, /* 2971: pointer.struct.asn1_string_st */
            	2862, 0,
            1, 8, 1, /* 2976: pointer.struct.asn1_string_st */
            	2862, 0,
            1, 8, 1, /* 2981: pointer.struct.asn1_string_st */
            	2862, 0,
            1, 8, 1, /* 2986: pointer.struct.asn1_string_st */
            	2862, 0,
            1, 8, 1, /* 2991: pointer.struct.asn1_string_st */
            	2862, 0,
            1, 8, 1, /* 2996: pointer.struct.asn1_string_st */
            	2862, 0,
            1, 8, 1, /* 3001: pointer.struct.asn1_string_st */
            	2862, 0,
            1, 8, 1, /* 3006: pointer.struct.asn1_string_st */
            	2862, 0,
            1, 8, 1, /* 3011: pointer.struct.asn1_string_st */
            	2862, 0,
            1, 8, 1, /* 3016: pointer.struct.ASN1_VALUE_st */
            	3021, 0,
            0, 0, 0, /* 3021: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3024: pointer.struct.X509_name_st */
            	3029, 0,
            0, 40, 3, /* 3029: struct.X509_name_st */
            	3038, 0,
            	3062, 16,
            	78, 24,
            1, 8, 1, /* 3038: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3043, 0,
            0, 32, 2, /* 3043: struct.stack_st_fake_X509_NAME_ENTRY */
            	3050, 8,
            	86, 24,
            64099, 8, 2, /* 3050: pointer_to_array_of_pointers_to_stack */
            	3057, 0,
            	83, 20,
            0, 8, 1, /* 3057: pointer.X509_NAME_ENTRY */
            	128, 0,
            1, 8, 1, /* 3062: pointer.struct.buf_mem_st */
            	3067, 0,
            0, 24, 1, /* 3067: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 3072: pointer.struct.X509_val_st */
            	3077, 0,
            0, 16, 2, /* 3077: struct.X509_val_st */
            	3084, 0,
            	3084, 8,
            1, 8, 1, /* 3084: pointer.struct.asn1_string_st */
            	2862, 0,
            1, 8, 1, /* 3089: pointer.struct.X509_pubkey_st */
            	3094, 0,
            0, 24, 3, /* 3094: struct.X509_pubkey_st */
            	2867, 0,
            	2956, 8,
            	3103, 16,
            1, 8, 1, /* 3103: pointer.struct.evp_pkey_st */
            	3108, 0,
            0, 56, 4, /* 3108: struct.evp_pkey_st */
            	3119, 16,
            	2779, 24,
            	3127, 32,
            	3326, 48,
            1, 8, 1, /* 3119: pointer.struct.evp_pkey_asn1_method_st */
            	3124, 0,
            0, 0, 0, /* 3124: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 3127: union.unknown */
            	99, 0,
            	3140, 0,
            	3245, 0,
            	3250, 0,
            	3318, 0,
            1, 8, 1, /* 3140: pointer.struct.rsa_st */
            	3145, 0,
            0, 168, 17, /* 3145: struct.rsa_st */
            	3182, 16,
            	2779, 24,
            	285, 32,
            	285, 40,
            	285, 48,
            	285, 56,
            	285, 64,
            	285, 72,
            	285, 80,
            	285, 88,
            	2706, 96,
            	2692, 120,
            	2692, 128,
            	2692, 136,
            	99, 144,
            	3237, 152,
            	3237, 160,
            1, 8, 1, /* 3182: pointer.struct.rsa_meth_st */
            	3187, 0,
            0, 112, 13, /* 3187: struct.rsa_meth_st */
            	5, 0,
            	3216, 8,
            	3216, 16,
            	3216, 24,
            	3216, 32,
            	3219, 40,
            	3222, 48,
            	3225, 56,
            	3225, 64,
            	99, 80,
            	3228, 88,
            	3231, 96,
            	3234, 104,
            64097, 8, 0, /* 3216: pointer.func */
            64097, 8, 0, /* 3219: pointer.func */
            64097, 8, 0, /* 3222: pointer.func */
            64097, 8, 0, /* 3225: pointer.func */
            64097, 8, 0, /* 3228: pointer.func */
            64097, 8, 0, /* 3231: pointer.func */
            64097, 8, 0, /* 3234: pointer.func */
            1, 8, 1, /* 3237: pointer.struct.bn_blinding_st */
            	3242, 0,
            0, 0, 0, /* 3242: struct.bn_blinding_st */
            1, 8, 1, /* 3245: pointer.struct.dsa_st */
            	2667, 0,
            1, 8, 1, /* 3250: pointer.struct.dh_st */
            	3255, 0,
            0, 144, 12, /* 3255: struct.dh_st */
            	285, 8,
            	285, 16,
            	285, 32,
            	285, 40,
            	2692, 56,
            	285, 64,
            	285, 72,
            	78, 80,
            	285, 96,
            	2706, 112,
            	3282, 128,
            	2779, 136,
            1, 8, 1, /* 3282: pointer.struct.dh_method */
            	3287, 0,
            0, 72, 8, /* 3287: struct.dh_method */
            	5, 0,
            	3306, 8,
            	3309, 16,
            	3312, 24,
            	3306, 32,
            	3306, 40,
            	99, 56,
            	3315, 64,
            64097, 8, 0, /* 3306: pointer.func */
            64097, 8, 0, /* 3309: pointer.func */
            64097, 8, 0, /* 3312: pointer.func */
            64097, 8, 0, /* 3315: pointer.func */
            1, 8, 1, /* 3318: pointer.struct.ec_key_st */
            	3323, 0,
            0, 0, 0, /* 3323: struct.ec_key_st */
            1, 8, 1, /* 3326: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3331, 0,
            0, 32, 2, /* 3331: struct.stack_st_fake_X509_ATTRIBUTE */
            	3338, 8,
            	86, 24,
            64099, 8, 2, /* 3338: pointer_to_array_of_pointers_to_stack */
            	3345, 0,
            	83, 20,
            0, 8, 1, /* 3345: pointer.X509_ATTRIBUTE */
            	1328, 0,
            1, 8, 1, /* 3350: pointer.struct.stack_st_X509_EXTENSION */
            	3355, 0,
            0, 32, 2, /* 3355: struct.stack_st_fake_X509_EXTENSION */
            	3362, 8,
            	86, 24,
            64099, 8, 2, /* 3362: pointer_to_array_of_pointers_to_stack */
            	3369, 0,
            	83, 20,
            0, 8, 1, /* 3369: pointer.X509_EXTENSION */
            	34, 0,
            0, 24, 1, /* 3374: struct.ASN1_ENCODING_st */
            	78, 0,
            1, 8, 1, /* 3379: pointer.struct.AUTHORITY_KEYID_st */
            	3384, 0,
            0, 24, 3, /* 3384: struct.AUTHORITY_KEYID_st */
            	2961, 0,
            	3393, 8,
            	2857, 16,
            1, 8, 1, /* 3393: pointer.struct.stack_st_GENERAL_NAME */
            	3398, 0,
            0, 32, 2, /* 3398: struct.stack_st_fake_GENERAL_NAME */
            	3405, 8,
            	86, 24,
            64099, 8, 2, /* 3405: pointer_to_array_of_pointers_to_stack */
            	3412, 0,
            	83, 20,
            0, 8, 1, /* 3412: pointer.GENERAL_NAME */
            	1801, 0,
            1, 8, 1, /* 3417: pointer.struct.X509_POLICY_CACHE_st */
            	3422, 0,
            0, 0, 0, /* 3422: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 3425: pointer.struct.stack_st_DIST_POINT */
            	3430, 0,
            0, 32, 2, /* 3430: struct.stack_st_fake_DIST_POINT */
            	3437, 8,
            	86, 24,
            64099, 8, 2, /* 3437: pointer_to_array_of_pointers_to_stack */
            	3444, 0,
            	83, 20,
            0, 8, 1, /* 3444: pointer.DIST_POINT */
            	1744, 0,
            1, 8, 1, /* 3449: pointer.struct.stack_st_GENERAL_NAME */
            	3454, 0,
            0, 32, 2, /* 3454: struct.stack_st_fake_GENERAL_NAME */
            	3461, 8,
            	86, 24,
            64099, 8, 2, /* 3461: pointer_to_array_of_pointers_to_stack */
            	3468, 0,
            	83, 20,
            0, 8, 1, /* 3468: pointer.GENERAL_NAME */
            	1801, 0,
            1, 8, 1, /* 3473: pointer.struct.NAME_CONSTRAINTS_st */
            	3478, 0,
            0, 16, 2, /* 3478: struct.NAME_CONSTRAINTS_st */
            	3485, 0,
            	3485, 8,
            1, 8, 1, /* 3485: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3490, 0,
            0, 32, 2, /* 3490: struct.stack_st_fake_GENERAL_SUBTREE */
            	3497, 8,
            	86, 24,
            64099, 8, 2, /* 3497: pointer_to_array_of_pointers_to_stack */
            	3504, 0,
            	83, 20,
            0, 8, 1, /* 3504: pointer.GENERAL_SUBTREE */
            	3509, 0,
            0, 0, 1, /* 3509: GENERAL_SUBTREE */
            	3514, 0,
            0, 24, 3, /* 3514: struct.GENERAL_SUBTREE_st */
            	3523, 0,
            	3650, 8,
            	3650, 16,
            1, 8, 1, /* 3523: pointer.struct.GENERAL_NAME_st */
            	3528, 0,
            0, 16, 1, /* 3528: struct.GENERAL_NAME_st */
            	3533, 8,
            0, 8, 15, /* 3533: union.unknown */
            	99, 0,
            	3566, 0,
            	3675, 0,
            	3675, 0,
            	3592, 0,
            	3715, 0,
            	3763, 0,
            	3675, 0,
            	3660, 0,
            	3578, 0,
            	3660, 0,
            	3715, 0,
            	3675, 0,
            	3578, 0,
            	3592, 0,
            1, 8, 1, /* 3566: pointer.struct.otherName_st */
            	3571, 0,
            0, 16, 2, /* 3571: struct.otherName_st */
            	3578, 0,
            	3592, 8,
            1, 8, 1, /* 3578: pointer.struct.asn1_object_st */
            	3583, 0,
            0, 40, 3, /* 3583: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 3592: pointer.struct.asn1_type_st */
            	3597, 0,
            0, 16, 1, /* 3597: struct.asn1_type_st */
            	3602, 8,
            0, 8, 20, /* 3602: union.unknown */
            	99, 0,
            	3645, 0,
            	3578, 0,
            	3650, 0,
            	3655, 0,
            	2787, 0,
            	3660, 0,
            	3665, 0,
            	3670, 0,
            	3675, 0,
            	3680, 0,
            	3685, 0,
            	3690, 0,
            	3695, 0,
            	3700, 0,
            	3705, 0,
            	3710, 0,
            	3645, 0,
            	3645, 0,
            	2003, 0,
            1, 8, 1, /* 3645: pointer.struct.asn1_string_st */
            	2792, 0,
            1, 8, 1, /* 3650: pointer.struct.asn1_string_st */
            	2792, 0,
            1, 8, 1, /* 3655: pointer.struct.asn1_string_st */
            	2792, 0,
            1, 8, 1, /* 3660: pointer.struct.asn1_string_st */
            	2792, 0,
            1, 8, 1, /* 3665: pointer.struct.asn1_string_st */
            	2792, 0,
            1, 8, 1, /* 3670: pointer.struct.asn1_string_st */
            	2792, 0,
            1, 8, 1, /* 3675: pointer.struct.asn1_string_st */
            	2792, 0,
            1, 8, 1, /* 3680: pointer.struct.asn1_string_st */
            	2792, 0,
            1, 8, 1, /* 3685: pointer.struct.asn1_string_st */
            	2792, 0,
            1, 8, 1, /* 3690: pointer.struct.asn1_string_st */
            	2792, 0,
            1, 8, 1, /* 3695: pointer.struct.asn1_string_st */
            	2792, 0,
            1, 8, 1, /* 3700: pointer.struct.asn1_string_st */
            	2792, 0,
            1, 8, 1, /* 3705: pointer.struct.asn1_string_st */
            	2792, 0,
            1, 8, 1, /* 3710: pointer.struct.asn1_string_st */
            	2792, 0,
            1, 8, 1, /* 3715: pointer.struct.X509_name_st */
            	3720, 0,
            0, 40, 3, /* 3720: struct.X509_name_st */
            	3729, 0,
            	3753, 16,
            	78, 24,
            1, 8, 1, /* 3729: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3734, 0,
            0, 32, 2, /* 3734: struct.stack_st_fake_X509_NAME_ENTRY */
            	3741, 8,
            	86, 24,
            64099, 8, 2, /* 3741: pointer_to_array_of_pointers_to_stack */
            	3748, 0,
            	83, 20,
            0, 8, 1, /* 3748: pointer.X509_NAME_ENTRY */
            	128, 0,
            1, 8, 1, /* 3753: pointer.struct.buf_mem_st */
            	3758, 0,
            0, 24, 1, /* 3758: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 3763: pointer.struct.EDIPartyName_st */
            	3768, 0,
            0, 16, 2, /* 3768: struct.EDIPartyName_st */
            	3645, 0,
            	3645, 8,
            1, 8, 1, /* 3775: pointer.struct.x509_cert_aux_st */
            	3780, 0,
            0, 40, 5, /* 3780: struct.x509_cert_aux_st */
            	3793, 0,
            	3793, 8,
            	3011, 16,
            	2961, 24,
            	3817, 32,
            1, 8, 1, /* 3793: pointer.struct.stack_st_ASN1_OBJECT */
            	3798, 0,
            0, 32, 2, /* 3798: struct.stack_st_fake_ASN1_OBJECT */
            	3805, 8,
            	86, 24,
            64099, 8, 2, /* 3805: pointer_to_array_of_pointers_to_stack */
            	3812, 0,
            	83, 20,
            0, 8, 1, /* 3812: pointer.ASN1_OBJECT */
            	2203, 0,
            1, 8, 1, /* 3817: pointer.struct.stack_st_X509_ALGOR */
            	3822, 0,
            0, 32, 2, /* 3822: struct.stack_st_fake_X509_ALGOR */
            	3829, 8,
            	86, 24,
            64099, 8, 2, /* 3829: pointer_to_array_of_pointers_to_stack */
            	3836, 0,
            	83, 20,
            0, 8, 1, /* 3836: pointer.X509_ALGOR */
            	2241, 0,
            64097, 8, 0, /* 3841: pointer.func */
            1, 8, 1, /* 3844: pointer.struct.X509_algor_st */
            	3849, 0,
            0, 16, 2, /* 3849: struct.X509_algor_st */
            	3856, 0,
            	3870, 8,
            1, 8, 1, /* 3856: pointer.struct.asn1_object_st */
            	3861, 0,
            0, 40, 3, /* 3861: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	60, 24,
            1, 8, 1, /* 3870: pointer.struct.asn1_type_st */
            	3875, 0,
            0, 16, 1, /* 3875: struct.asn1_type_st */
            	3880, 8,
            0, 8, 20, /* 3880: union.unknown */
            	99, 0,
            	3923, 0,
            	3856, 0,
            	3933, 0,
            	3938, 0,
            	3943, 0,
            	3948, 0,
            	3953, 0,
            	3958, 0,
            	3963, 0,
            	3968, 0,
            	3973, 0,
            	3978, 0,
            	3983, 0,
            	3988, 0,
            	3993, 0,
            	3998, 0,
            	3923, 0,
            	3923, 0,
            	4003, 0,
            1, 8, 1, /* 3923: pointer.struct.asn1_string_st */
            	3928, 0,
            0, 24, 1, /* 3928: struct.asn1_string_st */
            	78, 8,
            1, 8, 1, /* 3933: pointer.struct.asn1_string_st */
            	3928, 0,
            1, 8, 1, /* 3938: pointer.struct.asn1_string_st */
            	3928, 0,
            1, 8, 1, /* 3943: pointer.struct.asn1_string_st */
            	3928, 0,
            1, 8, 1, /* 3948: pointer.struct.asn1_string_st */
            	3928, 0,
            1, 8, 1, /* 3953: pointer.struct.asn1_string_st */
            	3928, 0,
            1, 8, 1, /* 3958: pointer.struct.asn1_string_st */
            	3928, 0,
            1, 8, 1, /* 3963: pointer.struct.asn1_string_st */
            	3928, 0,
            1, 8, 1, /* 3968: pointer.struct.asn1_string_st */
            	3928, 0,
            1, 8, 1, /* 3973: pointer.struct.asn1_string_st */
            	3928, 0,
            1, 8, 1, /* 3978: pointer.struct.asn1_string_st */
            	3928, 0,
            1, 8, 1, /* 3983: pointer.struct.asn1_string_st */
            	3928, 0,
            1, 8, 1, /* 3988: pointer.struct.asn1_string_st */
            	3928, 0,
            1, 8, 1, /* 3993: pointer.struct.asn1_string_st */
            	3928, 0,
            1, 8, 1, /* 3998: pointer.struct.asn1_string_st */
            	3928, 0,
            1, 8, 1, /* 4003: pointer.struct.ASN1_VALUE_st */
            	4008, 0,
            0, 0, 0, /* 4008: struct.ASN1_VALUE_st */
            64097, 8, 0, /* 4011: pointer.func */
            0, 72, 8, /* 4014: struct.dh_method */
            	5, 0,
            	4033, 8,
            	4036, 16,
            	4011, 24,
            	4033, 32,
            	4033, 40,
            	99, 56,
            	4039, 64,
            64097, 8, 0, /* 4033: pointer.func */
            64097, 8, 0, /* 4036: pointer.func */
            64097, 8, 0, /* 4039: pointer.func */
            64097, 8, 0, /* 4042: pointer.func */
            64097, 8, 0, /* 4045: pointer.func */
            64097, 8, 0, /* 4048: pointer.func */
            1, 8, 1, /* 4051: pointer.struct.comp_method_st */
            	4056, 0,
            0, 64, 7, /* 4056: struct.comp_method_st */
            	5, 8,
            	4073, 16,
            	4076, 24,
            	4079, 32,
            	4079, 40,
            	354, 48,
            	354, 56,
            64097, 8, 0, /* 4073: pointer.func */
            64097, 8, 0, /* 4076: pointer.func */
            64097, 8, 0, /* 4079: pointer.func */
            0, 24, 2, /* 4082: struct.ssl_comp_st */
            	5, 8,
            	4051, 16,
            64097, 8, 0, /* 4089: pointer.func */
            1, 8, 1, /* 4092: pointer.struct.dsa_st */
            	4097, 0,
            0, 136, 11, /* 4097: struct.dsa_st */
            	4122, 24,
            	4122, 32,
            	4122, 40,
            	4122, 48,
            	4122, 56,
            	4122, 64,
            	4122, 72,
            	4132, 88,
            	4146, 104,
            	4168, 120,
            	4210, 128,
            1, 8, 1, /* 4122: pointer.struct.bignum_st */
            	4127, 0,
            0, 24, 1, /* 4127: struct.bignum_st */
            	295, 0,
            1, 8, 1, /* 4132: pointer.struct.bn_mont_ctx_st */
            	4137, 0,
            0, 96, 3, /* 4137: struct.bn_mont_ctx_st */
            	4127, 8,
            	4127, 32,
            	4127, 56,
            0, 16, 1, /* 4146: struct.crypto_ex_data_st */
            	4151, 0,
            1, 8, 1, /* 4151: pointer.struct.stack_st_void */
            	4156, 0,
            0, 32, 1, /* 4156: struct.stack_st_void */
            	4161, 0,
            0, 32, 2, /* 4161: struct.stack_st */
            	1120, 8,
            	86, 24,
            1, 8, 1, /* 4168: pointer.struct.dsa_method */
            	4173, 0,
            0, 96, 11, /* 4173: struct.dsa_method */
            	5, 0,
            	4048, 8,
            	4198, 16,
            	4201, 24,
            	4045, 32,
            	4204, 40,
            	4042, 48,
            	4042, 56,
            	99, 72,
            	4207, 80,
            	4042, 88,
            64097, 8, 0, /* 4198: pointer.func */
            64097, 8, 0, /* 4201: pointer.func */
            64097, 8, 0, /* 4204: pointer.func */
            64097, 8, 0, /* 4207: pointer.func */
            1, 8, 1, /* 4210: pointer.struct.engine_st */
            	4215, 0,
            0, 0, 0, /* 4215: struct.engine_st */
            1, 8, 1, /* 4218: pointer.struct.bn_blinding_st */
            	4223, 0,
            0, 0, 0, /* 4223: struct.bn_blinding_st */
            64097, 8, 0, /* 4226: pointer.func */
            64097, 8, 0, /* 4229: pointer.func */
            64097, 8, 0, /* 4232: pointer.func */
            0, 56, 4, /* 4235: struct.evp_pkey_st */
            	4246, 16,
            	4210, 24,
            	4254, 32,
            	4406, 48,
            1, 8, 1, /* 4246: pointer.struct.evp_pkey_asn1_method_st */
            	4251, 0,
            0, 0, 0, /* 4251: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 4254: union.unknown */
            	99, 0,
            	4267, 0,
            	4092, 0,
            	4361, 0,
            	4398, 0,
            1, 8, 1, /* 4267: pointer.struct.rsa_st */
            	4272, 0,
            0, 168, 17, /* 4272: struct.rsa_st */
            	4309, 16,
            	4210, 24,
            	4122, 32,
            	4122, 40,
            	4122, 48,
            	4122, 56,
            	4122, 64,
            	4122, 72,
            	4122, 80,
            	4122, 88,
            	4146, 96,
            	4132, 120,
            	4132, 128,
            	4132, 136,
            	99, 144,
            	4218, 152,
            	4218, 160,
            1, 8, 1, /* 4309: pointer.struct.rsa_meth_st */
            	4314, 0,
            0, 112, 13, /* 4314: struct.rsa_meth_st */
            	5, 0,
            	4343, 8,
            	4343, 16,
            	4343, 24,
            	4343, 32,
            	4346, 40,
            	4349, 48,
            	4229, 56,
            	4229, 64,
            	99, 80,
            	4352, 88,
            	4355, 96,
            	4358, 104,
            64097, 8, 0, /* 4343: pointer.func */
            64097, 8, 0, /* 4346: pointer.func */
            64097, 8, 0, /* 4349: pointer.func */
            64097, 8, 0, /* 4352: pointer.func */
            64097, 8, 0, /* 4355: pointer.func */
            64097, 8, 0, /* 4358: pointer.func */
            1, 8, 1, /* 4361: pointer.struct.dh_st */
            	4366, 0,
            0, 144, 12, /* 4366: struct.dh_st */
            	4122, 8,
            	4122, 16,
            	4122, 32,
            	4122, 40,
            	4132, 56,
            	4122, 64,
            	4122, 72,
            	78, 80,
            	4122, 96,
            	4146, 112,
            	4393, 128,
            	4210, 136,
            1, 8, 1, /* 4393: pointer.struct.dh_method */
            	4014, 0,
            1, 8, 1, /* 4398: pointer.struct.ec_key_st */
            	4403, 0,
            0, 0, 0, /* 4403: struct.ec_key_st */
            1, 8, 1, /* 4406: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4411, 0,
            0, 32, 2, /* 4411: struct.stack_st_fake_X509_ATTRIBUTE */
            	4418, 8,
            	86, 24,
            64099, 8, 2, /* 4418: pointer_to_array_of_pointers_to_stack */
            	4425, 0,
            	83, 20,
            0, 8, 1, /* 4425: pointer.X509_ATTRIBUTE */
            	1328, 0,
            1, 8, 1, /* 4430: pointer.struct.asn1_string_st */
            	3928, 0,
            64097, 8, 0, /* 4435: pointer.func */
            1, 8, 1, /* 4438: pointer.struct.X509_val_st */
            	4443, 0,
            0, 16, 2, /* 4443: struct.X509_val_st */
            	4430, 0,
            	4430, 8,
            64097, 8, 0, /* 4450: pointer.func */
            1, 8, 1, /* 4453: pointer.struct.AUTHORITY_KEYID_st */
            	4458, 0,
            0, 0, 0, /* 4458: struct.AUTHORITY_KEYID_st */
            64097, 8, 0, /* 4461: pointer.func */
            0, 0, 0, /* 4464: struct.X509_POLICY_CACHE_st */
            64097, 8, 0, /* 4467: pointer.func */
            0, 0, 1, /* 4470: X509 */
            	4475, 0,
            0, 184, 12, /* 4475: struct.x509_st */
            	4502, 0,
            	3844, 8,
            	3943, 16,
            	99, 32,
            	4146, 40,
            	3948, 104,
            	4453, 112,
            	4628, 120,
            	4633, 128,
            	4657, 136,
            	4681, 144,
            	4689, 176,
            1, 8, 1, /* 4502: pointer.struct.x509_cinf_st */
            	4507, 0,
            0, 104, 11, /* 4507: struct.x509_cinf_st */
            	3933, 0,
            	3933, 8,
            	3844, 16,
            	4532, 24,
            	4438, 32,
            	4532, 40,
            	4580, 48,
            	3943, 56,
            	3943, 64,
            	4599, 72,
            	4623, 80,
            1, 8, 1, /* 4532: pointer.struct.X509_name_st */
            	4537, 0,
            0, 40, 3, /* 4537: struct.X509_name_st */
            	4546, 0,
            	4570, 16,
            	78, 24,
            1, 8, 1, /* 4546: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4551, 0,
            0, 32, 2, /* 4551: struct.stack_st_fake_X509_NAME_ENTRY */
            	4558, 8,
            	86, 24,
            64099, 8, 2, /* 4558: pointer_to_array_of_pointers_to_stack */
            	4565, 0,
            	83, 20,
            0, 8, 1, /* 4565: pointer.X509_NAME_ENTRY */
            	128, 0,
            1, 8, 1, /* 4570: pointer.struct.buf_mem_st */
            	4575, 0,
            0, 24, 1, /* 4575: struct.buf_mem_st */
            	99, 8,
            1, 8, 1, /* 4580: pointer.struct.X509_pubkey_st */
            	4585, 0,
            0, 24, 3, /* 4585: struct.X509_pubkey_st */
            	3844, 0,
            	3943, 8,
            	4594, 16,
            1, 8, 1, /* 4594: pointer.struct.evp_pkey_st */
            	4235, 0,
            1, 8, 1, /* 4599: pointer.struct.stack_st_X509_EXTENSION */
            	4604, 0,
            0, 32, 2, /* 4604: struct.stack_st_fake_X509_EXTENSION */
            	4611, 8,
            	86, 24,
            64099, 8, 2, /* 4611: pointer_to_array_of_pointers_to_stack */
            	4618, 0,
            	83, 20,
            0, 8, 1, /* 4618: pointer.X509_EXTENSION */
            	34, 0,
            0, 24, 1, /* 4623: struct.ASN1_ENCODING_st */
            	78, 0,
            1, 8, 1, /* 4628: pointer.struct.X509_POLICY_CACHE_st */
            	4464, 0,
            1, 8, 1, /* 4633: pointer.struct.stack_st_DIST_POINT */
            	4638, 0,
            0, 32, 2, /* 4638: struct.stack_st_fake_DIST_POINT */
            	4645, 8,
            	86, 24,
            64099, 8, 2, /* 4645: pointer_to_array_of_pointers_to_stack */
            	4652, 0,
            	83, 20,
            0, 8, 1, /* 4652: pointer.DIST_POINT */
            	1744, 0,
            1, 8, 1, /* 4657: pointer.struct.stack_st_GENERAL_NAME */
            	4662, 0,
            0, 32, 2, /* 4662: struct.stack_st_fake_GENERAL_NAME */
            	4669, 8,
            	86, 24,
            64099, 8, 2, /* 4669: pointer_to_array_of_pointers_to_stack */
            	4676, 0,
            	83, 20,
            0, 8, 1, /* 4676: pointer.GENERAL_NAME */
            	1801, 0,
            1, 8, 1, /* 4681: pointer.struct.NAME_CONSTRAINTS_st */
            	4686, 0,
            0, 0, 0, /* 4686: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4689: pointer.struct.x509_cert_aux_st */
            	4694, 0,
            0, 40, 5, /* 4694: struct.x509_cert_aux_st */
            	4707, 0,
            	4707, 8,
            	3998, 16,
            	3948, 24,
            	4731, 32,
            1, 8, 1, /* 4707: pointer.struct.stack_st_ASN1_OBJECT */
            	4712, 0,
            0, 32, 2, /* 4712: struct.stack_st_fake_ASN1_OBJECT */
            	4719, 8,
            	86, 24,
            64099, 8, 2, /* 4719: pointer_to_array_of_pointers_to_stack */
            	4726, 0,
            	83, 20,
            0, 8, 1, /* 4726: pointer.ASN1_OBJECT */
            	2203, 0,
            1, 8, 1, /* 4731: pointer.struct.stack_st_X509_ALGOR */
            	4736, 0,
            0, 32, 2, /* 4736: struct.stack_st_fake_X509_ALGOR */
            	4743, 8,
            	86, 24,
            64099, 8, 2, /* 4743: pointer_to_array_of_pointers_to_stack */
            	4750, 0,
            	83, 20,
            0, 8, 1, /* 4750: pointer.X509_ALGOR */
            	2241, 0,
            64097, 8, 0, /* 4755: pointer.func */
            1, 8, 1, /* 4758: pointer.struct.sess_cert_st */
            	4763, 0,
            0, 248, 5, /* 4763: struct.sess_cert_st */
            	4776, 0,
            	4800, 16,
            	4861, 216,
            	4866, 224,
            	4871, 232,
            1, 8, 1, /* 4776: pointer.struct.stack_st_X509 */
            	4781, 0,
            0, 32, 2, /* 4781: struct.stack_st_fake_X509 */
            	4788, 8,
            	86, 24,
            64099, 8, 2, /* 4788: pointer_to_array_of_pointers_to_stack */
            	4795, 0,
            	83, 20,
            0, 8, 1, /* 4795: pointer.X509 */
            	4470, 0,
            1, 8, 1, /* 4800: pointer.struct.cert_pkey_st */
            	4805, 0,
            0, 24, 3, /* 4805: struct.cert_pkey_st */
            	4814, 0,
            	3103, 8,
            	4819, 16,
            1, 8, 1, /* 4814: pointer.struct.x509_st */
            	2800, 0,
            1, 8, 1, /* 4819: pointer.struct.env_md_st */
            	4824, 0,
            0, 120, 8, /* 4824: struct.env_md_st */
            	4843, 24,
            	4846, 32,
            	4849, 40,
            	4852, 48,
            	4843, 56,
            	4435, 64,
            	4855, 72,
            	4858, 112,
            64097, 8, 0, /* 4843: pointer.func */
            64097, 8, 0, /* 4846: pointer.func */
            64097, 8, 0, /* 4849: pointer.func */
            64097, 8, 0, /* 4852: pointer.func */
            64097, 8, 0, /* 4855: pointer.func */
            64097, 8, 0, /* 4858: pointer.func */
            1, 8, 1, /* 4861: pointer.struct.rsa_st */
            	3145, 0,
            1, 8, 1, /* 4866: pointer.struct.dh_st */
            	3255, 0,
            1, 8, 1, /* 4871: pointer.struct.ec_key_st */
            	3323, 0,
            64097, 8, 0, /* 4876: pointer.func */
            1, 8, 1, /* 4879: pointer.struct.ssl_session_st */
            	4884, 0,
            0, 352, 14, /* 4884: struct.ssl_session_st */
            	99, 144,
            	99, 152,
            	4758, 168,
            	4814, 176,
            	4915, 224,
            	4925, 240,
            	2706, 248,
            	4959, 264,
            	4959, 272,
            	99, 280,
            	78, 296,
            	78, 312,
            	78, 320,
            	99, 344,
            1, 8, 1, /* 4915: pointer.struct.ssl_cipher_st */
            	4920, 0,
            0, 88, 1, /* 4920: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 4925: pointer.struct.stack_st_SSL_CIPHER */
            	4930, 0,
            0, 32, 2, /* 4930: struct.stack_st_fake_SSL_CIPHER */
            	4937, 8,
            	86, 24,
            64099, 8, 2, /* 4937: pointer_to_array_of_pointers_to_stack */
            	4944, 0,
            	83, 20,
            0, 8, 1, /* 4944: pointer.SSL_CIPHER */
            	4949, 0,
            0, 0, 1, /* 4949: SSL_CIPHER */
            	4954, 0,
            0, 88, 1, /* 4954: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 4959: pointer.struct.ssl_session_st */
            	4884, 0,
            1, 8, 1, /* 4964: pointer.struct.comp_ctx_st */
            	4969, 0,
            0, 56, 2, /* 4969: struct.comp_ctx_st */
            	4051, 0,
            	2706, 40,
            0, 168, 4, /* 4976: struct.evp_cipher_ctx_st */
            	4987, 0,
            	2779, 8,
            	273, 96,
            	273, 120,
            1, 8, 1, /* 4987: pointer.struct.evp_cipher_st */
            	4992, 0,
            0, 88, 7, /* 4992: struct.evp_cipher_st */
            	5009, 24,
            	5012, 32,
            	4467, 40,
            	5015, 56,
            	5015, 64,
            	5018, 72,
            	273, 80,
            64097, 8, 0, /* 5009: pointer.func */
            64097, 8, 0, /* 5012: pointer.func */
            64097, 8, 0, /* 5015: pointer.func */
            64097, 8, 0, /* 5018: pointer.func */
            0, 24, 1, /* 5021: struct.buf_mem_st */
            	99, 8,
            0, 40, 4, /* 5026: struct.dtls1_retransmit_state */
            	5037, 0,
            	5042, 8,
            	4964, 16,
            	4879, 24,
            1, 8, 1, /* 5037: pointer.struct.evp_cipher_ctx_st */
            	4976, 0,
            1, 8, 1, /* 5042: pointer.struct.env_md_ctx_st */
            	5047, 0,
            0, 48, 5, /* 5047: struct.env_md_ctx_st */
            	4819, 0,
            	2779, 8,
            	273, 24,
            	5060, 32,
            	4846, 40,
            1, 8, 1, /* 5060: pointer.struct.evp_pkey_ctx_st */
            	5065, 0,
            0, 0, 0, /* 5065: struct.evp_pkey_ctx_st */
            1, 8, 1, /* 5068: pointer.struct._pqueue */
            	5073, 0,
            0, 0, 0, /* 5073: struct._pqueue */
            64097, 8, 0, /* 5076: pointer.func */
            64097, 8, 0, /* 5079: pointer.func */
            64097, 8, 0, /* 5082: pointer.func */
            1, 8, 1, /* 5085: pointer.struct.ssl3_enc_method */
            	5090, 0,
            0, 112, 11, /* 5090: struct.ssl3_enc_method */
            	5115, 0,
            	5118, 8,
            	5121, 16,
            	5079, 24,
            	5115, 32,
            	5124, 40,
            	5127, 56,
            	5, 64,
            	5, 80,
            	5130, 96,
            	5082, 104,
            64097, 8, 0, /* 5115: pointer.func */
            64097, 8, 0, /* 5118: pointer.func */
            64097, 8, 0, /* 5121: pointer.func */
            64097, 8, 0, /* 5124: pointer.func */
            64097, 8, 0, /* 5127: pointer.func */
            64097, 8, 0, /* 5130: pointer.func */
            0, 80, 9, /* 5133: struct.bio_method_st */
            	5, 8,
            	5154, 16,
            	5157, 24,
            	5160, 32,
            	5157, 40,
            	5163, 48,
            	5166, 56,
            	5166, 64,
            	5169, 72,
            64097, 8, 0, /* 5154: pointer.func */
            64097, 8, 0, /* 5157: pointer.func */
            64097, 8, 0, /* 5160: pointer.func */
            64097, 8, 0, /* 5163: pointer.func */
            64097, 8, 0, /* 5166: pointer.func */
            64097, 8, 0, /* 5169: pointer.func */
            1, 8, 1, /* 5172: pointer.struct.bio_st */
            	5177, 0,
            0, 112, 7, /* 5177: struct.bio_st */
            	5194, 0,
            	4089, 8,
            	99, 16,
            	273, 48,
            	5172, 56,
            	5172, 64,
            	2706, 96,
            1, 8, 1, /* 5194: pointer.struct.bio_method_st */
            	5133, 0,
            1, 8, 1, /* 5199: pointer.struct.dtls1_state_st */
            	5204, 0,
            0, 888, 7, /* 5204: struct.dtls1_state_st */
            	5221, 576,
            	5221, 592,
            	5068, 608,
            	5068, 616,
            	5221, 624,
            	5226, 648,
            	5226, 736,
            0, 16, 1, /* 5221: struct.record_pqueue_st */
            	5068, 8,
            0, 88, 1, /* 5226: struct.hm_header_st */
            	5026, 48,
            0, 344, 9, /* 5231: struct.ssl2_state_st */
            	60, 24,
            	78, 56,
            	78, 64,
            	78, 72,
            	78, 104,
            	78, 112,
            	78, 120,
            	78, 128,
            	78, 136,
            64097, 8, 0, /* 5252: pointer.func */
            64097, 8, 0, /* 5255: pointer.func */
            64097, 8, 0, /* 5258: pointer.func */
            1, 8, 1, /* 5261: pointer.struct.ssl_st */
            	5266, 0,
            0, 808, 51, /* 5266: struct.ssl_st */
            	5371, 8,
            	5468, 16,
            	5468, 24,
            	5468, 32,
            	5121, 48,
            	3062, 80,
            	273, 88,
            	78, 104,
            	5473, 120,
            	5478, 128,
            	5199, 136,
            	5616, 152,
            	273, 160,
            	5619, 176,
            	4925, 184,
            	4925, 192,
            	5037, 208,
            	5042, 216,
            	4964, 224,
            	5037, 232,
            	5042, 240,
            	4964, 248,
            	5631, 256,
            	4879, 304,
            	5662, 312,
            	5665, 328,
            	5076, 336,
            	5668, 352,
            	5671, 360,
            	5674, 368,
            	2706, 392,
            	5544, 408,
            	5892, 464,
            	273, 472,
            	99, 480,
            	195, 504,
            	10, 512,
            	78, 520,
            	78, 544,
            	78, 560,
            	273, 568,
            	2656, 584,
            	5895, 592,
            	273, 600,
            	2797, 608,
            	273, 616,
            	5674, 624,
            	78, 632,
            	5868, 648,
            	5898, 656,
            	242, 680,
            1, 8, 1, /* 5371: pointer.struct.ssl_method_st */
            	5376, 0,
            0, 232, 28, /* 5376: struct.ssl_method_st */
            	5121, 8,
            	5435, 16,
            	5435, 24,
            	5121, 32,
            	5121, 40,
            	5438, 48,
            	5438, 56,
            	5441, 64,
            	5121, 72,
            	5121, 80,
            	5121, 88,
            	5258, 96,
            	5252, 104,
            	5444, 112,
            	5121, 120,
            	5255, 128,
            	5447, 136,
            	4876, 144,
            	5450, 152,
            	5453, 160,
            	5456, 168,
            	5459, 176,
            	5462, 184,
            	354, 192,
            	5085, 200,
            	5456, 208,
            	4232, 216,
            	5465, 224,
            64097, 8, 0, /* 5435: pointer.func */
            64097, 8, 0, /* 5438: pointer.func */
            64097, 8, 0, /* 5441: pointer.func */
            64097, 8, 0, /* 5444: pointer.func */
            64097, 8, 0, /* 5447: pointer.func */
            64097, 8, 0, /* 5450: pointer.func */
            64097, 8, 0, /* 5453: pointer.func */
            64097, 8, 0, /* 5456: pointer.func */
            64097, 8, 0, /* 5459: pointer.func */
            64097, 8, 0, /* 5462: pointer.func */
            64097, 8, 0, /* 5465: pointer.func */
            1, 8, 1, /* 5468: pointer.struct.bio_st */
            	5177, 0,
            1, 8, 1, /* 5473: pointer.struct.ssl2_state_st */
            	5231, 0,
            1, 8, 1, /* 5478: pointer.struct.ssl3_state_st */
            	5483, 0,
            0, 1200, 10, /* 5483: struct.ssl3_state_st */
            	5506, 240,
            	5506, 264,
            	5511, 288,
            	5511, 344,
            	60, 432,
            	5468, 440,
            	5520, 448,
            	273, 496,
            	273, 512,
            	5525, 528,
            0, 24, 1, /* 5506: struct.ssl3_buffer_st */
            	78, 0,
            0, 56, 3, /* 5511: struct.ssl3_record_st */
            	78, 16,
            	78, 24,
            	78, 32,
            1, 8, 1, /* 5520: pointer.pointer.struct.env_md_ctx_st */
            	5042, 0,
            0, 528, 8, /* 5525: struct.unknown */
            	4915, 408,
            	4866, 416,
            	4871, 424,
            	5544, 464,
            	78, 480,
            	4987, 488,
            	4819, 496,
            	5611, 512,
            1, 8, 1, /* 5544: pointer.struct.stack_st_X509_NAME */
            	5549, 0,
            0, 32, 2, /* 5549: struct.stack_st_fake_X509_NAME */
            	5556, 8,
            	86, 24,
            64099, 8, 2, /* 5556: pointer_to_array_of_pointers_to_stack */
            	5563, 0,
            	83, 20,
            0, 8, 1, /* 5563: pointer.X509_NAME */
            	5568, 0,
            0, 0, 1, /* 5568: X509_NAME */
            	5573, 0,
            0, 40, 3, /* 5573: struct.X509_name_st */
            	5582, 0,
            	5606, 16,
            	78, 24,
            1, 8, 1, /* 5582: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5587, 0,
            0, 32, 2, /* 5587: struct.stack_st_fake_X509_NAME_ENTRY */
            	5594, 8,
            	86, 24,
            64099, 8, 2, /* 5594: pointer_to_array_of_pointers_to_stack */
            	5601, 0,
            	83, 20,
            0, 8, 1, /* 5601: pointer.X509_NAME_ENTRY */
            	128, 0,
            1, 8, 1, /* 5606: pointer.struct.buf_mem_st */
            	5021, 0,
            1, 8, 1, /* 5611: pointer.struct.ssl_comp_st */
            	4082, 0,
            64097, 8, 0, /* 5616: pointer.func */
            1, 8, 1, /* 5619: pointer.struct.X509_VERIFY_PARAM_st */
            	5624, 0,
            0, 56, 2, /* 5624: struct.X509_VERIFY_PARAM_st */
            	99, 0,
            	3793, 48,
            1, 8, 1, /* 5631: pointer.struct.cert_st */
            	5636, 0,
            0, 296, 7, /* 5636: struct.cert_st */
            	4800, 0,
            	4861, 48,
            	5653, 56,
            	4866, 64,
            	5656, 72,
            	4871, 80,
            	5659, 88,
            64097, 8, 0, /* 5653: pointer.func */
            64097, 8, 0, /* 5656: pointer.func */
            64097, 8, 0, /* 5659: pointer.func */
            64097, 8, 0, /* 5662: pointer.func */
            64097, 8, 0, /* 5665: pointer.func */
            64097, 8, 0, /* 5668: pointer.func */
            64097, 8, 0, /* 5671: pointer.func */
            1, 8, 1, /* 5674: pointer.struct.ssl_ctx_st */
            	5679, 0,
            0, 736, 50, /* 5679: struct.ssl_ctx_st */
            	5371, 0,
            	4925, 8,
            	4925, 16,
            	5782, 24,
            	5850, 32,
            	4959, 48,
            	4959, 56,
            	465, 80,
            	3841, 88,
            	392, 96,
            	2661, 152,
            	273, 160,
            	4461, 168,
            	273, 176,
            	389, 184,
            	4450, 192,
            	386, 200,
            	2706, 208,
            	4819, 224,
            	4819, 232,
            	4819, 240,
            	4776, 248,
            	357, 256,
            	5076, 264,
            	5544, 272,
            	5631, 304,
            	5616, 320,
            	273, 328,
            	5665, 376,
            	5662, 384,
            	5619, 392,
            	2779, 408,
            	276, 416,
            	273, 424,
            	2664, 480,
            	279, 488,
            	273, 496,
            	313, 504,
            	273, 512,
            	99, 520,
            	5668, 528,
            	5671, 536,
            	5855, 552,
            	5855, 560,
            	242, 568,
            	239, 696,
            	273, 704,
            	5865, 712,
            	273, 720,
            	5868, 728,
            1, 8, 1, /* 5782: pointer.struct.x509_store_st */
            	5787, 0,
            0, 144, 15, /* 5787: struct.x509_store_st */
            	5820, 8,
            	2627, 16,
            	5619, 24,
            	438, 32,
            	5665, 40,
            	435, 48,
            	5844, 56,
            	438, 64,
            	4755, 72,
            	432, 80,
            	5847, 88,
            	429, 96,
            	4226, 104,
            	438, 112,
            	2706, 120,
            1, 8, 1, /* 5820: pointer.struct.stack_st_X509_OBJECT */
            	5825, 0,
            0, 32, 2, /* 5825: struct.stack_st_fake_X509_OBJECT */
            	5832, 8,
            	86, 24,
            64099, 8, 2, /* 5832: pointer_to_array_of_pointers_to_stack */
            	5839, 0,
            	83, 20,
            0, 8, 1, /* 5839: pointer.X509_OBJECT */
            	617, 0,
            64097, 8, 0, /* 5844: pointer.func */
            64097, 8, 0, /* 5847: pointer.func */
            1, 8, 1, /* 5850: pointer.struct.lhash_st */
            	417, 0,
            1, 8, 1, /* 5855: pointer.struct.ssl3_buf_freelist_st */
            	5860, 0,
            0, 24, 1, /* 5860: struct.ssl3_buf_freelist_st */
            	303, 16,
            64097, 8, 0, /* 5865: pointer.func */
            1, 8, 1, /* 5868: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	5873, 0,
            0, 32, 2, /* 5873: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	5880, 8,
            	86, 24,
            64099, 8, 2, /* 5880: pointer_to_array_of_pointers_to_stack */
            	5887, 0,
            	83, 20,
            0, 8, 1, /* 5887: pointer.SRTP_PROTECTION_PROFILE */
            	229, 0,
            64097, 8, 0, /* 5892: pointer.func */
            64097, 8, 0, /* 5895: pointer.func */
            1, 8, 1, /* 5898: pointer.struct.srtp_protection_profile_st */
            	0, 0,
            0, 1, 0, /* 5903: char */
        },
        .arg_entity_index = { 5261, },
        .ret_entity_index = 83,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL * new_arg_a = *((SSL * *)new_args->args[0]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_SSL_shutdown)(SSL *);
    orig_SSL_shutdown = dlsym(RTLD_NEXT, "SSL_shutdown");
    *new_ret_ptr = (*orig_SSL_shutdown)(new_arg_a);

    syscall(889);

    return ret;
}

