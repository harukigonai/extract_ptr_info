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

int bb_X509_check_private_key(X509 * arg_a,EVP_PKEY * arg_b);

int X509_check_private_key(X509 * arg_a,EVP_PKEY * arg_b) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_check_private_key called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_check_private_key(arg_a,arg_b);
    else {
        int (*orig_X509_check_private_key)(X509 *,EVP_PKEY *);
        orig_X509_check_private_key = dlsym(RTLD_NEXT, "X509_check_private_key");
        return orig_X509_check_private_key(arg_a,arg_b);
    }
}

int bb_X509_check_private_key(X509 * arg_a,EVP_PKEY * arg_b) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.struct.dh_st */
            	5, 0,
            0, 144, 12, /* 5: struct.dh_st */
            	32, 8,
            	32, 16,
            	32, 32,
            	32, 40,
            	55, 56,
            	32, 64,
            	32, 72,
            	69, 80,
            	32, 96,
            	77, 112,
            	112, 128,
            	153, 136,
            1, 8, 1, /* 32: pointer.struct.bignum_st */
            	37, 0,
            0, 24, 1, /* 37: struct.bignum_st */
            	42, 0,
            8884099, 8, 2, /* 42: pointer_to_array_of_pointers_to_stack */
            	49, 0,
            	52, 12,
            0, 4, 0, /* 49: unsigned int */
            0, 4, 0, /* 52: int */
            1, 8, 1, /* 55: pointer.struct.bn_mont_ctx_st */
            	60, 0,
            0, 96, 3, /* 60: struct.bn_mont_ctx_st */
            	37, 8,
            	37, 32,
            	37, 56,
            1, 8, 1, /* 69: pointer.unsigned char */
            	74, 0,
            0, 1, 0, /* 74: unsigned char */
            0, 16, 1, /* 77: struct.crypto_ex_data_st */
            	82, 0,
            1, 8, 1, /* 82: pointer.struct.stack_st_void */
            	87, 0,
            0, 32, 1, /* 87: struct.stack_st_void */
            	92, 0,
            0, 32, 2, /* 92: struct.stack_st */
            	99, 8,
            	109, 24,
            1, 8, 1, /* 99: pointer.pointer.char */
            	104, 0,
            1, 8, 1, /* 104: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 109: pointer.func */
            1, 8, 1, /* 112: pointer.struct.dh_method */
            	117, 0,
            0, 72, 8, /* 117: struct.dh_method */
            	136, 0,
            	141, 8,
            	144, 16,
            	147, 24,
            	141, 32,
            	141, 40,
            	104, 56,
            	150, 64,
            1, 8, 1, /* 136: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 141: pointer.func */
            8884097, 8, 0, /* 144: pointer.func */
            8884097, 8, 0, /* 147: pointer.func */
            8884097, 8, 0, /* 150: pointer.func */
            1, 8, 1, /* 153: pointer.struct.engine_st */
            	158, 0,
            0, 216, 24, /* 158: struct.engine_st */
            	136, 0,
            	136, 8,
            	209, 16,
            	264, 24,
            	315, 32,
            	351, 40,
            	368, 48,
            	395, 56,
            	430, 64,
            	438, 72,
            	441, 80,
            	444, 88,
            	447, 96,
            	450, 104,
            	450, 112,
            	450, 120,
            	453, 128,
            	456, 136,
            	456, 144,
            	459, 152,
            	462, 160,
            	474, 184,
            	496, 200,
            	496, 208,
            1, 8, 1, /* 209: pointer.struct.rsa_meth_st */
            	214, 0,
            0, 112, 13, /* 214: struct.rsa_meth_st */
            	136, 0,
            	243, 8,
            	243, 16,
            	243, 24,
            	243, 32,
            	246, 40,
            	249, 48,
            	252, 56,
            	252, 64,
            	104, 80,
            	255, 88,
            	258, 96,
            	261, 104,
            8884097, 8, 0, /* 243: pointer.func */
            8884097, 8, 0, /* 246: pointer.func */
            8884097, 8, 0, /* 249: pointer.func */
            8884097, 8, 0, /* 252: pointer.func */
            8884097, 8, 0, /* 255: pointer.func */
            8884097, 8, 0, /* 258: pointer.func */
            8884097, 8, 0, /* 261: pointer.func */
            1, 8, 1, /* 264: pointer.struct.dsa_method */
            	269, 0,
            0, 96, 11, /* 269: struct.dsa_method */
            	136, 0,
            	294, 8,
            	297, 16,
            	300, 24,
            	303, 32,
            	306, 40,
            	309, 48,
            	309, 56,
            	104, 72,
            	312, 80,
            	309, 88,
            8884097, 8, 0, /* 294: pointer.func */
            8884097, 8, 0, /* 297: pointer.func */
            8884097, 8, 0, /* 300: pointer.func */
            8884097, 8, 0, /* 303: pointer.func */
            8884097, 8, 0, /* 306: pointer.func */
            8884097, 8, 0, /* 309: pointer.func */
            8884097, 8, 0, /* 312: pointer.func */
            1, 8, 1, /* 315: pointer.struct.dh_method */
            	320, 0,
            0, 72, 8, /* 320: struct.dh_method */
            	136, 0,
            	339, 8,
            	342, 16,
            	345, 24,
            	339, 32,
            	339, 40,
            	104, 56,
            	348, 64,
            8884097, 8, 0, /* 339: pointer.func */
            8884097, 8, 0, /* 342: pointer.func */
            8884097, 8, 0, /* 345: pointer.func */
            8884097, 8, 0, /* 348: pointer.func */
            1, 8, 1, /* 351: pointer.struct.ecdh_method */
            	356, 0,
            0, 32, 3, /* 356: struct.ecdh_method */
            	136, 0,
            	365, 8,
            	104, 24,
            8884097, 8, 0, /* 365: pointer.func */
            1, 8, 1, /* 368: pointer.struct.ecdsa_method */
            	373, 0,
            0, 48, 5, /* 373: struct.ecdsa_method */
            	136, 0,
            	386, 8,
            	389, 16,
            	392, 24,
            	104, 40,
            8884097, 8, 0, /* 386: pointer.func */
            8884097, 8, 0, /* 389: pointer.func */
            8884097, 8, 0, /* 392: pointer.func */
            1, 8, 1, /* 395: pointer.struct.rand_meth_st */
            	400, 0,
            0, 48, 6, /* 400: struct.rand_meth_st */
            	415, 0,
            	418, 8,
            	421, 16,
            	424, 24,
            	418, 32,
            	427, 40,
            8884097, 8, 0, /* 415: pointer.func */
            8884097, 8, 0, /* 418: pointer.func */
            8884097, 8, 0, /* 421: pointer.func */
            8884097, 8, 0, /* 424: pointer.func */
            8884097, 8, 0, /* 427: pointer.func */
            1, 8, 1, /* 430: pointer.struct.store_method_st */
            	435, 0,
            0, 0, 0, /* 435: struct.store_method_st */
            8884097, 8, 0, /* 438: pointer.func */
            8884097, 8, 0, /* 441: pointer.func */
            8884097, 8, 0, /* 444: pointer.func */
            8884097, 8, 0, /* 447: pointer.func */
            8884097, 8, 0, /* 450: pointer.func */
            8884097, 8, 0, /* 453: pointer.func */
            8884097, 8, 0, /* 456: pointer.func */
            8884097, 8, 0, /* 459: pointer.func */
            1, 8, 1, /* 462: pointer.struct.ENGINE_CMD_DEFN_st */
            	467, 0,
            0, 32, 2, /* 467: struct.ENGINE_CMD_DEFN_st */
            	136, 8,
            	136, 16,
            0, 16, 1, /* 474: struct.crypto_ex_data_st */
            	479, 0,
            1, 8, 1, /* 479: pointer.struct.stack_st_void */
            	484, 0,
            0, 32, 1, /* 484: struct.stack_st_void */
            	489, 0,
            0, 32, 2, /* 489: struct.stack_st */
            	99, 8,
            	109, 24,
            1, 8, 1, /* 496: pointer.struct.engine_st */
            	158, 0,
            1, 8, 1, /* 501: pointer.struct.dsa_st */
            	506, 0,
            0, 136, 11, /* 506: struct.dsa_st */
            	531, 24,
            	531, 32,
            	531, 40,
            	531, 48,
            	531, 56,
            	531, 64,
            	531, 72,
            	548, 88,
            	562, 104,
            	584, 120,
            	635, 128,
            1, 8, 1, /* 531: pointer.struct.bignum_st */
            	536, 0,
            0, 24, 1, /* 536: struct.bignum_st */
            	541, 0,
            8884099, 8, 2, /* 541: pointer_to_array_of_pointers_to_stack */
            	49, 0,
            	52, 12,
            1, 8, 1, /* 548: pointer.struct.bn_mont_ctx_st */
            	553, 0,
            0, 96, 3, /* 553: struct.bn_mont_ctx_st */
            	536, 8,
            	536, 32,
            	536, 56,
            0, 16, 1, /* 562: struct.crypto_ex_data_st */
            	567, 0,
            1, 8, 1, /* 567: pointer.struct.stack_st_void */
            	572, 0,
            0, 32, 1, /* 572: struct.stack_st_void */
            	577, 0,
            0, 32, 2, /* 577: struct.stack_st */
            	99, 8,
            	109, 24,
            1, 8, 1, /* 584: pointer.struct.dsa_method */
            	589, 0,
            0, 96, 11, /* 589: struct.dsa_method */
            	136, 0,
            	614, 8,
            	617, 16,
            	620, 24,
            	623, 32,
            	626, 40,
            	629, 48,
            	629, 56,
            	104, 72,
            	632, 80,
            	629, 88,
            8884097, 8, 0, /* 614: pointer.func */
            8884097, 8, 0, /* 617: pointer.func */
            8884097, 8, 0, /* 620: pointer.func */
            8884097, 8, 0, /* 623: pointer.func */
            8884097, 8, 0, /* 626: pointer.func */
            8884097, 8, 0, /* 629: pointer.func */
            8884097, 8, 0, /* 632: pointer.func */
            1, 8, 1, /* 635: pointer.struct.engine_st */
            	158, 0,
            1, 8, 1, /* 640: pointer.struct.rsa_st */
            	645, 0,
            0, 168, 17, /* 645: struct.rsa_st */
            	682, 16,
            	737, 24,
            	742, 32,
            	742, 40,
            	742, 48,
            	742, 56,
            	742, 64,
            	742, 72,
            	742, 80,
            	742, 88,
            	759, 96,
            	781, 120,
            	781, 128,
            	781, 136,
            	104, 144,
            	795, 152,
            	795, 160,
            1, 8, 1, /* 682: pointer.struct.rsa_meth_st */
            	687, 0,
            0, 112, 13, /* 687: struct.rsa_meth_st */
            	136, 0,
            	716, 8,
            	716, 16,
            	716, 24,
            	716, 32,
            	719, 40,
            	722, 48,
            	725, 56,
            	725, 64,
            	104, 80,
            	728, 88,
            	731, 96,
            	734, 104,
            8884097, 8, 0, /* 716: pointer.func */
            8884097, 8, 0, /* 719: pointer.func */
            8884097, 8, 0, /* 722: pointer.func */
            8884097, 8, 0, /* 725: pointer.func */
            8884097, 8, 0, /* 728: pointer.func */
            8884097, 8, 0, /* 731: pointer.func */
            8884097, 8, 0, /* 734: pointer.func */
            1, 8, 1, /* 737: pointer.struct.engine_st */
            	158, 0,
            1, 8, 1, /* 742: pointer.struct.bignum_st */
            	747, 0,
            0, 24, 1, /* 747: struct.bignum_st */
            	752, 0,
            8884099, 8, 2, /* 752: pointer_to_array_of_pointers_to_stack */
            	49, 0,
            	52, 12,
            0, 16, 1, /* 759: struct.crypto_ex_data_st */
            	764, 0,
            1, 8, 1, /* 764: pointer.struct.stack_st_void */
            	769, 0,
            0, 32, 1, /* 769: struct.stack_st_void */
            	774, 0,
            0, 32, 2, /* 774: struct.stack_st */
            	99, 8,
            	109, 24,
            1, 8, 1, /* 781: pointer.struct.bn_mont_ctx_st */
            	786, 0,
            0, 96, 3, /* 786: struct.bn_mont_ctx_st */
            	747, 8,
            	747, 32,
            	747, 56,
            1, 8, 1, /* 795: pointer.struct.bn_blinding_st */
            	800, 0,
            0, 88, 7, /* 800: struct.bn_blinding_st */
            	817, 0,
            	817, 8,
            	817, 16,
            	817, 24,
            	834, 40,
            	842, 72,
            	856, 80,
            1, 8, 1, /* 817: pointer.struct.bignum_st */
            	822, 0,
            0, 24, 1, /* 822: struct.bignum_st */
            	827, 0,
            8884099, 8, 2, /* 827: pointer_to_array_of_pointers_to_stack */
            	49, 0,
            	52, 12,
            0, 16, 1, /* 834: struct.crypto_threadid_st */
            	839, 0,
            0, 8, 0, /* 839: pointer.void */
            1, 8, 1, /* 842: pointer.struct.bn_mont_ctx_st */
            	847, 0,
            0, 96, 3, /* 847: struct.bn_mont_ctx_st */
            	822, 8,
            	822, 32,
            	822, 56,
            8884097, 8, 0, /* 856: pointer.func */
            0, 0, 1, /* 859: X509_ALGOR */
            	864, 0,
            0, 16, 2, /* 864: struct.X509_algor_st */
            	871, 0,
            	890, 8,
            1, 8, 1, /* 871: pointer.struct.asn1_object_st */
            	876, 0,
            0, 40, 3, /* 876: struct.asn1_object_st */
            	136, 0,
            	136, 8,
            	885, 24,
            1, 8, 1, /* 885: pointer.unsigned char */
            	74, 0,
            1, 8, 1, /* 890: pointer.struct.asn1_type_st */
            	895, 0,
            0, 16, 1, /* 895: struct.asn1_type_st */
            	900, 8,
            0, 8, 20, /* 900: union.unknown */
            	104, 0,
            	943, 0,
            	871, 0,
            	953, 0,
            	958, 0,
            	963, 0,
            	968, 0,
            	973, 0,
            	978, 0,
            	983, 0,
            	988, 0,
            	993, 0,
            	998, 0,
            	1003, 0,
            	1008, 0,
            	1013, 0,
            	1018, 0,
            	943, 0,
            	943, 0,
            	1023, 0,
            1, 8, 1, /* 943: pointer.struct.asn1_string_st */
            	948, 0,
            0, 24, 1, /* 948: struct.asn1_string_st */
            	69, 8,
            1, 8, 1, /* 953: pointer.struct.asn1_string_st */
            	948, 0,
            1, 8, 1, /* 958: pointer.struct.asn1_string_st */
            	948, 0,
            1, 8, 1, /* 963: pointer.struct.asn1_string_st */
            	948, 0,
            1, 8, 1, /* 968: pointer.struct.asn1_string_st */
            	948, 0,
            1, 8, 1, /* 973: pointer.struct.asn1_string_st */
            	948, 0,
            1, 8, 1, /* 978: pointer.struct.asn1_string_st */
            	948, 0,
            1, 8, 1, /* 983: pointer.struct.asn1_string_st */
            	948, 0,
            1, 8, 1, /* 988: pointer.struct.asn1_string_st */
            	948, 0,
            1, 8, 1, /* 993: pointer.struct.asn1_string_st */
            	948, 0,
            1, 8, 1, /* 998: pointer.struct.asn1_string_st */
            	948, 0,
            1, 8, 1, /* 1003: pointer.struct.asn1_string_st */
            	948, 0,
            1, 8, 1, /* 1008: pointer.struct.asn1_string_st */
            	948, 0,
            1, 8, 1, /* 1013: pointer.struct.asn1_string_st */
            	948, 0,
            1, 8, 1, /* 1018: pointer.struct.asn1_string_st */
            	948, 0,
            1, 8, 1, /* 1023: pointer.struct.ASN1_VALUE_st */
            	1028, 0,
            0, 0, 0, /* 1028: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1031: pointer.struct.asn1_string_st */
            	1036, 0,
            0, 24, 1, /* 1036: struct.asn1_string_st */
            	69, 8,
            0, 40, 5, /* 1041: struct.x509_cert_aux_st */
            	1054, 0,
            	1054, 8,
            	1031, 16,
            	1092, 24,
            	1097, 32,
            1, 8, 1, /* 1054: pointer.struct.stack_st_ASN1_OBJECT */
            	1059, 0,
            0, 32, 2, /* 1059: struct.stack_st_fake_ASN1_OBJECT */
            	1066, 8,
            	109, 24,
            8884099, 8, 2, /* 1066: pointer_to_array_of_pointers_to_stack */
            	1073, 0,
            	52, 20,
            0, 8, 1, /* 1073: pointer.ASN1_OBJECT */
            	1078, 0,
            0, 0, 1, /* 1078: ASN1_OBJECT */
            	1083, 0,
            0, 40, 3, /* 1083: struct.asn1_object_st */
            	136, 0,
            	136, 8,
            	885, 24,
            1, 8, 1, /* 1092: pointer.struct.asn1_string_st */
            	1036, 0,
            1, 8, 1, /* 1097: pointer.struct.stack_st_X509_ALGOR */
            	1102, 0,
            0, 32, 2, /* 1102: struct.stack_st_fake_X509_ALGOR */
            	1109, 8,
            	109, 24,
            8884099, 8, 2, /* 1109: pointer_to_array_of_pointers_to_stack */
            	1116, 0,
            	52, 20,
            0, 8, 1, /* 1116: pointer.X509_ALGOR */
            	859, 0,
            1, 8, 1, /* 1121: pointer.struct.x509_cert_aux_st */
            	1041, 0,
            1, 8, 1, /* 1126: pointer.struct.EDIPartyName_st */
            	1131, 0,
            0, 16, 2, /* 1131: struct.EDIPartyName_st */
            	1138, 0,
            	1138, 8,
            1, 8, 1, /* 1138: pointer.struct.asn1_string_st */
            	1143, 0,
            0, 24, 1, /* 1143: struct.asn1_string_st */
            	69, 8,
            1, 8, 1, /* 1148: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1153, 0,
            0, 32, 2, /* 1153: struct.stack_st_fake_X509_NAME_ENTRY */
            	1160, 8,
            	109, 24,
            8884099, 8, 2, /* 1160: pointer_to_array_of_pointers_to_stack */
            	1167, 0,
            	52, 20,
            0, 8, 1, /* 1167: pointer.X509_NAME_ENTRY */
            	1172, 0,
            0, 0, 1, /* 1172: X509_NAME_ENTRY */
            	1177, 0,
            0, 24, 2, /* 1177: struct.X509_name_entry_st */
            	1184, 0,
            	1198, 8,
            1, 8, 1, /* 1184: pointer.struct.asn1_object_st */
            	1189, 0,
            0, 40, 3, /* 1189: struct.asn1_object_st */
            	136, 0,
            	136, 8,
            	885, 24,
            1, 8, 1, /* 1198: pointer.struct.asn1_string_st */
            	1203, 0,
            0, 24, 1, /* 1203: struct.asn1_string_st */
            	69, 8,
            0, 40, 3, /* 1208: struct.X509_name_st */
            	1148, 0,
            	1217, 16,
            	69, 24,
            1, 8, 1, /* 1217: pointer.struct.buf_mem_st */
            	1222, 0,
            0, 24, 1, /* 1222: struct.buf_mem_st */
            	104, 8,
            1, 8, 1, /* 1227: pointer.struct.X509_name_st */
            	1208, 0,
            1, 8, 1, /* 1232: pointer.struct.asn1_string_st */
            	1143, 0,
            1, 8, 1, /* 1237: pointer.struct.asn1_string_st */
            	1143, 0,
            1, 8, 1, /* 1242: pointer.struct.asn1_string_st */
            	1143, 0,
            1, 8, 1, /* 1247: pointer.struct.asn1_string_st */
            	1143, 0,
            1, 8, 1, /* 1252: pointer.struct.asn1_string_st */
            	1143, 0,
            1, 8, 1, /* 1257: pointer.struct.asn1_string_st */
            	1143, 0,
            1, 8, 1, /* 1262: pointer.struct.asn1_string_st */
            	1143, 0,
            1, 8, 1, /* 1267: pointer.struct.asn1_string_st */
            	1143, 0,
            0, 8, 20, /* 1272: union.unknown */
            	104, 0,
            	1138, 0,
            	1315, 0,
            	1329, 0,
            	1334, 0,
            	1339, 0,
            	1267, 0,
            	1262, 0,
            	1257, 0,
            	1344, 0,
            	1252, 0,
            	1247, 0,
            	1349, 0,
            	1242, 0,
            	1237, 0,
            	1354, 0,
            	1232, 0,
            	1138, 0,
            	1138, 0,
            	1359, 0,
            1, 8, 1, /* 1315: pointer.struct.asn1_object_st */
            	1320, 0,
            0, 40, 3, /* 1320: struct.asn1_object_st */
            	136, 0,
            	136, 8,
            	885, 24,
            1, 8, 1, /* 1329: pointer.struct.asn1_string_st */
            	1143, 0,
            1, 8, 1, /* 1334: pointer.struct.asn1_string_st */
            	1143, 0,
            1, 8, 1, /* 1339: pointer.struct.asn1_string_st */
            	1143, 0,
            1, 8, 1, /* 1344: pointer.struct.asn1_string_st */
            	1143, 0,
            1, 8, 1, /* 1349: pointer.struct.asn1_string_st */
            	1143, 0,
            1, 8, 1, /* 1354: pointer.struct.asn1_string_st */
            	1143, 0,
            1, 8, 1, /* 1359: pointer.struct.ASN1_VALUE_st */
            	1364, 0,
            0, 0, 0, /* 1364: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1367: pointer.struct.otherName_st */
            	1372, 0,
            0, 16, 2, /* 1372: struct.otherName_st */
            	1315, 0,
            	1379, 8,
            1, 8, 1, /* 1379: pointer.struct.asn1_type_st */
            	1384, 0,
            0, 16, 1, /* 1384: struct.asn1_type_st */
            	1272, 8,
            0, 16, 1, /* 1389: struct.GENERAL_NAME_st */
            	1394, 8,
            0, 8, 15, /* 1394: union.unknown */
            	104, 0,
            	1367, 0,
            	1344, 0,
            	1344, 0,
            	1379, 0,
            	1227, 0,
            	1126, 0,
            	1344, 0,
            	1267, 0,
            	1315, 0,
            	1267, 0,
            	1227, 0,
            	1344, 0,
            	1315, 0,
            	1379, 0,
            1, 8, 1, /* 1427: pointer.struct.GENERAL_NAME_st */
            	1389, 0,
            0, 24, 3, /* 1432: struct.GENERAL_SUBTREE_st */
            	1427, 0,
            	1329, 8,
            	1329, 16,
            0, 8, 5, /* 1441: union.unknown */
            	104, 0,
            	640, 0,
            	501, 0,
            	0, 0,
            	1454, 0,
            1, 8, 1, /* 1454: pointer.struct.ec_key_st */
            	1459, 0,
            0, 56, 4, /* 1459: struct.ec_key_st */
            	1470, 8,
            	1918, 16,
            	1923, 24,
            	1940, 48,
            1, 8, 1, /* 1470: pointer.struct.ec_group_st */
            	1475, 0,
            0, 232, 12, /* 1475: struct.ec_group_st */
            	1502, 0,
            	1674, 8,
            	1874, 16,
            	1874, 40,
            	69, 80,
            	1886, 96,
            	1874, 104,
            	1874, 152,
            	1874, 176,
            	839, 208,
            	839, 216,
            	1915, 224,
            1, 8, 1, /* 1502: pointer.struct.ec_method_st */
            	1507, 0,
            0, 304, 37, /* 1507: struct.ec_method_st */
            	1584, 8,
            	1587, 16,
            	1587, 24,
            	1590, 32,
            	1593, 40,
            	1596, 48,
            	1599, 56,
            	1602, 64,
            	1605, 72,
            	1608, 80,
            	1608, 88,
            	1611, 96,
            	1614, 104,
            	1617, 112,
            	1620, 120,
            	1623, 128,
            	1626, 136,
            	1629, 144,
            	1632, 152,
            	1635, 160,
            	1638, 168,
            	1641, 176,
            	1644, 184,
            	1647, 192,
            	1650, 200,
            	1653, 208,
            	1644, 216,
            	1656, 224,
            	1659, 232,
            	1662, 240,
            	1599, 248,
            	1665, 256,
            	1668, 264,
            	1665, 272,
            	1668, 280,
            	1668, 288,
            	1671, 296,
            8884097, 8, 0, /* 1584: pointer.func */
            8884097, 8, 0, /* 1587: pointer.func */
            8884097, 8, 0, /* 1590: pointer.func */
            8884097, 8, 0, /* 1593: pointer.func */
            8884097, 8, 0, /* 1596: pointer.func */
            8884097, 8, 0, /* 1599: pointer.func */
            8884097, 8, 0, /* 1602: pointer.func */
            8884097, 8, 0, /* 1605: pointer.func */
            8884097, 8, 0, /* 1608: pointer.func */
            8884097, 8, 0, /* 1611: pointer.func */
            8884097, 8, 0, /* 1614: pointer.func */
            8884097, 8, 0, /* 1617: pointer.func */
            8884097, 8, 0, /* 1620: pointer.func */
            8884097, 8, 0, /* 1623: pointer.func */
            8884097, 8, 0, /* 1626: pointer.func */
            8884097, 8, 0, /* 1629: pointer.func */
            8884097, 8, 0, /* 1632: pointer.func */
            8884097, 8, 0, /* 1635: pointer.func */
            8884097, 8, 0, /* 1638: pointer.func */
            8884097, 8, 0, /* 1641: pointer.func */
            8884097, 8, 0, /* 1644: pointer.func */
            8884097, 8, 0, /* 1647: pointer.func */
            8884097, 8, 0, /* 1650: pointer.func */
            8884097, 8, 0, /* 1653: pointer.func */
            8884097, 8, 0, /* 1656: pointer.func */
            8884097, 8, 0, /* 1659: pointer.func */
            8884097, 8, 0, /* 1662: pointer.func */
            8884097, 8, 0, /* 1665: pointer.func */
            8884097, 8, 0, /* 1668: pointer.func */
            8884097, 8, 0, /* 1671: pointer.func */
            1, 8, 1, /* 1674: pointer.struct.ec_point_st */
            	1679, 0,
            0, 88, 4, /* 1679: struct.ec_point_st */
            	1690, 0,
            	1862, 8,
            	1862, 32,
            	1862, 56,
            1, 8, 1, /* 1690: pointer.struct.ec_method_st */
            	1695, 0,
            0, 304, 37, /* 1695: struct.ec_method_st */
            	1772, 8,
            	1775, 16,
            	1775, 24,
            	1778, 32,
            	1781, 40,
            	1784, 48,
            	1787, 56,
            	1790, 64,
            	1793, 72,
            	1796, 80,
            	1796, 88,
            	1799, 96,
            	1802, 104,
            	1805, 112,
            	1808, 120,
            	1811, 128,
            	1814, 136,
            	1817, 144,
            	1820, 152,
            	1823, 160,
            	1826, 168,
            	1829, 176,
            	1832, 184,
            	1835, 192,
            	1838, 200,
            	1841, 208,
            	1832, 216,
            	1844, 224,
            	1847, 232,
            	1850, 240,
            	1787, 248,
            	1853, 256,
            	1856, 264,
            	1853, 272,
            	1856, 280,
            	1856, 288,
            	1859, 296,
            8884097, 8, 0, /* 1772: pointer.func */
            8884097, 8, 0, /* 1775: pointer.func */
            8884097, 8, 0, /* 1778: pointer.func */
            8884097, 8, 0, /* 1781: pointer.func */
            8884097, 8, 0, /* 1784: pointer.func */
            8884097, 8, 0, /* 1787: pointer.func */
            8884097, 8, 0, /* 1790: pointer.func */
            8884097, 8, 0, /* 1793: pointer.func */
            8884097, 8, 0, /* 1796: pointer.func */
            8884097, 8, 0, /* 1799: pointer.func */
            8884097, 8, 0, /* 1802: pointer.func */
            8884097, 8, 0, /* 1805: pointer.func */
            8884097, 8, 0, /* 1808: pointer.func */
            8884097, 8, 0, /* 1811: pointer.func */
            8884097, 8, 0, /* 1814: pointer.func */
            8884097, 8, 0, /* 1817: pointer.func */
            8884097, 8, 0, /* 1820: pointer.func */
            8884097, 8, 0, /* 1823: pointer.func */
            8884097, 8, 0, /* 1826: pointer.func */
            8884097, 8, 0, /* 1829: pointer.func */
            8884097, 8, 0, /* 1832: pointer.func */
            8884097, 8, 0, /* 1835: pointer.func */
            8884097, 8, 0, /* 1838: pointer.func */
            8884097, 8, 0, /* 1841: pointer.func */
            8884097, 8, 0, /* 1844: pointer.func */
            8884097, 8, 0, /* 1847: pointer.func */
            8884097, 8, 0, /* 1850: pointer.func */
            8884097, 8, 0, /* 1853: pointer.func */
            8884097, 8, 0, /* 1856: pointer.func */
            8884097, 8, 0, /* 1859: pointer.func */
            0, 24, 1, /* 1862: struct.bignum_st */
            	1867, 0,
            8884099, 8, 2, /* 1867: pointer_to_array_of_pointers_to_stack */
            	49, 0,
            	52, 12,
            0, 24, 1, /* 1874: struct.bignum_st */
            	1879, 0,
            8884099, 8, 2, /* 1879: pointer_to_array_of_pointers_to_stack */
            	49, 0,
            	52, 12,
            1, 8, 1, /* 1886: pointer.struct.ec_extra_data_st */
            	1891, 0,
            0, 40, 5, /* 1891: struct.ec_extra_data_st */
            	1904, 0,
            	839, 8,
            	1909, 16,
            	1912, 24,
            	1912, 32,
            1, 8, 1, /* 1904: pointer.struct.ec_extra_data_st */
            	1891, 0,
            8884097, 8, 0, /* 1909: pointer.func */
            8884097, 8, 0, /* 1912: pointer.func */
            8884097, 8, 0, /* 1915: pointer.func */
            1, 8, 1, /* 1918: pointer.struct.ec_point_st */
            	1679, 0,
            1, 8, 1, /* 1923: pointer.struct.bignum_st */
            	1928, 0,
            0, 24, 1, /* 1928: struct.bignum_st */
            	1933, 0,
            8884099, 8, 2, /* 1933: pointer_to_array_of_pointers_to_stack */
            	49, 0,
            	52, 12,
            1, 8, 1, /* 1940: pointer.struct.ec_extra_data_st */
            	1945, 0,
            0, 40, 5, /* 1945: struct.ec_extra_data_st */
            	1958, 0,
            	839, 8,
            	1909, 16,
            	1912, 24,
            	1912, 32,
            1, 8, 1, /* 1958: pointer.struct.ec_extra_data_st */
            	1945, 0,
            1, 8, 1, /* 1963: pointer.struct.stack_st_GENERAL_NAME */
            	1968, 0,
            0, 32, 2, /* 1968: struct.stack_st_fake_GENERAL_NAME */
            	1975, 8,
            	109, 24,
            8884099, 8, 2, /* 1975: pointer_to_array_of_pointers_to_stack */
            	1982, 0,
            	52, 20,
            0, 8, 1, /* 1982: pointer.GENERAL_NAME */
            	1987, 0,
            0, 0, 1, /* 1987: GENERAL_NAME */
            	1992, 0,
            0, 16, 1, /* 1992: struct.GENERAL_NAME_st */
            	1997, 8,
            0, 8, 15, /* 1997: union.unknown */
            	104, 0,
            	2030, 0,
            	2149, 0,
            	2149, 0,
            	2056, 0,
            	2197, 0,
            	2245, 0,
            	2149, 0,
            	2134, 0,
            	2042, 0,
            	2134, 0,
            	2197, 0,
            	2149, 0,
            	2042, 0,
            	2056, 0,
            1, 8, 1, /* 2030: pointer.struct.otherName_st */
            	2035, 0,
            0, 16, 2, /* 2035: struct.otherName_st */
            	2042, 0,
            	2056, 8,
            1, 8, 1, /* 2042: pointer.struct.asn1_object_st */
            	2047, 0,
            0, 40, 3, /* 2047: struct.asn1_object_st */
            	136, 0,
            	136, 8,
            	885, 24,
            1, 8, 1, /* 2056: pointer.struct.asn1_type_st */
            	2061, 0,
            0, 16, 1, /* 2061: struct.asn1_type_st */
            	2066, 8,
            0, 8, 20, /* 2066: union.unknown */
            	104, 0,
            	2109, 0,
            	2042, 0,
            	2119, 0,
            	2124, 0,
            	2129, 0,
            	2134, 0,
            	2139, 0,
            	2144, 0,
            	2149, 0,
            	2154, 0,
            	2159, 0,
            	2164, 0,
            	2169, 0,
            	2174, 0,
            	2179, 0,
            	2184, 0,
            	2109, 0,
            	2109, 0,
            	2189, 0,
            1, 8, 1, /* 2109: pointer.struct.asn1_string_st */
            	2114, 0,
            0, 24, 1, /* 2114: struct.asn1_string_st */
            	69, 8,
            1, 8, 1, /* 2119: pointer.struct.asn1_string_st */
            	2114, 0,
            1, 8, 1, /* 2124: pointer.struct.asn1_string_st */
            	2114, 0,
            1, 8, 1, /* 2129: pointer.struct.asn1_string_st */
            	2114, 0,
            1, 8, 1, /* 2134: pointer.struct.asn1_string_st */
            	2114, 0,
            1, 8, 1, /* 2139: pointer.struct.asn1_string_st */
            	2114, 0,
            1, 8, 1, /* 2144: pointer.struct.asn1_string_st */
            	2114, 0,
            1, 8, 1, /* 2149: pointer.struct.asn1_string_st */
            	2114, 0,
            1, 8, 1, /* 2154: pointer.struct.asn1_string_st */
            	2114, 0,
            1, 8, 1, /* 2159: pointer.struct.asn1_string_st */
            	2114, 0,
            1, 8, 1, /* 2164: pointer.struct.asn1_string_st */
            	2114, 0,
            1, 8, 1, /* 2169: pointer.struct.asn1_string_st */
            	2114, 0,
            1, 8, 1, /* 2174: pointer.struct.asn1_string_st */
            	2114, 0,
            1, 8, 1, /* 2179: pointer.struct.asn1_string_st */
            	2114, 0,
            1, 8, 1, /* 2184: pointer.struct.asn1_string_st */
            	2114, 0,
            1, 8, 1, /* 2189: pointer.struct.ASN1_VALUE_st */
            	2194, 0,
            0, 0, 0, /* 2194: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2197: pointer.struct.X509_name_st */
            	2202, 0,
            0, 40, 3, /* 2202: struct.X509_name_st */
            	2211, 0,
            	2235, 16,
            	69, 24,
            1, 8, 1, /* 2211: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2216, 0,
            0, 32, 2, /* 2216: struct.stack_st_fake_X509_NAME_ENTRY */
            	2223, 8,
            	109, 24,
            8884099, 8, 2, /* 2223: pointer_to_array_of_pointers_to_stack */
            	2230, 0,
            	52, 20,
            0, 8, 1, /* 2230: pointer.X509_NAME_ENTRY */
            	1172, 0,
            1, 8, 1, /* 2235: pointer.struct.buf_mem_st */
            	2240, 0,
            0, 24, 1, /* 2240: struct.buf_mem_st */
            	104, 8,
            1, 8, 1, /* 2245: pointer.struct.EDIPartyName_st */
            	2250, 0,
            0, 16, 2, /* 2250: struct.EDIPartyName_st */
            	2109, 0,
            	2109, 8,
            0, 24, 1, /* 2257: struct.asn1_string_st */
            	69, 8,
            1, 8, 1, /* 2262: pointer.struct.buf_mem_st */
            	2267, 0,
            0, 24, 1, /* 2267: struct.buf_mem_st */
            	104, 8,
            1, 8, 1, /* 2272: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2277, 0,
            0, 32, 2, /* 2277: struct.stack_st_fake_X509_NAME_ENTRY */
            	2284, 8,
            	109, 24,
            8884099, 8, 2, /* 2284: pointer_to_array_of_pointers_to_stack */
            	2291, 0,
            	52, 20,
            0, 8, 1, /* 2291: pointer.X509_NAME_ENTRY */
            	1172, 0,
            1, 8, 1, /* 2296: pointer.struct.stack_st_GENERAL_NAME */
            	2301, 0,
            0, 32, 2, /* 2301: struct.stack_st_fake_GENERAL_NAME */
            	2308, 8,
            	109, 24,
            8884099, 8, 2, /* 2308: pointer_to_array_of_pointers_to_stack */
            	2315, 0,
            	52, 20,
            0, 8, 1, /* 2315: pointer.GENERAL_NAME */
            	1987, 0,
            0, 8, 2, /* 2320: union.unknown */
            	2296, 0,
            	2272, 0,
            0, 24, 2, /* 2327: struct.DIST_POINT_NAME_st */
            	2320, 8,
            	2334, 16,
            1, 8, 1, /* 2334: pointer.struct.X509_name_st */
            	2339, 0,
            0, 40, 3, /* 2339: struct.X509_name_st */
            	2272, 0,
            	2262, 16,
            	69, 24,
            0, 0, 1, /* 2348: DIST_POINT */
            	2353, 0,
            0, 32, 3, /* 2353: struct.DIST_POINT_st */
            	2362, 0,
            	2367, 8,
            	2296, 16,
            1, 8, 1, /* 2362: pointer.struct.DIST_POINT_NAME_st */
            	2327, 0,
            1, 8, 1, /* 2367: pointer.struct.asn1_string_st */
            	2257, 0,
            1, 8, 1, /* 2372: pointer.struct.stack_st_DIST_POINT */
            	2377, 0,
            0, 32, 2, /* 2377: struct.stack_st_fake_DIST_POINT */
            	2384, 8,
            	109, 24,
            8884099, 8, 2, /* 2384: pointer_to_array_of_pointers_to_stack */
            	2391, 0,
            	52, 20,
            0, 8, 1, /* 2391: pointer.DIST_POINT */
            	2348, 0,
            0, 32, 3, /* 2396: struct.X509_POLICY_DATA_st */
            	2405, 8,
            	2419, 16,
            	2664, 24,
            1, 8, 1, /* 2405: pointer.struct.asn1_object_st */
            	2410, 0,
            0, 40, 3, /* 2410: struct.asn1_object_st */
            	136, 0,
            	136, 8,
            	885, 24,
            1, 8, 1, /* 2419: pointer.struct.stack_st_POLICYQUALINFO */
            	2424, 0,
            0, 32, 2, /* 2424: struct.stack_st_fake_POLICYQUALINFO */
            	2431, 8,
            	109, 24,
            8884099, 8, 2, /* 2431: pointer_to_array_of_pointers_to_stack */
            	2438, 0,
            	52, 20,
            0, 8, 1, /* 2438: pointer.POLICYQUALINFO */
            	2443, 0,
            0, 0, 1, /* 2443: POLICYQUALINFO */
            	2448, 0,
            0, 16, 2, /* 2448: struct.POLICYQUALINFO_st */
            	2455, 0,
            	2469, 8,
            1, 8, 1, /* 2455: pointer.struct.asn1_object_st */
            	2460, 0,
            0, 40, 3, /* 2460: struct.asn1_object_st */
            	136, 0,
            	136, 8,
            	885, 24,
            0, 8, 3, /* 2469: union.unknown */
            	2478, 0,
            	2488, 0,
            	2546, 0,
            1, 8, 1, /* 2478: pointer.struct.asn1_string_st */
            	2483, 0,
            0, 24, 1, /* 2483: struct.asn1_string_st */
            	69, 8,
            1, 8, 1, /* 2488: pointer.struct.USERNOTICE_st */
            	2493, 0,
            0, 16, 2, /* 2493: struct.USERNOTICE_st */
            	2500, 0,
            	2512, 8,
            1, 8, 1, /* 2500: pointer.struct.NOTICEREF_st */
            	2505, 0,
            0, 16, 2, /* 2505: struct.NOTICEREF_st */
            	2512, 0,
            	2517, 8,
            1, 8, 1, /* 2512: pointer.struct.asn1_string_st */
            	2483, 0,
            1, 8, 1, /* 2517: pointer.struct.stack_st_ASN1_INTEGER */
            	2522, 0,
            0, 32, 2, /* 2522: struct.stack_st_fake_ASN1_INTEGER */
            	2529, 8,
            	109, 24,
            8884099, 8, 2, /* 2529: pointer_to_array_of_pointers_to_stack */
            	2536, 0,
            	52, 20,
            0, 8, 1, /* 2536: pointer.ASN1_INTEGER */
            	2541, 0,
            0, 0, 1, /* 2541: ASN1_INTEGER */
            	948, 0,
            1, 8, 1, /* 2546: pointer.struct.asn1_type_st */
            	2551, 0,
            0, 16, 1, /* 2551: struct.asn1_type_st */
            	2556, 8,
            0, 8, 20, /* 2556: union.unknown */
            	104, 0,
            	2512, 0,
            	2455, 0,
            	2599, 0,
            	2604, 0,
            	2609, 0,
            	2614, 0,
            	2619, 0,
            	2624, 0,
            	2478, 0,
            	2629, 0,
            	2634, 0,
            	2639, 0,
            	2644, 0,
            	2649, 0,
            	2654, 0,
            	2659, 0,
            	2512, 0,
            	2512, 0,
            	1359, 0,
            1, 8, 1, /* 2599: pointer.struct.asn1_string_st */
            	2483, 0,
            1, 8, 1, /* 2604: pointer.struct.asn1_string_st */
            	2483, 0,
            1, 8, 1, /* 2609: pointer.struct.asn1_string_st */
            	2483, 0,
            1, 8, 1, /* 2614: pointer.struct.asn1_string_st */
            	2483, 0,
            1, 8, 1, /* 2619: pointer.struct.asn1_string_st */
            	2483, 0,
            1, 8, 1, /* 2624: pointer.struct.asn1_string_st */
            	2483, 0,
            1, 8, 1, /* 2629: pointer.struct.asn1_string_st */
            	2483, 0,
            1, 8, 1, /* 2634: pointer.struct.asn1_string_st */
            	2483, 0,
            1, 8, 1, /* 2639: pointer.struct.asn1_string_st */
            	2483, 0,
            1, 8, 1, /* 2644: pointer.struct.asn1_string_st */
            	2483, 0,
            1, 8, 1, /* 2649: pointer.struct.asn1_string_st */
            	2483, 0,
            1, 8, 1, /* 2654: pointer.struct.asn1_string_st */
            	2483, 0,
            1, 8, 1, /* 2659: pointer.struct.asn1_string_st */
            	2483, 0,
            1, 8, 1, /* 2664: pointer.struct.stack_st_ASN1_OBJECT */
            	2669, 0,
            0, 32, 2, /* 2669: struct.stack_st_fake_ASN1_OBJECT */
            	2676, 8,
            	109, 24,
            8884099, 8, 2, /* 2676: pointer_to_array_of_pointers_to_stack */
            	2683, 0,
            	52, 20,
            0, 8, 1, /* 2683: pointer.ASN1_OBJECT */
            	1078, 0,
            1, 8, 1, /* 2688: pointer.struct.stack_st_X509_POLICY_DATA */
            	2693, 0,
            0, 32, 2, /* 2693: struct.stack_st_fake_X509_POLICY_DATA */
            	2700, 8,
            	109, 24,
            8884099, 8, 2, /* 2700: pointer_to_array_of_pointers_to_stack */
            	2707, 0,
            	52, 20,
            0, 8, 1, /* 2707: pointer.X509_POLICY_DATA */
            	2712, 0,
            0, 0, 1, /* 2712: X509_POLICY_DATA */
            	2396, 0,
            1, 8, 1, /* 2717: pointer.struct.stack_st_ASN1_OBJECT */
            	2722, 0,
            0, 32, 2, /* 2722: struct.stack_st_fake_ASN1_OBJECT */
            	2729, 8,
            	109, 24,
            8884099, 8, 2, /* 2729: pointer_to_array_of_pointers_to_stack */
            	2736, 0,
            	52, 20,
            0, 8, 1, /* 2736: pointer.ASN1_OBJECT */
            	1078, 0,
            0, 0, 1, /* 2741: GENERAL_SUBTREE */
            	1432, 0,
            1, 8, 1, /* 2746: pointer.struct.stack_st_POLICYQUALINFO */
            	2751, 0,
            0, 32, 2, /* 2751: struct.stack_st_fake_POLICYQUALINFO */
            	2758, 8,
            	109, 24,
            8884099, 8, 2, /* 2758: pointer_to_array_of_pointers_to_stack */
            	2765, 0,
            	52, 20,
            0, 8, 1, /* 2765: pointer.POLICYQUALINFO */
            	2443, 0,
            0, 40, 3, /* 2770: struct.asn1_object_st */
            	136, 0,
            	136, 8,
            	885, 24,
            0, 32, 3, /* 2779: struct.X509_POLICY_DATA_st */
            	2788, 8,
            	2746, 16,
            	2717, 24,
            1, 8, 1, /* 2788: pointer.struct.asn1_object_st */
            	2770, 0,
            1, 8, 1, /* 2793: pointer.struct.X509_POLICY_DATA_st */
            	2779, 0,
            0, 40, 2, /* 2798: struct.X509_POLICY_CACHE_st */
            	2793, 0,
            	2688, 8,
            1, 8, 1, /* 2805: pointer.struct.stack_st_GENERAL_NAME */
            	2810, 0,
            0, 32, 2, /* 2810: struct.stack_st_fake_GENERAL_NAME */
            	2817, 8,
            	109, 24,
            8884099, 8, 2, /* 2817: pointer_to_array_of_pointers_to_stack */
            	2824, 0,
            	52, 20,
            0, 8, 1, /* 2824: pointer.GENERAL_NAME */
            	1987, 0,
            1, 8, 1, /* 2829: pointer.struct.asn1_string_st */
            	2834, 0,
            0, 24, 1, /* 2834: struct.asn1_string_st */
            	69, 8,
            1, 8, 1, /* 2839: pointer.struct.AUTHORITY_KEYID_st */
            	2844, 0,
            0, 24, 3, /* 2844: struct.AUTHORITY_KEYID_st */
            	2829, 0,
            	2805, 8,
            	2853, 16,
            1, 8, 1, /* 2853: pointer.struct.asn1_string_st */
            	2834, 0,
            0, 32, 1, /* 2858: struct.stack_st_void */
            	2863, 0,
            0, 32, 2, /* 2863: struct.stack_st */
            	99, 8,
            	109, 24,
            1, 8, 1, /* 2870: pointer.struct.stack_st_void */
            	2858, 0,
            0, 24, 1, /* 2875: struct.asn1_string_st */
            	69, 8,
            1, 8, 1, /* 2880: pointer.struct.asn1_string_st */
            	2875, 0,
            0, 40, 3, /* 2885: struct.asn1_object_st */
            	136, 0,
            	136, 8,
            	885, 24,
            1, 8, 1, /* 2894: pointer.struct.asn1_object_st */
            	2885, 0,
            0, 24, 2, /* 2899: struct.X509_extension_st */
            	2894, 0,
            	2880, 16,
            0, 0, 1, /* 2906: X509_EXTENSION */
            	2899, 0,
            1, 8, 1, /* 2911: pointer.struct.stack_st_X509_EXTENSION */
            	2916, 0,
            0, 32, 2, /* 2916: struct.stack_st_fake_X509_EXTENSION */
            	2923, 8,
            	109, 24,
            8884099, 8, 2, /* 2923: pointer_to_array_of_pointers_to_stack */
            	2930, 0,
            	52, 20,
            0, 8, 1, /* 2930: pointer.X509_EXTENSION */
            	2906, 0,
            1, 8, 1, /* 2935: pointer.struct.asn1_string_st */
            	1036, 0,
            1, 8, 1, /* 2940: pointer.struct.asn1_string_st */
            	2945, 0,
            0, 24, 1, /* 2945: struct.asn1_string_st */
            	69, 8,
            1, 8, 1, /* 2950: pointer.struct.asn1_string_st */
            	2945, 0,
            1, 8, 1, /* 2955: pointer.struct.asn1_string_st */
            	2945, 0,
            1, 8, 1, /* 2960: pointer.struct.asn1_string_st */
            	2945, 0,
            1, 8, 1, /* 2965: pointer.struct.asn1_string_st */
            	2945, 0,
            1, 8, 1, /* 2970: pointer.struct.asn1_string_st */
            	2945, 0,
            1, 8, 1, /* 2975: pointer.struct.asn1_string_st */
            	2945, 0,
            1, 8, 1, /* 2980: pointer.struct.asn1_string_st */
            	2945, 0,
            0, 16, 1, /* 2985: struct.asn1_type_st */
            	2990, 8,
            0, 8, 20, /* 2990: union.unknown */
            	104, 0,
            	2980, 0,
            	3033, 0,
            	3047, 0,
            	2975, 0,
            	3052, 0,
            	2970, 0,
            	3057, 0,
            	2965, 0,
            	2960, 0,
            	2955, 0,
            	2950, 0,
            	3062, 0,
            	3067, 0,
            	3072, 0,
            	3077, 0,
            	2940, 0,
            	2980, 0,
            	2980, 0,
            	1023, 0,
            1, 8, 1, /* 3033: pointer.struct.asn1_object_st */
            	3038, 0,
            0, 40, 3, /* 3038: struct.asn1_object_st */
            	136, 0,
            	136, 8,
            	885, 24,
            1, 8, 1, /* 3047: pointer.struct.asn1_string_st */
            	2945, 0,
            1, 8, 1, /* 3052: pointer.struct.asn1_string_st */
            	2945, 0,
            1, 8, 1, /* 3057: pointer.struct.asn1_string_st */
            	2945, 0,
            1, 8, 1, /* 3062: pointer.struct.asn1_string_st */
            	2945, 0,
            1, 8, 1, /* 3067: pointer.struct.asn1_string_st */
            	2945, 0,
            1, 8, 1, /* 3072: pointer.struct.asn1_string_st */
            	2945, 0,
            1, 8, 1, /* 3077: pointer.struct.asn1_string_st */
            	2945, 0,
            0, 0, 0, /* 3082: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3085: pointer.struct.asn1_string_st */
            	3090, 0,
            0, 24, 1, /* 3090: struct.asn1_string_st */
            	69, 8,
            1, 8, 1, /* 3095: pointer.struct.asn1_string_st */
            	3090, 0,
            1, 8, 1, /* 3100: pointer.struct.asn1_string_st */
            	3090, 0,
            1, 8, 1, /* 3105: pointer.struct.asn1_string_st */
            	3090, 0,
            1, 8, 1, /* 3110: pointer.struct.asn1_string_st */
            	3090, 0,
            1, 8, 1, /* 3115: pointer.struct.asn1_string_st */
            	3090, 0,
            1, 8, 1, /* 3120: pointer.struct.asn1_object_st */
            	3125, 0,
            0, 40, 3, /* 3125: struct.asn1_object_st */
            	136, 0,
            	136, 8,
            	885, 24,
            1, 8, 1, /* 3134: pointer.struct.asn1_string_st */
            	3090, 0,
            1, 8, 1, /* 3139: pointer.struct.stack_st_ASN1_TYPE */
            	3144, 0,
            0, 32, 2, /* 3144: struct.stack_st_fake_ASN1_TYPE */
            	3151, 8,
            	109, 24,
            8884099, 8, 2, /* 3151: pointer_to_array_of_pointers_to_stack */
            	3158, 0,
            	52, 20,
            0, 8, 1, /* 3158: pointer.ASN1_TYPE */
            	3163, 0,
            0, 0, 1, /* 3163: ASN1_TYPE */
            	3168, 0,
            0, 16, 1, /* 3168: struct.asn1_type_st */
            	3173, 8,
            0, 8, 20, /* 3173: union.unknown */
            	104, 0,
            	3134, 0,
            	3120, 0,
            	3115, 0,
            	3216, 0,
            	3221, 0,
            	3226, 0,
            	3110, 0,
            	3231, 0,
            	3105, 0,
            	3236, 0,
            	3241, 0,
            	3246, 0,
            	3251, 0,
            	3100, 0,
            	3095, 0,
            	3085, 0,
            	3134, 0,
            	3134, 0,
            	3256, 0,
            1, 8, 1, /* 3216: pointer.struct.asn1_string_st */
            	3090, 0,
            1, 8, 1, /* 3221: pointer.struct.asn1_string_st */
            	3090, 0,
            1, 8, 1, /* 3226: pointer.struct.asn1_string_st */
            	3090, 0,
            1, 8, 1, /* 3231: pointer.struct.asn1_string_st */
            	3090, 0,
            1, 8, 1, /* 3236: pointer.struct.asn1_string_st */
            	3090, 0,
            1, 8, 1, /* 3241: pointer.struct.asn1_string_st */
            	3090, 0,
            1, 8, 1, /* 3246: pointer.struct.asn1_string_st */
            	3090, 0,
            1, 8, 1, /* 3251: pointer.struct.asn1_string_st */
            	3090, 0,
            1, 8, 1, /* 3256: pointer.struct.ASN1_VALUE_st */
            	3082, 0,
            0, 24, 2, /* 3261: struct.x509_attributes_st */
            	3033, 0,
            	3268, 16,
            0, 8, 3, /* 3268: union.unknown */
            	104, 0,
            	3139, 0,
            	3277, 0,
            1, 8, 1, /* 3277: pointer.struct.asn1_type_st */
            	2985, 0,
            1, 8, 1, /* 3282: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3287, 0,
            0, 32, 2, /* 3287: struct.stack_st_fake_X509_ATTRIBUTE */
            	3294, 8,
            	109, 24,
            8884099, 8, 2, /* 3294: pointer_to_array_of_pointers_to_stack */
            	3301, 0,
            	52, 20,
            0, 8, 1, /* 3301: pointer.X509_ATTRIBUTE */
            	3306, 0,
            0, 0, 1, /* 3306: X509_ATTRIBUTE */
            	3261, 0,
            0, 16, 1, /* 3311: struct.crypto_ex_data_st */
            	2870, 0,
            0, 24, 1, /* 3316: struct.ASN1_ENCODING_st */
            	69, 0,
            8884099, 8, 2, /* 3321: pointer_to_array_of_pointers_to_stack */
            	3328, 0,
            	52, 20,
            0, 8, 1, /* 3328: pointer.X509_ATTRIBUTE */
            	3306, 0,
            8884097, 8, 0, /* 3333: pointer.func */
            1, 8, 1, /* 3336: pointer.struct.NAME_CONSTRAINTS_st */
            	3341, 0,
            0, 16, 2, /* 3341: struct.NAME_CONSTRAINTS_st */
            	3348, 0,
            	3348, 8,
            1, 8, 1, /* 3348: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3353, 0,
            0, 32, 2, /* 3353: struct.stack_st_fake_GENERAL_SUBTREE */
            	3360, 8,
            	109, 24,
            8884099, 8, 2, /* 3360: pointer_to_array_of_pointers_to_stack */
            	3367, 0,
            	52, 20,
            0, 8, 1, /* 3367: pointer.GENERAL_SUBTREE */
            	2741, 0,
            8884097, 8, 0, /* 3372: pointer.func */
            8884097, 8, 0, /* 3375: pointer.func */
            0, 208, 24, /* 3378: struct.evp_pkey_asn1_method_st */
            	104, 16,
            	104, 24,
            	3429, 32,
            	3432, 40,
            	3435, 48,
            	3438, 56,
            	3441, 64,
            	3444, 72,
            	3438, 80,
            	3333, 88,
            	3333, 96,
            	3447, 104,
            	3450, 112,
            	3333, 120,
            	3375, 128,
            	3435, 136,
            	3438, 144,
            	3453, 152,
            	3456, 160,
            	3372, 168,
            	3447, 176,
            	3450, 184,
            	3459, 192,
            	3462, 200,
            8884097, 8, 0, /* 3429: pointer.func */
            8884097, 8, 0, /* 3432: pointer.func */
            8884097, 8, 0, /* 3435: pointer.func */
            8884097, 8, 0, /* 3438: pointer.func */
            8884097, 8, 0, /* 3441: pointer.func */
            8884097, 8, 0, /* 3444: pointer.func */
            8884097, 8, 0, /* 3447: pointer.func */
            8884097, 8, 0, /* 3450: pointer.func */
            8884097, 8, 0, /* 3453: pointer.func */
            8884097, 8, 0, /* 3456: pointer.func */
            8884097, 8, 0, /* 3459: pointer.func */
            8884097, 8, 0, /* 3462: pointer.func */
            1, 8, 1, /* 3465: pointer.struct.evp_pkey_st */
            	3470, 0,
            0, 56, 4, /* 3470: struct.evp_pkey_st */
            	3481, 16,
            	3486, 24,
            	1441, 32,
            	3491, 48,
            1, 8, 1, /* 3481: pointer.struct.evp_pkey_asn1_method_st */
            	3378, 0,
            1, 8, 1, /* 3486: pointer.struct.engine_st */
            	158, 0,
            1, 8, 1, /* 3491: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3496, 0,
            0, 32, 2, /* 3496: struct.stack_st_fake_X509_ATTRIBUTE */
            	3321, 8,
            	109, 24,
            1, 8, 1, /* 3503: pointer.struct.evp_pkey_asn1_method_st */
            	3378, 0,
            0, 56, 4, /* 3508: struct.evp_pkey_st */
            	3503, 16,
            	3519, 24,
            	3524, 32,
            	3282, 48,
            1, 8, 1, /* 3519: pointer.struct.engine_st */
            	158, 0,
            0, 8, 5, /* 3524: union.unknown */
            	104, 0,
            	3537, 0,
            	3542, 0,
            	3547, 0,
            	3552, 0,
            1, 8, 1, /* 3537: pointer.struct.rsa_st */
            	645, 0,
            1, 8, 1, /* 3542: pointer.struct.dsa_st */
            	506, 0,
            1, 8, 1, /* 3547: pointer.struct.dh_st */
            	5, 0,
            1, 8, 1, /* 3552: pointer.struct.ec_key_st */
            	1459, 0,
            1, 8, 1, /* 3557: pointer.struct.evp_pkey_st */
            	3508, 0,
            0, 24, 1, /* 3562: struct.asn1_string_st */
            	69, 8,
            1, 8, 1, /* 3567: pointer.struct.x509_st */
            	3572, 0,
            0, 184, 12, /* 3572: struct.x509_st */
            	3599, 0,
            	3634, 8,
            	2935, 16,
            	104, 32,
            	3311, 40,
            	1092, 104,
            	2839, 112,
            	3728, 120,
            	2372, 128,
            	1963, 136,
            	3336, 144,
            	1121, 176,
            1, 8, 1, /* 3599: pointer.struct.x509_cinf_st */
            	3604, 0,
            0, 104, 11, /* 3604: struct.x509_cinf_st */
            	3629, 0,
            	3629, 8,
            	3634, 16,
            	3639, 24,
            	3687, 32,
            	3639, 40,
            	3704, 48,
            	2935, 56,
            	2935, 64,
            	2911, 72,
            	3316, 80,
            1, 8, 1, /* 3629: pointer.struct.asn1_string_st */
            	1036, 0,
            1, 8, 1, /* 3634: pointer.struct.X509_algor_st */
            	864, 0,
            1, 8, 1, /* 3639: pointer.struct.X509_name_st */
            	3644, 0,
            0, 40, 3, /* 3644: struct.X509_name_st */
            	3653, 0,
            	3677, 16,
            	69, 24,
            1, 8, 1, /* 3653: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3658, 0,
            0, 32, 2, /* 3658: struct.stack_st_fake_X509_NAME_ENTRY */
            	3665, 8,
            	109, 24,
            8884099, 8, 2, /* 3665: pointer_to_array_of_pointers_to_stack */
            	3672, 0,
            	52, 20,
            0, 8, 1, /* 3672: pointer.X509_NAME_ENTRY */
            	1172, 0,
            1, 8, 1, /* 3677: pointer.struct.buf_mem_st */
            	3682, 0,
            0, 24, 1, /* 3682: struct.buf_mem_st */
            	104, 8,
            1, 8, 1, /* 3687: pointer.struct.X509_val_st */
            	3692, 0,
            0, 16, 2, /* 3692: struct.X509_val_st */
            	3699, 0,
            	3699, 8,
            1, 8, 1, /* 3699: pointer.struct.asn1_string_st */
            	1036, 0,
            1, 8, 1, /* 3704: pointer.struct.X509_pubkey_st */
            	3709, 0,
            0, 24, 3, /* 3709: struct.X509_pubkey_st */
            	3718, 0,
            	3723, 8,
            	3557, 16,
            1, 8, 1, /* 3718: pointer.struct.X509_algor_st */
            	864, 0,
            1, 8, 1, /* 3723: pointer.struct.asn1_string_st */
            	3562, 0,
            1, 8, 1, /* 3728: pointer.struct.X509_POLICY_CACHE_st */
            	2798, 0,
            0, 1, 0, /* 3733: char */
        },
        .arg_entity_index = { 3567, 3465, },
        .ret_entity_index = 52,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    EVP_PKEY * new_arg_b = *((EVP_PKEY * *)new_args->args[1]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_X509_check_private_key)(X509 *,EVP_PKEY *);
    orig_X509_check_private_key = dlsym(RTLD_NEXT, "X509_check_private_key");
    *new_ret_ptr = (*orig_X509_check_private_key)(new_arg_a,new_arg_b);

    syscall(889);

    return ret;
}

