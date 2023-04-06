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

long bb_SSL_CTX_set_timeout(SSL_CTX * arg_a,long arg_b);

long SSL_CTX_set_timeout(SSL_CTX * arg_a,long arg_b) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_set_timeout called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_CTX_set_timeout(arg_a,arg_b);
    else {
        long (*orig_SSL_CTX_set_timeout)(SSL_CTX *,long);
        orig_SSL_CTX_set_timeout = dlsym(RTLD_NEXT, "SSL_CTX_set_timeout");
        return orig_SSL_CTX_set_timeout(arg_a,arg_b);
    }
}

long bb_SSL_CTX_set_timeout(SSL_CTX * arg_a,long arg_b) 
{
    long ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 1, /* 0: SRTP_PROTECTION_PROFILE */
            	5, 0,
            0, 16, 1, /* 5: struct.srtp_protection_profile_st */
            	10, 0,
            1, 8, 1, /* 10: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 15: pointer.func */
            0, 24, 1, /* 18: struct.bignum_st */
            	23, 0,
            8884099, 8, 2, /* 23: pointer_to_array_of_pointers_to_stack */
            	30, 0,
            	33, 12,
            0, 4, 0, /* 30: unsigned int */
            0, 4, 0, /* 33: int */
            1, 8, 1, /* 36: pointer.struct.ssl3_buf_freelist_st */
            	41, 0,
            0, 24, 1, /* 41: struct.ssl3_buf_freelist_st */
            	46, 16,
            1, 8, 1, /* 46: pointer.struct.ssl3_buf_freelist_entry_st */
            	51, 0,
            0, 8, 1, /* 51: struct.ssl3_buf_freelist_entry_st */
            	46, 0,
            8884097, 8, 0, /* 56: pointer.func */
            8884097, 8, 0, /* 59: pointer.func */
            8884097, 8, 0, /* 62: pointer.func */
            8884097, 8, 0, /* 65: pointer.func */
            8884097, 8, 0, /* 68: pointer.func */
            1, 8, 1, /* 71: pointer.struct.dh_st */
            	76, 0,
            0, 144, 12, /* 76: struct.dh_st */
            	103, 8,
            	103, 16,
            	103, 32,
            	103, 40,
            	120, 56,
            	103, 64,
            	103, 72,
            	134, 80,
            	103, 96,
            	142, 112,
            	177, 128,
            	213, 136,
            1, 8, 1, /* 103: pointer.struct.bignum_st */
            	108, 0,
            0, 24, 1, /* 108: struct.bignum_st */
            	113, 0,
            8884099, 8, 2, /* 113: pointer_to_array_of_pointers_to_stack */
            	30, 0,
            	33, 12,
            1, 8, 1, /* 120: pointer.struct.bn_mont_ctx_st */
            	125, 0,
            0, 96, 3, /* 125: struct.bn_mont_ctx_st */
            	108, 8,
            	108, 32,
            	108, 56,
            1, 8, 1, /* 134: pointer.unsigned char */
            	139, 0,
            0, 1, 0, /* 139: unsigned char */
            0, 16, 1, /* 142: struct.crypto_ex_data_st */
            	147, 0,
            1, 8, 1, /* 147: pointer.struct.stack_st_void */
            	152, 0,
            0, 32, 1, /* 152: struct.stack_st_void */
            	157, 0,
            0, 32, 2, /* 157: struct.stack_st */
            	164, 8,
            	174, 24,
            1, 8, 1, /* 164: pointer.pointer.char */
            	169, 0,
            1, 8, 1, /* 169: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 174: pointer.func */
            1, 8, 1, /* 177: pointer.struct.dh_method */
            	182, 0,
            0, 72, 8, /* 182: struct.dh_method */
            	10, 0,
            	201, 8,
            	204, 16,
            	207, 24,
            	201, 32,
            	201, 40,
            	169, 56,
            	210, 64,
            8884097, 8, 0, /* 201: pointer.func */
            8884097, 8, 0, /* 204: pointer.func */
            8884097, 8, 0, /* 207: pointer.func */
            8884097, 8, 0, /* 210: pointer.func */
            1, 8, 1, /* 213: pointer.struct.engine_st */
            	218, 0,
            0, 216, 24, /* 218: struct.engine_st */
            	10, 0,
            	10, 8,
            	269, 16,
            	324, 24,
            	375, 32,
            	411, 40,
            	428, 48,
            	455, 56,
            	490, 64,
            	498, 72,
            	501, 80,
            	504, 88,
            	507, 96,
            	510, 104,
            	510, 112,
            	510, 120,
            	513, 128,
            	516, 136,
            	516, 144,
            	519, 152,
            	522, 160,
            	534, 184,
            	556, 200,
            	556, 208,
            1, 8, 1, /* 269: pointer.struct.rsa_meth_st */
            	274, 0,
            0, 112, 13, /* 274: struct.rsa_meth_st */
            	10, 0,
            	303, 8,
            	303, 16,
            	303, 24,
            	303, 32,
            	306, 40,
            	309, 48,
            	312, 56,
            	312, 64,
            	169, 80,
            	315, 88,
            	318, 96,
            	321, 104,
            8884097, 8, 0, /* 303: pointer.func */
            8884097, 8, 0, /* 306: pointer.func */
            8884097, 8, 0, /* 309: pointer.func */
            8884097, 8, 0, /* 312: pointer.func */
            8884097, 8, 0, /* 315: pointer.func */
            8884097, 8, 0, /* 318: pointer.func */
            8884097, 8, 0, /* 321: pointer.func */
            1, 8, 1, /* 324: pointer.struct.dsa_method */
            	329, 0,
            0, 96, 11, /* 329: struct.dsa_method */
            	10, 0,
            	354, 8,
            	357, 16,
            	360, 24,
            	363, 32,
            	366, 40,
            	369, 48,
            	369, 56,
            	169, 72,
            	372, 80,
            	369, 88,
            8884097, 8, 0, /* 354: pointer.func */
            8884097, 8, 0, /* 357: pointer.func */
            8884097, 8, 0, /* 360: pointer.func */
            8884097, 8, 0, /* 363: pointer.func */
            8884097, 8, 0, /* 366: pointer.func */
            8884097, 8, 0, /* 369: pointer.func */
            8884097, 8, 0, /* 372: pointer.func */
            1, 8, 1, /* 375: pointer.struct.dh_method */
            	380, 0,
            0, 72, 8, /* 380: struct.dh_method */
            	10, 0,
            	399, 8,
            	402, 16,
            	405, 24,
            	399, 32,
            	399, 40,
            	169, 56,
            	408, 64,
            8884097, 8, 0, /* 399: pointer.func */
            8884097, 8, 0, /* 402: pointer.func */
            8884097, 8, 0, /* 405: pointer.func */
            8884097, 8, 0, /* 408: pointer.func */
            1, 8, 1, /* 411: pointer.struct.ecdh_method */
            	416, 0,
            0, 32, 3, /* 416: struct.ecdh_method */
            	10, 0,
            	425, 8,
            	169, 24,
            8884097, 8, 0, /* 425: pointer.func */
            1, 8, 1, /* 428: pointer.struct.ecdsa_method */
            	433, 0,
            0, 48, 5, /* 433: struct.ecdsa_method */
            	10, 0,
            	446, 8,
            	449, 16,
            	452, 24,
            	169, 40,
            8884097, 8, 0, /* 446: pointer.func */
            8884097, 8, 0, /* 449: pointer.func */
            8884097, 8, 0, /* 452: pointer.func */
            1, 8, 1, /* 455: pointer.struct.rand_meth_st */
            	460, 0,
            0, 48, 6, /* 460: struct.rand_meth_st */
            	475, 0,
            	478, 8,
            	481, 16,
            	484, 24,
            	478, 32,
            	487, 40,
            8884097, 8, 0, /* 475: pointer.func */
            8884097, 8, 0, /* 478: pointer.func */
            8884097, 8, 0, /* 481: pointer.func */
            8884097, 8, 0, /* 484: pointer.func */
            8884097, 8, 0, /* 487: pointer.func */
            1, 8, 1, /* 490: pointer.struct.store_method_st */
            	495, 0,
            0, 0, 0, /* 495: struct.store_method_st */
            8884097, 8, 0, /* 498: pointer.func */
            8884097, 8, 0, /* 501: pointer.func */
            8884097, 8, 0, /* 504: pointer.func */
            8884097, 8, 0, /* 507: pointer.func */
            8884097, 8, 0, /* 510: pointer.func */
            8884097, 8, 0, /* 513: pointer.func */
            8884097, 8, 0, /* 516: pointer.func */
            8884097, 8, 0, /* 519: pointer.func */
            1, 8, 1, /* 522: pointer.struct.ENGINE_CMD_DEFN_st */
            	527, 0,
            0, 32, 2, /* 527: struct.ENGINE_CMD_DEFN_st */
            	10, 8,
            	10, 16,
            0, 16, 1, /* 534: struct.crypto_ex_data_st */
            	539, 0,
            1, 8, 1, /* 539: pointer.struct.stack_st_void */
            	544, 0,
            0, 32, 1, /* 544: struct.stack_st_void */
            	549, 0,
            0, 32, 2, /* 549: struct.stack_st */
            	164, 8,
            	174, 24,
            1, 8, 1, /* 556: pointer.struct.engine_st */
            	218, 0,
            1, 8, 1, /* 561: pointer.struct.rsa_st */
            	566, 0,
            0, 168, 17, /* 566: struct.rsa_st */
            	603, 16,
            	658, 24,
            	663, 32,
            	663, 40,
            	663, 48,
            	663, 56,
            	663, 64,
            	663, 72,
            	663, 80,
            	663, 88,
            	680, 96,
            	702, 120,
            	702, 128,
            	702, 136,
            	169, 144,
            	716, 152,
            	716, 160,
            1, 8, 1, /* 603: pointer.struct.rsa_meth_st */
            	608, 0,
            0, 112, 13, /* 608: struct.rsa_meth_st */
            	10, 0,
            	637, 8,
            	637, 16,
            	637, 24,
            	637, 32,
            	640, 40,
            	643, 48,
            	646, 56,
            	646, 64,
            	169, 80,
            	649, 88,
            	652, 96,
            	655, 104,
            8884097, 8, 0, /* 637: pointer.func */
            8884097, 8, 0, /* 640: pointer.func */
            8884097, 8, 0, /* 643: pointer.func */
            8884097, 8, 0, /* 646: pointer.func */
            8884097, 8, 0, /* 649: pointer.func */
            8884097, 8, 0, /* 652: pointer.func */
            8884097, 8, 0, /* 655: pointer.func */
            1, 8, 1, /* 658: pointer.struct.engine_st */
            	218, 0,
            1, 8, 1, /* 663: pointer.struct.bignum_st */
            	668, 0,
            0, 24, 1, /* 668: struct.bignum_st */
            	673, 0,
            8884099, 8, 2, /* 673: pointer_to_array_of_pointers_to_stack */
            	30, 0,
            	33, 12,
            0, 16, 1, /* 680: struct.crypto_ex_data_st */
            	685, 0,
            1, 8, 1, /* 685: pointer.struct.stack_st_void */
            	690, 0,
            0, 32, 1, /* 690: struct.stack_st_void */
            	695, 0,
            0, 32, 2, /* 695: struct.stack_st */
            	164, 8,
            	174, 24,
            1, 8, 1, /* 702: pointer.struct.bn_mont_ctx_st */
            	707, 0,
            0, 96, 3, /* 707: struct.bn_mont_ctx_st */
            	668, 8,
            	668, 32,
            	668, 56,
            1, 8, 1, /* 716: pointer.struct.bn_blinding_st */
            	721, 0,
            0, 88, 7, /* 721: struct.bn_blinding_st */
            	738, 0,
            	738, 8,
            	738, 16,
            	738, 24,
            	755, 40,
            	763, 72,
            	777, 80,
            1, 8, 1, /* 738: pointer.struct.bignum_st */
            	743, 0,
            0, 24, 1, /* 743: struct.bignum_st */
            	748, 0,
            8884099, 8, 2, /* 748: pointer_to_array_of_pointers_to_stack */
            	30, 0,
            	33, 12,
            0, 16, 1, /* 755: struct.crypto_threadid_st */
            	760, 0,
            0, 8, 0, /* 760: pointer.void */
            1, 8, 1, /* 763: pointer.struct.bn_mont_ctx_st */
            	768, 0,
            0, 96, 3, /* 768: struct.bn_mont_ctx_st */
            	743, 8,
            	743, 32,
            	743, 56,
            8884097, 8, 0, /* 777: pointer.func */
            8884097, 8, 0, /* 780: pointer.func */
            8884097, 8, 0, /* 783: pointer.func */
            1, 8, 1, /* 786: pointer.struct.env_md_st */
            	791, 0,
            0, 120, 8, /* 791: struct.env_md_st */
            	810, 24,
            	783, 32,
            	780, 40,
            	813, 48,
            	810, 56,
            	816, 64,
            	819, 72,
            	822, 112,
            8884097, 8, 0, /* 810: pointer.func */
            8884097, 8, 0, /* 813: pointer.func */
            8884097, 8, 0, /* 816: pointer.func */
            8884097, 8, 0, /* 819: pointer.func */
            8884097, 8, 0, /* 822: pointer.func */
            1, 8, 1, /* 825: pointer.struct.stack_st_X509_ATTRIBUTE */
            	830, 0,
            0, 32, 2, /* 830: struct.stack_st_fake_X509_ATTRIBUTE */
            	837, 8,
            	174, 24,
            8884099, 8, 2, /* 837: pointer_to_array_of_pointers_to_stack */
            	844, 0,
            	33, 20,
            0, 8, 1, /* 844: pointer.X509_ATTRIBUTE */
            	849, 0,
            0, 0, 1, /* 849: X509_ATTRIBUTE */
            	854, 0,
            0, 24, 2, /* 854: struct.x509_attributes_st */
            	861, 0,
            	880, 16,
            1, 8, 1, /* 861: pointer.struct.asn1_object_st */
            	866, 0,
            0, 40, 3, /* 866: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	875, 24,
            1, 8, 1, /* 875: pointer.unsigned char */
            	139, 0,
            0, 8, 3, /* 880: union.unknown */
            	169, 0,
            	889, 0,
            	1068, 0,
            1, 8, 1, /* 889: pointer.struct.stack_st_ASN1_TYPE */
            	894, 0,
            0, 32, 2, /* 894: struct.stack_st_fake_ASN1_TYPE */
            	901, 8,
            	174, 24,
            8884099, 8, 2, /* 901: pointer_to_array_of_pointers_to_stack */
            	908, 0,
            	33, 20,
            0, 8, 1, /* 908: pointer.ASN1_TYPE */
            	913, 0,
            0, 0, 1, /* 913: ASN1_TYPE */
            	918, 0,
            0, 16, 1, /* 918: struct.asn1_type_st */
            	923, 8,
            0, 8, 20, /* 923: union.unknown */
            	169, 0,
            	966, 0,
            	976, 0,
            	990, 0,
            	995, 0,
            	1000, 0,
            	1005, 0,
            	1010, 0,
            	1015, 0,
            	1020, 0,
            	1025, 0,
            	1030, 0,
            	1035, 0,
            	1040, 0,
            	1045, 0,
            	1050, 0,
            	1055, 0,
            	966, 0,
            	966, 0,
            	1060, 0,
            1, 8, 1, /* 966: pointer.struct.asn1_string_st */
            	971, 0,
            0, 24, 1, /* 971: struct.asn1_string_st */
            	134, 8,
            1, 8, 1, /* 976: pointer.struct.asn1_object_st */
            	981, 0,
            0, 40, 3, /* 981: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	875, 24,
            1, 8, 1, /* 990: pointer.struct.asn1_string_st */
            	971, 0,
            1, 8, 1, /* 995: pointer.struct.asn1_string_st */
            	971, 0,
            1, 8, 1, /* 1000: pointer.struct.asn1_string_st */
            	971, 0,
            1, 8, 1, /* 1005: pointer.struct.asn1_string_st */
            	971, 0,
            1, 8, 1, /* 1010: pointer.struct.asn1_string_st */
            	971, 0,
            1, 8, 1, /* 1015: pointer.struct.asn1_string_st */
            	971, 0,
            1, 8, 1, /* 1020: pointer.struct.asn1_string_st */
            	971, 0,
            1, 8, 1, /* 1025: pointer.struct.asn1_string_st */
            	971, 0,
            1, 8, 1, /* 1030: pointer.struct.asn1_string_st */
            	971, 0,
            1, 8, 1, /* 1035: pointer.struct.asn1_string_st */
            	971, 0,
            1, 8, 1, /* 1040: pointer.struct.asn1_string_st */
            	971, 0,
            1, 8, 1, /* 1045: pointer.struct.asn1_string_st */
            	971, 0,
            1, 8, 1, /* 1050: pointer.struct.asn1_string_st */
            	971, 0,
            1, 8, 1, /* 1055: pointer.struct.asn1_string_st */
            	971, 0,
            1, 8, 1, /* 1060: pointer.struct.ASN1_VALUE_st */
            	1065, 0,
            0, 0, 0, /* 1065: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1068: pointer.struct.asn1_type_st */
            	1073, 0,
            0, 16, 1, /* 1073: struct.asn1_type_st */
            	1078, 8,
            0, 8, 20, /* 1078: union.unknown */
            	169, 0,
            	1121, 0,
            	861, 0,
            	1131, 0,
            	1136, 0,
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
            	1121, 0,
            	1121, 0,
            	1201, 0,
            1, 8, 1, /* 1121: pointer.struct.asn1_string_st */
            	1126, 0,
            0, 24, 1, /* 1126: struct.asn1_string_st */
            	134, 8,
            1, 8, 1, /* 1131: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1136: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1141: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1146: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1151: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1156: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1161: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1166: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1171: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1176: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1181: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1186: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1191: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1196: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1201: pointer.struct.ASN1_VALUE_st */
            	1206, 0,
            0, 0, 0, /* 1206: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1209: pointer.struct.dh_st */
            	76, 0,
            1, 8, 1, /* 1214: pointer.struct.dsa_st */
            	1219, 0,
            0, 136, 11, /* 1219: struct.dsa_st */
            	1244, 24,
            	1244, 32,
            	1244, 40,
            	1244, 48,
            	1244, 56,
            	1244, 64,
            	1244, 72,
            	1261, 88,
            	1275, 104,
            	1297, 120,
            	1348, 128,
            1, 8, 1, /* 1244: pointer.struct.bignum_st */
            	1249, 0,
            0, 24, 1, /* 1249: struct.bignum_st */
            	1254, 0,
            8884099, 8, 2, /* 1254: pointer_to_array_of_pointers_to_stack */
            	30, 0,
            	33, 12,
            1, 8, 1, /* 1261: pointer.struct.bn_mont_ctx_st */
            	1266, 0,
            0, 96, 3, /* 1266: struct.bn_mont_ctx_st */
            	1249, 8,
            	1249, 32,
            	1249, 56,
            0, 16, 1, /* 1275: struct.crypto_ex_data_st */
            	1280, 0,
            1, 8, 1, /* 1280: pointer.struct.stack_st_void */
            	1285, 0,
            0, 32, 1, /* 1285: struct.stack_st_void */
            	1290, 0,
            0, 32, 2, /* 1290: struct.stack_st */
            	164, 8,
            	174, 24,
            1, 8, 1, /* 1297: pointer.struct.dsa_method */
            	1302, 0,
            0, 96, 11, /* 1302: struct.dsa_method */
            	10, 0,
            	1327, 8,
            	1330, 16,
            	1333, 24,
            	1336, 32,
            	1339, 40,
            	1342, 48,
            	1342, 56,
            	169, 72,
            	1345, 80,
            	1342, 88,
            8884097, 8, 0, /* 1327: pointer.func */
            8884097, 8, 0, /* 1330: pointer.func */
            8884097, 8, 0, /* 1333: pointer.func */
            8884097, 8, 0, /* 1336: pointer.func */
            8884097, 8, 0, /* 1339: pointer.func */
            8884097, 8, 0, /* 1342: pointer.func */
            8884097, 8, 0, /* 1345: pointer.func */
            1, 8, 1, /* 1348: pointer.struct.engine_st */
            	218, 0,
            1, 8, 1, /* 1353: pointer.struct.rsa_st */
            	566, 0,
            0, 8, 5, /* 1358: union.unknown */
            	169, 0,
            	1353, 0,
            	1214, 0,
            	1209, 0,
            	1371, 0,
            1, 8, 1, /* 1371: pointer.struct.ec_key_st */
            	1376, 0,
            0, 56, 4, /* 1376: struct.ec_key_st */
            	1387, 8,
            	1835, 16,
            	1840, 24,
            	1857, 48,
            1, 8, 1, /* 1387: pointer.struct.ec_group_st */
            	1392, 0,
            0, 232, 12, /* 1392: struct.ec_group_st */
            	1419, 0,
            	1591, 8,
            	1791, 16,
            	1791, 40,
            	134, 80,
            	1803, 96,
            	1791, 104,
            	1791, 152,
            	1791, 176,
            	760, 208,
            	760, 216,
            	1832, 224,
            1, 8, 1, /* 1419: pointer.struct.ec_method_st */
            	1424, 0,
            0, 304, 37, /* 1424: struct.ec_method_st */
            	1501, 8,
            	1504, 16,
            	1504, 24,
            	1507, 32,
            	1510, 40,
            	1513, 48,
            	1516, 56,
            	1519, 64,
            	1522, 72,
            	1525, 80,
            	1525, 88,
            	1528, 96,
            	1531, 104,
            	1534, 112,
            	1537, 120,
            	1540, 128,
            	1543, 136,
            	1546, 144,
            	1549, 152,
            	1552, 160,
            	1555, 168,
            	1558, 176,
            	1561, 184,
            	1564, 192,
            	1567, 200,
            	1570, 208,
            	1561, 216,
            	1573, 224,
            	1576, 232,
            	1579, 240,
            	1516, 248,
            	1582, 256,
            	1585, 264,
            	1582, 272,
            	1585, 280,
            	1585, 288,
            	1588, 296,
            8884097, 8, 0, /* 1501: pointer.func */
            8884097, 8, 0, /* 1504: pointer.func */
            8884097, 8, 0, /* 1507: pointer.func */
            8884097, 8, 0, /* 1510: pointer.func */
            8884097, 8, 0, /* 1513: pointer.func */
            8884097, 8, 0, /* 1516: pointer.func */
            8884097, 8, 0, /* 1519: pointer.func */
            8884097, 8, 0, /* 1522: pointer.func */
            8884097, 8, 0, /* 1525: pointer.func */
            8884097, 8, 0, /* 1528: pointer.func */
            8884097, 8, 0, /* 1531: pointer.func */
            8884097, 8, 0, /* 1534: pointer.func */
            8884097, 8, 0, /* 1537: pointer.func */
            8884097, 8, 0, /* 1540: pointer.func */
            8884097, 8, 0, /* 1543: pointer.func */
            8884097, 8, 0, /* 1546: pointer.func */
            8884097, 8, 0, /* 1549: pointer.func */
            8884097, 8, 0, /* 1552: pointer.func */
            8884097, 8, 0, /* 1555: pointer.func */
            8884097, 8, 0, /* 1558: pointer.func */
            8884097, 8, 0, /* 1561: pointer.func */
            8884097, 8, 0, /* 1564: pointer.func */
            8884097, 8, 0, /* 1567: pointer.func */
            8884097, 8, 0, /* 1570: pointer.func */
            8884097, 8, 0, /* 1573: pointer.func */
            8884097, 8, 0, /* 1576: pointer.func */
            8884097, 8, 0, /* 1579: pointer.func */
            8884097, 8, 0, /* 1582: pointer.func */
            8884097, 8, 0, /* 1585: pointer.func */
            8884097, 8, 0, /* 1588: pointer.func */
            1, 8, 1, /* 1591: pointer.struct.ec_point_st */
            	1596, 0,
            0, 88, 4, /* 1596: struct.ec_point_st */
            	1607, 0,
            	1779, 8,
            	1779, 32,
            	1779, 56,
            1, 8, 1, /* 1607: pointer.struct.ec_method_st */
            	1612, 0,
            0, 304, 37, /* 1612: struct.ec_method_st */
            	1689, 8,
            	1692, 16,
            	1692, 24,
            	1695, 32,
            	1698, 40,
            	1701, 48,
            	1704, 56,
            	1707, 64,
            	1710, 72,
            	1713, 80,
            	1713, 88,
            	1716, 96,
            	1719, 104,
            	1722, 112,
            	1725, 120,
            	1728, 128,
            	1731, 136,
            	1734, 144,
            	1737, 152,
            	1740, 160,
            	1743, 168,
            	1746, 176,
            	1749, 184,
            	1752, 192,
            	1755, 200,
            	1758, 208,
            	1749, 216,
            	1761, 224,
            	1764, 232,
            	1767, 240,
            	1704, 248,
            	1770, 256,
            	1773, 264,
            	1770, 272,
            	1773, 280,
            	1773, 288,
            	1776, 296,
            8884097, 8, 0, /* 1689: pointer.func */
            8884097, 8, 0, /* 1692: pointer.func */
            8884097, 8, 0, /* 1695: pointer.func */
            8884097, 8, 0, /* 1698: pointer.func */
            8884097, 8, 0, /* 1701: pointer.func */
            8884097, 8, 0, /* 1704: pointer.func */
            8884097, 8, 0, /* 1707: pointer.func */
            8884097, 8, 0, /* 1710: pointer.func */
            8884097, 8, 0, /* 1713: pointer.func */
            8884097, 8, 0, /* 1716: pointer.func */
            8884097, 8, 0, /* 1719: pointer.func */
            8884097, 8, 0, /* 1722: pointer.func */
            8884097, 8, 0, /* 1725: pointer.func */
            8884097, 8, 0, /* 1728: pointer.func */
            8884097, 8, 0, /* 1731: pointer.func */
            8884097, 8, 0, /* 1734: pointer.func */
            8884097, 8, 0, /* 1737: pointer.func */
            8884097, 8, 0, /* 1740: pointer.func */
            8884097, 8, 0, /* 1743: pointer.func */
            8884097, 8, 0, /* 1746: pointer.func */
            8884097, 8, 0, /* 1749: pointer.func */
            8884097, 8, 0, /* 1752: pointer.func */
            8884097, 8, 0, /* 1755: pointer.func */
            8884097, 8, 0, /* 1758: pointer.func */
            8884097, 8, 0, /* 1761: pointer.func */
            8884097, 8, 0, /* 1764: pointer.func */
            8884097, 8, 0, /* 1767: pointer.func */
            8884097, 8, 0, /* 1770: pointer.func */
            8884097, 8, 0, /* 1773: pointer.func */
            8884097, 8, 0, /* 1776: pointer.func */
            0, 24, 1, /* 1779: struct.bignum_st */
            	1784, 0,
            8884099, 8, 2, /* 1784: pointer_to_array_of_pointers_to_stack */
            	30, 0,
            	33, 12,
            0, 24, 1, /* 1791: struct.bignum_st */
            	1796, 0,
            8884099, 8, 2, /* 1796: pointer_to_array_of_pointers_to_stack */
            	30, 0,
            	33, 12,
            1, 8, 1, /* 1803: pointer.struct.ec_extra_data_st */
            	1808, 0,
            0, 40, 5, /* 1808: struct.ec_extra_data_st */
            	1821, 0,
            	760, 8,
            	1826, 16,
            	1829, 24,
            	1829, 32,
            1, 8, 1, /* 1821: pointer.struct.ec_extra_data_st */
            	1808, 0,
            8884097, 8, 0, /* 1826: pointer.func */
            8884097, 8, 0, /* 1829: pointer.func */
            8884097, 8, 0, /* 1832: pointer.func */
            1, 8, 1, /* 1835: pointer.struct.ec_point_st */
            	1596, 0,
            1, 8, 1, /* 1840: pointer.struct.bignum_st */
            	1845, 0,
            0, 24, 1, /* 1845: struct.bignum_st */
            	1850, 0,
            8884099, 8, 2, /* 1850: pointer_to_array_of_pointers_to_stack */
            	30, 0,
            	33, 12,
            1, 8, 1, /* 1857: pointer.struct.ec_extra_data_st */
            	1862, 0,
            0, 40, 5, /* 1862: struct.ec_extra_data_st */
            	1875, 0,
            	760, 8,
            	1826, 16,
            	1829, 24,
            	1829, 32,
            1, 8, 1, /* 1875: pointer.struct.ec_extra_data_st */
            	1862, 0,
            0, 56, 4, /* 1880: struct.evp_pkey_st */
            	1891, 16,
            	1992, 24,
            	1358, 32,
            	825, 48,
            1, 8, 1, /* 1891: pointer.struct.evp_pkey_asn1_method_st */
            	1896, 0,
            0, 208, 24, /* 1896: struct.evp_pkey_asn1_method_st */
            	169, 16,
            	169, 24,
            	1947, 32,
            	1950, 40,
            	1953, 48,
            	1956, 56,
            	1959, 64,
            	1962, 72,
            	1956, 80,
            	1965, 88,
            	1965, 96,
            	1968, 104,
            	1971, 112,
            	1965, 120,
            	1974, 128,
            	1953, 136,
            	1956, 144,
            	1977, 152,
            	1980, 160,
            	1983, 168,
            	1968, 176,
            	1971, 184,
            	1986, 192,
            	1989, 200,
            8884097, 8, 0, /* 1947: pointer.func */
            8884097, 8, 0, /* 1950: pointer.func */
            8884097, 8, 0, /* 1953: pointer.func */
            8884097, 8, 0, /* 1956: pointer.func */
            8884097, 8, 0, /* 1959: pointer.func */
            8884097, 8, 0, /* 1962: pointer.func */
            8884097, 8, 0, /* 1965: pointer.func */
            8884097, 8, 0, /* 1968: pointer.func */
            8884097, 8, 0, /* 1971: pointer.func */
            8884097, 8, 0, /* 1974: pointer.func */
            8884097, 8, 0, /* 1977: pointer.func */
            8884097, 8, 0, /* 1980: pointer.func */
            8884097, 8, 0, /* 1983: pointer.func */
            8884097, 8, 0, /* 1986: pointer.func */
            8884097, 8, 0, /* 1989: pointer.func */
            1, 8, 1, /* 1992: pointer.struct.engine_st */
            	218, 0,
            1, 8, 1, /* 1997: pointer.struct.stack_st_X509_ALGOR */
            	2002, 0,
            0, 32, 2, /* 2002: struct.stack_st_fake_X509_ALGOR */
            	2009, 8,
            	174, 24,
            8884099, 8, 2, /* 2009: pointer_to_array_of_pointers_to_stack */
            	2016, 0,
            	33, 20,
            0, 8, 1, /* 2016: pointer.X509_ALGOR */
            	2021, 0,
            0, 0, 1, /* 2021: X509_ALGOR */
            	2026, 0,
            0, 16, 2, /* 2026: struct.X509_algor_st */
            	2033, 0,
            	2047, 8,
            1, 8, 1, /* 2033: pointer.struct.asn1_object_st */
            	2038, 0,
            0, 40, 3, /* 2038: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	875, 24,
            1, 8, 1, /* 2047: pointer.struct.asn1_type_st */
            	2052, 0,
            0, 16, 1, /* 2052: struct.asn1_type_st */
            	2057, 8,
            0, 8, 20, /* 2057: union.unknown */
            	169, 0,
            	2100, 0,
            	2033, 0,
            	2110, 0,
            	2115, 0,
            	2120, 0,
            	2125, 0,
            	2130, 0,
            	2135, 0,
            	2140, 0,
            	2145, 0,
            	2150, 0,
            	2155, 0,
            	2160, 0,
            	2165, 0,
            	2170, 0,
            	2175, 0,
            	2100, 0,
            	2100, 0,
            	1201, 0,
            1, 8, 1, /* 2100: pointer.struct.asn1_string_st */
            	2105, 0,
            0, 24, 1, /* 2105: struct.asn1_string_st */
            	134, 8,
            1, 8, 1, /* 2110: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2115: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2120: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2125: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2130: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2135: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2140: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2145: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2150: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2155: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2160: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2165: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2170: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2175: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2180: pointer.struct.asn1_string_st */
            	2185, 0,
            0, 24, 1, /* 2185: struct.asn1_string_st */
            	134, 8,
            0, 32, 1, /* 2190: struct.stack_st_void */
            	2195, 0,
            0, 32, 2, /* 2195: struct.stack_st */
            	164, 8,
            	174, 24,
            0, 24, 1, /* 2202: struct.ASN1_ENCODING_st */
            	134, 0,
            1, 8, 1, /* 2207: pointer.struct.stack_st_X509_EXTENSION */
            	2212, 0,
            0, 32, 2, /* 2212: struct.stack_st_fake_X509_EXTENSION */
            	2219, 8,
            	174, 24,
            8884099, 8, 2, /* 2219: pointer_to_array_of_pointers_to_stack */
            	2226, 0,
            	33, 20,
            0, 8, 1, /* 2226: pointer.X509_EXTENSION */
            	2231, 0,
            0, 0, 1, /* 2231: X509_EXTENSION */
            	2236, 0,
            0, 24, 2, /* 2236: struct.X509_extension_st */
            	2243, 0,
            	2257, 16,
            1, 8, 1, /* 2243: pointer.struct.asn1_object_st */
            	2248, 0,
            0, 40, 3, /* 2248: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	875, 24,
            1, 8, 1, /* 2257: pointer.struct.asn1_string_st */
            	2262, 0,
            0, 24, 1, /* 2262: struct.asn1_string_st */
            	134, 8,
            1, 8, 1, /* 2267: pointer.struct.X509_pubkey_st */
            	2272, 0,
            0, 24, 3, /* 2272: struct.X509_pubkey_st */
            	2281, 0,
            	2286, 8,
            	2296, 16,
            1, 8, 1, /* 2281: pointer.struct.X509_algor_st */
            	2026, 0,
            1, 8, 1, /* 2286: pointer.struct.asn1_string_st */
            	2291, 0,
            0, 24, 1, /* 2291: struct.asn1_string_st */
            	134, 8,
            1, 8, 1, /* 2296: pointer.struct.evp_pkey_st */
            	2301, 0,
            0, 56, 4, /* 2301: struct.evp_pkey_st */
            	2312, 16,
            	2317, 24,
            	2322, 32,
            	2355, 48,
            1, 8, 1, /* 2312: pointer.struct.evp_pkey_asn1_method_st */
            	1896, 0,
            1, 8, 1, /* 2317: pointer.struct.engine_st */
            	218, 0,
            0, 8, 5, /* 2322: union.unknown */
            	169, 0,
            	2335, 0,
            	2340, 0,
            	2345, 0,
            	2350, 0,
            1, 8, 1, /* 2335: pointer.struct.rsa_st */
            	566, 0,
            1, 8, 1, /* 2340: pointer.struct.dsa_st */
            	1219, 0,
            1, 8, 1, /* 2345: pointer.struct.dh_st */
            	76, 0,
            1, 8, 1, /* 2350: pointer.struct.ec_key_st */
            	1376, 0,
            1, 8, 1, /* 2355: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2360, 0,
            0, 32, 2, /* 2360: struct.stack_st_fake_X509_ATTRIBUTE */
            	2367, 8,
            	174, 24,
            8884099, 8, 2, /* 2367: pointer_to_array_of_pointers_to_stack */
            	2374, 0,
            	33, 20,
            0, 8, 1, /* 2374: pointer.X509_ATTRIBUTE */
            	849, 0,
            1, 8, 1, /* 2379: pointer.struct.buf_mem_st */
            	2384, 0,
            0, 24, 1, /* 2384: struct.buf_mem_st */
            	169, 8,
            1, 8, 1, /* 2389: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2394, 0,
            0, 32, 2, /* 2394: struct.stack_st_fake_X509_NAME_ENTRY */
            	2401, 8,
            	174, 24,
            8884099, 8, 2, /* 2401: pointer_to_array_of_pointers_to_stack */
            	2408, 0,
            	33, 20,
            0, 8, 1, /* 2408: pointer.X509_NAME_ENTRY */
            	2413, 0,
            0, 0, 1, /* 2413: X509_NAME_ENTRY */
            	2418, 0,
            0, 24, 2, /* 2418: struct.X509_name_entry_st */
            	2425, 0,
            	2439, 8,
            1, 8, 1, /* 2425: pointer.struct.asn1_object_st */
            	2430, 0,
            0, 40, 3, /* 2430: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	875, 24,
            1, 8, 1, /* 2439: pointer.struct.asn1_string_st */
            	2444, 0,
            0, 24, 1, /* 2444: struct.asn1_string_st */
            	134, 8,
            1, 8, 1, /* 2449: pointer.struct.asn1_string_st */
            	2185, 0,
            0, 104, 11, /* 2454: struct.x509_cinf_st */
            	2449, 0,
            	2449, 8,
            	2479, 16,
            	2484, 24,
            	2498, 32,
            	2484, 40,
            	2267, 48,
            	2515, 56,
            	2515, 64,
            	2207, 72,
            	2202, 80,
            1, 8, 1, /* 2479: pointer.struct.X509_algor_st */
            	2026, 0,
            1, 8, 1, /* 2484: pointer.struct.X509_name_st */
            	2489, 0,
            0, 40, 3, /* 2489: struct.X509_name_st */
            	2389, 0,
            	2379, 16,
            	134, 24,
            1, 8, 1, /* 2498: pointer.struct.X509_val_st */
            	2503, 0,
            0, 16, 2, /* 2503: struct.X509_val_st */
            	2510, 0,
            	2510, 8,
            1, 8, 1, /* 2510: pointer.struct.asn1_string_st */
            	2185, 0,
            1, 8, 1, /* 2515: pointer.struct.asn1_string_st */
            	2185, 0,
            0, 296, 7, /* 2520: struct.cert_st */
            	2537, 0,
            	561, 48,
            	3879, 56,
            	71, 64,
            	68, 72,
            	3882, 80,
            	3887, 88,
            1, 8, 1, /* 2537: pointer.struct.cert_pkey_st */
            	2542, 0,
            0, 24, 3, /* 2542: struct.cert_pkey_st */
            	2551, 0,
            	3874, 8,
            	786, 16,
            1, 8, 1, /* 2551: pointer.struct.x509_st */
            	2556, 0,
            0, 184, 12, /* 2556: struct.x509_st */
            	2583, 0,
            	2479, 8,
            	2515, 16,
            	169, 32,
            	2588, 40,
            	2598, 104,
            	2603, 112,
            	2926, 120,
            	3357, 128,
            	3496, 136,
            	3520, 144,
            	3832, 176,
            1, 8, 1, /* 2583: pointer.struct.x509_cinf_st */
            	2454, 0,
            0, 16, 1, /* 2588: struct.crypto_ex_data_st */
            	2593, 0,
            1, 8, 1, /* 2593: pointer.struct.stack_st_void */
            	2190, 0,
            1, 8, 1, /* 2598: pointer.struct.asn1_string_st */
            	2185, 0,
            1, 8, 1, /* 2603: pointer.struct.AUTHORITY_KEYID_st */
            	2608, 0,
            0, 24, 3, /* 2608: struct.AUTHORITY_KEYID_st */
            	2617, 0,
            	2627, 8,
            	2921, 16,
            1, 8, 1, /* 2617: pointer.struct.asn1_string_st */
            	2622, 0,
            0, 24, 1, /* 2622: struct.asn1_string_st */
            	134, 8,
            1, 8, 1, /* 2627: pointer.struct.stack_st_GENERAL_NAME */
            	2632, 0,
            0, 32, 2, /* 2632: struct.stack_st_fake_GENERAL_NAME */
            	2639, 8,
            	174, 24,
            8884099, 8, 2, /* 2639: pointer_to_array_of_pointers_to_stack */
            	2646, 0,
            	33, 20,
            0, 8, 1, /* 2646: pointer.GENERAL_NAME */
            	2651, 0,
            0, 0, 1, /* 2651: GENERAL_NAME */
            	2656, 0,
            0, 16, 1, /* 2656: struct.GENERAL_NAME_st */
            	2661, 8,
            0, 8, 15, /* 2661: union.unknown */
            	169, 0,
            	2694, 0,
            	2813, 0,
            	2813, 0,
            	2720, 0,
            	2861, 0,
            	2909, 0,
            	2813, 0,
            	2798, 0,
            	2706, 0,
            	2798, 0,
            	2861, 0,
            	2813, 0,
            	2706, 0,
            	2720, 0,
            1, 8, 1, /* 2694: pointer.struct.otherName_st */
            	2699, 0,
            0, 16, 2, /* 2699: struct.otherName_st */
            	2706, 0,
            	2720, 8,
            1, 8, 1, /* 2706: pointer.struct.asn1_object_st */
            	2711, 0,
            0, 40, 3, /* 2711: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	875, 24,
            1, 8, 1, /* 2720: pointer.struct.asn1_type_st */
            	2725, 0,
            0, 16, 1, /* 2725: struct.asn1_type_st */
            	2730, 8,
            0, 8, 20, /* 2730: union.unknown */
            	169, 0,
            	2773, 0,
            	2706, 0,
            	2783, 0,
            	2788, 0,
            	2793, 0,
            	2798, 0,
            	2803, 0,
            	2808, 0,
            	2813, 0,
            	2818, 0,
            	2823, 0,
            	2828, 0,
            	2833, 0,
            	2838, 0,
            	2843, 0,
            	2848, 0,
            	2773, 0,
            	2773, 0,
            	2853, 0,
            1, 8, 1, /* 2773: pointer.struct.asn1_string_st */
            	2778, 0,
            0, 24, 1, /* 2778: struct.asn1_string_st */
            	134, 8,
            1, 8, 1, /* 2783: pointer.struct.asn1_string_st */
            	2778, 0,
            1, 8, 1, /* 2788: pointer.struct.asn1_string_st */
            	2778, 0,
            1, 8, 1, /* 2793: pointer.struct.asn1_string_st */
            	2778, 0,
            1, 8, 1, /* 2798: pointer.struct.asn1_string_st */
            	2778, 0,
            1, 8, 1, /* 2803: pointer.struct.asn1_string_st */
            	2778, 0,
            1, 8, 1, /* 2808: pointer.struct.asn1_string_st */
            	2778, 0,
            1, 8, 1, /* 2813: pointer.struct.asn1_string_st */
            	2778, 0,
            1, 8, 1, /* 2818: pointer.struct.asn1_string_st */
            	2778, 0,
            1, 8, 1, /* 2823: pointer.struct.asn1_string_st */
            	2778, 0,
            1, 8, 1, /* 2828: pointer.struct.asn1_string_st */
            	2778, 0,
            1, 8, 1, /* 2833: pointer.struct.asn1_string_st */
            	2778, 0,
            1, 8, 1, /* 2838: pointer.struct.asn1_string_st */
            	2778, 0,
            1, 8, 1, /* 2843: pointer.struct.asn1_string_st */
            	2778, 0,
            1, 8, 1, /* 2848: pointer.struct.asn1_string_st */
            	2778, 0,
            1, 8, 1, /* 2853: pointer.struct.ASN1_VALUE_st */
            	2858, 0,
            0, 0, 0, /* 2858: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2861: pointer.struct.X509_name_st */
            	2866, 0,
            0, 40, 3, /* 2866: struct.X509_name_st */
            	2875, 0,
            	2899, 16,
            	134, 24,
            1, 8, 1, /* 2875: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2880, 0,
            0, 32, 2, /* 2880: struct.stack_st_fake_X509_NAME_ENTRY */
            	2887, 8,
            	174, 24,
            8884099, 8, 2, /* 2887: pointer_to_array_of_pointers_to_stack */
            	2894, 0,
            	33, 20,
            0, 8, 1, /* 2894: pointer.X509_NAME_ENTRY */
            	2413, 0,
            1, 8, 1, /* 2899: pointer.struct.buf_mem_st */
            	2904, 0,
            0, 24, 1, /* 2904: struct.buf_mem_st */
            	169, 8,
            1, 8, 1, /* 2909: pointer.struct.EDIPartyName_st */
            	2914, 0,
            0, 16, 2, /* 2914: struct.EDIPartyName_st */
            	2773, 0,
            	2773, 8,
            1, 8, 1, /* 2921: pointer.struct.asn1_string_st */
            	2622, 0,
            1, 8, 1, /* 2926: pointer.struct.X509_POLICY_CACHE_st */
            	2931, 0,
            0, 40, 2, /* 2931: struct.X509_POLICY_CACHE_st */
            	2938, 0,
            	3257, 8,
            1, 8, 1, /* 2938: pointer.struct.X509_POLICY_DATA_st */
            	2943, 0,
            0, 32, 3, /* 2943: struct.X509_POLICY_DATA_st */
            	2952, 8,
            	2966, 16,
            	3219, 24,
            1, 8, 1, /* 2952: pointer.struct.asn1_object_st */
            	2957, 0,
            0, 40, 3, /* 2957: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	875, 24,
            1, 8, 1, /* 2966: pointer.struct.stack_st_POLICYQUALINFO */
            	2971, 0,
            0, 32, 2, /* 2971: struct.stack_st_fake_POLICYQUALINFO */
            	2978, 8,
            	174, 24,
            8884099, 8, 2, /* 2978: pointer_to_array_of_pointers_to_stack */
            	2985, 0,
            	33, 20,
            0, 8, 1, /* 2985: pointer.POLICYQUALINFO */
            	2990, 0,
            0, 0, 1, /* 2990: POLICYQUALINFO */
            	2995, 0,
            0, 16, 2, /* 2995: struct.POLICYQUALINFO_st */
            	3002, 0,
            	3016, 8,
            1, 8, 1, /* 3002: pointer.struct.asn1_object_st */
            	3007, 0,
            0, 40, 3, /* 3007: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	875, 24,
            0, 8, 3, /* 3016: union.unknown */
            	3025, 0,
            	3035, 0,
            	3093, 0,
            1, 8, 1, /* 3025: pointer.struct.asn1_string_st */
            	3030, 0,
            0, 24, 1, /* 3030: struct.asn1_string_st */
            	134, 8,
            1, 8, 1, /* 3035: pointer.struct.USERNOTICE_st */
            	3040, 0,
            0, 16, 2, /* 3040: struct.USERNOTICE_st */
            	3047, 0,
            	3059, 8,
            1, 8, 1, /* 3047: pointer.struct.NOTICEREF_st */
            	3052, 0,
            0, 16, 2, /* 3052: struct.NOTICEREF_st */
            	3059, 0,
            	3064, 8,
            1, 8, 1, /* 3059: pointer.struct.asn1_string_st */
            	3030, 0,
            1, 8, 1, /* 3064: pointer.struct.stack_st_ASN1_INTEGER */
            	3069, 0,
            0, 32, 2, /* 3069: struct.stack_st_fake_ASN1_INTEGER */
            	3076, 8,
            	174, 24,
            8884099, 8, 2, /* 3076: pointer_to_array_of_pointers_to_stack */
            	3083, 0,
            	33, 20,
            0, 8, 1, /* 3083: pointer.ASN1_INTEGER */
            	3088, 0,
            0, 0, 1, /* 3088: ASN1_INTEGER */
            	2105, 0,
            1, 8, 1, /* 3093: pointer.struct.asn1_type_st */
            	3098, 0,
            0, 16, 1, /* 3098: struct.asn1_type_st */
            	3103, 8,
            0, 8, 20, /* 3103: union.unknown */
            	169, 0,
            	3059, 0,
            	3002, 0,
            	3146, 0,
            	3151, 0,
            	3156, 0,
            	3161, 0,
            	3166, 0,
            	3171, 0,
            	3025, 0,
            	3176, 0,
            	3181, 0,
            	3186, 0,
            	3191, 0,
            	3196, 0,
            	3201, 0,
            	3206, 0,
            	3059, 0,
            	3059, 0,
            	3211, 0,
            1, 8, 1, /* 3146: pointer.struct.asn1_string_st */
            	3030, 0,
            1, 8, 1, /* 3151: pointer.struct.asn1_string_st */
            	3030, 0,
            1, 8, 1, /* 3156: pointer.struct.asn1_string_st */
            	3030, 0,
            1, 8, 1, /* 3161: pointer.struct.asn1_string_st */
            	3030, 0,
            1, 8, 1, /* 3166: pointer.struct.asn1_string_st */
            	3030, 0,
            1, 8, 1, /* 3171: pointer.struct.asn1_string_st */
            	3030, 0,
            1, 8, 1, /* 3176: pointer.struct.asn1_string_st */
            	3030, 0,
            1, 8, 1, /* 3181: pointer.struct.asn1_string_st */
            	3030, 0,
            1, 8, 1, /* 3186: pointer.struct.asn1_string_st */
            	3030, 0,
            1, 8, 1, /* 3191: pointer.struct.asn1_string_st */
            	3030, 0,
            1, 8, 1, /* 3196: pointer.struct.asn1_string_st */
            	3030, 0,
            1, 8, 1, /* 3201: pointer.struct.asn1_string_st */
            	3030, 0,
            1, 8, 1, /* 3206: pointer.struct.asn1_string_st */
            	3030, 0,
            1, 8, 1, /* 3211: pointer.struct.ASN1_VALUE_st */
            	3216, 0,
            0, 0, 0, /* 3216: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3219: pointer.struct.stack_st_ASN1_OBJECT */
            	3224, 0,
            0, 32, 2, /* 3224: struct.stack_st_fake_ASN1_OBJECT */
            	3231, 8,
            	174, 24,
            8884099, 8, 2, /* 3231: pointer_to_array_of_pointers_to_stack */
            	3238, 0,
            	33, 20,
            0, 8, 1, /* 3238: pointer.ASN1_OBJECT */
            	3243, 0,
            0, 0, 1, /* 3243: ASN1_OBJECT */
            	3248, 0,
            0, 40, 3, /* 3248: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	875, 24,
            1, 8, 1, /* 3257: pointer.struct.stack_st_X509_POLICY_DATA */
            	3262, 0,
            0, 32, 2, /* 3262: struct.stack_st_fake_X509_POLICY_DATA */
            	3269, 8,
            	174, 24,
            8884099, 8, 2, /* 3269: pointer_to_array_of_pointers_to_stack */
            	3276, 0,
            	33, 20,
            0, 8, 1, /* 3276: pointer.X509_POLICY_DATA */
            	3281, 0,
            0, 0, 1, /* 3281: X509_POLICY_DATA */
            	3286, 0,
            0, 32, 3, /* 3286: struct.X509_POLICY_DATA_st */
            	3295, 8,
            	3309, 16,
            	3333, 24,
            1, 8, 1, /* 3295: pointer.struct.asn1_object_st */
            	3300, 0,
            0, 40, 3, /* 3300: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	875, 24,
            1, 8, 1, /* 3309: pointer.struct.stack_st_POLICYQUALINFO */
            	3314, 0,
            0, 32, 2, /* 3314: struct.stack_st_fake_POLICYQUALINFO */
            	3321, 8,
            	174, 24,
            8884099, 8, 2, /* 3321: pointer_to_array_of_pointers_to_stack */
            	3328, 0,
            	33, 20,
            0, 8, 1, /* 3328: pointer.POLICYQUALINFO */
            	2990, 0,
            1, 8, 1, /* 3333: pointer.struct.stack_st_ASN1_OBJECT */
            	3338, 0,
            0, 32, 2, /* 3338: struct.stack_st_fake_ASN1_OBJECT */
            	3345, 8,
            	174, 24,
            8884099, 8, 2, /* 3345: pointer_to_array_of_pointers_to_stack */
            	3352, 0,
            	33, 20,
            0, 8, 1, /* 3352: pointer.ASN1_OBJECT */
            	3243, 0,
            1, 8, 1, /* 3357: pointer.struct.stack_st_DIST_POINT */
            	3362, 0,
            0, 32, 2, /* 3362: struct.stack_st_fake_DIST_POINT */
            	3369, 8,
            	174, 24,
            8884099, 8, 2, /* 3369: pointer_to_array_of_pointers_to_stack */
            	3376, 0,
            	33, 20,
            0, 8, 1, /* 3376: pointer.DIST_POINT */
            	3381, 0,
            0, 0, 1, /* 3381: DIST_POINT */
            	3386, 0,
            0, 32, 3, /* 3386: struct.DIST_POINT_st */
            	3395, 0,
            	3486, 8,
            	3414, 16,
            1, 8, 1, /* 3395: pointer.struct.DIST_POINT_NAME_st */
            	3400, 0,
            0, 24, 2, /* 3400: struct.DIST_POINT_NAME_st */
            	3407, 8,
            	3462, 16,
            0, 8, 2, /* 3407: union.unknown */
            	3414, 0,
            	3438, 0,
            1, 8, 1, /* 3414: pointer.struct.stack_st_GENERAL_NAME */
            	3419, 0,
            0, 32, 2, /* 3419: struct.stack_st_fake_GENERAL_NAME */
            	3426, 8,
            	174, 24,
            8884099, 8, 2, /* 3426: pointer_to_array_of_pointers_to_stack */
            	3433, 0,
            	33, 20,
            0, 8, 1, /* 3433: pointer.GENERAL_NAME */
            	2651, 0,
            1, 8, 1, /* 3438: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3443, 0,
            0, 32, 2, /* 3443: struct.stack_st_fake_X509_NAME_ENTRY */
            	3450, 8,
            	174, 24,
            8884099, 8, 2, /* 3450: pointer_to_array_of_pointers_to_stack */
            	3457, 0,
            	33, 20,
            0, 8, 1, /* 3457: pointer.X509_NAME_ENTRY */
            	2413, 0,
            1, 8, 1, /* 3462: pointer.struct.X509_name_st */
            	3467, 0,
            0, 40, 3, /* 3467: struct.X509_name_st */
            	3438, 0,
            	3476, 16,
            	134, 24,
            1, 8, 1, /* 3476: pointer.struct.buf_mem_st */
            	3481, 0,
            0, 24, 1, /* 3481: struct.buf_mem_st */
            	169, 8,
            1, 8, 1, /* 3486: pointer.struct.asn1_string_st */
            	3491, 0,
            0, 24, 1, /* 3491: struct.asn1_string_st */
            	134, 8,
            1, 8, 1, /* 3496: pointer.struct.stack_st_GENERAL_NAME */
            	3501, 0,
            0, 32, 2, /* 3501: struct.stack_st_fake_GENERAL_NAME */
            	3508, 8,
            	174, 24,
            8884099, 8, 2, /* 3508: pointer_to_array_of_pointers_to_stack */
            	3515, 0,
            	33, 20,
            0, 8, 1, /* 3515: pointer.GENERAL_NAME */
            	2651, 0,
            1, 8, 1, /* 3520: pointer.struct.NAME_CONSTRAINTS_st */
            	3525, 0,
            0, 16, 2, /* 3525: struct.NAME_CONSTRAINTS_st */
            	3532, 0,
            	3532, 8,
            1, 8, 1, /* 3532: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3537, 0,
            0, 32, 2, /* 3537: struct.stack_st_fake_GENERAL_SUBTREE */
            	3544, 8,
            	174, 24,
            8884099, 8, 2, /* 3544: pointer_to_array_of_pointers_to_stack */
            	3551, 0,
            	33, 20,
            0, 8, 1, /* 3551: pointer.GENERAL_SUBTREE */
            	3556, 0,
            0, 0, 1, /* 3556: GENERAL_SUBTREE */
            	3561, 0,
            0, 24, 3, /* 3561: struct.GENERAL_SUBTREE_st */
            	3570, 0,
            	3702, 8,
            	3702, 16,
            1, 8, 1, /* 3570: pointer.struct.GENERAL_NAME_st */
            	3575, 0,
            0, 16, 1, /* 3575: struct.GENERAL_NAME_st */
            	3580, 8,
            0, 8, 15, /* 3580: union.unknown */
            	169, 0,
            	3613, 0,
            	3732, 0,
            	3732, 0,
            	3639, 0,
            	3772, 0,
            	3820, 0,
            	3732, 0,
            	3717, 0,
            	3625, 0,
            	3717, 0,
            	3772, 0,
            	3732, 0,
            	3625, 0,
            	3639, 0,
            1, 8, 1, /* 3613: pointer.struct.otherName_st */
            	3618, 0,
            0, 16, 2, /* 3618: struct.otherName_st */
            	3625, 0,
            	3639, 8,
            1, 8, 1, /* 3625: pointer.struct.asn1_object_st */
            	3630, 0,
            0, 40, 3, /* 3630: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	875, 24,
            1, 8, 1, /* 3639: pointer.struct.asn1_type_st */
            	3644, 0,
            0, 16, 1, /* 3644: struct.asn1_type_st */
            	3649, 8,
            0, 8, 20, /* 3649: union.unknown */
            	169, 0,
            	3692, 0,
            	3625, 0,
            	3702, 0,
            	3707, 0,
            	3712, 0,
            	3717, 0,
            	3722, 0,
            	3727, 0,
            	3732, 0,
            	3737, 0,
            	3742, 0,
            	3747, 0,
            	3752, 0,
            	3757, 0,
            	3762, 0,
            	3767, 0,
            	3692, 0,
            	3692, 0,
            	3211, 0,
            1, 8, 1, /* 3692: pointer.struct.asn1_string_st */
            	3697, 0,
            0, 24, 1, /* 3697: struct.asn1_string_st */
            	134, 8,
            1, 8, 1, /* 3702: pointer.struct.asn1_string_st */
            	3697, 0,
            1, 8, 1, /* 3707: pointer.struct.asn1_string_st */
            	3697, 0,
            1, 8, 1, /* 3712: pointer.struct.asn1_string_st */
            	3697, 0,
            1, 8, 1, /* 3717: pointer.struct.asn1_string_st */
            	3697, 0,
            1, 8, 1, /* 3722: pointer.struct.asn1_string_st */
            	3697, 0,
            1, 8, 1, /* 3727: pointer.struct.asn1_string_st */
            	3697, 0,
            1, 8, 1, /* 3732: pointer.struct.asn1_string_st */
            	3697, 0,
            1, 8, 1, /* 3737: pointer.struct.asn1_string_st */
            	3697, 0,
            1, 8, 1, /* 3742: pointer.struct.asn1_string_st */
            	3697, 0,
            1, 8, 1, /* 3747: pointer.struct.asn1_string_st */
            	3697, 0,
            1, 8, 1, /* 3752: pointer.struct.asn1_string_st */
            	3697, 0,
            1, 8, 1, /* 3757: pointer.struct.asn1_string_st */
            	3697, 0,
            1, 8, 1, /* 3762: pointer.struct.asn1_string_st */
            	3697, 0,
            1, 8, 1, /* 3767: pointer.struct.asn1_string_st */
            	3697, 0,
            1, 8, 1, /* 3772: pointer.struct.X509_name_st */
            	3777, 0,
            0, 40, 3, /* 3777: struct.X509_name_st */
            	3786, 0,
            	3810, 16,
            	134, 24,
            1, 8, 1, /* 3786: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3791, 0,
            0, 32, 2, /* 3791: struct.stack_st_fake_X509_NAME_ENTRY */
            	3798, 8,
            	174, 24,
            8884099, 8, 2, /* 3798: pointer_to_array_of_pointers_to_stack */
            	3805, 0,
            	33, 20,
            0, 8, 1, /* 3805: pointer.X509_NAME_ENTRY */
            	2413, 0,
            1, 8, 1, /* 3810: pointer.struct.buf_mem_st */
            	3815, 0,
            0, 24, 1, /* 3815: struct.buf_mem_st */
            	169, 8,
            1, 8, 1, /* 3820: pointer.struct.EDIPartyName_st */
            	3825, 0,
            0, 16, 2, /* 3825: struct.EDIPartyName_st */
            	3692, 0,
            	3692, 8,
            1, 8, 1, /* 3832: pointer.struct.x509_cert_aux_st */
            	3837, 0,
            0, 40, 5, /* 3837: struct.x509_cert_aux_st */
            	3850, 0,
            	3850, 8,
            	2180, 16,
            	2598, 24,
            	1997, 32,
            1, 8, 1, /* 3850: pointer.struct.stack_st_ASN1_OBJECT */
            	3855, 0,
            0, 32, 2, /* 3855: struct.stack_st_fake_ASN1_OBJECT */
            	3862, 8,
            	174, 24,
            8884099, 8, 2, /* 3862: pointer_to_array_of_pointers_to_stack */
            	3869, 0,
            	33, 20,
            0, 8, 1, /* 3869: pointer.ASN1_OBJECT */
            	3243, 0,
            1, 8, 1, /* 3874: pointer.struct.evp_pkey_st */
            	1880, 0,
            8884097, 8, 0, /* 3879: pointer.func */
            1, 8, 1, /* 3882: pointer.struct.ec_key_st */
            	1376, 0,
            8884097, 8, 0, /* 3887: pointer.func */
            0, 24, 1, /* 3890: struct.buf_mem_st */
            	169, 8,
            1, 8, 1, /* 3895: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3900, 0,
            0, 32, 2, /* 3900: struct.stack_st_fake_X509_NAME_ENTRY */
            	3907, 8,
            	174, 24,
            8884099, 8, 2, /* 3907: pointer_to_array_of_pointers_to_stack */
            	3914, 0,
            	33, 20,
            0, 8, 1, /* 3914: pointer.X509_NAME_ENTRY */
            	2413, 0,
            0, 0, 1, /* 3919: X509_NAME */
            	3924, 0,
            0, 40, 3, /* 3924: struct.X509_name_st */
            	3895, 0,
            	3933, 16,
            	134, 24,
            1, 8, 1, /* 3933: pointer.struct.buf_mem_st */
            	3890, 0,
            1, 8, 1, /* 3938: pointer.struct.stack_st_X509_NAME */
            	3943, 0,
            0, 32, 2, /* 3943: struct.stack_st_fake_X509_NAME */
            	3950, 8,
            	174, 24,
            8884099, 8, 2, /* 3950: pointer_to_array_of_pointers_to_stack */
            	3957, 0,
            	33, 20,
            0, 8, 1, /* 3957: pointer.X509_NAME */
            	3919, 0,
            8884097, 8, 0, /* 3962: pointer.func */
            8884097, 8, 0, /* 3965: pointer.func */
            8884097, 8, 0, /* 3968: pointer.func */
            8884097, 8, 0, /* 3971: pointer.func */
            0, 64, 7, /* 3974: struct.comp_method_st */
            	10, 8,
            	3971, 16,
            	3968, 24,
            	3965, 32,
            	3965, 40,
            	3991, 48,
            	3991, 56,
            8884097, 8, 0, /* 3991: pointer.func */
            1, 8, 1, /* 3994: pointer.struct.comp_method_st */
            	3974, 0,
            0, 0, 1, /* 3999: SSL_COMP */
            	4004, 0,
            0, 24, 2, /* 4004: struct.ssl_comp_st */
            	10, 8,
            	3994, 16,
            1, 8, 1, /* 4011: pointer.struct.stack_st_SSL_COMP */
            	4016, 0,
            0, 32, 2, /* 4016: struct.stack_st_fake_SSL_COMP */
            	4023, 8,
            	174, 24,
            8884099, 8, 2, /* 4023: pointer_to_array_of_pointers_to_stack */
            	4030, 0,
            	33, 20,
            0, 8, 1, /* 4030: pointer.SSL_COMP */
            	3999, 0,
            8884097, 8, 0, /* 4035: pointer.func */
            8884097, 8, 0, /* 4038: pointer.func */
            8884097, 8, 0, /* 4041: pointer.func */
            0, 120, 8, /* 4044: struct.env_md_st */
            	4041, 24,
            	4038, 32,
            	4063, 40,
            	4035, 48,
            	4041, 56,
            	816, 64,
            	819, 72,
            	4066, 112,
            8884097, 8, 0, /* 4063: pointer.func */
            8884097, 8, 0, /* 4066: pointer.func */
            1, 8, 1, /* 4069: pointer.struct.env_md_st */
            	4044, 0,
            8884097, 8, 0, /* 4074: pointer.func */
            8884097, 8, 0, /* 4077: pointer.func */
            8884097, 8, 0, /* 4080: pointer.func */
            8884097, 8, 0, /* 4083: pointer.func */
            8884097, 8, 0, /* 4086: pointer.func */
            0, 88, 1, /* 4089: struct.ssl_cipher_st */
            	10, 8,
            1, 8, 1, /* 4094: pointer.struct.ssl_cipher_st */
            	4089, 0,
            1, 8, 1, /* 4099: pointer.struct.stack_st_X509_ALGOR */
            	4104, 0,
            0, 32, 2, /* 4104: struct.stack_st_fake_X509_ALGOR */
            	4111, 8,
            	174, 24,
            8884099, 8, 2, /* 4111: pointer_to_array_of_pointers_to_stack */
            	4118, 0,
            	33, 20,
            0, 8, 1, /* 4118: pointer.X509_ALGOR */
            	2021, 0,
            1, 8, 1, /* 4123: pointer.struct.asn1_string_st */
            	4128, 0,
            0, 24, 1, /* 4128: struct.asn1_string_st */
            	134, 8,
            1, 8, 1, /* 4133: pointer.struct.x509_cert_aux_st */
            	4138, 0,
            0, 40, 5, /* 4138: struct.x509_cert_aux_st */
            	4151, 0,
            	4151, 8,
            	4123, 16,
            	4175, 24,
            	4099, 32,
            1, 8, 1, /* 4151: pointer.struct.stack_st_ASN1_OBJECT */
            	4156, 0,
            0, 32, 2, /* 4156: struct.stack_st_fake_ASN1_OBJECT */
            	4163, 8,
            	174, 24,
            8884099, 8, 2, /* 4163: pointer_to_array_of_pointers_to_stack */
            	4170, 0,
            	33, 20,
            0, 8, 1, /* 4170: pointer.ASN1_OBJECT */
            	3243, 0,
            1, 8, 1, /* 4175: pointer.struct.asn1_string_st */
            	4128, 0,
            0, 24, 1, /* 4180: struct.ASN1_ENCODING_st */
            	134, 0,
            1, 8, 1, /* 4185: pointer.struct.stack_st_X509_EXTENSION */
            	4190, 0,
            0, 32, 2, /* 4190: struct.stack_st_fake_X509_EXTENSION */
            	4197, 8,
            	174, 24,
            8884099, 8, 2, /* 4197: pointer_to_array_of_pointers_to_stack */
            	4204, 0,
            	33, 20,
            0, 8, 1, /* 4204: pointer.X509_EXTENSION */
            	2231, 0,
            1, 8, 1, /* 4209: pointer.struct.asn1_string_st */
            	4128, 0,
            1, 8, 1, /* 4214: pointer.struct.X509_pubkey_st */
            	2272, 0,
            0, 16, 2, /* 4219: struct.X509_val_st */
            	4226, 0,
            	4226, 8,
            1, 8, 1, /* 4226: pointer.struct.asn1_string_st */
            	4128, 0,
            1, 8, 1, /* 4231: pointer.struct.X509_val_st */
            	4219, 0,
            0, 24, 1, /* 4236: struct.buf_mem_st */
            	169, 8,
            0, 40, 3, /* 4241: struct.X509_name_st */
            	4250, 0,
            	4274, 16,
            	134, 24,
            1, 8, 1, /* 4250: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4255, 0,
            0, 32, 2, /* 4255: struct.stack_st_fake_X509_NAME_ENTRY */
            	4262, 8,
            	174, 24,
            8884099, 8, 2, /* 4262: pointer_to_array_of_pointers_to_stack */
            	4269, 0,
            	33, 20,
            0, 8, 1, /* 4269: pointer.X509_NAME_ENTRY */
            	2413, 0,
            1, 8, 1, /* 4274: pointer.struct.buf_mem_st */
            	4236, 0,
            1, 8, 1, /* 4279: pointer.struct.X509_name_st */
            	4241, 0,
            1, 8, 1, /* 4284: pointer.struct.X509_algor_st */
            	2026, 0,
            0, 104, 11, /* 4289: struct.x509_cinf_st */
            	4314, 0,
            	4314, 8,
            	4284, 16,
            	4279, 24,
            	4231, 32,
            	4279, 40,
            	4214, 48,
            	4209, 56,
            	4209, 64,
            	4185, 72,
            	4180, 80,
            1, 8, 1, /* 4314: pointer.struct.asn1_string_st */
            	4128, 0,
            1, 8, 1, /* 4319: pointer.struct.x509_cinf_st */
            	4289, 0,
            1, 8, 1, /* 4324: pointer.struct.dh_st */
            	76, 0,
            8884097, 8, 0, /* 4329: pointer.func */
            8884097, 8, 0, /* 4332: pointer.func */
            0, 120, 8, /* 4335: struct.env_md_st */
            	4354, 24,
            	4357, 32,
            	4332, 40,
            	4360, 48,
            	4354, 56,
            	816, 64,
            	819, 72,
            	4329, 112,
            8884097, 8, 0, /* 4354: pointer.func */
            8884097, 8, 0, /* 4357: pointer.func */
            8884097, 8, 0, /* 4360: pointer.func */
            1, 8, 1, /* 4363: pointer.struct.dsa_st */
            	1219, 0,
            1, 8, 1, /* 4368: pointer.struct.rsa_st */
            	566, 0,
            0, 8, 5, /* 4373: union.unknown */
            	169, 0,
            	4368, 0,
            	4363, 0,
            	4386, 0,
            	1371, 0,
            1, 8, 1, /* 4386: pointer.struct.dh_st */
            	76, 0,
            0, 56, 4, /* 4391: struct.evp_pkey_st */
            	1891, 16,
            	1992, 24,
            	4373, 32,
            	4402, 48,
            1, 8, 1, /* 4402: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4407, 0,
            0, 32, 2, /* 4407: struct.stack_st_fake_X509_ATTRIBUTE */
            	4414, 8,
            	174, 24,
            8884099, 8, 2, /* 4414: pointer_to_array_of_pointers_to_stack */
            	4421, 0,
            	33, 20,
            0, 8, 1, /* 4421: pointer.X509_ATTRIBUTE */
            	849, 0,
            1, 8, 1, /* 4426: pointer.struct.asn1_string_st */
            	4431, 0,
            0, 24, 1, /* 4431: struct.asn1_string_st */
            	134, 8,
            0, 40, 5, /* 4436: struct.x509_cert_aux_st */
            	4449, 0,
            	4449, 8,
            	4426, 16,
            	4473, 24,
            	4478, 32,
            1, 8, 1, /* 4449: pointer.struct.stack_st_ASN1_OBJECT */
            	4454, 0,
            0, 32, 2, /* 4454: struct.stack_st_fake_ASN1_OBJECT */
            	4461, 8,
            	174, 24,
            8884099, 8, 2, /* 4461: pointer_to_array_of_pointers_to_stack */
            	4468, 0,
            	33, 20,
            0, 8, 1, /* 4468: pointer.ASN1_OBJECT */
            	3243, 0,
            1, 8, 1, /* 4473: pointer.struct.asn1_string_st */
            	4431, 0,
            1, 8, 1, /* 4478: pointer.struct.stack_st_X509_ALGOR */
            	4483, 0,
            0, 32, 2, /* 4483: struct.stack_st_fake_X509_ALGOR */
            	4490, 8,
            	174, 24,
            8884099, 8, 2, /* 4490: pointer_to_array_of_pointers_to_stack */
            	4497, 0,
            	33, 20,
            0, 8, 1, /* 4497: pointer.X509_ALGOR */
            	2021, 0,
            0, 32, 1, /* 4502: struct.stack_st_void */
            	4507, 0,
            0, 32, 2, /* 4507: struct.stack_st */
            	164, 8,
            	174, 24,
            0, 16, 1, /* 4514: struct.crypto_ex_data_st */
            	4519, 0,
            1, 8, 1, /* 4519: pointer.struct.stack_st_void */
            	4502, 0,
            0, 24, 1, /* 4524: struct.ASN1_ENCODING_st */
            	134, 0,
            1, 8, 1, /* 4529: pointer.struct.stack_st_X509_EXTENSION */
            	4534, 0,
            0, 32, 2, /* 4534: struct.stack_st_fake_X509_EXTENSION */
            	4541, 8,
            	174, 24,
            8884099, 8, 2, /* 4541: pointer_to_array_of_pointers_to_stack */
            	4548, 0,
            	33, 20,
            0, 8, 1, /* 4548: pointer.X509_EXTENSION */
            	2231, 0,
            1, 8, 1, /* 4553: pointer.struct.asn1_string_st */
            	4431, 0,
            1, 8, 1, /* 4558: pointer.struct.X509_pubkey_st */
            	2272, 0,
            0, 16, 2, /* 4563: struct.X509_val_st */
            	4570, 0,
            	4570, 8,
            1, 8, 1, /* 4570: pointer.struct.asn1_string_st */
            	4431, 0,
            0, 24, 1, /* 4575: struct.buf_mem_st */
            	169, 8,
            1, 8, 1, /* 4580: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4585, 0,
            0, 32, 2, /* 4585: struct.stack_st_fake_X509_NAME_ENTRY */
            	4592, 8,
            	174, 24,
            8884099, 8, 2, /* 4592: pointer_to_array_of_pointers_to_stack */
            	4599, 0,
            	33, 20,
            0, 8, 1, /* 4599: pointer.X509_NAME_ENTRY */
            	2413, 0,
            1, 8, 1, /* 4604: pointer.struct.X509_algor_st */
            	2026, 0,
            1, 8, 1, /* 4609: pointer.struct.asn1_string_st */
            	4431, 0,
            1, 8, 1, /* 4614: pointer.struct.x509_cinf_st */
            	4619, 0,
            0, 104, 11, /* 4619: struct.x509_cinf_st */
            	4609, 0,
            	4609, 8,
            	4604, 16,
            	4644, 24,
            	4663, 32,
            	4644, 40,
            	4558, 48,
            	4553, 56,
            	4553, 64,
            	4529, 72,
            	4524, 80,
            1, 8, 1, /* 4644: pointer.struct.X509_name_st */
            	4649, 0,
            0, 40, 3, /* 4649: struct.X509_name_st */
            	4580, 0,
            	4658, 16,
            	134, 24,
            1, 8, 1, /* 4658: pointer.struct.buf_mem_st */
            	4575, 0,
            1, 8, 1, /* 4663: pointer.struct.X509_val_st */
            	4563, 0,
            1, 8, 1, /* 4668: pointer.struct.cert_pkey_st */
            	4673, 0,
            0, 24, 3, /* 4673: struct.cert_pkey_st */
            	4682, 0,
            	4719, 8,
            	4724, 16,
            1, 8, 1, /* 4682: pointer.struct.x509_st */
            	4687, 0,
            0, 184, 12, /* 4687: struct.x509_st */
            	4614, 0,
            	4604, 8,
            	4553, 16,
            	169, 32,
            	4514, 40,
            	4473, 104,
            	2603, 112,
            	2926, 120,
            	3357, 128,
            	3496, 136,
            	3520, 144,
            	4714, 176,
            1, 8, 1, /* 4714: pointer.struct.x509_cert_aux_st */
            	4436, 0,
            1, 8, 1, /* 4719: pointer.struct.evp_pkey_st */
            	4391, 0,
            1, 8, 1, /* 4724: pointer.struct.env_md_st */
            	4335, 0,
            1, 8, 1, /* 4729: pointer.struct.stack_st_X509_ALGOR */
            	4734, 0,
            0, 32, 2, /* 4734: struct.stack_st_fake_X509_ALGOR */
            	4741, 8,
            	174, 24,
            8884099, 8, 2, /* 4741: pointer_to_array_of_pointers_to_stack */
            	4748, 0,
            	33, 20,
            0, 8, 1, /* 4748: pointer.X509_ALGOR */
            	2021, 0,
            1, 8, 1, /* 4753: pointer.struct.stack_st_ASN1_OBJECT */
            	4758, 0,
            0, 32, 2, /* 4758: struct.stack_st_fake_ASN1_OBJECT */
            	4765, 8,
            	174, 24,
            8884099, 8, 2, /* 4765: pointer_to_array_of_pointers_to_stack */
            	4772, 0,
            	33, 20,
            0, 8, 1, /* 4772: pointer.ASN1_OBJECT */
            	3243, 0,
            0, 40, 5, /* 4777: struct.x509_cert_aux_st */
            	4753, 0,
            	4753, 8,
            	4790, 16,
            	4800, 24,
            	4729, 32,
            1, 8, 1, /* 4790: pointer.struct.asn1_string_st */
            	4795, 0,
            0, 24, 1, /* 4795: struct.asn1_string_st */
            	134, 8,
            1, 8, 1, /* 4800: pointer.struct.asn1_string_st */
            	4795, 0,
            1, 8, 1, /* 4805: pointer.struct.x509_cert_aux_st */
            	4777, 0,
            1, 8, 1, /* 4810: pointer.struct.NAME_CONSTRAINTS_st */
            	3525, 0,
            1, 8, 1, /* 4815: pointer.struct.stack_st_GENERAL_NAME */
            	4820, 0,
            0, 32, 2, /* 4820: struct.stack_st_fake_GENERAL_NAME */
            	4827, 8,
            	174, 24,
            8884099, 8, 2, /* 4827: pointer_to_array_of_pointers_to_stack */
            	4834, 0,
            	33, 20,
            0, 8, 1, /* 4834: pointer.GENERAL_NAME */
            	2651, 0,
            1, 8, 1, /* 4839: pointer.struct.bignum_st */
            	18, 0,
            1, 8, 1, /* 4844: pointer.struct.X509_POLICY_CACHE_st */
            	2931, 0,
            1, 8, 1, /* 4849: pointer.struct.AUTHORITY_KEYID_st */
            	2608, 0,
            1, 8, 1, /* 4854: pointer.struct.stack_st_X509_EXTENSION */
            	4859, 0,
            0, 32, 2, /* 4859: struct.stack_st_fake_X509_EXTENSION */
            	4866, 8,
            	174, 24,
            8884099, 8, 2, /* 4866: pointer_to_array_of_pointers_to_stack */
            	4873, 0,
            	33, 20,
            0, 8, 1, /* 4873: pointer.X509_EXTENSION */
            	2231, 0,
            1, 8, 1, /* 4878: pointer.struct.asn1_string_st */
            	4795, 0,
            1, 8, 1, /* 4883: pointer.struct.X509_pubkey_st */
            	2272, 0,
            1, 8, 1, /* 4888: pointer.struct.asn1_string_st */
            	4795, 0,
            0, 24, 1, /* 4893: struct.buf_mem_st */
            	169, 8,
            1, 8, 1, /* 4898: pointer.struct.buf_mem_st */
            	4893, 0,
            1, 8, 1, /* 4903: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4908, 0,
            0, 32, 2, /* 4908: struct.stack_st_fake_X509_NAME_ENTRY */
            	4915, 8,
            	174, 24,
            8884099, 8, 2, /* 4915: pointer_to_array_of_pointers_to_stack */
            	4922, 0,
            	33, 20,
            0, 8, 1, /* 4922: pointer.X509_NAME_ENTRY */
            	2413, 0,
            0, 40, 3, /* 4927: struct.X509_name_st */
            	4903, 0,
            	4898, 16,
            	134, 24,
            1, 8, 1, /* 4936: pointer.struct.X509_name_st */
            	4927, 0,
            1, 8, 1, /* 4941: pointer.struct.asn1_string_st */
            	4795, 0,
            0, 104, 11, /* 4946: struct.x509_cinf_st */
            	4941, 0,
            	4941, 8,
            	4971, 16,
            	4936, 24,
            	4976, 32,
            	4936, 40,
            	4883, 48,
            	4878, 56,
            	4878, 64,
            	4854, 72,
            	4988, 80,
            1, 8, 1, /* 4971: pointer.struct.X509_algor_st */
            	2026, 0,
            1, 8, 1, /* 4976: pointer.struct.X509_val_st */
            	4981, 0,
            0, 16, 2, /* 4981: struct.X509_val_st */
            	4888, 0,
            	4888, 8,
            0, 24, 1, /* 4988: struct.ASN1_ENCODING_st */
            	134, 0,
            1, 8, 1, /* 4993: pointer.struct.x509_cinf_st */
            	4946, 0,
            0, 352, 14, /* 4998: struct.ssl_session_st */
            	169, 144,
            	169, 152,
            	5029, 168,
            	5154, 176,
            	4094, 224,
            	5208, 240,
            	5186, 248,
            	5242, 264,
            	5242, 272,
            	169, 280,
            	134, 296,
            	134, 312,
            	134, 320,
            	169, 344,
            1, 8, 1, /* 5029: pointer.struct.sess_cert_st */
            	5034, 0,
            0, 248, 5, /* 5034: struct.sess_cert_st */
            	5047, 0,
            	4668, 16,
            	5149, 216,
            	4324, 224,
            	3882, 232,
            1, 8, 1, /* 5047: pointer.struct.stack_st_X509 */
            	5052, 0,
            0, 32, 2, /* 5052: struct.stack_st_fake_X509 */
            	5059, 8,
            	174, 24,
            8884099, 8, 2, /* 5059: pointer_to_array_of_pointers_to_stack */
            	5066, 0,
            	33, 20,
            0, 8, 1, /* 5066: pointer.X509 */
            	5071, 0,
            0, 0, 1, /* 5071: X509 */
            	5076, 0,
            0, 184, 12, /* 5076: struct.x509_st */
            	4993, 0,
            	4971, 8,
            	4878, 16,
            	169, 32,
            	5103, 40,
            	4800, 104,
            	4849, 112,
            	4844, 120,
            	5125, 128,
            	4815, 136,
            	4810, 144,
            	4805, 176,
            0, 16, 1, /* 5103: struct.crypto_ex_data_st */
            	5108, 0,
            1, 8, 1, /* 5108: pointer.struct.stack_st_void */
            	5113, 0,
            0, 32, 1, /* 5113: struct.stack_st_void */
            	5118, 0,
            0, 32, 2, /* 5118: struct.stack_st */
            	164, 8,
            	174, 24,
            1, 8, 1, /* 5125: pointer.struct.stack_st_DIST_POINT */
            	5130, 0,
            0, 32, 2, /* 5130: struct.stack_st_fake_DIST_POINT */
            	5137, 8,
            	174, 24,
            8884099, 8, 2, /* 5137: pointer_to_array_of_pointers_to_stack */
            	5144, 0,
            	33, 20,
            0, 8, 1, /* 5144: pointer.DIST_POINT */
            	3381, 0,
            1, 8, 1, /* 5149: pointer.struct.rsa_st */
            	566, 0,
            1, 8, 1, /* 5154: pointer.struct.x509_st */
            	5159, 0,
            0, 184, 12, /* 5159: struct.x509_st */
            	4319, 0,
            	4284, 8,
            	4209, 16,
            	169, 32,
            	5186, 40,
            	4175, 104,
            	2603, 112,
            	2926, 120,
            	3357, 128,
            	3496, 136,
            	3520, 144,
            	4133, 176,
            0, 16, 1, /* 5186: struct.crypto_ex_data_st */
            	5191, 0,
            1, 8, 1, /* 5191: pointer.struct.stack_st_void */
            	5196, 0,
            0, 32, 1, /* 5196: struct.stack_st_void */
            	5201, 0,
            0, 32, 2, /* 5201: struct.stack_st */
            	164, 8,
            	174, 24,
            1, 8, 1, /* 5208: pointer.struct.stack_st_SSL_CIPHER */
            	5213, 0,
            0, 32, 2, /* 5213: struct.stack_st_fake_SSL_CIPHER */
            	5220, 8,
            	174, 24,
            8884099, 8, 2, /* 5220: pointer_to_array_of_pointers_to_stack */
            	5227, 0,
            	33, 20,
            0, 8, 1, /* 5227: pointer.SSL_CIPHER */
            	5232, 0,
            0, 0, 1, /* 5232: SSL_CIPHER */
            	5237, 0,
            0, 88, 1, /* 5237: struct.ssl_cipher_st */
            	10, 8,
            1, 8, 1, /* 5242: pointer.struct.ssl_session_st */
            	4998, 0,
            1, 8, 1, /* 5247: pointer.struct.lhash_node_st */
            	5252, 0,
            0, 24, 2, /* 5252: struct.lhash_node_st */
            	760, 0,
            	5247, 8,
            0, 176, 3, /* 5259: struct.lhash_st */
            	5268, 0,
            	174, 8,
            	5275, 16,
            8884099, 8, 2, /* 5268: pointer_to_array_of_pointers_to_stack */
            	5247, 0,
            	30, 28,
            8884097, 8, 0, /* 5275: pointer.func */
            1, 8, 1, /* 5278: pointer.struct.lhash_st */
            	5259, 0,
            8884097, 8, 0, /* 5283: pointer.func */
            8884097, 8, 0, /* 5286: pointer.func */
            8884097, 8, 0, /* 5289: pointer.func */
            8884097, 8, 0, /* 5292: pointer.func */
            8884097, 8, 0, /* 5295: pointer.func */
            0, 56, 2, /* 5298: struct.X509_VERIFY_PARAM_st */
            	169, 0,
            	4151, 48,
            1, 8, 1, /* 5305: pointer.struct.X509_VERIFY_PARAM_st */
            	5298, 0,
            8884097, 8, 0, /* 5310: pointer.func */
            8884097, 8, 0, /* 5313: pointer.func */
            8884097, 8, 0, /* 5316: pointer.func */
            1, 8, 1, /* 5319: pointer.struct.X509_VERIFY_PARAM_st */
            	5324, 0,
            0, 56, 2, /* 5324: struct.X509_VERIFY_PARAM_st */
            	169, 0,
            	5331, 48,
            1, 8, 1, /* 5331: pointer.struct.stack_st_ASN1_OBJECT */
            	5336, 0,
            0, 32, 2, /* 5336: struct.stack_st_fake_ASN1_OBJECT */
            	5343, 8,
            	174, 24,
            8884099, 8, 2, /* 5343: pointer_to_array_of_pointers_to_stack */
            	5350, 0,
            	33, 20,
            0, 8, 1, /* 5350: pointer.ASN1_OBJECT */
            	3243, 0,
            1, 8, 1, /* 5355: pointer.struct.stack_st_X509_LOOKUP */
            	5360, 0,
            0, 32, 2, /* 5360: struct.stack_st_fake_X509_LOOKUP */
            	5367, 8,
            	174, 24,
            8884099, 8, 2, /* 5367: pointer_to_array_of_pointers_to_stack */
            	5374, 0,
            	33, 20,
            0, 8, 1, /* 5374: pointer.X509_LOOKUP */
            	5379, 0,
            0, 0, 1, /* 5379: X509_LOOKUP */
            	5384, 0,
            0, 32, 3, /* 5384: struct.x509_lookup_st */
            	5393, 8,
            	169, 16,
            	5442, 24,
            1, 8, 1, /* 5393: pointer.struct.x509_lookup_method_st */
            	5398, 0,
            0, 80, 10, /* 5398: struct.x509_lookup_method_st */
            	10, 0,
            	5421, 8,
            	5424, 16,
            	5421, 24,
            	5421, 32,
            	5427, 40,
            	5430, 48,
            	5433, 56,
            	5436, 64,
            	5439, 72,
            8884097, 8, 0, /* 5421: pointer.func */
            8884097, 8, 0, /* 5424: pointer.func */
            8884097, 8, 0, /* 5427: pointer.func */
            8884097, 8, 0, /* 5430: pointer.func */
            8884097, 8, 0, /* 5433: pointer.func */
            8884097, 8, 0, /* 5436: pointer.func */
            8884097, 8, 0, /* 5439: pointer.func */
            1, 8, 1, /* 5442: pointer.struct.x509_store_st */
            	5447, 0,
            0, 144, 15, /* 5447: struct.x509_store_st */
            	5480, 8,
            	5355, 16,
            	5319, 24,
            	5316, 32,
            	5313, 40,
            	6260, 48,
            	6263, 56,
            	5316, 64,
            	6266, 72,
            	6269, 80,
            	6272, 88,
            	5310, 96,
            	6275, 104,
            	5316, 112,
            	5706, 120,
            1, 8, 1, /* 5480: pointer.struct.stack_st_X509_OBJECT */
            	5485, 0,
            0, 32, 2, /* 5485: struct.stack_st_fake_X509_OBJECT */
            	5492, 8,
            	174, 24,
            8884099, 8, 2, /* 5492: pointer_to_array_of_pointers_to_stack */
            	5499, 0,
            	33, 20,
            0, 8, 1, /* 5499: pointer.X509_OBJECT */
            	5504, 0,
            0, 0, 1, /* 5504: X509_OBJECT */
            	5509, 0,
            0, 16, 1, /* 5509: struct.x509_object_st */
            	5514, 8,
            0, 8, 4, /* 5514: union.unknown */
            	169, 0,
            	5525, 0,
            	5843, 0,
            	6177, 0,
            1, 8, 1, /* 5525: pointer.struct.x509_st */
            	5530, 0,
            0, 184, 12, /* 5530: struct.x509_st */
            	5557, 0,
            	5597, 8,
            	5672, 16,
            	169, 32,
            	5706, 40,
            	5728, 104,
            	5733, 112,
            	5738, 120,
            	5743, 128,
            	5767, 136,
            	5791, 144,
            	5796, 176,
            1, 8, 1, /* 5557: pointer.struct.x509_cinf_st */
            	5562, 0,
            0, 104, 11, /* 5562: struct.x509_cinf_st */
            	5587, 0,
            	5587, 8,
            	5597, 16,
            	5602, 24,
            	5650, 32,
            	5602, 40,
            	5667, 48,
            	5672, 56,
            	5672, 64,
            	5677, 72,
            	5701, 80,
            1, 8, 1, /* 5587: pointer.struct.asn1_string_st */
            	5592, 0,
            0, 24, 1, /* 5592: struct.asn1_string_st */
            	134, 8,
            1, 8, 1, /* 5597: pointer.struct.X509_algor_st */
            	2026, 0,
            1, 8, 1, /* 5602: pointer.struct.X509_name_st */
            	5607, 0,
            0, 40, 3, /* 5607: struct.X509_name_st */
            	5616, 0,
            	5640, 16,
            	134, 24,
            1, 8, 1, /* 5616: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5621, 0,
            0, 32, 2, /* 5621: struct.stack_st_fake_X509_NAME_ENTRY */
            	5628, 8,
            	174, 24,
            8884099, 8, 2, /* 5628: pointer_to_array_of_pointers_to_stack */
            	5635, 0,
            	33, 20,
            0, 8, 1, /* 5635: pointer.X509_NAME_ENTRY */
            	2413, 0,
            1, 8, 1, /* 5640: pointer.struct.buf_mem_st */
            	5645, 0,
            0, 24, 1, /* 5645: struct.buf_mem_st */
            	169, 8,
            1, 8, 1, /* 5650: pointer.struct.X509_val_st */
            	5655, 0,
            0, 16, 2, /* 5655: struct.X509_val_st */
            	5662, 0,
            	5662, 8,
            1, 8, 1, /* 5662: pointer.struct.asn1_string_st */
            	5592, 0,
            1, 8, 1, /* 5667: pointer.struct.X509_pubkey_st */
            	2272, 0,
            1, 8, 1, /* 5672: pointer.struct.asn1_string_st */
            	5592, 0,
            1, 8, 1, /* 5677: pointer.struct.stack_st_X509_EXTENSION */
            	5682, 0,
            0, 32, 2, /* 5682: struct.stack_st_fake_X509_EXTENSION */
            	5689, 8,
            	174, 24,
            8884099, 8, 2, /* 5689: pointer_to_array_of_pointers_to_stack */
            	5696, 0,
            	33, 20,
            0, 8, 1, /* 5696: pointer.X509_EXTENSION */
            	2231, 0,
            0, 24, 1, /* 5701: struct.ASN1_ENCODING_st */
            	134, 0,
            0, 16, 1, /* 5706: struct.crypto_ex_data_st */
            	5711, 0,
            1, 8, 1, /* 5711: pointer.struct.stack_st_void */
            	5716, 0,
            0, 32, 1, /* 5716: struct.stack_st_void */
            	5721, 0,
            0, 32, 2, /* 5721: struct.stack_st */
            	164, 8,
            	174, 24,
            1, 8, 1, /* 5728: pointer.struct.asn1_string_st */
            	5592, 0,
            1, 8, 1, /* 5733: pointer.struct.AUTHORITY_KEYID_st */
            	2608, 0,
            1, 8, 1, /* 5738: pointer.struct.X509_POLICY_CACHE_st */
            	2931, 0,
            1, 8, 1, /* 5743: pointer.struct.stack_st_DIST_POINT */
            	5748, 0,
            0, 32, 2, /* 5748: struct.stack_st_fake_DIST_POINT */
            	5755, 8,
            	174, 24,
            8884099, 8, 2, /* 5755: pointer_to_array_of_pointers_to_stack */
            	5762, 0,
            	33, 20,
            0, 8, 1, /* 5762: pointer.DIST_POINT */
            	3381, 0,
            1, 8, 1, /* 5767: pointer.struct.stack_st_GENERAL_NAME */
            	5772, 0,
            0, 32, 2, /* 5772: struct.stack_st_fake_GENERAL_NAME */
            	5779, 8,
            	174, 24,
            8884099, 8, 2, /* 5779: pointer_to_array_of_pointers_to_stack */
            	5786, 0,
            	33, 20,
            0, 8, 1, /* 5786: pointer.GENERAL_NAME */
            	2651, 0,
            1, 8, 1, /* 5791: pointer.struct.NAME_CONSTRAINTS_st */
            	3525, 0,
            1, 8, 1, /* 5796: pointer.struct.x509_cert_aux_st */
            	5801, 0,
            0, 40, 5, /* 5801: struct.x509_cert_aux_st */
            	5331, 0,
            	5331, 8,
            	5814, 16,
            	5728, 24,
            	5819, 32,
            1, 8, 1, /* 5814: pointer.struct.asn1_string_st */
            	5592, 0,
            1, 8, 1, /* 5819: pointer.struct.stack_st_X509_ALGOR */
            	5824, 0,
            0, 32, 2, /* 5824: struct.stack_st_fake_X509_ALGOR */
            	5831, 8,
            	174, 24,
            8884099, 8, 2, /* 5831: pointer_to_array_of_pointers_to_stack */
            	5838, 0,
            	33, 20,
            0, 8, 1, /* 5838: pointer.X509_ALGOR */
            	2021, 0,
            1, 8, 1, /* 5843: pointer.struct.X509_crl_st */
            	5848, 0,
            0, 120, 10, /* 5848: struct.X509_crl_st */
            	5871, 0,
            	5597, 8,
            	5672, 16,
            	5733, 32,
            	5998, 40,
            	5587, 56,
            	5587, 64,
            	6111, 96,
            	6152, 104,
            	760, 112,
            1, 8, 1, /* 5871: pointer.struct.X509_crl_info_st */
            	5876, 0,
            0, 80, 8, /* 5876: struct.X509_crl_info_st */
            	5587, 0,
            	5597, 8,
            	5602, 16,
            	5662, 24,
            	5662, 32,
            	5895, 40,
            	5677, 48,
            	5701, 56,
            1, 8, 1, /* 5895: pointer.struct.stack_st_X509_REVOKED */
            	5900, 0,
            0, 32, 2, /* 5900: struct.stack_st_fake_X509_REVOKED */
            	5907, 8,
            	174, 24,
            8884099, 8, 2, /* 5907: pointer_to_array_of_pointers_to_stack */
            	5914, 0,
            	33, 20,
            0, 8, 1, /* 5914: pointer.X509_REVOKED */
            	5919, 0,
            0, 0, 1, /* 5919: X509_REVOKED */
            	5924, 0,
            0, 40, 4, /* 5924: struct.x509_revoked_st */
            	5935, 0,
            	5945, 8,
            	5950, 16,
            	5974, 24,
            1, 8, 1, /* 5935: pointer.struct.asn1_string_st */
            	5940, 0,
            0, 24, 1, /* 5940: struct.asn1_string_st */
            	134, 8,
            1, 8, 1, /* 5945: pointer.struct.asn1_string_st */
            	5940, 0,
            1, 8, 1, /* 5950: pointer.struct.stack_st_X509_EXTENSION */
            	5955, 0,
            0, 32, 2, /* 5955: struct.stack_st_fake_X509_EXTENSION */
            	5962, 8,
            	174, 24,
            8884099, 8, 2, /* 5962: pointer_to_array_of_pointers_to_stack */
            	5969, 0,
            	33, 20,
            0, 8, 1, /* 5969: pointer.X509_EXTENSION */
            	2231, 0,
            1, 8, 1, /* 5974: pointer.struct.stack_st_GENERAL_NAME */
            	5979, 0,
            0, 32, 2, /* 5979: struct.stack_st_fake_GENERAL_NAME */
            	5986, 8,
            	174, 24,
            8884099, 8, 2, /* 5986: pointer_to_array_of_pointers_to_stack */
            	5993, 0,
            	33, 20,
            0, 8, 1, /* 5993: pointer.GENERAL_NAME */
            	2651, 0,
            1, 8, 1, /* 5998: pointer.struct.ISSUING_DIST_POINT_st */
            	6003, 0,
            0, 32, 2, /* 6003: struct.ISSUING_DIST_POINT_st */
            	6010, 0,
            	6101, 16,
            1, 8, 1, /* 6010: pointer.struct.DIST_POINT_NAME_st */
            	6015, 0,
            0, 24, 2, /* 6015: struct.DIST_POINT_NAME_st */
            	6022, 8,
            	6077, 16,
            0, 8, 2, /* 6022: union.unknown */
            	6029, 0,
            	6053, 0,
            1, 8, 1, /* 6029: pointer.struct.stack_st_GENERAL_NAME */
            	6034, 0,
            0, 32, 2, /* 6034: struct.stack_st_fake_GENERAL_NAME */
            	6041, 8,
            	174, 24,
            8884099, 8, 2, /* 6041: pointer_to_array_of_pointers_to_stack */
            	6048, 0,
            	33, 20,
            0, 8, 1, /* 6048: pointer.GENERAL_NAME */
            	2651, 0,
            1, 8, 1, /* 6053: pointer.struct.stack_st_X509_NAME_ENTRY */
            	6058, 0,
            0, 32, 2, /* 6058: struct.stack_st_fake_X509_NAME_ENTRY */
            	6065, 8,
            	174, 24,
            8884099, 8, 2, /* 6065: pointer_to_array_of_pointers_to_stack */
            	6072, 0,
            	33, 20,
            0, 8, 1, /* 6072: pointer.X509_NAME_ENTRY */
            	2413, 0,
            1, 8, 1, /* 6077: pointer.struct.X509_name_st */
            	6082, 0,
            0, 40, 3, /* 6082: struct.X509_name_st */
            	6053, 0,
            	6091, 16,
            	134, 24,
            1, 8, 1, /* 6091: pointer.struct.buf_mem_st */
            	6096, 0,
            0, 24, 1, /* 6096: struct.buf_mem_st */
            	169, 8,
            1, 8, 1, /* 6101: pointer.struct.asn1_string_st */
            	6106, 0,
            0, 24, 1, /* 6106: struct.asn1_string_st */
            	134, 8,
            1, 8, 1, /* 6111: pointer.struct.stack_st_GENERAL_NAMES */
            	6116, 0,
            0, 32, 2, /* 6116: struct.stack_st_fake_GENERAL_NAMES */
            	6123, 8,
            	174, 24,
            8884099, 8, 2, /* 6123: pointer_to_array_of_pointers_to_stack */
            	6130, 0,
            	33, 20,
            0, 8, 1, /* 6130: pointer.GENERAL_NAMES */
            	6135, 0,
            0, 0, 1, /* 6135: GENERAL_NAMES */
            	6140, 0,
            0, 32, 1, /* 6140: struct.stack_st_GENERAL_NAME */
            	6145, 0,
            0, 32, 2, /* 6145: struct.stack_st */
            	164, 8,
            	174, 24,
            1, 8, 1, /* 6152: pointer.struct.x509_crl_method_st */
            	6157, 0,
            0, 40, 4, /* 6157: struct.x509_crl_method_st */
            	6168, 8,
            	6168, 16,
            	6171, 24,
            	6174, 32,
            8884097, 8, 0, /* 6168: pointer.func */
            8884097, 8, 0, /* 6171: pointer.func */
            8884097, 8, 0, /* 6174: pointer.func */
            1, 8, 1, /* 6177: pointer.struct.evp_pkey_st */
            	6182, 0,
            0, 56, 4, /* 6182: struct.evp_pkey_st */
            	6193, 16,
            	6198, 24,
            	6203, 32,
            	6236, 48,
            1, 8, 1, /* 6193: pointer.struct.evp_pkey_asn1_method_st */
            	1896, 0,
            1, 8, 1, /* 6198: pointer.struct.engine_st */
            	218, 0,
            0, 8, 5, /* 6203: union.unknown */
            	169, 0,
            	6216, 0,
            	6221, 0,
            	6226, 0,
            	6231, 0,
            1, 8, 1, /* 6216: pointer.struct.rsa_st */
            	566, 0,
            1, 8, 1, /* 6221: pointer.struct.dsa_st */
            	1219, 0,
            1, 8, 1, /* 6226: pointer.struct.dh_st */
            	76, 0,
            1, 8, 1, /* 6231: pointer.struct.ec_key_st */
            	1376, 0,
            1, 8, 1, /* 6236: pointer.struct.stack_st_X509_ATTRIBUTE */
            	6241, 0,
            0, 32, 2, /* 6241: struct.stack_st_fake_X509_ATTRIBUTE */
            	6248, 8,
            	174, 24,
            8884099, 8, 2, /* 6248: pointer_to_array_of_pointers_to_stack */
            	6255, 0,
            	33, 20,
            0, 8, 1, /* 6255: pointer.X509_ATTRIBUTE */
            	849, 0,
            8884097, 8, 0, /* 6260: pointer.func */
            8884097, 8, 0, /* 6263: pointer.func */
            8884097, 8, 0, /* 6266: pointer.func */
            8884097, 8, 0, /* 6269: pointer.func */
            8884097, 8, 0, /* 6272: pointer.func */
            8884097, 8, 0, /* 6275: pointer.func */
            1, 8, 1, /* 6278: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	6283, 0,
            0, 32, 2, /* 6283: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	6290, 8,
            	174, 24,
            8884099, 8, 2, /* 6290: pointer_to_array_of_pointers_to_stack */
            	6297, 0,
            	33, 20,
            0, 8, 1, /* 6297: pointer.SRTP_PROTECTION_PROFILE */
            	0, 0,
            8884097, 8, 0, /* 6302: pointer.func */
            1, 8, 1, /* 6305: pointer.struct.stack_st_X509 */
            	6310, 0,
            0, 32, 2, /* 6310: struct.stack_st_fake_X509 */
            	6317, 8,
            	174, 24,
            8884099, 8, 2, /* 6317: pointer_to_array_of_pointers_to_stack */
            	6324, 0,
            	33, 20,
            0, 8, 1, /* 6324: pointer.X509 */
            	5071, 0,
            8884097, 8, 0, /* 6329: pointer.func */
            1, 8, 1, /* 6332: pointer.struct.ssl_ctx_st */
            	6337, 0,
            0, 736, 50, /* 6337: struct.ssl_ctx_st */
            	6440, 0,
            	5208, 8,
            	5208, 16,
            	6606, 24,
            	5278, 32,
            	5242, 48,
            	5242, 56,
            	4086, 80,
            	6698, 88,
            	6701, 96,
            	6704, 152,
            	760, 160,
            	4083, 168,
            	760, 176,
            	4080, 184,
            	4077, 192,
            	4074, 200,
            	5186, 208,
            	4069, 224,
            	4069, 232,
            	4069, 240,
            	6305, 248,
            	4011, 256,
            	3962, 264,
            	3938, 272,
            	6707, 304,
            	6712, 320,
            	760, 328,
            	5292, 376,
            	65, 384,
            	5305, 392,
            	1992, 408,
            	6715, 416,
            	760, 424,
            	6718, 480,
            	62, 488,
            	760, 496,
            	59, 504,
            	760, 512,
            	169, 520,
            	56, 528,
            	6721, 536,
            	36, 552,
            	36, 560,
            	6724, 568,
            	6758, 696,
            	760, 704,
            	15, 712,
            	760, 720,
            	6278, 728,
            1, 8, 1, /* 6440: pointer.struct.ssl_method_st */
            	6445, 0,
            0, 232, 28, /* 6445: struct.ssl_method_st */
            	6504, 8,
            	6507, 16,
            	6507, 24,
            	6504, 32,
            	6504, 40,
            	6510, 48,
            	6510, 56,
            	6513, 64,
            	6504, 72,
            	6504, 80,
            	6504, 88,
            	6516, 96,
            	6519, 104,
            	6522, 112,
            	6504, 120,
            	6525, 128,
            	6528, 136,
            	6531, 144,
            	6534, 152,
            	6537, 160,
            	487, 168,
            	6540, 176,
            	6543, 184,
            	3991, 192,
            	6546, 200,
            	487, 208,
            	6600, 216,
            	6603, 224,
            8884097, 8, 0, /* 6504: pointer.func */
            8884097, 8, 0, /* 6507: pointer.func */
            8884097, 8, 0, /* 6510: pointer.func */
            8884097, 8, 0, /* 6513: pointer.func */
            8884097, 8, 0, /* 6516: pointer.func */
            8884097, 8, 0, /* 6519: pointer.func */
            8884097, 8, 0, /* 6522: pointer.func */
            8884097, 8, 0, /* 6525: pointer.func */
            8884097, 8, 0, /* 6528: pointer.func */
            8884097, 8, 0, /* 6531: pointer.func */
            8884097, 8, 0, /* 6534: pointer.func */
            8884097, 8, 0, /* 6537: pointer.func */
            8884097, 8, 0, /* 6540: pointer.func */
            8884097, 8, 0, /* 6543: pointer.func */
            1, 8, 1, /* 6546: pointer.struct.ssl3_enc_method */
            	6551, 0,
            0, 112, 11, /* 6551: struct.ssl3_enc_method */
            	6576, 0,
            	6579, 8,
            	6582, 16,
            	6585, 24,
            	6576, 32,
            	6588, 40,
            	6591, 56,
            	10, 64,
            	10, 80,
            	6594, 96,
            	6597, 104,
            8884097, 8, 0, /* 6576: pointer.func */
            8884097, 8, 0, /* 6579: pointer.func */
            8884097, 8, 0, /* 6582: pointer.func */
            8884097, 8, 0, /* 6585: pointer.func */
            8884097, 8, 0, /* 6588: pointer.func */
            8884097, 8, 0, /* 6591: pointer.func */
            8884097, 8, 0, /* 6594: pointer.func */
            8884097, 8, 0, /* 6597: pointer.func */
            8884097, 8, 0, /* 6600: pointer.func */
            8884097, 8, 0, /* 6603: pointer.func */
            1, 8, 1, /* 6606: pointer.struct.x509_store_st */
            	6611, 0,
            0, 144, 15, /* 6611: struct.x509_store_st */
            	6644, 8,
            	6668, 16,
            	5305, 24,
            	5295, 32,
            	5292, 40,
            	5289, 48,
            	6329, 56,
            	5295, 64,
            	6302, 72,
            	6692, 80,
            	5286, 88,
            	6695, 96,
            	5283, 104,
            	5295, 112,
            	5186, 120,
            1, 8, 1, /* 6644: pointer.struct.stack_st_X509_OBJECT */
            	6649, 0,
            0, 32, 2, /* 6649: struct.stack_st_fake_X509_OBJECT */
            	6656, 8,
            	174, 24,
            8884099, 8, 2, /* 6656: pointer_to_array_of_pointers_to_stack */
            	6663, 0,
            	33, 20,
            0, 8, 1, /* 6663: pointer.X509_OBJECT */
            	5504, 0,
            1, 8, 1, /* 6668: pointer.struct.stack_st_X509_LOOKUP */
            	6673, 0,
            0, 32, 2, /* 6673: struct.stack_st_fake_X509_LOOKUP */
            	6680, 8,
            	174, 24,
            8884099, 8, 2, /* 6680: pointer_to_array_of_pointers_to_stack */
            	6687, 0,
            	33, 20,
            0, 8, 1, /* 6687: pointer.X509_LOOKUP */
            	5379, 0,
            8884097, 8, 0, /* 6692: pointer.func */
            8884097, 8, 0, /* 6695: pointer.func */
            8884097, 8, 0, /* 6698: pointer.func */
            8884097, 8, 0, /* 6701: pointer.func */
            8884097, 8, 0, /* 6704: pointer.func */
            1, 8, 1, /* 6707: pointer.struct.cert_st */
            	2520, 0,
            8884097, 8, 0, /* 6712: pointer.func */
            8884097, 8, 0, /* 6715: pointer.func */
            8884097, 8, 0, /* 6718: pointer.func */
            8884097, 8, 0, /* 6721: pointer.func */
            0, 128, 14, /* 6724: struct.srp_ctx_st */
            	760, 0,
            	6715, 8,
            	62, 16,
            	6755, 24,
            	169, 32,
            	4839, 40,
            	4839, 48,
            	4839, 56,
            	4839, 64,
            	4839, 72,
            	4839, 80,
            	4839, 88,
            	4839, 96,
            	169, 104,
            8884097, 8, 0, /* 6755: pointer.func */
            8884097, 8, 0, /* 6758: pointer.func */
            0, 1, 0, /* 6761: char */
            0, 8, 0, /* 6764: long int */
        },
        .arg_entity_index = { 6332, 6764, },
        .ret_entity_index = 6764,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    long new_arg_b = *((long *)new_args->args[1]);

    long *new_ret_ptr = (long *)new_args->ret;

    long (*orig_SSL_CTX_set_timeout)(SSL_CTX *,long);
    orig_SSL_CTX_set_timeout = dlsym(RTLD_NEXT, "SSL_CTX_set_timeout");
    *new_ret_ptr = (*orig_SSL_CTX_set_timeout)(new_arg_a,new_arg_b);

    syscall(889);

    return ret;
}

