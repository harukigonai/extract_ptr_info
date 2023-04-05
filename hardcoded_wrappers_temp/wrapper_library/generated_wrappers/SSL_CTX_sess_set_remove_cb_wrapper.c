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

void bb_SSL_CTX_sess_set_remove_cb(SSL_CTX * arg_a,void (*arg_b)(struct ssl_ctx_st *,SSL_SESSION *));

void SSL_CTX_sess_set_remove_cb(SSL_CTX * arg_a,void (*arg_b)(struct ssl_ctx_st *,SSL_SESSION *)) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_sess_set_remove_cb called %lu\n", in_lib);
    if (!in_lib)
        bb_SSL_CTX_sess_set_remove_cb(arg_a,arg_b);
    else {
        void (*orig_SSL_CTX_sess_set_remove_cb)(SSL_CTX *,void (*)(struct ssl_ctx_st *,SSL_SESSION *));
        orig_SSL_CTX_sess_set_remove_cb = dlsym(RTLD_NEXT, "SSL_CTX_sess_set_remove_cb");
        orig_SSL_CTX_sess_set_remove_cb(arg_a,arg_b);
    }
}

void bb_SSL_CTX_sess_set_remove_cb(SSL_CTX * arg_a,void (*arg_b)(struct ssl_ctx_st *,SSL_SESSION *)) 
{
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            64097, 8, 0, /* 0: pointer.func */
            0, 0, 1, /* 3: SRTP_PROTECTION_PROFILE */
            	8, 0,
            0, 16, 1, /* 8: struct.srtp_protection_profile_st */
            	13, 0,
            1, 8, 1, /* 13: pointer.char */
            	64096, 0,
            64097, 8, 0, /* 18: pointer.func */
            0, 128, 14, /* 21: struct.srp_ctx_st */
            	52, 0,
            	55, 8,
            	58, 16,
            	61, 24,
            	64, 32,
            	69, 40,
            	69, 48,
            	69, 56,
            	69, 64,
            	69, 72,
            	69, 80,
            	69, 88,
            	69, 96,
            	64, 104,
            0, 8, 0, /* 52: pointer.void */
            64097, 8, 0, /* 55: pointer.func */
            64097, 8, 0, /* 58: pointer.func */
            64097, 8, 0, /* 61: pointer.func */
            1, 8, 1, /* 64: pointer.char */
            	64096, 0,
            1, 8, 1, /* 69: pointer.struct.bignum_st */
            	74, 0,
            0, 24, 1, /* 74: struct.bignum_st */
            	79, 0,
            1, 8, 1, /* 79: pointer.unsigned int */
            	84, 0,
            0, 4, 0, /* 84: unsigned int */
            64097, 8, 0, /* 87: pointer.func */
            0, 8, 1, /* 90: struct.ssl3_buf_freelist_entry_st */
            	95, 0,
            1, 8, 1, /* 95: pointer.struct.ssl3_buf_freelist_entry_st */
            	90, 0,
            1, 8, 1, /* 100: pointer.struct.ssl3_buf_freelist_st */
            	105, 0,
            0, 24, 1, /* 105: struct.ssl3_buf_freelist_st */
            	95, 16,
            64097, 8, 0, /* 110: pointer.func */
            64097, 8, 0, /* 113: pointer.func */
            64097, 8, 0, /* 116: pointer.func */
            64097, 8, 0, /* 119: pointer.func */
            64097, 8, 0, /* 122: pointer.func */
            0, 296, 7, /* 125: struct.cert_st */
            	142, 0,
            	2052, 48,
            	122, 56,
            	2057, 64,
            	119, 72,
            	2062, 80,
            	116, 88,
            1, 8, 1, /* 142: pointer.struct.cert_pkey_st */
            	147, 0,
            0, 24, 3, /* 147: struct.cert_pkey_st */
            	156, 0,
            	519, 8,
            	2007, 16,
            1, 8, 1, /* 156: pointer.struct.x509_st */
            	161, 0,
            0, 184, 12, /* 161: struct.x509_st */
            	188, 0,
            	236, 8,
            	330, 16,
            	64, 32,
            	661, 40,
            	335, 104,
            	1311, 112,
            	1319, 120,
            	1327, 128,
            	1736, 136,
            	1760, 144,
            	1768, 176,
            1, 8, 1, /* 188: pointer.struct.x509_cinf_st */
            	193, 0,
            0, 104, 11, /* 193: struct.x509_cinf_st */
            	218, 0,
            	218, 8,
            	236, 16,
            	398, 24,
            	488, 32,
            	398, 40,
            	505, 48,
            	330, 56,
            	330, 64,
            	1246, 72,
            	1306, 80,
            1, 8, 1, /* 218: pointer.struct.asn1_string_st */
            	223, 0,
            0, 24, 1, /* 223: struct.asn1_string_st */
            	228, 8,
            1, 8, 1, /* 228: pointer.unsigned char */
            	233, 0,
            0, 1, 0, /* 233: unsigned char */
            1, 8, 1, /* 236: pointer.struct.X509_algor_st */
            	241, 0,
            0, 16, 2, /* 241: struct.X509_algor_st */
            	248, 0,
            	267, 8,
            1, 8, 1, /* 248: pointer.struct.asn1_object_st */
            	253, 0,
            0, 40, 3, /* 253: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	262, 24,
            1, 8, 1, /* 262: pointer.unsigned char */
            	233, 0,
            1, 8, 1, /* 267: pointer.struct.asn1_type_st */
            	272, 0,
            0, 16, 1, /* 272: struct.asn1_type_st */
            	277, 8,
            0, 8, 20, /* 277: union.unknown */
            	64, 0,
            	320, 0,
            	248, 0,
            	218, 0,
            	325, 0,
            	330, 0,
            	335, 0,
            	340, 0,
            	345, 0,
            	350, 0,
            	355, 0,
            	360, 0,
            	365, 0,
            	370, 0,
            	375, 0,
            	380, 0,
            	385, 0,
            	320, 0,
            	320, 0,
            	390, 0,
            1, 8, 1, /* 320: pointer.struct.asn1_string_st */
            	223, 0,
            1, 8, 1, /* 325: pointer.struct.asn1_string_st */
            	223, 0,
            1, 8, 1, /* 330: pointer.struct.asn1_string_st */
            	223, 0,
            1, 8, 1, /* 335: pointer.struct.asn1_string_st */
            	223, 0,
            1, 8, 1, /* 340: pointer.struct.asn1_string_st */
            	223, 0,
            1, 8, 1, /* 345: pointer.struct.asn1_string_st */
            	223, 0,
            1, 8, 1, /* 350: pointer.struct.asn1_string_st */
            	223, 0,
            1, 8, 1, /* 355: pointer.struct.asn1_string_st */
            	223, 0,
            1, 8, 1, /* 360: pointer.struct.asn1_string_st */
            	223, 0,
            1, 8, 1, /* 365: pointer.struct.asn1_string_st */
            	223, 0,
            1, 8, 1, /* 370: pointer.struct.asn1_string_st */
            	223, 0,
            1, 8, 1, /* 375: pointer.struct.asn1_string_st */
            	223, 0,
            1, 8, 1, /* 380: pointer.struct.asn1_string_st */
            	223, 0,
            1, 8, 1, /* 385: pointer.struct.asn1_string_st */
            	223, 0,
            1, 8, 1, /* 390: pointer.struct.ASN1_VALUE_st */
            	395, 0,
            0, 0, 0, /* 395: struct.ASN1_VALUE_st */
            1, 8, 1, /* 398: pointer.struct.X509_name_st */
            	403, 0,
            0, 40, 3, /* 403: struct.X509_name_st */
            	412, 0,
            	478, 16,
            	228, 24,
            1, 8, 1, /* 412: pointer.struct.stack_st_X509_NAME_ENTRY */
            	417, 0,
            0, 32, 2, /* 417: struct.stack_st_fake_X509_NAME_ENTRY */
            	424, 8,
            	475, 24,
            64099, 8, 2, /* 424: pointer_to_array_of_pointers_to_stack */
            	431, 0,
            	472, 20,
            0, 8, 1, /* 431: pointer.X509_NAME_ENTRY */
            	436, 0,
            0, 0, 1, /* 436: X509_NAME_ENTRY */
            	441, 0,
            0, 24, 2, /* 441: struct.X509_name_entry_st */
            	448, 0,
            	462, 8,
            1, 8, 1, /* 448: pointer.struct.asn1_object_st */
            	453, 0,
            0, 40, 3, /* 453: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	262, 24,
            1, 8, 1, /* 462: pointer.struct.asn1_string_st */
            	467, 0,
            0, 24, 1, /* 467: struct.asn1_string_st */
            	228, 8,
            0, 4, 0, /* 472: int */
            64097, 8, 0, /* 475: pointer.func */
            1, 8, 1, /* 478: pointer.struct.buf_mem_st */
            	483, 0,
            0, 24, 1, /* 483: struct.buf_mem_st */
            	64, 8,
            1, 8, 1, /* 488: pointer.struct.X509_val_st */
            	493, 0,
            0, 16, 2, /* 493: struct.X509_val_st */
            	500, 0,
            	500, 8,
            1, 8, 1, /* 500: pointer.struct.asn1_string_st */
            	223, 0,
            1, 8, 1, /* 505: pointer.struct.X509_pubkey_st */
            	510, 0,
            0, 24, 3, /* 510: struct.X509_pubkey_st */
            	236, 0,
            	330, 8,
            	519, 16,
            1, 8, 1, /* 519: pointer.struct.evp_pkey_st */
            	524, 0,
            0, 56, 4, /* 524: struct.evp_pkey_st */
            	535, 16,
            	543, 24,
            	551, 32,
            	867, 48,
            1, 8, 1, /* 535: pointer.struct.evp_pkey_asn1_method_st */
            	540, 0,
            0, 0, 0, /* 540: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 543: pointer.struct.engine_st */
            	548, 0,
            0, 0, 0, /* 548: struct.engine_st */
            0, 8, 5, /* 551: union.unknown */
            	64, 0,
            	564, 0,
            	710, 0,
            	791, 0,
            	859, 0,
            1, 8, 1, /* 564: pointer.struct.rsa_st */
            	569, 0,
            0, 168, 17, /* 569: struct.rsa_st */
            	606, 16,
            	543, 24,
            	69, 32,
            	69, 40,
            	69, 48,
            	69, 56,
            	69, 64,
            	69, 72,
            	69, 80,
            	69, 88,
            	661, 96,
            	688, 120,
            	688, 128,
            	688, 136,
            	64, 144,
            	702, 152,
            	702, 160,
            1, 8, 1, /* 606: pointer.struct.rsa_meth_st */
            	611, 0,
            0, 112, 13, /* 611: struct.rsa_meth_st */
            	13, 0,
            	640, 8,
            	640, 16,
            	640, 24,
            	640, 32,
            	643, 40,
            	646, 48,
            	649, 56,
            	649, 64,
            	64, 80,
            	652, 88,
            	655, 96,
            	658, 104,
            64097, 8, 0, /* 640: pointer.func */
            64097, 8, 0, /* 643: pointer.func */
            64097, 8, 0, /* 646: pointer.func */
            64097, 8, 0, /* 649: pointer.func */
            64097, 8, 0, /* 652: pointer.func */
            64097, 8, 0, /* 655: pointer.func */
            64097, 8, 0, /* 658: pointer.func */
            0, 16, 1, /* 661: struct.crypto_ex_data_st */
            	666, 0,
            1, 8, 1, /* 666: pointer.struct.stack_st_void */
            	671, 0,
            0, 32, 1, /* 671: struct.stack_st_void */
            	676, 0,
            0, 32, 2, /* 676: struct.stack_st */
            	683, 8,
            	475, 24,
            1, 8, 1, /* 683: pointer.pointer.char */
            	64, 0,
            1, 8, 1, /* 688: pointer.struct.bn_mont_ctx_st */
            	693, 0,
            0, 96, 3, /* 693: struct.bn_mont_ctx_st */
            	74, 8,
            	74, 32,
            	74, 56,
            1, 8, 1, /* 702: pointer.struct.bn_blinding_st */
            	707, 0,
            0, 0, 0, /* 707: struct.bn_blinding_st */
            1, 8, 1, /* 710: pointer.struct.dsa_st */
            	715, 0,
            0, 136, 11, /* 715: struct.dsa_st */
            	69, 24,
            	69, 32,
            	69, 40,
            	69, 48,
            	69, 56,
            	69, 64,
            	69, 72,
            	688, 88,
            	661, 104,
            	740, 120,
            	543, 128,
            1, 8, 1, /* 740: pointer.struct.dsa_method */
            	745, 0,
            0, 96, 11, /* 745: struct.dsa_method */
            	13, 0,
            	770, 8,
            	773, 16,
            	776, 24,
            	779, 32,
            	782, 40,
            	785, 48,
            	785, 56,
            	64, 72,
            	788, 80,
            	785, 88,
            64097, 8, 0, /* 770: pointer.func */
            64097, 8, 0, /* 773: pointer.func */
            64097, 8, 0, /* 776: pointer.func */
            64097, 8, 0, /* 779: pointer.func */
            64097, 8, 0, /* 782: pointer.func */
            64097, 8, 0, /* 785: pointer.func */
            64097, 8, 0, /* 788: pointer.func */
            1, 8, 1, /* 791: pointer.struct.dh_st */
            	796, 0,
            0, 144, 12, /* 796: struct.dh_st */
            	69, 8,
            	69, 16,
            	69, 32,
            	69, 40,
            	688, 56,
            	69, 64,
            	69, 72,
            	228, 80,
            	69, 96,
            	661, 112,
            	823, 128,
            	543, 136,
            1, 8, 1, /* 823: pointer.struct.dh_method */
            	828, 0,
            0, 72, 8, /* 828: struct.dh_method */
            	13, 0,
            	847, 8,
            	850, 16,
            	853, 24,
            	847, 32,
            	847, 40,
            	64, 56,
            	856, 64,
            64097, 8, 0, /* 847: pointer.func */
            64097, 8, 0, /* 850: pointer.func */
            64097, 8, 0, /* 853: pointer.func */
            64097, 8, 0, /* 856: pointer.func */
            1, 8, 1, /* 859: pointer.struct.ec_key_st */
            	864, 0,
            0, 0, 0, /* 864: struct.ec_key_st */
            1, 8, 1, /* 867: pointer.struct.stack_st_X509_ATTRIBUTE */
            	872, 0,
            0, 32, 2, /* 872: struct.stack_st_fake_X509_ATTRIBUTE */
            	879, 8,
            	475, 24,
            64099, 8, 2, /* 879: pointer_to_array_of_pointers_to_stack */
            	886, 0,
            	472, 20,
            0, 8, 1, /* 886: pointer.X509_ATTRIBUTE */
            	891, 0,
            0, 0, 1, /* 891: X509_ATTRIBUTE */
            	896, 0,
            0, 24, 2, /* 896: struct.x509_attributes_st */
            	903, 0,
            	917, 16,
            1, 8, 1, /* 903: pointer.struct.asn1_object_st */
            	908, 0,
            0, 40, 3, /* 908: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	262, 24,
            0, 8, 3, /* 917: union.unknown */
            	64, 0,
            	926, 0,
            	1105, 0,
            1, 8, 1, /* 926: pointer.struct.stack_st_ASN1_TYPE */
            	931, 0,
            0, 32, 2, /* 931: struct.stack_st_fake_ASN1_TYPE */
            	938, 8,
            	475, 24,
            64099, 8, 2, /* 938: pointer_to_array_of_pointers_to_stack */
            	945, 0,
            	472, 20,
            0, 8, 1, /* 945: pointer.ASN1_TYPE */
            	950, 0,
            0, 0, 1, /* 950: ASN1_TYPE */
            	955, 0,
            0, 16, 1, /* 955: struct.asn1_type_st */
            	960, 8,
            0, 8, 20, /* 960: union.unknown */
            	64, 0,
            	1003, 0,
            	1013, 0,
            	1027, 0,
            	1032, 0,
            	1037, 0,
            	1042, 0,
            	1047, 0,
            	1052, 0,
            	1057, 0,
            	1062, 0,
            	1067, 0,
            	1072, 0,
            	1077, 0,
            	1082, 0,
            	1087, 0,
            	1092, 0,
            	1003, 0,
            	1003, 0,
            	1097, 0,
            1, 8, 1, /* 1003: pointer.struct.asn1_string_st */
            	1008, 0,
            0, 24, 1, /* 1008: struct.asn1_string_st */
            	228, 8,
            1, 8, 1, /* 1013: pointer.struct.asn1_object_st */
            	1018, 0,
            0, 40, 3, /* 1018: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	262, 24,
            1, 8, 1, /* 1027: pointer.struct.asn1_string_st */
            	1008, 0,
            1, 8, 1, /* 1032: pointer.struct.asn1_string_st */
            	1008, 0,
            1, 8, 1, /* 1037: pointer.struct.asn1_string_st */
            	1008, 0,
            1, 8, 1, /* 1042: pointer.struct.asn1_string_st */
            	1008, 0,
            1, 8, 1, /* 1047: pointer.struct.asn1_string_st */
            	1008, 0,
            1, 8, 1, /* 1052: pointer.struct.asn1_string_st */
            	1008, 0,
            1, 8, 1, /* 1057: pointer.struct.asn1_string_st */
            	1008, 0,
            1, 8, 1, /* 1062: pointer.struct.asn1_string_st */
            	1008, 0,
            1, 8, 1, /* 1067: pointer.struct.asn1_string_st */
            	1008, 0,
            1, 8, 1, /* 1072: pointer.struct.asn1_string_st */
            	1008, 0,
            1, 8, 1, /* 1077: pointer.struct.asn1_string_st */
            	1008, 0,
            1, 8, 1, /* 1082: pointer.struct.asn1_string_st */
            	1008, 0,
            1, 8, 1, /* 1087: pointer.struct.asn1_string_st */
            	1008, 0,
            1, 8, 1, /* 1092: pointer.struct.asn1_string_st */
            	1008, 0,
            1, 8, 1, /* 1097: pointer.struct.ASN1_VALUE_st */
            	1102, 0,
            0, 0, 0, /* 1102: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1105: pointer.struct.asn1_type_st */
            	1110, 0,
            0, 16, 1, /* 1110: struct.asn1_type_st */
            	1115, 8,
            0, 8, 20, /* 1115: union.unknown */
            	64, 0,
            	1158, 0,
            	903, 0,
            	1168, 0,
            	1173, 0,
            	1178, 0,
            	1183, 0,
            	1188, 0,
            	1193, 0,
            	1198, 0,
            	1203, 0,
            	1208, 0,
            	1213, 0,
            	1218, 0,
            	1223, 0,
            	1228, 0,
            	1233, 0,
            	1158, 0,
            	1158, 0,
            	1238, 0,
            1, 8, 1, /* 1158: pointer.struct.asn1_string_st */
            	1163, 0,
            0, 24, 1, /* 1163: struct.asn1_string_st */
            	228, 8,
            1, 8, 1, /* 1168: pointer.struct.asn1_string_st */
            	1163, 0,
            1, 8, 1, /* 1173: pointer.struct.asn1_string_st */
            	1163, 0,
            1, 8, 1, /* 1178: pointer.struct.asn1_string_st */
            	1163, 0,
            1, 8, 1, /* 1183: pointer.struct.asn1_string_st */
            	1163, 0,
            1, 8, 1, /* 1188: pointer.struct.asn1_string_st */
            	1163, 0,
            1, 8, 1, /* 1193: pointer.struct.asn1_string_st */
            	1163, 0,
            1, 8, 1, /* 1198: pointer.struct.asn1_string_st */
            	1163, 0,
            1, 8, 1, /* 1203: pointer.struct.asn1_string_st */
            	1163, 0,
            1, 8, 1, /* 1208: pointer.struct.asn1_string_st */
            	1163, 0,
            1, 8, 1, /* 1213: pointer.struct.asn1_string_st */
            	1163, 0,
            1, 8, 1, /* 1218: pointer.struct.asn1_string_st */
            	1163, 0,
            1, 8, 1, /* 1223: pointer.struct.asn1_string_st */
            	1163, 0,
            1, 8, 1, /* 1228: pointer.struct.asn1_string_st */
            	1163, 0,
            1, 8, 1, /* 1233: pointer.struct.asn1_string_st */
            	1163, 0,
            1, 8, 1, /* 1238: pointer.struct.ASN1_VALUE_st */
            	1243, 0,
            0, 0, 0, /* 1243: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1246: pointer.struct.stack_st_X509_EXTENSION */
            	1251, 0,
            0, 32, 2, /* 1251: struct.stack_st_fake_X509_EXTENSION */
            	1258, 8,
            	475, 24,
            64099, 8, 2, /* 1258: pointer_to_array_of_pointers_to_stack */
            	1265, 0,
            	472, 20,
            0, 8, 1, /* 1265: pointer.X509_EXTENSION */
            	1270, 0,
            0, 0, 1, /* 1270: X509_EXTENSION */
            	1275, 0,
            0, 24, 2, /* 1275: struct.X509_extension_st */
            	1282, 0,
            	1296, 16,
            1, 8, 1, /* 1282: pointer.struct.asn1_object_st */
            	1287, 0,
            0, 40, 3, /* 1287: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	262, 24,
            1, 8, 1, /* 1296: pointer.struct.asn1_string_st */
            	1301, 0,
            0, 24, 1, /* 1301: struct.asn1_string_st */
            	228, 8,
            0, 24, 1, /* 1306: struct.ASN1_ENCODING_st */
            	228, 0,
            1, 8, 1, /* 1311: pointer.struct.AUTHORITY_KEYID_st */
            	1316, 0,
            0, 0, 0, /* 1316: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 1319: pointer.struct.X509_POLICY_CACHE_st */
            	1324, 0,
            0, 0, 0, /* 1324: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1327: pointer.struct.stack_st_DIST_POINT */
            	1332, 0,
            0, 32, 2, /* 1332: struct.stack_st_fake_DIST_POINT */
            	1339, 8,
            	475, 24,
            64099, 8, 2, /* 1339: pointer_to_array_of_pointers_to_stack */
            	1346, 0,
            	472, 20,
            0, 8, 1, /* 1346: pointer.DIST_POINT */
            	1351, 0,
            0, 0, 1, /* 1351: DIST_POINT */
            	1356, 0,
            0, 32, 3, /* 1356: struct.DIST_POINT_st */
            	1365, 0,
            	1726, 8,
            	1384, 16,
            1, 8, 1, /* 1365: pointer.struct.DIST_POINT_NAME_st */
            	1370, 0,
            0, 24, 2, /* 1370: struct.DIST_POINT_NAME_st */
            	1377, 8,
            	1702, 16,
            0, 8, 2, /* 1377: union.unknown */
            	1384, 0,
            	1678, 0,
            1, 8, 1, /* 1384: pointer.struct.stack_st_GENERAL_NAME */
            	1389, 0,
            0, 32, 2, /* 1389: struct.stack_st_fake_GENERAL_NAME */
            	1396, 8,
            	475, 24,
            64099, 8, 2, /* 1396: pointer_to_array_of_pointers_to_stack */
            	1403, 0,
            	472, 20,
            0, 8, 1, /* 1403: pointer.GENERAL_NAME */
            	1408, 0,
            0, 0, 1, /* 1408: GENERAL_NAME */
            	1413, 0,
            0, 16, 1, /* 1413: struct.GENERAL_NAME_st */
            	1418, 8,
            0, 8, 15, /* 1418: union.unknown */
            	64, 0,
            	1451, 0,
            	1570, 0,
            	1570, 0,
            	1477, 0,
            	1618, 0,
            	1666, 0,
            	1570, 0,
            	1555, 0,
            	1463, 0,
            	1555, 0,
            	1618, 0,
            	1570, 0,
            	1463, 0,
            	1477, 0,
            1, 8, 1, /* 1451: pointer.struct.otherName_st */
            	1456, 0,
            0, 16, 2, /* 1456: struct.otherName_st */
            	1463, 0,
            	1477, 8,
            1, 8, 1, /* 1463: pointer.struct.asn1_object_st */
            	1468, 0,
            0, 40, 3, /* 1468: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	262, 24,
            1, 8, 1, /* 1477: pointer.struct.asn1_type_st */
            	1482, 0,
            0, 16, 1, /* 1482: struct.asn1_type_st */
            	1487, 8,
            0, 8, 20, /* 1487: union.unknown */
            	64, 0,
            	1530, 0,
            	1463, 0,
            	1540, 0,
            	1545, 0,
            	1550, 0,
            	1555, 0,
            	1560, 0,
            	1565, 0,
            	1570, 0,
            	1575, 0,
            	1580, 0,
            	1585, 0,
            	1590, 0,
            	1595, 0,
            	1600, 0,
            	1605, 0,
            	1530, 0,
            	1530, 0,
            	1610, 0,
            1, 8, 1, /* 1530: pointer.struct.asn1_string_st */
            	1535, 0,
            0, 24, 1, /* 1535: struct.asn1_string_st */
            	228, 8,
            1, 8, 1, /* 1540: pointer.struct.asn1_string_st */
            	1535, 0,
            1, 8, 1, /* 1545: pointer.struct.asn1_string_st */
            	1535, 0,
            1, 8, 1, /* 1550: pointer.struct.asn1_string_st */
            	1535, 0,
            1, 8, 1, /* 1555: pointer.struct.asn1_string_st */
            	1535, 0,
            1, 8, 1, /* 1560: pointer.struct.asn1_string_st */
            	1535, 0,
            1, 8, 1, /* 1565: pointer.struct.asn1_string_st */
            	1535, 0,
            1, 8, 1, /* 1570: pointer.struct.asn1_string_st */
            	1535, 0,
            1, 8, 1, /* 1575: pointer.struct.asn1_string_st */
            	1535, 0,
            1, 8, 1, /* 1580: pointer.struct.asn1_string_st */
            	1535, 0,
            1, 8, 1, /* 1585: pointer.struct.asn1_string_st */
            	1535, 0,
            1, 8, 1, /* 1590: pointer.struct.asn1_string_st */
            	1535, 0,
            1, 8, 1, /* 1595: pointer.struct.asn1_string_st */
            	1535, 0,
            1, 8, 1, /* 1600: pointer.struct.asn1_string_st */
            	1535, 0,
            1, 8, 1, /* 1605: pointer.struct.asn1_string_st */
            	1535, 0,
            1, 8, 1, /* 1610: pointer.struct.ASN1_VALUE_st */
            	1615, 0,
            0, 0, 0, /* 1615: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1618: pointer.struct.X509_name_st */
            	1623, 0,
            0, 40, 3, /* 1623: struct.X509_name_st */
            	1632, 0,
            	1656, 16,
            	228, 24,
            1, 8, 1, /* 1632: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1637, 0,
            0, 32, 2, /* 1637: struct.stack_st_fake_X509_NAME_ENTRY */
            	1644, 8,
            	475, 24,
            64099, 8, 2, /* 1644: pointer_to_array_of_pointers_to_stack */
            	1651, 0,
            	472, 20,
            0, 8, 1, /* 1651: pointer.X509_NAME_ENTRY */
            	436, 0,
            1, 8, 1, /* 1656: pointer.struct.buf_mem_st */
            	1661, 0,
            0, 24, 1, /* 1661: struct.buf_mem_st */
            	64, 8,
            1, 8, 1, /* 1666: pointer.struct.EDIPartyName_st */
            	1671, 0,
            0, 16, 2, /* 1671: struct.EDIPartyName_st */
            	1530, 0,
            	1530, 8,
            1, 8, 1, /* 1678: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1683, 0,
            0, 32, 2, /* 1683: struct.stack_st_fake_X509_NAME_ENTRY */
            	1690, 8,
            	475, 24,
            64099, 8, 2, /* 1690: pointer_to_array_of_pointers_to_stack */
            	1697, 0,
            	472, 20,
            0, 8, 1, /* 1697: pointer.X509_NAME_ENTRY */
            	436, 0,
            1, 8, 1, /* 1702: pointer.struct.X509_name_st */
            	1707, 0,
            0, 40, 3, /* 1707: struct.X509_name_st */
            	1678, 0,
            	1716, 16,
            	228, 24,
            1, 8, 1, /* 1716: pointer.struct.buf_mem_st */
            	1721, 0,
            0, 24, 1, /* 1721: struct.buf_mem_st */
            	64, 8,
            1, 8, 1, /* 1726: pointer.struct.asn1_string_st */
            	1731, 0,
            0, 24, 1, /* 1731: struct.asn1_string_st */
            	228, 8,
            1, 8, 1, /* 1736: pointer.struct.stack_st_GENERAL_NAME */
            	1741, 0,
            0, 32, 2, /* 1741: struct.stack_st_fake_GENERAL_NAME */
            	1748, 8,
            	475, 24,
            64099, 8, 2, /* 1748: pointer_to_array_of_pointers_to_stack */
            	1755, 0,
            	472, 20,
            0, 8, 1, /* 1755: pointer.GENERAL_NAME */
            	1408, 0,
            1, 8, 1, /* 1760: pointer.struct.NAME_CONSTRAINTS_st */
            	1765, 0,
            0, 0, 0, /* 1765: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 1768: pointer.struct.x509_cert_aux_st */
            	1773, 0,
            0, 40, 5, /* 1773: struct.x509_cert_aux_st */
            	1786, 0,
            	1786, 8,
            	385, 16,
            	335, 24,
            	1824, 32,
            1, 8, 1, /* 1786: pointer.struct.stack_st_ASN1_OBJECT */
            	1791, 0,
            0, 32, 2, /* 1791: struct.stack_st_fake_ASN1_OBJECT */
            	1798, 8,
            	475, 24,
            64099, 8, 2, /* 1798: pointer_to_array_of_pointers_to_stack */
            	1805, 0,
            	472, 20,
            0, 8, 1, /* 1805: pointer.ASN1_OBJECT */
            	1810, 0,
            0, 0, 1, /* 1810: ASN1_OBJECT */
            	1815, 0,
            0, 40, 3, /* 1815: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	262, 24,
            1, 8, 1, /* 1824: pointer.struct.stack_st_X509_ALGOR */
            	1829, 0,
            0, 32, 2, /* 1829: struct.stack_st_fake_X509_ALGOR */
            	1836, 8,
            	475, 24,
            64099, 8, 2, /* 1836: pointer_to_array_of_pointers_to_stack */
            	1843, 0,
            	472, 20,
            0, 8, 1, /* 1843: pointer.X509_ALGOR */
            	1848, 0,
            0, 0, 1, /* 1848: X509_ALGOR */
            	1853, 0,
            0, 16, 2, /* 1853: struct.X509_algor_st */
            	1860, 0,
            	1874, 8,
            1, 8, 1, /* 1860: pointer.struct.asn1_object_st */
            	1865, 0,
            0, 40, 3, /* 1865: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	262, 24,
            1, 8, 1, /* 1874: pointer.struct.asn1_type_st */
            	1879, 0,
            0, 16, 1, /* 1879: struct.asn1_type_st */
            	1884, 8,
            0, 8, 20, /* 1884: union.unknown */
            	64, 0,
            	1927, 0,
            	1860, 0,
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
            	1997, 0,
            	2002, 0,
            	1927, 0,
            	1927, 0,
            	1238, 0,
            1, 8, 1, /* 1927: pointer.struct.asn1_string_st */
            	1932, 0,
            0, 24, 1, /* 1932: struct.asn1_string_st */
            	228, 8,
            1, 8, 1, /* 1937: pointer.struct.asn1_string_st */
            	1932, 0,
            1, 8, 1, /* 1942: pointer.struct.asn1_string_st */
            	1932, 0,
            1, 8, 1, /* 1947: pointer.struct.asn1_string_st */
            	1932, 0,
            1, 8, 1, /* 1952: pointer.struct.asn1_string_st */
            	1932, 0,
            1, 8, 1, /* 1957: pointer.struct.asn1_string_st */
            	1932, 0,
            1, 8, 1, /* 1962: pointer.struct.asn1_string_st */
            	1932, 0,
            1, 8, 1, /* 1967: pointer.struct.asn1_string_st */
            	1932, 0,
            1, 8, 1, /* 1972: pointer.struct.asn1_string_st */
            	1932, 0,
            1, 8, 1, /* 1977: pointer.struct.asn1_string_st */
            	1932, 0,
            1, 8, 1, /* 1982: pointer.struct.asn1_string_st */
            	1932, 0,
            1, 8, 1, /* 1987: pointer.struct.asn1_string_st */
            	1932, 0,
            1, 8, 1, /* 1992: pointer.struct.asn1_string_st */
            	1932, 0,
            1, 8, 1, /* 1997: pointer.struct.asn1_string_st */
            	1932, 0,
            1, 8, 1, /* 2002: pointer.struct.asn1_string_st */
            	1932, 0,
            1, 8, 1, /* 2007: pointer.struct.env_md_st */
            	2012, 0,
            0, 120, 8, /* 2012: struct.env_md_st */
            	2031, 24,
            	2034, 32,
            	2037, 40,
            	2040, 48,
            	2031, 56,
            	2043, 64,
            	2046, 72,
            	2049, 112,
            64097, 8, 0, /* 2031: pointer.func */
            64097, 8, 0, /* 2034: pointer.func */
            64097, 8, 0, /* 2037: pointer.func */
            64097, 8, 0, /* 2040: pointer.func */
            64097, 8, 0, /* 2043: pointer.func */
            64097, 8, 0, /* 2046: pointer.func */
            64097, 8, 0, /* 2049: pointer.func */
            1, 8, 1, /* 2052: pointer.struct.rsa_st */
            	569, 0,
            1, 8, 1, /* 2057: pointer.struct.dh_st */
            	796, 0,
            1, 8, 1, /* 2062: pointer.struct.ec_key_st */
            	864, 0,
            0, 24, 1, /* 2067: struct.buf_mem_st */
            	64, 8,
            0, 40, 3, /* 2072: struct.X509_name_st */
            	2081, 0,
            	2105, 16,
            	228, 24,
            1, 8, 1, /* 2081: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2086, 0,
            0, 32, 2, /* 2086: struct.stack_st_fake_X509_NAME_ENTRY */
            	2093, 8,
            	475, 24,
            64099, 8, 2, /* 2093: pointer_to_array_of_pointers_to_stack */
            	2100, 0,
            	472, 20,
            0, 8, 1, /* 2100: pointer.X509_NAME_ENTRY */
            	436, 0,
            1, 8, 1, /* 2105: pointer.struct.buf_mem_st */
            	2067, 0,
            64097, 8, 0, /* 2110: pointer.func */
            64097, 8, 0, /* 2113: pointer.func */
            64097, 8, 0, /* 2116: pointer.func */
            1, 8, 1, /* 2119: pointer.struct.stack_st_SSL_COMP */
            	2124, 0,
            0, 32, 2, /* 2124: struct.stack_st_fake_SSL_COMP */
            	2131, 8,
            	475, 24,
            64099, 8, 2, /* 2131: pointer_to_array_of_pointers_to_stack */
            	2138, 0,
            	472, 20,
            0, 8, 1, /* 2138: pointer.SSL_COMP */
            	2143, 0,
            0, 0, 1, /* 2143: SSL_COMP */
            	2148, 0,
            0, 24, 2, /* 2148: struct.ssl_comp_st */
            	13, 8,
            	2155, 16,
            1, 8, 1, /* 2155: pointer.struct.comp_method_st */
            	2160, 0,
            0, 64, 7, /* 2160: struct.comp_method_st */
            	13, 8,
            	2116, 16,
            	2177, 24,
            	2113, 32,
            	2113, 40,
            	2180, 48,
            	2180, 56,
            64097, 8, 0, /* 2177: pointer.func */
            64097, 8, 0, /* 2180: pointer.func */
            64097, 8, 0, /* 2183: pointer.func */
            64097, 8, 0, /* 2186: pointer.func */
            0, 88, 1, /* 2189: struct.ssl_cipher_st */
            	13, 8,
            1, 8, 1, /* 2194: pointer.struct.ssl_cipher_st */
            	2189, 0,
            0, 16, 1, /* 2199: struct.crypto_ex_data_st */
            	2204, 0,
            1, 8, 1, /* 2204: pointer.struct.stack_st_void */
            	2209, 0,
            0, 32, 1, /* 2209: struct.stack_st_void */
            	2214, 0,
            0, 32, 2, /* 2214: struct.stack_st */
            	683, 8,
            	475, 24,
            0, 136, 11, /* 2221: struct.dsa_st */
            	2246, 24,
            	2246, 32,
            	2246, 40,
            	2246, 48,
            	2246, 56,
            	2246, 64,
            	2246, 72,
            	2256, 88,
            	2199, 104,
            	2270, 120,
            	2321, 128,
            1, 8, 1, /* 2246: pointer.struct.bignum_st */
            	2251, 0,
            0, 24, 1, /* 2251: struct.bignum_st */
            	79, 0,
            1, 8, 1, /* 2256: pointer.struct.bn_mont_ctx_st */
            	2261, 0,
            0, 96, 3, /* 2261: struct.bn_mont_ctx_st */
            	2251, 8,
            	2251, 32,
            	2251, 56,
            1, 8, 1, /* 2270: pointer.struct.dsa_method */
            	2275, 0,
            0, 96, 11, /* 2275: struct.dsa_method */
            	13, 0,
            	2300, 8,
            	2303, 16,
            	2306, 24,
            	2309, 32,
            	2312, 40,
            	2315, 48,
            	2315, 56,
            	64, 72,
            	2318, 80,
            	2315, 88,
            64097, 8, 0, /* 2300: pointer.func */
            64097, 8, 0, /* 2303: pointer.func */
            64097, 8, 0, /* 2306: pointer.func */
            64097, 8, 0, /* 2309: pointer.func */
            64097, 8, 0, /* 2312: pointer.func */
            64097, 8, 0, /* 2315: pointer.func */
            64097, 8, 0, /* 2318: pointer.func */
            1, 8, 1, /* 2321: pointer.struct.engine_st */
            	2326, 0,
            0, 0, 0, /* 2326: struct.engine_st */
            1, 8, 1, /* 2329: pointer.struct.cert_st */
            	125, 0,
            1, 8, 1, /* 2334: pointer.struct.X509_algor_st */
            	2339, 0,
            0, 16, 2, /* 2339: struct.X509_algor_st */
            	2346, 0,
            	2360, 8,
            1, 8, 1, /* 2346: pointer.struct.asn1_object_st */
            	2351, 0,
            0, 40, 3, /* 2351: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	262, 24,
            1, 8, 1, /* 2360: pointer.struct.asn1_type_st */
            	2365, 0,
            0, 16, 1, /* 2365: struct.asn1_type_st */
            	2370, 8,
            0, 8, 20, /* 2370: union.unknown */
            	64, 0,
            	2413, 0,
            	2346, 0,
            	2423, 0,
            	2428, 0,
            	2433, 0,
            	2438, 0,
            	2443, 0,
            	2448, 0,
            	2453, 0,
            	2458, 0,
            	2463, 0,
            	2468, 0,
            	2473, 0,
            	2478, 0,
            	2483, 0,
            	2488, 0,
            	2413, 0,
            	2413, 0,
            	1238, 0,
            1, 8, 1, /* 2413: pointer.struct.asn1_string_st */
            	2418, 0,
            0, 24, 1, /* 2418: struct.asn1_string_st */
            	228, 8,
            1, 8, 1, /* 2423: pointer.struct.asn1_string_st */
            	2418, 0,
            1, 8, 1, /* 2428: pointer.struct.asn1_string_st */
            	2418, 0,
            1, 8, 1, /* 2433: pointer.struct.asn1_string_st */
            	2418, 0,
            1, 8, 1, /* 2438: pointer.struct.asn1_string_st */
            	2418, 0,
            1, 8, 1, /* 2443: pointer.struct.asn1_string_st */
            	2418, 0,
            1, 8, 1, /* 2448: pointer.struct.asn1_string_st */
            	2418, 0,
            1, 8, 1, /* 2453: pointer.struct.asn1_string_st */
            	2418, 0,
            1, 8, 1, /* 2458: pointer.struct.asn1_string_st */
            	2418, 0,
            1, 8, 1, /* 2463: pointer.struct.asn1_string_st */
            	2418, 0,
            1, 8, 1, /* 2468: pointer.struct.asn1_string_st */
            	2418, 0,
            1, 8, 1, /* 2473: pointer.struct.asn1_string_st */
            	2418, 0,
            1, 8, 1, /* 2478: pointer.struct.asn1_string_st */
            	2418, 0,
            1, 8, 1, /* 2483: pointer.struct.asn1_string_st */
            	2418, 0,
            1, 8, 1, /* 2488: pointer.struct.asn1_string_st */
            	2418, 0,
            1, 8, 1, /* 2493: pointer.struct.stack_st_DIST_POINT */
            	2498, 0,
            0, 32, 2, /* 2498: struct.stack_st_fake_DIST_POINT */
            	2505, 8,
            	475, 24,
            64099, 8, 2, /* 2505: pointer_to_array_of_pointers_to_stack */
            	2512, 0,
            	472, 20,
            0, 8, 1, /* 2512: pointer.DIST_POINT */
            	1351, 0,
            1, 8, 1, /* 2517: pointer.struct.X509_POLICY_CACHE_st */
            	2522, 0,
            0, 0, 0, /* 2522: struct.X509_POLICY_CACHE_st */
            0, 0, 0, /* 2525: struct.ec_key_st */
            1, 8, 1, /* 2528: pointer.struct.AUTHORITY_KEYID_st */
            	2533, 0,
            0, 0, 0, /* 2533: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 2536: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	2541, 0,
            0, 32, 2, /* 2541: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	2548, 8,
            	475, 24,
            64099, 8, 2, /* 2548: pointer_to_array_of_pointers_to_stack */
            	2555, 0,
            	472, 20,
            0, 8, 1, /* 2555: pointer.SRTP_PROTECTION_PROFILE */
            	3, 0,
            64097, 8, 0, /* 2560: pointer.func */
            64097, 8, 0, /* 2563: pointer.func */
            1, 8, 1, /* 2566: pointer.struct.X509_pubkey_st */
            	2571, 0,
            0, 24, 3, /* 2571: struct.X509_pubkey_st */
            	2580, 0,
            	2679, 8,
            	2747, 16,
            1, 8, 1, /* 2580: pointer.struct.X509_algor_st */
            	2585, 0,
            0, 16, 2, /* 2585: struct.X509_algor_st */
            	2592, 0,
            	2606, 8,
            1, 8, 1, /* 2592: pointer.struct.asn1_object_st */
            	2597, 0,
            0, 40, 3, /* 2597: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	262, 24,
            1, 8, 1, /* 2606: pointer.struct.asn1_type_st */
            	2611, 0,
            0, 16, 1, /* 2611: struct.asn1_type_st */
            	2616, 8,
            0, 8, 20, /* 2616: union.unknown */
            	64, 0,
            	2659, 0,
            	2592, 0,
            	2669, 0,
            	2674, 0,
            	2679, 0,
            	2684, 0,
            	2689, 0,
            	2694, 0,
            	2699, 0,
            	2704, 0,
            	2709, 0,
            	2714, 0,
            	2719, 0,
            	2724, 0,
            	2729, 0,
            	2734, 0,
            	2659, 0,
            	2659, 0,
            	2739, 0,
            1, 8, 1, /* 2659: pointer.struct.asn1_string_st */
            	2664, 0,
            0, 24, 1, /* 2664: struct.asn1_string_st */
            	228, 8,
            1, 8, 1, /* 2669: pointer.struct.asn1_string_st */
            	2664, 0,
            1, 8, 1, /* 2674: pointer.struct.asn1_string_st */
            	2664, 0,
            1, 8, 1, /* 2679: pointer.struct.asn1_string_st */
            	2664, 0,
            1, 8, 1, /* 2684: pointer.struct.asn1_string_st */
            	2664, 0,
            1, 8, 1, /* 2689: pointer.struct.asn1_string_st */
            	2664, 0,
            1, 8, 1, /* 2694: pointer.struct.asn1_string_st */
            	2664, 0,
            1, 8, 1, /* 2699: pointer.struct.asn1_string_st */
            	2664, 0,
            1, 8, 1, /* 2704: pointer.struct.asn1_string_st */
            	2664, 0,
            1, 8, 1, /* 2709: pointer.struct.asn1_string_st */
            	2664, 0,
            1, 8, 1, /* 2714: pointer.struct.asn1_string_st */
            	2664, 0,
            1, 8, 1, /* 2719: pointer.struct.asn1_string_st */
            	2664, 0,
            1, 8, 1, /* 2724: pointer.struct.asn1_string_st */
            	2664, 0,
            1, 8, 1, /* 2729: pointer.struct.asn1_string_st */
            	2664, 0,
            1, 8, 1, /* 2734: pointer.struct.asn1_string_st */
            	2664, 0,
            1, 8, 1, /* 2739: pointer.struct.ASN1_VALUE_st */
            	2744, 0,
            0, 0, 0, /* 2744: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2747: pointer.struct.evp_pkey_st */
            	2752, 0,
            0, 56, 4, /* 2752: struct.evp_pkey_st */
            	2763, 16,
            	2771, 24,
            	2779, 32,
            	3097, 48,
            1, 8, 1, /* 2763: pointer.struct.evp_pkey_asn1_method_st */
            	2768, 0,
            0, 0, 0, /* 2768: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 2771: pointer.struct.engine_st */
            	2776, 0,
            0, 0, 0, /* 2776: struct.engine_st */
            0, 8, 5, /* 2779: union.unknown */
            	64, 0,
            	2792, 0,
            	2943, 0,
            	3021, 0,
            	3089, 0,
            1, 8, 1, /* 2792: pointer.struct.rsa_st */
            	2797, 0,
            0, 168, 17, /* 2797: struct.rsa_st */
            	2834, 16,
            	2771, 24,
            	2889, 32,
            	2889, 40,
            	2889, 48,
            	2889, 56,
            	2889, 64,
            	2889, 72,
            	2889, 80,
            	2889, 88,
            	2899, 96,
            	2921, 120,
            	2921, 128,
            	2921, 136,
            	64, 144,
            	2935, 152,
            	2935, 160,
            1, 8, 1, /* 2834: pointer.struct.rsa_meth_st */
            	2839, 0,
            0, 112, 13, /* 2839: struct.rsa_meth_st */
            	13, 0,
            	2868, 8,
            	2868, 16,
            	2868, 24,
            	2868, 32,
            	2871, 40,
            	2874, 48,
            	2877, 56,
            	2877, 64,
            	64, 80,
            	2880, 88,
            	2883, 96,
            	2886, 104,
            64097, 8, 0, /* 2868: pointer.func */
            64097, 8, 0, /* 2871: pointer.func */
            64097, 8, 0, /* 2874: pointer.func */
            64097, 8, 0, /* 2877: pointer.func */
            64097, 8, 0, /* 2880: pointer.func */
            64097, 8, 0, /* 2883: pointer.func */
            64097, 8, 0, /* 2886: pointer.func */
            1, 8, 1, /* 2889: pointer.struct.bignum_st */
            	2894, 0,
            0, 24, 1, /* 2894: struct.bignum_st */
            	79, 0,
            0, 16, 1, /* 2899: struct.crypto_ex_data_st */
            	2904, 0,
            1, 8, 1, /* 2904: pointer.struct.stack_st_void */
            	2909, 0,
            0, 32, 1, /* 2909: struct.stack_st_void */
            	2914, 0,
            0, 32, 2, /* 2914: struct.stack_st */
            	683, 8,
            	475, 24,
            1, 8, 1, /* 2921: pointer.struct.bn_mont_ctx_st */
            	2926, 0,
            0, 96, 3, /* 2926: struct.bn_mont_ctx_st */
            	2894, 8,
            	2894, 32,
            	2894, 56,
            1, 8, 1, /* 2935: pointer.struct.bn_blinding_st */
            	2940, 0,
            0, 0, 0, /* 2940: struct.bn_blinding_st */
            1, 8, 1, /* 2943: pointer.struct.dsa_st */
            	2948, 0,
            0, 136, 11, /* 2948: struct.dsa_st */
            	2889, 24,
            	2889, 32,
            	2889, 40,
            	2889, 48,
            	2889, 56,
            	2889, 64,
            	2889, 72,
            	2921, 88,
            	2899, 104,
            	2973, 120,
            	2771, 128,
            1, 8, 1, /* 2973: pointer.struct.dsa_method */
            	2978, 0,
            0, 96, 11, /* 2978: struct.dsa_method */
            	13, 0,
            	3003, 8,
            	3006, 16,
            	3009, 24,
            	2563, 32,
            	3012, 40,
            	3015, 48,
            	3015, 56,
            	64, 72,
            	3018, 80,
            	3015, 88,
            64097, 8, 0, /* 3003: pointer.func */
            64097, 8, 0, /* 3006: pointer.func */
            64097, 8, 0, /* 3009: pointer.func */
            64097, 8, 0, /* 3012: pointer.func */
            64097, 8, 0, /* 3015: pointer.func */
            64097, 8, 0, /* 3018: pointer.func */
            1, 8, 1, /* 3021: pointer.struct.dh_st */
            	3026, 0,
            0, 144, 12, /* 3026: struct.dh_st */
            	2889, 8,
            	2889, 16,
            	2889, 32,
            	2889, 40,
            	2921, 56,
            	2889, 64,
            	2889, 72,
            	228, 80,
            	2889, 96,
            	2899, 112,
            	3053, 128,
            	2771, 136,
            1, 8, 1, /* 3053: pointer.struct.dh_method */
            	3058, 0,
            0, 72, 8, /* 3058: struct.dh_method */
            	13, 0,
            	3077, 8,
            	3080, 16,
            	3083, 24,
            	3077, 32,
            	3077, 40,
            	64, 56,
            	3086, 64,
            64097, 8, 0, /* 3077: pointer.func */
            64097, 8, 0, /* 3080: pointer.func */
            64097, 8, 0, /* 3083: pointer.func */
            64097, 8, 0, /* 3086: pointer.func */
            1, 8, 1, /* 3089: pointer.struct.ec_key_st */
            	3094, 0,
            0, 0, 0, /* 3094: struct.ec_key_st */
            1, 8, 1, /* 3097: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3102, 0,
            0, 32, 2, /* 3102: struct.stack_st_fake_X509_ATTRIBUTE */
            	3109, 8,
            	475, 24,
            64099, 8, 2, /* 3109: pointer_to_array_of_pointers_to_stack */
            	3116, 0,
            	472, 20,
            0, 8, 1, /* 3116: pointer.X509_ATTRIBUTE */
            	891, 0,
            0, 0, 1, /* 3121: X509_OBJECT */
            	3126, 0,
            0, 16, 1, /* 3126: struct.x509_object_st */
            	3131, 8,
            0, 8, 4, /* 3131: union.unknown */
            	64, 0,
            	3142, 0,
            	3654, 0,
            	3283, 0,
            1, 8, 1, /* 3142: pointer.struct.x509_st */
            	3147, 0,
            0, 184, 12, /* 3147: struct.x509_st */
            	3174, 0,
            	2334, 8,
            	2433, 16,
            	64, 32,
            	2199, 40,
            	2438, 104,
            	2528, 112,
            	2517, 120,
            	2493, 128,
            	3556, 136,
            	3580, 144,
            	3588, 176,
            1, 8, 1, /* 3174: pointer.struct.x509_cinf_st */
            	3179, 0,
            0, 104, 11, /* 3179: struct.x509_cinf_st */
            	2423, 0,
            	2423, 8,
            	2334, 16,
            	3204, 24,
            	3252, 32,
            	3204, 40,
            	3269, 48,
            	2433, 56,
            	2433, 64,
            	3527, 72,
            	3551, 80,
            1, 8, 1, /* 3204: pointer.struct.X509_name_st */
            	3209, 0,
            0, 40, 3, /* 3209: struct.X509_name_st */
            	3218, 0,
            	3242, 16,
            	228, 24,
            1, 8, 1, /* 3218: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3223, 0,
            0, 32, 2, /* 3223: struct.stack_st_fake_X509_NAME_ENTRY */
            	3230, 8,
            	475, 24,
            64099, 8, 2, /* 3230: pointer_to_array_of_pointers_to_stack */
            	3237, 0,
            	472, 20,
            0, 8, 1, /* 3237: pointer.X509_NAME_ENTRY */
            	436, 0,
            1, 8, 1, /* 3242: pointer.struct.buf_mem_st */
            	3247, 0,
            0, 24, 1, /* 3247: struct.buf_mem_st */
            	64, 8,
            1, 8, 1, /* 3252: pointer.struct.X509_val_st */
            	3257, 0,
            0, 16, 2, /* 3257: struct.X509_val_st */
            	3264, 0,
            	3264, 8,
            1, 8, 1, /* 3264: pointer.struct.asn1_string_st */
            	2418, 0,
            1, 8, 1, /* 3269: pointer.struct.X509_pubkey_st */
            	3274, 0,
            0, 24, 3, /* 3274: struct.X509_pubkey_st */
            	2334, 0,
            	2433, 8,
            	3283, 16,
            1, 8, 1, /* 3283: pointer.struct.evp_pkey_st */
            	3288, 0,
            0, 56, 4, /* 3288: struct.evp_pkey_st */
            	3299, 16,
            	2321, 24,
            	3307, 32,
            	3503, 48,
            1, 8, 1, /* 3299: pointer.struct.evp_pkey_asn1_method_st */
            	3304, 0,
            0, 0, 0, /* 3304: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 3307: union.unknown */
            	64, 0,
            	3320, 0,
            	3425, 0,
            	3430, 0,
            	3498, 0,
            1, 8, 1, /* 3320: pointer.struct.rsa_st */
            	3325, 0,
            0, 168, 17, /* 3325: struct.rsa_st */
            	3362, 16,
            	2321, 24,
            	2246, 32,
            	2246, 40,
            	2246, 48,
            	2246, 56,
            	2246, 64,
            	2246, 72,
            	2246, 80,
            	2246, 88,
            	2199, 96,
            	2256, 120,
            	2256, 128,
            	2256, 136,
            	64, 144,
            	3417, 152,
            	3417, 160,
            1, 8, 1, /* 3362: pointer.struct.rsa_meth_st */
            	3367, 0,
            0, 112, 13, /* 3367: struct.rsa_meth_st */
            	13, 0,
            	3396, 8,
            	3396, 16,
            	3396, 24,
            	3396, 32,
            	3399, 40,
            	3402, 48,
            	3405, 56,
            	3405, 64,
            	64, 80,
            	3408, 88,
            	3411, 96,
            	3414, 104,
            64097, 8, 0, /* 3396: pointer.func */
            64097, 8, 0, /* 3399: pointer.func */
            64097, 8, 0, /* 3402: pointer.func */
            64097, 8, 0, /* 3405: pointer.func */
            64097, 8, 0, /* 3408: pointer.func */
            64097, 8, 0, /* 3411: pointer.func */
            64097, 8, 0, /* 3414: pointer.func */
            1, 8, 1, /* 3417: pointer.struct.bn_blinding_st */
            	3422, 0,
            0, 0, 0, /* 3422: struct.bn_blinding_st */
            1, 8, 1, /* 3425: pointer.struct.dsa_st */
            	2221, 0,
            1, 8, 1, /* 3430: pointer.struct.dh_st */
            	3435, 0,
            0, 144, 12, /* 3435: struct.dh_st */
            	2246, 8,
            	2246, 16,
            	2246, 32,
            	2246, 40,
            	2256, 56,
            	2246, 64,
            	2246, 72,
            	228, 80,
            	2246, 96,
            	2199, 112,
            	3462, 128,
            	2321, 136,
            1, 8, 1, /* 3462: pointer.struct.dh_method */
            	3467, 0,
            0, 72, 8, /* 3467: struct.dh_method */
            	13, 0,
            	3486, 8,
            	3489, 16,
            	3492, 24,
            	3486, 32,
            	3486, 40,
            	64, 56,
            	3495, 64,
            64097, 8, 0, /* 3486: pointer.func */
            64097, 8, 0, /* 3489: pointer.func */
            64097, 8, 0, /* 3492: pointer.func */
            64097, 8, 0, /* 3495: pointer.func */
            1, 8, 1, /* 3498: pointer.struct.ec_key_st */
            	2525, 0,
            1, 8, 1, /* 3503: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3508, 0,
            0, 32, 2, /* 3508: struct.stack_st_fake_X509_ATTRIBUTE */
            	3515, 8,
            	475, 24,
            64099, 8, 2, /* 3515: pointer_to_array_of_pointers_to_stack */
            	3522, 0,
            	472, 20,
            0, 8, 1, /* 3522: pointer.X509_ATTRIBUTE */
            	891, 0,
            1, 8, 1, /* 3527: pointer.struct.stack_st_X509_EXTENSION */
            	3532, 0,
            0, 32, 2, /* 3532: struct.stack_st_fake_X509_EXTENSION */
            	3539, 8,
            	475, 24,
            64099, 8, 2, /* 3539: pointer_to_array_of_pointers_to_stack */
            	3546, 0,
            	472, 20,
            0, 8, 1, /* 3546: pointer.X509_EXTENSION */
            	1270, 0,
            0, 24, 1, /* 3551: struct.ASN1_ENCODING_st */
            	228, 0,
            1, 8, 1, /* 3556: pointer.struct.stack_st_GENERAL_NAME */
            	3561, 0,
            0, 32, 2, /* 3561: struct.stack_st_fake_GENERAL_NAME */
            	3568, 8,
            	475, 24,
            64099, 8, 2, /* 3568: pointer_to_array_of_pointers_to_stack */
            	3575, 0,
            	472, 20,
            0, 8, 1, /* 3575: pointer.GENERAL_NAME */
            	1408, 0,
            1, 8, 1, /* 3580: pointer.struct.NAME_CONSTRAINTS_st */
            	3585, 0,
            0, 0, 0, /* 3585: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3588: pointer.struct.x509_cert_aux_st */
            	3593, 0,
            0, 40, 5, /* 3593: struct.x509_cert_aux_st */
            	3606, 0,
            	3606, 8,
            	2488, 16,
            	2438, 24,
            	3630, 32,
            1, 8, 1, /* 3606: pointer.struct.stack_st_ASN1_OBJECT */
            	3611, 0,
            0, 32, 2, /* 3611: struct.stack_st_fake_ASN1_OBJECT */
            	3618, 8,
            	475, 24,
            64099, 8, 2, /* 3618: pointer_to_array_of_pointers_to_stack */
            	3625, 0,
            	472, 20,
            0, 8, 1, /* 3625: pointer.ASN1_OBJECT */
            	1810, 0,
            1, 8, 1, /* 3630: pointer.struct.stack_st_X509_ALGOR */
            	3635, 0,
            0, 32, 2, /* 3635: struct.stack_st_fake_X509_ALGOR */
            	3642, 8,
            	475, 24,
            64099, 8, 2, /* 3642: pointer_to_array_of_pointers_to_stack */
            	3649, 0,
            	472, 20,
            0, 8, 1, /* 3649: pointer.X509_ALGOR */
            	1848, 0,
            1, 8, 1, /* 3654: pointer.struct.X509_crl_st */
            	3659, 0,
            0, 120, 10, /* 3659: struct.X509_crl_st */
            	3682, 0,
            	2334, 8,
            	2433, 16,
            	2528, 32,
            	3809, 40,
            	2423, 56,
            	2423, 64,
            	3817, 96,
            	3858, 104,
            	52, 112,
            1, 8, 1, /* 3682: pointer.struct.X509_crl_info_st */
            	3687, 0,
            0, 80, 8, /* 3687: struct.X509_crl_info_st */
            	2423, 0,
            	2334, 8,
            	3204, 16,
            	3264, 24,
            	3264, 32,
            	3706, 40,
            	3527, 48,
            	3551, 56,
            1, 8, 1, /* 3706: pointer.struct.stack_st_X509_REVOKED */
            	3711, 0,
            0, 32, 2, /* 3711: struct.stack_st_fake_X509_REVOKED */
            	3718, 8,
            	475, 24,
            64099, 8, 2, /* 3718: pointer_to_array_of_pointers_to_stack */
            	3725, 0,
            	472, 20,
            0, 8, 1, /* 3725: pointer.X509_REVOKED */
            	3730, 0,
            0, 0, 1, /* 3730: X509_REVOKED */
            	3735, 0,
            0, 40, 4, /* 3735: struct.x509_revoked_st */
            	3746, 0,
            	3756, 8,
            	3761, 16,
            	3785, 24,
            1, 8, 1, /* 3746: pointer.struct.asn1_string_st */
            	3751, 0,
            0, 24, 1, /* 3751: struct.asn1_string_st */
            	228, 8,
            1, 8, 1, /* 3756: pointer.struct.asn1_string_st */
            	3751, 0,
            1, 8, 1, /* 3761: pointer.struct.stack_st_X509_EXTENSION */
            	3766, 0,
            0, 32, 2, /* 3766: struct.stack_st_fake_X509_EXTENSION */
            	3773, 8,
            	475, 24,
            64099, 8, 2, /* 3773: pointer_to_array_of_pointers_to_stack */
            	3780, 0,
            	472, 20,
            0, 8, 1, /* 3780: pointer.X509_EXTENSION */
            	1270, 0,
            1, 8, 1, /* 3785: pointer.struct.stack_st_GENERAL_NAME */
            	3790, 0,
            0, 32, 2, /* 3790: struct.stack_st_fake_GENERAL_NAME */
            	3797, 8,
            	475, 24,
            64099, 8, 2, /* 3797: pointer_to_array_of_pointers_to_stack */
            	3804, 0,
            	472, 20,
            0, 8, 1, /* 3804: pointer.GENERAL_NAME */
            	1408, 0,
            1, 8, 1, /* 3809: pointer.struct.ISSUING_DIST_POINT_st */
            	3814, 0,
            0, 0, 0, /* 3814: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 3817: pointer.struct.stack_st_GENERAL_NAMES */
            	3822, 0,
            0, 32, 2, /* 3822: struct.stack_st_fake_GENERAL_NAMES */
            	3829, 8,
            	475, 24,
            64099, 8, 2, /* 3829: pointer_to_array_of_pointers_to_stack */
            	3836, 0,
            	472, 20,
            0, 8, 1, /* 3836: pointer.GENERAL_NAMES */
            	3841, 0,
            0, 0, 1, /* 3841: GENERAL_NAMES */
            	3846, 0,
            0, 32, 1, /* 3846: struct.stack_st_GENERAL_NAME */
            	3851, 0,
            0, 32, 2, /* 3851: struct.stack_st */
            	683, 8,
            	475, 24,
            1, 8, 1, /* 3858: pointer.struct.x509_crl_method_st */
            	3863, 0,
            0, 0, 0, /* 3863: struct.x509_crl_method_st */
            64097, 8, 0, /* 3866: pointer.func */
            64097, 8, 0, /* 3869: pointer.func */
            0, 104, 11, /* 3872: struct.x509_cinf_st */
            	2669, 0,
            	2669, 8,
            	2580, 16,
            	3897, 24,
            	3945, 32,
            	3897, 40,
            	2566, 48,
            	2679, 56,
            	2679, 64,
            	3962, 72,
            	3986, 80,
            1, 8, 1, /* 3897: pointer.struct.X509_name_st */
            	3902, 0,
            0, 40, 3, /* 3902: struct.X509_name_st */
            	3911, 0,
            	3935, 16,
            	228, 24,
            1, 8, 1, /* 3911: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3916, 0,
            0, 32, 2, /* 3916: struct.stack_st_fake_X509_NAME_ENTRY */
            	3923, 8,
            	475, 24,
            64099, 8, 2, /* 3923: pointer_to_array_of_pointers_to_stack */
            	3930, 0,
            	472, 20,
            0, 8, 1, /* 3930: pointer.X509_NAME_ENTRY */
            	436, 0,
            1, 8, 1, /* 3935: pointer.struct.buf_mem_st */
            	3940, 0,
            0, 24, 1, /* 3940: struct.buf_mem_st */
            	64, 8,
            1, 8, 1, /* 3945: pointer.struct.X509_val_st */
            	3950, 0,
            0, 16, 2, /* 3950: struct.X509_val_st */
            	3957, 0,
            	3957, 8,
            1, 8, 1, /* 3957: pointer.struct.asn1_string_st */
            	2664, 0,
            1, 8, 1, /* 3962: pointer.struct.stack_st_X509_EXTENSION */
            	3967, 0,
            0, 32, 2, /* 3967: struct.stack_st_fake_X509_EXTENSION */
            	3974, 8,
            	475, 24,
            64099, 8, 2, /* 3974: pointer_to_array_of_pointers_to_stack */
            	3981, 0,
            	472, 20,
            0, 8, 1, /* 3981: pointer.X509_EXTENSION */
            	1270, 0,
            0, 24, 1, /* 3986: struct.ASN1_ENCODING_st */
            	228, 0,
            0, 0, 0, /* 3991: struct.X509_POLICY_CACHE_st */
            64097, 8, 0, /* 3994: pointer.func */
            64097, 8, 0, /* 3997: pointer.func */
            0, 0, 0, /* 4000: struct.NAME_CONSTRAINTS_st */
            64097, 8, 0, /* 4003: pointer.func */
            0, 0, 1, /* 4006: SSL_CIPHER */
            	4011, 0,
            0, 88, 1, /* 4011: struct.ssl_cipher_st */
            	13, 8,
            0, 352, 14, /* 4016: struct.ssl_session_st */
            	64, 144,
            	64, 152,
            	4047, 168,
            	156, 176,
            	2194, 224,
            	4258, 240,
            	661, 248,
            	4282, 264,
            	4282, 272,
            	64, 280,
            	228, 296,
            	228, 312,
            	228, 320,
            	64, 344,
            1, 8, 1, /* 4047: pointer.struct.sess_cert_st */
            	4052, 0,
            0, 248, 5, /* 4052: struct.sess_cert_st */
            	4065, 0,
            	142, 16,
            	2052, 216,
            	2057, 224,
            	2062, 232,
            1, 8, 1, /* 4065: pointer.struct.stack_st_X509 */
            	4070, 0,
            0, 32, 2, /* 4070: struct.stack_st_fake_X509 */
            	4077, 8,
            	475, 24,
            64099, 8, 2, /* 4077: pointer_to_array_of_pointers_to_stack */
            	4084, 0,
            	472, 20,
            0, 8, 1, /* 4084: pointer.X509 */
            	4089, 0,
            0, 0, 1, /* 4089: X509 */
            	4094, 0,
            0, 184, 12, /* 4094: struct.x509_st */
            	4121, 0,
            	2580, 8,
            	2679, 16,
            	64, 32,
            	2899, 40,
            	2684, 104,
            	4126, 112,
            	4134, 120,
            	4139, 128,
            	4163, 136,
            	4187, 144,
            	4192, 176,
            1, 8, 1, /* 4121: pointer.struct.x509_cinf_st */
            	3872, 0,
            1, 8, 1, /* 4126: pointer.struct.AUTHORITY_KEYID_st */
            	4131, 0,
            0, 0, 0, /* 4131: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4134: pointer.struct.X509_POLICY_CACHE_st */
            	3991, 0,
            1, 8, 1, /* 4139: pointer.struct.stack_st_DIST_POINT */
            	4144, 0,
            0, 32, 2, /* 4144: struct.stack_st_fake_DIST_POINT */
            	4151, 8,
            	475, 24,
            64099, 8, 2, /* 4151: pointer_to_array_of_pointers_to_stack */
            	4158, 0,
            	472, 20,
            0, 8, 1, /* 4158: pointer.DIST_POINT */
            	1351, 0,
            1, 8, 1, /* 4163: pointer.struct.stack_st_GENERAL_NAME */
            	4168, 0,
            0, 32, 2, /* 4168: struct.stack_st_fake_GENERAL_NAME */
            	4175, 8,
            	475, 24,
            64099, 8, 2, /* 4175: pointer_to_array_of_pointers_to_stack */
            	4182, 0,
            	472, 20,
            0, 8, 1, /* 4182: pointer.GENERAL_NAME */
            	1408, 0,
            1, 8, 1, /* 4187: pointer.struct.NAME_CONSTRAINTS_st */
            	4000, 0,
            1, 8, 1, /* 4192: pointer.struct.x509_cert_aux_st */
            	4197, 0,
            0, 40, 5, /* 4197: struct.x509_cert_aux_st */
            	4210, 0,
            	4210, 8,
            	2734, 16,
            	2684, 24,
            	4234, 32,
            1, 8, 1, /* 4210: pointer.struct.stack_st_ASN1_OBJECT */
            	4215, 0,
            0, 32, 2, /* 4215: struct.stack_st_fake_ASN1_OBJECT */
            	4222, 8,
            	475, 24,
            64099, 8, 2, /* 4222: pointer_to_array_of_pointers_to_stack */
            	4229, 0,
            	472, 20,
            0, 8, 1, /* 4229: pointer.ASN1_OBJECT */
            	1810, 0,
            1, 8, 1, /* 4234: pointer.struct.stack_st_X509_ALGOR */
            	4239, 0,
            0, 32, 2, /* 4239: struct.stack_st_fake_X509_ALGOR */
            	4246, 8,
            	475, 24,
            64099, 8, 2, /* 4246: pointer_to_array_of_pointers_to_stack */
            	4253, 0,
            	472, 20,
            0, 8, 1, /* 4253: pointer.X509_ALGOR */
            	1848, 0,
            1, 8, 1, /* 4258: pointer.struct.stack_st_SSL_CIPHER */
            	4263, 0,
            0, 32, 2, /* 4263: struct.stack_st_fake_SSL_CIPHER */
            	4270, 8,
            	475, 24,
            64099, 8, 2, /* 4270: pointer_to_array_of_pointers_to_stack */
            	4277, 0,
            	472, 20,
            0, 8, 1, /* 4277: pointer.SSL_CIPHER */
            	4006, 0,
            1, 8, 1, /* 4282: pointer.struct.ssl_session_st */
            	4016, 0,
            64097, 8, 0, /* 4287: pointer.func */
            64097, 8, 0, /* 4290: pointer.func */
            64097, 8, 0, /* 4293: pointer.func */
            1, 8, 1, /* 4296: pointer.struct.stack_st_X509_LOOKUP */
            	4301, 0,
            0, 32, 2, /* 4301: struct.stack_st_fake_X509_LOOKUP */
            	4308, 8,
            	475, 24,
            64099, 8, 2, /* 4308: pointer_to_array_of_pointers_to_stack */
            	4315, 0,
            	472, 20,
            0, 8, 1, /* 4315: pointer.X509_LOOKUP */
            	4320, 0,
            0, 0, 1, /* 4320: X509_LOOKUP */
            	4325, 0,
            0, 32, 3, /* 4325: struct.x509_lookup_st */
            	4334, 8,
            	64, 16,
            	4377, 24,
            1, 8, 1, /* 4334: pointer.struct.x509_lookup_method_st */
            	4339, 0,
            0, 80, 10, /* 4339: struct.x509_lookup_method_st */
            	13, 0,
            	4362, 8,
            	2560, 16,
            	4362, 24,
            	4362, 32,
            	4365, 40,
            	4368, 48,
            	4287, 56,
            	4371, 64,
            	4374, 72,
            64097, 8, 0, /* 4362: pointer.func */
            64097, 8, 0, /* 4365: pointer.func */
            64097, 8, 0, /* 4368: pointer.func */
            64097, 8, 0, /* 4371: pointer.func */
            64097, 8, 0, /* 4374: pointer.func */
            1, 8, 1, /* 4377: pointer.struct.x509_store_st */
            	4382, 0,
            0, 144, 15, /* 4382: struct.x509_store_st */
            	4415, 8,
            	4296, 16,
            	4439, 24,
            	4451, 32,
            	4454, 40,
            	4457, 48,
            	4460, 56,
            	4451, 64,
            	4463, 72,
            	4466, 80,
            	4469, 88,
            	4472, 96,
            	4290, 104,
            	4451, 112,
            	2199, 120,
            1, 8, 1, /* 4415: pointer.struct.stack_st_X509_OBJECT */
            	4420, 0,
            0, 32, 2, /* 4420: struct.stack_st_fake_X509_OBJECT */
            	4427, 8,
            	475, 24,
            64099, 8, 2, /* 4427: pointer_to_array_of_pointers_to_stack */
            	4434, 0,
            	472, 20,
            0, 8, 1, /* 4434: pointer.X509_OBJECT */
            	3121, 0,
            1, 8, 1, /* 4439: pointer.struct.X509_VERIFY_PARAM_st */
            	4444, 0,
            0, 56, 2, /* 4444: struct.X509_VERIFY_PARAM_st */
            	64, 0,
            	3606, 48,
            64097, 8, 0, /* 4451: pointer.func */
            64097, 8, 0, /* 4454: pointer.func */
            64097, 8, 0, /* 4457: pointer.func */
            64097, 8, 0, /* 4460: pointer.func */
            64097, 8, 0, /* 4463: pointer.func */
            64097, 8, 0, /* 4466: pointer.func */
            64097, 8, 0, /* 4469: pointer.func */
            64097, 8, 0, /* 4472: pointer.func */
            64097, 8, 0, /* 4475: pointer.func */
            0, 144, 15, /* 4478: struct.x509_store_st */
            	4511, 8,
            	4535, 16,
            	4559, 24,
            	4571, 32,
            	4574, 40,
            	4577, 48,
            	4580, 56,
            	4571, 64,
            	4583, 72,
            	4586, 80,
            	4589, 88,
            	3869, 96,
            	4592, 104,
            	4571, 112,
            	661, 120,
            1, 8, 1, /* 4511: pointer.struct.stack_st_X509_OBJECT */
            	4516, 0,
            0, 32, 2, /* 4516: struct.stack_st_fake_X509_OBJECT */
            	4523, 8,
            	475, 24,
            64099, 8, 2, /* 4523: pointer_to_array_of_pointers_to_stack */
            	4530, 0,
            	472, 20,
            0, 8, 1, /* 4530: pointer.X509_OBJECT */
            	3121, 0,
            1, 8, 1, /* 4535: pointer.struct.stack_st_X509_LOOKUP */
            	4540, 0,
            0, 32, 2, /* 4540: struct.stack_st_fake_X509_LOOKUP */
            	4547, 8,
            	475, 24,
            64099, 8, 2, /* 4547: pointer_to_array_of_pointers_to_stack */
            	4554, 0,
            	472, 20,
            0, 8, 1, /* 4554: pointer.X509_LOOKUP */
            	4320, 0,
            1, 8, 1, /* 4559: pointer.struct.X509_VERIFY_PARAM_st */
            	4564, 0,
            0, 56, 2, /* 4564: struct.X509_VERIFY_PARAM_st */
            	64, 0,
            	1786, 48,
            64097, 8, 0, /* 4571: pointer.func */
            64097, 8, 0, /* 4574: pointer.func */
            64097, 8, 0, /* 4577: pointer.func */
            64097, 8, 0, /* 4580: pointer.func */
            64097, 8, 0, /* 4583: pointer.func */
            64097, 8, 0, /* 4586: pointer.func */
            64097, 8, 0, /* 4589: pointer.func */
            64097, 8, 0, /* 4592: pointer.func */
            64097, 8, 0, /* 4595: pointer.func */
            64097, 8, 0, /* 4598: pointer.func */
            64097, 8, 0, /* 4601: pointer.func */
            0, 112, 11, /* 4604: struct.ssl3_enc_method */
            	4629, 0,
            	4475, 8,
            	4632, 16,
            	4635, 24,
            	4629, 32,
            	4638, 40,
            	4641, 56,
            	13, 64,
            	13, 80,
            	4644, 96,
            	4647, 104,
            64097, 8, 0, /* 4629: pointer.func */
            64097, 8, 0, /* 4632: pointer.func */
            64097, 8, 0, /* 4635: pointer.func */
            64097, 8, 0, /* 4638: pointer.func */
            64097, 8, 0, /* 4641: pointer.func */
            64097, 8, 0, /* 4644: pointer.func */
            64097, 8, 0, /* 4647: pointer.func */
            64097, 8, 0, /* 4650: pointer.func */
            64097, 8, 0, /* 4653: pointer.func */
            0, 736, 50, /* 4656: struct.ssl_ctx_st */
            	4759, 0,
            	4258, 8,
            	4258, 16,
            	4864, 24,
            	4869, 32,
            	4282, 48,
            	4282, 56,
            	3866, 80,
            	3994, 88,
            	4905, 96,
            	4595, 152,
            	52, 160,
            	4908, 168,
            	52, 176,
            	2186, 184,
            	4911, 192,
            	2183, 200,
            	661, 208,
            	2007, 224,
            	2007, 232,
            	2007, 240,
            	4065, 248,
            	2119, 256,
            	2110, 264,
            	4914, 272,
            	2329, 304,
            	3997, 320,
            	52, 328,
            	4574, 376,
            	4943, 384,
            	4559, 392,
            	543, 408,
            	55, 416,
            	52, 424,
            	4601, 480,
            	58, 488,
            	52, 496,
            	113, 504,
            	52, 512,
            	64, 520,
            	110, 528,
            	4946, 536,
            	100, 552,
            	100, 560,
            	21, 568,
            	87, 696,
            	52, 704,
            	18, 712,
            	52, 720,
            	2536, 728,
            1, 8, 1, /* 4759: pointer.struct.ssl_method_st */
            	4764, 0,
            0, 232, 28, /* 4764: struct.ssl_method_st */
            	4632, 8,
            	4823, 16,
            	4823, 24,
            	4632, 32,
            	4632, 40,
            	4826, 48,
            	4826, 56,
            	4829, 64,
            	4632, 72,
            	4632, 80,
            	4632, 88,
            	4832, 96,
            	4653, 104,
            	4650, 112,
            	4632, 120,
            	4598, 128,
            	4835, 136,
            	4838, 144,
            	4293, 152,
            	4841, 160,
            	4844, 168,
            	4847, 176,
            	4850, 184,
            	2180, 192,
            	4853, 200,
            	4844, 208,
            	4858, 216,
            	4861, 224,
            64097, 8, 0, /* 4823: pointer.func */
            64097, 8, 0, /* 4826: pointer.func */
            64097, 8, 0, /* 4829: pointer.func */
            64097, 8, 0, /* 4832: pointer.func */
            64097, 8, 0, /* 4835: pointer.func */
            64097, 8, 0, /* 4838: pointer.func */
            64097, 8, 0, /* 4841: pointer.func */
            64097, 8, 0, /* 4844: pointer.func */
            64097, 8, 0, /* 4847: pointer.func */
            64097, 8, 0, /* 4850: pointer.func */
            1, 8, 1, /* 4853: pointer.struct.ssl3_enc_method */
            	4604, 0,
            64097, 8, 0, /* 4858: pointer.func */
            64097, 8, 0, /* 4861: pointer.func */
            1, 8, 1, /* 4864: pointer.struct.x509_store_st */
            	4478, 0,
            1, 8, 1, /* 4869: pointer.struct.lhash_st */
            	4874, 0,
            0, 176, 3, /* 4874: struct.lhash_st */
            	4883, 0,
            	475, 8,
            	4003, 16,
            1, 8, 1, /* 4883: pointer.pointer.struct.lhash_node_st */
            	4888, 0,
            1, 8, 1, /* 4888: pointer.struct.lhash_node_st */
            	4893, 0,
            0, 24, 2, /* 4893: struct.lhash_node_st */
            	52, 0,
            	4900, 8,
            1, 8, 1, /* 4900: pointer.struct.lhash_node_st */
            	4893, 0,
            64097, 8, 0, /* 4905: pointer.func */
            64097, 8, 0, /* 4908: pointer.func */
            64097, 8, 0, /* 4911: pointer.func */
            1, 8, 1, /* 4914: pointer.struct.stack_st_X509_NAME */
            	4919, 0,
            0, 32, 2, /* 4919: struct.stack_st_fake_X509_NAME */
            	4926, 8,
            	475, 24,
            64099, 8, 2, /* 4926: pointer_to_array_of_pointers_to_stack */
            	4933, 0,
            	472, 20,
            0, 8, 1, /* 4933: pointer.X509_NAME */
            	4938, 0,
            0, 0, 1, /* 4938: X509_NAME */
            	2072, 0,
            64097, 8, 0, /* 4943: pointer.func */
            64097, 8, 0, /* 4946: pointer.func */
            1, 8, 1, /* 4949: pointer.struct.ssl_ctx_st */
            	4656, 0,
            0, 1, 0, /* 4954: char */
        },
        .arg_entity_index = { 4949, 0, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    void (*new_arg_b)(struct ssl_ctx_st *,SSL_SESSION *) = *((void (**)(struct ssl_ctx_st *,SSL_SESSION *))new_args->args[1]);

    void (*orig_SSL_CTX_sess_set_remove_cb)(SSL_CTX *,void (*)(struct ssl_ctx_st *,SSL_SESSION *));
    orig_SSL_CTX_sess_set_remove_cb = dlsym(RTLD_NEXT, "SSL_CTX_sess_set_remove_cb");
    (*orig_SSL_CTX_sess_set_remove_cb)(new_arg_a,new_arg_b);

    syscall(889);

}

