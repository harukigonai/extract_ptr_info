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

int bb_SSL_CTX_use_PrivateKey_file(SSL_CTX * arg_a,const char * arg_b,int arg_c);

int SSL_CTX_use_PrivateKey_file(SSL_CTX * arg_a,const char * arg_b,int arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_use_PrivateKey_file called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_CTX_use_PrivateKey_file(arg_a,arg_b,arg_c);
    else {
        int (*orig_SSL_CTX_use_PrivateKey_file)(SSL_CTX *,const char *,int);
        orig_SSL_CTX_use_PrivateKey_file = dlsym(RTLD_NEXT, "SSL_CTX_use_PrivateKey_file");
        return orig_SSL_CTX_use_PrivateKey_file(arg_a,arg_b,arg_c);
    }
}

int bb_SSL_CTX_use_PrivateKey_file(SSL_CTX * arg_a,const char * arg_b,int arg_c) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 16, 1, /* 0: struct.srtp_protection_profile_st */
            	5, 0,
            1, 8, 1, /* 5: pointer.char */
            	8884096, 0,
            0, 0, 1, /* 10: SRTP_PROTECTION_PROFILE */
            	0, 0,
            8884097, 8, 0, /* 15: pointer.func */
            0, 8, 1, /* 18: struct.ssl3_buf_freelist_entry_st */
            	23, 0,
            1, 8, 1, /* 23: pointer.struct.ssl3_buf_freelist_entry_st */
            	18, 0,
            0, 24, 1, /* 28: struct.ssl3_buf_freelist_st */
            	23, 16,
            1, 8, 1, /* 33: pointer.struct.ssl3_buf_freelist_st */
            	28, 0,
            8884097, 8, 0, /* 38: pointer.func */
            8884097, 8, 0, /* 41: pointer.func */
            8884097, 8, 0, /* 44: pointer.func */
            8884097, 8, 0, /* 47: pointer.func */
            8884097, 8, 0, /* 50: pointer.func */
            8884097, 8, 0, /* 53: pointer.func */
            8884097, 8, 0, /* 56: pointer.func */
            8884097, 8, 0, /* 59: pointer.func */
            0, 296, 7, /* 62: struct.cert_st */
            	79, 0,
            	2003, 48,
            	59, 56,
            	2008, 64,
            	56, 72,
            	2013, 80,
            	53, 88,
            1, 8, 1, /* 79: pointer.struct.cert_pkey_st */
            	84, 0,
            0, 24, 3, /* 84: struct.cert_pkey_st */
            	93, 0,
            	461, 8,
            	1958, 16,
            1, 8, 1, /* 93: pointer.struct.x509_st */
            	98, 0,
            0, 184, 12, /* 98: struct.x509_st */
            	125, 0,
            	173, 8,
            	272, 16,
            	257, 32,
            	621, 40,
            	277, 104,
            	1271, 112,
            	1279, 120,
            	1287, 128,
            	1696, 136,
            	1720, 144,
            	1728, 176,
            1, 8, 1, /* 125: pointer.struct.x509_cinf_st */
            	130, 0,
            0, 104, 11, /* 130: struct.x509_cinf_st */
            	155, 0,
            	155, 8,
            	173, 16,
            	340, 24,
            	430, 32,
            	340, 40,
            	447, 48,
            	272, 56,
            	272, 64,
            	1206, 72,
            	1266, 80,
            1, 8, 1, /* 155: pointer.struct.asn1_string_st */
            	160, 0,
            0, 24, 1, /* 160: struct.asn1_string_st */
            	165, 8,
            1, 8, 1, /* 165: pointer.unsigned char */
            	170, 0,
            0, 1, 0, /* 170: unsigned char */
            1, 8, 1, /* 173: pointer.struct.X509_algor_st */
            	178, 0,
            0, 16, 2, /* 178: struct.X509_algor_st */
            	185, 0,
            	204, 8,
            1, 8, 1, /* 185: pointer.struct.asn1_object_st */
            	190, 0,
            0, 40, 3, /* 190: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	199, 24,
            1, 8, 1, /* 199: pointer.unsigned char */
            	170, 0,
            1, 8, 1, /* 204: pointer.struct.asn1_type_st */
            	209, 0,
            0, 16, 1, /* 209: struct.asn1_type_st */
            	214, 8,
            0, 8, 20, /* 214: union.unknown */
            	257, 0,
            	262, 0,
            	185, 0,
            	155, 0,
            	267, 0,
            	272, 0,
            	277, 0,
            	282, 0,
            	287, 0,
            	292, 0,
            	297, 0,
            	302, 0,
            	307, 0,
            	312, 0,
            	317, 0,
            	322, 0,
            	327, 0,
            	262, 0,
            	262, 0,
            	332, 0,
            1, 8, 1, /* 257: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 262: pointer.struct.asn1_string_st */
            	160, 0,
            1, 8, 1, /* 267: pointer.struct.asn1_string_st */
            	160, 0,
            1, 8, 1, /* 272: pointer.struct.asn1_string_st */
            	160, 0,
            1, 8, 1, /* 277: pointer.struct.asn1_string_st */
            	160, 0,
            1, 8, 1, /* 282: pointer.struct.asn1_string_st */
            	160, 0,
            1, 8, 1, /* 287: pointer.struct.asn1_string_st */
            	160, 0,
            1, 8, 1, /* 292: pointer.struct.asn1_string_st */
            	160, 0,
            1, 8, 1, /* 297: pointer.struct.asn1_string_st */
            	160, 0,
            1, 8, 1, /* 302: pointer.struct.asn1_string_st */
            	160, 0,
            1, 8, 1, /* 307: pointer.struct.asn1_string_st */
            	160, 0,
            1, 8, 1, /* 312: pointer.struct.asn1_string_st */
            	160, 0,
            1, 8, 1, /* 317: pointer.struct.asn1_string_st */
            	160, 0,
            1, 8, 1, /* 322: pointer.struct.asn1_string_st */
            	160, 0,
            1, 8, 1, /* 327: pointer.struct.asn1_string_st */
            	160, 0,
            1, 8, 1, /* 332: pointer.struct.ASN1_VALUE_st */
            	337, 0,
            0, 0, 0, /* 337: struct.ASN1_VALUE_st */
            1, 8, 1, /* 340: pointer.struct.X509_name_st */
            	345, 0,
            0, 40, 3, /* 345: struct.X509_name_st */
            	354, 0,
            	420, 16,
            	165, 24,
            1, 8, 1, /* 354: pointer.struct.stack_st_X509_NAME_ENTRY */
            	359, 0,
            0, 32, 2, /* 359: struct.stack_st_fake_X509_NAME_ENTRY */
            	366, 8,
            	417, 24,
            8884099, 8, 2, /* 366: pointer_to_array_of_pointers_to_stack */
            	373, 0,
            	414, 20,
            0, 8, 1, /* 373: pointer.X509_NAME_ENTRY */
            	378, 0,
            0, 0, 1, /* 378: X509_NAME_ENTRY */
            	383, 0,
            0, 24, 2, /* 383: struct.X509_name_entry_st */
            	390, 0,
            	404, 8,
            1, 8, 1, /* 390: pointer.struct.asn1_object_st */
            	395, 0,
            0, 40, 3, /* 395: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	199, 24,
            1, 8, 1, /* 404: pointer.struct.asn1_string_st */
            	409, 0,
            0, 24, 1, /* 409: struct.asn1_string_st */
            	165, 8,
            0, 4, 0, /* 414: int */
            8884097, 8, 0, /* 417: pointer.func */
            1, 8, 1, /* 420: pointer.struct.buf_mem_st */
            	425, 0,
            0, 24, 1, /* 425: struct.buf_mem_st */
            	257, 8,
            1, 8, 1, /* 430: pointer.struct.X509_val_st */
            	435, 0,
            0, 16, 2, /* 435: struct.X509_val_st */
            	442, 0,
            	442, 8,
            1, 8, 1, /* 442: pointer.struct.asn1_string_st */
            	160, 0,
            1, 8, 1, /* 447: pointer.struct.X509_pubkey_st */
            	452, 0,
            0, 24, 3, /* 452: struct.X509_pubkey_st */
            	173, 0,
            	272, 8,
            	461, 16,
            1, 8, 1, /* 461: pointer.struct.evp_pkey_st */
            	466, 0,
            0, 56, 4, /* 466: struct.evp_pkey_st */
            	477, 16,
            	485, 24,
            	493, 32,
            	827, 48,
            1, 8, 1, /* 477: pointer.struct.evp_pkey_asn1_method_st */
            	482, 0,
            0, 0, 0, /* 482: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 485: pointer.struct.engine_st */
            	490, 0,
            0, 0, 0, /* 490: struct.engine_st */
            0, 8, 5, /* 493: union.unknown */
            	257, 0,
            	506, 0,
            	670, 0,
            	751, 0,
            	819, 0,
            1, 8, 1, /* 506: pointer.struct.rsa_st */
            	511, 0,
            0, 168, 17, /* 511: struct.rsa_st */
            	548, 16,
            	485, 24,
            	603, 32,
            	603, 40,
            	603, 48,
            	603, 56,
            	603, 64,
            	603, 72,
            	603, 80,
            	603, 88,
            	621, 96,
            	648, 120,
            	648, 128,
            	648, 136,
            	257, 144,
            	662, 152,
            	662, 160,
            1, 8, 1, /* 548: pointer.struct.rsa_meth_st */
            	553, 0,
            0, 112, 13, /* 553: struct.rsa_meth_st */
            	5, 0,
            	582, 8,
            	582, 16,
            	582, 24,
            	582, 32,
            	585, 40,
            	588, 48,
            	591, 56,
            	591, 64,
            	257, 80,
            	594, 88,
            	597, 96,
            	600, 104,
            8884097, 8, 0, /* 582: pointer.func */
            8884097, 8, 0, /* 585: pointer.func */
            8884097, 8, 0, /* 588: pointer.func */
            8884097, 8, 0, /* 591: pointer.func */
            8884097, 8, 0, /* 594: pointer.func */
            8884097, 8, 0, /* 597: pointer.func */
            8884097, 8, 0, /* 600: pointer.func */
            1, 8, 1, /* 603: pointer.struct.bignum_st */
            	608, 0,
            0, 24, 1, /* 608: struct.bignum_st */
            	613, 0,
            1, 8, 1, /* 613: pointer.unsigned int */
            	618, 0,
            0, 4, 0, /* 618: unsigned int */
            0, 16, 1, /* 621: struct.crypto_ex_data_st */
            	626, 0,
            1, 8, 1, /* 626: pointer.struct.stack_st_void */
            	631, 0,
            0, 32, 1, /* 631: struct.stack_st_void */
            	636, 0,
            0, 32, 2, /* 636: struct.stack_st */
            	643, 8,
            	417, 24,
            1, 8, 1, /* 643: pointer.pointer.char */
            	257, 0,
            1, 8, 1, /* 648: pointer.struct.bn_mont_ctx_st */
            	653, 0,
            0, 96, 3, /* 653: struct.bn_mont_ctx_st */
            	608, 8,
            	608, 32,
            	608, 56,
            1, 8, 1, /* 662: pointer.struct.bn_blinding_st */
            	667, 0,
            0, 0, 0, /* 667: struct.bn_blinding_st */
            1, 8, 1, /* 670: pointer.struct.dsa_st */
            	675, 0,
            0, 136, 11, /* 675: struct.dsa_st */
            	603, 24,
            	603, 32,
            	603, 40,
            	603, 48,
            	603, 56,
            	603, 64,
            	603, 72,
            	648, 88,
            	621, 104,
            	700, 120,
            	485, 128,
            1, 8, 1, /* 700: pointer.struct.dsa_method */
            	705, 0,
            0, 96, 11, /* 705: struct.dsa_method */
            	5, 0,
            	730, 8,
            	733, 16,
            	736, 24,
            	739, 32,
            	742, 40,
            	745, 48,
            	745, 56,
            	257, 72,
            	748, 80,
            	745, 88,
            8884097, 8, 0, /* 730: pointer.func */
            8884097, 8, 0, /* 733: pointer.func */
            8884097, 8, 0, /* 736: pointer.func */
            8884097, 8, 0, /* 739: pointer.func */
            8884097, 8, 0, /* 742: pointer.func */
            8884097, 8, 0, /* 745: pointer.func */
            8884097, 8, 0, /* 748: pointer.func */
            1, 8, 1, /* 751: pointer.struct.dh_st */
            	756, 0,
            0, 144, 12, /* 756: struct.dh_st */
            	603, 8,
            	603, 16,
            	603, 32,
            	603, 40,
            	648, 56,
            	603, 64,
            	603, 72,
            	165, 80,
            	603, 96,
            	621, 112,
            	783, 128,
            	485, 136,
            1, 8, 1, /* 783: pointer.struct.dh_method */
            	788, 0,
            0, 72, 8, /* 788: struct.dh_method */
            	5, 0,
            	807, 8,
            	810, 16,
            	813, 24,
            	807, 32,
            	807, 40,
            	257, 56,
            	816, 64,
            8884097, 8, 0, /* 807: pointer.func */
            8884097, 8, 0, /* 810: pointer.func */
            8884097, 8, 0, /* 813: pointer.func */
            8884097, 8, 0, /* 816: pointer.func */
            1, 8, 1, /* 819: pointer.struct.ec_key_st */
            	824, 0,
            0, 0, 0, /* 824: struct.ec_key_st */
            1, 8, 1, /* 827: pointer.struct.stack_st_X509_ATTRIBUTE */
            	832, 0,
            0, 32, 2, /* 832: struct.stack_st_fake_X509_ATTRIBUTE */
            	839, 8,
            	417, 24,
            8884099, 8, 2, /* 839: pointer_to_array_of_pointers_to_stack */
            	846, 0,
            	414, 20,
            0, 8, 1, /* 846: pointer.X509_ATTRIBUTE */
            	851, 0,
            0, 0, 1, /* 851: X509_ATTRIBUTE */
            	856, 0,
            0, 24, 2, /* 856: struct.x509_attributes_st */
            	863, 0,
            	877, 16,
            1, 8, 1, /* 863: pointer.struct.asn1_object_st */
            	868, 0,
            0, 40, 3, /* 868: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	199, 24,
            0, 8, 3, /* 877: union.unknown */
            	257, 0,
            	886, 0,
            	1065, 0,
            1, 8, 1, /* 886: pointer.struct.stack_st_ASN1_TYPE */
            	891, 0,
            0, 32, 2, /* 891: struct.stack_st_fake_ASN1_TYPE */
            	898, 8,
            	417, 24,
            8884099, 8, 2, /* 898: pointer_to_array_of_pointers_to_stack */
            	905, 0,
            	414, 20,
            0, 8, 1, /* 905: pointer.ASN1_TYPE */
            	910, 0,
            0, 0, 1, /* 910: ASN1_TYPE */
            	915, 0,
            0, 16, 1, /* 915: struct.asn1_type_st */
            	920, 8,
            0, 8, 20, /* 920: union.unknown */
            	257, 0,
            	963, 0,
            	973, 0,
            	987, 0,
            	992, 0,
            	997, 0,
            	1002, 0,
            	1007, 0,
            	1012, 0,
            	1017, 0,
            	1022, 0,
            	1027, 0,
            	1032, 0,
            	1037, 0,
            	1042, 0,
            	1047, 0,
            	1052, 0,
            	963, 0,
            	963, 0,
            	1057, 0,
            1, 8, 1, /* 963: pointer.struct.asn1_string_st */
            	968, 0,
            0, 24, 1, /* 968: struct.asn1_string_st */
            	165, 8,
            1, 8, 1, /* 973: pointer.struct.asn1_object_st */
            	978, 0,
            0, 40, 3, /* 978: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	199, 24,
            1, 8, 1, /* 987: pointer.struct.asn1_string_st */
            	968, 0,
            1, 8, 1, /* 992: pointer.struct.asn1_string_st */
            	968, 0,
            1, 8, 1, /* 997: pointer.struct.asn1_string_st */
            	968, 0,
            1, 8, 1, /* 1002: pointer.struct.asn1_string_st */
            	968, 0,
            1, 8, 1, /* 1007: pointer.struct.asn1_string_st */
            	968, 0,
            1, 8, 1, /* 1012: pointer.struct.asn1_string_st */
            	968, 0,
            1, 8, 1, /* 1017: pointer.struct.asn1_string_st */
            	968, 0,
            1, 8, 1, /* 1022: pointer.struct.asn1_string_st */
            	968, 0,
            1, 8, 1, /* 1027: pointer.struct.asn1_string_st */
            	968, 0,
            1, 8, 1, /* 1032: pointer.struct.asn1_string_st */
            	968, 0,
            1, 8, 1, /* 1037: pointer.struct.asn1_string_st */
            	968, 0,
            1, 8, 1, /* 1042: pointer.struct.asn1_string_st */
            	968, 0,
            1, 8, 1, /* 1047: pointer.struct.asn1_string_st */
            	968, 0,
            1, 8, 1, /* 1052: pointer.struct.asn1_string_st */
            	968, 0,
            1, 8, 1, /* 1057: pointer.struct.ASN1_VALUE_st */
            	1062, 0,
            0, 0, 0, /* 1062: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1065: pointer.struct.asn1_type_st */
            	1070, 0,
            0, 16, 1, /* 1070: struct.asn1_type_st */
            	1075, 8,
            0, 8, 20, /* 1075: union.unknown */
            	257, 0,
            	1118, 0,
            	863, 0,
            	1128, 0,
            	1133, 0,
            	1138, 0,
            	1143, 0,
            	1148, 0,
            	1153, 0,
            	1158, 0,
            	1163, 0,
            	1168, 0,
            	1173, 0,
            	1178, 0,
            	1183, 0,
            	1188, 0,
            	1193, 0,
            	1118, 0,
            	1118, 0,
            	1198, 0,
            1, 8, 1, /* 1118: pointer.struct.asn1_string_st */
            	1123, 0,
            0, 24, 1, /* 1123: struct.asn1_string_st */
            	165, 8,
            1, 8, 1, /* 1128: pointer.struct.asn1_string_st */
            	1123, 0,
            1, 8, 1, /* 1133: pointer.struct.asn1_string_st */
            	1123, 0,
            1, 8, 1, /* 1138: pointer.struct.asn1_string_st */
            	1123, 0,
            1, 8, 1, /* 1143: pointer.struct.asn1_string_st */
            	1123, 0,
            1, 8, 1, /* 1148: pointer.struct.asn1_string_st */
            	1123, 0,
            1, 8, 1, /* 1153: pointer.struct.asn1_string_st */
            	1123, 0,
            1, 8, 1, /* 1158: pointer.struct.asn1_string_st */
            	1123, 0,
            1, 8, 1, /* 1163: pointer.struct.asn1_string_st */
            	1123, 0,
            1, 8, 1, /* 1168: pointer.struct.asn1_string_st */
            	1123, 0,
            1, 8, 1, /* 1173: pointer.struct.asn1_string_st */
            	1123, 0,
            1, 8, 1, /* 1178: pointer.struct.asn1_string_st */
            	1123, 0,
            1, 8, 1, /* 1183: pointer.struct.asn1_string_st */
            	1123, 0,
            1, 8, 1, /* 1188: pointer.struct.asn1_string_st */
            	1123, 0,
            1, 8, 1, /* 1193: pointer.struct.asn1_string_st */
            	1123, 0,
            1, 8, 1, /* 1198: pointer.struct.ASN1_VALUE_st */
            	1203, 0,
            0, 0, 0, /* 1203: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1206: pointer.struct.stack_st_X509_EXTENSION */
            	1211, 0,
            0, 32, 2, /* 1211: struct.stack_st_fake_X509_EXTENSION */
            	1218, 8,
            	417, 24,
            8884099, 8, 2, /* 1218: pointer_to_array_of_pointers_to_stack */
            	1225, 0,
            	414, 20,
            0, 8, 1, /* 1225: pointer.X509_EXTENSION */
            	1230, 0,
            0, 0, 1, /* 1230: X509_EXTENSION */
            	1235, 0,
            0, 24, 2, /* 1235: struct.X509_extension_st */
            	1242, 0,
            	1256, 16,
            1, 8, 1, /* 1242: pointer.struct.asn1_object_st */
            	1247, 0,
            0, 40, 3, /* 1247: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	199, 24,
            1, 8, 1, /* 1256: pointer.struct.asn1_string_st */
            	1261, 0,
            0, 24, 1, /* 1261: struct.asn1_string_st */
            	165, 8,
            0, 24, 1, /* 1266: struct.ASN1_ENCODING_st */
            	165, 0,
            1, 8, 1, /* 1271: pointer.struct.AUTHORITY_KEYID_st */
            	1276, 0,
            0, 0, 0, /* 1276: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 1279: pointer.struct.X509_POLICY_CACHE_st */
            	1284, 0,
            0, 0, 0, /* 1284: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1287: pointer.struct.stack_st_DIST_POINT */
            	1292, 0,
            0, 32, 2, /* 1292: struct.stack_st_fake_DIST_POINT */
            	1299, 8,
            	417, 24,
            8884099, 8, 2, /* 1299: pointer_to_array_of_pointers_to_stack */
            	1306, 0,
            	414, 20,
            0, 8, 1, /* 1306: pointer.DIST_POINT */
            	1311, 0,
            0, 0, 1, /* 1311: DIST_POINT */
            	1316, 0,
            0, 32, 3, /* 1316: struct.DIST_POINT_st */
            	1325, 0,
            	1686, 8,
            	1344, 16,
            1, 8, 1, /* 1325: pointer.struct.DIST_POINT_NAME_st */
            	1330, 0,
            0, 24, 2, /* 1330: struct.DIST_POINT_NAME_st */
            	1337, 8,
            	1662, 16,
            0, 8, 2, /* 1337: union.unknown */
            	1344, 0,
            	1638, 0,
            1, 8, 1, /* 1344: pointer.struct.stack_st_GENERAL_NAME */
            	1349, 0,
            0, 32, 2, /* 1349: struct.stack_st_fake_GENERAL_NAME */
            	1356, 8,
            	417, 24,
            8884099, 8, 2, /* 1356: pointer_to_array_of_pointers_to_stack */
            	1363, 0,
            	414, 20,
            0, 8, 1, /* 1363: pointer.GENERAL_NAME */
            	1368, 0,
            0, 0, 1, /* 1368: GENERAL_NAME */
            	1373, 0,
            0, 16, 1, /* 1373: struct.GENERAL_NAME_st */
            	1378, 8,
            0, 8, 15, /* 1378: union.unknown */
            	257, 0,
            	1411, 0,
            	1530, 0,
            	1530, 0,
            	1437, 0,
            	1578, 0,
            	1626, 0,
            	1530, 0,
            	1515, 0,
            	1423, 0,
            	1515, 0,
            	1578, 0,
            	1530, 0,
            	1423, 0,
            	1437, 0,
            1, 8, 1, /* 1411: pointer.struct.otherName_st */
            	1416, 0,
            0, 16, 2, /* 1416: struct.otherName_st */
            	1423, 0,
            	1437, 8,
            1, 8, 1, /* 1423: pointer.struct.asn1_object_st */
            	1428, 0,
            0, 40, 3, /* 1428: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	199, 24,
            1, 8, 1, /* 1437: pointer.struct.asn1_type_st */
            	1442, 0,
            0, 16, 1, /* 1442: struct.asn1_type_st */
            	1447, 8,
            0, 8, 20, /* 1447: union.unknown */
            	257, 0,
            	1490, 0,
            	1423, 0,
            	1500, 0,
            	1505, 0,
            	1510, 0,
            	1515, 0,
            	1520, 0,
            	1525, 0,
            	1530, 0,
            	1535, 0,
            	1540, 0,
            	1545, 0,
            	1550, 0,
            	1555, 0,
            	1560, 0,
            	1565, 0,
            	1490, 0,
            	1490, 0,
            	1570, 0,
            1, 8, 1, /* 1490: pointer.struct.asn1_string_st */
            	1495, 0,
            0, 24, 1, /* 1495: struct.asn1_string_st */
            	165, 8,
            1, 8, 1, /* 1500: pointer.struct.asn1_string_st */
            	1495, 0,
            1, 8, 1, /* 1505: pointer.struct.asn1_string_st */
            	1495, 0,
            1, 8, 1, /* 1510: pointer.struct.asn1_string_st */
            	1495, 0,
            1, 8, 1, /* 1515: pointer.struct.asn1_string_st */
            	1495, 0,
            1, 8, 1, /* 1520: pointer.struct.asn1_string_st */
            	1495, 0,
            1, 8, 1, /* 1525: pointer.struct.asn1_string_st */
            	1495, 0,
            1, 8, 1, /* 1530: pointer.struct.asn1_string_st */
            	1495, 0,
            1, 8, 1, /* 1535: pointer.struct.asn1_string_st */
            	1495, 0,
            1, 8, 1, /* 1540: pointer.struct.asn1_string_st */
            	1495, 0,
            1, 8, 1, /* 1545: pointer.struct.asn1_string_st */
            	1495, 0,
            1, 8, 1, /* 1550: pointer.struct.asn1_string_st */
            	1495, 0,
            1, 8, 1, /* 1555: pointer.struct.asn1_string_st */
            	1495, 0,
            1, 8, 1, /* 1560: pointer.struct.asn1_string_st */
            	1495, 0,
            1, 8, 1, /* 1565: pointer.struct.asn1_string_st */
            	1495, 0,
            1, 8, 1, /* 1570: pointer.struct.ASN1_VALUE_st */
            	1575, 0,
            0, 0, 0, /* 1575: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1578: pointer.struct.X509_name_st */
            	1583, 0,
            0, 40, 3, /* 1583: struct.X509_name_st */
            	1592, 0,
            	1616, 16,
            	165, 24,
            1, 8, 1, /* 1592: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1597, 0,
            0, 32, 2, /* 1597: struct.stack_st_fake_X509_NAME_ENTRY */
            	1604, 8,
            	417, 24,
            8884099, 8, 2, /* 1604: pointer_to_array_of_pointers_to_stack */
            	1611, 0,
            	414, 20,
            0, 8, 1, /* 1611: pointer.X509_NAME_ENTRY */
            	378, 0,
            1, 8, 1, /* 1616: pointer.struct.buf_mem_st */
            	1621, 0,
            0, 24, 1, /* 1621: struct.buf_mem_st */
            	257, 8,
            1, 8, 1, /* 1626: pointer.struct.EDIPartyName_st */
            	1631, 0,
            0, 16, 2, /* 1631: struct.EDIPartyName_st */
            	1490, 0,
            	1490, 8,
            1, 8, 1, /* 1638: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1643, 0,
            0, 32, 2, /* 1643: struct.stack_st_fake_X509_NAME_ENTRY */
            	1650, 8,
            	417, 24,
            8884099, 8, 2, /* 1650: pointer_to_array_of_pointers_to_stack */
            	1657, 0,
            	414, 20,
            0, 8, 1, /* 1657: pointer.X509_NAME_ENTRY */
            	378, 0,
            1, 8, 1, /* 1662: pointer.struct.X509_name_st */
            	1667, 0,
            0, 40, 3, /* 1667: struct.X509_name_st */
            	1638, 0,
            	1676, 16,
            	165, 24,
            1, 8, 1, /* 1676: pointer.struct.buf_mem_st */
            	1681, 0,
            0, 24, 1, /* 1681: struct.buf_mem_st */
            	257, 8,
            1, 8, 1, /* 1686: pointer.struct.asn1_string_st */
            	1691, 0,
            0, 24, 1, /* 1691: struct.asn1_string_st */
            	165, 8,
            1, 8, 1, /* 1696: pointer.struct.stack_st_GENERAL_NAME */
            	1701, 0,
            0, 32, 2, /* 1701: struct.stack_st_fake_GENERAL_NAME */
            	1708, 8,
            	417, 24,
            8884099, 8, 2, /* 1708: pointer_to_array_of_pointers_to_stack */
            	1715, 0,
            	414, 20,
            0, 8, 1, /* 1715: pointer.GENERAL_NAME */
            	1368, 0,
            1, 8, 1, /* 1720: pointer.struct.NAME_CONSTRAINTS_st */
            	1725, 0,
            0, 0, 0, /* 1725: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 1728: pointer.struct.x509_cert_aux_st */
            	1733, 0,
            0, 40, 5, /* 1733: struct.x509_cert_aux_st */
            	1746, 0,
            	1746, 8,
            	327, 16,
            	277, 24,
            	1775, 32,
            1, 8, 1, /* 1746: pointer.struct.stack_st_ASN1_OBJECT */
            	1751, 0,
            0, 32, 2, /* 1751: struct.stack_st_fake_ASN1_OBJECT */
            	1758, 8,
            	417, 24,
            8884099, 8, 2, /* 1758: pointer_to_array_of_pointers_to_stack */
            	1765, 0,
            	414, 20,
            0, 8, 1, /* 1765: pointer.ASN1_OBJECT */
            	1770, 0,
            0, 0, 1, /* 1770: ASN1_OBJECT */
            	978, 0,
            1, 8, 1, /* 1775: pointer.struct.stack_st_X509_ALGOR */
            	1780, 0,
            0, 32, 2, /* 1780: struct.stack_st_fake_X509_ALGOR */
            	1787, 8,
            	417, 24,
            8884099, 8, 2, /* 1787: pointer_to_array_of_pointers_to_stack */
            	1794, 0,
            	414, 20,
            0, 8, 1, /* 1794: pointer.X509_ALGOR */
            	1799, 0,
            0, 0, 1, /* 1799: X509_ALGOR */
            	1804, 0,
            0, 16, 2, /* 1804: struct.X509_algor_st */
            	1811, 0,
            	1825, 8,
            1, 8, 1, /* 1811: pointer.struct.asn1_object_st */
            	1816, 0,
            0, 40, 3, /* 1816: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	199, 24,
            1, 8, 1, /* 1825: pointer.struct.asn1_type_st */
            	1830, 0,
            0, 16, 1, /* 1830: struct.asn1_type_st */
            	1835, 8,
            0, 8, 20, /* 1835: union.unknown */
            	257, 0,
            	1878, 0,
            	1811, 0,
            	1888, 0,
            	1893, 0,
            	1898, 0,
            	1903, 0,
            	1908, 0,
            	1913, 0,
            	1918, 0,
            	1923, 0,
            	1928, 0,
            	1933, 0,
            	1938, 0,
            	1943, 0,
            	1948, 0,
            	1953, 0,
            	1878, 0,
            	1878, 0,
            	1198, 0,
            1, 8, 1, /* 1878: pointer.struct.asn1_string_st */
            	1883, 0,
            0, 24, 1, /* 1883: struct.asn1_string_st */
            	165, 8,
            1, 8, 1, /* 1888: pointer.struct.asn1_string_st */
            	1883, 0,
            1, 8, 1, /* 1893: pointer.struct.asn1_string_st */
            	1883, 0,
            1, 8, 1, /* 1898: pointer.struct.asn1_string_st */
            	1883, 0,
            1, 8, 1, /* 1903: pointer.struct.asn1_string_st */
            	1883, 0,
            1, 8, 1, /* 1908: pointer.struct.asn1_string_st */
            	1883, 0,
            1, 8, 1, /* 1913: pointer.struct.asn1_string_st */
            	1883, 0,
            1, 8, 1, /* 1918: pointer.struct.asn1_string_st */
            	1883, 0,
            1, 8, 1, /* 1923: pointer.struct.asn1_string_st */
            	1883, 0,
            1, 8, 1, /* 1928: pointer.struct.asn1_string_st */
            	1883, 0,
            1, 8, 1, /* 1933: pointer.struct.asn1_string_st */
            	1883, 0,
            1, 8, 1, /* 1938: pointer.struct.asn1_string_st */
            	1883, 0,
            1, 8, 1, /* 1943: pointer.struct.asn1_string_st */
            	1883, 0,
            1, 8, 1, /* 1948: pointer.struct.asn1_string_st */
            	1883, 0,
            1, 8, 1, /* 1953: pointer.struct.asn1_string_st */
            	1883, 0,
            1, 8, 1, /* 1958: pointer.struct.env_md_st */
            	1963, 0,
            0, 120, 8, /* 1963: struct.env_md_st */
            	1982, 24,
            	1985, 32,
            	1988, 40,
            	1991, 48,
            	1982, 56,
            	1994, 64,
            	1997, 72,
            	2000, 112,
            8884097, 8, 0, /* 1982: pointer.func */
            8884097, 8, 0, /* 1985: pointer.func */
            8884097, 8, 0, /* 1988: pointer.func */
            8884097, 8, 0, /* 1991: pointer.func */
            8884097, 8, 0, /* 1994: pointer.func */
            8884097, 8, 0, /* 1997: pointer.func */
            8884097, 8, 0, /* 2000: pointer.func */
            1, 8, 1, /* 2003: pointer.struct.rsa_st */
            	511, 0,
            1, 8, 1, /* 2008: pointer.struct.dh_st */
            	756, 0,
            1, 8, 1, /* 2013: pointer.struct.ec_key_st */
            	824, 0,
            1, 8, 1, /* 2018: pointer.struct.cert_st */
            	62, 0,
            0, 24, 1, /* 2023: struct.buf_mem_st */
            	257, 8,
            1, 8, 1, /* 2028: pointer.struct.buf_mem_st */
            	2023, 0,
            0, 40, 3, /* 2033: struct.X509_name_st */
            	2042, 0,
            	2028, 16,
            	165, 24,
            1, 8, 1, /* 2042: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2047, 0,
            0, 32, 2, /* 2047: struct.stack_st_fake_X509_NAME_ENTRY */
            	2054, 8,
            	417, 24,
            8884099, 8, 2, /* 2054: pointer_to_array_of_pointers_to_stack */
            	2061, 0,
            	414, 20,
            0, 8, 1, /* 2061: pointer.X509_NAME_ENTRY */
            	378, 0,
            8884097, 8, 0, /* 2066: pointer.func */
            8884097, 8, 0, /* 2069: pointer.func */
            8884097, 8, 0, /* 2072: pointer.func */
            0, 64, 7, /* 2075: struct.comp_method_st */
            	5, 8,
            	2092, 16,
            	2072, 24,
            	2069, 32,
            	2069, 40,
            	2095, 48,
            	2095, 56,
            8884097, 8, 0, /* 2092: pointer.func */
            8884097, 8, 0, /* 2095: pointer.func */
            1, 8, 1, /* 2098: pointer.struct.comp_method_st */
            	2075, 0,
            1, 8, 1, /* 2103: pointer.struct.stack_st_SSL_COMP */
            	2108, 0,
            0, 32, 2, /* 2108: struct.stack_st_fake_SSL_COMP */
            	2115, 8,
            	417, 24,
            8884099, 8, 2, /* 2115: pointer_to_array_of_pointers_to_stack */
            	2122, 0,
            	414, 20,
            0, 8, 1, /* 2122: pointer.SSL_COMP */
            	2127, 0,
            0, 0, 1, /* 2127: SSL_COMP */
            	2132, 0,
            0, 24, 2, /* 2132: struct.ssl_comp_st */
            	5, 8,
            	2098, 16,
            8884097, 8, 0, /* 2139: pointer.func */
            8884097, 8, 0, /* 2142: pointer.func */
            8884097, 8, 0, /* 2145: pointer.func */
            8884097, 8, 0, /* 2148: pointer.func */
            8884097, 8, 0, /* 2151: pointer.func */
            0, 16, 1, /* 2154: struct.crypto_ex_data_st */
            	2159, 0,
            1, 8, 1, /* 2159: pointer.struct.stack_st_void */
            	2164, 0,
            0, 32, 1, /* 2164: struct.stack_st_void */
            	2169, 0,
            0, 32, 2, /* 2169: struct.stack_st */
            	643, 8,
            	417, 24,
            0, 24, 1, /* 2176: struct.ASN1_ENCODING_st */
            	165, 0,
            8884097, 8, 0, /* 2181: pointer.func */
            0, 144, 12, /* 2184: struct.dh_st */
            	2211, 8,
            	2211, 16,
            	2211, 32,
            	2211, 40,
            	2221, 56,
            	2211, 64,
            	2211, 72,
            	165, 80,
            	2211, 96,
            	2235, 112,
            	2257, 128,
            	2293, 136,
            1, 8, 1, /* 2211: pointer.struct.bignum_st */
            	2216, 0,
            0, 24, 1, /* 2216: struct.bignum_st */
            	613, 0,
            1, 8, 1, /* 2221: pointer.struct.bn_mont_ctx_st */
            	2226, 0,
            0, 96, 3, /* 2226: struct.bn_mont_ctx_st */
            	2216, 8,
            	2216, 32,
            	2216, 56,
            0, 16, 1, /* 2235: struct.crypto_ex_data_st */
            	2240, 0,
            1, 8, 1, /* 2240: pointer.struct.stack_st_void */
            	2245, 0,
            0, 32, 1, /* 2245: struct.stack_st_void */
            	2250, 0,
            0, 32, 2, /* 2250: struct.stack_st */
            	643, 8,
            	417, 24,
            1, 8, 1, /* 2257: pointer.struct.dh_method */
            	2262, 0,
            0, 72, 8, /* 2262: struct.dh_method */
            	5, 0,
            	2281, 8,
            	2284, 16,
            	2287, 24,
            	2281, 32,
            	2281, 40,
            	257, 56,
            	2290, 64,
            8884097, 8, 0, /* 2281: pointer.func */
            8884097, 8, 0, /* 2284: pointer.func */
            8884097, 8, 0, /* 2287: pointer.func */
            8884097, 8, 0, /* 2290: pointer.func */
            1, 8, 1, /* 2293: pointer.struct.engine_st */
            	2298, 0,
            0, 0, 0, /* 2298: struct.engine_st */
            0, 0, 1, /* 2301: X509_LOOKUP */
            	2306, 0,
            0, 32, 3, /* 2306: struct.x509_lookup_st */
            	2315, 8,
            	257, 16,
            	2364, 24,
            1, 8, 1, /* 2315: pointer.struct.x509_lookup_method_st */
            	2320, 0,
            0, 80, 10, /* 2320: struct.x509_lookup_method_st */
            	5, 0,
            	2343, 8,
            	2346, 16,
            	2343, 24,
            	2343, 32,
            	2349, 40,
            	2352, 48,
            	2355, 56,
            	2358, 64,
            	2361, 72,
            8884097, 8, 0, /* 2343: pointer.func */
            8884097, 8, 0, /* 2346: pointer.func */
            8884097, 8, 0, /* 2349: pointer.func */
            8884097, 8, 0, /* 2352: pointer.func */
            8884097, 8, 0, /* 2355: pointer.func */
            8884097, 8, 0, /* 2358: pointer.func */
            8884097, 8, 0, /* 2361: pointer.func */
            1, 8, 1, /* 2364: pointer.struct.x509_store_st */
            	2369, 0,
            0, 144, 15, /* 2369: struct.x509_store_st */
            	2402, 8,
            	3479, 16,
            	3503, 24,
            	3515, 32,
            	3518, 40,
            	3521, 48,
            	3524, 56,
            	3515, 64,
            	3527, 72,
            	3530, 80,
            	3533, 88,
            	3536, 96,
            	3539, 104,
            	3515, 112,
            	2154, 120,
            1, 8, 1, /* 2402: pointer.struct.stack_st_X509_OBJECT */
            	2407, 0,
            0, 32, 2, /* 2407: struct.stack_st_fake_X509_OBJECT */
            	2414, 8,
            	417, 24,
            8884099, 8, 2, /* 2414: pointer_to_array_of_pointers_to_stack */
            	2421, 0,
            	414, 20,
            0, 8, 1, /* 2421: pointer.X509_OBJECT */
            	2426, 0,
            0, 0, 1, /* 2426: X509_OBJECT */
            	2431, 0,
            0, 16, 1, /* 2431: struct.x509_object_st */
            	2436, 8,
            0, 8, 4, /* 2436: union.unknown */
            	257, 0,
            	2447, 0,
            	3264, 0,
            	2747, 0,
            1, 8, 1, /* 2447: pointer.struct.x509_st */
            	2452, 0,
            0, 184, 12, /* 2452: struct.x509_st */
            	2479, 0,
            	2519, 8,
            	2608, 16,
            	257, 32,
            	2154, 40,
            	2613, 104,
            	3126, 112,
            	3134, 120,
            	3142, 128,
            	3166, 136,
            	3190, 144,
            	3198, 176,
            1, 8, 1, /* 2479: pointer.struct.x509_cinf_st */
            	2484, 0,
            0, 104, 11, /* 2484: struct.x509_cinf_st */
            	2509, 0,
            	2509, 8,
            	2519, 16,
            	2668, 24,
            	2716, 32,
            	2668, 40,
            	2733, 48,
            	2608, 56,
            	2608, 64,
            	3102, 72,
            	2176, 80,
            1, 8, 1, /* 2509: pointer.struct.asn1_string_st */
            	2514, 0,
            0, 24, 1, /* 2514: struct.asn1_string_st */
            	165, 8,
            1, 8, 1, /* 2519: pointer.struct.X509_algor_st */
            	2524, 0,
            0, 16, 2, /* 2524: struct.X509_algor_st */
            	2531, 0,
            	2545, 8,
            1, 8, 1, /* 2531: pointer.struct.asn1_object_st */
            	2536, 0,
            0, 40, 3, /* 2536: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	199, 24,
            1, 8, 1, /* 2545: pointer.struct.asn1_type_st */
            	2550, 0,
            0, 16, 1, /* 2550: struct.asn1_type_st */
            	2555, 8,
            0, 8, 20, /* 2555: union.unknown */
            	257, 0,
            	2598, 0,
            	2531, 0,
            	2509, 0,
            	2603, 0,
            	2608, 0,
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
            	2598, 0,
            	2598, 0,
            	1198, 0,
            1, 8, 1, /* 2598: pointer.struct.asn1_string_st */
            	2514, 0,
            1, 8, 1, /* 2603: pointer.struct.asn1_string_st */
            	2514, 0,
            1, 8, 1, /* 2608: pointer.struct.asn1_string_st */
            	2514, 0,
            1, 8, 1, /* 2613: pointer.struct.asn1_string_st */
            	2514, 0,
            1, 8, 1, /* 2618: pointer.struct.asn1_string_st */
            	2514, 0,
            1, 8, 1, /* 2623: pointer.struct.asn1_string_st */
            	2514, 0,
            1, 8, 1, /* 2628: pointer.struct.asn1_string_st */
            	2514, 0,
            1, 8, 1, /* 2633: pointer.struct.asn1_string_st */
            	2514, 0,
            1, 8, 1, /* 2638: pointer.struct.asn1_string_st */
            	2514, 0,
            1, 8, 1, /* 2643: pointer.struct.asn1_string_st */
            	2514, 0,
            1, 8, 1, /* 2648: pointer.struct.asn1_string_st */
            	2514, 0,
            1, 8, 1, /* 2653: pointer.struct.asn1_string_st */
            	2514, 0,
            1, 8, 1, /* 2658: pointer.struct.asn1_string_st */
            	2514, 0,
            1, 8, 1, /* 2663: pointer.struct.asn1_string_st */
            	2514, 0,
            1, 8, 1, /* 2668: pointer.struct.X509_name_st */
            	2673, 0,
            0, 40, 3, /* 2673: struct.X509_name_st */
            	2682, 0,
            	2706, 16,
            	165, 24,
            1, 8, 1, /* 2682: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2687, 0,
            0, 32, 2, /* 2687: struct.stack_st_fake_X509_NAME_ENTRY */
            	2694, 8,
            	417, 24,
            8884099, 8, 2, /* 2694: pointer_to_array_of_pointers_to_stack */
            	2701, 0,
            	414, 20,
            0, 8, 1, /* 2701: pointer.X509_NAME_ENTRY */
            	378, 0,
            1, 8, 1, /* 2706: pointer.struct.buf_mem_st */
            	2711, 0,
            0, 24, 1, /* 2711: struct.buf_mem_st */
            	257, 8,
            1, 8, 1, /* 2716: pointer.struct.X509_val_st */
            	2721, 0,
            0, 16, 2, /* 2721: struct.X509_val_st */
            	2728, 0,
            	2728, 8,
            1, 8, 1, /* 2728: pointer.struct.asn1_string_st */
            	2514, 0,
            1, 8, 1, /* 2733: pointer.struct.X509_pubkey_st */
            	2738, 0,
            0, 24, 3, /* 2738: struct.X509_pubkey_st */
            	2519, 0,
            	2608, 8,
            	2747, 16,
            1, 8, 1, /* 2747: pointer.struct.evp_pkey_st */
            	2752, 0,
            0, 56, 4, /* 2752: struct.evp_pkey_st */
            	2763, 16,
            	2771, 24,
            	2779, 32,
            	3078, 48,
            1, 8, 1, /* 2763: pointer.struct.evp_pkey_asn1_method_st */
            	2768, 0,
            0, 0, 0, /* 2768: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 2771: pointer.struct.engine_st */
            	2776, 0,
            0, 0, 0, /* 2776: struct.engine_st */
            0, 8, 5, /* 2779: union.unknown */
            	257, 0,
            	2792, 0,
            	2921, 0,
            	3002, 0,
            	3070, 0,
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
            	2154, 96,
            	2899, 120,
            	2899, 128,
            	2899, 136,
            	257, 144,
            	2913, 152,
            	2913, 160,
            1, 8, 1, /* 2834: pointer.struct.rsa_meth_st */
            	2839, 0,
            0, 112, 13, /* 2839: struct.rsa_meth_st */
            	5, 0,
            	2868, 8,
            	2868, 16,
            	2868, 24,
            	2868, 32,
            	2871, 40,
            	2874, 48,
            	2877, 56,
            	2877, 64,
            	257, 80,
            	2880, 88,
            	2883, 96,
            	2886, 104,
            8884097, 8, 0, /* 2868: pointer.func */
            8884097, 8, 0, /* 2871: pointer.func */
            8884097, 8, 0, /* 2874: pointer.func */
            8884097, 8, 0, /* 2877: pointer.func */
            8884097, 8, 0, /* 2880: pointer.func */
            8884097, 8, 0, /* 2883: pointer.func */
            8884097, 8, 0, /* 2886: pointer.func */
            1, 8, 1, /* 2889: pointer.struct.bignum_st */
            	2894, 0,
            0, 24, 1, /* 2894: struct.bignum_st */
            	613, 0,
            1, 8, 1, /* 2899: pointer.struct.bn_mont_ctx_st */
            	2904, 0,
            0, 96, 3, /* 2904: struct.bn_mont_ctx_st */
            	2894, 8,
            	2894, 32,
            	2894, 56,
            1, 8, 1, /* 2913: pointer.struct.bn_blinding_st */
            	2918, 0,
            0, 0, 0, /* 2918: struct.bn_blinding_st */
            1, 8, 1, /* 2921: pointer.struct.dsa_st */
            	2926, 0,
            0, 136, 11, /* 2926: struct.dsa_st */
            	2889, 24,
            	2889, 32,
            	2889, 40,
            	2889, 48,
            	2889, 56,
            	2889, 64,
            	2889, 72,
            	2899, 88,
            	2154, 104,
            	2951, 120,
            	2771, 128,
            1, 8, 1, /* 2951: pointer.struct.dsa_method */
            	2956, 0,
            0, 96, 11, /* 2956: struct.dsa_method */
            	5, 0,
            	2981, 8,
            	2984, 16,
            	2987, 24,
            	2990, 32,
            	2993, 40,
            	2996, 48,
            	2996, 56,
            	257, 72,
            	2999, 80,
            	2996, 88,
            8884097, 8, 0, /* 2981: pointer.func */
            8884097, 8, 0, /* 2984: pointer.func */
            8884097, 8, 0, /* 2987: pointer.func */
            8884097, 8, 0, /* 2990: pointer.func */
            8884097, 8, 0, /* 2993: pointer.func */
            8884097, 8, 0, /* 2996: pointer.func */
            8884097, 8, 0, /* 2999: pointer.func */
            1, 8, 1, /* 3002: pointer.struct.dh_st */
            	3007, 0,
            0, 144, 12, /* 3007: struct.dh_st */
            	2889, 8,
            	2889, 16,
            	2889, 32,
            	2889, 40,
            	2899, 56,
            	2889, 64,
            	2889, 72,
            	165, 80,
            	2889, 96,
            	2154, 112,
            	3034, 128,
            	2771, 136,
            1, 8, 1, /* 3034: pointer.struct.dh_method */
            	3039, 0,
            0, 72, 8, /* 3039: struct.dh_method */
            	5, 0,
            	3058, 8,
            	3061, 16,
            	3064, 24,
            	3058, 32,
            	3058, 40,
            	257, 56,
            	3067, 64,
            8884097, 8, 0, /* 3058: pointer.func */
            8884097, 8, 0, /* 3061: pointer.func */
            8884097, 8, 0, /* 3064: pointer.func */
            8884097, 8, 0, /* 3067: pointer.func */
            1, 8, 1, /* 3070: pointer.struct.ec_key_st */
            	3075, 0,
            0, 0, 0, /* 3075: struct.ec_key_st */
            1, 8, 1, /* 3078: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3083, 0,
            0, 32, 2, /* 3083: struct.stack_st_fake_X509_ATTRIBUTE */
            	3090, 8,
            	417, 24,
            8884099, 8, 2, /* 3090: pointer_to_array_of_pointers_to_stack */
            	3097, 0,
            	414, 20,
            0, 8, 1, /* 3097: pointer.X509_ATTRIBUTE */
            	851, 0,
            1, 8, 1, /* 3102: pointer.struct.stack_st_X509_EXTENSION */
            	3107, 0,
            0, 32, 2, /* 3107: struct.stack_st_fake_X509_EXTENSION */
            	3114, 8,
            	417, 24,
            8884099, 8, 2, /* 3114: pointer_to_array_of_pointers_to_stack */
            	3121, 0,
            	414, 20,
            0, 8, 1, /* 3121: pointer.X509_EXTENSION */
            	1230, 0,
            1, 8, 1, /* 3126: pointer.struct.AUTHORITY_KEYID_st */
            	3131, 0,
            0, 0, 0, /* 3131: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 3134: pointer.struct.X509_POLICY_CACHE_st */
            	3139, 0,
            0, 0, 0, /* 3139: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 3142: pointer.struct.stack_st_DIST_POINT */
            	3147, 0,
            0, 32, 2, /* 3147: struct.stack_st_fake_DIST_POINT */
            	3154, 8,
            	417, 24,
            8884099, 8, 2, /* 3154: pointer_to_array_of_pointers_to_stack */
            	3161, 0,
            	414, 20,
            0, 8, 1, /* 3161: pointer.DIST_POINT */
            	1311, 0,
            1, 8, 1, /* 3166: pointer.struct.stack_st_GENERAL_NAME */
            	3171, 0,
            0, 32, 2, /* 3171: struct.stack_st_fake_GENERAL_NAME */
            	3178, 8,
            	417, 24,
            8884099, 8, 2, /* 3178: pointer_to_array_of_pointers_to_stack */
            	3185, 0,
            	414, 20,
            0, 8, 1, /* 3185: pointer.GENERAL_NAME */
            	1368, 0,
            1, 8, 1, /* 3190: pointer.struct.NAME_CONSTRAINTS_st */
            	3195, 0,
            0, 0, 0, /* 3195: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3198: pointer.struct.x509_cert_aux_st */
            	3203, 0,
            0, 40, 5, /* 3203: struct.x509_cert_aux_st */
            	3216, 0,
            	3216, 8,
            	2663, 16,
            	2613, 24,
            	3240, 32,
            1, 8, 1, /* 3216: pointer.struct.stack_st_ASN1_OBJECT */
            	3221, 0,
            0, 32, 2, /* 3221: struct.stack_st_fake_ASN1_OBJECT */
            	3228, 8,
            	417, 24,
            8884099, 8, 2, /* 3228: pointer_to_array_of_pointers_to_stack */
            	3235, 0,
            	414, 20,
            0, 8, 1, /* 3235: pointer.ASN1_OBJECT */
            	1770, 0,
            1, 8, 1, /* 3240: pointer.struct.stack_st_X509_ALGOR */
            	3245, 0,
            0, 32, 2, /* 3245: struct.stack_st_fake_X509_ALGOR */
            	3252, 8,
            	417, 24,
            8884099, 8, 2, /* 3252: pointer_to_array_of_pointers_to_stack */
            	3259, 0,
            	414, 20,
            0, 8, 1, /* 3259: pointer.X509_ALGOR */
            	1799, 0,
            1, 8, 1, /* 3264: pointer.struct.X509_crl_st */
            	3269, 0,
            0, 120, 10, /* 3269: struct.X509_crl_st */
            	3292, 0,
            	2519, 8,
            	2608, 16,
            	3126, 32,
            	3419, 40,
            	2509, 56,
            	2509, 64,
            	3427, 96,
            	3468, 104,
            	3476, 112,
            1, 8, 1, /* 3292: pointer.struct.X509_crl_info_st */
            	3297, 0,
            0, 80, 8, /* 3297: struct.X509_crl_info_st */
            	2509, 0,
            	2519, 8,
            	2668, 16,
            	2728, 24,
            	2728, 32,
            	3316, 40,
            	3102, 48,
            	2176, 56,
            1, 8, 1, /* 3316: pointer.struct.stack_st_X509_REVOKED */
            	3321, 0,
            0, 32, 2, /* 3321: struct.stack_st_fake_X509_REVOKED */
            	3328, 8,
            	417, 24,
            8884099, 8, 2, /* 3328: pointer_to_array_of_pointers_to_stack */
            	3335, 0,
            	414, 20,
            0, 8, 1, /* 3335: pointer.X509_REVOKED */
            	3340, 0,
            0, 0, 1, /* 3340: X509_REVOKED */
            	3345, 0,
            0, 40, 4, /* 3345: struct.x509_revoked_st */
            	3356, 0,
            	3366, 8,
            	3371, 16,
            	3395, 24,
            1, 8, 1, /* 3356: pointer.struct.asn1_string_st */
            	3361, 0,
            0, 24, 1, /* 3361: struct.asn1_string_st */
            	165, 8,
            1, 8, 1, /* 3366: pointer.struct.asn1_string_st */
            	3361, 0,
            1, 8, 1, /* 3371: pointer.struct.stack_st_X509_EXTENSION */
            	3376, 0,
            0, 32, 2, /* 3376: struct.stack_st_fake_X509_EXTENSION */
            	3383, 8,
            	417, 24,
            8884099, 8, 2, /* 3383: pointer_to_array_of_pointers_to_stack */
            	3390, 0,
            	414, 20,
            0, 8, 1, /* 3390: pointer.X509_EXTENSION */
            	1230, 0,
            1, 8, 1, /* 3395: pointer.struct.stack_st_GENERAL_NAME */
            	3400, 0,
            0, 32, 2, /* 3400: struct.stack_st_fake_GENERAL_NAME */
            	3407, 8,
            	417, 24,
            8884099, 8, 2, /* 3407: pointer_to_array_of_pointers_to_stack */
            	3414, 0,
            	414, 20,
            0, 8, 1, /* 3414: pointer.GENERAL_NAME */
            	1368, 0,
            1, 8, 1, /* 3419: pointer.struct.ISSUING_DIST_POINT_st */
            	3424, 0,
            0, 0, 0, /* 3424: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 3427: pointer.struct.stack_st_GENERAL_NAMES */
            	3432, 0,
            0, 32, 2, /* 3432: struct.stack_st_fake_GENERAL_NAMES */
            	3439, 8,
            	417, 24,
            8884099, 8, 2, /* 3439: pointer_to_array_of_pointers_to_stack */
            	3446, 0,
            	414, 20,
            0, 8, 1, /* 3446: pointer.GENERAL_NAMES */
            	3451, 0,
            0, 0, 1, /* 3451: GENERAL_NAMES */
            	3456, 0,
            0, 32, 1, /* 3456: struct.stack_st_GENERAL_NAME */
            	3461, 0,
            0, 32, 2, /* 3461: struct.stack_st */
            	643, 8,
            	417, 24,
            1, 8, 1, /* 3468: pointer.struct.x509_crl_method_st */
            	3473, 0,
            0, 0, 0, /* 3473: struct.x509_crl_method_st */
            0, 8, 0, /* 3476: pointer.void */
            1, 8, 1, /* 3479: pointer.struct.stack_st_X509_LOOKUP */
            	3484, 0,
            0, 32, 2, /* 3484: struct.stack_st_fake_X509_LOOKUP */
            	3491, 8,
            	417, 24,
            8884099, 8, 2, /* 3491: pointer_to_array_of_pointers_to_stack */
            	3498, 0,
            	414, 20,
            0, 8, 1, /* 3498: pointer.X509_LOOKUP */
            	2301, 0,
            1, 8, 1, /* 3503: pointer.struct.X509_VERIFY_PARAM_st */
            	3508, 0,
            0, 56, 2, /* 3508: struct.X509_VERIFY_PARAM_st */
            	257, 0,
            	3216, 48,
            8884097, 8, 0, /* 3515: pointer.func */
            8884097, 8, 0, /* 3518: pointer.func */
            8884097, 8, 0, /* 3521: pointer.func */
            8884097, 8, 0, /* 3524: pointer.func */
            8884097, 8, 0, /* 3527: pointer.func */
            8884097, 8, 0, /* 3530: pointer.func */
            8884097, 8, 0, /* 3533: pointer.func */
            8884097, 8, 0, /* 3536: pointer.func */
            8884097, 8, 0, /* 3539: pointer.func */
            8884097, 8, 0, /* 3542: pointer.func */
            8884097, 8, 0, /* 3545: pointer.func */
            0, 104, 11, /* 3548: struct.x509_cinf_st */
            	3573, 0,
            	3573, 8,
            	3583, 16,
            	3740, 24,
            	3788, 32,
            	3740, 40,
            	3805, 48,
            	3672, 56,
            	3672, 64,
            	4076, 72,
            	4100, 80,
            1, 8, 1, /* 3573: pointer.struct.asn1_string_st */
            	3578, 0,
            0, 24, 1, /* 3578: struct.asn1_string_st */
            	165, 8,
            1, 8, 1, /* 3583: pointer.struct.X509_algor_st */
            	3588, 0,
            0, 16, 2, /* 3588: struct.X509_algor_st */
            	3595, 0,
            	3609, 8,
            1, 8, 1, /* 3595: pointer.struct.asn1_object_st */
            	3600, 0,
            0, 40, 3, /* 3600: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	199, 24,
            1, 8, 1, /* 3609: pointer.struct.asn1_type_st */
            	3614, 0,
            0, 16, 1, /* 3614: struct.asn1_type_st */
            	3619, 8,
            0, 8, 20, /* 3619: union.unknown */
            	257, 0,
            	3662, 0,
            	3595, 0,
            	3573, 0,
            	3667, 0,
            	3672, 0,
            	3677, 0,
            	3682, 0,
            	3687, 0,
            	3692, 0,
            	3697, 0,
            	3702, 0,
            	3707, 0,
            	3712, 0,
            	3717, 0,
            	3722, 0,
            	3727, 0,
            	3662, 0,
            	3662, 0,
            	3732, 0,
            1, 8, 1, /* 3662: pointer.struct.asn1_string_st */
            	3578, 0,
            1, 8, 1, /* 3667: pointer.struct.asn1_string_st */
            	3578, 0,
            1, 8, 1, /* 3672: pointer.struct.asn1_string_st */
            	3578, 0,
            1, 8, 1, /* 3677: pointer.struct.asn1_string_st */
            	3578, 0,
            1, 8, 1, /* 3682: pointer.struct.asn1_string_st */
            	3578, 0,
            1, 8, 1, /* 3687: pointer.struct.asn1_string_st */
            	3578, 0,
            1, 8, 1, /* 3692: pointer.struct.asn1_string_st */
            	3578, 0,
            1, 8, 1, /* 3697: pointer.struct.asn1_string_st */
            	3578, 0,
            1, 8, 1, /* 3702: pointer.struct.asn1_string_st */
            	3578, 0,
            1, 8, 1, /* 3707: pointer.struct.asn1_string_st */
            	3578, 0,
            1, 8, 1, /* 3712: pointer.struct.asn1_string_st */
            	3578, 0,
            1, 8, 1, /* 3717: pointer.struct.asn1_string_st */
            	3578, 0,
            1, 8, 1, /* 3722: pointer.struct.asn1_string_st */
            	3578, 0,
            1, 8, 1, /* 3727: pointer.struct.asn1_string_st */
            	3578, 0,
            1, 8, 1, /* 3732: pointer.struct.ASN1_VALUE_st */
            	3737, 0,
            0, 0, 0, /* 3737: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3740: pointer.struct.X509_name_st */
            	3745, 0,
            0, 40, 3, /* 3745: struct.X509_name_st */
            	3754, 0,
            	3778, 16,
            	165, 24,
            1, 8, 1, /* 3754: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3759, 0,
            0, 32, 2, /* 3759: struct.stack_st_fake_X509_NAME_ENTRY */
            	3766, 8,
            	417, 24,
            8884099, 8, 2, /* 3766: pointer_to_array_of_pointers_to_stack */
            	3773, 0,
            	414, 20,
            0, 8, 1, /* 3773: pointer.X509_NAME_ENTRY */
            	378, 0,
            1, 8, 1, /* 3778: pointer.struct.buf_mem_st */
            	3783, 0,
            0, 24, 1, /* 3783: struct.buf_mem_st */
            	257, 8,
            1, 8, 1, /* 3788: pointer.struct.X509_val_st */
            	3793, 0,
            0, 16, 2, /* 3793: struct.X509_val_st */
            	3800, 0,
            	3800, 8,
            1, 8, 1, /* 3800: pointer.struct.asn1_string_st */
            	3578, 0,
            1, 8, 1, /* 3805: pointer.struct.X509_pubkey_st */
            	3810, 0,
            0, 24, 3, /* 3810: struct.X509_pubkey_st */
            	3583, 0,
            	3672, 8,
            	3819, 16,
            1, 8, 1, /* 3819: pointer.struct.evp_pkey_st */
            	3824, 0,
            0, 56, 4, /* 3824: struct.evp_pkey_st */
            	3835, 16,
            	2293, 24,
            	3843, 32,
            	4052, 48,
            1, 8, 1, /* 3835: pointer.struct.evp_pkey_asn1_method_st */
            	3840, 0,
            0, 0, 0, /* 3840: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 3843: union.unknown */
            	257, 0,
            	3856, 0,
            	3961, 0,
            	4039, 0,
            	4044, 0,
            1, 8, 1, /* 3856: pointer.struct.rsa_st */
            	3861, 0,
            0, 168, 17, /* 3861: struct.rsa_st */
            	3898, 16,
            	2293, 24,
            	2211, 32,
            	2211, 40,
            	2211, 48,
            	2211, 56,
            	2211, 64,
            	2211, 72,
            	2211, 80,
            	2211, 88,
            	2235, 96,
            	2221, 120,
            	2221, 128,
            	2221, 136,
            	257, 144,
            	3953, 152,
            	3953, 160,
            1, 8, 1, /* 3898: pointer.struct.rsa_meth_st */
            	3903, 0,
            0, 112, 13, /* 3903: struct.rsa_meth_st */
            	5, 0,
            	3932, 8,
            	3932, 16,
            	3932, 24,
            	3932, 32,
            	3935, 40,
            	3938, 48,
            	3941, 56,
            	3941, 64,
            	257, 80,
            	3944, 88,
            	3947, 96,
            	3950, 104,
            8884097, 8, 0, /* 3932: pointer.func */
            8884097, 8, 0, /* 3935: pointer.func */
            8884097, 8, 0, /* 3938: pointer.func */
            8884097, 8, 0, /* 3941: pointer.func */
            8884097, 8, 0, /* 3944: pointer.func */
            8884097, 8, 0, /* 3947: pointer.func */
            8884097, 8, 0, /* 3950: pointer.func */
            1, 8, 1, /* 3953: pointer.struct.bn_blinding_st */
            	3958, 0,
            0, 0, 0, /* 3958: struct.bn_blinding_st */
            1, 8, 1, /* 3961: pointer.struct.dsa_st */
            	3966, 0,
            0, 136, 11, /* 3966: struct.dsa_st */
            	2211, 24,
            	2211, 32,
            	2211, 40,
            	2211, 48,
            	2211, 56,
            	2211, 64,
            	2211, 72,
            	2221, 88,
            	2235, 104,
            	3991, 120,
            	2293, 128,
            1, 8, 1, /* 3991: pointer.struct.dsa_method */
            	3996, 0,
            0, 96, 11, /* 3996: struct.dsa_method */
            	5, 0,
            	4021, 8,
            	4024, 16,
            	4027, 24,
            	3545, 32,
            	4030, 40,
            	4033, 48,
            	4033, 56,
            	257, 72,
            	4036, 80,
            	4033, 88,
            8884097, 8, 0, /* 4021: pointer.func */
            8884097, 8, 0, /* 4024: pointer.func */
            8884097, 8, 0, /* 4027: pointer.func */
            8884097, 8, 0, /* 4030: pointer.func */
            8884097, 8, 0, /* 4033: pointer.func */
            8884097, 8, 0, /* 4036: pointer.func */
            1, 8, 1, /* 4039: pointer.struct.dh_st */
            	2184, 0,
            1, 8, 1, /* 4044: pointer.struct.ec_key_st */
            	4049, 0,
            0, 0, 0, /* 4049: struct.ec_key_st */
            1, 8, 1, /* 4052: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4057, 0,
            0, 32, 2, /* 4057: struct.stack_st_fake_X509_ATTRIBUTE */
            	4064, 8,
            	417, 24,
            8884099, 8, 2, /* 4064: pointer_to_array_of_pointers_to_stack */
            	4071, 0,
            	414, 20,
            0, 8, 1, /* 4071: pointer.X509_ATTRIBUTE */
            	851, 0,
            1, 8, 1, /* 4076: pointer.struct.stack_st_X509_EXTENSION */
            	4081, 0,
            0, 32, 2, /* 4081: struct.stack_st_fake_X509_EXTENSION */
            	4088, 8,
            	417, 24,
            8884099, 8, 2, /* 4088: pointer_to_array_of_pointers_to_stack */
            	4095, 0,
            	414, 20,
            0, 8, 1, /* 4095: pointer.X509_EXTENSION */
            	1230, 0,
            0, 24, 1, /* 4100: struct.ASN1_ENCODING_st */
            	165, 0,
            0, 0, 0, /* 4105: struct.X509_POLICY_CACHE_st */
            8884097, 8, 0, /* 4108: pointer.func */
            1, 8, 1, /* 4111: pointer.struct.ssl_cipher_st */
            	4116, 0,
            0, 88, 1, /* 4116: struct.ssl_cipher_st */
            	5, 8,
            8884097, 8, 0, /* 4121: pointer.func */
            8884097, 8, 0, /* 4124: pointer.func */
            0, 0, 0, /* 4127: struct.NAME_CONSTRAINTS_st */
            8884097, 8, 0, /* 4130: pointer.func */
            8884097, 8, 0, /* 4133: pointer.func */
            8884097, 8, 0, /* 4136: pointer.func */
            0, 0, 1, /* 4139: SSL_CIPHER */
            	4144, 0,
            0, 88, 1, /* 4144: struct.ssl_cipher_st */
            	5, 8,
            0, 8, 1, /* 4149: pointer.SRTP_PROTECTION_PROFILE */
            	10, 0,
            8884097, 8, 0, /* 4154: pointer.func */
            8884097, 8, 0, /* 4157: pointer.func */
            1, 8, 1, /* 4160: pointer.struct.ssl_method_st */
            	4165, 0,
            0, 232, 28, /* 4165: struct.ssl_method_st */
            	4157, 8,
            	4224, 16,
            	4224, 24,
            	4157, 32,
            	4157, 40,
            	4227, 48,
            	4227, 56,
            	4230, 64,
            	4157, 72,
            	4157, 80,
            	4157, 88,
            	4233, 96,
            	4154, 104,
            	4236, 112,
            	4157, 120,
            	4239, 128,
            	4242, 136,
            	4245, 144,
            	4248, 152,
            	4251, 160,
            	4254, 168,
            	4257, 176,
            	2181, 184,
            	2095, 192,
            	4260, 200,
            	4254, 208,
            	4305, 216,
            	4308, 224,
            8884097, 8, 0, /* 4224: pointer.func */
            8884097, 8, 0, /* 4227: pointer.func */
            8884097, 8, 0, /* 4230: pointer.func */
            8884097, 8, 0, /* 4233: pointer.func */
            8884097, 8, 0, /* 4236: pointer.func */
            8884097, 8, 0, /* 4239: pointer.func */
            8884097, 8, 0, /* 4242: pointer.func */
            8884097, 8, 0, /* 4245: pointer.func */
            8884097, 8, 0, /* 4248: pointer.func */
            8884097, 8, 0, /* 4251: pointer.func */
            8884097, 8, 0, /* 4254: pointer.func */
            8884097, 8, 0, /* 4257: pointer.func */
            1, 8, 1, /* 4260: pointer.struct.ssl3_enc_method */
            	4265, 0,
            0, 112, 11, /* 4265: struct.ssl3_enc_method */
            	4290, 0,
            	4293, 8,
            	4157, 16,
            	4296, 24,
            	4290, 32,
            	4136, 40,
            	4299, 56,
            	5, 64,
            	5, 80,
            	4302, 96,
            	4108, 104,
            8884097, 8, 0, /* 4290: pointer.func */
            8884097, 8, 0, /* 4293: pointer.func */
            8884097, 8, 0, /* 4296: pointer.func */
            8884097, 8, 0, /* 4299: pointer.func */
            8884097, 8, 0, /* 4302: pointer.func */
            8884097, 8, 0, /* 4305: pointer.func */
            8884097, 8, 0, /* 4308: pointer.func */
            1, 8, 1, /* 4311: pointer.struct.stack_st_SSL_CIPHER */
            	4316, 0,
            0, 32, 2, /* 4316: struct.stack_st_fake_SSL_CIPHER */
            	4323, 8,
            	417, 24,
            8884099, 8, 2, /* 4323: pointer_to_array_of_pointers_to_stack */
            	4330, 0,
            	414, 20,
            0, 8, 1, /* 4330: pointer.SSL_CIPHER */
            	4139, 0,
            0, 144, 15, /* 4335: struct.x509_store_st */
            	4368, 8,
            	4392, 16,
            	4416, 24,
            	4428, 32,
            	4431, 40,
            	4434, 48,
            	4437, 56,
            	4428, 64,
            	4121, 72,
            	4440, 80,
            	4443, 88,
            	4446, 96,
            	4449, 104,
            	4428, 112,
            	621, 120,
            1, 8, 1, /* 4368: pointer.struct.stack_st_X509_OBJECT */
            	4373, 0,
            0, 32, 2, /* 4373: struct.stack_st_fake_X509_OBJECT */
            	4380, 8,
            	417, 24,
            8884099, 8, 2, /* 4380: pointer_to_array_of_pointers_to_stack */
            	4387, 0,
            	414, 20,
            0, 8, 1, /* 4387: pointer.X509_OBJECT */
            	2426, 0,
            1, 8, 1, /* 4392: pointer.struct.stack_st_X509_LOOKUP */
            	4397, 0,
            0, 32, 2, /* 4397: struct.stack_st_fake_X509_LOOKUP */
            	4404, 8,
            	417, 24,
            8884099, 8, 2, /* 4404: pointer_to_array_of_pointers_to_stack */
            	4411, 0,
            	414, 20,
            0, 8, 1, /* 4411: pointer.X509_LOOKUP */
            	2301, 0,
            1, 8, 1, /* 4416: pointer.struct.X509_VERIFY_PARAM_st */
            	4421, 0,
            0, 56, 2, /* 4421: struct.X509_VERIFY_PARAM_st */
            	257, 0,
            	1746, 48,
            8884097, 8, 0, /* 4428: pointer.func */
            8884097, 8, 0, /* 4431: pointer.func */
            8884097, 8, 0, /* 4434: pointer.func */
            8884097, 8, 0, /* 4437: pointer.func */
            8884097, 8, 0, /* 4440: pointer.func */
            8884097, 8, 0, /* 4443: pointer.func */
            8884097, 8, 0, /* 4446: pointer.func */
            8884097, 8, 0, /* 4449: pointer.func */
            1, 8, 1, /* 4452: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	4457, 0,
            0, 32, 2, /* 4457: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	4464, 8,
            	417, 24,
            8884099, 8, 2, /* 4464: pointer_to_array_of_pointers_to_stack */
            	4149, 0,
            	414, 20,
            0, 736, 50, /* 4471: struct.ssl_ctx_st */
            	4160, 0,
            	4311, 8,
            	4311, 16,
            	4574, 24,
            	4579, 32,
            	4615, 48,
            	4615, 56,
            	4133, 80,
            	4124, 88,
            	2151, 96,
            	2148, 152,
            	3476, 160,
            	4862, 168,
            	3476, 176,
            	2145, 184,
            	2142, 192,
            	2139, 200,
            	621, 208,
            	1958, 224,
            	1958, 232,
            	1958, 240,
            	4669, 248,
            	2103, 256,
            	2066, 264,
            	4865, 272,
            	2018, 304,
            	50, 320,
            	3476, 328,
            	4431, 376,
            	44, 384,
            	4416, 392,
            	485, 408,
            	4894, 416,
            	3476, 424,
            	41, 480,
            	3542, 488,
            	3476, 496,
            	38, 504,
            	3476, 512,
            	257, 520,
            	4130, 528,
            	4897, 536,
            	33, 552,
            	33, 560,
            	4900, 568,
            	4931, 696,
            	3476, 704,
            	47, 712,
            	3476, 720,
            	4452, 728,
            1, 8, 1, /* 4574: pointer.struct.x509_store_st */
            	4335, 0,
            1, 8, 1, /* 4579: pointer.struct.lhash_st */
            	4584, 0,
            0, 176, 3, /* 4584: struct.lhash_st */
            	4593, 0,
            	417, 8,
            	4612, 16,
            8884099, 8, 2, /* 4593: pointer_to_array_of_pointers_to_stack */
            	4600, 0,
            	618, 28,
            1, 8, 1, /* 4600: pointer.struct.lhash_node_st */
            	4605, 0,
            0, 24, 2, /* 4605: struct.lhash_node_st */
            	3476, 0,
            	4600, 8,
            8884097, 8, 0, /* 4612: pointer.func */
            1, 8, 1, /* 4615: pointer.struct.ssl_session_st */
            	4620, 0,
            0, 352, 14, /* 4620: struct.ssl_session_st */
            	257, 144,
            	257, 152,
            	4651, 168,
            	93, 176,
            	4111, 224,
            	4311, 240,
            	621, 248,
            	4615, 264,
            	4615, 272,
            	257, 280,
            	165, 296,
            	165, 312,
            	165, 320,
            	257, 344,
            1, 8, 1, /* 4651: pointer.struct.sess_cert_st */
            	4656, 0,
            0, 248, 5, /* 4656: struct.sess_cert_st */
            	4669, 0,
            	79, 16,
            	2003, 216,
            	2008, 224,
            	2013, 232,
            1, 8, 1, /* 4669: pointer.struct.stack_st_X509 */
            	4674, 0,
            0, 32, 2, /* 4674: struct.stack_st_fake_X509 */
            	4681, 8,
            	417, 24,
            8884099, 8, 2, /* 4681: pointer_to_array_of_pointers_to_stack */
            	4688, 0,
            	414, 20,
            0, 8, 1, /* 4688: pointer.X509 */
            	4693, 0,
            0, 0, 1, /* 4693: X509 */
            	4698, 0,
            0, 184, 12, /* 4698: struct.x509_st */
            	4725, 0,
            	3583, 8,
            	3672, 16,
            	257, 32,
            	2235, 40,
            	3677, 104,
            	4730, 112,
            	4738, 120,
            	4743, 128,
            	4767, 136,
            	4791, 144,
            	4796, 176,
            1, 8, 1, /* 4725: pointer.struct.x509_cinf_st */
            	3548, 0,
            1, 8, 1, /* 4730: pointer.struct.AUTHORITY_KEYID_st */
            	4735, 0,
            0, 0, 0, /* 4735: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4738: pointer.struct.X509_POLICY_CACHE_st */
            	4105, 0,
            1, 8, 1, /* 4743: pointer.struct.stack_st_DIST_POINT */
            	4748, 0,
            0, 32, 2, /* 4748: struct.stack_st_fake_DIST_POINT */
            	4755, 8,
            	417, 24,
            8884099, 8, 2, /* 4755: pointer_to_array_of_pointers_to_stack */
            	4762, 0,
            	414, 20,
            0, 8, 1, /* 4762: pointer.DIST_POINT */
            	1311, 0,
            1, 8, 1, /* 4767: pointer.struct.stack_st_GENERAL_NAME */
            	4772, 0,
            0, 32, 2, /* 4772: struct.stack_st_fake_GENERAL_NAME */
            	4779, 8,
            	417, 24,
            8884099, 8, 2, /* 4779: pointer_to_array_of_pointers_to_stack */
            	4786, 0,
            	414, 20,
            0, 8, 1, /* 4786: pointer.GENERAL_NAME */
            	1368, 0,
            1, 8, 1, /* 4791: pointer.struct.NAME_CONSTRAINTS_st */
            	4127, 0,
            1, 8, 1, /* 4796: pointer.struct.x509_cert_aux_st */
            	4801, 0,
            0, 40, 5, /* 4801: struct.x509_cert_aux_st */
            	4814, 0,
            	4814, 8,
            	3727, 16,
            	3677, 24,
            	4838, 32,
            1, 8, 1, /* 4814: pointer.struct.stack_st_ASN1_OBJECT */
            	4819, 0,
            0, 32, 2, /* 4819: struct.stack_st_fake_ASN1_OBJECT */
            	4826, 8,
            	417, 24,
            8884099, 8, 2, /* 4826: pointer_to_array_of_pointers_to_stack */
            	4833, 0,
            	414, 20,
            0, 8, 1, /* 4833: pointer.ASN1_OBJECT */
            	1770, 0,
            1, 8, 1, /* 4838: pointer.struct.stack_st_X509_ALGOR */
            	4843, 0,
            0, 32, 2, /* 4843: struct.stack_st_fake_X509_ALGOR */
            	4850, 8,
            	417, 24,
            8884099, 8, 2, /* 4850: pointer_to_array_of_pointers_to_stack */
            	4857, 0,
            	414, 20,
            0, 8, 1, /* 4857: pointer.X509_ALGOR */
            	1799, 0,
            8884097, 8, 0, /* 4862: pointer.func */
            1, 8, 1, /* 4865: pointer.struct.stack_st_X509_NAME */
            	4870, 0,
            0, 32, 2, /* 4870: struct.stack_st_fake_X509_NAME */
            	4877, 8,
            	417, 24,
            8884099, 8, 2, /* 4877: pointer_to_array_of_pointers_to_stack */
            	4884, 0,
            	414, 20,
            0, 8, 1, /* 4884: pointer.X509_NAME */
            	4889, 0,
            0, 0, 1, /* 4889: X509_NAME */
            	2033, 0,
            8884097, 8, 0, /* 4894: pointer.func */
            8884097, 8, 0, /* 4897: pointer.func */
            0, 128, 14, /* 4900: struct.srp_ctx_st */
            	3476, 0,
            	4894, 8,
            	3542, 16,
            	15, 24,
            	257, 32,
            	603, 40,
            	603, 48,
            	603, 56,
            	603, 64,
            	603, 72,
            	603, 80,
            	603, 88,
            	603, 96,
            	257, 104,
            8884097, 8, 0, /* 4931: pointer.func */
            0, 1, 0, /* 4934: char */
            1, 8, 1, /* 4937: pointer.struct.ssl_ctx_st */
            	4471, 0,
        },
        .arg_entity_index = { 4937, 5, 414, },
        .ret_entity_index = 414,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    const char * new_arg_b = *((const char * *)new_args->args[1]);

    int new_arg_c = *((int *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_SSL_CTX_use_PrivateKey_file)(SSL_CTX *,const char *,int);
    orig_SSL_CTX_use_PrivateKey_file = dlsym(RTLD_NEXT, "SSL_CTX_use_PrivateKey_file");
    *new_ret_ptr = (*orig_SSL_CTX_use_PrivateKey_file)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    return ret;
}

