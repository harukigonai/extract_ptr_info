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

void bb_SSL_CTX_sess_set_new_cb(SSL_CTX * arg_a,int (*arg_b)(struct ssl_st *, SSL_SESSION *));

void SSL_CTX_sess_set_new_cb(SSL_CTX * arg_a,int (*arg_b)(struct ssl_st *, SSL_SESSION *)) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_sess_set_new_cb called %lu\n", in_lib);
    if (!in_lib)
        bb_SSL_CTX_sess_set_new_cb(arg_a,arg_b);
    else {
        void (*orig_SSL_CTX_sess_set_new_cb)(SSL_CTX *,int (*)(struct ssl_st *, SSL_SESSION *));
        orig_SSL_CTX_sess_set_new_cb = dlsym(RTLD_NEXT, "SSL_CTX_sess_set_new_cb");
        orig_SSL_CTX_sess_set_new_cb(arg_a,arg_b);
    }
}

void bb_SSL_CTX_sess_set_new_cb(SSL_CTX * arg_a,int (*arg_b)(struct ssl_st *, SSL_SESSION *)) 
{
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 1, /* 0: SRTP_PROTECTION_PROFILE */
            	5, 0,
            0, 16, 1, /* 5: struct.srtp_protection_profile_st */
            	10, 0,
            1, 8, 1, /* 10: pointer.char */
            	64096, 0,
            64097, 8, 0, /* 15: pointer.func */
            0, 128, 14, /* 18: struct.srp_ctx_st */
            	49, 0,
            	52, 8,
            	55, 16,
            	58, 24,
            	61, 32,
            	66, 40,
            	66, 48,
            	66, 56,
            	66, 64,
            	66, 72,
            	66, 80,
            	66, 88,
            	66, 96,
            	61, 104,
            0, 8, 0, /* 49: pointer.void */
            64097, 8, 0, /* 52: pointer.func */
            64097, 8, 0, /* 55: pointer.func */
            64097, 8, 0, /* 58: pointer.func */
            1, 8, 1, /* 61: pointer.char */
            	64096, 0,
            1, 8, 1, /* 66: pointer.struct.bignum_st */
            	71, 0,
            0, 24, 1, /* 71: struct.bignum_st */
            	76, 0,
            1, 8, 1, /* 76: pointer.unsigned int */
            	81, 0,
            0, 4, 0, /* 81: unsigned int */
            64097, 8, 0, /* 84: pointer.func */
            0, 8, 1, /* 87: struct.ssl3_buf_freelist_entry_st */
            	92, 0,
            1, 8, 1, /* 92: pointer.struct.ssl3_buf_freelist_entry_st */
            	87, 0,
            1, 8, 1, /* 97: pointer.struct.ssl3_buf_freelist_st */
            	102, 0,
            0, 24, 1, /* 102: struct.ssl3_buf_freelist_st */
            	92, 16,
            64097, 8, 0, /* 107: pointer.func */
            64097, 8, 0, /* 110: pointer.func */
            64097, 8, 0, /* 113: pointer.func */
            64097, 8, 0, /* 116: pointer.func */
            64097, 8, 0, /* 119: pointer.func */
            0, 296, 7, /* 122: struct.cert_st */
            	139, 0,
            	2049, 48,
            	119, 56,
            	2054, 64,
            	116, 72,
            	2059, 80,
            	113, 88,
            1, 8, 1, /* 139: pointer.struct.cert_pkey_st */
            	144, 0,
            0, 24, 3, /* 144: struct.cert_pkey_st */
            	153, 0,
            	516, 8,
            	2004, 16,
            1, 8, 1, /* 153: pointer.struct.x509_st */
            	158, 0,
            0, 184, 12, /* 158: struct.x509_st */
            	185, 0,
            	233, 8,
            	327, 16,
            	61, 32,
            	658, 40,
            	332, 104,
            	1308, 112,
            	1316, 120,
            	1324, 128,
            	1733, 136,
            	1757, 144,
            	1765, 176,
            1, 8, 1, /* 185: pointer.struct.x509_cinf_st */
            	190, 0,
            0, 104, 11, /* 190: struct.x509_cinf_st */
            	215, 0,
            	215, 8,
            	233, 16,
            	395, 24,
            	485, 32,
            	395, 40,
            	502, 48,
            	327, 56,
            	327, 64,
            	1243, 72,
            	1303, 80,
            1, 8, 1, /* 215: pointer.struct.asn1_string_st */
            	220, 0,
            0, 24, 1, /* 220: struct.asn1_string_st */
            	225, 8,
            1, 8, 1, /* 225: pointer.unsigned char */
            	230, 0,
            0, 1, 0, /* 230: unsigned char */
            1, 8, 1, /* 233: pointer.struct.X509_algor_st */
            	238, 0,
            0, 16, 2, /* 238: struct.X509_algor_st */
            	245, 0,
            	264, 8,
            1, 8, 1, /* 245: pointer.struct.asn1_object_st */
            	250, 0,
            0, 40, 3, /* 250: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	259, 24,
            1, 8, 1, /* 259: pointer.unsigned char */
            	230, 0,
            1, 8, 1, /* 264: pointer.struct.asn1_type_st */
            	269, 0,
            0, 16, 1, /* 269: struct.asn1_type_st */
            	274, 8,
            0, 8, 20, /* 274: union.unknown */
            	61, 0,
            	317, 0,
            	245, 0,
            	215, 0,
            	322, 0,
            	327, 0,
            	332, 0,
            	337, 0,
            	342, 0,
            	347, 0,
            	352, 0,
            	357, 0,
            	362, 0,
            	367, 0,
            	372, 0,
            	377, 0,
            	382, 0,
            	317, 0,
            	317, 0,
            	387, 0,
            1, 8, 1, /* 317: pointer.struct.asn1_string_st */
            	220, 0,
            1, 8, 1, /* 322: pointer.struct.asn1_string_st */
            	220, 0,
            1, 8, 1, /* 327: pointer.struct.asn1_string_st */
            	220, 0,
            1, 8, 1, /* 332: pointer.struct.asn1_string_st */
            	220, 0,
            1, 8, 1, /* 337: pointer.struct.asn1_string_st */
            	220, 0,
            1, 8, 1, /* 342: pointer.struct.asn1_string_st */
            	220, 0,
            1, 8, 1, /* 347: pointer.struct.asn1_string_st */
            	220, 0,
            1, 8, 1, /* 352: pointer.struct.asn1_string_st */
            	220, 0,
            1, 8, 1, /* 357: pointer.struct.asn1_string_st */
            	220, 0,
            1, 8, 1, /* 362: pointer.struct.asn1_string_st */
            	220, 0,
            1, 8, 1, /* 367: pointer.struct.asn1_string_st */
            	220, 0,
            1, 8, 1, /* 372: pointer.struct.asn1_string_st */
            	220, 0,
            1, 8, 1, /* 377: pointer.struct.asn1_string_st */
            	220, 0,
            1, 8, 1, /* 382: pointer.struct.asn1_string_st */
            	220, 0,
            1, 8, 1, /* 387: pointer.struct.ASN1_VALUE_st */
            	392, 0,
            0, 0, 0, /* 392: struct.ASN1_VALUE_st */
            1, 8, 1, /* 395: pointer.struct.X509_name_st */
            	400, 0,
            0, 40, 3, /* 400: struct.X509_name_st */
            	409, 0,
            	475, 16,
            	225, 24,
            1, 8, 1, /* 409: pointer.struct.stack_st_X509_NAME_ENTRY */
            	414, 0,
            0, 32, 2, /* 414: struct.stack_st_fake_X509_NAME_ENTRY */
            	421, 8,
            	472, 24,
            64099, 8, 2, /* 421: pointer_to_array_of_pointers_to_stack */
            	428, 0,
            	469, 20,
            0, 8, 1, /* 428: pointer.X509_NAME_ENTRY */
            	433, 0,
            0, 0, 1, /* 433: X509_NAME_ENTRY */
            	438, 0,
            0, 24, 2, /* 438: struct.X509_name_entry_st */
            	445, 0,
            	459, 8,
            1, 8, 1, /* 445: pointer.struct.asn1_object_st */
            	450, 0,
            0, 40, 3, /* 450: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	259, 24,
            1, 8, 1, /* 459: pointer.struct.asn1_string_st */
            	464, 0,
            0, 24, 1, /* 464: struct.asn1_string_st */
            	225, 8,
            0, 4, 0, /* 469: int */
            64097, 8, 0, /* 472: pointer.func */
            1, 8, 1, /* 475: pointer.struct.buf_mem_st */
            	480, 0,
            0, 24, 1, /* 480: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 485: pointer.struct.X509_val_st */
            	490, 0,
            0, 16, 2, /* 490: struct.X509_val_st */
            	497, 0,
            	497, 8,
            1, 8, 1, /* 497: pointer.struct.asn1_string_st */
            	220, 0,
            1, 8, 1, /* 502: pointer.struct.X509_pubkey_st */
            	507, 0,
            0, 24, 3, /* 507: struct.X509_pubkey_st */
            	233, 0,
            	327, 8,
            	516, 16,
            1, 8, 1, /* 516: pointer.struct.evp_pkey_st */
            	521, 0,
            0, 56, 4, /* 521: struct.evp_pkey_st */
            	532, 16,
            	540, 24,
            	548, 32,
            	864, 48,
            1, 8, 1, /* 532: pointer.struct.evp_pkey_asn1_method_st */
            	537, 0,
            0, 0, 0, /* 537: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 540: pointer.struct.engine_st */
            	545, 0,
            0, 0, 0, /* 545: struct.engine_st */
            0, 8, 5, /* 548: union.unknown */
            	61, 0,
            	561, 0,
            	707, 0,
            	788, 0,
            	856, 0,
            1, 8, 1, /* 561: pointer.struct.rsa_st */
            	566, 0,
            0, 168, 17, /* 566: struct.rsa_st */
            	603, 16,
            	540, 24,
            	66, 32,
            	66, 40,
            	66, 48,
            	66, 56,
            	66, 64,
            	66, 72,
            	66, 80,
            	66, 88,
            	658, 96,
            	685, 120,
            	685, 128,
            	685, 136,
            	61, 144,
            	699, 152,
            	699, 160,
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
            	61, 80,
            	649, 88,
            	652, 96,
            	655, 104,
            64097, 8, 0, /* 637: pointer.func */
            64097, 8, 0, /* 640: pointer.func */
            64097, 8, 0, /* 643: pointer.func */
            64097, 8, 0, /* 646: pointer.func */
            64097, 8, 0, /* 649: pointer.func */
            64097, 8, 0, /* 652: pointer.func */
            64097, 8, 0, /* 655: pointer.func */
            0, 16, 1, /* 658: struct.crypto_ex_data_st */
            	663, 0,
            1, 8, 1, /* 663: pointer.struct.stack_st_void */
            	668, 0,
            0, 32, 1, /* 668: struct.stack_st_void */
            	673, 0,
            0, 32, 2, /* 673: struct.stack_st */
            	680, 8,
            	472, 24,
            1, 8, 1, /* 680: pointer.pointer.char */
            	61, 0,
            1, 8, 1, /* 685: pointer.struct.bn_mont_ctx_st */
            	690, 0,
            0, 96, 3, /* 690: struct.bn_mont_ctx_st */
            	71, 8,
            	71, 32,
            	71, 56,
            1, 8, 1, /* 699: pointer.struct.bn_blinding_st */
            	704, 0,
            0, 0, 0, /* 704: struct.bn_blinding_st */
            1, 8, 1, /* 707: pointer.struct.dsa_st */
            	712, 0,
            0, 136, 11, /* 712: struct.dsa_st */
            	66, 24,
            	66, 32,
            	66, 40,
            	66, 48,
            	66, 56,
            	66, 64,
            	66, 72,
            	685, 88,
            	658, 104,
            	737, 120,
            	540, 128,
            1, 8, 1, /* 737: pointer.struct.dsa_method */
            	742, 0,
            0, 96, 11, /* 742: struct.dsa_method */
            	10, 0,
            	767, 8,
            	770, 16,
            	773, 24,
            	776, 32,
            	779, 40,
            	782, 48,
            	782, 56,
            	61, 72,
            	785, 80,
            	782, 88,
            64097, 8, 0, /* 767: pointer.func */
            64097, 8, 0, /* 770: pointer.func */
            64097, 8, 0, /* 773: pointer.func */
            64097, 8, 0, /* 776: pointer.func */
            64097, 8, 0, /* 779: pointer.func */
            64097, 8, 0, /* 782: pointer.func */
            64097, 8, 0, /* 785: pointer.func */
            1, 8, 1, /* 788: pointer.struct.dh_st */
            	793, 0,
            0, 144, 12, /* 793: struct.dh_st */
            	66, 8,
            	66, 16,
            	66, 32,
            	66, 40,
            	685, 56,
            	66, 64,
            	66, 72,
            	225, 80,
            	66, 96,
            	658, 112,
            	820, 128,
            	540, 136,
            1, 8, 1, /* 820: pointer.struct.dh_method */
            	825, 0,
            0, 72, 8, /* 825: struct.dh_method */
            	10, 0,
            	844, 8,
            	847, 16,
            	850, 24,
            	844, 32,
            	844, 40,
            	61, 56,
            	853, 64,
            64097, 8, 0, /* 844: pointer.func */
            64097, 8, 0, /* 847: pointer.func */
            64097, 8, 0, /* 850: pointer.func */
            64097, 8, 0, /* 853: pointer.func */
            1, 8, 1, /* 856: pointer.struct.ec_key_st */
            	861, 0,
            0, 0, 0, /* 861: struct.ec_key_st */
            1, 8, 1, /* 864: pointer.struct.stack_st_X509_ATTRIBUTE */
            	869, 0,
            0, 32, 2, /* 869: struct.stack_st_fake_X509_ATTRIBUTE */
            	876, 8,
            	472, 24,
            64099, 8, 2, /* 876: pointer_to_array_of_pointers_to_stack */
            	883, 0,
            	469, 20,
            0, 8, 1, /* 883: pointer.X509_ATTRIBUTE */
            	888, 0,
            0, 0, 1, /* 888: X509_ATTRIBUTE */
            	893, 0,
            0, 24, 2, /* 893: struct.x509_attributes_st */
            	900, 0,
            	914, 16,
            1, 8, 1, /* 900: pointer.struct.asn1_object_st */
            	905, 0,
            0, 40, 3, /* 905: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	259, 24,
            0, 8, 3, /* 914: union.unknown */
            	61, 0,
            	923, 0,
            	1102, 0,
            1, 8, 1, /* 923: pointer.struct.stack_st_ASN1_TYPE */
            	928, 0,
            0, 32, 2, /* 928: struct.stack_st_fake_ASN1_TYPE */
            	935, 8,
            	472, 24,
            64099, 8, 2, /* 935: pointer_to_array_of_pointers_to_stack */
            	942, 0,
            	469, 20,
            0, 8, 1, /* 942: pointer.ASN1_TYPE */
            	947, 0,
            0, 0, 1, /* 947: ASN1_TYPE */
            	952, 0,
            0, 16, 1, /* 952: struct.asn1_type_st */
            	957, 8,
            0, 8, 20, /* 957: union.unknown */
            	61, 0,
            	1000, 0,
            	1010, 0,
            	1024, 0,
            	1029, 0,
            	1034, 0,
            	1039, 0,
            	1044, 0,
            	1049, 0,
            	1054, 0,
            	1059, 0,
            	1064, 0,
            	1069, 0,
            	1074, 0,
            	1079, 0,
            	1084, 0,
            	1089, 0,
            	1000, 0,
            	1000, 0,
            	1094, 0,
            1, 8, 1, /* 1000: pointer.struct.asn1_string_st */
            	1005, 0,
            0, 24, 1, /* 1005: struct.asn1_string_st */
            	225, 8,
            1, 8, 1, /* 1010: pointer.struct.asn1_object_st */
            	1015, 0,
            0, 40, 3, /* 1015: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	259, 24,
            1, 8, 1, /* 1024: pointer.struct.asn1_string_st */
            	1005, 0,
            1, 8, 1, /* 1029: pointer.struct.asn1_string_st */
            	1005, 0,
            1, 8, 1, /* 1034: pointer.struct.asn1_string_st */
            	1005, 0,
            1, 8, 1, /* 1039: pointer.struct.asn1_string_st */
            	1005, 0,
            1, 8, 1, /* 1044: pointer.struct.asn1_string_st */
            	1005, 0,
            1, 8, 1, /* 1049: pointer.struct.asn1_string_st */
            	1005, 0,
            1, 8, 1, /* 1054: pointer.struct.asn1_string_st */
            	1005, 0,
            1, 8, 1, /* 1059: pointer.struct.asn1_string_st */
            	1005, 0,
            1, 8, 1, /* 1064: pointer.struct.asn1_string_st */
            	1005, 0,
            1, 8, 1, /* 1069: pointer.struct.asn1_string_st */
            	1005, 0,
            1, 8, 1, /* 1074: pointer.struct.asn1_string_st */
            	1005, 0,
            1, 8, 1, /* 1079: pointer.struct.asn1_string_st */
            	1005, 0,
            1, 8, 1, /* 1084: pointer.struct.asn1_string_st */
            	1005, 0,
            1, 8, 1, /* 1089: pointer.struct.asn1_string_st */
            	1005, 0,
            1, 8, 1, /* 1094: pointer.struct.ASN1_VALUE_st */
            	1099, 0,
            0, 0, 0, /* 1099: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1102: pointer.struct.asn1_type_st */
            	1107, 0,
            0, 16, 1, /* 1107: struct.asn1_type_st */
            	1112, 8,
            0, 8, 20, /* 1112: union.unknown */
            	61, 0,
            	1155, 0,
            	900, 0,
            	1165, 0,
            	1170, 0,
            	1175, 0,
            	1180, 0,
            	1185, 0,
            	1190, 0,
            	1195, 0,
            	1200, 0,
            	1205, 0,
            	1210, 0,
            	1215, 0,
            	1220, 0,
            	1225, 0,
            	1230, 0,
            	1155, 0,
            	1155, 0,
            	1235, 0,
            1, 8, 1, /* 1155: pointer.struct.asn1_string_st */
            	1160, 0,
            0, 24, 1, /* 1160: struct.asn1_string_st */
            	225, 8,
            1, 8, 1, /* 1165: pointer.struct.asn1_string_st */
            	1160, 0,
            1, 8, 1, /* 1170: pointer.struct.asn1_string_st */
            	1160, 0,
            1, 8, 1, /* 1175: pointer.struct.asn1_string_st */
            	1160, 0,
            1, 8, 1, /* 1180: pointer.struct.asn1_string_st */
            	1160, 0,
            1, 8, 1, /* 1185: pointer.struct.asn1_string_st */
            	1160, 0,
            1, 8, 1, /* 1190: pointer.struct.asn1_string_st */
            	1160, 0,
            1, 8, 1, /* 1195: pointer.struct.asn1_string_st */
            	1160, 0,
            1, 8, 1, /* 1200: pointer.struct.asn1_string_st */
            	1160, 0,
            1, 8, 1, /* 1205: pointer.struct.asn1_string_st */
            	1160, 0,
            1, 8, 1, /* 1210: pointer.struct.asn1_string_st */
            	1160, 0,
            1, 8, 1, /* 1215: pointer.struct.asn1_string_st */
            	1160, 0,
            1, 8, 1, /* 1220: pointer.struct.asn1_string_st */
            	1160, 0,
            1, 8, 1, /* 1225: pointer.struct.asn1_string_st */
            	1160, 0,
            1, 8, 1, /* 1230: pointer.struct.asn1_string_st */
            	1160, 0,
            1, 8, 1, /* 1235: pointer.struct.ASN1_VALUE_st */
            	1240, 0,
            0, 0, 0, /* 1240: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1243: pointer.struct.stack_st_X509_EXTENSION */
            	1248, 0,
            0, 32, 2, /* 1248: struct.stack_st_fake_X509_EXTENSION */
            	1255, 8,
            	472, 24,
            64099, 8, 2, /* 1255: pointer_to_array_of_pointers_to_stack */
            	1262, 0,
            	469, 20,
            0, 8, 1, /* 1262: pointer.X509_EXTENSION */
            	1267, 0,
            0, 0, 1, /* 1267: X509_EXTENSION */
            	1272, 0,
            0, 24, 2, /* 1272: struct.X509_extension_st */
            	1279, 0,
            	1293, 16,
            1, 8, 1, /* 1279: pointer.struct.asn1_object_st */
            	1284, 0,
            0, 40, 3, /* 1284: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	259, 24,
            1, 8, 1, /* 1293: pointer.struct.asn1_string_st */
            	1298, 0,
            0, 24, 1, /* 1298: struct.asn1_string_st */
            	225, 8,
            0, 24, 1, /* 1303: struct.ASN1_ENCODING_st */
            	225, 0,
            1, 8, 1, /* 1308: pointer.struct.AUTHORITY_KEYID_st */
            	1313, 0,
            0, 0, 0, /* 1313: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 1316: pointer.struct.X509_POLICY_CACHE_st */
            	1321, 0,
            0, 0, 0, /* 1321: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1324: pointer.struct.stack_st_DIST_POINT */
            	1329, 0,
            0, 32, 2, /* 1329: struct.stack_st_fake_DIST_POINT */
            	1336, 8,
            	472, 24,
            64099, 8, 2, /* 1336: pointer_to_array_of_pointers_to_stack */
            	1343, 0,
            	469, 20,
            0, 8, 1, /* 1343: pointer.DIST_POINT */
            	1348, 0,
            0, 0, 1, /* 1348: DIST_POINT */
            	1353, 0,
            0, 32, 3, /* 1353: struct.DIST_POINT_st */
            	1362, 0,
            	1723, 8,
            	1381, 16,
            1, 8, 1, /* 1362: pointer.struct.DIST_POINT_NAME_st */
            	1367, 0,
            0, 24, 2, /* 1367: struct.DIST_POINT_NAME_st */
            	1374, 8,
            	1699, 16,
            0, 8, 2, /* 1374: union.unknown */
            	1381, 0,
            	1675, 0,
            1, 8, 1, /* 1381: pointer.struct.stack_st_GENERAL_NAME */
            	1386, 0,
            0, 32, 2, /* 1386: struct.stack_st_fake_GENERAL_NAME */
            	1393, 8,
            	472, 24,
            64099, 8, 2, /* 1393: pointer_to_array_of_pointers_to_stack */
            	1400, 0,
            	469, 20,
            0, 8, 1, /* 1400: pointer.GENERAL_NAME */
            	1405, 0,
            0, 0, 1, /* 1405: GENERAL_NAME */
            	1410, 0,
            0, 16, 1, /* 1410: struct.GENERAL_NAME_st */
            	1415, 8,
            0, 8, 15, /* 1415: union.unknown */
            	61, 0,
            	1448, 0,
            	1567, 0,
            	1567, 0,
            	1474, 0,
            	1615, 0,
            	1663, 0,
            	1567, 0,
            	1552, 0,
            	1460, 0,
            	1552, 0,
            	1615, 0,
            	1567, 0,
            	1460, 0,
            	1474, 0,
            1, 8, 1, /* 1448: pointer.struct.otherName_st */
            	1453, 0,
            0, 16, 2, /* 1453: struct.otherName_st */
            	1460, 0,
            	1474, 8,
            1, 8, 1, /* 1460: pointer.struct.asn1_object_st */
            	1465, 0,
            0, 40, 3, /* 1465: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	259, 24,
            1, 8, 1, /* 1474: pointer.struct.asn1_type_st */
            	1479, 0,
            0, 16, 1, /* 1479: struct.asn1_type_st */
            	1484, 8,
            0, 8, 20, /* 1484: union.unknown */
            	61, 0,
            	1527, 0,
            	1460, 0,
            	1537, 0,
            	1542, 0,
            	1547, 0,
            	1552, 0,
            	1557, 0,
            	1562, 0,
            	1567, 0,
            	1572, 0,
            	1577, 0,
            	1582, 0,
            	1587, 0,
            	1592, 0,
            	1597, 0,
            	1602, 0,
            	1527, 0,
            	1527, 0,
            	1607, 0,
            1, 8, 1, /* 1527: pointer.struct.asn1_string_st */
            	1532, 0,
            0, 24, 1, /* 1532: struct.asn1_string_st */
            	225, 8,
            1, 8, 1, /* 1537: pointer.struct.asn1_string_st */
            	1532, 0,
            1, 8, 1, /* 1542: pointer.struct.asn1_string_st */
            	1532, 0,
            1, 8, 1, /* 1547: pointer.struct.asn1_string_st */
            	1532, 0,
            1, 8, 1, /* 1552: pointer.struct.asn1_string_st */
            	1532, 0,
            1, 8, 1, /* 1557: pointer.struct.asn1_string_st */
            	1532, 0,
            1, 8, 1, /* 1562: pointer.struct.asn1_string_st */
            	1532, 0,
            1, 8, 1, /* 1567: pointer.struct.asn1_string_st */
            	1532, 0,
            1, 8, 1, /* 1572: pointer.struct.asn1_string_st */
            	1532, 0,
            1, 8, 1, /* 1577: pointer.struct.asn1_string_st */
            	1532, 0,
            1, 8, 1, /* 1582: pointer.struct.asn1_string_st */
            	1532, 0,
            1, 8, 1, /* 1587: pointer.struct.asn1_string_st */
            	1532, 0,
            1, 8, 1, /* 1592: pointer.struct.asn1_string_st */
            	1532, 0,
            1, 8, 1, /* 1597: pointer.struct.asn1_string_st */
            	1532, 0,
            1, 8, 1, /* 1602: pointer.struct.asn1_string_st */
            	1532, 0,
            1, 8, 1, /* 1607: pointer.struct.ASN1_VALUE_st */
            	1612, 0,
            0, 0, 0, /* 1612: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1615: pointer.struct.X509_name_st */
            	1620, 0,
            0, 40, 3, /* 1620: struct.X509_name_st */
            	1629, 0,
            	1653, 16,
            	225, 24,
            1, 8, 1, /* 1629: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1634, 0,
            0, 32, 2, /* 1634: struct.stack_st_fake_X509_NAME_ENTRY */
            	1641, 8,
            	472, 24,
            64099, 8, 2, /* 1641: pointer_to_array_of_pointers_to_stack */
            	1648, 0,
            	469, 20,
            0, 8, 1, /* 1648: pointer.X509_NAME_ENTRY */
            	433, 0,
            1, 8, 1, /* 1653: pointer.struct.buf_mem_st */
            	1658, 0,
            0, 24, 1, /* 1658: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 1663: pointer.struct.EDIPartyName_st */
            	1668, 0,
            0, 16, 2, /* 1668: struct.EDIPartyName_st */
            	1527, 0,
            	1527, 8,
            1, 8, 1, /* 1675: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1680, 0,
            0, 32, 2, /* 1680: struct.stack_st_fake_X509_NAME_ENTRY */
            	1687, 8,
            	472, 24,
            64099, 8, 2, /* 1687: pointer_to_array_of_pointers_to_stack */
            	1694, 0,
            	469, 20,
            0, 8, 1, /* 1694: pointer.X509_NAME_ENTRY */
            	433, 0,
            1, 8, 1, /* 1699: pointer.struct.X509_name_st */
            	1704, 0,
            0, 40, 3, /* 1704: struct.X509_name_st */
            	1675, 0,
            	1713, 16,
            	225, 24,
            1, 8, 1, /* 1713: pointer.struct.buf_mem_st */
            	1718, 0,
            0, 24, 1, /* 1718: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 1723: pointer.struct.asn1_string_st */
            	1728, 0,
            0, 24, 1, /* 1728: struct.asn1_string_st */
            	225, 8,
            1, 8, 1, /* 1733: pointer.struct.stack_st_GENERAL_NAME */
            	1738, 0,
            0, 32, 2, /* 1738: struct.stack_st_fake_GENERAL_NAME */
            	1745, 8,
            	472, 24,
            64099, 8, 2, /* 1745: pointer_to_array_of_pointers_to_stack */
            	1752, 0,
            	469, 20,
            0, 8, 1, /* 1752: pointer.GENERAL_NAME */
            	1405, 0,
            1, 8, 1, /* 1757: pointer.struct.NAME_CONSTRAINTS_st */
            	1762, 0,
            0, 0, 0, /* 1762: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 1765: pointer.struct.x509_cert_aux_st */
            	1770, 0,
            0, 40, 5, /* 1770: struct.x509_cert_aux_st */
            	1783, 0,
            	1783, 8,
            	382, 16,
            	332, 24,
            	1821, 32,
            1, 8, 1, /* 1783: pointer.struct.stack_st_ASN1_OBJECT */
            	1788, 0,
            0, 32, 2, /* 1788: struct.stack_st_fake_ASN1_OBJECT */
            	1795, 8,
            	472, 24,
            64099, 8, 2, /* 1795: pointer_to_array_of_pointers_to_stack */
            	1802, 0,
            	469, 20,
            0, 8, 1, /* 1802: pointer.ASN1_OBJECT */
            	1807, 0,
            0, 0, 1, /* 1807: ASN1_OBJECT */
            	1812, 0,
            0, 40, 3, /* 1812: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	259, 24,
            1, 8, 1, /* 1821: pointer.struct.stack_st_X509_ALGOR */
            	1826, 0,
            0, 32, 2, /* 1826: struct.stack_st_fake_X509_ALGOR */
            	1833, 8,
            	472, 24,
            64099, 8, 2, /* 1833: pointer_to_array_of_pointers_to_stack */
            	1840, 0,
            	469, 20,
            0, 8, 1, /* 1840: pointer.X509_ALGOR */
            	1845, 0,
            0, 0, 1, /* 1845: X509_ALGOR */
            	1850, 0,
            0, 16, 2, /* 1850: struct.X509_algor_st */
            	1857, 0,
            	1871, 8,
            1, 8, 1, /* 1857: pointer.struct.asn1_object_st */
            	1862, 0,
            0, 40, 3, /* 1862: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	259, 24,
            1, 8, 1, /* 1871: pointer.struct.asn1_type_st */
            	1876, 0,
            0, 16, 1, /* 1876: struct.asn1_type_st */
            	1881, 8,
            0, 8, 20, /* 1881: union.unknown */
            	61, 0,
            	1924, 0,
            	1857, 0,
            	1934, 0,
            	1939, 0,
            	1944, 0,
            	1949, 0,
            	1954, 0,
            	1959, 0,
            	1964, 0,
            	1969, 0,
            	1974, 0,
            	1979, 0,
            	1984, 0,
            	1989, 0,
            	1994, 0,
            	1999, 0,
            	1924, 0,
            	1924, 0,
            	1235, 0,
            1, 8, 1, /* 1924: pointer.struct.asn1_string_st */
            	1929, 0,
            0, 24, 1, /* 1929: struct.asn1_string_st */
            	225, 8,
            1, 8, 1, /* 1934: pointer.struct.asn1_string_st */
            	1929, 0,
            1, 8, 1, /* 1939: pointer.struct.asn1_string_st */
            	1929, 0,
            1, 8, 1, /* 1944: pointer.struct.asn1_string_st */
            	1929, 0,
            1, 8, 1, /* 1949: pointer.struct.asn1_string_st */
            	1929, 0,
            1, 8, 1, /* 1954: pointer.struct.asn1_string_st */
            	1929, 0,
            1, 8, 1, /* 1959: pointer.struct.asn1_string_st */
            	1929, 0,
            1, 8, 1, /* 1964: pointer.struct.asn1_string_st */
            	1929, 0,
            1, 8, 1, /* 1969: pointer.struct.asn1_string_st */
            	1929, 0,
            1, 8, 1, /* 1974: pointer.struct.asn1_string_st */
            	1929, 0,
            1, 8, 1, /* 1979: pointer.struct.asn1_string_st */
            	1929, 0,
            1, 8, 1, /* 1984: pointer.struct.asn1_string_st */
            	1929, 0,
            1, 8, 1, /* 1989: pointer.struct.asn1_string_st */
            	1929, 0,
            1, 8, 1, /* 1994: pointer.struct.asn1_string_st */
            	1929, 0,
            1, 8, 1, /* 1999: pointer.struct.asn1_string_st */
            	1929, 0,
            1, 8, 1, /* 2004: pointer.struct.env_md_st */
            	2009, 0,
            0, 120, 8, /* 2009: struct.env_md_st */
            	2028, 24,
            	2031, 32,
            	2034, 40,
            	2037, 48,
            	2028, 56,
            	2040, 64,
            	2043, 72,
            	2046, 112,
            64097, 8, 0, /* 2028: pointer.func */
            64097, 8, 0, /* 2031: pointer.func */
            64097, 8, 0, /* 2034: pointer.func */
            64097, 8, 0, /* 2037: pointer.func */
            64097, 8, 0, /* 2040: pointer.func */
            64097, 8, 0, /* 2043: pointer.func */
            64097, 8, 0, /* 2046: pointer.func */
            1, 8, 1, /* 2049: pointer.struct.rsa_st */
            	566, 0,
            1, 8, 1, /* 2054: pointer.struct.dh_st */
            	793, 0,
            1, 8, 1, /* 2059: pointer.struct.ec_key_st */
            	861, 0,
            0, 24, 1, /* 2064: struct.buf_mem_st */
            	61, 8,
            0, 40, 3, /* 2069: struct.X509_name_st */
            	2078, 0,
            	2102, 16,
            	225, 24,
            1, 8, 1, /* 2078: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2083, 0,
            0, 32, 2, /* 2083: struct.stack_st_fake_X509_NAME_ENTRY */
            	2090, 8,
            	472, 24,
            64099, 8, 2, /* 2090: pointer_to_array_of_pointers_to_stack */
            	2097, 0,
            	469, 20,
            0, 8, 1, /* 2097: pointer.X509_NAME_ENTRY */
            	433, 0,
            1, 8, 1, /* 2102: pointer.struct.buf_mem_st */
            	2064, 0,
            64097, 8, 0, /* 2107: pointer.func */
            64097, 8, 0, /* 2110: pointer.func */
            64097, 8, 0, /* 2113: pointer.func */
            1, 8, 1, /* 2116: pointer.struct.stack_st_SSL_COMP */
            	2121, 0,
            0, 32, 2, /* 2121: struct.stack_st_fake_SSL_COMP */
            	2128, 8,
            	472, 24,
            64099, 8, 2, /* 2128: pointer_to_array_of_pointers_to_stack */
            	2135, 0,
            	469, 20,
            0, 8, 1, /* 2135: pointer.SSL_COMP */
            	2140, 0,
            0, 0, 1, /* 2140: SSL_COMP */
            	2145, 0,
            0, 24, 2, /* 2145: struct.ssl_comp_st */
            	10, 8,
            	2152, 16,
            1, 8, 1, /* 2152: pointer.struct.comp_method_st */
            	2157, 0,
            0, 64, 7, /* 2157: struct.comp_method_st */
            	10, 8,
            	2113, 16,
            	2174, 24,
            	2110, 32,
            	2110, 40,
            	2177, 48,
            	2177, 56,
            64097, 8, 0, /* 2174: pointer.func */
            64097, 8, 0, /* 2177: pointer.func */
            64097, 8, 0, /* 2180: pointer.func */
            64097, 8, 0, /* 2183: pointer.func */
            0, 88, 1, /* 2186: struct.ssl_cipher_st */
            	10, 8,
            1, 8, 1, /* 2191: pointer.struct.ssl_cipher_st */
            	2186, 0,
            0, 16, 1, /* 2196: struct.crypto_ex_data_st */
            	2201, 0,
            1, 8, 1, /* 2201: pointer.struct.stack_st_void */
            	2206, 0,
            0, 32, 1, /* 2206: struct.stack_st_void */
            	2211, 0,
            0, 32, 2, /* 2211: struct.stack_st */
            	680, 8,
            	472, 24,
            0, 136, 11, /* 2218: struct.dsa_st */
            	2243, 24,
            	2243, 32,
            	2243, 40,
            	2243, 48,
            	2243, 56,
            	2243, 64,
            	2243, 72,
            	2253, 88,
            	2196, 104,
            	2267, 120,
            	2318, 128,
            1, 8, 1, /* 2243: pointer.struct.bignum_st */
            	2248, 0,
            0, 24, 1, /* 2248: struct.bignum_st */
            	76, 0,
            1, 8, 1, /* 2253: pointer.struct.bn_mont_ctx_st */
            	2258, 0,
            0, 96, 3, /* 2258: struct.bn_mont_ctx_st */
            	2248, 8,
            	2248, 32,
            	2248, 56,
            1, 8, 1, /* 2267: pointer.struct.dsa_method */
            	2272, 0,
            0, 96, 11, /* 2272: struct.dsa_method */
            	10, 0,
            	2297, 8,
            	2300, 16,
            	2303, 24,
            	2306, 32,
            	2309, 40,
            	2312, 48,
            	2312, 56,
            	61, 72,
            	2315, 80,
            	2312, 88,
            64097, 8, 0, /* 2297: pointer.func */
            64097, 8, 0, /* 2300: pointer.func */
            64097, 8, 0, /* 2303: pointer.func */
            64097, 8, 0, /* 2306: pointer.func */
            64097, 8, 0, /* 2309: pointer.func */
            64097, 8, 0, /* 2312: pointer.func */
            64097, 8, 0, /* 2315: pointer.func */
            1, 8, 1, /* 2318: pointer.struct.engine_st */
            	2323, 0,
            0, 0, 0, /* 2323: struct.engine_st */
            1, 8, 1, /* 2326: pointer.struct.cert_st */
            	122, 0,
            1, 8, 1, /* 2331: pointer.struct.X509_algor_st */
            	2336, 0,
            0, 16, 2, /* 2336: struct.X509_algor_st */
            	2343, 0,
            	2357, 8,
            1, 8, 1, /* 2343: pointer.struct.asn1_object_st */
            	2348, 0,
            0, 40, 3, /* 2348: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	259, 24,
            1, 8, 1, /* 2357: pointer.struct.asn1_type_st */
            	2362, 0,
            0, 16, 1, /* 2362: struct.asn1_type_st */
            	2367, 8,
            0, 8, 20, /* 2367: union.unknown */
            	61, 0,
            	2410, 0,
            	2343, 0,
            	2420, 0,
            	2425, 0,
            	2430, 0,
            	2435, 0,
            	2440, 0,
            	2445, 0,
            	2450, 0,
            	2455, 0,
            	2460, 0,
            	2465, 0,
            	2470, 0,
            	2475, 0,
            	2480, 0,
            	2485, 0,
            	2410, 0,
            	2410, 0,
            	1235, 0,
            1, 8, 1, /* 2410: pointer.struct.asn1_string_st */
            	2415, 0,
            0, 24, 1, /* 2415: struct.asn1_string_st */
            	225, 8,
            1, 8, 1, /* 2420: pointer.struct.asn1_string_st */
            	2415, 0,
            1, 8, 1, /* 2425: pointer.struct.asn1_string_st */
            	2415, 0,
            1, 8, 1, /* 2430: pointer.struct.asn1_string_st */
            	2415, 0,
            1, 8, 1, /* 2435: pointer.struct.asn1_string_st */
            	2415, 0,
            1, 8, 1, /* 2440: pointer.struct.asn1_string_st */
            	2415, 0,
            1, 8, 1, /* 2445: pointer.struct.asn1_string_st */
            	2415, 0,
            1, 8, 1, /* 2450: pointer.struct.asn1_string_st */
            	2415, 0,
            1, 8, 1, /* 2455: pointer.struct.asn1_string_st */
            	2415, 0,
            1, 8, 1, /* 2460: pointer.struct.asn1_string_st */
            	2415, 0,
            1, 8, 1, /* 2465: pointer.struct.asn1_string_st */
            	2415, 0,
            1, 8, 1, /* 2470: pointer.struct.asn1_string_st */
            	2415, 0,
            1, 8, 1, /* 2475: pointer.struct.asn1_string_st */
            	2415, 0,
            1, 8, 1, /* 2480: pointer.struct.asn1_string_st */
            	2415, 0,
            1, 8, 1, /* 2485: pointer.struct.asn1_string_st */
            	2415, 0,
            1, 8, 1, /* 2490: pointer.struct.stack_st_DIST_POINT */
            	2495, 0,
            0, 32, 2, /* 2495: struct.stack_st_fake_DIST_POINT */
            	2502, 8,
            	472, 24,
            64099, 8, 2, /* 2502: pointer_to_array_of_pointers_to_stack */
            	2509, 0,
            	469, 20,
            0, 8, 1, /* 2509: pointer.DIST_POINT */
            	1348, 0,
            1, 8, 1, /* 2514: pointer.struct.X509_POLICY_CACHE_st */
            	2519, 0,
            0, 0, 0, /* 2519: struct.X509_POLICY_CACHE_st */
            0, 0, 0, /* 2522: struct.ec_key_st */
            1, 8, 1, /* 2525: pointer.struct.AUTHORITY_KEYID_st */
            	2530, 0,
            0, 0, 0, /* 2530: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 2533: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	2538, 0,
            0, 32, 2, /* 2538: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	2545, 8,
            	472, 24,
            64099, 8, 2, /* 2545: pointer_to_array_of_pointers_to_stack */
            	2552, 0,
            	469, 20,
            0, 8, 1, /* 2552: pointer.SRTP_PROTECTION_PROFILE */
            	0, 0,
            64097, 8, 0, /* 2557: pointer.func */
            64097, 8, 0, /* 2560: pointer.func */
            1, 8, 1, /* 2563: pointer.struct.X509_pubkey_st */
            	2568, 0,
            0, 24, 3, /* 2568: struct.X509_pubkey_st */
            	2577, 0,
            	2676, 8,
            	2744, 16,
            1, 8, 1, /* 2577: pointer.struct.X509_algor_st */
            	2582, 0,
            0, 16, 2, /* 2582: struct.X509_algor_st */
            	2589, 0,
            	2603, 8,
            1, 8, 1, /* 2589: pointer.struct.asn1_object_st */
            	2594, 0,
            0, 40, 3, /* 2594: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	259, 24,
            1, 8, 1, /* 2603: pointer.struct.asn1_type_st */
            	2608, 0,
            0, 16, 1, /* 2608: struct.asn1_type_st */
            	2613, 8,
            0, 8, 20, /* 2613: union.unknown */
            	61, 0,
            	2656, 0,
            	2589, 0,
            	2666, 0,
            	2671, 0,
            	2676, 0,
            	2681, 0,
            	2686, 0,
            	2691, 0,
            	2696, 0,
            	2701, 0,
            	2706, 0,
            	2711, 0,
            	2716, 0,
            	2721, 0,
            	2726, 0,
            	2731, 0,
            	2656, 0,
            	2656, 0,
            	2736, 0,
            1, 8, 1, /* 2656: pointer.struct.asn1_string_st */
            	2661, 0,
            0, 24, 1, /* 2661: struct.asn1_string_st */
            	225, 8,
            1, 8, 1, /* 2666: pointer.struct.asn1_string_st */
            	2661, 0,
            1, 8, 1, /* 2671: pointer.struct.asn1_string_st */
            	2661, 0,
            1, 8, 1, /* 2676: pointer.struct.asn1_string_st */
            	2661, 0,
            1, 8, 1, /* 2681: pointer.struct.asn1_string_st */
            	2661, 0,
            1, 8, 1, /* 2686: pointer.struct.asn1_string_st */
            	2661, 0,
            1, 8, 1, /* 2691: pointer.struct.asn1_string_st */
            	2661, 0,
            1, 8, 1, /* 2696: pointer.struct.asn1_string_st */
            	2661, 0,
            1, 8, 1, /* 2701: pointer.struct.asn1_string_st */
            	2661, 0,
            1, 8, 1, /* 2706: pointer.struct.asn1_string_st */
            	2661, 0,
            1, 8, 1, /* 2711: pointer.struct.asn1_string_st */
            	2661, 0,
            1, 8, 1, /* 2716: pointer.struct.asn1_string_st */
            	2661, 0,
            1, 8, 1, /* 2721: pointer.struct.asn1_string_st */
            	2661, 0,
            1, 8, 1, /* 2726: pointer.struct.asn1_string_st */
            	2661, 0,
            1, 8, 1, /* 2731: pointer.struct.asn1_string_st */
            	2661, 0,
            1, 8, 1, /* 2736: pointer.struct.ASN1_VALUE_st */
            	2741, 0,
            0, 0, 0, /* 2741: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2744: pointer.struct.evp_pkey_st */
            	2749, 0,
            0, 56, 4, /* 2749: struct.evp_pkey_st */
            	2760, 16,
            	2768, 24,
            	2776, 32,
            	3094, 48,
            1, 8, 1, /* 2760: pointer.struct.evp_pkey_asn1_method_st */
            	2765, 0,
            0, 0, 0, /* 2765: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 2768: pointer.struct.engine_st */
            	2773, 0,
            0, 0, 0, /* 2773: struct.engine_st */
            0, 8, 5, /* 2776: union.unknown */
            	61, 0,
            	2789, 0,
            	2940, 0,
            	3018, 0,
            	3086, 0,
            1, 8, 1, /* 2789: pointer.struct.rsa_st */
            	2794, 0,
            0, 168, 17, /* 2794: struct.rsa_st */
            	2831, 16,
            	2768, 24,
            	2886, 32,
            	2886, 40,
            	2886, 48,
            	2886, 56,
            	2886, 64,
            	2886, 72,
            	2886, 80,
            	2886, 88,
            	2896, 96,
            	2918, 120,
            	2918, 128,
            	2918, 136,
            	61, 144,
            	2932, 152,
            	2932, 160,
            1, 8, 1, /* 2831: pointer.struct.rsa_meth_st */
            	2836, 0,
            0, 112, 13, /* 2836: struct.rsa_meth_st */
            	10, 0,
            	2865, 8,
            	2865, 16,
            	2865, 24,
            	2865, 32,
            	2868, 40,
            	2871, 48,
            	2874, 56,
            	2874, 64,
            	61, 80,
            	2877, 88,
            	2880, 96,
            	2883, 104,
            64097, 8, 0, /* 2865: pointer.func */
            64097, 8, 0, /* 2868: pointer.func */
            64097, 8, 0, /* 2871: pointer.func */
            64097, 8, 0, /* 2874: pointer.func */
            64097, 8, 0, /* 2877: pointer.func */
            64097, 8, 0, /* 2880: pointer.func */
            64097, 8, 0, /* 2883: pointer.func */
            1, 8, 1, /* 2886: pointer.struct.bignum_st */
            	2891, 0,
            0, 24, 1, /* 2891: struct.bignum_st */
            	76, 0,
            0, 16, 1, /* 2896: struct.crypto_ex_data_st */
            	2901, 0,
            1, 8, 1, /* 2901: pointer.struct.stack_st_void */
            	2906, 0,
            0, 32, 1, /* 2906: struct.stack_st_void */
            	2911, 0,
            0, 32, 2, /* 2911: struct.stack_st */
            	680, 8,
            	472, 24,
            1, 8, 1, /* 2918: pointer.struct.bn_mont_ctx_st */
            	2923, 0,
            0, 96, 3, /* 2923: struct.bn_mont_ctx_st */
            	2891, 8,
            	2891, 32,
            	2891, 56,
            1, 8, 1, /* 2932: pointer.struct.bn_blinding_st */
            	2937, 0,
            0, 0, 0, /* 2937: struct.bn_blinding_st */
            1, 8, 1, /* 2940: pointer.struct.dsa_st */
            	2945, 0,
            0, 136, 11, /* 2945: struct.dsa_st */
            	2886, 24,
            	2886, 32,
            	2886, 40,
            	2886, 48,
            	2886, 56,
            	2886, 64,
            	2886, 72,
            	2918, 88,
            	2896, 104,
            	2970, 120,
            	2768, 128,
            1, 8, 1, /* 2970: pointer.struct.dsa_method */
            	2975, 0,
            0, 96, 11, /* 2975: struct.dsa_method */
            	10, 0,
            	3000, 8,
            	3003, 16,
            	3006, 24,
            	2560, 32,
            	3009, 40,
            	3012, 48,
            	3012, 56,
            	61, 72,
            	3015, 80,
            	3012, 88,
            64097, 8, 0, /* 3000: pointer.func */
            64097, 8, 0, /* 3003: pointer.func */
            64097, 8, 0, /* 3006: pointer.func */
            64097, 8, 0, /* 3009: pointer.func */
            64097, 8, 0, /* 3012: pointer.func */
            64097, 8, 0, /* 3015: pointer.func */
            1, 8, 1, /* 3018: pointer.struct.dh_st */
            	3023, 0,
            0, 144, 12, /* 3023: struct.dh_st */
            	2886, 8,
            	2886, 16,
            	2886, 32,
            	2886, 40,
            	2918, 56,
            	2886, 64,
            	2886, 72,
            	225, 80,
            	2886, 96,
            	2896, 112,
            	3050, 128,
            	2768, 136,
            1, 8, 1, /* 3050: pointer.struct.dh_method */
            	3055, 0,
            0, 72, 8, /* 3055: struct.dh_method */
            	10, 0,
            	3074, 8,
            	3077, 16,
            	3080, 24,
            	3074, 32,
            	3074, 40,
            	61, 56,
            	3083, 64,
            64097, 8, 0, /* 3074: pointer.func */
            64097, 8, 0, /* 3077: pointer.func */
            64097, 8, 0, /* 3080: pointer.func */
            64097, 8, 0, /* 3083: pointer.func */
            1, 8, 1, /* 3086: pointer.struct.ec_key_st */
            	3091, 0,
            0, 0, 0, /* 3091: struct.ec_key_st */
            1, 8, 1, /* 3094: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3099, 0,
            0, 32, 2, /* 3099: struct.stack_st_fake_X509_ATTRIBUTE */
            	3106, 8,
            	472, 24,
            64099, 8, 2, /* 3106: pointer_to_array_of_pointers_to_stack */
            	3113, 0,
            	469, 20,
            0, 8, 1, /* 3113: pointer.X509_ATTRIBUTE */
            	888, 0,
            0, 0, 1, /* 3118: X509_OBJECT */
            	3123, 0,
            0, 16, 1, /* 3123: struct.x509_object_st */
            	3128, 8,
            0, 8, 4, /* 3128: union.unknown */
            	61, 0,
            	3139, 0,
            	3651, 0,
            	3280, 0,
            1, 8, 1, /* 3139: pointer.struct.x509_st */
            	3144, 0,
            0, 184, 12, /* 3144: struct.x509_st */
            	3171, 0,
            	2331, 8,
            	2430, 16,
            	61, 32,
            	2196, 40,
            	2435, 104,
            	2525, 112,
            	2514, 120,
            	2490, 128,
            	3553, 136,
            	3577, 144,
            	3585, 176,
            1, 8, 1, /* 3171: pointer.struct.x509_cinf_st */
            	3176, 0,
            0, 104, 11, /* 3176: struct.x509_cinf_st */
            	2420, 0,
            	2420, 8,
            	2331, 16,
            	3201, 24,
            	3249, 32,
            	3201, 40,
            	3266, 48,
            	2430, 56,
            	2430, 64,
            	3524, 72,
            	3548, 80,
            1, 8, 1, /* 3201: pointer.struct.X509_name_st */
            	3206, 0,
            0, 40, 3, /* 3206: struct.X509_name_st */
            	3215, 0,
            	3239, 16,
            	225, 24,
            1, 8, 1, /* 3215: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3220, 0,
            0, 32, 2, /* 3220: struct.stack_st_fake_X509_NAME_ENTRY */
            	3227, 8,
            	472, 24,
            64099, 8, 2, /* 3227: pointer_to_array_of_pointers_to_stack */
            	3234, 0,
            	469, 20,
            0, 8, 1, /* 3234: pointer.X509_NAME_ENTRY */
            	433, 0,
            1, 8, 1, /* 3239: pointer.struct.buf_mem_st */
            	3244, 0,
            0, 24, 1, /* 3244: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 3249: pointer.struct.X509_val_st */
            	3254, 0,
            0, 16, 2, /* 3254: struct.X509_val_st */
            	3261, 0,
            	3261, 8,
            1, 8, 1, /* 3261: pointer.struct.asn1_string_st */
            	2415, 0,
            1, 8, 1, /* 3266: pointer.struct.X509_pubkey_st */
            	3271, 0,
            0, 24, 3, /* 3271: struct.X509_pubkey_st */
            	2331, 0,
            	2430, 8,
            	3280, 16,
            1, 8, 1, /* 3280: pointer.struct.evp_pkey_st */
            	3285, 0,
            0, 56, 4, /* 3285: struct.evp_pkey_st */
            	3296, 16,
            	2318, 24,
            	3304, 32,
            	3500, 48,
            1, 8, 1, /* 3296: pointer.struct.evp_pkey_asn1_method_st */
            	3301, 0,
            0, 0, 0, /* 3301: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 3304: union.unknown */
            	61, 0,
            	3317, 0,
            	3422, 0,
            	3427, 0,
            	3495, 0,
            1, 8, 1, /* 3317: pointer.struct.rsa_st */
            	3322, 0,
            0, 168, 17, /* 3322: struct.rsa_st */
            	3359, 16,
            	2318, 24,
            	2243, 32,
            	2243, 40,
            	2243, 48,
            	2243, 56,
            	2243, 64,
            	2243, 72,
            	2243, 80,
            	2243, 88,
            	2196, 96,
            	2253, 120,
            	2253, 128,
            	2253, 136,
            	61, 144,
            	3414, 152,
            	3414, 160,
            1, 8, 1, /* 3359: pointer.struct.rsa_meth_st */
            	3364, 0,
            0, 112, 13, /* 3364: struct.rsa_meth_st */
            	10, 0,
            	3393, 8,
            	3393, 16,
            	3393, 24,
            	3393, 32,
            	3396, 40,
            	3399, 48,
            	3402, 56,
            	3402, 64,
            	61, 80,
            	3405, 88,
            	3408, 96,
            	3411, 104,
            64097, 8, 0, /* 3393: pointer.func */
            64097, 8, 0, /* 3396: pointer.func */
            64097, 8, 0, /* 3399: pointer.func */
            64097, 8, 0, /* 3402: pointer.func */
            64097, 8, 0, /* 3405: pointer.func */
            64097, 8, 0, /* 3408: pointer.func */
            64097, 8, 0, /* 3411: pointer.func */
            1, 8, 1, /* 3414: pointer.struct.bn_blinding_st */
            	3419, 0,
            0, 0, 0, /* 3419: struct.bn_blinding_st */
            1, 8, 1, /* 3422: pointer.struct.dsa_st */
            	2218, 0,
            1, 8, 1, /* 3427: pointer.struct.dh_st */
            	3432, 0,
            0, 144, 12, /* 3432: struct.dh_st */
            	2243, 8,
            	2243, 16,
            	2243, 32,
            	2243, 40,
            	2253, 56,
            	2243, 64,
            	2243, 72,
            	225, 80,
            	2243, 96,
            	2196, 112,
            	3459, 128,
            	2318, 136,
            1, 8, 1, /* 3459: pointer.struct.dh_method */
            	3464, 0,
            0, 72, 8, /* 3464: struct.dh_method */
            	10, 0,
            	3483, 8,
            	3486, 16,
            	3489, 24,
            	3483, 32,
            	3483, 40,
            	61, 56,
            	3492, 64,
            64097, 8, 0, /* 3483: pointer.func */
            64097, 8, 0, /* 3486: pointer.func */
            64097, 8, 0, /* 3489: pointer.func */
            64097, 8, 0, /* 3492: pointer.func */
            1, 8, 1, /* 3495: pointer.struct.ec_key_st */
            	2522, 0,
            1, 8, 1, /* 3500: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3505, 0,
            0, 32, 2, /* 3505: struct.stack_st_fake_X509_ATTRIBUTE */
            	3512, 8,
            	472, 24,
            64099, 8, 2, /* 3512: pointer_to_array_of_pointers_to_stack */
            	3519, 0,
            	469, 20,
            0, 8, 1, /* 3519: pointer.X509_ATTRIBUTE */
            	888, 0,
            1, 8, 1, /* 3524: pointer.struct.stack_st_X509_EXTENSION */
            	3529, 0,
            0, 32, 2, /* 3529: struct.stack_st_fake_X509_EXTENSION */
            	3536, 8,
            	472, 24,
            64099, 8, 2, /* 3536: pointer_to_array_of_pointers_to_stack */
            	3543, 0,
            	469, 20,
            0, 8, 1, /* 3543: pointer.X509_EXTENSION */
            	1267, 0,
            0, 24, 1, /* 3548: struct.ASN1_ENCODING_st */
            	225, 0,
            1, 8, 1, /* 3553: pointer.struct.stack_st_GENERAL_NAME */
            	3558, 0,
            0, 32, 2, /* 3558: struct.stack_st_fake_GENERAL_NAME */
            	3565, 8,
            	472, 24,
            64099, 8, 2, /* 3565: pointer_to_array_of_pointers_to_stack */
            	3572, 0,
            	469, 20,
            0, 8, 1, /* 3572: pointer.GENERAL_NAME */
            	1405, 0,
            1, 8, 1, /* 3577: pointer.struct.NAME_CONSTRAINTS_st */
            	3582, 0,
            0, 0, 0, /* 3582: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3585: pointer.struct.x509_cert_aux_st */
            	3590, 0,
            0, 40, 5, /* 3590: struct.x509_cert_aux_st */
            	3603, 0,
            	3603, 8,
            	2485, 16,
            	2435, 24,
            	3627, 32,
            1, 8, 1, /* 3603: pointer.struct.stack_st_ASN1_OBJECT */
            	3608, 0,
            0, 32, 2, /* 3608: struct.stack_st_fake_ASN1_OBJECT */
            	3615, 8,
            	472, 24,
            64099, 8, 2, /* 3615: pointer_to_array_of_pointers_to_stack */
            	3622, 0,
            	469, 20,
            0, 8, 1, /* 3622: pointer.ASN1_OBJECT */
            	1807, 0,
            1, 8, 1, /* 3627: pointer.struct.stack_st_X509_ALGOR */
            	3632, 0,
            0, 32, 2, /* 3632: struct.stack_st_fake_X509_ALGOR */
            	3639, 8,
            	472, 24,
            64099, 8, 2, /* 3639: pointer_to_array_of_pointers_to_stack */
            	3646, 0,
            	469, 20,
            0, 8, 1, /* 3646: pointer.X509_ALGOR */
            	1845, 0,
            1, 8, 1, /* 3651: pointer.struct.X509_crl_st */
            	3656, 0,
            0, 120, 10, /* 3656: struct.X509_crl_st */
            	3679, 0,
            	2331, 8,
            	2430, 16,
            	2525, 32,
            	3806, 40,
            	2420, 56,
            	2420, 64,
            	3814, 96,
            	3855, 104,
            	49, 112,
            1, 8, 1, /* 3679: pointer.struct.X509_crl_info_st */
            	3684, 0,
            0, 80, 8, /* 3684: struct.X509_crl_info_st */
            	2420, 0,
            	2331, 8,
            	3201, 16,
            	3261, 24,
            	3261, 32,
            	3703, 40,
            	3524, 48,
            	3548, 56,
            1, 8, 1, /* 3703: pointer.struct.stack_st_X509_REVOKED */
            	3708, 0,
            0, 32, 2, /* 3708: struct.stack_st_fake_X509_REVOKED */
            	3715, 8,
            	472, 24,
            64099, 8, 2, /* 3715: pointer_to_array_of_pointers_to_stack */
            	3722, 0,
            	469, 20,
            0, 8, 1, /* 3722: pointer.X509_REVOKED */
            	3727, 0,
            0, 0, 1, /* 3727: X509_REVOKED */
            	3732, 0,
            0, 40, 4, /* 3732: struct.x509_revoked_st */
            	3743, 0,
            	3753, 8,
            	3758, 16,
            	3782, 24,
            1, 8, 1, /* 3743: pointer.struct.asn1_string_st */
            	3748, 0,
            0, 24, 1, /* 3748: struct.asn1_string_st */
            	225, 8,
            1, 8, 1, /* 3753: pointer.struct.asn1_string_st */
            	3748, 0,
            1, 8, 1, /* 3758: pointer.struct.stack_st_X509_EXTENSION */
            	3763, 0,
            0, 32, 2, /* 3763: struct.stack_st_fake_X509_EXTENSION */
            	3770, 8,
            	472, 24,
            64099, 8, 2, /* 3770: pointer_to_array_of_pointers_to_stack */
            	3777, 0,
            	469, 20,
            0, 8, 1, /* 3777: pointer.X509_EXTENSION */
            	1267, 0,
            1, 8, 1, /* 3782: pointer.struct.stack_st_GENERAL_NAME */
            	3787, 0,
            0, 32, 2, /* 3787: struct.stack_st_fake_GENERAL_NAME */
            	3794, 8,
            	472, 24,
            64099, 8, 2, /* 3794: pointer_to_array_of_pointers_to_stack */
            	3801, 0,
            	469, 20,
            0, 8, 1, /* 3801: pointer.GENERAL_NAME */
            	1405, 0,
            1, 8, 1, /* 3806: pointer.struct.ISSUING_DIST_POINT_st */
            	3811, 0,
            0, 0, 0, /* 3811: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 3814: pointer.struct.stack_st_GENERAL_NAMES */
            	3819, 0,
            0, 32, 2, /* 3819: struct.stack_st_fake_GENERAL_NAMES */
            	3826, 8,
            	472, 24,
            64099, 8, 2, /* 3826: pointer_to_array_of_pointers_to_stack */
            	3833, 0,
            	469, 20,
            0, 8, 1, /* 3833: pointer.GENERAL_NAMES */
            	3838, 0,
            0, 0, 1, /* 3838: GENERAL_NAMES */
            	3843, 0,
            0, 32, 1, /* 3843: struct.stack_st_GENERAL_NAME */
            	3848, 0,
            0, 32, 2, /* 3848: struct.stack_st */
            	680, 8,
            	472, 24,
            1, 8, 1, /* 3855: pointer.struct.x509_crl_method_st */
            	3860, 0,
            0, 0, 0, /* 3860: struct.x509_crl_method_st */
            64097, 8, 0, /* 3863: pointer.func */
            64097, 8, 0, /* 3866: pointer.func */
            0, 104, 11, /* 3869: struct.x509_cinf_st */
            	2666, 0,
            	2666, 8,
            	2577, 16,
            	3894, 24,
            	3942, 32,
            	3894, 40,
            	2563, 48,
            	2676, 56,
            	2676, 64,
            	3959, 72,
            	3983, 80,
            1, 8, 1, /* 3894: pointer.struct.X509_name_st */
            	3899, 0,
            0, 40, 3, /* 3899: struct.X509_name_st */
            	3908, 0,
            	3932, 16,
            	225, 24,
            1, 8, 1, /* 3908: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3913, 0,
            0, 32, 2, /* 3913: struct.stack_st_fake_X509_NAME_ENTRY */
            	3920, 8,
            	472, 24,
            64099, 8, 2, /* 3920: pointer_to_array_of_pointers_to_stack */
            	3927, 0,
            	469, 20,
            0, 8, 1, /* 3927: pointer.X509_NAME_ENTRY */
            	433, 0,
            1, 8, 1, /* 3932: pointer.struct.buf_mem_st */
            	3937, 0,
            0, 24, 1, /* 3937: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 3942: pointer.struct.X509_val_st */
            	3947, 0,
            0, 16, 2, /* 3947: struct.X509_val_st */
            	3954, 0,
            	3954, 8,
            1, 8, 1, /* 3954: pointer.struct.asn1_string_st */
            	2661, 0,
            1, 8, 1, /* 3959: pointer.struct.stack_st_X509_EXTENSION */
            	3964, 0,
            0, 32, 2, /* 3964: struct.stack_st_fake_X509_EXTENSION */
            	3971, 8,
            	472, 24,
            64099, 8, 2, /* 3971: pointer_to_array_of_pointers_to_stack */
            	3978, 0,
            	469, 20,
            0, 8, 1, /* 3978: pointer.X509_EXTENSION */
            	1267, 0,
            0, 24, 1, /* 3983: struct.ASN1_ENCODING_st */
            	225, 0,
            0, 0, 0, /* 3988: struct.X509_POLICY_CACHE_st */
            64097, 8, 0, /* 3991: pointer.func */
            64097, 8, 0, /* 3994: pointer.func */
            0, 0, 0, /* 3997: struct.NAME_CONSTRAINTS_st */
            64097, 8, 0, /* 4000: pointer.func */
            0, 0, 1, /* 4003: SSL_CIPHER */
            	4008, 0,
            0, 88, 1, /* 4008: struct.ssl_cipher_st */
            	10, 8,
            0, 352, 14, /* 4013: struct.ssl_session_st */
            	61, 144,
            	61, 152,
            	4044, 168,
            	153, 176,
            	2191, 224,
            	4255, 240,
            	658, 248,
            	4279, 264,
            	4279, 272,
            	61, 280,
            	225, 296,
            	225, 312,
            	225, 320,
            	61, 344,
            1, 8, 1, /* 4044: pointer.struct.sess_cert_st */
            	4049, 0,
            0, 248, 5, /* 4049: struct.sess_cert_st */
            	4062, 0,
            	139, 16,
            	2049, 216,
            	2054, 224,
            	2059, 232,
            1, 8, 1, /* 4062: pointer.struct.stack_st_X509 */
            	4067, 0,
            0, 32, 2, /* 4067: struct.stack_st_fake_X509 */
            	4074, 8,
            	472, 24,
            64099, 8, 2, /* 4074: pointer_to_array_of_pointers_to_stack */
            	4081, 0,
            	469, 20,
            0, 8, 1, /* 4081: pointer.X509 */
            	4086, 0,
            0, 0, 1, /* 4086: X509 */
            	4091, 0,
            0, 184, 12, /* 4091: struct.x509_st */
            	4118, 0,
            	2577, 8,
            	2676, 16,
            	61, 32,
            	2896, 40,
            	2681, 104,
            	4123, 112,
            	4131, 120,
            	4136, 128,
            	4160, 136,
            	4184, 144,
            	4189, 176,
            1, 8, 1, /* 4118: pointer.struct.x509_cinf_st */
            	3869, 0,
            1, 8, 1, /* 4123: pointer.struct.AUTHORITY_KEYID_st */
            	4128, 0,
            0, 0, 0, /* 4128: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4131: pointer.struct.X509_POLICY_CACHE_st */
            	3988, 0,
            1, 8, 1, /* 4136: pointer.struct.stack_st_DIST_POINT */
            	4141, 0,
            0, 32, 2, /* 4141: struct.stack_st_fake_DIST_POINT */
            	4148, 8,
            	472, 24,
            64099, 8, 2, /* 4148: pointer_to_array_of_pointers_to_stack */
            	4155, 0,
            	469, 20,
            0, 8, 1, /* 4155: pointer.DIST_POINT */
            	1348, 0,
            1, 8, 1, /* 4160: pointer.struct.stack_st_GENERAL_NAME */
            	4165, 0,
            0, 32, 2, /* 4165: struct.stack_st_fake_GENERAL_NAME */
            	4172, 8,
            	472, 24,
            64099, 8, 2, /* 4172: pointer_to_array_of_pointers_to_stack */
            	4179, 0,
            	469, 20,
            0, 8, 1, /* 4179: pointer.GENERAL_NAME */
            	1405, 0,
            1, 8, 1, /* 4184: pointer.struct.NAME_CONSTRAINTS_st */
            	3997, 0,
            1, 8, 1, /* 4189: pointer.struct.x509_cert_aux_st */
            	4194, 0,
            0, 40, 5, /* 4194: struct.x509_cert_aux_st */
            	4207, 0,
            	4207, 8,
            	2731, 16,
            	2681, 24,
            	4231, 32,
            1, 8, 1, /* 4207: pointer.struct.stack_st_ASN1_OBJECT */
            	4212, 0,
            0, 32, 2, /* 4212: struct.stack_st_fake_ASN1_OBJECT */
            	4219, 8,
            	472, 24,
            64099, 8, 2, /* 4219: pointer_to_array_of_pointers_to_stack */
            	4226, 0,
            	469, 20,
            0, 8, 1, /* 4226: pointer.ASN1_OBJECT */
            	1807, 0,
            1, 8, 1, /* 4231: pointer.struct.stack_st_X509_ALGOR */
            	4236, 0,
            0, 32, 2, /* 4236: struct.stack_st_fake_X509_ALGOR */
            	4243, 8,
            	472, 24,
            64099, 8, 2, /* 4243: pointer_to_array_of_pointers_to_stack */
            	4250, 0,
            	469, 20,
            0, 8, 1, /* 4250: pointer.X509_ALGOR */
            	1845, 0,
            1, 8, 1, /* 4255: pointer.struct.stack_st_SSL_CIPHER */
            	4260, 0,
            0, 32, 2, /* 4260: struct.stack_st_fake_SSL_CIPHER */
            	4267, 8,
            	472, 24,
            64099, 8, 2, /* 4267: pointer_to_array_of_pointers_to_stack */
            	4274, 0,
            	469, 20,
            0, 8, 1, /* 4274: pointer.SSL_CIPHER */
            	4003, 0,
            1, 8, 1, /* 4279: pointer.struct.ssl_session_st */
            	4013, 0,
            64097, 8, 0, /* 4284: pointer.func */
            64097, 8, 0, /* 4287: pointer.func */
            64097, 8, 0, /* 4290: pointer.func */
            1, 8, 1, /* 4293: pointer.struct.stack_st_X509_LOOKUP */
            	4298, 0,
            0, 32, 2, /* 4298: struct.stack_st_fake_X509_LOOKUP */
            	4305, 8,
            	472, 24,
            64099, 8, 2, /* 4305: pointer_to_array_of_pointers_to_stack */
            	4312, 0,
            	469, 20,
            0, 8, 1, /* 4312: pointer.X509_LOOKUP */
            	4317, 0,
            0, 0, 1, /* 4317: X509_LOOKUP */
            	4322, 0,
            0, 32, 3, /* 4322: struct.x509_lookup_st */
            	4331, 8,
            	61, 16,
            	4374, 24,
            1, 8, 1, /* 4331: pointer.struct.x509_lookup_method_st */
            	4336, 0,
            0, 80, 10, /* 4336: struct.x509_lookup_method_st */
            	10, 0,
            	4359, 8,
            	2557, 16,
            	4359, 24,
            	4359, 32,
            	4362, 40,
            	4365, 48,
            	4284, 56,
            	4368, 64,
            	4371, 72,
            64097, 8, 0, /* 4359: pointer.func */
            64097, 8, 0, /* 4362: pointer.func */
            64097, 8, 0, /* 4365: pointer.func */
            64097, 8, 0, /* 4368: pointer.func */
            64097, 8, 0, /* 4371: pointer.func */
            1, 8, 1, /* 4374: pointer.struct.x509_store_st */
            	4379, 0,
            0, 144, 15, /* 4379: struct.x509_store_st */
            	4412, 8,
            	4293, 16,
            	4436, 24,
            	4448, 32,
            	4451, 40,
            	4454, 48,
            	4457, 56,
            	4448, 64,
            	4460, 72,
            	4463, 80,
            	4466, 88,
            	4469, 96,
            	4287, 104,
            	4448, 112,
            	2196, 120,
            1, 8, 1, /* 4412: pointer.struct.stack_st_X509_OBJECT */
            	4417, 0,
            0, 32, 2, /* 4417: struct.stack_st_fake_X509_OBJECT */
            	4424, 8,
            	472, 24,
            64099, 8, 2, /* 4424: pointer_to_array_of_pointers_to_stack */
            	4431, 0,
            	469, 20,
            0, 8, 1, /* 4431: pointer.X509_OBJECT */
            	3118, 0,
            1, 8, 1, /* 4436: pointer.struct.X509_VERIFY_PARAM_st */
            	4441, 0,
            0, 56, 2, /* 4441: struct.X509_VERIFY_PARAM_st */
            	61, 0,
            	3603, 48,
            64097, 8, 0, /* 4448: pointer.func */
            64097, 8, 0, /* 4451: pointer.func */
            64097, 8, 0, /* 4454: pointer.func */
            64097, 8, 0, /* 4457: pointer.func */
            64097, 8, 0, /* 4460: pointer.func */
            64097, 8, 0, /* 4463: pointer.func */
            64097, 8, 0, /* 4466: pointer.func */
            64097, 8, 0, /* 4469: pointer.func */
            64097, 8, 0, /* 4472: pointer.func */
            0, 144, 15, /* 4475: struct.x509_store_st */
            	4508, 8,
            	4532, 16,
            	4556, 24,
            	4568, 32,
            	4571, 40,
            	4574, 48,
            	4577, 56,
            	4568, 64,
            	4580, 72,
            	4583, 80,
            	4586, 88,
            	3866, 96,
            	4589, 104,
            	4568, 112,
            	658, 120,
            1, 8, 1, /* 4508: pointer.struct.stack_st_X509_OBJECT */
            	4513, 0,
            0, 32, 2, /* 4513: struct.stack_st_fake_X509_OBJECT */
            	4520, 8,
            	472, 24,
            64099, 8, 2, /* 4520: pointer_to_array_of_pointers_to_stack */
            	4527, 0,
            	469, 20,
            0, 8, 1, /* 4527: pointer.X509_OBJECT */
            	3118, 0,
            1, 8, 1, /* 4532: pointer.struct.stack_st_X509_LOOKUP */
            	4537, 0,
            0, 32, 2, /* 4537: struct.stack_st_fake_X509_LOOKUP */
            	4544, 8,
            	472, 24,
            64099, 8, 2, /* 4544: pointer_to_array_of_pointers_to_stack */
            	4551, 0,
            	469, 20,
            0, 8, 1, /* 4551: pointer.X509_LOOKUP */
            	4317, 0,
            1, 8, 1, /* 4556: pointer.struct.X509_VERIFY_PARAM_st */
            	4561, 0,
            0, 56, 2, /* 4561: struct.X509_VERIFY_PARAM_st */
            	61, 0,
            	1783, 48,
            64097, 8, 0, /* 4568: pointer.func */
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
            0, 112, 11, /* 4601: struct.ssl3_enc_method */
            	4626, 0,
            	4472, 8,
            	4629, 16,
            	4632, 24,
            	4626, 32,
            	4635, 40,
            	4638, 56,
            	10, 64,
            	10, 80,
            	4641, 96,
            	4644, 104,
            64097, 8, 0, /* 4626: pointer.func */
            64097, 8, 0, /* 4629: pointer.func */
            64097, 8, 0, /* 4632: pointer.func */
            64097, 8, 0, /* 4635: pointer.func */
            64097, 8, 0, /* 4638: pointer.func */
            64097, 8, 0, /* 4641: pointer.func */
            64097, 8, 0, /* 4644: pointer.func */
            64097, 8, 0, /* 4647: pointer.func */
            64097, 8, 0, /* 4650: pointer.func */
            0, 736, 50, /* 4653: struct.ssl_ctx_st */
            	4756, 0,
            	4255, 8,
            	4255, 16,
            	4861, 24,
            	4866, 32,
            	4279, 48,
            	4279, 56,
            	3863, 80,
            	3991, 88,
            	4902, 96,
            	4592, 152,
            	49, 160,
            	4905, 168,
            	49, 176,
            	2183, 184,
            	4908, 192,
            	2180, 200,
            	658, 208,
            	2004, 224,
            	2004, 232,
            	2004, 240,
            	4062, 248,
            	2116, 256,
            	2107, 264,
            	4911, 272,
            	2326, 304,
            	3994, 320,
            	49, 328,
            	4571, 376,
            	4940, 384,
            	4556, 392,
            	540, 408,
            	52, 416,
            	49, 424,
            	4598, 480,
            	55, 488,
            	49, 496,
            	110, 504,
            	49, 512,
            	61, 520,
            	107, 528,
            	4943, 536,
            	97, 552,
            	97, 560,
            	18, 568,
            	84, 696,
            	49, 704,
            	15, 712,
            	49, 720,
            	2533, 728,
            1, 8, 1, /* 4756: pointer.struct.ssl_method_st */
            	4761, 0,
            0, 232, 28, /* 4761: struct.ssl_method_st */
            	4629, 8,
            	4820, 16,
            	4820, 24,
            	4629, 32,
            	4629, 40,
            	4823, 48,
            	4823, 56,
            	4826, 64,
            	4629, 72,
            	4629, 80,
            	4629, 88,
            	4829, 96,
            	4650, 104,
            	4647, 112,
            	4629, 120,
            	4595, 128,
            	4832, 136,
            	4835, 144,
            	4290, 152,
            	4838, 160,
            	4841, 168,
            	4844, 176,
            	4847, 184,
            	2177, 192,
            	4850, 200,
            	4841, 208,
            	4855, 216,
            	4858, 224,
            64097, 8, 0, /* 4820: pointer.func */
            64097, 8, 0, /* 4823: pointer.func */
            64097, 8, 0, /* 4826: pointer.func */
            64097, 8, 0, /* 4829: pointer.func */
            64097, 8, 0, /* 4832: pointer.func */
            64097, 8, 0, /* 4835: pointer.func */
            64097, 8, 0, /* 4838: pointer.func */
            64097, 8, 0, /* 4841: pointer.func */
            64097, 8, 0, /* 4844: pointer.func */
            64097, 8, 0, /* 4847: pointer.func */
            1, 8, 1, /* 4850: pointer.struct.ssl3_enc_method */
            	4601, 0,
            64097, 8, 0, /* 4855: pointer.func */
            64097, 8, 0, /* 4858: pointer.func */
            1, 8, 1, /* 4861: pointer.struct.x509_store_st */
            	4475, 0,
            1, 8, 1, /* 4866: pointer.struct.lhash_st */
            	4871, 0,
            0, 176, 3, /* 4871: struct.lhash_st */
            	4880, 0,
            	472, 8,
            	4000, 16,
            1, 8, 1, /* 4880: pointer.pointer.struct.lhash_node_st */
            	4885, 0,
            1, 8, 1, /* 4885: pointer.struct.lhash_node_st */
            	4890, 0,
            0, 24, 2, /* 4890: struct.lhash_node_st */
            	49, 0,
            	4897, 8,
            1, 8, 1, /* 4897: pointer.struct.lhash_node_st */
            	4890, 0,
            64097, 8, 0, /* 4902: pointer.func */
            64097, 8, 0, /* 4905: pointer.func */
            64097, 8, 0, /* 4908: pointer.func */
            1, 8, 1, /* 4911: pointer.struct.stack_st_X509_NAME */
            	4916, 0,
            0, 32, 2, /* 4916: struct.stack_st_fake_X509_NAME */
            	4923, 8,
            	472, 24,
            64099, 8, 2, /* 4923: pointer_to_array_of_pointers_to_stack */
            	4930, 0,
            	469, 20,
            0, 8, 1, /* 4930: pointer.X509_NAME */
            	4935, 0,
            0, 0, 1, /* 4935: X509_NAME */
            	2069, 0,
            64097, 8, 0, /* 4940: pointer.func */
            64097, 8, 0, /* 4943: pointer.func */
            1, 8, 1, /* 4946: pointer.struct.ssl_ctx_st */
            	4653, 0,
            0, 1, 0, /* 4951: char */
        },
        .arg_entity_index = { 4946, 3863, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    int (*new_arg_b)(struct ssl_st *, SSL_SESSION *) = *((int (**)(struct ssl_st *, SSL_SESSION *))new_args->args[1]);

    void (*orig_SSL_CTX_sess_set_new_cb)(SSL_CTX *,int (*)(struct ssl_st *, SSL_SESSION *));
    orig_SSL_CTX_sess_set_new_cb = dlsym(RTLD_NEXT, "SSL_CTX_sess_set_new_cb");
    (*orig_SSL_CTX_sess_set_new_cb)(new_arg_a,new_arg_b);

    syscall(889);

}

