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
            	8884096, 0,
            8884097, 8, 0, /* 15: pointer.func */
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
            8884097, 8, 0, /* 52: pointer.func */
            8884097, 8, 0, /* 55: pointer.func */
            8884097, 8, 0, /* 58: pointer.func */
            1, 8, 1, /* 61: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 66: pointer.struct.bignum_st */
            	71, 0,
            0, 24, 1, /* 71: struct.bignum_st */
            	76, 0,
            1, 8, 1, /* 76: pointer.unsigned int */
            	81, 0,
            0, 4, 0, /* 81: unsigned int */
            8884097, 8, 0, /* 84: pointer.func */
            0, 8, 1, /* 87: struct.ssl3_buf_freelist_entry_st */
            	92, 0,
            1, 8, 1, /* 92: pointer.struct.ssl3_buf_freelist_entry_st */
            	87, 0,
            1, 8, 1, /* 97: pointer.struct.ssl3_buf_freelist_st */
            	102, 0,
            0, 24, 1, /* 102: struct.ssl3_buf_freelist_st */
            	92, 16,
            8884097, 8, 0, /* 107: pointer.func */
            8884097, 8, 0, /* 110: pointer.func */
            8884097, 8, 0, /* 113: pointer.func */
            8884097, 8, 0, /* 116: pointer.func */
            8884097, 8, 0, /* 119: pointer.func */
            0, 296, 7, /* 122: struct.cert_st */
            	139, 0,
            	1907, 48,
            	119, 56,
            	1912, 64,
            	116, 72,
            	1917, 80,
            	113, 88,
            1, 8, 1, /* 139: pointer.struct.cert_pkey_st */
            	144, 0,
            0, 24, 3, /* 144: struct.cert_pkey_st */
            	153, 0,
            	516, 8,
            	1862, 16,
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
            8884099, 8, 2, /* 421: pointer_to_array_of_pointers_to_stack */
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
            8884097, 8, 0, /* 472: pointer.func */
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
            8884097, 8, 0, /* 637: pointer.func */
            8884097, 8, 0, /* 640: pointer.func */
            8884097, 8, 0, /* 643: pointer.func */
            8884097, 8, 0, /* 646: pointer.func */
            8884097, 8, 0, /* 649: pointer.func */
            8884097, 8, 0, /* 652: pointer.func */
            8884097, 8, 0, /* 655: pointer.func */
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
            8884097, 8, 0, /* 767: pointer.func */
            8884097, 8, 0, /* 770: pointer.func */
            8884097, 8, 0, /* 773: pointer.func */
            8884097, 8, 0, /* 776: pointer.func */
            8884097, 8, 0, /* 779: pointer.func */
            8884097, 8, 0, /* 782: pointer.func */
            8884097, 8, 0, /* 785: pointer.func */
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
            8884097, 8, 0, /* 844: pointer.func */
            8884097, 8, 0, /* 847: pointer.func */
            8884097, 8, 0, /* 850: pointer.func */
            8884097, 8, 0, /* 853: pointer.func */
            1, 8, 1, /* 856: pointer.struct.ec_key_st */
            	861, 0,
            0, 0, 0, /* 861: struct.ec_key_st */
            1, 8, 1, /* 864: pointer.struct.stack_st_X509_ATTRIBUTE */
            	869, 0,
            0, 32, 2, /* 869: struct.stack_st_fake_X509_ATTRIBUTE */
            	876, 8,
            	472, 24,
            8884099, 8, 2, /* 876: pointer_to_array_of_pointers_to_stack */
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
            8884099, 8, 2, /* 935: pointer_to_array_of_pointers_to_stack */
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
            8884099, 8, 2, /* 1255: pointer_to_array_of_pointers_to_stack */
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
            8884099, 8, 2, /* 1336: pointer_to_array_of_pointers_to_stack */
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
            8884099, 8, 2, /* 1393: pointer_to_array_of_pointers_to_stack */
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
            8884099, 8, 2, /* 1641: pointer_to_array_of_pointers_to_stack */
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
            8884099, 8, 2, /* 1687: pointer_to_array_of_pointers_to_stack */
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
            8884099, 8, 2, /* 1745: pointer_to_array_of_pointers_to_stack */
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
            8884099, 8, 2, /* 1795: pointer_to_array_of_pointers_to_stack */
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
            8884099, 8, 2, /* 1833: pointer_to_array_of_pointers_to_stack */
            	1840, 0,
            	469, 20,
            0, 8, 1, /* 1840: pointer.X509_ALGOR */
            	1845, 0,
            0, 0, 1, /* 1845: X509_ALGOR */
            	1850, 0,
            0, 16, 2, /* 1850: struct.X509_algor_st */
            	1010, 0,
            	1857, 8,
            1, 8, 1, /* 1857: pointer.struct.asn1_type_st */
            	952, 0,
            1, 8, 1, /* 1862: pointer.struct.env_md_st */
            	1867, 0,
            0, 120, 8, /* 1867: struct.env_md_st */
            	1886, 24,
            	1889, 32,
            	1892, 40,
            	1895, 48,
            	1886, 56,
            	1898, 64,
            	1901, 72,
            	1904, 112,
            8884097, 8, 0, /* 1886: pointer.func */
            8884097, 8, 0, /* 1889: pointer.func */
            8884097, 8, 0, /* 1892: pointer.func */
            8884097, 8, 0, /* 1895: pointer.func */
            8884097, 8, 0, /* 1898: pointer.func */
            8884097, 8, 0, /* 1901: pointer.func */
            8884097, 8, 0, /* 1904: pointer.func */
            1, 8, 1, /* 1907: pointer.struct.rsa_st */
            	566, 0,
            1, 8, 1, /* 1912: pointer.struct.dh_st */
            	793, 0,
            1, 8, 1, /* 1917: pointer.struct.ec_key_st */
            	861, 0,
            1, 8, 1, /* 1922: pointer.struct.stack_st_X509_NAME */
            	1927, 0,
            0, 32, 2, /* 1927: struct.stack_st_fake_X509_NAME */
            	1934, 8,
            	472, 24,
            8884099, 8, 2, /* 1934: pointer_to_array_of_pointers_to_stack */
            	1941, 0,
            	469, 20,
            0, 8, 1, /* 1941: pointer.X509_NAME */
            	1946, 0,
            0, 0, 1, /* 1946: X509_NAME */
            	1951, 0,
            0, 40, 3, /* 1951: struct.X509_name_st */
            	1960, 0,
            	1984, 16,
            	225, 24,
            1, 8, 1, /* 1960: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1965, 0,
            0, 32, 2, /* 1965: struct.stack_st_fake_X509_NAME_ENTRY */
            	1972, 8,
            	472, 24,
            8884099, 8, 2, /* 1972: pointer_to_array_of_pointers_to_stack */
            	1979, 0,
            	469, 20,
            0, 8, 1, /* 1979: pointer.X509_NAME_ENTRY */
            	433, 0,
            1, 8, 1, /* 1984: pointer.struct.buf_mem_st */
            	1989, 0,
            0, 24, 1, /* 1989: struct.buf_mem_st */
            	61, 8,
            8884097, 8, 0, /* 1994: pointer.func */
            8884097, 8, 0, /* 1997: pointer.func */
            8884097, 8, 0, /* 2000: pointer.func */
            0, 64, 7, /* 2003: struct.comp_method_st */
            	10, 8,
            	2020, 16,
            	2000, 24,
            	1997, 32,
            	1997, 40,
            	2023, 48,
            	2023, 56,
            8884097, 8, 0, /* 2020: pointer.func */
            8884097, 8, 0, /* 2023: pointer.func */
            1, 8, 1, /* 2026: pointer.struct.comp_method_st */
            	2003, 0,
            0, 0, 1, /* 2031: SSL_COMP */
            	2036, 0,
            0, 24, 2, /* 2036: struct.ssl_comp_st */
            	10, 8,
            	2026, 16,
            1, 8, 1, /* 2043: pointer.struct.stack_st_SSL_COMP */
            	2048, 0,
            0, 32, 2, /* 2048: struct.stack_st_fake_SSL_COMP */
            	2055, 8,
            	472, 24,
            8884099, 8, 2, /* 2055: pointer_to_array_of_pointers_to_stack */
            	2062, 0,
            	469, 20,
            0, 8, 1, /* 2062: pointer.SSL_COMP */
            	2031, 0,
            8884097, 8, 0, /* 2067: pointer.func */
            8884097, 8, 0, /* 2070: pointer.func */
            8884097, 8, 0, /* 2073: pointer.func */
            8884097, 8, 0, /* 2076: pointer.func */
            8884097, 8, 0, /* 2079: pointer.func */
            0, 88, 1, /* 2082: struct.ssl_cipher_st */
            	10, 8,
            1, 8, 1, /* 2087: pointer.struct.ssl_cipher_st */
            	2082, 0,
            0, 16, 1, /* 2092: struct.crypto_ex_data_st */
            	2097, 0,
            1, 8, 1, /* 2097: pointer.struct.stack_st_void */
            	2102, 0,
            0, 32, 1, /* 2102: struct.stack_st_void */
            	2107, 0,
            0, 32, 2, /* 2107: struct.stack_st */
            	680, 8,
            	472, 24,
            8884097, 8, 0, /* 2114: pointer.func */
            8884097, 8, 0, /* 2117: pointer.func */
            0, 168, 17, /* 2120: struct.rsa_st */
            	2157, 16,
            	2209, 24,
            	2217, 32,
            	2217, 40,
            	2217, 48,
            	2217, 56,
            	2217, 64,
            	2217, 72,
            	2217, 80,
            	2217, 88,
            	2227, 96,
            	2249, 120,
            	2249, 128,
            	2249, 136,
            	61, 144,
            	2263, 152,
            	2263, 160,
            1, 8, 1, /* 2157: pointer.struct.rsa_meth_st */
            	2162, 0,
            0, 112, 13, /* 2162: struct.rsa_meth_st */
            	10, 0,
            	2191, 8,
            	2191, 16,
            	2191, 24,
            	2191, 32,
            	2117, 40,
            	2194, 48,
            	2197, 56,
            	2197, 64,
            	61, 80,
            	2200, 88,
            	2203, 96,
            	2206, 104,
            8884097, 8, 0, /* 2191: pointer.func */
            8884097, 8, 0, /* 2194: pointer.func */
            8884097, 8, 0, /* 2197: pointer.func */
            8884097, 8, 0, /* 2200: pointer.func */
            8884097, 8, 0, /* 2203: pointer.func */
            8884097, 8, 0, /* 2206: pointer.func */
            1, 8, 1, /* 2209: pointer.struct.engine_st */
            	2214, 0,
            0, 0, 0, /* 2214: struct.engine_st */
            1, 8, 1, /* 2217: pointer.struct.bignum_st */
            	2222, 0,
            0, 24, 1, /* 2222: struct.bignum_st */
            	76, 0,
            0, 16, 1, /* 2227: struct.crypto_ex_data_st */
            	2232, 0,
            1, 8, 1, /* 2232: pointer.struct.stack_st_void */
            	2237, 0,
            0, 32, 1, /* 2237: struct.stack_st_void */
            	2242, 0,
            0, 32, 2, /* 2242: struct.stack_st */
            	680, 8,
            	472, 24,
            1, 8, 1, /* 2249: pointer.struct.bn_mont_ctx_st */
            	2254, 0,
            0, 96, 3, /* 2254: struct.bn_mont_ctx_st */
            	2222, 8,
            	2222, 32,
            	2222, 56,
            1, 8, 1, /* 2263: pointer.struct.bn_blinding_st */
            	2268, 0,
            0, 0, 0, /* 2268: struct.bn_blinding_st */
            0, 72, 8, /* 2271: struct.dh_method */
            	10, 0,
            	2290, 8,
            	2293, 16,
            	2296, 24,
            	2290, 32,
            	2290, 40,
            	61, 56,
            	2299, 64,
            8884097, 8, 0, /* 2290: pointer.func */
            8884097, 8, 0, /* 2293: pointer.func */
            8884097, 8, 0, /* 2296: pointer.func */
            8884097, 8, 0, /* 2299: pointer.func */
            8884097, 8, 0, /* 2302: pointer.func */
            8884097, 8, 0, /* 2305: pointer.func */
            1, 8, 1, /* 2308: pointer.struct.X509_crl_info_st */
            	2313, 0,
            0, 80, 8, /* 2313: struct.X509_crl_info_st */
            	2332, 0,
            	2342, 8,
            	2491, 16,
            	2539, 24,
            	2539, 32,
            	2544, 40,
            	2647, 48,
            	2671, 56,
            1, 8, 1, /* 2332: pointer.struct.asn1_string_st */
            	2337, 0,
            0, 24, 1, /* 2337: struct.asn1_string_st */
            	225, 8,
            1, 8, 1, /* 2342: pointer.struct.X509_algor_st */
            	2347, 0,
            0, 16, 2, /* 2347: struct.X509_algor_st */
            	2354, 0,
            	2368, 8,
            1, 8, 1, /* 2354: pointer.struct.asn1_object_st */
            	2359, 0,
            0, 40, 3, /* 2359: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	259, 24,
            1, 8, 1, /* 2368: pointer.struct.asn1_type_st */
            	2373, 0,
            0, 16, 1, /* 2373: struct.asn1_type_st */
            	2378, 8,
            0, 8, 20, /* 2378: union.unknown */
            	61, 0,
            	2421, 0,
            	2354, 0,
            	2332, 0,
            	2426, 0,
            	2431, 0,
            	2436, 0,
            	2441, 0,
            	2446, 0,
            	2451, 0,
            	2456, 0,
            	2461, 0,
            	2466, 0,
            	2471, 0,
            	2476, 0,
            	2481, 0,
            	2486, 0,
            	2421, 0,
            	2421, 0,
            	1235, 0,
            1, 8, 1, /* 2421: pointer.struct.asn1_string_st */
            	2337, 0,
            1, 8, 1, /* 2426: pointer.struct.asn1_string_st */
            	2337, 0,
            1, 8, 1, /* 2431: pointer.struct.asn1_string_st */
            	2337, 0,
            1, 8, 1, /* 2436: pointer.struct.asn1_string_st */
            	2337, 0,
            1, 8, 1, /* 2441: pointer.struct.asn1_string_st */
            	2337, 0,
            1, 8, 1, /* 2446: pointer.struct.asn1_string_st */
            	2337, 0,
            1, 8, 1, /* 2451: pointer.struct.asn1_string_st */
            	2337, 0,
            1, 8, 1, /* 2456: pointer.struct.asn1_string_st */
            	2337, 0,
            1, 8, 1, /* 2461: pointer.struct.asn1_string_st */
            	2337, 0,
            1, 8, 1, /* 2466: pointer.struct.asn1_string_st */
            	2337, 0,
            1, 8, 1, /* 2471: pointer.struct.asn1_string_st */
            	2337, 0,
            1, 8, 1, /* 2476: pointer.struct.asn1_string_st */
            	2337, 0,
            1, 8, 1, /* 2481: pointer.struct.asn1_string_st */
            	2337, 0,
            1, 8, 1, /* 2486: pointer.struct.asn1_string_st */
            	2337, 0,
            1, 8, 1, /* 2491: pointer.struct.X509_name_st */
            	2496, 0,
            0, 40, 3, /* 2496: struct.X509_name_st */
            	2505, 0,
            	2529, 16,
            	225, 24,
            1, 8, 1, /* 2505: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2510, 0,
            0, 32, 2, /* 2510: struct.stack_st_fake_X509_NAME_ENTRY */
            	2517, 8,
            	472, 24,
            8884099, 8, 2, /* 2517: pointer_to_array_of_pointers_to_stack */
            	2524, 0,
            	469, 20,
            0, 8, 1, /* 2524: pointer.X509_NAME_ENTRY */
            	433, 0,
            1, 8, 1, /* 2529: pointer.struct.buf_mem_st */
            	2534, 0,
            0, 24, 1, /* 2534: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 2539: pointer.struct.asn1_string_st */
            	2337, 0,
            1, 8, 1, /* 2544: pointer.struct.stack_st_X509_REVOKED */
            	2549, 0,
            0, 32, 2, /* 2549: struct.stack_st_fake_X509_REVOKED */
            	2556, 8,
            	472, 24,
            8884099, 8, 2, /* 2556: pointer_to_array_of_pointers_to_stack */
            	2563, 0,
            	469, 20,
            0, 8, 1, /* 2563: pointer.X509_REVOKED */
            	2568, 0,
            0, 0, 1, /* 2568: X509_REVOKED */
            	2573, 0,
            0, 40, 4, /* 2573: struct.x509_revoked_st */
            	2584, 0,
            	2594, 8,
            	2599, 16,
            	2623, 24,
            1, 8, 1, /* 2584: pointer.struct.asn1_string_st */
            	2589, 0,
            0, 24, 1, /* 2589: struct.asn1_string_st */
            	225, 8,
            1, 8, 1, /* 2594: pointer.struct.asn1_string_st */
            	2589, 0,
            1, 8, 1, /* 2599: pointer.struct.stack_st_X509_EXTENSION */
            	2604, 0,
            0, 32, 2, /* 2604: struct.stack_st_fake_X509_EXTENSION */
            	2611, 8,
            	472, 24,
            8884099, 8, 2, /* 2611: pointer_to_array_of_pointers_to_stack */
            	2618, 0,
            	469, 20,
            0, 8, 1, /* 2618: pointer.X509_EXTENSION */
            	1267, 0,
            1, 8, 1, /* 2623: pointer.struct.stack_st_GENERAL_NAME */
            	2628, 0,
            0, 32, 2, /* 2628: struct.stack_st_fake_GENERAL_NAME */
            	2635, 8,
            	472, 24,
            8884099, 8, 2, /* 2635: pointer_to_array_of_pointers_to_stack */
            	2642, 0,
            	469, 20,
            0, 8, 1, /* 2642: pointer.GENERAL_NAME */
            	1405, 0,
            1, 8, 1, /* 2647: pointer.struct.stack_st_X509_EXTENSION */
            	2652, 0,
            0, 32, 2, /* 2652: struct.stack_st_fake_X509_EXTENSION */
            	2659, 8,
            	472, 24,
            8884099, 8, 2, /* 2659: pointer_to_array_of_pointers_to_stack */
            	2666, 0,
            	469, 20,
            0, 8, 1, /* 2666: pointer.X509_EXTENSION */
            	1267, 0,
            0, 24, 1, /* 2671: struct.ASN1_ENCODING_st */
            	225, 0,
            1, 8, 1, /* 2676: pointer.struct.cert_st */
            	122, 0,
            1, 8, 1, /* 2681: pointer.struct.X509_POLICY_CACHE_st */
            	2686, 0,
            0, 0, 0, /* 2686: struct.X509_POLICY_CACHE_st */
            0, 0, 0, /* 2689: struct.AUTHORITY_KEYID_st */
            0, 0, 0, /* 2692: struct.ec_key_st */
            1, 8, 1, /* 2695: pointer.struct.AUTHORITY_KEYID_st */
            	2689, 0,
            1, 8, 1, /* 2700: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	2705, 0,
            0, 32, 2, /* 2705: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	2712, 8,
            	472, 24,
            8884099, 8, 2, /* 2712: pointer_to_array_of_pointers_to_stack */
            	2719, 0,
            	469, 20,
            0, 8, 1, /* 2719: pointer.SRTP_PROTECTION_PROFILE */
            	0, 0,
            8884097, 8, 0, /* 2724: pointer.func */
            8884097, 8, 0, /* 2727: pointer.func */
            1, 8, 1, /* 2730: pointer.struct.stack_st_X509_OBJECT */
            	2735, 0,
            0, 32, 2, /* 2735: struct.stack_st_fake_X509_OBJECT */
            	2742, 8,
            	472, 24,
            8884099, 8, 2, /* 2742: pointer_to_array_of_pointers_to_stack */
            	2749, 0,
            	469, 20,
            0, 8, 1, /* 2749: pointer.X509_OBJECT */
            	2754, 0,
            0, 0, 1, /* 2754: X509_OBJECT */
            	2759, 0,
            0, 16, 1, /* 2759: struct.x509_object_st */
            	2764, 8,
            0, 8, 4, /* 2764: union.unknown */
            	61, 0,
            	2775, 0,
            	3306, 0,
            	2863, 0,
            1, 8, 1, /* 2775: pointer.struct.x509_st */
            	2780, 0,
            0, 184, 12, /* 2780: struct.x509_st */
            	2807, 0,
            	2342, 8,
            	2431, 16,
            	61, 32,
            	2092, 40,
            	2436, 104,
            	2695, 112,
            	2681, 120,
            	3184, 128,
            	3208, 136,
            	3232, 144,
            	3240, 176,
            1, 8, 1, /* 2807: pointer.struct.x509_cinf_st */
            	2812, 0,
            0, 104, 11, /* 2812: struct.x509_cinf_st */
            	2332, 0,
            	2332, 8,
            	2342, 16,
            	2491, 24,
            	2837, 32,
            	2491, 40,
            	2849, 48,
            	2431, 56,
            	2431, 64,
            	2647, 72,
            	2671, 80,
            1, 8, 1, /* 2837: pointer.struct.X509_val_st */
            	2842, 0,
            0, 16, 2, /* 2842: struct.X509_val_st */
            	2539, 0,
            	2539, 8,
            1, 8, 1, /* 2849: pointer.struct.X509_pubkey_st */
            	2854, 0,
            0, 24, 3, /* 2854: struct.X509_pubkey_st */
            	2342, 0,
            	2431, 8,
            	2863, 16,
            1, 8, 1, /* 2863: pointer.struct.evp_pkey_st */
            	2868, 0,
            0, 56, 4, /* 2868: struct.evp_pkey_st */
            	2879, 16,
            	2887, 24,
            	2895, 32,
            	3160, 48,
            1, 8, 1, /* 2879: pointer.struct.evp_pkey_asn1_method_st */
            	2884, 0,
            0, 0, 0, /* 2884: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 2887: pointer.struct.engine_st */
            	2892, 0,
            0, 0, 0, /* 2892: struct.engine_st */
            0, 8, 5, /* 2895: union.unknown */
            	61, 0,
            	2908, 0,
            	3037, 0,
            	3118, 0,
            	3155, 0,
            1, 8, 1, /* 2908: pointer.struct.rsa_st */
            	2913, 0,
            0, 168, 17, /* 2913: struct.rsa_st */
            	2950, 16,
            	2887, 24,
            	3005, 32,
            	3005, 40,
            	3005, 48,
            	3005, 56,
            	3005, 64,
            	3005, 72,
            	3005, 80,
            	3005, 88,
            	2092, 96,
            	3015, 120,
            	3015, 128,
            	3015, 136,
            	61, 144,
            	3029, 152,
            	3029, 160,
            1, 8, 1, /* 2950: pointer.struct.rsa_meth_st */
            	2955, 0,
            0, 112, 13, /* 2955: struct.rsa_meth_st */
            	10, 0,
            	2984, 8,
            	2984, 16,
            	2984, 24,
            	2984, 32,
            	2987, 40,
            	2990, 48,
            	2993, 56,
            	2993, 64,
            	61, 80,
            	2996, 88,
            	2999, 96,
            	3002, 104,
            8884097, 8, 0, /* 2984: pointer.func */
            8884097, 8, 0, /* 2987: pointer.func */
            8884097, 8, 0, /* 2990: pointer.func */
            8884097, 8, 0, /* 2993: pointer.func */
            8884097, 8, 0, /* 2996: pointer.func */
            8884097, 8, 0, /* 2999: pointer.func */
            8884097, 8, 0, /* 3002: pointer.func */
            1, 8, 1, /* 3005: pointer.struct.bignum_st */
            	3010, 0,
            0, 24, 1, /* 3010: struct.bignum_st */
            	76, 0,
            1, 8, 1, /* 3015: pointer.struct.bn_mont_ctx_st */
            	3020, 0,
            0, 96, 3, /* 3020: struct.bn_mont_ctx_st */
            	3010, 8,
            	3010, 32,
            	3010, 56,
            1, 8, 1, /* 3029: pointer.struct.bn_blinding_st */
            	3034, 0,
            0, 0, 0, /* 3034: struct.bn_blinding_st */
            1, 8, 1, /* 3037: pointer.struct.dsa_st */
            	3042, 0,
            0, 136, 11, /* 3042: struct.dsa_st */
            	3005, 24,
            	3005, 32,
            	3005, 40,
            	3005, 48,
            	3005, 56,
            	3005, 64,
            	3005, 72,
            	3015, 88,
            	2092, 104,
            	3067, 120,
            	2887, 128,
            1, 8, 1, /* 3067: pointer.struct.dsa_method */
            	3072, 0,
            0, 96, 11, /* 3072: struct.dsa_method */
            	10, 0,
            	3097, 8,
            	3100, 16,
            	3103, 24,
            	3106, 32,
            	3109, 40,
            	3112, 48,
            	3112, 56,
            	61, 72,
            	3115, 80,
            	3112, 88,
            8884097, 8, 0, /* 3097: pointer.func */
            8884097, 8, 0, /* 3100: pointer.func */
            8884097, 8, 0, /* 3103: pointer.func */
            8884097, 8, 0, /* 3106: pointer.func */
            8884097, 8, 0, /* 3109: pointer.func */
            8884097, 8, 0, /* 3112: pointer.func */
            8884097, 8, 0, /* 3115: pointer.func */
            1, 8, 1, /* 3118: pointer.struct.dh_st */
            	3123, 0,
            0, 144, 12, /* 3123: struct.dh_st */
            	3005, 8,
            	3005, 16,
            	3005, 32,
            	3005, 40,
            	3015, 56,
            	3005, 64,
            	3005, 72,
            	225, 80,
            	3005, 96,
            	2092, 112,
            	3150, 128,
            	2887, 136,
            1, 8, 1, /* 3150: pointer.struct.dh_method */
            	2271, 0,
            1, 8, 1, /* 3155: pointer.struct.ec_key_st */
            	2692, 0,
            1, 8, 1, /* 3160: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3165, 0,
            0, 32, 2, /* 3165: struct.stack_st_fake_X509_ATTRIBUTE */
            	3172, 8,
            	472, 24,
            8884099, 8, 2, /* 3172: pointer_to_array_of_pointers_to_stack */
            	3179, 0,
            	469, 20,
            0, 8, 1, /* 3179: pointer.X509_ATTRIBUTE */
            	888, 0,
            1, 8, 1, /* 3184: pointer.struct.stack_st_DIST_POINT */
            	3189, 0,
            0, 32, 2, /* 3189: struct.stack_st_fake_DIST_POINT */
            	3196, 8,
            	472, 24,
            8884099, 8, 2, /* 3196: pointer_to_array_of_pointers_to_stack */
            	3203, 0,
            	469, 20,
            0, 8, 1, /* 3203: pointer.DIST_POINT */
            	1348, 0,
            1, 8, 1, /* 3208: pointer.struct.stack_st_GENERAL_NAME */
            	3213, 0,
            0, 32, 2, /* 3213: struct.stack_st_fake_GENERAL_NAME */
            	3220, 8,
            	472, 24,
            8884099, 8, 2, /* 3220: pointer_to_array_of_pointers_to_stack */
            	3227, 0,
            	469, 20,
            0, 8, 1, /* 3227: pointer.GENERAL_NAME */
            	1405, 0,
            1, 8, 1, /* 3232: pointer.struct.NAME_CONSTRAINTS_st */
            	3237, 0,
            0, 0, 0, /* 3237: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3240: pointer.struct.x509_cert_aux_st */
            	3245, 0,
            0, 40, 5, /* 3245: struct.x509_cert_aux_st */
            	3258, 0,
            	3258, 8,
            	2486, 16,
            	2436, 24,
            	3282, 32,
            1, 8, 1, /* 3258: pointer.struct.stack_st_ASN1_OBJECT */
            	3263, 0,
            0, 32, 2, /* 3263: struct.stack_st_fake_ASN1_OBJECT */
            	3270, 8,
            	472, 24,
            8884099, 8, 2, /* 3270: pointer_to_array_of_pointers_to_stack */
            	3277, 0,
            	469, 20,
            0, 8, 1, /* 3277: pointer.ASN1_OBJECT */
            	1807, 0,
            1, 8, 1, /* 3282: pointer.struct.stack_st_X509_ALGOR */
            	3287, 0,
            0, 32, 2, /* 3287: struct.stack_st_fake_X509_ALGOR */
            	3294, 8,
            	472, 24,
            8884099, 8, 2, /* 3294: pointer_to_array_of_pointers_to_stack */
            	3301, 0,
            	469, 20,
            0, 8, 1, /* 3301: pointer.X509_ALGOR */
            	1845, 0,
            1, 8, 1, /* 3306: pointer.struct.X509_crl_st */
            	3311, 0,
            0, 120, 10, /* 3311: struct.X509_crl_st */
            	2308, 0,
            	2342, 8,
            	2431, 16,
            	2695, 32,
            	3334, 40,
            	2332, 56,
            	2332, 64,
            	3342, 96,
            	3383, 104,
            	49, 112,
            1, 8, 1, /* 3334: pointer.struct.ISSUING_DIST_POINT_st */
            	3339, 0,
            0, 0, 0, /* 3339: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 3342: pointer.struct.stack_st_GENERAL_NAMES */
            	3347, 0,
            0, 32, 2, /* 3347: struct.stack_st_fake_GENERAL_NAMES */
            	3354, 8,
            	472, 24,
            8884099, 8, 2, /* 3354: pointer_to_array_of_pointers_to_stack */
            	3361, 0,
            	469, 20,
            0, 8, 1, /* 3361: pointer.GENERAL_NAMES */
            	3366, 0,
            0, 0, 1, /* 3366: GENERAL_NAMES */
            	3371, 0,
            0, 32, 1, /* 3371: struct.stack_st_GENERAL_NAME */
            	3376, 0,
            0, 32, 2, /* 3376: struct.stack_st */
            	680, 8,
            	472, 24,
            1, 8, 1, /* 3383: pointer.struct.x509_crl_method_st */
            	3388, 0,
            0, 0, 0, /* 3388: struct.x509_crl_method_st */
            8884097, 8, 0, /* 3391: pointer.func */
            8884097, 8, 0, /* 3394: pointer.func */
            0, 104, 11, /* 3397: struct.x509_cinf_st */
            	3422, 0,
            	3422, 8,
            	3432, 16,
            	3589, 24,
            	3594, 32,
            	3589, 40,
            	3611, 48,
            	3521, 56,
            	3521, 64,
            	3845, 72,
            	3869, 80,
            1, 8, 1, /* 3422: pointer.struct.asn1_string_st */
            	3427, 0,
            0, 24, 1, /* 3427: struct.asn1_string_st */
            	225, 8,
            1, 8, 1, /* 3432: pointer.struct.X509_algor_st */
            	3437, 0,
            0, 16, 2, /* 3437: struct.X509_algor_st */
            	3444, 0,
            	3458, 8,
            1, 8, 1, /* 3444: pointer.struct.asn1_object_st */
            	3449, 0,
            0, 40, 3, /* 3449: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	259, 24,
            1, 8, 1, /* 3458: pointer.struct.asn1_type_st */
            	3463, 0,
            0, 16, 1, /* 3463: struct.asn1_type_st */
            	3468, 8,
            0, 8, 20, /* 3468: union.unknown */
            	61, 0,
            	3511, 0,
            	3444, 0,
            	3422, 0,
            	3516, 0,
            	3521, 0,
            	3526, 0,
            	3531, 0,
            	3536, 0,
            	3541, 0,
            	3546, 0,
            	3551, 0,
            	3556, 0,
            	3561, 0,
            	3566, 0,
            	3571, 0,
            	3576, 0,
            	3511, 0,
            	3511, 0,
            	3581, 0,
            1, 8, 1, /* 3511: pointer.struct.asn1_string_st */
            	3427, 0,
            1, 8, 1, /* 3516: pointer.struct.asn1_string_st */
            	3427, 0,
            1, 8, 1, /* 3521: pointer.struct.asn1_string_st */
            	3427, 0,
            1, 8, 1, /* 3526: pointer.struct.asn1_string_st */
            	3427, 0,
            1, 8, 1, /* 3531: pointer.struct.asn1_string_st */
            	3427, 0,
            1, 8, 1, /* 3536: pointer.struct.asn1_string_st */
            	3427, 0,
            1, 8, 1, /* 3541: pointer.struct.asn1_string_st */
            	3427, 0,
            1, 8, 1, /* 3546: pointer.struct.asn1_string_st */
            	3427, 0,
            1, 8, 1, /* 3551: pointer.struct.asn1_string_st */
            	3427, 0,
            1, 8, 1, /* 3556: pointer.struct.asn1_string_st */
            	3427, 0,
            1, 8, 1, /* 3561: pointer.struct.asn1_string_st */
            	3427, 0,
            1, 8, 1, /* 3566: pointer.struct.asn1_string_st */
            	3427, 0,
            1, 8, 1, /* 3571: pointer.struct.asn1_string_st */
            	3427, 0,
            1, 8, 1, /* 3576: pointer.struct.asn1_string_st */
            	3427, 0,
            1, 8, 1, /* 3581: pointer.struct.ASN1_VALUE_st */
            	3586, 0,
            0, 0, 0, /* 3586: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3589: pointer.struct.X509_name_st */
            	1951, 0,
            1, 8, 1, /* 3594: pointer.struct.X509_val_st */
            	3599, 0,
            0, 16, 2, /* 3599: struct.X509_val_st */
            	3606, 0,
            	3606, 8,
            1, 8, 1, /* 3606: pointer.struct.asn1_string_st */
            	3427, 0,
            1, 8, 1, /* 3611: pointer.struct.X509_pubkey_st */
            	3616, 0,
            0, 24, 3, /* 3616: struct.X509_pubkey_st */
            	3432, 0,
            	3521, 8,
            	3625, 16,
            1, 8, 1, /* 3625: pointer.struct.evp_pkey_st */
            	3630, 0,
            0, 56, 4, /* 3630: struct.evp_pkey_st */
            	3641, 16,
            	2209, 24,
            	3649, 32,
            	3821, 48,
            1, 8, 1, /* 3641: pointer.struct.evp_pkey_asn1_method_st */
            	3646, 0,
            0, 0, 0, /* 3646: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 3649: union.unknown */
            	61, 0,
            	3662, 0,
            	3667, 0,
            	3745, 0,
            	3813, 0,
            1, 8, 1, /* 3662: pointer.struct.rsa_st */
            	2120, 0,
            1, 8, 1, /* 3667: pointer.struct.dsa_st */
            	3672, 0,
            0, 136, 11, /* 3672: struct.dsa_st */
            	2217, 24,
            	2217, 32,
            	2217, 40,
            	2217, 48,
            	2217, 56,
            	2217, 64,
            	2217, 72,
            	2249, 88,
            	2227, 104,
            	3697, 120,
            	2209, 128,
            1, 8, 1, /* 3697: pointer.struct.dsa_method */
            	3702, 0,
            0, 96, 11, /* 3702: struct.dsa_method */
            	10, 0,
            	3727, 8,
            	3730, 16,
            	3733, 24,
            	3391, 32,
            	3736, 40,
            	3739, 48,
            	3739, 56,
            	61, 72,
            	3742, 80,
            	3739, 88,
            8884097, 8, 0, /* 3727: pointer.func */
            8884097, 8, 0, /* 3730: pointer.func */
            8884097, 8, 0, /* 3733: pointer.func */
            8884097, 8, 0, /* 3736: pointer.func */
            8884097, 8, 0, /* 3739: pointer.func */
            8884097, 8, 0, /* 3742: pointer.func */
            1, 8, 1, /* 3745: pointer.struct.dh_st */
            	3750, 0,
            0, 144, 12, /* 3750: struct.dh_st */
            	2217, 8,
            	2217, 16,
            	2217, 32,
            	2217, 40,
            	2249, 56,
            	2217, 64,
            	2217, 72,
            	225, 80,
            	2217, 96,
            	2227, 112,
            	3777, 128,
            	2209, 136,
            1, 8, 1, /* 3777: pointer.struct.dh_method */
            	3782, 0,
            0, 72, 8, /* 3782: struct.dh_method */
            	10, 0,
            	3801, 8,
            	3804, 16,
            	3807, 24,
            	3801, 32,
            	3801, 40,
            	61, 56,
            	3810, 64,
            8884097, 8, 0, /* 3801: pointer.func */
            8884097, 8, 0, /* 3804: pointer.func */
            8884097, 8, 0, /* 3807: pointer.func */
            8884097, 8, 0, /* 3810: pointer.func */
            1, 8, 1, /* 3813: pointer.struct.ec_key_st */
            	3818, 0,
            0, 0, 0, /* 3818: struct.ec_key_st */
            1, 8, 1, /* 3821: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3826, 0,
            0, 32, 2, /* 3826: struct.stack_st_fake_X509_ATTRIBUTE */
            	3833, 8,
            	472, 24,
            8884099, 8, 2, /* 3833: pointer_to_array_of_pointers_to_stack */
            	3840, 0,
            	469, 20,
            0, 8, 1, /* 3840: pointer.X509_ATTRIBUTE */
            	888, 0,
            1, 8, 1, /* 3845: pointer.struct.stack_st_X509_EXTENSION */
            	3850, 0,
            0, 32, 2, /* 3850: struct.stack_st_fake_X509_EXTENSION */
            	3857, 8,
            	472, 24,
            8884099, 8, 2, /* 3857: pointer_to_array_of_pointers_to_stack */
            	3864, 0,
            	469, 20,
            0, 8, 1, /* 3864: pointer.X509_EXTENSION */
            	1267, 0,
            0, 24, 1, /* 3869: struct.ASN1_ENCODING_st */
            	225, 0,
            8884097, 8, 0, /* 3874: pointer.func */
            0, 0, 0, /* 3877: struct.X509_POLICY_CACHE_st */
            0, 112, 11, /* 3880: struct.ssl3_enc_method */
            	3874, 0,
            	3905, 8,
            	3908, 16,
            	3911, 24,
            	3874, 32,
            	3914, 40,
            	3917, 56,
            	10, 64,
            	10, 80,
            	3920, 96,
            	3923, 104,
            8884097, 8, 0, /* 3905: pointer.func */
            8884097, 8, 0, /* 3908: pointer.func */
            8884097, 8, 0, /* 3911: pointer.func */
            8884097, 8, 0, /* 3914: pointer.func */
            8884097, 8, 0, /* 3917: pointer.func */
            8884097, 8, 0, /* 3920: pointer.func */
            8884097, 8, 0, /* 3923: pointer.func */
            0, 0, 0, /* 3926: struct.NAME_CONSTRAINTS_st */
            8884097, 8, 0, /* 3929: pointer.func */
            8884097, 8, 0, /* 3932: pointer.func */
            0, 0, 1, /* 3935: SSL_CIPHER */
            	3940, 0,
            0, 88, 1, /* 3940: struct.ssl_cipher_st */
            	10, 8,
            8884097, 8, 0, /* 3945: pointer.func */
            8884097, 8, 0, /* 3948: pointer.func */
            8884097, 8, 0, /* 3951: pointer.func */
            0, 144, 15, /* 3954: struct.x509_store_st */
            	2730, 8,
            	3987, 16,
            	4184, 24,
            	4196, 32,
            	4199, 40,
            	4202, 48,
            	4205, 56,
            	4196, 64,
            	4208, 72,
            	4211, 80,
            	4214, 88,
            	3394, 96,
            	4217, 104,
            	4196, 112,
            	658, 120,
            1, 8, 1, /* 3987: pointer.struct.stack_st_X509_LOOKUP */
            	3992, 0,
            0, 32, 2, /* 3992: struct.stack_st_fake_X509_LOOKUP */
            	3999, 8,
            	472, 24,
            8884099, 8, 2, /* 3999: pointer_to_array_of_pointers_to_stack */
            	4006, 0,
            	469, 20,
            0, 8, 1, /* 4006: pointer.X509_LOOKUP */
            	4011, 0,
            0, 0, 1, /* 4011: X509_LOOKUP */
            	4016, 0,
            0, 32, 3, /* 4016: struct.x509_lookup_st */
            	4025, 8,
            	61, 16,
            	4068, 24,
            1, 8, 1, /* 4025: pointer.struct.x509_lookup_method_st */
            	4030, 0,
            0, 80, 10, /* 4030: struct.x509_lookup_method_st */
            	10, 0,
            	4053, 8,
            	2724, 16,
            	4053, 24,
            	4053, 32,
            	4056, 40,
            	4059, 48,
            	3945, 56,
            	4062, 64,
            	4065, 72,
            8884097, 8, 0, /* 4053: pointer.func */
            8884097, 8, 0, /* 4056: pointer.func */
            8884097, 8, 0, /* 4059: pointer.func */
            8884097, 8, 0, /* 4062: pointer.func */
            8884097, 8, 0, /* 4065: pointer.func */
            1, 8, 1, /* 4068: pointer.struct.x509_store_st */
            	4073, 0,
            0, 144, 15, /* 4073: struct.x509_store_st */
            	4106, 8,
            	4130, 16,
            	4154, 24,
            	4166, 32,
            	4169, 40,
            	4172, 48,
            	2305, 56,
            	4166, 64,
            	4175, 72,
            	4178, 80,
            	4181, 88,
            	2114, 96,
            	3951, 104,
            	4166, 112,
            	2092, 120,
            1, 8, 1, /* 4106: pointer.struct.stack_st_X509_OBJECT */
            	4111, 0,
            0, 32, 2, /* 4111: struct.stack_st_fake_X509_OBJECT */
            	4118, 8,
            	472, 24,
            8884099, 8, 2, /* 4118: pointer_to_array_of_pointers_to_stack */
            	4125, 0,
            	469, 20,
            0, 8, 1, /* 4125: pointer.X509_OBJECT */
            	2754, 0,
            1, 8, 1, /* 4130: pointer.struct.stack_st_X509_LOOKUP */
            	4135, 0,
            0, 32, 2, /* 4135: struct.stack_st_fake_X509_LOOKUP */
            	4142, 8,
            	472, 24,
            8884099, 8, 2, /* 4142: pointer_to_array_of_pointers_to_stack */
            	4149, 0,
            	469, 20,
            0, 8, 1, /* 4149: pointer.X509_LOOKUP */
            	4011, 0,
            1, 8, 1, /* 4154: pointer.struct.X509_VERIFY_PARAM_st */
            	4159, 0,
            0, 56, 2, /* 4159: struct.X509_VERIFY_PARAM_st */
            	61, 0,
            	3258, 48,
            8884097, 8, 0, /* 4166: pointer.func */
            8884097, 8, 0, /* 4169: pointer.func */
            8884097, 8, 0, /* 4172: pointer.func */
            8884097, 8, 0, /* 4175: pointer.func */
            8884097, 8, 0, /* 4178: pointer.func */
            8884097, 8, 0, /* 4181: pointer.func */
            1, 8, 1, /* 4184: pointer.struct.X509_VERIFY_PARAM_st */
            	4189, 0,
            0, 56, 2, /* 4189: struct.X509_VERIFY_PARAM_st */
            	61, 0,
            	1783, 48,
            8884097, 8, 0, /* 4196: pointer.func */
            8884097, 8, 0, /* 4199: pointer.func */
            8884097, 8, 0, /* 4202: pointer.func */
            8884097, 8, 0, /* 4205: pointer.func */
            8884097, 8, 0, /* 4208: pointer.func */
            8884097, 8, 0, /* 4211: pointer.func */
            8884097, 8, 0, /* 4214: pointer.func */
            8884097, 8, 0, /* 4217: pointer.func */
            8884097, 8, 0, /* 4220: pointer.func */
            8884097, 8, 0, /* 4223: pointer.func */
            1, 8, 1, /* 4226: pointer.struct.ssl3_enc_method */
            	3880, 0,
            8884097, 8, 0, /* 4231: pointer.func */
            0, 736, 50, /* 4234: struct.ssl_ctx_st */
            	4337, 0,
            	4434, 8,
            	4434, 16,
            	4458, 24,
            	4463, 32,
            	4499, 48,
            	4499, 56,
            	2079, 80,
            	2076, 88,
            	4746, 96,
            	2073, 152,
            	49, 160,
            	4749, 168,
            	49, 176,
            	2070, 184,
            	4752, 192,
            	2067, 200,
            	658, 208,
            	1862, 224,
            	1862, 232,
            	1862, 240,
            	4553, 248,
            	2043, 256,
            	1994, 264,
            	1922, 272,
            	2676, 304,
            	3929, 320,
            	49, 328,
            	4199, 376,
            	4755, 384,
            	4184, 392,
            	540, 408,
            	52, 416,
            	49, 424,
            	4223, 480,
            	55, 488,
            	49, 496,
            	110, 504,
            	49, 512,
            	61, 520,
            	107, 528,
            	4758, 536,
            	97, 552,
            	97, 560,
            	18, 568,
            	84, 696,
            	49, 704,
            	15, 712,
            	49, 720,
            	2700, 728,
            1, 8, 1, /* 4337: pointer.struct.ssl_method_st */
            	4342, 0,
            0, 232, 28, /* 4342: struct.ssl_method_st */
            	3908, 8,
            	4401, 16,
            	4401, 24,
            	3908, 32,
            	3908, 40,
            	4404, 48,
            	4404, 56,
            	4407, 64,
            	3908, 72,
            	3908, 80,
            	3908, 88,
            	2727, 96,
            	3932, 104,
            	4231, 112,
            	3908, 120,
            	4410, 128,
            	2302, 136,
            	4413, 144,
            	4220, 152,
            	4416, 160,
            	4419, 168,
            	4422, 176,
            	4425, 184,
            	2023, 192,
            	4226, 200,
            	4419, 208,
            	4428, 216,
            	4431, 224,
            8884097, 8, 0, /* 4401: pointer.func */
            8884097, 8, 0, /* 4404: pointer.func */
            8884097, 8, 0, /* 4407: pointer.func */
            8884097, 8, 0, /* 4410: pointer.func */
            8884097, 8, 0, /* 4413: pointer.func */
            8884097, 8, 0, /* 4416: pointer.func */
            8884097, 8, 0, /* 4419: pointer.func */
            8884097, 8, 0, /* 4422: pointer.func */
            8884097, 8, 0, /* 4425: pointer.func */
            8884097, 8, 0, /* 4428: pointer.func */
            8884097, 8, 0, /* 4431: pointer.func */
            1, 8, 1, /* 4434: pointer.struct.stack_st_SSL_CIPHER */
            	4439, 0,
            0, 32, 2, /* 4439: struct.stack_st_fake_SSL_CIPHER */
            	4446, 8,
            	472, 24,
            8884099, 8, 2, /* 4446: pointer_to_array_of_pointers_to_stack */
            	4453, 0,
            	469, 20,
            0, 8, 1, /* 4453: pointer.SSL_CIPHER */
            	3935, 0,
            1, 8, 1, /* 4458: pointer.struct.x509_store_st */
            	3954, 0,
            1, 8, 1, /* 4463: pointer.struct.lhash_st */
            	4468, 0,
            0, 176, 3, /* 4468: struct.lhash_st */
            	4477, 0,
            	472, 8,
            	3948, 16,
            1, 8, 1, /* 4477: pointer.pointer.struct.lhash_node_st */
            	4482, 0,
            1, 8, 1, /* 4482: pointer.struct.lhash_node_st */
            	4487, 0,
            0, 24, 2, /* 4487: struct.lhash_node_st */
            	49, 0,
            	4494, 8,
            1, 8, 1, /* 4494: pointer.struct.lhash_node_st */
            	4487, 0,
            1, 8, 1, /* 4499: pointer.struct.ssl_session_st */
            	4504, 0,
            0, 352, 14, /* 4504: struct.ssl_session_st */
            	61, 144,
            	61, 152,
            	4535, 168,
            	153, 176,
            	2087, 224,
            	4434, 240,
            	658, 248,
            	4499, 264,
            	4499, 272,
            	61, 280,
            	225, 296,
            	225, 312,
            	225, 320,
            	61, 344,
            1, 8, 1, /* 4535: pointer.struct.sess_cert_st */
            	4540, 0,
            0, 248, 5, /* 4540: struct.sess_cert_st */
            	4553, 0,
            	139, 16,
            	1907, 216,
            	1912, 224,
            	1917, 232,
            1, 8, 1, /* 4553: pointer.struct.stack_st_X509 */
            	4558, 0,
            0, 32, 2, /* 4558: struct.stack_st_fake_X509 */
            	4565, 8,
            	472, 24,
            8884099, 8, 2, /* 4565: pointer_to_array_of_pointers_to_stack */
            	4572, 0,
            	469, 20,
            0, 8, 1, /* 4572: pointer.X509 */
            	4577, 0,
            0, 0, 1, /* 4577: X509 */
            	4582, 0,
            0, 184, 12, /* 4582: struct.x509_st */
            	4609, 0,
            	3432, 8,
            	3521, 16,
            	61, 32,
            	2227, 40,
            	3526, 104,
            	4614, 112,
            	4622, 120,
            	4627, 128,
            	4651, 136,
            	4675, 144,
            	4680, 176,
            1, 8, 1, /* 4609: pointer.struct.x509_cinf_st */
            	3397, 0,
            1, 8, 1, /* 4614: pointer.struct.AUTHORITY_KEYID_st */
            	4619, 0,
            0, 0, 0, /* 4619: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4622: pointer.struct.X509_POLICY_CACHE_st */
            	3877, 0,
            1, 8, 1, /* 4627: pointer.struct.stack_st_DIST_POINT */
            	4632, 0,
            0, 32, 2, /* 4632: struct.stack_st_fake_DIST_POINT */
            	4639, 8,
            	472, 24,
            8884099, 8, 2, /* 4639: pointer_to_array_of_pointers_to_stack */
            	4646, 0,
            	469, 20,
            0, 8, 1, /* 4646: pointer.DIST_POINT */
            	1348, 0,
            1, 8, 1, /* 4651: pointer.struct.stack_st_GENERAL_NAME */
            	4656, 0,
            0, 32, 2, /* 4656: struct.stack_st_fake_GENERAL_NAME */
            	4663, 8,
            	472, 24,
            8884099, 8, 2, /* 4663: pointer_to_array_of_pointers_to_stack */
            	4670, 0,
            	469, 20,
            0, 8, 1, /* 4670: pointer.GENERAL_NAME */
            	1405, 0,
            1, 8, 1, /* 4675: pointer.struct.NAME_CONSTRAINTS_st */
            	3926, 0,
            1, 8, 1, /* 4680: pointer.struct.x509_cert_aux_st */
            	4685, 0,
            0, 40, 5, /* 4685: struct.x509_cert_aux_st */
            	4698, 0,
            	4698, 8,
            	3576, 16,
            	3526, 24,
            	4722, 32,
            1, 8, 1, /* 4698: pointer.struct.stack_st_ASN1_OBJECT */
            	4703, 0,
            0, 32, 2, /* 4703: struct.stack_st_fake_ASN1_OBJECT */
            	4710, 8,
            	472, 24,
            8884099, 8, 2, /* 4710: pointer_to_array_of_pointers_to_stack */
            	4717, 0,
            	469, 20,
            0, 8, 1, /* 4717: pointer.ASN1_OBJECT */
            	1807, 0,
            1, 8, 1, /* 4722: pointer.struct.stack_st_X509_ALGOR */
            	4727, 0,
            0, 32, 2, /* 4727: struct.stack_st_fake_X509_ALGOR */
            	4734, 8,
            	472, 24,
            8884099, 8, 2, /* 4734: pointer_to_array_of_pointers_to_stack */
            	4741, 0,
            	469, 20,
            0, 8, 1, /* 4741: pointer.X509_ALGOR */
            	1845, 0,
            8884097, 8, 0, /* 4746: pointer.func */
            8884097, 8, 0, /* 4749: pointer.func */
            8884097, 8, 0, /* 4752: pointer.func */
            8884097, 8, 0, /* 4755: pointer.func */
            8884097, 8, 0, /* 4758: pointer.func */
            1, 8, 1, /* 4761: pointer.struct.ssl_ctx_st */
            	4234, 0,
            0, 1, 0, /* 4766: char */
        },
        .arg_entity_index = { 4761, 2079, },
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

