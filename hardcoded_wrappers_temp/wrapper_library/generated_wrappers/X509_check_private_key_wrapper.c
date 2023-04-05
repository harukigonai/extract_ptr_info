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
            1, 8, 1, /* 0: pointer.struct.asn1_string_st */
            	5, 0,
            0, 24, 1, /* 5: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 10: pointer.unsigned char */
            	15, 0,
            0, 1, 0, /* 15: unsigned char */
            1, 8, 1, /* 18: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 23: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 28: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 33: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 38: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 43: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 48: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 53: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 58: pointer.struct.asn1_string_st */
            	5, 0,
            0, 0, 1, /* 63: X509_ALGOR */
            	68, 0,
            0, 16, 2, /* 68: struct.X509_algor_st */
            	75, 0,
            	99, 8,
            1, 8, 1, /* 75: pointer.struct.asn1_object_st */
            	80, 0,
            0, 40, 3, /* 80: struct.asn1_object_st */
            	89, 0,
            	89, 8,
            	94, 24,
            1, 8, 1, /* 89: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 94: pointer.unsigned char */
            	15, 0,
            1, 8, 1, /* 99: pointer.struct.asn1_type_st */
            	104, 0,
            0, 16, 1, /* 104: struct.asn1_type_st */
            	109, 8,
            0, 8, 20, /* 109: union.unknown */
            	152, 0,
            	157, 0,
            	75, 0,
            	58, 0,
            	162, 0,
            	53, 0,
            	48, 0,
            	167, 0,
            	172, 0,
            	43, 0,
            	38, 0,
            	177, 0,
            	33, 0,
            	28, 0,
            	23, 0,
            	18, 0,
            	0, 0,
            	157, 0,
            	157, 0,
            	182, 0,
            1, 8, 1, /* 152: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 157: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 162: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 167: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 172: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 177: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 182: pointer.struct.ASN1_VALUE_st */
            	187, 0,
            0, 0, 0, /* 187: struct.ASN1_VALUE_st */
            1, 8, 1, /* 190: pointer.struct.stack_st_X509_ALGOR */
            	195, 0,
            0, 32, 2, /* 195: struct.stack_st_fake_X509_ALGOR */
            	202, 8,
            	217, 24,
            8884099, 8, 2, /* 202: pointer_to_array_of_pointers_to_stack */
            	209, 0,
            	214, 20,
            0, 8, 1, /* 209: pointer.X509_ALGOR */
            	63, 0,
            0, 4, 0, /* 214: int */
            8884097, 8, 0, /* 217: pointer.func */
            1, 8, 1, /* 220: pointer.struct.stack_st_GENERAL_SUBTREE */
            	225, 0,
            0, 32, 2, /* 225: struct.stack_st_fake_GENERAL_SUBTREE */
            	232, 8,
            	217, 24,
            8884099, 8, 2, /* 232: pointer_to_array_of_pointers_to_stack */
            	239, 0,
            	214, 20,
            0, 8, 1, /* 239: pointer.GENERAL_SUBTREE */
            	244, 0,
            0, 0, 1, /* 244: GENERAL_SUBTREE */
            	249, 0,
            0, 24, 3, /* 249: struct.GENERAL_SUBTREE_st */
            	258, 0,
            	390, 8,
            	390, 16,
            1, 8, 1, /* 258: pointer.struct.GENERAL_NAME_st */
            	263, 0,
            0, 16, 1, /* 263: struct.GENERAL_NAME_st */
            	268, 8,
            0, 8, 15, /* 268: union.unknown */
            	152, 0,
            	301, 0,
            	420, 0,
            	420, 0,
            	327, 0,
            	468, 0,
            	552, 0,
            	420, 0,
            	405, 0,
            	313, 0,
            	405, 0,
            	468, 0,
            	420, 0,
            	313, 0,
            	327, 0,
            1, 8, 1, /* 301: pointer.struct.otherName_st */
            	306, 0,
            0, 16, 2, /* 306: struct.otherName_st */
            	313, 0,
            	327, 8,
            1, 8, 1, /* 313: pointer.struct.asn1_object_st */
            	318, 0,
            0, 40, 3, /* 318: struct.asn1_object_st */
            	89, 0,
            	89, 8,
            	94, 24,
            1, 8, 1, /* 327: pointer.struct.asn1_type_st */
            	332, 0,
            0, 16, 1, /* 332: struct.asn1_type_st */
            	337, 8,
            0, 8, 20, /* 337: union.unknown */
            	152, 0,
            	380, 0,
            	313, 0,
            	390, 0,
            	395, 0,
            	400, 0,
            	405, 0,
            	410, 0,
            	415, 0,
            	420, 0,
            	425, 0,
            	430, 0,
            	435, 0,
            	440, 0,
            	445, 0,
            	450, 0,
            	455, 0,
            	380, 0,
            	380, 0,
            	460, 0,
            1, 8, 1, /* 380: pointer.struct.asn1_string_st */
            	385, 0,
            0, 24, 1, /* 385: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 390: pointer.struct.asn1_string_st */
            	385, 0,
            1, 8, 1, /* 395: pointer.struct.asn1_string_st */
            	385, 0,
            1, 8, 1, /* 400: pointer.struct.asn1_string_st */
            	385, 0,
            1, 8, 1, /* 405: pointer.struct.asn1_string_st */
            	385, 0,
            1, 8, 1, /* 410: pointer.struct.asn1_string_st */
            	385, 0,
            1, 8, 1, /* 415: pointer.struct.asn1_string_st */
            	385, 0,
            1, 8, 1, /* 420: pointer.struct.asn1_string_st */
            	385, 0,
            1, 8, 1, /* 425: pointer.struct.asn1_string_st */
            	385, 0,
            1, 8, 1, /* 430: pointer.struct.asn1_string_st */
            	385, 0,
            1, 8, 1, /* 435: pointer.struct.asn1_string_st */
            	385, 0,
            1, 8, 1, /* 440: pointer.struct.asn1_string_st */
            	385, 0,
            1, 8, 1, /* 445: pointer.struct.asn1_string_st */
            	385, 0,
            1, 8, 1, /* 450: pointer.struct.asn1_string_st */
            	385, 0,
            1, 8, 1, /* 455: pointer.struct.asn1_string_st */
            	385, 0,
            1, 8, 1, /* 460: pointer.struct.ASN1_VALUE_st */
            	465, 0,
            0, 0, 0, /* 465: struct.ASN1_VALUE_st */
            1, 8, 1, /* 468: pointer.struct.X509_name_st */
            	473, 0,
            0, 40, 3, /* 473: struct.X509_name_st */
            	482, 0,
            	542, 16,
            	10, 24,
            1, 8, 1, /* 482: pointer.struct.stack_st_X509_NAME_ENTRY */
            	487, 0,
            0, 32, 2, /* 487: struct.stack_st_fake_X509_NAME_ENTRY */
            	494, 8,
            	217, 24,
            8884099, 8, 2, /* 494: pointer_to_array_of_pointers_to_stack */
            	501, 0,
            	214, 20,
            0, 8, 1, /* 501: pointer.X509_NAME_ENTRY */
            	506, 0,
            0, 0, 1, /* 506: X509_NAME_ENTRY */
            	511, 0,
            0, 24, 2, /* 511: struct.X509_name_entry_st */
            	518, 0,
            	532, 8,
            1, 8, 1, /* 518: pointer.struct.asn1_object_st */
            	523, 0,
            0, 40, 3, /* 523: struct.asn1_object_st */
            	89, 0,
            	89, 8,
            	94, 24,
            1, 8, 1, /* 532: pointer.struct.asn1_string_st */
            	537, 0,
            0, 24, 1, /* 537: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 542: pointer.struct.buf_mem_st */
            	547, 0,
            0, 24, 1, /* 547: struct.buf_mem_st */
            	152, 8,
            1, 8, 1, /* 552: pointer.struct.EDIPartyName_st */
            	557, 0,
            0, 16, 2, /* 557: struct.EDIPartyName_st */
            	380, 0,
            	380, 8,
            1, 8, 1, /* 564: pointer.struct.NAME_CONSTRAINTS_st */
            	569, 0,
            0, 16, 2, /* 569: struct.NAME_CONSTRAINTS_st */
            	220, 0,
            	220, 8,
            1, 8, 1, /* 576: pointer.struct.stack_st_GENERAL_NAME */
            	581, 0,
            0, 32, 2, /* 581: struct.stack_st_fake_GENERAL_NAME */
            	588, 8,
            	217, 24,
            8884099, 8, 2, /* 588: pointer_to_array_of_pointers_to_stack */
            	595, 0,
            	214, 20,
            0, 8, 1, /* 595: pointer.GENERAL_NAME */
            	600, 0,
            0, 0, 1, /* 600: GENERAL_NAME */
            	263, 0,
            0, 24, 1, /* 605: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 610: pointer.struct.asn1_string_st */
            	605, 0,
            0, 40, 3, /* 615: struct.X509_name_st */
            	624, 0,
            	648, 16,
            	10, 24,
            1, 8, 1, /* 624: pointer.struct.stack_st_X509_NAME_ENTRY */
            	629, 0,
            0, 32, 2, /* 629: struct.stack_st_fake_X509_NAME_ENTRY */
            	636, 8,
            	217, 24,
            8884099, 8, 2, /* 636: pointer_to_array_of_pointers_to_stack */
            	643, 0,
            	214, 20,
            0, 8, 1, /* 643: pointer.X509_NAME_ENTRY */
            	506, 0,
            1, 8, 1, /* 648: pointer.struct.buf_mem_st */
            	653, 0,
            0, 24, 1, /* 653: struct.buf_mem_st */
            	152, 8,
            1, 8, 1, /* 658: pointer.struct.X509_name_st */
            	615, 0,
            1, 8, 1, /* 663: pointer.struct.stack_st_GENERAL_NAME */
            	668, 0,
            0, 32, 2, /* 668: struct.stack_st_fake_GENERAL_NAME */
            	675, 8,
            	217, 24,
            8884099, 8, 2, /* 675: pointer_to_array_of_pointers_to_stack */
            	682, 0,
            	214, 20,
            0, 8, 1, /* 682: pointer.GENERAL_NAME */
            	600, 0,
            0, 8, 2, /* 687: union.unknown */
            	663, 0,
            	624, 0,
            0, 24, 2, /* 694: struct.DIST_POINT_NAME_st */
            	687, 8,
            	658, 16,
            1, 8, 1, /* 701: pointer.struct.stack_st_DIST_POINT */
            	706, 0,
            0, 32, 2, /* 706: struct.stack_st_fake_DIST_POINT */
            	713, 8,
            	217, 24,
            8884099, 8, 2, /* 713: pointer_to_array_of_pointers_to_stack */
            	720, 0,
            	214, 20,
            0, 8, 1, /* 720: pointer.DIST_POINT */
            	725, 0,
            0, 0, 1, /* 725: DIST_POINT */
            	730, 0,
            0, 32, 3, /* 730: struct.DIST_POINT_st */
            	739, 0,
            	610, 8,
            	663, 16,
            1, 8, 1, /* 739: pointer.struct.DIST_POINT_NAME_st */
            	694, 0,
            0, 0, 0, /* 744: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 747: pointer.struct.AUTHORITY_KEYID_st */
            	752, 0,
            0, 24, 3, /* 752: struct.AUTHORITY_KEYID_st */
            	761, 0,
            	771, 8,
            	795, 16,
            1, 8, 1, /* 761: pointer.struct.asn1_string_st */
            	766, 0,
            0, 24, 1, /* 766: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 771: pointer.struct.stack_st_GENERAL_NAME */
            	776, 0,
            0, 32, 2, /* 776: struct.stack_st_fake_GENERAL_NAME */
            	783, 8,
            	217, 24,
            8884099, 8, 2, /* 783: pointer_to_array_of_pointers_to_stack */
            	790, 0,
            	214, 20,
            0, 8, 1, /* 790: pointer.GENERAL_NAME */
            	600, 0,
            1, 8, 1, /* 795: pointer.struct.asn1_string_st */
            	766, 0,
            0, 24, 1, /* 800: struct.asn1_string_st */
            	10, 8,
            0, 40, 3, /* 805: struct.asn1_object_st */
            	89, 0,
            	89, 8,
            	94, 24,
            0, 24, 2, /* 814: struct.X509_extension_st */
            	821, 0,
            	826, 16,
            1, 8, 1, /* 821: pointer.struct.asn1_object_st */
            	805, 0,
            1, 8, 1, /* 826: pointer.struct.asn1_string_st */
            	800, 0,
            0, 0, 1, /* 831: X509_EXTENSION */
            	814, 0,
            1, 8, 1, /* 836: pointer.struct.stack_st_X509_EXTENSION */
            	841, 0,
            0, 32, 2, /* 841: struct.stack_st_fake_X509_EXTENSION */
            	848, 8,
            	217, 24,
            8884099, 8, 2, /* 848: pointer_to_array_of_pointers_to_stack */
            	855, 0,
            	214, 20,
            0, 8, 1, /* 855: pointer.X509_EXTENSION */
            	831, 0,
            0, 0, 1, /* 860: ASN1_OBJECT */
            	865, 0,
            0, 40, 3, /* 865: struct.asn1_object_st */
            	89, 0,
            	89, 8,
            	94, 24,
            1, 8, 1, /* 874: pointer.struct.asn1_string_st */
            	879, 0,
            0, 24, 1, /* 879: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 884: pointer.struct.asn1_string_st */
            	879, 0,
            1, 8, 1, /* 889: pointer.struct.asn1_string_st */
            	879, 0,
            1, 8, 1, /* 894: pointer.struct.asn1_string_st */
            	879, 0,
            1, 8, 1, /* 899: pointer.struct.asn1_string_st */
            	879, 0,
            0, 24, 1, /* 904: struct.ASN1_ENCODING_st */
            	10, 0,
            1, 8, 1, /* 909: pointer.struct.asn1_string_st */
            	879, 0,
            1, 8, 1, /* 914: pointer.struct.asn1_string_st */
            	879, 0,
            1, 8, 1, /* 919: pointer.struct.asn1_string_st */
            	879, 0,
            1, 8, 1, /* 924: pointer.struct.asn1_string_st */
            	879, 0,
            1, 8, 1, /* 929: pointer.struct.asn1_string_st */
            	879, 0,
            1, 8, 1, /* 934: pointer.struct.asn1_string_st */
            	879, 0,
            0, 8, 20, /* 939: union.unknown */
            	152, 0,
            	934, 0,
            	982, 0,
            	929, 0,
            	924, 0,
            	919, 0,
            	914, 0,
            	996, 0,
            	1001, 0,
            	909, 0,
            	899, 0,
            	894, 0,
            	889, 0,
            	884, 0,
            	874, 0,
            	1006, 0,
            	1011, 0,
            	934, 0,
            	934, 0,
            	182, 0,
            1, 8, 1, /* 982: pointer.struct.asn1_object_st */
            	987, 0,
            0, 40, 3, /* 987: struct.asn1_object_st */
            	89, 0,
            	89, 8,
            	94, 24,
            1, 8, 1, /* 996: pointer.struct.asn1_string_st */
            	879, 0,
            1, 8, 1, /* 1001: pointer.struct.asn1_string_st */
            	879, 0,
            1, 8, 1, /* 1006: pointer.struct.asn1_string_st */
            	879, 0,
            1, 8, 1, /* 1011: pointer.struct.asn1_string_st */
            	879, 0,
            1, 8, 1, /* 1016: pointer.struct.asn1_type_st */
            	1021, 0,
            0, 16, 1, /* 1021: struct.asn1_type_st */
            	939, 8,
            1, 8, 1, /* 1026: pointer.struct.ASN1_VALUE_st */
            	1031, 0,
            0, 0, 0, /* 1031: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1034: pointer.struct.asn1_string_st */
            	1039, 0,
            0, 24, 1, /* 1039: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 1044: pointer.struct.asn1_string_st */
            	1039, 0,
            1, 8, 1, /* 1049: pointer.struct.asn1_string_st */
            	1039, 0,
            1, 8, 1, /* 1054: pointer.struct.asn1_string_st */
            	1039, 0,
            1, 8, 1, /* 1059: pointer.struct.evp_pkey_asn1_method_st */
            	1064, 0,
            0, 0, 0, /* 1064: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 1067: pointer.struct.asn1_string_st */
            	1039, 0,
            0, 24, 1, /* 1072: struct.buf_mem_st */
            	152, 8,
            1, 8, 1, /* 1077: pointer.struct.evp_pkey_st */
            	1082, 0,
            0, 56, 4, /* 1082: struct.evp_pkey_st */
            	1059, 16,
            	1093, 24,
            	1101, 32,
            	1435, 48,
            1, 8, 1, /* 1093: pointer.struct.engine_st */
            	1098, 0,
            0, 0, 0, /* 1098: struct.engine_st */
            0, 8, 5, /* 1101: union.unknown */
            	152, 0,
            	1114, 0,
            	1278, 0,
            	1359, 0,
            	1427, 0,
            1, 8, 1, /* 1114: pointer.struct.rsa_st */
            	1119, 0,
            0, 168, 17, /* 1119: struct.rsa_st */
            	1156, 16,
            	1093, 24,
            	1211, 32,
            	1211, 40,
            	1211, 48,
            	1211, 56,
            	1211, 64,
            	1211, 72,
            	1211, 80,
            	1211, 88,
            	1229, 96,
            	1256, 120,
            	1256, 128,
            	1256, 136,
            	152, 144,
            	1270, 152,
            	1270, 160,
            1, 8, 1, /* 1156: pointer.struct.rsa_meth_st */
            	1161, 0,
            0, 112, 13, /* 1161: struct.rsa_meth_st */
            	89, 0,
            	1190, 8,
            	1190, 16,
            	1190, 24,
            	1190, 32,
            	1193, 40,
            	1196, 48,
            	1199, 56,
            	1199, 64,
            	152, 80,
            	1202, 88,
            	1205, 96,
            	1208, 104,
            8884097, 8, 0, /* 1190: pointer.func */
            8884097, 8, 0, /* 1193: pointer.func */
            8884097, 8, 0, /* 1196: pointer.func */
            8884097, 8, 0, /* 1199: pointer.func */
            8884097, 8, 0, /* 1202: pointer.func */
            8884097, 8, 0, /* 1205: pointer.func */
            8884097, 8, 0, /* 1208: pointer.func */
            1, 8, 1, /* 1211: pointer.struct.bignum_st */
            	1216, 0,
            0, 24, 1, /* 1216: struct.bignum_st */
            	1221, 0,
            1, 8, 1, /* 1221: pointer.unsigned int */
            	1226, 0,
            0, 4, 0, /* 1226: unsigned int */
            0, 16, 1, /* 1229: struct.crypto_ex_data_st */
            	1234, 0,
            1, 8, 1, /* 1234: pointer.struct.stack_st_void */
            	1239, 0,
            0, 32, 1, /* 1239: struct.stack_st_void */
            	1244, 0,
            0, 32, 2, /* 1244: struct.stack_st */
            	1251, 8,
            	217, 24,
            1, 8, 1, /* 1251: pointer.pointer.char */
            	152, 0,
            1, 8, 1, /* 1256: pointer.struct.bn_mont_ctx_st */
            	1261, 0,
            0, 96, 3, /* 1261: struct.bn_mont_ctx_st */
            	1216, 8,
            	1216, 32,
            	1216, 56,
            1, 8, 1, /* 1270: pointer.struct.bn_blinding_st */
            	1275, 0,
            0, 0, 0, /* 1275: struct.bn_blinding_st */
            1, 8, 1, /* 1278: pointer.struct.dsa_st */
            	1283, 0,
            0, 136, 11, /* 1283: struct.dsa_st */
            	1211, 24,
            	1211, 32,
            	1211, 40,
            	1211, 48,
            	1211, 56,
            	1211, 64,
            	1211, 72,
            	1256, 88,
            	1229, 104,
            	1308, 120,
            	1093, 128,
            1, 8, 1, /* 1308: pointer.struct.dsa_method */
            	1313, 0,
            0, 96, 11, /* 1313: struct.dsa_method */
            	89, 0,
            	1338, 8,
            	1341, 16,
            	1344, 24,
            	1347, 32,
            	1350, 40,
            	1353, 48,
            	1353, 56,
            	152, 72,
            	1356, 80,
            	1353, 88,
            8884097, 8, 0, /* 1338: pointer.func */
            8884097, 8, 0, /* 1341: pointer.func */
            8884097, 8, 0, /* 1344: pointer.func */
            8884097, 8, 0, /* 1347: pointer.func */
            8884097, 8, 0, /* 1350: pointer.func */
            8884097, 8, 0, /* 1353: pointer.func */
            8884097, 8, 0, /* 1356: pointer.func */
            1, 8, 1, /* 1359: pointer.struct.dh_st */
            	1364, 0,
            0, 144, 12, /* 1364: struct.dh_st */
            	1211, 8,
            	1211, 16,
            	1211, 32,
            	1211, 40,
            	1256, 56,
            	1211, 64,
            	1211, 72,
            	10, 80,
            	1211, 96,
            	1229, 112,
            	1391, 128,
            	1093, 136,
            1, 8, 1, /* 1391: pointer.struct.dh_method */
            	1396, 0,
            0, 72, 8, /* 1396: struct.dh_method */
            	89, 0,
            	1415, 8,
            	1418, 16,
            	1421, 24,
            	1415, 32,
            	1415, 40,
            	152, 56,
            	1424, 64,
            8884097, 8, 0, /* 1415: pointer.func */
            8884097, 8, 0, /* 1418: pointer.func */
            8884097, 8, 0, /* 1421: pointer.func */
            8884097, 8, 0, /* 1424: pointer.func */
            1, 8, 1, /* 1427: pointer.struct.ec_key_st */
            	1432, 0,
            0, 0, 0, /* 1432: struct.ec_key_st */
            1, 8, 1, /* 1435: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1440, 0,
            0, 32, 2, /* 1440: struct.stack_st_fake_X509_ATTRIBUTE */
            	1447, 8,
            	217, 24,
            8884099, 8, 2, /* 1447: pointer_to_array_of_pointers_to_stack */
            	1454, 0,
            	214, 20,
            0, 8, 1, /* 1454: pointer.X509_ATTRIBUTE */
            	1459, 0,
            0, 0, 1, /* 1459: X509_ATTRIBUTE */
            	1464, 0,
            0, 24, 2, /* 1464: struct.x509_attributes_st */
            	982, 0,
            	1471, 16,
            0, 8, 3, /* 1471: union.unknown */
            	152, 0,
            	1480, 0,
            	1016, 0,
            1, 8, 1, /* 1480: pointer.struct.stack_st_ASN1_TYPE */
            	1485, 0,
            0, 32, 2, /* 1485: struct.stack_st_fake_ASN1_TYPE */
            	1492, 8,
            	217, 24,
            8884099, 8, 2, /* 1492: pointer_to_array_of_pointers_to_stack */
            	1499, 0,
            	214, 20,
            0, 8, 1, /* 1499: pointer.ASN1_TYPE */
            	1504, 0,
            0, 0, 1, /* 1504: ASN1_TYPE */
            	1509, 0,
            0, 16, 1, /* 1509: struct.asn1_type_st */
            	1514, 8,
            0, 8, 20, /* 1514: union.unknown */
            	152, 0,
            	1557, 0,
            	1562, 0,
            	1567, 0,
            	1572, 0,
            	1577, 0,
            	1582, 0,
            	1587, 0,
            	1054, 0,
            	1592, 0,
            	1049, 0,
            	1597, 0,
            	1602, 0,
            	1067, 0,
            	1607, 0,
            	1044, 0,
            	1034, 0,
            	1557, 0,
            	1557, 0,
            	1026, 0,
            1, 8, 1, /* 1557: pointer.struct.asn1_string_st */
            	1039, 0,
            1, 8, 1, /* 1562: pointer.struct.asn1_object_st */
            	865, 0,
            1, 8, 1, /* 1567: pointer.struct.asn1_string_st */
            	1039, 0,
            1, 8, 1, /* 1572: pointer.struct.asn1_string_st */
            	1039, 0,
            1, 8, 1, /* 1577: pointer.struct.asn1_string_st */
            	1039, 0,
            1, 8, 1, /* 1582: pointer.struct.asn1_string_st */
            	1039, 0,
            1, 8, 1, /* 1587: pointer.struct.asn1_string_st */
            	1039, 0,
            1, 8, 1, /* 1592: pointer.struct.asn1_string_st */
            	1039, 0,
            1, 8, 1, /* 1597: pointer.struct.asn1_string_st */
            	1039, 0,
            1, 8, 1, /* 1602: pointer.struct.asn1_string_st */
            	1039, 0,
            1, 8, 1, /* 1607: pointer.struct.asn1_string_st */
            	1039, 0,
            1, 8, 1, /* 1612: pointer.struct.asn1_string_st */
            	766, 0,
            1, 8, 1, /* 1617: pointer.struct.x509_st */
            	1622, 0,
            0, 184, 12, /* 1622: struct.x509_st */
            	1649, 0,
            	1679, 8,
            	1768, 16,
            	152, 32,
            	1229, 40,
            	761, 104,
            	747, 112,
            	1892, 120,
            	701, 128,
            	576, 136,
            	564, 144,
            	1897, 176,
            1, 8, 1, /* 1649: pointer.struct.x509_cinf_st */
            	1654, 0,
            0, 104, 11, /* 1654: struct.x509_cinf_st */
            	795, 0,
            	795, 8,
            	1679, 16,
            	1818, 24,
            	1861, 32,
            	1818, 40,
            	1878, 48,
            	1768, 56,
            	1768, 64,
            	836, 72,
            	904, 80,
            1, 8, 1, /* 1679: pointer.struct.X509_algor_st */
            	1684, 0,
            0, 16, 2, /* 1684: struct.X509_algor_st */
            	1691, 0,
            	1705, 8,
            1, 8, 1, /* 1691: pointer.struct.asn1_object_st */
            	1696, 0,
            0, 40, 3, /* 1696: struct.asn1_object_st */
            	89, 0,
            	89, 8,
            	94, 24,
            1, 8, 1, /* 1705: pointer.struct.asn1_type_st */
            	1710, 0,
            0, 16, 1, /* 1710: struct.asn1_type_st */
            	1715, 8,
            0, 8, 20, /* 1715: union.unknown */
            	152, 0,
            	1758, 0,
            	1691, 0,
            	795, 0,
            	1763, 0,
            	1768, 0,
            	761, 0,
            	1773, 0,
            	1778, 0,
            	1783, 0,
            	1788, 0,
            	1793, 0,
            	1798, 0,
            	1803, 0,
            	1612, 0,
            	1808, 0,
            	1813, 0,
            	1758, 0,
            	1758, 0,
            	182, 0,
            1, 8, 1, /* 1758: pointer.struct.asn1_string_st */
            	766, 0,
            1, 8, 1, /* 1763: pointer.struct.asn1_string_st */
            	766, 0,
            1, 8, 1, /* 1768: pointer.struct.asn1_string_st */
            	766, 0,
            1, 8, 1, /* 1773: pointer.struct.asn1_string_st */
            	766, 0,
            1, 8, 1, /* 1778: pointer.struct.asn1_string_st */
            	766, 0,
            1, 8, 1, /* 1783: pointer.struct.asn1_string_st */
            	766, 0,
            1, 8, 1, /* 1788: pointer.struct.asn1_string_st */
            	766, 0,
            1, 8, 1, /* 1793: pointer.struct.asn1_string_st */
            	766, 0,
            1, 8, 1, /* 1798: pointer.struct.asn1_string_st */
            	766, 0,
            1, 8, 1, /* 1803: pointer.struct.asn1_string_st */
            	766, 0,
            1, 8, 1, /* 1808: pointer.struct.asn1_string_st */
            	766, 0,
            1, 8, 1, /* 1813: pointer.struct.asn1_string_st */
            	766, 0,
            1, 8, 1, /* 1818: pointer.struct.X509_name_st */
            	1823, 0,
            0, 40, 3, /* 1823: struct.X509_name_st */
            	1832, 0,
            	1856, 16,
            	10, 24,
            1, 8, 1, /* 1832: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1837, 0,
            0, 32, 2, /* 1837: struct.stack_st_fake_X509_NAME_ENTRY */
            	1844, 8,
            	217, 24,
            8884099, 8, 2, /* 1844: pointer_to_array_of_pointers_to_stack */
            	1851, 0,
            	214, 20,
            0, 8, 1, /* 1851: pointer.X509_NAME_ENTRY */
            	506, 0,
            1, 8, 1, /* 1856: pointer.struct.buf_mem_st */
            	1072, 0,
            1, 8, 1, /* 1861: pointer.struct.X509_val_st */
            	1866, 0,
            0, 16, 2, /* 1866: struct.X509_val_st */
            	1873, 0,
            	1873, 8,
            1, 8, 1, /* 1873: pointer.struct.asn1_string_st */
            	766, 0,
            1, 8, 1, /* 1878: pointer.struct.X509_pubkey_st */
            	1883, 0,
            0, 24, 3, /* 1883: struct.X509_pubkey_st */
            	1679, 0,
            	1768, 8,
            	1077, 16,
            1, 8, 1, /* 1892: pointer.struct.X509_POLICY_CACHE_st */
            	744, 0,
            1, 8, 1, /* 1897: pointer.struct.x509_cert_aux_st */
            	1902, 0,
            0, 40, 5, /* 1902: struct.x509_cert_aux_st */
            	1915, 0,
            	1915, 8,
            	1813, 16,
            	761, 24,
            	190, 32,
            1, 8, 1, /* 1915: pointer.struct.stack_st_ASN1_OBJECT */
            	1920, 0,
            0, 32, 2, /* 1920: struct.stack_st_fake_ASN1_OBJECT */
            	1927, 8,
            	217, 24,
            8884099, 8, 2, /* 1927: pointer_to_array_of_pointers_to_stack */
            	1934, 0,
            	214, 20,
            0, 8, 1, /* 1934: pointer.ASN1_OBJECT */
            	860, 0,
            0, 1, 0, /* 1939: char */
        },
        .arg_entity_index = { 1617, 1077, },
        .ret_entity_index = 214,
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

