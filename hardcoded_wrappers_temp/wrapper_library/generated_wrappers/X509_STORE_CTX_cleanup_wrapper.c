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

void bb_X509_STORE_CTX_cleanup(X509_STORE_CTX * arg_a);

void X509_STORE_CTX_cleanup(X509_STORE_CTX * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_STORE_CTX_cleanup called %lu\n", in_lib);
    if (!in_lib)
        bb_X509_STORE_CTX_cleanup(arg_a);
    else {
        void (*orig_X509_STORE_CTX_cleanup)(X509_STORE_CTX *);
        orig_X509_STORE_CTX_cleanup = dlsym(RTLD_NEXT, "X509_STORE_CTX_cleanup");
        orig_X509_STORE_CTX_cleanup(arg_a);
    }
}

void bb_X509_STORE_CTX_cleanup(X509_STORE_CTX * arg_a) 
{
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.struct.ISSUING_DIST_POINT_st */
            	5, 0,
            0, 32, 2, /* 5: struct.ISSUING_DIST_POINT_st */
            	12, 0,
            	438, 16,
            1, 8, 1, /* 12: pointer.struct.DIST_POINT_NAME_st */
            	17, 0,
            0, 24, 2, /* 17: struct.DIST_POINT_NAME_st */
            	24, 8,
            	414, 16,
            0, 8, 2, /* 24: union.unknown */
            	31, 0,
            	390, 0,
            1, 8, 1, /* 31: pointer.struct.stack_st_GENERAL_NAME */
            	36, 0,
            0, 32, 2, /* 36: struct.stack_st_fake_GENERAL_NAME */
            	43, 8,
            	365, 24,
            8884099, 8, 2, /* 43: pointer_to_array_of_pointers_to_stack */
            	50, 0,
            	362, 20,
            0, 8, 1, /* 50: pointer.GENERAL_NAME */
            	55, 0,
            0, 0, 1, /* 55: GENERAL_NAME */
            	60, 0,
            0, 16, 1, /* 60: struct.GENERAL_NAME_st */
            	65, 8,
            0, 8, 15, /* 65: union.unknown */
            	98, 0,
            	103, 0,
            	240, 0,
            	240, 0,
            	142, 0,
            	288, 0,
            	378, 0,
            	240, 0,
            	225, 0,
            	115, 0,
            	225, 0,
            	288, 0,
            	240, 0,
            	115, 0,
            	142, 0,
            1, 8, 1, /* 98: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 103: pointer.struct.otherName_st */
            	108, 0,
            0, 16, 2, /* 108: struct.otherName_st */
            	115, 0,
            	142, 8,
            1, 8, 1, /* 115: pointer.struct.asn1_object_st */
            	120, 0,
            0, 40, 3, /* 120: struct.asn1_object_st */
            	129, 0,
            	129, 8,
            	134, 24,
            1, 8, 1, /* 129: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 134: pointer.unsigned char */
            	139, 0,
            0, 1, 0, /* 139: unsigned char */
            1, 8, 1, /* 142: pointer.struct.asn1_type_st */
            	147, 0,
            0, 16, 1, /* 147: struct.asn1_type_st */
            	152, 8,
            0, 8, 20, /* 152: union.unknown */
            	98, 0,
            	195, 0,
            	115, 0,
            	210, 0,
            	215, 0,
            	220, 0,
            	225, 0,
            	230, 0,
            	235, 0,
            	240, 0,
            	245, 0,
            	250, 0,
            	255, 0,
            	260, 0,
            	265, 0,
            	270, 0,
            	275, 0,
            	195, 0,
            	195, 0,
            	280, 0,
            1, 8, 1, /* 195: pointer.struct.asn1_string_st */
            	200, 0,
            0, 24, 1, /* 200: struct.asn1_string_st */
            	205, 8,
            1, 8, 1, /* 205: pointer.unsigned char */
            	139, 0,
            1, 8, 1, /* 210: pointer.struct.asn1_string_st */
            	200, 0,
            1, 8, 1, /* 215: pointer.struct.asn1_string_st */
            	200, 0,
            1, 8, 1, /* 220: pointer.struct.asn1_string_st */
            	200, 0,
            1, 8, 1, /* 225: pointer.struct.asn1_string_st */
            	200, 0,
            1, 8, 1, /* 230: pointer.struct.asn1_string_st */
            	200, 0,
            1, 8, 1, /* 235: pointer.struct.asn1_string_st */
            	200, 0,
            1, 8, 1, /* 240: pointer.struct.asn1_string_st */
            	200, 0,
            1, 8, 1, /* 245: pointer.struct.asn1_string_st */
            	200, 0,
            1, 8, 1, /* 250: pointer.struct.asn1_string_st */
            	200, 0,
            1, 8, 1, /* 255: pointer.struct.asn1_string_st */
            	200, 0,
            1, 8, 1, /* 260: pointer.struct.asn1_string_st */
            	200, 0,
            1, 8, 1, /* 265: pointer.struct.asn1_string_st */
            	200, 0,
            1, 8, 1, /* 270: pointer.struct.asn1_string_st */
            	200, 0,
            1, 8, 1, /* 275: pointer.struct.asn1_string_st */
            	200, 0,
            1, 8, 1, /* 280: pointer.struct.ASN1_VALUE_st */
            	285, 0,
            0, 0, 0, /* 285: struct.ASN1_VALUE_st */
            1, 8, 1, /* 288: pointer.struct.X509_name_st */
            	293, 0,
            0, 40, 3, /* 293: struct.X509_name_st */
            	302, 0,
            	368, 16,
            	205, 24,
            1, 8, 1, /* 302: pointer.struct.stack_st_X509_NAME_ENTRY */
            	307, 0,
            0, 32, 2, /* 307: struct.stack_st_fake_X509_NAME_ENTRY */
            	314, 8,
            	365, 24,
            8884099, 8, 2, /* 314: pointer_to_array_of_pointers_to_stack */
            	321, 0,
            	362, 20,
            0, 8, 1, /* 321: pointer.X509_NAME_ENTRY */
            	326, 0,
            0, 0, 1, /* 326: X509_NAME_ENTRY */
            	331, 0,
            0, 24, 2, /* 331: struct.X509_name_entry_st */
            	338, 0,
            	352, 8,
            1, 8, 1, /* 338: pointer.struct.asn1_object_st */
            	343, 0,
            0, 40, 3, /* 343: struct.asn1_object_st */
            	129, 0,
            	129, 8,
            	134, 24,
            1, 8, 1, /* 352: pointer.struct.asn1_string_st */
            	357, 0,
            0, 24, 1, /* 357: struct.asn1_string_st */
            	205, 8,
            0, 4, 0, /* 362: int */
            8884097, 8, 0, /* 365: pointer.func */
            1, 8, 1, /* 368: pointer.struct.buf_mem_st */
            	373, 0,
            0, 24, 1, /* 373: struct.buf_mem_st */
            	98, 8,
            1, 8, 1, /* 378: pointer.struct.EDIPartyName_st */
            	383, 0,
            0, 16, 2, /* 383: struct.EDIPartyName_st */
            	195, 0,
            	195, 8,
            1, 8, 1, /* 390: pointer.struct.stack_st_X509_NAME_ENTRY */
            	395, 0,
            0, 32, 2, /* 395: struct.stack_st_fake_X509_NAME_ENTRY */
            	402, 8,
            	365, 24,
            8884099, 8, 2, /* 402: pointer_to_array_of_pointers_to_stack */
            	409, 0,
            	362, 20,
            0, 8, 1, /* 409: pointer.X509_NAME_ENTRY */
            	326, 0,
            1, 8, 1, /* 414: pointer.struct.X509_name_st */
            	419, 0,
            0, 40, 3, /* 419: struct.X509_name_st */
            	390, 0,
            	428, 16,
            	205, 24,
            1, 8, 1, /* 428: pointer.struct.buf_mem_st */
            	433, 0,
            0, 24, 1, /* 433: struct.buf_mem_st */
            	98, 8,
            1, 8, 1, /* 438: pointer.struct.asn1_string_st */
            	443, 0,
            0, 24, 1, /* 443: struct.asn1_string_st */
            	205, 8,
            0, 80, 8, /* 448: struct.X509_crl_info_st */
            	467, 0,
            	472, 8,
            	414, 16,
            	639, 24,
            	639, 32,
            	644, 40,
            	783, 48,
            	807, 56,
            1, 8, 1, /* 467: pointer.struct.asn1_string_st */
            	443, 0,
            1, 8, 1, /* 472: pointer.struct.X509_algor_st */
            	477, 0,
            0, 16, 2, /* 477: struct.X509_algor_st */
            	484, 0,
            	498, 8,
            1, 8, 1, /* 484: pointer.struct.asn1_object_st */
            	489, 0,
            0, 40, 3, /* 489: struct.asn1_object_st */
            	129, 0,
            	129, 8,
            	134, 24,
            1, 8, 1, /* 498: pointer.struct.asn1_type_st */
            	503, 0,
            0, 16, 1, /* 503: struct.asn1_type_st */
            	508, 8,
            0, 8, 20, /* 508: union.unknown */
            	98, 0,
            	551, 0,
            	484, 0,
            	561, 0,
            	566, 0,
            	571, 0,
            	576, 0,
            	581, 0,
            	586, 0,
            	591, 0,
            	596, 0,
            	601, 0,
            	606, 0,
            	611, 0,
            	616, 0,
            	621, 0,
            	626, 0,
            	551, 0,
            	551, 0,
            	631, 0,
            1, 8, 1, /* 551: pointer.struct.asn1_string_st */
            	556, 0,
            0, 24, 1, /* 556: struct.asn1_string_st */
            	205, 8,
            1, 8, 1, /* 561: pointer.struct.asn1_string_st */
            	556, 0,
            1, 8, 1, /* 566: pointer.struct.asn1_string_st */
            	556, 0,
            1, 8, 1, /* 571: pointer.struct.asn1_string_st */
            	556, 0,
            1, 8, 1, /* 576: pointer.struct.asn1_string_st */
            	556, 0,
            1, 8, 1, /* 581: pointer.struct.asn1_string_st */
            	556, 0,
            1, 8, 1, /* 586: pointer.struct.asn1_string_st */
            	556, 0,
            1, 8, 1, /* 591: pointer.struct.asn1_string_st */
            	556, 0,
            1, 8, 1, /* 596: pointer.struct.asn1_string_st */
            	556, 0,
            1, 8, 1, /* 601: pointer.struct.asn1_string_st */
            	556, 0,
            1, 8, 1, /* 606: pointer.struct.asn1_string_st */
            	556, 0,
            1, 8, 1, /* 611: pointer.struct.asn1_string_st */
            	556, 0,
            1, 8, 1, /* 616: pointer.struct.asn1_string_st */
            	556, 0,
            1, 8, 1, /* 621: pointer.struct.asn1_string_st */
            	556, 0,
            1, 8, 1, /* 626: pointer.struct.asn1_string_st */
            	556, 0,
            1, 8, 1, /* 631: pointer.struct.ASN1_VALUE_st */
            	636, 0,
            0, 0, 0, /* 636: struct.ASN1_VALUE_st */
            1, 8, 1, /* 639: pointer.struct.asn1_string_st */
            	443, 0,
            1, 8, 1, /* 644: pointer.struct.stack_st_X509_REVOKED */
            	649, 0,
            0, 32, 2, /* 649: struct.stack_st_fake_X509_REVOKED */
            	656, 8,
            	365, 24,
            8884099, 8, 2, /* 656: pointer_to_array_of_pointers_to_stack */
            	663, 0,
            	362, 20,
            0, 8, 1, /* 663: pointer.X509_REVOKED */
            	668, 0,
            0, 0, 1, /* 668: X509_REVOKED */
            	673, 0,
            0, 40, 4, /* 673: struct.x509_revoked_st */
            	684, 0,
            	694, 8,
            	699, 16,
            	759, 24,
            1, 8, 1, /* 684: pointer.struct.asn1_string_st */
            	689, 0,
            0, 24, 1, /* 689: struct.asn1_string_st */
            	205, 8,
            1, 8, 1, /* 694: pointer.struct.asn1_string_st */
            	689, 0,
            1, 8, 1, /* 699: pointer.struct.stack_st_X509_EXTENSION */
            	704, 0,
            0, 32, 2, /* 704: struct.stack_st_fake_X509_EXTENSION */
            	711, 8,
            	365, 24,
            8884099, 8, 2, /* 711: pointer_to_array_of_pointers_to_stack */
            	718, 0,
            	362, 20,
            0, 8, 1, /* 718: pointer.X509_EXTENSION */
            	723, 0,
            0, 0, 1, /* 723: X509_EXTENSION */
            	728, 0,
            0, 24, 2, /* 728: struct.X509_extension_st */
            	735, 0,
            	749, 16,
            1, 8, 1, /* 735: pointer.struct.asn1_object_st */
            	740, 0,
            0, 40, 3, /* 740: struct.asn1_object_st */
            	129, 0,
            	129, 8,
            	134, 24,
            1, 8, 1, /* 749: pointer.struct.asn1_string_st */
            	754, 0,
            0, 24, 1, /* 754: struct.asn1_string_st */
            	205, 8,
            1, 8, 1, /* 759: pointer.struct.stack_st_GENERAL_NAME */
            	764, 0,
            0, 32, 2, /* 764: struct.stack_st_fake_GENERAL_NAME */
            	771, 8,
            	365, 24,
            8884099, 8, 2, /* 771: pointer_to_array_of_pointers_to_stack */
            	778, 0,
            	362, 20,
            0, 8, 1, /* 778: pointer.GENERAL_NAME */
            	55, 0,
            1, 8, 1, /* 783: pointer.struct.stack_st_X509_EXTENSION */
            	788, 0,
            0, 32, 2, /* 788: struct.stack_st_fake_X509_EXTENSION */
            	795, 8,
            	365, 24,
            8884099, 8, 2, /* 795: pointer_to_array_of_pointers_to_stack */
            	802, 0,
            	362, 20,
            0, 8, 1, /* 802: pointer.X509_EXTENSION */
            	723, 0,
            0, 24, 1, /* 807: struct.ASN1_ENCODING_st */
            	205, 0,
            1, 8, 1, /* 812: pointer.struct.X509_crl_info_st */
            	448, 0,
            1, 8, 1, /* 817: pointer.struct.X509_crl_st */
            	822, 0,
            0, 120, 10, /* 822: struct.X509_crl_st */
            	812, 0,
            	472, 8,
            	438, 16,
            	845, 32,
            	0, 40,
            	467, 56,
            	467, 64,
            	898, 96,
            	944, 104,
            	969, 112,
            1, 8, 1, /* 845: pointer.struct.AUTHORITY_KEYID_st */
            	850, 0,
            0, 24, 3, /* 850: struct.AUTHORITY_KEYID_st */
            	859, 0,
            	869, 8,
            	893, 16,
            1, 8, 1, /* 859: pointer.struct.asn1_string_st */
            	864, 0,
            0, 24, 1, /* 864: struct.asn1_string_st */
            	205, 8,
            1, 8, 1, /* 869: pointer.struct.stack_st_GENERAL_NAME */
            	874, 0,
            0, 32, 2, /* 874: struct.stack_st_fake_GENERAL_NAME */
            	881, 8,
            	365, 24,
            8884099, 8, 2, /* 881: pointer_to_array_of_pointers_to_stack */
            	888, 0,
            	362, 20,
            0, 8, 1, /* 888: pointer.GENERAL_NAME */
            	55, 0,
            1, 8, 1, /* 893: pointer.struct.asn1_string_st */
            	864, 0,
            1, 8, 1, /* 898: pointer.struct.stack_st_GENERAL_NAMES */
            	903, 0,
            0, 32, 2, /* 903: struct.stack_st_fake_GENERAL_NAMES */
            	910, 8,
            	365, 24,
            8884099, 8, 2, /* 910: pointer_to_array_of_pointers_to_stack */
            	917, 0,
            	362, 20,
            0, 8, 1, /* 917: pointer.GENERAL_NAMES */
            	922, 0,
            0, 0, 1, /* 922: GENERAL_NAMES */
            	927, 0,
            0, 32, 1, /* 927: struct.stack_st_GENERAL_NAME */
            	932, 0,
            0, 32, 2, /* 932: struct.stack_st */
            	939, 8,
            	365, 24,
            1, 8, 1, /* 939: pointer.pointer.char */
            	98, 0,
            1, 8, 1, /* 944: pointer.struct.x509_crl_method_st */
            	949, 0,
            0, 40, 4, /* 949: struct.x509_crl_method_st */
            	960, 8,
            	960, 16,
            	963, 24,
            	966, 32,
            8884097, 8, 0, /* 960: pointer.func */
            8884097, 8, 0, /* 963: pointer.func */
            8884097, 8, 0, /* 966: pointer.func */
            0, 8, 0, /* 969: pointer.void */
            1, 8, 1, /* 972: pointer.struct.stack_st_X509_POLICY_DATA */
            	977, 0,
            0, 32, 2, /* 977: struct.stack_st_fake_X509_POLICY_DATA */
            	984, 8,
            	365, 24,
            8884099, 8, 2, /* 984: pointer_to_array_of_pointers_to_stack */
            	991, 0,
            	362, 20,
            0, 8, 1, /* 991: pointer.X509_POLICY_DATA */
            	996, 0,
            0, 0, 1, /* 996: X509_POLICY_DATA */
            	1001, 0,
            0, 32, 3, /* 1001: struct.X509_POLICY_DATA_st */
            	1010, 8,
            	1024, 16,
            	1282, 24,
            1, 8, 1, /* 1010: pointer.struct.asn1_object_st */
            	1015, 0,
            0, 40, 3, /* 1015: struct.asn1_object_st */
            	129, 0,
            	129, 8,
            	134, 24,
            1, 8, 1, /* 1024: pointer.struct.stack_st_POLICYQUALINFO */
            	1029, 0,
            0, 32, 2, /* 1029: struct.stack_st_fake_POLICYQUALINFO */
            	1036, 8,
            	365, 24,
            8884099, 8, 2, /* 1036: pointer_to_array_of_pointers_to_stack */
            	1043, 0,
            	362, 20,
            0, 8, 1, /* 1043: pointer.POLICYQUALINFO */
            	1048, 0,
            0, 0, 1, /* 1048: POLICYQUALINFO */
            	1053, 0,
            0, 16, 2, /* 1053: struct.POLICYQUALINFO_st */
            	1060, 0,
            	1074, 8,
            1, 8, 1, /* 1060: pointer.struct.asn1_object_st */
            	1065, 0,
            0, 40, 3, /* 1065: struct.asn1_object_st */
            	129, 0,
            	129, 8,
            	134, 24,
            0, 8, 3, /* 1074: union.unknown */
            	1083, 0,
            	1093, 0,
            	1156, 0,
            1, 8, 1, /* 1083: pointer.struct.asn1_string_st */
            	1088, 0,
            0, 24, 1, /* 1088: struct.asn1_string_st */
            	205, 8,
            1, 8, 1, /* 1093: pointer.struct.USERNOTICE_st */
            	1098, 0,
            0, 16, 2, /* 1098: struct.USERNOTICE_st */
            	1105, 0,
            	1117, 8,
            1, 8, 1, /* 1105: pointer.struct.NOTICEREF_st */
            	1110, 0,
            0, 16, 2, /* 1110: struct.NOTICEREF_st */
            	1117, 0,
            	1122, 8,
            1, 8, 1, /* 1117: pointer.struct.asn1_string_st */
            	1088, 0,
            1, 8, 1, /* 1122: pointer.struct.stack_st_ASN1_INTEGER */
            	1127, 0,
            0, 32, 2, /* 1127: struct.stack_st_fake_ASN1_INTEGER */
            	1134, 8,
            	365, 24,
            8884099, 8, 2, /* 1134: pointer_to_array_of_pointers_to_stack */
            	1141, 0,
            	362, 20,
            0, 8, 1, /* 1141: pointer.ASN1_INTEGER */
            	1146, 0,
            0, 0, 1, /* 1146: ASN1_INTEGER */
            	1151, 0,
            0, 24, 1, /* 1151: struct.asn1_string_st */
            	205, 8,
            1, 8, 1, /* 1156: pointer.struct.asn1_type_st */
            	1161, 0,
            0, 16, 1, /* 1161: struct.asn1_type_st */
            	1166, 8,
            0, 8, 20, /* 1166: union.unknown */
            	98, 0,
            	1117, 0,
            	1060, 0,
            	1209, 0,
            	1214, 0,
            	1219, 0,
            	1224, 0,
            	1229, 0,
            	1234, 0,
            	1083, 0,
            	1239, 0,
            	1244, 0,
            	1249, 0,
            	1254, 0,
            	1259, 0,
            	1264, 0,
            	1269, 0,
            	1117, 0,
            	1117, 0,
            	1274, 0,
            1, 8, 1, /* 1209: pointer.struct.asn1_string_st */
            	1088, 0,
            1, 8, 1, /* 1214: pointer.struct.asn1_string_st */
            	1088, 0,
            1, 8, 1, /* 1219: pointer.struct.asn1_string_st */
            	1088, 0,
            1, 8, 1, /* 1224: pointer.struct.asn1_string_st */
            	1088, 0,
            1, 8, 1, /* 1229: pointer.struct.asn1_string_st */
            	1088, 0,
            1, 8, 1, /* 1234: pointer.struct.asn1_string_st */
            	1088, 0,
            1, 8, 1, /* 1239: pointer.struct.asn1_string_st */
            	1088, 0,
            1, 8, 1, /* 1244: pointer.struct.asn1_string_st */
            	1088, 0,
            1, 8, 1, /* 1249: pointer.struct.asn1_string_st */
            	1088, 0,
            1, 8, 1, /* 1254: pointer.struct.asn1_string_st */
            	1088, 0,
            1, 8, 1, /* 1259: pointer.struct.asn1_string_st */
            	1088, 0,
            1, 8, 1, /* 1264: pointer.struct.asn1_string_st */
            	1088, 0,
            1, 8, 1, /* 1269: pointer.struct.asn1_string_st */
            	1088, 0,
            1, 8, 1, /* 1274: pointer.struct.ASN1_VALUE_st */
            	1279, 0,
            0, 0, 0, /* 1279: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1282: pointer.struct.stack_st_ASN1_OBJECT */
            	1287, 0,
            0, 32, 2, /* 1287: struct.stack_st_fake_ASN1_OBJECT */
            	1294, 8,
            	365, 24,
            8884099, 8, 2, /* 1294: pointer_to_array_of_pointers_to_stack */
            	1301, 0,
            	362, 20,
            0, 8, 1, /* 1301: pointer.ASN1_OBJECT */
            	1306, 0,
            0, 0, 1, /* 1306: ASN1_OBJECT */
            	1311, 0,
            0, 40, 3, /* 1311: struct.asn1_object_st */
            	129, 0,
            	129, 8,
            	134, 24,
            1, 8, 1, /* 1320: pointer.struct.asn1_object_st */
            	1325, 0,
            0, 40, 3, /* 1325: struct.asn1_object_st */
            	129, 0,
            	129, 8,
            	134, 24,
            0, 24, 2, /* 1334: struct.X509_POLICY_NODE_st */
            	1341, 0,
            	1403, 8,
            1, 8, 1, /* 1341: pointer.struct.X509_POLICY_DATA_st */
            	1346, 0,
            0, 32, 3, /* 1346: struct.X509_POLICY_DATA_st */
            	1320, 8,
            	1355, 16,
            	1379, 24,
            1, 8, 1, /* 1355: pointer.struct.stack_st_POLICYQUALINFO */
            	1360, 0,
            0, 32, 2, /* 1360: struct.stack_st_fake_POLICYQUALINFO */
            	1367, 8,
            	365, 24,
            8884099, 8, 2, /* 1367: pointer_to_array_of_pointers_to_stack */
            	1374, 0,
            	362, 20,
            0, 8, 1, /* 1374: pointer.POLICYQUALINFO */
            	1048, 0,
            1, 8, 1, /* 1379: pointer.struct.stack_st_ASN1_OBJECT */
            	1384, 0,
            0, 32, 2, /* 1384: struct.stack_st_fake_ASN1_OBJECT */
            	1391, 8,
            	365, 24,
            8884099, 8, 2, /* 1391: pointer_to_array_of_pointers_to_stack */
            	1398, 0,
            	362, 20,
            0, 8, 1, /* 1398: pointer.ASN1_OBJECT */
            	1306, 0,
            1, 8, 1, /* 1403: pointer.struct.X509_POLICY_NODE_st */
            	1334, 0,
            0, 0, 1, /* 1408: X509_POLICY_NODE */
            	1413, 0,
            0, 24, 2, /* 1413: struct.X509_POLICY_NODE_st */
            	1420, 0,
            	1425, 8,
            1, 8, 1, /* 1420: pointer.struct.X509_POLICY_DATA_st */
            	1001, 0,
            1, 8, 1, /* 1425: pointer.struct.X509_POLICY_NODE_st */
            	1413, 0,
            1, 8, 1, /* 1430: pointer.struct.asn1_string_st */
            	1435, 0,
            0, 24, 1, /* 1435: struct.asn1_string_st */
            	205, 8,
            0, 40, 5, /* 1440: struct.x509_cert_aux_st */
            	1379, 0,
            	1379, 8,
            	1430, 16,
            	1453, 24,
            	1458, 32,
            1, 8, 1, /* 1453: pointer.struct.asn1_string_st */
            	1435, 0,
            1, 8, 1, /* 1458: pointer.struct.stack_st_X509_ALGOR */
            	1463, 0,
            0, 32, 2, /* 1463: struct.stack_st_fake_X509_ALGOR */
            	1470, 8,
            	365, 24,
            8884099, 8, 2, /* 1470: pointer_to_array_of_pointers_to_stack */
            	1477, 0,
            	362, 20,
            0, 8, 1, /* 1477: pointer.X509_ALGOR */
            	1482, 0,
            0, 0, 1, /* 1482: X509_ALGOR */
            	477, 0,
            1, 8, 1, /* 1487: pointer.struct.x509_cert_aux_st */
            	1440, 0,
            1, 8, 1, /* 1492: pointer.struct.stack_st_GENERAL_NAME */
            	1497, 0,
            0, 32, 2, /* 1497: struct.stack_st_fake_GENERAL_NAME */
            	1504, 8,
            	365, 24,
            8884099, 8, 2, /* 1504: pointer_to_array_of_pointers_to_stack */
            	1511, 0,
            	362, 20,
            0, 8, 1, /* 1511: pointer.GENERAL_NAME */
            	55, 0,
            1, 8, 1, /* 1516: pointer.struct.stack_st_DIST_POINT */
            	1521, 0,
            0, 32, 2, /* 1521: struct.stack_st_fake_DIST_POINT */
            	1528, 8,
            	365, 24,
            8884099, 8, 2, /* 1528: pointer_to_array_of_pointers_to_stack */
            	1535, 0,
            	362, 20,
            0, 8, 1, /* 1535: pointer.DIST_POINT */
            	1540, 0,
            0, 0, 1, /* 1540: DIST_POINT */
            	1545, 0,
            0, 32, 3, /* 1545: struct.DIST_POINT_st */
            	12, 0,
            	438, 8,
            	31, 16,
            1, 8, 1, /* 1554: pointer.struct.stack_st_X509_EXTENSION */
            	1559, 0,
            0, 32, 2, /* 1559: struct.stack_st_fake_X509_EXTENSION */
            	1566, 8,
            	365, 24,
            8884099, 8, 2, /* 1566: pointer_to_array_of_pointers_to_stack */
            	1573, 0,
            	362, 20,
            0, 8, 1, /* 1573: pointer.X509_EXTENSION */
            	723, 0,
            1, 8, 1, /* 1578: pointer.struct.X509_val_st */
            	1583, 0,
            0, 16, 2, /* 1583: struct.X509_val_st */
            	1590, 0,
            	1590, 8,
            1, 8, 1, /* 1590: pointer.struct.asn1_string_st */
            	1435, 0,
            1, 8, 1, /* 1595: pointer.struct.buf_mem_st */
            	1600, 0,
            0, 24, 1, /* 1600: struct.buf_mem_st */
            	98, 8,
            1, 8, 1, /* 1605: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1610, 0,
            0, 32, 2, /* 1610: struct.stack_st_fake_X509_NAME_ENTRY */
            	1617, 8,
            	365, 24,
            8884099, 8, 2, /* 1617: pointer_to_array_of_pointers_to_stack */
            	1624, 0,
            	362, 20,
            0, 8, 1, /* 1624: pointer.X509_NAME_ENTRY */
            	326, 0,
            0, 40, 3, /* 1629: struct.X509_name_st */
            	1605, 0,
            	1595, 16,
            	205, 24,
            0, 184, 12, /* 1638: struct.x509_st */
            	1665, 0,
            	1700, 8,
            	3535, 16,
            	98, 32,
            	3545, 40,
            	1453, 104,
            	3567, 112,
            	3572, 120,
            	1516, 128,
            	1492, 136,
            	3684, 144,
            	1487, 176,
            1, 8, 1, /* 1665: pointer.struct.x509_cinf_st */
            	1670, 0,
            0, 104, 11, /* 1670: struct.x509_cinf_st */
            	1695, 0,
            	1695, 8,
            	1700, 16,
            	1705, 24,
            	1578, 32,
            	1705, 40,
            	1710, 48,
            	3535, 56,
            	3535, 64,
            	1554, 72,
            	3540, 80,
            1, 8, 1, /* 1695: pointer.struct.asn1_string_st */
            	1435, 0,
            1, 8, 1, /* 1700: pointer.struct.X509_algor_st */
            	477, 0,
            1, 8, 1, /* 1705: pointer.struct.X509_name_st */
            	1629, 0,
            1, 8, 1, /* 1710: pointer.struct.X509_pubkey_st */
            	1715, 0,
            0, 24, 3, /* 1715: struct.X509_pubkey_st */
            	1724, 0,
            	1729, 8,
            	1739, 16,
            1, 8, 1, /* 1724: pointer.struct.X509_algor_st */
            	477, 0,
            1, 8, 1, /* 1729: pointer.struct.asn1_string_st */
            	1734, 0,
            0, 24, 1, /* 1734: struct.asn1_string_st */
            	205, 8,
            1, 8, 1, /* 1739: pointer.struct.evp_pkey_st */
            	1744, 0,
            0, 56, 4, /* 1744: struct.evp_pkey_st */
            	1755, 16,
            	1856, 24,
            	2204, 32,
            	3156, 48,
            1, 8, 1, /* 1755: pointer.struct.evp_pkey_asn1_method_st */
            	1760, 0,
            0, 208, 24, /* 1760: struct.evp_pkey_asn1_method_st */
            	98, 16,
            	98, 24,
            	1811, 32,
            	1814, 40,
            	1817, 48,
            	1820, 56,
            	1823, 64,
            	1826, 72,
            	1820, 80,
            	1829, 88,
            	1829, 96,
            	1832, 104,
            	1835, 112,
            	1829, 120,
            	1838, 128,
            	1817, 136,
            	1820, 144,
            	1841, 152,
            	1844, 160,
            	1847, 168,
            	1832, 176,
            	1835, 184,
            	1850, 192,
            	1853, 200,
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
            1, 8, 1, /* 1856: pointer.struct.engine_st */
            	1861, 0,
            0, 216, 24, /* 1861: struct.engine_st */
            	129, 0,
            	129, 8,
            	1912, 16,
            	1967, 24,
            	2018, 32,
            	2054, 40,
            	2071, 48,
            	2098, 56,
            	2133, 64,
            	2141, 72,
            	2144, 80,
            	2147, 88,
            	2150, 96,
            	2153, 104,
            	2153, 112,
            	2153, 120,
            	2156, 128,
            	2159, 136,
            	2159, 144,
            	2162, 152,
            	2165, 160,
            	2177, 184,
            	2199, 200,
            	2199, 208,
            1, 8, 1, /* 1912: pointer.struct.rsa_meth_st */
            	1917, 0,
            0, 112, 13, /* 1917: struct.rsa_meth_st */
            	129, 0,
            	1946, 8,
            	1946, 16,
            	1946, 24,
            	1946, 32,
            	1949, 40,
            	1952, 48,
            	1955, 56,
            	1955, 64,
            	98, 80,
            	1958, 88,
            	1961, 96,
            	1964, 104,
            8884097, 8, 0, /* 1946: pointer.func */
            8884097, 8, 0, /* 1949: pointer.func */
            8884097, 8, 0, /* 1952: pointer.func */
            8884097, 8, 0, /* 1955: pointer.func */
            8884097, 8, 0, /* 1958: pointer.func */
            8884097, 8, 0, /* 1961: pointer.func */
            8884097, 8, 0, /* 1964: pointer.func */
            1, 8, 1, /* 1967: pointer.struct.dsa_method */
            	1972, 0,
            0, 96, 11, /* 1972: struct.dsa_method */
            	129, 0,
            	1997, 8,
            	2000, 16,
            	2003, 24,
            	2006, 32,
            	2009, 40,
            	2012, 48,
            	2012, 56,
            	98, 72,
            	2015, 80,
            	2012, 88,
            8884097, 8, 0, /* 1997: pointer.func */
            8884097, 8, 0, /* 2000: pointer.func */
            8884097, 8, 0, /* 2003: pointer.func */
            8884097, 8, 0, /* 2006: pointer.func */
            8884097, 8, 0, /* 2009: pointer.func */
            8884097, 8, 0, /* 2012: pointer.func */
            8884097, 8, 0, /* 2015: pointer.func */
            1, 8, 1, /* 2018: pointer.struct.dh_method */
            	2023, 0,
            0, 72, 8, /* 2023: struct.dh_method */
            	129, 0,
            	2042, 8,
            	2045, 16,
            	2048, 24,
            	2042, 32,
            	2042, 40,
            	98, 56,
            	2051, 64,
            8884097, 8, 0, /* 2042: pointer.func */
            8884097, 8, 0, /* 2045: pointer.func */
            8884097, 8, 0, /* 2048: pointer.func */
            8884097, 8, 0, /* 2051: pointer.func */
            1, 8, 1, /* 2054: pointer.struct.ecdh_method */
            	2059, 0,
            0, 32, 3, /* 2059: struct.ecdh_method */
            	129, 0,
            	2068, 8,
            	98, 24,
            8884097, 8, 0, /* 2068: pointer.func */
            1, 8, 1, /* 2071: pointer.struct.ecdsa_method */
            	2076, 0,
            0, 48, 5, /* 2076: struct.ecdsa_method */
            	129, 0,
            	2089, 8,
            	2092, 16,
            	2095, 24,
            	98, 40,
            8884097, 8, 0, /* 2089: pointer.func */
            8884097, 8, 0, /* 2092: pointer.func */
            8884097, 8, 0, /* 2095: pointer.func */
            1, 8, 1, /* 2098: pointer.struct.rand_meth_st */
            	2103, 0,
            0, 48, 6, /* 2103: struct.rand_meth_st */
            	2118, 0,
            	2121, 8,
            	2124, 16,
            	2127, 24,
            	2121, 32,
            	2130, 40,
            8884097, 8, 0, /* 2118: pointer.func */
            8884097, 8, 0, /* 2121: pointer.func */
            8884097, 8, 0, /* 2124: pointer.func */
            8884097, 8, 0, /* 2127: pointer.func */
            8884097, 8, 0, /* 2130: pointer.func */
            1, 8, 1, /* 2133: pointer.struct.store_method_st */
            	2138, 0,
            0, 0, 0, /* 2138: struct.store_method_st */
            8884097, 8, 0, /* 2141: pointer.func */
            8884097, 8, 0, /* 2144: pointer.func */
            8884097, 8, 0, /* 2147: pointer.func */
            8884097, 8, 0, /* 2150: pointer.func */
            8884097, 8, 0, /* 2153: pointer.func */
            8884097, 8, 0, /* 2156: pointer.func */
            8884097, 8, 0, /* 2159: pointer.func */
            8884097, 8, 0, /* 2162: pointer.func */
            1, 8, 1, /* 2165: pointer.struct.ENGINE_CMD_DEFN_st */
            	2170, 0,
            0, 32, 2, /* 2170: struct.ENGINE_CMD_DEFN_st */
            	129, 8,
            	129, 16,
            0, 16, 1, /* 2177: struct.crypto_ex_data_st */
            	2182, 0,
            1, 8, 1, /* 2182: pointer.struct.stack_st_void */
            	2187, 0,
            0, 32, 1, /* 2187: struct.stack_st_void */
            	2192, 0,
            0, 32, 2, /* 2192: struct.stack_st */
            	939, 8,
            	365, 24,
            1, 8, 1, /* 2199: pointer.struct.engine_st */
            	1861, 0,
            0, 8, 5, /* 2204: union.unknown */
            	98, 0,
            	2217, 0,
            	2427, 0,
            	2554, 0,
            	2668, 0,
            1, 8, 1, /* 2217: pointer.struct.rsa_st */
            	2222, 0,
            0, 168, 17, /* 2222: struct.rsa_st */
            	2259, 16,
            	2314, 24,
            	2319, 32,
            	2319, 40,
            	2319, 48,
            	2319, 56,
            	2319, 64,
            	2319, 72,
            	2319, 80,
            	2319, 88,
            	2337, 96,
            	2359, 120,
            	2359, 128,
            	2359, 136,
            	98, 144,
            	2373, 152,
            	2373, 160,
            1, 8, 1, /* 2259: pointer.struct.rsa_meth_st */
            	2264, 0,
            0, 112, 13, /* 2264: struct.rsa_meth_st */
            	129, 0,
            	2293, 8,
            	2293, 16,
            	2293, 24,
            	2293, 32,
            	2296, 40,
            	2299, 48,
            	2302, 56,
            	2302, 64,
            	98, 80,
            	2305, 88,
            	2308, 96,
            	2311, 104,
            8884097, 8, 0, /* 2293: pointer.func */
            8884097, 8, 0, /* 2296: pointer.func */
            8884097, 8, 0, /* 2299: pointer.func */
            8884097, 8, 0, /* 2302: pointer.func */
            8884097, 8, 0, /* 2305: pointer.func */
            8884097, 8, 0, /* 2308: pointer.func */
            8884097, 8, 0, /* 2311: pointer.func */
            1, 8, 1, /* 2314: pointer.struct.engine_st */
            	1861, 0,
            1, 8, 1, /* 2319: pointer.struct.bignum_st */
            	2324, 0,
            0, 24, 1, /* 2324: struct.bignum_st */
            	2329, 0,
            1, 8, 1, /* 2329: pointer.unsigned int */
            	2334, 0,
            0, 4, 0, /* 2334: unsigned int */
            0, 16, 1, /* 2337: struct.crypto_ex_data_st */
            	2342, 0,
            1, 8, 1, /* 2342: pointer.struct.stack_st_void */
            	2347, 0,
            0, 32, 1, /* 2347: struct.stack_st_void */
            	2352, 0,
            0, 32, 2, /* 2352: struct.stack_st */
            	939, 8,
            	365, 24,
            1, 8, 1, /* 2359: pointer.struct.bn_mont_ctx_st */
            	2364, 0,
            0, 96, 3, /* 2364: struct.bn_mont_ctx_st */
            	2324, 8,
            	2324, 32,
            	2324, 56,
            1, 8, 1, /* 2373: pointer.struct.bn_blinding_st */
            	2378, 0,
            0, 88, 7, /* 2378: struct.bn_blinding_st */
            	2395, 0,
            	2395, 8,
            	2395, 16,
            	2395, 24,
            	2405, 40,
            	2410, 72,
            	2424, 80,
            1, 8, 1, /* 2395: pointer.struct.bignum_st */
            	2400, 0,
            0, 24, 1, /* 2400: struct.bignum_st */
            	2329, 0,
            0, 16, 1, /* 2405: struct.crypto_threadid_st */
            	969, 0,
            1, 8, 1, /* 2410: pointer.struct.bn_mont_ctx_st */
            	2415, 0,
            0, 96, 3, /* 2415: struct.bn_mont_ctx_st */
            	2400, 8,
            	2400, 32,
            	2400, 56,
            8884097, 8, 0, /* 2424: pointer.func */
            1, 8, 1, /* 2427: pointer.struct.dsa_st */
            	2432, 0,
            0, 136, 11, /* 2432: struct.dsa_st */
            	2457, 24,
            	2457, 32,
            	2457, 40,
            	2457, 48,
            	2457, 56,
            	2457, 64,
            	2457, 72,
            	2467, 88,
            	2481, 104,
            	2503, 120,
            	1856, 128,
            1, 8, 1, /* 2457: pointer.struct.bignum_st */
            	2462, 0,
            0, 24, 1, /* 2462: struct.bignum_st */
            	2329, 0,
            1, 8, 1, /* 2467: pointer.struct.bn_mont_ctx_st */
            	2472, 0,
            0, 96, 3, /* 2472: struct.bn_mont_ctx_st */
            	2462, 8,
            	2462, 32,
            	2462, 56,
            0, 16, 1, /* 2481: struct.crypto_ex_data_st */
            	2486, 0,
            1, 8, 1, /* 2486: pointer.struct.stack_st_void */
            	2491, 0,
            0, 32, 1, /* 2491: struct.stack_st_void */
            	2496, 0,
            0, 32, 2, /* 2496: struct.stack_st */
            	939, 8,
            	365, 24,
            1, 8, 1, /* 2503: pointer.struct.dsa_method */
            	2508, 0,
            0, 96, 11, /* 2508: struct.dsa_method */
            	129, 0,
            	2533, 8,
            	2536, 16,
            	2539, 24,
            	2542, 32,
            	2545, 40,
            	2548, 48,
            	2548, 56,
            	98, 72,
            	2551, 80,
            	2548, 88,
            8884097, 8, 0, /* 2533: pointer.func */
            8884097, 8, 0, /* 2536: pointer.func */
            8884097, 8, 0, /* 2539: pointer.func */
            8884097, 8, 0, /* 2542: pointer.func */
            8884097, 8, 0, /* 2545: pointer.func */
            8884097, 8, 0, /* 2548: pointer.func */
            8884097, 8, 0, /* 2551: pointer.func */
            1, 8, 1, /* 2554: pointer.struct.dh_st */
            	2559, 0,
            0, 144, 12, /* 2559: struct.dh_st */
            	2586, 8,
            	2586, 16,
            	2586, 32,
            	2586, 40,
            	2596, 56,
            	2586, 64,
            	2586, 72,
            	205, 80,
            	2586, 96,
            	2610, 112,
            	2632, 128,
            	2314, 136,
            1, 8, 1, /* 2586: pointer.struct.bignum_st */
            	2591, 0,
            0, 24, 1, /* 2591: struct.bignum_st */
            	2329, 0,
            1, 8, 1, /* 2596: pointer.struct.bn_mont_ctx_st */
            	2601, 0,
            0, 96, 3, /* 2601: struct.bn_mont_ctx_st */
            	2591, 8,
            	2591, 32,
            	2591, 56,
            0, 16, 1, /* 2610: struct.crypto_ex_data_st */
            	2615, 0,
            1, 8, 1, /* 2615: pointer.struct.stack_st_void */
            	2620, 0,
            0, 32, 1, /* 2620: struct.stack_st_void */
            	2625, 0,
            0, 32, 2, /* 2625: struct.stack_st */
            	939, 8,
            	365, 24,
            1, 8, 1, /* 2632: pointer.struct.dh_method */
            	2637, 0,
            0, 72, 8, /* 2637: struct.dh_method */
            	129, 0,
            	2656, 8,
            	2659, 16,
            	2662, 24,
            	2656, 32,
            	2656, 40,
            	98, 56,
            	2665, 64,
            8884097, 8, 0, /* 2656: pointer.func */
            8884097, 8, 0, /* 2659: pointer.func */
            8884097, 8, 0, /* 2662: pointer.func */
            8884097, 8, 0, /* 2665: pointer.func */
            1, 8, 1, /* 2668: pointer.struct.ec_key_st */
            	2673, 0,
            0, 56, 4, /* 2673: struct.ec_key_st */
            	2684, 8,
            	3118, 16,
            	3123, 24,
            	3133, 48,
            1, 8, 1, /* 2684: pointer.struct.ec_group_st */
            	2689, 0,
            0, 232, 12, /* 2689: struct.ec_group_st */
            	2716, 0,
            	2888, 8,
            	3081, 16,
            	3081, 40,
            	205, 80,
            	3086, 96,
            	3081, 104,
            	3081, 152,
            	3081, 176,
            	969, 208,
            	969, 216,
            	3115, 224,
            1, 8, 1, /* 2716: pointer.struct.ec_method_st */
            	2721, 0,
            0, 304, 37, /* 2721: struct.ec_method_st */
            	2798, 8,
            	2801, 16,
            	2801, 24,
            	2804, 32,
            	2807, 40,
            	2810, 48,
            	2813, 56,
            	2816, 64,
            	2819, 72,
            	2822, 80,
            	2822, 88,
            	2825, 96,
            	2828, 104,
            	2831, 112,
            	2834, 120,
            	2837, 128,
            	2840, 136,
            	2843, 144,
            	2846, 152,
            	2849, 160,
            	2852, 168,
            	2855, 176,
            	2858, 184,
            	2861, 192,
            	2864, 200,
            	2867, 208,
            	2858, 216,
            	2870, 224,
            	2873, 232,
            	2876, 240,
            	2813, 248,
            	2879, 256,
            	2882, 264,
            	2879, 272,
            	2882, 280,
            	2882, 288,
            	2885, 296,
            8884097, 8, 0, /* 2798: pointer.func */
            8884097, 8, 0, /* 2801: pointer.func */
            8884097, 8, 0, /* 2804: pointer.func */
            8884097, 8, 0, /* 2807: pointer.func */
            8884097, 8, 0, /* 2810: pointer.func */
            8884097, 8, 0, /* 2813: pointer.func */
            8884097, 8, 0, /* 2816: pointer.func */
            8884097, 8, 0, /* 2819: pointer.func */
            8884097, 8, 0, /* 2822: pointer.func */
            8884097, 8, 0, /* 2825: pointer.func */
            8884097, 8, 0, /* 2828: pointer.func */
            8884097, 8, 0, /* 2831: pointer.func */
            8884097, 8, 0, /* 2834: pointer.func */
            8884097, 8, 0, /* 2837: pointer.func */
            8884097, 8, 0, /* 2840: pointer.func */
            8884097, 8, 0, /* 2843: pointer.func */
            8884097, 8, 0, /* 2846: pointer.func */
            8884097, 8, 0, /* 2849: pointer.func */
            8884097, 8, 0, /* 2852: pointer.func */
            8884097, 8, 0, /* 2855: pointer.func */
            8884097, 8, 0, /* 2858: pointer.func */
            8884097, 8, 0, /* 2861: pointer.func */
            8884097, 8, 0, /* 2864: pointer.func */
            8884097, 8, 0, /* 2867: pointer.func */
            8884097, 8, 0, /* 2870: pointer.func */
            8884097, 8, 0, /* 2873: pointer.func */
            8884097, 8, 0, /* 2876: pointer.func */
            8884097, 8, 0, /* 2879: pointer.func */
            8884097, 8, 0, /* 2882: pointer.func */
            8884097, 8, 0, /* 2885: pointer.func */
            1, 8, 1, /* 2888: pointer.struct.ec_point_st */
            	2893, 0,
            0, 88, 4, /* 2893: struct.ec_point_st */
            	2904, 0,
            	3076, 8,
            	3076, 32,
            	3076, 56,
            1, 8, 1, /* 2904: pointer.struct.ec_method_st */
            	2909, 0,
            0, 304, 37, /* 2909: struct.ec_method_st */
            	2986, 8,
            	2989, 16,
            	2989, 24,
            	2992, 32,
            	2995, 40,
            	2998, 48,
            	3001, 56,
            	3004, 64,
            	3007, 72,
            	3010, 80,
            	3010, 88,
            	3013, 96,
            	3016, 104,
            	3019, 112,
            	3022, 120,
            	3025, 128,
            	3028, 136,
            	3031, 144,
            	3034, 152,
            	3037, 160,
            	3040, 168,
            	3043, 176,
            	3046, 184,
            	3049, 192,
            	3052, 200,
            	3055, 208,
            	3046, 216,
            	3058, 224,
            	3061, 232,
            	3064, 240,
            	3001, 248,
            	3067, 256,
            	3070, 264,
            	3067, 272,
            	3070, 280,
            	3070, 288,
            	3073, 296,
            8884097, 8, 0, /* 2986: pointer.func */
            8884097, 8, 0, /* 2989: pointer.func */
            8884097, 8, 0, /* 2992: pointer.func */
            8884097, 8, 0, /* 2995: pointer.func */
            8884097, 8, 0, /* 2998: pointer.func */
            8884097, 8, 0, /* 3001: pointer.func */
            8884097, 8, 0, /* 3004: pointer.func */
            8884097, 8, 0, /* 3007: pointer.func */
            8884097, 8, 0, /* 3010: pointer.func */
            8884097, 8, 0, /* 3013: pointer.func */
            8884097, 8, 0, /* 3016: pointer.func */
            8884097, 8, 0, /* 3019: pointer.func */
            8884097, 8, 0, /* 3022: pointer.func */
            8884097, 8, 0, /* 3025: pointer.func */
            8884097, 8, 0, /* 3028: pointer.func */
            8884097, 8, 0, /* 3031: pointer.func */
            8884097, 8, 0, /* 3034: pointer.func */
            8884097, 8, 0, /* 3037: pointer.func */
            8884097, 8, 0, /* 3040: pointer.func */
            8884097, 8, 0, /* 3043: pointer.func */
            8884097, 8, 0, /* 3046: pointer.func */
            8884097, 8, 0, /* 3049: pointer.func */
            8884097, 8, 0, /* 3052: pointer.func */
            8884097, 8, 0, /* 3055: pointer.func */
            8884097, 8, 0, /* 3058: pointer.func */
            8884097, 8, 0, /* 3061: pointer.func */
            8884097, 8, 0, /* 3064: pointer.func */
            8884097, 8, 0, /* 3067: pointer.func */
            8884097, 8, 0, /* 3070: pointer.func */
            8884097, 8, 0, /* 3073: pointer.func */
            0, 24, 1, /* 3076: struct.bignum_st */
            	2329, 0,
            0, 24, 1, /* 3081: struct.bignum_st */
            	2329, 0,
            1, 8, 1, /* 3086: pointer.struct.ec_extra_data_st */
            	3091, 0,
            0, 40, 5, /* 3091: struct.ec_extra_data_st */
            	3104, 0,
            	969, 8,
            	3109, 16,
            	3112, 24,
            	3112, 32,
            1, 8, 1, /* 3104: pointer.struct.ec_extra_data_st */
            	3091, 0,
            8884097, 8, 0, /* 3109: pointer.func */
            8884097, 8, 0, /* 3112: pointer.func */
            8884097, 8, 0, /* 3115: pointer.func */
            1, 8, 1, /* 3118: pointer.struct.ec_point_st */
            	2893, 0,
            1, 8, 1, /* 3123: pointer.struct.bignum_st */
            	3128, 0,
            0, 24, 1, /* 3128: struct.bignum_st */
            	2329, 0,
            1, 8, 1, /* 3133: pointer.struct.ec_extra_data_st */
            	3138, 0,
            0, 40, 5, /* 3138: struct.ec_extra_data_st */
            	3151, 0,
            	969, 8,
            	3109, 16,
            	3112, 24,
            	3112, 32,
            1, 8, 1, /* 3151: pointer.struct.ec_extra_data_st */
            	3138, 0,
            1, 8, 1, /* 3156: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3161, 0,
            0, 32, 2, /* 3161: struct.stack_st_fake_X509_ATTRIBUTE */
            	3168, 8,
            	365, 24,
            8884099, 8, 2, /* 3168: pointer_to_array_of_pointers_to_stack */
            	3175, 0,
            	362, 20,
            0, 8, 1, /* 3175: pointer.X509_ATTRIBUTE */
            	3180, 0,
            0, 0, 1, /* 3180: X509_ATTRIBUTE */
            	3185, 0,
            0, 24, 2, /* 3185: struct.x509_attributes_st */
            	3192, 0,
            	3206, 16,
            1, 8, 1, /* 3192: pointer.struct.asn1_object_st */
            	3197, 0,
            0, 40, 3, /* 3197: struct.asn1_object_st */
            	129, 0,
            	129, 8,
            	134, 24,
            0, 8, 3, /* 3206: union.unknown */
            	98, 0,
            	3215, 0,
            	3394, 0,
            1, 8, 1, /* 3215: pointer.struct.stack_st_ASN1_TYPE */
            	3220, 0,
            0, 32, 2, /* 3220: struct.stack_st_fake_ASN1_TYPE */
            	3227, 8,
            	365, 24,
            8884099, 8, 2, /* 3227: pointer_to_array_of_pointers_to_stack */
            	3234, 0,
            	362, 20,
            0, 8, 1, /* 3234: pointer.ASN1_TYPE */
            	3239, 0,
            0, 0, 1, /* 3239: ASN1_TYPE */
            	3244, 0,
            0, 16, 1, /* 3244: struct.asn1_type_st */
            	3249, 8,
            0, 8, 20, /* 3249: union.unknown */
            	98, 0,
            	3292, 0,
            	3302, 0,
            	3316, 0,
            	3321, 0,
            	3326, 0,
            	3331, 0,
            	3336, 0,
            	3341, 0,
            	3346, 0,
            	3351, 0,
            	3356, 0,
            	3361, 0,
            	3366, 0,
            	3371, 0,
            	3376, 0,
            	3381, 0,
            	3292, 0,
            	3292, 0,
            	3386, 0,
            1, 8, 1, /* 3292: pointer.struct.asn1_string_st */
            	3297, 0,
            0, 24, 1, /* 3297: struct.asn1_string_st */
            	205, 8,
            1, 8, 1, /* 3302: pointer.struct.asn1_object_st */
            	3307, 0,
            0, 40, 3, /* 3307: struct.asn1_object_st */
            	129, 0,
            	129, 8,
            	134, 24,
            1, 8, 1, /* 3316: pointer.struct.asn1_string_st */
            	3297, 0,
            1, 8, 1, /* 3321: pointer.struct.asn1_string_st */
            	3297, 0,
            1, 8, 1, /* 3326: pointer.struct.asn1_string_st */
            	3297, 0,
            1, 8, 1, /* 3331: pointer.struct.asn1_string_st */
            	3297, 0,
            1, 8, 1, /* 3336: pointer.struct.asn1_string_st */
            	3297, 0,
            1, 8, 1, /* 3341: pointer.struct.asn1_string_st */
            	3297, 0,
            1, 8, 1, /* 3346: pointer.struct.asn1_string_st */
            	3297, 0,
            1, 8, 1, /* 3351: pointer.struct.asn1_string_st */
            	3297, 0,
            1, 8, 1, /* 3356: pointer.struct.asn1_string_st */
            	3297, 0,
            1, 8, 1, /* 3361: pointer.struct.asn1_string_st */
            	3297, 0,
            1, 8, 1, /* 3366: pointer.struct.asn1_string_st */
            	3297, 0,
            1, 8, 1, /* 3371: pointer.struct.asn1_string_st */
            	3297, 0,
            1, 8, 1, /* 3376: pointer.struct.asn1_string_st */
            	3297, 0,
            1, 8, 1, /* 3381: pointer.struct.asn1_string_st */
            	3297, 0,
            1, 8, 1, /* 3386: pointer.struct.ASN1_VALUE_st */
            	3391, 0,
            0, 0, 0, /* 3391: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3394: pointer.struct.asn1_type_st */
            	3399, 0,
            0, 16, 1, /* 3399: struct.asn1_type_st */
            	3404, 8,
            0, 8, 20, /* 3404: union.unknown */
            	98, 0,
            	3447, 0,
            	3192, 0,
            	3457, 0,
            	3462, 0,
            	3467, 0,
            	3472, 0,
            	3477, 0,
            	3482, 0,
            	3487, 0,
            	3492, 0,
            	3497, 0,
            	3502, 0,
            	3507, 0,
            	3512, 0,
            	3517, 0,
            	3522, 0,
            	3447, 0,
            	3447, 0,
            	3527, 0,
            1, 8, 1, /* 3447: pointer.struct.asn1_string_st */
            	3452, 0,
            0, 24, 1, /* 3452: struct.asn1_string_st */
            	205, 8,
            1, 8, 1, /* 3457: pointer.struct.asn1_string_st */
            	3452, 0,
            1, 8, 1, /* 3462: pointer.struct.asn1_string_st */
            	3452, 0,
            1, 8, 1, /* 3467: pointer.struct.asn1_string_st */
            	3452, 0,
            1, 8, 1, /* 3472: pointer.struct.asn1_string_st */
            	3452, 0,
            1, 8, 1, /* 3477: pointer.struct.asn1_string_st */
            	3452, 0,
            1, 8, 1, /* 3482: pointer.struct.asn1_string_st */
            	3452, 0,
            1, 8, 1, /* 3487: pointer.struct.asn1_string_st */
            	3452, 0,
            1, 8, 1, /* 3492: pointer.struct.asn1_string_st */
            	3452, 0,
            1, 8, 1, /* 3497: pointer.struct.asn1_string_st */
            	3452, 0,
            1, 8, 1, /* 3502: pointer.struct.asn1_string_st */
            	3452, 0,
            1, 8, 1, /* 3507: pointer.struct.asn1_string_st */
            	3452, 0,
            1, 8, 1, /* 3512: pointer.struct.asn1_string_st */
            	3452, 0,
            1, 8, 1, /* 3517: pointer.struct.asn1_string_st */
            	3452, 0,
            1, 8, 1, /* 3522: pointer.struct.asn1_string_st */
            	3452, 0,
            1, 8, 1, /* 3527: pointer.struct.ASN1_VALUE_st */
            	3532, 0,
            0, 0, 0, /* 3532: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3535: pointer.struct.asn1_string_st */
            	1435, 0,
            0, 24, 1, /* 3540: struct.ASN1_ENCODING_st */
            	205, 0,
            0, 16, 1, /* 3545: struct.crypto_ex_data_st */
            	3550, 0,
            1, 8, 1, /* 3550: pointer.struct.stack_st_void */
            	3555, 0,
            0, 32, 1, /* 3555: struct.stack_st_void */
            	3560, 0,
            0, 32, 2, /* 3560: struct.stack_st */
            	939, 8,
            	365, 24,
            1, 8, 1, /* 3567: pointer.struct.AUTHORITY_KEYID_st */
            	850, 0,
            1, 8, 1, /* 3572: pointer.struct.X509_POLICY_CACHE_st */
            	3577, 0,
            0, 40, 2, /* 3577: struct.X509_POLICY_CACHE_st */
            	3584, 0,
            	3660, 8,
            1, 8, 1, /* 3584: pointer.struct.X509_POLICY_DATA_st */
            	3589, 0,
            0, 32, 3, /* 3589: struct.X509_POLICY_DATA_st */
            	3598, 8,
            	3612, 16,
            	3636, 24,
            1, 8, 1, /* 3598: pointer.struct.asn1_object_st */
            	3603, 0,
            0, 40, 3, /* 3603: struct.asn1_object_st */
            	129, 0,
            	129, 8,
            	134, 24,
            1, 8, 1, /* 3612: pointer.struct.stack_st_POLICYQUALINFO */
            	3617, 0,
            0, 32, 2, /* 3617: struct.stack_st_fake_POLICYQUALINFO */
            	3624, 8,
            	365, 24,
            8884099, 8, 2, /* 3624: pointer_to_array_of_pointers_to_stack */
            	3631, 0,
            	362, 20,
            0, 8, 1, /* 3631: pointer.POLICYQUALINFO */
            	1048, 0,
            1, 8, 1, /* 3636: pointer.struct.stack_st_ASN1_OBJECT */
            	3641, 0,
            0, 32, 2, /* 3641: struct.stack_st_fake_ASN1_OBJECT */
            	3648, 8,
            	365, 24,
            8884099, 8, 2, /* 3648: pointer_to_array_of_pointers_to_stack */
            	3655, 0,
            	362, 20,
            0, 8, 1, /* 3655: pointer.ASN1_OBJECT */
            	1306, 0,
            1, 8, 1, /* 3660: pointer.struct.stack_st_X509_POLICY_DATA */
            	3665, 0,
            0, 32, 2, /* 3665: struct.stack_st_fake_X509_POLICY_DATA */
            	3672, 8,
            	365, 24,
            8884099, 8, 2, /* 3672: pointer_to_array_of_pointers_to_stack */
            	3679, 0,
            	362, 20,
            0, 8, 1, /* 3679: pointer.X509_POLICY_DATA */
            	996, 0,
            1, 8, 1, /* 3684: pointer.struct.NAME_CONSTRAINTS_st */
            	3689, 0,
            0, 16, 2, /* 3689: struct.NAME_CONSTRAINTS_st */
            	3696, 0,
            	3696, 8,
            1, 8, 1, /* 3696: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3701, 0,
            0, 32, 2, /* 3701: struct.stack_st_fake_GENERAL_SUBTREE */
            	3708, 8,
            	365, 24,
            8884099, 8, 2, /* 3708: pointer_to_array_of_pointers_to_stack */
            	3715, 0,
            	362, 20,
            0, 8, 1, /* 3715: pointer.GENERAL_SUBTREE */
            	3720, 0,
            0, 0, 1, /* 3720: GENERAL_SUBTREE */
            	3725, 0,
            0, 24, 3, /* 3725: struct.GENERAL_SUBTREE_st */
            	3734, 0,
            	3866, 8,
            	3866, 16,
            1, 8, 1, /* 3734: pointer.struct.GENERAL_NAME_st */
            	3739, 0,
            0, 16, 1, /* 3739: struct.GENERAL_NAME_st */
            	3744, 8,
            0, 8, 15, /* 3744: union.unknown */
            	98, 0,
            	3777, 0,
            	3896, 0,
            	3896, 0,
            	3803, 0,
            	3936, 0,
            	3984, 0,
            	3896, 0,
            	3881, 0,
            	3789, 0,
            	3881, 0,
            	3936, 0,
            	3896, 0,
            	3789, 0,
            	3803, 0,
            1, 8, 1, /* 3777: pointer.struct.otherName_st */
            	3782, 0,
            0, 16, 2, /* 3782: struct.otherName_st */
            	3789, 0,
            	3803, 8,
            1, 8, 1, /* 3789: pointer.struct.asn1_object_st */
            	3794, 0,
            0, 40, 3, /* 3794: struct.asn1_object_st */
            	129, 0,
            	129, 8,
            	134, 24,
            1, 8, 1, /* 3803: pointer.struct.asn1_type_st */
            	3808, 0,
            0, 16, 1, /* 3808: struct.asn1_type_st */
            	3813, 8,
            0, 8, 20, /* 3813: union.unknown */
            	98, 0,
            	3856, 0,
            	3789, 0,
            	3866, 0,
            	3871, 0,
            	3876, 0,
            	3881, 0,
            	3886, 0,
            	3891, 0,
            	3896, 0,
            	3901, 0,
            	3906, 0,
            	3911, 0,
            	3916, 0,
            	3921, 0,
            	3926, 0,
            	3931, 0,
            	3856, 0,
            	3856, 0,
            	1274, 0,
            1, 8, 1, /* 3856: pointer.struct.asn1_string_st */
            	3861, 0,
            0, 24, 1, /* 3861: struct.asn1_string_st */
            	205, 8,
            1, 8, 1, /* 3866: pointer.struct.asn1_string_st */
            	3861, 0,
            1, 8, 1, /* 3871: pointer.struct.asn1_string_st */
            	3861, 0,
            1, 8, 1, /* 3876: pointer.struct.asn1_string_st */
            	3861, 0,
            1, 8, 1, /* 3881: pointer.struct.asn1_string_st */
            	3861, 0,
            1, 8, 1, /* 3886: pointer.struct.asn1_string_st */
            	3861, 0,
            1, 8, 1, /* 3891: pointer.struct.asn1_string_st */
            	3861, 0,
            1, 8, 1, /* 3896: pointer.struct.asn1_string_st */
            	3861, 0,
            1, 8, 1, /* 3901: pointer.struct.asn1_string_st */
            	3861, 0,
            1, 8, 1, /* 3906: pointer.struct.asn1_string_st */
            	3861, 0,
            1, 8, 1, /* 3911: pointer.struct.asn1_string_st */
            	3861, 0,
            1, 8, 1, /* 3916: pointer.struct.asn1_string_st */
            	3861, 0,
            1, 8, 1, /* 3921: pointer.struct.asn1_string_st */
            	3861, 0,
            1, 8, 1, /* 3926: pointer.struct.asn1_string_st */
            	3861, 0,
            1, 8, 1, /* 3931: pointer.struct.asn1_string_st */
            	3861, 0,
            1, 8, 1, /* 3936: pointer.struct.X509_name_st */
            	3941, 0,
            0, 40, 3, /* 3941: struct.X509_name_st */
            	3950, 0,
            	3974, 16,
            	205, 24,
            1, 8, 1, /* 3950: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3955, 0,
            0, 32, 2, /* 3955: struct.stack_st_fake_X509_NAME_ENTRY */
            	3962, 8,
            	365, 24,
            8884099, 8, 2, /* 3962: pointer_to_array_of_pointers_to_stack */
            	3969, 0,
            	362, 20,
            0, 8, 1, /* 3969: pointer.X509_NAME_ENTRY */
            	326, 0,
            1, 8, 1, /* 3974: pointer.struct.buf_mem_st */
            	3979, 0,
            0, 24, 1, /* 3979: struct.buf_mem_st */
            	98, 8,
            1, 8, 1, /* 3984: pointer.struct.EDIPartyName_st */
            	3989, 0,
            0, 16, 2, /* 3989: struct.EDIPartyName_st */
            	3856, 0,
            	3856, 8,
            1, 8, 1, /* 3996: pointer.struct.x509_st */
            	1638, 0,
            0, 32, 3, /* 4001: struct.X509_POLICY_LEVEL_st */
            	3996, 0,
            	4010, 8,
            	1403, 16,
            1, 8, 1, /* 4010: pointer.struct.stack_st_X509_POLICY_NODE */
            	4015, 0,
            0, 32, 2, /* 4015: struct.stack_st_fake_X509_POLICY_NODE */
            	4022, 8,
            	365, 24,
            8884099, 8, 2, /* 4022: pointer_to_array_of_pointers_to_stack */
            	4029, 0,
            	362, 20,
            0, 8, 1, /* 4029: pointer.X509_POLICY_NODE */
            	1408, 0,
            1, 8, 1, /* 4034: pointer.struct.X509_POLICY_LEVEL_st */
            	4001, 0,
            0, 48, 4, /* 4039: struct.X509_POLICY_TREE_st */
            	4034, 0,
            	972, 16,
            	4010, 24,
            	4010, 32,
            1, 8, 1, /* 4050: pointer.struct.asn1_string_st */
            	1151, 0,
            0, 24, 1, /* 4055: struct.ASN1_ENCODING_st */
            	205, 0,
            1, 8, 1, /* 4060: pointer.struct.buf_mem_st */
            	4065, 0,
            0, 24, 1, /* 4065: struct.buf_mem_st */
            	98, 8,
            1, 8, 1, /* 4070: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4075, 0,
            0, 32, 2, /* 4075: struct.stack_st_fake_X509_NAME_ENTRY */
            	4082, 8,
            	365, 24,
            8884099, 8, 2, /* 4082: pointer_to_array_of_pointers_to_stack */
            	4089, 0,
            	362, 20,
            0, 8, 1, /* 4089: pointer.X509_NAME_ENTRY */
            	326, 0,
            1, 8, 1, /* 4094: pointer.struct.X509_crl_info_st */
            	4099, 0,
            0, 80, 8, /* 4099: struct.X509_crl_info_st */
            	4118, 0,
            	4123, 8,
            	4128, 16,
            	4142, 24,
            	4142, 32,
            	4147, 40,
            	4171, 48,
            	4055, 56,
            1, 8, 1, /* 4118: pointer.struct.asn1_string_st */
            	1151, 0,
            1, 8, 1, /* 4123: pointer.struct.X509_algor_st */
            	477, 0,
            1, 8, 1, /* 4128: pointer.struct.X509_name_st */
            	4133, 0,
            0, 40, 3, /* 4133: struct.X509_name_st */
            	4070, 0,
            	4060, 16,
            	205, 24,
            1, 8, 1, /* 4142: pointer.struct.asn1_string_st */
            	1151, 0,
            1, 8, 1, /* 4147: pointer.struct.stack_st_X509_REVOKED */
            	4152, 0,
            0, 32, 2, /* 4152: struct.stack_st_fake_X509_REVOKED */
            	4159, 8,
            	365, 24,
            8884099, 8, 2, /* 4159: pointer_to_array_of_pointers_to_stack */
            	4166, 0,
            	362, 20,
            0, 8, 1, /* 4166: pointer.X509_REVOKED */
            	668, 0,
            1, 8, 1, /* 4171: pointer.struct.stack_st_X509_EXTENSION */
            	4176, 0,
            0, 32, 2, /* 4176: struct.stack_st_fake_X509_EXTENSION */
            	4183, 8,
            	365, 24,
            8884099, 8, 2, /* 4183: pointer_to_array_of_pointers_to_stack */
            	4190, 0,
            	362, 20,
            0, 8, 1, /* 4190: pointer.X509_EXTENSION */
            	723, 0,
            0, 120, 10, /* 4195: struct.X509_crl_st */
            	4094, 0,
            	4123, 8,
            	4050, 16,
            	4218, 32,
            	4223, 40,
            	4118, 56,
            	4118, 64,
            	898, 96,
            	944, 104,
            	969, 112,
            1, 8, 1, /* 4218: pointer.struct.AUTHORITY_KEYID_st */
            	850, 0,
            1, 8, 1, /* 4223: pointer.struct.ISSUING_DIST_POINT_st */
            	5, 0,
            0, 0, 1, /* 4228: X509_CRL */
            	4195, 0,
            1, 8, 1, /* 4233: pointer.struct.stack_st_X509_CRL */
            	4238, 0,
            0, 32, 2, /* 4238: struct.stack_st_fake_X509_CRL */
            	4245, 8,
            	365, 24,
            8884099, 8, 2, /* 4245: pointer_to_array_of_pointers_to_stack */
            	4252, 0,
            	362, 20,
            0, 8, 1, /* 4252: pointer.X509_CRL */
            	4228, 0,
            1, 8, 1, /* 4257: pointer.struct.stack_st_X509_ALGOR */
            	4262, 0,
            0, 32, 2, /* 4262: struct.stack_st_fake_X509_ALGOR */
            	4269, 8,
            	365, 24,
            8884099, 8, 2, /* 4269: pointer_to_array_of_pointers_to_stack */
            	4276, 0,
            	362, 20,
            0, 8, 1, /* 4276: pointer.X509_ALGOR */
            	1482, 0,
            1, 8, 1, /* 4281: pointer.struct.asn1_string_st */
            	4286, 0,
            0, 24, 1, /* 4286: struct.asn1_string_st */
            	205, 8,
            1, 8, 1, /* 4291: pointer.struct.stack_st_ASN1_OBJECT */
            	4296, 0,
            0, 32, 2, /* 4296: struct.stack_st_fake_ASN1_OBJECT */
            	4303, 8,
            	365, 24,
            8884099, 8, 2, /* 4303: pointer_to_array_of_pointers_to_stack */
            	4310, 0,
            	362, 20,
            0, 8, 1, /* 4310: pointer.ASN1_OBJECT */
            	1306, 0,
            1, 8, 1, /* 4315: pointer.struct.x509_cert_aux_st */
            	4320, 0,
            0, 40, 5, /* 4320: struct.x509_cert_aux_st */
            	4291, 0,
            	4291, 8,
            	4281, 16,
            	4333, 24,
            	4257, 32,
            1, 8, 1, /* 4333: pointer.struct.asn1_string_st */
            	4286, 0,
            1, 8, 1, /* 4338: pointer.struct.stack_st_DIST_POINT */
            	4343, 0,
            0, 32, 2, /* 4343: struct.stack_st_fake_DIST_POINT */
            	4350, 8,
            	365, 24,
            8884099, 8, 2, /* 4350: pointer_to_array_of_pointers_to_stack */
            	4357, 0,
            	362, 20,
            0, 8, 1, /* 4357: pointer.DIST_POINT */
            	1540, 0,
            1, 8, 1, /* 4362: pointer.struct.AUTHORITY_KEYID_st */
            	850, 0,
            1, 8, 1, /* 4367: pointer.struct.stack_st_X509_EXTENSION */
            	4372, 0,
            0, 32, 2, /* 4372: struct.stack_st_fake_X509_EXTENSION */
            	4379, 8,
            	365, 24,
            8884099, 8, 2, /* 4379: pointer_to_array_of_pointers_to_stack */
            	4386, 0,
            	362, 20,
            0, 8, 1, /* 4386: pointer.X509_EXTENSION */
            	723, 0,
            1, 8, 1, /* 4391: pointer.struct.asn1_string_st */
            	4286, 0,
            1, 8, 1, /* 4396: pointer.struct.X509_val_st */
            	4401, 0,
            0, 16, 2, /* 4401: struct.X509_val_st */
            	4391, 0,
            	4391, 8,
            1, 8, 1, /* 4408: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4413, 0,
            0, 32, 2, /* 4413: struct.stack_st_fake_X509_NAME_ENTRY */
            	4420, 8,
            	365, 24,
            8884099, 8, 2, /* 4420: pointer_to_array_of_pointers_to_stack */
            	4427, 0,
            	362, 20,
            0, 8, 1, /* 4427: pointer.X509_NAME_ENTRY */
            	326, 0,
            1, 8, 1, /* 4432: pointer.struct.X509_name_st */
            	4437, 0,
            0, 40, 3, /* 4437: struct.X509_name_st */
            	4408, 0,
            	4446, 16,
            	205, 24,
            1, 8, 1, /* 4446: pointer.struct.buf_mem_st */
            	4451, 0,
            0, 24, 1, /* 4451: struct.buf_mem_st */
            	98, 8,
            1, 8, 1, /* 4456: pointer.struct.X509_algor_st */
            	477, 0,
            1, 8, 1, /* 4461: pointer.struct.x509_cinf_st */
            	4466, 0,
            0, 104, 11, /* 4466: struct.x509_cinf_st */
            	4491, 0,
            	4491, 8,
            	4456, 16,
            	4432, 24,
            	4396, 32,
            	4432, 40,
            	4496, 48,
            	4501, 56,
            	4501, 64,
            	4367, 72,
            	4506, 80,
            1, 8, 1, /* 4491: pointer.struct.asn1_string_st */
            	4286, 0,
            1, 8, 1, /* 4496: pointer.struct.X509_pubkey_st */
            	1715, 0,
            1, 8, 1, /* 4501: pointer.struct.asn1_string_st */
            	4286, 0,
            0, 24, 1, /* 4506: struct.ASN1_ENCODING_st */
            	205, 0,
            0, 184, 12, /* 4511: struct.x509_st */
            	4461, 0,
            	4456, 8,
            	4501, 16,
            	98, 32,
            	2481, 40,
            	4333, 104,
            	4362, 112,
            	4538, 120,
            	4338, 128,
            	759, 136,
            	4543, 144,
            	4315, 176,
            1, 8, 1, /* 4538: pointer.struct.X509_POLICY_CACHE_st */
            	3577, 0,
            1, 8, 1, /* 4543: pointer.struct.NAME_CONSTRAINTS_st */
            	3689, 0,
            0, 0, 1, /* 4548: X509 */
            	4511, 0,
            1, 8, 1, /* 4553: pointer.struct.asn1_string_st */
            	443, 0,
            0, 40, 5, /* 4558: struct.x509_cert_aux_st */
            	4571, 0,
            	4571, 8,
            	4553, 16,
            	4595, 24,
            	4600, 32,
            1, 8, 1, /* 4571: pointer.struct.stack_st_ASN1_OBJECT */
            	4576, 0,
            0, 32, 2, /* 4576: struct.stack_st_fake_ASN1_OBJECT */
            	4583, 8,
            	365, 24,
            8884099, 8, 2, /* 4583: pointer_to_array_of_pointers_to_stack */
            	4590, 0,
            	362, 20,
            0, 8, 1, /* 4590: pointer.ASN1_OBJECT */
            	1306, 0,
            1, 8, 1, /* 4595: pointer.struct.asn1_string_st */
            	443, 0,
            1, 8, 1, /* 4600: pointer.struct.stack_st_X509_ALGOR */
            	4605, 0,
            0, 32, 2, /* 4605: struct.stack_st_fake_X509_ALGOR */
            	4612, 8,
            	365, 24,
            8884099, 8, 2, /* 4612: pointer_to_array_of_pointers_to_stack */
            	4619, 0,
            	362, 20,
            0, 8, 1, /* 4619: pointer.X509_ALGOR */
            	1482, 0,
            1, 8, 1, /* 4624: pointer.struct.x509_cert_aux_st */
            	4558, 0,
            1, 8, 1, /* 4629: pointer.struct.stack_st_GENERAL_NAME */
            	4634, 0,
            0, 32, 2, /* 4634: struct.stack_st_fake_GENERAL_NAME */
            	4641, 8,
            	365, 24,
            8884099, 8, 2, /* 4641: pointer_to_array_of_pointers_to_stack */
            	4648, 0,
            	362, 20,
            0, 8, 1, /* 4648: pointer.GENERAL_NAME */
            	55, 0,
            1, 8, 1, /* 4653: pointer.struct.stack_st_DIST_POINT */
            	4658, 0,
            0, 32, 2, /* 4658: struct.stack_st_fake_DIST_POINT */
            	4665, 8,
            	365, 24,
            8884099, 8, 2, /* 4665: pointer_to_array_of_pointers_to_stack */
            	4672, 0,
            	362, 20,
            0, 8, 1, /* 4672: pointer.DIST_POINT */
            	1540, 0,
            1, 8, 1, /* 4677: pointer.struct.X509_pubkey_st */
            	1715, 0,
            1, 8, 1, /* 4682: pointer.struct.X509_val_st */
            	4687, 0,
            0, 16, 2, /* 4687: struct.X509_val_st */
            	639, 0,
            	639, 8,
            0, 184, 12, /* 4694: struct.x509_st */
            	4721, 0,
            	472, 8,
            	438, 16,
            	98, 32,
            	4751, 40,
            	4595, 104,
            	845, 112,
            	4773, 120,
            	4653, 128,
            	4629, 136,
            	4778, 144,
            	4624, 176,
            1, 8, 1, /* 4721: pointer.struct.x509_cinf_st */
            	4726, 0,
            0, 104, 11, /* 4726: struct.x509_cinf_st */
            	467, 0,
            	467, 8,
            	472, 16,
            	414, 24,
            	4682, 32,
            	414, 40,
            	4677, 48,
            	438, 56,
            	438, 64,
            	783, 72,
            	807, 80,
            0, 16, 1, /* 4751: struct.crypto_ex_data_st */
            	4756, 0,
            1, 8, 1, /* 4756: pointer.struct.stack_st_void */
            	4761, 0,
            0, 32, 1, /* 4761: struct.stack_st_void */
            	4766, 0,
            0, 32, 2, /* 4766: struct.stack_st */
            	939, 8,
            	365, 24,
            1, 8, 1, /* 4773: pointer.struct.X509_POLICY_CACHE_st */
            	3577, 0,
            1, 8, 1, /* 4778: pointer.struct.NAME_CONSTRAINTS_st */
            	3689, 0,
            8884097, 8, 0, /* 4783: pointer.func */
            8884097, 8, 0, /* 4786: pointer.func */
            8884097, 8, 0, /* 4789: pointer.func */
            8884097, 8, 0, /* 4792: pointer.func */
            8884097, 8, 0, /* 4795: pointer.func */
            8884097, 8, 0, /* 4798: pointer.func */
            8884097, 8, 0, /* 4801: pointer.func */
            8884097, 8, 0, /* 4804: pointer.func */
            8884097, 8, 0, /* 4807: pointer.func */
            8884097, 8, 0, /* 4810: pointer.func */
            1, 8, 1, /* 4813: pointer.struct.X509_VERIFY_PARAM_st */
            	4818, 0,
            0, 56, 2, /* 4818: struct.X509_VERIFY_PARAM_st */
            	98, 0,
            	4825, 48,
            1, 8, 1, /* 4825: pointer.struct.stack_st_ASN1_OBJECT */
            	4830, 0,
            0, 32, 2, /* 4830: struct.stack_st_fake_ASN1_OBJECT */
            	4837, 8,
            	365, 24,
            8884099, 8, 2, /* 4837: pointer_to_array_of_pointers_to_stack */
            	4844, 0,
            	362, 20,
            0, 8, 1, /* 4844: pointer.ASN1_OBJECT */
            	1306, 0,
            1, 8, 1, /* 4849: pointer.struct.stack_st_X509_LOOKUP */
            	4854, 0,
            0, 32, 2, /* 4854: struct.stack_st_fake_X509_LOOKUP */
            	4861, 8,
            	365, 24,
            8884099, 8, 2, /* 4861: pointer_to_array_of_pointers_to_stack */
            	4868, 0,
            	362, 20,
            0, 8, 1, /* 4868: pointer.X509_LOOKUP */
            	4873, 0,
            0, 0, 1, /* 4873: X509_LOOKUP */
            	4878, 0,
            0, 32, 3, /* 4878: struct.x509_lookup_st */
            	4887, 8,
            	98, 16,
            	4936, 24,
            1, 8, 1, /* 4887: pointer.struct.x509_lookup_method_st */
            	4892, 0,
            0, 80, 10, /* 4892: struct.x509_lookup_method_st */
            	129, 0,
            	4915, 8,
            	4918, 16,
            	4915, 24,
            	4915, 32,
            	4921, 40,
            	4924, 48,
            	4927, 56,
            	4930, 64,
            	4933, 72,
            8884097, 8, 0, /* 4915: pointer.func */
            8884097, 8, 0, /* 4918: pointer.func */
            8884097, 8, 0, /* 4921: pointer.func */
            8884097, 8, 0, /* 4924: pointer.func */
            8884097, 8, 0, /* 4927: pointer.func */
            8884097, 8, 0, /* 4930: pointer.func */
            8884097, 8, 0, /* 4933: pointer.func */
            1, 8, 1, /* 4936: pointer.struct.x509_store_st */
            	4941, 0,
            0, 144, 15, /* 4941: struct.x509_store_st */
            	4974, 8,
            	4849, 16,
            	4813, 24,
            	4810, 32,
            	5481, 40,
            	5484, 48,
            	4807, 56,
            	4810, 64,
            	5487, 72,
            	4804, 80,
            	5490, 88,
            	4801, 96,
            	4798, 104,
            	4810, 112,
            	5200, 120,
            1, 8, 1, /* 4974: pointer.struct.stack_st_X509_OBJECT */
            	4979, 0,
            0, 32, 2, /* 4979: struct.stack_st_fake_X509_OBJECT */
            	4986, 8,
            	365, 24,
            8884099, 8, 2, /* 4986: pointer_to_array_of_pointers_to_stack */
            	4993, 0,
            	362, 20,
            0, 8, 1, /* 4993: pointer.X509_OBJECT */
            	4998, 0,
            0, 0, 1, /* 4998: X509_OBJECT */
            	5003, 0,
            0, 16, 1, /* 5003: struct.x509_object_st */
            	5008, 8,
            0, 8, 4, /* 5008: union.unknown */
            	98, 0,
            	5019, 0,
            	5327, 0,
            	5403, 0,
            1, 8, 1, /* 5019: pointer.struct.x509_st */
            	5024, 0,
            0, 184, 12, /* 5024: struct.x509_st */
            	5051, 0,
            	5091, 8,
            	5166, 16,
            	98, 32,
            	5200, 40,
            	5222, 104,
            	4218, 112,
            	4773, 120,
            	5227, 128,
            	5251, 136,
            	5275, 144,
            	5280, 176,
            1, 8, 1, /* 5051: pointer.struct.x509_cinf_st */
            	5056, 0,
            0, 104, 11, /* 5056: struct.x509_cinf_st */
            	5081, 0,
            	5081, 8,
            	5091, 16,
            	5096, 24,
            	5144, 32,
            	5096, 40,
            	5161, 48,
            	5166, 56,
            	5166, 64,
            	5171, 72,
            	5195, 80,
            1, 8, 1, /* 5081: pointer.struct.asn1_string_st */
            	5086, 0,
            0, 24, 1, /* 5086: struct.asn1_string_st */
            	205, 8,
            1, 8, 1, /* 5091: pointer.struct.X509_algor_st */
            	477, 0,
            1, 8, 1, /* 5096: pointer.struct.X509_name_st */
            	5101, 0,
            0, 40, 3, /* 5101: struct.X509_name_st */
            	5110, 0,
            	5134, 16,
            	205, 24,
            1, 8, 1, /* 5110: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5115, 0,
            0, 32, 2, /* 5115: struct.stack_st_fake_X509_NAME_ENTRY */
            	5122, 8,
            	365, 24,
            8884099, 8, 2, /* 5122: pointer_to_array_of_pointers_to_stack */
            	5129, 0,
            	362, 20,
            0, 8, 1, /* 5129: pointer.X509_NAME_ENTRY */
            	326, 0,
            1, 8, 1, /* 5134: pointer.struct.buf_mem_st */
            	5139, 0,
            0, 24, 1, /* 5139: struct.buf_mem_st */
            	98, 8,
            1, 8, 1, /* 5144: pointer.struct.X509_val_st */
            	5149, 0,
            0, 16, 2, /* 5149: struct.X509_val_st */
            	5156, 0,
            	5156, 8,
            1, 8, 1, /* 5156: pointer.struct.asn1_string_st */
            	5086, 0,
            1, 8, 1, /* 5161: pointer.struct.X509_pubkey_st */
            	1715, 0,
            1, 8, 1, /* 5166: pointer.struct.asn1_string_st */
            	5086, 0,
            1, 8, 1, /* 5171: pointer.struct.stack_st_X509_EXTENSION */
            	5176, 0,
            0, 32, 2, /* 5176: struct.stack_st_fake_X509_EXTENSION */
            	5183, 8,
            	365, 24,
            8884099, 8, 2, /* 5183: pointer_to_array_of_pointers_to_stack */
            	5190, 0,
            	362, 20,
            0, 8, 1, /* 5190: pointer.X509_EXTENSION */
            	723, 0,
            0, 24, 1, /* 5195: struct.ASN1_ENCODING_st */
            	205, 0,
            0, 16, 1, /* 5200: struct.crypto_ex_data_st */
            	5205, 0,
            1, 8, 1, /* 5205: pointer.struct.stack_st_void */
            	5210, 0,
            0, 32, 1, /* 5210: struct.stack_st_void */
            	5215, 0,
            0, 32, 2, /* 5215: struct.stack_st */
            	939, 8,
            	365, 24,
            1, 8, 1, /* 5222: pointer.struct.asn1_string_st */
            	5086, 0,
            1, 8, 1, /* 5227: pointer.struct.stack_st_DIST_POINT */
            	5232, 0,
            0, 32, 2, /* 5232: struct.stack_st_fake_DIST_POINT */
            	5239, 8,
            	365, 24,
            8884099, 8, 2, /* 5239: pointer_to_array_of_pointers_to_stack */
            	5246, 0,
            	362, 20,
            0, 8, 1, /* 5246: pointer.DIST_POINT */
            	1540, 0,
            1, 8, 1, /* 5251: pointer.struct.stack_st_GENERAL_NAME */
            	5256, 0,
            0, 32, 2, /* 5256: struct.stack_st_fake_GENERAL_NAME */
            	5263, 8,
            	365, 24,
            8884099, 8, 2, /* 5263: pointer_to_array_of_pointers_to_stack */
            	5270, 0,
            	362, 20,
            0, 8, 1, /* 5270: pointer.GENERAL_NAME */
            	55, 0,
            1, 8, 1, /* 5275: pointer.struct.NAME_CONSTRAINTS_st */
            	3689, 0,
            1, 8, 1, /* 5280: pointer.struct.x509_cert_aux_st */
            	5285, 0,
            0, 40, 5, /* 5285: struct.x509_cert_aux_st */
            	4825, 0,
            	4825, 8,
            	5298, 16,
            	5222, 24,
            	5303, 32,
            1, 8, 1, /* 5298: pointer.struct.asn1_string_st */
            	5086, 0,
            1, 8, 1, /* 5303: pointer.struct.stack_st_X509_ALGOR */
            	5308, 0,
            0, 32, 2, /* 5308: struct.stack_st_fake_X509_ALGOR */
            	5315, 8,
            	365, 24,
            8884099, 8, 2, /* 5315: pointer_to_array_of_pointers_to_stack */
            	5322, 0,
            	362, 20,
            0, 8, 1, /* 5322: pointer.X509_ALGOR */
            	1482, 0,
            1, 8, 1, /* 5327: pointer.struct.X509_crl_st */
            	5332, 0,
            0, 120, 10, /* 5332: struct.X509_crl_st */
            	5355, 0,
            	5091, 8,
            	5166, 16,
            	4218, 32,
            	4223, 40,
            	5081, 56,
            	5081, 64,
            	898, 96,
            	944, 104,
            	969, 112,
            1, 8, 1, /* 5355: pointer.struct.X509_crl_info_st */
            	5360, 0,
            0, 80, 8, /* 5360: struct.X509_crl_info_st */
            	5081, 0,
            	5091, 8,
            	5096, 16,
            	5156, 24,
            	5156, 32,
            	5379, 40,
            	5171, 48,
            	5195, 56,
            1, 8, 1, /* 5379: pointer.struct.stack_st_X509_REVOKED */
            	5384, 0,
            0, 32, 2, /* 5384: struct.stack_st_fake_X509_REVOKED */
            	5391, 8,
            	365, 24,
            8884099, 8, 2, /* 5391: pointer_to_array_of_pointers_to_stack */
            	5398, 0,
            	362, 20,
            0, 8, 1, /* 5398: pointer.X509_REVOKED */
            	668, 0,
            1, 8, 1, /* 5403: pointer.struct.evp_pkey_st */
            	5408, 0,
            0, 56, 4, /* 5408: struct.evp_pkey_st */
            	5419, 16,
            	2314, 24,
            	5424, 32,
            	5457, 48,
            1, 8, 1, /* 5419: pointer.struct.evp_pkey_asn1_method_st */
            	1760, 0,
            0, 8, 5, /* 5424: union.unknown */
            	98, 0,
            	5437, 0,
            	5442, 0,
            	5447, 0,
            	5452, 0,
            1, 8, 1, /* 5437: pointer.struct.rsa_st */
            	2222, 0,
            1, 8, 1, /* 5442: pointer.struct.dsa_st */
            	2432, 0,
            1, 8, 1, /* 5447: pointer.struct.dh_st */
            	2559, 0,
            1, 8, 1, /* 5452: pointer.struct.ec_key_st */
            	2673, 0,
            1, 8, 1, /* 5457: pointer.struct.stack_st_X509_ATTRIBUTE */
            	5462, 0,
            0, 32, 2, /* 5462: struct.stack_st_fake_X509_ATTRIBUTE */
            	5469, 8,
            	365, 24,
            8884099, 8, 2, /* 5469: pointer_to_array_of_pointers_to_stack */
            	5476, 0,
            	362, 20,
            0, 8, 1, /* 5476: pointer.X509_ATTRIBUTE */
            	3180, 0,
            8884097, 8, 0, /* 5481: pointer.func */
            8884097, 8, 0, /* 5484: pointer.func */
            8884097, 8, 0, /* 5487: pointer.func */
            8884097, 8, 0, /* 5490: pointer.func */
            0, 144, 15, /* 5493: struct.x509_store_st */
            	5526, 8,
            	5550, 16,
            	5574, 24,
            	4795, 32,
            	5586, 40,
            	5589, 48,
            	4792, 56,
            	4795, 64,
            	5592, 72,
            	4789, 80,
            	4786, 88,
            	4783, 96,
            	5595, 104,
            	4795, 112,
            	4751, 120,
            1, 8, 1, /* 5526: pointer.struct.stack_st_X509_OBJECT */
            	5531, 0,
            0, 32, 2, /* 5531: struct.stack_st_fake_X509_OBJECT */
            	5538, 8,
            	365, 24,
            8884099, 8, 2, /* 5538: pointer_to_array_of_pointers_to_stack */
            	5545, 0,
            	362, 20,
            0, 8, 1, /* 5545: pointer.X509_OBJECT */
            	4998, 0,
            1, 8, 1, /* 5550: pointer.struct.stack_st_X509_LOOKUP */
            	5555, 0,
            0, 32, 2, /* 5555: struct.stack_st_fake_X509_LOOKUP */
            	5562, 8,
            	365, 24,
            8884099, 8, 2, /* 5562: pointer_to_array_of_pointers_to_stack */
            	5569, 0,
            	362, 20,
            0, 8, 1, /* 5569: pointer.X509_LOOKUP */
            	4873, 0,
            1, 8, 1, /* 5574: pointer.struct.X509_VERIFY_PARAM_st */
            	5579, 0,
            0, 56, 2, /* 5579: struct.X509_VERIFY_PARAM_st */
            	98, 0,
            	4571, 48,
            8884097, 8, 0, /* 5586: pointer.func */
            8884097, 8, 0, /* 5589: pointer.func */
            8884097, 8, 0, /* 5592: pointer.func */
            8884097, 8, 0, /* 5595: pointer.func */
            1, 8, 1, /* 5598: pointer.struct.x509_store_st */
            	5493, 0,
            1, 8, 1, /* 5603: pointer.struct.x509_st */
            	4694, 0,
            1, 8, 1, /* 5608: pointer.struct.x509_store_ctx_st */
            	5613, 0,
            0, 248, 25, /* 5613: struct.x509_store_ctx_st */
            	5598, 0,
            	5603, 16,
            	5666, 24,
            	4233, 32,
            	5574, 40,
            	969, 48,
            	4795, 56,
            	5586, 64,
            	5589, 72,
            	4792, 80,
            	4795, 88,
            	5592, 96,
            	4789, 104,
            	4786, 112,
            	4795, 120,
            	4783, 128,
            	5595, 136,
            	4795, 144,
            	5666, 160,
            	5690, 168,
            	5603, 192,
            	5603, 200,
            	817, 208,
            	5608, 224,
            	4751, 232,
            1, 8, 1, /* 5666: pointer.struct.stack_st_X509 */
            	5671, 0,
            0, 32, 2, /* 5671: struct.stack_st_fake_X509 */
            	5678, 8,
            	365, 24,
            8884099, 8, 2, /* 5678: pointer_to_array_of_pointers_to_stack */
            	5685, 0,
            	362, 20,
            0, 8, 1, /* 5685: pointer.X509 */
            	4548, 0,
            1, 8, 1, /* 5690: pointer.struct.X509_POLICY_TREE_st */
            	4039, 0,
            0, 1, 0, /* 5695: char */
        },
        .arg_entity_index = { 5608, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509_STORE_CTX * new_arg_a = *((X509_STORE_CTX * *)new_args->args[0]);

    void (*orig_X509_STORE_CTX_cleanup)(X509_STORE_CTX *);
    orig_X509_STORE_CTX_cleanup = dlsym(RTLD_NEXT, "X509_STORE_CTX_cleanup");
    (*orig_X509_STORE_CTX_cleanup)(new_arg_a);

    syscall(889);

}

