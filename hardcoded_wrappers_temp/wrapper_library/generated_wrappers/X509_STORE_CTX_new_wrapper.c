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

X509_STORE_CTX * bb_X509_STORE_CTX_new(void);

X509_STORE_CTX * X509_STORE_CTX_new(void) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_STORE_CTX_new called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_STORE_CTX_new();
    else {
        X509_STORE_CTX * (*orig_X509_STORE_CTX_new)(void);
        orig_X509_STORE_CTX_new = dlsym(RTLD_NEXT, "X509_STORE_CTX_new");
        return orig_X509_STORE_CTX_new();
    }
}

X509_STORE_CTX * bb_X509_STORE_CTX_new(void) 
{
    X509_STORE_CTX * ret;

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
            1, 8, 1, /* 448: pointer.struct.stack_st_X509_REVOKED */
            	453, 0,
            0, 32, 2, /* 453: struct.stack_st_fake_X509_REVOKED */
            	460, 8,
            	365, 24,
            8884099, 8, 2, /* 460: pointer_to_array_of_pointers_to_stack */
            	467, 0,
            	362, 20,
            0, 8, 1, /* 467: pointer.X509_REVOKED */
            	472, 0,
            0, 0, 1, /* 472: X509_REVOKED */
            	477, 0,
            0, 40, 4, /* 477: struct.x509_revoked_st */
            	488, 0,
            	498, 8,
            	503, 16,
            	563, 24,
            1, 8, 1, /* 488: pointer.struct.asn1_string_st */
            	493, 0,
            0, 24, 1, /* 493: struct.asn1_string_st */
            	205, 8,
            1, 8, 1, /* 498: pointer.struct.asn1_string_st */
            	493, 0,
            1, 8, 1, /* 503: pointer.struct.stack_st_X509_EXTENSION */
            	508, 0,
            0, 32, 2, /* 508: struct.stack_st_fake_X509_EXTENSION */
            	515, 8,
            	365, 24,
            8884099, 8, 2, /* 515: pointer_to_array_of_pointers_to_stack */
            	522, 0,
            	362, 20,
            0, 8, 1, /* 522: pointer.X509_EXTENSION */
            	527, 0,
            0, 0, 1, /* 527: X509_EXTENSION */
            	532, 0,
            0, 24, 2, /* 532: struct.X509_extension_st */
            	539, 0,
            	553, 16,
            1, 8, 1, /* 539: pointer.struct.asn1_object_st */
            	544, 0,
            0, 40, 3, /* 544: struct.asn1_object_st */
            	129, 0,
            	129, 8,
            	134, 24,
            1, 8, 1, /* 553: pointer.struct.asn1_string_st */
            	558, 0,
            0, 24, 1, /* 558: struct.asn1_string_st */
            	205, 8,
            1, 8, 1, /* 563: pointer.struct.stack_st_GENERAL_NAME */
            	568, 0,
            0, 32, 2, /* 568: struct.stack_st_fake_GENERAL_NAME */
            	575, 8,
            	365, 24,
            8884099, 8, 2, /* 575: pointer_to_array_of_pointers_to_stack */
            	582, 0,
            	362, 20,
            0, 8, 1, /* 582: pointer.GENERAL_NAME */
            	55, 0,
            0, 80, 8, /* 587: struct.X509_crl_info_st */
            	606, 0,
            	616, 8,
            	783, 16,
            	831, 24,
            	831, 32,
            	448, 40,
            	836, 48,
            	860, 56,
            1, 8, 1, /* 606: pointer.struct.asn1_string_st */
            	611, 0,
            0, 24, 1, /* 611: struct.asn1_string_st */
            	205, 8,
            1, 8, 1, /* 616: pointer.struct.X509_algor_st */
            	621, 0,
            0, 16, 2, /* 621: struct.X509_algor_st */
            	628, 0,
            	642, 8,
            1, 8, 1, /* 628: pointer.struct.asn1_object_st */
            	633, 0,
            0, 40, 3, /* 633: struct.asn1_object_st */
            	129, 0,
            	129, 8,
            	134, 24,
            1, 8, 1, /* 642: pointer.struct.asn1_type_st */
            	647, 0,
            0, 16, 1, /* 647: struct.asn1_type_st */
            	652, 8,
            0, 8, 20, /* 652: union.unknown */
            	98, 0,
            	695, 0,
            	628, 0,
            	705, 0,
            	710, 0,
            	715, 0,
            	720, 0,
            	725, 0,
            	730, 0,
            	735, 0,
            	740, 0,
            	745, 0,
            	750, 0,
            	755, 0,
            	760, 0,
            	765, 0,
            	770, 0,
            	695, 0,
            	695, 0,
            	775, 0,
            1, 8, 1, /* 695: pointer.struct.asn1_string_st */
            	700, 0,
            0, 24, 1, /* 700: struct.asn1_string_st */
            	205, 8,
            1, 8, 1, /* 705: pointer.struct.asn1_string_st */
            	700, 0,
            1, 8, 1, /* 710: pointer.struct.asn1_string_st */
            	700, 0,
            1, 8, 1, /* 715: pointer.struct.asn1_string_st */
            	700, 0,
            1, 8, 1, /* 720: pointer.struct.asn1_string_st */
            	700, 0,
            1, 8, 1, /* 725: pointer.struct.asn1_string_st */
            	700, 0,
            1, 8, 1, /* 730: pointer.struct.asn1_string_st */
            	700, 0,
            1, 8, 1, /* 735: pointer.struct.asn1_string_st */
            	700, 0,
            1, 8, 1, /* 740: pointer.struct.asn1_string_st */
            	700, 0,
            1, 8, 1, /* 745: pointer.struct.asn1_string_st */
            	700, 0,
            1, 8, 1, /* 750: pointer.struct.asn1_string_st */
            	700, 0,
            1, 8, 1, /* 755: pointer.struct.asn1_string_st */
            	700, 0,
            1, 8, 1, /* 760: pointer.struct.asn1_string_st */
            	700, 0,
            1, 8, 1, /* 765: pointer.struct.asn1_string_st */
            	700, 0,
            1, 8, 1, /* 770: pointer.struct.asn1_string_st */
            	700, 0,
            1, 8, 1, /* 775: pointer.struct.ASN1_VALUE_st */
            	780, 0,
            0, 0, 0, /* 780: struct.ASN1_VALUE_st */
            1, 8, 1, /* 783: pointer.struct.X509_name_st */
            	788, 0,
            0, 40, 3, /* 788: struct.X509_name_st */
            	797, 0,
            	821, 16,
            	205, 24,
            1, 8, 1, /* 797: pointer.struct.stack_st_X509_NAME_ENTRY */
            	802, 0,
            0, 32, 2, /* 802: struct.stack_st_fake_X509_NAME_ENTRY */
            	809, 8,
            	365, 24,
            8884099, 8, 2, /* 809: pointer_to_array_of_pointers_to_stack */
            	816, 0,
            	362, 20,
            0, 8, 1, /* 816: pointer.X509_NAME_ENTRY */
            	326, 0,
            1, 8, 1, /* 821: pointer.struct.buf_mem_st */
            	826, 0,
            0, 24, 1, /* 826: struct.buf_mem_st */
            	98, 8,
            1, 8, 1, /* 831: pointer.struct.asn1_string_st */
            	611, 0,
            1, 8, 1, /* 836: pointer.struct.stack_st_X509_EXTENSION */
            	841, 0,
            0, 32, 2, /* 841: struct.stack_st_fake_X509_EXTENSION */
            	848, 8,
            	365, 24,
            8884099, 8, 2, /* 848: pointer_to_array_of_pointers_to_stack */
            	855, 0,
            	362, 20,
            0, 8, 1, /* 855: pointer.X509_EXTENSION */
            	527, 0,
            0, 24, 1, /* 860: struct.ASN1_ENCODING_st */
            	205, 0,
            1, 8, 1, /* 865: pointer.struct.X509_crl_info_st */
            	587, 0,
            1, 8, 1, /* 870: pointer.struct.X509_crl_st */
            	875, 0,
            0, 120, 10, /* 875: struct.X509_crl_st */
            	865, 0,
            	616, 8,
            	898, 16,
            	903, 32,
            	0, 40,
            	606, 56,
            	606, 64,
            	956, 96,
            	1002, 104,
            	1027, 112,
            1, 8, 1, /* 898: pointer.struct.asn1_string_st */
            	611, 0,
            1, 8, 1, /* 903: pointer.struct.AUTHORITY_KEYID_st */
            	908, 0,
            0, 24, 3, /* 908: struct.AUTHORITY_KEYID_st */
            	917, 0,
            	927, 8,
            	951, 16,
            1, 8, 1, /* 917: pointer.struct.asn1_string_st */
            	922, 0,
            0, 24, 1, /* 922: struct.asn1_string_st */
            	205, 8,
            1, 8, 1, /* 927: pointer.struct.stack_st_GENERAL_NAME */
            	932, 0,
            0, 32, 2, /* 932: struct.stack_st_fake_GENERAL_NAME */
            	939, 8,
            	365, 24,
            8884099, 8, 2, /* 939: pointer_to_array_of_pointers_to_stack */
            	946, 0,
            	362, 20,
            0, 8, 1, /* 946: pointer.GENERAL_NAME */
            	55, 0,
            1, 8, 1, /* 951: pointer.struct.asn1_string_st */
            	922, 0,
            1, 8, 1, /* 956: pointer.struct.stack_st_GENERAL_NAMES */
            	961, 0,
            0, 32, 2, /* 961: struct.stack_st_fake_GENERAL_NAMES */
            	968, 8,
            	365, 24,
            8884099, 8, 2, /* 968: pointer_to_array_of_pointers_to_stack */
            	975, 0,
            	362, 20,
            0, 8, 1, /* 975: pointer.GENERAL_NAMES */
            	980, 0,
            0, 0, 1, /* 980: GENERAL_NAMES */
            	985, 0,
            0, 32, 1, /* 985: struct.stack_st_GENERAL_NAME */
            	990, 0,
            0, 32, 2, /* 990: struct.stack_st */
            	997, 8,
            	365, 24,
            1, 8, 1, /* 997: pointer.pointer.char */
            	98, 0,
            1, 8, 1, /* 1002: pointer.struct.x509_crl_method_st */
            	1007, 0,
            0, 40, 4, /* 1007: struct.x509_crl_method_st */
            	1018, 8,
            	1018, 16,
            	1021, 24,
            	1024, 32,
            8884097, 8, 0, /* 1018: pointer.func */
            8884097, 8, 0, /* 1021: pointer.func */
            8884097, 8, 0, /* 1024: pointer.func */
            0, 8, 0, /* 1027: pointer.void */
            1, 8, 1, /* 1030: pointer.struct.X509_POLICY_DATA_st */
            	1035, 0,
            0, 32, 3, /* 1035: struct.X509_POLICY_DATA_st */
            	1044, 8,
            	1058, 16,
            	1311, 24,
            1, 8, 1, /* 1044: pointer.struct.asn1_object_st */
            	1049, 0,
            0, 40, 3, /* 1049: struct.asn1_object_st */
            	129, 0,
            	129, 8,
            	134, 24,
            1, 8, 1, /* 1058: pointer.struct.stack_st_POLICYQUALINFO */
            	1063, 0,
            0, 32, 2, /* 1063: struct.stack_st_fake_POLICYQUALINFO */
            	1070, 8,
            	365, 24,
            8884099, 8, 2, /* 1070: pointer_to_array_of_pointers_to_stack */
            	1077, 0,
            	362, 20,
            0, 8, 1, /* 1077: pointer.POLICYQUALINFO */
            	1082, 0,
            0, 0, 1, /* 1082: POLICYQUALINFO */
            	1087, 0,
            0, 16, 2, /* 1087: struct.POLICYQUALINFO_st */
            	1094, 0,
            	1108, 8,
            1, 8, 1, /* 1094: pointer.struct.asn1_object_st */
            	1099, 0,
            0, 40, 3, /* 1099: struct.asn1_object_st */
            	129, 0,
            	129, 8,
            	134, 24,
            0, 8, 3, /* 1108: union.unknown */
            	1117, 0,
            	1127, 0,
            	1185, 0,
            1, 8, 1, /* 1117: pointer.struct.asn1_string_st */
            	1122, 0,
            0, 24, 1, /* 1122: struct.asn1_string_st */
            	205, 8,
            1, 8, 1, /* 1127: pointer.struct.USERNOTICE_st */
            	1132, 0,
            0, 16, 2, /* 1132: struct.USERNOTICE_st */
            	1139, 0,
            	1151, 8,
            1, 8, 1, /* 1139: pointer.struct.NOTICEREF_st */
            	1144, 0,
            0, 16, 2, /* 1144: struct.NOTICEREF_st */
            	1151, 0,
            	1156, 8,
            1, 8, 1, /* 1151: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1156: pointer.struct.stack_st_ASN1_INTEGER */
            	1161, 0,
            0, 32, 2, /* 1161: struct.stack_st_fake_ASN1_INTEGER */
            	1168, 8,
            	365, 24,
            8884099, 8, 2, /* 1168: pointer_to_array_of_pointers_to_stack */
            	1175, 0,
            	362, 20,
            0, 8, 1, /* 1175: pointer.ASN1_INTEGER */
            	1180, 0,
            0, 0, 1, /* 1180: ASN1_INTEGER */
            	700, 0,
            1, 8, 1, /* 1185: pointer.struct.asn1_type_st */
            	1190, 0,
            0, 16, 1, /* 1190: struct.asn1_type_st */
            	1195, 8,
            0, 8, 20, /* 1195: union.unknown */
            	98, 0,
            	1151, 0,
            	1094, 0,
            	1238, 0,
            	1243, 0,
            	1248, 0,
            	1253, 0,
            	1258, 0,
            	1263, 0,
            	1117, 0,
            	1268, 0,
            	1273, 0,
            	1278, 0,
            	1283, 0,
            	1288, 0,
            	1293, 0,
            	1298, 0,
            	1151, 0,
            	1151, 0,
            	1303, 0,
            1, 8, 1, /* 1238: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1243: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1248: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1253: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1258: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1263: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1268: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1273: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1278: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1283: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1288: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1293: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1298: pointer.struct.asn1_string_st */
            	1122, 0,
            1, 8, 1, /* 1303: pointer.struct.ASN1_VALUE_st */
            	1308, 0,
            0, 0, 0, /* 1308: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1311: pointer.struct.stack_st_ASN1_OBJECT */
            	1316, 0,
            0, 32, 2, /* 1316: struct.stack_st_fake_ASN1_OBJECT */
            	1323, 8,
            	365, 24,
            8884099, 8, 2, /* 1323: pointer_to_array_of_pointers_to_stack */
            	1330, 0,
            	362, 20,
            0, 8, 1, /* 1330: pointer.ASN1_OBJECT */
            	1335, 0,
            0, 0, 1, /* 1335: ASN1_OBJECT */
            	1340, 0,
            0, 40, 3, /* 1340: struct.asn1_object_st */
            	129, 0,
            	129, 8,
            	134, 24,
            0, 24, 2, /* 1349: struct.X509_POLICY_NODE_st */
            	1030, 0,
            	1356, 8,
            1, 8, 1, /* 1356: pointer.struct.X509_POLICY_NODE_st */
            	1349, 0,
            1, 8, 1, /* 1361: pointer.struct.X509_POLICY_NODE_st */
            	1366, 0,
            0, 24, 2, /* 1366: struct.X509_POLICY_NODE_st */
            	1373, 0,
            	1361, 8,
            1, 8, 1, /* 1373: pointer.struct.X509_POLICY_DATA_st */
            	1378, 0,
            0, 32, 3, /* 1378: struct.X509_POLICY_DATA_st */
            	1387, 8,
            	1401, 16,
            	1425, 24,
            1, 8, 1, /* 1387: pointer.struct.asn1_object_st */
            	1392, 0,
            0, 40, 3, /* 1392: struct.asn1_object_st */
            	129, 0,
            	129, 8,
            	134, 24,
            1, 8, 1, /* 1401: pointer.struct.stack_st_POLICYQUALINFO */
            	1406, 0,
            0, 32, 2, /* 1406: struct.stack_st_fake_POLICYQUALINFO */
            	1413, 8,
            	365, 24,
            8884099, 8, 2, /* 1413: pointer_to_array_of_pointers_to_stack */
            	1420, 0,
            	362, 20,
            0, 8, 1, /* 1420: pointer.POLICYQUALINFO */
            	1082, 0,
            1, 8, 1, /* 1425: pointer.struct.stack_st_ASN1_OBJECT */
            	1430, 0,
            0, 32, 2, /* 1430: struct.stack_st_fake_ASN1_OBJECT */
            	1437, 8,
            	365, 24,
            8884099, 8, 2, /* 1437: pointer_to_array_of_pointers_to_stack */
            	1444, 0,
            	362, 20,
            0, 8, 1, /* 1444: pointer.ASN1_OBJECT */
            	1335, 0,
            0, 0, 1, /* 1449: X509_POLICY_NODE */
            	1366, 0,
            0, 40, 5, /* 1454: struct.x509_cert_aux_st */
            	1311, 0,
            	1311, 8,
            	1467, 16,
            	1477, 24,
            	1482, 32,
            1, 8, 1, /* 1467: pointer.struct.asn1_string_st */
            	1472, 0,
            0, 24, 1, /* 1472: struct.asn1_string_st */
            	205, 8,
            1, 8, 1, /* 1477: pointer.struct.asn1_string_st */
            	1472, 0,
            1, 8, 1, /* 1482: pointer.struct.stack_st_X509_ALGOR */
            	1487, 0,
            0, 32, 2, /* 1487: struct.stack_st_fake_X509_ALGOR */
            	1494, 8,
            	365, 24,
            8884099, 8, 2, /* 1494: pointer_to_array_of_pointers_to_stack */
            	1501, 0,
            	362, 20,
            0, 8, 1, /* 1501: pointer.X509_ALGOR */
            	1506, 0,
            0, 0, 1, /* 1506: X509_ALGOR */
            	621, 0,
            1, 8, 1, /* 1511: pointer.struct.x509_cert_aux_st */
            	1454, 0,
            1, 8, 1, /* 1516: pointer.struct.NAME_CONSTRAINTS_st */
            	1521, 0,
            0, 16, 2, /* 1521: struct.NAME_CONSTRAINTS_st */
            	1528, 0,
            	1528, 8,
            1, 8, 1, /* 1528: pointer.struct.stack_st_GENERAL_SUBTREE */
            	1533, 0,
            0, 32, 2, /* 1533: struct.stack_st_fake_GENERAL_SUBTREE */
            	1540, 8,
            	365, 24,
            8884099, 8, 2, /* 1540: pointer_to_array_of_pointers_to_stack */
            	1547, 0,
            	362, 20,
            0, 8, 1, /* 1547: pointer.GENERAL_SUBTREE */
            	1552, 0,
            0, 0, 1, /* 1552: GENERAL_SUBTREE */
            	1557, 0,
            0, 24, 3, /* 1557: struct.GENERAL_SUBTREE_st */
            	1566, 0,
            	1698, 8,
            	1698, 16,
            1, 8, 1, /* 1566: pointer.struct.GENERAL_NAME_st */
            	1571, 0,
            0, 16, 1, /* 1571: struct.GENERAL_NAME_st */
            	1576, 8,
            0, 8, 15, /* 1576: union.unknown */
            	98, 0,
            	1609, 0,
            	1728, 0,
            	1728, 0,
            	1635, 0,
            	1768, 0,
            	1816, 0,
            	1728, 0,
            	1713, 0,
            	1621, 0,
            	1713, 0,
            	1768, 0,
            	1728, 0,
            	1621, 0,
            	1635, 0,
            1, 8, 1, /* 1609: pointer.struct.otherName_st */
            	1614, 0,
            0, 16, 2, /* 1614: struct.otherName_st */
            	1621, 0,
            	1635, 8,
            1, 8, 1, /* 1621: pointer.struct.asn1_object_st */
            	1626, 0,
            0, 40, 3, /* 1626: struct.asn1_object_st */
            	129, 0,
            	129, 8,
            	134, 24,
            1, 8, 1, /* 1635: pointer.struct.asn1_type_st */
            	1640, 0,
            0, 16, 1, /* 1640: struct.asn1_type_st */
            	1645, 8,
            0, 8, 20, /* 1645: union.unknown */
            	98, 0,
            	1688, 0,
            	1621, 0,
            	1698, 0,
            	1703, 0,
            	1708, 0,
            	1713, 0,
            	1718, 0,
            	1723, 0,
            	1728, 0,
            	1733, 0,
            	1738, 0,
            	1743, 0,
            	1748, 0,
            	1753, 0,
            	1758, 0,
            	1763, 0,
            	1688, 0,
            	1688, 0,
            	1303, 0,
            1, 8, 1, /* 1688: pointer.struct.asn1_string_st */
            	1693, 0,
            0, 24, 1, /* 1693: struct.asn1_string_st */
            	205, 8,
            1, 8, 1, /* 1698: pointer.struct.asn1_string_st */
            	1693, 0,
            1, 8, 1, /* 1703: pointer.struct.asn1_string_st */
            	1693, 0,
            1, 8, 1, /* 1708: pointer.struct.asn1_string_st */
            	1693, 0,
            1, 8, 1, /* 1713: pointer.struct.asn1_string_st */
            	1693, 0,
            1, 8, 1, /* 1718: pointer.struct.asn1_string_st */
            	1693, 0,
            1, 8, 1, /* 1723: pointer.struct.asn1_string_st */
            	1693, 0,
            1, 8, 1, /* 1728: pointer.struct.asn1_string_st */
            	1693, 0,
            1, 8, 1, /* 1733: pointer.struct.asn1_string_st */
            	1693, 0,
            1, 8, 1, /* 1738: pointer.struct.asn1_string_st */
            	1693, 0,
            1, 8, 1, /* 1743: pointer.struct.asn1_string_st */
            	1693, 0,
            1, 8, 1, /* 1748: pointer.struct.asn1_string_st */
            	1693, 0,
            1, 8, 1, /* 1753: pointer.struct.asn1_string_st */
            	1693, 0,
            1, 8, 1, /* 1758: pointer.struct.asn1_string_st */
            	1693, 0,
            1, 8, 1, /* 1763: pointer.struct.asn1_string_st */
            	1693, 0,
            1, 8, 1, /* 1768: pointer.struct.X509_name_st */
            	1773, 0,
            0, 40, 3, /* 1773: struct.X509_name_st */
            	1782, 0,
            	1806, 16,
            	205, 24,
            1, 8, 1, /* 1782: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1787, 0,
            0, 32, 2, /* 1787: struct.stack_st_fake_X509_NAME_ENTRY */
            	1794, 8,
            	365, 24,
            8884099, 8, 2, /* 1794: pointer_to_array_of_pointers_to_stack */
            	1801, 0,
            	362, 20,
            0, 8, 1, /* 1801: pointer.X509_NAME_ENTRY */
            	326, 0,
            1, 8, 1, /* 1806: pointer.struct.buf_mem_st */
            	1811, 0,
            0, 24, 1, /* 1811: struct.buf_mem_st */
            	98, 8,
            1, 8, 1, /* 1816: pointer.struct.EDIPartyName_st */
            	1821, 0,
            0, 16, 2, /* 1821: struct.EDIPartyName_st */
            	1688, 0,
            	1688, 8,
            1, 8, 1, /* 1828: pointer.struct.AUTHORITY_KEYID_st */
            	908, 0,
            0, 32, 2, /* 1833: struct.stack_st */
            	997, 8,
            	365, 24,
            1, 8, 1, /* 1840: pointer.struct.stack_st_void */
            	1845, 0,
            0, 32, 1, /* 1845: struct.stack_st_void */
            	1833, 0,
            0, 16, 1, /* 1850: struct.crypto_ex_data_st */
            	1840, 0,
            1, 8, 1, /* 1855: pointer.struct.stack_st_X509_EXTENSION */
            	1860, 0,
            0, 32, 2, /* 1860: struct.stack_st_fake_X509_EXTENSION */
            	1867, 8,
            	365, 24,
            8884099, 8, 2, /* 1867: pointer_to_array_of_pointers_to_stack */
            	1874, 0,
            	362, 20,
            0, 8, 1, /* 1874: pointer.X509_EXTENSION */
            	527, 0,
            1, 8, 1, /* 1879: pointer.struct.asn1_string_st */
            	1472, 0,
            1, 8, 1, /* 1884: pointer.struct.asn1_string_st */
            	1472, 0,
            0, 16, 2, /* 1889: struct.X509_val_st */
            	1884, 0,
            	1884, 8,
            1, 8, 1, /* 1896: pointer.struct.X509_val_st */
            	1889, 0,
            1, 8, 1, /* 1901: pointer.struct.buf_mem_st */
            	1906, 0,
            0, 24, 1, /* 1906: struct.buf_mem_st */
            	98, 8,
            1, 8, 1, /* 1911: pointer.struct.X509_name_st */
            	1916, 0,
            0, 40, 3, /* 1916: struct.X509_name_st */
            	1925, 0,
            	1901, 16,
            	205, 24,
            1, 8, 1, /* 1925: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1930, 0,
            0, 32, 2, /* 1930: struct.stack_st_fake_X509_NAME_ENTRY */
            	1937, 8,
            	365, 24,
            8884099, 8, 2, /* 1937: pointer_to_array_of_pointers_to_stack */
            	1944, 0,
            	362, 20,
            0, 8, 1, /* 1944: pointer.X509_NAME_ENTRY */
            	326, 0,
            1, 8, 1, /* 1949: pointer.struct.x509_cinf_st */
            	1954, 0,
            0, 104, 11, /* 1954: struct.x509_cinf_st */
            	1979, 0,
            	1979, 8,
            	1984, 16,
            	1911, 24,
            	1896, 32,
            	1911, 40,
            	1989, 48,
            	1879, 56,
            	1879, 64,
            	1855, 72,
            	3860, 80,
            1, 8, 1, /* 1979: pointer.struct.asn1_string_st */
            	1472, 0,
            1, 8, 1, /* 1984: pointer.struct.X509_algor_st */
            	621, 0,
            1, 8, 1, /* 1989: pointer.struct.X509_pubkey_st */
            	1994, 0,
            0, 24, 3, /* 1994: struct.X509_pubkey_st */
            	2003, 0,
            	2008, 8,
            	2018, 16,
            1, 8, 1, /* 2003: pointer.struct.X509_algor_st */
            	621, 0,
            1, 8, 1, /* 2008: pointer.struct.asn1_string_st */
            	2013, 0,
            0, 24, 1, /* 2013: struct.asn1_string_st */
            	205, 8,
            1, 8, 1, /* 2018: pointer.struct.evp_pkey_st */
            	2023, 0,
            0, 56, 4, /* 2023: struct.evp_pkey_st */
            	2034, 16,
            	2135, 24,
            	2483, 32,
            	3489, 48,
            1, 8, 1, /* 2034: pointer.struct.evp_pkey_asn1_method_st */
            	2039, 0,
            0, 208, 24, /* 2039: struct.evp_pkey_asn1_method_st */
            	98, 16,
            	98, 24,
            	2090, 32,
            	2093, 40,
            	2096, 48,
            	2099, 56,
            	2102, 64,
            	2105, 72,
            	2099, 80,
            	2108, 88,
            	2108, 96,
            	2111, 104,
            	2114, 112,
            	2108, 120,
            	2117, 128,
            	2096, 136,
            	2099, 144,
            	2120, 152,
            	2123, 160,
            	2126, 168,
            	2111, 176,
            	2114, 184,
            	2129, 192,
            	2132, 200,
            8884097, 8, 0, /* 2090: pointer.func */
            8884097, 8, 0, /* 2093: pointer.func */
            8884097, 8, 0, /* 2096: pointer.func */
            8884097, 8, 0, /* 2099: pointer.func */
            8884097, 8, 0, /* 2102: pointer.func */
            8884097, 8, 0, /* 2105: pointer.func */
            8884097, 8, 0, /* 2108: pointer.func */
            8884097, 8, 0, /* 2111: pointer.func */
            8884097, 8, 0, /* 2114: pointer.func */
            8884097, 8, 0, /* 2117: pointer.func */
            8884097, 8, 0, /* 2120: pointer.func */
            8884097, 8, 0, /* 2123: pointer.func */
            8884097, 8, 0, /* 2126: pointer.func */
            8884097, 8, 0, /* 2129: pointer.func */
            8884097, 8, 0, /* 2132: pointer.func */
            1, 8, 1, /* 2135: pointer.struct.engine_st */
            	2140, 0,
            0, 216, 24, /* 2140: struct.engine_st */
            	129, 0,
            	129, 8,
            	2191, 16,
            	2246, 24,
            	2297, 32,
            	2333, 40,
            	2350, 48,
            	2377, 56,
            	2412, 64,
            	2420, 72,
            	2423, 80,
            	2426, 88,
            	2429, 96,
            	2432, 104,
            	2432, 112,
            	2432, 120,
            	2435, 128,
            	2438, 136,
            	2438, 144,
            	2441, 152,
            	2444, 160,
            	2456, 184,
            	2478, 200,
            	2478, 208,
            1, 8, 1, /* 2191: pointer.struct.rsa_meth_st */
            	2196, 0,
            0, 112, 13, /* 2196: struct.rsa_meth_st */
            	129, 0,
            	2225, 8,
            	2225, 16,
            	2225, 24,
            	2225, 32,
            	2228, 40,
            	2231, 48,
            	2234, 56,
            	2234, 64,
            	98, 80,
            	2237, 88,
            	2240, 96,
            	2243, 104,
            8884097, 8, 0, /* 2225: pointer.func */
            8884097, 8, 0, /* 2228: pointer.func */
            8884097, 8, 0, /* 2231: pointer.func */
            8884097, 8, 0, /* 2234: pointer.func */
            8884097, 8, 0, /* 2237: pointer.func */
            8884097, 8, 0, /* 2240: pointer.func */
            8884097, 8, 0, /* 2243: pointer.func */
            1, 8, 1, /* 2246: pointer.struct.dsa_method */
            	2251, 0,
            0, 96, 11, /* 2251: struct.dsa_method */
            	129, 0,
            	2276, 8,
            	2279, 16,
            	2282, 24,
            	2285, 32,
            	2288, 40,
            	2291, 48,
            	2291, 56,
            	98, 72,
            	2294, 80,
            	2291, 88,
            8884097, 8, 0, /* 2276: pointer.func */
            8884097, 8, 0, /* 2279: pointer.func */
            8884097, 8, 0, /* 2282: pointer.func */
            8884097, 8, 0, /* 2285: pointer.func */
            8884097, 8, 0, /* 2288: pointer.func */
            8884097, 8, 0, /* 2291: pointer.func */
            8884097, 8, 0, /* 2294: pointer.func */
            1, 8, 1, /* 2297: pointer.struct.dh_method */
            	2302, 0,
            0, 72, 8, /* 2302: struct.dh_method */
            	129, 0,
            	2321, 8,
            	2324, 16,
            	2327, 24,
            	2321, 32,
            	2321, 40,
            	98, 56,
            	2330, 64,
            8884097, 8, 0, /* 2321: pointer.func */
            8884097, 8, 0, /* 2324: pointer.func */
            8884097, 8, 0, /* 2327: pointer.func */
            8884097, 8, 0, /* 2330: pointer.func */
            1, 8, 1, /* 2333: pointer.struct.ecdh_method */
            	2338, 0,
            0, 32, 3, /* 2338: struct.ecdh_method */
            	129, 0,
            	2347, 8,
            	98, 24,
            8884097, 8, 0, /* 2347: pointer.func */
            1, 8, 1, /* 2350: pointer.struct.ecdsa_method */
            	2355, 0,
            0, 48, 5, /* 2355: struct.ecdsa_method */
            	129, 0,
            	2368, 8,
            	2371, 16,
            	2374, 24,
            	98, 40,
            8884097, 8, 0, /* 2368: pointer.func */
            8884097, 8, 0, /* 2371: pointer.func */
            8884097, 8, 0, /* 2374: pointer.func */
            1, 8, 1, /* 2377: pointer.struct.rand_meth_st */
            	2382, 0,
            0, 48, 6, /* 2382: struct.rand_meth_st */
            	2397, 0,
            	2400, 8,
            	2403, 16,
            	2406, 24,
            	2400, 32,
            	2409, 40,
            8884097, 8, 0, /* 2397: pointer.func */
            8884097, 8, 0, /* 2400: pointer.func */
            8884097, 8, 0, /* 2403: pointer.func */
            8884097, 8, 0, /* 2406: pointer.func */
            8884097, 8, 0, /* 2409: pointer.func */
            1, 8, 1, /* 2412: pointer.struct.store_method_st */
            	2417, 0,
            0, 0, 0, /* 2417: struct.store_method_st */
            8884097, 8, 0, /* 2420: pointer.func */
            8884097, 8, 0, /* 2423: pointer.func */
            8884097, 8, 0, /* 2426: pointer.func */
            8884097, 8, 0, /* 2429: pointer.func */
            8884097, 8, 0, /* 2432: pointer.func */
            8884097, 8, 0, /* 2435: pointer.func */
            8884097, 8, 0, /* 2438: pointer.func */
            8884097, 8, 0, /* 2441: pointer.func */
            1, 8, 1, /* 2444: pointer.struct.ENGINE_CMD_DEFN_st */
            	2449, 0,
            0, 32, 2, /* 2449: struct.ENGINE_CMD_DEFN_st */
            	129, 8,
            	129, 16,
            0, 16, 1, /* 2456: struct.crypto_ex_data_st */
            	2461, 0,
            1, 8, 1, /* 2461: pointer.struct.stack_st_void */
            	2466, 0,
            0, 32, 1, /* 2466: struct.stack_st_void */
            	2471, 0,
            0, 32, 2, /* 2471: struct.stack_st */
            	997, 8,
            	365, 24,
            1, 8, 1, /* 2478: pointer.struct.engine_st */
            	2140, 0,
            0, 8, 5, /* 2483: union.unknown */
            	98, 0,
            	2496, 0,
            	2715, 0,
            	2854, 0,
            	2980, 0,
            1, 8, 1, /* 2496: pointer.struct.rsa_st */
            	2501, 0,
            0, 168, 17, /* 2501: struct.rsa_st */
            	2538, 16,
            	2593, 24,
            	2598, 32,
            	2598, 40,
            	2598, 48,
            	2598, 56,
            	2598, 64,
            	2598, 72,
            	2598, 80,
            	2598, 88,
            	2618, 96,
            	2640, 120,
            	2640, 128,
            	2640, 136,
            	98, 144,
            	2654, 152,
            	2654, 160,
            1, 8, 1, /* 2538: pointer.struct.rsa_meth_st */
            	2543, 0,
            0, 112, 13, /* 2543: struct.rsa_meth_st */
            	129, 0,
            	2572, 8,
            	2572, 16,
            	2572, 24,
            	2572, 32,
            	2575, 40,
            	2578, 48,
            	2581, 56,
            	2581, 64,
            	98, 80,
            	2584, 88,
            	2587, 96,
            	2590, 104,
            8884097, 8, 0, /* 2572: pointer.func */
            8884097, 8, 0, /* 2575: pointer.func */
            8884097, 8, 0, /* 2578: pointer.func */
            8884097, 8, 0, /* 2581: pointer.func */
            8884097, 8, 0, /* 2584: pointer.func */
            8884097, 8, 0, /* 2587: pointer.func */
            8884097, 8, 0, /* 2590: pointer.func */
            1, 8, 1, /* 2593: pointer.struct.engine_st */
            	2140, 0,
            1, 8, 1, /* 2598: pointer.struct.bignum_st */
            	2603, 0,
            0, 24, 1, /* 2603: struct.bignum_st */
            	2608, 0,
            8884099, 8, 2, /* 2608: pointer_to_array_of_pointers_to_stack */
            	2615, 0,
            	362, 12,
            0, 4, 0, /* 2615: unsigned int */
            0, 16, 1, /* 2618: struct.crypto_ex_data_st */
            	2623, 0,
            1, 8, 1, /* 2623: pointer.struct.stack_st_void */
            	2628, 0,
            0, 32, 1, /* 2628: struct.stack_st_void */
            	2633, 0,
            0, 32, 2, /* 2633: struct.stack_st */
            	997, 8,
            	365, 24,
            1, 8, 1, /* 2640: pointer.struct.bn_mont_ctx_st */
            	2645, 0,
            0, 96, 3, /* 2645: struct.bn_mont_ctx_st */
            	2603, 8,
            	2603, 32,
            	2603, 56,
            1, 8, 1, /* 2654: pointer.struct.bn_blinding_st */
            	2659, 0,
            0, 88, 7, /* 2659: struct.bn_blinding_st */
            	2676, 0,
            	2676, 8,
            	2676, 16,
            	2676, 24,
            	2693, 40,
            	2698, 72,
            	2712, 80,
            1, 8, 1, /* 2676: pointer.struct.bignum_st */
            	2681, 0,
            0, 24, 1, /* 2681: struct.bignum_st */
            	2686, 0,
            8884099, 8, 2, /* 2686: pointer_to_array_of_pointers_to_stack */
            	2615, 0,
            	362, 12,
            0, 16, 1, /* 2693: struct.crypto_threadid_st */
            	1027, 0,
            1, 8, 1, /* 2698: pointer.struct.bn_mont_ctx_st */
            	2703, 0,
            0, 96, 3, /* 2703: struct.bn_mont_ctx_st */
            	2681, 8,
            	2681, 32,
            	2681, 56,
            8884097, 8, 0, /* 2712: pointer.func */
            1, 8, 1, /* 2715: pointer.struct.dsa_st */
            	2720, 0,
            0, 136, 11, /* 2720: struct.dsa_st */
            	2745, 24,
            	2745, 32,
            	2745, 40,
            	2745, 48,
            	2745, 56,
            	2745, 64,
            	2745, 72,
            	2762, 88,
            	2776, 104,
            	2798, 120,
            	2849, 128,
            1, 8, 1, /* 2745: pointer.struct.bignum_st */
            	2750, 0,
            0, 24, 1, /* 2750: struct.bignum_st */
            	2755, 0,
            8884099, 8, 2, /* 2755: pointer_to_array_of_pointers_to_stack */
            	2615, 0,
            	362, 12,
            1, 8, 1, /* 2762: pointer.struct.bn_mont_ctx_st */
            	2767, 0,
            0, 96, 3, /* 2767: struct.bn_mont_ctx_st */
            	2750, 8,
            	2750, 32,
            	2750, 56,
            0, 16, 1, /* 2776: struct.crypto_ex_data_st */
            	2781, 0,
            1, 8, 1, /* 2781: pointer.struct.stack_st_void */
            	2786, 0,
            0, 32, 1, /* 2786: struct.stack_st_void */
            	2791, 0,
            0, 32, 2, /* 2791: struct.stack_st */
            	997, 8,
            	365, 24,
            1, 8, 1, /* 2798: pointer.struct.dsa_method */
            	2803, 0,
            0, 96, 11, /* 2803: struct.dsa_method */
            	129, 0,
            	2828, 8,
            	2831, 16,
            	2834, 24,
            	2837, 32,
            	2840, 40,
            	2843, 48,
            	2843, 56,
            	98, 72,
            	2846, 80,
            	2843, 88,
            8884097, 8, 0, /* 2828: pointer.func */
            8884097, 8, 0, /* 2831: pointer.func */
            8884097, 8, 0, /* 2834: pointer.func */
            8884097, 8, 0, /* 2837: pointer.func */
            8884097, 8, 0, /* 2840: pointer.func */
            8884097, 8, 0, /* 2843: pointer.func */
            8884097, 8, 0, /* 2846: pointer.func */
            1, 8, 1, /* 2849: pointer.struct.engine_st */
            	2140, 0,
            1, 8, 1, /* 2854: pointer.struct.dh_st */
            	2859, 0,
            0, 144, 12, /* 2859: struct.dh_st */
            	2886, 8,
            	2886, 16,
            	2886, 32,
            	2886, 40,
            	2903, 56,
            	2886, 64,
            	2886, 72,
            	205, 80,
            	2886, 96,
            	2917, 112,
            	2939, 128,
            	2975, 136,
            1, 8, 1, /* 2886: pointer.struct.bignum_st */
            	2891, 0,
            0, 24, 1, /* 2891: struct.bignum_st */
            	2896, 0,
            8884099, 8, 2, /* 2896: pointer_to_array_of_pointers_to_stack */
            	2615, 0,
            	362, 12,
            1, 8, 1, /* 2903: pointer.struct.bn_mont_ctx_st */
            	2908, 0,
            0, 96, 3, /* 2908: struct.bn_mont_ctx_st */
            	2891, 8,
            	2891, 32,
            	2891, 56,
            0, 16, 1, /* 2917: struct.crypto_ex_data_st */
            	2922, 0,
            1, 8, 1, /* 2922: pointer.struct.stack_st_void */
            	2927, 0,
            0, 32, 1, /* 2927: struct.stack_st_void */
            	2932, 0,
            0, 32, 2, /* 2932: struct.stack_st */
            	997, 8,
            	365, 24,
            1, 8, 1, /* 2939: pointer.struct.dh_method */
            	2944, 0,
            0, 72, 8, /* 2944: struct.dh_method */
            	129, 0,
            	2963, 8,
            	2966, 16,
            	2969, 24,
            	2963, 32,
            	2963, 40,
            	98, 56,
            	2972, 64,
            8884097, 8, 0, /* 2963: pointer.func */
            8884097, 8, 0, /* 2966: pointer.func */
            8884097, 8, 0, /* 2969: pointer.func */
            8884097, 8, 0, /* 2972: pointer.func */
            1, 8, 1, /* 2975: pointer.struct.engine_st */
            	2140, 0,
            1, 8, 1, /* 2980: pointer.struct.ec_key_st */
            	2985, 0,
            0, 56, 4, /* 2985: struct.ec_key_st */
            	2996, 8,
            	3444, 16,
            	3449, 24,
            	3466, 48,
            1, 8, 1, /* 2996: pointer.struct.ec_group_st */
            	3001, 0,
            0, 232, 12, /* 3001: struct.ec_group_st */
            	3028, 0,
            	3200, 8,
            	3400, 16,
            	3400, 40,
            	205, 80,
            	3412, 96,
            	3400, 104,
            	3400, 152,
            	3400, 176,
            	1027, 208,
            	1027, 216,
            	3441, 224,
            1, 8, 1, /* 3028: pointer.struct.ec_method_st */
            	3033, 0,
            0, 304, 37, /* 3033: struct.ec_method_st */
            	3110, 8,
            	3113, 16,
            	3113, 24,
            	3116, 32,
            	3119, 40,
            	3122, 48,
            	3125, 56,
            	3128, 64,
            	3131, 72,
            	3134, 80,
            	3134, 88,
            	3137, 96,
            	3140, 104,
            	3143, 112,
            	3146, 120,
            	3149, 128,
            	3152, 136,
            	3155, 144,
            	3158, 152,
            	3161, 160,
            	3164, 168,
            	3167, 176,
            	3170, 184,
            	3173, 192,
            	3176, 200,
            	3179, 208,
            	3170, 216,
            	3182, 224,
            	3185, 232,
            	3188, 240,
            	3125, 248,
            	3191, 256,
            	3194, 264,
            	3191, 272,
            	3194, 280,
            	3194, 288,
            	3197, 296,
            8884097, 8, 0, /* 3110: pointer.func */
            8884097, 8, 0, /* 3113: pointer.func */
            8884097, 8, 0, /* 3116: pointer.func */
            8884097, 8, 0, /* 3119: pointer.func */
            8884097, 8, 0, /* 3122: pointer.func */
            8884097, 8, 0, /* 3125: pointer.func */
            8884097, 8, 0, /* 3128: pointer.func */
            8884097, 8, 0, /* 3131: pointer.func */
            8884097, 8, 0, /* 3134: pointer.func */
            8884097, 8, 0, /* 3137: pointer.func */
            8884097, 8, 0, /* 3140: pointer.func */
            8884097, 8, 0, /* 3143: pointer.func */
            8884097, 8, 0, /* 3146: pointer.func */
            8884097, 8, 0, /* 3149: pointer.func */
            8884097, 8, 0, /* 3152: pointer.func */
            8884097, 8, 0, /* 3155: pointer.func */
            8884097, 8, 0, /* 3158: pointer.func */
            8884097, 8, 0, /* 3161: pointer.func */
            8884097, 8, 0, /* 3164: pointer.func */
            8884097, 8, 0, /* 3167: pointer.func */
            8884097, 8, 0, /* 3170: pointer.func */
            8884097, 8, 0, /* 3173: pointer.func */
            8884097, 8, 0, /* 3176: pointer.func */
            8884097, 8, 0, /* 3179: pointer.func */
            8884097, 8, 0, /* 3182: pointer.func */
            8884097, 8, 0, /* 3185: pointer.func */
            8884097, 8, 0, /* 3188: pointer.func */
            8884097, 8, 0, /* 3191: pointer.func */
            8884097, 8, 0, /* 3194: pointer.func */
            8884097, 8, 0, /* 3197: pointer.func */
            1, 8, 1, /* 3200: pointer.struct.ec_point_st */
            	3205, 0,
            0, 88, 4, /* 3205: struct.ec_point_st */
            	3216, 0,
            	3388, 8,
            	3388, 32,
            	3388, 56,
            1, 8, 1, /* 3216: pointer.struct.ec_method_st */
            	3221, 0,
            0, 304, 37, /* 3221: struct.ec_method_st */
            	3298, 8,
            	3301, 16,
            	3301, 24,
            	3304, 32,
            	3307, 40,
            	3310, 48,
            	3313, 56,
            	3316, 64,
            	3319, 72,
            	3322, 80,
            	3322, 88,
            	3325, 96,
            	3328, 104,
            	3331, 112,
            	3334, 120,
            	3337, 128,
            	3340, 136,
            	3343, 144,
            	3346, 152,
            	3349, 160,
            	3352, 168,
            	3355, 176,
            	3358, 184,
            	3361, 192,
            	3364, 200,
            	3367, 208,
            	3358, 216,
            	3370, 224,
            	3373, 232,
            	3376, 240,
            	3313, 248,
            	3379, 256,
            	3382, 264,
            	3379, 272,
            	3382, 280,
            	3382, 288,
            	3385, 296,
            8884097, 8, 0, /* 3298: pointer.func */
            8884097, 8, 0, /* 3301: pointer.func */
            8884097, 8, 0, /* 3304: pointer.func */
            8884097, 8, 0, /* 3307: pointer.func */
            8884097, 8, 0, /* 3310: pointer.func */
            8884097, 8, 0, /* 3313: pointer.func */
            8884097, 8, 0, /* 3316: pointer.func */
            8884097, 8, 0, /* 3319: pointer.func */
            8884097, 8, 0, /* 3322: pointer.func */
            8884097, 8, 0, /* 3325: pointer.func */
            8884097, 8, 0, /* 3328: pointer.func */
            8884097, 8, 0, /* 3331: pointer.func */
            8884097, 8, 0, /* 3334: pointer.func */
            8884097, 8, 0, /* 3337: pointer.func */
            8884097, 8, 0, /* 3340: pointer.func */
            8884097, 8, 0, /* 3343: pointer.func */
            8884097, 8, 0, /* 3346: pointer.func */
            8884097, 8, 0, /* 3349: pointer.func */
            8884097, 8, 0, /* 3352: pointer.func */
            8884097, 8, 0, /* 3355: pointer.func */
            8884097, 8, 0, /* 3358: pointer.func */
            8884097, 8, 0, /* 3361: pointer.func */
            8884097, 8, 0, /* 3364: pointer.func */
            8884097, 8, 0, /* 3367: pointer.func */
            8884097, 8, 0, /* 3370: pointer.func */
            8884097, 8, 0, /* 3373: pointer.func */
            8884097, 8, 0, /* 3376: pointer.func */
            8884097, 8, 0, /* 3379: pointer.func */
            8884097, 8, 0, /* 3382: pointer.func */
            8884097, 8, 0, /* 3385: pointer.func */
            0, 24, 1, /* 3388: struct.bignum_st */
            	3393, 0,
            8884099, 8, 2, /* 3393: pointer_to_array_of_pointers_to_stack */
            	2615, 0,
            	362, 12,
            0, 24, 1, /* 3400: struct.bignum_st */
            	3405, 0,
            8884099, 8, 2, /* 3405: pointer_to_array_of_pointers_to_stack */
            	2615, 0,
            	362, 12,
            1, 8, 1, /* 3412: pointer.struct.ec_extra_data_st */
            	3417, 0,
            0, 40, 5, /* 3417: struct.ec_extra_data_st */
            	3430, 0,
            	1027, 8,
            	3435, 16,
            	3438, 24,
            	3438, 32,
            1, 8, 1, /* 3430: pointer.struct.ec_extra_data_st */
            	3417, 0,
            8884097, 8, 0, /* 3435: pointer.func */
            8884097, 8, 0, /* 3438: pointer.func */
            8884097, 8, 0, /* 3441: pointer.func */
            1, 8, 1, /* 3444: pointer.struct.ec_point_st */
            	3205, 0,
            1, 8, 1, /* 3449: pointer.struct.bignum_st */
            	3454, 0,
            0, 24, 1, /* 3454: struct.bignum_st */
            	3459, 0,
            8884099, 8, 2, /* 3459: pointer_to_array_of_pointers_to_stack */
            	2615, 0,
            	362, 12,
            1, 8, 1, /* 3466: pointer.struct.ec_extra_data_st */
            	3471, 0,
            0, 40, 5, /* 3471: struct.ec_extra_data_st */
            	3484, 0,
            	1027, 8,
            	3435, 16,
            	3438, 24,
            	3438, 32,
            1, 8, 1, /* 3484: pointer.struct.ec_extra_data_st */
            	3471, 0,
            1, 8, 1, /* 3489: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3494, 0,
            0, 32, 2, /* 3494: struct.stack_st_fake_X509_ATTRIBUTE */
            	3501, 8,
            	365, 24,
            8884099, 8, 2, /* 3501: pointer_to_array_of_pointers_to_stack */
            	3508, 0,
            	362, 20,
            0, 8, 1, /* 3508: pointer.X509_ATTRIBUTE */
            	3513, 0,
            0, 0, 1, /* 3513: X509_ATTRIBUTE */
            	3518, 0,
            0, 24, 2, /* 3518: struct.x509_attributes_st */
            	3525, 0,
            	3539, 16,
            1, 8, 1, /* 3525: pointer.struct.asn1_object_st */
            	3530, 0,
            0, 40, 3, /* 3530: struct.asn1_object_st */
            	129, 0,
            	129, 8,
            	134, 24,
            0, 8, 3, /* 3539: union.unknown */
            	98, 0,
            	3548, 0,
            	3727, 0,
            1, 8, 1, /* 3548: pointer.struct.stack_st_ASN1_TYPE */
            	3553, 0,
            0, 32, 2, /* 3553: struct.stack_st_fake_ASN1_TYPE */
            	3560, 8,
            	365, 24,
            8884099, 8, 2, /* 3560: pointer_to_array_of_pointers_to_stack */
            	3567, 0,
            	362, 20,
            0, 8, 1, /* 3567: pointer.ASN1_TYPE */
            	3572, 0,
            0, 0, 1, /* 3572: ASN1_TYPE */
            	3577, 0,
            0, 16, 1, /* 3577: struct.asn1_type_st */
            	3582, 8,
            0, 8, 20, /* 3582: union.unknown */
            	98, 0,
            	3625, 0,
            	3635, 0,
            	3649, 0,
            	3654, 0,
            	3659, 0,
            	3664, 0,
            	3669, 0,
            	3674, 0,
            	3679, 0,
            	3684, 0,
            	3689, 0,
            	3694, 0,
            	3699, 0,
            	3704, 0,
            	3709, 0,
            	3714, 0,
            	3625, 0,
            	3625, 0,
            	3719, 0,
            1, 8, 1, /* 3625: pointer.struct.asn1_string_st */
            	3630, 0,
            0, 24, 1, /* 3630: struct.asn1_string_st */
            	205, 8,
            1, 8, 1, /* 3635: pointer.struct.asn1_object_st */
            	3640, 0,
            0, 40, 3, /* 3640: struct.asn1_object_st */
            	129, 0,
            	129, 8,
            	134, 24,
            1, 8, 1, /* 3649: pointer.struct.asn1_string_st */
            	3630, 0,
            1, 8, 1, /* 3654: pointer.struct.asn1_string_st */
            	3630, 0,
            1, 8, 1, /* 3659: pointer.struct.asn1_string_st */
            	3630, 0,
            1, 8, 1, /* 3664: pointer.struct.asn1_string_st */
            	3630, 0,
            1, 8, 1, /* 3669: pointer.struct.asn1_string_st */
            	3630, 0,
            1, 8, 1, /* 3674: pointer.struct.asn1_string_st */
            	3630, 0,
            1, 8, 1, /* 3679: pointer.struct.asn1_string_st */
            	3630, 0,
            1, 8, 1, /* 3684: pointer.struct.asn1_string_st */
            	3630, 0,
            1, 8, 1, /* 3689: pointer.struct.asn1_string_st */
            	3630, 0,
            1, 8, 1, /* 3694: pointer.struct.asn1_string_st */
            	3630, 0,
            1, 8, 1, /* 3699: pointer.struct.asn1_string_st */
            	3630, 0,
            1, 8, 1, /* 3704: pointer.struct.asn1_string_st */
            	3630, 0,
            1, 8, 1, /* 3709: pointer.struct.asn1_string_st */
            	3630, 0,
            1, 8, 1, /* 3714: pointer.struct.asn1_string_st */
            	3630, 0,
            1, 8, 1, /* 3719: pointer.struct.ASN1_VALUE_st */
            	3724, 0,
            0, 0, 0, /* 3724: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3727: pointer.struct.asn1_type_st */
            	3732, 0,
            0, 16, 1, /* 3732: struct.asn1_type_st */
            	3737, 8,
            0, 8, 20, /* 3737: union.unknown */
            	98, 0,
            	3780, 0,
            	3525, 0,
            	3790, 0,
            	3795, 0,
            	3800, 0,
            	3805, 0,
            	3810, 0,
            	3815, 0,
            	3820, 0,
            	3825, 0,
            	3830, 0,
            	3835, 0,
            	3840, 0,
            	3845, 0,
            	3850, 0,
            	3855, 0,
            	3780, 0,
            	3780, 0,
            	775, 0,
            1, 8, 1, /* 3780: pointer.struct.asn1_string_st */
            	3785, 0,
            0, 24, 1, /* 3785: struct.asn1_string_st */
            	205, 8,
            1, 8, 1, /* 3790: pointer.struct.asn1_string_st */
            	3785, 0,
            1, 8, 1, /* 3795: pointer.struct.asn1_string_st */
            	3785, 0,
            1, 8, 1, /* 3800: pointer.struct.asn1_string_st */
            	3785, 0,
            1, 8, 1, /* 3805: pointer.struct.asn1_string_st */
            	3785, 0,
            1, 8, 1, /* 3810: pointer.struct.asn1_string_st */
            	3785, 0,
            1, 8, 1, /* 3815: pointer.struct.asn1_string_st */
            	3785, 0,
            1, 8, 1, /* 3820: pointer.struct.asn1_string_st */
            	3785, 0,
            1, 8, 1, /* 3825: pointer.struct.asn1_string_st */
            	3785, 0,
            1, 8, 1, /* 3830: pointer.struct.asn1_string_st */
            	3785, 0,
            1, 8, 1, /* 3835: pointer.struct.asn1_string_st */
            	3785, 0,
            1, 8, 1, /* 3840: pointer.struct.asn1_string_st */
            	3785, 0,
            1, 8, 1, /* 3845: pointer.struct.asn1_string_st */
            	3785, 0,
            1, 8, 1, /* 3850: pointer.struct.asn1_string_st */
            	3785, 0,
            1, 8, 1, /* 3855: pointer.struct.asn1_string_st */
            	3785, 0,
            0, 24, 1, /* 3860: struct.ASN1_ENCODING_st */
            	205, 0,
            1, 8, 1, /* 3865: pointer.struct.x509_st */
            	3870, 0,
            0, 184, 12, /* 3870: struct.x509_st */
            	1949, 0,
            	1984, 8,
            	1879, 16,
            	98, 32,
            	1850, 40,
            	1477, 104,
            	1828, 112,
            	3897, 120,
            	3943, 128,
            	4024, 136,
            	1516, 144,
            	1511, 176,
            1, 8, 1, /* 3897: pointer.struct.X509_POLICY_CACHE_st */
            	3902, 0,
            0, 40, 2, /* 3902: struct.X509_POLICY_CACHE_st */
            	3909, 0,
            	3914, 8,
            1, 8, 1, /* 3909: pointer.struct.X509_POLICY_DATA_st */
            	1035, 0,
            1, 8, 1, /* 3914: pointer.struct.stack_st_X509_POLICY_DATA */
            	3919, 0,
            0, 32, 2, /* 3919: struct.stack_st_fake_X509_POLICY_DATA */
            	3926, 8,
            	365, 24,
            8884099, 8, 2, /* 3926: pointer_to_array_of_pointers_to_stack */
            	3933, 0,
            	362, 20,
            0, 8, 1, /* 3933: pointer.X509_POLICY_DATA */
            	3938, 0,
            0, 0, 1, /* 3938: X509_POLICY_DATA */
            	1378, 0,
            1, 8, 1, /* 3943: pointer.struct.stack_st_DIST_POINT */
            	3948, 0,
            0, 32, 2, /* 3948: struct.stack_st_fake_DIST_POINT */
            	3955, 8,
            	365, 24,
            8884099, 8, 2, /* 3955: pointer_to_array_of_pointers_to_stack */
            	3962, 0,
            	362, 20,
            0, 8, 1, /* 3962: pointer.DIST_POINT */
            	3967, 0,
            0, 0, 1, /* 3967: DIST_POINT */
            	3972, 0,
            0, 32, 3, /* 3972: struct.DIST_POINT_st */
            	3981, 0,
            	898, 8,
            	4000, 16,
            1, 8, 1, /* 3981: pointer.struct.DIST_POINT_NAME_st */
            	3986, 0,
            0, 24, 2, /* 3986: struct.DIST_POINT_NAME_st */
            	3993, 8,
            	783, 16,
            0, 8, 2, /* 3993: union.unknown */
            	4000, 0,
            	797, 0,
            1, 8, 1, /* 4000: pointer.struct.stack_st_GENERAL_NAME */
            	4005, 0,
            0, 32, 2, /* 4005: struct.stack_st_fake_GENERAL_NAME */
            	4012, 8,
            	365, 24,
            8884099, 8, 2, /* 4012: pointer_to_array_of_pointers_to_stack */
            	4019, 0,
            	362, 20,
            0, 8, 1, /* 4019: pointer.GENERAL_NAME */
            	55, 0,
            1, 8, 1, /* 4024: pointer.struct.stack_st_GENERAL_NAME */
            	4029, 0,
            0, 32, 2, /* 4029: struct.stack_st_fake_GENERAL_NAME */
            	4036, 8,
            	365, 24,
            8884099, 8, 2, /* 4036: pointer_to_array_of_pointers_to_stack */
            	4043, 0,
            	362, 20,
            0, 8, 1, /* 4043: pointer.GENERAL_NAME */
            	55, 0,
            0, 32, 3, /* 4048: struct.X509_POLICY_LEVEL_st */
            	3865, 0,
            	4057, 8,
            	1356, 16,
            1, 8, 1, /* 4057: pointer.struct.stack_st_X509_POLICY_NODE */
            	4062, 0,
            0, 32, 2, /* 4062: struct.stack_st_fake_X509_POLICY_NODE */
            	4069, 8,
            	365, 24,
            8884099, 8, 2, /* 4069: pointer_to_array_of_pointers_to_stack */
            	4076, 0,
            	362, 20,
            0, 8, 1, /* 4076: pointer.X509_POLICY_NODE */
            	1449, 0,
            0, 48, 4, /* 4081: struct.X509_POLICY_TREE_st */
            	4092, 0,
            	3914, 16,
            	4057, 24,
            	4057, 32,
            1, 8, 1, /* 4092: pointer.struct.X509_POLICY_LEVEL_st */
            	4048, 0,
            1, 8, 1, /* 4097: pointer.struct.X509_POLICY_TREE_st */
            	4081, 0,
            1, 8, 1, /* 4102: pointer.struct.x509_crl_method_st */
            	1007, 0,
            1, 8, 1, /* 4107: pointer.struct.ISSUING_DIST_POINT_st */
            	5, 0,
            1, 8, 1, /* 4112: pointer.struct.AUTHORITY_KEYID_st */
            	908, 0,
            0, 24, 1, /* 4117: struct.ASN1_ENCODING_st */
            	205, 0,
            1, 8, 1, /* 4122: pointer.struct.stack_st_X509_EXTENSION */
            	4127, 0,
            0, 32, 2, /* 4127: struct.stack_st_fake_X509_EXTENSION */
            	4134, 8,
            	365, 24,
            8884099, 8, 2, /* 4134: pointer_to_array_of_pointers_to_stack */
            	4141, 0,
            	362, 20,
            0, 8, 1, /* 4141: pointer.X509_EXTENSION */
            	527, 0,
            1, 8, 1, /* 4146: pointer.struct.asn1_string_st */
            	4151, 0,
            0, 24, 1, /* 4151: struct.asn1_string_st */
            	205, 8,
            0, 24, 1, /* 4156: struct.buf_mem_st */
            	98, 8,
            0, 40, 3, /* 4161: struct.X509_name_st */
            	4170, 0,
            	4194, 16,
            	205, 24,
            1, 8, 1, /* 4170: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4175, 0,
            0, 32, 2, /* 4175: struct.stack_st_fake_X509_NAME_ENTRY */
            	4182, 8,
            	365, 24,
            8884099, 8, 2, /* 4182: pointer_to_array_of_pointers_to_stack */
            	4189, 0,
            	362, 20,
            0, 8, 1, /* 4189: pointer.X509_NAME_ENTRY */
            	326, 0,
            1, 8, 1, /* 4194: pointer.struct.buf_mem_st */
            	4156, 0,
            1, 8, 1, /* 4199: pointer.struct.X509_name_st */
            	4161, 0,
            1, 8, 1, /* 4204: pointer.struct.asn1_string_st */
            	4151, 0,
            1, 8, 1, /* 4209: pointer.struct.X509_crl_info_st */
            	4214, 0,
            0, 80, 8, /* 4214: struct.X509_crl_info_st */
            	4204, 0,
            	4233, 8,
            	4199, 16,
            	4146, 24,
            	4146, 32,
            	4238, 40,
            	4122, 48,
            	4117, 56,
            1, 8, 1, /* 4233: pointer.struct.X509_algor_st */
            	621, 0,
            1, 8, 1, /* 4238: pointer.struct.stack_st_X509_REVOKED */
            	4243, 0,
            0, 32, 2, /* 4243: struct.stack_st_fake_X509_REVOKED */
            	4250, 8,
            	365, 24,
            8884099, 8, 2, /* 4250: pointer_to_array_of_pointers_to_stack */
            	4257, 0,
            	362, 20,
            0, 8, 1, /* 4257: pointer.X509_REVOKED */
            	472, 0,
            1, 8, 1, /* 4262: pointer.struct.stack_st_X509_ALGOR */
            	4267, 0,
            0, 32, 2, /* 4267: struct.stack_st_fake_X509_ALGOR */
            	4274, 8,
            	365, 24,
            8884099, 8, 2, /* 4274: pointer_to_array_of_pointers_to_stack */
            	4281, 0,
            	362, 20,
            0, 8, 1, /* 4281: pointer.X509_ALGOR */
            	1506, 0,
            1, 8, 1, /* 4286: pointer.struct.stack_st_ASN1_OBJECT */
            	4291, 0,
            0, 32, 2, /* 4291: struct.stack_st_fake_ASN1_OBJECT */
            	4298, 8,
            	365, 24,
            8884099, 8, 2, /* 4298: pointer_to_array_of_pointers_to_stack */
            	4305, 0,
            	362, 20,
            0, 8, 1, /* 4305: pointer.ASN1_OBJECT */
            	1335, 0,
            0, 40, 5, /* 4310: struct.x509_cert_aux_st */
            	4286, 0,
            	4286, 8,
            	4323, 16,
            	4333, 24,
            	4262, 32,
            1, 8, 1, /* 4323: pointer.struct.asn1_string_st */
            	4328, 0,
            0, 24, 1, /* 4328: struct.asn1_string_st */
            	205, 8,
            1, 8, 1, /* 4333: pointer.struct.asn1_string_st */
            	4328, 0,
            1, 8, 1, /* 4338: pointer.struct.NAME_CONSTRAINTS_st */
            	1521, 0,
            1, 8, 1, /* 4343: pointer.struct.stack_st_GENERAL_NAME */
            	4348, 0,
            0, 32, 2, /* 4348: struct.stack_st_fake_GENERAL_NAME */
            	4355, 8,
            	365, 24,
            8884099, 8, 2, /* 4355: pointer_to_array_of_pointers_to_stack */
            	4362, 0,
            	362, 20,
            0, 8, 1, /* 4362: pointer.GENERAL_NAME */
            	55, 0,
            1, 8, 1, /* 4367: pointer.struct.X509_POLICY_CACHE_st */
            	3902, 0,
            1, 8, 1, /* 4372: pointer.struct.asn1_string_st */
            	4151, 0,
            1, 8, 1, /* 4377: pointer.struct.AUTHORITY_KEYID_st */
            	908, 0,
            0, 32, 2, /* 4382: struct.stack_st */
            	997, 8,
            	365, 24,
            1, 8, 1, /* 4389: pointer.struct.stack_st_X509_EXTENSION */
            	4394, 0,
            0, 32, 2, /* 4394: struct.stack_st_fake_X509_EXTENSION */
            	4401, 8,
            	365, 24,
            8884099, 8, 2, /* 4401: pointer_to_array_of_pointers_to_stack */
            	4408, 0,
            	362, 20,
            0, 8, 1, /* 4408: pointer.X509_EXTENSION */
            	527, 0,
            1, 8, 1, /* 4413: pointer.struct.asn1_string_st */
            	4328, 0,
            1, 8, 1, /* 4418: pointer.struct.X509_pubkey_st */
            	1994, 0,
            1, 8, 1, /* 4423: pointer.struct.asn1_string_st */
            	4328, 0,
            1, 8, 1, /* 4428: pointer.struct.buf_mem_st */
            	4433, 0,
            0, 24, 1, /* 4433: struct.buf_mem_st */
            	98, 8,
            1, 8, 1, /* 4438: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4443, 0,
            0, 32, 2, /* 4443: struct.stack_st_fake_X509_NAME_ENTRY */
            	4450, 8,
            	365, 24,
            8884099, 8, 2, /* 4450: pointer_to_array_of_pointers_to_stack */
            	4457, 0,
            	362, 20,
            0, 8, 1, /* 4457: pointer.X509_NAME_ENTRY */
            	326, 0,
            0, 40, 3, /* 4462: struct.X509_name_st */
            	4438, 0,
            	4428, 16,
            	205, 24,
            1, 8, 1, /* 4471: pointer.struct.X509_name_st */
            	4462, 0,
            1, 8, 1, /* 4476: pointer.struct.asn1_string_st */
            	4328, 0,
            0, 104, 11, /* 4481: struct.x509_cinf_st */
            	4476, 0,
            	4476, 8,
            	4506, 16,
            	4471, 24,
            	4511, 32,
            	4471, 40,
            	4418, 48,
            	4413, 56,
            	4413, 64,
            	4389, 72,
            	4523, 80,
            1, 8, 1, /* 4506: pointer.struct.X509_algor_st */
            	621, 0,
            1, 8, 1, /* 4511: pointer.struct.X509_val_st */
            	4516, 0,
            0, 16, 2, /* 4516: struct.X509_val_st */
            	4423, 0,
            	4423, 8,
            0, 24, 1, /* 4523: struct.ASN1_ENCODING_st */
            	205, 0,
            1, 8, 1, /* 4528: pointer.struct.x509_cinf_st */
            	4481, 0,
            1, 8, 1, /* 4533: pointer.struct.asn1_string_st */
            	611, 0,
            1, 8, 1, /* 4538: pointer.struct.NAME_CONSTRAINTS_st */
            	1521, 0,
            1, 8, 1, /* 4543: pointer.struct.stack_st_GENERAL_NAME */
            	4548, 0,
            0, 32, 2, /* 4548: struct.stack_st_fake_GENERAL_NAME */
            	4555, 8,
            	365, 24,
            8884099, 8, 2, /* 4555: pointer_to_array_of_pointers_to_stack */
            	4562, 0,
            	362, 20,
            0, 8, 1, /* 4562: pointer.GENERAL_NAME */
            	55, 0,
            1, 8, 1, /* 4567: pointer.struct.stack_st_DIST_POINT */
            	4572, 0,
            0, 32, 2, /* 4572: struct.stack_st_fake_DIST_POINT */
            	4579, 8,
            	365, 24,
            8884099, 8, 2, /* 4579: pointer_to_array_of_pointers_to_stack */
            	4586, 0,
            	362, 20,
            0, 8, 1, /* 4586: pointer.DIST_POINT */
            	3967, 0,
            1, 8, 1, /* 4591: pointer.struct.asn1_string_st */
            	611, 0,
            1, 8, 1, /* 4596: pointer.struct.X509_pubkey_st */
            	1994, 0,
            1, 8, 1, /* 4601: pointer.struct.X509_val_st */
            	4606, 0,
            0, 16, 2, /* 4606: struct.X509_val_st */
            	831, 0,
            	831, 8,
            0, 184, 12, /* 4613: struct.x509_st */
            	4640, 0,
            	616, 8,
            	898, 16,
            	98, 32,
            	4670, 40,
            	4591, 104,
            	903, 112,
            	4692, 120,
            	4567, 128,
            	4543, 136,
            	4538, 144,
            	4697, 176,
            1, 8, 1, /* 4640: pointer.struct.x509_cinf_st */
            	4645, 0,
            0, 104, 11, /* 4645: struct.x509_cinf_st */
            	606, 0,
            	606, 8,
            	616, 16,
            	783, 24,
            	4601, 32,
            	783, 40,
            	4596, 48,
            	898, 56,
            	898, 64,
            	836, 72,
            	860, 80,
            0, 16, 1, /* 4670: struct.crypto_ex_data_st */
            	4675, 0,
            1, 8, 1, /* 4675: pointer.struct.stack_st_void */
            	4680, 0,
            0, 32, 1, /* 4680: struct.stack_st_void */
            	4685, 0,
            0, 32, 2, /* 4685: struct.stack_st */
            	997, 8,
            	365, 24,
            1, 8, 1, /* 4692: pointer.struct.X509_POLICY_CACHE_st */
            	3902, 0,
            1, 8, 1, /* 4697: pointer.struct.x509_cert_aux_st */
            	4702, 0,
            0, 40, 5, /* 4702: struct.x509_cert_aux_st */
            	4715, 0,
            	4715, 8,
            	4533, 16,
            	4591, 24,
            	4739, 32,
            1, 8, 1, /* 4715: pointer.struct.stack_st_ASN1_OBJECT */
            	4720, 0,
            0, 32, 2, /* 4720: struct.stack_st_fake_ASN1_OBJECT */
            	4727, 8,
            	365, 24,
            8884099, 8, 2, /* 4727: pointer_to_array_of_pointers_to_stack */
            	4734, 0,
            	362, 20,
            0, 8, 1, /* 4734: pointer.ASN1_OBJECT */
            	1335, 0,
            1, 8, 1, /* 4739: pointer.struct.stack_st_X509_ALGOR */
            	4744, 0,
            0, 32, 2, /* 4744: struct.stack_st_fake_X509_ALGOR */
            	4751, 8,
            	365, 24,
            8884099, 8, 2, /* 4751: pointer_to_array_of_pointers_to_stack */
            	4758, 0,
            	362, 20,
            0, 8, 1, /* 4758: pointer.X509_ALGOR */
            	1506, 0,
            1, 8, 1, /* 4763: pointer.struct.x509_st */
            	4613, 0,
            8884097, 8, 0, /* 4768: pointer.func */
            8884097, 8, 0, /* 4771: pointer.func */
            8884097, 8, 0, /* 4774: pointer.func */
            8884097, 8, 0, /* 4777: pointer.func */
            8884097, 8, 0, /* 4780: pointer.func */
            8884097, 8, 0, /* 4783: pointer.func */
            8884097, 8, 0, /* 4786: pointer.func */
            8884097, 8, 0, /* 4789: pointer.func */
            1, 8, 1, /* 4792: pointer.struct.X509_VERIFY_PARAM_st */
            	4797, 0,
            0, 56, 2, /* 4797: struct.X509_VERIFY_PARAM_st */
            	98, 0,
            	4804, 48,
            1, 8, 1, /* 4804: pointer.struct.stack_st_ASN1_OBJECT */
            	4809, 0,
            0, 32, 2, /* 4809: struct.stack_st_fake_ASN1_OBJECT */
            	4816, 8,
            	365, 24,
            8884099, 8, 2, /* 4816: pointer_to_array_of_pointers_to_stack */
            	4823, 0,
            	362, 20,
            0, 8, 1, /* 4823: pointer.ASN1_OBJECT */
            	1335, 0,
            1, 8, 1, /* 4828: pointer.struct.stack_st_X509_LOOKUP */
            	4833, 0,
            0, 32, 2, /* 4833: struct.stack_st_fake_X509_LOOKUP */
            	4840, 8,
            	365, 24,
            8884099, 8, 2, /* 4840: pointer_to_array_of_pointers_to_stack */
            	4847, 0,
            	362, 20,
            0, 8, 1, /* 4847: pointer.X509_LOOKUP */
            	4852, 0,
            0, 0, 1, /* 4852: X509_LOOKUP */
            	4857, 0,
            0, 32, 3, /* 4857: struct.x509_lookup_st */
            	4866, 8,
            	98, 16,
            	4915, 24,
            1, 8, 1, /* 4866: pointer.struct.x509_lookup_method_st */
            	4871, 0,
            0, 80, 10, /* 4871: struct.x509_lookup_method_st */
            	129, 0,
            	4894, 8,
            	4897, 16,
            	4894, 24,
            	4894, 32,
            	4900, 40,
            	4903, 48,
            	4906, 56,
            	4909, 64,
            	4912, 72,
            8884097, 8, 0, /* 4894: pointer.func */
            8884097, 8, 0, /* 4897: pointer.func */
            8884097, 8, 0, /* 4900: pointer.func */
            8884097, 8, 0, /* 4903: pointer.func */
            8884097, 8, 0, /* 4906: pointer.func */
            8884097, 8, 0, /* 4909: pointer.func */
            8884097, 8, 0, /* 4912: pointer.func */
            1, 8, 1, /* 4915: pointer.struct.x509_store_st */
            	4920, 0,
            0, 144, 15, /* 4920: struct.x509_store_st */
            	4953, 8,
            	4828, 16,
            	4792, 24,
            	4789, 32,
            	4786, 40,
            	5475, 48,
            	5478, 56,
            	4789, 64,
            	5481, 72,
            	5484, 80,
            	5487, 88,
            	4783, 96,
            	5490, 104,
            	4789, 112,
            	5179, 120,
            1, 8, 1, /* 4953: pointer.struct.stack_st_X509_OBJECT */
            	4958, 0,
            0, 32, 2, /* 4958: struct.stack_st_fake_X509_OBJECT */
            	4965, 8,
            	365, 24,
            8884099, 8, 2, /* 4965: pointer_to_array_of_pointers_to_stack */
            	4972, 0,
            	362, 20,
            0, 8, 1, /* 4972: pointer.X509_OBJECT */
            	4977, 0,
            0, 0, 1, /* 4977: X509_OBJECT */
            	4982, 0,
            0, 16, 1, /* 4982: struct.x509_object_st */
            	4987, 8,
            0, 8, 4, /* 4987: union.unknown */
            	98, 0,
            	4998, 0,
            	5311, 0,
            	5392, 0,
            1, 8, 1, /* 4998: pointer.struct.x509_st */
            	5003, 0,
            0, 184, 12, /* 5003: struct.x509_st */
            	5030, 0,
            	5070, 8,
            	5145, 16,
            	98, 32,
            	5179, 40,
            	5201, 104,
            	5206, 112,
            	4692, 120,
            	5211, 128,
            	5235, 136,
            	5259, 144,
            	5264, 176,
            1, 8, 1, /* 5030: pointer.struct.x509_cinf_st */
            	5035, 0,
            0, 104, 11, /* 5035: struct.x509_cinf_st */
            	5060, 0,
            	5060, 8,
            	5070, 16,
            	5075, 24,
            	5123, 32,
            	5075, 40,
            	5140, 48,
            	5145, 56,
            	5145, 64,
            	5150, 72,
            	5174, 80,
            1, 8, 1, /* 5060: pointer.struct.asn1_string_st */
            	5065, 0,
            0, 24, 1, /* 5065: struct.asn1_string_st */
            	205, 8,
            1, 8, 1, /* 5070: pointer.struct.X509_algor_st */
            	621, 0,
            1, 8, 1, /* 5075: pointer.struct.X509_name_st */
            	5080, 0,
            0, 40, 3, /* 5080: struct.X509_name_st */
            	5089, 0,
            	5113, 16,
            	205, 24,
            1, 8, 1, /* 5089: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5094, 0,
            0, 32, 2, /* 5094: struct.stack_st_fake_X509_NAME_ENTRY */
            	5101, 8,
            	365, 24,
            8884099, 8, 2, /* 5101: pointer_to_array_of_pointers_to_stack */
            	5108, 0,
            	362, 20,
            0, 8, 1, /* 5108: pointer.X509_NAME_ENTRY */
            	326, 0,
            1, 8, 1, /* 5113: pointer.struct.buf_mem_st */
            	5118, 0,
            0, 24, 1, /* 5118: struct.buf_mem_st */
            	98, 8,
            1, 8, 1, /* 5123: pointer.struct.X509_val_st */
            	5128, 0,
            0, 16, 2, /* 5128: struct.X509_val_st */
            	5135, 0,
            	5135, 8,
            1, 8, 1, /* 5135: pointer.struct.asn1_string_st */
            	5065, 0,
            1, 8, 1, /* 5140: pointer.struct.X509_pubkey_st */
            	1994, 0,
            1, 8, 1, /* 5145: pointer.struct.asn1_string_st */
            	5065, 0,
            1, 8, 1, /* 5150: pointer.struct.stack_st_X509_EXTENSION */
            	5155, 0,
            0, 32, 2, /* 5155: struct.stack_st_fake_X509_EXTENSION */
            	5162, 8,
            	365, 24,
            8884099, 8, 2, /* 5162: pointer_to_array_of_pointers_to_stack */
            	5169, 0,
            	362, 20,
            0, 8, 1, /* 5169: pointer.X509_EXTENSION */
            	527, 0,
            0, 24, 1, /* 5174: struct.ASN1_ENCODING_st */
            	205, 0,
            0, 16, 1, /* 5179: struct.crypto_ex_data_st */
            	5184, 0,
            1, 8, 1, /* 5184: pointer.struct.stack_st_void */
            	5189, 0,
            0, 32, 1, /* 5189: struct.stack_st_void */
            	5194, 0,
            0, 32, 2, /* 5194: struct.stack_st */
            	997, 8,
            	365, 24,
            1, 8, 1, /* 5201: pointer.struct.asn1_string_st */
            	5065, 0,
            1, 8, 1, /* 5206: pointer.struct.AUTHORITY_KEYID_st */
            	908, 0,
            1, 8, 1, /* 5211: pointer.struct.stack_st_DIST_POINT */
            	5216, 0,
            0, 32, 2, /* 5216: struct.stack_st_fake_DIST_POINT */
            	5223, 8,
            	365, 24,
            8884099, 8, 2, /* 5223: pointer_to_array_of_pointers_to_stack */
            	5230, 0,
            	362, 20,
            0, 8, 1, /* 5230: pointer.DIST_POINT */
            	3967, 0,
            1, 8, 1, /* 5235: pointer.struct.stack_st_GENERAL_NAME */
            	5240, 0,
            0, 32, 2, /* 5240: struct.stack_st_fake_GENERAL_NAME */
            	5247, 8,
            	365, 24,
            8884099, 8, 2, /* 5247: pointer_to_array_of_pointers_to_stack */
            	5254, 0,
            	362, 20,
            0, 8, 1, /* 5254: pointer.GENERAL_NAME */
            	55, 0,
            1, 8, 1, /* 5259: pointer.struct.NAME_CONSTRAINTS_st */
            	1521, 0,
            1, 8, 1, /* 5264: pointer.struct.x509_cert_aux_st */
            	5269, 0,
            0, 40, 5, /* 5269: struct.x509_cert_aux_st */
            	4804, 0,
            	4804, 8,
            	5282, 16,
            	5201, 24,
            	5287, 32,
            1, 8, 1, /* 5282: pointer.struct.asn1_string_st */
            	5065, 0,
            1, 8, 1, /* 5287: pointer.struct.stack_st_X509_ALGOR */
            	5292, 0,
            0, 32, 2, /* 5292: struct.stack_st_fake_X509_ALGOR */
            	5299, 8,
            	365, 24,
            8884099, 8, 2, /* 5299: pointer_to_array_of_pointers_to_stack */
            	5306, 0,
            	362, 20,
            0, 8, 1, /* 5306: pointer.X509_ALGOR */
            	1506, 0,
            1, 8, 1, /* 5311: pointer.struct.X509_crl_st */
            	5316, 0,
            0, 120, 10, /* 5316: struct.X509_crl_st */
            	5339, 0,
            	5070, 8,
            	5145, 16,
            	5206, 32,
            	5387, 40,
            	5060, 56,
            	5060, 64,
            	956, 96,
            	1002, 104,
            	1027, 112,
            1, 8, 1, /* 5339: pointer.struct.X509_crl_info_st */
            	5344, 0,
            0, 80, 8, /* 5344: struct.X509_crl_info_st */
            	5060, 0,
            	5070, 8,
            	5075, 16,
            	5135, 24,
            	5135, 32,
            	5363, 40,
            	5150, 48,
            	5174, 56,
            1, 8, 1, /* 5363: pointer.struct.stack_st_X509_REVOKED */
            	5368, 0,
            0, 32, 2, /* 5368: struct.stack_st_fake_X509_REVOKED */
            	5375, 8,
            	365, 24,
            8884099, 8, 2, /* 5375: pointer_to_array_of_pointers_to_stack */
            	5382, 0,
            	362, 20,
            0, 8, 1, /* 5382: pointer.X509_REVOKED */
            	472, 0,
            1, 8, 1, /* 5387: pointer.struct.ISSUING_DIST_POINT_st */
            	5, 0,
            1, 8, 1, /* 5392: pointer.struct.evp_pkey_st */
            	5397, 0,
            0, 56, 4, /* 5397: struct.evp_pkey_st */
            	5408, 16,
            	5413, 24,
            	5418, 32,
            	5451, 48,
            1, 8, 1, /* 5408: pointer.struct.evp_pkey_asn1_method_st */
            	2039, 0,
            1, 8, 1, /* 5413: pointer.struct.engine_st */
            	2140, 0,
            0, 8, 5, /* 5418: union.unknown */
            	98, 0,
            	5431, 0,
            	5436, 0,
            	5441, 0,
            	5446, 0,
            1, 8, 1, /* 5431: pointer.struct.rsa_st */
            	2501, 0,
            1, 8, 1, /* 5436: pointer.struct.dsa_st */
            	2720, 0,
            1, 8, 1, /* 5441: pointer.struct.dh_st */
            	2859, 0,
            1, 8, 1, /* 5446: pointer.struct.ec_key_st */
            	2985, 0,
            1, 8, 1, /* 5451: pointer.struct.stack_st_X509_ATTRIBUTE */
            	5456, 0,
            0, 32, 2, /* 5456: struct.stack_st_fake_X509_ATTRIBUTE */
            	5463, 8,
            	365, 24,
            8884099, 8, 2, /* 5463: pointer_to_array_of_pointers_to_stack */
            	5470, 0,
            	362, 20,
            0, 8, 1, /* 5470: pointer.X509_ATTRIBUTE */
            	3513, 0,
            8884097, 8, 0, /* 5475: pointer.func */
            8884097, 8, 0, /* 5478: pointer.func */
            8884097, 8, 0, /* 5481: pointer.func */
            8884097, 8, 0, /* 5484: pointer.func */
            8884097, 8, 0, /* 5487: pointer.func */
            8884097, 8, 0, /* 5490: pointer.func */
            8884097, 8, 0, /* 5493: pointer.func */
            8884097, 8, 0, /* 5496: pointer.func */
            1, 8, 1, /* 5499: pointer.struct.stack_st_X509 */
            	5504, 0,
            0, 32, 2, /* 5504: struct.stack_st_fake_X509 */
            	5511, 8,
            	365, 24,
            8884099, 8, 2, /* 5511: pointer_to_array_of_pointers_to_stack */
            	5518, 0,
            	362, 20,
            0, 8, 1, /* 5518: pointer.X509 */
            	5523, 0,
            0, 0, 1, /* 5523: X509 */
            	5528, 0,
            0, 184, 12, /* 5528: struct.x509_st */
            	4528, 0,
            	4506, 8,
            	4413, 16,
            	98, 32,
            	5555, 40,
            	4333, 104,
            	4377, 112,
            	4367, 120,
            	5570, 128,
            	4343, 136,
            	4338, 144,
            	5594, 176,
            0, 16, 1, /* 5555: struct.crypto_ex_data_st */
            	5560, 0,
            1, 8, 1, /* 5560: pointer.struct.stack_st_void */
            	5565, 0,
            0, 32, 1, /* 5565: struct.stack_st_void */
            	4382, 0,
            1, 8, 1, /* 5570: pointer.struct.stack_st_DIST_POINT */
            	5575, 0,
            0, 32, 2, /* 5575: struct.stack_st_fake_DIST_POINT */
            	5582, 8,
            	365, 24,
            8884099, 8, 2, /* 5582: pointer_to_array_of_pointers_to_stack */
            	5589, 0,
            	362, 20,
            0, 8, 1, /* 5589: pointer.DIST_POINT */
            	3967, 0,
            1, 8, 1, /* 5594: pointer.struct.x509_cert_aux_st */
            	4310, 0,
            0, 1, 0, /* 5599: char */
            1, 8, 1, /* 5602: pointer.struct.stack_st_GENERAL_NAMES */
            	5607, 0,
            0, 32, 2, /* 5607: struct.stack_st_fake_GENERAL_NAMES */
            	5614, 8,
            	365, 24,
            8884099, 8, 2, /* 5614: pointer_to_array_of_pointers_to_stack */
            	5621, 0,
            	362, 20,
            0, 8, 1, /* 5621: pointer.GENERAL_NAMES */
            	980, 0,
            8884097, 8, 0, /* 5626: pointer.func */
            1, 8, 1, /* 5629: pointer.struct.x509_store_st */
            	5634, 0,
            0, 144, 15, /* 5634: struct.x509_store_st */
            	5667, 8,
            	5691, 16,
            	5715, 24,
            	5626, 32,
            	5493, 40,
            	5496, 48,
            	4780, 56,
            	5626, 64,
            	4777, 72,
            	4774, 80,
            	4771, 88,
            	4768, 96,
            	5727, 104,
            	5626, 112,
            	4670, 120,
            1, 8, 1, /* 5667: pointer.struct.stack_st_X509_OBJECT */
            	5672, 0,
            0, 32, 2, /* 5672: struct.stack_st_fake_X509_OBJECT */
            	5679, 8,
            	365, 24,
            8884099, 8, 2, /* 5679: pointer_to_array_of_pointers_to_stack */
            	5686, 0,
            	362, 20,
            0, 8, 1, /* 5686: pointer.X509_OBJECT */
            	4977, 0,
            1, 8, 1, /* 5691: pointer.struct.stack_st_X509_LOOKUP */
            	5696, 0,
            0, 32, 2, /* 5696: struct.stack_st_fake_X509_LOOKUP */
            	5703, 8,
            	365, 24,
            8884099, 8, 2, /* 5703: pointer_to_array_of_pointers_to_stack */
            	5710, 0,
            	362, 20,
            0, 8, 1, /* 5710: pointer.X509_LOOKUP */
            	4852, 0,
            1, 8, 1, /* 5715: pointer.struct.X509_VERIFY_PARAM_st */
            	5720, 0,
            0, 56, 2, /* 5720: struct.X509_VERIFY_PARAM_st */
            	98, 0,
            	4715, 48,
            8884097, 8, 0, /* 5727: pointer.func */
            0, 248, 25, /* 5730: struct.x509_store_ctx_st */
            	5629, 0,
            	4763, 16,
            	5499, 24,
            	5783, 32,
            	5715, 40,
            	1027, 48,
            	5626, 56,
            	5493, 64,
            	5496, 72,
            	4780, 80,
            	5626, 88,
            	4777, 96,
            	4774, 104,
            	4771, 112,
            	5626, 120,
            	4768, 128,
            	5727, 136,
            	5626, 144,
            	5499, 160,
            	4097, 168,
            	4763, 192,
            	4763, 200,
            	870, 208,
            	5835, 224,
            	4670, 232,
            1, 8, 1, /* 5783: pointer.struct.stack_st_X509_CRL */
            	5788, 0,
            0, 32, 2, /* 5788: struct.stack_st_fake_X509_CRL */
            	5795, 8,
            	365, 24,
            8884099, 8, 2, /* 5795: pointer_to_array_of_pointers_to_stack */
            	5802, 0,
            	362, 20,
            0, 8, 1, /* 5802: pointer.X509_CRL */
            	5807, 0,
            0, 0, 1, /* 5807: X509_CRL */
            	5812, 0,
            0, 120, 10, /* 5812: struct.X509_crl_st */
            	4209, 0,
            	4233, 8,
            	4372, 16,
            	4112, 32,
            	4107, 40,
            	4204, 56,
            	4204, 64,
            	5602, 96,
            	4102, 104,
            	1027, 112,
            1, 8, 1, /* 5835: pointer.struct.x509_store_ctx_st */
            	5730, 0,
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 5835,
    };
    struct lib_enter_args *args_addr = &args;
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509_STORE_CTX * *new_ret_ptr = (X509_STORE_CTX * *)new_args->ret;

    X509_STORE_CTX * (*orig_X509_STORE_CTX_new)(void);
    orig_X509_STORE_CTX_new = dlsym(RTLD_NEXT, "X509_STORE_CTX_new");
    *new_ret_ptr = (*orig_X509_STORE_CTX_new)();

    syscall(889);

    return ret;
}

