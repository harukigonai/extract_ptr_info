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

void * bb_X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d);

void * X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_get_ext_d2i called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_get_ext_d2i(arg_a,arg_b,arg_c,arg_d);
    else {
        void * (*orig_X509_get_ext_d2i)(X509 *,int,int *,int *);
        orig_X509_get_ext_d2i = dlsym(RTLD_NEXT, "X509_get_ext_d2i");
        return orig_X509_get_ext_d2i(arg_a,arg_b,arg_c,arg_d);
    }
}

void * bb_X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d) 
{
    void * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 1, /* 0: X509_ALGOR */
            	5, 0,
            0, 16, 2, /* 5: struct.X509_algor_st */
            	12, 0,
            	39, 8,
            1, 8, 1, /* 12: pointer.struct.asn1_object_st */
            	17, 0,
            0, 40, 3, /* 17: struct.asn1_object_st */
            	26, 0,
            	26, 8,
            	31, 24,
            1, 8, 1, /* 26: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 31: pointer.unsigned char */
            	36, 0,
            0, 1, 0, /* 36: unsigned char */
            1, 8, 1, /* 39: pointer.struct.asn1_type_st */
            	44, 0,
            0, 16, 1, /* 44: struct.asn1_type_st */
            	49, 8,
            0, 8, 20, /* 49: union.unknown */
            	92, 0,
            	97, 0,
            	12, 0,
            	112, 0,
            	117, 0,
            	122, 0,
            	127, 0,
            	132, 0,
            	137, 0,
            	142, 0,
            	147, 0,
            	152, 0,
            	157, 0,
            	162, 0,
            	167, 0,
            	172, 0,
            	177, 0,
            	97, 0,
            	97, 0,
            	182, 0,
            1, 8, 1, /* 92: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 97: pointer.struct.asn1_string_st */
            	102, 0,
            0, 24, 1, /* 102: struct.asn1_string_st */
            	107, 8,
            1, 8, 1, /* 107: pointer.unsigned char */
            	36, 0,
            1, 8, 1, /* 112: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 117: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 122: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 127: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 132: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 137: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 142: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 147: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 152: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 157: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 162: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 167: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 172: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 177: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 182: pointer.struct.ASN1_VALUE_st */
            	187, 0,
            0, 0, 0, /* 187: struct.ASN1_VALUE_st */
            1, 8, 1, /* 190: pointer.struct.stack_st_ASN1_OBJECT */
            	195, 0,
            0, 32, 2, /* 195: struct.stack_st_fake_ASN1_OBJECT */
            	202, 8,
            	231, 24,
            8884099, 8, 2, /* 202: pointer_to_array_of_pointers_to_stack */
            	209, 0,
            	228, 20,
            0, 8, 1, /* 209: pointer.ASN1_OBJECT */
            	214, 0,
            0, 0, 1, /* 214: ASN1_OBJECT */
            	219, 0,
            0, 40, 3, /* 219: struct.asn1_object_st */
            	26, 0,
            	26, 8,
            	31, 24,
            0, 4, 0, /* 228: int */
            8884097, 8, 0, /* 231: pointer.func */
            1, 8, 1, /* 234: pointer.struct.x509_cert_aux_st */
            	239, 0,
            0, 40, 5, /* 239: struct.x509_cert_aux_st */
            	190, 0,
            	190, 8,
            	252, 16,
            	262, 24,
            	267, 32,
            1, 8, 1, /* 252: pointer.struct.asn1_string_st */
            	257, 0,
            0, 24, 1, /* 257: struct.asn1_string_st */
            	107, 8,
            1, 8, 1, /* 262: pointer.struct.asn1_string_st */
            	257, 0,
            1, 8, 1, /* 267: pointer.struct.stack_st_X509_ALGOR */
            	272, 0,
            0, 32, 2, /* 272: struct.stack_st_fake_X509_ALGOR */
            	279, 8,
            	231, 24,
            8884099, 8, 2, /* 279: pointer_to_array_of_pointers_to_stack */
            	286, 0,
            	228, 20,
            0, 8, 1, /* 286: pointer.X509_ALGOR */
            	0, 0,
            1, 8, 1, /* 291: pointer.struct.EDIPartyName_st */
            	296, 0,
            0, 16, 2, /* 296: struct.EDIPartyName_st */
            	303, 0,
            	303, 8,
            1, 8, 1, /* 303: pointer.struct.asn1_string_st */
            	308, 0,
            0, 24, 1, /* 308: struct.asn1_string_st */
            	107, 8,
            1, 8, 1, /* 313: pointer.struct.stack_st_X509_NAME_ENTRY */
            	318, 0,
            0, 32, 2, /* 318: struct.stack_st_fake_X509_NAME_ENTRY */
            	325, 8,
            	231, 24,
            8884099, 8, 2, /* 325: pointer_to_array_of_pointers_to_stack */
            	332, 0,
            	228, 20,
            0, 8, 1, /* 332: pointer.X509_NAME_ENTRY */
            	337, 0,
            0, 0, 1, /* 337: X509_NAME_ENTRY */
            	342, 0,
            0, 24, 2, /* 342: struct.X509_name_entry_st */
            	349, 0,
            	363, 8,
            1, 8, 1, /* 349: pointer.struct.asn1_object_st */
            	354, 0,
            0, 40, 3, /* 354: struct.asn1_object_st */
            	26, 0,
            	26, 8,
            	31, 24,
            1, 8, 1, /* 363: pointer.struct.asn1_string_st */
            	368, 0,
            0, 24, 1, /* 368: struct.asn1_string_st */
            	107, 8,
            0, 40, 3, /* 373: struct.X509_name_st */
            	313, 0,
            	382, 16,
            	107, 24,
            1, 8, 1, /* 382: pointer.struct.buf_mem_st */
            	387, 0,
            0, 24, 1, /* 387: struct.buf_mem_st */
            	92, 8,
            1, 8, 1, /* 392: pointer.struct.X509_name_st */
            	373, 0,
            1, 8, 1, /* 397: pointer.struct.asn1_string_st */
            	308, 0,
            1, 8, 1, /* 402: pointer.struct.asn1_string_st */
            	308, 0,
            1, 8, 1, /* 407: pointer.struct.asn1_string_st */
            	308, 0,
            1, 8, 1, /* 412: pointer.struct.asn1_string_st */
            	308, 0,
            1, 8, 1, /* 417: pointer.struct.asn1_string_st */
            	308, 0,
            1, 8, 1, /* 422: pointer.struct.asn1_string_st */
            	308, 0,
            0, 8, 20, /* 427: union.unknown */
            	92, 0,
            	303, 0,
            	470, 0,
            	484, 0,
            	489, 0,
            	494, 0,
            	422, 0,
            	499, 0,
            	417, 0,
            	504, 0,
            	412, 0,
            	407, 0,
            	509, 0,
            	514, 0,
            	402, 0,
            	519, 0,
            	397, 0,
            	303, 0,
            	303, 0,
            	524, 0,
            1, 8, 1, /* 470: pointer.struct.asn1_object_st */
            	475, 0,
            0, 40, 3, /* 475: struct.asn1_object_st */
            	26, 0,
            	26, 8,
            	31, 24,
            1, 8, 1, /* 484: pointer.struct.asn1_string_st */
            	308, 0,
            1, 8, 1, /* 489: pointer.struct.asn1_string_st */
            	308, 0,
            1, 8, 1, /* 494: pointer.struct.asn1_string_st */
            	308, 0,
            1, 8, 1, /* 499: pointer.struct.asn1_string_st */
            	308, 0,
            1, 8, 1, /* 504: pointer.struct.asn1_string_st */
            	308, 0,
            1, 8, 1, /* 509: pointer.struct.asn1_string_st */
            	308, 0,
            1, 8, 1, /* 514: pointer.struct.asn1_string_st */
            	308, 0,
            1, 8, 1, /* 519: pointer.struct.asn1_string_st */
            	308, 0,
            1, 8, 1, /* 524: pointer.struct.ASN1_VALUE_st */
            	529, 0,
            0, 0, 0, /* 529: struct.ASN1_VALUE_st */
            1, 8, 1, /* 532: pointer.struct.otherName_st */
            	537, 0,
            0, 16, 2, /* 537: struct.otherName_st */
            	470, 0,
            	544, 8,
            1, 8, 1, /* 544: pointer.struct.asn1_type_st */
            	549, 0,
            0, 16, 1, /* 549: struct.asn1_type_st */
            	427, 8,
            0, 16, 1, /* 554: struct.GENERAL_NAME_st */
            	559, 8,
            0, 8, 15, /* 559: union.unknown */
            	92, 0,
            	532, 0,
            	504, 0,
            	504, 0,
            	544, 0,
            	392, 0,
            	291, 0,
            	504, 0,
            	422, 0,
            	470, 0,
            	422, 0,
            	392, 0,
            	504, 0,
            	470, 0,
            	544, 0,
            1, 8, 1, /* 592: pointer.struct.GENERAL_NAME_st */
            	554, 0,
            1, 8, 1, /* 597: pointer.struct.NAME_CONSTRAINTS_st */
            	602, 0,
            0, 16, 2, /* 602: struct.NAME_CONSTRAINTS_st */
            	609, 0,
            	609, 8,
            1, 8, 1, /* 609: pointer.struct.stack_st_GENERAL_SUBTREE */
            	614, 0,
            0, 32, 2, /* 614: struct.stack_st_fake_GENERAL_SUBTREE */
            	621, 8,
            	231, 24,
            8884099, 8, 2, /* 621: pointer_to_array_of_pointers_to_stack */
            	628, 0,
            	228, 20,
            0, 8, 1, /* 628: pointer.GENERAL_SUBTREE */
            	633, 0,
            0, 0, 1, /* 633: GENERAL_SUBTREE */
            	638, 0,
            0, 24, 3, /* 638: struct.GENERAL_SUBTREE_st */
            	592, 0,
            	484, 8,
            	484, 16,
            1, 8, 1, /* 647: pointer.struct.stack_st_GENERAL_NAME */
            	652, 0,
            0, 32, 2, /* 652: struct.stack_st_fake_GENERAL_NAME */
            	659, 8,
            	231, 24,
            8884099, 8, 2, /* 659: pointer_to_array_of_pointers_to_stack */
            	666, 0,
            	228, 20,
            0, 8, 1, /* 666: pointer.GENERAL_NAME */
            	671, 0,
            0, 0, 1, /* 671: GENERAL_NAME */
            	676, 0,
            0, 16, 1, /* 676: struct.GENERAL_NAME_st */
            	681, 8,
            0, 8, 15, /* 681: union.unknown */
            	92, 0,
            	714, 0,
            	833, 0,
            	833, 0,
            	740, 0,
            	881, 0,
            	929, 0,
            	833, 0,
            	818, 0,
            	726, 0,
            	818, 0,
            	881, 0,
            	833, 0,
            	726, 0,
            	740, 0,
            1, 8, 1, /* 714: pointer.struct.otherName_st */
            	719, 0,
            0, 16, 2, /* 719: struct.otherName_st */
            	726, 0,
            	740, 8,
            1, 8, 1, /* 726: pointer.struct.asn1_object_st */
            	731, 0,
            0, 40, 3, /* 731: struct.asn1_object_st */
            	26, 0,
            	26, 8,
            	31, 24,
            1, 8, 1, /* 740: pointer.struct.asn1_type_st */
            	745, 0,
            0, 16, 1, /* 745: struct.asn1_type_st */
            	750, 8,
            0, 8, 20, /* 750: union.unknown */
            	92, 0,
            	793, 0,
            	726, 0,
            	803, 0,
            	808, 0,
            	813, 0,
            	818, 0,
            	823, 0,
            	828, 0,
            	833, 0,
            	838, 0,
            	843, 0,
            	848, 0,
            	853, 0,
            	858, 0,
            	863, 0,
            	868, 0,
            	793, 0,
            	793, 0,
            	873, 0,
            1, 8, 1, /* 793: pointer.struct.asn1_string_st */
            	798, 0,
            0, 24, 1, /* 798: struct.asn1_string_st */
            	107, 8,
            1, 8, 1, /* 803: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 808: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 813: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 818: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 823: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 828: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 833: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 838: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 843: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 848: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 853: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 858: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 863: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 868: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 873: pointer.struct.ASN1_VALUE_st */
            	878, 0,
            0, 0, 0, /* 878: struct.ASN1_VALUE_st */
            1, 8, 1, /* 881: pointer.struct.X509_name_st */
            	886, 0,
            0, 40, 3, /* 886: struct.X509_name_st */
            	895, 0,
            	919, 16,
            	107, 24,
            1, 8, 1, /* 895: pointer.struct.stack_st_X509_NAME_ENTRY */
            	900, 0,
            0, 32, 2, /* 900: struct.stack_st_fake_X509_NAME_ENTRY */
            	907, 8,
            	231, 24,
            8884099, 8, 2, /* 907: pointer_to_array_of_pointers_to_stack */
            	914, 0,
            	228, 20,
            0, 8, 1, /* 914: pointer.X509_NAME_ENTRY */
            	337, 0,
            1, 8, 1, /* 919: pointer.struct.buf_mem_st */
            	924, 0,
            0, 24, 1, /* 924: struct.buf_mem_st */
            	92, 8,
            1, 8, 1, /* 929: pointer.struct.EDIPartyName_st */
            	934, 0,
            0, 16, 2, /* 934: struct.EDIPartyName_st */
            	793, 0,
            	793, 8,
            0, 24, 1, /* 941: struct.asn1_string_st */
            	107, 8,
            1, 8, 1, /* 946: pointer.struct.buf_mem_st */
            	951, 0,
            0, 24, 1, /* 951: struct.buf_mem_st */
            	92, 8,
            1, 8, 1, /* 956: pointer.struct.stack_st_X509_NAME_ENTRY */
            	961, 0,
            0, 32, 2, /* 961: struct.stack_st_fake_X509_NAME_ENTRY */
            	968, 8,
            	231, 24,
            8884099, 8, 2, /* 968: pointer_to_array_of_pointers_to_stack */
            	975, 0,
            	228, 20,
            0, 8, 1, /* 975: pointer.X509_NAME_ENTRY */
            	337, 0,
            1, 8, 1, /* 980: pointer.struct.stack_st_GENERAL_NAME */
            	985, 0,
            0, 32, 2, /* 985: struct.stack_st_fake_GENERAL_NAME */
            	992, 8,
            	231, 24,
            8884099, 8, 2, /* 992: pointer_to_array_of_pointers_to_stack */
            	999, 0,
            	228, 20,
            0, 8, 1, /* 999: pointer.GENERAL_NAME */
            	671, 0,
            0, 8, 2, /* 1004: union.unknown */
            	980, 0,
            	956, 0,
            0, 24, 2, /* 1011: struct.DIST_POINT_NAME_st */
            	1004, 8,
            	1018, 16,
            1, 8, 1, /* 1018: pointer.struct.X509_name_st */
            	1023, 0,
            0, 40, 3, /* 1023: struct.X509_name_st */
            	956, 0,
            	946, 16,
            	107, 24,
            0, 0, 1, /* 1032: DIST_POINT */
            	1037, 0,
            0, 32, 3, /* 1037: struct.DIST_POINT_st */
            	1046, 0,
            	1051, 8,
            	980, 16,
            1, 8, 1, /* 1046: pointer.struct.DIST_POINT_NAME_st */
            	1011, 0,
            1, 8, 1, /* 1051: pointer.struct.asn1_string_st */
            	941, 0,
            1, 8, 1, /* 1056: pointer.struct.stack_st_DIST_POINT */
            	1061, 0,
            0, 32, 2, /* 1061: struct.stack_st_fake_DIST_POINT */
            	1068, 8,
            	231, 24,
            8884099, 8, 2, /* 1068: pointer_to_array_of_pointers_to_stack */
            	1075, 0,
            	228, 20,
            0, 8, 1, /* 1075: pointer.DIST_POINT */
            	1032, 0,
            0, 32, 3, /* 1080: struct.X509_POLICY_DATA_st */
            	1089, 8,
            	1103, 16,
            	1348, 24,
            1, 8, 1, /* 1089: pointer.struct.asn1_object_st */
            	1094, 0,
            0, 40, 3, /* 1094: struct.asn1_object_st */
            	26, 0,
            	26, 8,
            	31, 24,
            1, 8, 1, /* 1103: pointer.struct.stack_st_POLICYQUALINFO */
            	1108, 0,
            0, 32, 2, /* 1108: struct.stack_st_fake_POLICYQUALINFO */
            	1115, 8,
            	231, 24,
            8884099, 8, 2, /* 1115: pointer_to_array_of_pointers_to_stack */
            	1122, 0,
            	228, 20,
            0, 8, 1, /* 1122: pointer.POLICYQUALINFO */
            	1127, 0,
            0, 0, 1, /* 1127: POLICYQUALINFO */
            	1132, 0,
            0, 16, 2, /* 1132: struct.POLICYQUALINFO_st */
            	1139, 0,
            	1153, 8,
            1, 8, 1, /* 1139: pointer.struct.asn1_object_st */
            	1144, 0,
            0, 40, 3, /* 1144: struct.asn1_object_st */
            	26, 0,
            	26, 8,
            	31, 24,
            0, 8, 3, /* 1153: union.unknown */
            	1162, 0,
            	1172, 0,
            	1230, 0,
            1, 8, 1, /* 1162: pointer.struct.asn1_string_st */
            	1167, 0,
            0, 24, 1, /* 1167: struct.asn1_string_st */
            	107, 8,
            1, 8, 1, /* 1172: pointer.struct.USERNOTICE_st */
            	1177, 0,
            0, 16, 2, /* 1177: struct.USERNOTICE_st */
            	1184, 0,
            	1196, 8,
            1, 8, 1, /* 1184: pointer.struct.NOTICEREF_st */
            	1189, 0,
            0, 16, 2, /* 1189: struct.NOTICEREF_st */
            	1196, 0,
            	1201, 8,
            1, 8, 1, /* 1196: pointer.struct.asn1_string_st */
            	1167, 0,
            1, 8, 1, /* 1201: pointer.struct.stack_st_ASN1_INTEGER */
            	1206, 0,
            0, 32, 2, /* 1206: struct.stack_st_fake_ASN1_INTEGER */
            	1213, 8,
            	231, 24,
            8884099, 8, 2, /* 1213: pointer_to_array_of_pointers_to_stack */
            	1220, 0,
            	228, 20,
            0, 8, 1, /* 1220: pointer.ASN1_INTEGER */
            	1225, 0,
            0, 0, 1, /* 1225: ASN1_INTEGER */
            	102, 0,
            1, 8, 1, /* 1230: pointer.struct.asn1_type_st */
            	1235, 0,
            0, 16, 1, /* 1235: struct.asn1_type_st */
            	1240, 8,
            0, 8, 20, /* 1240: union.unknown */
            	92, 0,
            	1196, 0,
            	1139, 0,
            	1283, 0,
            	1288, 0,
            	1293, 0,
            	1298, 0,
            	1303, 0,
            	1308, 0,
            	1162, 0,
            	1313, 0,
            	1318, 0,
            	1323, 0,
            	1328, 0,
            	1333, 0,
            	1338, 0,
            	1343, 0,
            	1196, 0,
            	1196, 0,
            	524, 0,
            1, 8, 1, /* 1283: pointer.struct.asn1_string_st */
            	1167, 0,
            1, 8, 1, /* 1288: pointer.struct.asn1_string_st */
            	1167, 0,
            1, 8, 1, /* 1293: pointer.struct.asn1_string_st */
            	1167, 0,
            1, 8, 1, /* 1298: pointer.struct.asn1_string_st */
            	1167, 0,
            1, 8, 1, /* 1303: pointer.struct.asn1_string_st */
            	1167, 0,
            1, 8, 1, /* 1308: pointer.struct.asn1_string_st */
            	1167, 0,
            1, 8, 1, /* 1313: pointer.struct.asn1_string_st */
            	1167, 0,
            1, 8, 1, /* 1318: pointer.struct.asn1_string_st */
            	1167, 0,
            1, 8, 1, /* 1323: pointer.struct.asn1_string_st */
            	1167, 0,
            1, 8, 1, /* 1328: pointer.struct.asn1_string_st */
            	1167, 0,
            1, 8, 1, /* 1333: pointer.struct.asn1_string_st */
            	1167, 0,
            1, 8, 1, /* 1338: pointer.struct.asn1_string_st */
            	1167, 0,
            1, 8, 1, /* 1343: pointer.struct.asn1_string_st */
            	1167, 0,
            1, 8, 1, /* 1348: pointer.struct.stack_st_ASN1_OBJECT */
            	1353, 0,
            0, 32, 2, /* 1353: struct.stack_st_fake_ASN1_OBJECT */
            	1360, 8,
            	231, 24,
            8884099, 8, 2, /* 1360: pointer_to_array_of_pointers_to_stack */
            	1367, 0,
            	228, 20,
            0, 8, 1, /* 1367: pointer.ASN1_OBJECT */
            	214, 0,
            1, 8, 1, /* 1372: pointer.struct.stack_st_X509_POLICY_DATA */
            	1377, 0,
            0, 32, 2, /* 1377: struct.stack_st_fake_X509_POLICY_DATA */
            	1384, 8,
            	231, 24,
            8884099, 8, 2, /* 1384: pointer_to_array_of_pointers_to_stack */
            	1391, 0,
            	228, 20,
            0, 8, 1, /* 1391: pointer.X509_POLICY_DATA */
            	1396, 0,
            0, 0, 1, /* 1396: X509_POLICY_DATA */
            	1080, 0,
            1, 8, 1, /* 1401: pointer.struct.stack_st_ASN1_OBJECT */
            	1406, 0,
            0, 32, 2, /* 1406: struct.stack_st_fake_ASN1_OBJECT */
            	1413, 8,
            	231, 24,
            8884099, 8, 2, /* 1413: pointer_to_array_of_pointers_to_stack */
            	1420, 0,
            	228, 20,
            0, 8, 1, /* 1420: pointer.ASN1_OBJECT */
            	214, 0,
            1, 8, 1, /* 1425: pointer.struct.stack_st_POLICYQUALINFO */
            	1430, 0,
            0, 32, 2, /* 1430: struct.stack_st_fake_POLICYQUALINFO */
            	1437, 8,
            	231, 24,
            8884099, 8, 2, /* 1437: pointer_to_array_of_pointers_to_stack */
            	1444, 0,
            	228, 20,
            0, 8, 1, /* 1444: pointer.POLICYQUALINFO */
            	1127, 0,
            0, 40, 3, /* 1449: struct.asn1_object_st */
            	26, 0,
            	26, 8,
            	31, 24,
            0, 32, 3, /* 1458: struct.X509_POLICY_DATA_st */
            	1467, 8,
            	1425, 16,
            	1401, 24,
            1, 8, 1, /* 1467: pointer.struct.asn1_object_st */
            	1449, 0,
            1, 8, 1, /* 1472: pointer.struct.X509_POLICY_DATA_st */
            	1458, 0,
            0, 40, 2, /* 1477: struct.X509_POLICY_CACHE_st */
            	1472, 0,
            	1372, 8,
            1, 8, 1, /* 1484: pointer.struct.stack_st_GENERAL_NAME */
            	1489, 0,
            0, 32, 2, /* 1489: struct.stack_st_fake_GENERAL_NAME */
            	1496, 8,
            	231, 24,
            8884099, 8, 2, /* 1496: pointer_to_array_of_pointers_to_stack */
            	1503, 0,
            	228, 20,
            0, 8, 1, /* 1503: pointer.GENERAL_NAME */
            	671, 0,
            1, 8, 1, /* 1508: pointer.struct.asn1_string_st */
            	1513, 0,
            0, 24, 1, /* 1513: struct.asn1_string_st */
            	107, 8,
            0, 32, 1, /* 1518: struct.stack_st_void */
            	1523, 0,
            0, 32, 2, /* 1523: struct.stack_st */
            	1530, 8,
            	231, 24,
            1, 8, 1, /* 1530: pointer.pointer.char */
            	92, 0,
            1, 8, 1, /* 1535: pointer.struct.stack_st_void */
            	1518, 0,
            0, 16, 1, /* 1540: struct.crypto_ex_data_st */
            	1535, 0,
            0, 40, 3, /* 1545: struct.asn1_object_st */
            	26, 0,
            	26, 8,
            	31, 24,
            1, 8, 1, /* 1554: pointer.struct.asn1_object_st */
            	1545, 0,
            0, 24, 2, /* 1559: struct.X509_extension_st */
            	1554, 0,
            	262, 16,
            0, 0, 1, /* 1566: X509_EXTENSION */
            	1559, 0,
            1, 8, 1, /* 1571: pointer.struct.stack_st_X509_EXTENSION */
            	1576, 0,
            0, 32, 2, /* 1576: struct.stack_st_fake_X509_EXTENSION */
            	1583, 8,
            	231, 24,
            8884099, 8, 2, /* 1583: pointer_to_array_of_pointers_to_stack */
            	1590, 0,
            	228, 20,
            0, 8, 1, /* 1590: pointer.X509_EXTENSION */
            	1566, 0,
            1, 8, 1, /* 1595: pointer.struct.asn1_string_st */
            	257, 0,
            1, 8, 1, /* 1600: pointer.struct.asn1_string_st */
            	1605, 0,
            0, 24, 1, /* 1605: struct.asn1_string_st */
            	107, 8,
            1, 8, 1, /* 1610: pointer.struct.asn1_string_st */
            	1605, 0,
            1, 8, 1, /* 1615: pointer.struct.asn1_string_st */
            	1605, 0,
            1, 8, 1, /* 1620: pointer.struct.asn1_string_st */
            	1605, 0,
            1, 8, 1, /* 1625: pointer.struct.asn1_string_st */
            	1605, 0,
            1, 8, 1, /* 1630: pointer.struct.asn1_string_st */
            	1605, 0,
            1, 8, 1, /* 1635: pointer.struct.asn1_string_st */
            	1605, 0,
            1, 8, 1, /* 1640: pointer.struct.asn1_string_st */
            	1605, 0,
            0, 16, 1, /* 1645: struct.asn1_type_st */
            	1650, 8,
            0, 8, 20, /* 1650: union.unknown */
            	92, 0,
            	1640, 0,
            	1693, 0,
            	1707, 0,
            	1635, 0,
            	1712, 0,
            	1630, 0,
            	1717, 0,
            	1625, 0,
            	1620, 0,
            	1615, 0,
            	1610, 0,
            	1722, 0,
            	1727, 0,
            	1732, 0,
            	1737, 0,
            	1600, 0,
            	1640, 0,
            	1640, 0,
            	182, 0,
            1, 8, 1, /* 1693: pointer.struct.asn1_object_st */
            	1698, 0,
            0, 40, 3, /* 1698: struct.asn1_object_st */
            	26, 0,
            	26, 8,
            	31, 24,
            1, 8, 1, /* 1707: pointer.struct.asn1_string_st */
            	1605, 0,
            1, 8, 1, /* 1712: pointer.struct.asn1_string_st */
            	1605, 0,
            1, 8, 1, /* 1717: pointer.struct.asn1_string_st */
            	1605, 0,
            1, 8, 1, /* 1722: pointer.struct.asn1_string_st */
            	1605, 0,
            1, 8, 1, /* 1727: pointer.struct.asn1_string_st */
            	1605, 0,
            1, 8, 1, /* 1732: pointer.struct.asn1_string_st */
            	1605, 0,
            1, 8, 1, /* 1737: pointer.struct.asn1_string_st */
            	1605, 0,
            1, 8, 1, /* 1742: pointer.struct.asn1_string_st */
            	1747, 0,
            0, 24, 1, /* 1747: struct.asn1_string_st */
            	107, 8,
            1, 8, 1, /* 1752: pointer.struct.asn1_string_st */
            	1747, 0,
            1, 8, 1, /* 1757: pointer.struct.asn1_string_st */
            	1747, 0,
            1, 8, 1, /* 1762: pointer.struct.asn1_string_st */
            	1747, 0,
            1, 8, 1, /* 1767: pointer.struct.asn1_string_st */
            	1747, 0,
            1, 8, 1, /* 1772: pointer.struct.asn1_object_st */
            	1777, 0,
            0, 40, 3, /* 1777: struct.asn1_object_st */
            	26, 0,
            	26, 8,
            	31, 24,
            1, 8, 1, /* 1786: pointer.struct.asn1_string_st */
            	1747, 0,
            1, 8, 1, /* 1791: pointer.struct.stack_st_ASN1_TYPE */
            	1796, 0,
            0, 32, 2, /* 1796: struct.stack_st_fake_ASN1_TYPE */
            	1803, 8,
            	231, 24,
            8884099, 8, 2, /* 1803: pointer_to_array_of_pointers_to_stack */
            	1810, 0,
            	228, 20,
            0, 8, 1, /* 1810: pointer.ASN1_TYPE */
            	1815, 0,
            0, 0, 1, /* 1815: ASN1_TYPE */
            	1820, 0,
            0, 16, 1, /* 1820: struct.asn1_type_st */
            	1825, 8,
            0, 8, 20, /* 1825: union.unknown */
            	92, 0,
            	1786, 0,
            	1772, 0,
            	1767, 0,
            	1868, 0,
            	1873, 0,
            	1878, 0,
            	1883, 0,
            	1888, 0,
            	1762, 0,
            	1893, 0,
            	1898, 0,
            	1903, 0,
            	1908, 0,
            	1757, 0,
            	1752, 0,
            	1742, 0,
            	1786, 0,
            	1786, 0,
            	1913, 0,
            1, 8, 1, /* 1868: pointer.struct.asn1_string_st */
            	1747, 0,
            1, 8, 1, /* 1873: pointer.struct.asn1_string_st */
            	1747, 0,
            1, 8, 1, /* 1878: pointer.struct.asn1_string_st */
            	1747, 0,
            1, 8, 1, /* 1883: pointer.struct.asn1_string_st */
            	1747, 0,
            1, 8, 1, /* 1888: pointer.struct.asn1_string_st */
            	1747, 0,
            1, 8, 1, /* 1893: pointer.struct.asn1_string_st */
            	1747, 0,
            1, 8, 1, /* 1898: pointer.struct.asn1_string_st */
            	1747, 0,
            1, 8, 1, /* 1903: pointer.struct.asn1_string_st */
            	1747, 0,
            1, 8, 1, /* 1908: pointer.struct.asn1_string_st */
            	1747, 0,
            1, 8, 1, /* 1913: pointer.struct.ASN1_VALUE_st */
            	1918, 0,
            0, 0, 0, /* 1918: struct.ASN1_VALUE_st */
            0, 24, 2, /* 1921: struct.x509_attributes_st */
            	1693, 0,
            	1928, 16,
            0, 8, 3, /* 1928: union.unknown */
            	92, 0,
            	1791, 0,
            	1937, 0,
            1, 8, 1, /* 1937: pointer.struct.asn1_type_st */
            	1645, 0,
            1, 8, 1, /* 1942: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1947, 0,
            0, 32, 2, /* 1947: struct.stack_st_fake_X509_ATTRIBUTE */
            	1954, 8,
            	231, 24,
            8884099, 8, 2, /* 1954: pointer_to_array_of_pointers_to_stack */
            	1961, 0,
            	228, 20,
            0, 8, 1, /* 1961: pointer.X509_ATTRIBUTE */
            	1966, 0,
            0, 0, 1, /* 1966: X509_ATTRIBUTE */
            	1921, 0,
            1, 8, 1, /* 1971: pointer.struct.ec_extra_data_st */
            	1976, 0,
            0, 40, 5, /* 1976: struct.ec_extra_data_st */
            	1971, 0,
            	1989, 8,
            	1992, 16,
            	1995, 24,
            	1995, 32,
            0, 8, 0, /* 1989: pointer.void */
            8884097, 8, 0, /* 1992: pointer.func */
            8884097, 8, 0, /* 1995: pointer.func */
            1, 8, 1, /* 1998: pointer.struct.ec_extra_data_st */
            	1976, 0,
            0, 24, 1, /* 2003: struct.bignum_st */
            	2008, 0,
            8884099, 8, 2, /* 2008: pointer_to_array_of_pointers_to_stack */
            	2015, 0,
            	228, 12,
            0, 4, 0, /* 2015: unsigned int */
            1, 8, 1, /* 2018: pointer.struct.bignum_st */
            	2003, 0,
            1, 8, 1, /* 2023: pointer.struct.ec_point_st */
            	2028, 0,
            0, 88, 4, /* 2028: struct.ec_point_st */
            	2039, 0,
            	2211, 8,
            	2211, 32,
            	2211, 56,
            1, 8, 1, /* 2039: pointer.struct.ec_method_st */
            	2044, 0,
            0, 304, 37, /* 2044: struct.ec_method_st */
            	2121, 8,
            	2124, 16,
            	2124, 24,
            	2127, 32,
            	2130, 40,
            	2133, 48,
            	2136, 56,
            	2139, 64,
            	2142, 72,
            	2145, 80,
            	2145, 88,
            	2148, 96,
            	2151, 104,
            	2154, 112,
            	2157, 120,
            	2160, 128,
            	2163, 136,
            	2166, 144,
            	2169, 152,
            	2172, 160,
            	2175, 168,
            	2178, 176,
            	2181, 184,
            	2184, 192,
            	2187, 200,
            	2190, 208,
            	2181, 216,
            	2193, 224,
            	2196, 232,
            	2199, 240,
            	2136, 248,
            	2202, 256,
            	2205, 264,
            	2202, 272,
            	2205, 280,
            	2205, 288,
            	2208, 296,
            8884097, 8, 0, /* 2121: pointer.func */
            8884097, 8, 0, /* 2124: pointer.func */
            8884097, 8, 0, /* 2127: pointer.func */
            8884097, 8, 0, /* 2130: pointer.func */
            8884097, 8, 0, /* 2133: pointer.func */
            8884097, 8, 0, /* 2136: pointer.func */
            8884097, 8, 0, /* 2139: pointer.func */
            8884097, 8, 0, /* 2142: pointer.func */
            8884097, 8, 0, /* 2145: pointer.func */
            8884097, 8, 0, /* 2148: pointer.func */
            8884097, 8, 0, /* 2151: pointer.func */
            8884097, 8, 0, /* 2154: pointer.func */
            8884097, 8, 0, /* 2157: pointer.func */
            8884097, 8, 0, /* 2160: pointer.func */
            8884097, 8, 0, /* 2163: pointer.func */
            8884097, 8, 0, /* 2166: pointer.func */
            8884097, 8, 0, /* 2169: pointer.func */
            8884097, 8, 0, /* 2172: pointer.func */
            8884097, 8, 0, /* 2175: pointer.func */
            8884097, 8, 0, /* 2178: pointer.func */
            8884097, 8, 0, /* 2181: pointer.func */
            8884097, 8, 0, /* 2184: pointer.func */
            8884097, 8, 0, /* 2187: pointer.func */
            8884097, 8, 0, /* 2190: pointer.func */
            8884097, 8, 0, /* 2193: pointer.func */
            8884097, 8, 0, /* 2196: pointer.func */
            8884097, 8, 0, /* 2199: pointer.func */
            8884097, 8, 0, /* 2202: pointer.func */
            8884097, 8, 0, /* 2205: pointer.func */
            8884097, 8, 0, /* 2208: pointer.func */
            0, 24, 1, /* 2211: struct.bignum_st */
            	2216, 0,
            8884099, 8, 2, /* 2216: pointer_to_array_of_pointers_to_stack */
            	2015, 0,
            	228, 12,
            8884097, 8, 0, /* 2223: pointer.func */
            1, 8, 1, /* 2226: pointer.struct.ec_extra_data_st */
            	2231, 0,
            0, 40, 5, /* 2231: struct.ec_extra_data_st */
            	2226, 0,
            	1989, 8,
            	1992, 16,
            	1995, 24,
            	1995, 32,
            1, 8, 1, /* 2244: pointer.struct.ec_extra_data_st */
            	2231, 0,
            0, 24, 1, /* 2249: struct.bignum_st */
            	2254, 0,
            8884099, 8, 2, /* 2254: pointer_to_array_of_pointers_to_stack */
            	2015, 0,
            	228, 12,
            1, 8, 1, /* 2261: pointer.struct.asn1_string_st */
            	1513, 0,
            8884097, 8, 0, /* 2266: pointer.func */
            8884097, 8, 0, /* 2269: pointer.func */
            8884097, 8, 0, /* 2272: pointer.func */
            8884097, 8, 0, /* 2275: pointer.func */
            8884097, 8, 0, /* 2278: pointer.func */
            8884097, 8, 0, /* 2281: pointer.func */
            1, 8, 1, /* 2284: pointer.struct.X509_val_st */
            	2289, 0,
            0, 16, 2, /* 2289: struct.X509_val_st */
            	2296, 0,
            	2296, 8,
            1, 8, 1, /* 2296: pointer.struct.asn1_string_st */
            	257, 0,
            8884097, 8, 0, /* 2301: pointer.func */
            8884097, 8, 0, /* 2304: pointer.func */
            8884097, 8, 0, /* 2307: pointer.func */
            1, 8, 1, /* 2310: pointer.struct.dh_method */
            	2315, 0,
            0, 72, 8, /* 2315: struct.dh_method */
            	26, 0,
            	2334, 8,
            	2337, 16,
            	2307, 24,
            	2334, 32,
            	2334, 40,
            	92, 56,
            	2340, 64,
            8884097, 8, 0, /* 2334: pointer.func */
            8884097, 8, 0, /* 2337: pointer.func */
            8884097, 8, 0, /* 2340: pointer.func */
            8884097, 8, 0, /* 2343: pointer.func */
            8884097, 8, 0, /* 2346: pointer.func */
            8884097, 8, 0, /* 2349: pointer.func */
            8884097, 8, 0, /* 2352: pointer.func */
            8884097, 8, 0, /* 2355: pointer.func */
            8884097, 8, 0, /* 2358: pointer.func */
            0, 96, 11, /* 2361: struct.dsa_method */
            	26, 0,
            	2355, 8,
            	2386, 16,
            	2352, 24,
            	2349, 32,
            	2304, 40,
            	2346, 48,
            	2346, 56,
            	92, 72,
            	2389, 80,
            	2346, 88,
            8884097, 8, 0, /* 2386: pointer.func */
            8884097, 8, 0, /* 2389: pointer.func */
            0, 32, 3, /* 2392: struct.ecdh_method */
            	26, 0,
            	2401, 8,
            	92, 24,
            8884097, 8, 0, /* 2401: pointer.func */
            8884097, 8, 0, /* 2404: pointer.func */
            8884097, 8, 0, /* 2407: pointer.func */
            1, 8, 1, /* 2410: pointer.struct.dsa_method */
            	2361, 0,
            8884097, 8, 0, /* 2415: pointer.func */
            0, 32, 2, /* 2418: struct.stack_st */
            	1530, 8,
            	231, 24,
            8884097, 8, 0, /* 2425: pointer.func */
            0, 112, 13, /* 2428: struct.rsa_meth_st */
            	26, 0,
            	2457, 8,
            	2457, 16,
            	2457, 24,
            	2457, 32,
            	2425, 40,
            	2460, 48,
            	2278, 56,
            	2278, 64,
            	92, 80,
            	2463, 88,
            	2415, 96,
            	2466, 104,
            8884097, 8, 0, /* 2457: pointer.func */
            8884097, 8, 0, /* 2460: pointer.func */
            8884097, 8, 0, /* 2463: pointer.func */
            8884097, 8, 0, /* 2466: pointer.func */
            1, 8, 1, /* 2469: pointer.struct.rsa_meth_st */
            	2428, 0,
            1, 8, 1, /* 2474: pointer.struct.ec_method_st */
            	2479, 0,
            0, 304, 37, /* 2479: struct.ec_method_st */
            	2556, 8,
            	2559, 16,
            	2559, 24,
            	2562, 32,
            	2565, 40,
            	2568, 48,
            	2571, 56,
            	2574, 64,
            	2577, 72,
            	2580, 80,
            	2580, 88,
            	2583, 96,
            	2586, 104,
            	2589, 112,
            	2592, 120,
            	2272, 128,
            	2595, 136,
            	2598, 144,
            	2601, 152,
            	2604, 160,
            	2607, 168,
            	2610, 176,
            	2613, 184,
            	2616, 192,
            	2619, 200,
            	2622, 208,
            	2613, 216,
            	2625, 224,
            	2628, 232,
            	2631, 240,
            	2571, 248,
            	2634, 256,
            	2637, 264,
            	2634, 272,
            	2637, 280,
            	2637, 288,
            	2640, 296,
            8884097, 8, 0, /* 2556: pointer.func */
            8884097, 8, 0, /* 2559: pointer.func */
            8884097, 8, 0, /* 2562: pointer.func */
            8884097, 8, 0, /* 2565: pointer.func */
            8884097, 8, 0, /* 2568: pointer.func */
            8884097, 8, 0, /* 2571: pointer.func */
            8884097, 8, 0, /* 2574: pointer.func */
            8884097, 8, 0, /* 2577: pointer.func */
            8884097, 8, 0, /* 2580: pointer.func */
            8884097, 8, 0, /* 2583: pointer.func */
            8884097, 8, 0, /* 2586: pointer.func */
            8884097, 8, 0, /* 2589: pointer.func */
            8884097, 8, 0, /* 2592: pointer.func */
            8884097, 8, 0, /* 2595: pointer.func */
            8884097, 8, 0, /* 2598: pointer.func */
            8884097, 8, 0, /* 2601: pointer.func */
            8884097, 8, 0, /* 2604: pointer.func */
            8884097, 8, 0, /* 2607: pointer.func */
            8884097, 8, 0, /* 2610: pointer.func */
            8884097, 8, 0, /* 2613: pointer.func */
            8884097, 8, 0, /* 2616: pointer.func */
            8884097, 8, 0, /* 2619: pointer.func */
            8884097, 8, 0, /* 2622: pointer.func */
            8884097, 8, 0, /* 2625: pointer.func */
            8884097, 8, 0, /* 2628: pointer.func */
            8884097, 8, 0, /* 2631: pointer.func */
            8884097, 8, 0, /* 2634: pointer.func */
            8884097, 8, 0, /* 2637: pointer.func */
            8884097, 8, 0, /* 2640: pointer.func */
            8884097, 8, 0, /* 2643: pointer.func */
            0, 48, 5, /* 2646: struct.ecdsa_method */
            	26, 0,
            	2659, 8,
            	2301, 16,
            	2662, 24,
            	92, 40,
            8884097, 8, 0, /* 2659: pointer.func */
            8884097, 8, 0, /* 2662: pointer.func */
            8884097, 8, 0, /* 2665: pointer.func */
            0, 56, 4, /* 2668: struct.evp_pkey_st */
            	2679, 16,
            	2768, 24,
            	2928, 32,
            	1942, 48,
            1, 8, 1, /* 2679: pointer.struct.evp_pkey_asn1_method_st */
            	2684, 0,
            0, 208, 24, /* 2684: struct.evp_pkey_asn1_method_st */
            	92, 16,
            	92, 24,
            	2735, 32,
            	2738, 40,
            	2741, 48,
            	2744, 56,
            	2747, 64,
            	2750, 72,
            	2744, 80,
            	2404, 88,
            	2404, 96,
            	2753, 104,
            	2665, 112,
            	2404, 120,
            	2756, 128,
            	2741, 136,
            	2744, 144,
            	2759, 152,
            	2762, 160,
            	2643, 168,
            	2753, 176,
            	2665, 184,
            	2281, 192,
            	2765, 200,
            8884097, 8, 0, /* 2735: pointer.func */
            8884097, 8, 0, /* 2738: pointer.func */
            8884097, 8, 0, /* 2741: pointer.func */
            8884097, 8, 0, /* 2744: pointer.func */
            8884097, 8, 0, /* 2747: pointer.func */
            8884097, 8, 0, /* 2750: pointer.func */
            8884097, 8, 0, /* 2753: pointer.func */
            8884097, 8, 0, /* 2756: pointer.func */
            8884097, 8, 0, /* 2759: pointer.func */
            8884097, 8, 0, /* 2762: pointer.func */
            8884097, 8, 0, /* 2765: pointer.func */
            1, 8, 1, /* 2768: pointer.struct.engine_st */
            	2773, 0,
            0, 216, 24, /* 2773: struct.engine_st */
            	26, 0,
            	26, 8,
            	2469, 16,
            	2410, 24,
            	2310, 32,
            	2824, 40,
            	2829, 48,
            	2834, 56,
            	2860, 64,
            	2266, 72,
            	2868, 80,
            	2871, 88,
            	2874, 96,
            	2877, 104,
            	2877, 112,
            	2877, 120,
            	2880, 128,
            	2883, 136,
            	2883, 144,
            	2886, 152,
            	2889, 160,
            	2901, 184,
            	2923, 200,
            	2923, 208,
            1, 8, 1, /* 2824: pointer.struct.ecdh_method */
            	2392, 0,
            1, 8, 1, /* 2829: pointer.struct.ecdsa_method */
            	2646, 0,
            1, 8, 1, /* 2834: pointer.struct.rand_meth_st */
            	2839, 0,
            0, 48, 6, /* 2839: struct.rand_meth_st */
            	2343, 0,
            	2854, 8,
            	2857, 16,
            	2275, 24,
            	2854, 32,
            	2269, 40,
            8884097, 8, 0, /* 2854: pointer.func */
            8884097, 8, 0, /* 2857: pointer.func */
            1, 8, 1, /* 2860: pointer.struct.store_method_st */
            	2865, 0,
            0, 0, 0, /* 2865: struct.store_method_st */
            8884097, 8, 0, /* 2868: pointer.func */
            8884097, 8, 0, /* 2871: pointer.func */
            8884097, 8, 0, /* 2874: pointer.func */
            8884097, 8, 0, /* 2877: pointer.func */
            8884097, 8, 0, /* 2880: pointer.func */
            8884097, 8, 0, /* 2883: pointer.func */
            8884097, 8, 0, /* 2886: pointer.func */
            1, 8, 1, /* 2889: pointer.struct.ENGINE_CMD_DEFN_st */
            	2894, 0,
            0, 32, 2, /* 2894: struct.ENGINE_CMD_DEFN_st */
            	26, 8,
            	26, 16,
            0, 16, 1, /* 2901: struct.crypto_ex_data_st */
            	2906, 0,
            1, 8, 1, /* 2906: pointer.struct.stack_st_void */
            	2911, 0,
            0, 32, 1, /* 2911: struct.stack_st_void */
            	2916, 0,
            0, 32, 2, /* 2916: struct.stack_st */
            	1530, 8,
            	231, 24,
            1, 8, 1, /* 2923: pointer.struct.engine_st */
            	2773, 0,
            0, 8, 5, /* 2928: union.unknown */
            	92, 0,
            	2941, 0,
            	3151, 0,
            	3283, 0,
            	3409, 0,
            1, 8, 1, /* 2941: pointer.struct.rsa_st */
            	2946, 0,
            0, 168, 17, /* 2946: struct.rsa_st */
            	2983, 16,
            	3032, 24,
            	3037, 32,
            	3037, 40,
            	3037, 48,
            	3037, 56,
            	3037, 64,
            	3037, 72,
            	3037, 80,
            	3037, 88,
            	3054, 96,
            	3076, 120,
            	3076, 128,
            	3076, 136,
            	92, 144,
            	3090, 152,
            	3090, 160,
            1, 8, 1, /* 2983: pointer.struct.rsa_meth_st */
            	2988, 0,
            0, 112, 13, /* 2988: struct.rsa_meth_st */
            	26, 0,
            	3017, 8,
            	3017, 16,
            	3017, 24,
            	3017, 32,
            	3020, 40,
            	2358, 48,
            	3023, 56,
            	3023, 64,
            	92, 80,
            	3026, 88,
            	2407, 96,
            	3029, 104,
            8884097, 8, 0, /* 3017: pointer.func */
            8884097, 8, 0, /* 3020: pointer.func */
            8884097, 8, 0, /* 3023: pointer.func */
            8884097, 8, 0, /* 3026: pointer.func */
            8884097, 8, 0, /* 3029: pointer.func */
            1, 8, 1, /* 3032: pointer.struct.engine_st */
            	2773, 0,
            1, 8, 1, /* 3037: pointer.struct.bignum_st */
            	3042, 0,
            0, 24, 1, /* 3042: struct.bignum_st */
            	3047, 0,
            8884099, 8, 2, /* 3047: pointer_to_array_of_pointers_to_stack */
            	2015, 0,
            	228, 12,
            0, 16, 1, /* 3054: struct.crypto_ex_data_st */
            	3059, 0,
            1, 8, 1, /* 3059: pointer.struct.stack_st_void */
            	3064, 0,
            0, 32, 1, /* 3064: struct.stack_st_void */
            	3069, 0,
            0, 32, 2, /* 3069: struct.stack_st */
            	1530, 8,
            	231, 24,
            1, 8, 1, /* 3076: pointer.struct.bn_mont_ctx_st */
            	3081, 0,
            0, 96, 3, /* 3081: struct.bn_mont_ctx_st */
            	3042, 8,
            	3042, 32,
            	3042, 56,
            1, 8, 1, /* 3090: pointer.struct.bn_blinding_st */
            	3095, 0,
            0, 88, 7, /* 3095: struct.bn_blinding_st */
            	3112, 0,
            	3112, 8,
            	3112, 16,
            	3112, 24,
            	3129, 40,
            	3134, 72,
            	3148, 80,
            1, 8, 1, /* 3112: pointer.struct.bignum_st */
            	3117, 0,
            0, 24, 1, /* 3117: struct.bignum_st */
            	3122, 0,
            8884099, 8, 2, /* 3122: pointer_to_array_of_pointers_to_stack */
            	2015, 0,
            	228, 12,
            0, 16, 1, /* 3129: struct.crypto_threadid_st */
            	1989, 0,
            1, 8, 1, /* 3134: pointer.struct.bn_mont_ctx_st */
            	3139, 0,
            0, 96, 3, /* 3139: struct.bn_mont_ctx_st */
            	3117, 8,
            	3117, 32,
            	3117, 56,
            8884097, 8, 0, /* 3148: pointer.func */
            1, 8, 1, /* 3151: pointer.struct.dsa_st */
            	3156, 0,
            0, 136, 11, /* 3156: struct.dsa_st */
            	3181, 24,
            	3181, 32,
            	3181, 40,
            	3181, 48,
            	3181, 56,
            	3181, 64,
            	3181, 72,
            	3198, 88,
            	3212, 104,
            	3227, 120,
            	3278, 128,
            1, 8, 1, /* 3181: pointer.struct.bignum_st */
            	3186, 0,
            0, 24, 1, /* 3186: struct.bignum_st */
            	3191, 0,
            8884099, 8, 2, /* 3191: pointer_to_array_of_pointers_to_stack */
            	2015, 0,
            	228, 12,
            1, 8, 1, /* 3198: pointer.struct.bn_mont_ctx_st */
            	3203, 0,
            0, 96, 3, /* 3203: struct.bn_mont_ctx_st */
            	3186, 8,
            	3186, 32,
            	3186, 56,
            0, 16, 1, /* 3212: struct.crypto_ex_data_st */
            	3217, 0,
            1, 8, 1, /* 3217: pointer.struct.stack_st_void */
            	3222, 0,
            0, 32, 1, /* 3222: struct.stack_st_void */
            	2418, 0,
            1, 8, 1, /* 3227: pointer.struct.dsa_method */
            	3232, 0,
            0, 96, 11, /* 3232: struct.dsa_method */
            	26, 0,
            	3257, 8,
            	3260, 16,
            	3263, 24,
            	3266, 32,
            	3269, 40,
            	3272, 48,
            	3272, 56,
            	92, 72,
            	3275, 80,
            	3272, 88,
            8884097, 8, 0, /* 3257: pointer.func */
            8884097, 8, 0, /* 3260: pointer.func */
            8884097, 8, 0, /* 3263: pointer.func */
            8884097, 8, 0, /* 3266: pointer.func */
            8884097, 8, 0, /* 3269: pointer.func */
            8884097, 8, 0, /* 3272: pointer.func */
            8884097, 8, 0, /* 3275: pointer.func */
            1, 8, 1, /* 3278: pointer.struct.engine_st */
            	2773, 0,
            1, 8, 1, /* 3283: pointer.struct.dh_st */
            	3288, 0,
            0, 144, 12, /* 3288: struct.dh_st */
            	3315, 8,
            	3315, 16,
            	3315, 32,
            	3315, 40,
            	3332, 56,
            	3315, 64,
            	3315, 72,
            	107, 80,
            	3315, 96,
            	3346, 112,
            	3368, 128,
            	3404, 136,
            1, 8, 1, /* 3315: pointer.struct.bignum_st */
            	3320, 0,
            0, 24, 1, /* 3320: struct.bignum_st */
            	3325, 0,
            8884099, 8, 2, /* 3325: pointer_to_array_of_pointers_to_stack */
            	2015, 0,
            	228, 12,
            1, 8, 1, /* 3332: pointer.struct.bn_mont_ctx_st */
            	3337, 0,
            0, 96, 3, /* 3337: struct.bn_mont_ctx_st */
            	3320, 8,
            	3320, 32,
            	3320, 56,
            0, 16, 1, /* 3346: struct.crypto_ex_data_st */
            	3351, 0,
            1, 8, 1, /* 3351: pointer.struct.stack_st_void */
            	3356, 0,
            0, 32, 1, /* 3356: struct.stack_st_void */
            	3361, 0,
            0, 32, 2, /* 3361: struct.stack_st */
            	1530, 8,
            	231, 24,
            1, 8, 1, /* 3368: pointer.struct.dh_method */
            	3373, 0,
            0, 72, 8, /* 3373: struct.dh_method */
            	26, 0,
            	3392, 8,
            	3395, 16,
            	3398, 24,
            	3392, 32,
            	3392, 40,
            	92, 56,
            	3401, 64,
            8884097, 8, 0, /* 3392: pointer.func */
            8884097, 8, 0, /* 3395: pointer.func */
            8884097, 8, 0, /* 3398: pointer.func */
            8884097, 8, 0, /* 3401: pointer.func */
            1, 8, 1, /* 3404: pointer.struct.engine_st */
            	2773, 0,
            1, 8, 1, /* 3409: pointer.struct.ec_key_st */
            	3414, 0,
            0, 56, 4, /* 3414: struct.ec_key_st */
            	3425, 8,
            	2023, 16,
            	2018, 24,
            	1998, 48,
            1, 8, 1, /* 3425: pointer.struct.ec_group_st */
            	3430, 0,
            0, 232, 12, /* 3430: struct.ec_group_st */
            	2474, 0,
            	3457, 8,
            	2249, 16,
            	2249, 40,
            	107, 80,
            	2244, 96,
            	2249, 104,
            	2249, 152,
            	2249, 176,
            	1989, 208,
            	1989, 216,
            	2223, 224,
            1, 8, 1, /* 3457: pointer.struct.ec_point_st */
            	2028, 0,
            1, 8, 1, /* 3462: pointer.struct.evp_pkey_st */
            	2668, 0,
            0, 24, 1, /* 3467: struct.asn1_string_st */
            	107, 8,
            1, 8, 1, /* 3472: pointer.struct.AUTHORITY_KEYID_st */
            	3477, 0,
            0, 24, 3, /* 3477: struct.AUTHORITY_KEYID_st */
            	1508, 0,
            	1484, 8,
            	2261, 16,
            1, 8, 1, /* 3486: pointer.struct.asn1_string_st */
            	3467, 0,
            0, 24, 3, /* 3491: struct.X509_pubkey_st */
            	3500, 0,
            	3486, 8,
            	3462, 16,
            1, 8, 1, /* 3500: pointer.struct.X509_algor_st */
            	5, 0,
            0, 184, 12, /* 3505: struct.x509_st */
            	3532, 0,
            	3567, 8,
            	1595, 16,
            	92, 32,
            	1540, 40,
            	262, 104,
            	3472, 112,
            	3630, 120,
            	1056, 128,
            	647, 136,
            	597, 144,
            	234, 176,
            1, 8, 1, /* 3532: pointer.struct.x509_cinf_st */
            	3537, 0,
            0, 104, 11, /* 3537: struct.x509_cinf_st */
            	3562, 0,
            	3562, 8,
            	3567, 16,
            	3572, 24,
            	2284, 32,
            	3572, 40,
            	3620, 48,
            	1595, 56,
            	1595, 64,
            	1571, 72,
            	3625, 80,
            1, 8, 1, /* 3562: pointer.struct.asn1_string_st */
            	257, 0,
            1, 8, 1, /* 3567: pointer.struct.X509_algor_st */
            	5, 0,
            1, 8, 1, /* 3572: pointer.struct.X509_name_st */
            	3577, 0,
            0, 40, 3, /* 3577: struct.X509_name_st */
            	3586, 0,
            	3610, 16,
            	107, 24,
            1, 8, 1, /* 3586: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3591, 0,
            0, 32, 2, /* 3591: struct.stack_st_fake_X509_NAME_ENTRY */
            	3598, 8,
            	231, 24,
            8884099, 8, 2, /* 3598: pointer_to_array_of_pointers_to_stack */
            	3605, 0,
            	228, 20,
            0, 8, 1, /* 3605: pointer.X509_NAME_ENTRY */
            	337, 0,
            1, 8, 1, /* 3610: pointer.struct.buf_mem_st */
            	3615, 0,
            0, 24, 1, /* 3615: struct.buf_mem_st */
            	92, 8,
            1, 8, 1, /* 3620: pointer.struct.X509_pubkey_st */
            	3491, 0,
            0, 24, 1, /* 3625: struct.ASN1_ENCODING_st */
            	107, 0,
            1, 8, 1, /* 3630: pointer.struct.X509_POLICY_CACHE_st */
            	1477, 0,
            1, 8, 1, /* 3635: pointer.int */
            	228, 0,
            0, 1, 0, /* 3640: char */
            1, 8, 1, /* 3643: pointer.struct.x509_st */
            	3505, 0,
        },
        .arg_entity_index = { 3643, 228, 3635, 3635, },
        .ret_entity_index = 1989,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    int new_arg_b = *((int *)new_args->args[1]);

    int * new_arg_c = *((int * *)new_args->args[2]);

    int * new_arg_d = *((int * *)new_args->args[3]);

    void * *new_ret_ptr = (void * *)new_args->ret;

    void * (*orig_X509_get_ext_d2i)(X509 *,int,int *,int *);
    orig_X509_get_ext_d2i = dlsym(RTLD_NEXT, "X509_get_ext_d2i");
    *new_ret_ptr = (*orig_X509_get_ext_d2i)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    return ret;
}

