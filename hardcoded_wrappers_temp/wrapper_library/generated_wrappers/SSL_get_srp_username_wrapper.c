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

char * bb_SSL_get_srp_username(SSL * arg_a);

char * SSL_get_srp_username(SSL * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_get_srp_username called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_get_srp_username(arg_a);
    else {
        char * (*orig_SSL_get_srp_username)(SSL *);
        orig_SSL_get_srp_username = dlsym(RTLD_NEXT, "SSL_get_srp_username");
        return orig_SSL_get_srp_username(arg_a);
    }
}

char * bb_SSL_get_srp_username(SSL * arg_a) 
{
    char * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 16, 1, /* 0: struct.srtp_protection_profile_st */
            	5, 0,
            1, 8, 1, /* 5: pointer.char */
            	64096, 0,
            1, 8, 1, /* 10: pointer.struct.srtp_protection_profile_st */
            	0, 0,
            64097, 8, 0, /* 15: pointer.func */
            64097, 8, 0, /* 18: pointer.func */
            0, 16, 1, /* 21: struct.tls_session_ticket_ext_st */
            	26, 8,
            0, 8, 0, /* 26: pointer.void */
            1, 8, 1, /* 29: pointer.struct.tls_session_ticket_ext_st */
            	21, 0,
            0, 24, 1, /* 34: struct.asn1_string_st */
            	39, 8,
            1, 8, 1, /* 39: pointer.unsigned char */
            	44, 0,
            0, 1, 0, /* 44: unsigned char */
            0, 24, 1, /* 47: struct.buf_mem_st */
            	52, 8,
            1, 8, 1, /* 52: pointer.char */
            	64096, 0,
            1, 8, 1, /* 57: pointer.struct.stack_st_X509_NAME_ENTRY */
            	62, 0,
            0, 32, 2, /* 62: struct.stack_st_fake_X509_NAME_ENTRY */
            	69, 8,
            	125, 24,
            64099, 8, 2, /* 69: pointer_to_array_of_pointers_to_stack */
            	76, 0,
            	122, 20,
            0, 8, 1, /* 76: pointer.X509_NAME_ENTRY */
            	81, 0,
            0, 0, 1, /* 81: X509_NAME_ENTRY */
            	86, 0,
            0, 24, 2, /* 86: struct.X509_name_entry_st */
            	93, 0,
            	112, 8,
            1, 8, 1, /* 93: pointer.struct.asn1_object_st */
            	98, 0,
            0, 40, 3, /* 98: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	107, 24,
            1, 8, 1, /* 107: pointer.unsigned char */
            	44, 0,
            1, 8, 1, /* 112: pointer.struct.asn1_string_st */
            	117, 0,
            0, 24, 1, /* 117: struct.asn1_string_st */
            	39, 8,
            0, 4, 0, /* 122: int */
            64097, 8, 0, /* 125: pointer.func */
            0, 40, 3, /* 128: struct.X509_name_st */
            	57, 0,
            	137, 16,
            	39, 24,
            1, 8, 1, /* 137: pointer.struct.buf_mem_st */
            	47, 0,
            1, 8, 1, /* 142: pointer.struct.X509_name_st */
            	128, 0,
            0, 8, 2, /* 147: union.unknown */
            	142, 0,
            	154, 0,
            1, 8, 1, /* 154: pointer.struct.asn1_string_st */
            	34, 0,
            64097, 8, 0, /* 159: pointer.func */
            0, 16, 1, /* 162: struct.srtp_protection_profile_st */
            	5, 0,
            1, 8, 1, /* 167: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	172, 0,
            0, 32, 2, /* 172: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	179, 8,
            	125, 24,
            64099, 8, 2, /* 179: pointer_to_array_of_pointers_to_stack */
            	186, 0,
            	122, 20,
            0, 8, 1, /* 186: pointer.SRTP_PROTECTION_PROFILE */
            	191, 0,
            0, 0, 1, /* 191: SRTP_PROTECTION_PROFILE */
            	162, 0,
            64097, 8, 0, /* 196: pointer.func */
            64097, 8, 0, /* 199: pointer.func */
            64097, 8, 0, /* 202: pointer.func */
            0, 128, 14, /* 205: struct.srp_ctx_st */
            	26, 0,
            	236, 8,
            	239, 16,
            	202, 24,
            	52, 32,
            	242, 40,
            	242, 48,
            	242, 56,
            	242, 64,
            	242, 72,
            	242, 80,
            	242, 88,
            	242, 96,
            	52, 104,
            64097, 8, 0, /* 236: pointer.func */
            64097, 8, 0, /* 239: pointer.func */
            1, 8, 1, /* 242: pointer.struct.bignum_st */
            	247, 0,
            0, 24, 1, /* 247: struct.bignum_st */
            	252, 0,
            1, 8, 1, /* 252: pointer.unsigned int */
            	257, 0,
            0, 4, 0, /* 257: unsigned int */
            0, 8, 1, /* 260: struct.ssl3_buf_freelist_entry_st */
            	265, 0,
            1, 8, 1, /* 265: pointer.struct.ssl3_buf_freelist_entry_st */
            	260, 0,
            64097, 8, 0, /* 270: pointer.func */
            64097, 8, 0, /* 273: pointer.func */
            64097, 8, 0, /* 276: pointer.func */
            0, 24, 2, /* 279: struct.ssl_comp_st */
            	5, 8,
            	286, 16,
            1, 8, 1, /* 286: pointer.struct.comp_method_st */
            	291, 0,
            0, 64, 7, /* 291: struct.comp_method_st */
            	5, 8,
            	273, 16,
            	308, 24,
            	270, 32,
            	270, 40,
            	311, 48,
            	311, 56,
            64097, 8, 0, /* 308: pointer.func */
            64097, 8, 0, /* 311: pointer.func */
            1, 8, 1, /* 314: pointer.struct.stack_st_SSL_COMP */
            	319, 0,
            0, 32, 2, /* 319: struct.stack_st_fake_SSL_COMP */
            	326, 8,
            	125, 24,
            64099, 8, 2, /* 326: pointer_to_array_of_pointers_to_stack */
            	333, 0,
            	122, 20,
            0, 8, 1, /* 333: pointer.SSL_COMP */
            	338, 0,
            0, 0, 1, /* 338: SSL_COMP */
            	279, 0,
            64097, 8, 0, /* 343: pointer.func */
            64097, 8, 0, /* 346: pointer.func */
            1, 8, 1, /* 349: pointer.struct.lhash_node_st */
            	354, 0,
            0, 24, 2, /* 354: struct.lhash_node_st */
            	26, 0,
            	349, 8,
            1, 8, 1, /* 361: pointer.struct.lhash_node_st */
            	354, 0,
            1, 8, 1, /* 366: pointer.pointer.struct.lhash_node_st */
            	361, 0,
            0, 176, 3, /* 371: struct.lhash_st */
            	366, 0,
            	125, 8,
            	380, 16,
            64097, 8, 0, /* 380: pointer.func */
            64097, 8, 0, /* 383: pointer.func */
            64097, 8, 0, /* 386: pointer.func */
            64097, 8, 0, /* 389: pointer.func */
            64097, 8, 0, /* 392: pointer.func */
            64097, 8, 0, /* 395: pointer.func */
            64097, 8, 0, /* 398: pointer.func */
            64097, 8, 0, /* 401: pointer.func */
            64097, 8, 0, /* 404: pointer.func */
            64097, 8, 0, /* 407: pointer.func */
            64097, 8, 0, /* 410: pointer.func */
            64097, 8, 0, /* 413: pointer.func */
            64097, 8, 0, /* 416: pointer.func */
            64097, 8, 0, /* 419: pointer.func */
            64097, 8, 0, /* 422: pointer.func */
            64097, 8, 0, /* 425: pointer.func */
            1, 8, 1, /* 428: pointer.struct.stack_st_X509_LOOKUP */
            	433, 0,
            0, 32, 2, /* 433: struct.stack_st_fake_X509_LOOKUP */
            	440, 8,
            	125, 24,
            64099, 8, 2, /* 440: pointer_to_array_of_pointers_to_stack */
            	447, 0,
            	122, 20,
            0, 8, 1, /* 447: pointer.X509_LOOKUP */
            	452, 0,
            0, 0, 1, /* 452: X509_LOOKUP */
            	457, 0,
            0, 32, 3, /* 457: struct.x509_lookup_st */
            	466, 8,
            	52, 16,
            	515, 24,
            1, 8, 1, /* 466: pointer.struct.x509_lookup_method_st */
            	471, 0,
            0, 80, 10, /* 471: struct.x509_lookup_method_st */
            	5, 0,
            	494, 8,
            	497, 16,
            	494, 24,
            	494, 32,
            	500, 40,
            	503, 48,
            	506, 56,
            	509, 64,
            	512, 72,
            64097, 8, 0, /* 494: pointer.func */
            64097, 8, 0, /* 497: pointer.func */
            64097, 8, 0, /* 500: pointer.func */
            64097, 8, 0, /* 503: pointer.func */
            64097, 8, 0, /* 506: pointer.func */
            64097, 8, 0, /* 509: pointer.func */
            64097, 8, 0, /* 512: pointer.func */
            1, 8, 1, /* 515: pointer.struct.x509_store_st */
            	520, 0,
            0, 144, 15, /* 520: struct.x509_store_st */
            	553, 8,
            	428, 16,
            	2608, 24,
            	425, 32,
            	422, 40,
            	419, 48,
            	416, 56,
            	425, 64,
            	413, 72,
            	410, 80,
            	2620, 88,
            	407, 96,
            	404, 104,
            	425, 112,
            	1058, 120,
            1, 8, 1, /* 553: pointer.struct.stack_st_X509_OBJECT */
            	558, 0,
            0, 32, 2, /* 558: struct.stack_st_fake_X509_OBJECT */
            	565, 8,
            	125, 24,
            64099, 8, 2, /* 565: pointer_to_array_of_pointers_to_stack */
            	572, 0,
            	122, 20,
            0, 8, 1, /* 572: pointer.X509_OBJECT */
            	577, 0,
            0, 0, 1, /* 577: X509_OBJECT */
            	582, 0,
            0, 16, 1, /* 582: struct.x509_object_st */
            	587, 8,
            0, 8, 4, /* 587: union.unknown */
            	52, 0,
            	598, 0,
            	2396, 0,
            	906, 0,
            1, 8, 1, /* 598: pointer.struct.x509_st */
            	603, 0,
            0, 184, 12, /* 603: struct.x509_st */
            	630, 0,
            	670, 8,
            	759, 16,
            	52, 32,
            	1058, 40,
            	764, 104,
            	1700, 112,
            	1708, 120,
            	1716, 128,
            	2125, 136,
            	2149, 144,
            	2157, 176,
            1, 8, 1, /* 630: pointer.struct.x509_cinf_st */
            	635, 0,
            0, 104, 11, /* 635: struct.x509_cinf_st */
            	660, 0,
            	660, 8,
            	670, 16,
            	827, 24,
            	875, 32,
            	827, 40,
            	892, 48,
            	759, 56,
            	759, 64,
            	1635, 72,
            	1695, 80,
            1, 8, 1, /* 660: pointer.struct.asn1_string_st */
            	665, 0,
            0, 24, 1, /* 665: struct.asn1_string_st */
            	39, 8,
            1, 8, 1, /* 670: pointer.struct.X509_algor_st */
            	675, 0,
            0, 16, 2, /* 675: struct.X509_algor_st */
            	682, 0,
            	696, 8,
            1, 8, 1, /* 682: pointer.struct.asn1_object_st */
            	687, 0,
            0, 40, 3, /* 687: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	107, 24,
            1, 8, 1, /* 696: pointer.struct.asn1_type_st */
            	701, 0,
            0, 16, 1, /* 701: struct.asn1_type_st */
            	706, 8,
            0, 8, 20, /* 706: union.unknown */
            	52, 0,
            	749, 0,
            	682, 0,
            	660, 0,
            	754, 0,
            	759, 0,
            	764, 0,
            	769, 0,
            	774, 0,
            	779, 0,
            	784, 0,
            	789, 0,
            	794, 0,
            	799, 0,
            	804, 0,
            	809, 0,
            	814, 0,
            	749, 0,
            	749, 0,
            	819, 0,
            1, 8, 1, /* 749: pointer.struct.asn1_string_st */
            	665, 0,
            1, 8, 1, /* 754: pointer.struct.asn1_string_st */
            	665, 0,
            1, 8, 1, /* 759: pointer.struct.asn1_string_st */
            	665, 0,
            1, 8, 1, /* 764: pointer.struct.asn1_string_st */
            	665, 0,
            1, 8, 1, /* 769: pointer.struct.asn1_string_st */
            	665, 0,
            1, 8, 1, /* 774: pointer.struct.asn1_string_st */
            	665, 0,
            1, 8, 1, /* 779: pointer.struct.asn1_string_st */
            	665, 0,
            1, 8, 1, /* 784: pointer.struct.asn1_string_st */
            	665, 0,
            1, 8, 1, /* 789: pointer.struct.asn1_string_st */
            	665, 0,
            1, 8, 1, /* 794: pointer.struct.asn1_string_st */
            	665, 0,
            1, 8, 1, /* 799: pointer.struct.asn1_string_st */
            	665, 0,
            1, 8, 1, /* 804: pointer.struct.asn1_string_st */
            	665, 0,
            1, 8, 1, /* 809: pointer.struct.asn1_string_st */
            	665, 0,
            1, 8, 1, /* 814: pointer.struct.asn1_string_st */
            	665, 0,
            1, 8, 1, /* 819: pointer.struct.ASN1_VALUE_st */
            	824, 0,
            0, 0, 0, /* 824: struct.ASN1_VALUE_st */
            1, 8, 1, /* 827: pointer.struct.X509_name_st */
            	832, 0,
            0, 40, 3, /* 832: struct.X509_name_st */
            	841, 0,
            	865, 16,
            	39, 24,
            1, 8, 1, /* 841: pointer.struct.stack_st_X509_NAME_ENTRY */
            	846, 0,
            0, 32, 2, /* 846: struct.stack_st_fake_X509_NAME_ENTRY */
            	853, 8,
            	125, 24,
            64099, 8, 2, /* 853: pointer_to_array_of_pointers_to_stack */
            	860, 0,
            	122, 20,
            0, 8, 1, /* 860: pointer.X509_NAME_ENTRY */
            	81, 0,
            1, 8, 1, /* 865: pointer.struct.buf_mem_st */
            	870, 0,
            0, 24, 1, /* 870: struct.buf_mem_st */
            	52, 8,
            1, 8, 1, /* 875: pointer.struct.X509_val_st */
            	880, 0,
            0, 16, 2, /* 880: struct.X509_val_st */
            	887, 0,
            	887, 8,
            1, 8, 1, /* 887: pointer.struct.asn1_string_st */
            	665, 0,
            1, 8, 1, /* 892: pointer.struct.X509_pubkey_st */
            	897, 0,
            0, 24, 3, /* 897: struct.X509_pubkey_st */
            	670, 0,
            	759, 8,
            	906, 16,
            1, 8, 1, /* 906: pointer.struct.evp_pkey_st */
            	911, 0,
            0, 56, 4, /* 911: struct.evp_pkey_st */
            	922, 16,
            	930, 24,
            	938, 32,
            	1264, 48,
            1, 8, 1, /* 922: pointer.struct.evp_pkey_asn1_method_st */
            	927, 0,
            0, 0, 0, /* 927: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 930: pointer.struct.engine_st */
            	935, 0,
            0, 0, 0, /* 935: struct.engine_st */
            0, 8, 5, /* 938: union.unknown */
            	52, 0,
            	951, 0,
            	1107, 0,
            	1188, 0,
            	1256, 0,
            1, 8, 1, /* 951: pointer.struct.rsa_st */
            	956, 0,
            0, 168, 17, /* 956: struct.rsa_st */
            	993, 16,
            	930, 24,
            	1048, 32,
            	1048, 40,
            	1048, 48,
            	1048, 56,
            	1048, 64,
            	1048, 72,
            	1048, 80,
            	1048, 88,
            	1058, 96,
            	1085, 120,
            	1085, 128,
            	1085, 136,
            	52, 144,
            	1099, 152,
            	1099, 160,
            1, 8, 1, /* 993: pointer.struct.rsa_meth_st */
            	998, 0,
            0, 112, 13, /* 998: struct.rsa_meth_st */
            	5, 0,
            	1027, 8,
            	1027, 16,
            	1027, 24,
            	1027, 32,
            	1030, 40,
            	1033, 48,
            	1036, 56,
            	1036, 64,
            	52, 80,
            	1039, 88,
            	1042, 96,
            	1045, 104,
            64097, 8, 0, /* 1027: pointer.func */
            64097, 8, 0, /* 1030: pointer.func */
            64097, 8, 0, /* 1033: pointer.func */
            64097, 8, 0, /* 1036: pointer.func */
            64097, 8, 0, /* 1039: pointer.func */
            64097, 8, 0, /* 1042: pointer.func */
            64097, 8, 0, /* 1045: pointer.func */
            1, 8, 1, /* 1048: pointer.struct.bignum_st */
            	1053, 0,
            0, 24, 1, /* 1053: struct.bignum_st */
            	252, 0,
            0, 16, 1, /* 1058: struct.crypto_ex_data_st */
            	1063, 0,
            1, 8, 1, /* 1063: pointer.struct.stack_st_void */
            	1068, 0,
            0, 32, 1, /* 1068: struct.stack_st_void */
            	1073, 0,
            0, 32, 2, /* 1073: struct.stack_st */
            	1080, 8,
            	125, 24,
            1, 8, 1, /* 1080: pointer.pointer.char */
            	52, 0,
            1, 8, 1, /* 1085: pointer.struct.bn_mont_ctx_st */
            	1090, 0,
            0, 96, 3, /* 1090: struct.bn_mont_ctx_st */
            	1053, 8,
            	1053, 32,
            	1053, 56,
            1, 8, 1, /* 1099: pointer.struct.bn_blinding_st */
            	1104, 0,
            0, 0, 0, /* 1104: struct.bn_blinding_st */
            1, 8, 1, /* 1107: pointer.struct.dsa_st */
            	1112, 0,
            0, 136, 11, /* 1112: struct.dsa_st */
            	1048, 24,
            	1048, 32,
            	1048, 40,
            	1048, 48,
            	1048, 56,
            	1048, 64,
            	1048, 72,
            	1085, 88,
            	1058, 104,
            	1137, 120,
            	930, 128,
            1, 8, 1, /* 1137: pointer.struct.dsa_method */
            	1142, 0,
            0, 96, 11, /* 1142: struct.dsa_method */
            	5, 0,
            	1167, 8,
            	1170, 16,
            	1173, 24,
            	1176, 32,
            	1179, 40,
            	1182, 48,
            	1182, 56,
            	52, 72,
            	1185, 80,
            	1182, 88,
            64097, 8, 0, /* 1167: pointer.func */
            64097, 8, 0, /* 1170: pointer.func */
            64097, 8, 0, /* 1173: pointer.func */
            64097, 8, 0, /* 1176: pointer.func */
            64097, 8, 0, /* 1179: pointer.func */
            64097, 8, 0, /* 1182: pointer.func */
            64097, 8, 0, /* 1185: pointer.func */
            1, 8, 1, /* 1188: pointer.struct.dh_st */
            	1193, 0,
            0, 144, 12, /* 1193: struct.dh_st */
            	1048, 8,
            	1048, 16,
            	1048, 32,
            	1048, 40,
            	1085, 56,
            	1048, 64,
            	1048, 72,
            	39, 80,
            	1048, 96,
            	1058, 112,
            	1220, 128,
            	930, 136,
            1, 8, 1, /* 1220: pointer.struct.dh_method */
            	1225, 0,
            0, 72, 8, /* 1225: struct.dh_method */
            	5, 0,
            	1244, 8,
            	1247, 16,
            	1250, 24,
            	1244, 32,
            	1244, 40,
            	52, 56,
            	1253, 64,
            64097, 8, 0, /* 1244: pointer.func */
            64097, 8, 0, /* 1247: pointer.func */
            64097, 8, 0, /* 1250: pointer.func */
            64097, 8, 0, /* 1253: pointer.func */
            1, 8, 1, /* 1256: pointer.struct.ec_key_st */
            	1261, 0,
            0, 0, 0, /* 1261: struct.ec_key_st */
            1, 8, 1, /* 1264: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1269, 0,
            0, 32, 2, /* 1269: struct.stack_st_fake_X509_ATTRIBUTE */
            	1276, 8,
            	125, 24,
            64099, 8, 2, /* 1276: pointer_to_array_of_pointers_to_stack */
            	1283, 0,
            	122, 20,
            0, 8, 1, /* 1283: pointer.X509_ATTRIBUTE */
            	1288, 0,
            0, 0, 1, /* 1288: X509_ATTRIBUTE */
            	1293, 0,
            0, 24, 2, /* 1293: struct.x509_attributes_st */
            	1300, 0,
            	1314, 16,
            1, 8, 1, /* 1300: pointer.struct.asn1_object_st */
            	1305, 0,
            0, 40, 3, /* 1305: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	107, 24,
            0, 8, 3, /* 1314: union.unknown */
            	52, 0,
            	1323, 0,
            	1502, 0,
            1, 8, 1, /* 1323: pointer.struct.stack_st_ASN1_TYPE */
            	1328, 0,
            0, 32, 2, /* 1328: struct.stack_st_fake_ASN1_TYPE */
            	1335, 8,
            	125, 24,
            64099, 8, 2, /* 1335: pointer_to_array_of_pointers_to_stack */
            	1342, 0,
            	122, 20,
            0, 8, 1, /* 1342: pointer.ASN1_TYPE */
            	1347, 0,
            0, 0, 1, /* 1347: ASN1_TYPE */
            	1352, 0,
            0, 16, 1, /* 1352: struct.asn1_type_st */
            	1357, 8,
            0, 8, 20, /* 1357: union.unknown */
            	52, 0,
            	1400, 0,
            	1410, 0,
            	1424, 0,
            	1429, 0,
            	1434, 0,
            	1439, 0,
            	1444, 0,
            	1449, 0,
            	1454, 0,
            	1459, 0,
            	1464, 0,
            	1469, 0,
            	1474, 0,
            	1479, 0,
            	1484, 0,
            	1489, 0,
            	1400, 0,
            	1400, 0,
            	1494, 0,
            1, 8, 1, /* 1400: pointer.struct.asn1_string_st */
            	1405, 0,
            0, 24, 1, /* 1405: struct.asn1_string_st */
            	39, 8,
            1, 8, 1, /* 1410: pointer.struct.asn1_object_st */
            	1415, 0,
            0, 40, 3, /* 1415: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	107, 24,
            1, 8, 1, /* 1424: pointer.struct.asn1_string_st */
            	1405, 0,
            1, 8, 1, /* 1429: pointer.struct.asn1_string_st */
            	1405, 0,
            1, 8, 1, /* 1434: pointer.struct.asn1_string_st */
            	1405, 0,
            1, 8, 1, /* 1439: pointer.struct.asn1_string_st */
            	1405, 0,
            1, 8, 1, /* 1444: pointer.struct.asn1_string_st */
            	1405, 0,
            1, 8, 1, /* 1449: pointer.struct.asn1_string_st */
            	1405, 0,
            1, 8, 1, /* 1454: pointer.struct.asn1_string_st */
            	1405, 0,
            1, 8, 1, /* 1459: pointer.struct.asn1_string_st */
            	1405, 0,
            1, 8, 1, /* 1464: pointer.struct.asn1_string_st */
            	1405, 0,
            1, 8, 1, /* 1469: pointer.struct.asn1_string_st */
            	1405, 0,
            1, 8, 1, /* 1474: pointer.struct.asn1_string_st */
            	1405, 0,
            1, 8, 1, /* 1479: pointer.struct.asn1_string_st */
            	1405, 0,
            1, 8, 1, /* 1484: pointer.struct.asn1_string_st */
            	1405, 0,
            1, 8, 1, /* 1489: pointer.struct.asn1_string_st */
            	1405, 0,
            1, 8, 1, /* 1494: pointer.struct.ASN1_VALUE_st */
            	1499, 0,
            0, 0, 0, /* 1499: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1502: pointer.struct.asn1_type_st */
            	1507, 0,
            0, 16, 1, /* 1507: struct.asn1_type_st */
            	1512, 8,
            0, 8, 20, /* 1512: union.unknown */
            	52, 0,
            	1555, 0,
            	1300, 0,
            	1565, 0,
            	1570, 0,
            	1575, 0,
            	1580, 0,
            	1585, 0,
            	1590, 0,
            	1595, 0,
            	1600, 0,
            	1605, 0,
            	1610, 0,
            	1615, 0,
            	1620, 0,
            	1625, 0,
            	1630, 0,
            	1555, 0,
            	1555, 0,
            	819, 0,
            1, 8, 1, /* 1555: pointer.struct.asn1_string_st */
            	1560, 0,
            0, 24, 1, /* 1560: struct.asn1_string_st */
            	39, 8,
            1, 8, 1, /* 1565: pointer.struct.asn1_string_st */
            	1560, 0,
            1, 8, 1, /* 1570: pointer.struct.asn1_string_st */
            	1560, 0,
            1, 8, 1, /* 1575: pointer.struct.asn1_string_st */
            	1560, 0,
            1, 8, 1, /* 1580: pointer.struct.asn1_string_st */
            	1560, 0,
            1, 8, 1, /* 1585: pointer.struct.asn1_string_st */
            	1560, 0,
            1, 8, 1, /* 1590: pointer.struct.asn1_string_st */
            	1560, 0,
            1, 8, 1, /* 1595: pointer.struct.asn1_string_st */
            	1560, 0,
            1, 8, 1, /* 1600: pointer.struct.asn1_string_st */
            	1560, 0,
            1, 8, 1, /* 1605: pointer.struct.asn1_string_st */
            	1560, 0,
            1, 8, 1, /* 1610: pointer.struct.asn1_string_st */
            	1560, 0,
            1, 8, 1, /* 1615: pointer.struct.asn1_string_st */
            	1560, 0,
            1, 8, 1, /* 1620: pointer.struct.asn1_string_st */
            	1560, 0,
            1, 8, 1, /* 1625: pointer.struct.asn1_string_st */
            	1560, 0,
            1, 8, 1, /* 1630: pointer.struct.asn1_string_st */
            	1560, 0,
            1, 8, 1, /* 1635: pointer.struct.stack_st_X509_EXTENSION */
            	1640, 0,
            0, 32, 2, /* 1640: struct.stack_st_fake_X509_EXTENSION */
            	1647, 8,
            	125, 24,
            64099, 8, 2, /* 1647: pointer_to_array_of_pointers_to_stack */
            	1654, 0,
            	122, 20,
            0, 8, 1, /* 1654: pointer.X509_EXTENSION */
            	1659, 0,
            0, 0, 1, /* 1659: X509_EXTENSION */
            	1664, 0,
            0, 24, 2, /* 1664: struct.X509_extension_st */
            	1671, 0,
            	1685, 16,
            1, 8, 1, /* 1671: pointer.struct.asn1_object_st */
            	1676, 0,
            0, 40, 3, /* 1676: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	107, 24,
            1, 8, 1, /* 1685: pointer.struct.asn1_string_st */
            	1690, 0,
            0, 24, 1, /* 1690: struct.asn1_string_st */
            	39, 8,
            0, 24, 1, /* 1695: struct.ASN1_ENCODING_st */
            	39, 0,
            1, 8, 1, /* 1700: pointer.struct.AUTHORITY_KEYID_st */
            	1705, 0,
            0, 0, 0, /* 1705: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 1708: pointer.struct.X509_POLICY_CACHE_st */
            	1713, 0,
            0, 0, 0, /* 1713: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1716: pointer.struct.stack_st_DIST_POINT */
            	1721, 0,
            0, 32, 2, /* 1721: struct.stack_st_fake_DIST_POINT */
            	1728, 8,
            	125, 24,
            64099, 8, 2, /* 1728: pointer_to_array_of_pointers_to_stack */
            	1735, 0,
            	122, 20,
            0, 8, 1, /* 1735: pointer.DIST_POINT */
            	1740, 0,
            0, 0, 1, /* 1740: DIST_POINT */
            	1745, 0,
            0, 32, 3, /* 1745: struct.DIST_POINT_st */
            	1754, 0,
            	2115, 8,
            	1773, 16,
            1, 8, 1, /* 1754: pointer.struct.DIST_POINT_NAME_st */
            	1759, 0,
            0, 24, 2, /* 1759: struct.DIST_POINT_NAME_st */
            	1766, 8,
            	2091, 16,
            0, 8, 2, /* 1766: union.unknown */
            	1773, 0,
            	2067, 0,
            1, 8, 1, /* 1773: pointer.struct.stack_st_GENERAL_NAME */
            	1778, 0,
            0, 32, 2, /* 1778: struct.stack_st_fake_GENERAL_NAME */
            	1785, 8,
            	125, 24,
            64099, 8, 2, /* 1785: pointer_to_array_of_pointers_to_stack */
            	1792, 0,
            	122, 20,
            0, 8, 1, /* 1792: pointer.GENERAL_NAME */
            	1797, 0,
            0, 0, 1, /* 1797: GENERAL_NAME */
            	1802, 0,
            0, 16, 1, /* 1802: struct.GENERAL_NAME_st */
            	1807, 8,
            0, 8, 15, /* 1807: union.unknown */
            	52, 0,
            	1840, 0,
            	1959, 0,
            	1959, 0,
            	1866, 0,
            	2007, 0,
            	2055, 0,
            	1959, 0,
            	1944, 0,
            	1852, 0,
            	1944, 0,
            	2007, 0,
            	1959, 0,
            	1852, 0,
            	1866, 0,
            1, 8, 1, /* 1840: pointer.struct.otherName_st */
            	1845, 0,
            0, 16, 2, /* 1845: struct.otherName_st */
            	1852, 0,
            	1866, 8,
            1, 8, 1, /* 1852: pointer.struct.asn1_object_st */
            	1857, 0,
            0, 40, 3, /* 1857: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	107, 24,
            1, 8, 1, /* 1866: pointer.struct.asn1_type_st */
            	1871, 0,
            0, 16, 1, /* 1871: struct.asn1_type_st */
            	1876, 8,
            0, 8, 20, /* 1876: union.unknown */
            	52, 0,
            	1919, 0,
            	1852, 0,
            	1929, 0,
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
            	1919, 0,
            	1919, 0,
            	1999, 0,
            1, 8, 1, /* 1919: pointer.struct.asn1_string_st */
            	1924, 0,
            0, 24, 1, /* 1924: struct.asn1_string_st */
            	39, 8,
            1, 8, 1, /* 1929: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1934: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1939: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1944: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1949: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1954: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1959: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1964: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1969: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1974: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1979: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1984: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1989: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1994: pointer.struct.asn1_string_st */
            	1924, 0,
            1, 8, 1, /* 1999: pointer.struct.ASN1_VALUE_st */
            	2004, 0,
            0, 0, 0, /* 2004: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2007: pointer.struct.X509_name_st */
            	2012, 0,
            0, 40, 3, /* 2012: struct.X509_name_st */
            	2021, 0,
            	2045, 16,
            	39, 24,
            1, 8, 1, /* 2021: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2026, 0,
            0, 32, 2, /* 2026: struct.stack_st_fake_X509_NAME_ENTRY */
            	2033, 8,
            	125, 24,
            64099, 8, 2, /* 2033: pointer_to_array_of_pointers_to_stack */
            	2040, 0,
            	122, 20,
            0, 8, 1, /* 2040: pointer.X509_NAME_ENTRY */
            	81, 0,
            1, 8, 1, /* 2045: pointer.struct.buf_mem_st */
            	2050, 0,
            0, 24, 1, /* 2050: struct.buf_mem_st */
            	52, 8,
            1, 8, 1, /* 2055: pointer.struct.EDIPartyName_st */
            	2060, 0,
            0, 16, 2, /* 2060: struct.EDIPartyName_st */
            	1919, 0,
            	1919, 8,
            1, 8, 1, /* 2067: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2072, 0,
            0, 32, 2, /* 2072: struct.stack_st_fake_X509_NAME_ENTRY */
            	2079, 8,
            	125, 24,
            64099, 8, 2, /* 2079: pointer_to_array_of_pointers_to_stack */
            	2086, 0,
            	122, 20,
            0, 8, 1, /* 2086: pointer.X509_NAME_ENTRY */
            	81, 0,
            1, 8, 1, /* 2091: pointer.struct.X509_name_st */
            	2096, 0,
            0, 40, 3, /* 2096: struct.X509_name_st */
            	2067, 0,
            	2105, 16,
            	39, 24,
            1, 8, 1, /* 2105: pointer.struct.buf_mem_st */
            	2110, 0,
            0, 24, 1, /* 2110: struct.buf_mem_st */
            	52, 8,
            1, 8, 1, /* 2115: pointer.struct.asn1_string_st */
            	2120, 0,
            0, 24, 1, /* 2120: struct.asn1_string_st */
            	39, 8,
            1, 8, 1, /* 2125: pointer.struct.stack_st_GENERAL_NAME */
            	2130, 0,
            0, 32, 2, /* 2130: struct.stack_st_fake_GENERAL_NAME */
            	2137, 8,
            	125, 24,
            64099, 8, 2, /* 2137: pointer_to_array_of_pointers_to_stack */
            	2144, 0,
            	122, 20,
            0, 8, 1, /* 2144: pointer.GENERAL_NAME */
            	1797, 0,
            1, 8, 1, /* 2149: pointer.struct.NAME_CONSTRAINTS_st */
            	2154, 0,
            0, 0, 0, /* 2154: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 2157: pointer.struct.x509_cert_aux_st */
            	2162, 0,
            0, 40, 5, /* 2162: struct.x509_cert_aux_st */
            	2175, 0,
            	2175, 8,
            	814, 16,
            	764, 24,
            	2213, 32,
            1, 8, 1, /* 2175: pointer.struct.stack_st_ASN1_OBJECT */
            	2180, 0,
            0, 32, 2, /* 2180: struct.stack_st_fake_ASN1_OBJECT */
            	2187, 8,
            	125, 24,
            64099, 8, 2, /* 2187: pointer_to_array_of_pointers_to_stack */
            	2194, 0,
            	122, 20,
            0, 8, 1, /* 2194: pointer.ASN1_OBJECT */
            	2199, 0,
            0, 0, 1, /* 2199: ASN1_OBJECT */
            	2204, 0,
            0, 40, 3, /* 2204: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	107, 24,
            1, 8, 1, /* 2213: pointer.struct.stack_st_X509_ALGOR */
            	2218, 0,
            0, 32, 2, /* 2218: struct.stack_st_fake_X509_ALGOR */
            	2225, 8,
            	125, 24,
            64099, 8, 2, /* 2225: pointer_to_array_of_pointers_to_stack */
            	2232, 0,
            	122, 20,
            0, 8, 1, /* 2232: pointer.X509_ALGOR */
            	2237, 0,
            0, 0, 1, /* 2237: X509_ALGOR */
            	2242, 0,
            0, 16, 2, /* 2242: struct.X509_algor_st */
            	2249, 0,
            	2263, 8,
            1, 8, 1, /* 2249: pointer.struct.asn1_object_st */
            	2254, 0,
            0, 40, 3, /* 2254: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	107, 24,
            1, 8, 1, /* 2263: pointer.struct.asn1_type_st */
            	2268, 0,
            0, 16, 1, /* 2268: struct.asn1_type_st */
            	2273, 8,
            0, 8, 20, /* 2273: union.unknown */
            	52, 0,
            	2316, 0,
            	2249, 0,
            	2326, 0,
            	2331, 0,
            	2336, 0,
            	2341, 0,
            	2346, 0,
            	2351, 0,
            	2356, 0,
            	2361, 0,
            	2366, 0,
            	2371, 0,
            	2376, 0,
            	2381, 0,
            	2386, 0,
            	2391, 0,
            	2316, 0,
            	2316, 0,
            	819, 0,
            1, 8, 1, /* 2316: pointer.struct.asn1_string_st */
            	2321, 0,
            0, 24, 1, /* 2321: struct.asn1_string_st */
            	39, 8,
            1, 8, 1, /* 2326: pointer.struct.asn1_string_st */
            	2321, 0,
            1, 8, 1, /* 2331: pointer.struct.asn1_string_st */
            	2321, 0,
            1, 8, 1, /* 2336: pointer.struct.asn1_string_st */
            	2321, 0,
            1, 8, 1, /* 2341: pointer.struct.asn1_string_st */
            	2321, 0,
            1, 8, 1, /* 2346: pointer.struct.asn1_string_st */
            	2321, 0,
            1, 8, 1, /* 2351: pointer.struct.asn1_string_st */
            	2321, 0,
            1, 8, 1, /* 2356: pointer.struct.asn1_string_st */
            	2321, 0,
            1, 8, 1, /* 2361: pointer.struct.asn1_string_st */
            	2321, 0,
            1, 8, 1, /* 2366: pointer.struct.asn1_string_st */
            	2321, 0,
            1, 8, 1, /* 2371: pointer.struct.asn1_string_st */
            	2321, 0,
            1, 8, 1, /* 2376: pointer.struct.asn1_string_st */
            	2321, 0,
            1, 8, 1, /* 2381: pointer.struct.asn1_string_st */
            	2321, 0,
            1, 8, 1, /* 2386: pointer.struct.asn1_string_st */
            	2321, 0,
            1, 8, 1, /* 2391: pointer.struct.asn1_string_st */
            	2321, 0,
            1, 8, 1, /* 2396: pointer.struct.X509_crl_st */
            	2401, 0,
            0, 120, 10, /* 2401: struct.X509_crl_st */
            	2424, 0,
            	670, 8,
            	759, 16,
            	1700, 32,
            	2551, 40,
            	660, 56,
            	660, 64,
            	2559, 96,
            	2600, 104,
            	26, 112,
            1, 8, 1, /* 2424: pointer.struct.X509_crl_info_st */
            	2429, 0,
            0, 80, 8, /* 2429: struct.X509_crl_info_st */
            	660, 0,
            	670, 8,
            	827, 16,
            	887, 24,
            	887, 32,
            	2448, 40,
            	1635, 48,
            	1695, 56,
            1, 8, 1, /* 2448: pointer.struct.stack_st_X509_REVOKED */
            	2453, 0,
            0, 32, 2, /* 2453: struct.stack_st_fake_X509_REVOKED */
            	2460, 8,
            	125, 24,
            64099, 8, 2, /* 2460: pointer_to_array_of_pointers_to_stack */
            	2467, 0,
            	122, 20,
            0, 8, 1, /* 2467: pointer.X509_REVOKED */
            	2472, 0,
            0, 0, 1, /* 2472: X509_REVOKED */
            	2477, 0,
            0, 40, 4, /* 2477: struct.x509_revoked_st */
            	2488, 0,
            	2498, 8,
            	2503, 16,
            	2527, 24,
            1, 8, 1, /* 2488: pointer.struct.asn1_string_st */
            	2493, 0,
            0, 24, 1, /* 2493: struct.asn1_string_st */
            	39, 8,
            1, 8, 1, /* 2498: pointer.struct.asn1_string_st */
            	2493, 0,
            1, 8, 1, /* 2503: pointer.struct.stack_st_X509_EXTENSION */
            	2508, 0,
            0, 32, 2, /* 2508: struct.stack_st_fake_X509_EXTENSION */
            	2515, 8,
            	125, 24,
            64099, 8, 2, /* 2515: pointer_to_array_of_pointers_to_stack */
            	2522, 0,
            	122, 20,
            0, 8, 1, /* 2522: pointer.X509_EXTENSION */
            	1659, 0,
            1, 8, 1, /* 2527: pointer.struct.stack_st_GENERAL_NAME */
            	2532, 0,
            0, 32, 2, /* 2532: struct.stack_st_fake_GENERAL_NAME */
            	2539, 8,
            	125, 24,
            64099, 8, 2, /* 2539: pointer_to_array_of_pointers_to_stack */
            	2546, 0,
            	122, 20,
            0, 8, 1, /* 2546: pointer.GENERAL_NAME */
            	1797, 0,
            1, 8, 1, /* 2551: pointer.struct.ISSUING_DIST_POINT_st */
            	2556, 0,
            0, 0, 0, /* 2556: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 2559: pointer.struct.stack_st_GENERAL_NAMES */
            	2564, 0,
            0, 32, 2, /* 2564: struct.stack_st_fake_GENERAL_NAMES */
            	2571, 8,
            	125, 24,
            64099, 8, 2, /* 2571: pointer_to_array_of_pointers_to_stack */
            	2578, 0,
            	122, 20,
            0, 8, 1, /* 2578: pointer.GENERAL_NAMES */
            	2583, 0,
            0, 0, 1, /* 2583: GENERAL_NAMES */
            	2588, 0,
            0, 32, 1, /* 2588: struct.stack_st_GENERAL_NAME */
            	2593, 0,
            0, 32, 2, /* 2593: struct.stack_st */
            	1080, 8,
            	125, 24,
            1, 8, 1, /* 2600: pointer.struct.x509_crl_method_st */
            	2605, 0,
            0, 0, 0, /* 2605: struct.x509_crl_method_st */
            1, 8, 1, /* 2608: pointer.struct.X509_VERIFY_PARAM_st */
            	2613, 0,
            0, 56, 2, /* 2613: struct.X509_VERIFY_PARAM_st */
            	52, 0,
            	2175, 48,
            64097, 8, 0, /* 2620: pointer.func */
            1, 8, 1, /* 2623: pointer.struct.stack_st_X509_LOOKUP */
            	2628, 0,
            0, 32, 2, /* 2628: struct.stack_st_fake_X509_LOOKUP */
            	2635, 8,
            	125, 24,
            64099, 8, 2, /* 2635: pointer_to_array_of_pointers_to_stack */
            	2642, 0,
            	122, 20,
            0, 8, 1, /* 2642: pointer.X509_LOOKUP */
            	452, 0,
            1, 8, 1, /* 2647: pointer.struct.ssl3_buf_freelist_st */
            	2652, 0,
            0, 24, 1, /* 2652: struct.ssl3_buf_freelist_st */
            	265, 16,
            1, 8, 1, /* 2657: pointer.struct.stack_st_X509_EXTENSION */
            	2662, 0,
            0, 32, 2, /* 2662: struct.stack_st_fake_X509_EXTENSION */
            	2669, 8,
            	125, 24,
            64099, 8, 2, /* 2669: pointer_to_array_of_pointers_to_stack */
            	2676, 0,
            	122, 20,
            0, 8, 1, /* 2676: pointer.X509_EXTENSION */
            	1659, 0,
            1, 8, 1, /* 2681: pointer.struct.dh_st */
            	2686, 0,
            0, 144, 12, /* 2686: struct.dh_st */
            	242, 8,
            	242, 16,
            	242, 32,
            	242, 40,
            	2713, 56,
            	242, 64,
            	242, 72,
            	39, 80,
            	242, 96,
            	2727, 112,
            	2749, 128,
            	2785, 136,
            1, 8, 1, /* 2713: pointer.struct.bn_mont_ctx_st */
            	2718, 0,
            0, 96, 3, /* 2718: struct.bn_mont_ctx_st */
            	247, 8,
            	247, 32,
            	247, 56,
            0, 16, 1, /* 2727: struct.crypto_ex_data_st */
            	2732, 0,
            1, 8, 1, /* 2732: pointer.struct.stack_st_void */
            	2737, 0,
            0, 32, 1, /* 2737: struct.stack_st_void */
            	2742, 0,
            0, 32, 2, /* 2742: struct.stack_st */
            	1080, 8,
            	125, 24,
            1, 8, 1, /* 2749: pointer.struct.dh_method */
            	2754, 0,
            0, 72, 8, /* 2754: struct.dh_method */
            	5, 0,
            	2773, 8,
            	2776, 16,
            	2779, 24,
            	2773, 32,
            	2773, 40,
            	52, 56,
            	2782, 64,
            64097, 8, 0, /* 2773: pointer.func */
            64097, 8, 0, /* 2776: pointer.func */
            64097, 8, 0, /* 2779: pointer.func */
            64097, 8, 0, /* 2782: pointer.func */
            1, 8, 1, /* 2785: pointer.struct.engine_st */
            	2790, 0,
            0, 0, 0, /* 2790: struct.engine_st */
            1, 8, 1, /* 2793: pointer.struct.ssl2_state_st */
            	2798, 0,
            0, 344, 9, /* 2798: struct.ssl2_state_st */
            	107, 24,
            	39, 56,
            	39, 64,
            	39, 72,
            	39, 104,
            	39, 112,
            	39, 120,
            	39, 128,
            	39, 136,
            1, 8, 1, /* 2819: pointer.struct.stack_st_X509_ALGOR */
            	2824, 0,
            0, 32, 2, /* 2824: struct.stack_st_fake_X509_ALGOR */
            	2831, 8,
            	125, 24,
            64099, 8, 2, /* 2831: pointer_to_array_of_pointers_to_stack */
            	2838, 0,
            	122, 20,
            0, 8, 1, /* 2838: pointer.X509_ALGOR */
            	2237, 0,
            1, 8, 1, /* 2843: pointer.struct.asn1_string_st */
            	2848, 0,
            0, 24, 1, /* 2848: struct.asn1_string_st */
            	39, 8,
            0, 0, 0, /* 2853: struct.ec_key_st */
            0, 232, 28, /* 2856: struct.ssl_method_st */
            	2915, 8,
            	2918, 16,
            	2918, 24,
            	2915, 32,
            	2915, 40,
            	2921, 48,
            	2921, 56,
            	2924, 64,
            	2915, 72,
            	2915, 80,
            	2915, 88,
            	2927, 96,
            	2930, 104,
            	2933, 112,
            	2915, 120,
            	2936, 128,
            	2939, 136,
            	2942, 144,
            	2945, 152,
            	2948, 160,
            	2951, 168,
            	2954, 176,
            	2957, 184,
            	311, 192,
            	2960, 200,
            	2951, 208,
            	3011, 216,
            	3014, 224,
            64097, 8, 0, /* 2915: pointer.func */
            64097, 8, 0, /* 2918: pointer.func */
            64097, 8, 0, /* 2921: pointer.func */
            64097, 8, 0, /* 2924: pointer.func */
            64097, 8, 0, /* 2927: pointer.func */
            64097, 8, 0, /* 2930: pointer.func */
            64097, 8, 0, /* 2933: pointer.func */
            64097, 8, 0, /* 2936: pointer.func */
            64097, 8, 0, /* 2939: pointer.func */
            64097, 8, 0, /* 2942: pointer.func */
            64097, 8, 0, /* 2945: pointer.func */
            64097, 8, 0, /* 2948: pointer.func */
            64097, 8, 0, /* 2951: pointer.func */
            64097, 8, 0, /* 2954: pointer.func */
            64097, 8, 0, /* 2957: pointer.func */
            1, 8, 1, /* 2960: pointer.struct.ssl3_enc_method */
            	2965, 0,
            0, 112, 11, /* 2965: struct.ssl3_enc_method */
            	2990, 0,
            	2993, 8,
            	2915, 16,
            	2996, 24,
            	2990, 32,
            	2999, 40,
            	3002, 56,
            	5, 64,
            	5, 80,
            	3005, 96,
            	3008, 104,
            64097, 8, 0, /* 2990: pointer.func */
            64097, 8, 0, /* 2993: pointer.func */
            64097, 8, 0, /* 2996: pointer.func */
            64097, 8, 0, /* 2999: pointer.func */
            64097, 8, 0, /* 3002: pointer.func */
            64097, 8, 0, /* 3005: pointer.func */
            64097, 8, 0, /* 3008: pointer.func */
            64097, 8, 0, /* 3011: pointer.func */
            64097, 8, 0, /* 3014: pointer.func */
            64097, 8, 0, /* 3017: pointer.func */
            0, 296, 7, /* 3020: struct.cert_st */
            	3037, 0,
            	3797, 48,
            	3802, 56,
            	2681, 64,
            	3805, 72,
            	3808, 80,
            	3813, 88,
            1, 8, 1, /* 3037: pointer.struct.cert_pkey_st */
            	3042, 0,
            0, 24, 3, /* 3042: struct.cert_pkey_st */
            	3051, 0,
            	3349, 8,
            	3752, 16,
            1, 8, 1, /* 3051: pointer.struct.x509_st */
            	3056, 0,
            0, 184, 12, /* 3056: struct.x509_st */
            	3083, 0,
            	3118, 8,
            	3207, 16,
            	52, 32,
            	2727, 40,
            	3212, 104,
            	3638, 112,
            	3646, 120,
            	3654, 128,
            	3678, 136,
            	3702, 144,
            	3710, 176,
            1, 8, 1, /* 3083: pointer.struct.x509_cinf_st */
            	3088, 0,
            0, 104, 11, /* 3088: struct.x509_cinf_st */
            	3113, 0,
            	3113, 8,
            	3118, 16,
            	3270, 24,
            	3318, 32,
            	3270, 40,
            	3335, 48,
            	3207, 56,
            	3207, 64,
            	3609, 72,
            	3633, 80,
            1, 8, 1, /* 3113: pointer.struct.asn1_string_st */
            	2848, 0,
            1, 8, 1, /* 3118: pointer.struct.X509_algor_st */
            	3123, 0,
            0, 16, 2, /* 3123: struct.X509_algor_st */
            	3130, 0,
            	3144, 8,
            1, 8, 1, /* 3130: pointer.struct.asn1_object_st */
            	3135, 0,
            0, 40, 3, /* 3135: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	107, 24,
            1, 8, 1, /* 3144: pointer.struct.asn1_type_st */
            	3149, 0,
            0, 16, 1, /* 3149: struct.asn1_type_st */
            	3154, 8,
            0, 8, 20, /* 3154: union.unknown */
            	52, 0,
            	3197, 0,
            	3130, 0,
            	3113, 0,
            	3202, 0,
            	3207, 0,
            	3212, 0,
            	3217, 0,
            	3222, 0,
            	3227, 0,
            	3232, 0,
            	3237, 0,
            	3242, 0,
            	3247, 0,
            	3252, 0,
            	3257, 0,
            	2843, 0,
            	3197, 0,
            	3197, 0,
            	3262, 0,
            1, 8, 1, /* 3197: pointer.struct.asn1_string_st */
            	2848, 0,
            1, 8, 1, /* 3202: pointer.struct.asn1_string_st */
            	2848, 0,
            1, 8, 1, /* 3207: pointer.struct.asn1_string_st */
            	2848, 0,
            1, 8, 1, /* 3212: pointer.struct.asn1_string_st */
            	2848, 0,
            1, 8, 1, /* 3217: pointer.struct.asn1_string_st */
            	2848, 0,
            1, 8, 1, /* 3222: pointer.struct.asn1_string_st */
            	2848, 0,
            1, 8, 1, /* 3227: pointer.struct.asn1_string_st */
            	2848, 0,
            1, 8, 1, /* 3232: pointer.struct.asn1_string_st */
            	2848, 0,
            1, 8, 1, /* 3237: pointer.struct.asn1_string_st */
            	2848, 0,
            1, 8, 1, /* 3242: pointer.struct.asn1_string_st */
            	2848, 0,
            1, 8, 1, /* 3247: pointer.struct.asn1_string_st */
            	2848, 0,
            1, 8, 1, /* 3252: pointer.struct.asn1_string_st */
            	2848, 0,
            1, 8, 1, /* 3257: pointer.struct.asn1_string_st */
            	2848, 0,
            1, 8, 1, /* 3262: pointer.struct.ASN1_VALUE_st */
            	3267, 0,
            0, 0, 0, /* 3267: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3270: pointer.struct.X509_name_st */
            	3275, 0,
            0, 40, 3, /* 3275: struct.X509_name_st */
            	3284, 0,
            	3308, 16,
            	39, 24,
            1, 8, 1, /* 3284: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3289, 0,
            0, 32, 2, /* 3289: struct.stack_st_fake_X509_NAME_ENTRY */
            	3296, 8,
            	125, 24,
            64099, 8, 2, /* 3296: pointer_to_array_of_pointers_to_stack */
            	3303, 0,
            	122, 20,
            0, 8, 1, /* 3303: pointer.X509_NAME_ENTRY */
            	81, 0,
            1, 8, 1, /* 3308: pointer.struct.buf_mem_st */
            	3313, 0,
            0, 24, 1, /* 3313: struct.buf_mem_st */
            	52, 8,
            1, 8, 1, /* 3318: pointer.struct.X509_val_st */
            	3323, 0,
            0, 16, 2, /* 3323: struct.X509_val_st */
            	3330, 0,
            	3330, 8,
            1, 8, 1, /* 3330: pointer.struct.asn1_string_st */
            	2848, 0,
            1, 8, 1, /* 3335: pointer.struct.X509_pubkey_st */
            	3340, 0,
            0, 24, 3, /* 3340: struct.X509_pubkey_st */
            	3118, 0,
            	3207, 8,
            	3349, 16,
            1, 8, 1, /* 3349: pointer.struct.evp_pkey_st */
            	3354, 0,
            0, 56, 4, /* 3354: struct.evp_pkey_st */
            	3365, 16,
            	2785, 24,
            	3373, 32,
            	3585, 48,
            1, 8, 1, /* 3365: pointer.struct.evp_pkey_asn1_method_st */
            	3370, 0,
            0, 0, 0, /* 3370: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 3373: union.unknown */
            	52, 0,
            	3386, 0,
            	3491, 0,
            	3572, 0,
            	3577, 0,
            1, 8, 1, /* 3386: pointer.struct.rsa_st */
            	3391, 0,
            0, 168, 17, /* 3391: struct.rsa_st */
            	3428, 16,
            	2785, 24,
            	242, 32,
            	242, 40,
            	242, 48,
            	242, 56,
            	242, 64,
            	242, 72,
            	242, 80,
            	242, 88,
            	2727, 96,
            	2713, 120,
            	2713, 128,
            	2713, 136,
            	52, 144,
            	3483, 152,
            	3483, 160,
            1, 8, 1, /* 3428: pointer.struct.rsa_meth_st */
            	3433, 0,
            0, 112, 13, /* 3433: struct.rsa_meth_st */
            	5, 0,
            	3462, 8,
            	3462, 16,
            	3462, 24,
            	3462, 32,
            	3465, 40,
            	3468, 48,
            	3471, 56,
            	3471, 64,
            	52, 80,
            	3474, 88,
            	3477, 96,
            	3480, 104,
            64097, 8, 0, /* 3462: pointer.func */
            64097, 8, 0, /* 3465: pointer.func */
            64097, 8, 0, /* 3468: pointer.func */
            64097, 8, 0, /* 3471: pointer.func */
            64097, 8, 0, /* 3474: pointer.func */
            64097, 8, 0, /* 3477: pointer.func */
            64097, 8, 0, /* 3480: pointer.func */
            1, 8, 1, /* 3483: pointer.struct.bn_blinding_st */
            	3488, 0,
            0, 0, 0, /* 3488: struct.bn_blinding_st */
            1, 8, 1, /* 3491: pointer.struct.dsa_st */
            	3496, 0,
            0, 136, 11, /* 3496: struct.dsa_st */
            	242, 24,
            	242, 32,
            	242, 40,
            	242, 48,
            	242, 56,
            	242, 64,
            	242, 72,
            	2713, 88,
            	2727, 104,
            	3521, 120,
            	2785, 128,
            1, 8, 1, /* 3521: pointer.struct.dsa_method */
            	3526, 0,
            0, 96, 11, /* 3526: struct.dsa_method */
            	5, 0,
            	3551, 8,
            	3554, 16,
            	3557, 24,
            	3560, 32,
            	3563, 40,
            	3566, 48,
            	3566, 56,
            	52, 72,
            	3569, 80,
            	3566, 88,
            64097, 8, 0, /* 3551: pointer.func */
            64097, 8, 0, /* 3554: pointer.func */
            64097, 8, 0, /* 3557: pointer.func */
            64097, 8, 0, /* 3560: pointer.func */
            64097, 8, 0, /* 3563: pointer.func */
            64097, 8, 0, /* 3566: pointer.func */
            64097, 8, 0, /* 3569: pointer.func */
            1, 8, 1, /* 3572: pointer.struct.dh_st */
            	2686, 0,
            1, 8, 1, /* 3577: pointer.struct.ec_key_st */
            	3582, 0,
            0, 0, 0, /* 3582: struct.ec_key_st */
            1, 8, 1, /* 3585: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3590, 0,
            0, 32, 2, /* 3590: struct.stack_st_fake_X509_ATTRIBUTE */
            	3597, 8,
            	125, 24,
            64099, 8, 2, /* 3597: pointer_to_array_of_pointers_to_stack */
            	3604, 0,
            	122, 20,
            0, 8, 1, /* 3604: pointer.X509_ATTRIBUTE */
            	1288, 0,
            1, 8, 1, /* 3609: pointer.struct.stack_st_X509_EXTENSION */
            	3614, 0,
            0, 32, 2, /* 3614: struct.stack_st_fake_X509_EXTENSION */
            	3621, 8,
            	125, 24,
            64099, 8, 2, /* 3621: pointer_to_array_of_pointers_to_stack */
            	3628, 0,
            	122, 20,
            0, 8, 1, /* 3628: pointer.X509_EXTENSION */
            	1659, 0,
            0, 24, 1, /* 3633: struct.ASN1_ENCODING_st */
            	39, 0,
            1, 8, 1, /* 3638: pointer.struct.AUTHORITY_KEYID_st */
            	3643, 0,
            0, 0, 0, /* 3643: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 3646: pointer.struct.X509_POLICY_CACHE_st */
            	3651, 0,
            0, 0, 0, /* 3651: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 3654: pointer.struct.stack_st_DIST_POINT */
            	3659, 0,
            0, 32, 2, /* 3659: struct.stack_st_fake_DIST_POINT */
            	3666, 8,
            	125, 24,
            64099, 8, 2, /* 3666: pointer_to_array_of_pointers_to_stack */
            	3673, 0,
            	122, 20,
            0, 8, 1, /* 3673: pointer.DIST_POINT */
            	1740, 0,
            1, 8, 1, /* 3678: pointer.struct.stack_st_GENERAL_NAME */
            	3683, 0,
            0, 32, 2, /* 3683: struct.stack_st_fake_GENERAL_NAME */
            	3690, 8,
            	125, 24,
            64099, 8, 2, /* 3690: pointer_to_array_of_pointers_to_stack */
            	3697, 0,
            	122, 20,
            0, 8, 1, /* 3697: pointer.GENERAL_NAME */
            	1797, 0,
            1, 8, 1, /* 3702: pointer.struct.NAME_CONSTRAINTS_st */
            	3707, 0,
            0, 0, 0, /* 3707: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3710: pointer.struct.x509_cert_aux_st */
            	3715, 0,
            0, 40, 5, /* 3715: struct.x509_cert_aux_st */
            	3728, 0,
            	3728, 8,
            	2843, 16,
            	3212, 24,
            	2819, 32,
            1, 8, 1, /* 3728: pointer.struct.stack_st_ASN1_OBJECT */
            	3733, 0,
            0, 32, 2, /* 3733: struct.stack_st_fake_ASN1_OBJECT */
            	3740, 8,
            	125, 24,
            64099, 8, 2, /* 3740: pointer_to_array_of_pointers_to_stack */
            	3747, 0,
            	122, 20,
            0, 8, 1, /* 3747: pointer.ASN1_OBJECT */
            	2199, 0,
            1, 8, 1, /* 3752: pointer.struct.env_md_st */
            	3757, 0,
            0, 120, 8, /* 3757: struct.env_md_st */
            	3776, 24,
            	3779, 32,
            	3782, 40,
            	3785, 48,
            	3776, 56,
            	3788, 64,
            	3791, 72,
            	3794, 112,
            64097, 8, 0, /* 3776: pointer.func */
            64097, 8, 0, /* 3779: pointer.func */
            64097, 8, 0, /* 3782: pointer.func */
            64097, 8, 0, /* 3785: pointer.func */
            64097, 8, 0, /* 3788: pointer.func */
            64097, 8, 0, /* 3791: pointer.func */
            64097, 8, 0, /* 3794: pointer.func */
            1, 8, 1, /* 3797: pointer.struct.rsa_st */
            	3391, 0,
            64097, 8, 0, /* 3802: pointer.func */
            64097, 8, 0, /* 3805: pointer.func */
            1, 8, 1, /* 3808: pointer.struct.ec_key_st */
            	3582, 0,
            64097, 8, 0, /* 3813: pointer.func */
            64097, 8, 0, /* 3816: pointer.func */
            0, 72, 8, /* 3819: struct.dh_method */
            	5, 0,
            	3816, 8,
            	3838, 16,
            	3017, 24,
            	3816, 32,
            	3816, 40,
            	52, 56,
            	3841, 64,
            64097, 8, 0, /* 3838: pointer.func */
            64097, 8, 0, /* 3841: pointer.func */
            64097, 8, 0, /* 3844: pointer.func */
            64097, 8, 0, /* 3847: pointer.func */
            0, 248, 5, /* 3850: struct.sess_cert_st */
            	3863, 0,
            	3037, 16,
            	3797, 216,
            	2681, 224,
            	3808, 232,
            1, 8, 1, /* 3863: pointer.struct.stack_st_X509 */
            	3868, 0,
            0, 32, 2, /* 3868: struct.stack_st_fake_X509 */
            	3875, 8,
            	125, 24,
            64099, 8, 2, /* 3875: pointer_to_array_of_pointers_to_stack */
            	3882, 0,
            	122, 20,
            0, 8, 1, /* 3882: pointer.X509 */
            	3887, 0,
            0, 0, 1, /* 3887: X509 */
            	3892, 0,
            0, 184, 12, /* 3892: struct.x509_st */
            	3919, 0,
            	3959, 8,
            	4048, 16,
            	52, 32,
            	4347, 40,
            	4053, 104,
            	4561, 112,
            	4569, 120,
            	4577, 128,
            	4601, 136,
            	4625, 144,
            	4633, 176,
            1, 8, 1, /* 3919: pointer.struct.x509_cinf_st */
            	3924, 0,
            0, 104, 11, /* 3924: struct.x509_cinf_st */
            	3949, 0,
            	3949, 8,
            	3959, 16,
            	4116, 24,
            	4164, 32,
            	4116, 40,
            	4181, 48,
            	4048, 56,
            	4048, 64,
            	4532, 72,
            	4556, 80,
            1, 8, 1, /* 3949: pointer.struct.asn1_string_st */
            	3954, 0,
            0, 24, 1, /* 3954: struct.asn1_string_st */
            	39, 8,
            1, 8, 1, /* 3959: pointer.struct.X509_algor_st */
            	3964, 0,
            0, 16, 2, /* 3964: struct.X509_algor_st */
            	3971, 0,
            	3985, 8,
            1, 8, 1, /* 3971: pointer.struct.asn1_object_st */
            	3976, 0,
            0, 40, 3, /* 3976: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	107, 24,
            1, 8, 1, /* 3985: pointer.struct.asn1_type_st */
            	3990, 0,
            0, 16, 1, /* 3990: struct.asn1_type_st */
            	3995, 8,
            0, 8, 20, /* 3995: union.unknown */
            	52, 0,
            	4038, 0,
            	3971, 0,
            	3949, 0,
            	4043, 0,
            	4048, 0,
            	4053, 0,
            	4058, 0,
            	4063, 0,
            	4068, 0,
            	4073, 0,
            	4078, 0,
            	4083, 0,
            	4088, 0,
            	4093, 0,
            	4098, 0,
            	4103, 0,
            	4038, 0,
            	4038, 0,
            	4108, 0,
            1, 8, 1, /* 4038: pointer.struct.asn1_string_st */
            	3954, 0,
            1, 8, 1, /* 4043: pointer.struct.asn1_string_st */
            	3954, 0,
            1, 8, 1, /* 4048: pointer.struct.asn1_string_st */
            	3954, 0,
            1, 8, 1, /* 4053: pointer.struct.asn1_string_st */
            	3954, 0,
            1, 8, 1, /* 4058: pointer.struct.asn1_string_st */
            	3954, 0,
            1, 8, 1, /* 4063: pointer.struct.asn1_string_st */
            	3954, 0,
            1, 8, 1, /* 4068: pointer.struct.asn1_string_st */
            	3954, 0,
            1, 8, 1, /* 4073: pointer.struct.asn1_string_st */
            	3954, 0,
            1, 8, 1, /* 4078: pointer.struct.asn1_string_st */
            	3954, 0,
            1, 8, 1, /* 4083: pointer.struct.asn1_string_st */
            	3954, 0,
            1, 8, 1, /* 4088: pointer.struct.asn1_string_st */
            	3954, 0,
            1, 8, 1, /* 4093: pointer.struct.asn1_string_st */
            	3954, 0,
            1, 8, 1, /* 4098: pointer.struct.asn1_string_st */
            	3954, 0,
            1, 8, 1, /* 4103: pointer.struct.asn1_string_st */
            	3954, 0,
            1, 8, 1, /* 4108: pointer.struct.ASN1_VALUE_st */
            	4113, 0,
            0, 0, 0, /* 4113: struct.ASN1_VALUE_st */
            1, 8, 1, /* 4116: pointer.struct.X509_name_st */
            	4121, 0,
            0, 40, 3, /* 4121: struct.X509_name_st */
            	4130, 0,
            	4154, 16,
            	39, 24,
            1, 8, 1, /* 4130: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4135, 0,
            0, 32, 2, /* 4135: struct.stack_st_fake_X509_NAME_ENTRY */
            	4142, 8,
            	125, 24,
            64099, 8, 2, /* 4142: pointer_to_array_of_pointers_to_stack */
            	4149, 0,
            	122, 20,
            0, 8, 1, /* 4149: pointer.X509_NAME_ENTRY */
            	81, 0,
            1, 8, 1, /* 4154: pointer.struct.buf_mem_st */
            	4159, 0,
            0, 24, 1, /* 4159: struct.buf_mem_st */
            	52, 8,
            1, 8, 1, /* 4164: pointer.struct.X509_val_st */
            	4169, 0,
            0, 16, 2, /* 4169: struct.X509_val_st */
            	4176, 0,
            	4176, 8,
            1, 8, 1, /* 4176: pointer.struct.asn1_string_st */
            	3954, 0,
            1, 8, 1, /* 4181: pointer.struct.X509_pubkey_st */
            	4186, 0,
            0, 24, 3, /* 4186: struct.X509_pubkey_st */
            	3959, 0,
            	4048, 8,
            	4195, 16,
            1, 8, 1, /* 4195: pointer.struct.evp_pkey_st */
            	4200, 0,
            0, 56, 4, /* 4200: struct.evp_pkey_st */
            	4211, 16,
            	4219, 24,
            	4227, 32,
            	4508, 48,
            1, 8, 1, /* 4211: pointer.struct.evp_pkey_asn1_method_st */
            	4216, 0,
            0, 0, 0, /* 4216: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 4219: pointer.struct.engine_st */
            	4224, 0,
            0, 0, 0, /* 4224: struct.engine_st */
            0, 8, 5, /* 4227: union.unknown */
            	52, 0,
            	4240, 0,
            	4391, 0,
            	4466, 0,
            	4503, 0,
            1, 8, 1, /* 4240: pointer.struct.rsa_st */
            	4245, 0,
            0, 168, 17, /* 4245: struct.rsa_st */
            	4282, 16,
            	4219, 24,
            	4337, 32,
            	4337, 40,
            	4337, 48,
            	4337, 56,
            	4337, 64,
            	4337, 72,
            	4337, 80,
            	4337, 88,
            	4347, 96,
            	4369, 120,
            	4369, 128,
            	4369, 136,
            	52, 144,
            	4383, 152,
            	4383, 160,
            1, 8, 1, /* 4282: pointer.struct.rsa_meth_st */
            	4287, 0,
            0, 112, 13, /* 4287: struct.rsa_meth_st */
            	5, 0,
            	4316, 8,
            	4316, 16,
            	4316, 24,
            	4316, 32,
            	4319, 40,
            	4322, 48,
            	4325, 56,
            	4325, 64,
            	52, 80,
            	4328, 88,
            	4331, 96,
            	4334, 104,
            64097, 8, 0, /* 4316: pointer.func */
            64097, 8, 0, /* 4319: pointer.func */
            64097, 8, 0, /* 4322: pointer.func */
            64097, 8, 0, /* 4325: pointer.func */
            64097, 8, 0, /* 4328: pointer.func */
            64097, 8, 0, /* 4331: pointer.func */
            64097, 8, 0, /* 4334: pointer.func */
            1, 8, 1, /* 4337: pointer.struct.bignum_st */
            	4342, 0,
            0, 24, 1, /* 4342: struct.bignum_st */
            	252, 0,
            0, 16, 1, /* 4347: struct.crypto_ex_data_st */
            	4352, 0,
            1, 8, 1, /* 4352: pointer.struct.stack_st_void */
            	4357, 0,
            0, 32, 1, /* 4357: struct.stack_st_void */
            	4362, 0,
            0, 32, 2, /* 4362: struct.stack_st */
            	1080, 8,
            	125, 24,
            1, 8, 1, /* 4369: pointer.struct.bn_mont_ctx_st */
            	4374, 0,
            0, 96, 3, /* 4374: struct.bn_mont_ctx_st */
            	4342, 8,
            	4342, 32,
            	4342, 56,
            1, 8, 1, /* 4383: pointer.struct.bn_blinding_st */
            	4388, 0,
            0, 0, 0, /* 4388: struct.bn_blinding_st */
            1, 8, 1, /* 4391: pointer.struct.dsa_st */
            	4396, 0,
            0, 136, 11, /* 4396: struct.dsa_st */
            	4337, 24,
            	4337, 32,
            	4337, 40,
            	4337, 48,
            	4337, 56,
            	4337, 64,
            	4337, 72,
            	4369, 88,
            	4347, 104,
            	4421, 120,
            	4219, 128,
            1, 8, 1, /* 4421: pointer.struct.dsa_method */
            	4426, 0,
            0, 96, 11, /* 4426: struct.dsa_method */
            	5, 0,
            	4451, 8,
            	3847, 16,
            	3844, 24,
            	4454, 32,
            	4457, 40,
            	4460, 48,
            	4460, 56,
            	52, 72,
            	4463, 80,
            	4460, 88,
            64097, 8, 0, /* 4451: pointer.func */
            64097, 8, 0, /* 4454: pointer.func */
            64097, 8, 0, /* 4457: pointer.func */
            64097, 8, 0, /* 4460: pointer.func */
            64097, 8, 0, /* 4463: pointer.func */
            1, 8, 1, /* 4466: pointer.struct.dh_st */
            	4471, 0,
            0, 144, 12, /* 4471: struct.dh_st */
            	4337, 8,
            	4337, 16,
            	4337, 32,
            	4337, 40,
            	4369, 56,
            	4337, 64,
            	4337, 72,
            	39, 80,
            	4337, 96,
            	4347, 112,
            	4498, 128,
            	4219, 136,
            1, 8, 1, /* 4498: pointer.struct.dh_method */
            	3819, 0,
            1, 8, 1, /* 4503: pointer.struct.ec_key_st */
            	2853, 0,
            1, 8, 1, /* 4508: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4513, 0,
            0, 32, 2, /* 4513: struct.stack_st_fake_X509_ATTRIBUTE */
            	4520, 8,
            	125, 24,
            64099, 8, 2, /* 4520: pointer_to_array_of_pointers_to_stack */
            	4527, 0,
            	122, 20,
            0, 8, 1, /* 4527: pointer.X509_ATTRIBUTE */
            	1288, 0,
            1, 8, 1, /* 4532: pointer.struct.stack_st_X509_EXTENSION */
            	4537, 0,
            0, 32, 2, /* 4537: struct.stack_st_fake_X509_EXTENSION */
            	4544, 8,
            	125, 24,
            64099, 8, 2, /* 4544: pointer_to_array_of_pointers_to_stack */
            	4551, 0,
            	122, 20,
            0, 8, 1, /* 4551: pointer.X509_EXTENSION */
            	1659, 0,
            0, 24, 1, /* 4556: struct.ASN1_ENCODING_st */
            	39, 0,
            1, 8, 1, /* 4561: pointer.struct.AUTHORITY_KEYID_st */
            	4566, 0,
            0, 0, 0, /* 4566: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4569: pointer.struct.X509_POLICY_CACHE_st */
            	4574, 0,
            0, 0, 0, /* 4574: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 4577: pointer.struct.stack_st_DIST_POINT */
            	4582, 0,
            0, 32, 2, /* 4582: struct.stack_st_fake_DIST_POINT */
            	4589, 8,
            	125, 24,
            64099, 8, 2, /* 4589: pointer_to_array_of_pointers_to_stack */
            	4596, 0,
            	122, 20,
            0, 8, 1, /* 4596: pointer.DIST_POINT */
            	1740, 0,
            1, 8, 1, /* 4601: pointer.struct.stack_st_GENERAL_NAME */
            	4606, 0,
            0, 32, 2, /* 4606: struct.stack_st_fake_GENERAL_NAME */
            	4613, 8,
            	125, 24,
            64099, 8, 2, /* 4613: pointer_to_array_of_pointers_to_stack */
            	4620, 0,
            	122, 20,
            0, 8, 1, /* 4620: pointer.GENERAL_NAME */
            	1797, 0,
            1, 8, 1, /* 4625: pointer.struct.NAME_CONSTRAINTS_st */
            	4630, 0,
            0, 0, 0, /* 4630: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4633: pointer.struct.x509_cert_aux_st */
            	4638, 0,
            0, 40, 5, /* 4638: struct.x509_cert_aux_st */
            	4651, 0,
            	4651, 8,
            	4103, 16,
            	4053, 24,
            	4675, 32,
            1, 8, 1, /* 4651: pointer.struct.stack_st_ASN1_OBJECT */
            	4656, 0,
            0, 32, 2, /* 4656: struct.stack_st_fake_ASN1_OBJECT */
            	4663, 8,
            	125, 24,
            64099, 8, 2, /* 4663: pointer_to_array_of_pointers_to_stack */
            	4670, 0,
            	122, 20,
            0, 8, 1, /* 4670: pointer.ASN1_OBJECT */
            	2199, 0,
            1, 8, 1, /* 4675: pointer.struct.stack_st_X509_ALGOR */
            	4680, 0,
            0, 32, 2, /* 4680: struct.stack_st_fake_X509_ALGOR */
            	4687, 8,
            	125, 24,
            64099, 8, 2, /* 4687: pointer_to_array_of_pointers_to_stack */
            	4694, 0,
            	122, 20,
            0, 8, 1, /* 4694: pointer.X509_ALGOR */
            	2237, 0,
            64097, 8, 0, /* 4699: pointer.func */
            0, 56, 2, /* 4702: struct.X509_VERIFY_PARAM_st */
            	52, 0,
            	3728, 48,
            1, 8, 1, /* 4709: pointer.struct.env_md_ctx_st */
            	4714, 0,
            0, 48, 5, /* 4714: struct.env_md_ctx_st */
            	3752, 0,
            	2785, 8,
            	26, 24,
            	4727, 32,
            	3779, 40,
            1, 8, 1, /* 4727: pointer.struct.evp_pkey_ctx_st */
            	4732, 0,
            0, 0, 0, /* 4732: struct.evp_pkey_ctx_st */
            0, 0, 1, /* 4735: OCSP_RESPID */
            	4740, 0,
            0, 16, 1, /* 4740: struct.ocsp_responder_id_st */
            	147, 8,
            1, 8, 1, /* 4745: pointer.struct.stack_st_X509_OBJECT */
            	4750, 0,
            0, 32, 2, /* 4750: struct.stack_st_fake_X509_OBJECT */
            	4757, 8,
            	125, 24,
            64099, 8, 2, /* 4757: pointer_to_array_of_pointers_to_stack */
            	4764, 0,
            	122, 20,
            0, 8, 1, /* 4764: pointer.X509_OBJECT */
            	577, 0,
            64097, 8, 0, /* 4769: pointer.func */
            1, 8, 1, /* 4772: pointer.struct.dtls1_state_st */
            	4777, 0,
            0, 888, 7, /* 4777: struct.dtls1_state_st */
            	4794, 576,
            	4794, 592,
            	4799, 608,
            	4799, 616,
            	4794, 624,
            	4807, 648,
            	4807, 736,
            0, 16, 1, /* 4794: struct.record_pqueue_st */
            	4799, 8,
            1, 8, 1, /* 4799: pointer.struct._pqueue */
            	4804, 0,
            0, 0, 0, /* 4804: struct._pqueue */
            0, 88, 1, /* 4807: struct.hm_header_st */
            	4812, 48,
            0, 40, 4, /* 4812: struct.dtls1_retransmit_state */
            	4823, 0,
            	4709, 8,
            	4876, 16,
            	4919, 24,
            1, 8, 1, /* 4823: pointer.struct.evp_cipher_ctx_st */
            	4828, 0,
            0, 168, 4, /* 4828: struct.evp_cipher_ctx_st */
            	4839, 0,
            	2785, 8,
            	26, 96,
            	26, 120,
            1, 8, 1, /* 4839: pointer.struct.evp_cipher_st */
            	4844, 0,
            0, 88, 7, /* 4844: struct.evp_cipher_st */
            	4861, 24,
            	4864, 32,
            	4867, 40,
            	4870, 56,
            	4870, 64,
            	4873, 72,
            	26, 80,
            64097, 8, 0, /* 4861: pointer.func */
            64097, 8, 0, /* 4864: pointer.func */
            64097, 8, 0, /* 4867: pointer.func */
            64097, 8, 0, /* 4870: pointer.func */
            64097, 8, 0, /* 4873: pointer.func */
            1, 8, 1, /* 4876: pointer.struct.comp_ctx_st */
            	4881, 0,
            0, 56, 2, /* 4881: struct.comp_ctx_st */
            	4888, 0,
            	2727, 40,
            1, 8, 1, /* 4888: pointer.struct.comp_method_st */
            	4893, 0,
            0, 64, 7, /* 4893: struct.comp_method_st */
            	5, 8,
            	4910, 16,
            	4913, 24,
            	4916, 32,
            	4916, 40,
            	311, 48,
            	311, 56,
            64097, 8, 0, /* 4910: pointer.func */
            64097, 8, 0, /* 4913: pointer.func */
            64097, 8, 0, /* 4916: pointer.func */
            1, 8, 1, /* 4919: pointer.struct.ssl_session_st */
            	4924, 0,
            0, 352, 14, /* 4924: struct.ssl_session_st */
            	52, 144,
            	52, 152,
            	4955, 168,
            	3051, 176,
            	4960, 224,
            	4970, 240,
            	2727, 248,
            	5004, 264,
            	5004, 272,
            	52, 280,
            	39, 296,
            	39, 312,
            	39, 320,
            	52, 344,
            1, 8, 1, /* 4955: pointer.struct.sess_cert_st */
            	3850, 0,
            1, 8, 1, /* 4960: pointer.struct.ssl_cipher_st */
            	4965, 0,
            0, 88, 1, /* 4965: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 4970: pointer.struct.stack_st_SSL_CIPHER */
            	4975, 0,
            0, 32, 2, /* 4975: struct.stack_st_fake_SSL_CIPHER */
            	4982, 8,
            	125, 24,
            64099, 8, 2, /* 4982: pointer_to_array_of_pointers_to_stack */
            	4989, 0,
            	122, 20,
            0, 8, 1, /* 4989: pointer.SSL_CIPHER */
            	4994, 0,
            0, 0, 1, /* 4994: SSL_CIPHER */
            	4999, 0,
            0, 88, 1, /* 4999: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 5004: pointer.struct.ssl_session_st */
            	4924, 0,
            64097, 8, 0, /* 5009: pointer.func */
            64097, 8, 0, /* 5012: pointer.func */
            64097, 8, 0, /* 5015: pointer.func */
            1, 8, 1, /* 5018: pointer.pointer.struct.env_md_ctx_st */
            	4709, 0,
            64097, 8, 0, /* 5023: pointer.func */
            0, 1200, 10, /* 5026: struct.ssl3_state_st */
            	5049, 240,
            	5049, 264,
            	5054, 288,
            	5054, 344,
            	107, 432,
            	5063, 440,
            	5018, 448,
            	26, 496,
            	26, 512,
            	5131, 528,
            0, 24, 1, /* 5049: struct.ssl3_buffer_st */
            	39, 0,
            0, 56, 3, /* 5054: struct.ssl3_record_st */
            	39, 16,
            	39, 24,
            	39, 32,
            1, 8, 1, /* 5063: pointer.struct.bio_st */
            	5068, 0,
            0, 112, 7, /* 5068: struct.bio_st */
            	5085, 0,
            	5123, 8,
            	52, 16,
            	26, 48,
            	5126, 56,
            	5126, 64,
            	2727, 96,
            1, 8, 1, /* 5085: pointer.struct.bio_method_st */
            	5090, 0,
            0, 80, 9, /* 5090: struct.bio_method_st */
            	5, 8,
            	5111, 16,
            	5114, 24,
            	5012, 32,
            	5114, 40,
            	5117, 48,
            	5120, 56,
            	5120, 64,
            	5023, 72,
            64097, 8, 0, /* 5111: pointer.func */
            64097, 8, 0, /* 5114: pointer.func */
            64097, 8, 0, /* 5117: pointer.func */
            64097, 8, 0, /* 5120: pointer.func */
            64097, 8, 0, /* 5123: pointer.func */
            1, 8, 1, /* 5126: pointer.struct.bio_st */
            	5068, 0,
            0, 528, 8, /* 5131: struct.unknown */
            	4960, 408,
            	2681, 416,
            	3808, 424,
            	5150, 464,
            	39, 480,
            	4839, 488,
            	3752, 496,
            	5222, 512,
            1, 8, 1, /* 5150: pointer.struct.stack_st_X509_NAME */
            	5155, 0,
            0, 32, 2, /* 5155: struct.stack_st_fake_X509_NAME */
            	5162, 8,
            	125, 24,
            64099, 8, 2, /* 5162: pointer_to_array_of_pointers_to_stack */
            	5169, 0,
            	122, 20,
            0, 8, 1, /* 5169: pointer.X509_NAME */
            	5174, 0,
            0, 0, 1, /* 5174: X509_NAME */
            	5179, 0,
            0, 40, 3, /* 5179: struct.X509_name_st */
            	5188, 0,
            	5212, 16,
            	39, 24,
            1, 8, 1, /* 5188: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5193, 0,
            0, 32, 2, /* 5193: struct.stack_st_fake_X509_NAME_ENTRY */
            	5200, 8,
            	125, 24,
            64099, 8, 2, /* 5200: pointer_to_array_of_pointers_to_stack */
            	5207, 0,
            	122, 20,
            0, 8, 1, /* 5207: pointer.X509_NAME_ENTRY */
            	81, 0,
            1, 8, 1, /* 5212: pointer.struct.buf_mem_st */
            	5217, 0,
            0, 24, 1, /* 5217: struct.buf_mem_st */
            	52, 8,
            1, 8, 1, /* 5222: pointer.struct.ssl_comp_st */
            	5227, 0,
            0, 24, 2, /* 5227: struct.ssl_comp_st */
            	5, 8,
            	4888, 16,
            0, 808, 51, /* 5234: struct.ssl_st */
            	5339, 8,
            	5063, 16,
            	5063, 24,
            	5063, 32,
            	2915, 48,
            	3308, 80,
            	26, 88,
            	39, 104,
            	2793, 120,
            	5344, 128,
            	4772, 136,
            	5349, 152,
            	26, 160,
            	5352, 176,
            	4970, 184,
            	4970, 192,
            	4823, 208,
            	4709, 216,
            	4876, 224,
            	4823, 232,
            	4709, 240,
            	4876, 248,
            	5357, 256,
            	4919, 304,
            	5362, 312,
            	5009, 328,
            	4699, 336,
            	5365, 352,
            	5368, 360,
            	5371, 368,
            	2727, 392,
            	5150, 408,
            	159, 464,
            	26, 472,
            	52, 480,
            	5540, 504,
            	2657, 512,
            	39, 520,
            	39, 544,
            	39, 560,
            	26, 568,
            	29, 584,
            	18, 592,
            	26, 600,
            	15, 608,
            	26, 616,
            	5371, 624,
            	39, 632,
            	167, 648,
            	10, 656,
            	205, 680,
            1, 8, 1, /* 5339: pointer.struct.ssl_method_st */
            	2856, 0,
            1, 8, 1, /* 5344: pointer.struct.ssl3_state_st */
            	5026, 0,
            64097, 8, 0, /* 5349: pointer.func */
            1, 8, 1, /* 5352: pointer.struct.X509_VERIFY_PARAM_st */
            	4702, 0,
            1, 8, 1, /* 5357: pointer.struct.cert_st */
            	3020, 0,
            64097, 8, 0, /* 5362: pointer.func */
            64097, 8, 0, /* 5365: pointer.func */
            64097, 8, 0, /* 5368: pointer.func */
            1, 8, 1, /* 5371: pointer.struct.ssl_ctx_st */
            	5376, 0,
            0, 736, 50, /* 5376: struct.ssl_ctx_st */
            	5339, 0,
            	4970, 8,
            	4970, 16,
            	5479, 24,
            	5520, 32,
            	5004, 48,
            	5004, 56,
            	346, 80,
            	5525, 88,
            	5528, 96,
            	5015, 152,
            	26, 160,
            	4769, 168,
            	26, 176,
            	343, 184,
            	5531, 192,
            	5534, 200,
            	2727, 208,
            	3752, 224,
            	3752, 232,
            	3752, 240,
            	3863, 248,
            	314, 256,
            	4699, 264,
            	5150, 272,
            	5357, 304,
            	5349, 320,
            	26, 328,
            	5009, 376,
            	5362, 384,
            	5352, 392,
            	2785, 408,
            	236, 416,
            	26, 424,
            	5537, 480,
            	239, 488,
            	26, 496,
            	276, 504,
            	26, 512,
            	52, 520,
            	5365, 528,
            	5368, 536,
            	2647, 552,
            	2647, 560,
            	205, 568,
            	199, 696,
            	26, 704,
            	196, 712,
            	26, 720,
            	167, 728,
            1, 8, 1, /* 5479: pointer.struct.x509_store_st */
            	5484, 0,
            0, 144, 15, /* 5484: struct.x509_store_st */
            	4745, 8,
            	2623, 16,
            	5352, 24,
            	5517, 32,
            	5009, 40,
            	401, 48,
            	398, 56,
            	5517, 64,
            	395, 72,
            	392, 80,
            	389, 88,
            	386, 96,
            	383, 104,
            	5517, 112,
            	2727, 120,
            64097, 8, 0, /* 5517: pointer.func */
            1, 8, 1, /* 5520: pointer.struct.lhash_st */
            	371, 0,
            64097, 8, 0, /* 5525: pointer.func */
            64097, 8, 0, /* 5528: pointer.func */
            64097, 8, 0, /* 5531: pointer.func */
            64097, 8, 0, /* 5534: pointer.func */
            64097, 8, 0, /* 5537: pointer.func */
            1, 8, 1, /* 5540: pointer.struct.stack_st_OCSP_RESPID */
            	5545, 0,
            0, 32, 2, /* 5545: struct.stack_st_fake_OCSP_RESPID */
            	5552, 8,
            	125, 24,
            64099, 8, 2, /* 5552: pointer_to_array_of_pointers_to_stack */
            	5559, 0,
            	122, 20,
            0, 8, 1, /* 5559: pointer.OCSP_RESPID */
            	4735, 0,
            0, 1, 0, /* 5564: char */
            1, 8, 1, /* 5567: pointer.struct.ssl_st */
            	5234, 0,
        },
        .arg_entity_index = { 5567, },
        .ret_entity_index = 52,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL * new_arg_a = *((SSL * *)new_args->args[0]);

    char * *new_ret_ptr = (char * *)new_args->ret;

    char * (*orig_SSL_get_srp_username)(SSL *);
    orig_SSL_get_srp_username = dlsym(RTLD_NEXT, "SSL_get_srp_username");
    *new_ret_ptr = (*orig_SSL_get_srp_username)(new_arg_a);

    syscall(889);

    return ret;
}

