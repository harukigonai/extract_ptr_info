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
            8884097, 8, 0, /* 0: pointer.func */
            0, 0, 1, /* 3: SRTP_PROTECTION_PROFILE */
            	8, 0,
            0, 16, 1, /* 8: struct.srtp_protection_profile_st */
            	13, 0,
            1, 8, 1, /* 13: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 18: pointer.func */
            8884097, 8, 0, /* 21: pointer.func */
            0, 8, 1, /* 24: struct.ssl3_buf_freelist_entry_st */
            	29, 0,
            1, 8, 1, /* 29: pointer.struct.ssl3_buf_freelist_entry_st */
            	24, 0,
            1, 8, 1, /* 34: pointer.struct.ssl3_buf_freelist_st */
            	39, 0,
            0, 24, 1, /* 39: struct.ssl3_buf_freelist_st */
            	29, 16,
            8884097, 8, 0, /* 44: pointer.func */
            8884097, 8, 0, /* 47: pointer.func */
            8884097, 8, 0, /* 50: pointer.func */
            8884097, 8, 0, /* 53: pointer.func */
            8884097, 8, 0, /* 56: pointer.func */
            8884097, 8, 0, /* 59: pointer.func */
            1, 8, 1, /* 62: pointer.struct.buf_mem_st */
            	67, 0,
            0, 24, 1, /* 67: struct.buf_mem_st */
            	72, 8,
            1, 8, 1, /* 72: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 77: pointer.struct.stack_st_X509_NAME_ENTRY */
            	82, 0,
            0, 32, 2, /* 82: struct.stack_st_fake_X509_NAME_ENTRY */
            	89, 8,
            	153, 24,
            8884099, 8, 2, /* 89: pointer_to_array_of_pointers_to_stack */
            	96, 0,
            	150, 20,
            0, 8, 1, /* 96: pointer.X509_NAME_ENTRY */
            	101, 0,
            0, 0, 1, /* 101: X509_NAME_ENTRY */
            	106, 0,
            0, 24, 2, /* 106: struct.X509_name_entry_st */
            	113, 0,
            	135, 8,
            1, 8, 1, /* 113: pointer.struct.asn1_object_st */
            	118, 0,
            0, 40, 3, /* 118: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	127, 24,
            1, 8, 1, /* 127: pointer.unsigned char */
            	132, 0,
            0, 1, 0, /* 132: unsigned char */
            1, 8, 1, /* 135: pointer.struct.asn1_string_st */
            	140, 0,
            0, 24, 1, /* 140: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 145: pointer.unsigned char */
            	132, 0,
            0, 4, 0, /* 150: int */
            8884097, 8, 0, /* 153: pointer.func */
            1, 8, 1, /* 156: pointer.struct.stack_st_X509_NAME */
            	161, 0,
            0, 32, 2, /* 161: struct.stack_st_fake_X509_NAME */
            	168, 8,
            	153, 24,
            8884099, 8, 2, /* 168: pointer_to_array_of_pointers_to_stack */
            	175, 0,
            	150, 20,
            0, 8, 1, /* 175: pointer.X509_NAME */
            	180, 0,
            0, 0, 1, /* 180: X509_NAME */
            	185, 0,
            0, 40, 3, /* 185: struct.X509_name_st */
            	77, 0,
            	62, 16,
            	145, 24,
            8884097, 8, 0, /* 194: pointer.func */
            8884097, 8, 0, /* 197: pointer.func */
            8884097, 8, 0, /* 200: pointer.func */
            8884097, 8, 0, /* 203: pointer.func */
            0, 128, 14, /* 206: struct.srp_ctx_st */
            	237, 0,
            	50, 8,
            	240, 16,
            	243, 24,
            	72, 32,
            	246, 40,
            	246, 48,
            	246, 56,
            	246, 64,
            	246, 72,
            	246, 80,
            	246, 88,
            	246, 96,
            	72, 104,
            0, 8, 0, /* 237: pointer.void */
            8884097, 8, 0, /* 240: pointer.func */
            8884097, 8, 0, /* 243: pointer.func */
            1, 8, 1, /* 246: pointer.struct.bignum_st */
            	251, 0,
            0, 24, 1, /* 251: struct.bignum_st */
            	256, 0,
            1, 8, 1, /* 256: pointer.unsigned int */
            	261, 0,
            0, 4, 0, /* 261: unsigned int */
            0, 64, 7, /* 264: struct.comp_method_st */
            	13, 8,
            	203, 16,
            	200, 24,
            	197, 32,
            	197, 40,
            	281, 48,
            	281, 56,
            8884097, 8, 0, /* 281: pointer.func */
            1, 8, 1, /* 284: pointer.struct.comp_method_st */
            	264, 0,
            0, 0, 1, /* 289: SSL_COMP */
            	294, 0,
            0, 24, 2, /* 294: struct.ssl_comp_st */
            	13, 8,
            	284, 16,
            1, 8, 1, /* 301: pointer.struct.stack_st_SSL_COMP */
            	306, 0,
            0, 32, 2, /* 306: struct.stack_st_fake_SSL_COMP */
            	313, 8,
            	153, 24,
            8884099, 8, 2, /* 313: pointer_to_array_of_pointers_to_stack */
            	320, 0,
            	150, 20,
            0, 8, 1, /* 320: pointer.SSL_COMP */
            	289, 0,
            8884097, 8, 0, /* 325: pointer.func */
            8884097, 8, 0, /* 328: pointer.func */
            8884097, 8, 0, /* 331: pointer.func */
            0, 88, 1, /* 334: struct.ssl_cipher_st */
            	13, 8,
            1, 8, 1, /* 339: pointer.struct.ssl_cipher_st */
            	334, 0,
            1, 8, 1, /* 344: pointer.struct.ec_key_st */
            	349, 0,
            0, 0, 0, /* 349: struct.ec_key_st */
            1, 8, 1, /* 352: pointer.struct.dh_st */
            	357, 0,
            0, 144, 12, /* 357: struct.dh_st */
            	246, 8,
            	246, 16,
            	246, 32,
            	246, 40,
            	384, 56,
            	246, 64,
            	246, 72,
            	145, 80,
            	246, 96,
            	398, 112,
            	425, 128,
            	461, 136,
            1, 8, 1, /* 384: pointer.struct.bn_mont_ctx_st */
            	389, 0,
            0, 96, 3, /* 389: struct.bn_mont_ctx_st */
            	251, 8,
            	251, 32,
            	251, 56,
            0, 16, 1, /* 398: struct.crypto_ex_data_st */
            	403, 0,
            1, 8, 1, /* 403: pointer.struct.stack_st_void */
            	408, 0,
            0, 32, 1, /* 408: struct.stack_st_void */
            	413, 0,
            0, 32, 2, /* 413: struct.stack_st */
            	420, 8,
            	153, 24,
            1, 8, 1, /* 420: pointer.pointer.char */
            	72, 0,
            1, 8, 1, /* 425: pointer.struct.dh_method */
            	430, 0,
            0, 72, 8, /* 430: struct.dh_method */
            	13, 0,
            	449, 8,
            	452, 16,
            	455, 24,
            	449, 32,
            	449, 40,
            	72, 56,
            	458, 64,
            8884097, 8, 0, /* 449: pointer.func */
            8884097, 8, 0, /* 452: pointer.func */
            8884097, 8, 0, /* 455: pointer.func */
            8884097, 8, 0, /* 458: pointer.func */
            1, 8, 1, /* 461: pointer.struct.engine_st */
            	466, 0,
            0, 0, 0, /* 466: struct.engine_st */
            8884097, 8, 0, /* 469: pointer.func */
            8884097, 8, 0, /* 472: pointer.func */
            8884097, 8, 0, /* 475: pointer.func */
            8884097, 8, 0, /* 478: pointer.func */
            8884097, 8, 0, /* 481: pointer.func */
            8884097, 8, 0, /* 484: pointer.func */
            0, 120, 8, /* 487: struct.env_md_st */
            	484, 24,
            	481, 32,
            	478, 40,
            	475, 48,
            	484, 56,
            	472, 64,
            	469, 72,
            	506, 112,
            8884097, 8, 0, /* 506: pointer.func */
            1, 8, 1, /* 509: pointer.struct.x509_cert_aux_st */
            	514, 0,
            0, 40, 5, /* 514: struct.x509_cert_aux_st */
            	527, 0,
            	527, 8,
            	565, 16,
            	575, 24,
            	580, 32,
            1, 8, 1, /* 527: pointer.struct.stack_st_ASN1_OBJECT */
            	532, 0,
            0, 32, 2, /* 532: struct.stack_st_fake_ASN1_OBJECT */
            	539, 8,
            	153, 24,
            8884099, 8, 2, /* 539: pointer_to_array_of_pointers_to_stack */
            	546, 0,
            	150, 20,
            0, 8, 1, /* 546: pointer.ASN1_OBJECT */
            	551, 0,
            0, 0, 1, /* 551: ASN1_OBJECT */
            	556, 0,
            0, 40, 3, /* 556: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	127, 24,
            1, 8, 1, /* 565: pointer.struct.asn1_string_st */
            	570, 0,
            0, 24, 1, /* 570: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 575: pointer.struct.asn1_string_st */
            	570, 0,
            1, 8, 1, /* 580: pointer.struct.stack_st_X509_ALGOR */
            	585, 0,
            0, 32, 2, /* 585: struct.stack_st_fake_X509_ALGOR */
            	592, 8,
            	153, 24,
            8884099, 8, 2, /* 592: pointer_to_array_of_pointers_to_stack */
            	599, 0,
            	150, 20,
            0, 8, 1, /* 599: pointer.X509_ALGOR */
            	604, 0,
            0, 0, 1, /* 604: X509_ALGOR */
            	609, 0,
            0, 16, 2, /* 609: struct.X509_algor_st */
            	616, 0,
            	630, 8,
            1, 8, 1, /* 616: pointer.struct.asn1_object_st */
            	621, 0,
            0, 40, 3, /* 621: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	127, 24,
            1, 8, 1, /* 630: pointer.struct.asn1_type_st */
            	635, 0,
            0, 16, 1, /* 635: struct.asn1_type_st */
            	640, 8,
            0, 8, 20, /* 640: union.unknown */
            	72, 0,
            	683, 0,
            	616, 0,
            	693, 0,
            	698, 0,
            	703, 0,
            	708, 0,
            	713, 0,
            	718, 0,
            	723, 0,
            	728, 0,
            	733, 0,
            	738, 0,
            	743, 0,
            	748, 0,
            	753, 0,
            	758, 0,
            	683, 0,
            	683, 0,
            	763, 0,
            1, 8, 1, /* 683: pointer.struct.asn1_string_st */
            	688, 0,
            0, 24, 1, /* 688: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 693: pointer.struct.asn1_string_st */
            	688, 0,
            1, 8, 1, /* 698: pointer.struct.asn1_string_st */
            	688, 0,
            1, 8, 1, /* 703: pointer.struct.asn1_string_st */
            	688, 0,
            1, 8, 1, /* 708: pointer.struct.asn1_string_st */
            	688, 0,
            1, 8, 1, /* 713: pointer.struct.asn1_string_st */
            	688, 0,
            1, 8, 1, /* 718: pointer.struct.asn1_string_st */
            	688, 0,
            1, 8, 1, /* 723: pointer.struct.asn1_string_st */
            	688, 0,
            1, 8, 1, /* 728: pointer.struct.asn1_string_st */
            	688, 0,
            1, 8, 1, /* 733: pointer.struct.asn1_string_st */
            	688, 0,
            1, 8, 1, /* 738: pointer.struct.asn1_string_st */
            	688, 0,
            1, 8, 1, /* 743: pointer.struct.asn1_string_st */
            	688, 0,
            1, 8, 1, /* 748: pointer.struct.asn1_string_st */
            	688, 0,
            1, 8, 1, /* 753: pointer.struct.asn1_string_st */
            	688, 0,
            1, 8, 1, /* 758: pointer.struct.asn1_string_st */
            	688, 0,
            1, 8, 1, /* 763: pointer.struct.ASN1_VALUE_st */
            	768, 0,
            0, 0, 0, /* 768: struct.ASN1_VALUE_st */
            1, 8, 1, /* 771: pointer.struct.stack_st_GENERAL_NAME */
            	776, 0,
            0, 32, 2, /* 776: struct.stack_st_fake_GENERAL_NAME */
            	783, 8,
            	153, 24,
            8884099, 8, 2, /* 783: pointer_to_array_of_pointers_to_stack */
            	790, 0,
            	150, 20,
            0, 8, 1, /* 790: pointer.GENERAL_NAME */
            	795, 0,
            0, 0, 1, /* 795: GENERAL_NAME */
            	800, 0,
            0, 16, 1, /* 800: struct.GENERAL_NAME_st */
            	805, 8,
            0, 8, 15, /* 805: union.unknown */
            	72, 0,
            	838, 0,
            	957, 0,
            	957, 0,
            	864, 0,
            	1005, 0,
            	1053, 0,
            	957, 0,
            	942, 0,
            	850, 0,
            	942, 0,
            	1005, 0,
            	957, 0,
            	850, 0,
            	864, 0,
            1, 8, 1, /* 838: pointer.struct.otherName_st */
            	843, 0,
            0, 16, 2, /* 843: struct.otherName_st */
            	850, 0,
            	864, 8,
            1, 8, 1, /* 850: pointer.struct.asn1_object_st */
            	855, 0,
            0, 40, 3, /* 855: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	127, 24,
            1, 8, 1, /* 864: pointer.struct.asn1_type_st */
            	869, 0,
            0, 16, 1, /* 869: struct.asn1_type_st */
            	874, 8,
            0, 8, 20, /* 874: union.unknown */
            	72, 0,
            	917, 0,
            	850, 0,
            	927, 0,
            	932, 0,
            	937, 0,
            	942, 0,
            	947, 0,
            	952, 0,
            	957, 0,
            	962, 0,
            	967, 0,
            	972, 0,
            	977, 0,
            	982, 0,
            	987, 0,
            	992, 0,
            	917, 0,
            	917, 0,
            	997, 0,
            1, 8, 1, /* 917: pointer.struct.asn1_string_st */
            	922, 0,
            0, 24, 1, /* 922: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 927: pointer.struct.asn1_string_st */
            	922, 0,
            1, 8, 1, /* 932: pointer.struct.asn1_string_st */
            	922, 0,
            1, 8, 1, /* 937: pointer.struct.asn1_string_st */
            	922, 0,
            1, 8, 1, /* 942: pointer.struct.asn1_string_st */
            	922, 0,
            1, 8, 1, /* 947: pointer.struct.asn1_string_st */
            	922, 0,
            1, 8, 1, /* 952: pointer.struct.asn1_string_st */
            	922, 0,
            1, 8, 1, /* 957: pointer.struct.asn1_string_st */
            	922, 0,
            1, 8, 1, /* 962: pointer.struct.asn1_string_st */
            	922, 0,
            1, 8, 1, /* 967: pointer.struct.asn1_string_st */
            	922, 0,
            1, 8, 1, /* 972: pointer.struct.asn1_string_st */
            	922, 0,
            1, 8, 1, /* 977: pointer.struct.asn1_string_st */
            	922, 0,
            1, 8, 1, /* 982: pointer.struct.asn1_string_st */
            	922, 0,
            1, 8, 1, /* 987: pointer.struct.asn1_string_st */
            	922, 0,
            1, 8, 1, /* 992: pointer.struct.asn1_string_st */
            	922, 0,
            1, 8, 1, /* 997: pointer.struct.ASN1_VALUE_st */
            	1002, 0,
            0, 0, 0, /* 1002: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1005: pointer.struct.X509_name_st */
            	1010, 0,
            0, 40, 3, /* 1010: struct.X509_name_st */
            	1019, 0,
            	1043, 16,
            	145, 24,
            1, 8, 1, /* 1019: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1024, 0,
            0, 32, 2, /* 1024: struct.stack_st_fake_X509_NAME_ENTRY */
            	1031, 8,
            	153, 24,
            8884099, 8, 2, /* 1031: pointer_to_array_of_pointers_to_stack */
            	1038, 0,
            	150, 20,
            0, 8, 1, /* 1038: pointer.X509_NAME_ENTRY */
            	101, 0,
            1, 8, 1, /* 1043: pointer.struct.buf_mem_st */
            	1048, 0,
            0, 24, 1, /* 1048: struct.buf_mem_st */
            	72, 8,
            1, 8, 1, /* 1053: pointer.struct.EDIPartyName_st */
            	1058, 0,
            0, 16, 2, /* 1058: struct.EDIPartyName_st */
            	917, 0,
            	917, 8,
            1, 8, 1, /* 1065: pointer.struct.stack_st_DIST_POINT */
            	1070, 0,
            0, 32, 2, /* 1070: struct.stack_st_fake_DIST_POINT */
            	1077, 8,
            	153, 24,
            8884099, 8, 2, /* 1077: pointer_to_array_of_pointers_to_stack */
            	1084, 0,
            	150, 20,
            0, 8, 1, /* 1084: pointer.DIST_POINT */
            	1089, 0,
            0, 0, 1, /* 1089: DIST_POINT */
            	1094, 0,
            0, 32, 3, /* 1094: struct.DIST_POINT_st */
            	1103, 0,
            	1194, 8,
            	1122, 16,
            1, 8, 1, /* 1103: pointer.struct.DIST_POINT_NAME_st */
            	1108, 0,
            0, 24, 2, /* 1108: struct.DIST_POINT_NAME_st */
            	1115, 8,
            	1170, 16,
            0, 8, 2, /* 1115: union.unknown */
            	1122, 0,
            	1146, 0,
            1, 8, 1, /* 1122: pointer.struct.stack_st_GENERAL_NAME */
            	1127, 0,
            0, 32, 2, /* 1127: struct.stack_st_fake_GENERAL_NAME */
            	1134, 8,
            	153, 24,
            8884099, 8, 2, /* 1134: pointer_to_array_of_pointers_to_stack */
            	1141, 0,
            	150, 20,
            0, 8, 1, /* 1141: pointer.GENERAL_NAME */
            	795, 0,
            1, 8, 1, /* 1146: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1151, 0,
            0, 32, 2, /* 1151: struct.stack_st_fake_X509_NAME_ENTRY */
            	1158, 8,
            	153, 24,
            8884099, 8, 2, /* 1158: pointer_to_array_of_pointers_to_stack */
            	1165, 0,
            	150, 20,
            0, 8, 1, /* 1165: pointer.X509_NAME_ENTRY */
            	101, 0,
            1, 8, 1, /* 1170: pointer.struct.X509_name_st */
            	1175, 0,
            0, 40, 3, /* 1175: struct.X509_name_st */
            	1146, 0,
            	1184, 16,
            	145, 24,
            1, 8, 1, /* 1184: pointer.struct.buf_mem_st */
            	1189, 0,
            0, 24, 1, /* 1189: struct.buf_mem_st */
            	72, 8,
            1, 8, 1, /* 1194: pointer.struct.asn1_string_st */
            	1199, 0,
            0, 24, 1, /* 1199: struct.asn1_string_st */
            	145, 8,
            0, 0, 0, /* 1204: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1207: pointer.struct.X509_POLICY_CACHE_st */
            	1204, 0,
            0, 0, 0, /* 1212: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 1215: pointer.struct.AUTHORITY_KEYID_st */
            	1212, 0,
            0, 24, 1, /* 1220: struct.ASN1_ENCODING_st */
            	145, 0,
            1, 8, 1, /* 1225: pointer.struct.stack_st_X509_EXTENSION */
            	1230, 0,
            0, 32, 2, /* 1230: struct.stack_st_fake_X509_EXTENSION */
            	1237, 8,
            	153, 24,
            8884099, 8, 2, /* 1237: pointer_to_array_of_pointers_to_stack */
            	1244, 0,
            	150, 20,
            0, 8, 1, /* 1244: pointer.X509_EXTENSION */
            	1249, 0,
            0, 0, 1, /* 1249: X509_EXTENSION */
            	1254, 0,
            0, 24, 2, /* 1254: struct.X509_extension_st */
            	1261, 0,
            	1275, 16,
            1, 8, 1, /* 1261: pointer.struct.asn1_object_st */
            	1266, 0,
            0, 40, 3, /* 1266: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	127, 24,
            1, 8, 1, /* 1275: pointer.struct.asn1_string_st */
            	1280, 0,
            0, 24, 1, /* 1280: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 1285: pointer.struct.dh_st */
            	357, 0,
            8884097, 8, 0, /* 1290: pointer.func */
            8884097, 8, 0, /* 1293: pointer.func */
            0, 16, 1, /* 1296: struct.crypto_ex_data_st */
            	1301, 0,
            1, 8, 1, /* 1301: pointer.struct.stack_st_void */
            	1306, 0,
            0, 32, 1, /* 1306: struct.stack_st_void */
            	1311, 0,
            0, 32, 2, /* 1311: struct.stack_st */
            	420, 8,
            	153, 24,
            8884097, 8, 0, /* 1318: pointer.func */
            1, 8, 1, /* 1321: pointer.struct.ec_key_st */
            	349, 0,
            0, 136, 11, /* 1326: struct.dsa_st */
            	1351, 24,
            	1351, 32,
            	1351, 40,
            	1351, 48,
            	1351, 56,
            	1351, 64,
            	1351, 72,
            	1361, 88,
            	1296, 104,
            	1375, 120,
            	1426, 128,
            1, 8, 1, /* 1351: pointer.struct.bignum_st */
            	1356, 0,
            0, 24, 1, /* 1356: struct.bignum_st */
            	256, 0,
            1, 8, 1, /* 1361: pointer.struct.bn_mont_ctx_st */
            	1366, 0,
            0, 96, 3, /* 1366: struct.bn_mont_ctx_st */
            	1356, 8,
            	1356, 32,
            	1356, 56,
            1, 8, 1, /* 1375: pointer.struct.dsa_method */
            	1380, 0,
            0, 96, 11, /* 1380: struct.dsa_method */
            	13, 0,
            	1405, 8,
            	1408, 16,
            	1411, 24,
            	1414, 32,
            	1417, 40,
            	1420, 48,
            	1420, 56,
            	72, 72,
            	1423, 80,
            	1420, 88,
            8884097, 8, 0, /* 1405: pointer.func */
            8884097, 8, 0, /* 1408: pointer.func */
            8884097, 8, 0, /* 1411: pointer.func */
            8884097, 8, 0, /* 1414: pointer.func */
            8884097, 8, 0, /* 1417: pointer.func */
            8884097, 8, 0, /* 1420: pointer.func */
            8884097, 8, 0, /* 1423: pointer.func */
            1, 8, 1, /* 1426: pointer.struct.engine_st */
            	1431, 0,
            0, 0, 0, /* 1431: struct.engine_st */
            1, 8, 1, /* 1434: pointer.struct.X509_crl_info_st */
            	1439, 0,
            0, 80, 8, /* 1439: struct.X509_crl_info_st */
            	1458, 0,
            	1468, 8,
            	1617, 16,
            	1665, 24,
            	1665, 32,
            	1670, 40,
            	1773, 48,
            	1797, 56,
            1, 8, 1, /* 1458: pointer.struct.asn1_string_st */
            	1463, 0,
            0, 24, 1, /* 1463: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 1468: pointer.struct.X509_algor_st */
            	1473, 0,
            0, 16, 2, /* 1473: struct.X509_algor_st */
            	1480, 0,
            	1494, 8,
            1, 8, 1, /* 1480: pointer.struct.asn1_object_st */
            	1485, 0,
            0, 40, 3, /* 1485: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	127, 24,
            1, 8, 1, /* 1494: pointer.struct.asn1_type_st */
            	1499, 0,
            0, 16, 1, /* 1499: struct.asn1_type_st */
            	1504, 8,
            0, 8, 20, /* 1504: union.unknown */
            	72, 0,
            	1547, 0,
            	1480, 0,
            	1458, 0,
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
            	1607, 0,
            	1612, 0,
            	1547, 0,
            	1547, 0,
            	763, 0,
            1, 8, 1, /* 1547: pointer.struct.asn1_string_st */
            	1463, 0,
            1, 8, 1, /* 1552: pointer.struct.asn1_string_st */
            	1463, 0,
            1, 8, 1, /* 1557: pointer.struct.asn1_string_st */
            	1463, 0,
            1, 8, 1, /* 1562: pointer.struct.asn1_string_st */
            	1463, 0,
            1, 8, 1, /* 1567: pointer.struct.asn1_string_st */
            	1463, 0,
            1, 8, 1, /* 1572: pointer.struct.asn1_string_st */
            	1463, 0,
            1, 8, 1, /* 1577: pointer.struct.asn1_string_st */
            	1463, 0,
            1, 8, 1, /* 1582: pointer.struct.asn1_string_st */
            	1463, 0,
            1, 8, 1, /* 1587: pointer.struct.asn1_string_st */
            	1463, 0,
            1, 8, 1, /* 1592: pointer.struct.asn1_string_st */
            	1463, 0,
            1, 8, 1, /* 1597: pointer.struct.asn1_string_st */
            	1463, 0,
            1, 8, 1, /* 1602: pointer.struct.asn1_string_st */
            	1463, 0,
            1, 8, 1, /* 1607: pointer.struct.asn1_string_st */
            	1463, 0,
            1, 8, 1, /* 1612: pointer.struct.asn1_string_st */
            	1463, 0,
            1, 8, 1, /* 1617: pointer.struct.X509_name_st */
            	1622, 0,
            0, 40, 3, /* 1622: struct.X509_name_st */
            	1631, 0,
            	1655, 16,
            	145, 24,
            1, 8, 1, /* 1631: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1636, 0,
            0, 32, 2, /* 1636: struct.stack_st_fake_X509_NAME_ENTRY */
            	1643, 8,
            	153, 24,
            8884099, 8, 2, /* 1643: pointer_to_array_of_pointers_to_stack */
            	1650, 0,
            	150, 20,
            0, 8, 1, /* 1650: pointer.X509_NAME_ENTRY */
            	101, 0,
            1, 8, 1, /* 1655: pointer.struct.buf_mem_st */
            	1660, 0,
            0, 24, 1, /* 1660: struct.buf_mem_st */
            	72, 8,
            1, 8, 1, /* 1665: pointer.struct.asn1_string_st */
            	1463, 0,
            1, 8, 1, /* 1670: pointer.struct.stack_st_X509_REVOKED */
            	1675, 0,
            0, 32, 2, /* 1675: struct.stack_st_fake_X509_REVOKED */
            	1682, 8,
            	153, 24,
            8884099, 8, 2, /* 1682: pointer_to_array_of_pointers_to_stack */
            	1689, 0,
            	150, 20,
            0, 8, 1, /* 1689: pointer.X509_REVOKED */
            	1694, 0,
            0, 0, 1, /* 1694: X509_REVOKED */
            	1699, 0,
            0, 40, 4, /* 1699: struct.x509_revoked_st */
            	1710, 0,
            	1720, 8,
            	1725, 16,
            	1749, 24,
            1, 8, 1, /* 1710: pointer.struct.asn1_string_st */
            	1715, 0,
            0, 24, 1, /* 1715: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 1720: pointer.struct.asn1_string_st */
            	1715, 0,
            1, 8, 1, /* 1725: pointer.struct.stack_st_X509_EXTENSION */
            	1730, 0,
            0, 32, 2, /* 1730: struct.stack_st_fake_X509_EXTENSION */
            	1737, 8,
            	153, 24,
            8884099, 8, 2, /* 1737: pointer_to_array_of_pointers_to_stack */
            	1744, 0,
            	150, 20,
            0, 8, 1, /* 1744: pointer.X509_EXTENSION */
            	1249, 0,
            1, 8, 1, /* 1749: pointer.struct.stack_st_GENERAL_NAME */
            	1754, 0,
            0, 32, 2, /* 1754: struct.stack_st_fake_GENERAL_NAME */
            	1761, 8,
            	153, 24,
            8884099, 8, 2, /* 1761: pointer_to_array_of_pointers_to_stack */
            	1768, 0,
            	150, 20,
            0, 8, 1, /* 1768: pointer.GENERAL_NAME */
            	795, 0,
            1, 8, 1, /* 1773: pointer.struct.stack_st_X509_EXTENSION */
            	1778, 0,
            0, 32, 2, /* 1778: struct.stack_st_fake_X509_EXTENSION */
            	1785, 8,
            	153, 24,
            8884099, 8, 2, /* 1785: pointer_to_array_of_pointers_to_stack */
            	1792, 0,
            	150, 20,
            0, 8, 1, /* 1792: pointer.X509_EXTENSION */
            	1249, 0,
            0, 24, 1, /* 1797: struct.ASN1_ENCODING_st */
            	145, 0,
            1, 8, 1, /* 1802: pointer.struct.cert_st */
            	1807, 0,
            0, 296, 7, /* 1807: struct.cert_st */
            	1824, 0,
            	2732, 48,
            	59, 56,
            	352, 64,
            	56, 72,
            	344, 80,
            	53, 88,
            1, 8, 1, /* 1824: pointer.struct.cert_pkey_st */
            	1829, 0,
            0, 24, 3, /* 1829: struct.cert_pkey_st */
            	1838, 0,
            	2131, 8,
            	2727, 16,
            1, 8, 1, /* 1838: pointer.struct.x509_st */
            	1843, 0,
            0, 184, 12, /* 1843: struct.x509_st */
            	1870, 0,
            	1905, 8,
            	1994, 16,
            	72, 32,
            	398, 40,
            	575, 104,
            	1215, 112,
            	1207, 120,
            	1065, 128,
            	771, 136,
            	2719, 144,
            	509, 176,
            1, 8, 1, /* 1870: pointer.struct.x509_cinf_st */
            	1875, 0,
            0, 104, 11, /* 1875: struct.x509_cinf_st */
            	1900, 0,
            	1900, 8,
            	1905, 16,
            	2052, 24,
            	2100, 32,
            	2052, 40,
            	2117, 48,
            	1994, 56,
            	1994, 64,
            	1225, 72,
            	1220, 80,
            1, 8, 1, /* 1900: pointer.struct.asn1_string_st */
            	570, 0,
            1, 8, 1, /* 1905: pointer.struct.X509_algor_st */
            	1910, 0,
            0, 16, 2, /* 1910: struct.X509_algor_st */
            	1917, 0,
            	1931, 8,
            1, 8, 1, /* 1917: pointer.struct.asn1_object_st */
            	1922, 0,
            0, 40, 3, /* 1922: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	127, 24,
            1, 8, 1, /* 1931: pointer.struct.asn1_type_st */
            	1936, 0,
            0, 16, 1, /* 1936: struct.asn1_type_st */
            	1941, 8,
            0, 8, 20, /* 1941: union.unknown */
            	72, 0,
            	1984, 0,
            	1917, 0,
            	1900, 0,
            	1989, 0,
            	1994, 0,
            	575, 0,
            	1999, 0,
            	2004, 0,
            	2009, 0,
            	2014, 0,
            	2019, 0,
            	2024, 0,
            	2029, 0,
            	2034, 0,
            	2039, 0,
            	565, 0,
            	1984, 0,
            	1984, 0,
            	2044, 0,
            1, 8, 1, /* 1984: pointer.struct.asn1_string_st */
            	570, 0,
            1, 8, 1, /* 1989: pointer.struct.asn1_string_st */
            	570, 0,
            1, 8, 1, /* 1994: pointer.struct.asn1_string_st */
            	570, 0,
            1, 8, 1, /* 1999: pointer.struct.asn1_string_st */
            	570, 0,
            1, 8, 1, /* 2004: pointer.struct.asn1_string_st */
            	570, 0,
            1, 8, 1, /* 2009: pointer.struct.asn1_string_st */
            	570, 0,
            1, 8, 1, /* 2014: pointer.struct.asn1_string_st */
            	570, 0,
            1, 8, 1, /* 2019: pointer.struct.asn1_string_st */
            	570, 0,
            1, 8, 1, /* 2024: pointer.struct.asn1_string_st */
            	570, 0,
            1, 8, 1, /* 2029: pointer.struct.asn1_string_st */
            	570, 0,
            1, 8, 1, /* 2034: pointer.struct.asn1_string_st */
            	570, 0,
            1, 8, 1, /* 2039: pointer.struct.asn1_string_st */
            	570, 0,
            1, 8, 1, /* 2044: pointer.struct.ASN1_VALUE_st */
            	2049, 0,
            0, 0, 0, /* 2049: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2052: pointer.struct.X509_name_st */
            	2057, 0,
            0, 40, 3, /* 2057: struct.X509_name_st */
            	2066, 0,
            	2090, 16,
            	145, 24,
            1, 8, 1, /* 2066: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2071, 0,
            0, 32, 2, /* 2071: struct.stack_st_fake_X509_NAME_ENTRY */
            	2078, 8,
            	153, 24,
            8884099, 8, 2, /* 2078: pointer_to_array_of_pointers_to_stack */
            	2085, 0,
            	150, 20,
            0, 8, 1, /* 2085: pointer.X509_NAME_ENTRY */
            	101, 0,
            1, 8, 1, /* 2090: pointer.struct.buf_mem_st */
            	2095, 0,
            0, 24, 1, /* 2095: struct.buf_mem_st */
            	72, 8,
            1, 8, 1, /* 2100: pointer.struct.X509_val_st */
            	2105, 0,
            0, 16, 2, /* 2105: struct.X509_val_st */
            	2112, 0,
            	2112, 8,
            1, 8, 1, /* 2112: pointer.struct.asn1_string_st */
            	570, 0,
            1, 8, 1, /* 2117: pointer.struct.X509_pubkey_st */
            	2122, 0,
            0, 24, 3, /* 2122: struct.X509_pubkey_st */
            	1905, 0,
            	1994, 8,
            	2131, 16,
            1, 8, 1, /* 2131: pointer.struct.evp_pkey_st */
            	2136, 0,
            0, 56, 4, /* 2136: struct.evp_pkey_st */
            	2147, 16,
            	461, 24,
            	2155, 32,
            	2348, 48,
            1, 8, 1, /* 2147: pointer.struct.evp_pkey_asn1_method_st */
            	2152, 0,
            0, 0, 0, /* 2152: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 2155: union.unknown */
            	72, 0,
            	2168, 0,
            	2273, 0,
            	1285, 0,
            	1321, 0,
            1, 8, 1, /* 2168: pointer.struct.rsa_st */
            	2173, 0,
            0, 168, 17, /* 2173: struct.rsa_st */
            	2210, 16,
            	461, 24,
            	246, 32,
            	246, 40,
            	246, 48,
            	246, 56,
            	246, 64,
            	246, 72,
            	246, 80,
            	246, 88,
            	398, 96,
            	384, 120,
            	384, 128,
            	384, 136,
            	72, 144,
            	2265, 152,
            	2265, 160,
            1, 8, 1, /* 2210: pointer.struct.rsa_meth_st */
            	2215, 0,
            0, 112, 13, /* 2215: struct.rsa_meth_st */
            	13, 0,
            	2244, 8,
            	2244, 16,
            	2244, 24,
            	2244, 32,
            	2247, 40,
            	2250, 48,
            	2253, 56,
            	2253, 64,
            	72, 80,
            	2256, 88,
            	2259, 96,
            	2262, 104,
            8884097, 8, 0, /* 2244: pointer.func */
            8884097, 8, 0, /* 2247: pointer.func */
            8884097, 8, 0, /* 2250: pointer.func */
            8884097, 8, 0, /* 2253: pointer.func */
            8884097, 8, 0, /* 2256: pointer.func */
            8884097, 8, 0, /* 2259: pointer.func */
            8884097, 8, 0, /* 2262: pointer.func */
            1, 8, 1, /* 2265: pointer.struct.bn_blinding_st */
            	2270, 0,
            0, 0, 0, /* 2270: struct.bn_blinding_st */
            1, 8, 1, /* 2273: pointer.struct.dsa_st */
            	2278, 0,
            0, 136, 11, /* 2278: struct.dsa_st */
            	246, 24,
            	246, 32,
            	246, 40,
            	246, 48,
            	246, 56,
            	246, 64,
            	246, 72,
            	384, 88,
            	398, 104,
            	2303, 120,
            	461, 128,
            1, 8, 1, /* 2303: pointer.struct.dsa_method */
            	2308, 0,
            0, 96, 11, /* 2308: struct.dsa_method */
            	13, 0,
            	2333, 8,
            	2336, 16,
            	2339, 24,
            	1293, 32,
            	1290, 40,
            	2342, 48,
            	2342, 56,
            	72, 72,
            	2345, 80,
            	2342, 88,
            8884097, 8, 0, /* 2333: pointer.func */
            8884097, 8, 0, /* 2336: pointer.func */
            8884097, 8, 0, /* 2339: pointer.func */
            8884097, 8, 0, /* 2342: pointer.func */
            8884097, 8, 0, /* 2345: pointer.func */
            1, 8, 1, /* 2348: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2353, 0,
            0, 32, 2, /* 2353: struct.stack_st_fake_X509_ATTRIBUTE */
            	2360, 8,
            	153, 24,
            8884099, 8, 2, /* 2360: pointer_to_array_of_pointers_to_stack */
            	2367, 0,
            	150, 20,
            0, 8, 1, /* 2367: pointer.X509_ATTRIBUTE */
            	2372, 0,
            0, 0, 1, /* 2372: X509_ATTRIBUTE */
            	2377, 0,
            0, 24, 2, /* 2377: struct.x509_attributes_st */
            	2384, 0,
            	2398, 16,
            1, 8, 1, /* 2384: pointer.struct.asn1_object_st */
            	2389, 0,
            0, 40, 3, /* 2389: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	127, 24,
            0, 8, 3, /* 2398: union.unknown */
            	72, 0,
            	2407, 0,
            	2586, 0,
            1, 8, 1, /* 2407: pointer.struct.stack_st_ASN1_TYPE */
            	2412, 0,
            0, 32, 2, /* 2412: struct.stack_st_fake_ASN1_TYPE */
            	2419, 8,
            	153, 24,
            8884099, 8, 2, /* 2419: pointer_to_array_of_pointers_to_stack */
            	2426, 0,
            	150, 20,
            0, 8, 1, /* 2426: pointer.ASN1_TYPE */
            	2431, 0,
            0, 0, 1, /* 2431: ASN1_TYPE */
            	2436, 0,
            0, 16, 1, /* 2436: struct.asn1_type_st */
            	2441, 8,
            0, 8, 20, /* 2441: union.unknown */
            	72, 0,
            	2484, 0,
            	2494, 0,
            	2508, 0,
            	2513, 0,
            	2518, 0,
            	2523, 0,
            	2528, 0,
            	2533, 0,
            	2538, 0,
            	2543, 0,
            	2548, 0,
            	2553, 0,
            	2558, 0,
            	2563, 0,
            	2568, 0,
            	2573, 0,
            	2484, 0,
            	2484, 0,
            	2578, 0,
            1, 8, 1, /* 2484: pointer.struct.asn1_string_st */
            	2489, 0,
            0, 24, 1, /* 2489: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 2494: pointer.struct.asn1_object_st */
            	2499, 0,
            0, 40, 3, /* 2499: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	127, 24,
            1, 8, 1, /* 2508: pointer.struct.asn1_string_st */
            	2489, 0,
            1, 8, 1, /* 2513: pointer.struct.asn1_string_st */
            	2489, 0,
            1, 8, 1, /* 2518: pointer.struct.asn1_string_st */
            	2489, 0,
            1, 8, 1, /* 2523: pointer.struct.asn1_string_st */
            	2489, 0,
            1, 8, 1, /* 2528: pointer.struct.asn1_string_st */
            	2489, 0,
            1, 8, 1, /* 2533: pointer.struct.asn1_string_st */
            	2489, 0,
            1, 8, 1, /* 2538: pointer.struct.asn1_string_st */
            	2489, 0,
            1, 8, 1, /* 2543: pointer.struct.asn1_string_st */
            	2489, 0,
            1, 8, 1, /* 2548: pointer.struct.asn1_string_st */
            	2489, 0,
            1, 8, 1, /* 2553: pointer.struct.asn1_string_st */
            	2489, 0,
            1, 8, 1, /* 2558: pointer.struct.asn1_string_st */
            	2489, 0,
            1, 8, 1, /* 2563: pointer.struct.asn1_string_st */
            	2489, 0,
            1, 8, 1, /* 2568: pointer.struct.asn1_string_st */
            	2489, 0,
            1, 8, 1, /* 2573: pointer.struct.asn1_string_st */
            	2489, 0,
            1, 8, 1, /* 2578: pointer.struct.ASN1_VALUE_st */
            	2583, 0,
            0, 0, 0, /* 2583: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2586: pointer.struct.asn1_type_st */
            	2591, 0,
            0, 16, 1, /* 2591: struct.asn1_type_st */
            	2596, 8,
            0, 8, 20, /* 2596: union.unknown */
            	72, 0,
            	2639, 0,
            	2384, 0,
            	2649, 0,
            	2654, 0,
            	2659, 0,
            	2664, 0,
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
            	2639, 0,
            	2639, 0,
            	763, 0,
            1, 8, 1, /* 2639: pointer.struct.asn1_string_st */
            	2644, 0,
            0, 24, 1, /* 2644: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 2649: pointer.struct.asn1_string_st */
            	2644, 0,
            1, 8, 1, /* 2654: pointer.struct.asn1_string_st */
            	2644, 0,
            1, 8, 1, /* 2659: pointer.struct.asn1_string_st */
            	2644, 0,
            1, 8, 1, /* 2664: pointer.struct.asn1_string_st */
            	2644, 0,
            1, 8, 1, /* 2669: pointer.struct.asn1_string_st */
            	2644, 0,
            1, 8, 1, /* 2674: pointer.struct.asn1_string_st */
            	2644, 0,
            1, 8, 1, /* 2679: pointer.struct.asn1_string_st */
            	2644, 0,
            1, 8, 1, /* 2684: pointer.struct.asn1_string_st */
            	2644, 0,
            1, 8, 1, /* 2689: pointer.struct.asn1_string_st */
            	2644, 0,
            1, 8, 1, /* 2694: pointer.struct.asn1_string_st */
            	2644, 0,
            1, 8, 1, /* 2699: pointer.struct.asn1_string_st */
            	2644, 0,
            1, 8, 1, /* 2704: pointer.struct.asn1_string_st */
            	2644, 0,
            1, 8, 1, /* 2709: pointer.struct.asn1_string_st */
            	2644, 0,
            1, 8, 1, /* 2714: pointer.struct.asn1_string_st */
            	2644, 0,
            1, 8, 1, /* 2719: pointer.struct.NAME_CONSTRAINTS_st */
            	2724, 0,
            0, 0, 0, /* 2724: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 2727: pointer.struct.env_md_st */
            	487, 0,
            1, 8, 1, /* 2732: pointer.struct.rsa_st */
            	2173, 0,
            1, 8, 1, /* 2737: pointer.struct.stack_st_DIST_POINT */
            	2742, 0,
            0, 32, 2, /* 2742: struct.stack_st_fake_DIST_POINT */
            	2749, 8,
            	153, 24,
            8884099, 8, 2, /* 2749: pointer_to_array_of_pointers_to_stack */
            	2756, 0,
            	150, 20,
            0, 8, 1, /* 2756: pointer.DIST_POINT */
            	1089, 0,
            1, 8, 1, /* 2761: pointer.struct.X509_POLICY_CACHE_st */
            	2766, 0,
            0, 0, 0, /* 2766: struct.X509_POLICY_CACHE_st */
            0, 0, 0, /* 2769: struct.AUTHORITY_KEYID_st */
            0, 0, 0, /* 2772: struct.ec_key_st */
            1, 8, 1, /* 2775: pointer.struct.AUTHORITY_KEYID_st */
            	2769, 0,
            1, 8, 1, /* 2780: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	2785, 0,
            0, 32, 2, /* 2785: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	2792, 8,
            	153, 24,
            8884099, 8, 2, /* 2792: pointer_to_array_of_pointers_to_stack */
            	2799, 0,
            	150, 20,
            0, 8, 1, /* 2799: pointer.SRTP_PROTECTION_PROFILE */
            	3, 0,
            8884097, 8, 0, /* 2804: pointer.func */
            8884097, 8, 0, /* 2807: pointer.func */
            8884097, 8, 0, /* 2810: pointer.func */
            8884097, 8, 0, /* 2813: pointer.func */
            0, 104, 11, /* 2816: struct.x509_cinf_st */
            	2841, 0,
            	2841, 8,
            	2851, 16,
            	3008, 24,
            	3056, 32,
            	3008, 40,
            	3073, 48,
            	2940, 56,
            	2940, 64,
            	3461, 72,
            	3485, 80,
            1, 8, 1, /* 2841: pointer.struct.asn1_string_st */
            	2846, 0,
            0, 24, 1, /* 2846: struct.asn1_string_st */
            	145, 8,
            1, 8, 1, /* 2851: pointer.struct.X509_algor_st */
            	2856, 0,
            0, 16, 2, /* 2856: struct.X509_algor_st */
            	2863, 0,
            	2877, 8,
            1, 8, 1, /* 2863: pointer.struct.asn1_object_st */
            	2868, 0,
            0, 40, 3, /* 2868: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	127, 24,
            1, 8, 1, /* 2877: pointer.struct.asn1_type_st */
            	2882, 0,
            0, 16, 1, /* 2882: struct.asn1_type_st */
            	2887, 8,
            0, 8, 20, /* 2887: union.unknown */
            	72, 0,
            	2930, 0,
            	2863, 0,
            	2841, 0,
            	2935, 0,
            	2940, 0,
            	2945, 0,
            	2950, 0,
            	2955, 0,
            	2960, 0,
            	2965, 0,
            	2970, 0,
            	2975, 0,
            	2980, 0,
            	2985, 0,
            	2990, 0,
            	2995, 0,
            	2930, 0,
            	2930, 0,
            	3000, 0,
            1, 8, 1, /* 2930: pointer.struct.asn1_string_st */
            	2846, 0,
            1, 8, 1, /* 2935: pointer.struct.asn1_string_st */
            	2846, 0,
            1, 8, 1, /* 2940: pointer.struct.asn1_string_st */
            	2846, 0,
            1, 8, 1, /* 2945: pointer.struct.asn1_string_st */
            	2846, 0,
            1, 8, 1, /* 2950: pointer.struct.asn1_string_st */
            	2846, 0,
            1, 8, 1, /* 2955: pointer.struct.asn1_string_st */
            	2846, 0,
            1, 8, 1, /* 2960: pointer.struct.asn1_string_st */
            	2846, 0,
            1, 8, 1, /* 2965: pointer.struct.asn1_string_st */
            	2846, 0,
            1, 8, 1, /* 2970: pointer.struct.asn1_string_st */
            	2846, 0,
            1, 8, 1, /* 2975: pointer.struct.asn1_string_st */
            	2846, 0,
            1, 8, 1, /* 2980: pointer.struct.asn1_string_st */
            	2846, 0,
            1, 8, 1, /* 2985: pointer.struct.asn1_string_st */
            	2846, 0,
            1, 8, 1, /* 2990: pointer.struct.asn1_string_st */
            	2846, 0,
            1, 8, 1, /* 2995: pointer.struct.asn1_string_st */
            	2846, 0,
            1, 8, 1, /* 3000: pointer.struct.ASN1_VALUE_st */
            	3005, 0,
            0, 0, 0, /* 3005: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3008: pointer.struct.X509_name_st */
            	3013, 0,
            0, 40, 3, /* 3013: struct.X509_name_st */
            	3022, 0,
            	3046, 16,
            	145, 24,
            1, 8, 1, /* 3022: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3027, 0,
            0, 32, 2, /* 3027: struct.stack_st_fake_X509_NAME_ENTRY */
            	3034, 8,
            	153, 24,
            8884099, 8, 2, /* 3034: pointer_to_array_of_pointers_to_stack */
            	3041, 0,
            	150, 20,
            0, 8, 1, /* 3041: pointer.X509_NAME_ENTRY */
            	101, 0,
            1, 8, 1, /* 3046: pointer.struct.buf_mem_st */
            	3051, 0,
            0, 24, 1, /* 3051: struct.buf_mem_st */
            	72, 8,
            1, 8, 1, /* 3056: pointer.struct.X509_val_st */
            	3061, 0,
            0, 16, 2, /* 3061: struct.X509_val_st */
            	3068, 0,
            	3068, 8,
            1, 8, 1, /* 3068: pointer.struct.asn1_string_st */
            	2846, 0,
            1, 8, 1, /* 3073: pointer.struct.X509_pubkey_st */
            	3078, 0,
            0, 24, 3, /* 3078: struct.X509_pubkey_st */
            	2851, 0,
            	2940, 8,
            	3087, 16,
            1, 8, 1, /* 3087: pointer.struct.evp_pkey_st */
            	3092, 0,
            0, 56, 4, /* 3092: struct.evp_pkey_st */
            	3103, 16,
            	3111, 24,
            	3119, 32,
            	3437, 48,
            1, 8, 1, /* 3103: pointer.struct.evp_pkey_asn1_method_st */
            	3108, 0,
            0, 0, 0, /* 3108: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 3111: pointer.struct.engine_st */
            	3116, 0,
            0, 0, 0, /* 3116: struct.engine_st */
            0, 8, 5, /* 3119: union.unknown */
            	72, 0,
            	3132, 0,
            	3283, 0,
            	3361, 0,
            	3429, 0,
            1, 8, 1, /* 3132: pointer.struct.rsa_st */
            	3137, 0,
            0, 168, 17, /* 3137: struct.rsa_st */
            	3174, 16,
            	3111, 24,
            	3229, 32,
            	3229, 40,
            	3229, 48,
            	3229, 56,
            	3229, 64,
            	3229, 72,
            	3229, 80,
            	3229, 88,
            	3239, 96,
            	3261, 120,
            	3261, 128,
            	3261, 136,
            	72, 144,
            	3275, 152,
            	3275, 160,
            1, 8, 1, /* 3174: pointer.struct.rsa_meth_st */
            	3179, 0,
            0, 112, 13, /* 3179: struct.rsa_meth_st */
            	13, 0,
            	3208, 8,
            	3208, 16,
            	3208, 24,
            	3208, 32,
            	3211, 40,
            	3214, 48,
            	3217, 56,
            	3217, 64,
            	72, 80,
            	3220, 88,
            	3223, 96,
            	3226, 104,
            8884097, 8, 0, /* 3208: pointer.func */
            8884097, 8, 0, /* 3211: pointer.func */
            8884097, 8, 0, /* 3214: pointer.func */
            8884097, 8, 0, /* 3217: pointer.func */
            8884097, 8, 0, /* 3220: pointer.func */
            8884097, 8, 0, /* 3223: pointer.func */
            8884097, 8, 0, /* 3226: pointer.func */
            1, 8, 1, /* 3229: pointer.struct.bignum_st */
            	3234, 0,
            0, 24, 1, /* 3234: struct.bignum_st */
            	256, 0,
            0, 16, 1, /* 3239: struct.crypto_ex_data_st */
            	3244, 0,
            1, 8, 1, /* 3244: pointer.struct.stack_st_void */
            	3249, 0,
            0, 32, 1, /* 3249: struct.stack_st_void */
            	3254, 0,
            0, 32, 2, /* 3254: struct.stack_st */
            	420, 8,
            	153, 24,
            1, 8, 1, /* 3261: pointer.struct.bn_mont_ctx_st */
            	3266, 0,
            0, 96, 3, /* 3266: struct.bn_mont_ctx_st */
            	3234, 8,
            	3234, 32,
            	3234, 56,
            1, 8, 1, /* 3275: pointer.struct.bn_blinding_st */
            	3280, 0,
            0, 0, 0, /* 3280: struct.bn_blinding_st */
            1, 8, 1, /* 3283: pointer.struct.dsa_st */
            	3288, 0,
            0, 136, 11, /* 3288: struct.dsa_st */
            	3229, 24,
            	3229, 32,
            	3229, 40,
            	3229, 48,
            	3229, 56,
            	3229, 64,
            	3229, 72,
            	3261, 88,
            	3239, 104,
            	3313, 120,
            	3111, 128,
            1, 8, 1, /* 3313: pointer.struct.dsa_method */
            	3318, 0,
            0, 96, 11, /* 3318: struct.dsa_method */
            	13, 0,
            	3343, 8,
            	3346, 16,
            	3349, 24,
            	2810, 32,
            	3352, 40,
            	3355, 48,
            	3355, 56,
            	72, 72,
            	3358, 80,
            	3355, 88,
            8884097, 8, 0, /* 3343: pointer.func */
            8884097, 8, 0, /* 3346: pointer.func */
            8884097, 8, 0, /* 3349: pointer.func */
            8884097, 8, 0, /* 3352: pointer.func */
            8884097, 8, 0, /* 3355: pointer.func */
            8884097, 8, 0, /* 3358: pointer.func */
            1, 8, 1, /* 3361: pointer.struct.dh_st */
            	3366, 0,
            0, 144, 12, /* 3366: struct.dh_st */
            	3229, 8,
            	3229, 16,
            	3229, 32,
            	3229, 40,
            	3261, 56,
            	3229, 64,
            	3229, 72,
            	145, 80,
            	3229, 96,
            	3239, 112,
            	3393, 128,
            	3111, 136,
            1, 8, 1, /* 3393: pointer.struct.dh_method */
            	3398, 0,
            0, 72, 8, /* 3398: struct.dh_method */
            	13, 0,
            	3417, 8,
            	3420, 16,
            	3423, 24,
            	3417, 32,
            	3417, 40,
            	72, 56,
            	3426, 64,
            8884097, 8, 0, /* 3417: pointer.func */
            8884097, 8, 0, /* 3420: pointer.func */
            8884097, 8, 0, /* 3423: pointer.func */
            8884097, 8, 0, /* 3426: pointer.func */
            1, 8, 1, /* 3429: pointer.struct.ec_key_st */
            	3434, 0,
            0, 0, 0, /* 3434: struct.ec_key_st */
            1, 8, 1, /* 3437: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3442, 0,
            0, 32, 2, /* 3442: struct.stack_st_fake_X509_ATTRIBUTE */
            	3449, 8,
            	153, 24,
            8884099, 8, 2, /* 3449: pointer_to_array_of_pointers_to_stack */
            	3456, 0,
            	150, 20,
            0, 8, 1, /* 3456: pointer.X509_ATTRIBUTE */
            	2372, 0,
            1, 8, 1, /* 3461: pointer.struct.stack_st_X509_EXTENSION */
            	3466, 0,
            0, 32, 2, /* 3466: struct.stack_st_fake_X509_EXTENSION */
            	3473, 8,
            	153, 24,
            8884099, 8, 2, /* 3473: pointer_to_array_of_pointers_to_stack */
            	3480, 0,
            	150, 20,
            0, 8, 1, /* 3480: pointer.X509_EXTENSION */
            	1249, 0,
            0, 24, 1, /* 3485: struct.ASN1_ENCODING_st */
            	145, 0,
            0, 0, 0, /* 3490: struct.X509_POLICY_CACHE_st */
            8884097, 8, 0, /* 3493: pointer.func */
            0, 184, 12, /* 3496: struct.x509_st */
            	3523, 0,
            	1468, 8,
            	1557, 16,
            	72, 32,
            	1296, 40,
            	1562, 104,
            	2775, 112,
            	2761, 120,
            	2737, 128,
            	3823, 136,
            	3847, 144,
            	3855, 176,
            1, 8, 1, /* 3523: pointer.struct.x509_cinf_st */
            	3528, 0,
            0, 104, 11, /* 3528: struct.x509_cinf_st */
            	1458, 0,
            	1458, 8,
            	1468, 16,
            	1617, 24,
            	3553, 32,
            	1617, 40,
            	3565, 48,
            	1557, 56,
            	1557, 64,
            	1773, 72,
            	1797, 80,
            1, 8, 1, /* 3553: pointer.struct.X509_val_st */
            	3558, 0,
            0, 16, 2, /* 3558: struct.X509_val_st */
            	1665, 0,
            	1665, 8,
            1, 8, 1, /* 3565: pointer.struct.X509_pubkey_st */
            	3570, 0,
            0, 24, 3, /* 3570: struct.X509_pubkey_st */
            	1468, 0,
            	1557, 8,
            	3579, 16,
            1, 8, 1, /* 3579: pointer.struct.evp_pkey_st */
            	3584, 0,
            0, 56, 4, /* 3584: struct.evp_pkey_st */
            	3595, 16,
            	1426, 24,
            	3603, 32,
            	3799, 48,
            1, 8, 1, /* 3595: pointer.struct.evp_pkey_asn1_method_st */
            	3600, 0,
            0, 0, 0, /* 3600: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 3603: union.unknown */
            	72, 0,
            	3616, 0,
            	3721, 0,
            	3726, 0,
            	3794, 0,
            1, 8, 1, /* 3616: pointer.struct.rsa_st */
            	3621, 0,
            0, 168, 17, /* 3621: struct.rsa_st */
            	3658, 16,
            	1426, 24,
            	1351, 32,
            	1351, 40,
            	1351, 48,
            	1351, 56,
            	1351, 64,
            	1351, 72,
            	1351, 80,
            	1351, 88,
            	1296, 96,
            	1361, 120,
            	1361, 128,
            	1361, 136,
            	72, 144,
            	3713, 152,
            	3713, 160,
            1, 8, 1, /* 3658: pointer.struct.rsa_meth_st */
            	3663, 0,
            0, 112, 13, /* 3663: struct.rsa_meth_st */
            	13, 0,
            	3692, 8,
            	3692, 16,
            	3692, 24,
            	3692, 32,
            	3695, 40,
            	3698, 48,
            	3701, 56,
            	3701, 64,
            	72, 80,
            	3704, 88,
            	3707, 96,
            	3710, 104,
            8884097, 8, 0, /* 3692: pointer.func */
            8884097, 8, 0, /* 3695: pointer.func */
            8884097, 8, 0, /* 3698: pointer.func */
            8884097, 8, 0, /* 3701: pointer.func */
            8884097, 8, 0, /* 3704: pointer.func */
            8884097, 8, 0, /* 3707: pointer.func */
            8884097, 8, 0, /* 3710: pointer.func */
            1, 8, 1, /* 3713: pointer.struct.bn_blinding_st */
            	3718, 0,
            0, 0, 0, /* 3718: struct.bn_blinding_st */
            1, 8, 1, /* 3721: pointer.struct.dsa_st */
            	1326, 0,
            1, 8, 1, /* 3726: pointer.struct.dh_st */
            	3731, 0,
            0, 144, 12, /* 3731: struct.dh_st */
            	1351, 8,
            	1351, 16,
            	1351, 32,
            	1351, 40,
            	1361, 56,
            	1351, 64,
            	1351, 72,
            	145, 80,
            	1351, 96,
            	1296, 112,
            	3758, 128,
            	1426, 136,
            1, 8, 1, /* 3758: pointer.struct.dh_method */
            	3763, 0,
            0, 72, 8, /* 3763: struct.dh_method */
            	13, 0,
            	3782, 8,
            	3785, 16,
            	3788, 24,
            	3782, 32,
            	3782, 40,
            	72, 56,
            	3791, 64,
            8884097, 8, 0, /* 3782: pointer.func */
            8884097, 8, 0, /* 3785: pointer.func */
            8884097, 8, 0, /* 3788: pointer.func */
            8884097, 8, 0, /* 3791: pointer.func */
            1, 8, 1, /* 3794: pointer.struct.ec_key_st */
            	2772, 0,
            1, 8, 1, /* 3799: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3804, 0,
            0, 32, 2, /* 3804: struct.stack_st_fake_X509_ATTRIBUTE */
            	3811, 8,
            	153, 24,
            8884099, 8, 2, /* 3811: pointer_to_array_of_pointers_to_stack */
            	3818, 0,
            	150, 20,
            0, 8, 1, /* 3818: pointer.X509_ATTRIBUTE */
            	2372, 0,
            1, 8, 1, /* 3823: pointer.struct.stack_st_GENERAL_NAME */
            	3828, 0,
            0, 32, 2, /* 3828: struct.stack_st_fake_GENERAL_NAME */
            	3835, 8,
            	153, 24,
            8884099, 8, 2, /* 3835: pointer_to_array_of_pointers_to_stack */
            	3842, 0,
            	150, 20,
            0, 8, 1, /* 3842: pointer.GENERAL_NAME */
            	795, 0,
            1, 8, 1, /* 3847: pointer.struct.NAME_CONSTRAINTS_st */
            	3852, 0,
            0, 0, 0, /* 3852: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3855: pointer.struct.x509_cert_aux_st */
            	3860, 0,
            0, 40, 5, /* 3860: struct.x509_cert_aux_st */
            	3873, 0,
            	3873, 8,
            	1612, 16,
            	1562, 24,
            	3897, 32,
            1, 8, 1, /* 3873: pointer.struct.stack_st_ASN1_OBJECT */
            	3878, 0,
            0, 32, 2, /* 3878: struct.stack_st_fake_ASN1_OBJECT */
            	3885, 8,
            	153, 24,
            8884099, 8, 2, /* 3885: pointer_to_array_of_pointers_to_stack */
            	3892, 0,
            	150, 20,
            0, 8, 1, /* 3892: pointer.ASN1_OBJECT */
            	551, 0,
            1, 8, 1, /* 3897: pointer.struct.stack_st_X509_ALGOR */
            	3902, 0,
            0, 32, 2, /* 3902: struct.stack_st_fake_X509_ALGOR */
            	3909, 8,
            	153, 24,
            8884099, 8, 2, /* 3909: pointer_to_array_of_pointers_to_stack */
            	3916, 0,
            	150, 20,
            0, 8, 1, /* 3916: pointer.X509_ALGOR */
            	604, 0,
            0, 184, 12, /* 3921: struct.x509_st */
            	3948, 0,
            	2851, 8,
            	2940, 16,
            	72, 32,
            	3239, 40,
            	2945, 104,
            	3953, 112,
            	3961, 120,
            	3966, 128,
            	3990, 136,
            	4014, 144,
            	4022, 176,
            1, 8, 1, /* 3948: pointer.struct.x509_cinf_st */
            	2816, 0,
            1, 8, 1, /* 3953: pointer.struct.AUTHORITY_KEYID_st */
            	3958, 0,
            0, 0, 0, /* 3958: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 3961: pointer.struct.X509_POLICY_CACHE_st */
            	3490, 0,
            1, 8, 1, /* 3966: pointer.struct.stack_st_DIST_POINT */
            	3971, 0,
            0, 32, 2, /* 3971: struct.stack_st_fake_DIST_POINT */
            	3978, 8,
            	153, 24,
            8884099, 8, 2, /* 3978: pointer_to_array_of_pointers_to_stack */
            	3985, 0,
            	150, 20,
            0, 8, 1, /* 3985: pointer.DIST_POINT */
            	1089, 0,
            1, 8, 1, /* 3990: pointer.struct.stack_st_GENERAL_NAME */
            	3995, 0,
            0, 32, 2, /* 3995: struct.stack_st_fake_GENERAL_NAME */
            	4002, 8,
            	153, 24,
            8884099, 8, 2, /* 4002: pointer_to_array_of_pointers_to_stack */
            	4009, 0,
            	150, 20,
            0, 8, 1, /* 4009: pointer.GENERAL_NAME */
            	795, 0,
            1, 8, 1, /* 4014: pointer.struct.NAME_CONSTRAINTS_st */
            	4019, 0,
            0, 0, 0, /* 4019: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4022: pointer.struct.x509_cert_aux_st */
            	4027, 0,
            0, 40, 5, /* 4027: struct.x509_cert_aux_st */
            	4040, 0,
            	4040, 8,
            	2995, 16,
            	2945, 24,
            	4064, 32,
            1, 8, 1, /* 4040: pointer.struct.stack_st_ASN1_OBJECT */
            	4045, 0,
            0, 32, 2, /* 4045: struct.stack_st_fake_ASN1_OBJECT */
            	4052, 8,
            	153, 24,
            8884099, 8, 2, /* 4052: pointer_to_array_of_pointers_to_stack */
            	4059, 0,
            	150, 20,
            0, 8, 1, /* 4059: pointer.ASN1_OBJECT */
            	551, 0,
            1, 8, 1, /* 4064: pointer.struct.stack_st_X509_ALGOR */
            	4069, 0,
            0, 32, 2, /* 4069: struct.stack_st_fake_X509_ALGOR */
            	4076, 8,
            	153, 24,
            8884099, 8, 2, /* 4076: pointer_to_array_of_pointers_to_stack */
            	4083, 0,
            	150, 20,
            0, 8, 1, /* 4083: pointer.X509_ALGOR */
            	604, 0,
            8884097, 8, 0, /* 4088: pointer.func */
            8884097, 8, 0, /* 4091: pointer.func */
            0, 32, 1, /* 4094: struct.stack_st_GENERAL_NAME */
            	4099, 0,
            0, 32, 2, /* 4099: struct.stack_st */
            	420, 8,
            	153, 24,
            1, 8, 1, /* 4106: pointer.struct.x509_st */
            	3496, 0,
            0, 0, 1, /* 4111: SSL_CIPHER */
            	4116, 0,
            0, 88, 1, /* 4116: struct.ssl_cipher_st */
            	13, 8,
            8884097, 8, 0, /* 4121: pointer.func */
            8884097, 8, 0, /* 4124: pointer.func */
            0, 144, 15, /* 4127: struct.x509_store_st */
            	4160, 8,
            	4278, 16,
            	4481, 24,
            	4493, 32,
            	4496, 40,
            	4499, 48,
            	4502, 56,
            	4493, 64,
            	4505, 72,
            	4508, 80,
            	4511, 88,
            	2813, 96,
            	4514, 104,
            	4493, 112,
            	398, 120,
            1, 8, 1, /* 4160: pointer.struct.stack_st_X509_OBJECT */
            	4165, 0,
            0, 32, 2, /* 4165: struct.stack_st_fake_X509_OBJECT */
            	4172, 8,
            	153, 24,
            8884099, 8, 2, /* 4172: pointer_to_array_of_pointers_to_stack */
            	4179, 0,
            	150, 20,
            0, 8, 1, /* 4179: pointer.X509_OBJECT */
            	4184, 0,
            0, 0, 1, /* 4184: X509_OBJECT */
            	4189, 0,
            0, 16, 1, /* 4189: struct.x509_object_st */
            	4194, 8,
            0, 8, 4, /* 4194: union.unknown */
            	72, 0,
            	4106, 0,
            	4205, 0,
            	3579, 0,
            1, 8, 1, /* 4205: pointer.struct.X509_crl_st */
            	4210, 0,
            0, 120, 10, /* 4210: struct.X509_crl_st */
            	1434, 0,
            	1468, 8,
            	1557, 16,
            	2775, 32,
            	4233, 40,
            	1458, 56,
            	1458, 64,
            	4241, 96,
            	4270, 104,
            	237, 112,
            1, 8, 1, /* 4233: pointer.struct.ISSUING_DIST_POINT_st */
            	4238, 0,
            0, 0, 0, /* 4238: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 4241: pointer.struct.stack_st_GENERAL_NAMES */
            	4246, 0,
            0, 32, 2, /* 4246: struct.stack_st_fake_GENERAL_NAMES */
            	4253, 8,
            	153, 24,
            8884099, 8, 2, /* 4253: pointer_to_array_of_pointers_to_stack */
            	4260, 0,
            	150, 20,
            0, 8, 1, /* 4260: pointer.GENERAL_NAMES */
            	4265, 0,
            0, 0, 1, /* 4265: GENERAL_NAMES */
            	4094, 0,
            1, 8, 1, /* 4270: pointer.struct.x509_crl_method_st */
            	4275, 0,
            0, 0, 0, /* 4275: struct.x509_crl_method_st */
            1, 8, 1, /* 4278: pointer.struct.stack_st_X509_LOOKUP */
            	4283, 0,
            0, 32, 2, /* 4283: struct.stack_st_fake_X509_LOOKUP */
            	4290, 8,
            	153, 24,
            8884099, 8, 2, /* 4290: pointer_to_array_of_pointers_to_stack */
            	4297, 0,
            	150, 20,
            0, 8, 1, /* 4297: pointer.X509_LOOKUP */
            	4302, 0,
            0, 0, 1, /* 4302: X509_LOOKUP */
            	4307, 0,
            0, 32, 3, /* 4307: struct.x509_lookup_st */
            	4316, 8,
            	72, 16,
            	4359, 24,
            1, 8, 1, /* 4316: pointer.struct.x509_lookup_method_st */
            	4321, 0,
            0, 80, 10, /* 4321: struct.x509_lookup_method_st */
            	13, 0,
            	4344, 8,
            	2804, 16,
            	4344, 24,
            	4344, 32,
            	4347, 40,
            	4350, 48,
            	4121, 56,
            	4353, 64,
            	4356, 72,
            8884097, 8, 0, /* 4344: pointer.func */
            8884097, 8, 0, /* 4347: pointer.func */
            8884097, 8, 0, /* 4350: pointer.func */
            8884097, 8, 0, /* 4353: pointer.func */
            8884097, 8, 0, /* 4356: pointer.func */
            1, 8, 1, /* 4359: pointer.struct.x509_store_st */
            	4364, 0,
            0, 144, 15, /* 4364: struct.x509_store_st */
            	4397, 8,
            	4421, 16,
            	4445, 24,
            	4457, 32,
            	4460, 40,
            	4463, 48,
            	4466, 56,
            	4457, 64,
            	4469, 72,
            	4472, 80,
            	4475, 88,
            	4478, 96,
            	4124, 104,
            	4457, 112,
            	1296, 120,
            1, 8, 1, /* 4397: pointer.struct.stack_st_X509_OBJECT */
            	4402, 0,
            0, 32, 2, /* 4402: struct.stack_st_fake_X509_OBJECT */
            	4409, 8,
            	153, 24,
            8884099, 8, 2, /* 4409: pointer_to_array_of_pointers_to_stack */
            	4416, 0,
            	150, 20,
            0, 8, 1, /* 4416: pointer.X509_OBJECT */
            	4184, 0,
            1, 8, 1, /* 4421: pointer.struct.stack_st_X509_LOOKUP */
            	4426, 0,
            0, 32, 2, /* 4426: struct.stack_st_fake_X509_LOOKUP */
            	4433, 8,
            	153, 24,
            8884099, 8, 2, /* 4433: pointer_to_array_of_pointers_to_stack */
            	4440, 0,
            	150, 20,
            0, 8, 1, /* 4440: pointer.X509_LOOKUP */
            	4302, 0,
            1, 8, 1, /* 4445: pointer.struct.X509_VERIFY_PARAM_st */
            	4450, 0,
            0, 56, 2, /* 4450: struct.X509_VERIFY_PARAM_st */
            	72, 0,
            	3873, 48,
            8884097, 8, 0, /* 4457: pointer.func */
            8884097, 8, 0, /* 4460: pointer.func */
            8884097, 8, 0, /* 4463: pointer.func */
            8884097, 8, 0, /* 4466: pointer.func */
            8884097, 8, 0, /* 4469: pointer.func */
            8884097, 8, 0, /* 4472: pointer.func */
            8884097, 8, 0, /* 4475: pointer.func */
            8884097, 8, 0, /* 4478: pointer.func */
            1, 8, 1, /* 4481: pointer.struct.X509_VERIFY_PARAM_st */
            	4486, 0,
            0, 56, 2, /* 4486: struct.X509_VERIFY_PARAM_st */
            	72, 0,
            	527, 48,
            8884097, 8, 0, /* 4493: pointer.func */
            8884097, 8, 0, /* 4496: pointer.func */
            8884097, 8, 0, /* 4499: pointer.func */
            8884097, 8, 0, /* 4502: pointer.func */
            8884097, 8, 0, /* 4505: pointer.func */
            8884097, 8, 0, /* 4508: pointer.func */
            8884097, 8, 0, /* 4511: pointer.func */
            8884097, 8, 0, /* 4514: pointer.func */
            8884097, 8, 0, /* 4517: pointer.func */
            8884097, 8, 0, /* 4520: pointer.func */
            8884097, 8, 0, /* 4523: pointer.func */
            0, 112, 11, /* 4526: struct.ssl3_enc_method */
            	3493, 0,
            	4520, 8,
            	4551, 16,
            	4554, 24,
            	3493, 32,
            	4557, 40,
            	4560, 56,
            	13, 64,
            	13, 80,
            	4563, 96,
            	4566, 104,
            8884097, 8, 0, /* 4551: pointer.func */
            8884097, 8, 0, /* 4554: pointer.func */
            8884097, 8, 0, /* 4557: pointer.func */
            8884097, 8, 0, /* 4560: pointer.func */
            8884097, 8, 0, /* 4563: pointer.func */
            8884097, 8, 0, /* 4566: pointer.func */
            8884097, 8, 0, /* 4569: pointer.func */
            8884097, 8, 0, /* 4572: pointer.func */
            8884097, 8, 0, /* 4575: pointer.func */
            0, 736, 50, /* 4578: struct.ssl_ctx_st */
            	4681, 0,
            	4783, 8,
            	4783, 16,
            	4807, 24,
            	4812, 32,
            	4851, 48,
            	4851, 56,
            	331, 80,
            	4088, 88,
            	4934, 96,
            	1318, 152,
            	237, 160,
            	4937, 168,
            	237, 176,
            	328, 184,
            	4940, 192,
            	325, 200,
            	398, 208,
            	2727, 224,
            	2727, 232,
            	2727, 240,
            	4905, 248,
            	301, 256,
            	194, 264,
            	156, 272,
            	1802, 304,
            	4091, 320,
            	237, 328,
            	4496, 376,
            	4943, 384,
            	4481, 392,
            	461, 408,
            	50, 416,
            	237, 424,
            	4523, 480,
            	240, 488,
            	237, 496,
            	47, 504,
            	237, 512,
            	72, 520,
            	44, 528,
            	4946, 536,
            	34, 552,
            	34, 560,
            	206, 568,
            	21, 696,
            	237, 704,
            	18, 712,
            	237, 720,
            	2780, 728,
            1, 8, 1, /* 4681: pointer.struct.ssl_method_st */
            	4686, 0,
            0, 232, 28, /* 4686: struct.ssl_method_st */
            	4551, 8,
            	4745, 16,
            	4745, 24,
            	4551, 32,
            	4551, 40,
            	4748, 48,
            	4748, 56,
            	4751, 64,
            	4551, 72,
            	4551, 80,
            	4551, 88,
            	2807, 96,
            	4575, 104,
            	4569, 112,
            	4551, 120,
            	4754, 128,
            	4757, 136,
            	4760, 144,
            	4517, 152,
            	4763, 160,
            	4766, 168,
            	4769, 176,
            	4572, 184,
            	281, 192,
            	4772, 200,
            	4766, 208,
            	4777, 216,
            	4780, 224,
            8884097, 8, 0, /* 4745: pointer.func */
            8884097, 8, 0, /* 4748: pointer.func */
            8884097, 8, 0, /* 4751: pointer.func */
            8884097, 8, 0, /* 4754: pointer.func */
            8884097, 8, 0, /* 4757: pointer.func */
            8884097, 8, 0, /* 4760: pointer.func */
            8884097, 8, 0, /* 4763: pointer.func */
            8884097, 8, 0, /* 4766: pointer.func */
            8884097, 8, 0, /* 4769: pointer.func */
            1, 8, 1, /* 4772: pointer.struct.ssl3_enc_method */
            	4526, 0,
            8884097, 8, 0, /* 4777: pointer.func */
            8884097, 8, 0, /* 4780: pointer.func */
            1, 8, 1, /* 4783: pointer.struct.stack_st_SSL_CIPHER */
            	4788, 0,
            0, 32, 2, /* 4788: struct.stack_st_fake_SSL_CIPHER */
            	4795, 8,
            	153, 24,
            8884099, 8, 2, /* 4795: pointer_to_array_of_pointers_to_stack */
            	4802, 0,
            	150, 20,
            0, 8, 1, /* 4802: pointer.SSL_CIPHER */
            	4111, 0,
            1, 8, 1, /* 4807: pointer.struct.x509_store_st */
            	4127, 0,
            1, 8, 1, /* 4812: pointer.struct.lhash_st */
            	4817, 0,
            0, 176, 3, /* 4817: struct.lhash_st */
            	4826, 0,
            	153, 8,
            	4848, 16,
            1, 8, 1, /* 4826: pointer.pointer.struct.lhash_node_st */
            	4831, 0,
            1, 8, 1, /* 4831: pointer.struct.lhash_node_st */
            	4836, 0,
            0, 24, 2, /* 4836: struct.lhash_node_st */
            	237, 0,
            	4843, 8,
            1, 8, 1, /* 4843: pointer.struct.lhash_node_st */
            	4836, 0,
            8884097, 8, 0, /* 4848: pointer.func */
            1, 8, 1, /* 4851: pointer.struct.ssl_session_st */
            	4856, 0,
            0, 352, 14, /* 4856: struct.ssl_session_st */
            	72, 144,
            	72, 152,
            	4887, 168,
            	1838, 176,
            	339, 224,
            	4783, 240,
            	398, 248,
            	4851, 264,
            	4851, 272,
            	72, 280,
            	145, 296,
            	145, 312,
            	145, 320,
            	72, 344,
            1, 8, 1, /* 4887: pointer.struct.sess_cert_st */
            	4892, 0,
            0, 248, 5, /* 4892: struct.sess_cert_st */
            	4905, 0,
            	1824, 16,
            	2732, 216,
            	352, 224,
            	344, 232,
            1, 8, 1, /* 4905: pointer.struct.stack_st_X509 */
            	4910, 0,
            0, 32, 2, /* 4910: struct.stack_st_fake_X509 */
            	4917, 8,
            	153, 24,
            8884099, 8, 2, /* 4917: pointer_to_array_of_pointers_to_stack */
            	4924, 0,
            	150, 20,
            0, 8, 1, /* 4924: pointer.X509 */
            	4929, 0,
            0, 0, 1, /* 4929: X509 */
            	3921, 0,
            8884097, 8, 0, /* 4934: pointer.func */
            8884097, 8, 0, /* 4937: pointer.func */
            8884097, 8, 0, /* 4940: pointer.func */
            8884097, 8, 0, /* 4943: pointer.func */
            8884097, 8, 0, /* 4946: pointer.func */
            1, 8, 1, /* 4949: pointer.struct.ssl_ctx_st */
            	4578, 0,
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

