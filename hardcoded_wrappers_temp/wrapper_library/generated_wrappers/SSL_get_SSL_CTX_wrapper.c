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

SSL_CTX * bb_SSL_get_SSL_CTX(const SSL * arg_a);

SSL_CTX * SSL_get_SSL_CTX(const SSL * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_get_SSL_CTX called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_get_SSL_CTX(arg_a);
    else {
        SSL_CTX * (*orig_SSL_get_SSL_CTX)(const SSL *);
        orig_SSL_get_SSL_CTX = dlsym(RTLD_NEXT, "SSL_get_SSL_CTX");
        return orig_SSL_get_SSL_CTX(arg_a);
    }
}

SSL_CTX * bb_SSL_get_SSL_CTX(const SSL * arg_a) 
{
    SSL_CTX * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 16, 1, /* 0: struct.srtp_protection_profile_st */
            	5, 0,
            1, 8, 1, /* 5: pointer.char */
            	8884096, 0,
            0, 16, 1, /* 10: struct.tls_session_ticket_ext_st */
            	15, 8,
            0, 8, 0, /* 15: pointer.void */
            0, 0, 1, /* 18: OCSP_RESPID */
            	23, 0,
            0, 16, 1, /* 23: struct.ocsp_responder_id_st */
            	28, 8,
            0, 8, 2, /* 28: union.unknown */
            	35, 0,
            	143, 0,
            1, 8, 1, /* 35: pointer.struct.X509_name_st */
            	40, 0,
            0, 40, 3, /* 40: struct.X509_name_st */
            	49, 0,
            	128, 16,
            	117, 24,
            1, 8, 1, /* 49: pointer.struct.stack_st_X509_NAME_ENTRY */
            	54, 0,
            0, 32, 2, /* 54: struct.stack_st_fake_X509_NAME_ENTRY */
            	61, 8,
            	125, 24,
            8884099, 8, 2, /* 61: pointer_to_array_of_pointers_to_stack */
            	68, 0,
            	122, 20,
            0, 8, 1, /* 68: pointer.X509_NAME_ENTRY */
            	73, 0,
            0, 0, 1, /* 73: X509_NAME_ENTRY */
            	78, 0,
            0, 24, 2, /* 78: struct.X509_name_entry_st */
            	85, 0,
            	107, 8,
            1, 8, 1, /* 85: pointer.struct.asn1_object_st */
            	90, 0,
            0, 40, 3, /* 90: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	99, 24,
            1, 8, 1, /* 99: pointer.unsigned char */
            	104, 0,
            0, 1, 0, /* 104: unsigned char */
            1, 8, 1, /* 107: pointer.struct.asn1_string_st */
            	112, 0,
            0, 24, 1, /* 112: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 117: pointer.unsigned char */
            	104, 0,
            0, 4, 0, /* 122: int */
            8884097, 8, 0, /* 125: pointer.func */
            1, 8, 1, /* 128: pointer.struct.buf_mem_st */
            	133, 0,
            0, 24, 1, /* 133: struct.buf_mem_st */
            	138, 8,
            1, 8, 1, /* 138: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 143: pointer.struct.asn1_string_st */
            	148, 0,
            0, 24, 1, /* 148: struct.asn1_string_st */
            	117, 8,
            8884097, 8, 0, /* 153: pointer.func */
            0, 24, 1, /* 156: struct.bignum_st */
            	161, 0,
            8884099, 8, 2, /* 161: pointer_to_array_of_pointers_to_stack */
            	168, 0,
            	122, 12,
            0, 4, 0, /* 168: unsigned int */
            1, 8, 1, /* 171: pointer.struct.bignum_st */
            	156, 0,
            1, 8, 1, /* 176: pointer.struct.ssl3_buf_freelist_st */
            	181, 0,
            0, 24, 1, /* 181: struct.ssl3_buf_freelist_st */
            	186, 16,
            1, 8, 1, /* 186: pointer.struct.ssl3_buf_freelist_entry_st */
            	191, 0,
            0, 8, 1, /* 191: struct.ssl3_buf_freelist_entry_st */
            	186, 0,
            8884097, 8, 0, /* 196: pointer.func */
            8884097, 8, 0, /* 199: pointer.func */
            8884097, 8, 0, /* 202: pointer.func */
            8884097, 8, 0, /* 205: pointer.func */
            8884097, 8, 0, /* 208: pointer.func */
            8884097, 8, 0, /* 211: pointer.func */
            8884097, 8, 0, /* 214: pointer.func */
            8884097, 8, 0, /* 217: pointer.func */
            1, 8, 1, /* 220: pointer.struct.stack_st_X509_OBJECT */
            	225, 0,
            0, 32, 2, /* 225: struct.stack_st_fake_X509_OBJECT */
            	232, 8,
            	125, 24,
            8884099, 8, 2, /* 232: pointer_to_array_of_pointers_to_stack */
            	239, 0,
            	122, 20,
            0, 8, 1, /* 239: pointer.X509_OBJECT */
            	244, 0,
            0, 0, 1, /* 244: X509_OBJECT */
            	249, 0,
            0, 16, 1, /* 249: struct.x509_object_st */
            	254, 8,
            0, 8, 4, /* 254: union.unknown */
            	138, 0,
            	265, 0,
            	3786, 0,
            	4120, 0,
            1, 8, 1, /* 265: pointer.struct.x509_st */
            	270, 0,
            0, 184, 12, /* 270: struct.x509_st */
            	297, 0,
            	337, 8,
            	2442, 16,
            	138, 32,
            	2512, 40,
            	2534, 104,
            	2539, 112,
            	2804, 120,
            	3235, 128,
            	3374, 136,
            	3398, 144,
            	3710, 176,
            1, 8, 1, /* 297: pointer.struct.x509_cinf_st */
            	302, 0,
            0, 104, 11, /* 302: struct.x509_cinf_st */
            	327, 0,
            	327, 8,
            	337, 16,
            	504, 24,
            	552, 32,
            	504, 40,
            	569, 48,
            	2442, 56,
            	2442, 64,
            	2447, 72,
            	2507, 80,
            1, 8, 1, /* 327: pointer.struct.asn1_string_st */
            	332, 0,
            0, 24, 1, /* 332: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 337: pointer.struct.X509_algor_st */
            	342, 0,
            0, 16, 2, /* 342: struct.X509_algor_st */
            	349, 0,
            	363, 8,
            1, 8, 1, /* 349: pointer.struct.asn1_object_st */
            	354, 0,
            0, 40, 3, /* 354: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	99, 24,
            1, 8, 1, /* 363: pointer.struct.asn1_type_st */
            	368, 0,
            0, 16, 1, /* 368: struct.asn1_type_st */
            	373, 8,
            0, 8, 20, /* 373: union.unknown */
            	138, 0,
            	416, 0,
            	349, 0,
            	426, 0,
            	431, 0,
            	436, 0,
            	441, 0,
            	446, 0,
            	451, 0,
            	456, 0,
            	461, 0,
            	466, 0,
            	471, 0,
            	476, 0,
            	481, 0,
            	486, 0,
            	491, 0,
            	416, 0,
            	416, 0,
            	496, 0,
            1, 8, 1, /* 416: pointer.struct.asn1_string_st */
            	421, 0,
            0, 24, 1, /* 421: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 426: pointer.struct.asn1_string_st */
            	421, 0,
            1, 8, 1, /* 431: pointer.struct.asn1_string_st */
            	421, 0,
            1, 8, 1, /* 436: pointer.struct.asn1_string_st */
            	421, 0,
            1, 8, 1, /* 441: pointer.struct.asn1_string_st */
            	421, 0,
            1, 8, 1, /* 446: pointer.struct.asn1_string_st */
            	421, 0,
            1, 8, 1, /* 451: pointer.struct.asn1_string_st */
            	421, 0,
            1, 8, 1, /* 456: pointer.struct.asn1_string_st */
            	421, 0,
            1, 8, 1, /* 461: pointer.struct.asn1_string_st */
            	421, 0,
            1, 8, 1, /* 466: pointer.struct.asn1_string_st */
            	421, 0,
            1, 8, 1, /* 471: pointer.struct.asn1_string_st */
            	421, 0,
            1, 8, 1, /* 476: pointer.struct.asn1_string_st */
            	421, 0,
            1, 8, 1, /* 481: pointer.struct.asn1_string_st */
            	421, 0,
            1, 8, 1, /* 486: pointer.struct.asn1_string_st */
            	421, 0,
            1, 8, 1, /* 491: pointer.struct.asn1_string_st */
            	421, 0,
            1, 8, 1, /* 496: pointer.struct.ASN1_VALUE_st */
            	501, 0,
            0, 0, 0, /* 501: struct.ASN1_VALUE_st */
            1, 8, 1, /* 504: pointer.struct.X509_name_st */
            	509, 0,
            0, 40, 3, /* 509: struct.X509_name_st */
            	518, 0,
            	542, 16,
            	117, 24,
            1, 8, 1, /* 518: pointer.struct.stack_st_X509_NAME_ENTRY */
            	523, 0,
            0, 32, 2, /* 523: struct.stack_st_fake_X509_NAME_ENTRY */
            	530, 8,
            	125, 24,
            8884099, 8, 2, /* 530: pointer_to_array_of_pointers_to_stack */
            	537, 0,
            	122, 20,
            0, 8, 1, /* 537: pointer.X509_NAME_ENTRY */
            	73, 0,
            1, 8, 1, /* 542: pointer.struct.buf_mem_st */
            	547, 0,
            0, 24, 1, /* 547: struct.buf_mem_st */
            	138, 8,
            1, 8, 1, /* 552: pointer.struct.X509_val_st */
            	557, 0,
            0, 16, 2, /* 557: struct.X509_val_st */
            	564, 0,
            	564, 8,
            1, 8, 1, /* 564: pointer.struct.asn1_string_st */
            	332, 0,
            1, 8, 1, /* 569: pointer.struct.X509_pubkey_st */
            	574, 0,
            0, 24, 3, /* 574: struct.X509_pubkey_st */
            	583, 0,
            	588, 8,
            	598, 16,
            1, 8, 1, /* 583: pointer.struct.X509_algor_st */
            	342, 0,
            1, 8, 1, /* 588: pointer.struct.asn1_string_st */
            	593, 0,
            0, 24, 1, /* 593: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 598: pointer.struct.evp_pkey_st */
            	603, 0,
            0, 56, 4, /* 603: struct.evp_pkey_st */
            	614, 16,
            	715, 24,
            	1068, 32,
            	2071, 48,
            1, 8, 1, /* 614: pointer.struct.evp_pkey_asn1_method_st */
            	619, 0,
            0, 208, 24, /* 619: struct.evp_pkey_asn1_method_st */
            	138, 16,
            	138, 24,
            	670, 32,
            	673, 40,
            	676, 48,
            	679, 56,
            	682, 64,
            	685, 72,
            	679, 80,
            	688, 88,
            	688, 96,
            	691, 104,
            	694, 112,
            	688, 120,
            	697, 128,
            	676, 136,
            	679, 144,
            	700, 152,
            	703, 160,
            	706, 168,
            	691, 176,
            	694, 184,
            	709, 192,
            	712, 200,
            8884097, 8, 0, /* 670: pointer.func */
            8884097, 8, 0, /* 673: pointer.func */
            8884097, 8, 0, /* 676: pointer.func */
            8884097, 8, 0, /* 679: pointer.func */
            8884097, 8, 0, /* 682: pointer.func */
            8884097, 8, 0, /* 685: pointer.func */
            8884097, 8, 0, /* 688: pointer.func */
            8884097, 8, 0, /* 691: pointer.func */
            8884097, 8, 0, /* 694: pointer.func */
            8884097, 8, 0, /* 697: pointer.func */
            8884097, 8, 0, /* 700: pointer.func */
            8884097, 8, 0, /* 703: pointer.func */
            8884097, 8, 0, /* 706: pointer.func */
            8884097, 8, 0, /* 709: pointer.func */
            8884097, 8, 0, /* 712: pointer.func */
            1, 8, 1, /* 715: pointer.struct.engine_st */
            	720, 0,
            0, 216, 24, /* 720: struct.engine_st */
            	5, 0,
            	5, 8,
            	771, 16,
            	826, 24,
            	877, 32,
            	913, 40,
            	930, 48,
            	957, 56,
            	992, 64,
            	1000, 72,
            	1003, 80,
            	1006, 88,
            	1009, 96,
            	1012, 104,
            	1012, 112,
            	1012, 120,
            	1015, 128,
            	1018, 136,
            	1018, 144,
            	1021, 152,
            	1024, 160,
            	1036, 184,
            	1063, 200,
            	1063, 208,
            1, 8, 1, /* 771: pointer.struct.rsa_meth_st */
            	776, 0,
            0, 112, 13, /* 776: struct.rsa_meth_st */
            	5, 0,
            	805, 8,
            	805, 16,
            	805, 24,
            	805, 32,
            	808, 40,
            	811, 48,
            	814, 56,
            	814, 64,
            	138, 80,
            	817, 88,
            	820, 96,
            	823, 104,
            8884097, 8, 0, /* 805: pointer.func */
            8884097, 8, 0, /* 808: pointer.func */
            8884097, 8, 0, /* 811: pointer.func */
            8884097, 8, 0, /* 814: pointer.func */
            8884097, 8, 0, /* 817: pointer.func */
            8884097, 8, 0, /* 820: pointer.func */
            8884097, 8, 0, /* 823: pointer.func */
            1, 8, 1, /* 826: pointer.struct.dsa_method */
            	831, 0,
            0, 96, 11, /* 831: struct.dsa_method */
            	5, 0,
            	856, 8,
            	859, 16,
            	862, 24,
            	865, 32,
            	868, 40,
            	871, 48,
            	871, 56,
            	138, 72,
            	874, 80,
            	871, 88,
            8884097, 8, 0, /* 856: pointer.func */
            8884097, 8, 0, /* 859: pointer.func */
            8884097, 8, 0, /* 862: pointer.func */
            8884097, 8, 0, /* 865: pointer.func */
            8884097, 8, 0, /* 868: pointer.func */
            8884097, 8, 0, /* 871: pointer.func */
            8884097, 8, 0, /* 874: pointer.func */
            1, 8, 1, /* 877: pointer.struct.dh_method */
            	882, 0,
            0, 72, 8, /* 882: struct.dh_method */
            	5, 0,
            	901, 8,
            	904, 16,
            	907, 24,
            	901, 32,
            	901, 40,
            	138, 56,
            	910, 64,
            8884097, 8, 0, /* 901: pointer.func */
            8884097, 8, 0, /* 904: pointer.func */
            8884097, 8, 0, /* 907: pointer.func */
            8884097, 8, 0, /* 910: pointer.func */
            1, 8, 1, /* 913: pointer.struct.ecdh_method */
            	918, 0,
            0, 32, 3, /* 918: struct.ecdh_method */
            	5, 0,
            	927, 8,
            	138, 24,
            8884097, 8, 0, /* 927: pointer.func */
            1, 8, 1, /* 930: pointer.struct.ecdsa_method */
            	935, 0,
            0, 48, 5, /* 935: struct.ecdsa_method */
            	5, 0,
            	948, 8,
            	951, 16,
            	954, 24,
            	138, 40,
            8884097, 8, 0, /* 948: pointer.func */
            8884097, 8, 0, /* 951: pointer.func */
            8884097, 8, 0, /* 954: pointer.func */
            1, 8, 1, /* 957: pointer.struct.rand_meth_st */
            	962, 0,
            0, 48, 6, /* 962: struct.rand_meth_st */
            	977, 0,
            	980, 8,
            	983, 16,
            	986, 24,
            	980, 32,
            	989, 40,
            8884097, 8, 0, /* 977: pointer.func */
            8884097, 8, 0, /* 980: pointer.func */
            8884097, 8, 0, /* 983: pointer.func */
            8884097, 8, 0, /* 986: pointer.func */
            8884097, 8, 0, /* 989: pointer.func */
            1, 8, 1, /* 992: pointer.struct.store_method_st */
            	997, 0,
            0, 0, 0, /* 997: struct.store_method_st */
            8884097, 8, 0, /* 1000: pointer.func */
            8884097, 8, 0, /* 1003: pointer.func */
            8884097, 8, 0, /* 1006: pointer.func */
            8884097, 8, 0, /* 1009: pointer.func */
            8884097, 8, 0, /* 1012: pointer.func */
            8884097, 8, 0, /* 1015: pointer.func */
            8884097, 8, 0, /* 1018: pointer.func */
            8884097, 8, 0, /* 1021: pointer.func */
            1, 8, 1, /* 1024: pointer.struct.ENGINE_CMD_DEFN_st */
            	1029, 0,
            0, 32, 2, /* 1029: struct.ENGINE_CMD_DEFN_st */
            	5, 8,
            	5, 16,
            0, 16, 1, /* 1036: struct.crypto_ex_data_st */
            	1041, 0,
            1, 8, 1, /* 1041: pointer.struct.stack_st_void */
            	1046, 0,
            0, 32, 1, /* 1046: struct.stack_st_void */
            	1051, 0,
            0, 32, 2, /* 1051: struct.stack_st */
            	1058, 8,
            	125, 24,
            1, 8, 1, /* 1058: pointer.pointer.char */
            	138, 0,
            1, 8, 1, /* 1063: pointer.struct.engine_st */
            	720, 0,
            0, 8, 5, /* 1068: union.unknown */
            	138, 0,
            	1081, 0,
            	1297, 0,
            	1436, 0,
            	1562, 0,
            1, 8, 1, /* 1081: pointer.struct.rsa_st */
            	1086, 0,
            0, 168, 17, /* 1086: struct.rsa_st */
            	1123, 16,
            	1178, 24,
            	1183, 32,
            	1183, 40,
            	1183, 48,
            	1183, 56,
            	1183, 64,
            	1183, 72,
            	1183, 80,
            	1183, 88,
            	1200, 96,
            	1222, 120,
            	1222, 128,
            	1222, 136,
            	138, 144,
            	1236, 152,
            	1236, 160,
            1, 8, 1, /* 1123: pointer.struct.rsa_meth_st */
            	1128, 0,
            0, 112, 13, /* 1128: struct.rsa_meth_st */
            	5, 0,
            	1157, 8,
            	1157, 16,
            	1157, 24,
            	1157, 32,
            	1160, 40,
            	1163, 48,
            	1166, 56,
            	1166, 64,
            	138, 80,
            	1169, 88,
            	1172, 96,
            	1175, 104,
            8884097, 8, 0, /* 1157: pointer.func */
            8884097, 8, 0, /* 1160: pointer.func */
            8884097, 8, 0, /* 1163: pointer.func */
            8884097, 8, 0, /* 1166: pointer.func */
            8884097, 8, 0, /* 1169: pointer.func */
            8884097, 8, 0, /* 1172: pointer.func */
            8884097, 8, 0, /* 1175: pointer.func */
            1, 8, 1, /* 1178: pointer.struct.engine_st */
            	720, 0,
            1, 8, 1, /* 1183: pointer.struct.bignum_st */
            	1188, 0,
            0, 24, 1, /* 1188: struct.bignum_st */
            	1193, 0,
            8884099, 8, 2, /* 1193: pointer_to_array_of_pointers_to_stack */
            	168, 0,
            	122, 12,
            0, 16, 1, /* 1200: struct.crypto_ex_data_st */
            	1205, 0,
            1, 8, 1, /* 1205: pointer.struct.stack_st_void */
            	1210, 0,
            0, 32, 1, /* 1210: struct.stack_st_void */
            	1215, 0,
            0, 32, 2, /* 1215: struct.stack_st */
            	1058, 8,
            	125, 24,
            1, 8, 1, /* 1222: pointer.struct.bn_mont_ctx_st */
            	1227, 0,
            0, 96, 3, /* 1227: struct.bn_mont_ctx_st */
            	1188, 8,
            	1188, 32,
            	1188, 56,
            1, 8, 1, /* 1236: pointer.struct.bn_blinding_st */
            	1241, 0,
            0, 88, 7, /* 1241: struct.bn_blinding_st */
            	1258, 0,
            	1258, 8,
            	1258, 16,
            	1258, 24,
            	1275, 40,
            	1280, 72,
            	1294, 80,
            1, 8, 1, /* 1258: pointer.struct.bignum_st */
            	1263, 0,
            0, 24, 1, /* 1263: struct.bignum_st */
            	1268, 0,
            8884099, 8, 2, /* 1268: pointer_to_array_of_pointers_to_stack */
            	168, 0,
            	122, 12,
            0, 16, 1, /* 1275: struct.crypto_threadid_st */
            	15, 0,
            1, 8, 1, /* 1280: pointer.struct.bn_mont_ctx_st */
            	1285, 0,
            0, 96, 3, /* 1285: struct.bn_mont_ctx_st */
            	1263, 8,
            	1263, 32,
            	1263, 56,
            8884097, 8, 0, /* 1294: pointer.func */
            1, 8, 1, /* 1297: pointer.struct.dsa_st */
            	1302, 0,
            0, 136, 11, /* 1302: struct.dsa_st */
            	1327, 24,
            	1327, 32,
            	1327, 40,
            	1327, 48,
            	1327, 56,
            	1327, 64,
            	1327, 72,
            	1344, 88,
            	1358, 104,
            	1380, 120,
            	1431, 128,
            1, 8, 1, /* 1327: pointer.struct.bignum_st */
            	1332, 0,
            0, 24, 1, /* 1332: struct.bignum_st */
            	1337, 0,
            8884099, 8, 2, /* 1337: pointer_to_array_of_pointers_to_stack */
            	168, 0,
            	122, 12,
            1, 8, 1, /* 1344: pointer.struct.bn_mont_ctx_st */
            	1349, 0,
            0, 96, 3, /* 1349: struct.bn_mont_ctx_st */
            	1332, 8,
            	1332, 32,
            	1332, 56,
            0, 16, 1, /* 1358: struct.crypto_ex_data_st */
            	1363, 0,
            1, 8, 1, /* 1363: pointer.struct.stack_st_void */
            	1368, 0,
            0, 32, 1, /* 1368: struct.stack_st_void */
            	1373, 0,
            0, 32, 2, /* 1373: struct.stack_st */
            	1058, 8,
            	125, 24,
            1, 8, 1, /* 1380: pointer.struct.dsa_method */
            	1385, 0,
            0, 96, 11, /* 1385: struct.dsa_method */
            	5, 0,
            	1410, 8,
            	1413, 16,
            	1416, 24,
            	1419, 32,
            	1422, 40,
            	1425, 48,
            	1425, 56,
            	138, 72,
            	1428, 80,
            	1425, 88,
            8884097, 8, 0, /* 1410: pointer.func */
            8884097, 8, 0, /* 1413: pointer.func */
            8884097, 8, 0, /* 1416: pointer.func */
            8884097, 8, 0, /* 1419: pointer.func */
            8884097, 8, 0, /* 1422: pointer.func */
            8884097, 8, 0, /* 1425: pointer.func */
            8884097, 8, 0, /* 1428: pointer.func */
            1, 8, 1, /* 1431: pointer.struct.engine_st */
            	720, 0,
            1, 8, 1, /* 1436: pointer.struct.dh_st */
            	1441, 0,
            0, 144, 12, /* 1441: struct.dh_st */
            	1468, 8,
            	1468, 16,
            	1468, 32,
            	1468, 40,
            	1485, 56,
            	1468, 64,
            	1468, 72,
            	117, 80,
            	1468, 96,
            	1499, 112,
            	1521, 128,
            	1557, 136,
            1, 8, 1, /* 1468: pointer.struct.bignum_st */
            	1473, 0,
            0, 24, 1, /* 1473: struct.bignum_st */
            	1478, 0,
            8884099, 8, 2, /* 1478: pointer_to_array_of_pointers_to_stack */
            	168, 0,
            	122, 12,
            1, 8, 1, /* 1485: pointer.struct.bn_mont_ctx_st */
            	1490, 0,
            0, 96, 3, /* 1490: struct.bn_mont_ctx_st */
            	1473, 8,
            	1473, 32,
            	1473, 56,
            0, 16, 1, /* 1499: struct.crypto_ex_data_st */
            	1504, 0,
            1, 8, 1, /* 1504: pointer.struct.stack_st_void */
            	1509, 0,
            0, 32, 1, /* 1509: struct.stack_st_void */
            	1514, 0,
            0, 32, 2, /* 1514: struct.stack_st */
            	1058, 8,
            	125, 24,
            1, 8, 1, /* 1521: pointer.struct.dh_method */
            	1526, 0,
            0, 72, 8, /* 1526: struct.dh_method */
            	5, 0,
            	1545, 8,
            	1548, 16,
            	1551, 24,
            	1545, 32,
            	1545, 40,
            	138, 56,
            	1554, 64,
            8884097, 8, 0, /* 1545: pointer.func */
            8884097, 8, 0, /* 1548: pointer.func */
            8884097, 8, 0, /* 1551: pointer.func */
            8884097, 8, 0, /* 1554: pointer.func */
            1, 8, 1, /* 1557: pointer.struct.engine_st */
            	720, 0,
            1, 8, 1, /* 1562: pointer.struct.ec_key_st */
            	1567, 0,
            0, 56, 4, /* 1567: struct.ec_key_st */
            	1578, 8,
            	2026, 16,
            	2031, 24,
            	2048, 48,
            1, 8, 1, /* 1578: pointer.struct.ec_group_st */
            	1583, 0,
            0, 232, 12, /* 1583: struct.ec_group_st */
            	1610, 0,
            	1782, 8,
            	1982, 16,
            	1982, 40,
            	117, 80,
            	1994, 96,
            	1982, 104,
            	1982, 152,
            	1982, 176,
            	15, 208,
            	15, 216,
            	2023, 224,
            1, 8, 1, /* 1610: pointer.struct.ec_method_st */
            	1615, 0,
            0, 304, 37, /* 1615: struct.ec_method_st */
            	1692, 8,
            	1695, 16,
            	1695, 24,
            	1698, 32,
            	1701, 40,
            	1704, 48,
            	1707, 56,
            	1710, 64,
            	1713, 72,
            	1716, 80,
            	1716, 88,
            	1719, 96,
            	1722, 104,
            	1725, 112,
            	1728, 120,
            	1731, 128,
            	1734, 136,
            	1737, 144,
            	1740, 152,
            	1743, 160,
            	1746, 168,
            	1749, 176,
            	1752, 184,
            	1755, 192,
            	1758, 200,
            	1761, 208,
            	1752, 216,
            	1764, 224,
            	1767, 232,
            	1770, 240,
            	1707, 248,
            	1773, 256,
            	1776, 264,
            	1773, 272,
            	1776, 280,
            	1776, 288,
            	1779, 296,
            8884097, 8, 0, /* 1692: pointer.func */
            8884097, 8, 0, /* 1695: pointer.func */
            8884097, 8, 0, /* 1698: pointer.func */
            8884097, 8, 0, /* 1701: pointer.func */
            8884097, 8, 0, /* 1704: pointer.func */
            8884097, 8, 0, /* 1707: pointer.func */
            8884097, 8, 0, /* 1710: pointer.func */
            8884097, 8, 0, /* 1713: pointer.func */
            8884097, 8, 0, /* 1716: pointer.func */
            8884097, 8, 0, /* 1719: pointer.func */
            8884097, 8, 0, /* 1722: pointer.func */
            8884097, 8, 0, /* 1725: pointer.func */
            8884097, 8, 0, /* 1728: pointer.func */
            8884097, 8, 0, /* 1731: pointer.func */
            8884097, 8, 0, /* 1734: pointer.func */
            8884097, 8, 0, /* 1737: pointer.func */
            8884097, 8, 0, /* 1740: pointer.func */
            8884097, 8, 0, /* 1743: pointer.func */
            8884097, 8, 0, /* 1746: pointer.func */
            8884097, 8, 0, /* 1749: pointer.func */
            8884097, 8, 0, /* 1752: pointer.func */
            8884097, 8, 0, /* 1755: pointer.func */
            8884097, 8, 0, /* 1758: pointer.func */
            8884097, 8, 0, /* 1761: pointer.func */
            8884097, 8, 0, /* 1764: pointer.func */
            8884097, 8, 0, /* 1767: pointer.func */
            8884097, 8, 0, /* 1770: pointer.func */
            8884097, 8, 0, /* 1773: pointer.func */
            8884097, 8, 0, /* 1776: pointer.func */
            8884097, 8, 0, /* 1779: pointer.func */
            1, 8, 1, /* 1782: pointer.struct.ec_point_st */
            	1787, 0,
            0, 88, 4, /* 1787: struct.ec_point_st */
            	1798, 0,
            	1970, 8,
            	1970, 32,
            	1970, 56,
            1, 8, 1, /* 1798: pointer.struct.ec_method_st */
            	1803, 0,
            0, 304, 37, /* 1803: struct.ec_method_st */
            	1880, 8,
            	1883, 16,
            	1883, 24,
            	1886, 32,
            	1889, 40,
            	1892, 48,
            	1895, 56,
            	1898, 64,
            	1901, 72,
            	1904, 80,
            	1904, 88,
            	1907, 96,
            	1910, 104,
            	1913, 112,
            	1916, 120,
            	1919, 128,
            	1922, 136,
            	1925, 144,
            	1928, 152,
            	1931, 160,
            	1934, 168,
            	1937, 176,
            	1940, 184,
            	1943, 192,
            	1946, 200,
            	1949, 208,
            	1940, 216,
            	1952, 224,
            	1955, 232,
            	1958, 240,
            	1895, 248,
            	1961, 256,
            	1964, 264,
            	1961, 272,
            	1964, 280,
            	1964, 288,
            	1967, 296,
            8884097, 8, 0, /* 1880: pointer.func */
            8884097, 8, 0, /* 1883: pointer.func */
            8884097, 8, 0, /* 1886: pointer.func */
            8884097, 8, 0, /* 1889: pointer.func */
            8884097, 8, 0, /* 1892: pointer.func */
            8884097, 8, 0, /* 1895: pointer.func */
            8884097, 8, 0, /* 1898: pointer.func */
            8884097, 8, 0, /* 1901: pointer.func */
            8884097, 8, 0, /* 1904: pointer.func */
            8884097, 8, 0, /* 1907: pointer.func */
            8884097, 8, 0, /* 1910: pointer.func */
            8884097, 8, 0, /* 1913: pointer.func */
            8884097, 8, 0, /* 1916: pointer.func */
            8884097, 8, 0, /* 1919: pointer.func */
            8884097, 8, 0, /* 1922: pointer.func */
            8884097, 8, 0, /* 1925: pointer.func */
            8884097, 8, 0, /* 1928: pointer.func */
            8884097, 8, 0, /* 1931: pointer.func */
            8884097, 8, 0, /* 1934: pointer.func */
            8884097, 8, 0, /* 1937: pointer.func */
            8884097, 8, 0, /* 1940: pointer.func */
            8884097, 8, 0, /* 1943: pointer.func */
            8884097, 8, 0, /* 1946: pointer.func */
            8884097, 8, 0, /* 1949: pointer.func */
            8884097, 8, 0, /* 1952: pointer.func */
            8884097, 8, 0, /* 1955: pointer.func */
            8884097, 8, 0, /* 1958: pointer.func */
            8884097, 8, 0, /* 1961: pointer.func */
            8884097, 8, 0, /* 1964: pointer.func */
            8884097, 8, 0, /* 1967: pointer.func */
            0, 24, 1, /* 1970: struct.bignum_st */
            	1975, 0,
            8884099, 8, 2, /* 1975: pointer_to_array_of_pointers_to_stack */
            	168, 0,
            	122, 12,
            0, 24, 1, /* 1982: struct.bignum_st */
            	1987, 0,
            8884099, 8, 2, /* 1987: pointer_to_array_of_pointers_to_stack */
            	168, 0,
            	122, 12,
            1, 8, 1, /* 1994: pointer.struct.ec_extra_data_st */
            	1999, 0,
            0, 40, 5, /* 1999: struct.ec_extra_data_st */
            	2012, 0,
            	15, 8,
            	2017, 16,
            	2020, 24,
            	2020, 32,
            1, 8, 1, /* 2012: pointer.struct.ec_extra_data_st */
            	1999, 0,
            8884097, 8, 0, /* 2017: pointer.func */
            8884097, 8, 0, /* 2020: pointer.func */
            8884097, 8, 0, /* 2023: pointer.func */
            1, 8, 1, /* 2026: pointer.struct.ec_point_st */
            	1787, 0,
            1, 8, 1, /* 2031: pointer.struct.bignum_st */
            	2036, 0,
            0, 24, 1, /* 2036: struct.bignum_st */
            	2041, 0,
            8884099, 8, 2, /* 2041: pointer_to_array_of_pointers_to_stack */
            	168, 0,
            	122, 12,
            1, 8, 1, /* 2048: pointer.struct.ec_extra_data_st */
            	2053, 0,
            0, 40, 5, /* 2053: struct.ec_extra_data_st */
            	2066, 0,
            	15, 8,
            	2017, 16,
            	2020, 24,
            	2020, 32,
            1, 8, 1, /* 2066: pointer.struct.ec_extra_data_st */
            	2053, 0,
            1, 8, 1, /* 2071: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2076, 0,
            0, 32, 2, /* 2076: struct.stack_st_fake_X509_ATTRIBUTE */
            	2083, 8,
            	125, 24,
            8884099, 8, 2, /* 2083: pointer_to_array_of_pointers_to_stack */
            	2090, 0,
            	122, 20,
            0, 8, 1, /* 2090: pointer.X509_ATTRIBUTE */
            	2095, 0,
            0, 0, 1, /* 2095: X509_ATTRIBUTE */
            	2100, 0,
            0, 24, 2, /* 2100: struct.x509_attributes_st */
            	2107, 0,
            	2121, 16,
            1, 8, 1, /* 2107: pointer.struct.asn1_object_st */
            	2112, 0,
            0, 40, 3, /* 2112: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	99, 24,
            0, 8, 3, /* 2121: union.unknown */
            	138, 0,
            	2130, 0,
            	2309, 0,
            1, 8, 1, /* 2130: pointer.struct.stack_st_ASN1_TYPE */
            	2135, 0,
            0, 32, 2, /* 2135: struct.stack_st_fake_ASN1_TYPE */
            	2142, 8,
            	125, 24,
            8884099, 8, 2, /* 2142: pointer_to_array_of_pointers_to_stack */
            	2149, 0,
            	122, 20,
            0, 8, 1, /* 2149: pointer.ASN1_TYPE */
            	2154, 0,
            0, 0, 1, /* 2154: ASN1_TYPE */
            	2159, 0,
            0, 16, 1, /* 2159: struct.asn1_type_st */
            	2164, 8,
            0, 8, 20, /* 2164: union.unknown */
            	138, 0,
            	2207, 0,
            	2217, 0,
            	2231, 0,
            	2236, 0,
            	2241, 0,
            	2246, 0,
            	2251, 0,
            	2256, 0,
            	2261, 0,
            	2266, 0,
            	2271, 0,
            	2276, 0,
            	2281, 0,
            	2286, 0,
            	2291, 0,
            	2296, 0,
            	2207, 0,
            	2207, 0,
            	2301, 0,
            1, 8, 1, /* 2207: pointer.struct.asn1_string_st */
            	2212, 0,
            0, 24, 1, /* 2212: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 2217: pointer.struct.asn1_object_st */
            	2222, 0,
            0, 40, 3, /* 2222: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	99, 24,
            1, 8, 1, /* 2231: pointer.struct.asn1_string_st */
            	2212, 0,
            1, 8, 1, /* 2236: pointer.struct.asn1_string_st */
            	2212, 0,
            1, 8, 1, /* 2241: pointer.struct.asn1_string_st */
            	2212, 0,
            1, 8, 1, /* 2246: pointer.struct.asn1_string_st */
            	2212, 0,
            1, 8, 1, /* 2251: pointer.struct.asn1_string_st */
            	2212, 0,
            1, 8, 1, /* 2256: pointer.struct.asn1_string_st */
            	2212, 0,
            1, 8, 1, /* 2261: pointer.struct.asn1_string_st */
            	2212, 0,
            1, 8, 1, /* 2266: pointer.struct.asn1_string_st */
            	2212, 0,
            1, 8, 1, /* 2271: pointer.struct.asn1_string_st */
            	2212, 0,
            1, 8, 1, /* 2276: pointer.struct.asn1_string_st */
            	2212, 0,
            1, 8, 1, /* 2281: pointer.struct.asn1_string_st */
            	2212, 0,
            1, 8, 1, /* 2286: pointer.struct.asn1_string_st */
            	2212, 0,
            1, 8, 1, /* 2291: pointer.struct.asn1_string_st */
            	2212, 0,
            1, 8, 1, /* 2296: pointer.struct.asn1_string_st */
            	2212, 0,
            1, 8, 1, /* 2301: pointer.struct.ASN1_VALUE_st */
            	2306, 0,
            0, 0, 0, /* 2306: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2309: pointer.struct.asn1_type_st */
            	2314, 0,
            0, 16, 1, /* 2314: struct.asn1_type_st */
            	2319, 8,
            0, 8, 20, /* 2319: union.unknown */
            	138, 0,
            	2362, 0,
            	2107, 0,
            	2372, 0,
            	2377, 0,
            	2382, 0,
            	2387, 0,
            	2392, 0,
            	2397, 0,
            	2402, 0,
            	2407, 0,
            	2412, 0,
            	2417, 0,
            	2422, 0,
            	2427, 0,
            	2432, 0,
            	2437, 0,
            	2362, 0,
            	2362, 0,
            	496, 0,
            1, 8, 1, /* 2362: pointer.struct.asn1_string_st */
            	2367, 0,
            0, 24, 1, /* 2367: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 2372: pointer.struct.asn1_string_st */
            	2367, 0,
            1, 8, 1, /* 2377: pointer.struct.asn1_string_st */
            	2367, 0,
            1, 8, 1, /* 2382: pointer.struct.asn1_string_st */
            	2367, 0,
            1, 8, 1, /* 2387: pointer.struct.asn1_string_st */
            	2367, 0,
            1, 8, 1, /* 2392: pointer.struct.asn1_string_st */
            	2367, 0,
            1, 8, 1, /* 2397: pointer.struct.asn1_string_st */
            	2367, 0,
            1, 8, 1, /* 2402: pointer.struct.asn1_string_st */
            	2367, 0,
            1, 8, 1, /* 2407: pointer.struct.asn1_string_st */
            	2367, 0,
            1, 8, 1, /* 2412: pointer.struct.asn1_string_st */
            	2367, 0,
            1, 8, 1, /* 2417: pointer.struct.asn1_string_st */
            	2367, 0,
            1, 8, 1, /* 2422: pointer.struct.asn1_string_st */
            	2367, 0,
            1, 8, 1, /* 2427: pointer.struct.asn1_string_st */
            	2367, 0,
            1, 8, 1, /* 2432: pointer.struct.asn1_string_st */
            	2367, 0,
            1, 8, 1, /* 2437: pointer.struct.asn1_string_st */
            	2367, 0,
            1, 8, 1, /* 2442: pointer.struct.asn1_string_st */
            	332, 0,
            1, 8, 1, /* 2447: pointer.struct.stack_st_X509_EXTENSION */
            	2452, 0,
            0, 32, 2, /* 2452: struct.stack_st_fake_X509_EXTENSION */
            	2459, 8,
            	125, 24,
            8884099, 8, 2, /* 2459: pointer_to_array_of_pointers_to_stack */
            	2466, 0,
            	122, 20,
            0, 8, 1, /* 2466: pointer.X509_EXTENSION */
            	2471, 0,
            0, 0, 1, /* 2471: X509_EXTENSION */
            	2476, 0,
            0, 24, 2, /* 2476: struct.X509_extension_st */
            	2483, 0,
            	2497, 16,
            1, 8, 1, /* 2483: pointer.struct.asn1_object_st */
            	2488, 0,
            0, 40, 3, /* 2488: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	99, 24,
            1, 8, 1, /* 2497: pointer.struct.asn1_string_st */
            	2502, 0,
            0, 24, 1, /* 2502: struct.asn1_string_st */
            	117, 8,
            0, 24, 1, /* 2507: struct.ASN1_ENCODING_st */
            	117, 0,
            0, 16, 1, /* 2512: struct.crypto_ex_data_st */
            	2517, 0,
            1, 8, 1, /* 2517: pointer.struct.stack_st_void */
            	2522, 0,
            0, 32, 1, /* 2522: struct.stack_st_void */
            	2527, 0,
            0, 32, 2, /* 2527: struct.stack_st */
            	1058, 8,
            	125, 24,
            1, 8, 1, /* 2534: pointer.struct.asn1_string_st */
            	332, 0,
            1, 8, 1, /* 2539: pointer.struct.AUTHORITY_KEYID_st */
            	2544, 0,
            0, 24, 3, /* 2544: struct.AUTHORITY_KEYID_st */
            	2553, 0,
            	2563, 8,
            	2799, 16,
            1, 8, 1, /* 2553: pointer.struct.asn1_string_st */
            	2558, 0,
            0, 24, 1, /* 2558: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 2563: pointer.struct.stack_st_GENERAL_NAME */
            	2568, 0,
            0, 32, 2, /* 2568: struct.stack_st_fake_GENERAL_NAME */
            	2575, 8,
            	125, 24,
            8884099, 8, 2, /* 2575: pointer_to_array_of_pointers_to_stack */
            	2582, 0,
            	122, 20,
            0, 8, 1, /* 2582: pointer.GENERAL_NAME */
            	2587, 0,
            0, 0, 1, /* 2587: GENERAL_NAME */
            	2592, 0,
            0, 16, 1, /* 2592: struct.GENERAL_NAME_st */
            	2597, 8,
            0, 8, 15, /* 2597: union.unknown */
            	138, 0,
            	2630, 0,
            	2739, 0,
            	2739, 0,
            	2656, 0,
            	35, 0,
            	2787, 0,
            	2739, 0,
            	143, 0,
            	2642, 0,
            	143, 0,
            	35, 0,
            	2739, 0,
            	2642, 0,
            	2656, 0,
            1, 8, 1, /* 2630: pointer.struct.otherName_st */
            	2635, 0,
            0, 16, 2, /* 2635: struct.otherName_st */
            	2642, 0,
            	2656, 8,
            1, 8, 1, /* 2642: pointer.struct.asn1_object_st */
            	2647, 0,
            0, 40, 3, /* 2647: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	99, 24,
            1, 8, 1, /* 2656: pointer.struct.asn1_type_st */
            	2661, 0,
            0, 16, 1, /* 2661: struct.asn1_type_st */
            	2666, 8,
            0, 8, 20, /* 2666: union.unknown */
            	138, 0,
            	2709, 0,
            	2642, 0,
            	2714, 0,
            	2719, 0,
            	2724, 0,
            	143, 0,
            	2729, 0,
            	2734, 0,
            	2739, 0,
            	2744, 0,
            	2749, 0,
            	2754, 0,
            	2759, 0,
            	2764, 0,
            	2769, 0,
            	2774, 0,
            	2709, 0,
            	2709, 0,
            	2779, 0,
            1, 8, 1, /* 2709: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2714: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2719: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2724: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2729: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2734: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2739: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2744: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2749: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2754: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2759: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2764: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2769: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2774: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2779: pointer.struct.ASN1_VALUE_st */
            	2784, 0,
            0, 0, 0, /* 2784: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2787: pointer.struct.EDIPartyName_st */
            	2792, 0,
            0, 16, 2, /* 2792: struct.EDIPartyName_st */
            	2709, 0,
            	2709, 8,
            1, 8, 1, /* 2799: pointer.struct.asn1_string_st */
            	2558, 0,
            1, 8, 1, /* 2804: pointer.struct.X509_POLICY_CACHE_st */
            	2809, 0,
            0, 40, 2, /* 2809: struct.X509_POLICY_CACHE_st */
            	2816, 0,
            	3135, 8,
            1, 8, 1, /* 2816: pointer.struct.X509_POLICY_DATA_st */
            	2821, 0,
            0, 32, 3, /* 2821: struct.X509_POLICY_DATA_st */
            	2830, 8,
            	2844, 16,
            	3097, 24,
            1, 8, 1, /* 2830: pointer.struct.asn1_object_st */
            	2835, 0,
            0, 40, 3, /* 2835: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	99, 24,
            1, 8, 1, /* 2844: pointer.struct.stack_st_POLICYQUALINFO */
            	2849, 0,
            0, 32, 2, /* 2849: struct.stack_st_fake_POLICYQUALINFO */
            	2856, 8,
            	125, 24,
            8884099, 8, 2, /* 2856: pointer_to_array_of_pointers_to_stack */
            	2863, 0,
            	122, 20,
            0, 8, 1, /* 2863: pointer.POLICYQUALINFO */
            	2868, 0,
            0, 0, 1, /* 2868: POLICYQUALINFO */
            	2873, 0,
            0, 16, 2, /* 2873: struct.POLICYQUALINFO_st */
            	2880, 0,
            	2894, 8,
            1, 8, 1, /* 2880: pointer.struct.asn1_object_st */
            	2885, 0,
            0, 40, 3, /* 2885: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	99, 24,
            0, 8, 3, /* 2894: union.unknown */
            	2903, 0,
            	2913, 0,
            	2971, 0,
            1, 8, 1, /* 2903: pointer.struct.asn1_string_st */
            	2908, 0,
            0, 24, 1, /* 2908: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 2913: pointer.struct.USERNOTICE_st */
            	2918, 0,
            0, 16, 2, /* 2918: struct.USERNOTICE_st */
            	2925, 0,
            	2937, 8,
            1, 8, 1, /* 2925: pointer.struct.NOTICEREF_st */
            	2930, 0,
            0, 16, 2, /* 2930: struct.NOTICEREF_st */
            	2937, 0,
            	2942, 8,
            1, 8, 1, /* 2937: pointer.struct.asn1_string_st */
            	2908, 0,
            1, 8, 1, /* 2942: pointer.struct.stack_st_ASN1_INTEGER */
            	2947, 0,
            0, 32, 2, /* 2947: struct.stack_st_fake_ASN1_INTEGER */
            	2954, 8,
            	125, 24,
            8884099, 8, 2, /* 2954: pointer_to_array_of_pointers_to_stack */
            	2961, 0,
            	122, 20,
            0, 8, 1, /* 2961: pointer.ASN1_INTEGER */
            	2966, 0,
            0, 0, 1, /* 2966: ASN1_INTEGER */
            	421, 0,
            1, 8, 1, /* 2971: pointer.struct.asn1_type_st */
            	2976, 0,
            0, 16, 1, /* 2976: struct.asn1_type_st */
            	2981, 8,
            0, 8, 20, /* 2981: union.unknown */
            	138, 0,
            	2937, 0,
            	2880, 0,
            	3024, 0,
            	3029, 0,
            	3034, 0,
            	3039, 0,
            	3044, 0,
            	3049, 0,
            	2903, 0,
            	3054, 0,
            	3059, 0,
            	3064, 0,
            	3069, 0,
            	3074, 0,
            	3079, 0,
            	3084, 0,
            	2937, 0,
            	2937, 0,
            	3089, 0,
            1, 8, 1, /* 3024: pointer.struct.asn1_string_st */
            	2908, 0,
            1, 8, 1, /* 3029: pointer.struct.asn1_string_st */
            	2908, 0,
            1, 8, 1, /* 3034: pointer.struct.asn1_string_st */
            	2908, 0,
            1, 8, 1, /* 3039: pointer.struct.asn1_string_st */
            	2908, 0,
            1, 8, 1, /* 3044: pointer.struct.asn1_string_st */
            	2908, 0,
            1, 8, 1, /* 3049: pointer.struct.asn1_string_st */
            	2908, 0,
            1, 8, 1, /* 3054: pointer.struct.asn1_string_st */
            	2908, 0,
            1, 8, 1, /* 3059: pointer.struct.asn1_string_st */
            	2908, 0,
            1, 8, 1, /* 3064: pointer.struct.asn1_string_st */
            	2908, 0,
            1, 8, 1, /* 3069: pointer.struct.asn1_string_st */
            	2908, 0,
            1, 8, 1, /* 3074: pointer.struct.asn1_string_st */
            	2908, 0,
            1, 8, 1, /* 3079: pointer.struct.asn1_string_st */
            	2908, 0,
            1, 8, 1, /* 3084: pointer.struct.asn1_string_st */
            	2908, 0,
            1, 8, 1, /* 3089: pointer.struct.ASN1_VALUE_st */
            	3094, 0,
            0, 0, 0, /* 3094: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3097: pointer.struct.stack_st_ASN1_OBJECT */
            	3102, 0,
            0, 32, 2, /* 3102: struct.stack_st_fake_ASN1_OBJECT */
            	3109, 8,
            	125, 24,
            8884099, 8, 2, /* 3109: pointer_to_array_of_pointers_to_stack */
            	3116, 0,
            	122, 20,
            0, 8, 1, /* 3116: pointer.ASN1_OBJECT */
            	3121, 0,
            0, 0, 1, /* 3121: ASN1_OBJECT */
            	3126, 0,
            0, 40, 3, /* 3126: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	99, 24,
            1, 8, 1, /* 3135: pointer.struct.stack_st_X509_POLICY_DATA */
            	3140, 0,
            0, 32, 2, /* 3140: struct.stack_st_fake_X509_POLICY_DATA */
            	3147, 8,
            	125, 24,
            8884099, 8, 2, /* 3147: pointer_to_array_of_pointers_to_stack */
            	3154, 0,
            	122, 20,
            0, 8, 1, /* 3154: pointer.X509_POLICY_DATA */
            	3159, 0,
            0, 0, 1, /* 3159: X509_POLICY_DATA */
            	3164, 0,
            0, 32, 3, /* 3164: struct.X509_POLICY_DATA_st */
            	3173, 8,
            	3187, 16,
            	3211, 24,
            1, 8, 1, /* 3173: pointer.struct.asn1_object_st */
            	3178, 0,
            0, 40, 3, /* 3178: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	99, 24,
            1, 8, 1, /* 3187: pointer.struct.stack_st_POLICYQUALINFO */
            	3192, 0,
            0, 32, 2, /* 3192: struct.stack_st_fake_POLICYQUALINFO */
            	3199, 8,
            	125, 24,
            8884099, 8, 2, /* 3199: pointer_to_array_of_pointers_to_stack */
            	3206, 0,
            	122, 20,
            0, 8, 1, /* 3206: pointer.POLICYQUALINFO */
            	2868, 0,
            1, 8, 1, /* 3211: pointer.struct.stack_st_ASN1_OBJECT */
            	3216, 0,
            0, 32, 2, /* 3216: struct.stack_st_fake_ASN1_OBJECT */
            	3223, 8,
            	125, 24,
            8884099, 8, 2, /* 3223: pointer_to_array_of_pointers_to_stack */
            	3230, 0,
            	122, 20,
            0, 8, 1, /* 3230: pointer.ASN1_OBJECT */
            	3121, 0,
            1, 8, 1, /* 3235: pointer.struct.stack_st_DIST_POINT */
            	3240, 0,
            0, 32, 2, /* 3240: struct.stack_st_fake_DIST_POINT */
            	3247, 8,
            	125, 24,
            8884099, 8, 2, /* 3247: pointer_to_array_of_pointers_to_stack */
            	3254, 0,
            	122, 20,
            0, 8, 1, /* 3254: pointer.DIST_POINT */
            	3259, 0,
            0, 0, 1, /* 3259: DIST_POINT */
            	3264, 0,
            0, 32, 3, /* 3264: struct.DIST_POINT_st */
            	3273, 0,
            	3364, 8,
            	3292, 16,
            1, 8, 1, /* 3273: pointer.struct.DIST_POINT_NAME_st */
            	3278, 0,
            0, 24, 2, /* 3278: struct.DIST_POINT_NAME_st */
            	3285, 8,
            	3340, 16,
            0, 8, 2, /* 3285: union.unknown */
            	3292, 0,
            	3316, 0,
            1, 8, 1, /* 3292: pointer.struct.stack_st_GENERAL_NAME */
            	3297, 0,
            0, 32, 2, /* 3297: struct.stack_st_fake_GENERAL_NAME */
            	3304, 8,
            	125, 24,
            8884099, 8, 2, /* 3304: pointer_to_array_of_pointers_to_stack */
            	3311, 0,
            	122, 20,
            0, 8, 1, /* 3311: pointer.GENERAL_NAME */
            	2587, 0,
            1, 8, 1, /* 3316: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3321, 0,
            0, 32, 2, /* 3321: struct.stack_st_fake_X509_NAME_ENTRY */
            	3328, 8,
            	125, 24,
            8884099, 8, 2, /* 3328: pointer_to_array_of_pointers_to_stack */
            	3335, 0,
            	122, 20,
            0, 8, 1, /* 3335: pointer.X509_NAME_ENTRY */
            	73, 0,
            1, 8, 1, /* 3340: pointer.struct.X509_name_st */
            	3345, 0,
            0, 40, 3, /* 3345: struct.X509_name_st */
            	3316, 0,
            	3354, 16,
            	117, 24,
            1, 8, 1, /* 3354: pointer.struct.buf_mem_st */
            	3359, 0,
            0, 24, 1, /* 3359: struct.buf_mem_st */
            	138, 8,
            1, 8, 1, /* 3364: pointer.struct.asn1_string_st */
            	3369, 0,
            0, 24, 1, /* 3369: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 3374: pointer.struct.stack_st_GENERAL_NAME */
            	3379, 0,
            0, 32, 2, /* 3379: struct.stack_st_fake_GENERAL_NAME */
            	3386, 8,
            	125, 24,
            8884099, 8, 2, /* 3386: pointer_to_array_of_pointers_to_stack */
            	3393, 0,
            	122, 20,
            0, 8, 1, /* 3393: pointer.GENERAL_NAME */
            	2587, 0,
            1, 8, 1, /* 3398: pointer.struct.NAME_CONSTRAINTS_st */
            	3403, 0,
            0, 16, 2, /* 3403: struct.NAME_CONSTRAINTS_st */
            	3410, 0,
            	3410, 8,
            1, 8, 1, /* 3410: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3415, 0,
            0, 32, 2, /* 3415: struct.stack_st_fake_GENERAL_SUBTREE */
            	3422, 8,
            	125, 24,
            8884099, 8, 2, /* 3422: pointer_to_array_of_pointers_to_stack */
            	3429, 0,
            	122, 20,
            0, 8, 1, /* 3429: pointer.GENERAL_SUBTREE */
            	3434, 0,
            0, 0, 1, /* 3434: GENERAL_SUBTREE */
            	3439, 0,
            0, 24, 3, /* 3439: struct.GENERAL_SUBTREE_st */
            	3448, 0,
            	3580, 8,
            	3580, 16,
            1, 8, 1, /* 3448: pointer.struct.GENERAL_NAME_st */
            	3453, 0,
            0, 16, 1, /* 3453: struct.GENERAL_NAME_st */
            	3458, 8,
            0, 8, 15, /* 3458: union.unknown */
            	138, 0,
            	3491, 0,
            	3610, 0,
            	3610, 0,
            	3517, 0,
            	3650, 0,
            	3698, 0,
            	3610, 0,
            	3595, 0,
            	3503, 0,
            	3595, 0,
            	3650, 0,
            	3610, 0,
            	3503, 0,
            	3517, 0,
            1, 8, 1, /* 3491: pointer.struct.otherName_st */
            	3496, 0,
            0, 16, 2, /* 3496: struct.otherName_st */
            	3503, 0,
            	3517, 8,
            1, 8, 1, /* 3503: pointer.struct.asn1_object_st */
            	3508, 0,
            0, 40, 3, /* 3508: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	99, 24,
            1, 8, 1, /* 3517: pointer.struct.asn1_type_st */
            	3522, 0,
            0, 16, 1, /* 3522: struct.asn1_type_st */
            	3527, 8,
            0, 8, 20, /* 3527: union.unknown */
            	138, 0,
            	3570, 0,
            	3503, 0,
            	3580, 0,
            	3585, 0,
            	3590, 0,
            	3595, 0,
            	3600, 0,
            	3605, 0,
            	3610, 0,
            	3615, 0,
            	3620, 0,
            	3625, 0,
            	3630, 0,
            	3635, 0,
            	3640, 0,
            	3645, 0,
            	3570, 0,
            	3570, 0,
            	3089, 0,
            1, 8, 1, /* 3570: pointer.struct.asn1_string_st */
            	3575, 0,
            0, 24, 1, /* 3575: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 3580: pointer.struct.asn1_string_st */
            	3575, 0,
            1, 8, 1, /* 3585: pointer.struct.asn1_string_st */
            	3575, 0,
            1, 8, 1, /* 3590: pointer.struct.asn1_string_st */
            	3575, 0,
            1, 8, 1, /* 3595: pointer.struct.asn1_string_st */
            	3575, 0,
            1, 8, 1, /* 3600: pointer.struct.asn1_string_st */
            	3575, 0,
            1, 8, 1, /* 3605: pointer.struct.asn1_string_st */
            	3575, 0,
            1, 8, 1, /* 3610: pointer.struct.asn1_string_st */
            	3575, 0,
            1, 8, 1, /* 3615: pointer.struct.asn1_string_st */
            	3575, 0,
            1, 8, 1, /* 3620: pointer.struct.asn1_string_st */
            	3575, 0,
            1, 8, 1, /* 3625: pointer.struct.asn1_string_st */
            	3575, 0,
            1, 8, 1, /* 3630: pointer.struct.asn1_string_st */
            	3575, 0,
            1, 8, 1, /* 3635: pointer.struct.asn1_string_st */
            	3575, 0,
            1, 8, 1, /* 3640: pointer.struct.asn1_string_st */
            	3575, 0,
            1, 8, 1, /* 3645: pointer.struct.asn1_string_st */
            	3575, 0,
            1, 8, 1, /* 3650: pointer.struct.X509_name_st */
            	3655, 0,
            0, 40, 3, /* 3655: struct.X509_name_st */
            	3664, 0,
            	3688, 16,
            	117, 24,
            1, 8, 1, /* 3664: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3669, 0,
            0, 32, 2, /* 3669: struct.stack_st_fake_X509_NAME_ENTRY */
            	3676, 8,
            	125, 24,
            8884099, 8, 2, /* 3676: pointer_to_array_of_pointers_to_stack */
            	3683, 0,
            	122, 20,
            0, 8, 1, /* 3683: pointer.X509_NAME_ENTRY */
            	73, 0,
            1, 8, 1, /* 3688: pointer.struct.buf_mem_st */
            	3693, 0,
            0, 24, 1, /* 3693: struct.buf_mem_st */
            	138, 8,
            1, 8, 1, /* 3698: pointer.struct.EDIPartyName_st */
            	3703, 0,
            0, 16, 2, /* 3703: struct.EDIPartyName_st */
            	3570, 0,
            	3570, 8,
            1, 8, 1, /* 3710: pointer.struct.x509_cert_aux_st */
            	3715, 0,
            0, 40, 5, /* 3715: struct.x509_cert_aux_st */
            	3728, 0,
            	3728, 8,
            	3752, 16,
            	2534, 24,
            	3757, 32,
            1, 8, 1, /* 3728: pointer.struct.stack_st_ASN1_OBJECT */
            	3733, 0,
            0, 32, 2, /* 3733: struct.stack_st_fake_ASN1_OBJECT */
            	3740, 8,
            	125, 24,
            8884099, 8, 2, /* 3740: pointer_to_array_of_pointers_to_stack */
            	3747, 0,
            	122, 20,
            0, 8, 1, /* 3747: pointer.ASN1_OBJECT */
            	3121, 0,
            1, 8, 1, /* 3752: pointer.struct.asn1_string_st */
            	332, 0,
            1, 8, 1, /* 3757: pointer.struct.stack_st_X509_ALGOR */
            	3762, 0,
            0, 32, 2, /* 3762: struct.stack_st_fake_X509_ALGOR */
            	3769, 8,
            	125, 24,
            8884099, 8, 2, /* 3769: pointer_to_array_of_pointers_to_stack */
            	3776, 0,
            	122, 20,
            0, 8, 1, /* 3776: pointer.X509_ALGOR */
            	3781, 0,
            0, 0, 1, /* 3781: X509_ALGOR */
            	342, 0,
            1, 8, 1, /* 3786: pointer.struct.X509_crl_st */
            	3791, 0,
            0, 120, 10, /* 3791: struct.X509_crl_st */
            	3814, 0,
            	337, 8,
            	2442, 16,
            	2539, 32,
            	3941, 40,
            	327, 56,
            	327, 64,
            	4054, 96,
            	4095, 104,
            	15, 112,
            1, 8, 1, /* 3814: pointer.struct.X509_crl_info_st */
            	3819, 0,
            0, 80, 8, /* 3819: struct.X509_crl_info_st */
            	327, 0,
            	337, 8,
            	504, 16,
            	564, 24,
            	564, 32,
            	3838, 40,
            	2447, 48,
            	2507, 56,
            1, 8, 1, /* 3838: pointer.struct.stack_st_X509_REVOKED */
            	3843, 0,
            0, 32, 2, /* 3843: struct.stack_st_fake_X509_REVOKED */
            	3850, 8,
            	125, 24,
            8884099, 8, 2, /* 3850: pointer_to_array_of_pointers_to_stack */
            	3857, 0,
            	122, 20,
            0, 8, 1, /* 3857: pointer.X509_REVOKED */
            	3862, 0,
            0, 0, 1, /* 3862: X509_REVOKED */
            	3867, 0,
            0, 40, 4, /* 3867: struct.x509_revoked_st */
            	3878, 0,
            	3888, 8,
            	3893, 16,
            	3917, 24,
            1, 8, 1, /* 3878: pointer.struct.asn1_string_st */
            	3883, 0,
            0, 24, 1, /* 3883: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 3888: pointer.struct.asn1_string_st */
            	3883, 0,
            1, 8, 1, /* 3893: pointer.struct.stack_st_X509_EXTENSION */
            	3898, 0,
            0, 32, 2, /* 3898: struct.stack_st_fake_X509_EXTENSION */
            	3905, 8,
            	125, 24,
            8884099, 8, 2, /* 3905: pointer_to_array_of_pointers_to_stack */
            	3912, 0,
            	122, 20,
            0, 8, 1, /* 3912: pointer.X509_EXTENSION */
            	2471, 0,
            1, 8, 1, /* 3917: pointer.struct.stack_st_GENERAL_NAME */
            	3922, 0,
            0, 32, 2, /* 3922: struct.stack_st_fake_GENERAL_NAME */
            	3929, 8,
            	125, 24,
            8884099, 8, 2, /* 3929: pointer_to_array_of_pointers_to_stack */
            	3936, 0,
            	122, 20,
            0, 8, 1, /* 3936: pointer.GENERAL_NAME */
            	2587, 0,
            1, 8, 1, /* 3941: pointer.struct.ISSUING_DIST_POINT_st */
            	3946, 0,
            0, 32, 2, /* 3946: struct.ISSUING_DIST_POINT_st */
            	3953, 0,
            	4044, 16,
            1, 8, 1, /* 3953: pointer.struct.DIST_POINT_NAME_st */
            	3958, 0,
            0, 24, 2, /* 3958: struct.DIST_POINT_NAME_st */
            	3965, 8,
            	4020, 16,
            0, 8, 2, /* 3965: union.unknown */
            	3972, 0,
            	3996, 0,
            1, 8, 1, /* 3972: pointer.struct.stack_st_GENERAL_NAME */
            	3977, 0,
            0, 32, 2, /* 3977: struct.stack_st_fake_GENERAL_NAME */
            	3984, 8,
            	125, 24,
            8884099, 8, 2, /* 3984: pointer_to_array_of_pointers_to_stack */
            	3991, 0,
            	122, 20,
            0, 8, 1, /* 3991: pointer.GENERAL_NAME */
            	2587, 0,
            1, 8, 1, /* 3996: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4001, 0,
            0, 32, 2, /* 4001: struct.stack_st_fake_X509_NAME_ENTRY */
            	4008, 8,
            	125, 24,
            8884099, 8, 2, /* 4008: pointer_to_array_of_pointers_to_stack */
            	4015, 0,
            	122, 20,
            0, 8, 1, /* 4015: pointer.X509_NAME_ENTRY */
            	73, 0,
            1, 8, 1, /* 4020: pointer.struct.X509_name_st */
            	4025, 0,
            0, 40, 3, /* 4025: struct.X509_name_st */
            	3996, 0,
            	4034, 16,
            	117, 24,
            1, 8, 1, /* 4034: pointer.struct.buf_mem_st */
            	4039, 0,
            0, 24, 1, /* 4039: struct.buf_mem_st */
            	138, 8,
            1, 8, 1, /* 4044: pointer.struct.asn1_string_st */
            	4049, 0,
            0, 24, 1, /* 4049: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 4054: pointer.struct.stack_st_GENERAL_NAMES */
            	4059, 0,
            0, 32, 2, /* 4059: struct.stack_st_fake_GENERAL_NAMES */
            	4066, 8,
            	125, 24,
            8884099, 8, 2, /* 4066: pointer_to_array_of_pointers_to_stack */
            	4073, 0,
            	122, 20,
            0, 8, 1, /* 4073: pointer.GENERAL_NAMES */
            	4078, 0,
            0, 0, 1, /* 4078: GENERAL_NAMES */
            	4083, 0,
            0, 32, 1, /* 4083: struct.stack_st_GENERAL_NAME */
            	4088, 0,
            0, 32, 2, /* 4088: struct.stack_st */
            	1058, 8,
            	125, 24,
            1, 8, 1, /* 4095: pointer.struct.x509_crl_method_st */
            	4100, 0,
            0, 40, 4, /* 4100: struct.x509_crl_method_st */
            	4111, 8,
            	4111, 16,
            	4114, 24,
            	4117, 32,
            8884097, 8, 0, /* 4111: pointer.func */
            8884097, 8, 0, /* 4114: pointer.func */
            8884097, 8, 0, /* 4117: pointer.func */
            1, 8, 1, /* 4120: pointer.struct.evp_pkey_st */
            	4125, 0,
            0, 56, 4, /* 4125: struct.evp_pkey_st */
            	4136, 16,
            	4141, 24,
            	4146, 32,
            	4179, 48,
            1, 8, 1, /* 4136: pointer.struct.evp_pkey_asn1_method_st */
            	619, 0,
            1, 8, 1, /* 4141: pointer.struct.engine_st */
            	720, 0,
            0, 8, 5, /* 4146: union.unknown */
            	138, 0,
            	4159, 0,
            	4164, 0,
            	4169, 0,
            	4174, 0,
            1, 8, 1, /* 4159: pointer.struct.rsa_st */
            	1086, 0,
            1, 8, 1, /* 4164: pointer.struct.dsa_st */
            	1302, 0,
            1, 8, 1, /* 4169: pointer.struct.dh_st */
            	1441, 0,
            1, 8, 1, /* 4174: pointer.struct.ec_key_st */
            	1567, 0,
            1, 8, 1, /* 4179: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4184, 0,
            0, 32, 2, /* 4184: struct.stack_st_fake_X509_ATTRIBUTE */
            	4191, 8,
            	125, 24,
            8884099, 8, 2, /* 4191: pointer_to_array_of_pointers_to_stack */
            	4198, 0,
            	122, 20,
            0, 8, 1, /* 4198: pointer.X509_ATTRIBUTE */
            	2095, 0,
            1, 8, 1, /* 4203: pointer.struct.ssl_ctx_st */
            	4208, 0,
            0, 736, 50, /* 4208: struct.ssl_ctx_st */
            	4311, 0,
            	4480, 8,
            	4480, 16,
            	4514, 24,
            	4834, 32,
            	4870, 48,
            	4870, 56,
            	6032, 80,
            	6035, 88,
            	6038, 96,
            	202, 152,
            	15, 160,
            	6041, 168,
            	15, 176,
            	199, 184,
            	6044, 192,
            	6047, 200,
            	4812, 208,
            	6050, 224,
            	6050, 232,
            	6050, 240,
            	6089, 248,
            	6113, 256,
            	6180, 264,
            	6183, 272,
            	6255, 304,
            	6696, 320,
            	15, 328,
            	4803, 376,
            	6699, 384,
            	4764, 392,
            	5667, 408,
            	6702, 416,
            	15, 424,
            	6705, 480,
            	6708, 488,
            	15, 496,
            	196, 504,
            	15, 512,
            	138, 520,
            	6711, 528,
            	6714, 536,
            	176, 552,
            	176, 560,
            	6717, 568,
            	6751, 696,
            	15, 704,
            	153, 712,
            	15, 720,
            	6754, 728,
            1, 8, 1, /* 4311: pointer.struct.ssl_method_st */
            	4316, 0,
            0, 232, 28, /* 4316: struct.ssl_method_st */
            	4375, 8,
            	4378, 16,
            	4378, 24,
            	4375, 32,
            	4375, 40,
            	4381, 48,
            	4381, 56,
            	4384, 64,
            	4375, 72,
            	4375, 80,
            	4375, 88,
            	4387, 96,
            	4390, 104,
            	4393, 112,
            	4375, 120,
            	4396, 128,
            	4399, 136,
            	4402, 144,
            	4405, 152,
            	4408, 160,
            	989, 168,
            	4411, 176,
            	4414, 184,
            	4417, 192,
            	4420, 200,
            	989, 208,
            	4474, 216,
            	4477, 224,
            8884097, 8, 0, /* 4375: pointer.func */
            8884097, 8, 0, /* 4378: pointer.func */
            8884097, 8, 0, /* 4381: pointer.func */
            8884097, 8, 0, /* 4384: pointer.func */
            8884097, 8, 0, /* 4387: pointer.func */
            8884097, 8, 0, /* 4390: pointer.func */
            8884097, 8, 0, /* 4393: pointer.func */
            8884097, 8, 0, /* 4396: pointer.func */
            8884097, 8, 0, /* 4399: pointer.func */
            8884097, 8, 0, /* 4402: pointer.func */
            8884097, 8, 0, /* 4405: pointer.func */
            8884097, 8, 0, /* 4408: pointer.func */
            8884097, 8, 0, /* 4411: pointer.func */
            8884097, 8, 0, /* 4414: pointer.func */
            8884097, 8, 0, /* 4417: pointer.func */
            1, 8, 1, /* 4420: pointer.struct.ssl3_enc_method */
            	4425, 0,
            0, 112, 11, /* 4425: struct.ssl3_enc_method */
            	4450, 0,
            	4453, 8,
            	4456, 16,
            	4459, 24,
            	4450, 32,
            	4462, 40,
            	4465, 56,
            	5, 64,
            	5, 80,
            	4468, 96,
            	4471, 104,
            8884097, 8, 0, /* 4450: pointer.func */
            8884097, 8, 0, /* 4453: pointer.func */
            8884097, 8, 0, /* 4456: pointer.func */
            8884097, 8, 0, /* 4459: pointer.func */
            8884097, 8, 0, /* 4462: pointer.func */
            8884097, 8, 0, /* 4465: pointer.func */
            8884097, 8, 0, /* 4468: pointer.func */
            8884097, 8, 0, /* 4471: pointer.func */
            8884097, 8, 0, /* 4474: pointer.func */
            8884097, 8, 0, /* 4477: pointer.func */
            1, 8, 1, /* 4480: pointer.struct.stack_st_SSL_CIPHER */
            	4485, 0,
            0, 32, 2, /* 4485: struct.stack_st_fake_SSL_CIPHER */
            	4492, 8,
            	125, 24,
            8884099, 8, 2, /* 4492: pointer_to_array_of_pointers_to_stack */
            	4499, 0,
            	122, 20,
            0, 8, 1, /* 4499: pointer.SSL_CIPHER */
            	4504, 0,
            0, 0, 1, /* 4504: SSL_CIPHER */
            	4509, 0,
            0, 88, 1, /* 4509: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 4514: pointer.struct.x509_store_st */
            	4519, 0,
            0, 144, 15, /* 4519: struct.x509_store_st */
            	220, 8,
            	4552, 16,
            	4764, 24,
            	4800, 32,
            	4803, 40,
            	4806, 48,
            	217, 56,
            	4800, 64,
            	214, 72,
            	211, 80,
            	208, 88,
            	205, 96,
            	4809, 104,
            	4800, 112,
            	4812, 120,
            1, 8, 1, /* 4552: pointer.struct.stack_st_X509_LOOKUP */
            	4557, 0,
            0, 32, 2, /* 4557: struct.stack_st_fake_X509_LOOKUP */
            	4564, 8,
            	125, 24,
            8884099, 8, 2, /* 4564: pointer_to_array_of_pointers_to_stack */
            	4571, 0,
            	122, 20,
            0, 8, 1, /* 4571: pointer.X509_LOOKUP */
            	4576, 0,
            0, 0, 1, /* 4576: X509_LOOKUP */
            	4581, 0,
            0, 32, 3, /* 4581: struct.x509_lookup_st */
            	4590, 8,
            	138, 16,
            	4639, 24,
            1, 8, 1, /* 4590: pointer.struct.x509_lookup_method_st */
            	4595, 0,
            0, 80, 10, /* 4595: struct.x509_lookup_method_st */
            	5, 0,
            	4618, 8,
            	4621, 16,
            	4618, 24,
            	4618, 32,
            	4624, 40,
            	4627, 48,
            	4630, 56,
            	4633, 64,
            	4636, 72,
            8884097, 8, 0, /* 4618: pointer.func */
            8884097, 8, 0, /* 4621: pointer.func */
            8884097, 8, 0, /* 4624: pointer.func */
            8884097, 8, 0, /* 4627: pointer.func */
            8884097, 8, 0, /* 4630: pointer.func */
            8884097, 8, 0, /* 4633: pointer.func */
            8884097, 8, 0, /* 4636: pointer.func */
            1, 8, 1, /* 4639: pointer.struct.x509_store_st */
            	4644, 0,
            0, 144, 15, /* 4644: struct.x509_store_st */
            	4677, 8,
            	4701, 16,
            	4725, 24,
            	4737, 32,
            	4740, 40,
            	4743, 48,
            	4746, 56,
            	4737, 64,
            	4749, 72,
            	4752, 80,
            	4755, 88,
            	4758, 96,
            	4761, 104,
            	4737, 112,
            	2512, 120,
            1, 8, 1, /* 4677: pointer.struct.stack_st_X509_OBJECT */
            	4682, 0,
            0, 32, 2, /* 4682: struct.stack_st_fake_X509_OBJECT */
            	4689, 8,
            	125, 24,
            8884099, 8, 2, /* 4689: pointer_to_array_of_pointers_to_stack */
            	4696, 0,
            	122, 20,
            0, 8, 1, /* 4696: pointer.X509_OBJECT */
            	244, 0,
            1, 8, 1, /* 4701: pointer.struct.stack_st_X509_LOOKUP */
            	4706, 0,
            0, 32, 2, /* 4706: struct.stack_st_fake_X509_LOOKUP */
            	4713, 8,
            	125, 24,
            8884099, 8, 2, /* 4713: pointer_to_array_of_pointers_to_stack */
            	4720, 0,
            	122, 20,
            0, 8, 1, /* 4720: pointer.X509_LOOKUP */
            	4576, 0,
            1, 8, 1, /* 4725: pointer.struct.X509_VERIFY_PARAM_st */
            	4730, 0,
            0, 56, 2, /* 4730: struct.X509_VERIFY_PARAM_st */
            	138, 0,
            	3728, 48,
            8884097, 8, 0, /* 4737: pointer.func */
            8884097, 8, 0, /* 4740: pointer.func */
            8884097, 8, 0, /* 4743: pointer.func */
            8884097, 8, 0, /* 4746: pointer.func */
            8884097, 8, 0, /* 4749: pointer.func */
            8884097, 8, 0, /* 4752: pointer.func */
            8884097, 8, 0, /* 4755: pointer.func */
            8884097, 8, 0, /* 4758: pointer.func */
            8884097, 8, 0, /* 4761: pointer.func */
            1, 8, 1, /* 4764: pointer.struct.X509_VERIFY_PARAM_st */
            	4769, 0,
            0, 56, 2, /* 4769: struct.X509_VERIFY_PARAM_st */
            	138, 0,
            	4776, 48,
            1, 8, 1, /* 4776: pointer.struct.stack_st_ASN1_OBJECT */
            	4781, 0,
            0, 32, 2, /* 4781: struct.stack_st_fake_ASN1_OBJECT */
            	4788, 8,
            	125, 24,
            8884099, 8, 2, /* 4788: pointer_to_array_of_pointers_to_stack */
            	4795, 0,
            	122, 20,
            0, 8, 1, /* 4795: pointer.ASN1_OBJECT */
            	3121, 0,
            8884097, 8, 0, /* 4800: pointer.func */
            8884097, 8, 0, /* 4803: pointer.func */
            8884097, 8, 0, /* 4806: pointer.func */
            8884097, 8, 0, /* 4809: pointer.func */
            0, 16, 1, /* 4812: struct.crypto_ex_data_st */
            	4817, 0,
            1, 8, 1, /* 4817: pointer.struct.stack_st_void */
            	4822, 0,
            0, 32, 1, /* 4822: struct.stack_st_void */
            	4827, 0,
            0, 32, 2, /* 4827: struct.stack_st */
            	1058, 8,
            	125, 24,
            1, 8, 1, /* 4834: pointer.struct.lhash_st */
            	4839, 0,
            0, 176, 3, /* 4839: struct.lhash_st */
            	4848, 0,
            	125, 8,
            	4867, 16,
            8884099, 8, 2, /* 4848: pointer_to_array_of_pointers_to_stack */
            	4855, 0,
            	168, 28,
            1, 8, 1, /* 4855: pointer.struct.lhash_node_st */
            	4860, 0,
            0, 24, 2, /* 4860: struct.lhash_node_st */
            	15, 0,
            	4855, 8,
            8884097, 8, 0, /* 4867: pointer.func */
            1, 8, 1, /* 4870: pointer.struct.ssl_session_st */
            	4875, 0,
            0, 352, 14, /* 4875: struct.ssl_session_st */
            	138, 144,
            	138, 152,
            	4906, 168,
            	5789, 176,
            	6022, 224,
            	4480, 240,
            	4812, 248,
            	4870, 264,
            	4870, 272,
            	138, 280,
            	117, 296,
            	117, 312,
            	117, 320,
            	138, 344,
            1, 8, 1, /* 4906: pointer.struct.sess_cert_st */
            	4911, 0,
            0, 248, 5, /* 4911: struct.sess_cert_st */
            	4924, 0,
            	5290, 16,
            	5774, 216,
            	5779, 224,
            	5784, 232,
            1, 8, 1, /* 4924: pointer.struct.stack_st_X509 */
            	4929, 0,
            0, 32, 2, /* 4929: struct.stack_st_fake_X509 */
            	4936, 8,
            	125, 24,
            8884099, 8, 2, /* 4936: pointer_to_array_of_pointers_to_stack */
            	4943, 0,
            	122, 20,
            0, 8, 1, /* 4943: pointer.X509 */
            	4948, 0,
            0, 0, 1, /* 4948: X509 */
            	4953, 0,
            0, 184, 12, /* 4953: struct.x509_st */
            	4980, 0,
            	5020, 8,
            	5095, 16,
            	138, 32,
            	5129, 40,
            	5151, 104,
            	5156, 112,
            	5161, 120,
            	5166, 128,
            	5190, 136,
            	5214, 144,
            	5219, 176,
            1, 8, 1, /* 4980: pointer.struct.x509_cinf_st */
            	4985, 0,
            0, 104, 11, /* 4985: struct.x509_cinf_st */
            	5010, 0,
            	5010, 8,
            	5020, 16,
            	5025, 24,
            	5073, 32,
            	5025, 40,
            	5090, 48,
            	5095, 56,
            	5095, 64,
            	5100, 72,
            	5124, 80,
            1, 8, 1, /* 5010: pointer.struct.asn1_string_st */
            	5015, 0,
            0, 24, 1, /* 5015: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 5020: pointer.struct.X509_algor_st */
            	342, 0,
            1, 8, 1, /* 5025: pointer.struct.X509_name_st */
            	5030, 0,
            0, 40, 3, /* 5030: struct.X509_name_st */
            	5039, 0,
            	5063, 16,
            	117, 24,
            1, 8, 1, /* 5039: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5044, 0,
            0, 32, 2, /* 5044: struct.stack_st_fake_X509_NAME_ENTRY */
            	5051, 8,
            	125, 24,
            8884099, 8, 2, /* 5051: pointer_to_array_of_pointers_to_stack */
            	5058, 0,
            	122, 20,
            0, 8, 1, /* 5058: pointer.X509_NAME_ENTRY */
            	73, 0,
            1, 8, 1, /* 5063: pointer.struct.buf_mem_st */
            	5068, 0,
            0, 24, 1, /* 5068: struct.buf_mem_st */
            	138, 8,
            1, 8, 1, /* 5073: pointer.struct.X509_val_st */
            	5078, 0,
            0, 16, 2, /* 5078: struct.X509_val_st */
            	5085, 0,
            	5085, 8,
            1, 8, 1, /* 5085: pointer.struct.asn1_string_st */
            	5015, 0,
            1, 8, 1, /* 5090: pointer.struct.X509_pubkey_st */
            	574, 0,
            1, 8, 1, /* 5095: pointer.struct.asn1_string_st */
            	5015, 0,
            1, 8, 1, /* 5100: pointer.struct.stack_st_X509_EXTENSION */
            	5105, 0,
            0, 32, 2, /* 5105: struct.stack_st_fake_X509_EXTENSION */
            	5112, 8,
            	125, 24,
            8884099, 8, 2, /* 5112: pointer_to_array_of_pointers_to_stack */
            	5119, 0,
            	122, 20,
            0, 8, 1, /* 5119: pointer.X509_EXTENSION */
            	2471, 0,
            0, 24, 1, /* 5124: struct.ASN1_ENCODING_st */
            	117, 0,
            0, 16, 1, /* 5129: struct.crypto_ex_data_st */
            	5134, 0,
            1, 8, 1, /* 5134: pointer.struct.stack_st_void */
            	5139, 0,
            0, 32, 1, /* 5139: struct.stack_st_void */
            	5144, 0,
            0, 32, 2, /* 5144: struct.stack_st */
            	1058, 8,
            	125, 24,
            1, 8, 1, /* 5151: pointer.struct.asn1_string_st */
            	5015, 0,
            1, 8, 1, /* 5156: pointer.struct.AUTHORITY_KEYID_st */
            	2544, 0,
            1, 8, 1, /* 5161: pointer.struct.X509_POLICY_CACHE_st */
            	2809, 0,
            1, 8, 1, /* 5166: pointer.struct.stack_st_DIST_POINT */
            	5171, 0,
            0, 32, 2, /* 5171: struct.stack_st_fake_DIST_POINT */
            	5178, 8,
            	125, 24,
            8884099, 8, 2, /* 5178: pointer_to_array_of_pointers_to_stack */
            	5185, 0,
            	122, 20,
            0, 8, 1, /* 5185: pointer.DIST_POINT */
            	3259, 0,
            1, 8, 1, /* 5190: pointer.struct.stack_st_GENERAL_NAME */
            	5195, 0,
            0, 32, 2, /* 5195: struct.stack_st_fake_GENERAL_NAME */
            	5202, 8,
            	125, 24,
            8884099, 8, 2, /* 5202: pointer_to_array_of_pointers_to_stack */
            	5209, 0,
            	122, 20,
            0, 8, 1, /* 5209: pointer.GENERAL_NAME */
            	2587, 0,
            1, 8, 1, /* 5214: pointer.struct.NAME_CONSTRAINTS_st */
            	3403, 0,
            1, 8, 1, /* 5219: pointer.struct.x509_cert_aux_st */
            	5224, 0,
            0, 40, 5, /* 5224: struct.x509_cert_aux_st */
            	5237, 0,
            	5237, 8,
            	5261, 16,
            	5151, 24,
            	5266, 32,
            1, 8, 1, /* 5237: pointer.struct.stack_st_ASN1_OBJECT */
            	5242, 0,
            0, 32, 2, /* 5242: struct.stack_st_fake_ASN1_OBJECT */
            	5249, 8,
            	125, 24,
            8884099, 8, 2, /* 5249: pointer_to_array_of_pointers_to_stack */
            	5256, 0,
            	122, 20,
            0, 8, 1, /* 5256: pointer.ASN1_OBJECT */
            	3121, 0,
            1, 8, 1, /* 5261: pointer.struct.asn1_string_st */
            	5015, 0,
            1, 8, 1, /* 5266: pointer.struct.stack_st_X509_ALGOR */
            	5271, 0,
            0, 32, 2, /* 5271: struct.stack_st_fake_X509_ALGOR */
            	5278, 8,
            	125, 24,
            8884099, 8, 2, /* 5278: pointer_to_array_of_pointers_to_stack */
            	5285, 0,
            	122, 20,
            0, 8, 1, /* 5285: pointer.X509_ALGOR */
            	3781, 0,
            1, 8, 1, /* 5290: pointer.struct.cert_pkey_st */
            	5295, 0,
            0, 24, 3, /* 5295: struct.cert_pkey_st */
            	5304, 0,
            	5646, 8,
            	5729, 16,
            1, 8, 1, /* 5304: pointer.struct.x509_st */
            	5309, 0,
            0, 184, 12, /* 5309: struct.x509_st */
            	5336, 0,
            	5376, 8,
            	5451, 16,
            	138, 32,
            	5485, 40,
            	5507, 104,
            	5512, 112,
            	5517, 120,
            	5522, 128,
            	5546, 136,
            	5570, 144,
            	5575, 176,
            1, 8, 1, /* 5336: pointer.struct.x509_cinf_st */
            	5341, 0,
            0, 104, 11, /* 5341: struct.x509_cinf_st */
            	5366, 0,
            	5366, 8,
            	5376, 16,
            	5381, 24,
            	5429, 32,
            	5381, 40,
            	5446, 48,
            	5451, 56,
            	5451, 64,
            	5456, 72,
            	5480, 80,
            1, 8, 1, /* 5366: pointer.struct.asn1_string_st */
            	5371, 0,
            0, 24, 1, /* 5371: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 5376: pointer.struct.X509_algor_st */
            	342, 0,
            1, 8, 1, /* 5381: pointer.struct.X509_name_st */
            	5386, 0,
            0, 40, 3, /* 5386: struct.X509_name_st */
            	5395, 0,
            	5419, 16,
            	117, 24,
            1, 8, 1, /* 5395: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5400, 0,
            0, 32, 2, /* 5400: struct.stack_st_fake_X509_NAME_ENTRY */
            	5407, 8,
            	125, 24,
            8884099, 8, 2, /* 5407: pointer_to_array_of_pointers_to_stack */
            	5414, 0,
            	122, 20,
            0, 8, 1, /* 5414: pointer.X509_NAME_ENTRY */
            	73, 0,
            1, 8, 1, /* 5419: pointer.struct.buf_mem_st */
            	5424, 0,
            0, 24, 1, /* 5424: struct.buf_mem_st */
            	138, 8,
            1, 8, 1, /* 5429: pointer.struct.X509_val_st */
            	5434, 0,
            0, 16, 2, /* 5434: struct.X509_val_st */
            	5441, 0,
            	5441, 8,
            1, 8, 1, /* 5441: pointer.struct.asn1_string_st */
            	5371, 0,
            1, 8, 1, /* 5446: pointer.struct.X509_pubkey_st */
            	574, 0,
            1, 8, 1, /* 5451: pointer.struct.asn1_string_st */
            	5371, 0,
            1, 8, 1, /* 5456: pointer.struct.stack_st_X509_EXTENSION */
            	5461, 0,
            0, 32, 2, /* 5461: struct.stack_st_fake_X509_EXTENSION */
            	5468, 8,
            	125, 24,
            8884099, 8, 2, /* 5468: pointer_to_array_of_pointers_to_stack */
            	5475, 0,
            	122, 20,
            0, 8, 1, /* 5475: pointer.X509_EXTENSION */
            	2471, 0,
            0, 24, 1, /* 5480: struct.ASN1_ENCODING_st */
            	117, 0,
            0, 16, 1, /* 5485: struct.crypto_ex_data_st */
            	5490, 0,
            1, 8, 1, /* 5490: pointer.struct.stack_st_void */
            	5495, 0,
            0, 32, 1, /* 5495: struct.stack_st_void */
            	5500, 0,
            0, 32, 2, /* 5500: struct.stack_st */
            	1058, 8,
            	125, 24,
            1, 8, 1, /* 5507: pointer.struct.asn1_string_st */
            	5371, 0,
            1, 8, 1, /* 5512: pointer.struct.AUTHORITY_KEYID_st */
            	2544, 0,
            1, 8, 1, /* 5517: pointer.struct.X509_POLICY_CACHE_st */
            	2809, 0,
            1, 8, 1, /* 5522: pointer.struct.stack_st_DIST_POINT */
            	5527, 0,
            0, 32, 2, /* 5527: struct.stack_st_fake_DIST_POINT */
            	5534, 8,
            	125, 24,
            8884099, 8, 2, /* 5534: pointer_to_array_of_pointers_to_stack */
            	5541, 0,
            	122, 20,
            0, 8, 1, /* 5541: pointer.DIST_POINT */
            	3259, 0,
            1, 8, 1, /* 5546: pointer.struct.stack_st_GENERAL_NAME */
            	5551, 0,
            0, 32, 2, /* 5551: struct.stack_st_fake_GENERAL_NAME */
            	5558, 8,
            	125, 24,
            8884099, 8, 2, /* 5558: pointer_to_array_of_pointers_to_stack */
            	5565, 0,
            	122, 20,
            0, 8, 1, /* 5565: pointer.GENERAL_NAME */
            	2587, 0,
            1, 8, 1, /* 5570: pointer.struct.NAME_CONSTRAINTS_st */
            	3403, 0,
            1, 8, 1, /* 5575: pointer.struct.x509_cert_aux_st */
            	5580, 0,
            0, 40, 5, /* 5580: struct.x509_cert_aux_st */
            	5593, 0,
            	5593, 8,
            	5617, 16,
            	5507, 24,
            	5622, 32,
            1, 8, 1, /* 5593: pointer.struct.stack_st_ASN1_OBJECT */
            	5598, 0,
            0, 32, 2, /* 5598: struct.stack_st_fake_ASN1_OBJECT */
            	5605, 8,
            	125, 24,
            8884099, 8, 2, /* 5605: pointer_to_array_of_pointers_to_stack */
            	5612, 0,
            	122, 20,
            0, 8, 1, /* 5612: pointer.ASN1_OBJECT */
            	3121, 0,
            1, 8, 1, /* 5617: pointer.struct.asn1_string_st */
            	5371, 0,
            1, 8, 1, /* 5622: pointer.struct.stack_st_X509_ALGOR */
            	5627, 0,
            0, 32, 2, /* 5627: struct.stack_st_fake_X509_ALGOR */
            	5634, 8,
            	125, 24,
            8884099, 8, 2, /* 5634: pointer_to_array_of_pointers_to_stack */
            	5641, 0,
            	122, 20,
            0, 8, 1, /* 5641: pointer.X509_ALGOR */
            	3781, 0,
            1, 8, 1, /* 5646: pointer.struct.evp_pkey_st */
            	5651, 0,
            0, 56, 4, /* 5651: struct.evp_pkey_st */
            	5662, 16,
            	5667, 24,
            	5672, 32,
            	5705, 48,
            1, 8, 1, /* 5662: pointer.struct.evp_pkey_asn1_method_st */
            	619, 0,
            1, 8, 1, /* 5667: pointer.struct.engine_st */
            	720, 0,
            0, 8, 5, /* 5672: union.unknown */
            	138, 0,
            	5685, 0,
            	5690, 0,
            	5695, 0,
            	5700, 0,
            1, 8, 1, /* 5685: pointer.struct.rsa_st */
            	1086, 0,
            1, 8, 1, /* 5690: pointer.struct.dsa_st */
            	1302, 0,
            1, 8, 1, /* 5695: pointer.struct.dh_st */
            	1441, 0,
            1, 8, 1, /* 5700: pointer.struct.ec_key_st */
            	1567, 0,
            1, 8, 1, /* 5705: pointer.struct.stack_st_X509_ATTRIBUTE */
            	5710, 0,
            0, 32, 2, /* 5710: struct.stack_st_fake_X509_ATTRIBUTE */
            	5717, 8,
            	125, 24,
            8884099, 8, 2, /* 5717: pointer_to_array_of_pointers_to_stack */
            	5724, 0,
            	122, 20,
            0, 8, 1, /* 5724: pointer.X509_ATTRIBUTE */
            	2095, 0,
            1, 8, 1, /* 5729: pointer.struct.env_md_st */
            	5734, 0,
            0, 120, 8, /* 5734: struct.env_md_st */
            	5753, 24,
            	5756, 32,
            	5759, 40,
            	5762, 48,
            	5753, 56,
            	5765, 64,
            	5768, 72,
            	5771, 112,
            8884097, 8, 0, /* 5753: pointer.func */
            8884097, 8, 0, /* 5756: pointer.func */
            8884097, 8, 0, /* 5759: pointer.func */
            8884097, 8, 0, /* 5762: pointer.func */
            8884097, 8, 0, /* 5765: pointer.func */
            8884097, 8, 0, /* 5768: pointer.func */
            8884097, 8, 0, /* 5771: pointer.func */
            1, 8, 1, /* 5774: pointer.struct.rsa_st */
            	1086, 0,
            1, 8, 1, /* 5779: pointer.struct.dh_st */
            	1441, 0,
            1, 8, 1, /* 5784: pointer.struct.ec_key_st */
            	1567, 0,
            1, 8, 1, /* 5789: pointer.struct.x509_st */
            	5794, 0,
            0, 184, 12, /* 5794: struct.x509_st */
            	5821, 0,
            	5861, 8,
            	5936, 16,
            	138, 32,
            	4812, 40,
            	5970, 104,
            	5512, 112,
            	5517, 120,
            	5522, 128,
            	5546, 136,
            	5570, 144,
            	5975, 176,
            1, 8, 1, /* 5821: pointer.struct.x509_cinf_st */
            	5826, 0,
            0, 104, 11, /* 5826: struct.x509_cinf_st */
            	5851, 0,
            	5851, 8,
            	5861, 16,
            	5866, 24,
            	5914, 32,
            	5866, 40,
            	5931, 48,
            	5936, 56,
            	5936, 64,
            	5941, 72,
            	5965, 80,
            1, 8, 1, /* 5851: pointer.struct.asn1_string_st */
            	5856, 0,
            0, 24, 1, /* 5856: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 5861: pointer.struct.X509_algor_st */
            	342, 0,
            1, 8, 1, /* 5866: pointer.struct.X509_name_st */
            	5871, 0,
            0, 40, 3, /* 5871: struct.X509_name_st */
            	5880, 0,
            	5904, 16,
            	117, 24,
            1, 8, 1, /* 5880: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5885, 0,
            0, 32, 2, /* 5885: struct.stack_st_fake_X509_NAME_ENTRY */
            	5892, 8,
            	125, 24,
            8884099, 8, 2, /* 5892: pointer_to_array_of_pointers_to_stack */
            	5899, 0,
            	122, 20,
            0, 8, 1, /* 5899: pointer.X509_NAME_ENTRY */
            	73, 0,
            1, 8, 1, /* 5904: pointer.struct.buf_mem_st */
            	5909, 0,
            0, 24, 1, /* 5909: struct.buf_mem_st */
            	138, 8,
            1, 8, 1, /* 5914: pointer.struct.X509_val_st */
            	5919, 0,
            0, 16, 2, /* 5919: struct.X509_val_st */
            	5926, 0,
            	5926, 8,
            1, 8, 1, /* 5926: pointer.struct.asn1_string_st */
            	5856, 0,
            1, 8, 1, /* 5931: pointer.struct.X509_pubkey_st */
            	574, 0,
            1, 8, 1, /* 5936: pointer.struct.asn1_string_st */
            	5856, 0,
            1, 8, 1, /* 5941: pointer.struct.stack_st_X509_EXTENSION */
            	5946, 0,
            0, 32, 2, /* 5946: struct.stack_st_fake_X509_EXTENSION */
            	5953, 8,
            	125, 24,
            8884099, 8, 2, /* 5953: pointer_to_array_of_pointers_to_stack */
            	5960, 0,
            	122, 20,
            0, 8, 1, /* 5960: pointer.X509_EXTENSION */
            	2471, 0,
            0, 24, 1, /* 5965: struct.ASN1_ENCODING_st */
            	117, 0,
            1, 8, 1, /* 5970: pointer.struct.asn1_string_st */
            	5856, 0,
            1, 8, 1, /* 5975: pointer.struct.x509_cert_aux_st */
            	5980, 0,
            0, 40, 5, /* 5980: struct.x509_cert_aux_st */
            	4776, 0,
            	4776, 8,
            	5993, 16,
            	5970, 24,
            	5998, 32,
            1, 8, 1, /* 5993: pointer.struct.asn1_string_st */
            	5856, 0,
            1, 8, 1, /* 5998: pointer.struct.stack_st_X509_ALGOR */
            	6003, 0,
            0, 32, 2, /* 6003: struct.stack_st_fake_X509_ALGOR */
            	6010, 8,
            	125, 24,
            8884099, 8, 2, /* 6010: pointer_to_array_of_pointers_to_stack */
            	6017, 0,
            	122, 20,
            0, 8, 1, /* 6017: pointer.X509_ALGOR */
            	3781, 0,
            1, 8, 1, /* 6022: pointer.struct.ssl_cipher_st */
            	6027, 0,
            0, 88, 1, /* 6027: struct.ssl_cipher_st */
            	5, 8,
            8884097, 8, 0, /* 6032: pointer.func */
            8884097, 8, 0, /* 6035: pointer.func */
            8884097, 8, 0, /* 6038: pointer.func */
            8884097, 8, 0, /* 6041: pointer.func */
            8884097, 8, 0, /* 6044: pointer.func */
            8884097, 8, 0, /* 6047: pointer.func */
            1, 8, 1, /* 6050: pointer.struct.env_md_st */
            	6055, 0,
            0, 120, 8, /* 6055: struct.env_md_st */
            	6074, 24,
            	6077, 32,
            	6080, 40,
            	6083, 48,
            	6074, 56,
            	5765, 64,
            	5768, 72,
            	6086, 112,
            8884097, 8, 0, /* 6074: pointer.func */
            8884097, 8, 0, /* 6077: pointer.func */
            8884097, 8, 0, /* 6080: pointer.func */
            8884097, 8, 0, /* 6083: pointer.func */
            8884097, 8, 0, /* 6086: pointer.func */
            1, 8, 1, /* 6089: pointer.struct.stack_st_X509 */
            	6094, 0,
            0, 32, 2, /* 6094: struct.stack_st_fake_X509 */
            	6101, 8,
            	125, 24,
            8884099, 8, 2, /* 6101: pointer_to_array_of_pointers_to_stack */
            	6108, 0,
            	122, 20,
            0, 8, 1, /* 6108: pointer.X509 */
            	4948, 0,
            1, 8, 1, /* 6113: pointer.struct.stack_st_SSL_COMP */
            	6118, 0,
            0, 32, 2, /* 6118: struct.stack_st_fake_SSL_COMP */
            	6125, 8,
            	125, 24,
            8884099, 8, 2, /* 6125: pointer_to_array_of_pointers_to_stack */
            	6132, 0,
            	122, 20,
            0, 8, 1, /* 6132: pointer.SSL_COMP */
            	6137, 0,
            0, 0, 1, /* 6137: SSL_COMP */
            	6142, 0,
            0, 24, 2, /* 6142: struct.ssl_comp_st */
            	5, 8,
            	6149, 16,
            1, 8, 1, /* 6149: pointer.struct.comp_method_st */
            	6154, 0,
            0, 64, 7, /* 6154: struct.comp_method_st */
            	5, 8,
            	6171, 16,
            	6174, 24,
            	6177, 32,
            	6177, 40,
            	4417, 48,
            	4417, 56,
            8884097, 8, 0, /* 6171: pointer.func */
            8884097, 8, 0, /* 6174: pointer.func */
            8884097, 8, 0, /* 6177: pointer.func */
            8884097, 8, 0, /* 6180: pointer.func */
            1, 8, 1, /* 6183: pointer.struct.stack_st_X509_NAME */
            	6188, 0,
            0, 32, 2, /* 6188: struct.stack_st_fake_X509_NAME */
            	6195, 8,
            	125, 24,
            8884099, 8, 2, /* 6195: pointer_to_array_of_pointers_to_stack */
            	6202, 0,
            	122, 20,
            0, 8, 1, /* 6202: pointer.X509_NAME */
            	6207, 0,
            0, 0, 1, /* 6207: X509_NAME */
            	6212, 0,
            0, 40, 3, /* 6212: struct.X509_name_st */
            	6221, 0,
            	6245, 16,
            	117, 24,
            1, 8, 1, /* 6221: pointer.struct.stack_st_X509_NAME_ENTRY */
            	6226, 0,
            0, 32, 2, /* 6226: struct.stack_st_fake_X509_NAME_ENTRY */
            	6233, 8,
            	125, 24,
            8884099, 8, 2, /* 6233: pointer_to_array_of_pointers_to_stack */
            	6240, 0,
            	122, 20,
            0, 8, 1, /* 6240: pointer.X509_NAME_ENTRY */
            	73, 0,
            1, 8, 1, /* 6245: pointer.struct.buf_mem_st */
            	6250, 0,
            0, 24, 1, /* 6250: struct.buf_mem_st */
            	138, 8,
            1, 8, 1, /* 6255: pointer.struct.cert_st */
            	6260, 0,
            0, 296, 7, /* 6260: struct.cert_st */
            	6277, 0,
            	6677, 48,
            	6682, 56,
            	6685, 64,
            	6690, 72,
            	5784, 80,
            	6693, 88,
            1, 8, 1, /* 6277: pointer.struct.cert_pkey_st */
            	6282, 0,
            0, 24, 3, /* 6282: struct.cert_pkey_st */
            	6291, 0,
            	6570, 8,
            	6638, 16,
            1, 8, 1, /* 6291: pointer.struct.x509_st */
            	6296, 0,
            0, 184, 12, /* 6296: struct.x509_st */
            	6323, 0,
            	6363, 8,
            	6438, 16,
            	138, 32,
            	6472, 40,
            	6494, 104,
            	5512, 112,
            	5517, 120,
            	5522, 128,
            	5546, 136,
            	5570, 144,
            	6499, 176,
            1, 8, 1, /* 6323: pointer.struct.x509_cinf_st */
            	6328, 0,
            0, 104, 11, /* 6328: struct.x509_cinf_st */
            	6353, 0,
            	6353, 8,
            	6363, 16,
            	6368, 24,
            	6416, 32,
            	6368, 40,
            	6433, 48,
            	6438, 56,
            	6438, 64,
            	6443, 72,
            	6467, 80,
            1, 8, 1, /* 6353: pointer.struct.asn1_string_st */
            	6358, 0,
            0, 24, 1, /* 6358: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 6363: pointer.struct.X509_algor_st */
            	342, 0,
            1, 8, 1, /* 6368: pointer.struct.X509_name_st */
            	6373, 0,
            0, 40, 3, /* 6373: struct.X509_name_st */
            	6382, 0,
            	6406, 16,
            	117, 24,
            1, 8, 1, /* 6382: pointer.struct.stack_st_X509_NAME_ENTRY */
            	6387, 0,
            0, 32, 2, /* 6387: struct.stack_st_fake_X509_NAME_ENTRY */
            	6394, 8,
            	125, 24,
            8884099, 8, 2, /* 6394: pointer_to_array_of_pointers_to_stack */
            	6401, 0,
            	122, 20,
            0, 8, 1, /* 6401: pointer.X509_NAME_ENTRY */
            	73, 0,
            1, 8, 1, /* 6406: pointer.struct.buf_mem_st */
            	6411, 0,
            0, 24, 1, /* 6411: struct.buf_mem_st */
            	138, 8,
            1, 8, 1, /* 6416: pointer.struct.X509_val_st */
            	6421, 0,
            0, 16, 2, /* 6421: struct.X509_val_st */
            	6428, 0,
            	6428, 8,
            1, 8, 1, /* 6428: pointer.struct.asn1_string_st */
            	6358, 0,
            1, 8, 1, /* 6433: pointer.struct.X509_pubkey_st */
            	574, 0,
            1, 8, 1, /* 6438: pointer.struct.asn1_string_st */
            	6358, 0,
            1, 8, 1, /* 6443: pointer.struct.stack_st_X509_EXTENSION */
            	6448, 0,
            0, 32, 2, /* 6448: struct.stack_st_fake_X509_EXTENSION */
            	6455, 8,
            	125, 24,
            8884099, 8, 2, /* 6455: pointer_to_array_of_pointers_to_stack */
            	6462, 0,
            	122, 20,
            0, 8, 1, /* 6462: pointer.X509_EXTENSION */
            	2471, 0,
            0, 24, 1, /* 6467: struct.ASN1_ENCODING_st */
            	117, 0,
            0, 16, 1, /* 6472: struct.crypto_ex_data_st */
            	6477, 0,
            1, 8, 1, /* 6477: pointer.struct.stack_st_void */
            	6482, 0,
            0, 32, 1, /* 6482: struct.stack_st_void */
            	6487, 0,
            0, 32, 2, /* 6487: struct.stack_st */
            	1058, 8,
            	125, 24,
            1, 8, 1, /* 6494: pointer.struct.asn1_string_st */
            	6358, 0,
            1, 8, 1, /* 6499: pointer.struct.x509_cert_aux_st */
            	6504, 0,
            0, 40, 5, /* 6504: struct.x509_cert_aux_st */
            	6517, 0,
            	6517, 8,
            	6541, 16,
            	6494, 24,
            	6546, 32,
            1, 8, 1, /* 6517: pointer.struct.stack_st_ASN1_OBJECT */
            	6522, 0,
            0, 32, 2, /* 6522: struct.stack_st_fake_ASN1_OBJECT */
            	6529, 8,
            	125, 24,
            8884099, 8, 2, /* 6529: pointer_to_array_of_pointers_to_stack */
            	6536, 0,
            	122, 20,
            0, 8, 1, /* 6536: pointer.ASN1_OBJECT */
            	3121, 0,
            1, 8, 1, /* 6541: pointer.struct.asn1_string_st */
            	6358, 0,
            1, 8, 1, /* 6546: pointer.struct.stack_st_X509_ALGOR */
            	6551, 0,
            0, 32, 2, /* 6551: struct.stack_st_fake_X509_ALGOR */
            	6558, 8,
            	125, 24,
            8884099, 8, 2, /* 6558: pointer_to_array_of_pointers_to_stack */
            	6565, 0,
            	122, 20,
            0, 8, 1, /* 6565: pointer.X509_ALGOR */
            	3781, 0,
            1, 8, 1, /* 6570: pointer.struct.evp_pkey_st */
            	6575, 0,
            0, 56, 4, /* 6575: struct.evp_pkey_st */
            	5662, 16,
            	5667, 24,
            	6586, 32,
            	6614, 48,
            0, 8, 5, /* 6586: union.unknown */
            	138, 0,
            	6599, 0,
            	6604, 0,
            	6609, 0,
            	5700, 0,
            1, 8, 1, /* 6599: pointer.struct.rsa_st */
            	1086, 0,
            1, 8, 1, /* 6604: pointer.struct.dsa_st */
            	1302, 0,
            1, 8, 1, /* 6609: pointer.struct.dh_st */
            	1441, 0,
            1, 8, 1, /* 6614: pointer.struct.stack_st_X509_ATTRIBUTE */
            	6619, 0,
            0, 32, 2, /* 6619: struct.stack_st_fake_X509_ATTRIBUTE */
            	6626, 8,
            	125, 24,
            8884099, 8, 2, /* 6626: pointer_to_array_of_pointers_to_stack */
            	6633, 0,
            	122, 20,
            0, 8, 1, /* 6633: pointer.X509_ATTRIBUTE */
            	2095, 0,
            1, 8, 1, /* 6638: pointer.struct.env_md_st */
            	6643, 0,
            0, 120, 8, /* 6643: struct.env_md_st */
            	6662, 24,
            	6665, 32,
            	6668, 40,
            	6671, 48,
            	6662, 56,
            	5765, 64,
            	5768, 72,
            	6674, 112,
            8884097, 8, 0, /* 6662: pointer.func */
            8884097, 8, 0, /* 6665: pointer.func */
            8884097, 8, 0, /* 6668: pointer.func */
            8884097, 8, 0, /* 6671: pointer.func */
            8884097, 8, 0, /* 6674: pointer.func */
            1, 8, 1, /* 6677: pointer.struct.rsa_st */
            	1086, 0,
            8884097, 8, 0, /* 6682: pointer.func */
            1, 8, 1, /* 6685: pointer.struct.dh_st */
            	1441, 0,
            8884097, 8, 0, /* 6690: pointer.func */
            8884097, 8, 0, /* 6693: pointer.func */
            8884097, 8, 0, /* 6696: pointer.func */
            8884097, 8, 0, /* 6699: pointer.func */
            8884097, 8, 0, /* 6702: pointer.func */
            8884097, 8, 0, /* 6705: pointer.func */
            8884097, 8, 0, /* 6708: pointer.func */
            8884097, 8, 0, /* 6711: pointer.func */
            8884097, 8, 0, /* 6714: pointer.func */
            0, 128, 14, /* 6717: struct.srp_ctx_st */
            	15, 0,
            	6702, 8,
            	6708, 16,
            	6748, 24,
            	138, 32,
            	171, 40,
            	171, 48,
            	171, 56,
            	171, 64,
            	171, 72,
            	171, 80,
            	171, 88,
            	171, 96,
            	138, 104,
            8884097, 8, 0, /* 6748: pointer.func */
            8884097, 8, 0, /* 6751: pointer.func */
            1, 8, 1, /* 6754: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	6759, 0,
            0, 32, 2, /* 6759: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	6766, 8,
            	125, 24,
            8884099, 8, 2, /* 6766: pointer_to_array_of_pointers_to_stack */
            	6773, 0,
            	122, 20,
            0, 8, 1, /* 6773: pointer.SRTP_PROTECTION_PROFILE */
            	6778, 0,
            0, 0, 1, /* 6778: SRTP_PROTECTION_PROFILE */
            	6783, 0,
            0, 16, 1, /* 6783: struct.srtp_protection_profile_st */
            	5, 0,
            1, 8, 1, /* 6788: pointer.struct.evp_cipher_ctx_st */
            	6793, 0,
            0, 168, 4, /* 6793: struct.evp_cipher_ctx_st */
            	6804, 0,
            	5667, 8,
            	15, 96,
            	15, 120,
            1, 8, 1, /* 6804: pointer.struct.evp_cipher_st */
            	6809, 0,
            0, 88, 7, /* 6809: struct.evp_cipher_st */
            	6826, 24,
            	6829, 32,
            	6832, 40,
            	6835, 56,
            	6835, 64,
            	6838, 72,
            	15, 80,
            8884097, 8, 0, /* 6826: pointer.func */
            8884097, 8, 0, /* 6829: pointer.func */
            8884097, 8, 0, /* 6832: pointer.func */
            8884097, 8, 0, /* 6835: pointer.func */
            8884097, 8, 0, /* 6838: pointer.func */
            0, 40, 4, /* 6841: struct.dtls1_retransmit_state */
            	6788, 0,
            	6852, 8,
            	7074, 16,
            	7117, 24,
            1, 8, 1, /* 6852: pointer.struct.env_md_ctx_st */
            	6857, 0,
            0, 48, 5, /* 6857: struct.env_md_ctx_st */
            	6050, 0,
            	5667, 8,
            	15, 24,
            	6870, 32,
            	6077, 40,
            1, 8, 1, /* 6870: pointer.struct.evp_pkey_ctx_st */
            	6875, 0,
            0, 80, 8, /* 6875: struct.evp_pkey_ctx_st */
            	6894, 0,
            	1557, 8,
            	6988, 16,
            	6988, 24,
            	15, 40,
            	15, 48,
            	7066, 56,
            	7069, 64,
            1, 8, 1, /* 6894: pointer.struct.evp_pkey_method_st */
            	6899, 0,
            0, 208, 25, /* 6899: struct.evp_pkey_method_st */
            	6952, 8,
            	6955, 16,
            	6958, 24,
            	6952, 32,
            	6961, 40,
            	6952, 48,
            	6961, 56,
            	6952, 64,
            	6964, 72,
            	6952, 80,
            	6967, 88,
            	6952, 96,
            	6964, 104,
            	6970, 112,
            	6973, 120,
            	6970, 128,
            	6976, 136,
            	6952, 144,
            	6964, 152,
            	6952, 160,
            	6964, 168,
            	6952, 176,
            	6979, 184,
            	6982, 192,
            	6985, 200,
            8884097, 8, 0, /* 6952: pointer.func */
            8884097, 8, 0, /* 6955: pointer.func */
            8884097, 8, 0, /* 6958: pointer.func */
            8884097, 8, 0, /* 6961: pointer.func */
            8884097, 8, 0, /* 6964: pointer.func */
            8884097, 8, 0, /* 6967: pointer.func */
            8884097, 8, 0, /* 6970: pointer.func */
            8884097, 8, 0, /* 6973: pointer.func */
            8884097, 8, 0, /* 6976: pointer.func */
            8884097, 8, 0, /* 6979: pointer.func */
            8884097, 8, 0, /* 6982: pointer.func */
            8884097, 8, 0, /* 6985: pointer.func */
            1, 8, 1, /* 6988: pointer.struct.evp_pkey_st */
            	6993, 0,
            0, 56, 4, /* 6993: struct.evp_pkey_st */
            	7004, 16,
            	1557, 24,
            	7009, 32,
            	7042, 48,
            1, 8, 1, /* 7004: pointer.struct.evp_pkey_asn1_method_st */
            	619, 0,
            0, 8, 5, /* 7009: union.unknown */
            	138, 0,
            	7022, 0,
            	7027, 0,
            	7032, 0,
            	7037, 0,
            1, 8, 1, /* 7022: pointer.struct.rsa_st */
            	1086, 0,
            1, 8, 1, /* 7027: pointer.struct.dsa_st */
            	1302, 0,
            1, 8, 1, /* 7032: pointer.struct.dh_st */
            	1441, 0,
            1, 8, 1, /* 7037: pointer.struct.ec_key_st */
            	1567, 0,
            1, 8, 1, /* 7042: pointer.struct.stack_st_X509_ATTRIBUTE */
            	7047, 0,
            0, 32, 2, /* 7047: struct.stack_st_fake_X509_ATTRIBUTE */
            	7054, 8,
            	125, 24,
            8884099, 8, 2, /* 7054: pointer_to_array_of_pointers_to_stack */
            	7061, 0,
            	122, 20,
            0, 8, 1, /* 7061: pointer.X509_ATTRIBUTE */
            	2095, 0,
            8884097, 8, 0, /* 7066: pointer.func */
            1, 8, 1, /* 7069: pointer.int */
            	122, 0,
            1, 8, 1, /* 7074: pointer.struct.comp_ctx_st */
            	7079, 0,
            0, 56, 2, /* 7079: struct.comp_ctx_st */
            	7086, 0,
            	4812, 40,
            1, 8, 1, /* 7086: pointer.struct.comp_method_st */
            	7091, 0,
            0, 64, 7, /* 7091: struct.comp_method_st */
            	5, 8,
            	7108, 16,
            	7111, 24,
            	7114, 32,
            	7114, 40,
            	4417, 48,
            	4417, 56,
            8884097, 8, 0, /* 7108: pointer.func */
            8884097, 8, 0, /* 7111: pointer.func */
            8884097, 8, 0, /* 7114: pointer.func */
            1, 8, 1, /* 7117: pointer.struct.ssl_session_st */
            	4875, 0,
            0, 88, 1, /* 7122: struct.hm_header_st */
            	6841, 48,
            1, 8, 1, /* 7127: pointer.struct._pitem */
            	7132, 0,
            0, 24, 2, /* 7132: struct._pitem */
            	15, 8,
            	7127, 16,
            1, 8, 1, /* 7139: pointer.struct.dtls1_state_st */
            	7144, 0,
            0, 888, 7, /* 7144: struct.dtls1_state_st */
            	7161, 576,
            	7161, 592,
            	7166, 608,
            	7166, 616,
            	7161, 624,
            	7122, 648,
            	7122, 736,
            0, 16, 1, /* 7161: struct.record_pqueue_st */
            	7166, 8,
            1, 8, 1, /* 7166: pointer.struct._pqueue */
            	7171, 0,
            0, 16, 1, /* 7171: struct._pqueue */
            	7176, 0,
            1, 8, 1, /* 7176: pointer.struct._pitem */
            	7132, 0,
            0, 24, 2, /* 7181: struct.ssl_comp_st */
            	5, 8,
            	7086, 16,
            1, 8, 1, /* 7188: pointer.struct.dh_st */
            	1441, 0,
            0, 528, 8, /* 7193: struct.unknown */
            	6022, 408,
            	7188, 416,
            	5784, 424,
            	6183, 464,
            	117, 480,
            	6804, 488,
            	6050, 496,
            	7212, 512,
            1, 8, 1, /* 7212: pointer.struct.ssl_comp_st */
            	7181, 0,
            1, 8, 1, /* 7217: pointer.pointer.struct.env_md_ctx_st */
            	6852, 0,
            0, 56, 3, /* 7222: struct.ssl3_record_st */
            	117, 16,
            	117, 24,
            	117, 32,
            0, 1200, 10, /* 7231: struct.ssl3_state_st */
            	7254, 240,
            	7254, 264,
            	7222, 288,
            	7222, 344,
            	99, 432,
            	7259, 440,
            	7217, 448,
            	15, 496,
            	15, 512,
            	7193, 528,
            0, 24, 1, /* 7254: struct.ssl3_buffer_st */
            	117, 0,
            1, 8, 1, /* 7259: pointer.struct.bio_st */
            	7264, 0,
            0, 112, 7, /* 7264: struct.bio_st */
            	7281, 0,
            	7325, 8,
            	138, 16,
            	15, 48,
            	7328, 56,
            	7328, 64,
            	4812, 96,
            1, 8, 1, /* 7281: pointer.struct.bio_method_st */
            	7286, 0,
            0, 80, 9, /* 7286: struct.bio_method_st */
            	5, 8,
            	7307, 16,
            	7310, 24,
            	7313, 32,
            	7310, 40,
            	7316, 48,
            	7319, 56,
            	7319, 64,
            	7322, 72,
            8884097, 8, 0, /* 7307: pointer.func */
            8884097, 8, 0, /* 7310: pointer.func */
            8884097, 8, 0, /* 7313: pointer.func */
            8884097, 8, 0, /* 7316: pointer.func */
            8884097, 8, 0, /* 7319: pointer.func */
            8884097, 8, 0, /* 7322: pointer.func */
            8884097, 8, 0, /* 7325: pointer.func */
            1, 8, 1, /* 7328: pointer.struct.bio_st */
            	7264, 0,
            1, 8, 1, /* 7333: pointer.struct.ssl3_state_st */
            	7231, 0,
            8884097, 8, 0, /* 7338: pointer.func */
            0, 24, 1, /* 7341: struct.bignum_st */
            	7346, 0,
            8884099, 8, 2, /* 7346: pointer_to_array_of_pointers_to_stack */
            	168, 0,
            	122, 12,
            1, 8, 1, /* 7353: pointer.struct.bignum_st */
            	7341, 0,
            0, 128, 14, /* 7358: struct.srp_ctx_st */
            	15, 0,
            	7389, 8,
            	7392, 16,
            	7395, 24,
            	138, 32,
            	7353, 40,
            	7353, 48,
            	7353, 56,
            	7353, 64,
            	7353, 72,
            	7353, 80,
            	7353, 88,
            	7353, 96,
            	138, 104,
            8884097, 8, 0, /* 7389: pointer.func */
            8884097, 8, 0, /* 7392: pointer.func */
            8884097, 8, 0, /* 7395: pointer.func */
            8884097, 8, 0, /* 7398: pointer.func */
            1, 8, 1, /* 7401: pointer.struct.tls_session_ticket_ext_st */
            	10, 0,
            8884097, 8, 0, /* 7406: pointer.func */
            8884097, 8, 0, /* 7409: pointer.func */
            1, 8, 1, /* 7412: pointer.struct.cert_st */
            	6260, 0,
            1, 8, 1, /* 7417: pointer.struct.stack_st_X509_NAME */
            	7422, 0,
            0, 32, 2, /* 7422: struct.stack_st_fake_X509_NAME */
            	7429, 8,
            	125, 24,
            8884099, 8, 2, /* 7429: pointer_to_array_of_pointers_to_stack */
            	7436, 0,
            	122, 20,
            0, 8, 1, /* 7436: pointer.X509_NAME */
            	6207, 0,
            8884097, 8, 0, /* 7441: pointer.func */
            0, 344, 9, /* 7444: struct.ssl2_state_st */
            	99, 24,
            	117, 56,
            	117, 64,
            	117, 72,
            	117, 104,
            	117, 112,
            	117, 120,
            	117, 128,
            	117, 136,
            1, 8, 1, /* 7465: pointer.struct.stack_st_SSL_COMP */
            	7470, 0,
            0, 32, 2, /* 7470: struct.stack_st_fake_SSL_COMP */
            	7477, 8,
            	125, 24,
            8884099, 8, 2, /* 7477: pointer_to_array_of_pointers_to_stack */
            	7484, 0,
            	122, 20,
            0, 8, 1, /* 7484: pointer.SSL_COMP */
            	6137, 0,
            1, 8, 1, /* 7489: pointer.struct.stack_st_X509 */
            	7494, 0,
            0, 32, 2, /* 7494: struct.stack_st_fake_X509 */
            	7501, 8,
            	125, 24,
            8884099, 8, 2, /* 7501: pointer_to_array_of_pointers_to_stack */
            	7508, 0,
            	122, 20,
            0, 8, 1, /* 7508: pointer.X509 */
            	4948, 0,
            8884097, 8, 0, /* 7513: pointer.func */
            8884097, 8, 0, /* 7516: pointer.func */
            8884097, 8, 0, /* 7519: pointer.func */
            0, 120, 8, /* 7522: struct.env_md_st */
            	7519, 24,
            	7541, 32,
            	7516, 40,
            	7513, 48,
            	7519, 56,
            	5765, 64,
            	5768, 72,
            	7544, 112,
            8884097, 8, 0, /* 7541: pointer.func */
            8884097, 8, 0, /* 7544: pointer.func */
            8884097, 8, 0, /* 7547: pointer.func */
            8884097, 8, 0, /* 7550: pointer.func */
            8884097, 8, 0, /* 7553: pointer.func */
            0, 88, 1, /* 7556: struct.ssl_cipher_st */
            	5, 8,
            0, 40, 5, /* 7561: struct.x509_cert_aux_st */
            	7574, 0,
            	7574, 8,
            	7598, 16,
            	7608, 24,
            	7613, 32,
            1, 8, 1, /* 7574: pointer.struct.stack_st_ASN1_OBJECT */
            	7579, 0,
            0, 32, 2, /* 7579: struct.stack_st_fake_ASN1_OBJECT */
            	7586, 8,
            	125, 24,
            8884099, 8, 2, /* 7586: pointer_to_array_of_pointers_to_stack */
            	7593, 0,
            	122, 20,
            0, 8, 1, /* 7593: pointer.ASN1_OBJECT */
            	3121, 0,
            1, 8, 1, /* 7598: pointer.struct.asn1_string_st */
            	7603, 0,
            0, 24, 1, /* 7603: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 7608: pointer.struct.asn1_string_st */
            	7603, 0,
            1, 8, 1, /* 7613: pointer.struct.stack_st_X509_ALGOR */
            	7618, 0,
            0, 32, 2, /* 7618: struct.stack_st_fake_X509_ALGOR */
            	7625, 8,
            	125, 24,
            8884099, 8, 2, /* 7625: pointer_to_array_of_pointers_to_stack */
            	7632, 0,
            	122, 20,
            0, 8, 1, /* 7632: pointer.X509_ALGOR */
            	3781, 0,
            0, 808, 51, /* 7637: struct.ssl_st */
            	4311, 8,
            	7259, 16,
            	7259, 24,
            	7259, 32,
            	4375, 48,
            	5904, 80,
            	15, 88,
            	117, 104,
            	7742, 120,
            	7333, 128,
            	7139, 136,
            	6696, 152,
            	15, 160,
            	4764, 176,
            	4480, 184,
            	4480, 192,
            	6788, 208,
            	6852, 216,
            	7074, 224,
            	6788, 232,
            	6852, 240,
            	7074, 248,
            	6255, 256,
            	7117, 304,
            	6699, 312,
            	4803, 328,
            	6180, 336,
            	6711, 352,
            	6714, 360,
            	4203, 368,
            	4812, 392,
            	6183, 408,
            	7747, 464,
            	15, 472,
            	138, 480,
            	7750, 504,
            	7774, 512,
            	117, 520,
            	117, 544,
            	117, 560,
            	15, 568,
            	7401, 584,
            	7798, 592,
            	15, 600,
            	7801, 608,
            	15, 616,
            	4203, 624,
            	117, 632,
            	6754, 648,
            	7804, 656,
            	6717, 680,
            1, 8, 1, /* 7742: pointer.struct.ssl2_state_st */
            	7444, 0,
            8884097, 8, 0, /* 7747: pointer.func */
            1, 8, 1, /* 7750: pointer.struct.stack_st_OCSP_RESPID */
            	7755, 0,
            0, 32, 2, /* 7755: struct.stack_st_fake_OCSP_RESPID */
            	7762, 8,
            	125, 24,
            8884099, 8, 2, /* 7762: pointer_to_array_of_pointers_to_stack */
            	7769, 0,
            	122, 20,
            0, 8, 1, /* 7769: pointer.OCSP_RESPID */
            	18, 0,
            1, 8, 1, /* 7774: pointer.struct.stack_st_X509_EXTENSION */
            	7779, 0,
            0, 32, 2, /* 7779: struct.stack_st_fake_X509_EXTENSION */
            	7786, 8,
            	125, 24,
            8884099, 8, 2, /* 7786: pointer_to_array_of_pointers_to_stack */
            	7793, 0,
            	122, 20,
            0, 8, 1, /* 7793: pointer.X509_EXTENSION */
            	2471, 0,
            8884097, 8, 0, /* 7798: pointer.func */
            8884097, 8, 0, /* 7801: pointer.func */
            1, 8, 1, /* 7804: pointer.struct.srtp_protection_profile_st */
            	0, 0,
            1, 8, 1, /* 7809: pointer.struct.x509_cert_aux_st */
            	7561, 0,
            1, 8, 1, /* 7814: pointer.struct.NAME_CONSTRAINTS_st */
            	3403, 0,
            1, 8, 1, /* 7819: pointer.struct.stack_st_GENERAL_NAME */
            	7824, 0,
            0, 32, 2, /* 7824: struct.stack_st_fake_GENERAL_NAME */
            	7831, 8,
            	125, 24,
            8884099, 8, 2, /* 7831: pointer_to_array_of_pointers_to_stack */
            	7838, 0,
            	122, 20,
            0, 8, 1, /* 7838: pointer.GENERAL_NAME */
            	2587, 0,
            1, 8, 1, /* 7843: pointer.struct.stack_st_DIST_POINT */
            	7848, 0,
            0, 32, 2, /* 7848: struct.stack_st_fake_DIST_POINT */
            	7855, 8,
            	125, 24,
            8884099, 8, 2, /* 7855: pointer_to_array_of_pointers_to_stack */
            	7862, 0,
            	122, 20,
            0, 8, 1, /* 7862: pointer.DIST_POINT */
            	3259, 0,
            0, 24, 1, /* 7867: struct.ASN1_ENCODING_st */
            	117, 0,
            1, 8, 1, /* 7872: pointer.struct.stack_st_X509_EXTENSION */
            	7877, 0,
            0, 32, 2, /* 7877: struct.stack_st_fake_X509_EXTENSION */
            	7884, 8,
            	125, 24,
            8884099, 8, 2, /* 7884: pointer_to_array_of_pointers_to_stack */
            	7891, 0,
            	122, 20,
            0, 8, 1, /* 7891: pointer.X509_EXTENSION */
            	2471, 0,
            1, 8, 1, /* 7896: pointer.struct.X509_pubkey_st */
            	574, 0,
            1, 8, 1, /* 7901: pointer.struct.asn1_string_st */
            	7603, 0,
            0, 16, 2, /* 7906: struct.X509_val_st */
            	7901, 0,
            	7901, 8,
            1, 8, 1, /* 7913: pointer.struct.X509_val_st */
            	7906, 0,
            1, 8, 1, /* 7918: pointer.struct.X509_algor_st */
            	342, 0,
            1, 8, 1, /* 7923: pointer.struct.asn1_string_st */
            	7603, 0,
            0, 104, 11, /* 7928: struct.x509_cinf_st */
            	7923, 0,
            	7923, 8,
            	7918, 16,
            	7953, 24,
            	7913, 32,
            	7953, 40,
            	7896, 48,
            	8001, 56,
            	8001, 64,
            	7872, 72,
            	7867, 80,
            1, 8, 1, /* 7953: pointer.struct.X509_name_st */
            	7958, 0,
            0, 40, 3, /* 7958: struct.X509_name_st */
            	7967, 0,
            	7991, 16,
            	117, 24,
            1, 8, 1, /* 7967: pointer.struct.stack_st_X509_NAME_ENTRY */
            	7972, 0,
            0, 32, 2, /* 7972: struct.stack_st_fake_X509_NAME_ENTRY */
            	7979, 8,
            	125, 24,
            8884099, 8, 2, /* 7979: pointer_to_array_of_pointers_to_stack */
            	7986, 0,
            	122, 20,
            0, 8, 1, /* 7986: pointer.X509_NAME_ENTRY */
            	73, 0,
            1, 8, 1, /* 7991: pointer.struct.buf_mem_st */
            	7996, 0,
            0, 24, 1, /* 7996: struct.buf_mem_st */
            	138, 8,
            1, 8, 1, /* 8001: pointer.struct.asn1_string_st */
            	7603, 0,
            1, 8, 1, /* 8006: pointer.struct.ssl_st */
            	7637, 0,
            8884097, 8, 0, /* 8011: pointer.func */
            0, 32, 1, /* 8014: struct.stack_st_void */
            	8019, 0,
            0, 32, 2, /* 8019: struct.stack_st */
            	1058, 8,
            	125, 24,
            0, 16, 1, /* 8026: struct.crypto_ex_data_st */
            	8031, 0,
            1, 8, 1, /* 8031: pointer.struct.stack_st_void */
            	8014, 0,
            8884097, 8, 0, /* 8036: pointer.func */
            8884097, 8, 0, /* 8039: pointer.func */
            1, 8, 1, /* 8042: pointer.struct.sess_cert_st */
            	4911, 0,
            8884097, 8, 0, /* 8047: pointer.func */
            8884097, 8, 0, /* 8050: pointer.func */
            0, 56, 2, /* 8053: struct.X509_VERIFY_PARAM_st */
            	138, 0,
            	7574, 48,
            8884097, 8, 0, /* 8060: pointer.func */
            1, 8, 1, /* 8063: pointer.struct.stack_st_X509_LOOKUP */
            	8068, 0,
            0, 32, 2, /* 8068: struct.stack_st_fake_X509_LOOKUP */
            	8075, 8,
            	125, 24,
            8884099, 8, 2, /* 8075: pointer_to_array_of_pointers_to_stack */
            	8082, 0,
            	122, 20,
            0, 8, 1, /* 8082: pointer.X509_LOOKUP */
            	4576, 0,
            8884097, 8, 0, /* 8087: pointer.func */
            1, 8, 1, /* 8090: pointer.struct.AUTHORITY_KEYID_st */
            	2544, 0,
            1, 8, 1, /* 8095: pointer.struct.x509_st */
            	8100, 0,
            0, 184, 12, /* 8100: struct.x509_st */
            	8127, 0,
            	7918, 8,
            	8001, 16,
            	138, 32,
            	8026, 40,
            	7608, 104,
            	8090, 112,
            	5517, 120,
            	7843, 128,
            	7819, 136,
            	7814, 144,
            	7809, 176,
            1, 8, 1, /* 8127: pointer.struct.x509_cinf_st */
            	7928, 0,
            8884097, 8, 0, /* 8132: pointer.func */
            8884097, 8, 0, /* 8135: pointer.func */
            8884097, 8, 0, /* 8138: pointer.func */
            0, 144, 15, /* 8141: struct.x509_store_st */
            	8174, 8,
            	8063, 16,
            	8198, 24,
            	8050, 32,
            	8138, 40,
            	8203, 48,
            	8206, 56,
            	8050, 64,
            	8047, 72,
            	8039, 80,
            	8209, 88,
            	8036, 96,
            	8212, 104,
            	8050, 112,
            	8026, 120,
            1, 8, 1, /* 8174: pointer.struct.stack_st_X509_OBJECT */
            	8179, 0,
            0, 32, 2, /* 8179: struct.stack_st_fake_X509_OBJECT */
            	8186, 8,
            	125, 24,
            8884099, 8, 2, /* 8186: pointer_to_array_of_pointers_to_stack */
            	8193, 0,
            	122, 20,
            0, 8, 1, /* 8193: pointer.X509_OBJECT */
            	244, 0,
            1, 8, 1, /* 8198: pointer.struct.X509_VERIFY_PARAM_st */
            	8053, 0,
            8884097, 8, 0, /* 8203: pointer.func */
            8884097, 8, 0, /* 8206: pointer.func */
            8884097, 8, 0, /* 8209: pointer.func */
            8884097, 8, 0, /* 8212: pointer.func */
            8884097, 8, 0, /* 8215: pointer.func */
            8884097, 8, 0, /* 8218: pointer.func */
            8884097, 8, 0, /* 8221: pointer.func */
            8884097, 8, 0, /* 8224: pointer.func */
            1, 8, 1, /* 8227: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	8232, 0,
            0, 32, 2, /* 8232: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	8239, 8,
            	125, 24,
            8884099, 8, 2, /* 8239: pointer_to_array_of_pointers_to_stack */
            	8246, 0,
            	122, 20,
            0, 8, 1, /* 8246: pointer.SRTP_PROTECTION_PROFILE */
            	6778, 0,
            1, 8, 1, /* 8251: pointer.struct.x509_store_st */
            	8141, 0,
            1, 8, 1, /* 8256: pointer.struct.stack_st_SSL_CIPHER */
            	8261, 0,
            0, 32, 2, /* 8261: struct.stack_st_fake_SSL_CIPHER */
            	8268, 8,
            	125, 24,
            8884099, 8, 2, /* 8268: pointer_to_array_of_pointers_to_stack */
            	8275, 0,
            	122, 20,
            0, 8, 1, /* 8275: pointer.SSL_CIPHER */
            	4504, 0,
            8884097, 8, 0, /* 8280: pointer.func */
            0, 1, 0, /* 8283: char */
            0, 232, 28, /* 8286: struct.ssl_method_st */
            	8132, 8,
            	8345, 16,
            	8345, 24,
            	8132, 32,
            	8132, 40,
            	8348, 48,
            	8348, 56,
            	8351, 64,
            	8132, 72,
            	8132, 80,
            	8132, 88,
            	8280, 96,
            	8218, 104,
            	8354, 112,
            	8132, 120,
            	8357, 128,
            	8215, 136,
            	8360, 144,
            	8221, 152,
            	8363, 160,
            	989, 168,
            	8224, 176,
            	8135, 184,
            	4417, 192,
            	8366, 200,
            	989, 208,
            	8371, 216,
            	8374, 224,
            8884097, 8, 0, /* 8345: pointer.func */
            8884097, 8, 0, /* 8348: pointer.func */
            8884097, 8, 0, /* 8351: pointer.func */
            8884097, 8, 0, /* 8354: pointer.func */
            8884097, 8, 0, /* 8357: pointer.func */
            8884097, 8, 0, /* 8360: pointer.func */
            8884097, 8, 0, /* 8363: pointer.func */
            1, 8, 1, /* 8366: pointer.struct.ssl3_enc_method */
            	4425, 0,
            8884097, 8, 0, /* 8371: pointer.func */
            8884097, 8, 0, /* 8374: pointer.func */
            0, 736, 50, /* 8377: struct.ssl_ctx_st */
            	8480, 0,
            	8256, 8,
            	8256, 16,
            	8251, 24,
            	4834, 32,
            	8485, 48,
            	8485, 56,
            	8060, 80,
            	8011, 88,
            	7553, 96,
            	8087, 152,
            	15, 160,
            	6041, 168,
            	15, 176,
            	8526, 184,
            	7550, 192,
            	7547, 200,
            	8026, 208,
            	8529, 224,
            	8529, 232,
            	8529, 240,
            	7489, 248,
            	7465, 256,
            	7441, 264,
            	7417, 272,
            	7412, 304,
            	8534, 320,
            	15, 328,
            	8138, 376,
            	8537, 384,
            	8198, 392,
            	5667, 408,
            	7389, 416,
            	15, 424,
            	7398, 480,
            	7392, 488,
            	15, 496,
            	7406, 504,
            	15, 512,
            	138, 520,
            	7409, 528,
            	8540, 536,
            	8543, 552,
            	8543, 560,
            	7358, 568,
            	7338, 696,
            	15, 704,
            	8548, 712,
            	15, 720,
            	8227, 728,
            1, 8, 1, /* 8480: pointer.struct.ssl_method_st */
            	8286, 0,
            1, 8, 1, /* 8485: pointer.struct.ssl_session_st */
            	8490, 0,
            0, 352, 14, /* 8490: struct.ssl_session_st */
            	138, 144,
            	138, 152,
            	8042, 168,
            	8095, 176,
            	8521, 224,
            	8256, 240,
            	8026, 248,
            	8485, 264,
            	8485, 272,
            	138, 280,
            	117, 296,
            	117, 312,
            	117, 320,
            	138, 344,
            1, 8, 1, /* 8521: pointer.struct.ssl_cipher_st */
            	7556, 0,
            8884097, 8, 0, /* 8526: pointer.func */
            1, 8, 1, /* 8529: pointer.struct.env_md_st */
            	7522, 0,
            8884097, 8, 0, /* 8534: pointer.func */
            8884097, 8, 0, /* 8537: pointer.func */
            8884097, 8, 0, /* 8540: pointer.func */
            1, 8, 1, /* 8543: pointer.struct.ssl3_buf_freelist_st */
            	181, 0,
            8884097, 8, 0, /* 8548: pointer.func */
            1, 8, 1, /* 8551: pointer.struct.ssl_ctx_st */
            	8377, 0,
        },
        .arg_entity_index = { 8006, },
        .ret_entity_index = 8551,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL * new_arg_a = *((const SSL * *)new_args->args[0]);

    SSL_CTX * *new_ret_ptr = (SSL_CTX * *)new_args->ret;

    SSL_CTX * (*orig_SSL_get_SSL_CTX)(const SSL *);
    orig_SSL_get_SSL_CTX = dlsym(RTLD_NEXT, "SSL_get_SSL_CTX");
    *new_ret_ptr = (*orig_SSL_get_SSL_CTX)(new_arg_a);

    syscall(889);

    return ret;
}

