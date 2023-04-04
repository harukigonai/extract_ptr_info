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
            0, 16, 1, /* 0: struct.tls_session_ticket_ext_st */
            	5, 8,
            0, 8, 0, /* 5: pointer.void */
            4097, 8, 0, /* 8: pointer.func */
            4097, 8, 0, /* 11: pointer.func */
            1, 8, 1, /* 14: pointer.struct.ssl3_buf_freelist_entry_st */
            	19, 0,
            0, 8, 1, /* 19: struct.ssl3_buf_freelist_entry_st */
            	14, 0,
            4097, 8, 0, /* 24: pointer.func */
            4097, 8, 0, /* 27: pointer.func */
            4097, 8, 0, /* 30: pointer.func */
            4097, 8, 0, /* 33: pointer.func */
            4097, 8, 0, /* 36: pointer.func */
            1, 8, 1, /* 39: pointer.struct.lhash_node_st */
            	44, 0,
            0, 24, 2, /* 44: struct.lhash_node_st */
            	5, 0,
            	39, 8,
            0, 176, 3, /* 51: struct.lhash_st */
            	60, 0,
            	65, 8,
            	36, 16,
            1, 8, 1, /* 60: pointer.pointer.struct.lhash_node_st */
            	39, 0,
            4097, 8, 0, /* 65: pointer.func */
            1, 8, 1, /* 68: pointer.struct.lhash_st */
            	51, 0,
            4097, 8, 0, /* 73: pointer.func */
            4097, 8, 0, /* 76: pointer.func */
            4097, 8, 0, /* 79: pointer.func */
            4097, 8, 0, /* 82: pointer.func */
            4097, 8, 0, /* 85: pointer.func */
            4097, 8, 0, /* 88: pointer.func */
            4097, 8, 0, /* 91: pointer.func */
            4097, 8, 0, /* 94: pointer.func */
            4097, 8, 0, /* 97: pointer.func */
            4097, 8, 0, /* 100: pointer.func */
            4097, 8, 0, /* 103: pointer.func */
            4097, 8, 0, /* 106: pointer.func */
            0, 296, 8, /* 109: struct.cert_st */
            	128, 0,
            	897, 48,
            	998, 56,
            	1001, 64,
            	106, 72,
            	1033, 80,
            	103, 88,
            	1269, 96,
            1, 8, 1, /* 128: pointer.struct.cert_pkey_st */
            	133, 0,
            0, 24, 3, /* 133: struct.cert_pkey_st */
            	142, 0,
            	332, 8,
            	852, 16,
            1, 8, 1, /* 142: pointer.struct.x509_st */
            	147, 0,
            0, 184, 12, /* 147: struct.x509_st */
            	174, 0,
            	219, 8,
            	204, 16,
            	214, 32,
            	772, 40,
            	204, 104,
            	782, 112,
            	796, 120,
            	274, 128,
            	274, 136,
            	822, 144,
            	834, 176,
            1, 8, 1, /* 174: pointer.struct.x509_cinf_st */
            	179, 0,
            0, 104, 11, /* 179: struct.x509_cinf_st */
            	204, 0,
            	204, 8,
            	219, 16,
            	260, 24,
            	306, 32,
            	260, 40,
            	318, 48,
            	204, 56,
            	204, 64,
            	274, 72,
            	777, 80,
            1, 8, 1, /* 204: pointer.struct.asn1_string_st */
            	209, 0,
            0, 24, 1, /* 209: struct.asn1_string_st */
            	214, 8,
            1, 8, 1, /* 214: pointer.char */
            	4096, 0,
            1, 8, 1, /* 219: pointer.struct.X509_algor_st */
            	224, 0,
            0, 16, 2, /* 224: struct.X509_algor_st */
            	231, 0,
            	245, 8,
            1, 8, 1, /* 231: pointer.struct.asn1_object_st */
            	236, 0,
            0, 40, 3, /* 236: struct.asn1_object_st */
            	214, 0,
            	214, 8,
            	214, 24,
            1, 8, 1, /* 245: pointer.struct.asn1_type_st */
            	250, 0,
            0, 16, 1, /* 250: struct.asn1_type_st */
            	255, 8,
            0, 8, 1, /* 255: struct.fnames */
            	214, 0,
            1, 8, 1, /* 260: pointer.struct.X509_name_st */
            	265, 0,
            0, 40, 3, /* 265: struct.X509_name_st */
            	274, 0,
            	296, 16,
            	214, 24,
            1, 8, 1, /* 274: pointer.struct.stack_st_OPENSSL_STRING */
            	279, 0,
            0, 32, 1, /* 279: struct.stack_st_OPENSSL_STRING */
            	284, 0,
            0, 32, 2, /* 284: struct.stack_st */
            	291, 8,
            	65, 24,
            1, 8, 1, /* 291: pointer.pointer.char */
            	214, 0,
            1, 8, 1, /* 296: pointer.struct.buf_mem_st */
            	301, 0,
            0, 24, 1, /* 301: struct.buf_mem_st */
            	214, 8,
            1, 8, 1, /* 306: pointer.struct.X509_val_st */
            	311, 0,
            0, 16, 2, /* 311: struct.X509_val_st */
            	204, 0,
            	204, 8,
            1, 8, 1, /* 318: pointer.struct.X509_pubkey_st */
            	323, 0,
            0, 24, 3, /* 323: struct.X509_pubkey_st */
            	219, 0,
            	204, 8,
            	332, 16,
            1, 8, 1, /* 332: pointer.struct.evp_pkey_st */
            	337, 0,
            0, 56, 4, /* 337: struct.evp_pkey_st */
            	348, 16,
            	451, 24,
            	255, 32,
            	274, 48,
            1, 8, 1, /* 348: pointer.struct.evp_pkey_asn1_method_st */
            	353, 0,
            0, 208, 24, /* 353: struct.evp_pkey_asn1_method_st */
            	214, 16,
            	214, 24,
            	404, 32,
            	412, 40,
            	415, 48,
            	418, 56,
            	421, 64,
            	424, 72,
            	418, 80,
            	427, 88,
            	427, 96,
            	430, 104,
            	433, 112,
            	427, 120,
            	415, 128,
            	415, 136,
            	418, 144,
            	436, 152,
            	439, 160,
            	442, 168,
            	430, 176,
            	433, 184,
            	445, 192,
            	448, 200,
            1, 8, 1, /* 404: pointer.struct.unnamed */
            	409, 0,
            0, 0, 0, /* 409: struct.unnamed */
            4097, 8, 0, /* 412: pointer.func */
            4097, 8, 0, /* 415: pointer.func */
            4097, 8, 0, /* 418: pointer.func */
            4097, 8, 0, /* 421: pointer.func */
            4097, 8, 0, /* 424: pointer.func */
            4097, 8, 0, /* 427: pointer.func */
            4097, 8, 0, /* 430: pointer.func */
            4097, 8, 0, /* 433: pointer.func */
            4097, 8, 0, /* 436: pointer.func */
            4097, 8, 0, /* 439: pointer.func */
            4097, 8, 0, /* 442: pointer.func */
            4097, 8, 0, /* 445: pointer.func */
            4097, 8, 0, /* 448: pointer.func */
            1, 8, 1, /* 451: pointer.struct.engine_st */
            	456, 0,
            0, 216, 24, /* 456: struct.engine_st */
            	214, 0,
            	214, 8,
            	507, 16,
            	562, 24,
            	613, 32,
            	649, 40,
            	666, 48,
            	693, 56,
            	728, 64,
            	736, 72,
            	739, 80,
            	742, 88,
            	745, 96,
            	748, 104,
            	748, 112,
            	748, 120,
            	751, 128,
            	754, 136,
            	754, 144,
            	757, 152,
            	760, 160,
            	772, 184,
            	451, 200,
            	451, 208,
            1, 8, 1, /* 507: pointer.struct.rsa_meth_st */
            	512, 0,
            0, 112, 13, /* 512: struct.rsa_meth_st */
            	214, 0,
            	541, 8,
            	541, 16,
            	541, 24,
            	541, 32,
            	544, 40,
            	547, 48,
            	550, 56,
            	550, 64,
            	214, 80,
            	553, 88,
            	556, 96,
            	559, 104,
            4097, 8, 0, /* 541: pointer.func */
            4097, 8, 0, /* 544: pointer.func */
            4097, 8, 0, /* 547: pointer.func */
            4097, 8, 0, /* 550: pointer.func */
            4097, 8, 0, /* 553: pointer.func */
            4097, 8, 0, /* 556: pointer.func */
            4097, 8, 0, /* 559: pointer.func */
            1, 8, 1, /* 562: pointer.struct.dsa_method */
            	567, 0,
            0, 96, 11, /* 567: struct.dsa_method */
            	214, 0,
            	592, 8,
            	595, 16,
            	598, 24,
            	601, 32,
            	604, 40,
            	607, 48,
            	607, 56,
            	214, 72,
            	610, 80,
            	607, 88,
            4097, 8, 0, /* 592: pointer.func */
            4097, 8, 0, /* 595: pointer.func */
            4097, 8, 0, /* 598: pointer.func */
            4097, 8, 0, /* 601: pointer.func */
            4097, 8, 0, /* 604: pointer.func */
            4097, 8, 0, /* 607: pointer.func */
            4097, 8, 0, /* 610: pointer.func */
            1, 8, 1, /* 613: pointer.struct.dh_method */
            	618, 0,
            0, 72, 8, /* 618: struct.dh_method */
            	214, 0,
            	637, 8,
            	640, 16,
            	643, 24,
            	637, 32,
            	637, 40,
            	214, 56,
            	646, 64,
            4097, 8, 0, /* 637: pointer.func */
            4097, 8, 0, /* 640: pointer.func */
            4097, 8, 0, /* 643: pointer.func */
            4097, 8, 0, /* 646: pointer.func */
            1, 8, 1, /* 649: pointer.struct.ecdh_method */
            	654, 0,
            0, 32, 3, /* 654: struct.ecdh_method */
            	214, 0,
            	663, 8,
            	214, 24,
            4097, 8, 0, /* 663: pointer.func */
            1, 8, 1, /* 666: pointer.struct.ecdsa_method */
            	671, 0,
            0, 48, 5, /* 671: struct.ecdsa_method */
            	214, 0,
            	684, 8,
            	687, 16,
            	690, 24,
            	214, 40,
            4097, 8, 0, /* 684: pointer.func */
            4097, 8, 0, /* 687: pointer.func */
            4097, 8, 0, /* 690: pointer.func */
            1, 8, 1, /* 693: pointer.struct.rand_meth_st */
            	698, 0,
            0, 48, 6, /* 698: struct.rand_meth_st */
            	713, 0,
            	716, 8,
            	719, 16,
            	722, 24,
            	716, 32,
            	725, 40,
            4097, 8, 0, /* 713: pointer.func */
            4097, 8, 0, /* 716: pointer.func */
            4097, 8, 0, /* 719: pointer.func */
            4097, 8, 0, /* 722: pointer.func */
            4097, 8, 0, /* 725: pointer.func */
            1, 8, 1, /* 728: pointer.struct.store_method_st */
            	733, 0,
            0, 0, 0, /* 733: struct.store_method_st */
            4097, 8, 0, /* 736: pointer.func */
            4097, 8, 0, /* 739: pointer.func */
            4097, 8, 0, /* 742: pointer.func */
            4097, 8, 0, /* 745: pointer.func */
            4097, 8, 0, /* 748: pointer.func */
            4097, 8, 0, /* 751: pointer.func */
            4097, 8, 0, /* 754: pointer.func */
            4097, 8, 0, /* 757: pointer.func */
            1, 8, 1, /* 760: pointer.struct.ENGINE_CMD_DEFN_st */
            	765, 0,
            0, 32, 2, /* 765: struct.ENGINE_CMD_DEFN_st */
            	214, 8,
            	214, 16,
            0, 16, 1, /* 772: struct.crypto_ex_data_st */
            	274, 0,
            0, 24, 1, /* 777: struct.ASN1_ENCODING_st */
            	214, 0,
            1, 8, 1, /* 782: pointer.struct.AUTHORITY_KEYID_st */
            	787, 0,
            0, 24, 3, /* 787: struct.AUTHORITY_KEYID_st */
            	204, 0,
            	274, 8,
            	204, 16,
            1, 8, 1, /* 796: pointer.struct.X509_POLICY_CACHE_st */
            	801, 0,
            0, 40, 2, /* 801: struct.X509_POLICY_CACHE_st */
            	808, 0,
            	274, 8,
            1, 8, 1, /* 808: pointer.struct.X509_POLICY_DATA_st */
            	813, 0,
            0, 32, 3, /* 813: struct.X509_POLICY_DATA_st */
            	231, 8,
            	274, 16,
            	274, 24,
            1, 8, 1, /* 822: pointer.struct.NAME_CONSTRAINTS_st */
            	827, 0,
            0, 16, 2, /* 827: struct.NAME_CONSTRAINTS_st */
            	274, 0,
            	274, 8,
            1, 8, 1, /* 834: pointer.struct.x509_cert_aux_st */
            	839, 0,
            0, 40, 5, /* 839: struct.x509_cert_aux_st */
            	274, 0,
            	274, 8,
            	204, 16,
            	204, 24,
            	274, 32,
            1, 8, 1, /* 852: pointer.struct.env_md_st */
            	857, 0,
            0, 120, 8, /* 857: struct.env_md_st */
            	876, 24,
            	879, 32,
            	882, 40,
            	885, 48,
            	876, 56,
            	888, 64,
            	891, 72,
            	894, 112,
            4097, 8, 0, /* 876: pointer.func */
            4097, 8, 0, /* 879: pointer.func */
            4097, 8, 0, /* 882: pointer.func */
            4097, 8, 0, /* 885: pointer.func */
            4097, 8, 0, /* 888: pointer.func */
            4097, 8, 0, /* 891: pointer.func */
            4097, 8, 0, /* 894: pointer.func */
            1, 8, 1, /* 897: pointer.struct.rsa_st */
            	902, 0,
            0, 168, 17, /* 902: struct.rsa_st */
            	507, 16,
            	451, 24,
            	939, 32,
            	939, 40,
            	939, 48,
            	939, 56,
            	939, 64,
            	939, 72,
            	939, 80,
            	939, 88,
            	772, 96,
            	957, 120,
            	957, 128,
            	957, 136,
            	214, 144,
            	971, 152,
            	971, 160,
            1, 8, 1, /* 939: pointer.struct.bignum_st */
            	944, 0,
            0, 24, 1, /* 944: struct.bignum_st */
            	949, 0,
            1, 8, 1, /* 949: pointer.int */
            	954, 0,
            0, 4, 0, /* 954: int */
            1, 8, 1, /* 957: pointer.struct.bn_mont_ctx_st */
            	962, 0,
            0, 96, 3, /* 962: struct.bn_mont_ctx_st */
            	944, 8,
            	944, 32,
            	944, 56,
            1, 8, 1, /* 971: pointer.struct.bn_blinding_st */
            	976, 0,
            0, 88, 7, /* 976: struct.bn_blinding_st */
            	939, 0,
            	939, 8,
            	939, 16,
            	939, 24,
            	993, 40,
            	957, 72,
            	547, 80,
            0, 16, 1, /* 993: struct.iovec */
            	214, 0,
            4097, 8, 0, /* 998: pointer.func */
            1, 8, 1, /* 1001: pointer.struct.dh_st */
            	1006, 0,
            0, 144, 12, /* 1006: struct.dh_st */
            	939, 8,
            	939, 16,
            	939, 32,
            	939, 40,
            	957, 56,
            	939, 64,
            	939, 72,
            	214, 80,
            	939, 96,
            	772, 112,
            	613, 128,
            	451, 136,
            1, 8, 1, /* 1033: pointer.struct.ec_key_st */
            	1038, 0,
            0, 56, 4, /* 1038: struct.ec_key_st */
            	1049, 8,
            	1226, 16,
            	939, 24,
            	1242, 48,
            1, 8, 1, /* 1049: pointer.struct.ec_group_st */
            	1054, 0,
            0, 232, 12, /* 1054: struct.ec_group_st */
            	1081, 0,
            	1226, 8,
            	944, 16,
            	944, 40,
            	214, 80,
            	1242, 96,
            	944, 104,
            	944, 152,
            	944, 176,
            	214, 208,
            	214, 216,
            	1266, 224,
            1, 8, 1, /* 1081: pointer.struct.ec_method_st */
            	1086, 0,
            0, 304, 37, /* 1086: struct.ec_method_st */
            	1163, 8,
            	1166, 16,
            	1166, 24,
            	1169, 32,
            	1172, 40,
            	1172, 48,
            	1163, 56,
            	1175, 64,
            	1178, 72,
            	1181, 80,
            	1181, 88,
            	1184, 96,
            	1187, 104,
            	1190, 112,
            	1190, 120,
            	1193, 128,
            	1193, 136,
            	1196, 144,
            	1199, 152,
            	1202, 160,
            	1205, 168,
            	1208, 176,
            	1211, 184,
            	1187, 192,
            	1211, 200,
            	1208, 208,
            	1211, 216,
            	1214, 224,
            	1217, 232,
            	1175, 240,
            	1163, 248,
            	1172, 256,
            	1220, 264,
            	1172, 272,
            	1220, 280,
            	1220, 288,
            	1223, 296,
            4097, 8, 0, /* 1163: pointer.func */
            4097, 8, 0, /* 1166: pointer.func */
            4097, 8, 0, /* 1169: pointer.func */
            4097, 8, 0, /* 1172: pointer.func */
            4097, 8, 0, /* 1175: pointer.func */
            4097, 8, 0, /* 1178: pointer.func */
            4097, 8, 0, /* 1181: pointer.func */
            4097, 8, 0, /* 1184: pointer.func */
            4097, 8, 0, /* 1187: pointer.func */
            4097, 8, 0, /* 1190: pointer.func */
            4097, 8, 0, /* 1193: pointer.func */
            4097, 8, 0, /* 1196: pointer.func */
            4097, 8, 0, /* 1199: pointer.func */
            4097, 8, 0, /* 1202: pointer.func */
            4097, 8, 0, /* 1205: pointer.func */
            4097, 8, 0, /* 1208: pointer.func */
            4097, 8, 0, /* 1211: pointer.func */
            4097, 8, 0, /* 1214: pointer.func */
            4097, 8, 0, /* 1217: pointer.func */
            4097, 8, 0, /* 1220: pointer.func */
            4097, 8, 0, /* 1223: pointer.func */
            1, 8, 1, /* 1226: pointer.struct.ec_point_st */
            	1231, 0,
            0, 88, 4, /* 1231: struct.ec_point_st */
            	1081, 0,
            	944, 8,
            	944, 32,
            	944, 56,
            1, 8, 1, /* 1242: pointer.struct.ec_extra_data_st */
            	1247, 0,
            0, 40, 5, /* 1247: struct.ec_extra_data_st */
            	1242, 0,
            	5, 8,
            	1260, 16,
            	1263, 24,
            	1263, 32,
            4097, 8, 0, /* 1260: pointer.func */
            4097, 8, 0, /* 1263: pointer.func */
            4097, 8, 0, /* 1266: pointer.func */
            0, 192, 8, /* 1269: array[8].struct.cert_pkey_st */
            	133, 0,
            	133, 24,
            	133, 48,
            	133, 72,
            	133, 96,
            	133, 120,
            	133, 144,
            	133, 168,
            1, 8, 1, /* 1288: pointer.struct.cert_st */
            	109, 0,
            1, 8, 1, /* 1293: pointer.struct.X509_VERIFY_PARAM_st */
            	1298, 0,
            0, 56, 2, /* 1298: struct.X509_VERIFY_PARAM_st */
            	214, 0,
            	274, 48,
            4097, 8, 0, /* 1305: pointer.func */
            1, 8, 1, /* 1308: pointer.struct.ssl3_buf_freelist_st */
            	1313, 0,
            0, 24, 1, /* 1313: struct.ssl3_buf_freelist_st */
            	14, 16,
            0, 128, 14, /* 1318: struct.srp_ctx_st */
            	214, 0,
            	1349, 8,
            	24, 16,
            	11, 24,
            	214, 32,
            	939, 40,
            	939, 48,
            	939, 56,
            	939, 64,
            	939, 72,
            	939, 80,
            	939, 88,
            	939, 96,
            	214, 104,
            4097, 8, 0, /* 1349: pointer.func */
            4097, 8, 0, /* 1352: pointer.func */
            4097, 8, 0, /* 1355: pointer.func */
            1, 8, 1, /* 1358: pointer.struct.ssl_comp_st */
            	1363, 0,
            0, 24, 2, /* 1363: struct.ssl_comp_st */
            	214, 8,
            	1370, 16,
            1, 8, 1, /* 1370: pointer.struct.comp_method_st */
            	1375, 0,
            0, 64, 7, /* 1375: struct.comp_method_st */
            	214, 8,
            	1392, 16,
            	1395, 24,
            	1398, 32,
            	1398, 40,
            	1401, 48,
            	1401, 56,
            4097, 8, 0, /* 1392: pointer.func */
            4097, 8, 0, /* 1395: pointer.func */
            4097, 8, 0, /* 1398: pointer.func */
            4097, 8, 0, /* 1401: pointer.func */
            1, 8, 1, /* 1404: pointer.struct.evp_pkey_method_st */
            	1409, 0,
            0, 208, 25, /* 1409: struct.evp_pkey_method_st */
            	404, 8,
            	1355, 16,
            	1462, 24,
            	404, 32,
            	1465, 40,
            	404, 48,
            	1465, 56,
            	404, 64,
            	1468, 72,
            	404, 80,
            	1471, 88,
            	404, 96,
            	1468, 104,
            	1474, 112,
            	1477, 120,
            	1474, 128,
            	1480, 136,
            	404, 144,
            	1468, 152,
            	404, 160,
            	1468, 168,
            	404, 176,
            	1483, 184,
            	1486, 192,
            	1489, 200,
            4097, 8, 0, /* 1462: pointer.func */
            4097, 8, 0, /* 1465: pointer.func */
            4097, 8, 0, /* 1468: pointer.func */
            4097, 8, 0, /* 1471: pointer.func */
            4097, 8, 0, /* 1474: pointer.func */
            4097, 8, 0, /* 1477: pointer.func */
            4097, 8, 0, /* 1480: pointer.func */
            4097, 8, 0, /* 1483: pointer.func */
            4097, 8, 0, /* 1486: pointer.func */
            4097, 8, 0, /* 1489: pointer.func */
            0, 80, 8, /* 1492: struct.evp_pkey_ctx_st */
            	1404, 0,
            	451, 8,
            	332, 16,
            	332, 24,
            	214, 40,
            	214, 48,
            	404, 56,
            	949, 64,
            1, 8, 1, /* 1511: pointer.struct.ssl_method_st */
            	1516, 0,
            0, 232, 28, /* 1516: struct.ssl_method_st */
            	1575, 8,
            	1578, 16,
            	1578, 24,
            	1575, 32,
            	1575, 40,
            	1581, 48,
            	1581, 56,
            	1581, 64,
            	1575, 72,
            	1575, 80,
            	1575, 88,
            	1584, 96,
            	1587, 104,
            	1590, 112,
            	1575, 120,
            	1593, 128,
            	1596, 136,
            	1599, 144,
            	1602, 152,
            	1575, 160,
            	725, 168,
            	1605, 176,
            	1608, 184,
            	1401, 192,
            	1611, 200,
            	725, 208,
            	1656, 216,
            	1659, 224,
            4097, 8, 0, /* 1575: pointer.func */
            4097, 8, 0, /* 1578: pointer.func */
            4097, 8, 0, /* 1581: pointer.func */
            4097, 8, 0, /* 1584: pointer.func */
            4097, 8, 0, /* 1587: pointer.func */
            4097, 8, 0, /* 1590: pointer.func */
            4097, 8, 0, /* 1593: pointer.func */
            4097, 8, 0, /* 1596: pointer.func */
            4097, 8, 0, /* 1599: pointer.func */
            4097, 8, 0, /* 1602: pointer.func */
            4097, 8, 0, /* 1605: pointer.func */
            4097, 8, 0, /* 1608: pointer.func */
            1, 8, 1, /* 1611: pointer.struct.ssl3_enc_method */
            	1616, 0,
            0, 112, 11, /* 1616: struct.ssl3_enc_method */
            	1641, 0,
            	1581, 8,
            	1575, 16,
            	1352, 24,
            	1641, 32,
            	1644, 40,
            	1647, 56,
            	214, 64,
            	214, 80,
            	1650, 96,
            	1653, 104,
            4097, 8, 0, /* 1641: pointer.func */
            4097, 8, 0, /* 1644: pointer.func */
            4097, 8, 0, /* 1647: pointer.func */
            4097, 8, 0, /* 1650: pointer.func */
            4097, 8, 0, /* 1653: pointer.func */
            4097, 8, 0, /* 1656: pointer.func */
            4097, 8, 0, /* 1659: pointer.func */
            1, 8, 1, /* 1662: pointer.struct.iovec */
            	993, 0,
            1, 8, 1, /* 1667: pointer.struct.x509_store_st */
            	1672, 0,
            0, 144, 15, /* 1672: struct.x509_store_st */
            	274, 8,
            	274, 16,
            	1293, 24,
            	94, 32,
            	404, 40,
            	91, 48,
            	88, 56,
            	94, 64,
            	85, 72,
            	79, 80,
            	76, 88,
            	73, 96,
            	73, 104,
            	94, 112,
            	772, 120,
            1, 8, 1, /* 1705: pointer.struct.evp_pkey_ctx_st */
            	1492, 0,
            4097, 8, 0, /* 1710: pointer.func */
            4097, 8, 0, /* 1713: pointer.func */
            1, 8, 1, /* 1716: pointer.struct.dtls1_state_st */
            	1721, 0,
            0, 888, 7, /* 1721: struct.dtls1_state_st */
            	1738, 576,
            	1738, 592,
            	1743, 608,
            	1743, 616,
            	1738, 624,
            	1765, 648,
            	1765, 736,
            0, 16, 1, /* 1738: struct.record_pqueue_st */
            	1743, 8,
            1, 8, 1, /* 1743: pointer.struct._pqueue */
            	1748, 0,
            0, 16, 1, /* 1748: struct._pqueue */
            	1753, 0,
            1, 8, 1, /* 1753: pointer.struct._pitem */
            	1758, 0,
            0, 24, 2, /* 1758: struct._pitem */
            	5, 8,
            	1753, 16,
            0, 88, 1, /* 1765: struct.hm_header_st */
            	1770, 48,
            0, 40, 4, /* 1770: struct.dtls1_retransmit_state */
            	1781, 0,
            	1831, 8,
            	1849, 16,
            	1861, 24,
            1, 8, 1, /* 1781: pointer.struct.evp_cipher_ctx_st */
            	1786, 0,
            0, 168, 4, /* 1786: struct.evp_cipher_ctx_st */
            	1797, 0,
            	451, 8,
            	214, 96,
            	214, 120,
            1, 8, 1, /* 1797: pointer.struct.evp_cipher_st */
            	1802, 0,
            0, 88, 7, /* 1802: struct.evp_cipher_st */
            	1819, 24,
            	1822, 32,
            	1825, 40,
            	1710, 56,
            	1710, 64,
            	1828, 72,
            	214, 80,
            4097, 8, 0, /* 1819: pointer.func */
            4097, 8, 0, /* 1822: pointer.func */
            4097, 8, 0, /* 1825: pointer.func */
            4097, 8, 0, /* 1828: pointer.func */
            1, 8, 1, /* 1831: pointer.struct.env_md_ctx_st */
            	1836, 0,
            0, 48, 5, /* 1836: struct.env_md_ctx_st */
            	852, 0,
            	451, 8,
            	214, 24,
            	1705, 32,
            	879, 40,
            1, 8, 1, /* 1849: pointer.struct.comp_ctx_st */
            	1854, 0,
            0, 56, 2, /* 1854: struct.comp_ctx_st */
            	1370, 0,
            	772, 40,
            1, 8, 1, /* 1861: pointer.struct.ssl_session_st */
            	1866, 0,
            0, 352, 14, /* 1866: struct.ssl_session_st */
            	214, 144,
            	214, 152,
            	1897, 168,
            	142, 176,
            	1917, 224,
            	274, 240,
            	772, 248,
            	1861, 264,
            	1861, 272,
            	214, 280,
            	214, 296,
            	214, 312,
            	214, 320,
            	214, 344,
            1, 8, 1, /* 1897: pointer.struct.sess_cert_st */
            	1902, 0,
            0, 248, 6, /* 1902: struct.sess_cert_st */
            	274, 0,
            	128, 16,
            	1269, 24,
            	897, 216,
            	1001, 224,
            	1033, 232,
            1, 8, 1, /* 1917: pointer.struct.ssl_cipher_st */
            	1922, 0,
            0, 88, 1, /* 1922: struct.ssl_cipher_st */
            	214, 8,
            0, 80, 9, /* 1927: struct.bio_method_st */
            	214, 8,
            	1948, 16,
            	1948, 24,
            	1951, 32,
            	1948, 40,
            	1954, 48,
            	1957, 56,
            	1957, 64,
            	1960, 72,
            4097, 8, 0, /* 1948: pointer.func */
            4097, 8, 0, /* 1951: pointer.func */
            4097, 8, 0, /* 1954: pointer.func */
            4097, 8, 0, /* 1957: pointer.func */
            4097, 8, 0, /* 1960: pointer.func */
            1, 8, 1, /* 1963: pointer.struct.tls_session_ticket_ext_st */
            	0, 0,
            4097, 8, 0, /* 1968: pointer.func */
            1, 8, 1, /* 1971: pointer.struct.bio_method_st */
            	1927, 0,
            0, 1, 0, /* 1976: char */
            1, 8, 1, /* 1979: pointer.struct.ssl_ctx_st */
            	1984, 0,
            0, 736, 50, /* 1984: struct.ssl_ctx_st */
            	1511, 0,
            	274, 8,
            	274, 16,
            	1667, 24,
            	68, 32,
            	1861, 48,
            	1861, 56,
            	2087, 80,
            	2090, 88,
            	33, 96,
            	1968, 152,
            	214, 160,
            	30, 168,
            	214, 176,
            	1713, 184,
            	2093, 192,
            	1581, 200,
            	772, 208,
            	852, 224,
            	852, 232,
            	852, 240,
            	274, 248,
            	274, 256,
            	2096, 264,
            	274, 272,
            	1288, 304,
            	1305, 320,
            	214, 328,
            	100, 376,
            	2093, 384,
            	1293, 392,
            	451, 408,
            	1349, 416,
            	214, 424,
            	27, 480,
            	24, 488,
            	214, 496,
            	82, 504,
            	214, 512,
            	214, 520,
            	97, 528,
            	1352, 536,
            	1308, 552,
            	1308, 560,
            	1318, 568,
            	8, 696,
            	214, 704,
            	2099, 712,
            	214, 720,
            	274, 728,
            4097, 8, 0, /* 2087: pointer.func */
            4097, 8, 0, /* 2090: pointer.func */
            4097, 8, 0, /* 2093: pointer.func */
            4097, 8, 0, /* 2096: pointer.func */
            4097, 8, 0, /* 2099: pointer.func */
            0, 808, 51, /* 2102: struct.ssl_st */
            	1511, 8,
            	2207, 16,
            	2207, 24,
            	2207, 32,
            	404, 48,
            	296, 80,
            	214, 88,
            	214, 104,
            	2232, 120,
            	2258, 128,
            	1716, 136,
            	1305, 152,
            	214, 160,
            	1293, 176,
            	274, 184,
            	274, 192,
            	1781, 208,
            	1831, 216,
            	1849, 224,
            	1781, 232,
            	1831, 240,
            	1849, 248,
            	1288, 256,
            	1861, 304,
            	2093, 312,
            	100, 328,
            	2096, 336,
            	97, 352,
            	1352, 360,
            	1979, 368,
            	772, 392,
            	274, 408,
            	2324, 464,
            	214, 472,
            	214, 480,
            	274, 504,
            	274, 512,
            	214, 520,
            	214, 544,
            	214, 560,
            	214, 568,
            	1963, 584,
            	1644, 592,
            	214, 600,
            	2327, 608,
            	214, 616,
            	1979, 624,
            	214, 632,
            	274, 648,
            	1662, 656,
            	1318, 680,
            1, 8, 1, /* 2207: pointer.struct.bio_st */
            	2212, 0,
            0, 112, 7, /* 2212: struct.bio_st */
            	1971, 0,
            	2229, 8,
            	214, 16,
            	214, 48,
            	2207, 56,
            	2207, 64,
            	772, 96,
            4097, 8, 0, /* 2229: pointer.func */
            1, 8, 1, /* 2232: pointer.struct.ssl2_state_st */
            	2237, 0,
            0, 344, 9, /* 2237: struct.ssl2_state_st */
            	214, 24,
            	214, 56,
            	214, 64,
            	214, 72,
            	214, 104,
            	214, 112,
            	214, 120,
            	214, 128,
            	214, 136,
            1, 8, 1, /* 2258: pointer.struct.ssl3_state_st */
            	2263, 0,
            0, 1200, 10, /* 2263: struct.ssl3_state_st */
            	2286, 240,
            	2286, 264,
            	2291, 288,
            	2291, 344,
            	214, 432,
            	2207, 440,
            	2300, 448,
            	5, 496,
            	5, 512,
            	2305, 528,
            0, 24, 1, /* 2286: struct.ssl3_buffer_st */
            	214, 0,
            0, 56, 3, /* 2291: struct.ssl3_record_st */
            	214, 16,
            	214, 24,
            	214, 32,
            1, 8, 1, /* 2300: pointer.pointer.struct.env_md_ctx_st */
            	1831, 0,
            0, 528, 8, /* 2305: struct.anon */
            	1917, 408,
            	1001, 416,
            	1033, 424,
            	274, 464,
            	214, 480,
            	1797, 488,
            	852, 496,
            	1358, 512,
            4097, 8, 0, /* 2324: pointer.func */
            4097, 8, 0, /* 2327: pointer.func */
            1, 8, 1, /* 2330: pointer.struct.ssl_st */
            	2102, 0,
        },
        .arg_entity_index = { 2330, },
        .ret_entity_index = 214,
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

