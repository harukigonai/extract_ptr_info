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

void bb_X509_STORE_CTX_free(X509_STORE_CTX * arg_a);

void X509_STORE_CTX_free(X509_STORE_CTX * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_STORE_CTX_free called %lu\n", in_lib);
    if (!in_lib)
        bb_X509_STORE_CTX_free(arg_a);
    else {
        void (*orig_X509_STORE_CTX_free)(X509_STORE_CTX *);
        orig_X509_STORE_CTX_free = dlsym(RTLD_NEXT, "X509_STORE_CTX_free");
        orig_X509_STORE_CTX_free(arg_a);
    }
}

void bb_X509_STORE_CTX_free(X509_STORE_CTX * arg_a) 
{
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            0, 0, 0, /* 3: func */
            0, 0, 0, /* 6: func */
            4097, 8, 0, /* 9: pointer.func */
            0, 40, 4, /* 12: struct.x509_crl_method_st */
            	9, 8,
            	9, 16,
            	23, 24,
            	26, 32,
            4097, 8, 0, /* 23: pointer.func */
            4097, 8, 0, /* 26: pointer.func */
            0, 8, 1, /* 29: union.anon.1.3127 */
            	34, 0,
            0, 8, 1, /* 34: pointer.struct.stack_st_OPENSSL_STRING */
            	39, 0,
            0, 32, 1, /* 39: struct.stack_st_OPENSSL_STRING */
            	44, 0,
            0, 32, 2, /* 44: struct.stack_st */
            	51, 8,
            	61, 24,
            0, 8, 1, /* 51: pointer.pointer.char */
            	56, 0,
            0, 8, 1, /* 56: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 61: pointer.func */
            0, 32, 2, /* 64: struct.ISSUING_DIST_POINT_st */
            	71, 0,
            	107, 16,
            0, 8, 1, /* 71: pointer.struct.DIST_POINT_NAME_st */
            	76, 0,
            0, 24, 2, /* 76: struct.DIST_POINT_NAME_st */
            	29, 8,
            	83, 16,
            0, 8, 1, /* 83: pointer.struct.X509_name_st */
            	88, 0,
            0, 40, 3, /* 88: struct.X509_name_st */
            	34, 0,
            	97, 16,
            	56, 24,
            0, 8, 1, /* 97: pointer.struct.buf_mem_st */
            	102, 0,
            0, 24, 1, /* 102: struct.buf_mem_st */
            	56, 8,
            0, 8, 1, /* 107: pointer.struct.asn1_string_st */
            	112, 0,
            0, 24, 1, /* 112: struct.asn1_string_st */
            	56, 8,
            0, 8, 1, /* 117: pointer.struct.X509_crl_info_st */
            	122, 0,
            0, 80, 8, /* 122: struct.X509_crl_info_st */
            	107, 0,
            	141, 8,
            	83, 16,
            	107, 24,
            	107, 32,
            	34, 40,
            	34, 48,
            	182, 56,
            0, 8, 1, /* 141: pointer.struct.X509_algor_st */
            	146, 0,
            0, 16, 2, /* 146: struct.X509_algor_st */
            	153, 0,
            	167, 8,
            0, 8, 1, /* 153: pointer.struct.asn1_object_st */
            	158, 0,
            0, 40, 3, /* 158: struct.asn1_object_st */
            	56, 0,
            	56, 8,
            	56, 24,
            0, 8, 1, /* 167: pointer.struct.asn1_type_st */
            	172, 0,
            0, 16, 1, /* 172: struct.asn1_type_st */
            	177, 8,
            0, 8, 1, /* 177: struct.fnames */
            	56, 0,
            0, 24, 1, /* 182: struct.ASN1_ENCODING_st */
            	56, 0,
            0, 8, 1, /* 187: pointer.struct.ISSUING_DIST_POINT_st */
            	64, 0,
            0, 8, 1, /* 192: pointer.struct.X509_POLICY_NODE_st */
            	197, 0,
            0, 24, 2, /* 197: struct.X509_POLICY_NODE_st */
            	204, 0,
            	192, 8,
            0, 8, 1, /* 204: pointer.struct.X509_POLICY_DATA_st */
            	209, 0,
            0, 32, 3, /* 209: struct.X509_POLICY_DATA_st */
            	153, 8,
            	34, 16,
            	34, 24,
            0, 0, 0, /* 218: func */
            0, 0, 0, /* 221: func */
            4097, 8, 0, /* 224: pointer.func */
            0, 0, 0, /* 227: func */
            4097, 8, 0, /* 230: pointer.func */
            4097, 8, 0, /* 233: pointer.func */
            0, 0, 0, /* 236: func */
            0, 0, 0, /* 239: func */
            0, 0, 0, /* 242: func */
            0, 24, 3, /* 245: struct.X509_pubkey_st */
            	141, 0,
            	107, 8,
            	254, 16,
            0, 8, 1, /* 254: pointer.struct.evp_pkey_st */
            	259, 0,
            0, 56, 4, /* 259: struct.evp_pkey_st */
            	270, 16,
            	364, 24,
            	177, 32,
            	34, 48,
            0, 8, 1, /* 270: pointer.struct.evp_pkey_asn1_method_st */
            	275, 0,
            0, 208, 24, /* 275: struct.evp_pkey_asn1_method_st */
            	56, 16,
            	56, 24,
            	326, 32,
            	334, 40,
            	337, 48,
            	340, 56,
            	233, 64,
            	230, 72,
            	340, 80,
            	224, 88,
            	224, 96,
            	343, 104,
            	346, 112,
            	224, 120,
            	337, 128,
            	337, 136,
            	340, 144,
            	349, 152,
            	352, 160,
            	355, 168,
            	343, 176,
            	346, 184,
            	358, 192,
            	361, 200,
            0, 8, 1, /* 326: pointer.struct.unnamed */
            	331, 0,
            0, 0, 0, /* 331: struct.unnamed */
            4097, 8, 0, /* 334: pointer.func */
            4097, 8, 0, /* 337: pointer.func */
            4097, 8, 0, /* 340: pointer.func */
            4097, 8, 0, /* 343: pointer.func */
            4097, 8, 0, /* 346: pointer.func */
            4097, 8, 0, /* 349: pointer.func */
            4097, 8, 0, /* 352: pointer.func */
            4097, 8, 0, /* 355: pointer.func */
            4097, 8, 0, /* 358: pointer.func */
            4097, 8, 0, /* 361: pointer.func */
            0, 8, 1, /* 364: pointer.struct.engine_st */
            	369, 0,
            0, 216, 24, /* 369: struct.engine_st */
            	56, 0,
            	56, 8,
            	420, 16,
            	475, 24,
            	526, 32,
            	562, 40,
            	579, 48,
            	606, 56,
            	641, 64,
            	649, 72,
            	652, 80,
            	655, 88,
            	658, 96,
            	661, 104,
            	661, 112,
            	661, 120,
            	664, 128,
            	667, 136,
            	667, 144,
            	670, 152,
            	673, 160,
            	685, 184,
            	364, 200,
            	364, 208,
            0, 8, 1, /* 420: pointer.struct.rsa_meth_st */
            	425, 0,
            0, 112, 13, /* 425: struct.rsa_meth_st */
            	56, 0,
            	454, 8,
            	454, 16,
            	454, 24,
            	454, 32,
            	457, 40,
            	460, 48,
            	463, 56,
            	463, 64,
            	56, 80,
            	466, 88,
            	469, 96,
            	472, 104,
            4097, 8, 0, /* 454: pointer.func */
            4097, 8, 0, /* 457: pointer.func */
            4097, 8, 0, /* 460: pointer.func */
            4097, 8, 0, /* 463: pointer.func */
            4097, 8, 0, /* 466: pointer.func */
            4097, 8, 0, /* 469: pointer.func */
            4097, 8, 0, /* 472: pointer.func */
            0, 8, 1, /* 475: pointer.struct.dsa_method */
            	480, 0,
            0, 96, 11, /* 480: struct.dsa_method */
            	56, 0,
            	505, 8,
            	508, 16,
            	511, 24,
            	514, 32,
            	517, 40,
            	520, 48,
            	520, 56,
            	56, 72,
            	523, 80,
            	520, 88,
            4097, 8, 0, /* 505: pointer.func */
            4097, 8, 0, /* 508: pointer.func */
            4097, 8, 0, /* 511: pointer.func */
            4097, 8, 0, /* 514: pointer.func */
            4097, 8, 0, /* 517: pointer.func */
            4097, 8, 0, /* 520: pointer.func */
            4097, 8, 0, /* 523: pointer.func */
            0, 8, 1, /* 526: pointer.struct.dh_method */
            	531, 0,
            0, 72, 8, /* 531: struct.dh_method */
            	56, 0,
            	550, 8,
            	553, 16,
            	556, 24,
            	550, 32,
            	550, 40,
            	56, 56,
            	559, 64,
            4097, 8, 0, /* 550: pointer.func */
            4097, 8, 0, /* 553: pointer.func */
            4097, 8, 0, /* 556: pointer.func */
            4097, 8, 0, /* 559: pointer.func */
            0, 8, 1, /* 562: pointer.struct.ecdh_method */
            	567, 0,
            0, 32, 3, /* 567: struct.ecdh_method */
            	56, 0,
            	576, 8,
            	56, 24,
            4097, 8, 0, /* 576: pointer.func */
            0, 8, 1, /* 579: pointer.struct.ecdsa_method */
            	584, 0,
            0, 48, 5, /* 584: struct.ecdsa_method */
            	56, 0,
            	597, 8,
            	600, 16,
            	603, 24,
            	56, 40,
            4097, 8, 0, /* 597: pointer.func */
            4097, 8, 0, /* 600: pointer.func */
            4097, 8, 0, /* 603: pointer.func */
            0, 8, 1, /* 606: pointer.struct.rand_meth_st */
            	611, 0,
            0, 48, 6, /* 611: struct.rand_meth_st */
            	626, 0,
            	629, 8,
            	632, 16,
            	635, 24,
            	629, 32,
            	638, 40,
            4097, 8, 0, /* 626: pointer.func */
            4097, 8, 0, /* 629: pointer.func */
            4097, 8, 0, /* 632: pointer.func */
            4097, 8, 0, /* 635: pointer.func */
            4097, 8, 0, /* 638: pointer.func */
            0, 8, 1, /* 641: pointer.struct.store_method_st */
            	646, 0,
            0, 0, 0, /* 646: struct.store_method_st */
            4097, 8, 0, /* 649: pointer.func */
            4097, 8, 0, /* 652: pointer.func */
            4097, 8, 0, /* 655: pointer.func */
            4097, 8, 0, /* 658: pointer.func */
            4097, 8, 0, /* 661: pointer.func */
            4097, 8, 0, /* 664: pointer.func */
            4097, 8, 0, /* 667: pointer.func */
            4097, 8, 0, /* 670: pointer.func */
            0, 8, 1, /* 673: pointer.struct.ENGINE_CMD_DEFN_st */
            	678, 0,
            0, 32, 2, /* 678: struct.ENGINE_CMD_DEFN_st */
            	56, 8,
            	56, 16,
            0, 16, 1, /* 685: struct.crypto_ex_data_st */
            	34, 0,
            0, 8, 1, /* 690: pointer.struct.x509_cinf_st */
            	695, 0,
            0, 104, 11, /* 695: struct.x509_cinf_st */
            	107, 0,
            	107, 8,
            	141, 16,
            	83, 24,
            	720, 32,
            	83, 40,
            	732, 48,
            	107, 56,
            	107, 64,
            	34, 72,
            	182, 80,
            0, 8, 1, /* 720: pointer.struct.X509_val_st */
            	725, 0,
            0, 16, 2, /* 725: struct.X509_val_st */
            	107, 0,
            	107, 8,
            0, 8, 1, /* 732: pointer.struct.X509_pubkey_st */
            	245, 0,
            0, 8, 1, /* 737: pointer.struct.X509_POLICY_LEVEL_st */
            	742, 0,
            0, 32, 3, /* 742: struct.X509_POLICY_LEVEL_st */
            	751, 0,
            	34, 8,
            	192, 16,
            0, 8, 1, /* 751: pointer.struct.x509_st */
            	756, 0,
            0, 184, 12, /* 756: struct.x509_st */
            	690, 0,
            	141, 8,
            	107, 16,
            	56, 32,
            	685, 40,
            	107, 104,
            	783, 112,
            	797, 120,
            	34, 128,
            	34, 136,
            	809, 144,
            	821, 176,
            0, 8, 1, /* 783: pointer.struct.AUTHORITY_KEYID_st */
            	788, 0,
            0, 24, 3, /* 788: struct.AUTHORITY_KEYID_st */
            	107, 0,
            	34, 8,
            	107, 16,
            0, 8, 1, /* 797: pointer.struct.X509_POLICY_CACHE_st */
            	802, 0,
            0, 40, 2, /* 802: struct.X509_POLICY_CACHE_st */
            	204, 0,
            	34, 8,
            0, 8, 1, /* 809: pointer.struct.NAME_CONSTRAINTS_st */
            	814, 0,
            0, 16, 2, /* 814: struct.NAME_CONSTRAINTS_st */
            	34, 0,
            	34, 8,
            0, 8, 1, /* 821: pointer.struct.x509_cert_aux_st */
            	826, 0,
            0, 40, 5, /* 826: struct.x509_cert_aux_st */
            	34, 0,
            	34, 8,
            	107, 16,
            	107, 24,
            	34, 32,
            0, 8, 1, /* 839: pointer.struct.X509_POLICY_TREE_st */
            	844, 0,
            0, 48, 4, /* 844: struct.X509_POLICY_TREE_st */
            	737, 0,
            	34, 16,
            	34, 24,
            	34, 32,
            0, 20, 0, /* 855: array[20].char */
            0, 0, 0, /* 858: func */
            0, 0, 0, /* 861: func */
            0, 0, 0, /* 864: func */
            0, 0, 0, /* 867: func */
            0, 0, 0, /* 870: func */
            0, 0, 0, /* 873: func */
            0, 0, 0, /* 876: func */
            0, 0, 0, /* 879: func */
            0, 0, 0, /* 882: func */
            0, 0, 0, /* 885: func */
            0, 0, 0, /* 888: func */
            0, 0, 0, /* 891: func */
            0, 0, 0, /* 894: func */
            0, 8, 1, /* 897: pointer.struct.X509_crl_st */
            	902, 0,
            0, 120, 10, /* 902: struct.X509_crl_st */
            	117, 0,
            	141, 8,
            	107, 16,
            	783, 32,
            	187, 40,
            	107, 56,
            	107, 64,
            	34, 96,
            	925, 104,
            	930, 112,
            0, 8, 1, /* 925: pointer.struct.x509_crl_method_st */
            	12, 0,
            0, 8, 0, /* 930: pointer.void */
            0, 0, 0, /* 933: func */
            0, 0, 0, /* 936: func */
            0, 8, 1, /* 939: pointer.struct.X509_pubkey_st */
            	944, 0,
            0, 24, 3, /* 944: struct.X509_pubkey_st */
            	141, 0,
            	107, 8,
            	953, 16,
            0, 8, 1, /* 953: pointer.struct.evp_pkey_st */
            	958, 0,
            0, 56, 4, /* 958: struct.evp_pkey_st */
            	969, 16,
            	364, 24,
            	177, 32,
            	34, 48,
            0, 8, 1, /* 969: pointer.struct.evp_pkey_asn1_method_st */
            	974, 0,
            0, 208, 24, /* 974: struct.evp_pkey_asn1_method_st */
            	56, 16,
            	56, 24,
            	1025, 32,
            	1028, 40,
            	1031, 48,
            	1034, 56,
            	1037, 64,
            	1040, 72,
            	1034, 80,
            	1043, 88,
            	1043, 96,
            	1046, 104,
            	1049, 112,
            	1043, 120,
            	1031, 128,
            	1031, 136,
            	1034, 144,
            	349, 152,
            	1052, 160,
            	1055, 168,
            	1046, 176,
            	1049, 184,
            	1058, 192,
            	361, 200,
            4097, 8, 0, /* 1025: pointer.func */
            4097, 8, 0, /* 1028: pointer.func */
            4097, 8, 0, /* 1031: pointer.func */
            4097, 8, 0, /* 1034: pointer.func */
            4097, 8, 0, /* 1037: pointer.func */
            4097, 8, 0, /* 1040: pointer.func */
            4097, 8, 0, /* 1043: pointer.func */
            4097, 8, 0, /* 1046: pointer.func */
            4097, 8, 0, /* 1049: pointer.func */
            4097, 8, 0, /* 1052: pointer.func */
            4097, 8, 0, /* 1055: pointer.func */
            4097, 8, 0, /* 1058: pointer.func */
            0, 0, 0, /* 1061: func */
            0, 104, 11, /* 1064: struct.x509_cinf_st */
            	107, 0,
            	107, 8,
            	141, 16,
            	83, 24,
            	720, 32,
            	83, 40,
            	939, 48,
            	107, 56,
            	107, 64,
            	34, 72,
            	182, 80,
            0, 0, 0, /* 1089: func */
            0, 8, 1, /* 1092: pointer.struct.x509_cinf_st */
            	1064, 0,
            0, 0, 0, /* 1097: func */
            4097, 8, 0, /* 1100: pointer.func */
            0, 0, 0, /* 1103: func */
            0, 0, 0, /* 1106: func */
            0, 1, 0, /* 1109: char */
            0, 8, 1, /* 1112: pointer.struct.x509_st */
            	1117, 0,
            0, 184, 12, /* 1117: struct.x509_st */
            	1092, 0,
            	141, 8,
            	107, 16,
            	56, 32,
            	685, 40,
            	107, 104,
            	783, 112,
            	797, 120,
            	34, 128,
            	34, 136,
            	809, 144,
            	821, 176,
            0, 0, 0, /* 1144: func */
            0, 8, 1, /* 1147: pointer.struct.x509_store_st */
            	1152, 0,
            0, 144, 15, /* 1152: struct.x509_store_st */
            	34, 8,
            	34, 16,
            	1185, 24,
            	326, 32,
            	1197, 40,
            	1200, 48,
            	1203, 56,
            	326, 64,
            	1206, 72,
            	1209, 80,
            	1212, 88,
            	1100, 96,
            	1100, 104,
            	326, 112,
            	685, 120,
            0, 8, 1, /* 1185: pointer.struct.X509_VERIFY_PARAM_st */
            	1190, 0,
            0, 56, 2, /* 1190: struct.X509_VERIFY_PARAM_st */
            	56, 0,
            	34, 48,
            4097, 8, 0, /* 1197: pointer.func */
            4097, 8, 0, /* 1200: pointer.func */
            4097, 8, 0, /* 1203: pointer.func */
            4097, 8, 0, /* 1206: pointer.func */
            4097, 8, 0, /* 1209: pointer.func */
            4097, 8, 0, /* 1212: pointer.func */
            0, 0, 0, /* 1215: func */
            0, 0, 0, /* 1218: func */
            0, 0, 0, /* 1221: func */
            0, 4, 0, /* 1224: int */
            0, 0, 0, /* 1227: func */
            0, 0, 0, /* 1230: func */
            0, 248, 25, /* 1233: struct.x509_store_ctx_st */
            	1147, 0,
            	1112, 16,
            	34, 24,
            	34, 32,
            	1185, 40,
            	930, 48,
            	326, 56,
            	1197, 64,
            	1200, 72,
            	1203, 80,
            	326, 88,
            	1206, 96,
            	1209, 104,
            	1212, 112,
            	326, 120,
            	1100, 128,
            	1100, 136,
            	326, 144,
            	34, 160,
            	839, 168,
            	1112, 192,
            	1112, 200,
            	897, 208,
            	1286, 224,
            	685, 232,
            0, 8, 1, /* 1286: pointer.struct.x509_store_ctx_st */
            	1233, 0,
            0, 0, 0, /* 1291: func */
            0, 0, 0, /* 1294: func */
            0, 0, 0, /* 1297: func */
            0, 0, 0, /* 1300: func */
            0, 8, 0, /* 1303: long */
            0, 0, 0, /* 1306: func */
            0, 0, 0, /* 1309: func */
            0, 0, 0, /* 1312: func */
            0, 0, 0, /* 1315: func */
            0, 0, 0, /* 1318: func */
            0, 0, 0, /* 1321: func */
            0, 0, 0, /* 1324: func */
            0, 0, 0, /* 1327: func */
            0, 0, 0, /* 1330: func */
            0, 0, 0, /* 1333: func */
            0, 0, 0, /* 1336: func */
            0, 0, 0, /* 1339: func */
            0, 0, 0, /* 1342: func */
            0, 0, 0, /* 1345: func */
            0, 0, 0, /* 1348: func */
            0, 0, 0, /* 1351: func */
            0, 0, 0, /* 1354: func */
            0, 0, 0, /* 1357: func */
            0, 0, 0, /* 1360: func */
            0, 0, 0, /* 1363: func */
            0, 0, 0, /* 1366: func */
            0, 0, 0, /* 1369: func */
            0, 0, 0, /* 1372: func */
            0, 0, 0, /* 1375: func */
            0, 0, 0, /* 1378: func */
            0, 0, 0, /* 1381: func */
            0, 0, 0, /* 1384: func */
            0, 0, 0, /* 1387: func */
            0, 0, 0, /* 1390: func */
            0, 0, 0, /* 1393: func */
            0, 0, 0, /* 1396: func */
            0, 0, 0, /* 1399: func */
        },
        .arg_entity_index = { 1286, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509_STORE_CTX * new_arg_a = *((X509_STORE_CTX * *)new_args->args[0]);

    void (*orig_X509_STORE_CTX_free)(X509_STORE_CTX *);
    orig_X509_STORE_CTX_free = dlsym(RTLD_NEXT, "X509_STORE_CTX_free");
    (*orig_X509_STORE_CTX_free)(new_arg_a);

    syscall(889);

}

