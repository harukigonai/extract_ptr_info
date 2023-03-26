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

int X509_check_private_key(X509 * arg_a,EVP_PKEY * arg_b) 
{
    int ret;

    struct lib_enter_args args = {
        .entity_metadata = {
            0, 40, 5, /* 0: struct.x509_cert_aux_st */
            	13, 0,
            	13, 8,
            	60, 16,
            	60, 24,
            	13, 32,
            1, 8, 1, /* 13: pointer.struct.stack_st_OPENSSL_STRING */
            	18, 0,
            0, 32, 1, /* 18: struct.stack_st_OPENSSL_STRING */
            	23, 0,
            0, 32, 5, /* 23: struct.stack_st */
            	36, 0,
            	39, 8,
            	36, 16,
            	36, 20,
            	52, 24,
            0, 4, 0, /* 36: int */
            1, 8, 1, /* 39: pointer.pointer.char */
            	44, 0,
            1, 8, 1, /* 44: pointer.char */
            	49, 0,
            0, 1, 0, /* 49: char */
            1, 8, 1, /* 52: pointer.func */
            	57, 0,
            0, 0, 0, /* 57: func */
            1, 8, 1, /* 60: pointer.struct.asn1_string_st */
            	65, 0,
            0, 24, 4, /* 65: struct.asn1_string_st */
            	36, 0,
            	36, 4,
            	44, 8,
            	76, 16,
            0, 8, 0, /* 76: long */
            1, 8, 1, /* 79: pointer.struct.x509_cert_aux_st */
            	0, 0,
            0, 16, 2, /* 84: struct.NAME_CONSTRAINTS_st */
            	13, 0,
            	13, 8,
            1, 8, 1, /* 91: pointer.struct.NAME_CONSTRAINTS_st */
            	84, 0,
            0, 32, 4, /* 96: struct.X509_POLICY_DATA_st */
            	36, 0,
            	107, 8,
            	13, 16,
            	13, 24,
            1, 8, 1, /* 107: pointer.struct.asn1_object_st */
            	112, 0,
            0, 40, 6, /* 112: struct.asn1_object_st */
            	44, 0,
            	44, 8,
            	36, 16,
            	36, 20,
            	44, 24,
            	36, 32,
            1, 8, 1, /* 127: pointer.struct.X509_POLICY_DATA_st */
            	96, 0,
            1, 8, 1, /* 132: pointer.struct.X509_POLICY_CACHE_st */
            	137, 0,
            0, 40, 5, /* 137: struct.X509_POLICY_CACHE_st */
            	127, 0,
            	13, 8,
            	76, 16,
            	76, 24,
            	76, 32,
            1, 8, 1, /* 150: pointer.struct.AUTHORITY_KEYID_st */
            	155, 0,
            0, 24, 3, /* 155: struct.AUTHORITY_KEYID_st */
            	60, 0,
            	13, 8,
            	60, 16,
            1, 8, 1, /* 164: pointer.func */
            	169, 0,
            0, 0, 0, /* 169: func */
            0, 0, 0, /* 172: func */
            0, 0, 0, /* 175: func */
            0, 0, 0, /* 178: func */
            1, 8, 1, /* 181: pointer.func */
            	178, 0,
            0, 0, 0, /* 186: func */
            1, 8, 1, /* 189: pointer.func */
            	186, 0,
            0, 0, 0, /* 194: func */
            1, 8, 1, /* 197: pointer.func */
            	194, 0,
            0, 0, 0, /* 202: func */
            1, 8, 1, /* 205: pointer.func */
            	202, 0,
            0, 0, 0, /* 210: func */
            1, 8, 1, /* 213: pointer.func */
            	210, 0,
            0, 0, 0, /* 218: struct.store_method_st */
            1, 8, 1, /* 221: pointer.struct.store_method_st */
            	218, 0,
            0, 0, 0, /* 226: func */
            1, 8, 1, /* 229: pointer.struct.ENGINE_CMD_DEFN_st */
            	234, 0,
            0, 32, 4, /* 234: struct.ENGINE_CMD_DEFN_st */
            	36, 0,
            	44, 8,
            	44, 16,
            	36, 24,
            1, 8, 1, /* 245: pointer.func */
            	226, 0,
            0, 0, 0, /* 250: func */
            1, 8, 1, /* 253: pointer.func */
            	250, 0,
            1, 8, 1, /* 258: pointer.func */
            	172, 0,
            0, 0, 0, /* 263: func */
            1, 8, 1, /* 266: pointer.struct.ecdsa_method */
            	271, 0,
            0, 48, 6, /* 271: struct.ecdsa_method */
            	44, 0,
            	286, 8,
            	294, 16,
            	302, 24,
            	36, 32,
            	44, 40,
            1, 8, 1, /* 286: pointer.func */
            	291, 0,
            0, 0, 0, /* 291: func */
            1, 8, 1, /* 294: pointer.func */
            	299, 0,
            0, 0, 0, /* 299: func */
            1, 8, 1, /* 302: pointer.func */
            	307, 0,
            0, 0, 0, /* 307: func */
            1, 8, 1, /* 310: pointer.func */
            	263, 0,
            0, 0, 0, /* 315: func */
            0, 16, 2, /* 318: struct.crypto_ex_data_st */
            	13, 0,
            	36, 8,
            0, 0, 0, /* 325: func */
            0, 0, 0, /* 328: func */
            1, 8, 1, /* 331: pointer.func */
            	336, 0,
            0, 0, 0, /* 336: func */
            1, 8, 1, /* 339: pointer.func */
            	344, 0,
            0, 0, 0, /* 344: func */
            0, 0, 0, /* 347: func */
            1, 8, 1, /* 350: pointer.func */
            	347, 0,
            0, 24, 3, /* 355: struct.X509_pubkey_st.2915 */
            	364, 0,
            	60, 8,
            	393, 16,
            1, 8, 1, /* 364: pointer.struct.X509_algor_st */
            	369, 0,
            0, 16, 2, /* 369: struct.X509_algor_st */
            	107, 0,
            	376, 8,
            1, 8, 1, /* 376: pointer.struct.asn1_type_st */
            	381, 0,
            0, 16, 2, /* 381: struct.asn1_type_st */
            	36, 0,
            	388, 8,
            0, 8, 1, /* 388: struct.fnames */
            	44, 0,
            1, 8, 1, /* 393: pointer.struct.evp_pkey_st.2930 */
            	398, 0,
            0, 56, 8, /* 398: struct.evp_pkey_st.2930 */
            	36, 0,
            	36, 4,
            	36, 8,
            	417, 16,
            	569, 24,
            	388, 32,
            	36, 40,
            	13, 48,
            1, 8, 1, /* 417: pointer.struct.evp_pkey_asn1_method_st.2928 */
            	422, 0,
            0, 208, 27, /* 422: struct.evp_pkey_asn1_method_st.2928 */
            	36, 0,
            	36, 4,
            	76, 8,
            	44, 16,
            	44, 24,
            	479, 32,
            	487, 40,
            	350, 48,
            	495, 56,
            	500, 64,
            	508, 72,
            	495, 80,
            	513, 88,
            	513, 96,
            	521, 104,
            	529, 112,
            	513, 120,
            	350, 128,
            	350, 136,
            	495, 144,
            	537, 152,
            	310, 160,
            	545, 168,
            	521, 176,
            	529, 184,
            	553, 192,
            	561, 200,
            1, 8, 1, /* 479: pointer.func */
            	484, 0,
            0, 0, 0, /* 484: func */
            1, 8, 1, /* 487: pointer.func */
            	492, 0,
            0, 0, 0, /* 492: func */
            1, 8, 1, /* 495: pointer.func */
            	328, 0,
            1, 8, 1, /* 500: pointer.func */
            	505, 0,
            0, 0, 0, /* 505: func */
            1, 8, 1, /* 508: pointer.func */
            	325, 0,
            1, 8, 1, /* 513: pointer.func */
            	518, 0,
            0, 0, 0, /* 518: func */
            1, 8, 1, /* 521: pointer.func */
            	526, 0,
            0, 0, 0, /* 526: func */
            1, 8, 1, /* 529: pointer.func */
            	534, 0,
            0, 0, 0, /* 534: func */
            1, 8, 1, /* 537: pointer.func */
            	542, 0,
            0, 0, 0, /* 542: func */
            1, 8, 1, /* 545: pointer.func */
            	550, 0,
            0, 0, 0, /* 550: func */
            1, 8, 1, /* 553: pointer.func */
            	558, 0,
            0, 0, 0, /* 558: func */
            1, 8, 1, /* 561: pointer.func */
            	566, 0,
            0, 0, 0, /* 566: func */
            1, 8, 1, /* 569: pointer.struct.engine_st */
            	574, 0,
            0, 216, 27, /* 574: struct.engine_st */
            	44, 0,
            	44, 8,
            	631, 16,
            	720, 24,
            	800, 32,
            	858, 40,
            	266, 48,
            	874, 56,
            	221, 64,
            	213, 72,
            	205, 80,
            	197, 88,
            	189, 96,
            	181, 104,
            	181, 112,
            	181, 120,
            	918, 128,
            	258, 136,
            	258, 144,
            	164, 152,
            	229, 160,
            	36, 168,
            	36, 172,
            	36, 176,
            	318, 184,
            	569, 200,
            	569, 208,
            1, 8, 1, /* 631: pointer.struct.rsa_meth_st */
            	636, 0,
            0, 112, 14, /* 636: struct.rsa_meth_st */
            	44, 0,
            	667, 8,
            	667, 16,
            	667, 24,
            	667, 32,
            	675, 40,
            	683, 48,
            	691, 56,
            	691, 64,
            	36, 72,
            	44, 80,
            	699, 88,
            	707, 96,
            	712, 104,
            1, 8, 1, /* 667: pointer.func */
            	672, 0,
            0, 0, 0, /* 672: func */
            1, 8, 1, /* 675: pointer.func */
            	680, 0,
            0, 0, 0, /* 680: func */
            1, 8, 1, /* 683: pointer.func */
            	688, 0,
            0, 0, 0, /* 688: func */
            1, 8, 1, /* 691: pointer.func */
            	696, 0,
            0, 0, 0, /* 696: func */
            1, 8, 1, /* 699: pointer.func */
            	704, 0,
            0, 0, 0, /* 704: func */
            1, 8, 1, /* 707: pointer.func */
            	315, 0,
            1, 8, 1, /* 712: pointer.func */
            	717, 0,
            0, 0, 0, /* 717: func */
            1, 8, 1, /* 720: pointer.struct.dsa_method.1040 */
            	725, 0,
            0, 96, 12, /* 725: struct.dsa_method.1040 */
            	44, 0,
            	752, 8,
            	760, 16,
            	768, 24,
            	776, 32,
            	784, 40,
            	339, 48,
            	339, 56,
            	36, 64,
            	44, 72,
            	792, 80,
            	339, 88,
            1, 8, 1, /* 752: pointer.func */
            	757, 0,
            0, 0, 0, /* 757: func */
            1, 8, 1, /* 760: pointer.func */
            	765, 0,
            0, 0, 0, /* 765: func */
            1, 8, 1, /* 768: pointer.func */
            	773, 0,
            0, 0, 0, /* 773: func */
            1, 8, 1, /* 776: pointer.func */
            	781, 0,
            0, 0, 0, /* 781: func */
            1, 8, 1, /* 784: pointer.func */
            	789, 0,
            0, 0, 0, /* 789: func */
            1, 8, 1, /* 792: pointer.func */
            	797, 0,
            0, 0, 0, /* 797: func */
            1, 8, 1, /* 800: pointer.struct.dh_method */
            	805, 0,
            0, 72, 9, /* 805: struct.dh_method */
            	44, 0,
            	826, 8,
            	834, 16,
            	842, 24,
            	826, 32,
            	826, 40,
            	36, 48,
            	44, 56,
            	850, 64,
            1, 8, 1, /* 826: pointer.func */
            	831, 0,
            0, 0, 0, /* 831: func */
            1, 8, 1, /* 834: pointer.func */
            	839, 0,
            0, 0, 0, /* 839: func */
            1, 8, 1, /* 842: pointer.func */
            	847, 0,
            0, 0, 0, /* 847: func */
            1, 8, 1, /* 850: pointer.func */
            	855, 0,
            0, 0, 0, /* 855: func */
            1, 8, 1, /* 858: pointer.struct.ecdh_method */
            	863, 0,
            0, 32, 4, /* 863: struct.ecdh_method */
            	44, 0,
            	331, 8,
            	36, 16,
            	44, 24,
            1, 8, 1, /* 874: pointer.struct.rand_meth_st */
            	879, 0,
            0, 48, 6, /* 879: struct.rand_meth_st */
            	894, 0,
            	902, 8,
            	910, 16,
            	253, 24,
            	902, 32,
            	245, 40,
            1, 8, 1, /* 894: pointer.func */
            	899, 0,
            0, 0, 0, /* 899: func */
            1, 8, 1, /* 902: pointer.func */
            	907, 0,
            0, 0, 0, /* 907: func */
            1, 8, 1, /* 910: pointer.func */
            	915, 0,
            0, 0, 0, /* 915: func */
            1, 8, 1, /* 918: pointer.func */
            	175, 0,
            0, 20, 20, /* 923: array[20].char */
            	49, 0,
            	49, 1,
            	49, 2,
            	49, 3,
            	49, 4,
            	49, 5,
            	49, 6,
            	49, 7,
            	49, 8,
            	49, 9,
            	49, 10,
            	49, 11,
            	49, 12,
            	49, 13,
            	49, 14,
            	49, 15,
            	49, 16,
            	49, 17,
            	49, 18,
            	49, 19,
            0, 24, 3, /* 966: struct.buf_mem_st */
            	76, 0,
            	44, 8,
            	76, 16,
            0, 184, 21, /* 975: struct.x509_st.3164 */
            	1020, 0,
            	364, 8,
            	60, 16,
            	36, 24,
            	36, 28,
            	44, 32,
            	318, 40,
            	76, 56,
            	76, 64,
            	76, 72,
            	76, 80,
            	76, 88,
            	76, 96,
            	60, 104,
            	150, 112,
            	132, 120,
            	13, 128,
            	13, 136,
            	91, 144,
            	923, 152,
            	79, 176,
            1, 8, 1, /* 1020: pointer.struct.x509_cinf_st.3159 */
            	1025, 0,
            0, 104, 11, /* 1025: struct.x509_cinf_st.3159 */
            	60, 0,
            	60, 8,
            	364, 16,
            	1050, 24,
            	1073, 32,
            	1050, 40,
            	1085, 48,
            	60, 56,
            	60, 64,
            	13, 72,
            	1090, 80,
            1, 8, 1, /* 1050: pointer.struct.X509_name_st */
            	1055, 0,
            0, 40, 5, /* 1055: struct.X509_name_st */
            	13, 0,
            	36, 8,
            	1068, 16,
            	44, 24,
            	36, 32,
            1, 8, 1, /* 1068: pointer.struct.buf_mem_st */
            	966, 0,
            1, 8, 1, /* 1073: pointer.struct.X509_val_st */
            	1078, 0,
            0, 16, 2, /* 1078: struct.X509_val_st */
            	60, 0,
            	60, 8,
            1, 8, 1, /* 1085: pointer.struct.X509_pubkey_st.2915 */
            	355, 0,
            0, 24, 3, /* 1090: struct.ASN1_ENCODING_st */
            	44, 0,
            	76, 8,
            	36, 16,
            1, 8, 1, /* 1099: pointer.struct.x509_st.3164 */
            	975, 0,
        },
        .arg_entity_index = { 1099, 393, },
        .ret_entity_index = 36,
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
