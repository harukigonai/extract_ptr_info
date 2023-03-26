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

void * X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d) 
{
    void * ret;

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
            1, 8, 1, /* 175: pointer.func */
            	172, 0,
            0, 0, 0, /* 180: func */
            0, 0, 0, /* 183: func */
            1, 8, 1, /* 186: pointer.func */
            	183, 0,
            0, 0, 0, /* 191: func */
            1, 8, 1, /* 194: pointer.func */
            	191, 0,
            0, 0, 0, /* 199: func */
            1, 8, 1, /* 202: pointer.func */
            	199, 0,
            0, 0, 0, /* 207: func */
            1, 8, 1, /* 210: pointer.func */
            	207, 0,
            1, 8, 1, /* 215: pointer.func */
            	220, 0,
            0, 0, 0, /* 220: func */
            0, 0, 0, /* 223: struct.store_method_st */
            1, 8, 1, /* 226: pointer.struct.store_method_st */
            	223, 0,
            0, 0, 0, /* 231: func */
            1, 8, 1, /* 234: pointer.struct.ENGINE_CMD_DEFN_st */
            	239, 0,
            0, 32, 4, /* 239: struct.ENGINE_CMD_DEFN_st */
            	36, 0,
            	44, 8,
            	44, 16,
            	36, 24,
            1, 8, 1, /* 250: pointer.func */
            	231, 0,
            0, 0, 0, /* 255: func */
            1, 8, 1, /* 258: pointer.func */
            	255, 0,
            0, 0, 0, /* 263: func */
            0, 0, 0, /* 266: func */
            1, 8, 1, /* 269: pointer.func */
            	274, 0,
            0, 0, 0, /* 274: func */
            0, 0, 0, /* 277: func */
            0, 56, 8, /* 280: struct.evp_pkey_st */
            	36, 0,
            	36, 4,
            	36, 8,
            	299, 16,
            	464, 24,
            	880, 32,
            	36, 40,
            	13, 48,
            1, 8, 1, /* 299: pointer.struct.evp_pkey_asn1_method_st */
            	304, 0,
            0, 208, 27, /* 304: struct.evp_pkey_asn1_method_st */
            	36, 0,
            	36, 4,
            	76, 8,
            	44, 16,
            	44, 24,
            	361, 32,
            	369, 40,
            	377, 48,
            	385, 56,
            	393, 64,
            	401, 72,
            	385, 80,
            	409, 88,
            	409, 96,
            	417, 104,
            	422, 112,
            	409, 120,
            	377, 128,
            	377, 136,
            	385, 144,
            	427, 152,
            	435, 160,
            	440, 168,
            	417, 176,
            	422, 184,
            	448, 192,
            	456, 200,
            1, 8, 1, /* 361: pointer.struct.unnamed */
            	366, 0,
            0, 0, 0, /* 366: struct.unnamed */
            1, 8, 1, /* 369: pointer.func */
            	374, 0,
            0, 0, 0, /* 374: func */
            1, 8, 1, /* 377: pointer.func */
            	382, 0,
            0, 0, 0, /* 382: func */
            1, 8, 1, /* 385: pointer.func */
            	390, 0,
            0, 0, 0, /* 390: func */
            1, 8, 1, /* 393: pointer.func */
            	398, 0,
            0, 0, 0, /* 398: func */
            1, 8, 1, /* 401: pointer.func */
            	406, 0,
            0, 0, 0, /* 406: func */
            1, 8, 1, /* 409: pointer.func */
            	414, 0,
            0, 0, 0, /* 414: func */
            1, 8, 1, /* 417: pointer.func */
            	277, 0,
            1, 8, 1, /* 422: pointer.func */
            	266, 0,
            1, 8, 1, /* 427: pointer.func */
            	432, 0,
            0, 0, 0, /* 432: func */
            1, 8, 1, /* 435: pointer.func */
            	263, 0,
            1, 8, 1, /* 440: pointer.func */
            	445, 0,
            0, 0, 0, /* 445: func */
            1, 8, 1, /* 448: pointer.func */
            	453, 0,
            0, 0, 0, /* 453: func */
            1, 8, 1, /* 456: pointer.func */
            	461, 0,
            0, 0, 0, /* 461: func */
            1, 8, 1, /* 464: pointer.struct.engine_st */
            	469, 0,
            0, 216, 27, /* 469: struct.engine_st */
            	44, 0,
            	44, 8,
            	526, 16,
            	610, 24,
            	698, 32,
            	756, 40,
            	780, 48,
            	824, 56,
            	226, 64,
            	215, 72,
            	210, 80,
            	202, 88,
            	194, 96,
            	186, 104,
            	186, 112,
            	186, 120,
            	868, 128,
            	175, 136,
            	175, 144,
            	164, 152,
            	234, 160,
            	36, 168,
            	36, 172,
            	36, 176,
            	873, 184,
            	464, 200,
            	464, 208,
            1, 8, 1, /* 526: pointer.struct.rsa_meth_st */
            	531, 0,
            0, 112, 14, /* 531: struct.rsa_meth_st */
            	44, 0,
            	562, 8,
            	562, 16,
            	562, 24,
            	562, 32,
            	570, 40,
            	578, 48,
            	586, 56,
            	586, 64,
            	36, 72,
            	44, 80,
            	594, 88,
            	602, 96,
            	269, 104,
            1, 8, 1, /* 562: pointer.func */
            	567, 0,
            0, 0, 0, /* 567: func */
            1, 8, 1, /* 570: pointer.func */
            	575, 0,
            0, 0, 0, /* 575: func */
            1, 8, 1, /* 578: pointer.func */
            	583, 0,
            0, 0, 0, /* 583: func */
            1, 8, 1, /* 586: pointer.func */
            	591, 0,
            0, 0, 0, /* 591: func */
            1, 8, 1, /* 594: pointer.func */
            	599, 0,
            0, 0, 0, /* 599: func */
            1, 8, 1, /* 602: pointer.func */
            	607, 0,
            0, 0, 0, /* 607: func */
            1, 8, 1, /* 610: pointer.struct.dsa_method.1040 */
            	615, 0,
            0, 96, 12, /* 615: struct.dsa_method.1040 */
            	44, 0,
            	642, 8,
            	650, 16,
            	658, 24,
            	666, 32,
            	674, 40,
            	682, 48,
            	682, 56,
            	36, 64,
            	44, 72,
            	690, 80,
            	682, 88,
            1, 8, 1, /* 642: pointer.func */
            	647, 0,
            0, 0, 0, /* 647: func */
            1, 8, 1, /* 650: pointer.func */
            	655, 0,
            0, 0, 0, /* 655: func */
            1, 8, 1, /* 658: pointer.func */
            	663, 0,
            0, 0, 0, /* 663: func */
            1, 8, 1, /* 666: pointer.func */
            	671, 0,
            0, 0, 0, /* 671: func */
            1, 8, 1, /* 674: pointer.func */
            	679, 0,
            0, 0, 0, /* 679: func */
            1, 8, 1, /* 682: pointer.func */
            	687, 0,
            0, 0, 0, /* 687: func */
            1, 8, 1, /* 690: pointer.func */
            	695, 0,
            0, 0, 0, /* 695: func */
            1, 8, 1, /* 698: pointer.struct.dh_method */
            	703, 0,
            0, 72, 9, /* 703: struct.dh_method */
            	44, 0,
            	724, 8,
            	732, 16,
            	740, 24,
            	724, 32,
            	724, 40,
            	36, 48,
            	44, 56,
            	748, 64,
            1, 8, 1, /* 724: pointer.func */
            	729, 0,
            0, 0, 0, /* 729: func */
            1, 8, 1, /* 732: pointer.func */
            	737, 0,
            0, 0, 0, /* 737: func */
            1, 8, 1, /* 740: pointer.func */
            	745, 0,
            0, 0, 0, /* 745: func */
            1, 8, 1, /* 748: pointer.func */
            	753, 0,
            0, 0, 0, /* 753: func */
            1, 8, 1, /* 756: pointer.struct.ecdh_method */
            	761, 0,
            0, 32, 4, /* 761: struct.ecdh_method */
            	44, 0,
            	772, 8,
            	36, 16,
            	44, 24,
            1, 8, 1, /* 772: pointer.func */
            	777, 0,
            0, 0, 0, /* 777: func */
            1, 8, 1, /* 780: pointer.struct.ecdsa_method */
            	785, 0,
            0, 48, 6, /* 785: struct.ecdsa_method */
            	44, 0,
            	800, 8,
            	808, 16,
            	816, 24,
            	36, 32,
            	44, 40,
            1, 8, 1, /* 800: pointer.func */
            	805, 0,
            0, 0, 0, /* 805: func */
            1, 8, 1, /* 808: pointer.func */
            	813, 0,
            0, 0, 0, /* 813: func */
            1, 8, 1, /* 816: pointer.func */
            	821, 0,
            0, 0, 0, /* 821: func */
            1, 8, 1, /* 824: pointer.struct.rand_meth_st */
            	829, 0,
            0, 48, 6, /* 829: struct.rand_meth_st */
            	844, 0,
            	852, 8,
            	860, 16,
            	258, 24,
            	852, 32,
            	250, 40,
            1, 8, 1, /* 844: pointer.func */
            	849, 0,
            0, 0, 0, /* 849: func */
            1, 8, 1, /* 852: pointer.func */
            	857, 0,
            0, 0, 0, /* 857: func */
            1, 8, 1, /* 860: pointer.func */
            	865, 0,
            0, 0, 0, /* 865: func */
            1, 8, 1, /* 868: pointer.func */
            	180, 0,
            0, 16, 2, /* 873: struct.crypto_ex_data_st */
            	13, 0,
            	36, 8,
            0, 8, 1, /* 880: struct.fnames */
            	44, 0,
            1, 8, 1, /* 885: pointer.struct.x509_st */
            	890, 0,
            0, 184, 21, /* 890: struct.x509_st */
            	935, 0,
            	965, 8,
            	60, 16,
            	36, 24,
            	36, 28,
            	44, 32,
            	873, 40,
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
            	1061, 152,
            	79, 176,
            1, 8, 1, /* 935: pointer.struct.x509_cinf_st */
            	940, 0,
            0, 104, 11, /* 940: struct.x509_cinf_st */
            	60, 0,
            	60, 8,
            	965, 16,
            	989, 24,
            	1021, 32,
            	989, 40,
            	1033, 48,
            	60, 56,
            	60, 64,
            	13, 72,
            	1052, 80,
            1, 8, 1, /* 965: pointer.struct.X509_algor_st */
            	970, 0,
            0, 16, 2, /* 970: struct.X509_algor_st */
            	107, 0,
            	977, 8,
            1, 8, 1, /* 977: pointer.struct.asn1_type_st */
            	982, 0,
            0, 16, 2, /* 982: struct.asn1_type_st */
            	36, 0,
            	880, 8,
            1, 8, 1, /* 989: pointer.struct.X509_name_st */
            	994, 0,
            0, 40, 5, /* 994: struct.X509_name_st */
            	13, 0,
            	36, 8,
            	1007, 16,
            	44, 24,
            	36, 32,
            1, 8, 1, /* 1007: pointer.struct.buf_mem_st */
            	1012, 0,
            0, 24, 3, /* 1012: struct.buf_mem_st */
            	76, 0,
            	44, 8,
            	76, 16,
            1, 8, 1, /* 1021: pointer.struct.X509_val_st */
            	1026, 0,
            0, 16, 2, /* 1026: struct.X509_val_st */
            	60, 0,
            	60, 8,
            1, 8, 1, /* 1033: pointer.struct.X509_pubkey_st */
            	1038, 0,
            0, 24, 3, /* 1038: struct.X509_pubkey_st */
            	965, 0,
            	60, 8,
            	1047, 16,
            1, 8, 1, /* 1047: pointer.struct.evp_pkey_st */
            	280, 0,
            0, 24, 3, /* 1052: struct.ASN1_ENCODING_st */
            	44, 0,
            	76, 8,
            	36, 16,
            0, 20, 20, /* 1061: array[20].char */
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
            1, 8, 1, /* 1104: pointer.int */
            	36, 0,
        },
        .arg_entity_index = { 885, 36, 1104, 1104, },
        .ret_entity_index = 44,
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
