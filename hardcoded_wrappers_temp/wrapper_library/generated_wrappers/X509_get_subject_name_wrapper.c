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

X509_NAME * X509_get_subject_name(X509 * arg_a) 
{
    X509_NAME * ret;

    struct lib_enter_args args = {
        .entity_metadata = {
            0, 40, 5, /* 0: struct.x509_cert_aux_st */
            	13, 0,
            	13, 8,
            	51, 16,
            	51, 24,
            	13, 32,
            1, 8, 1, /* 13: pointer.struct.stack_st_OPENSSL_STRING */
            	18, 0,
            0, 32, 1, /* 18: struct.stack_st_OPENSSL_STRING */
            	23, 0,
            0, 32, 2, /* 23: struct.stack_st */
            	30, 8,
            	43, 24,
            1, 8, 1, /* 30: pointer.pointer.char */
            	35, 0,
            1, 8, 1, /* 35: pointer.char */
            	40, 0,
            0, 1, 0, /* 40: char */
            1, 8, 1, /* 43: pointer.func */
            	48, 0,
            0, 0, 0, /* 48: func */
            1, 8, 1, /* 51: pointer.struct.asn1_string_st */
            	56, 0,
            0, 24, 1, /* 56: struct.asn1_string_st */
            	35, 8,
            1, 8, 1, /* 61: pointer.struct.x509_cert_aux_st */
            	0, 0,
            0, 16, 2, /* 66: struct.NAME_CONSTRAINTS_st */
            	13, 0,
            	13, 8,
            1, 8, 1, /* 73: pointer.struct.NAME_CONSTRAINTS_st */
            	66, 0,
            0, 32, 3, /* 78: struct.X509_POLICY_DATA_st */
            	87, 8,
            	13, 16,
            	13, 24,
            1, 8, 1, /* 87: pointer.struct.asn1_object_st */
            	92, 0,
            0, 40, 3, /* 92: struct.asn1_object_st */
            	35, 0,
            	35, 8,
            	35, 24,
            1, 8, 1, /* 101: pointer.struct.X509_POLICY_DATA_st */
            	78, 0,
            1, 8, 1, /* 106: pointer.struct.X509_POLICY_CACHE_st */
            	111, 0,
            0, 40, 2, /* 111: struct.X509_POLICY_CACHE_st */
            	101, 0,
            	13, 8,
            1, 8, 1, /* 118: pointer.struct.AUTHORITY_KEYID_st */
            	123, 0,
            0, 24, 3, /* 123: struct.AUTHORITY_KEYID_st */
            	51, 0,
            	13, 8,
            	51, 16,
            1, 8, 1, /* 132: pointer.func */
            	137, 0,
            0, 0, 0, /* 137: func */
            0, 0, 0, /* 140: func */
            0, 0, 0, /* 143: func */
            0, 0, 0, /* 146: func */
            1, 8, 1, /* 149: pointer.func */
            	146, 0,
            0, 0, 0, /* 154: func */
            1, 8, 1, /* 157: pointer.func */
            	154, 0,
            0, 0, 0, /* 162: func */
            1, 8, 1, /* 165: pointer.func */
            	162, 0,
            0, 0, 0, /* 170: func */
            1, 8, 1, /* 173: pointer.func */
            	170, 0,
            0, 0, 0, /* 178: func */
            1, 8, 1, /* 181: pointer.func */
            	178, 0,
            0, 0, 0, /* 186: struct.store_method_st */
            1, 8, 1, /* 189: pointer.struct.store_method_st */
            	186, 0,
            0, 0, 0, /* 194: func */
            1, 8, 1, /* 197: pointer.struct.ENGINE_CMD_DEFN_st */
            	202, 0,
            0, 32, 2, /* 202: struct.ENGINE_CMD_DEFN_st */
            	35, 8,
            	35, 16,
            1, 8, 1, /* 209: pointer.func */
            	194, 0,
            0, 0, 0, /* 214: func */
            1, 8, 1, /* 217: pointer.func */
            	214, 0,
            1, 8, 1, /* 222: pointer.func */
            	140, 0,
            0, 0, 0, /* 227: func */
            1, 8, 1, /* 230: pointer.struct.ecdsa_method */
            	235, 0,
            0, 48, 5, /* 235: struct.ecdsa_method */
            	35, 0,
            	248, 8,
            	256, 16,
            	264, 24,
            	35, 40,
            1, 8, 1, /* 248: pointer.func */
            	253, 0,
            0, 0, 0, /* 253: func */
            1, 8, 1, /* 256: pointer.func */
            	261, 0,
            0, 0, 0, /* 261: func */
            1, 8, 1, /* 264: pointer.func */
            	269, 0,
            0, 0, 0, /* 269: func */
            1, 8, 1, /* 272: pointer.func */
            	227, 0,
            0, 0, 0, /* 277: func */
            0, 0, 0, /* 280: func */
            0, 0, 0, /* 283: func */
            1, 8, 1, /* 286: pointer.func */
            	291, 0,
            0, 0, 0, /* 291: func */
            1, 8, 1, /* 294: pointer.func */
            	299, 0,
            0, 0, 0, /* 299: func */
            0, 0, 0, /* 302: func */
            1, 8, 1, /* 305: pointer.func */
            	302, 0,
            0, 0, 0, /* 310: func */
            0, 24, 3, /* 313: struct.X509_pubkey_st.2915 */
            	322, 0,
            	51, 8,
            	349, 16,
            1, 8, 1, /* 322: pointer.struct.X509_algor_st */
            	327, 0,
            0, 16, 2, /* 327: struct.X509_algor_st */
            	87, 0,
            	334, 8,
            1, 8, 1, /* 334: pointer.struct.asn1_type_st */
            	339, 0,
            0, 16, 1, /* 339: struct.asn1_type_st */
            	344, 8,
            0, 8, 1, /* 344: struct.fnames */
            	35, 0,
            1, 8, 1, /* 349: pointer.struct.evp_pkey_st.2930 */
            	354, 0,
            0, 56, 4, /* 354: struct.evp_pkey_st.2930 */
            	365, 16,
            	508, 24,
            	344, 32,
            	13, 48,
            1, 8, 1, /* 365: pointer.struct.evp_pkey_asn1_method_st.2928 */
            	370, 0,
            0, 208, 24, /* 370: struct.evp_pkey_asn1_method_st.2928 */
            	35, 16,
            	35, 24,
            	421, 32,
            	426, 40,
            	305, 48,
            	434, 56,
            	439, 64,
            	447, 72,
            	434, 80,
            	452, 88,
            	452, 96,
            	460, 104,
            	468, 112,
            	452, 120,
            	305, 128,
            	305, 136,
            	434, 144,
            	476, 152,
            	272, 160,
            	484, 168,
            	460, 176,
            	468, 184,
            	492, 192,
            	500, 200,
            1, 8, 1, /* 421: pointer.func */
            	310, 0,
            1, 8, 1, /* 426: pointer.func */
            	431, 0,
            0, 0, 0, /* 431: func */
            1, 8, 1, /* 434: pointer.func */
            	283, 0,
            1, 8, 1, /* 439: pointer.func */
            	444, 0,
            0, 0, 0, /* 444: func */
            1, 8, 1, /* 447: pointer.func */
            	280, 0,
            1, 8, 1, /* 452: pointer.func */
            	457, 0,
            0, 0, 0, /* 457: func */
            1, 8, 1, /* 460: pointer.func */
            	465, 0,
            0, 0, 0, /* 465: func */
            1, 8, 1, /* 468: pointer.func */
            	473, 0,
            0, 0, 0, /* 473: func */
            1, 8, 1, /* 476: pointer.func */
            	481, 0,
            0, 0, 0, /* 481: func */
            1, 8, 1, /* 484: pointer.func */
            	489, 0,
            0, 0, 0, /* 489: func */
            1, 8, 1, /* 492: pointer.func */
            	497, 0,
            0, 0, 0, /* 497: func */
            1, 8, 1, /* 500: pointer.func */
            	505, 0,
            0, 0, 0, /* 505: func */
            1, 8, 1, /* 508: pointer.struct.engine_st */
            	513, 0,
            0, 216, 24, /* 513: struct.engine_st */
            	35, 0,
            	35, 8,
            	564, 16,
            	651, 24,
            	729, 32,
            	785, 40,
            	230, 48,
            	799, 56,
            	189, 64,
            	181, 72,
            	173, 80,
            	165, 88,
            	157, 96,
            	149, 104,
            	149, 112,
            	149, 120,
            	843, 128,
            	222, 136,
            	222, 144,
            	132, 152,
            	197, 160,
            	848, 184,
            	508, 200,
            	508, 208,
            1, 8, 1, /* 564: pointer.struct.rsa_meth_st */
            	569, 0,
            0, 112, 13, /* 569: struct.rsa_meth_st */
            	35, 0,
            	598, 8,
            	598, 16,
            	598, 24,
            	598, 32,
            	606, 40,
            	614, 48,
            	622, 56,
            	622, 64,
            	35, 80,
            	630, 88,
            	638, 96,
            	643, 104,
            1, 8, 1, /* 598: pointer.func */
            	603, 0,
            0, 0, 0, /* 603: func */
            1, 8, 1, /* 606: pointer.func */
            	611, 0,
            0, 0, 0, /* 611: func */
            1, 8, 1, /* 614: pointer.func */
            	619, 0,
            0, 0, 0, /* 619: func */
            1, 8, 1, /* 622: pointer.func */
            	627, 0,
            0, 0, 0, /* 627: func */
            1, 8, 1, /* 630: pointer.func */
            	635, 0,
            0, 0, 0, /* 635: func */
            1, 8, 1, /* 638: pointer.func */
            	277, 0,
            1, 8, 1, /* 643: pointer.func */
            	648, 0,
            0, 0, 0, /* 648: func */
            1, 8, 1, /* 651: pointer.struct.dsa_method.1040 */
            	656, 0,
            0, 96, 11, /* 656: struct.dsa_method.1040 */
            	35, 0,
            	681, 8,
            	689, 16,
            	697, 24,
            	705, 32,
            	713, 40,
            	294, 48,
            	294, 56,
            	35, 72,
            	721, 80,
            	294, 88,
            1, 8, 1, /* 681: pointer.func */
            	686, 0,
            0, 0, 0, /* 686: func */
            1, 8, 1, /* 689: pointer.func */
            	694, 0,
            0, 0, 0, /* 694: func */
            1, 8, 1, /* 697: pointer.func */
            	702, 0,
            0, 0, 0, /* 702: func */
            1, 8, 1, /* 705: pointer.func */
            	710, 0,
            0, 0, 0, /* 710: func */
            1, 8, 1, /* 713: pointer.func */
            	718, 0,
            0, 0, 0, /* 718: func */
            1, 8, 1, /* 721: pointer.func */
            	726, 0,
            0, 0, 0, /* 726: func */
            1, 8, 1, /* 729: pointer.struct.dh_method */
            	734, 0,
            0, 72, 8, /* 734: struct.dh_method */
            	35, 0,
            	753, 8,
            	761, 16,
            	769, 24,
            	753, 32,
            	753, 40,
            	35, 56,
            	777, 64,
            1, 8, 1, /* 753: pointer.func */
            	758, 0,
            0, 0, 0, /* 758: func */
            1, 8, 1, /* 761: pointer.func */
            	766, 0,
            0, 0, 0, /* 766: func */
            1, 8, 1, /* 769: pointer.func */
            	774, 0,
            0, 0, 0, /* 774: func */
            1, 8, 1, /* 777: pointer.func */
            	782, 0,
            0, 0, 0, /* 782: func */
            1, 8, 1, /* 785: pointer.struct.ecdh_method */
            	790, 0,
            0, 32, 3, /* 790: struct.ecdh_method */
            	35, 0,
            	286, 8,
            	35, 24,
            1, 8, 1, /* 799: pointer.struct.rand_meth_st */
            	804, 0,
            0, 48, 6, /* 804: struct.rand_meth_st */
            	819, 0,
            	827, 8,
            	835, 16,
            	217, 24,
            	827, 32,
            	209, 40,
            1, 8, 1, /* 819: pointer.func */
            	824, 0,
            0, 0, 0, /* 824: func */
            1, 8, 1, /* 827: pointer.func */
            	832, 0,
            0, 0, 0, /* 832: func */
            1, 8, 1, /* 835: pointer.func */
            	840, 0,
            0, 0, 0, /* 840: func */
            1, 8, 1, /* 843: pointer.func */
            	143, 0,
            0, 16, 1, /* 848: struct.crypto_ex_data_st */
            	13, 0,
            0, 24, 1, /* 853: struct.buf_mem_st */
            	35, 8,
            0, 20, 0, /* 858: array[20].char */
            1, 8, 1, /* 861: pointer.struct.buf_mem_st */
            	853, 0,
            0, 4, 0, /* 866: int */
            0, 24, 1, /* 869: struct.ASN1_ENCODING_st */
            	35, 0,
            0, 8, 0, /* 874: long */
            0, 40, 3, /* 877: struct.X509_name_st */
            	13, 0,
            	861, 16,
            	35, 24,
            1, 8, 1, /* 886: pointer.struct.x509_st.3164 */
            	891, 0,
            0, 184, 12, /* 891: struct.x509_st.3164 */
            	918, 0,
            	322, 8,
            	51, 16,
            	35, 32,
            	848, 40,
            	51, 104,
            	118, 112,
            	106, 120,
            	13, 128,
            	13, 136,
            	73, 144,
            	61, 176,
            1, 8, 1, /* 918: pointer.struct.x509_cinf_st.3159 */
            	923, 0,
            0, 104, 11, /* 923: struct.x509_cinf_st.3159 */
            	51, 0,
            	51, 8,
            	322, 16,
            	948, 24,
            	953, 32,
            	948, 40,
            	965, 48,
            	51, 56,
            	51, 64,
            	13, 72,
            	869, 80,
            1, 8, 1, /* 948: pointer.struct.X509_name_st */
            	877, 0,
            1, 8, 1, /* 953: pointer.struct.X509_val_st */
            	958, 0,
            0, 16, 2, /* 958: struct.X509_val_st */
            	51, 0,
            	51, 8,
            1, 8, 1, /* 965: pointer.struct.X509_pubkey_st.2915 */
            	313, 0,
        },
        .arg_entity_index = { 886, },
        .ret_entity_index = 948,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    X509_NAME * *new_ret_ptr = (X509_NAME * *)new_args->ret;

    X509_NAME * (*orig_X509_get_subject_name)(X509 *);
    orig_X509_get_subject_name = dlsym(RTLD_NEXT, "X509_get_subject_name");
    *new_ret_ptr = (*orig_X509_get_subject_name)(new_arg_a);

    syscall(889);

    return ret;
}

