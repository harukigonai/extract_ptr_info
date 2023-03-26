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

EVP_PKEY * X509_get_pubkey(X509 * arg_a) 
{
    EVP_PKEY * ret;

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
            0, 24, 3, /* 164: struct.X509_pubkey_st.2915 */
            	173, 0,
            	60, 8,
            	202, 16,
            1, 8, 1, /* 173: pointer.struct.X509_algor_st */
            	178, 0,
            0, 16, 2, /* 178: struct.X509_algor_st */
            	107, 0,
            	185, 8,
            1, 8, 1, /* 185: pointer.struct.asn1_type_st */
            	190, 0,
            0, 16, 2, /* 190: struct.asn1_type_st */
            	36, 0,
            	197, 8,
            0, 8, 1, /* 197: struct.fnames */
            	44, 0,
            1, 8, 1, /* 202: pointer.struct.evp_pkey_st.2930 */
            	207, 0,
            0, 56, 8, /* 207: struct.evp_pkey_st.2930 */
            	36, 0,
            	36, 4,
            	36, 8,
            	226, 16,
            	400, 24,
            	197, 32,
            	36, 40,
            	13, 48,
            1, 8, 1, /* 226: pointer.struct.evp_pkey_asn1_method_st.2928 */
            	231, 0,
            0, 208, 27, /* 231: struct.evp_pkey_asn1_method_st.2928 */
            	36, 0,
            	36, 4,
            	76, 8,
            	44, 16,
            	44, 24,
            	288, 32,
            	296, 40,
            	304, 48,
            	312, 56,
            	320, 64,
            	328, 72,
            	312, 80,
            	336, 88,
            	336, 96,
            	344, 104,
            	352, 112,
            	336, 120,
            	304, 128,
            	304, 136,
            	312, 144,
            	360, 152,
            	368, 160,
            	376, 168,
            	344, 176,
            	352, 184,
            	384, 192,
            	392, 200,
            1, 8, 1, /* 288: pointer.func */
            	293, 0,
            0, 0, 0, /* 293: func */
            1, 8, 1, /* 296: pointer.func */
            	301, 0,
            0, 0, 0, /* 301: func */
            1, 8, 1, /* 304: pointer.func */
            	309, 0,
            0, 0, 0, /* 309: func */
            1, 8, 1, /* 312: pointer.func */
            	317, 0,
            0, 0, 0, /* 317: func */
            1, 8, 1, /* 320: pointer.func */
            	325, 0,
            0, 0, 0, /* 325: func */
            1, 8, 1, /* 328: pointer.func */
            	333, 0,
            0, 0, 0, /* 333: func */
            1, 8, 1, /* 336: pointer.func */
            	341, 0,
            0, 0, 0, /* 341: func */
            1, 8, 1, /* 344: pointer.func */
            	349, 0,
            0, 0, 0, /* 349: func */
            1, 8, 1, /* 352: pointer.func */
            	357, 0,
            0, 0, 0, /* 357: func */
            1, 8, 1, /* 360: pointer.func */
            	365, 0,
            0, 0, 0, /* 365: func */
            1, 8, 1, /* 368: pointer.func */
            	373, 0,
            0, 0, 0, /* 373: func */
            1, 8, 1, /* 376: pointer.func */
            	381, 0,
            0, 0, 0, /* 381: func */
            1, 8, 1, /* 384: pointer.func */
            	389, 0,
            0, 0, 0, /* 389: func */
            1, 8, 1, /* 392: pointer.func */
            	397, 0,
            0, 0, 0, /* 397: func */
            1, 8, 1, /* 400: pointer.struct.engine_st */
            	405, 0,
            0, 216, 27, /* 405: struct.engine_st */
            	44, 0,
            	44, 8,
            	462, 16,
            	554, 24,
            	642, 32,
            	700, 40,
            	724, 48,
            	768, 56,
            	828, 64,
            	836, 72,
            	844, 80,
            	852, 88,
            	860, 96,
            	868, 104,
            	868, 112,
            	868, 120,
            	876, 128,
            	884, 136,
            	884, 144,
            	892, 152,
            	900, 160,
            	36, 168,
            	36, 172,
            	36, 176,
            	916, 184,
            	400, 200,
            	400, 208,
            1, 8, 1, /* 462: pointer.struct.rsa_meth_st */
            	467, 0,
            0, 112, 14, /* 467: struct.rsa_meth_st */
            	44, 0,
            	498, 8,
            	498, 16,
            	498, 24,
            	498, 32,
            	506, 40,
            	514, 48,
            	522, 56,
            	522, 64,
            	36, 72,
            	44, 80,
            	530, 88,
            	538, 96,
            	546, 104,
            1, 8, 1, /* 498: pointer.func */
            	503, 0,
            0, 0, 0, /* 503: func */
            1, 8, 1, /* 506: pointer.func */
            	511, 0,
            0, 0, 0, /* 511: func */
            1, 8, 1, /* 514: pointer.func */
            	519, 0,
            0, 0, 0, /* 519: func */
            1, 8, 1, /* 522: pointer.func */
            	527, 0,
            0, 0, 0, /* 527: func */
            1, 8, 1, /* 530: pointer.func */
            	535, 0,
            0, 0, 0, /* 535: func */
            1, 8, 1, /* 538: pointer.func */
            	543, 0,
            0, 0, 0, /* 543: func */
            1, 8, 1, /* 546: pointer.func */
            	551, 0,
            0, 0, 0, /* 551: func */
            1, 8, 1, /* 554: pointer.struct.dsa_method.1040 */
            	559, 0,
            0, 96, 12, /* 559: struct.dsa_method.1040 */
            	44, 0,
            	586, 8,
            	594, 16,
            	602, 24,
            	610, 32,
            	618, 40,
            	626, 48,
            	626, 56,
            	36, 64,
            	44, 72,
            	634, 80,
            	626, 88,
            1, 8, 1, /* 586: pointer.func */
            	591, 0,
            0, 0, 0, /* 591: func */
            1, 8, 1, /* 594: pointer.func */
            	599, 0,
            0, 0, 0, /* 599: func */
            1, 8, 1, /* 602: pointer.func */
            	607, 0,
            0, 0, 0, /* 607: func */
            1, 8, 1, /* 610: pointer.func */
            	615, 0,
            0, 0, 0, /* 615: func */
            1, 8, 1, /* 618: pointer.func */
            	623, 0,
            0, 0, 0, /* 623: func */
            1, 8, 1, /* 626: pointer.func */
            	631, 0,
            0, 0, 0, /* 631: func */
            1, 8, 1, /* 634: pointer.func */
            	639, 0,
            0, 0, 0, /* 639: func */
            1, 8, 1, /* 642: pointer.struct.dh_method */
            	647, 0,
            0, 72, 9, /* 647: struct.dh_method */
            	44, 0,
            	668, 8,
            	676, 16,
            	684, 24,
            	668, 32,
            	668, 40,
            	36, 48,
            	44, 56,
            	692, 64,
            1, 8, 1, /* 668: pointer.func */
            	673, 0,
            0, 0, 0, /* 673: func */
            1, 8, 1, /* 676: pointer.func */
            	681, 0,
            0, 0, 0, /* 681: func */
            1, 8, 1, /* 684: pointer.func */
            	689, 0,
            0, 0, 0, /* 689: func */
            1, 8, 1, /* 692: pointer.func */
            	697, 0,
            0, 0, 0, /* 697: func */
            1, 8, 1, /* 700: pointer.struct.ecdh_method */
            	705, 0,
            0, 32, 4, /* 705: struct.ecdh_method */
            	44, 0,
            	716, 8,
            	36, 16,
            	44, 24,
            1, 8, 1, /* 716: pointer.func */
            	721, 0,
            0, 0, 0, /* 721: func */
            1, 8, 1, /* 724: pointer.struct.ecdsa_method */
            	729, 0,
            0, 48, 6, /* 729: struct.ecdsa_method */
            	44, 0,
            	744, 8,
            	752, 16,
            	760, 24,
            	36, 32,
            	44, 40,
            1, 8, 1, /* 744: pointer.func */
            	749, 0,
            0, 0, 0, /* 749: func */
            1, 8, 1, /* 752: pointer.func */
            	757, 0,
            0, 0, 0, /* 757: func */
            1, 8, 1, /* 760: pointer.func */
            	765, 0,
            0, 0, 0, /* 765: func */
            1, 8, 1, /* 768: pointer.struct.rand_meth_st */
            	773, 0,
            0, 48, 6, /* 773: struct.rand_meth_st */
            	788, 0,
            	796, 8,
            	804, 16,
            	812, 24,
            	796, 32,
            	820, 40,
            1, 8, 1, /* 788: pointer.func */
            	793, 0,
            0, 0, 0, /* 793: func */
            1, 8, 1, /* 796: pointer.func */
            	801, 0,
            0, 0, 0, /* 801: func */
            1, 8, 1, /* 804: pointer.func */
            	809, 0,
            0, 0, 0, /* 809: func */
            1, 8, 1, /* 812: pointer.func */
            	817, 0,
            0, 0, 0, /* 817: func */
            1, 8, 1, /* 820: pointer.func */
            	825, 0,
            0, 0, 0, /* 825: func */
            1, 8, 1, /* 828: pointer.struct.store_method_st */
            	833, 0,
            0, 0, 0, /* 833: struct.store_method_st */
            1, 8, 1, /* 836: pointer.func */
            	841, 0,
            0, 0, 0, /* 841: func */
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
            	873, 0,
            0, 0, 0, /* 873: func */
            1, 8, 1, /* 876: pointer.func */
            	881, 0,
            0, 0, 0, /* 881: func */
            1, 8, 1, /* 884: pointer.func */
            	889, 0,
            0, 0, 0, /* 889: func */
            1, 8, 1, /* 892: pointer.func */
            	897, 0,
            0, 0, 0, /* 897: func */
            1, 8, 1, /* 900: pointer.struct.ENGINE_CMD_DEFN_st */
            	905, 0,
            0, 32, 4, /* 905: struct.ENGINE_CMD_DEFN_st */
            	36, 0,
            	44, 8,
            	44, 16,
            	36, 24,
            0, 16, 2, /* 916: struct.crypto_ex_data_st */
            	13, 0,
            	36, 8,
            1, 8, 1, /* 923: pointer.struct.X509_val_st */
            	928, 0,
            0, 16, 2, /* 928: struct.X509_val_st */
            	60, 0,
            	60, 8,
            0, 24, 3, /* 935: struct.buf_mem_st */
            	76, 0,
            	44, 8,
            	76, 16,
            1, 8, 1, /* 944: pointer.struct.buf_mem_st */
            	935, 0,
            0, 40, 5, /* 949: struct.X509_name_st */
            	13, 0,
            	36, 8,
            	944, 16,
            	44, 24,
            	36, 32,
            1, 8, 1, /* 962: pointer.struct.X509_name_st */
            	949, 0,
            0, 104, 11, /* 967: struct.x509_cinf_st.3159 */
            	60, 0,
            	60, 8,
            	173, 16,
            	962, 24,
            	923, 32,
            	962, 40,
            	992, 48,
            	60, 56,
            	60, 64,
            	13, 72,
            	997, 80,
            1, 8, 1, /* 992: pointer.struct.X509_pubkey_st.2915 */
            	164, 0,
            0, 24, 3, /* 997: struct.ASN1_ENCODING_st */
            	44, 0,
            	76, 8,
            	36, 16,
            0, 20, 20, /* 1006: array[20].char */
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
            1, 8, 1, /* 1049: pointer.struct.x509_cinf_st.3159 */
            	967, 0,
            1, 8, 1, /* 1054: pointer.struct.x509_st.3164 */
            	1059, 0,
            0, 184, 21, /* 1059: struct.x509_st.3164 */
            	1049, 0,
            	173, 8,
            	60, 16,
            	36, 24,
            	36, 28,
            	44, 32,
            	916, 40,
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
            	1006, 152,
            	79, 176,
        },
        .arg_entity_index = { 1054, },
        .ret_entity_index = 202,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    EVP_PKEY * *new_ret_ptr = (EVP_PKEY * *)new_args->ret;

    EVP_PKEY * (*orig_X509_get_pubkey)(X509 *);
    orig_X509_get_pubkey = dlsym(RTLD_NEXT, "X509_get_pubkey");
    *new_ret_ptr = (*orig_X509_get_pubkey)(new_arg_a);

    syscall(889);

    return ret;
}
