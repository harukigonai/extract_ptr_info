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
    printf("X509_get_pubkey called\n");
    EVP_PKEY * ret;

    struct lib_enter_args args = {
        .num_args = 0,
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
            0, 24, 3, /* 132: struct.X509_pubkey_st.2915 */
            	141, 0,
            	51, 8,
            	168, 16,
            1, 8, 1, /* 141: pointer.struct.X509_algor_st */
            	146, 0,
            0, 16, 2, /* 146: struct.X509_algor_st */
            	87, 0,
            	153, 8,
            1, 8, 1, /* 153: pointer.struct.asn1_type_st */
            	158, 0,
            0, 16, 1, /* 158: struct.asn1_type_st */
            	163, 8,
            0, 8, 1, /* 163: struct.fnames */
            	35, 0,
            1, 8, 1, /* 168: pointer.struct.evp_pkey_st.2930 */
            	173, 0,
            0, 56, 4, /* 173: struct.evp_pkey_st.2930 */
            	184, 16,
            	352, 24,
            	163, 32,
            	13, 48,
            1, 8, 1, /* 184: pointer.struct.evp_pkey_asn1_method_st.2928 */
            	189, 0,
            0, 208, 24, /* 189: struct.evp_pkey_asn1_method_st.2928 */
            	35, 16,
            	35, 24,
            	240, 32,
            	248, 40,
            	256, 48,
            	264, 56,
            	272, 64,
            	280, 72,
            	264, 80,
            	288, 88,
            	288, 96,
            	296, 104,
            	304, 112,
            	288, 120,
            	256, 128,
            	256, 136,
            	264, 144,
            	312, 152,
            	320, 160,
            	328, 168,
            	296, 176,
            	304, 184,
            	336, 192,
            	344, 200,
            1, 8, 1, /* 240: pointer.func */
            	245, 0,
            0, 0, 0, /* 245: func */
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
            	277, 0,
            0, 0, 0, /* 277: func */
            1, 8, 1, /* 280: pointer.func */
            	285, 0,
            0, 0, 0, /* 285: func */
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
            1, 8, 1, /* 352: pointer.struct.engine_st */
            	357, 0,
            0, 216, 24, /* 357: struct.engine_st */
            	35, 0,
            	35, 8,
            	408, 16,
            	498, 24,
            	584, 32,
            	640, 40,
            	662, 48,
            	704, 56,
            	764, 64,
            	772, 72,
            	780, 80,
            	788, 88,
            	796, 96,
            	804, 104,
            	804, 112,
            	804, 120,
            	812, 128,
            	820, 136,
            	820, 144,
            	828, 152,
            	836, 160,
            	848, 184,
            	352, 200,
            	352, 208,
            1, 8, 1, /* 408: pointer.struct.rsa_meth_st */
            	413, 0,
            0, 112, 13, /* 413: struct.rsa_meth_st */
            	35, 0,
            	442, 8,
            	442, 16,
            	442, 24,
            	442, 32,
            	450, 40,
            	458, 48,
            	466, 56,
            	466, 64,
            	35, 80,
            	474, 88,
            	482, 96,
            	490, 104,
            1, 8, 1, /* 442: pointer.func */
            	447, 0,
            0, 0, 0, /* 447: func */
            1, 8, 1, /* 450: pointer.func */
            	455, 0,
            0, 0, 0, /* 455: func */
            1, 8, 1, /* 458: pointer.func */
            	463, 0,
            0, 0, 0, /* 463: func */
            1, 8, 1, /* 466: pointer.func */
            	471, 0,
            0, 0, 0, /* 471: func */
            1, 8, 1, /* 474: pointer.func */
            	479, 0,
            0, 0, 0, /* 479: func */
            1, 8, 1, /* 482: pointer.func */
            	487, 0,
            0, 0, 0, /* 487: func */
            1, 8, 1, /* 490: pointer.func */
            	495, 0,
            0, 0, 0, /* 495: func */
            1, 8, 1, /* 498: pointer.struct.dsa_method.1040 */
            	503, 0,
            0, 96, 11, /* 503: struct.dsa_method.1040 */
            	35, 0,
            	528, 8,
            	536, 16,
            	544, 24,
            	552, 32,
            	560, 40,
            	568, 48,
            	568, 56,
            	35, 72,
            	576, 80,
            	568, 88,
            1, 8, 1, /* 528: pointer.func */
            	533, 0,
            0, 0, 0, /* 533: func */
            1, 8, 1, /* 536: pointer.func */
            	541, 0,
            0, 0, 0, /* 541: func */
            1, 8, 1, /* 544: pointer.func */
            	549, 0,
            0, 0, 0, /* 549: func */
            1, 8, 1, /* 552: pointer.func */
            	557, 0,
            0, 0, 0, /* 557: func */
            1, 8, 1, /* 560: pointer.func */
            	565, 0,
            0, 0, 0, /* 565: func */
            1, 8, 1, /* 568: pointer.func */
            	573, 0,
            0, 0, 0, /* 573: func */
            1, 8, 1, /* 576: pointer.func */
            	581, 0,
            0, 0, 0, /* 581: func */
            1, 8, 1, /* 584: pointer.struct.dh_method */
            	589, 0,
            0, 72, 8, /* 589: struct.dh_method */
            	35, 0,
            	608, 8,
            	616, 16,
            	624, 24,
            	608, 32,
            	608, 40,
            	35, 56,
            	632, 64,
            1, 8, 1, /* 608: pointer.func */
            	613, 0,
            0, 0, 0, /* 613: func */
            1, 8, 1, /* 616: pointer.func */
            	621, 0,
            0, 0, 0, /* 621: func */
            1, 8, 1, /* 624: pointer.func */
            	629, 0,
            0, 0, 0, /* 629: func */
            1, 8, 1, /* 632: pointer.func */
            	637, 0,
            0, 0, 0, /* 637: func */
            1, 8, 1, /* 640: pointer.struct.ecdh_method */
            	645, 0,
            0, 32, 3, /* 645: struct.ecdh_method */
            	35, 0,
            	654, 8,
            	35, 24,
            1, 8, 1, /* 654: pointer.func */
            	659, 0,
            0, 0, 0, /* 659: func */
            1, 8, 1, /* 662: pointer.struct.ecdsa_method */
            	667, 0,
            0, 48, 5, /* 667: struct.ecdsa_method */
            	35, 0,
            	680, 8,
            	688, 16,
            	696, 24,
            	35, 40,
            1, 8, 1, /* 680: pointer.func */
            	685, 0,
            0, 0, 0, /* 685: func */
            1, 8, 1, /* 688: pointer.func */
            	693, 0,
            0, 0, 0, /* 693: func */
            1, 8, 1, /* 696: pointer.func */
            	701, 0,
            0, 0, 0, /* 701: func */
            1, 8, 1, /* 704: pointer.struct.rand_meth_st */
            	709, 0,
            0, 48, 6, /* 709: struct.rand_meth_st */
            	724, 0,
            	732, 8,
            	740, 16,
            	748, 24,
            	732, 32,
            	756, 40,
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
            1, 8, 1, /* 756: pointer.func */
            	761, 0,
            0, 0, 0, /* 761: func */
            1, 8, 1, /* 764: pointer.struct.store_method_st */
            	769, 0,
            0, 0, 0, /* 769: struct.store_method_st */
            1, 8, 1, /* 772: pointer.func */
            	777, 0,
            0, 0, 0, /* 777: func */
            1, 8, 1, /* 780: pointer.func */
            	785, 0,
            0, 0, 0, /* 785: func */
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
            1, 8, 1, /* 828: pointer.func */
            	833, 0,
            0, 0, 0, /* 833: func */
            1, 8, 1, /* 836: pointer.struct.ENGINE_CMD_DEFN_st */
            	841, 0,
            0, 32, 2, /* 841: struct.ENGINE_CMD_DEFN_st */
            	35, 8,
            	35, 16,
            0, 16, 1, /* 848: struct.crypto_ex_data_st */
            	13, 0,
            1, 8, 1, /* 853: pointer.struct.X509_val_st */
            	858, 0,
            0, 16, 2, /* 858: struct.X509_val_st */
            	51, 0,
            	51, 8,
            0, 24, 1, /* 865: struct.buf_mem_st */
            	35, 8,
            1, 8, 1, /* 870: pointer.struct.buf_mem_st */
            	865, 0,
            0, 40, 3, /* 875: struct.X509_name_st */
            	13, 0,
            	870, 16,
            	35, 24,
            1, 8, 1, /* 884: pointer.struct.X509_name_st */
            	875, 0,
            0, 104, 11, /* 889: struct.x509_cinf_st.3159 */
            	51, 0,
            	51, 8,
            	141, 16,
            	884, 24,
            	853, 32,
            	884, 40,
            	914, 48,
            	51, 56,
            	51, 64,
            	13, 72,
            	919, 80,
            1, 8, 1, /* 914: pointer.struct.X509_pubkey_st.2915 */
            	132, 0,
            0, 24, 1, /* 919: struct.ASN1_ENCODING_st */
            	35, 0,
            0, 20, 0, /* 924: array[20].char */
            1, 8, 1, /* 927: pointer.struct.x509_st.3164 */
            	932, 0,
            0, 184, 12, /* 932: struct.x509_st.3164 */
            	959, 0,
            	141, 8,
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
            1, 8, 1, /* 959: pointer.struct.x509_cinf_st.3159 */
            	889, 0,
            0, 4, 0, /* 964: int */
            0, 8, 0, /* 967: long */
        },
        .arg_entity_index = { 927, },
        .ret_entity_index = 168,
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

