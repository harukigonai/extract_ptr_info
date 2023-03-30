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
    if (syscall(890))
        return _X509_get_ext_d2i(arg_a,arg_b,arg_c,arg_d);
    else {
        void * (*orig_X509_get_ext_d2i)(X509 *,int,int *,int *);
        orig_X509_get_ext_d2i = dlsym(RTLD_NEXT, "X509_get_ext_d2i");
        return orig_X509_get_ext_d2i(arg_a,arg_b,arg_c,arg_d);
    }
}

void * _X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d) 
{
    printf("X509_get_ext_d2i called\n");
    void * ret;

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
            1, 8, 1, /* 132: pointer.func */
            	137, 0,
            0, 0, 0, /* 137: func */
            0, 0, 0, /* 140: func */
            1, 8, 1, /* 143: pointer.func */
            	140, 0,
            0, 0, 0, /* 148: func */
            0, 0, 0, /* 151: func */
            1, 8, 1, /* 154: pointer.func */
            	151, 0,
            0, 0, 0, /* 159: func */
            1, 8, 1, /* 162: pointer.func */
            	159, 0,
            0, 0, 0, /* 167: func */
            1, 8, 1, /* 170: pointer.func */
            	167, 0,
            0, 0, 0, /* 175: func */
            1, 8, 1, /* 178: pointer.func */
            	175, 0,
            1, 8, 1, /* 183: pointer.func */
            	188, 0,
            0, 0, 0, /* 188: func */
            0, 0, 0, /* 191: struct.store_method_st */
            1, 8, 1, /* 194: pointer.struct.store_method_st */
            	191, 0,
            0, 0, 0, /* 199: func */
            1, 8, 1, /* 202: pointer.struct.ENGINE_CMD_DEFN_st */
            	207, 0,
            0, 32, 2, /* 207: struct.ENGINE_CMD_DEFN_st */
            	35, 8,
            	35, 16,
            1, 8, 1, /* 214: pointer.func */
            	199, 0,
            0, 0, 0, /* 219: func */
            1, 8, 1, /* 222: pointer.func */
            	219, 0,
            0, 0, 0, /* 227: func */
            0, 0, 0, /* 230: func */
            1, 8, 1, /* 233: pointer.func */
            	238, 0,
            0, 0, 0, /* 238: func */
            0, 56, 4, /* 241: struct.evp_pkey_st */
            	252, 16,
            	414, 24,
            	812, 32,
            	13, 48,
            1, 8, 1, /* 252: pointer.struct.evp_pkey_asn1_method_st */
            	257, 0,
            0, 208, 24, /* 257: struct.evp_pkey_asn1_method_st */
            	35, 16,
            	35, 24,
            	308, 32,
            	316, 40,
            	324, 48,
            	332, 56,
            	340, 64,
            	348, 72,
            	332, 80,
            	356, 88,
            	356, 96,
            	364, 104,
            	372, 112,
            	356, 120,
            	324, 128,
            	324, 136,
            	332, 144,
            	377, 152,
            	385, 160,
            	390, 168,
            	364, 176,
            	372, 184,
            	398, 192,
            	406, 200,
            1, 8, 1, /* 308: pointer.struct.unnamed */
            	313, 0,
            0, 0, 0, /* 313: struct.unnamed */
            1, 8, 1, /* 316: pointer.func */
            	321, 0,
            0, 0, 0, /* 321: func */
            1, 8, 1, /* 324: pointer.func */
            	329, 0,
            0, 0, 0, /* 329: func */
            1, 8, 1, /* 332: pointer.func */
            	337, 0,
            0, 0, 0, /* 337: func */
            1, 8, 1, /* 340: pointer.func */
            	345, 0,
            0, 0, 0, /* 345: func */
            1, 8, 1, /* 348: pointer.func */
            	353, 0,
            0, 0, 0, /* 353: func */
            1, 8, 1, /* 356: pointer.func */
            	361, 0,
            0, 0, 0, /* 361: func */
            1, 8, 1, /* 364: pointer.func */
            	369, 0,
            0, 0, 0, /* 369: func */
            1, 8, 1, /* 372: pointer.func */
            	230, 0,
            1, 8, 1, /* 377: pointer.func */
            	382, 0,
            0, 0, 0, /* 382: func */
            1, 8, 1, /* 385: pointer.func */
            	227, 0,
            1, 8, 1, /* 390: pointer.func */
            	395, 0,
            0, 0, 0, /* 395: func */
            1, 8, 1, /* 398: pointer.func */
            	403, 0,
            0, 0, 0, /* 403: func */
            1, 8, 1, /* 406: pointer.func */
            	411, 0,
            0, 0, 0, /* 411: func */
            1, 8, 1, /* 414: pointer.struct.engine_st */
            	419, 0,
            0, 216, 24, /* 419: struct.engine_st */
            	35, 0,
            	35, 8,
            	470, 16,
            	552, 24,
            	638, 32,
            	694, 40,
            	716, 48,
            	758, 56,
            	194, 64,
            	183, 72,
            	178, 80,
            	170, 88,
            	162, 96,
            	154, 104,
            	154, 112,
            	154, 120,
            	802, 128,
            	143, 136,
            	143, 144,
            	132, 152,
            	202, 160,
            	807, 184,
            	414, 200,
            	414, 208,
            1, 8, 1, /* 470: pointer.struct.rsa_meth_st */
            	475, 0,
            0, 112, 13, /* 475: struct.rsa_meth_st */
            	35, 0,
            	504, 8,
            	504, 16,
            	504, 24,
            	504, 32,
            	512, 40,
            	520, 48,
            	528, 56,
            	528, 64,
            	35, 80,
            	536, 88,
            	544, 96,
            	233, 104,
            1, 8, 1, /* 504: pointer.func */
            	509, 0,
            0, 0, 0, /* 509: func */
            1, 8, 1, /* 512: pointer.func */
            	517, 0,
            0, 0, 0, /* 517: func */
            1, 8, 1, /* 520: pointer.func */
            	525, 0,
            0, 0, 0, /* 525: func */
            1, 8, 1, /* 528: pointer.func */
            	533, 0,
            0, 0, 0, /* 533: func */
            1, 8, 1, /* 536: pointer.func */
            	541, 0,
            0, 0, 0, /* 541: func */
            1, 8, 1, /* 544: pointer.func */
            	549, 0,
            0, 0, 0, /* 549: func */
            1, 8, 1, /* 552: pointer.struct.dsa_method.1040 */
            	557, 0,
            0, 96, 11, /* 557: struct.dsa_method.1040 */
            	35, 0,
            	582, 8,
            	590, 16,
            	598, 24,
            	606, 32,
            	614, 40,
            	622, 48,
            	622, 56,
            	35, 72,
            	630, 80,
            	622, 88,
            1, 8, 1, /* 582: pointer.func */
            	587, 0,
            0, 0, 0, /* 587: func */
            1, 8, 1, /* 590: pointer.func */
            	595, 0,
            0, 0, 0, /* 595: func */
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
            1, 8, 1, /* 638: pointer.struct.dh_method */
            	643, 0,
            0, 72, 8, /* 643: struct.dh_method */
            	35, 0,
            	662, 8,
            	670, 16,
            	678, 24,
            	662, 32,
            	662, 40,
            	35, 56,
            	686, 64,
            1, 8, 1, /* 662: pointer.func */
            	667, 0,
            0, 0, 0, /* 667: func */
            1, 8, 1, /* 670: pointer.func */
            	675, 0,
            0, 0, 0, /* 675: func */
            1, 8, 1, /* 678: pointer.func */
            	683, 0,
            0, 0, 0, /* 683: func */
            1, 8, 1, /* 686: pointer.func */
            	691, 0,
            0, 0, 0, /* 691: func */
            1, 8, 1, /* 694: pointer.struct.ecdh_method */
            	699, 0,
            0, 32, 3, /* 699: struct.ecdh_method */
            	35, 0,
            	708, 8,
            	35, 24,
            1, 8, 1, /* 708: pointer.func */
            	713, 0,
            0, 0, 0, /* 713: func */
            1, 8, 1, /* 716: pointer.struct.ecdsa_method */
            	721, 0,
            0, 48, 5, /* 721: struct.ecdsa_method */
            	35, 0,
            	734, 8,
            	742, 16,
            	750, 24,
            	35, 40,
            1, 8, 1, /* 734: pointer.func */
            	739, 0,
            0, 0, 0, /* 739: func */
            1, 8, 1, /* 742: pointer.func */
            	747, 0,
            0, 0, 0, /* 747: func */
            1, 8, 1, /* 750: pointer.func */
            	755, 0,
            0, 0, 0, /* 755: func */
            1, 8, 1, /* 758: pointer.struct.rand_meth_st */
            	763, 0,
            0, 48, 6, /* 763: struct.rand_meth_st */
            	778, 0,
            	786, 8,
            	794, 16,
            	222, 24,
            	786, 32,
            	214, 40,
            1, 8, 1, /* 778: pointer.func */
            	783, 0,
            0, 0, 0, /* 783: func */
            1, 8, 1, /* 786: pointer.func */
            	791, 0,
            0, 0, 0, /* 791: func */
            1, 8, 1, /* 794: pointer.func */
            	799, 0,
            0, 0, 0, /* 799: func */
            1, 8, 1, /* 802: pointer.func */
            	148, 0,
            0, 16, 1, /* 807: struct.crypto_ex_data_st */
            	13, 0,
            0, 8, 1, /* 812: struct.fnames */
            	35, 0,
            1, 8, 1, /* 817: pointer.struct.x509_st */
            	822, 0,
            0, 184, 12, /* 822: struct.x509_st */
            	849, 0,
            	879, 8,
            	51, 16,
            	35, 32,
            	807, 40,
            	51, 104,
            	118, 112,
            	106, 120,
            	13, 128,
            	13, 136,
            	73, 144,
            	61, 176,
            1, 8, 1, /* 849: pointer.struct.x509_cinf_st */
            	854, 0,
            0, 104, 11, /* 854: struct.x509_cinf_st */
            	51, 0,
            	51, 8,
            	879, 16,
            	901, 24,
            	925, 32,
            	901, 40,
            	937, 48,
            	51, 56,
            	51, 64,
            	13, 72,
            	956, 80,
            1, 8, 1, /* 879: pointer.struct.X509_algor_st */
            	884, 0,
            0, 16, 2, /* 884: struct.X509_algor_st */
            	87, 0,
            	891, 8,
            1, 8, 1, /* 891: pointer.struct.asn1_type_st */
            	896, 0,
            0, 16, 1, /* 896: struct.asn1_type_st */
            	812, 8,
            1, 8, 1, /* 901: pointer.struct.X509_name_st */
            	906, 0,
            0, 40, 3, /* 906: struct.X509_name_st */
            	13, 0,
            	915, 16,
            	35, 24,
            1, 8, 1, /* 915: pointer.struct.buf_mem_st */
            	920, 0,
            0, 24, 1, /* 920: struct.buf_mem_st */
            	35, 8,
            1, 8, 1, /* 925: pointer.struct.X509_val_st */
            	930, 0,
            0, 16, 2, /* 930: struct.X509_val_st */
            	51, 0,
            	51, 8,
            1, 8, 1, /* 937: pointer.struct.X509_pubkey_st */
            	942, 0,
            0, 24, 3, /* 942: struct.X509_pubkey_st */
            	879, 0,
            	51, 8,
            	951, 16,
            1, 8, 1, /* 951: pointer.struct.evp_pkey_st */
            	241, 0,
            0, 24, 1, /* 956: struct.ASN1_ENCODING_st */
            	35, 0,
            0, 4, 0, /* 961: int */
            0, 20, 0, /* 964: array[20].char */
            0, 8, 0, /* 967: long */
            1, 8, 1, /* 970: pointer.int */
            	961, 0,
        },
        .arg_entity_index = { 817, 961, 970, 970, },
        .ret_entity_index = 35,
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

