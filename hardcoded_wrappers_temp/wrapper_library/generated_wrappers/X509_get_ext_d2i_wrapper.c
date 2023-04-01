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

void * bb_X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d);

void * X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_get_ext_d2i called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_get_ext_d2i(arg_a,arg_b,arg_c,arg_d);
    else {
        void * (*orig_X509_get_ext_d2i)(X509 *,int,int *,int *);
        orig_X509_get_ext_d2i = dlsym(RTLD_NEXT, "X509_get_ext_d2i");
        return orig_X509_get_ext_d2i(arg_a,arg_b,arg_c,arg_d);
    }
}

void * bb_X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d) 
{
    void * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.int */
            	5, 0,
            0, 4, 0, /* 5: int */
            1, 8, 1, /* 8: pointer.struct.x509_cert_aux_st */
            	13, 0,
            0, 40, 5, /* 13: struct.x509_cert_aux_st */
            	26, 0,
            	26, 8,
            	51, 16,
            	51, 24,
            	26, 32,
            1, 8, 1, /* 26: pointer.struct.stack_st_OPENSSL_STRING */
            	31, 0,
            0, 32, 1, /* 31: struct.stack_st_OPENSSL_STRING */
            	36, 0,
            0, 32, 1, /* 36: struct.stack_st */
            	41, 8,
            1, 8, 1, /* 41: pointer.pointer.char */
            	46, 0,
            1, 8, 1, /* 46: pointer.char */
            	4096, 0,
            1, 8, 1, /* 51: pointer.struct.asn1_string_st */
            	56, 0,
            0, 24, 1, /* 56: struct.asn1_string_st */
            	46, 8,
            1, 8, 1, /* 61: pointer.struct.NAME_CONSTRAINTS_st */
            	66, 0,
            0, 16, 2, /* 66: struct.NAME_CONSTRAINTS_st */
            	26, 0,
            	26, 8,
            1, 8, 1, /* 73: pointer.struct.X509_POLICY_CACHE_st */
            	78, 0,
            0, 40, 2, /* 78: struct.X509_POLICY_CACHE_st */
            	85, 0,
            	26, 8,
            1, 8, 1, /* 85: pointer.struct.X509_POLICY_DATA_st */
            	90, 0,
            0, 32, 3, /* 90: struct.X509_POLICY_DATA_st */
            	99, 8,
            	26, 16,
            	26, 24,
            1, 8, 1, /* 99: pointer.struct.asn1_object_st */
            	104, 0,
            0, 40, 3, /* 104: struct.asn1_object_st */
            	46, 0,
            	46, 8,
            	46, 24,
            0, 24, 1, /* 113: struct.ASN1_ENCODING_st */
            	46, 0,
            0, 32, 2, /* 118: struct.ENGINE_CMD_DEFN_st */
            	46, 8,
            	46, 16,
            1, 8, 1, /* 125: pointer.struct.ENGINE_CMD_DEFN_st */
            	118, 0,
            0, 0, 0, /* 130: func */
            4097, 8, 0, /* 133: pointer.func */
            0, 0, 0, /* 136: func */
            0, 0, 0, /* 139: func */
            0, 0, 0, /* 142: func */
            0, 16, 1, /* 145: struct.crypto_ex_data_st */
            	26, 0,
            0, 0, 0, /* 150: func */
            0, 0, 0, /* 153: func */
            4097, 8, 0, /* 156: pointer.func */
            0, 0, 0, /* 159: struct.store_method_st */
            1, 8, 1, /* 162: pointer.struct.store_method_st */
            	159, 0,
            0, 0, 0, /* 167: func */
            4097, 8, 0, /* 170: pointer.func */
            4097, 8, 0, /* 173: pointer.func */
            0, 0, 0, /* 176: func */
            0, 0, 0, /* 179: func */
            0, 96, 2, /* 182: struct.dsa_method.1040 */
            	46, 0,
            	46, 72,
            4097, 8, 0, /* 189: pointer.func */
            4097, 8, 0, /* 192: pointer.func */
            0, 20, 0, /* 195: array[20].char */
            4097, 8, 0, /* 198: pointer.func */
            0, 56, 4, /* 201: struct.evp_pkey_st */
            	212, 16,
            	234, 24,
            	329, 32,
            	26, 48,
            1, 8, 1, /* 212: pointer.struct.evp_pkey_asn1_method_st */
            	217, 0,
            0, 208, 3, /* 217: struct.evp_pkey_asn1_method_st */
            	46, 16,
            	46, 24,
            	226, 32,
            1, 8, 1, /* 226: pointer.struct.unnamed */
            	231, 0,
            0, 0, 0, /* 231: struct.unnamed */
            1, 8, 1, /* 234: pointer.struct.engine_st */
            	239, 0,
            0, 216, 13, /* 239: struct.engine_st */
            	46, 0,
            	46, 8,
            	268, 16,
            	280, 24,
            	285, 32,
            	297, 40,
            	309, 48,
            	321, 56,
            	162, 64,
            	125, 160,
            	145, 184,
            	234, 200,
            	234, 208,
            1, 8, 1, /* 268: pointer.struct.rsa_meth_st */
            	273, 0,
            0, 112, 2, /* 273: struct.rsa_meth_st */
            	46, 0,
            	46, 80,
            1, 8, 1, /* 280: pointer.struct.dsa_method.1040 */
            	182, 0,
            1, 8, 1, /* 285: pointer.struct.dh_method */
            	290, 0,
            0, 72, 2, /* 290: struct.dh_method */
            	46, 0,
            	46, 56,
            1, 8, 1, /* 297: pointer.struct.ecdh_method */
            	302, 0,
            0, 32, 2, /* 302: struct.ecdh_method */
            	46, 0,
            	46, 24,
            1, 8, 1, /* 309: pointer.struct.ecdsa_method */
            	314, 0,
            0, 48, 2, /* 314: struct.ecdsa_method */
            	46, 0,
            	46, 40,
            1, 8, 1, /* 321: pointer.struct.rand_meth_st */
            	326, 0,
            0, 48, 0, /* 326: struct.rand_meth_st */
            0, 8, 1, /* 329: struct.fnames */
            	46, 0,
            4097, 8, 0, /* 334: pointer.func */
            0, 0, 0, /* 337: func */
            4097, 8, 0, /* 340: pointer.func */
            0, 0, 0, /* 343: func */
            4097, 8, 0, /* 346: pointer.func */
            0, 0, 0, /* 349: func */
            0, 0, 0, /* 352: func */
            4097, 8, 0, /* 355: pointer.func */
            4097, 8, 0, /* 358: pointer.func */
            0, 0, 0, /* 361: func */
            0, 0, 0, /* 364: func */
            0, 0, 0, /* 367: func */
            0, 0, 0, /* 370: func */
            0, 24, 3, /* 373: struct.X509_pubkey_st */
            	382, 0,
            	51, 8,
            	404, 16,
            1, 8, 1, /* 382: pointer.struct.X509_algor_st */
            	387, 0,
            0, 16, 2, /* 387: struct.X509_algor_st */
            	99, 0,
            	394, 8,
            1, 8, 1, /* 394: pointer.struct.asn1_type_st */
            	399, 0,
            0, 16, 1, /* 399: struct.asn1_type_st */
            	329, 8,
            1, 8, 1, /* 404: pointer.struct.evp_pkey_st */
            	201, 0,
            4097, 8, 0, /* 409: pointer.func */
            0, 0, 0, /* 412: func */
            0, 0, 0, /* 415: func */
            0, 8, 0, /* 418: long */
            1, 8, 1, /* 421: pointer.struct.X509_val_st */
            	426, 0,
            0, 16, 2, /* 426: struct.X509_val_st */
            	51, 0,
            	51, 8,
            4097, 8, 0, /* 433: pointer.func */
            0, 0, 0, /* 436: func */
            4097, 8, 0, /* 439: pointer.func */
            0, 24, 1, /* 442: struct.buf_mem_st */
            	46, 8,
            0, 0, 0, /* 447: func */
            4097, 8, 0, /* 450: pointer.func */
            4097, 8, 0, /* 453: pointer.func */
            4097, 8, 0, /* 456: pointer.func */
            0, 0, 0, /* 459: func */
            4097, 8, 0, /* 462: pointer.func */
            4097, 8, 0, /* 465: pointer.func */
            0, 0, 0, /* 468: func */
            0, 0, 0, /* 471: func */
            0, 0, 0, /* 474: func */
            4097, 8, 0, /* 477: pointer.func */
            0, 0, 0, /* 480: func */
            0, 40, 3, /* 483: struct.X509_name_st */
            	26, 0,
            	492, 16,
            	46, 24,
            1, 8, 1, /* 492: pointer.struct.buf_mem_st */
            	442, 0,
            1, 8, 1, /* 497: pointer.struct.x509_cinf_st */
            	502, 0,
            0, 104, 11, /* 502: struct.x509_cinf_st */
            	51, 0,
            	51, 8,
            	382, 16,
            	527, 24,
            	421, 32,
            	527, 40,
            	532, 48,
            	51, 56,
            	51, 64,
            	26, 72,
            	113, 80,
            1, 8, 1, /* 527: pointer.struct.X509_name_st */
            	483, 0,
            1, 8, 1, /* 532: pointer.struct.X509_pubkey_st */
            	373, 0,
            4097, 8, 0, /* 537: pointer.func */
            1, 8, 1, /* 540: pointer.struct.AUTHORITY_KEYID_st */
            	545, 0,
            0, 24, 3, /* 545: struct.AUTHORITY_KEYID_st */
            	51, 0,
            	26, 8,
            	51, 16,
            4097, 8, 0, /* 554: pointer.func */
            1, 8, 1, /* 557: pointer.struct.x509_st */
            	562, 0,
            0, 184, 12, /* 562: struct.x509_st */
            	497, 0,
            	382, 8,
            	51, 16,
            	46, 32,
            	145, 40,
            	51, 104,
            	540, 112,
            	73, 120,
            	26, 128,
            	26, 136,
            	61, 144,
            	8, 176,
            4097, 8, 0, /* 589: pointer.func */
            0, 0, 0, /* 592: func */
            4097, 8, 0, /* 595: pointer.func */
            0, 0, 0, /* 598: func */
            4097, 8, 0, /* 601: pointer.func */
            4097, 8, 0, /* 604: pointer.func */
            4097, 8, 0, /* 607: pointer.func */
            0, 0, 0, /* 610: func */
            0, 0, 0, /* 613: func */
            4097, 8, 0, /* 616: pointer.func */
            4097, 8, 0, /* 619: pointer.func */
            0, 0, 0, /* 622: func */
            4097, 8, 0, /* 625: pointer.func */
            0, 0, 0, /* 628: func */
            4097, 8, 0, /* 631: pointer.func */
            4097, 8, 0, /* 634: pointer.func */
            0, 0, 0, /* 637: func */
            0, 0, 0, /* 640: func */
            4097, 8, 0, /* 643: pointer.func */
            4097, 8, 0, /* 646: pointer.func */
            4097, 8, 0, /* 649: pointer.func */
            0, 0, 0, /* 652: func */
            4097, 8, 0, /* 655: pointer.func */
            0, 0, 0, /* 658: func */
            4097, 8, 0, /* 661: pointer.func */
            0, 0, 0, /* 664: func */
            4097, 8, 0, /* 667: pointer.func */
            0, 0, 0, /* 670: func */
            0, 0, 0, /* 673: func */
            4097, 8, 0, /* 676: pointer.func */
            4097, 8, 0, /* 679: pointer.func */
            4097, 8, 0, /* 682: pointer.func */
            0, 0, 0, /* 685: func */
            0, 0, 0, /* 688: func */
            0, 0, 0, /* 691: func */
            4097, 8, 0, /* 694: pointer.func */
            0, 0, 0, /* 697: func */
            4097, 8, 0, /* 700: pointer.func */
            0, 0, 0, /* 703: func */
            0, 1, 0, /* 706: char */
            0, 0, 0, /* 709: func */
            4097, 8, 0, /* 712: pointer.func */
            0, 0, 0, /* 715: func */
            4097, 8, 0, /* 718: pointer.func */
            4097, 8, 0, /* 721: pointer.func */
            0, 0, 0, /* 724: func */
            4097, 8, 0, /* 727: pointer.func */
            4097, 8, 0, /* 730: pointer.func */
            0, 0, 0, /* 733: func */
            0, 0, 0, /* 736: func */
        },
        .arg_entity_index = { 557, 5, 0, 0, },
        .ret_entity_index = 46,
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

