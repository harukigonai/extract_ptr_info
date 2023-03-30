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

X509_NAME * bb_X509_get_subject_name(X509 * arg_a);

X509_NAME * X509_get_subject_name(X509 * arg_a) 
{
    printf("X509_get_subject_name called\n");
    if (!syscall(890))
        return bb_X509_get_subject_name(arg_a);
    else {
        X509_NAME * (*orig_X509_get_subject_name)(X509 *);
        orig_X509_get_subject_name = dlsym(RTLD_NEXT, "X509_get_subject_name");
        return orig_X509_get_subject_name(arg_a);
    }
}

X509_NAME * bb_X509_get_subject_name(X509 * arg_a) 
{
    X509_NAME * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 40, 5, /* 0: struct.x509_cert_aux_st */
            	13, 0,
            	13, 8,
            	41, 16,
            	41, 24,
            	13, 32,
            1, 8, 1, /* 13: pointer.struct.stack_st_OPENSSL_STRING */
            	18, 0,
            0, 32, 1, /* 18: struct.stack_st_OPENSSL_STRING */
            	23, 0,
            0, 32, 1, /* 23: struct.stack_st */
            	28, 8,
            1, 8, 1, /* 28: pointer.pointer.char */
            	33, 0,
            1, 8, 1, /* 33: pointer.char */
            	38, 0,
            0, 1, 0, /* 38: char */
            1, 8, 1, /* 41: pointer.struct.asn1_string_st */
            	46, 0,
            0, 24, 1, /* 46: struct.asn1_string_st */
            	33, 8,
            1, 8, 1, /* 51: pointer.struct.x509_cert_aux_st */
            	0, 0,
            0, 16, 2, /* 56: struct.NAME_CONSTRAINTS_st */
            	13, 0,
            	13, 8,
            1, 8, 1, /* 63: pointer.struct.NAME_CONSTRAINTS_st */
            	56, 0,
            0, 32, 3, /* 68: struct.X509_POLICY_DATA_st */
            	77, 8,
            	13, 16,
            	13, 24,
            1, 8, 1, /* 77: pointer.struct.asn1_object_st */
            	82, 0,
            0, 40, 3, /* 82: struct.asn1_object_st */
            	33, 0,
            	33, 8,
            	33, 24,
            1, 8, 1, /* 91: pointer.struct.X509_POLICY_DATA_st */
            	68, 0,
            1, 8, 1, /* 96: pointer.struct.X509_POLICY_CACHE_st */
            	101, 0,
            0, 40, 2, /* 101: struct.X509_POLICY_CACHE_st */
            	91, 0,
            	13, 8,
            1, 8, 1, /* 108: pointer.struct.AUTHORITY_KEYID_st */
            	113, 0,
            0, 24, 3, /* 113: struct.AUTHORITY_KEYID_st */
            	41, 0,
            	13, 8,
            	41, 16,
            0, 8, 0, /* 122: pointer.func */
            0, 0, 0, /* 125: func */
            0, 0, 0, /* 128: func */
            0, 0, 0, /* 131: func */
            0, 8, 0, /* 134: pointer.func */
            0, 0, 0, /* 137: func */
            0, 8, 0, /* 140: pointer.func */
            0, 0, 0, /* 143: func */
            0, 8, 0, /* 146: pointer.func */
            0, 0, 0, /* 149: func */
            0, 8, 0, /* 152: pointer.func */
            0, 0, 0, /* 155: func */
            0, 8, 0, /* 158: pointer.func */
            0, 0, 0, /* 161: struct.store_method_st */
            1, 8, 1, /* 164: pointer.struct.store_method_st */
            	161, 0,
            0, 0, 0, /* 169: func */
            1, 8, 1, /* 172: pointer.struct.ENGINE_CMD_DEFN_st */
            	177, 0,
            0, 32, 2, /* 177: struct.ENGINE_CMD_DEFN_st */
            	33, 8,
            	33, 16,
            0, 8, 0, /* 184: pointer.func */
            0, 0, 0, /* 187: func */
            0, 8, 0, /* 190: pointer.func */
            0, 8, 0, /* 193: pointer.func */
            0, 0, 0, /* 196: func */
            1, 8, 1, /* 199: pointer.struct.ecdsa_method */
            	204, 0,
            0, 48, 2, /* 204: struct.ecdsa_method */
            	33, 0,
            	33, 40,
            0, 8, 0, /* 211: pointer.func */
            0, 0, 0, /* 214: func */
            0, 0, 0, /* 217: func */
            0, 0, 0, /* 220: func */
            0, 8, 0, /* 223: pointer.func */
            0, 8, 0, /* 226: pointer.func */
            0, 0, 0, /* 229: func */
            0, 0, 0, /* 232: func */
            0, 8, 0, /* 235: pointer.func */
            0, 0, 0, /* 238: func */
            0, 24, 3, /* 241: struct.X509_pubkey_st.2915 */
            	250, 0,
            	41, 8,
            	277, 16,
            1, 8, 1, /* 250: pointer.struct.X509_algor_st */
            	255, 0,
            0, 16, 2, /* 255: struct.X509_algor_st */
            	77, 0,
            	262, 8,
            1, 8, 1, /* 262: pointer.struct.asn1_type_st */
            	267, 0,
            0, 16, 1, /* 267: struct.asn1_type_st */
            	272, 8,
            0, 8, 1, /* 272: struct.fnames */
            	33, 0,
            1, 8, 1, /* 277: pointer.struct.evp_pkey_st.2930 */
            	282, 0,
            0, 56, 4, /* 282: struct.evp_pkey_st.2930 */
            	293, 16,
            	305, 24,
            	272, 32,
            	13, 48,
            1, 8, 1, /* 293: pointer.struct.evp_pkey_asn1_method_st.2928 */
            	298, 0,
            0, 208, 2, /* 298: struct.evp_pkey_asn1_method_st.2928 */
            	33, 16,
            	33, 24,
            1, 8, 1, /* 305: pointer.struct.engine_st */
            	310, 0,
            0, 216, 13, /* 310: struct.engine_st */
            	33, 0,
            	33, 8,
            	339, 16,
            	351, 24,
            	363, 32,
            	375, 40,
            	199, 48,
            	387, 56,
            	164, 64,
            	172, 160,
            	395, 184,
            	305, 200,
            	305, 208,
            1, 8, 1, /* 339: pointer.struct.rsa_meth_st */
            	344, 0,
            0, 112, 2, /* 344: struct.rsa_meth_st */
            	33, 0,
            	33, 80,
            1, 8, 1, /* 351: pointer.struct.dsa_method.1040 */
            	356, 0,
            0, 96, 2, /* 356: struct.dsa_method.1040 */
            	33, 0,
            	33, 72,
            1, 8, 1, /* 363: pointer.struct.dh_method */
            	368, 0,
            0, 72, 2, /* 368: struct.dh_method */
            	33, 0,
            	33, 56,
            1, 8, 1, /* 375: pointer.struct.ecdh_method */
            	380, 0,
            0, 32, 2, /* 380: struct.ecdh_method */
            	33, 0,
            	33, 24,
            1, 8, 1, /* 387: pointer.struct.rand_meth_st */
            	392, 0,
            0, 48, 0, /* 392: struct.rand_meth_st */
            0, 16, 1, /* 395: struct.crypto_ex_data_st */
            	13, 0,
            0, 24, 1, /* 400: struct.buf_mem_st */
            	33, 8,
            0, 0, 0, /* 405: func */
            0, 20, 0, /* 408: array[20].char */
            0, 0, 0, /* 411: func */
            0, 0, 0, /* 414: func */
            0, 8, 0, /* 417: pointer.func */
            0, 0, 0, /* 420: func */
            1, 8, 1, /* 423: pointer.struct.buf_mem_st */
            	400, 0,
            0, 4, 0, /* 428: int */
            0, 24, 1, /* 431: struct.ASN1_ENCODING_st */
            	33, 0,
            0, 8, 0, /* 436: pointer.func */
            0, 8, 0, /* 439: pointer.func */
            0, 8, 0, /* 442: long */
            0, 40, 3, /* 445: struct.X509_name_st */
            	13, 0,
            	423, 16,
            	33, 24,
            0, 8, 0, /* 454: pointer.func */
            0, 0, 0, /* 457: func */
            1, 8, 1, /* 460: pointer.struct.x509_st.3164 */
            	465, 0,
            0, 184, 12, /* 465: struct.x509_st.3164 */
            	492, 0,
            	250, 8,
            	41, 16,
            	33, 32,
            	395, 40,
            	41, 104,
            	108, 112,
            	96, 120,
            	13, 128,
            	13, 136,
            	63, 144,
            	51, 176,
            1, 8, 1, /* 492: pointer.struct.x509_cinf_st.3159 */
            	497, 0,
            0, 104, 11, /* 497: struct.x509_cinf_st.3159 */
            	41, 0,
            	41, 8,
            	250, 16,
            	522, 24,
            	527, 32,
            	522, 40,
            	539, 48,
            	41, 56,
            	41, 64,
            	13, 72,
            	431, 80,
            1, 8, 1, /* 522: pointer.struct.X509_name_st */
            	445, 0,
            1, 8, 1, /* 527: pointer.struct.X509_val_st */
            	532, 0,
            0, 16, 2, /* 532: struct.X509_val_st */
            	41, 0,
            	41, 8,
            1, 8, 1, /* 539: pointer.struct.X509_pubkey_st.2915 */
            	241, 0,
            0, 8, 0, /* 544: pointer.func */
            0, 8, 0, /* 547: pointer.func */
            0, 8, 0, /* 550: pointer.func */
            0, 0, 0, /* 553: func */
            0, 8, 0, /* 556: pointer.func */
            0, 8, 0, /* 559: pointer.func */
            0, 8, 0, /* 562: pointer.func */
            0, 8, 0, /* 565: pointer.func */
            0, 0, 0, /* 568: func */
            0, 8, 0, /* 571: pointer.func */
            0, 8, 0, /* 574: pointer.func */
            0, 0, 0, /* 577: func */
            0, 0, 0, /* 580: func */
            0, 8, 0, /* 583: pointer.func */
            0, 0, 0, /* 586: func */
            0, 0, 0, /* 589: func */
            0, 0, 0, /* 592: func */
            0, 8, 0, /* 595: pointer.func */
            0, 0, 0, /* 598: func */
            0, 8, 0, /* 601: pointer.func */
            0, 0, 0, /* 604: func */
            0, 8, 0, /* 607: pointer.func */
            0, 8, 0, /* 610: pointer.func */
            0, 8, 0, /* 613: pointer.func */
            0, 0, 0, /* 616: func */
            0, 0, 0, /* 619: func */
            0, 8, 0, /* 622: pointer.func */
            0, 0, 0, /* 625: func */
            0, 0, 0, /* 628: func */
            0, 0, 0, /* 631: func */
            0, 0, 0, /* 634: func */
            0, 8, 0, /* 637: pointer.func */
            0, 0, 0, /* 640: func */
            0, 0, 0, /* 643: func */
            0, 0, 0, /* 646: func */
            0, 0, 0, /* 649: func */
            0, 8, 0, /* 652: pointer.func */
            0, 8, 0, /* 655: pointer.func */
            0, 8, 0, /* 658: pointer.func */
            0, 8, 0, /* 661: pointer.func */
            0, 0, 0, /* 664: func */
            0, 8, 0, /* 667: pointer.func */
            0, 0, 0, /* 670: func */
            0, 8, 0, /* 673: pointer.func */
            0, 0, 0, /* 676: func */
            0, 8, 0, /* 679: pointer.func */
            0, 8, 0, /* 682: pointer.func */
            0, 0, 0, /* 685: func */
            0, 8, 0, /* 688: pointer.func */
            0, 0, 0, /* 691: func */
            0, 8, 0, /* 694: pointer.func */
            0, 8, 0, /* 697: pointer.func */
            0, 8, 0, /* 700: pointer.func */
            0, 0, 0, /* 703: func */
            0, 8, 0, /* 706: pointer.func */
            0, 8, 0, /* 709: pointer.func */
            0, 8, 0, /* 712: pointer.func */
            0, 8, 0, /* 715: pointer.func */
            0, 0, 0, /* 718: func */
            0, 0, 0, /* 721: func */
            0, 0, 0, /* 724: func */
            0, 0, 0, /* 727: func */
        },
        .arg_entity_index = { 460, },
        .ret_entity_index = 522,
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

