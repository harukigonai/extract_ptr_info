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

EVP_PKEY * bb_X509_get_pubkey(X509 * arg_a);

EVP_PKEY * X509_get_pubkey(X509 * arg_a) 
{
    printf("X509_get_pubkey called\n");
    if (!syscall(890))
        return bb_X509_get_pubkey(arg_a);
    else {
        EVP_PKEY * (*orig_X509_get_pubkey)(X509 *);
        orig_X509_get_pubkey = dlsym(RTLD_NEXT, "X509_get_pubkey");
        return orig_X509_get_pubkey(arg_a);
    }
}

EVP_PKEY * bb_X509_get_pubkey(X509 * arg_a) 
{
    EVP_PKEY * ret;

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
            0, 24, 3, /* 122: struct.X509_pubkey_st.2915 */
            	131, 0,
            	41, 8,
            	158, 16,
            1, 8, 1, /* 131: pointer.struct.X509_algor_st */
            	136, 0,
            0, 16, 2, /* 136: struct.X509_algor_st */
            	77, 0,
            	143, 8,
            1, 8, 1, /* 143: pointer.struct.asn1_type_st */
            	148, 0,
            0, 16, 1, /* 148: struct.asn1_type_st */
            	153, 8,
            0, 8, 1, /* 153: struct.fnames */
            	33, 0,
            1, 8, 1, /* 158: pointer.struct.evp_pkey_st.2930 */
            	163, 0,
            0, 56, 4, /* 163: struct.evp_pkey_st.2930 */
            	174, 16,
            	186, 24,
            	153, 32,
            	13, 48,
            1, 8, 1, /* 174: pointer.struct.evp_pkey_asn1_method_st.2928 */
            	179, 0,
            0, 208, 2, /* 179: struct.evp_pkey_asn1_method_st.2928 */
            	33, 16,
            	33, 24,
            1, 8, 1, /* 186: pointer.struct.engine_st */
            	191, 0,
            0, 216, 13, /* 191: struct.engine_st */
            	33, 0,
            	33, 8,
            	220, 16,
            	232, 24,
            	244, 32,
            	256, 40,
            	268, 48,
            	280, 56,
            	288, 64,
            	296, 160,
            	308, 184,
            	186, 200,
            	186, 208,
            1, 8, 1, /* 220: pointer.struct.rsa_meth_st */
            	225, 0,
            0, 112, 2, /* 225: struct.rsa_meth_st */
            	33, 0,
            	33, 80,
            1, 8, 1, /* 232: pointer.struct.dsa_method.1040 */
            	237, 0,
            0, 96, 2, /* 237: struct.dsa_method.1040 */
            	33, 0,
            	33, 72,
            1, 8, 1, /* 244: pointer.struct.dh_method */
            	249, 0,
            0, 72, 2, /* 249: struct.dh_method */
            	33, 0,
            	33, 56,
            1, 8, 1, /* 256: pointer.struct.ecdh_method */
            	261, 0,
            0, 32, 2, /* 261: struct.ecdh_method */
            	33, 0,
            	33, 24,
            1, 8, 1, /* 268: pointer.struct.ecdsa_method */
            	273, 0,
            0, 48, 2, /* 273: struct.ecdsa_method */
            	33, 0,
            	33, 40,
            1, 8, 1, /* 280: pointer.struct.rand_meth_st */
            	285, 0,
            0, 48, 0, /* 285: struct.rand_meth_st */
            1, 8, 1, /* 288: pointer.struct.store_method_st */
            	293, 0,
            0, 0, 0, /* 293: struct.store_method_st */
            1, 8, 1, /* 296: pointer.struct.ENGINE_CMD_DEFN_st */
            	301, 0,
            0, 32, 2, /* 301: struct.ENGINE_CMD_DEFN_st */
            	33, 8,
            	33, 16,
            0, 16, 1, /* 308: struct.crypto_ex_data_st */
            	13, 0,
            1, 8, 1, /* 313: pointer.struct.X509_val_st */
            	318, 0,
            0, 16, 2, /* 318: struct.X509_val_st */
            	41, 0,
            	41, 8,
            0, 24, 1, /* 325: struct.buf_mem_st */
            	33, 8,
            1, 8, 1, /* 330: pointer.struct.buf_mem_st */
            	325, 0,
            0, 40, 3, /* 335: struct.X509_name_st */
            	13, 0,
            	330, 16,
            	33, 24,
            1, 8, 1, /* 344: pointer.struct.X509_name_st */
            	335, 0,
            0, 104, 11, /* 349: struct.x509_cinf_st.3159 */
            	41, 0,
            	41, 8,
            	131, 16,
            	344, 24,
            	313, 32,
            	344, 40,
            	374, 48,
            	41, 56,
            	41, 64,
            	13, 72,
            	379, 80,
            1, 8, 1, /* 374: pointer.struct.X509_pubkey_st.2915 */
            	122, 0,
            0, 24, 1, /* 379: struct.ASN1_ENCODING_st */
            	33, 0,
            0, 0, 0, /* 384: func */
            0, 20, 0, /* 387: array[20].char */
            0, 0, 0, /* 390: func */
            0, 8, 0, /* 393: pointer.func */
            0, 8, 0, /* 396: pointer.func */
            0, 8, 0, /* 399: pointer.func */
            0, 8, 0, /* 402: pointer.func */
            0, 0, 0, /* 405: func */
            0, 8, 0, /* 408: pointer.func */
            0, 0, 0, /* 411: func */
            0, 0, 0, /* 414: func */
            0, 0, 0, /* 417: func */
            0, 0, 0, /* 420: func */
            0, 0, 0, /* 423: func */
            0, 0, 0, /* 426: func */
            0, 8, 0, /* 429: pointer.func */
            0, 8, 0, /* 432: pointer.func */
            0, 8, 0, /* 435: pointer.func */
            0, 0, 0, /* 438: func */
            1, 8, 1, /* 441: pointer.struct.x509_st.3164 */
            	446, 0,
            0, 184, 12, /* 446: struct.x509_st.3164 */
            	473, 0,
            	131, 8,
            	41, 16,
            	33, 32,
            	308, 40,
            	41, 104,
            	108, 112,
            	96, 120,
            	13, 128,
            	13, 136,
            	63, 144,
            	51, 176,
            1, 8, 1, /* 473: pointer.struct.x509_cinf_st.3159 */
            	349, 0,
            0, 0, 0, /* 478: func */
            0, 0, 0, /* 481: func */
            0, 8, 0, /* 484: pointer.func */
            0, 8, 0, /* 487: pointer.func */
            0, 8, 0, /* 490: pointer.func */
            0, 8, 0, /* 493: pointer.func */
            0, 4, 0, /* 496: int */
            0, 8, 0, /* 499: pointer.func */
            0, 0, 0, /* 502: func */
            0, 0, 0, /* 505: func */
            0, 8, 0, /* 508: pointer.func */
            0, 0, 0, /* 511: func */
            0, 0, 0, /* 514: func */
            0, 8, 0, /* 517: pointer.func */
            0, 8, 0, /* 520: long */
            0, 8, 0, /* 523: pointer.func */
            0, 0, 0, /* 526: func */
            0, 0, 0, /* 529: func */
            0, 8, 0, /* 532: pointer.func */
            0, 0, 0, /* 535: func */
            0, 0, 0, /* 538: func */
            0, 0, 0, /* 541: func */
            0, 0, 0, /* 544: func */
            0, 8, 0, /* 547: pointer.func */
            0, 0, 0, /* 550: func */
            0, 8, 0, /* 553: pointer.func */
            0, 0, 0, /* 556: func */
            0, 0, 0, /* 559: func */
            0, 0, 0, /* 562: func */
            0, 0, 0, /* 565: func */
            0, 8, 0, /* 568: pointer.func */
            0, 0, 0, /* 571: func */
            0, 8, 0, /* 574: pointer.func */
            0, 0, 0, /* 577: func */
            0, 8, 0, /* 580: pointer.func */
            0, 8, 0, /* 583: pointer.func */
            0, 0, 0, /* 586: func */
            0, 8, 0, /* 589: pointer.func */
            0, 0, 0, /* 592: func */
            0, 8, 0, /* 595: pointer.func */
            0, 8, 0, /* 598: pointer.func */
            0, 8, 0, /* 601: pointer.func */
            0, 8, 0, /* 604: pointer.func */
            0, 0, 0, /* 607: func */
            0, 0, 0, /* 610: func */
            0, 8, 0, /* 613: pointer.func */
            0, 0, 0, /* 616: func */
            0, 8, 0, /* 619: pointer.func */
            0, 0, 0, /* 622: func */
            0, 8, 0, /* 625: pointer.func */
            0, 8, 0, /* 628: pointer.func */
            0, 0, 0, /* 631: func */
            0, 8, 0, /* 634: pointer.func */
            0, 8, 0, /* 637: pointer.func */
            0, 8, 0, /* 640: pointer.func */
            0, 8, 0, /* 643: pointer.func */
            0, 0, 0, /* 646: func */
            0, 8, 0, /* 649: pointer.func */
            0, 8, 0, /* 652: pointer.func */
            0, 0, 0, /* 655: func */
            0, 8, 0, /* 658: pointer.func */
            0, 0, 0, /* 661: func */
            0, 0, 0, /* 664: func */
            0, 8, 0, /* 667: pointer.func */
            0, 0, 0, /* 670: func */
            0, 8, 0, /* 673: pointer.func */
            0, 8, 0, /* 676: pointer.func */
            0, 8, 0, /* 679: pointer.func */
            0, 8, 0, /* 682: pointer.func */
            0, 8, 0, /* 685: pointer.func */
            0, 0, 0, /* 688: func */
            0, 0, 0, /* 691: func */
            0, 0, 0, /* 694: func */
            0, 0, 0, /* 697: func */
            0, 8, 0, /* 700: pointer.func */
            0, 0, 0, /* 703: func */
            0, 8, 0, /* 706: pointer.func */
            0, 8, 0, /* 709: pointer.func */
            0, 0, 0, /* 712: func */
            0, 8, 0, /* 715: pointer.func */
            0, 0, 0, /* 718: func */
            0, 0, 0, /* 721: func */
            0, 0, 0, /* 724: func */
            0, 8, 0, /* 727: pointer.func */
        },
        .arg_entity_index = { 441, },
        .ret_entity_index = 158,
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

