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

EVP_MD_CTX * bb_EVP_MD_CTX_create(void);

EVP_MD_CTX * EVP_MD_CTX_create(void) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_MD_CTX_create called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_MD_CTX_create();
    else {
        EVP_MD_CTX * (*orig_EVP_MD_CTX_create)(void);
        orig_EVP_MD_CTX_create = dlsym(RTLD_NEXT, "EVP_MD_CTX_create");
        return orig_EVP_MD_CTX_create();
    }
}

EVP_MD_CTX * bb_EVP_MD_CTX_create(void) 
{
    EVP_MD_CTX * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.int */
            	5, 0,
            0, 4, 0, /* 5: int */
            0, 8, 1, /* 8: struct.fnames */
            	13, 0,
            1, 8, 1, /* 13: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 18: pointer.func */
            4097, 8, 0, /* 21: pointer.func */
            0, 0, 0, /* 24: func */
            4097, 8, 0, /* 27: pointer.func */
            0, 0, 0, /* 30: func */
            4097, 8, 0, /* 33: pointer.func */
            4097, 8, 0, /* 36: pointer.func */
            4097, 8, 0, /* 39: pointer.func */
            0, 0, 0, /* 42: func */
            0, 0, 0, /* 45: func */
            0, 0, 0, /* 48: func */
            0, 0, 0, /* 51: func */
            4097, 8, 0, /* 54: pointer.func */
            0, 0, 0, /* 57: func */
            0, 56, 4, /* 60: struct.evp_pkey_st */
            	71, 16,
            	93, 24,
            	8, 32,
            	220, 48,
            1, 8, 1, /* 71: pointer.struct.evp_pkey_asn1_method_st */
            	76, 0,
            0, 208, 3, /* 76: struct.evp_pkey_asn1_method_st */
            	13, 16,
            	13, 24,
            	85, 32,
            1, 8, 1, /* 85: pointer.struct.unnamed */
            	90, 0,
            0, 0, 0, /* 90: struct.unnamed */
            1, 8, 1, /* 93: pointer.struct.engine_st */
            	98, 0,
            0, 216, 13, /* 98: struct.engine_st */
            	13, 0,
            	13, 8,
            	127, 16,
            	139, 24,
            	151, 32,
            	163, 40,
            	175, 48,
            	187, 56,
            	195, 64,
            	203, 160,
            	215, 184,
            	93, 200,
            	93, 208,
            1, 8, 1, /* 127: pointer.struct.rsa_meth_st */
            	132, 0,
            0, 112, 2, /* 132: struct.rsa_meth_st */
            	13, 0,
            	13, 80,
            1, 8, 1, /* 139: pointer.struct.dsa_method.1040 */
            	144, 0,
            0, 96, 2, /* 144: struct.dsa_method.1040 */
            	13, 0,
            	13, 72,
            1, 8, 1, /* 151: pointer.struct.dh_method */
            	156, 0,
            0, 72, 2, /* 156: struct.dh_method */
            	13, 0,
            	13, 56,
            1, 8, 1, /* 163: pointer.struct.ecdh_method */
            	168, 0,
            0, 32, 2, /* 168: struct.ecdh_method */
            	13, 0,
            	13, 24,
            1, 8, 1, /* 175: pointer.struct.ecdsa_method */
            	180, 0,
            0, 48, 2, /* 180: struct.ecdsa_method */
            	13, 0,
            	13, 40,
            1, 8, 1, /* 187: pointer.struct.rand_meth_st */
            	192, 0,
            0, 48, 0, /* 192: struct.rand_meth_st */
            1, 8, 1, /* 195: pointer.struct.store_method_st */
            	200, 0,
            0, 0, 0, /* 200: struct.store_method_st */
            1, 8, 1, /* 203: pointer.struct.ENGINE_CMD_DEFN_st */
            	208, 0,
            0, 32, 2, /* 208: struct.ENGINE_CMD_DEFN_st */
            	13, 8,
            	13, 16,
            0, 16, 1, /* 215: struct.crypto_ex_data_st */
            	220, 0,
            1, 8, 1, /* 220: pointer.struct.stack_st_OPENSSL_STRING */
            	225, 0,
            0, 32, 1, /* 225: struct.stack_st_OPENSSL_STRING */
            	230, 0,
            0, 32, 1, /* 230: struct.stack_st */
            	235, 8,
            1, 8, 1, /* 235: pointer.pointer.char */
            	13, 0,
            0, 0, 0, /* 240: func */
            0, 0, 0, /* 243: func */
            4097, 8, 0, /* 246: pointer.func */
            0, 0, 0, /* 249: func */
            4097, 8, 0, /* 252: pointer.func */
            0, 0, 0, /* 255: func */
            4097, 8, 0, /* 258: pointer.func */
            0, 0, 0, /* 261: func */
            0, 0, 0, /* 264: func */
            0, 0, 0, /* 267: func */
            0, 0, 0, /* 270: func */
            4097, 8, 0, /* 273: pointer.func */
            4097, 8, 0, /* 276: pointer.func */
            0, 0, 0, /* 279: func */
            4097, 8, 0, /* 282: pointer.func */
            4097, 8, 0, /* 285: pointer.func */
            0, 0, 0, /* 288: func */
            4097, 8, 0, /* 291: pointer.func */
            0, 0, 0, /* 294: func */
            4097, 8, 0, /* 297: pointer.func */
            4097, 8, 0, /* 300: pointer.func */
            4097, 8, 0, /* 303: pointer.func */
            0, 0, 0, /* 306: func */
            0, 0, 0, /* 309: func */
            4097, 8, 0, /* 312: pointer.func */
            0, 0, 0, /* 315: func */
            1, 8, 1, /* 318: pointer.struct.env_md_ctx_st */
            	323, 0,
            0, 48, 4, /* 323: struct.env_md_ctx_st */
            	334, 0,
            	93, 8,
            	13, 24,
            	342, 32,
            1, 8, 1, /* 334: pointer.struct.env_md_st */
            	339, 0,
            0, 120, 0, /* 339: struct.env_md_st */
            1, 8, 1, /* 342: pointer.struct.evp_pkey_ctx_st */
            	347, 0,
            0, 80, 8, /* 347: struct.evp_pkey_ctx_st */
            	366, 0,
            	93, 8,
            	392, 16,
            	392, 24,
            	13, 40,
            	13, 48,
            	85, 56,
            	0, 64,
            1, 8, 1, /* 366: pointer.struct.evp_pkey_method_st */
            	371, 0,
            0, 208, 9, /* 371: struct.evp_pkey_method_st */
            	85, 8,
            	85, 32,
            	85, 48,
            	85, 64,
            	85, 80,
            	85, 96,
            	85, 144,
            	85, 160,
            	85, 176,
            1, 8, 1, /* 392: pointer.struct.evp_pkey_st */
            	60, 0,
            4097, 8, 0, /* 397: pointer.func */
            4097, 8, 0, /* 400: pointer.func */
            4097, 8, 0, /* 403: pointer.func */
            4097, 8, 0, /* 406: pointer.func */
            0, 0, 0, /* 409: func */
            4097, 8, 0, /* 412: pointer.func */
            0, 0, 0, /* 415: func */
            0, 0, 0, /* 418: func */
            4097, 8, 0, /* 421: pointer.func */
            0, 0, 0, /* 424: func */
            4097, 8, 0, /* 427: pointer.func */
            4097, 8, 0, /* 430: pointer.func */
            0, 0, 0, /* 433: func */
            4097, 8, 0, /* 436: pointer.func */
            4097, 8, 0, /* 439: pointer.func */
            4097, 8, 0, /* 442: pointer.func */
            0, 0, 0, /* 445: func */
            4097, 8, 0, /* 448: pointer.func */
            0, 0, 0, /* 451: func */
            0, 0, 0, /* 454: func */
            4097, 8, 0, /* 457: pointer.func */
            4097, 8, 0, /* 460: pointer.func */
            4097, 8, 0, /* 463: pointer.func */
            0, 0, 0, /* 466: func */
            4097, 8, 0, /* 469: pointer.func */
            0, 0, 0, /* 472: func */
            0, 0, 0, /* 475: func */
            4097, 8, 0, /* 478: pointer.func */
            0, 0, 0, /* 481: func */
            0, 0, 0, /* 484: func */
            0, 0, 0, /* 487: func */
            0, 0, 0, /* 490: func */
            0, 0, 0, /* 493: func */
            0, 0, 0, /* 496: func */
            4097, 8, 0, /* 499: pointer.func */
            4097, 8, 0, /* 502: pointer.func */
            0, 0, 0, /* 505: func */
            4097, 8, 0, /* 508: pointer.func */
            4097, 8, 0, /* 511: pointer.func */
            0, 0, 0, /* 514: func */
            0, 0, 0, /* 517: func */
            0, 0, 0, /* 520: func */
            4097, 8, 0, /* 523: pointer.func */
            0, 0, 0, /* 526: func */
            0, 0, 0, /* 529: func */
            4097, 8, 0, /* 532: pointer.func */
            0, 0, 0, /* 535: func */
            0, 0, 0, /* 538: func */
            0, 8, 0, /* 541: long */
            4097, 8, 0, /* 544: pointer.func */
            0, 0, 0, /* 547: func */
            0, 0, 0, /* 550: func */
            4097, 8, 0, /* 553: pointer.func */
            4097, 8, 0, /* 556: pointer.func */
            4097, 8, 0, /* 559: pointer.func */
            4097, 8, 0, /* 562: pointer.func */
            0, 1, 0, /* 565: char */
            0, 20, 0, /* 568: array[5].int */
            0, 0, 0, /* 571: func */
            0, 0, 0, /* 574: func */
            0, 0, 0, /* 577: func */
            4097, 8, 0, /* 580: pointer.func */
            0, 0, 0, /* 583: func */
            4097, 8, 0, /* 586: pointer.func */
            4097, 8, 0, /* 589: pointer.func */
            0, 0, 0, /* 592: func */
            4097, 8, 0, /* 595: pointer.func */
            4097, 8, 0, /* 598: pointer.func */
            0, 0, 0, /* 601: func */
            4097, 8, 0, /* 604: pointer.func */
            4097, 8, 0, /* 607: pointer.func */
            0, 0, 0, /* 610: func */
            0, 0, 0, /* 613: func */
            4097, 8, 0, /* 616: pointer.func */
            4097, 8, 0, /* 619: pointer.func */
            4097, 8, 0, /* 622: pointer.func */
            0, 0, 0, /* 625: func */
            4097, 8, 0, /* 628: pointer.func */
            0, 0, 0, /* 631: func */
            4097, 8, 0, /* 634: pointer.func */
            0, 0, 0, /* 637: func */
            4097, 8, 0, /* 640: pointer.func */
            4097, 8, 0, /* 643: pointer.func */
            0, 0, 0, /* 646: func */
            0, 0, 0, /* 649: func */
            4097, 8, 0, /* 652: pointer.func */
            0, 0, 0, /* 655: func */
            4097, 8, 0, /* 658: pointer.func */
            0, 0, 0, /* 661: func */
            4097, 8, 0, /* 664: pointer.func */
            0, 0, 0, /* 667: func */
            4097, 8, 0, /* 670: pointer.func */
            0, 0, 0, /* 673: func */
            4097, 8, 0, /* 676: pointer.func */
            0, 0, 0, /* 679: func */
            0, 0, 0, /* 682: func */
            4097, 8, 0, /* 685: pointer.func */
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 318,
    };
    struct lib_enter_args *args_addr = &args;
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * *new_ret_ptr = (EVP_MD_CTX * *)new_args->ret;

    EVP_MD_CTX * (*orig_EVP_MD_CTX_create)(void);
    orig_EVP_MD_CTX_create = dlsym(RTLD_NEXT, "EVP_MD_CTX_create");
    *new_ret_ptr = (*orig_EVP_MD_CTX_create)();

    syscall(889);

    return ret;
}

