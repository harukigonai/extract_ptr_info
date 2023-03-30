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

int bb_HMAC_Init_ex(HMAC_CTX * arg_a,const void * arg_b,int arg_c,const EVP_MD * arg_d,ENGINE * arg_e);

int HMAC_Init_ex(HMAC_CTX * arg_a,const void * arg_b,int arg_c,const EVP_MD * arg_d,ENGINE * arg_e) 
{
    printf("HMAC_Init_ex called\n");
    if (!syscall(890))
        return bb_HMAC_Init_ex(arg_a,arg_b,arg_c,arg_d,arg_e);
    else {
        int (*orig_HMAC_Init_ex)(HMAC_CTX *,const void *,int,const EVP_MD *,ENGINE *);
        orig_HMAC_Init_ex = dlsym(RTLD_NEXT, "HMAC_Init_ex");
        return orig_HMAC_Init_ex(arg_a,arg_b,arg_c,arg_d,arg_e);
    }
}

int bb_HMAC_Init_ex(HMAC_CTX * arg_a,const void * arg_b,int arg_c,const EVP_MD * arg_d,ENGINE * arg_e) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 8, 1, /* 0: struct.fnames */
            	5, 0,
            1, 8, 1, /* 5: pointer.char */
            	10, 0,
            0, 1, 0, /* 10: char */
            0, 0, 0, /* 13: func */
            0, 8, 0, /* 16: pointer.func */
            0, 0, 0, /* 19: func */
            0, 8, 0, /* 22: pointer.func */
            0, 8, 0, /* 25: pointer.func */
            0, 0, 0, /* 28: func */
            0, 128, 0, /* 31: array[128].char */
            0, 8, 0, /* 34: pointer.func */
            0, 0, 0, /* 37: func */
            0, 8, 0, /* 40: pointer.func */
            0, 0, 0, /* 43: func */
            0, 8, 0, /* 46: pointer.func */
            0, 0, 0, /* 49: func */
            0, 8, 0, /* 52: pointer.func */
            0, 8, 0, /* 55: pointer.func */
            0, 8, 0, /* 58: pointer.func */
            0, 0, 0, /* 61: func */
            0, 8, 0, /* 64: pointer.func */
            0, 0, 0, /* 67: func */
            0, 8, 0, /* 70: pointer.func */
            0, 0, 0, /* 73: func */
            0, 208, 3, /* 76: struct.evp_pkey_asn1_method_st */
            	5, 16,
            	5, 24,
            	85, 32,
            1, 8, 1, /* 85: pointer.struct.unnamed */
            	90, 0,
            0, 0, 0, /* 90: struct.unnamed */
            1, 8, 1, /* 93: pointer.struct.evp_pkey_asn1_method_st */
            	76, 0,
            0, 56, 4, /* 98: struct.evp_pkey_st */
            	93, 16,
            	109, 24,
            	0, 32,
            	236, 48,
            1, 8, 1, /* 109: pointer.struct.engine_st */
            	114, 0,
            0, 216, 13, /* 114: struct.engine_st */
            	5, 0,
            	5, 8,
            	143, 16,
            	155, 24,
            	167, 32,
            	179, 40,
            	191, 48,
            	203, 56,
            	211, 64,
            	219, 160,
            	231, 184,
            	109, 200,
            	109, 208,
            1, 8, 1, /* 143: pointer.struct.rsa_meth_st */
            	148, 0,
            0, 112, 2, /* 148: struct.rsa_meth_st */
            	5, 0,
            	5, 80,
            1, 8, 1, /* 155: pointer.struct.dsa_method.1040 */
            	160, 0,
            0, 96, 2, /* 160: struct.dsa_method.1040 */
            	5, 0,
            	5, 72,
            1, 8, 1, /* 167: pointer.struct.dh_method */
            	172, 0,
            0, 72, 2, /* 172: struct.dh_method */
            	5, 0,
            	5, 56,
            1, 8, 1, /* 179: pointer.struct.ecdh_method */
            	184, 0,
            0, 32, 2, /* 184: struct.ecdh_method */
            	5, 0,
            	5, 24,
            1, 8, 1, /* 191: pointer.struct.ecdsa_method */
            	196, 0,
            0, 48, 2, /* 196: struct.ecdsa_method */
            	5, 0,
            	5, 40,
            1, 8, 1, /* 203: pointer.struct.rand_meth_st */
            	208, 0,
            0, 48, 0, /* 208: struct.rand_meth_st */
            1, 8, 1, /* 211: pointer.struct.store_method_st */
            	216, 0,
            0, 0, 0, /* 216: struct.store_method_st */
            1, 8, 1, /* 219: pointer.struct.ENGINE_CMD_DEFN_st */
            	224, 0,
            0, 32, 2, /* 224: struct.ENGINE_CMD_DEFN_st */
            	5, 8,
            	5, 16,
            0, 16, 1, /* 231: struct.crypto_ex_data_st */
            	236, 0,
            1, 8, 1, /* 236: pointer.struct.stack_st_OPENSSL_STRING */
            	241, 0,
            0, 32, 1, /* 241: struct.stack_st_OPENSSL_STRING */
            	246, 0,
            0, 32, 1, /* 246: struct.stack_st */
            	251, 8,
            1, 8, 1, /* 251: pointer.pointer.char */
            	5, 0,
            0, 0, 0, /* 256: func */
            0, 8, 0, /* 259: pointer.func */
            0, 8, 0, /* 262: pointer.func */
            0, 0, 0, /* 265: func */
            0, 8, 0, /* 268: pointer.func */
            0, 0, 0, /* 271: func */
            0, 8, 0, /* 274: pointer.func */
            0, 8, 0, /* 277: pointer.func */
            0, 8, 0, /* 280: pointer.func */
            0, 0, 0, /* 283: func */
            0, 8, 0, /* 286: pointer.func */
            0, 0, 0, /* 289: func */
            0, 0, 0, /* 292: func */
            0, 0, 0, /* 295: func */
            0, 0, 0, /* 298: func */
            0, 0, 0, /* 301: func */
            0, 0, 0, /* 304: func */
            0, 8, 0, /* 307: pointer.func */
            0, 8, 0, /* 310: pointer.func */
            0, 8, 0, /* 313: pointer.func */
            0, 8, 0, /* 316: pointer.func */
            0, 8, 0, /* 319: pointer.func */
            0, 8, 0, /* 322: pointer.func */
            0, 0, 0, /* 325: func */
            0, 8, 0, /* 328: pointer.func */
            0, 0, 0, /* 331: func */
            0, 0, 0, /* 334: func */
            0, 0, 0, /* 337: func */
            0, 0, 0, /* 340: func */
            0, 8, 0, /* 343: pointer.func */
            0, 0, 0, /* 346: func */
            0, 8, 0, /* 349: pointer.func */
            0, 8, 0, /* 352: pointer.func */
            0, 8, 0, /* 355: pointer.func */
            0, 0, 0, /* 358: func */
            0, 8, 0, /* 361: pointer.func */
            0, 8, 0, /* 364: pointer.func */
            0, 0, 0, /* 367: func */
            0, 0, 0, /* 370: func */
            0, 0, 0, /* 373: func */
            0, 0, 0, /* 376: func */
            0, 8, 0, /* 379: pointer.func */
            0, 8, 0, /* 382: pointer.func */
            1, 8, 1, /* 385: pointer.struct.env_md_st */
            	390, 0,
            0, 120, 0, /* 390: struct.env_md_st */
            0, 8, 0, /* 393: pointer.func */
            0, 8, 0, /* 396: pointer.func */
            0, 48, 4, /* 399: struct.env_md_ctx_st */
            	385, 0,
            	109, 8,
            	5, 24,
            	410, 32,
            1, 8, 1, /* 410: pointer.struct.evp_pkey_ctx_st */
            	415, 0,
            0, 80, 8, /* 415: struct.evp_pkey_ctx_st */
            	434, 0,
            	109, 8,
            	460, 16,
            	460, 24,
            	5, 40,
            	5, 48,
            	85, 56,
            	465, 64,
            1, 8, 1, /* 434: pointer.struct.evp_pkey_method_st */
            	439, 0,
            0, 208, 9, /* 439: struct.evp_pkey_method_st */
            	85, 8,
            	85, 32,
            	85, 48,
            	85, 64,
            	85, 80,
            	85, 96,
            	85, 144,
            	85, 160,
            	85, 176,
            1, 8, 1, /* 460: pointer.struct.evp_pkey_st */
            	98, 0,
            1, 8, 1, /* 465: pointer.int */
            	470, 0,
            0, 4, 0, /* 470: int */
            0, 8, 0, /* 473: pointer.func */
            0, 0, 0, /* 476: func */
            0, 0, 0, /* 479: func */
            0, 8, 0, /* 482: pointer.func */
            0, 288, 4, /* 485: struct.hmac_ctx_st */
            	385, 0,
            	399, 8,
            	399, 56,
            	399, 104,
            0, 8, 0, /* 496: pointer.func */
            0, 0, 0, /* 499: func */
            0, 8, 0, /* 502: pointer.func */
            0, 8, 0, /* 505: pointer.func */
            0, 0, 0, /* 508: func */
            0, 8, 0, /* 511: pointer.func */
            0, 0, 0, /* 514: func */
            1, 8, 1, /* 517: pointer.struct.hmac_ctx_st */
            	485, 0,
            0, 0, 0, /* 522: func */
            0, 8, 0, /* 525: pointer.func */
            0, 0, 0, /* 528: func */
            0, 0, 0, /* 531: func */
            0, 0, 0, /* 534: func */
            0, 8, 0, /* 537: pointer.func */
            0, 8, 0, /* 540: pointer.func */
            0, 8, 0, /* 543: pointer.func */
            0, 8, 0, /* 546: pointer.func */
            0, 0, 0, /* 549: func */
            0, 20, 0, /* 552: array[5].int */
            0, 8, 0, /* 555: pointer.func */
            0, 0, 0, /* 558: func */
            0, 0, 0, /* 561: func */
            0, 8, 0, /* 564: pointer.func */
            0, 0, 0, /* 567: func */
            0, 0, 0, /* 570: func */
            0, 0, 0, /* 573: func */
            0, 8, 0, /* 576: long */
            0, 0, 0, /* 579: func */
            0, 0, 0, /* 582: func */
            0, 8, 0, /* 585: pointer.func */
            0, 8, 0, /* 588: pointer.func */
            0, 8, 0, /* 591: pointer.func */
            0, 0, 0, /* 594: func */
            0, 8, 0, /* 597: pointer.func */
            0, 8, 0, /* 600: pointer.func */
            0, 0, 0, /* 603: func */
            0, 0, 0, /* 606: func */
            0, 0, 0, /* 609: func */
            0, 8, 0, /* 612: pointer.func */
            0, 0, 0, /* 615: func */
            0, 8, 0, /* 618: pointer.func */
            0, 8, 0, /* 621: pointer.func */
            0, 0, 0, /* 624: func */
            0, 8, 0, /* 627: pointer.func */
            0, 0, 0, /* 630: func */
            0, 8, 0, /* 633: pointer.func */
            0, 0, 0, /* 636: func */
            0, 8, 0, /* 639: pointer.func */
            0, 0, 0, /* 642: func */
            0, 0, 0, /* 645: func */
            0, 0, 0, /* 648: func */
            0, 0, 0, /* 651: func */
            0, 0, 0, /* 654: func */
            0, 8, 0, /* 657: pointer.func */
            0, 0, 0, /* 660: func */
            0, 0, 0, /* 663: func */
            0, 8, 0, /* 666: pointer.func */
            0, 8, 0, /* 669: pointer.func */
            0, 0, 0, /* 672: func */
            0, 8, 0, /* 675: pointer.func */
            0, 0, 0, /* 678: func */
            0, 0, 0, /* 681: func */
            0, 0, 0, /* 684: func */
            0, 8, 0, /* 687: pointer.func */
            0, 8, 0, /* 690: pointer.func */
            0, 8, 0, /* 693: pointer.func */
            0, 0, 0, /* 696: func */
            0, 8, 0, /* 699: pointer.func */
        },
        .arg_entity_index = { 517, 5, 470, 385, 109, },
        .ret_entity_index = 470,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_arg(args_addr, arg_e);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    HMAC_CTX * new_arg_a = *((HMAC_CTX * *)new_args->args[0]);

    const void * new_arg_b = *((const void * *)new_args->args[1]);

    int new_arg_c = *((int *)new_args->args[2]);

    const EVP_MD * new_arg_d = *((const EVP_MD * *)new_args->args[3]);

    ENGINE * new_arg_e = *((ENGINE * *)new_args->args[4]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_HMAC_Init_ex)(HMAC_CTX *,const void *,int,const EVP_MD *,ENGINE *);
    orig_HMAC_Init_ex = dlsym(RTLD_NEXT, "HMAC_Init_ex");
    *new_ret_ptr = (*orig_HMAC_Init_ex)(new_arg_a,new_arg_b,new_arg_c,new_arg_d,new_arg_e);

    syscall(889);

    return ret;
}

