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
    unsigned long in_lib = syscall(890);
    printf("HMAC_Init_ex called %lu\n", in_lib);
    if (!in_lib)
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
            0, 128, 0, /* 27: array[128].char */
            4097, 8, 0, /* 30: pointer.func */
            0, 0, 0, /* 33: func */
            4097, 8, 0, /* 36: pointer.func */
            4097, 8, 0, /* 39: pointer.func */
            4097, 8, 0, /* 42: pointer.func */
            0, 0, 0, /* 45: func */
            0, 0, 0, /* 48: func */
            0, 0, 0, /* 51: func */
            0, 0, 0, /* 54: func */
            4097, 8, 0, /* 57: pointer.func */
            0, 0, 0, /* 60: func */
            0, 56, 4, /* 63: struct.evp_pkey_st */
            	74, 16,
            	96, 24,
            	8, 32,
            	223, 48,
            1, 8, 1, /* 74: pointer.struct.evp_pkey_asn1_method_st */
            	79, 0,
            0, 208, 3, /* 79: struct.evp_pkey_asn1_method_st */
            	13, 16,
            	13, 24,
            	88, 32,
            1, 8, 1, /* 88: pointer.struct.unnamed */
            	93, 0,
            0, 0, 0, /* 93: struct.unnamed */
            1, 8, 1, /* 96: pointer.struct.engine_st */
            	101, 0,
            0, 216, 13, /* 101: struct.engine_st */
            	13, 0,
            	13, 8,
            	130, 16,
            	142, 24,
            	154, 32,
            	166, 40,
            	178, 48,
            	190, 56,
            	198, 64,
            	206, 160,
            	218, 184,
            	96, 200,
            	96, 208,
            1, 8, 1, /* 130: pointer.struct.rsa_meth_st */
            	135, 0,
            0, 112, 2, /* 135: struct.rsa_meth_st */
            	13, 0,
            	13, 80,
            1, 8, 1, /* 142: pointer.struct.dsa_method.1040 */
            	147, 0,
            0, 96, 2, /* 147: struct.dsa_method.1040 */
            	13, 0,
            	13, 72,
            1, 8, 1, /* 154: pointer.struct.dh_method */
            	159, 0,
            0, 72, 2, /* 159: struct.dh_method */
            	13, 0,
            	13, 56,
            1, 8, 1, /* 166: pointer.struct.ecdh_method */
            	171, 0,
            0, 32, 2, /* 171: struct.ecdh_method */
            	13, 0,
            	13, 24,
            1, 8, 1, /* 178: pointer.struct.ecdsa_method */
            	183, 0,
            0, 48, 2, /* 183: struct.ecdsa_method */
            	13, 0,
            	13, 40,
            1, 8, 1, /* 190: pointer.struct.rand_meth_st */
            	195, 0,
            0, 48, 0, /* 195: struct.rand_meth_st */
            1, 8, 1, /* 198: pointer.struct.store_method_st */
            	203, 0,
            0, 0, 0, /* 203: struct.store_method_st */
            1, 8, 1, /* 206: pointer.struct.ENGINE_CMD_DEFN_st */
            	211, 0,
            0, 32, 2, /* 211: struct.ENGINE_CMD_DEFN_st */
            	13, 8,
            	13, 16,
            0, 16, 1, /* 218: struct.crypto_ex_data_st */
            	223, 0,
            1, 8, 1, /* 223: pointer.struct.stack_st_OPENSSL_STRING */
            	228, 0,
            0, 32, 1, /* 228: struct.stack_st_OPENSSL_STRING */
            	233, 0,
            0, 32, 1, /* 233: struct.stack_st */
            	238, 8,
            1, 8, 1, /* 238: pointer.pointer.char */
            	13, 0,
            0, 0, 0, /* 243: func */
            0, 0, 0, /* 246: func */
            0, 0, 0, /* 249: func */
            4097, 8, 0, /* 252: pointer.func */
            0, 0, 0, /* 255: func */
            4097, 8, 0, /* 258: pointer.func */
            0, 0, 0, /* 261: func */
            4097, 8, 0, /* 264: pointer.func */
            0, 0, 0, /* 267: func */
            0, 0, 0, /* 270: func */
            0, 0, 0, /* 273: func */
            0, 0, 0, /* 276: func */
            4097, 8, 0, /* 279: pointer.func */
            4097, 8, 0, /* 282: pointer.func */
            0, 0, 0, /* 285: func */
            4097, 8, 0, /* 288: pointer.func */
            4097, 8, 0, /* 291: pointer.func */
            0, 0, 0, /* 294: func */
            4097, 8, 0, /* 297: pointer.func */
            0, 0, 0, /* 300: func */
            4097, 8, 0, /* 303: pointer.func */
            4097, 8, 0, /* 306: pointer.func */
            4097, 8, 0, /* 309: pointer.func */
            0, 0, 0, /* 312: func */
            4097, 8, 0, /* 315: pointer.func */
            4097, 8, 0, /* 318: pointer.func */
            0, 0, 0, /* 321: func */
            0, 0, 0, /* 324: func */
            4097, 8, 0, /* 327: pointer.func */
            4097, 8, 0, /* 330: pointer.func */
            4097, 8, 0, /* 333: pointer.func */
            4097, 8, 0, /* 336: pointer.func */
            4097, 8, 0, /* 339: pointer.func */
            0, 0, 0, /* 342: func */
            4097, 8, 0, /* 345: pointer.func */
            0, 0, 0, /* 348: func */
            0, 0, 0, /* 351: func */
            4097, 8, 0, /* 354: pointer.func */
            0, 0, 0, /* 357: func */
            4097, 8, 0, /* 360: pointer.func */
            0, 0, 0, /* 363: func */
            4097, 8, 0, /* 366: pointer.func */
            0, 0, 0, /* 369: func */
            4097, 8, 0, /* 372: pointer.func */
            4097, 8, 0, /* 375: pointer.func */
            4097, 8, 0, /* 378: pointer.func */
            0, 288, 4, /* 381: struct.hmac_ctx_st */
            	392, 0,
            	400, 8,
            	400, 56,
            	400, 104,
            1, 8, 1, /* 392: pointer.struct.env_md_st */
            	397, 0,
            0, 120, 0, /* 397: struct.env_md_st */
            0, 48, 4, /* 400: struct.env_md_ctx_st */
            	392, 0,
            	96, 8,
            	13, 24,
            	411, 32,
            1, 8, 1, /* 411: pointer.struct.evp_pkey_ctx_st */
            	416, 0,
            0, 80, 8, /* 416: struct.evp_pkey_ctx_st */
            	435, 0,
            	96, 8,
            	461, 16,
            	461, 24,
            	13, 40,
            	13, 48,
            	88, 56,
            	0, 64,
            1, 8, 1, /* 435: pointer.struct.evp_pkey_method_st */
            	440, 0,
            0, 208, 9, /* 440: struct.evp_pkey_method_st */
            	88, 8,
            	88, 32,
            	88, 48,
            	88, 64,
            	88, 80,
            	88, 96,
            	88, 144,
            	88, 160,
            	88, 176,
            1, 8, 1, /* 461: pointer.struct.evp_pkey_st */
            	63, 0,
            0, 0, 0, /* 466: func */
            0, 0, 0, /* 469: func */
            4097, 8, 0, /* 472: pointer.func */
            4097, 8, 0, /* 475: pointer.func */
            4097, 8, 0, /* 478: pointer.func */
            0, 0, 0, /* 481: func */
            4097, 8, 0, /* 484: pointer.func */
            0, 0, 0, /* 487: func */
            0, 8, 0, /* 490: long */
            4097, 8, 0, /* 493: pointer.func */
            4097, 8, 0, /* 496: pointer.func */
            0, 0, 0, /* 499: func */
            0, 0, 0, /* 502: func */
            0, 0, 0, /* 505: func */
            0, 0, 0, /* 508: func */
            0, 0, 0, /* 511: func */
            0, 0, 0, /* 514: func */
            4097, 8, 0, /* 517: pointer.func */
            4097, 8, 0, /* 520: pointer.func */
            0, 0, 0, /* 523: func */
            4097, 8, 0, /* 526: pointer.func */
            4097, 8, 0, /* 529: pointer.func */
            0, 0, 0, /* 532: func */
            0, 0, 0, /* 535: func */
            0, 0, 0, /* 538: func */
            4097, 8, 0, /* 541: pointer.func */
            0, 0, 0, /* 544: func */
            0, 0, 0, /* 547: func */
            4097, 8, 0, /* 550: pointer.func */
            0, 0, 0, /* 553: func */
            0, 0, 0, /* 556: func */
            0, 0, 0, /* 559: func */
            0, 0, 0, /* 562: func */
            4097, 8, 0, /* 565: pointer.func */
            4097, 8, 0, /* 568: pointer.func */
            4097, 8, 0, /* 571: pointer.func */
            4097, 8, 0, /* 574: pointer.func */
            0, 1, 0, /* 577: char */
            0, 20, 0, /* 580: array[5].int */
            0, 0, 0, /* 583: func */
            0, 0, 0, /* 586: func */
            0, 0, 0, /* 589: func */
            4097, 8, 0, /* 592: pointer.func */
            0, 0, 0, /* 595: func */
            4097, 8, 0, /* 598: pointer.func */
            4097, 8, 0, /* 601: pointer.func */
            0, 0, 0, /* 604: func */
            4097, 8, 0, /* 607: pointer.func */
            4097, 8, 0, /* 610: pointer.func */
            0, 0, 0, /* 613: func */
            4097, 8, 0, /* 616: pointer.func */
            4097, 8, 0, /* 619: pointer.func */
            0, 0, 0, /* 622: func */
            0, 0, 0, /* 625: func */
            4097, 8, 0, /* 628: pointer.func */
            4097, 8, 0, /* 631: pointer.func */
            4097, 8, 0, /* 634: pointer.func */
            0, 0, 0, /* 637: func */
            4097, 8, 0, /* 640: pointer.func */
            0, 0, 0, /* 643: func */
            4097, 8, 0, /* 646: pointer.func */
            0, 0, 0, /* 649: func */
            4097, 8, 0, /* 652: pointer.func */
            4097, 8, 0, /* 655: pointer.func */
            0, 0, 0, /* 658: func */
            0, 0, 0, /* 661: func */
            4097, 8, 0, /* 664: pointer.func */
            0, 0, 0, /* 667: func */
            4097, 8, 0, /* 670: pointer.func */
            0, 0, 0, /* 673: func */
            1, 8, 1, /* 676: pointer.struct.hmac_ctx_st */
            	381, 0,
            4097, 8, 0, /* 681: pointer.func */
            0, 0, 0, /* 684: func */
            4097, 8, 0, /* 687: pointer.func */
            0, 0, 0, /* 690: func */
            4097, 8, 0, /* 693: pointer.func */
            0, 0, 0, /* 696: func */
            0, 0, 0, /* 699: func */
        },
        .arg_entity_index = { 676, 13, 5, 392, 96, },
        .ret_entity_index = 5,
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

