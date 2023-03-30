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

int bb_EVP_SignFinal(EVP_MD_CTX * arg_a,unsigned char * arg_b,unsigned int * arg_c,EVP_PKEY * arg_d);

int EVP_SignFinal(EVP_MD_CTX * arg_a,unsigned char * arg_b,unsigned int * arg_c,EVP_PKEY * arg_d) 
{
    printf("EVP_SignFinal called\n");
    if (!syscall(890))
        return bb_EVP_SignFinal(arg_a,arg_b,arg_c,arg_d);
    else {
        int (*orig_EVP_SignFinal)(EVP_MD_CTX *,unsigned char *,unsigned int *,EVP_PKEY *);
        orig_EVP_SignFinal = dlsym(RTLD_NEXT, "EVP_SignFinal");
        return orig_EVP_SignFinal(arg_a,arg_b,arg_c,arg_d);
    }
}

int bb_EVP_SignFinal(EVP_MD_CTX * arg_a,unsigned char * arg_b,unsigned int * arg_c,EVP_PKEY * arg_d) 
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
            0, 8, 0, /* 31: pointer.func */
            0, 0, 0, /* 34: func */
            0, 8, 0, /* 37: pointer.func */
            0, 0, 0, /* 40: func */
            0, 8, 0, /* 43: pointer.func */
            0, 0, 0, /* 46: func */
            0, 8, 0, /* 49: pointer.func */
            0, 8, 0, /* 52: pointer.func */
            0, 8, 0, /* 55: pointer.func */
            0, 0, 0, /* 58: func */
            0, 8, 0, /* 61: pointer.func */
            0, 0, 0, /* 64: func */
            0, 8, 0, /* 67: pointer.func */
            0, 0, 0, /* 70: func */
            0, 208, 3, /* 73: struct.evp_pkey_asn1_method_st */
            	5, 16,
            	5, 24,
            	82, 32,
            1, 8, 1, /* 82: pointer.struct.unnamed */
            	87, 0,
            0, 0, 0, /* 87: struct.unnamed */
            1, 8, 1, /* 90: pointer.struct.evp_pkey_asn1_method_st */
            	73, 0,
            0, 56, 4, /* 95: struct.evp_pkey_st */
            	90, 16,
            	106, 24,
            	0, 32,
            	233, 48,
            1, 8, 1, /* 106: pointer.struct.engine_st */
            	111, 0,
            0, 216, 13, /* 111: struct.engine_st */
            	5, 0,
            	5, 8,
            	140, 16,
            	152, 24,
            	164, 32,
            	176, 40,
            	188, 48,
            	200, 56,
            	208, 64,
            	216, 160,
            	228, 184,
            	106, 200,
            	106, 208,
            1, 8, 1, /* 140: pointer.struct.rsa_meth_st */
            	145, 0,
            0, 112, 2, /* 145: struct.rsa_meth_st */
            	5, 0,
            	5, 80,
            1, 8, 1, /* 152: pointer.struct.dsa_method.1040 */
            	157, 0,
            0, 96, 2, /* 157: struct.dsa_method.1040 */
            	5, 0,
            	5, 72,
            1, 8, 1, /* 164: pointer.struct.dh_method */
            	169, 0,
            0, 72, 2, /* 169: struct.dh_method */
            	5, 0,
            	5, 56,
            1, 8, 1, /* 176: pointer.struct.ecdh_method */
            	181, 0,
            0, 32, 2, /* 181: struct.ecdh_method */
            	5, 0,
            	5, 24,
            1, 8, 1, /* 188: pointer.struct.ecdsa_method */
            	193, 0,
            0, 48, 2, /* 193: struct.ecdsa_method */
            	5, 0,
            	5, 40,
            1, 8, 1, /* 200: pointer.struct.rand_meth_st */
            	205, 0,
            0, 48, 0, /* 205: struct.rand_meth_st */
            1, 8, 1, /* 208: pointer.struct.store_method_st */
            	213, 0,
            0, 0, 0, /* 213: struct.store_method_st */
            1, 8, 1, /* 216: pointer.struct.ENGINE_CMD_DEFN_st */
            	221, 0,
            0, 32, 2, /* 221: struct.ENGINE_CMD_DEFN_st */
            	5, 8,
            	5, 16,
            0, 16, 1, /* 228: struct.crypto_ex_data_st */
            	233, 0,
            1, 8, 1, /* 233: pointer.struct.stack_st_OPENSSL_STRING */
            	238, 0,
            0, 32, 1, /* 238: struct.stack_st_OPENSSL_STRING */
            	243, 0,
            0, 32, 1, /* 243: struct.stack_st */
            	248, 8,
            1, 8, 1, /* 248: pointer.pointer.char */
            	5, 0,
            0, 0, 0, /* 253: func */
            0, 8, 0, /* 256: pointer.func */
            0, 8, 0, /* 259: pointer.func */
            0, 0, 0, /* 262: func */
            0, 8, 0, /* 265: pointer.func */
            0, 0, 0, /* 268: func */
            0, 8, 0, /* 271: pointer.func */
            0, 8, 0, /* 274: pointer.func */
            0, 8, 0, /* 277: pointer.func */
            0, 0, 0, /* 280: func */
            0, 8, 0, /* 283: pointer.func */
            0, 0, 0, /* 286: func */
            0, 0, 0, /* 289: func */
            0, 0, 0, /* 292: func */
            0, 0, 0, /* 295: func */
            0, 0, 0, /* 298: func */
            0, 0, 0, /* 301: func */
            0, 8, 0, /* 304: pointer.func */
            0, 8, 0, /* 307: pointer.func */
            0, 8, 0, /* 310: pointer.func */
            0, 8, 0, /* 313: pointer.func */
            0, 0, 0, /* 316: func */
            0, 8, 0, /* 319: pointer.func */
            0, 0, 0, /* 322: func */
            0, 0, 0, /* 325: func */
            0, 8, 0, /* 328: pointer.func */
            0, 0, 0, /* 331: func */
            0, 8, 0, /* 334: pointer.func */
            0, 8, 0, /* 337: pointer.func */
            0, 8, 0, /* 340: pointer.func */
            0, 0, 0, /* 343: func */
            0, 8, 0, /* 346: pointer.func */
            0, 8, 0, /* 349: pointer.func */
            0, 0, 0, /* 352: func */
            0, 0, 0, /* 355: func */
            0, 0, 0, /* 358: func */
            0, 0, 0, /* 361: func */
            0, 8, 0, /* 364: pointer.func */
            0, 8, 0, /* 367: pointer.func */
            1, 8, 1, /* 370: pointer.struct.env_md_st */
            	375, 0,
            0, 120, 0, /* 375: struct.env_md_st */
            0, 48, 4, /* 378: struct.env_md_ctx_st */
            	370, 0,
            	106, 8,
            	5, 24,
            	389, 32,
            1, 8, 1, /* 389: pointer.struct.evp_pkey_ctx_st */
            	394, 0,
            0, 80, 8, /* 394: struct.evp_pkey_ctx_st */
            	413, 0,
            	106, 8,
            	439, 16,
            	439, 24,
            	5, 40,
            	5, 48,
            	82, 56,
            	444, 64,
            1, 8, 1, /* 413: pointer.struct.evp_pkey_method_st */
            	418, 0,
            0, 208, 9, /* 418: struct.evp_pkey_method_st */
            	82, 8,
            	82, 32,
            	82, 48,
            	82, 64,
            	82, 80,
            	82, 96,
            	82, 144,
            	82, 160,
            	82, 176,
            1, 8, 1, /* 439: pointer.struct.evp_pkey_st */
            	95, 0,
            1, 8, 1, /* 444: pointer.int */
            	449, 0,
            0, 4, 0, /* 449: int */
            0, 8, 0, /* 452: pointer.func */
            0, 0, 0, /* 455: func */
            0, 0, 0, /* 458: func */
            0, 8, 0, /* 461: pointer.func */
            0, 8, 0, /* 464: pointer.func */
            0, 8, 0, /* 467: pointer.func */
            0, 0, 0, /* 470: func */
            1, 8, 1, /* 473: pointer.struct.env_md_ctx_st */
            	378, 0,
            0, 0, 0, /* 478: func */
            0, 8, 0, /* 481: pointer.func */
            0, 0, 0, /* 484: func */
            0, 8, 0, /* 487: pointer.func */
            0, 8, 0, /* 490: pointer.func */
            0, 0, 0, /* 493: func */
            0, 8, 0, /* 496: pointer.func */
            0, 0, 0, /* 499: func */
            0, 8, 0, /* 502: pointer.func */
            0, 0, 0, /* 505: func */
            0, 0, 0, /* 508: func */
            0, 0, 0, /* 511: func */
            0, 8, 0, /* 514: pointer.func */
            0, 8, 0, /* 517: pointer.func */
            0, 0, 0, /* 520: func */
            0, 20, 0, /* 523: array[5].int */
            0, 8, 0, /* 526: pointer.func */
            0, 0, 0, /* 529: func */
            0, 0, 0, /* 532: func */
            0, 8, 0, /* 535: pointer.func */
            0, 0, 0, /* 538: func */
            0, 0, 0, /* 541: func */
            0, 0, 0, /* 544: func */
            0, 8, 0, /* 547: long */
            0, 0, 0, /* 550: func */
            0, 0, 0, /* 553: func */
            0, 0, 0, /* 556: func */
            0, 0, 0, /* 559: func */
            0, 8, 0, /* 562: pointer.func */
            0, 8, 0, /* 565: pointer.func */
            0, 8, 0, /* 568: pointer.func */
            0, 0, 0, /* 571: func */
            0, 8, 0, /* 574: pointer.func */
            0, 8, 0, /* 577: pointer.func */
            0, 0, 0, /* 580: func */
            0, 0, 0, /* 583: func */
            0, 0, 0, /* 586: func */
            0, 8, 0, /* 589: pointer.func */
            0, 0, 0, /* 592: func */
            0, 8, 0, /* 595: pointer.func */
            0, 8, 0, /* 598: pointer.func */
            0, 8, 0, /* 601: pointer.func */
            0, 8, 0, /* 604: pointer.func */
            0, 0, 0, /* 607: func */
            0, 8, 0, /* 610: pointer.func */
            0, 0, 0, /* 613: func */
            0, 8, 0, /* 616: pointer.func */
            0, 0, 0, /* 619: func */
            0, 8, 0, /* 622: pointer.func */
            0, 0, 0, /* 625: func */
            0, 0, 0, /* 628: func */
            0, 0, 0, /* 631: func */
            0, 0, 0, /* 634: func */
            0, 0, 0, /* 637: func */
            0, 8, 0, /* 640: pointer.func */
            0, 0, 0, /* 643: func */
            0, 0, 0, /* 646: func */
            0, 8, 0, /* 649: pointer.func */
            0, 8, 0, /* 652: pointer.func */
            0, 0, 0, /* 655: func */
            0, 8, 0, /* 658: pointer.func */
            0, 0, 0, /* 661: func */
            0, 0, 0, /* 664: func */
            0, 8, 0, /* 667: pointer.func */
            0, 8, 0, /* 670: pointer.func */
            0, 8, 0, /* 673: pointer.func */
            0, 0, 0, /* 676: func */
            0, 8, 0, /* 679: pointer.func */
            0, 8, 0, /* 682: pointer.func */
            0, 8, 0, /* 685: pointer.func */
        },
        .arg_entity_index = { 473, 5, 444, 439, },
        .ret_entity_index = 449,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * new_arg_a = *((EVP_MD_CTX * *)new_args->args[0]);

    unsigned char * new_arg_b = *((unsigned char * *)new_args->args[1]);

    unsigned int * new_arg_c = *((unsigned int * *)new_args->args[2]);

    EVP_PKEY * new_arg_d = *((EVP_PKEY * *)new_args->args[3]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_SignFinal)(EVP_MD_CTX *,unsigned char *,unsigned int *,EVP_PKEY *);
    orig_EVP_SignFinal = dlsym(RTLD_NEXT, "EVP_SignFinal");
    *new_ret_ptr = (*orig_EVP_SignFinal)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    return ret;
}

