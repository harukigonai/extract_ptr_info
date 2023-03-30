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

EVP_PKEY * bb_PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d);

EVP_PKEY * PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d) 
{
    printf("PEM_read_bio_PrivateKey called\n");
    if (!syscall(890))
        return bb_PEM_read_bio_PrivateKey(arg_a,arg_b,arg_c,arg_d);
    else {
        EVP_PKEY * (*orig_PEM_read_bio_PrivateKey)(BIO *,EVP_PKEY **,pem_password_cb *,void *);
        orig_PEM_read_bio_PrivateKey = dlsym(RTLD_NEXT, "PEM_read_bio_PrivateKey");
        return orig_PEM_read_bio_PrivateKey(arg_a,arg_b,arg_c,arg_d);
    }
}

EVP_PKEY * bb_PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d) 
{
    EVP_PKEY * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 8, 0, /* 0: pointer.func */
            1, 8, 1, /* 3: pointer.pointer.struct.evp_pkey_st.2595 */
            	8, 0,
            1, 8, 1, /* 8: pointer.struct.evp_pkey_st.2595 */
            	13, 0,
            0, 56, 4, /* 13: struct.evp_pkey_st.2595 */
            	24, 16,
            	44, 24,
            	191, 32,
            	171, 48,
            1, 8, 1, /* 24: pointer.struct.evp_pkey_asn1_method_st.2593 */
            	29, 0,
            0, 208, 2, /* 29: struct.evp_pkey_asn1_method_st.2593 */
            	36, 16,
            	36, 24,
            1, 8, 1, /* 36: pointer.char */
            	41, 0,
            0, 1, 0, /* 41: char */
            1, 8, 1, /* 44: pointer.struct.engine_st */
            	49, 0,
            0, 216, 13, /* 49: struct.engine_st */
            	36, 0,
            	36, 8,
            	78, 16,
            	90, 24,
            	102, 32,
            	114, 40,
            	126, 48,
            	138, 56,
            	146, 64,
            	154, 160,
            	166, 184,
            	44, 200,
            	44, 208,
            1, 8, 1, /* 78: pointer.struct.rsa_meth_st */
            	83, 0,
            0, 112, 2, /* 83: struct.rsa_meth_st */
            	36, 0,
            	36, 80,
            1, 8, 1, /* 90: pointer.struct.dsa_method.1040 */
            	95, 0,
            0, 96, 2, /* 95: struct.dsa_method.1040 */
            	36, 0,
            	36, 72,
            1, 8, 1, /* 102: pointer.struct.dh_method */
            	107, 0,
            0, 72, 2, /* 107: struct.dh_method */
            	36, 0,
            	36, 56,
            1, 8, 1, /* 114: pointer.struct.ecdh_method */
            	119, 0,
            0, 32, 2, /* 119: struct.ecdh_method */
            	36, 0,
            	36, 24,
            1, 8, 1, /* 126: pointer.struct.ecdsa_method */
            	131, 0,
            0, 48, 2, /* 131: struct.ecdsa_method */
            	36, 0,
            	36, 40,
            1, 8, 1, /* 138: pointer.struct.rand_meth_st */
            	143, 0,
            0, 48, 0, /* 143: struct.rand_meth_st */
            1, 8, 1, /* 146: pointer.struct.store_method_st */
            	151, 0,
            0, 0, 0, /* 151: struct.store_method_st */
            1, 8, 1, /* 154: pointer.struct.ENGINE_CMD_DEFN_st */
            	159, 0,
            0, 32, 2, /* 159: struct.ENGINE_CMD_DEFN_st */
            	36, 8,
            	36, 16,
            0, 16, 1, /* 166: struct.crypto_ex_data_st */
            	171, 0,
            1, 8, 1, /* 171: pointer.struct.stack_st_OPENSSL_STRING */
            	176, 0,
            0, 32, 1, /* 176: struct.stack_st_OPENSSL_STRING */
            	181, 0,
            0, 32, 1, /* 181: struct.stack_st */
            	186, 8,
            1, 8, 1, /* 186: pointer.pointer.char */
            	36, 0,
            0, 8, 1, /* 191: struct.fnames */
            	36, 0,
            0, 0, 0, /* 196: func */
            0, 8, 0, /* 199: pointer.func */
            0, 0, 0, /* 202: func */
            0, 8, 0, /* 205: pointer.func */
            0, 0, 0, /* 208: func */
            0, 8, 0, /* 211: pointer.func */
            0, 0, 0, /* 214: func */
            0, 8, 0, /* 217: pointer.func */
            0, 8, 0, /* 220: pointer.func */
            0, 80, 1, /* 223: struct.bio_method_st */
            	36, 8,
            0, 112, 6, /* 228: struct.bio_st */
            	243, 0,
            	36, 16,
            	36, 48,
            	248, 56,
            	248, 64,
            	166, 96,
            1, 8, 1, /* 243: pointer.struct.bio_method_st */
            	223, 0,
            1, 8, 1, /* 248: pointer.struct.bio_st */
            	228, 0,
            0, 0, 0, /* 253: func */
            0, 8, 0, /* 256: pointer.func */
            0, 0, 0, /* 259: func */
            0, 8, 0, /* 262: pointer.func */
            0, 8, 0, /* 265: pointer.func */
            0, 8, 0, /* 268: pointer.func */
            0, 8, 0, /* 271: pointer.func */
            0, 8, 0, /* 274: pointer.func */
            0, 8, 0, /* 277: pointer.func */
            0, 0, 0, /* 280: func */
            0, 0, 0, /* 283: func */
            0, 8, 0, /* 286: pointer.func */
            0, 8, 0, /* 289: pointer.func */
            0, 8, 0, /* 292: pointer.func */
            0, 0, 0, /* 295: func */
            0, 0, 0, /* 298: func */
            0, 0, 0, /* 301: func */
            0, 8, 0, /* 304: pointer.func */
            0, 0, 0, /* 307: func */
            0, 8, 0, /* 310: pointer.func */
            0, 0, 0, /* 313: func */
            0, 0, 0, /* 316: func */
            0, 0, 0, /* 319: func */
            0, 8, 0, /* 322: pointer.func */
            0, 8, 0, /* 325: pointer.func */
            0, 0, 0, /* 328: func */
            0, 8, 0, /* 331: pointer.func */
            0, 0, 0, /* 334: func */
            0, 0, 0, /* 337: func */
            0, 8, 0, /* 340: pointer.func */
            0, 0, 0, /* 343: func */
            0, 8, 0, /* 346: pointer.func */
            0, 0, 0, /* 349: func */
            0, 0, 0, /* 352: func */
            0, 8, 0, /* 355: pointer.func */
            0, 8, 0, /* 358: pointer.func */
            0, 0, 0, /* 361: func */
            0, 0, 0, /* 364: func */
            0, 0, 0, /* 367: func */
            0, 8, 0, /* 370: pointer.func */
            0, 4, 0, /* 373: int */
            0, 8, 0, /* 376: pointer.func */
            0, 8, 0, /* 379: pointer.func */
            0, 0, 0, /* 382: func */
            0, 0, 0, /* 385: func */
            0, 0, 0, /* 388: func */
            0, 0, 0, /* 391: func */
            0, 0, 0, /* 394: func */
            0, 8, 0, /* 397: pointer.func */
            0, 0, 0, /* 400: func */
            0, 0, 0, /* 403: func */
            0, 8, 0, /* 406: long */
            0, 8, 0, /* 409: pointer.func */
            0, 8, 0, /* 412: pointer.func */
            0, 0, 0, /* 415: func */
            0, 0, 0, /* 418: func */
            0, 8, 0, /* 421: pointer.func */
            0, 0, 0, /* 424: func */
            0, 0, 0, /* 427: func */
            0, 8, 0, /* 430: pointer.func */
            0, 8, 0, /* 433: pointer.func */
            0, 0, 0, /* 436: func */
            0, 0, 0, /* 439: func */
            0, 8, 0, /* 442: pointer.func */
            0, 8, 0, /* 445: pointer.func */
            0, 8, 0, /* 448: pointer.func */
            0, 8, 0, /* 451: pointer.func */
            0, 8, 0, /* 454: pointer.func */
            0, 0, 0, /* 457: func */
            0, 8, 0, /* 460: pointer.func */
            0, 8, 0, /* 463: pointer.func */
            0, 0, 0, /* 466: func */
            0, 8, 0, /* 469: pointer.func */
            0, 0, 0, /* 472: func */
            0, 0, 0, /* 475: func */
            0, 8, 0, /* 478: pointer.func */
            0, 0, 0, /* 481: func */
            0, 0, 0, /* 484: func */
            0, 8, 0, /* 487: pointer.func */
            0, 8, 0, /* 490: pointer.func */
            0, 0, 0, /* 493: func */
            0, 8, 0, /* 496: pointer.func */
            0, 0, 0, /* 499: func */
            0, 8, 0, /* 502: pointer.func */
            0, 8, 0, /* 505: pointer.func */
            0, 0, 0, /* 508: func */
            0, 0, 0, /* 511: func */
            0, 8, 0, /* 514: pointer.func */
            0, 0, 0, /* 517: func */
            0, 0, 0, /* 520: func */
            0, 0, 0, /* 523: func */
            0, 0, 0, /* 526: func */
            0, 8, 0, /* 529: pointer.func */
            0, 8, 0, /* 532: pointer.func */
            0, 0, 0, /* 535: func */
            0, 8, 0, /* 538: pointer.func */
            0, 0, 0, /* 541: func */
            0, 8, 0, /* 544: pointer.func */
            0, 8, 0, /* 547: pointer.func */
            0, 8, 0, /* 550: pointer.func */
            0, 0, 0, /* 553: func */
            0, 8, 0, /* 556: pointer.func */
            0, 0, 0, /* 559: func */
            0, 0, 0, /* 562: func */
            0, 0, 0, /* 565: func */
            0, 8, 0, /* 568: pointer.func */
        },
        .arg_entity_index = { 248, 3, 0, 36, },
        .ret_entity_index = 8,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    BIO * new_arg_a = *((BIO * *)new_args->args[0]);

    EVP_PKEY ** new_arg_b = *((EVP_PKEY ** *)new_args->args[1]);

    pem_password_cb * new_arg_c = *((pem_password_cb * *)new_args->args[2]);

    void * new_arg_d = *((void * *)new_args->args[3]);

    EVP_PKEY * *new_ret_ptr = (EVP_PKEY * *)new_args->ret;

    EVP_PKEY * (*orig_PEM_read_bio_PrivateKey)(BIO *,EVP_PKEY **,pem_password_cb *,void *);
    orig_PEM_read_bio_PrivateKey = dlsym(RTLD_NEXT, "PEM_read_bio_PrivateKey");
    *new_ret_ptr = (*orig_PEM_read_bio_PrivateKey)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    return ret;
}

