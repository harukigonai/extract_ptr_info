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

int bb_EVP_PKEY_size(EVP_PKEY * arg_a);

int EVP_PKEY_size(EVP_PKEY * arg_a) 
{
    printf("EVP_PKEY_size called\n");
    if (!syscall(890))
        return bb_EVP_PKEY_size(arg_a);
    else {
        int (*orig_EVP_PKEY_size)(EVP_PKEY *);
        orig_EVP_PKEY_size = dlsym(RTLD_NEXT, "EVP_PKEY_size");
        return orig_EVP_PKEY_size(arg_a);
    }
}

int bb_EVP_PKEY_size(EVP_PKEY * arg_a) 
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
            1, 8, 1, /* 19: pointer.pointer.char */
            	5, 0,
            0, 0, 0, /* 24: func */
            0, 96, 2, /* 27: struct.dsa_method.1040 */
            	5, 0,
            	5, 72,
            1, 8, 1, /* 34: pointer.struct.dsa_method.1040 */
            	27, 0,
            0, 8, 0, /* 39: pointer.func */
            0, 8, 0, /* 42: pointer.func */
            0, 8, 0, /* 45: pointer.func */
            0, 8, 0, /* 48: pointer.func */
            0, 8, 0, /* 51: pointer.func */
            0, 8, 0, /* 54: pointer.func */
            0, 0, 0, /* 57: func */
            0, 0, 0, /* 60: func */
            0, 8, 0, /* 63: pointer.func */
            0, 208, 2, /* 66: struct.evp_pkey_asn1_method_st.2593 */
            	5, 16,
            	5, 24,
            1, 8, 1, /* 73: pointer.struct.rsa_meth_st */
            	78, 0,
            0, 112, 2, /* 78: struct.rsa_meth_st */
            	5, 0,
            	5, 80,
            0, 8, 0, /* 85: pointer.func */
            1, 8, 1, /* 88: pointer.struct.engine_st */
            	93, 0,
            0, 216, 13, /* 93: struct.engine_st */
            	5, 0,
            	5, 8,
            	73, 16,
            	34, 24,
            	122, 32,
            	134, 40,
            	146, 48,
            	158, 56,
            	166, 64,
            	174, 160,
            	186, 184,
            	88, 200,
            	88, 208,
            1, 8, 1, /* 122: pointer.struct.dh_method */
            	127, 0,
            0, 72, 2, /* 127: struct.dh_method */
            	5, 0,
            	5, 56,
            1, 8, 1, /* 134: pointer.struct.ecdh_method */
            	139, 0,
            0, 32, 2, /* 139: struct.ecdh_method */
            	5, 0,
            	5, 24,
            1, 8, 1, /* 146: pointer.struct.ecdsa_method */
            	151, 0,
            0, 48, 2, /* 151: struct.ecdsa_method */
            	5, 0,
            	5, 40,
            1, 8, 1, /* 158: pointer.struct.rand_meth_st */
            	163, 0,
            0, 48, 0, /* 163: struct.rand_meth_st */
            1, 8, 1, /* 166: pointer.struct.store_method_st */
            	171, 0,
            0, 0, 0, /* 171: struct.store_method_st */
            1, 8, 1, /* 174: pointer.struct.ENGINE_CMD_DEFN_st */
            	179, 0,
            0, 32, 2, /* 179: struct.ENGINE_CMD_DEFN_st */
            	5, 8,
            	5, 16,
            0, 16, 1, /* 186: struct.crypto_ex_data_st */
            	191, 0,
            1, 8, 1, /* 191: pointer.struct.stack_st_OPENSSL_STRING */
            	196, 0,
            0, 32, 1, /* 196: struct.stack_st_OPENSSL_STRING */
            	201, 0,
            0, 32, 1, /* 201: struct.stack_st */
            	19, 8,
            0, 8, 0, /* 206: pointer.func */
            0, 0, 0, /* 209: func */
            0, 0, 0, /* 212: func */
            0, 0, 0, /* 215: func */
            0, 8, 0, /* 218: pointer.func */
            0, 8, 0, /* 221: pointer.func */
            0, 0, 0, /* 224: func */
            0, 0, 0, /* 227: func */
            0, 0, 0, /* 230: func */
            0, 8, 0, /* 233: pointer.func */
            0, 8, 0, /* 236: pointer.func */
            0, 8, 0, /* 239: pointer.func */
            1, 8, 1, /* 242: pointer.struct.evp_pkey_asn1_method_st.2593 */
            	66, 0,
            0, 0, 0, /* 247: func */
            0, 0, 0, /* 250: func */
            0, 8, 0, /* 253: pointer.func */
            0, 0, 0, /* 256: func */
            0, 8, 0, /* 259: pointer.func */
            0, 0, 0, /* 262: func */
            0, 0, 0, /* 265: func */
            0, 56, 4, /* 268: struct.evp_pkey_st.2595 */
            	242, 16,
            	88, 24,
            	0, 32,
            	191, 48,
            0, 8, 0, /* 279: pointer.func */
            0, 0, 0, /* 282: func */
            0, 0, 0, /* 285: func */
            0, 0, 0, /* 288: func */
            0, 8, 0, /* 291: pointer.func */
            0, 0, 0, /* 294: func */
            0, 0, 0, /* 297: func */
            0, 0, 0, /* 300: func */
            0, 8, 0, /* 303: pointer.func */
            0, 4, 0, /* 306: int */
            0, 8, 0, /* 309: pointer.func */
            0, 8, 0, /* 312: pointer.func */
            0, 0, 0, /* 315: func */
            0, 8, 0, /* 318: pointer.func */
            0, 0, 0, /* 321: func */
            0, 0, 0, /* 324: func */
            0, 8, 0, /* 327: long */
            0, 8, 0, /* 330: pointer.func */
            0, 8, 0, /* 333: pointer.func */
            0, 0, 0, /* 336: func */
            0, 0, 0, /* 339: func */
            0, 8, 0, /* 342: pointer.func */
            0, 0, 0, /* 345: func */
            0, 0, 0, /* 348: func */
            0, 8, 0, /* 351: pointer.func */
            0, 0, 0, /* 354: func */
            0, 0, 0, /* 357: func */
            0, 8, 0, /* 360: pointer.func */
            0, 8, 0, /* 363: pointer.func */
            0, 8, 0, /* 366: pointer.func */
            0, 8, 0, /* 369: pointer.func */
            0, 8, 0, /* 372: pointer.func */
            0, 0, 0, /* 375: func */
            0, 8, 0, /* 378: pointer.func */
            0, 8, 0, /* 381: pointer.func */
            0, 0, 0, /* 384: func */
            0, 8, 0, /* 387: pointer.func */
            0, 0, 0, /* 390: func */
            0, 0, 0, /* 393: func */
            0, 8, 0, /* 396: pointer.func */
            0, 0, 0, /* 399: func */
            0, 0, 0, /* 402: func */
            0, 8, 0, /* 405: pointer.func */
            0, 8, 0, /* 408: pointer.func */
            0, 0, 0, /* 411: func */
            0, 8, 0, /* 414: pointer.func */
            0, 0, 0, /* 417: func */
            0, 8, 0, /* 420: pointer.func */
            0, 8, 0, /* 423: pointer.func */
            0, 0, 0, /* 426: func */
            0, 0, 0, /* 429: func */
            0, 8, 0, /* 432: pointer.func */
            0, 0, 0, /* 435: func */
            0, 0, 0, /* 438: func */
            0, 0, 0, /* 441: func */
            0, 0, 0, /* 444: func */
            0, 8, 0, /* 447: pointer.func */
            0, 8, 0, /* 450: pointer.func */
            0, 0, 0, /* 453: func */
            0, 8, 0, /* 456: pointer.func */
            0, 0, 0, /* 459: func */
            0, 8, 0, /* 462: pointer.func */
            0, 8, 0, /* 465: pointer.func */
            0, 8, 0, /* 468: pointer.func */
            0, 0, 0, /* 471: func */
            0, 8, 0, /* 474: pointer.func */
            0, 0, 0, /* 477: func */
            0, 0, 0, /* 480: func */
            1, 8, 1, /* 483: pointer.struct.evp_pkey_st.2595 */
            	268, 0,
            0, 0, 0, /* 488: func */
            0, 8, 0, /* 491: pointer.func */
        },
        .arg_entity_index = { 483, },
        .ret_entity_index = 306,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_PKEY * new_arg_a = *((EVP_PKEY * *)new_args->args[0]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_PKEY_size)(EVP_PKEY *);
    orig_EVP_PKEY_size = dlsym(RTLD_NEXT, "EVP_PKEY_size");
    *new_ret_ptr = (*orig_EVP_PKEY_size)(new_arg_a);

    syscall(889);

    return ret;
}

