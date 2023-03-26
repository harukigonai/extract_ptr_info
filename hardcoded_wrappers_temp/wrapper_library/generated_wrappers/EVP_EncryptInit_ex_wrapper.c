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

int EVP_EncryptInit_ex(EVP_CIPHER_CTX * arg_a,const EVP_CIPHER * arg_b,ENGINE * arg_c,const unsigned char * arg_d,const unsigned char * arg_e) 
{
    printf("EVP_EncryptInit_ex called\n");
    int ret;

    struct lib_enter_args args = {
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            0, 32, 1, /* 3: struct.stack_st_OPENSSL_STRING */
            	8, 0,
            0, 32, 2, /* 8: struct.stack_st */
            	15, 8,
            	28, 24,
            1, 8, 1, /* 15: pointer.pointer.char */
            	20, 0,
            1, 8, 1, /* 20: pointer.char */
            	25, 0,
            0, 1, 0, /* 25: char */
            1, 8, 1, /* 28: pointer.func */
            	0, 0,
            1, 8, 1, /* 33: pointer.struct.ENGINE_CMD_DEFN_st */
            	38, 0,
            0, 32, 2, /* 38: struct.ENGINE_CMD_DEFN_st */
            	20, 8,
            	20, 16,
            0, 0, 0, /* 45: func */
            0, 0, 0, /* 48: func */
            1, 8, 1, /* 51: pointer.func */
            	48, 0,
            0, 0, 0, /* 56: struct.unnamed */
            0, 0, 0, /* 59: func */
            1, 8, 1, /* 62: pointer.func */
            	59, 0,
            0, 0, 0, /* 67: func */
            1, 8, 1, /* 70: pointer.func */
            	67, 0,
            1, 8, 1, /* 75: pointer.func */
            	80, 0,
            0, 0, 0, /* 80: func */
            0, 0, 0, /* 83: func */
            0, 0, 0, /* 86: func */
            1, 8, 1, /* 89: pointer.func */
            	86, 0,
            0, 0, 0, /* 94: func */
            1, 8, 1, /* 97: pointer.func */
            	94, 0,
            1, 8, 1, /* 102: pointer.func */
            	107, 0,
            0, 0, 0, /* 107: func */
            0, 0, 0, /* 110: func */
            0, 0, 0, /* 113: func */
            1, 8, 1, /* 116: pointer.func */
            	110, 0,
            1, 8, 1, /* 121: pointer.struct.rand_meth_st */
            	126, 0,
            0, 48, 6, /* 126: struct.rand_meth_st */
            	116, 0,
            	102, 8,
            	97, 16,
            	89, 24,
            	102, 32,
            	141, 40,
            1, 8, 1, /* 141: pointer.func */
            	83, 0,
            0, 0, 0, /* 146: func */
            0, 0, 0, /* 149: func */
            1, 8, 1, /* 152: pointer.func */
            	149, 0,
            0, 48, 5, /* 157: struct.ecdsa_method */
            	20, 0,
            	152, 8,
            	170, 16,
            	175, 24,
            	20, 40,
            1, 8, 1, /* 170: pointer.func */
            	146, 0,
            1, 8, 1, /* 175: pointer.func */
            	180, 0,
            0, 0, 0, /* 180: func */
            1, 8, 1, /* 183: pointer.struct.ecdsa_method */
            	157, 0,
            0, 32, 3, /* 188: struct.ecdh_method */
            	20, 0,
            	197, 8,
            	20, 24,
            1, 8, 1, /* 197: pointer.func */
            	202, 0,
            0, 0, 0, /* 202: func */
            1, 8, 1, /* 205: pointer.struct.ecdh_method */
            	188, 0,
            1, 8, 1, /* 210: pointer.func */
            	215, 0,
            0, 0, 0, /* 215: func */
            0, 112, 13, /* 218: struct.rsa_meth_st.1132 */
            	20, 0,
            	247, 8,
            	247, 16,
            	247, 24,
            	247, 32,
            	255, 40,
            	263, 48,
            	271, 56,
            	271, 64,
            	20, 80,
            	279, 88,
            	287, 96,
            	295, 104,
            1, 8, 1, /* 247: pointer.func */
            	252, 0,
            0, 0, 0, /* 252: func */
            1, 8, 1, /* 255: pointer.func */
            	260, 0,
            0, 0, 0, /* 260: func */
            1, 8, 1, /* 263: pointer.func */
            	268, 0,
            0, 0, 0, /* 268: func */
            1, 8, 1, /* 271: pointer.func */
            	276, 0,
            0, 0, 0, /* 276: func */
            1, 8, 1, /* 279: pointer.func */
            	284, 0,
            0, 0, 0, /* 284: func */
            1, 8, 1, /* 287: pointer.func */
            	292, 0,
            0, 0, 0, /* 292: func */
            1, 8, 1, /* 295: pointer.func */
            	300, 0,
            0, 0, 0, /* 300: func */
            1, 8, 1, /* 303: pointer.struct.rsa_meth_st.1132 */
            	218, 0,
            0, 4, 0, /* 308: int */
            1, 8, 1, /* 311: pointer.func */
            	316, 0,
            0, 0, 0, /* 316: func */
            0, 216, 24, /* 319: struct.engine_st.1173 */
            	20, 0,
            	20, 8,
            	303, 16,
            	370, 24,
            	448, 32,
            	205, 40,
            	183, 48,
            	121, 56,
            	496, 64,
            	75, 72,
            	504, 80,
            	70, 88,
            	62, 96,
            	509, 104,
            	509, 112,
            	509, 120,
            	51, 128,
            	514, 136,
            	514, 144,
            	522, 152,
            	33, 160,
            	527, 184,
            	537, 200,
            	537, 208,
            1, 8, 1, /* 370: pointer.struct.dsa_method.1135 */
            	375, 0,
            0, 96, 11, /* 375: struct.dsa_method.1135 */
            	20, 0,
            	400, 8,
            	408, 16,
            	416, 24,
            	311, 32,
            	424, 40,
            	432, 48,
            	432, 56,
            	20, 72,
            	440, 80,
            	432, 88,
            1, 8, 1, /* 400: pointer.func */
            	405, 0,
            0, 0, 0, /* 405: func */
            1, 8, 1, /* 408: pointer.func */
            	413, 0,
            0, 0, 0, /* 413: func */
            1, 8, 1, /* 416: pointer.func */
            	421, 0,
            0, 0, 0, /* 421: func */
            1, 8, 1, /* 424: pointer.func */
            	429, 0,
            0, 0, 0, /* 429: func */
            1, 8, 1, /* 432: pointer.func */
            	437, 0,
            0, 0, 0, /* 437: func */
            1, 8, 1, /* 440: pointer.func */
            	445, 0,
            0, 0, 0, /* 445: func */
            1, 8, 1, /* 448: pointer.struct.dh_method.1137 */
            	453, 0,
            0, 72, 8, /* 453: struct.dh_method.1137 */
            	20, 0,
            	472, 8,
            	480, 16,
            	488, 24,
            	472, 32,
            	472, 40,
            	20, 56,
            	210, 64,
            1, 8, 1, /* 472: pointer.func */
            	477, 0,
            0, 0, 0, /* 477: func */
            1, 8, 1, /* 480: pointer.func */
            	485, 0,
            0, 0, 0, /* 485: func */
            1, 8, 1, /* 488: pointer.func */
            	493, 0,
            0, 0, 0, /* 493: func */
            1, 8, 1, /* 496: pointer.struct.store_method_st */
            	501, 0,
            0, 0, 0, /* 501: struct.store_method_st */
            1, 8, 1, /* 504: pointer.func */
            	113, 0,
            1, 8, 1, /* 509: pointer.struct.unnamed */
            	56, 0,
            1, 8, 1, /* 514: pointer.func */
            	519, 0,
            0, 0, 0, /* 519: func */
            1, 8, 1, /* 522: pointer.func */
            	45, 0,
            0, 16, 1, /* 527: struct.crypto_ex_data_st */
            	532, 0,
            1, 8, 1, /* 532: pointer.struct.stack_st_OPENSSL_STRING */
            	3, 0,
            1, 8, 1, /* 537: pointer.struct.engine_st.1173 */
            	319, 0,
            0, 0, 0, /* 542: func */
            1, 8, 1, /* 545: pointer.func */
            	542, 0,
            1, 8, 1, /* 550: pointer.struct.evp_cipher_ctx_st.2258 */
            	555, 0,
            0, 168, 4, /* 555: struct.evp_cipher_ctx_st.2258 */
            	566, 0,
            	537, 8,
            	20, 96,
            	20, 120,
            1, 8, 1, /* 566: pointer.struct.evp_cipher_st.2256 */
            	571, 0,
            0, 88, 7, /* 571: struct.evp_cipher_st.2256 */
            	588, 24,
            	596, 32,
            	604, 40,
            	612, 56,
            	612, 64,
            	545, 72,
            	20, 80,
            1, 8, 1, /* 588: pointer.func */
            	593, 0,
            0, 0, 0, /* 593: func */
            1, 8, 1, /* 596: pointer.func */
            	601, 0,
            0, 0, 0, /* 601: func */
            1, 8, 1, /* 604: pointer.func */
            	609, 0,
            0, 0, 0, /* 609: func */
            1, 8, 1, /* 612: pointer.func */
            	617, 0,
            0, 0, 0, /* 617: func */
            0, 32, 0, /* 620: array[32].char */
            0, 8, 0, /* 623: long */
            0, 16, 0, /* 626: array[16].char */
        },
        .arg_entity_index = { 550, 566, 537, 20, 20, },
        .ret_entity_index = 308,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_arg(args_addr, arg_e);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_CIPHER_CTX * new_arg_a = *((EVP_CIPHER_CTX * *)new_args->args[0]);

    const EVP_CIPHER * new_arg_b = *((const EVP_CIPHER * *)new_args->args[1]);

    ENGINE * new_arg_c = *((ENGINE * *)new_args->args[2]);

    const unsigned char * new_arg_d = *((const unsigned char * *)new_args->args[3]);

    const unsigned char * new_arg_e = *((const unsigned char * *)new_args->args[4]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_EncryptInit_ex)(EVP_CIPHER_CTX *,const EVP_CIPHER *,ENGINE *,const unsigned char *,const unsigned char *);
    orig_EVP_EncryptInit_ex = dlsym(RTLD_NEXT, "EVP_EncryptInit_ex");
    *new_ret_ptr = (*orig_EVP_EncryptInit_ex)(new_arg_a,new_arg_b,new_arg_c,new_arg_d,new_arg_e);

    syscall(889);

    return ret;
}

