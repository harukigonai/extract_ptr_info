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
    int ret;

    struct lib_enter_args args = {
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            0, 16, 2, /* 3: struct.crypto_ex_data_st */
            	10, 0,
            	33, 8,
            1, 8, 1, /* 10: pointer.struct.stack_st_OPENSSL_STRING */
            	15, 0,
            0, 32, 1, /* 15: struct.stack_st_OPENSSL_STRING */
            	20, 0,
            0, 32, 5, /* 20: struct.stack_st */
            	33, 0,
            	36, 8,
            	33, 16,
            	33, 20,
            	49, 24,
            0, 4, 0, /* 33: int */
            1, 8, 1, /* 36: pointer.pointer.char */
            	41, 0,
            1, 8, 1, /* 41: pointer.char */
            	46, 0,
            0, 1, 0, /* 46: char */
            1, 8, 1, /* 49: pointer.func */
            	0, 0,
            1, 8, 1, /* 54: pointer.struct.ENGINE_CMD_DEFN_st */
            	59, 0,
            0, 32, 4, /* 59: struct.ENGINE_CMD_DEFN_st */
            	33, 0,
            	41, 8,
            	41, 16,
            	33, 24,
            0, 0, 0, /* 70: func */
            0, 0, 0, /* 73: func */
            1, 8, 1, /* 76: pointer.func */
            	73, 0,
            0, 0, 0, /* 81: struct.unnamed */
            0, 0, 0, /* 84: func */
            1, 8, 1, /* 87: pointer.func */
            	84, 0,
            0, 0, 0, /* 92: func */
            1, 8, 1, /* 95: pointer.func */
            	92, 0,
            1, 8, 1, /* 100: pointer.func */
            	105, 0,
            0, 0, 0, /* 105: func */
            0, 0, 0, /* 108: func */
            0, 0, 0, /* 111: func */
            1, 8, 1, /* 114: pointer.func */
            	111, 0,
            0, 0, 0, /* 119: func */
            1, 8, 1, /* 122: pointer.func */
            	119, 0,
            1, 8, 1, /* 127: pointer.func */
            	132, 0,
            0, 0, 0, /* 132: func */
            0, 0, 0, /* 135: func */
            0, 0, 0, /* 138: func */
            1, 8, 1, /* 141: pointer.func */
            	135, 0,
            1, 8, 1, /* 146: pointer.struct.rand_meth_st */
            	151, 0,
            0, 48, 6, /* 151: struct.rand_meth_st */
            	141, 0,
            	127, 8,
            	122, 16,
            	114, 24,
            	127, 32,
            	166, 40,
            1, 8, 1, /* 166: pointer.func */
            	108, 0,
            0, 0, 0, /* 171: func */
            0, 0, 0, /* 174: func */
            1, 8, 1, /* 177: pointer.func */
            	174, 0,
            0, 48, 6, /* 182: struct.ecdsa_method */
            	41, 0,
            	177, 8,
            	197, 16,
            	202, 24,
            	33, 32,
            	41, 40,
            1, 8, 1, /* 197: pointer.func */
            	171, 0,
            1, 8, 1, /* 202: pointer.func */
            	207, 0,
            0, 0, 0, /* 207: func */
            1, 8, 1, /* 210: pointer.struct.ecdsa_method */
            	182, 0,
            0, 32, 4, /* 215: struct.ecdh_method */
            	41, 0,
            	226, 8,
            	33, 16,
            	41, 24,
            1, 8, 1, /* 226: pointer.func */
            	231, 0,
            0, 0, 0, /* 231: func */
            1, 8, 1, /* 234: pointer.func */
            	239, 0,
            0, 0, 0, /* 239: func */
            0, 112, 14, /* 242: struct.rsa_meth_st.1132 */
            	41, 0,
            	273, 8,
            	273, 16,
            	273, 24,
            	273, 32,
            	281, 40,
            	289, 48,
            	297, 56,
            	297, 64,
            	33, 72,
            	41, 80,
            	305, 88,
            	313, 96,
            	321, 104,
            1, 8, 1, /* 273: pointer.func */
            	278, 0,
            0, 0, 0, /* 278: func */
            1, 8, 1, /* 281: pointer.func */
            	286, 0,
            0, 0, 0, /* 286: func */
            1, 8, 1, /* 289: pointer.func */
            	294, 0,
            0, 0, 0, /* 294: func */
            1, 8, 1, /* 297: pointer.func */
            	302, 0,
            0, 0, 0, /* 302: func */
            1, 8, 1, /* 305: pointer.func */
            	310, 0,
            0, 0, 0, /* 310: func */
            1, 8, 1, /* 313: pointer.func */
            	318, 0,
            0, 0, 0, /* 318: func */
            1, 8, 1, /* 321: pointer.func */
            	326, 0,
            0, 0, 0, /* 326: func */
            1, 8, 1, /* 329: pointer.struct.rsa_meth_st.1132 */
            	242, 0,
            1, 8, 1, /* 334: pointer.func */
            	339, 0,
            0, 0, 0, /* 339: func */
            0, 216, 27, /* 342: struct.engine_st.1173 */
            	41, 0,
            	41, 8,
            	329, 16,
            	399, 24,
            	479, 32,
            	529, 40,
            	210, 48,
            	146, 56,
            	534, 64,
            	100, 72,
            	542, 80,
            	95, 88,
            	87, 96,
            	547, 104,
            	547, 112,
            	547, 120,
            	76, 128,
            	552, 136,
            	552, 144,
            	560, 152,
            	54, 160,
            	33, 168,
            	33, 172,
            	33, 176,
            	3, 184,
            	565, 200,
            	565, 208,
            1, 8, 1, /* 399: pointer.struct.dsa_method.1135 */
            	404, 0,
            0, 96, 12, /* 404: struct.dsa_method.1135 */
            	41, 0,
            	431, 8,
            	439, 16,
            	447, 24,
            	334, 32,
            	455, 40,
            	463, 48,
            	463, 56,
            	33, 64,
            	41, 72,
            	471, 80,
            	463, 88,
            1, 8, 1, /* 431: pointer.func */
            	436, 0,
            0, 0, 0, /* 436: func */
            1, 8, 1, /* 439: pointer.func */
            	444, 0,
            0, 0, 0, /* 444: func */
            1, 8, 1, /* 447: pointer.func */
            	452, 0,
            0, 0, 0, /* 452: func */
            1, 8, 1, /* 455: pointer.func */
            	460, 0,
            0, 0, 0, /* 460: func */
            1, 8, 1, /* 463: pointer.func */
            	468, 0,
            0, 0, 0, /* 468: func */
            1, 8, 1, /* 471: pointer.func */
            	476, 0,
            0, 0, 0, /* 476: func */
            1, 8, 1, /* 479: pointer.struct.dh_method.1137 */
            	484, 0,
            0, 72, 9, /* 484: struct.dh_method.1137 */
            	41, 0,
            	505, 8,
            	513, 16,
            	521, 24,
            	505, 32,
            	505, 40,
            	33, 48,
            	41, 56,
            	234, 64,
            1, 8, 1, /* 505: pointer.func */
            	510, 0,
            0, 0, 0, /* 510: func */
            1, 8, 1, /* 513: pointer.func */
            	518, 0,
            0, 0, 0, /* 518: func */
            1, 8, 1, /* 521: pointer.func */
            	526, 0,
            0, 0, 0, /* 526: func */
            1, 8, 1, /* 529: pointer.struct.ecdh_method */
            	215, 0,
            1, 8, 1, /* 534: pointer.struct.store_method_st */
            	539, 0,
            0, 0, 0, /* 539: struct.store_method_st */
            1, 8, 1, /* 542: pointer.func */
            	138, 0,
            1, 8, 1, /* 547: pointer.struct.unnamed */
            	81, 0,
            1, 8, 1, /* 552: pointer.func */
            	557, 0,
            0, 0, 0, /* 557: func */
            1, 8, 1, /* 560: pointer.func */
            	70, 0,
            1, 8, 1, /* 565: pointer.struct.engine_st.1173 */
            	342, 0,
            0, 0, 0, /* 570: func */
            0, 0, 0, /* 573: func */
            1, 8, 1, /* 576: pointer.func */
            	570, 0,
            1, 8, 1, /* 581: pointer.struct.evp_cipher_ctx_st.2258 */
            	586, 0,
            0, 168, 15, /* 586: struct.evp_cipher_ctx_st.2258 */
            	619, 0,
            	565, 8,
            	33, 16,
            	33, 20,
            	685, 24,
            	685, 40,
            	720, 56,
            	33, 88,
            	41, 96,
            	33, 104,
            	653, 112,
            	41, 120,
            	33, 128,
            	33, 132,
            	720, 136,
            1, 8, 1, /* 619: pointer.struct.evp_cipher_st.2256 */
            	624, 0,
            0, 88, 13, /* 624: struct.evp_cipher_st.2256 */
            	33, 0,
            	33, 4,
            	33, 8,
            	33, 12,
            	653, 16,
            	656, 24,
            	661, 32,
            	669, 40,
            	33, 48,
            	677, 56,
            	677, 64,
            	576, 72,
            	41, 80,
            0, 8, 0, /* 653: long */
            1, 8, 1, /* 656: pointer.func */
            	573, 0,
            1, 8, 1, /* 661: pointer.func */
            	666, 0,
            0, 0, 0, /* 666: func */
            1, 8, 1, /* 669: pointer.func */
            	674, 0,
            0, 0, 0, /* 674: func */
            1, 8, 1, /* 677: pointer.func */
            	682, 0,
            0, 0, 0, /* 682: func */
            0, 16, 16, /* 685: array[16].char */
            	46, 0,
            	46, 1,
            	46, 2,
            	46, 3,
            	46, 4,
            	46, 5,
            	46, 6,
            	46, 7,
            	46, 8,
            	46, 9,
            	46, 10,
            	46, 11,
            	46, 12,
            	46, 13,
            	46, 14,
            	46, 15,
            0, 32, 32, /* 720: array[32].char */
            	46, 0,
            	46, 1,
            	46, 2,
            	46, 3,
            	46, 4,
            	46, 5,
            	46, 6,
            	46, 7,
            	46, 8,
            	46, 9,
            	46, 10,
            	46, 11,
            	46, 12,
            	46, 13,
            	46, 14,
            	46, 15,
            	46, 16,
            	46, 17,
            	46, 18,
            	46, 19,
            	46, 20,
            	46, 21,
            	46, 22,
            	46, 23,
            	46, 24,
            	46, 25,
            	46, 26,
            	46, 27,
            	46, 28,
            	46, 29,
            	46, 30,
            	46, 31,
        },
        .arg_entity_index = { 581, 619, 565, 41, 41, },
        .ret_entity_index = 33,
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
