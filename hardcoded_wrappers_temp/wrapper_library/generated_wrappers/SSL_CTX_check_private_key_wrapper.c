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

int bb_SSL_CTX_check_private_key(const SSL_CTX * arg_a);

int SSL_CTX_check_private_key(const SSL_CTX * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_check_private_key called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_CTX_check_private_key(arg_a);
    else {
        int (*orig_SSL_CTX_check_private_key)(const SSL_CTX *);
        orig_SSL_CTX_check_private_key = dlsym(RTLD_NEXT, "SSL_CTX_check_private_key");
        return orig_SSL_CTX_check_private_key(arg_a);
    }
}

int bb_SSL_CTX_check_private_key(const SSL_CTX * arg_a) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 8, 1, /* 0: struct.ssl3_buf_freelist_entry_st */
            	5, 0,
            1, 8, 1, /* 5: pointer.struct.ssl3_buf_freelist_entry_st */
            	0, 0,
            1, 8, 1, /* 10: pointer.struct.ssl3_buf_freelist_st */
            	15, 0,
            0, 24, 1, /* 15: struct.ssl3_buf_freelist_st */
            	5, 16,
            0, 0, 0, /* 20: func */
            4097, 94416284673716, 94396347198816, /* 23: pointer.func */
            	4097, 0,
            	240, 0,
            	16, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	94396344434800, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	94416284674260, 94396347197568,
            	0, 296,
            	5, 63,
            	0, 513,
            	48, 612,
            	64, 644,
            	80, 726,
            	96, 1,
            	8, 1,
            	68, 0,
            	0, 24,
            	3, 77,
            	0, 265,
            	8, 505,
            	16, 1,
            	8, 1,
            	82, 0,
            	0, 184,
            	12, 109,
            	0, 154,
            	8, 139,
            	16, 149,
            	32, 425,
            	40, 139,
            	104, 435,
            	112, 449,
            	120, 209,
            	128, 209,
            	136, 475,
            	144, 487,
            	176, 1,
            	8, 1,
            	114, 0,
            	0, 104,
            	11, 139,
            	0, 139,
            	8, 154,
            	16, 195,
            	24, 239,
            	32, 195,
            	40, 251,
            	48, 139,
            	56, 139,
            	64, 209,
            	72, 430,
            	80, 1,
            	8, 1,
            	144, 0,
            	0, 24,
            	1, 149,
            	8, 1,
            	8, 1,
            	4096, 0,
            	1, 8,
            	1, 159,
            	0, 0,
            	16, 2,
            	166, 0,
            	180, 8,
            	1, 8,
            	1, 171,
            	0, 0,
            	40, 3,
            	149, 0,
            	149, 8,
            	149, 24,
            	1, 8,
            	1, 185,
            	0, 0,
            	16, 1,
            	190, 8,
            	0, 8,
            	1, 149,
            	0, 1,
            	8, 1,
            	200, 0,
            	0, 40,
            	3, 209,
            	0, 229,
            	16, 149,
            	24, 1,
            	8, 1,
            	214, 0,
            	0, 32,
            	1, 219,
            	0, 0,
            	32, 1,
            	224, 8,
            	1, 8,
            	1, 149,
            	0, 1,
            	8, 1,
            	234, 0,
            	0, 24,
            	1, 149,
            	8, 1,
            	8, 1,
            	244, 0,
            	0, 16,
            	2, 139,
            	0, 139,
            	8, 1,
            	8, 1,
            	256, 0,
            	0, 24,
            	3, 154,
            	0, 139,
            	8, 265,
            	16, 1,
            	8, 1,
            	270, 0,
            	0, 56,
            	4, 281,
            	16, 303,
            	24, 190,
            	32, 209,
            	48, 1,
            	8, 1,
            	286, 0,
            	0, 208,
            	3, 149,
            	16, 149,
            	24, 295,
            	32, 1,
            	8, 1,
            	300, 0,
            	0, 0,
            	0, 1,
            	8, 1,
            	308, 0,
            	0, 216,
            	13, 149,
            	0, 149,
            	8, 337,
            	16, 349,
            	24, 361,
            	32, 373,
            	40, 385,
            	48, 397,
            	56, 405,
            	64, 413,
            	160, 425,
            	184, 303,
            	200, 303,
            	208, 1,
            	8, 1,
            	342, 0,
            	0, 112,
            	2, 149,
            	0, 149,
            	80, 1,
            	8, 1,
            	354, 0,
            	0, 96,
            	2, 149,
            	0, 149,
            	72, 1,
            	8, 1,
            	366, 0,
            	0, 72,
            	2, 149,
            	0, 149,
            	56, 1,
            	8, 1,
            	378, 0,
            	0, 32,
            	2, 149,
            	0, 149,
            	24, 1,
            	8, 1,
            	390, 0,
            	0, 48,
            	2, 149,
            	0, 149,
            	40, 1,
            	8, 1,
            	402, 0,
            	0, 48,
            	0, 1,
            	8, 1,
            	410, 0,
            	0, 0,
            	0, 1,
            	8, 1,
            	418, 0,
            	0, 32,
            	2, 149,
            	8, 149,
            	16, 0,
            	16, 1,
            	209, 0,
            	0, 24,
            	1, 149,
            	0, 1,
            	8, 1,
            	440, 0,
            	0, 24,
            	3, 139,
            	0, 209,
            	8, 139,
            	16, 1,
            	8, 1,
            	454, 0,
            	0, 40,
            	2, 461,
            	0, 209,
            	8, 1,
            	8, 1,
            	466, 0,
            	0, 32,
            	3, 166,
            	8, 209,
            	16, 209,
            	24, 1,
            	8, 1,
            	480, 0,
            	0, 16,
            	2, 209,
            	0, 209,
            	8, 1,
            	8, 1,
            	492, 0,
            	0, 40,
            	5, 209,
            	0, 209,
            	8, 139,
            	16, 139,
            	24, 209,
            	32, 1,
            	8, 1,
            	510, 0,
            	0, 120,
            	0, 1,
            	8, 1,
            	518, 0,
            	0, 168,
            	17, 337,
            	16, 303,
            	24, 555,
            	32, 555,
            	40, 555,
            	48, 555,
            	56, 555,
            	64, 555,
            	72, 555,
            	80, 555,
            	88, 425,
            	96, 573,
            	120, 573,
            	128, 573,
            	136, 149,
            	144, 587,
            	152, 587,
            	160, 1,
            	8, 1,
            	560, 0,
            	0, 24,
            	1, 565,
            	0, 1,
            	8, 1,
            	570, 0,
            	0, 4,
            	0, 1,
            	8, 1,
            	578, 0,
            	0, 96,
            	3, 560,
            	8, 560,
            	32, 560,
            	56, 1,
            	8, 1,
            	592, 0,
            	0, 88,
            	6, 555,
            	0, 555,
            	8, 555,
            	16, 555,
            	24, 607,
            	40, 573,
            	72, 0,
            	16, 1,
            	149, 0,
            	1, 8,
            	1, 617,
            	0, 0,
            	144, 12,
            	555, 8,
            	555, 16,
            	555, 32,
            	555, 40,
            	573, 56,
            	555, 64,
            	555, 72,
            	149, 80,
            	555, 96,
            	425, 112,
            	361, 128,
            	303, 136,
            	1, 8,
            	1, 649,
            	0, 0,
            	56, 4,
            	660, 8,
            	698, 16,
            	555, 24,
            	714, 48,
            	1, 8,
            	1, 665,
            	0, 0,
            	232, 11,
            	690, 0,
            	698, 8,
            	560, 16,
            	560, 40,
            	149, 80,
            	714, 96,
            	560, 104,
            	560, 152,
            	560, 176,
            	149, 208,
            	149, 216,
            	1, 8,
            	1, 695,
            	0, 0,
            	304, 0,
            	1, 8,
            	1, 703,
            	0, 0,
            	88, 4,
            	690, 0,
            	560, 8,
            	560, 32,
            	560, 56,
            	1, 8,
            	1, 719,
            	0, 0,
            	40, 2,
            	714, 0,
            	149, 8,
            	0, 192,
            	8, 68,
            	0, 68,
            	24, 68,
            	48, 68,
            	72, 68,
            	96, 68,
            	120, 68,
            	144, 68,
            	168, 4097,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 44,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 0,
            	88, 1,
            	149, 8,
            	1, 8,
            	1, 781,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	1, 8,
            	1, 50,
            	0, 4097,
            	0, 0,
            	0, 8,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 24,
            	0, 4097,
            	0, 0,
            	0, 248,
            	6, 209,
            	0, 63,
            	16, 726,
            	24, 513,
            	216, 612,
            	224, 644,
            	232, 0,
            	32, 0,
            	4097, 0,
            	0, 1,
            	8, 1,
            	984, 0,
            	0, 4,
            	0, 0,
            	48, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	0, 8,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	8, 0,
            	0, 56,
            	2, 149,
            	0, 209,
            	48, 0,
            	144, 4,
            	209, 8,
            	209, 16,
            	1050, 24,
            	425, 120,
            	1, 8,
            	1, 1032,
            	0, 1,
            	8, 1,
            	1039, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	1, 8,
            	1, 1119,
            	0, 0,
            	736, 30,
            	1182, 0,
            	209, 8,
            	209, 16,
            	1055, 24,
            	979, 32,
            	1208, 48,
            	1208, 56,
            	149, 160,
            	149, 176,
            	425, 208,
            	505, 224,
            	505, 232,
            	505, 240,
            	209, 248,
            	209, 256,
            	209, 272,
            	878, 304,
            	149, 328,
            	1050, 392,
            	303, 408,
            	149, 424,
            	149, 496,
            	149, 512,
            	149, 520,
            	10, 552,
            	10, 560,
            	1249, 568,
            	149, 704,
            	149, 720,
            	209, 728,
            	1, 8,
            	1, 1187,
            	0, 0,
            	232, 1,
            	1192, 200,
            	1, 8,
            	1, 1197,
            	0, 0,
            	112, 4,
            	295, 0,
            	295, 32,
            	149, 64,
            	149, 80,
            	1, 8,
            	1, 1213,
            	0, 0,
            	352, 14,
            	149, 144,
            	149, 152,
            	1244, 168,
            	77, 176,
            	786, 224,
            	209, 240,
            	425, 248,
            	1208, 264,
            	1208, 272,
            	149, 280,
            	149, 296,
            	149, 312,
            	149, 320,
            	149, 344,
            	1, 8,
            	1, 958,
            	0, 0,
            	128, 11,
            	149, 0,
            	149, 32,
            	555, 40,
            	555, 48,
            	555, 56,
            	555, 64,
            	555, 72,
            	555, 80,
            	555, 88,
            	555, 96,
            	149, 104,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 1,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	20, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	0, 20,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
        },
        .arg_entity_index = { 1114, },
        .ret_entity_index = 570,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL_CTX * new_arg_a = *((const SSL_CTX * *)new_args->args[0]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_SSL_CTX_check_private_key)(const SSL_CTX *);
    orig_SSL_CTX_check_private_key = dlsym(RTLD_NEXT, "SSL_CTX_check_private_key");
    *new_ret_ptr = (*orig_SSL_CTX_check_private_key)(new_arg_a);

    syscall(889);

    return ret;
}

