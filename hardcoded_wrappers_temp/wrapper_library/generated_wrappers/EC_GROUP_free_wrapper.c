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

void bb_EC_GROUP_free(EC_GROUP * arg_a);

void EC_GROUP_free(EC_GROUP * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EC_GROUP_free called %lu\n", in_lib);
    if (!in_lib)
        bb_EC_GROUP_free(arg_a);
    else {
        void (*orig_EC_GROUP_free)(EC_GROUP *);
        orig_EC_GROUP_free = dlsym(RTLD_NEXT, "EC_GROUP_free");
        orig_EC_GROUP_free(arg_a);
    }
}

void bb_EC_GROUP_free(EC_GROUP * arg_a) 
{
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            8884097, 8, 0, /* 0: pointer.func */
            1, 8, 1, /* 3: pointer.struct.ec_extra_data_st */
            	8, 0,
            0, 40, 5, /* 8: struct.ec_extra_data_st */
            	3, 0,
            	21, 8,
            	24, 16,
            	27, 24,
            	27, 32,
            0, 8, 0, /* 21: pointer.void */
            8884097, 8, 0, /* 24: pointer.func */
            8884097, 8, 0, /* 27: pointer.func */
            1, 8, 1, /* 30: pointer.unsigned char */
            	35, 0,
            0, 1, 0, /* 35: unsigned char */
            0, 24, 1, /* 38: struct.bignum_st */
            	43, 0,
            1, 8, 1, /* 43: pointer.unsigned int */
            	48, 0,
            0, 4, 0, /* 48: unsigned int */
            8884097, 8, 0, /* 51: pointer.func */
            8884097, 8, 0, /* 54: pointer.func */
            8884097, 8, 0, /* 57: pointer.func */
            8884097, 8, 0, /* 60: pointer.func */
            8884097, 8, 0, /* 63: pointer.func */
            8884097, 8, 0, /* 66: pointer.func */
            8884097, 8, 0, /* 69: pointer.func */
            8884097, 8, 0, /* 72: pointer.func */
            0, 304, 37, /* 75: struct.ec_method_st */
            	152, 8,
            	155, 16,
            	155, 24,
            	158, 32,
            	161, 40,
            	164, 48,
            	167, 56,
            	170, 64,
            	173, 72,
            	176, 80,
            	176, 88,
            	179, 96,
            	182, 104,
            	185, 112,
            	188, 120,
            	191, 128,
            	194, 136,
            	197, 144,
            	200, 152,
            	203, 160,
            	206, 168,
            	209, 176,
            	212, 184,
            	72, 192,
            	215, 200,
            	218, 208,
            	212, 216,
            	66, 224,
            	221, 232,
            	224, 240,
            	167, 248,
            	227, 256,
            	230, 264,
            	227, 272,
            	230, 280,
            	230, 288,
            	233, 296,
            8884097, 8, 0, /* 152: pointer.func */
            8884097, 8, 0, /* 155: pointer.func */
            8884097, 8, 0, /* 158: pointer.func */
            8884097, 8, 0, /* 161: pointer.func */
            8884097, 8, 0, /* 164: pointer.func */
            8884097, 8, 0, /* 167: pointer.func */
            8884097, 8, 0, /* 170: pointer.func */
            8884097, 8, 0, /* 173: pointer.func */
            8884097, 8, 0, /* 176: pointer.func */
            8884097, 8, 0, /* 179: pointer.func */
            8884097, 8, 0, /* 182: pointer.func */
            8884097, 8, 0, /* 185: pointer.func */
            8884097, 8, 0, /* 188: pointer.func */
            8884097, 8, 0, /* 191: pointer.func */
            8884097, 8, 0, /* 194: pointer.func */
            8884097, 8, 0, /* 197: pointer.func */
            8884097, 8, 0, /* 200: pointer.func */
            8884097, 8, 0, /* 203: pointer.func */
            8884097, 8, 0, /* 206: pointer.func */
            8884097, 8, 0, /* 209: pointer.func */
            8884097, 8, 0, /* 212: pointer.func */
            8884097, 8, 0, /* 215: pointer.func */
            8884097, 8, 0, /* 218: pointer.func */
            8884097, 8, 0, /* 221: pointer.func */
            8884097, 8, 0, /* 224: pointer.func */
            8884097, 8, 0, /* 227: pointer.func */
            8884097, 8, 0, /* 230: pointer.func */
            8884097, 8, 0, /* 233: pointer.func */
            8884097, 8, 0, /* 236: pointer.func */
            1, 8, 1, /* 239: pointer.struct.ec_method_st */
            	75, 0,
            8884097, 8, 0, /* 244: pointer.func */
            8884097, 8, 0, /* 247: pointer.func */
            1, 8, 1, /* 250: pointer.struct.ec_extra_data_st */
            	8, 0,
            8884097, 8, 0, /* 255: pointer.func */
            1, 8, 1, /* 258: pointer.struct.ec_group_st */
            	263, 0,
            0, 232, 12, /* 263: struct.ec_group_st */
            	239, 0,
            	290, 8,
            	38, 16,
            	38, 40,
            	30, 80,
            	250, 96,
            	38, 104,
            	38, 152,
            	38, 176,
            	21, 208,
            	21, 216,
            	0, 224,
            1, 8, 1, /* 290: pointer.struct.ec_point_st */
            	295, 0,
            0, 88, 4, /* 295: struct.ec_point_st */
            	306, 0,
            	448, 8,
            	448, 32,
            	448, 56,
            1, 8, 1, /* 306: pointer.struct.ec_method_st */
            	311, 0,
            0, 304, 37, /* 311: struct.ec_method_st */
            	388, 8,
            	391, 16,
            	391, 24,
            	394, 32,
            	397, 40,
            	400, 48,
            	403, 56,
            	406, 64,
            	409, 72,
            	412, 80,
            	412, 88,
            	415, 96,
            	418, 104,
            	69, 112,
            	421, 120,
            	244, 128,
            	424, 136,
            	427, 144,
            	255, 152,
            	430, 160,
            	433, 168,
            	436, 176,
            	439, 184,
            	442, 192,
            	63, 200,
            	247, 208,
            	439, 216,
            	60, 224,
            	57, 232,
            	236, 240,
            	403, 248,
            	54, 256,
            	445, 264,
            	54, 272,
            	445, 280,
            	445, 288,
            	51, 296,
            8884097, 8, 0, /* 388: pointer.func */
            8884097, 8, 0, /* 391: pointer.func */
            8884097, 8, 0, /* 394: pointer.func */
            8884097, 8, 0, /* 397: pointer.func */
            8884097, 8, 0, /* 400: pointer.func */
            8884097, 8, 0, /* 403: pointer.func */
            8884097, 8, 0, /* 406: pointer.func */
            8884097, 8, 0, /* 409: pointer.func */
            8884097, 8, 0, /* 412: pointer.func */
            8884097, 8, 0, /* 415: pointer.func */
            8884097, 8, 0, /* 418: pointer.func */
            8884097, 8, 0, /* 421: pointer.func */
            8884097, 8, 0, /* 424: pointer.func */
            8884097, 8, 0, /* 427: pointer.func */
            8884097, 8, 0, /* 430: pointer.func */
            8884097, 8, 0, /* 433: pointer.func */
            8884097, 8, 0, /* 436: pointer.func */
            8884097, 8, 0, /* 439: pointer.func */
            8884097, 8, 0, /* 442: pointer.func */
            8884097, 8, 0, /* 445: pointer.func */
            0, 24, 1, /* 448: struct.bignum_st */
            	43, 0,
        },
        .arg_entity_index = { 258, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EC_GROUP * new_arg_a = *((EC_GROUP * *)new_args->args[0]);

    void (*orig_EC_GROUP_free)(EC_GROUP *);
    orig_EC_GROUP_free = dlsym(RTLD_NEXT, "EC_GROUP_free");
    (*orig_EC_GROUP_free)(new_arg_a);

    syscall(889);

}

