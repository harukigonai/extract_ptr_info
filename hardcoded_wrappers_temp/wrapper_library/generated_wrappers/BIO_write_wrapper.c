#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
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

int bb_BIO_write(BIO * arg_a,const void * arg_b,int arg_c);

int BIO_write(BIO * arg_a,const void * arg_b,int arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("BIO_write called %lu\n", in_lib);
    if (!in_lib)
        return bb_BIO_write(arg_a,arg_b,arg_c);
    else {
        int (*orig_BIO_write)(BIO *,const void *,int);
        orig_BIO_write = dlsym(RTLD_NEXT, "BIO_write");
        return orig_BIO_write(arg_a,arg_b,arg_c);
    }
}

int bb_BIO_write(BIO * arg_a,const void * arg_b,int arg_c) 
{
    int ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 8884097; em[1] = 8; em[2] = 0; /* 0: pointer.func */
    em[3] = 1; em[4] = 8; em[5] = 1; /* 3: pointer.struct.bio_st */
    	em[6] = 8; em[7] = 0; 
    em[8] = 0; em[9] = 112; em[10] = 7; /* 8: struct.bio_st */
    	em[11] = 25; em[12] = 0; 
    	em[13] = 74; em[14] = 8; 
    	em[15] = 77; em[16] = 16; 
    	em[17] = 82; em[18] = 48; 
    	em[19] = 3; em[20] = 56; 
    	em[21] = 3; em[22] = 64; 
    	em[23] = 85; em[24] = 96; 
    em[25] = 1; em[26] = 8; em[27] = 1; /* 25: pointer.struct.bio_method_st */
    	em[28] = 30; em[29] = 0; 
    em[30] = 0; em[31] = 80; em[32] = 9; /* 30: struct.bio_method_st */
    	em[33] = 51; em[34] = 8; 
    	em[35] = 56; em[36] = 16; 
    	em[37] = 59; em[38] = 24; 
    	em[39] = 62; em[40] = 32; 
    	em[41] = 59; em[42] = 40; 
    	em[43] = 65; em[44] = 48; 
    	em[45] = 68; em[46] = 56; 
    	em[47] = 68; em[48] = 64; 
    	em[49] = 71; em[50] = 72; 
    em[51] = 1; em[52] = 8; em[53] = 1; /* 51: pointer.char */
    	em[54] = 8884096; em[55] = 0; 
    em[56] = 8884097; em[57] = 8; em[58] = 0; /* 56: pointer.func */
    em[59] = 8884097; em[60] = 8; em[61] = 0; /* 59: pointer.func */
    em[62] = 8884097; em[63] = 8; em[64] = 0; /* 62: pointer.func */
    em[65] = 8884097; em[66] = 8; em[67] = 0; /* 65: pointer.func */
    em[68] = 8884097; em[69] = 8; em[70] = 0; /* 68: pointer.func */
    em[71] = 8884097; em[72] = 8; em[73] = 0; /* 71: pointer.func */
    em[74] = 8884097; em[75] = 8; em[76] = 0; /* 74: pointer.func */
    em[77] = 1; em[78] = 8; em[79] = 1; /* 77: pointer.char */
    	em[80] = 8884096; em[81] = 0; 
    em[82] = 0; em[83] = 8; em[84] = 0; /* 82: pointer.void */
    em[85] = 0; em[86] = 32; em[87] = 2; /* 85: struct.crypto_ex_data_st_fake */
    	em[88] = 92; em[89] = 8; 
    	em[90] = 0; em[91] = 24; 
    em[92] = 8884099; em[93] = 8; em[94] = 2; /* 92: pointer_to_array_of_pointers_to_stack */
    	em[95] = 82; em[96] = 0; 
    	em[97] = 99; em[98] = 20; 
    em[99] = 0; em[100] = 4; em[101] = 0; /* 99: int */
    em[102] = 0; em[103] = 1; em[104] = 0; /* 102: char */
    em[105] = 1; em[106] = 8; em[107] = 1; /* 105: pointer.struct.bio_st */
    	em[108] = 8; em[109] = 0; 
    args_addr->arg_entity_index[0] = 105;
    args_addr->arg_entity_index[1] = 82;
    args_addr->arg_entity_index[2] = 99;
    args_addr->ret_entity_index = 99;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    BIO * new_arg_a = *((BIO * *)new_args->args[0]);

    const void * new_arg_b = *((const void * *)new_args->args[1]);

    int new_arg_c = *((int *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_BIO_write)(BIO *,const void *,int);
    orig_BIO_write = dlsym(RTLD_NEXT, "BIO_write");
    *new_ret_ptr = (*orig_BIO_write)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    free(args_addr);

    return ret;
}

