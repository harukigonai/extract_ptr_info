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
    em[3] = 8884099; em[4] = 8; em[5] = 2; /* 3: pointer_to_array_of_pointers_to_stack */
    	em[6] = 10; em[7] = 0; 
    	em[8] = 13; em[9] = 20; 
    em[10] = 0; em[11] = 8; em[12] = 0; /* 10: pointer.void */
    em[13] = 0; em[14] = 4; em[15] = 0; /* 13: int */
    em[16] = 1; em[17] = 8; em[18] = 1; /* 16: pointer.struct.bio_st */
    	em[19] = 21; em[20] = 0; 
    em[21] = 0; em[22] = 112; em[23] = 7; /* 21: struct.bio_st */
    	em[24] = 38; em[25] = 0; 
    	em[26] = 87; em[27] = 8; 
    	em[28] = 90; em[29] = 16; 
    	em[30] = 10; em[31] = 48; 
    	em[32] = 16; em[33] = 56; 
    	em[34] = 16; em[35] = 64; 
    	em[36] = 95; em[37] = 96; 
    em[38] = 1; em[39] = 8; em[40] = 1; /* 38: pointer.struct.bio_method_st */
    	em[41] = 43; em[42] = 0; 
    em[43] = 0; em[44] = 80; em[45] = 9; /* 43: struct.bio_method_st */
    	em[46] = 64; em[47] = 8; 
    	em[48] = 69; em[49] = 16; 
    	em[50] = 72; em[51] = 24; 
    	em[52] = 75; em[53] = 32; 
    	em[54] = 72; em[55] = 40; 
    	em[56] = 78; em[57] = 48; 
    	em[58] = 81; em[59] = 56; 
    	em[60] = 81; em[61] = 64; 
    	em[62] = 84; em[63] = 72; 
    em[64] = 1; em[65] = 8; em[66] = 1; /* 64: pointer.char */
    	em[67] = 8884096; em[68] = 0; 
    em[69] = 8884097; em[70] = 8; em[71] = 0; /* 69: pointer.func */
    em[72] = 8884097; em[73] = 8; em[74] = 0; /* 72: pointer.func */
    em[75] = 8884097; em[76] = 8; em[77] = 0; /* 75: pointer.func */
    em[78] = 8884097; em[79] = 8; em[80] = 0; /* 78: pointer.func */
    em[81] = 8884097; em[82] = 8; em[83] = 0; /* 81: pointer.func */
    em[84] = 8884097; em[85] = 8; em[86] = 0; /* 84: pointer.func */
    em[87] = 8884097; em[88] = 8; em[89] = 0; /* 87: pointer.func */
    em[90] = 1; em[91] = 8; em[92] = 1; /* 90: pointer.char */
    	em[93] = 8884096; em[94] = 0; 
    em[95] = 0; em[96] = 32; em[97] = 2; /* 95: struct.crypto_ex_data_st_fake */
    	em[98] = 3; em[99] = 8; 
    	em[100] = 0; em[101] = 24; 
    em[102] = 0; em[103] = 1; em[104] = 0; /* 102: char */
    em[105] = 1; em[106] = 8; em[107] = 1; /* 105: pointer.struct.bio_st */
    	em[108] = 21; em[109] = 0; 
    args_addr->arg_entity_index[0] = 105;
    args_addr->arg_entity_index[1] = 10;
    args_addr->arg_entity_index[2] = 13;
    args_addr->ret_entity_index = 13;
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

