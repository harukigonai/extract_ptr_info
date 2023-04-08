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

int bb_EVP_EncryptInit_ex(EVP_CIPHER_CTX * arg_a,const EVP_CIPHER * arg_b,ENGINE * arg_c,const unsigned char * arg_d,const unsigned char * arg_e);

int EVP_EncryptInit_ex(EVP_CIPHER_CTX * arg_a,const EVP_CIPHER * arg_b,ENGINE * arg_c,const unsigned char * arg_d,const unsigned char * arg_e) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_EncryptInit_ex called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_EncryptInit_ex(arg_a,arg_b,arg_c,arg_d,arg_e);
    else {
        int (*orig_EVP_EncryptInit_ex)(EVP_CIPHER_CTX *,const EVP_CIPHER *,ENGINE *,const unsigned char *,const unsigned char *);
        orig_EVP_EncryptInit_ex = dlsym(RTLD_NEXT, "EVP_EncryptInit_ex");
        return orig_EVP_EncryptInit_ex(arg_a,arg_b,arg_c,arg_d,arg_e);
    }
}

int bb_EVP_EncryptInit_ex(EVP_CIPHER_CTX * arg_a,const EVP_CIPHER * arg_b,ENGINE * arg_c,const unsigned char * arg_d,const unsigned char * arg_e) 
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
    em[16] = 1; em[17] = 8; em[18] = 1; /* 16: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[19] = 21; em[20] = 0; 
    em[21] = 0; em[22] = 32; em[23] = 2; /* 21: struct.ENGINE_CMD_DEFN_st */
    	em[24] = 28; em[25] = 8; 
    	em[26] = 28; em[27] = 16; 
    em[28] = 1; em[29] = 8; em[30] = 1; /* 28: pointer.char */
    	em[31] = 8884096; em[32] = 0; 
    em[33] = 8884097; em[34] = 8; em[35] = 0; /* 33: pointer.func */
    em[36] = 8884097; em[37] = 8; em[38] = 0; /* 36: pointer.func */
    em[39] = 8884097; em[40] = 8; em[41] = 0; /* 39: pointer.func */
    em[42] = 8884097; em[43] = 8; em[44] = 0; /* 42: pointer.func */
    em[45] = 8884097; em[46] = 8; em[47] = 0; /* 45: pointer.func */
    em[48] = 8884097; em[49] = 8; em[50] = 0; /* 48: pointer.func */
    em[51] = 1; em[52] = 8; em[53] = 1; /* 51: pointer.struct.dsa_method */
    	em[54] = 56; em[55] = 0; 
    em[56] = 0; em[57] = 96; em[58] = 11; /* 56: struct.dsa_method */
    	em[59] = 28; em[60] = 0; 
    	em[61] = 81; em[62] = 8; 
    	em[63] = 84; em[64] = 16; 
    	em[65] = 87; em[66] = 24; 
    	em[67] = 90; em[68] = 32; 
    	em[69] = 93; em[70] = 40; 
    	em[71] = 96; em[72] = 48; 
    	em[73] = 96; em[74] = 56; 
    	em[75] = 99; em[76] = 72; 
    	em[77] = 104; em[78] = 80; 
    	em[79] = 96; em[80] = 88; 
    em[81] = 8884097; em[82] = 8; em[83] = 0; /* 81: pointer.func */
    em[84] = 8884097; em[85] = 8; em[86] = 0; /* 84: pointer.func */
    em[87] = 8884097; em[88] = 8; em[89] = 0; /* 87: pointer.func */
    em[90] = 8884097; em[91] = 8; em[92] = 0; /* 90: pointer.func */
    em[93] = 8884097; em[94] = 8; em[95] = 0; /* 93: pointer.func */
    em[96] = 8884097; em[97] = 8; em[98] = 0; /* 96: pointer.func */
    em[99] = 1; em[100] = 8; em[101] = 1; /* 99: pointer.char */
    	em[102] = 8884096; em[103] = 0; 
    em[104] = 8884097; em[105] = 8; em[106] = 0; /* 104: pointer.func */
    em[107] = 8884097; em[108] = 8; em[109] = 0; /* 107: pointer.func */
    em[110] = 8884097; em[111] = 8; em[112] = 0; /* 110: pointer.func */
    em[113] = 1; em[114] = 8; em[115] = 1; /* 113: pointer.struct.engine_st */
    	em[116] = 118; em[117] = 0; 
    em[118] = 0; em[119] = 216; em[120] = 24; /* 118: struct.engine_st */
    	em[121] = 28; em[122] = 0; 
    	em[123] = 28; em[124] = 8; 
    	em[125] = 169; em[126] = 16; 
    	em[127] = 51; em[128] = 24; 
    	em[129] = 218; em[130] = 32; 
    	em[131] = 254; em[132] = 40; 
    	em[133] = 271; em[134] = 48; 
    	em[135] = 298; em[136] = 56; 
    	em[137] = 333; em[138] = 64; 
    	em[139] = 341; em[140] = 72; 
    	em[141] = 344; em[142] = 80; 
    	em[143] = 48; em[144] = 88; 
    	em[145] = 45; em[146] = 96; 
    	em[147] = 42; em[148] = 104; 
    	em[149] = 42; em[150] = 112; 
    	em[151] = 42; em[152] = 120; 
    	em[153] = 39; em[154] = 128; 
    	em[155] = 36; em[156] = 136; 
    	em[157] = 36; em[158] = 144; 
    	em[159] = 33; em[160] = 152; 
    	em[161] = 16; em[162] = 160; 
    	em[163] = 347; em[164] = 184; 
    	em[165] = 354; em[166] = 200; 
    	em[167] = 354; em[168] = 208; 
    em[169] = 1; em[170] = 8; em[171] = 1; /* 169: pointer.struct.rsa_meth_st */
    	em[172] = 174; em[173] = 0; 
    em[174] = 0; em[175] = 112; em[176] = 13; /* 174: struct.rsa_meth_st */
    	em[177] = 28; em[178] = 0; 
    	em[179] = 203; em[180] = 8; 
    	em[181] = 203; em[182] = 16; 
    	em[183] = 203; em[184] = 24; 
    	em[185] = 203; em[186] = 32; 
    	em[187] = 206; em[188] = 40; 
    	em[189] = 107; em[190] = 48; 
    	em[191] = 209; em[192] = 56; 
    	em[193] = 209; em[194] = 64; 
    	em[195] = 99; em[196] = 80; 
    	em[197] = 212; em[198] = 88; 
    	em[199] = 110; em[200] = 96; 
    	em[201] = 215; em[202] = 104; 
    em[203] = 8884097; em[204] = 8; em[205] = 0; /* 203: pointer.func */
    em[206] = 8884097; em[207] = 8; em[208] = 0; /* 206: pointer.func */
    em[209] = 8884097; em[210] = 8; em[211] = 0; /* 209: pointer.func */
    em[212] = 8884097; em[213] = 8; em[214] = 0; /* 212: pointer.func */
    em[215] = 8884097; em[216] = 8; em[217] = 0; /* 215: pointer.func */
    em[218] = 1; em[219] = 8; em[220] = 1; /* 218: pointer.struct.dh_method */
    	em[221] = 223; em[222] = 0; 
    em[223] = 0; em[224] = 72; em[225] = 8; /* 223: struct.dh_method */
    	em[226] = 28; em[227] = 0; 
    	em[228] = 242; em[229] = 8; 
    	em[230] = 245; em[231] = 16; 
    	em[232] = 248; em[233] = 24; 
    	em[234] = 242; em[235] = 32; 
    	em[236] = 242; em[237] = 40; 
    	em[238] = 99; em[239] = 56; 
    	em[240] = 251; em[241] = 64; 
    em[242] = 8884097; em[243] = 8; em[244] = 0; /* 242: pointer.func */
    em[245] = 8884097; em[246] = 8; em[247] = 0; /* 245: pointer.func */
    em[248] = 8884097; em[249] = 8; em[250] = 0; /* 248: pointer.func */
    em[251] = 8884097; em[252] = 8; em[253] = 0; /* 251: pointer.func */
    em[254] = 1; em[255] = 8; em[256] = 1; /* 254: pointer.struct.ecdh_method */
    	em[257] = 259; em[258] = 0; 
    em[259] = 0; em[260] = 32; em[261] = 3; /* 259: struct.ecdh_method */
    	em[262] = 28; em[263] = 0; 
    	em[264] = 268; em[265] = 8; 
    	em[266] = 99; em[267] = 24; 
    em[268] = 8884097; em[269] = 8; em[270] = 0; /* 268: pointer.func */
    em[271] = 1; em[272] = 8; em[273] = 1; /* 271: pointer.struct.ecdsa_method */
    	em[274] = 276; em[275] = 0; 
    em[276] = 0; em[277] = 48; em[278] = 5; /* 276: struct.ecdsa_method */
    	em[279] = 28; em[280] = 0; 
    	em[281] = 289; em[282] = 8; 
    	em[283] = 292; em[284] = 16; 
    	em[285] = 295; em[286] = 24; 
    	em[287] = 99; em[288] = 40; 
    em[289] = 8884097; em[290] = 8; em[291] = 0; /* 289: pointer.func */
    em[292] = 8884097; em[293] = 8; em[294] = 0; /* 292: pointer.func */
    em[295] = 8884097; em[296] = 8; em[297] = 0; /* 295: pointer.func */
    em[298] = 1; em[299] = 8; em[300] = 1; /* 298: pointer.struct.rand_meth_st */
    	em[301] = 303; em[302] = 0; 
    em[303] = 0; em[304] = 48; em[305] = 6; /* 303: struct.rand_meth_st */
    	em[306] = 318; em[307] = 0; 
    	em[308] = 321; em[309] = 8; 
    	em[310] = 324; em[311] = 16; 
    	em[312] = 327; em[313] = 24; 
    	em[314] = 321; em[315] = 32; 
    	em[316] = 330; em[317] = 40; 
    em[318] = 8884097; em[319] = 8; em[320] = 0; /* 318: pointer.func */
    em[321] = 8884097; em[322] = 8; em[323] = 0; /* 321: pointer.func */
    em[324] = 8884097; em[325] = 8; em[326] = 0; /* 324: pointer.func */
    em[327] = 8884097; em[328] = 8; em[329] = 0; /* 327: pointer.func */
    em[330] = 8884097; em[331] = 8; em[332] = 0; /* 330: pointer.func */
    em[333] = 1; em[334] = 8; em[335] = 1; /* 333: pointer.struct.store_method_st */
    	em[336] = 338; em[337] = 0; 
    em[338] = 0; em[339] = 0; em[340] = 0; /* 338: struct.store_method_st */
    em[341] = 8884097; em[342] = 8; em[343] = 0; /* 341: pointer.func */
    em[344] = 8884097; em[345] = 8; em[346] = 0; /* 344: pointer.func */
    em[347] = 0; em[348] = 32; em[349] = 2; /* 347: struct.crypto_ex_data_st_fake */
    	em[350] = 3; em[351] = 8; 
    	em[352] = 0; em[353] = 24; 
    em[354] = 1; em[355] = 8; em[356] = 1; /* 354: pointer.struct.engine_st */
    	em[357] = 118; em[358] = 0; 
    em[359] = 0; em[360] = 1; em[361] = 0; /* 359: unsigned char */
    em[362] = 1; em[363] = 8; em[364] = 1; /* 362: pointer.struct.evp_cipher_st */
    	em[365] = 367; em[366] = 0; 
    em[367] = 0; em[368] = 88; em[369] = 7; /* 367: struct.evp_cipher_st */
    	em[370] = 384; em[371] = 24; 
    	em[372] = 387; em[373] = 32; 
    	em[374] = 390; em[375] = 40; 
    	em[376] = 393; em[377] = 56; 
    	em[378] = 393; em[379] = 64; 
    	em[380] = 396; em[381] = 72; 
    	em[382] = 10; em[383] = 80; 
    em[384] = 8884097; em[385] = 8; em[386] = 0; /* 384: pointer.func */
    em[387] = 8884097; em[388] = 8; em[389] = 0; /* 387: pointer.func */
    em[390] = 8884097; em[391] = 8; em[392] = 0; /* 390: pointer.func */
    em[393] = 8884097; em[394] = 8; em[395] = 0; /* 393: pointer.func */
    em[396] = 8884097; em[397] = 8; em[398] = 0; /* 396: pointer.func */
    em[399] = 0; em[400] = 1; em[401] = 0; /* 399: char */
    em[402] = 1; em[403] = 8; em[404] = 1; /* 402: pointer.unsigned char */
    	em[405] = 359; em[406] = 0; 
    em[407] = 1; em[408] = 8; em[409] = 1; /* 407: pointer.struct.evp_cipher_ctx_st */
    	em[410] = 412; em[411] = 0; 
    em[412] = 0; em[413] = 168; em[414] = 4; /* 412: struct.evp_cipher_ctx_st */
    	em[415] = 362; em[416] = 0; 
    	em[417] = 113; em[418] = 8; 
    	em[419] = 10; em[420] = 96; 
    	em[421] = 10; em[422] = 120; 
    args_addr->arg_entity_index[0] = 407;
    args_addr->arg_entity_index[1] = 362;
    args_addr->arg_entity_index[2] = 113;
    args_addr->arg_entity_index[3] = 402;
    args_addr->arg_entity_index[4] = 402;
    args_addr->ret_entity_index = 13;
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

    free(args_addr);

    return ret;
}

