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
    em[0] = 1; em[1] = 8; em[2] = 1; /* 0: pointer.struct.engine_st */
    	em[3] = 5; em[4] = 0; 
    em[5] = 0; em[6] = 216; em[7] = 24; /* 5: struct.engine_st */
    	em[8] = 56; em[9] = 0; 
    	em[10] = 56; em[11] = 8; 
    	em[12] = 61; em[13] = 16; 
    	em[14] = 121; em[15] = 24; 
    	em[16] = 172; em[17] = 32; 
    	em[18] = 208; em[19] = 40; 
    	em[20] = 225; em[21] = 48; 
    	em[22] = 252; em[23] = 56; 
    	em[24] = 287; em[25] = 64; 
    	em[26] = 295; em[27] = 72; 
    	em[28] = 298; em[29] = 80; 
    	em[30] = 301; em[31] = 88; 
    	em[32] = 304; em[33] = 96; 
    	em[34] = 307; em[35] = 104; 
    	em[36] = 307; em[37] = 112; 
    	em[38] = 307; em[39] = 120; 
    	em[40] = 310; em[41] = 128; 
    	em[42] = 313; em[43] = 136; 
    	em[44] = 313; em[45] = 144; 
    	em[46] = 316; em[47] = 152; 
    	em[48] = 319; em[49] = 160; 
    	em[50] = 331; em[51] = 184; 
    	em[52] = 0; em[53] = 200; 
    	em[54] = 0; em[55] = 208; 
    em[56] = 1; em[57] = 8; em[58] = 1; /* 56: pointer.char */
    	em[59] = 8884096; em[60] = 0; 
    em[61] = 1; em[62] = 8; em[63] = 1; /* 61: pointer.struct.rsa_meth_st */
    	em[64] = 66; em[65] = 0; 
    em[66] = 0; em[67] = 112; em[68] = 13; /* 66: struct.rsa_meth_st */
    	em[69] = 56; em[70] = 0; 
    	em[71] = 95; em[72] = 8; 
    	em[73] = 95; em[74] = 16; 
    	em[75] = 95; em[76] = 24; 
    	em[77] = 95; em[78] = 32; 
    	em[79] = 98; em[80] = 40; 
    	em[81] = 101; em[82] = 48; 
    	em[83] = 104; em[84] = 56; 
    	em[85] = 104; em[86] = 64; 
    	em[87] = 107; em[88] = 80; 
    	em[89] = 112; em[90] = 88; 
    	em[91] = 115; em[92] = 96; 
    	em[93] = 118; em[94] = 104; 
    em[95] = 8884097; em[96] = 8; em[97] = 0; /* 95: pointer.func */
    em[98] = 8884097; em[99] = 8; em[100] = 0; /* 98: pointer.func */
    em[101] = 8884097; em[102] = 8; em[103] = 0; /* 101: pointer.func */
    em[104] = 8884097; em[105] = 8; em[106] = 0; /* 104: pointer.func */
    em[107] = 1; em[108] = 8; em[109] = 1; /* 107: pointer.char */
    	em[110] = 8884096; em[111] = 0; 
    em[112] = 8884097; em[113] = 8; em[114] = 0; /* 112: pointer.func */
    em[115] = 8884097; em[116] = 8; em[117] = 0; /* 115: pointer.func */
    em[118] = 8884097; em[119] = 8; em[120] = 0; /* 118: pointer.func */
    em[121] = 1; em[122] = 8; em[123] = 1; /* 121: pointer.struct.dsa_method */
    	em[124] = 126; em[125] = 0; 
    em[126] = 0; em[127] = 96; em[128] = 11; /* 126: struct.dsa_method */
    	em[129] = 56; em[130] = 0; 
    	em[131] = 151; em[132] = 8; 
    	em[133] = 154; em[134] = 16; 
    	em[135] = 157; em[136] = 24; 
    	em[137] = 160; em[138] = 32; 
    	em[139] = 163; em[140] = 40; 
    	em[141] = 166; em[142] = 48; 
    	em[143] = 166; em[144] = 56; 
    	em[145] = 107; em[146] = 72; 
    	em[147] = 169; em[148] = 80; 
    	em[149] = 166; em[150] = 88; 
    em[151] = 8884097; em[152] = 8; em[153] = 0; /* 151: pointer.func */
    em[154] = 8884097; em[155] = 8; em[156] = 0; /* 154: pointer.func */
    em[157] = 8884097; em[158] = 8; em[159] = 0; /* 157: pointer.func */
    em[160] = 8884097; em[161] = 8; em[162] = 0; /* 160: pointer.func */
    em[163] = 8884097; em[164] = 8; em[165] = 0; /* 163: pointer.func */
    em[166] = 8884097; em[167] = 8; em[168] = 0; /* 166: pointer.func */
    em[169] = 8884097; em[170] = 8; em[171] = 0; /* 169: pointer.func */
    em[172] = 1; em[173] = 8; em[174] = 1; /* 172: pointer.struct.dh_method */
    	em[175] = 177; em[176] = 0; 
    em[177] = 0; em[178] = 72; em[179] = 8; /* 177: struct.dh_method */
    	em[180] = 56; em[181] = 0; 
    	em[182] = 196; em[183] = 8; 
    	em[184] = 199; em[185] = 16; 
    	em[186] = 202; em[187] = 24; 
    	em[188] = 196; em[189] = 32; 
    	em[190] = 196; em[191] = 40; 
    	em[192] = 107; em[193] = 56; 
    	em[194] = 205; em[195] = 64; 
    em[196] = 8884097; em[197] = 8; em[198] = 0; /* 196: pointer.func */
    em[199] = 8884097; em[200] = 8; em[201] = 0; /* 199: pointer.func */
    em[202] = 8884097; em[203] = 8; em[204] = 0; /* 202: pointer.func */
    em[205] = 8884097; em[206] = 8; em[207] = 0; /* 205: pointer.func */
    em[208] = 1; em[209] = 8; em[210] = 1; /* 208: pointer.struct.ecdh_method */
    	em[211] = 213; em[212] = 0; 
    em[213] = 0; em[214] = 32; em[215] = 3; /* 213: struct.ecdh_method */
    	em[216] = 56; em[217] = 0; 
    	em[218] = 222; em[219] = 8; 
    	em[220] = 107; em[221] = 24; 
    em[222] = 8884097; em[223] = 8; em[224] = 0; /* 222: pointer.func */
    em[225] = 1; em[226] = 8; em[227] = 1; /* 225: pointer.struct.ecdsa_method */
    	em[228] = 230; em[229] = 0; 
    em[230] = 0; em[231] = 48; em[232] = 5; /* 230: struct.ecdsa_method */
    	em[233] = 56; em[234] = 0; 
    	em[235] = 243; em[236] = 8; 
    	em[237] = 246; em[238] = 16; 
    	em[239] = 249; em[240] = 24; 
    	em[241] = 107; em[242] = 40; 
    em[243] = 8884097; em[244] = 8; em[245] = 0; /* 243: pointer.func */
    em[246] = 8884097; em[247] = 8; em[248] = 0; /* 246: pointer.func */
    em[249] = 8884097; em[250] = 8; em[251] = 0; /* 249: pointer.func */
    em[252] = 1; em[253] = 8; em[254] = 1; /* 252: pointer.struct.rand_meth_st */
    	em[255] = 257; em[256] = 0; 
    em[257] = 0; em[258] = 48; em[259] = 6; /* 257: struct.rand_meth_st */
    	em[260] = 272; em[261] = 0; 
    	em[262] = 275; em[263] = 8; 
    	em[264] = 278; em[265] = 16; 
    	em[266] = 281; em[267] = 24; 
    	em[268] = 275; em[269] = 32; 
    	em[270] = 284; em[271] = 40; 
    em[272] = 8884097; em[273] = 8; em[274] = 0; /* 272: pointer.func */
    em[275] = 8884097; em[276] = 8; em[277] = 0; /* 275: pointer.func */
    em[278] = 8884097; em[279] = 8; em[280] = 0; /* 278: pointer.func */
    em[281] = 8884097; em[282] = 8; em[283] = 0; /* 281: pointer.func */
    em[284] = 8884097; em[285] = 8; em[286] = 0; /* 284: pointer.func */
    em[287] = 1; em[288] = 8; em[289] = 1; /* 287: pointer.struct.store_method_st */
    	em[290] = 292; em[291] = 0; 
    em[292] = 0; em[293] = 0; em[294] = 0; /* 292: struct.store_method_st */
    em[295] = 8884097; em[296] = 8; em[297] = 0; /* 295: pointer.func */
    em[298] = 8884097; em[299] = 8; em[300] = 0; /* 298: pointer.func */
    em[301] = 8884097; em[302] = 8; em[303] = 0; /* 301: pointer.func */
    em[304] = 8884097; em[305] = 8; em[306] = 0; /* 304: pointer.func */
    em[307] = 8884097; em[308] = 8; em[309] = 0; /* 307: pointer.func */
    em[310] = 8884097; em[311] = 8; em[312] = 0; /* 310: pointer.func */
    em[313] = 8884097; em[314] = 8; em[315] = 0; /* 313: pointer.func */
    em[316] = 8884097; em[317] = 8; em[318] = 0; /* 316: pointer.func */
    em[319] = 1; em[320] = 8; em[321] = 1; /* 319: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[322] = 324; em[323] = 0; 
    em[324] = 0; em[325] = 32; em[326] = 2; /* 324: struct.ENGINE_CMD_DEFN_st */
    	em[327] = 56; em[328] = 8; 
    	em[329] = 56; em[330] = 16; 
    em[331] = 0; em[332] = 32; em[333] = 2; /* 331: struct.crypto_ex_data_st_fake */
    	em[334] = 338; em[335] = 8; 
    	em[336] = 351; em[337] = 24; 
    em[338] = 8884099; em[339] = 8; em[340] = 2; /* 338: pointer_to_array_of_pointers_to_stack */
    	em[341] = 345; em[342] = 0; 
    	em[343] = 348; em[344] = 20; 
    em[345] = 0; em[346] = 8; em[347] = 0; /* 345: pointer.void */
    em[348] = 0; em[349] = 4; em[350] = 0; /* 348: int */
    em[351] = 8884097; em[352] = 8; em[353] = 0; /* 351: pointer.func */
    em[354] = 1; em[355] = 8; em[356] = 1; /* 354: pointer.struct.engine_st */
    	em[357] = 5; em[358] = 0; 
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
    	em[382] = 345; em[383] = 80; 
    em[384] = 8884097; em[385] = 8; em[386] = 0; /* 384: pointer.func */
    em[387] = 8884097; em[388] = 8; em[389] = 0; /* 387: pointer.func */
    em[390] = 8884097; em[391] = 8; em[392] = 0; /* 390: pointer.func */
    em[393] = 8884097; em[394] = 8; em[395] = 0; /* 393: pointer.func */
    em[396] = 8884097; em[397] = 8; em[398] = 0; /* 396: pointer.func */
    em[399] = 1; em[400] = 8; em[401] = 1; /* 399: pointer.unsigned char */
    	em[402] = 359; em[403] = 0; 
    em[404] = 1; em[405] = 8; em[406] = 1; /* 404: pointer.struct.evp_cipher_ctx_st */
    	em[407] = 409; em[408] = 0; 
    em[409] = 0; em[410] = 168; em[411] = 4; /* 409: struct.evp_cipher_ctx_st */
    	em[412] = 362; em[413] = 0; 
    	em[414] = 354; em[415] = 8; 
    	em[416] = 345; em[417] = 96; 
    	em[418] = 345; em[419] = 120; 
    em[420] = 0; em[421] = 1; em[422] = 0; /* 420: char */
    args_addr->arg_entity_index[0] = 404;
    args_addr->arg_entity_index[1] = 362;
    args_addr->arg_entity_index[2] = 354;
    args_addr->arg_entity_index[3] = 399;
    args_addr->arg_entity_index[4] = 399;
    args_addr->ret_entity_index = 348;
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

