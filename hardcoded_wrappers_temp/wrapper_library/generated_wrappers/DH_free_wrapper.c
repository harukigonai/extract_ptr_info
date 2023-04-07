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

void bb_DH_free(DH * arg_a);

void DH_free(DH * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("DH_free called %lu\n", in_lib);
    if (!in_lib)
        bb_DH_free(arg_a);
    else {
        void (*orig_DH_free)(DH *);
        orig_DH_free = dlsym(RTLD_NEXT, "DH_free");
        orig_DH_free(arg_a);
    }
}

void bb_DH_free(DH * arg_a) 
{
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
    em[331] = 0; em[332] = 16; em[333] = 1; /* 331: struct.crypto_ex_data_st */
    	em[334] = 336; em[335] = 0; 
    em[336] = 1; em[337] = 8; em[338] = 1; /* 336: pointer.struct.stack_st_void */
    	em[339] = 341; em[340] = 0; 
    em[341] = 0; em[342] = 32; em[343] = 1; /* 341: struct.stack_st_void */
    	em[344] = 346; em[345] = 0; 
    em[346] = 0; em[347] = 32; em[348] = 2; /* 346: struct.stack_st */
    	em[349] = 353; em[350] = 8; 
    	em[351] = 358; em[352] = 24; 
    em[353] = 1; em[354] = 8; em[355] = 1; /* 353: pointer.pointer.char */
    	em[356] = 107; em[357] = 0; 
    em[358] = 8884097; em[359] = 8; em[360] = 0; /* 358: pointer.func */
    em[361] = 8884097; em[362] = 8; em[363] = 0; /* 361: pointer.func */
    em[364] = 0; em[365] = 72; em[366] = 8; /* 364: struct.dh_method */
    	em[367] = 56; em[368] = 0; 
    	em[369] = 361; em[370] = 8; 
    	em[371] = 383; em[372] = 16; 
    	em[373] = 386; em[374] = 24; 
    	em[375] = 361; em[376] = 32; 
    	em[377] = 361; em[378] = 40; 
    	em[379] = 107; em[380] = 56; 
    	em[381] = 389; em[382] = 64; 
    em[383] = 8884097; em[384] = 8; em[385] = 0; /* 383: pointer.func */
    em[386] = 8884097; em[387] = 8; em[388] = 0; /* 386: pointer.func */
    em[389] = 8884097; em[390] = 8; em[391] = 0; /* 389: pointer.func */
    em[392] = 0; em[393] = 1; em[394] = 0; /* 392: char */
    em[395] = 0; em[396] = 32; em[397] = 2; /* 395: struct.stack_st */
    	em[398] = 353; em[399] = 8; 
    	em[400] = 358; em[401] = 24; 
    em[402] = 1; em[403] = 8; em[404] = 1; /* 402: pointer.struct.dh_st */
    	em[405] = 407; em[406] = 0; 
    em[407] = 0; em[408] = 144; em[409] = 12; /* 407: struct.dh_st */
    	em[410] = 434; em[411] = 8; 
    	em[412] = 434; em[413] = 16; 
    	em[414] = 434; em[415] = 32; 
    	em[416] = 434; em[417] = 40; 
    	em[418] = 457; em[419] = 56; 
    	em[420] = 434; em[421] = 64; 
    	em[422] = 434; em[423] = 72; 
    	em[424] = 471; em[425] = 80; 
    	em[426] = 434; em[427] = 96; 
    	em[428] = 479; em[429] = 112; 
    	em[430] = 494; em[431] = 128; 
    	em[432] = 499; em[433] = 136; 
    em[434] = 1; em[435] = 8; em[436] = 1; /* 434: pointer.struct.bignum_st */
    	em[437] = 439; em[438] = 0; 
    em[439] = 0; em[440] = 24; em[441] = 1; /* 439: struct.bignum_st */
    	em[442] = 444; em[443] = 0; 
    em[444] = 8884099; em[445] = 8; em[446] = 2; /* 444: pointer_to_array_of_pointers_to_stack */
    	em[447] = 451; em[448] = 0; 
    	em[449] = 454; em[450] = 12; 
    em[451] = 0; em[452] = 8; em[453] = 0; /* 451: long unsigned int */
    em[454] = 0; em[455] = 4; em[456] = 0; /* 454: int */
    em[457] = 1; em[458] = 8; em[459] = 1; /* 457: pointer.struct.bn_mont_ctx_st */
    	em[460] = 462; em[461] = 0; 
    em[462] = 0; em[463] = 96; em[464] = 3; /* 462: struct.bn_mont_ctx_st */
    	em[465] = 439; em[466] = 8; 
    	em[467] = 439; em[468] = 32; 
    	em[469] = 439; em[470] = 56; 
    em[471] = 1; em[472] = 8; em[473] = 1; /* 471: pointer.unsigned char */
    	em[474] = 476; em[475] = 0; 
    em[476] = 0; em[477] = 1; em[478] = 0; /* 476: unsigned char */
    em[479] = 0; em[480] = 16; em[481] = 1; /* 479: struct.crypto_ex_data_st */
    	em[482] = 484; em[483] = 0; 
    em[484] = 1; em[485] = 8; em[486] = 1; /* 484: pointer.struct.stack_st_void */
    	em[487] = 489; em[488] = 0; 
    em[489] = 0; em[490] = 32; em[491] = 1; /* 489: struct.stack_st_void */
    	em[492] = 395; em[493] = 0; 
    em[494] = 1; em[495] = 8; em[496] = 1; /* 494: pointer.struct.dh_method */
    	em[497] = 364; em[498] = 0; 
    em[499] = 1; em[500] = 8; em[501] = 1; /* 499: pointer.struct.engine_st */
    	em[502] = 5; em[503] = 0; 
    args_addr->arg_entity_index[0] = 402;
    args_addr->ret_entity_index = -1;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    DH * new_arg_a = *((DH * *)new_args->args[0]);

    void (*orig_DH_free)(DH *);
    orig_DH_free = dlsym(RTLD_NEXT, "DH_free");
    (*orig_DH_free)(new_arg_a);

    syscall(889);

    free(args_addr);

}

