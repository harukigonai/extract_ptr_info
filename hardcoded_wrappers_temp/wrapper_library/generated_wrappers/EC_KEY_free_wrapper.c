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

void bb_EC_KEY_free(EC_KEY * arg_a);

void EC_KEY_free(EC_KEY * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EC_KEY_free called %lu\n", in_lib);
    if (!in_lib)
        bb_EC_KEY_free(arg_a);
    else {
        void (*orig_EC_KEY_free)(EC_KEY *);
        orig_EC_KEY_free = dlsym(RTLD_NEXT, "EC_KEY_free");
        orig_EC_KEY_free(arg_a);
    }
}

void bb_EC_KEY_free(EC_KEY * arg_a) 
{
    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 0; em[1] = 40; em[2] = 5; /* 0: struct.ec_extra_data_st */
    	em[3] = 13; em[4] = 0; 
    	em[5] = 18; em[6] = 8; 
    	em[7] = 21; em[8] = 16; 
    	em[9] = 24; em[10] = 24; 
    	em[11] = 24; em[12] = 32; 
    em[13] = 1; em[14] = 8; em[15] = 1; /* 13: pointer.struct.ec_extra_data_st */
    	em[16] = 0; em[17] = 0; 
    em[18] = 0; em[19] = 8; em[20] = 0; /* 18: pointer.void */
    em[21] = 8884097; em[22] = 8; em[23] = 0; /* 21: pointer.func */
    em[24] = 8884097; em[25] = 8; em[26] = 0; /* 24: pointer.func */
    em[27] = 1; em[28] = 8; em[29] = 1; /* 27: pointer.struct.ec_extra_data_st */
    	em[30] = 0; em[31] = 0; 
    em[32] = 0; em[33] = 24; em[34] = 1; /* 32: struct.bignum_st */
    	em[35] = 37; em[36] = 0; 
    em[37] = 8884099; em[38] = 8; em[39] = 2; /* 37: pointer_to_array_of_pointers_to_stack */
    	em[40] = 44; em[41] = 0; 
    	em[42] = 47; em[43] = 12; 
    em[44] = 0; em[45] = 8; em[46] = 0; /* 44: long unsigned int */
    em[47] = 0; em[48] = 4; em[49] = 0; /* 47: int */
    em[50] = 1; em[51] = 8; em[52] = 1; /* 50: pointer.struct.bignum_st */
    	em[53] = 32; em[54] = 0; 
    em[55] = 1; em[56] = 8; em[57] = 1; /* 55: pointer.struct.ec_extra_data_st */
    	em[58] = 60; em[59] = 0; 
    em[60] = 0; em[61] = 40; em[62] = 5; /* 60: struct.ec_extra_data_st */
    	em[63] = 55; em[64] = 0; 
    	em[65] = 18; em[66] = 8; 
    	em[67] = 21; em[68] = 16; 
    	em[69] = 24; em[70] = 24; 
    	em[71] = 24; em[72] = 32; 
    em[73] = 1; em[74] = 8; em[75] = 1; /* 73: pointer.unsigned char */
    	em[76] = 78; em[77] = 0; 
    em[78] = 0; em[79] = 1; em[80] = 0; /* 78: unsigned char */
    em[81] = 0; em[82] = 24; em[83] = 1; /* 81: struct.bignum_st */
    	em[84] = 86; em[85] = 0; 
    em[86] = 8884099; em[87] = 8; em[88] = 2; /* 86: pointer_to_array_of_pointers_to_stack */
    	em[89] = 44; em[90] = 0; 
    	em[91] = 47; em[92] = 12; 
    em[93] = 8884097; em[94] = 8; em[95] = 0; /* 93: pointer.func */
    em[96] = 8884097; em[97] = 8; em[98] = 0; /* 96: pointer.func */
    em[99] = 8884097; em[100] = 8; em[101] = 0; /* 99: pointer.func */
    em[102] = 8884097; em[103] = 8; em[104] = 0; /* 102: pointer.func */
    em[105] = 8884097; em[106] = 8; em[107] = 0; /* 105: pointer.func */
    em[108] = 8884097; em[109] = 8; em[110] = 0; /* 108: pointer.func */
    em[111] = 0; em[112] = 304; em[113] = 37; /* 111: struct.ec_method_st */
    	em[114] = 188; em[115] = 8; 
    	em[116] = 191; em[117] = 16; 
    	em[118] = 191; em[119] = 24; 
    	em[120] = 194; em[121] = 32; 
    	em[122] = 197; em[123] = 40; 
    	em[124] = 200; em[125] = 48; 
    	em[126] = 203; em[127] = 56; 
    	em[128] = 206; em[129] = 64; 
    	em[130] = 209; em[131] = 72; 
    	em[132] = 212; em[133] = 80; 
    	em[134] = 212; em[135] = 88; 
    	em[136] = 215; em[137] = 96; 
    	em[138] = 218; em[139] = 104; 
    	em[140] = 221; em[141] = 112; 
    	em[142] = 224; em[143] = 120; 
    	em[144] = 227; em[145] = 128; 
    	em[146] = 230; em[147] = 136; 
    	em[148] = 233; em[149] = 144; 
    	em[150] = 236; em[151] = 152; 
    	em[152] = 239; em[153] = 160; 
    	em[154] = 242; em[155] = 168; 
    	em[156] = 245; em[157] = 176; 
    	em[158] = 248; em[159] = 184; 
    	em[160] = 108; em[161] = 192; 
    	em[162] = 251; em[163] = 200; 
    	em[164] = 254; em[165] = 208; 
    	em[166] = 248; em[167] = 216; 
    	em[168] = 257; em[169] = 224; 
    	em[170] = 260; em[171] = 232; 
    	em[172] = 263; em[173] = 240; 
    	em[174] = 203; em[175] = 248; 
    	em[176] = 266; em[177] = 256; 
    	em[178] = 269; em[179] = 264; 
    	em[180] = 266; em[181] = 272; 
    	em[182] = 269; em[183] = 280; 
    	em[184] = 269; em[185] = 288; 
    	em[186] = 272; em[187] = 296; 
    em[188] = 8884097; em[189] = 8; em[190] = 0; /* 188: pointer.func */
    em[191] = 8884097; em[192] = 8; em[193] = 0; /* 191: pointer.func */
    em[194] = 8884097; em[195] = 8; em[196] = 0; /* 194: pointer.func */
    em[197] = 8884097; em[198] = 8; em[199] = 0; /* 197: pointer.func */
    em[200] = 8884097; em[201] = 8; em[202] = 0; /* 200: pointer.func */
    em[203] = 8884097; em[204] = 8; em[205] = 0; /* 203: pointer.func */
    em[206] = 8884097; em[207] = 8; em[208] = 0; /* 206: pointer.func */
    em[209] = 8884097; em[210] = 8; em[211] = 0; /* 209: pointer.func */
    em[212] = 8884097; em[213] = 8; em[214] = 0; /* 212: pointer.func */
    em[215] = 8884097; em[216] = 8; em[217] = 0; /* 215: pointer.func */
    em[218] = 8884097; em[219] = 8; em[220] = 0; /* 218: pointer.func */
    em[221] = 8884097; em[222] = 8; em[223] = 0; /* 221: pointer.func */
    em[224] = 8884097; em[225] = 8; em[226] = 0; /* 224: pointer.func */
    em[227] = 8884097; em[228] = 8; em[229] = 0; /* 227: pointer.func */
    em[230] = 8884097; em[231] = 8; em[232] = 0; /* 230: pointer.func */
    em[233] = 8884097; em[234] = 8; em[235] = 0; /* 233: pointer.func */
    em[236] = 8884097; em[237] = 8; em[238] = 0; /* 236: pointer.func */
    em[239] = 8884097; em[240] = 8; em[241] = 0; /* 239: pointer.func */
    em[242] = 8884097; em[243] = 8; em[244] = 0; /* 242: pointer.func */
    em[245] = 8884097; em[246] = 8; em[247] = 0; /* 245: pointer.func */
    em[248] = 8884097; em[249] = 8; em[250] = 0; /* 248: pointer.func */
    em[251] = 8884097; em[252] = 8; em[253] = 0; /* 251: pointer.func */
    em[254] = 8884097; em[255] = 8; em[256] = 0; /* 254: pointer.func */
    em[257] = 8884097; em[258] = 8; em[259] = 0; /* 257: pointer.func */
    em[260] = 8884097; em[261] = 8; em[262] = 0; /* 260: pointer.func */
    em[263] = 8884097; em[264] = 8; em[265] = 0; /* 263: pointer.func */
    em[266] = 8884097; em[267] = 8; em[268] = 0; /* 266: pointer.func */
    em[269] = 8884097; em[270] = 8; em[271] = 0; /* 269: pointer.func */
    em[272] = 8884097; em[273] = 8; em[274] = 0; /* 272: pointer.func */
    em[275] = 8884097; em[276] = 8; em[277] = 0; /* 275: pointer.func */
    em[278] = 1; em[279] = 8; em[280] = 1; /* 278: pointer.struct.ec_method_st */
    	em[281] = 111; em[282] = 0; 
    em[283] = 8884097; em[284] = 8; em[285] = 0; /* 283: pointer.func */
    em[286] = 8884097; em[287] = 8; em[288] = 0; /* 286: pointer.func */
    em[289] = 1; em[290] = 8; em[291] = 1; /* 289: pointer.struct.ec_extra_data_st */
    	em[292] = 60; em[293] = 0; 
    em[294] = 8884097; em[295] = 8; em[296] = 0; /* 294: pointer.func */
    em[297] = 8884097; em[298] = 8; em[299] = 0; /* 297: pointer.func */
    em[300] = 8884097; em[301] = 8; em[302] = 0; /* 300: pointer.func */
    em[303] = 1; em[304] = 8; em[305] = 1; /* 303: pointer.struct.ec_group_st */
    	em[306] = 308; em[307] = 0; 
    em[308] = 0; em[309] = 232; em[310] = 12; /* 308: struct.ec_group_st */
    	em[311] = 278; em[312] = 0; 
    	em[313] = 335; em[314] = 8; 
    	em[315] = 81; em[316] = 16; 
    	em[317] = 81; em[318] = 40; 
    	em[319] = 73; em[320] = 80; 
    	em[321] = 289; em[322] = 96; 
    	em[323] = 81; em[324] = 104; 
    	em[325] = 81; em[326] = 152; 
    	em[327] = 81; em[328] = 176; 
    	em[329] = 18; em[330] = 208; 
    	em[331] = 18; em[332] = 216; 
    	em[333] = 300; em[334] = 224; 
    em[335] = 1; em[336] = 8; em[337] = 1; /* 335: pointer.struct.ec_point_st */
    	em[338] = 340; em[339] = 0; 
    em[340] = 0; em[341] = 88; em[342] = 4; /* 340: struct.ec_point_st */
    	em[343] = 351; em[344] = 0; 
    	em[345] = 493; em[346] = 8; 
    	em[347] = 493; em[348] = 32; 
    	em[349] = 493; em[350] = 56; 
    em[351] = 1; em[352] = 8; em[353] = 1; /* 351: pointer.struct.ec_method_st */
    	em[354] = 356; em[355] = 0; 
    em[356] = 0; em[357] = 304; em[358] = 37; /* 356: struct.ec_method_st */
    	em[359] = 433; em[360] = 8; 
    	em[361] = 436; em[362] = 16; 
    	em[363] = 436; em[364] = 24; 
    	em[365] = 439; em[366] = 32; 
    	em[367] = 442; em[368] = 40; 
    	em[369] = 445; em[370] = 48; 
    	em[371] = 448; em[372] = 56; 
    	em[373] = 451; em[374] = 64; 
    	em[375] = 454; em[376] = 72; 
    	em[377] = 457; em[378] = 80; 
    	em[379] = 457; em[380] = 88; 
    	em[381] = 460; em[382] = 96; 
    	em[383] = 463; em[384] = 104; 
    	em[385] = 466; em[386] = 112; 
    	em[387] = 469; em[388] = 120; 
    	em[389] = 283; em[390] = 128; 
    	em[391] = 472; em[392] = 136; 
    	em[393] = 475; em[394] = 144; 
    	em[395] = 294; em[396] = 152; 
    	em[397] = 478; em[398] = 160; 
    	em[399] = 481; em[400] = 168; 
    	em[401] = 484; em[402] = 176; 
    	em[403] = 487; em[404] = 184; 
    	em[405] = 297; em[406] = 192; 
    	em[407] = 105; em[408] = 200; 
    	em[409] = 286; em[410] = 208; 
    	em[411] = 487; em[412] = 216; 
    	em[413] = 102; em[414] = 224; 
    	em[415] = 99; em[416] = 232; 
    	em[417] = 275; em[418] = 240; 
    	em[419] = 448; em[420] = 248; 
    	em[421] = 96; em[422] = 256; 
    	em[423] = 490; em[424] = 264; 
    	em[425] = 96; em[426] = 272; 
    	em[427] = 490; em[428] = 280; 
    	em[429] = 490; em[430] = 288; 
    	em[431] = 93; em[432] = 296; 
    em[433] = 8884097; em[434] = 8; em[435] = 0; /* 433: pointer.func */
    em[436] = 8884097; em[437] = 8; em[438] = 0; /* 436: pointer.func */
    em[439] = 8884097; em[440] = 8; em[441] = 0; /* 439: pointer.func */
    em[442] = 8884097; em[443] = 8; em[444] = 0; /* 442: pointer.func */
    em[445] = 8884097; em[446] = 8; em[447] = 0; /* 445: pointer.func */
    em[448] = 8884097; em[449] = 8; em[450] = 0; /* 448: pointer.func */
    em[451] = 8884097; em[452] = 8; em[453] = 0; /* 451: pointer.func */
    em[454] = 8884097; em[455] = 8; em[456] = 0; /* 454: pointer.func */
    em[457] = 8884097; em[458] = 8; em[459] = 0; /* 457: pointer.func */
    em[460] = 8884097; em[461] = 8; em[462] = 0; /* 460: pointer.func */
    em[463] = 8884097; em[464] = 8; em[465] = 0; /* 463: pointer.func */
    em[466] = 8884097; em[467] = 8; em[468] = 0; /* 466: pointer.func */
    em[469] = 8884097; em[470] = 8; em[471] = 0; /* 469: pointer.func */
    em[472] = 8884097; em[473] = 8; em[474] = 0; /* 472: pointer.func */
    em[475] = 8884097; em[476] = 8; em[477] = 0; /* 475: pointer.func */
    em[478] = 8884097; em[479] = 8; em[480] = 0; /* 478: pointer.func */
    em[481] = 8884097; em[482] = 8; em[483] = 0; /* 481: pointer.func */
    em[484] = 8884097; em[485] = 8; em[486] = 0; /* 484: pointer.func */
    em[487] = 8884097; em[488] = 8; em[489] = 0; /* 487: pointer.func */
    em[490] = 8884097; em[491] = 8; em[492] = 0; /* 490: pointer.func */
    em[493] = 0; em[494] = 24; em[495] = 1; /* 493: struct.bignum_st */
    	em[496] = 498; em[497] = 0; 
    em[498] = 8884099; em[499] = 8; em[500] = 2; /* 498: pointer_to_array_of_pointers_to_stack */
    	em[501] = 44; em[502] = 0; 
    	em[503] = 47; em[504] = 12; 
    em[505] = 1; em[506] = 8; em[507] = 1; /* 505: pointer.struct.ec_key_st */
    	em[508] = 510; em[509] = 0; 
    em[510] = 0; em[511] = 56; em[512] = 4; /* 510: struct.ec_key_st */
    	em[513] = 303; em[514] = 8; 
    	em[515] = 521; em[516] = 16; 
    	em[517] = 50; em[518] = 24; 
    	em[519] = 27; em[520] = 48; 
    em[521] = 1; em[522] = 8; em[523] = 1; /* 521: pointer.struct.ec_point_st */
    	em[524] = 340; em[525] = 0; 
    args_addr->arg_entity_index[0] = 505;
    args_addr->ret_entity_index = -1;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EC_KEY * new_arg_a = *((EC_KEY * *)new_args->args[0]);

    void (*orig_EC_KEY_free)(EC_KEY *);
    orig_EC_KEY_free = dlsym(RTLD_NEXT, "EC_KEY_free");
    (*orig_EC_KEY_free)(new_arg_a);

    syscall(889);

    free(args_addr);

}

