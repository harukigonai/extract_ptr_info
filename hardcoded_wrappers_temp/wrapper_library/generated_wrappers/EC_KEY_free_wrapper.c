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
    em[27] = 8884097; em[28] = 8; em[29] = 0; /* 27: pointer.func */
    em[30] = 1; em[31] = 8; em[32] = 1; /* 30: pointer.struct.ec_extra_data_st */
    	em[33] = 35; em[34] = 0; 
    em[35] = 0; em[36] = 40; em[37] = 5; /* 35: struct.ec_extra_data_st */
    	em[38] = 30; em[39] = 0; 
    	em[40] = 18; em[41] = 8; 
    	em[42] = 21; em[43] = 16; 
    	em[44] = 24; em[45] = 24; 
    	em[46] = 24; em[47] = 32; 
    em[48] = 0; em[49] = 4; em[50] = 0; /* 48: int */
    em[51] = 8884097; em[52] = 8; em[53] = 0; /* 51: pointer.func */
    em[54] = 8884097; em[55] = 8; em[56] = 0; /* 54: pointer.func */
    em[57] = 8884097; em[58] = 8; em[59] = 0; /* 57: pointer.func */
    em[60] = 8884097; em[61] = 8; em[62] = 0; /* 60: pointer.func */
    em[63] = 8884097; em[64] = 8; em[65] = 0; /* 63: pointer.func */
    em[66] = 8884097; em[67] = 8; em[68] = 0; /* 66: pointer.func */
    em[69] = 8884097; em[70] = 8; em[71] = 0; /* 69: pointer.func */
    em[72] = 8884097; em[73] = 8; em[74] = 0; /* 72: pointer.func */
    em[75] = 8884097; em[76] = 8; em[77] = 0; /* 75: pointer.func */
    em[78] = 8884097; em[79] = 8; em[80] = 0; /* 78: pointer.func */
    em[81] = 8884097; em[82] = 8; em[83] = 0; /* 81: pointer.func */
    em[84] = 1; em[85] = 8; em[86] = 1; /* 84: pointer.struct.ec_point_st */
    	em[87] = 89; em[88] = 0; 
    em[89] = 0; em[90] = 88; em[91] = 4; /* 89: struct.ec_point_st */
    	em[92] = 100; em[93] = 0; 
    	em[94] = 248; em[95] = 8; 
    	em[96] = 248; em[97] = 32; 
    	em[98] = 248; em[99] = 56; 
    em[100] = 1; em[101] = 8; em[102] = 1; /* 100: pointer.struct.ec_method_st */
    	em[103] = 105; em[104] = 0; 
    em[105] = 0; em[106] = 304; em[107] = 37; /* 105: struct.ec_method_st */
    	em[108] = 182; em[109] = 8; 
    	em[110] = 185; em[111] = 16; 
    	em[112] = 185; em[113] = 24; 
    	em[114] = 188; em[115] = 32; 
    	em[116] = 191; em[117] = 40; 
    	em[118] = 194; em[119] = 48; 
    	em[120] = 197; em[121] = 56; 
    	em[122] = 200; em[123] = 64; 
    	em[124] = 203; em[125] = 72; 
    	em[126] = 206; em[127] = 80; 
    	em[128] = 206; em[129] = 88; 
    	em[130] = 209; em[131] = 96; 
    	em[132] = 212; em[133] = 104; 
    	em[134] = 215; em[135] = 112; 
    	em[136] = 218; em[137] = 120; 
    	em[138] = 221; em[139] = 128; 
    	em[140] = 224; em[141] = 136; 
    	em[142] = 227; em[143] = 144; 
    	em[144] = 230; em[145] = 152; 
    	em[146] = 233; em[147] = 160; 
    	em[148] = 236; em[149] = 168; 
    	em[150] = 239; em[151] = 176; 
    	em[152] = 242; em[153] = 184; 
    	em[154] = 72; em[155] = 192; 
    	em[156] = 69; em[157] = 200; 
    	em[158] = 66; em[159] = 208; 
    	em[160] = 242; em[161] = 216; 
    	em[162] = 63; em[163] = 224; 
    	em[164] = 60; em[165] = 232; 
    	em[166] = 57; em[167] = 240; 
    	em[168] = 197; em[169] = 248; 
    	em[170] = 54; em[171] = 256; 
    	em[172] = 245; em[173] = 264; 
    	em[174] = 54; em[175] = 272; 
    	em[176] = 245; em[177] = 280; 
    	em[178] = 245; em[179] = 288; 
    	em[180] = 51; em[181] = 296; 
    em[182] = 8884097; em[183] = 8; em[184] = 0; /* 182: pointer.func */
    em[185] = 8884097; em[186] = 8; em[187] = 0; /* 185: pointer.func */
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
    em[248] = 0; em[249] = 24; em[250] = 1; /* 248: struct.bignum_st */
    	em[251] = 253; em[252] = 0; 
    em[253] = 8884099; em[254] = 8; em[255] = 2; /* 253: pointer_to_array_of_pointers_to_stack */
    	em[256] = 260; em[257] = 0; 
    	em[258] = 48; em[259] = 12; 
    em[260] = 0; em[261] = 8; em[262] = 0; /* 260: long unsigned int */
    em[263] = 1; em[264] = 8; em[265] = 1; /* 263: pointer.unsigned char */
    	em[266] = 268; em[267] = 0; 
    em[268] = 0; em[269] = 1; em[270] = 0; /* 268: unsigned char */
    em[271] = 8884097; em[272] = 8; em[273] = 0; /* 271: pointer.func */
    em[274] = 8884097; em[275] = 8; em[276] = 0; /* 274: pointer.func */
    em[277] = 8884097; em[278] = 8; em[279] = 0; /* 277: pointer.func */
    em[280] = 1; em[281] = 8; em[282] = 1; /* 280: pointer.struct.ec_extra_data_st */
    	em[283] = 0; em[284] = 0; 
    em[285] = 8884097; em[286] = 8; em[287] = 0; /* 285: pointer.func */
    em[288] = 8884099; em[289] = 8; em[290] = 2; /* 288: pointer_to_array_of_pointers_to_stack */
    	em[291] = 260; em[292] = 0; 
    	em[293] = 48; em[294] = 12; 
    em[295] = 8884097; em[296] = 8; em[297] = 0; /* 295: pointer.func */
    em[298] = 8884097; em[299] = 8; em[300] = 0; /* 298: pointer.func */
    em[301] = 0; em[302] = 24; em[303] = 1; /* 301: struct.bignum_st */
    	em[304] = 288; em[305] = 0; 
    em[306] = 8884097; em[307] = 8; em[308] = 0; /* 306: pointer.func */
    em[309] = 0; em[310] = 24; em[311] = 1; /* 309: struct.bignum_st */
    	em[312] = 314; em[313] = 0; 
    em[314] = 8884099; em[315] = 8; em[316] = 2; /* 314: pointer_to_array_of_pointers_to_stack */
    	em[317] = 260; em[318] = 0; 
    	em[319] = 48; em[320] = 12; 
    em[321] = 8884097; em[322] = 8; em[323] = 0; /* 321: pointer.func */
    em[324] = 1; em[325] = 8; em[326] = 1; /* 324: pointer.struct.ec_key_st */
    	em[327] = 329; em[328] = 0; 
    em[329] = 0; em[330] = 56; em[331] = 4; /* 329: struct.ec_key_st */
    	em[332] = 340; em[333] = 8; 
    	em[334] = 516; em[335] = 16; 
    	em[336] = 521; em[337] = 24; 
    	em[338] = 280; em[339] = 48; 
    em[340] = 1; em[341] = 8; em[342] = 1; /* 340: pointer.struct.ec_group_st */
    	em[343] = 345; em[344] = 0; 
    em[345] = 0; em[346] = 232; em[347] = 12; /* 345: struct.ec_group_st */
    	em[348] = 372; em[349] = 0; 
    	em[350] = 84; em[351] = 8; 
    	em[352] = 309; em[353] = 16; 
    	em[354] = 309; em[355] = 40; 
    	em[356] = 263; em[357] = 80; 
    	em[358] = 511; em[359] = 96; 
    	em[360] = 309; em[361] = 104; 
    	em[362] = 309; em[363] = 152; 
    	em[364] = 309; em[365] = 176; 
    	em[366] = 18; em[367] = 208; 
    	em[368] = 18; em[369] = 216; 
    	em[370] = 27; em[371] = 224; 
    em[372] = 1; em[373] = 8; em[374] = 1; /* 372: pointer.struct.ec_method_st */
    	em[375] = 377; em[376] = 0; 
    em[377] = 0; em[378] = 304; em[379] = 37; /* 377: struct.ec_method_st */
    	em[380] = 81; em[381] = 8; 
    	em[382] = 454; em[383] = 16; 
    	em[384] = 454; em[385] = 24; 
    	em[386] = 457; em[387] = 32; 
    	em[388] = 78; em[389] = 40; 
    	em[390] = 285; em[391] = 48; 
    	em[392] = 460; em[393] = 56; 
    	em[394] = 274; em[395] = 64; 
    	em[396] = 298; em[397] = 72; 
    	em[398] = 295; em[399] = 80; 
    	em[400] = 295; em[401] = 88; 
    	em[402] = 463; em[403] = 96; 
    	em[404] = 466; em[405] = 104; 
    	em[406] = 469; em[407] = 112; 
    	em[408] = 321; em[409] = 120; 
    	em[410] = 472; em[411] = 128; 
    	em[412] = 271; em[413] = 136; 
    	em[414] = 475; em[415] = 144; 
    	em[416] = 75; em[417] = 152; 
    	em[418] = 277; em[419] = 160; 
    	em[420] = 306; em[421] = 168; 
    	em[422] = 478; em[423] = 176; 
    	em[424] = 481; em[425] = 184; 
    	em[426] = 484; em[427] = 192; 
    	em[428] = 487; em[429] = 200; 
    	em[430] = 490; em[431] = 208; 
    	em[432] = 481; em[433] = 216; 
    	em[434] = 493; em[435] = 224; 
    	em[436] = 496; em[437] = 232; 
    	em[438] = 499; em[439] = 240; 
    	em[440] = 460; em[441] = 248; 
    	em[442] = 502; em[443] = 256; 
    	em[444] = 505; em[445] = 264; 
    	em[446] = 502; em[447] = 272; 
    	em[448] = 505; em[449] = 280; 
    	em[450] = 505; em[451] = 288; 
    	em[452] = 508; em[453] = 296; 
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
    em[493] = 8884097; em[494] = 8; em[495] = 0; /* 493: pointer.func */
    em[496] = 8884097; em[497] = 8; em[498] = 0; /* 496: pointer.func */
    em[499] = 8884097; em[500] = 8; em[501] = 0; /* 499: pointer.func */
    em[502] = 8884097; em[503] = 8; em[504] = 0; /* 502: pointer.func */
    em[505] = 8884097; em[506] = 8; em[507] = 0; /* 505: pointer.func */
    em[508] = 8884097; em[509] = 8; em[510] = 0; /* 508: pointer.func */
    em[511] = 1; em[512] = 8; em[513] = 1; /* 511: pointer.struct.ec_extra_data_st */
    	em[514] = 35; em[515] = 0; 
    em[516] = 1; em[517] = 8; em[518] = 1; /* 516: pointer.struct.ec_point_st */
    	em[519] = 89; em[520] = 0; 
    em[521] = 1; em[522] = 8; em[523] = 1; /* 521: pointer.struct.bignum_st */
    	em[524] = 301; em[525] = 0; 
    args_addr->arg_entity_index[0] = 324;
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

