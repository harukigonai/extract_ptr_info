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
    em[0] = 0; em[1] = 24; em[2] = 1; /* 0: struct.bignum_st */
    	em[3] = 5; em[4] = 0; 
    em[5] = 8884099; em[6] = 8; em[7] = 2; /* 5: pointer_to_array_of_pointers_to_stack */
    	em[8] = 12; em[9] = 0; 
    	em[10] = 15; em[11] = 12; 
    em[12] = 0; em[13] = 8; em[14] = 0; /* 12: long unsigned int */
    em[15] = 0; em[16] = 4; em[17] = 0; /* 15: int */
    em[18] = 8884097; em[19] = 8; em[20] = 0; /* 18: pointer.func */
    em[21] = 8884097; em[22] = 8; em[23] = 0; /* 21: pointer.func */
    em[24] = 1; em[25] = 8; em[26] = 1; /* 24: pointer.struct.ec_extra_data_st */
    	em[27] = 29; em[28] = 0; 
    em[29] = 0; em[30] = 40; em[31] = 5; /* 29: struct.ec_extra_data_st */
    	em[32] = 24; em[33] = 0; 
    	em[34] = 42; em[35] = 8; 
    	em[36] = 21; em[37] = 16; 
    	em[38] = 45; em[39] = 24; 
    	em[40] = 45; em[41] = 32; 
    em[42] = 0; em[43] = 8; em[44] = 0; /* 42: pointer.void */
    em[45] = 8884097; em[46] = 8; em[47] = 0; /* 45: pointer.func */
    em[48] = 1; em[49] = 8; em[50] = 1; /* 48: pointer.struct.ec_extra_data_st */
    	em[51] = 29; em[52] = 0; 
    em[53] = 0; em[54] = 24; em[55] = 1; /* 53: struct.bignum_st */
    	em[56] = 58; em[57] = 0; 
    em[58] = 8884099; em[59] = 8; em[60] = 2; /* 58: pointer_to_array_of_pointers_to_stack */
    	em[61] = 12; em[62] = 0; 
    	em[63] = 15; em[64] = 12; 
    em[65] = 0; em[66] = 40; em[67] = 5; /* 65: struct.ec_extra_data_st */
    	em[68] = 78; em[69] = 0; 
    	em[70] = 42; em[71] = 8; 
    	em[72] = 21; em[73] = 16; 
    	em[74] = 45; em[75] = 24; 
    	em[76] = 45; em[77] = 32; 
    em[78] = 1; em[79] = 8; em[80] = 1; /* 78: pointer.struct.ec_extra_data_st */
    	em[81] = 65; em[82] = 0; 
    em[83] = 8884097; em[84] = 8; em[85] = 0; /* 83: pointer.func */
    em[86] = 8884097; em[87] = 8; em[88] = 0; /* 86: pointer.func */
    em[89] = 8884097; em[90] = 8; em[91] = 0; /* 89: pointer.func */
    em[92] = 8884097; em[93] = 8; em[94] = 0; /* 92: pointer.func */
    em[95] = 8884097; em[96] = 8; em[97] = 0; /* 95: pointer.func */
    em[98] = 8884097; em[99] = 8; em[100] = 0; /* 98: pointer.func */
    em[101] = 1; em[102] = 8; em[103] = 1; /* 101: pointer.struct.ec_point_st */
    	em[104] = 106; em[105] = 0; 
    em[106] = 0; em[107] = 88; em[108] = 4; /* 106: struct.ec_point_st */
    	em[109] = 117; em[110] = 0; 
    	em[111] = 271; em[112] = 8; 
    	em[113] = 271; em[114] = 32; 
    	em[115] = 271; em[116] = 56; 
    em[117] = 1; em[118] = 8; em[119] = 1; /* 117: pointer.struct.ec_method_st */
    	em[120] = 122; em[121] = 0; 
    em[122] = 0; em[123] = 304; em[124] = 37; /* 122: struct.ec_method_st */
    	em[125] = 199; em[126] = 8; 
    	em[127] = 202; em[128] = 16; 
    	em[129] = 202; em[130] = 24; 
    	em[131] = 205; em[132] = 32; 
    	em[133] = 208; em[134] = 40; 
    	em[135] = 211; em[136] = 48; 
    	em[137] = 214; em[138] = 56; 
    	em[139] = 217; em[140] = 64; 
    	em[141] = 220; em[142] = 72; 
    	em[143] = 223; em[144] = 80; 
    	em[145] = 223; em[146] = 88; 
    	em[147] = 226; em[148] = 96; 
    	em[149] = 229; em[150] = 104; 
    	em[151] = 232; em[152] = 112; 
    	em[153] = 235; em[154] = 120; 
    	em[155] = 238; em[156] = 128; 
    	em[157] = 241; em[158] = 136; 
    	em[159] = 244; em[160] = 144; 
    	em[161] = 247; em[162] = 152; 
    	em[163] = 250; em[164] = 160; 
    	em[165] = 253; em[166] = 168; 
    	em[167] = 256; em[168] = 176; 
    	em[169] = 259; em[170] = 184; 
    	em[171] = 98; em[172] = 192; 
    	em[173] = 95; em[174] = 200; 
    	em[175] = 262; em[176] = 208; 
    	em[177] = 259; em[178] = 216; 
    	em[179] = 265; em[180] = 224; 
    	em[181] = 92; em[182] = 232; 
    	em[183] = 89; em[184] = 240; 
    	em[185] = 214; em[186] = 248; 
    	em[187] = 86; em[188] = 256; 
    	em[189] = 268; em[190] = 264; 
    	em[191] = 86; em[192] = 272; 
    	em[193] = 268; em[194] = 280; 
    	em[195] = 268; em[196] = 288; 
    	em[197] = 83; em[198] = 296; 
    em[199] = 8884097; em[200] = 8; em[201] = 0; /* 199: pointer.func */
    em[202] = 8884097; em[203] = 8; em[204] = 0; /* 202: pointer.func */
    em[205] = 8884097; em[206] = 8; em[207] = 0; /* 205: pointer.func */
    em[208] = 8884097; em[209] = 8; em[210] = 0; /* 208: pointer.func */
    em[211] = 8884097; em[212] = 8; em[213] = 0; /* 211: pointer.func */
    em[214] = 8884097; em[215] = 8; em[216] = 0; /* 214: pointer.func */
    em[217] = 8884097; em[218] = 8; em[219] = 0; /* 217: pointer.func */
    em[220] = 8884097; em[221] = 8; em[222] = 0; /* 220: pointer.func */
    em[223] = 8884097; em[224] = 8; em[225] = 0; /* 223: pointer.func */
    em[226] = 8884097; em[227] = 8; em[228] = 0; /* 226: pointer.func */
    em[229] = 8884097; em[230] = 8; em[231] = 0; /* 229: pointer.func */
    em[232] = 8884097; em[233] = 8; em[234] = 0; /* 232: pointer.func */
    em[235] = 8884097; em[236] = 8; em[237] = 0; /* 235: pointer.func */
    em[238] = 8884097; em[239] = 8; em[240] = 0; /* 238: pointer.func */
    em[241] = 8884097; em[242] = 8; em[243] = 0; /* 241: pointer.func */
    em[244] = 8884097; em[245] = 8; em[246] = 0; /* 244: pointer.func */
    em[247] = 8884097; em[248] = 8; em[249] = 0; /* 247: pointer.func */
    em[250] = 8884097; em[251] = 8; em[252] = 0; /* 250: pointer.func */
    em[253] = 8884097; em[254] = 8; em[255] = 0; /* 253: pointer.func */
    em[256] = 8884097; em[257] = 8; em[258] = 0; /* 256: pointer.func */
    em[259] = 8884097; em[260] = 8; em[261] = 0; /* 259: pointer.func */
    em[262] = 8884097; em[263] = 8; em[264] = 0; /* 262: pointer.func */
    em[265] = 8884097; em[266] = 8; em[267] = 0; /* 265: pointer.func */
    em[268] = 8884097; em[269] = 8; em[270] = 0; /* 268: pointer.func */
    em[271] = 0; em[272] = 24; em[273] = 1; /* 271: struct.bignum_st */
    	em[274] = 276; em[275] = 0; 
    em[276] = 8884099; em[277] = 8; em[278] = 2; /* 276: pointer_to_array_of_pointers_to_stack */
    	em[279] = 12; em[280] = 0; 
    	em[281] = 15; em[282] = 12; 
    em[283] = 8884097; em[284] = 8; em[285] = 0; /* 283: pointer.func */
    em[286] = 8884097; em[287] = 8; em[288] = 0; /* 286: pointer.func */
    em[289] = 8884097; em[290] = 8; em[291] = 0; /* 289: pointer.func */
    em[292] = 8884097; em[293] = 8; em[294] = 0; /* 292: pointer.func */
    em[295] = 0; em[296] = 56; em[297] = 4; /* 295: struct.ec_key_st */
    	em[298] = 306; em[299] = 8; 
    	em[300] = 101; em[301] = 16; 
    	em[302] = 511; em[303] = 24; 
    	em[304] = 516; em[305] = 48; 
    em[306] = 1; em[307] = 8; em[308] = 1; /* 306: pointer.struct.ec_group_st */
    	em[309] = 311; em[310] = 0; 
    em[311] = 0; em[312] = 232; em[313] = 12; /* 311: struct.ec_group_st */
    	em[314] = 338; em[315] = 0; 
    	em[316] = 498; em[317] = 8; 
    	em[318] = 53; em[319] = 16; 
    	em[320] = 53; em[321] = 40; 
    	em[322] = 503; em[323] = 80; 
    	em[324] = 48; em[325] = 96; 
    	em[326] = 53; em[327] = 104; 
    	em[328] = 53; em[329] = 152; 
    	em[330] = 53; em[331] = 176; 
    	em[332] = 42; em[333] = 208; 
    	em[334] = 42; em[335] = 216; 
    	em[336] = 18; em[337] = 224; 
    em[338] = 1; em[339] = 8; em[340] = 1; /* 338: pointer.struct.ec_method_st */
    	em[341] = 343; em[342] = 0; 
    em[343] = 0; em[344] = 304; em[345] = 37; /* 343: struct.ec_method_st */
    	em[346] = 420; em[347] = 8; 
    	em[348] = 423; em[349] = 16; 
    	em[350] = 423; em[351] = 24; 
    	em[352] = 426; em[353] = 32; 
    	em[354] = 429; em[355] = 40; 
    	em[356] = 432; em[357] = 48; 
    	em[358] = 435; em[359] = 56; 
    	em[360] = 438; em[361] = 64; 
    	em[362] = 441; em[363] = 72; 
    	em[364] = 289; em[365] = 80; 
    	em[366] = 289; em[367] = 88; 
    	em[368] = 444; em[369] = 96; 
    	em[370] = 447; em[371] = 104; 
    	em[372] = 450; em[373] = 112; 
    	em[374] = 453; em[375] = 120; 
    	em[376] = 456; em[377] = 128; 
    	em[378] = 459; em[379] = 136; 
    	em[380] = 462; em[381] = 144; 
    	em[382] = 292; em[383] = 152; 
    	em[384] = 465; em[385] = 160; 
    	em[386] = 286; em[387] = 168; 
    	em[388] = 468; em[389] = 176; 
    	em[390] = 471; em[391] = 184; 
    	em[392] = 283; em[393] = 192; 
    	em[394] = 474; em[395] = 200; 
    	em[396] = 477; em[397] = 208; 
    	em[398] = 471; em[399] = 216; 
    	em[400] = 480; em[401] = 224; 
    	em[402] = 483; em[403] = 232; 
    	em[404] = 486; em[405] = 240; 
    	em[406] = 435; em[407] = 248; 
    	em[408] = 489; em[409] = 256; 
    	em[410] = 492; em[411] = 264; 
    	em[412] = 489; em[413] = 272; 
    	em[414] = 492; em[415] = 280; 
    	em[416] = 492; em[417] = 288; 
    	em[418] = 495; em[419] = 296; 
    em[420] = 8884097; em[421] = 8; em[422] = 0; /* 420: pointer.func */
    em[423] = 8884097; em[424] = 8; em[425] = 0; /* 423: pointer.func */
    em[426] = 8884097; em[427] = 8; em[428] = 0; /* 426: pointer.func */
    em[429] = 8884097; em[430] = 8; em[431] = 0; /* 429: pointer.func */
    em[432] = 8884097; em[433] = 8; em[434] = 0; /* 432: pointer.func */
    em[435] = 8884097; em[436] = 8; em[437] = 0; /* 435: pointer.func */
    em[438] = 8884097; em[439] = 8; em[440] = 0; /* 438: pointer.func */
    em[441] = 8884097; em[442] = 8; em[443] = 0; /* 441: pointer.func */
    em[444] = 8884097; em[445] = 8; em[446] = 0; /* 444: pointer.func */
    em[447] = 8884097; em[448] = 8; em[449] = 0; /* 447: pointer.func */
    em[450] = 8884097; em[451] = 8; em[452] = 0; /* 450: pointer.func */
    em[453] = 8884097; em[454] = 8; em[455] = 0; /* 453: pointer.func */
    em[456] = 8884097; em[457] = 8; em[458] = 0; /* 456: pointer.func */
    em[459] = 8884097; em[460] = 8; em[461] = 0; /* 459: pointer.func */
    em[462] = 8884097; em[463] = 8; em[464] = 0; /* 462: pointer.func */
    em[465] = 8884097; em[466] = 8; em[467] = 0; /* 465: pointer.func */
    em[468] = 8884097; em[469] = 8; em[470] = 0; /* 468: pointer.func */
    em[471] = 8884097; em[472] = 8; em[473] = 0; /* 471: pointer.func */
    em[474] = 8884097; em[475] = 8; em[476] = 0; /* 474: pointer.func */
    em[477] = 8884097; em[478] = 8; em[479] = 0; /* 477: pointer.func */
    em[480] = 8884097; em[481] = 8; em[482] = 0; /* 480: pointer.func */
    em[483] = 8884097; em[484] = 8; em[485] = 0; /* 483: pointer.func */
    em[486] = 8884097; em[487] = 8; em[488] = 0; /* 486: pointer.func */
    em[489] = 8884097; em[490] = 8; em[491] = 0; /* 489: pointer.func */
    em[492] = 8884097; em[493] = 8; em[494] = 0; /* 492: pointer.func */
    em[495] = 8884097; em[496] = 8; em[497] = 0; /* 495: pointer.func */
    em[498] = 1; em[499] = 8; em[500] = 1; /* 498: pointer.struct.ec_point_st */
    	em[501] = 106; em[502] = 0; 
    em[503] = 1; em[504] = 8; em[505] = 1; /* 503: pointer.unsigned char */
    	em[506] = 508; em[507] = 0; 
    em[508] = 0; em[509] = 1; em[510] = 0; /* 508: unsigned char */
    em[511] = 1; em[512] = 8; em[513] = 1; /* 511: pointer.struct.bignum_st */
    	em[514] = 0; em[515] = 0; 
    em[516] = 1; em[517] = 8; em[518] = 1; /* 516: pointer.struct.ec_extra_data_st */
    	em[519] = 65; em[520] = 0; 
    em[521] = 1; em[522] = 8; em[523] = 1; /* 521: pointer.struct.ec_key_st */
    	em[524] = 295; em[525] = 0; 
    args_addr->arg_entity_index[0] = 521;
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

