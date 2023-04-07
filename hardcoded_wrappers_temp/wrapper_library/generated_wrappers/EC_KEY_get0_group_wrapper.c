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

const EC_GROUP * bb_EC_KEY_get0_group(const EC_KEY * arg_a);

const EC_GROUP * EC_KEY_get0_group(const EC_KEY * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EC_KEY_get0_group called %lu\n", in_lib);
    if (!in_lib)
        return bb_EC_KEY_get0_group(arg_a);
    else {
        const EC_GROUP * (*orig_EC_KEY_get0_group)(const EC_KEY *);
        orig_EC_KEY_get0_group = dlsym(RTLD_NEXT, "EC_KEY_get0_group");
        return orig_EC_KEY_get0_group(arg_a);
    }
}

const EC_GROUP * bb_EC_KEY_get0_group(const EC_KEY * arg_a) 
{
    const EC_GROUP * ret;

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
    em[55] = 1; em[56] = 8; em[57] = 1; /* 55: pointer.struct.ec_key_st */
    	em[58] = 60; em[59] = 0; 
    em[60] = 0; em[61] = 56; em[62] = 4; /* 60: struct.ec_key_st */
    	em[63] = 71; em[64] = 8; 
    	em[65] = 521; em[66] = 16; 
    	em[67] = 50; em[68] = 24; 
    	em[69] = 27; em[70] = 48; 
    em[71] = 1; em[72] = 8; em[73] = 1; /* 71: pointer.struct.ec_group_st */
    	em[74] = 76; em[75] = 0; 
    em[76] = 0; em[77] = 232; em[78] = 12; /* 76: struct.ec_group_st */
    	em[79] = 103; em[80] = 0; 
    	em[81] = 275; em[82] = 8; 
    	em[83] = 475; em[84] = 16; 
    	em[85] = 475; em[86] = 40; 
    	em[87] = 487; em[88] = 80; 
    	em[89] = 495; em[90] = 96; 
    	em[91] = 475; em[92] = 104; 
    	em[93] = 475; em[94] = 152; 
    	em[95] = 475; em[96] = 176; 
    	em[97] = 18; em[98] = 208; 
    	em[99] = 18; em[100] = 216; 
    	em[101] = 518; em[102] = 224; 
    em[103] = 1; em[104] = 8; em[105] = 1; /* 103: pointer.struct.ec_method_st */
    	em[106] = 108; em[107] = 0; 
    em[108] = 0; em[109] = 304; em[110] = 37; /* 108: struct.ec_method_st */
    	em[111] = 185; em[112] = 8; 
    	em[113] = 188; em[114] = 16; 
    	em[115] = 188; em[116] = 24; 
    	em[117] = 191; em[118] = 32; 
    	em[119] = 194; em[120] = 40; 
    	em[121] = 197; em[122] = 48; 
    	em[123] = 200; em[124] = 56; 
    	em[125] = 203; em[126] = 64; 
    	em[127] = 206; em[128] = 72; 
    	em[129] = 209; em[130] = 80; 
    	em[131] = 209; em[132] = 88; 
    	em[133] = 212; em[134] = 96; 
    	em[135] = 215; em[136] = 104; 
    	em[137] = 218; em[138] = 112; 
    	em[139] = 221; em[140] = 120; 
    	em[141] = 224; em[142] = 128; 
    	em[143] = 227; em[144] = 136; 
    	em[145] = 230; em[146] = 144; 
    	em[147] = 233; em[148] = 152; 
    	em[149] = 236; em[150] = 160; 
    	em[151] = 239; em[152] = 168; 
    	em[153] = 242; em[154] = 176; 
    	em[155] = 245; em[156] = 184; 
    	em[157] = 248; em[158] = 192; 
    	em[159] = 251; em[160] = 200; 
    	em[161] = 254; em[162] = 208; 
    	em[163] = 245; em[164] = 216; 
    	em[165] = 257; em[166] = 224; 
    	em[167] = 260; em[168] = 232; 
    	em[169] = 263; em[170] = 240; 
    	em[171] = 200; em[172] = 248; 
    	em[173] = 266; em[174] = 256; 
    	em[175] = 269; em[176] = 264; 
    	em[177] = 266; em[178] = 272; 
    	em[179] = 269; em[180] = 280; 
    	em[181] = 269; em[182] = 288; 
    	em[183] = 272; em[184] = 296; 
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
    em[248] = 8884097; em[249] = 8; em[250] = 0; /* 248: pointer.func */
    em[251] = 8884097; em[252] = 8; em[253] = 0; /* 251: pointer.func */
    em[254] = 8884097; em[255] = 8; em[256] = 0; /* 254: pointer.func */
    em[257] = 8884097; em[258] = 8; em[259] = 0; /* 257: pointer.func */
    em[260] = 8884097; em[261] = 8; em[262] = 0; /* 260: pointer.func */
    em[263] = 8884097; em[264] = 8; em[265] = 0; /* 263: pointer.func */
    em[266] = 8884097; em[267] = 8; em[268] = 0; /* 266: pointer.func */
    em[269] = 8884097; em[270] = 8; em[271] = 0; /* 269: pointer.func */
    em[272] = 8884097; em[273] = 8; em[274] = 0; /* 272: pointer.func */
    em[275] = 1; em[276] = 8; em[277] = 1; /* 275: pointer.struct.ec_point_st */
    	em[278] = 280; em[279] = 0; 
    em[280] = 0; em[281] = 88; em[282] = 4; /* 280: struct.ec_point_st */
    	em[283] = 291; em[284] = 0; 
    	em[285] = 463; em[286] = 8; 
    	em[287] = 463; em[288] = 32; 
    	em[289] = 463; em[290] = 56; 
    em[291] = 1; em[292] = 8; em[293] = 1; /* 291: pointer.struct.ec_method_st */
    	em[294] = 296; em[295] = 0; 
    em[296] = 0; em[297] = 304; em[298] = 37; /* 296: struct.ec_method_st */
    	em[299] = 373; em[300] = 8; 
    	em[301] = 376; em[302] = 16; 
    	em[303] = 376; em[304] = 24; 
    	em[305] = 379; em[306] = 32; 
    	em[307] = 382; em[308] = 40; 
    	em[309] = 385; em[310] = 48; 
    	em[311] = 388; em[312] = 56; 
    	em[313] = 391; em[314] = 64; 
    	em[315] = 394; em[316] = 72; 
    	em[317] = 397; em[318] = 80; 
    	em[319] = 397; em[320] = 88; 
    	em[321] = 400; em[322] = 96; 
    	em[323] = 403; em[324] = 104; 
    	em[325] = 406; em[326] = 112; 
    	em[327] = 409; em[328] = 120; 
    	em[329] = 412; em[330] = 128; 
    	em[331] = 415; em[332] = 136; 
    	em[333] = 418; em[334] = 144; 
    	em[335] = 421; em[336] = 152; 
    	em[337] = 424; em[338] = 160; 
    	em[339] = 427; em[340] = 168; 
    	em[341] = 430; em[342] = 176; 
    	em[343] = 433; em[344] = 184; 
    	em[345] = 436; em[346] = 192; 
    	em[347] = 439; em[348] = 200; 
    	em[349] = 442; em[350] = 208; 
    	em[351] = 433; em[352] = 216; 
    	em[353] = 445; em[354] = 224; 
    	em[355] = 448; em[356] = 232; 
    	em[357] = 451; em[358] = 240; 
    	em[359] = 388; em[360] = 248; 
    	em[361] = 454; em[362] = 256; 
    	em[363] = 457; em[364] = 264; 
    	em[365] = 454; em[366] = 272; 
    	em[367] = 457; em[368] = 280; 
    	em[369] = 457; em[370] = 288; 
    	em[371] = 460; em[372] = 296; 
    em[373] = 8884097; em[374] = 8; em[375] = 0; /* 373: pointer.func */
    em[376] = 8884097; em[377] = 8; em[378] = 0; /* 376: pointer.func */
    em[379] = 8884097; em[380] = 8; em[381] = 0; /* 379: pointer.func */
    em[382] = 8884097; em[383] = 8; em[384] = 0; /* 382: pointer.func */
    em[385] = 8884097; em[386] = 8; em[387] = 0; /* 385: pointer.func */
    em[388] = 8884097; em[389] = 8; em[390] = 0; /* 388: pointer.func */
    em[391] = 8884097; em[392] = 8; em[393] = 0; /* 391: pointer.func */
    em[394] = 8884097; em[395] = 8; em[396] = 0; /* 394: pointer.func */
    em[397] = 8884097; em[398] = 8; em[399] = 0; /* 397: pointer.func */
    em[400] = 8884097; em[401] = 8; em[402] = 0; /* 400: pointer.func */
    em[403] = 8884097; em[404] = 8; em[405] = 0; /* 403: pointer.func */
    em[406] = 8884097; em[407] = 8; em[408] = 0; /* 406: pointer.func */
    em[409] = 8884097; em[410] = 8; em[411] = 0; /* 409: pointer.func */
    em[412] = 8884097; em[413] = 8; em[414] = 0; /* 412: pointer.func */
    em[415] = 8884097; em[416] = 8; em[417] = 0; /* 415: pointer.func */
    em[418] = 8884097; em[419] = 8; em[420] = 0; /* 418: pointer.func */
    em[421] = 8884097; em[422] = 8; em[423] = 0; /* 421: pointer.func */
    em[424] = 8884097; em[425] = 8; em[426] = 0; /* 424: pointer.func */
    em[427] = 8884097; em[428] = 8; em[429] = 0; /* 427: pointer.func */
    em[430] = 8884097; em[431] = 8; em[432] = 0; /* 430: pointer.func */
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
    em[463] = 0; em[464] = 24; em[465] = 1; /* 463: struct.bignum_st */
    	em[466] = 468; em[467] = 0; 
    em[468] = 8884099; em[469] = 8; em[470] = 2; /* 468: pointer_to_array_of_pointers_to_stack */
    	em[471] = 44; em[472] = 0; 
    	em[473] = 47; em[474] = 12; 
    em[475] = 0; em[476] = 24; em[477] = 1; /* 475: struct.bignum_st */
    	em[478] = 480; em[479] = 0; 
    em[480] = 8884099; em[481] = 8; em[482] = 2; /* 480: pointer_to_array_of_pointers_to_stack */
    	em[483] = 44; em[484] = 0; 
    	em[485] = 47; em[486] = 12; 
    em[487] = 1; em[488] = 8; em[489] = 1; /* 487: pointer.unsigned char */
    	em[490] = 492; em[491] = 0; 
    em[492] = 0; em[493] = 1; em[494] = 0; /* 492: unsigned char */
    em[495] = 1; em[496] = 8; em[497] = 1; /* 495: pointer.struct.ec_extra_data_st */
    	em[498] = 500; em[499] = 0; 
    em[500] = 0; em[501] = 40; em[502] = 5; /* 500: struct.ec_extra_data_st */
    	em[503] = 513; em[504] = 0; 
    	em[505] = 18; em[506] = 8; 
    	em[507] = 21; em[508] = 16; 
    	em[509] = 24; em[510] = 24; 
    	em[511] = 24; em[512] = 32; 
    em[513] = 1; em[514] = 8; em[515] = 1; /* 513: pointer.struct.ec_extra_data_st */
    	em[516] = 500; em[517] = 0; 
    em[518] = 8884097; em[519] = 8; em[520] = 0; /* 518: pointer.func */
    em[521] = 1; em[522] = 8; em[523] = 1; /* 521: pointer.struct.ec_point_st */
    	em[524] = 280; em[525] = 0; 
    em[526] = 1; em[527] = 8; em[528] = 1; /* 526: pointer.struct.ec_group_st */
    	em[529] = 76; em[530] = 0; 
    args_addr->arg_entity_index[0] = 55;
    args_addr->ret_entity_index = 526;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const EC_KEY * new_arg_a = *((const EC_KEY * *)new_args->args[0]);

    const EC_GROUP * *new_ret_ptr = (const EC_GROUP * *)new_args->ret;

    const EC_GROUP * (*orig_EC_KEY_get0_group)(const EC_KEY *);
    orig_EC_KEY_get0_group = dlsym(RTLD_NEXT, "EC_KEY_get0_group");
    *new_ret_ptr = (*orig_EC_KEY_get0_group)(new_arg_a);

    syscall(889);

    free(args_addr);

    return ret;
}

