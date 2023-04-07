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

int bb_X509_check_private_key(X509 * arg_a,EVP_PKEY * arg_b);

int X509_check_private_key(X509 * arg_a,EVP_PKEY * arg_b) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_check_private_key called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_check_private_key(arg_a,arg_b);
    else {
        int (*orig_X509_check_private_key)(X509 *,EVP_PKEY *);
        orig_X509_check_private_key = dlsym(RTLD_NEXT, "X509_check_private_key");
        return orig_X509_check_private_key(arg_a,arg_b);
    }
}

int bb_X509_check_private_key(X509 * arg_a,EVP_PKEY * arg_b) 
{
    int ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 1; em[1] = 8; em[2] = 1; /* 0: pointer.struct.ec_key_st */
    	em[3] = 5; em[4] = 0; 
    em[5] = 0; em[6] = 56; em[7] = 4; /* 5: struct.ec_key_st */
    	em[8] = 16; em[9] = 8; 
    	em[10] = 481; em[11] = 16; 
    	em[12] = 486; em[13] = 24; 
    	em[14] = 503; em[15] = 48; 
    em[16] = 1; em[17] = 8; em[18] = 1; /* 16: pointer.struct.ec_group_st */
    	em[19] = 21; em[20] = 0; 
    em[21] = 0; em[22] = 232; em[23] = 12; /* 21: struct.ec_group_st */
    	em[24] = 48; em[25] = 0; 
    	em[26] = 220; em[27] = 8; 
    	em[28] = 426; em[29] = 16; 
    	em[30] = 426; em[31] = 40; 
    	em[32] = 438; em[33] = 80; 
    	em[34] = 446; em[35] = 96; 
    	em[36] = 426; em[37] = 104; 
    	em[38] = 426; em[39] = 152; 
    	em[40] = 426; em[41] = 176; 
    	em[42] = 469; em[43] = 208; 
    	em[44] = 469; em[45] = 216; 
    	em[46] = 478; em[47] = 224; 
    em[48] = 1; em[49] = 8; em[50] = 1; /* 48: pointer.struct.ec_method_st */
    	em[51] = 53; em[52] = 0; 
    em[53] = 0; em[54] = 304; em[55] = 37; /* 53: struct.ec_method_st */
    	em[56] = 130; em[57] = 8; 
    	em[58] = 133; em[59] = 16; 
    	em[60] = 133; em[61] = 24; 
    	em[62] = 136; em[63] = 32; 
    	em[64] = 139; em[65] = 40; 
    	em[66] = 142; em[67] = 48; 
    	em[68] = 145; em[69] = 56; 
    	em[70] = 148; em[71] = 64; 
    	em[72] = 151; em[73] = 72; 
    	em[74] = 154; em[75] = 80; 
    	em[76] = 154; em[77] = 88; 
    	em[78] = 157; em[79] = 96; 
    	em[80] = 160; em[81] = 104; 
    	em[82] = 163; em[83] = 112; 
    	em[84] = 166; em[85] = 120; 
    	em[86] = 169; em[87] = 128; 
    	em[88] = 172; em[89] = 136; 
    	em[90] = 175; em[91] = 144; 
    	em[92] = 178; em[93] = 152; 
    	em[94] = 181; em[95] = 160; 
    	em[96] = 184; em[97] = 168; 
    	em[98] = 187; em[99] = 176; 
    	em[100] = 190; em[101] = 184; 
    	em[102] = 193; em[103] = 192; 
    	em[104] = 196; em[105] = 200; 
    	em[106] = 199; em[107] = 208; 
    	em[108] = 190; em[109] = 216; 
    	em[110] = 202; em[111] = 224; 
    	em[112] = 205; em[113] = 232; 
    	em[114] = 208; em[115] = 240; 
    	em[116] = 145; em[117] = 248; 
    	em[118] = 211; em[119] = 256; 
    	em[120] = 214; em[121] = 264; 
    	em[122] = 211; em[123] = 272; 
    	em[124] = 214; em[125] = 280; 
    	em[126] = 214; em[127] = 288; 
    	em[128] = 217; em[129] = 296; 
    em[130] = 8884097; em[131] = 8; em[132] = 0; /* 130: pointer.func */
    em[133] = 8884097; em[134] = 8; em[135] = 0; /* 133: pointer.func */
    em[136] = 8884097; em[137] = 8; em[138] = 0; /* 136: pointer.func */
    em[139] = 8884097; em[140] = 8; em[141] = 0; /* 139: pointer.func */
    em[142] = 8884097; em[143] = 8; em[144] = 0; /* 142: pointer.func */
    em[145] = 8884097; em[146] = 8; em[147] = 0; /* 145: pointer.func */
    em[148] = 8884097; em[149] = 8; em[150] = 0; /* 148: pointer.func */
    em[151] = 8884097; em[152] = 8; em[153] = 0; /* 151: pointer.func */
    em[154] = 8884097; em[155] = 8; em[156] = 0; /* 154: pointer.func */
    em[157] = 8884097; em[158] = 8; em[159] = 0; /* 157: pointer.func */
    em[160] = 8884097; em[161] = 8; em[162] = 0; /* 160: pointer.func */
    em[163] = 8884097; em[164] = 8; em[165] = 0; /* 163: pointer.func */
    em[166] = 8884097; em[167] = 8; em[168] = 0; /* 166: pointer.func */
    em[169] = 8884097; em[170] = 8; em[171] = 0; /* 169: pointer.func */
    em[172] = 8884097; em[173] = 8; em[174] = 0; /* 172: pointer.func */
    em[175] = 8884097; em[176] = 8; em[177] = 0; /* 175: pointer.func */
    em[178] = 8884097; em[179] = 8; em[180] = 0; /* 178: pointer.func */
    em[181] = 8884097; em[182] = 8; em[183] = 0; /* 181: pointer.func */
    em[184] = 8884097; em[185] = 8; em[186] = 0; /* 184: pointer.func */
    em[187] = 8884097; em[188] = 8; em[189] = 0; /* 187: pointer.func */
    em[190] = 8884097; em[191] = 8; em[192] = 0; /* 190: pointer.func */
    em[193] = 8884097; em[194] = 8; em[195] = 0; /* 193: pointer.func */
    em[196] = 8884097; em[197] = 8; em[198] = 0; /* 196: pointer.func */
    em[199] = 8884097; em[200] = 8; em[201] = 0; /* 199: pointer.func */
    em[202] = 8884097; em[203] = 8; em[204] = 0; /* 202: pointer.func */
    em[205] = 8884097; em[206] = 8; em[207] = 0; /* 205: pointer.func */
    em[208] = 8884097; em[209] = 8; em[210] = 0; /* 208: pointer.func */
    em[211] = 8884097; em[212] = 8; em[213] = 0; /* 211: pointer.func */
    em[214] = 8884097; em[215] = 8; em[216] = 0; /* 214: pointer.func */
    em[217] = 8884097; em[218] = 8; em[219] = 0; /* 217: pointer.func */
    em[220] = 1; em[221] = 8; em[222] = 1; /* 220: pointer.struct.ec_point_st */
    	em[223] = 225; em[224] = 0; 
    em[225] = 0; em[226] = 88; em[227] = 4; /* 225: struct.ec_point_st */
    	em[228] = 236; em[229] = 0; 
    	em[230] = 408; em[231] = 8; 
    	em[232] = 408; em[233] = 32; 
    	em[234] = 408; em[235] = 56; 
    em[236] = 1; em[237] = 8; em[238] = 1; /* 236: pointer.struct.ec_method_st */
    	em[239] = 241; em[240] = 0; 
    em[241] = 0; em[242] = 304; em[243] = 37; /* 241: struct.ec_method_st */
    	em[244] = 318; em[245] = 8; 
    	em[246] = 321; em[247] = 16; 
    	em[248] = 321; em[249] = 24; 
    	em[250] = 324; em[251] = 32; 
    	em[252] = 327; em[253] = 40; 
    	em[254] = 330; em[255] = 48; 
    	em[256] = 333; em[257] = 56; 
    	em[258] = 336; em[259] = 64; 
    	em[260] = 339; em[261] = 72; 
    	em[262] = 342; em[263] = 80; 
    	em[264] = 342; em[265] = 88; 
    	em[266] = 345; em[267] = 96; 
    	em[268] = 348; em[269] = 104; 
    	em[270] = 351; em[271] = 112; 
    	em[272] = 354; em[273] = 120; 
    	em[274] = 357; em[275] = 128; 
    	em[276] = 360; em[277] = 136; 
    	em[278] = 363; em[279] = 144; 
    	em[280] = 366; em[281] = 152; 
    	em[282] = 369; em[283] = 160; 
    	em[284] = 372; em[285] = 168; 
    	em[286] = 375; em[287] = 176; 
    	em[288] = 378; em[289] = 184; 
    	em[290] = 381; em[291] = 192; 
    	em[292] = 384; em[293] = 200; 
    	em[294] = 387; em[295] = 208; 
    	em[296] = 378; em[297] = 216; 
    	em[298] = 390; em[299] = 224; 
    	em[300] = 393; em[301] = 232; 
    	em[302] = 396; em[303] = 240; 
    	em[304] = 333; em[305] = 248; 
    	em[306] = 399; em[307] = 256; 
    	em[308] = 402; em[309] = 264; 
    	em[310] = 399; em[311] = 272; 
    	em[312] = 402; em[313] = 280; 
    	em[314] = 402; em[315] = 288; 
    	em[316] = 405; em[317] = 296; 
    em[318] = 8884097; em[319] = 8; em[320] = 0; /* 318: pointer.func */
    em[321] = 8884097; em[322] = 8; em[323] = 0; /* 321: pointer.func */
    em[324] = 8884097; em[325] = 8; em[326] = 0; /* 324: pointer.func */
    em[327] = 8884097; em[328] = 8; em[329] = 0; /* 327: pointer.func */
    em[330] = 8884097; em[331] = 8; em[332] = 0; /* 330: pointer.func */
    em[333] = 8884097; em[334] = 8; em[335] = 0; /* 333: pointer.func */
    em[336] = 8884097; em[337] = 8; em[338] = 0; /* 336: pointer.func */
    em[339] = 8884097; em[340] = 8; em[341] = 0; /* 339: pointer.func */
    em[342] = 8884097; em[343] = 8; em[344] = 0; /* 342: pointer.func */
    em[345] = 8884097; em[346] = 8; em[347] = 0; /* 345: pointer.func */
    em[348] = 8884097; em[349] = 8; em[350] = 0; /* 348: pointer.func */
    em[351] = 8884097; em[352] = 8; em[353] = 0; /* 351: pointer.func */
    em[354] = 8884097; em[355] = 8; em[356] = 0; /* 354: pointer.func */
    em[357] = 8884097; em[358] = 8; em[359] = 0; /* 357: pointer.func */
    em[360] = 8884097; em[361] = 8; em[362] = 0; /* 360: pointer.func */
    em[363] = 8884097; em[364] = 8; em[365] = 0; /* 363: pointer.func */
    em[366] = 8884097; em[367] = 8; em[368] = 0; /* 366: pointer.func */
    em[369] = 8884097; em[370] = 8; em[371] = 0; /* 369: pointer.func */
    em[372] = 8884097; em[373] = 8; em[374] = 0; /* 372: pointer.func */
    em[375] = 8884097; em[376] = 8; em[377] = 0; /* 375: pointer.func */
    em[378] = 8884097; em[379] = 8; em[380] = 0; /* 378: pointer.func */
    em[381] = 8884097; em[382] = 8; em[383] = 0; /* 381: pointer.func */
    em[384] = 8884097; em[385] = 8; em[386] = 0; /* 384: pointer.func */
    em[387] = 8884097; em[388] = 8; em[389] = 0; /* 387: pointer.func */
    em[390] = 8884097; em[391] = 8; em[392] = 0; /* 390: pointer.func */
    em[393] = 8884097; em[394] = 8; em[395] = 0; /* 393: pointer.func */
    em[396] = 8884097; em[397] = 8; em[398] = 0; /* 396: pointer.func */
    em[399] = 8884097; em[400] = 8; em[401] = 0; /* 399: pointer.func */
    em[402] = 8884097; em[403] = 8; em[404] = 0; /* 402: pointer.func */
    em[405] = 8884097; em[406] = 8; em[407] = 0; /* 405: pointer.func */
    em[408] = 0; em[409] = 24; em[410] = 1; /* 408: struct.bignum_st */
    	em[411] = 413; em[412] = 0; 
    em[413] = 8884099; em[414] = 8; em[415] = 2; /* 413: pointer_to_array_of_pointers_to_stack */
    	em[416] = 420; em[417] = 0; 
    	em[418] = 423; em[419] = 12; 
    em[420] = 0; em[421] = 8; em[422] = 0; /* 420: long unsigned int */
    em[423] = 0; em[424] = 4; em[425] = 0; /* 423: int */
    em[426] = 0; em[427] = 24; em[428] = 1; /* 426: struct.bignum_st */
    	em[429] = 431; em[430] = 0; 
    em[431] = 8884099; em[432] = 8; em[433] = 2; /* 431: pointer_to_array_of_pointers_to_stack */
    	em[434] = 420; em[435] = 0; 
    	em[436] = 423; em[437] = 12; 
    em[438] = 1; em[439] = 8; em[440] = 1; /* 438: pointer.unsigned char */
    	em[441] = 443; em[442] = 0; 
    em[443] = 0; em[444] = 1; em[445] = 0; /* 443: unsigned char */
    em[446] = 1; em[447] = 8; em[448] = 1; /* 446: pointer.struct.ec_extra_data_st */
    	em[449] = 451; em[450] = 0; 
    em[451] = 0; em[452] = 40; em[453] = 5; /* 451: struct.ec_extra_data_st */
    	em[454] = 464; em[455] = 0; 
    	em[456] = 469; em[457] = 8; 
    	em[458] = 472; em[459] = 16; 
    	em[460] = 475; em[461] = 24; 
    	em[462] = 475; em[463] = 32; 
    em[464] = 1; em[465] = 8; em[466] = 1; /* 464: pointer.struct.ec_extra_data_st */
    	em[467] = 451; em[468] = 0; 
    em[469] = 0; em[470] = 8; em[471] = 0; /* 469: pointer.void */
    em[472] = 8884097; em[473] = 8; em[474] = 0; /* 472: pointer.func */
    em[475] = 8884097; em[476] = 8; em[477] = 0; /* 475: pointer.func */
    em[478] = 8884097; em[479] = 8; em[480] = 0; /* 478: pointer.func */
    em[481] = 1; em[482] = 8; em[483] = 1; /* 481: pointer.struct.ec_point_st */
    	em[484] = 225; em[485] = 0; 
    em[486] = 1; em[487] = 8; em[488] = 1; /* 486: pointer.struct.bignum_st */
    	em[489] = 491; em[490] = 0; 
    em[491] = 0; em[492] = 24; em[493] = 1; /* 491: struct.bignum_st */
    	em[494] = 496; em[495] = 0; 
    em[496] = 8884099; em[497] = 8; em[498] = 2; /* 496: pointer_to_array_of_pointers_to_stack */
    	em[499] = 420; em[500] = 0; 
    	em[501] = 423; em[502] = 12; 
    em[503] = 1; em[504] = 8; em[505] = 1; /* 503: pointer.struct.ec_extra_data_st */
    	em[506] = 508; em[507] = 0; 
    em[508] = 0; em[509] = 40; em[510] = 5; /* 508: struct.ec_extra_data_st */
    	em[511] = 521; em[512] = 0; 
    	em[513] = 469; em[514] = 8; 
    	em[515] = 472; em[516] = 16; 
    	em[517] = 475; em[518] = 24; 
    	em[519] = 475; em[520] = 32; 
    em[521] = 1; em[522] = 8; em[523] = 1; /* 521: pointer.struct.ec_extra_data_st */
    	em[524] = 508; em[525] = 0; 
    em[526] = 1; em[527] = 8; em[528] = 1; /* 526: pointer.struct.dh_st */
    	em[529] = 531; em[530] = 0; 
    em[531] = 0; em[532] = 144; em[533] = 12; /* 531: struct.dh_st */
    	em[534] = 558; em[535] = 8; 
    	em[536] = 558; em[537] = 16; 
    	em[538] = 558; em[539] = 32; 
    	em[540] = 558; em[541] = 40; 
    	em[542] = 575; em[543] = 56; 
    	em[544] = 558; em[545] = 64; 
    	em[546] = 558; em[547] = 72; 
    	em[548] = 438; em[549] = 80; 
    	em[550] = 558; em[551] = 96; 
    	em[552] = 589; em[553] = 112; 
    	em[554] = 624; em[555] = 128; 
    	em[556] = 665; em[557] = 136; 
    em[558] = 1; em[559] = 8; em[560] = 1; /* 558: pointer.struct.bignum_st */
    	em[561] = 563; em[562] = 0; 
    em[563] = 0; em[564] = 24; em[565] = 1; /* 563: struct.bignum_st */
    	em[566] = 568; em[567] = 0; 
    em[568] = 8884099; em[569] = 8; em[570] = 2; /* 568: pointer_to_array_of_pointers_to_stack */
    	em[571] = 420; em[572] = 0; 
    	em[573] = 423; em[574] = 12; 
    em[575] = 1; em[576] = 8; em[577] = 1; /* 575: pointer.struct.bn_mont_ctx_st */
    	em[578] = 580; em[579] = 0; 
    em[580] = 0; em[581] = 96; em[582] = 3; /* 580: struct.bn_mont_ctx_st */
    	em[583] = 563; em[584] = 8; 
    	em[585] = 563; em[586] = 32; 
    	em[587] = 563; em[588] = 56; 
    em[589] = 0; em[590] = 16; em[591] = 1; /* 589: struct.crypto_ex_data_st */
    	em[592] = 594; em[593] = 0; 
    em[594] = 1; em[595] = 8; em[596] = 1; /* 594: pointer.struct.stack_st_void */
    	em[597] = 599; em[598] = 0; 
    em[599] = 0; em[600] = 32; em[601] = 1; /* 599: struct.stack_st_void */
    	em[602] = 604; em[603] = 0; 
    em[604] = 0; em[605] = 32; em[606] = 2; /* 604: struct.stack_st */
    	em[607] = 611; em[608] = 8; 
    	em[609] = 621; em[610] = 24; 
    em[611] = 1; em[612] = 8; em[613] = 1; /* 611: pointer.pointer.char */
    	em[614] = 616; em[615] = 0; 
    em[616] = 1; em[617] = 8; em[618] = 1; /* 616: pointer.char */
    	em[619] = 8884096; em[620] = 0; 
    em[621] = 8884097; em[622] = 8; em[623] = 0; /* 621: pointer.func */
    em[624] = 1; em[625] = 8; em[626] = 1; /* 624: pointer.struct.dh_method */
    	em[627] = 629; em[628] = 0; 
    em[629] = 0; em[630] = 72; em[631] = 8; /* 629: struct.dh_method */
    	em[632] = 648; em[633] = 0; 
    	em[634] = 653; em[635] = 8; 
    	em[636] = 656; em[637] = 16; 
    	em[638] = 659; em[639] = 24; 
    	em[640] = 653; em[641] = 32; 
    	em[642] = 653; em[643] = 40; 
    	em[644] = 616; em[645] = 56; 
    	em[646] = 662; em[647] = 64; 
    em[648] = 1; em[649] = 8; em[650] = 1; /* 648: pointer.char */
    	em[651] = 8884096; em[652] = 0; 
    em[653] = 8884097; em[654] = 8; em[655] = 0; /* 653: pointer.func */
    em[656] = 8884097; em[657] = 8; em[658] = 0; /* 656: pointer.func */
    em[659] = 8884097; em[660] = 8; em[661] = 0; /* 659: pointer.func */
    em[662] = 8884097; em[663] = 8; em[664] = 0; /* 662: pointer.func */
    em[665] = 1; em[666] = 8; em[667] = 1; /* 665: pointer.struct.engine_st */
    	em[668] = 670; em[669] = 0; 
    em[670] = 0; em[671] = 216; em[672] = 24; /* 670: struct.engine_st */
    	em[673] = 648; em[674] = 0; 
    	em[675] = 648; em[676] = 8; 
    	em[677] = 721; em[678] = 16; 
    	em[679] = 776; em[680] = 24; 
    	em[681] = 827; em[682] = 32; 
    	em[683] = 863; em[684] = 40; 
    	em[685] = 880; em[686] = 48; 
    	em[687] = 907; em[688] = 56; 
    	em[689] = 942; em[690] = 64; 
    	em[691] = 950; em[692] = 72; 
    	em[693] = 953; em[694] = 80; 
    	em[695] = 956; em[696] = 88; 
    	em[697] = 959; em[698] = 96; 
    	em[699] = 962; em[700] = 104; 
    	em[701] = 962; em[702] = 112; 
    	em[703] = 962; em[704] = 120; 
    	em[705] = 965; em[706] = 128; 
    	em[707] = 968; em[708] = 136; 
    	em[709] = 968; em[710] = 144; 
    	em[711] = 971; em[712] = 152; 
    	em[713] = 974; em[714] = 160; 
    	em[715] = 986; em[716] = 184; 
    	em[717] = 1008; em[718] = 200; 
    	em[719] = 1008; em[720] = 208; 
    em[721] = 1; em[722] = 8; em[723] = 1; /* 721: pointer.struct.rsa_meth_st */
    	em[724] = 726; em[725] = 0; 
    em[726] = 0; em[727] = 112; em[728] = 13; /* 726: struct.rsa_meth_st */
    	em[729] = 648; em[730] = 0; 
    	em[731] = 755; em[732] = 8; 
    	em[733] = 755; em[734] = 16; 
    	em[735] = 755; em[736] = 24; 
    	em[737] = 755; em[738] = 32; 
    	em[739] = 758; em[740] = 40; 
    	em[741] = 761; em[742] = 48; 
    	em[743] = 764; em[744] = 56; 
    	em[745] = 764; em[746] = 64; 
    	em[747] = 616; em[748] = 80; 
    	em[749] = 767; em[750] = 88; 
    	em[751] = 770; em[752] = 96; 
    	em[753] = 773; em[754] = 104; 
    em[755] = 8884097; em[756] = 8; em[757] = 0; /* 755: pointer.func */
    em[758] = 8884097; em[759] = 8; em[760] = 0; /* 758: pointer.func */
    em[761] = 8884097; em[762] = 8; em[763] = 0; /* 761: pointer.func */
    em[764] = 8884097; em[765] = 8; em[766] = 0; /* 764: pointer.func */
    em[767] = 8884097; em[768] = 8; em[769] = 0; /* 767: pointer.func */
    em[770] = 8884097; em[771] = 8; em[772] = 0; /* 770: pointer.func */
    em[773] = 8884097; em[774] = 8; em[775] = 0; /* 773: pointer.func */
    em[776] = 1; em[777] = 8; em[778] = 1; /* 776: pointer.struct.dsa_method */
    	em[779] = 781; em[780] = 0; 
    em[781] = 0; em[782] = 96; em[783] = 11; /* 781: struct.dsa_method */
    	em[784] = 648; em[785] = 0; 
    	em[786] = 806; em[787] = 8; 
    	em[788] = 809; em[789] = 16; 
    	em[790] = 812; em[791] = 24; 
    	em[792] = 815; em[793] = 32; 
    	em[794] = 818; em[795] = 40; 
    	em[796] = 821; em[797] = 48; 
    	em[798] = 821; em[799] = 56; 
    	em[800] = 616; em[801] = 72; 
    	em[802] = 824; em[803] = 80; 
    	em[804] = 821; em[805] = 88; 
    em[806] = 8884097; em[807] = 8; em[808] = 0; /* 806: pointer.func */
    em[809] = 8884097; em[810] = 8; em[811] = 0; /* 809: pointer.func */
    em[812] = 8884097; em[813] = 8; em[814] = 0; /* 812: pointer.func */
    em[815] = 8884097; em[816] = 8; em[817] = 0; /* 815: pointer.func */
    em[818] = 8884097; em[819] = 8; em[820] = 0; /* 818: pointer.func */
    em[821] = 8884097; em[822] = 8; em[823] = 0; /* 821: pointer.func */
    em[824] = 8884097; em[825] = 8; em[826] = 0; /* 824: pointer.func */
    em[827] = 1; em[828] = 8; em[829] = 1; /* 827: pointer.struct.dh_method */
    	em[830] = 832; em[831] = 0; 
    em[832] = 0; em[833] = 72; em[834] = 8; /* 832: struct.dh_method */
    	em[835] = 648; em[836] = 0; 
    	em[837] = 851; em[838] = 8; 
    	em[839] = 854; em[840] = 16; 
    	em[841] = 857; em[842] = 24; 
    	em[843] = 851; em[844] = 32; 
    	em[845] = 851; em[846] = 40; 
    	em[847] = 616; em[848] = 56; 
    	em[849] = 860; em[850] = 64; 
    em[851] = 8884097; em[852] = 8; em[853] = 0; /* 851: pointer.func */
    em[854] = 8884097; em[855] = 8; em[856] = 0; /* 854: pointer.func */
    em[857] = 8884097; em[858] = 8; em[859] = 0; /* 857: pointer.func */
    em[860] = 8884097; em[861] = 8; em[862] = 0; /* 860: pointer.func */
    em[863] = 1; em[864] = 8; em[865] = 1; /* 863: pointer.struct.ecdh_method */
    	em[866] = 868; em[867] = 0; 
    em[868] = 0; em[869] = 32; em[870] = 3; /* 868: struct.ecdh_method */
    	em[871] = 648; em[872] = 0; 
    	em[873] = 877; em[874] = 8; 
    	em[875] = 616; em[876] = 24; 
    em[877] = 8884097; em[878] = 8; em[879] = 0; /* 877: pointer.func */
    em[880] = 1; em[881] = 8; em[882] = 1; /* 880: pointer.struct.ecdsa_method */
    	em[883] = 885; em[884] = 0; 
    em[885] = 0; em[886] = 48; em[887] = 5; /* 885: struct.ecdsa_method */
    	em[888] = 648; em[889] = 0; 
    	em[890] = 898; em[891] = 8; 
    	em[892] = 901; em[893] = 16; 
    	em[894] = 904; em[895] = 24; 
    	em[896] = 616; em[897] = 40; 
    em[898] = 8884097; em[899] = 8; em[900] = 0; /* 898: pointer.func */
    em[901] = 8884097; em[902] = 8; em[903] = 0; /* 901: pointer.func */
    em[904] = 8884097; em[905] = 8; em[906] = 0; /* 904: pointer.func */
    em[907] = 1; em[908] = 8; em[909] = 1; /* 907: pointer.struct.rand_meth_st */
    	em[910] = 912; em[911] = 0; 
    em[912] = 0; em[913] = 48; em[914] = 6; /* 912: struct.rand_meth_st */
    	em[915] = 927; em[916] = 0; 
    	em[917] = 930; em[918] = 8; 
    	em[919] = 933; em[920] = 16; 
    	em[921] = 936; em[922] = 24; 
    	em[923] = 930; em[924] = 32; 
    	em[925] = 939; em[926] = 40; 
    em[927] = 8884097; em[928] = 8; em[929] = 0; /* 927: pointer.func */
    em[930] = 8884097; em[931] = 8; em[932] = 0; /* 930: pointer.func */
    em[933] = 8884097; em[934] = 8; em[935] = 0; /* 933: pointer.func */
    em[936] = 8884097; em[937] = 8; em[938] = 0; /* 936: pointer.func */
    em[939] = 8884097; em[940] = 8; em[941] = 0; /* 939: pointer.func */
    em[942] = 1; em[943] = 8; em[944] = 1; /* 942: pointer.struct.store_method_st */
    	em[945] = 947; em[946] = 0; 
    em[947] = 0; em[948] = 0; em[949] = 0; /* 947: struct.store_method_st */
    em[950] = 8884097; em[951] = 8; em[952] = 0; /* 950: pointer.func */
    em[953] = 8884097; em[954] = 8; em[955] = 0; /* 953: pointer.func */
    em[956] = 8884097; em[957] = 8; em[958] = 0; /* 956: pointer.func */
    em[959] = 8884097; em[960] = 8; em[961] = 0; /* 959: pointer.func */
    em[962] = 8884097; em[963] = 8; em[964] = 0; /* 962: pointer.func */
    em[965] = 8884097; em[966] = 8; em[967] = 0; /* 965: pointer.func */
    em[968] = 8884097; em[969] = 8; em[970] = 0; /* 968: pointer.func */
    em[971] = 8884097; em[972] = 8; em[973] = 0; /* 971: pointer.func */
    em[974] = 1; em[975] = 8; em[976] = 1; /* 974: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[977] = 979; em[978] = 0; 
    em[979] = 0; em[980] = 32; em[981] = 2; /* 979: struct.ENGINE_CMD_DEFN_st */
    	em[982] = 648; em[983] = 8; 
    	em[984] = 648; em[985] = 16; 
    em[986] = 0; em[987] = 16; em[988] = 1; /* 986: struct.crypto_ex_data_st */
    	em[989] = 991; em[990] = 0; 
    em[991] = 1; em[992] = 8; em[993] = 1; /* 991: pointer.struct.stack_st_void */
    	em[994] = 996; em[995] = 0; 
    em[996] = 0; em[997] = 32; em[998] = 1; /* 996: struct.stack_st_void */
    	em[999] = 1001; em[1000] = 0; 
    em[1001] = 0; em[1002] = 32; em[1003] = 2; /* 1001: struct.stack_st */
    	em[1004] = 611; em[1005] = 8; 
    	em[1006] = 621; em[1007] = 24; 
    em[1008] = 1; em[1009] = 8; em[1010] = 1; /* 1008: pointer.struct.engine_st */
    	em[1011] = 670; em[1012] = 0; 
    em[1013] = 1; em[1014] = 8; em[1015] = 1; /* 1013: pointer.struct.dsa_st */
    	em[1016] = 1018; em[1017] = 0; 
    em[1018] = 0; em[1019] = 136; em[1020] = 11; /* 1018: struct.dsa_st */
    	em[1021] = 1043; em[1022] = 24; 
    	em[1023] = 1043; em[1024] = 32; 
    	em[1025] = 1043; em[1026] = 40; 
    	em[1027] = 1043; em[1028] = 48; 
    	em[1029] = 1043; em[1030] = 56; 
    	em[1031] = 1043; em[1032] = 64; 
    	em[1033] = 1043; em[1034] = 72; 
    	em[1035] = 1060; em[1036] = 88; 
    	em[1037] = 1074; em[1038] = 104; 
    	em[1039] = 1096; em[1040] = 120; 
    	em[1041] = 665; em[1042] = 128; 
    em[1043] = 1; em[1044] = 8; em[1045] = 1; /* 1043: pointer.struct.bignum_st */
    	em[1046] = 1048; em[1047] = 0; 
    em[1048] = 0; em[1049] = 24; em[1050] = 1; /* 1048: struct.bignum_st */
    	em[1051] = 1053; em[1052] = 0; 
    em[1053] = 8884099; em[1054] = 8; em[1055] = 2; /* 1053: pointer_to_array_of_pointers_to_stack */
    	em[1056] = 420; em[1057] = 0; 
    	em[1058] = 423; em[1059] = 12; 
    em[1060] = 1; em[1061] = 8; em[1062] = 1; /* 1060: pointer.struct.bn_mont_ctx_st */
    	em[1063] = 1065; em[1064] = 0; 
    em[1065] = 0; em[1066] = 96; em[1067] = 3; /* 1065: struct.bn_mont_ctx_st */
    	em[1068] = 1048; em[1069] = 8; 
    	em[1070] = 1048; em[1071] = 32; 
    	em[1072] = 1048; em[1073] = 56; 
    em[1074] = 0; em[1075] = 16; em[1076] = 1; /* 1074: struct.crypto_ex_data_st */
    	em[1077] = 1079; em[1078] = 0; 
    em[1079] = 1; em[1080] = 8; em[1081] = 1; /* 1079: pointer.struct.stack_st_void */
    	em[1082] = 1084; em[1083] = 0; 
    em[1084] = 0; em[1085] = 32; em[1086] = 1; /* 1084: struct.stack_st_void */
    	em[1087] = 1089; em[1088] = 0; 
    em[1089] = 0; em[1090] = 32; em[1091] = 2; /* 1089: struct.stack_st */
    	em[1092] = 611; em[1093] = 8; 
    	em[1094] = 621; em[1095] = 24; 
    em[1096] = 1; em[1097] = 8; em[1098] = 1; /* 1096: pointer.struct.dsa_method */
    	em[1099] = 1101; em[1100] = 0; 
    em[1101] = 0; em[1102] = 96; em[1103] = 11; /* 1101: struct.dsa_method */
    	em[1104] = 648; em[1105] = 0; 
    	em[1106] = 1126; em[1107] = 8; 
    	em[1108] = 1129; em[1109] = 16; 
    	em[1110] = 1132; em[1111] = 24; 
    	em[1112] = 1135; em[1113] = 32; 
    	em[1114] = 1138; em[1115] = 40; 
    	em[1116] = 1141; em[1117] = 48; 
    	em[1118] = 1141; em[1119] = 56; 
    	em[1120] = 616; em[1121] = 72; 
    	em[1122] = 1144; em[1123] = 80; 
    	em[1124] = 1141; em[1125] = 88; 
    em[1126] = 8884097; em[1127] = 8; em[1128] = 0; /* 1126: pointer.func */
    em[1129] = 8884097; em[1130] = 8; em[1131] = 0; /* 1129: pointer.func */
    em[1132] = 8884097; em[1133] = 8; em[1134] = 0; /* 1132: pointer.func */
    em[1135] = 8884097; em[1136] = 8; em[1137] = 0; /* 1135: pointer.func */
    em[1138] = 8884097; em[1139] = 8; em[1140] = 0; /* 1138: pointer.func */
    em[1141] = 8884097; em[1142] = 8; em[1143] = 0; /* 1141: pointer.func */
    em[1144] = 8884097; em[1145] = 8; em[1146] = 0; /* 1144: pointer.func */
    em[1147] = 1; em[1148] = 8; em[1149] = 1; /* 1147: pointer.struct.rsa_st */
    	em[1150] = 1152; em[1151] = 0; 
    em[1152] = 0; em[1153] = 168; em[1154] = 17; /* 1152: struct.rsa_st */
    	em[1155] = 1189; em[1156] = 16; 
    	em[1157] = 665; em[1158] = 24; 
    	em[1159] = 1043; em[1160] = 32; 
    	em[1161] = 1043; em[1162] = 40; 
    	em[1163] = 1043; em[1164] = 48; 
    	em[1165] = 1043; em[1166] = 56; 
    	em[1167] = 1043; em[1168] = 64; 
    	em[1169] = 1043; em[1170] = 72; 
    	em[1171] = 1043; em[1172] = 80; 
    	em[1173] = 1043; em[1174] = 88; 
    	em[1175] = 1074; em[1176] = 96; 
    	em[1177] = 1060; em[1178] = 120; 
    	em[1179] = 1060; em[1180] = 128; 
    	em[1181] = 1060; em[1182] = 136; 
    	em[1183] = 616; em[1184] = 144; 
    	em[1185] = 1244; em[1186] = 152; 
    	em[1187] = 1244; em[1188] = 160; 
    em[1189] = 1; em[1190] = 8; em[1191] = 1; /* 1189: pointer.struct.rsa_meth_st */
    	em[1192] = 1194; em[1193] = 0; 
    em[1194] = 0; em[1195] = 112; em[1196] = 13; /* 1194: struct.rsa_meth_st */
    	em[1197] = 648; em[1198] = 0; 
    	em[1199] = 1223; em[1200] = 8; 
    	em[1201] = 1223; em[1202] = 16; 
    	em[1203] = 1223; em[1204] = 24; 
    	em[1205] = 1223; em[1206] = 32; 
    	em[1207] = 1226; em[1208] = 40; 
    	em[1209] = 1229; em[1210] = 48; 
    	em[1211] = 1232; em[1212] = 56; 
    	em[1213] = 1232; em[1214] = 64; 
    	em[1215] = 616; em[1216] = 80; 
    	em[1217] = 1235; em[1218] = 88; 
    	em[1219] = 1238; em[1220] = 96; 
    	em[1221] = 1241; em[1222] = 104; 
    em[1223] = 8884097; em[1224] = 8; em[1225] = 0; /* 1223: pointer.func */
    em[1226] = 8884097; em[1227] = 8; em[1228] = 0; /* 1226: pointer.func */
    em[1229] = 8884097; em[1230] = 8; em[1231] = 0; /* 1229: pointer.func */
    em[1232] = 8884097; em[1233] = 8; em[1234] = 0; /* 1232: pointer.func */
    em[1235] = 8884097; em[1236] = 8; em[1237] = 0; /* 1235: pointer.func */
    em[1238] = 8884097; em[1239] = 8; em[1240] = 0; /* 1238: pointer.func */
    em[1241] = 8884097; em[1242] = 8; em[1243] = 0; /* 1241: pointer.func */
    em[1244] = 1; em[1245] = 8; em[1246] = 1; /* 1244: pointer.struct.bn_blinding_st */
    	em[1247] = 1249; em[1248] = 0; 
    em[1249] = 0; em[1250] = 88; em[1251] = 7; /* 1249: struct.bn_blinding_st */
    	em[1252] = 1266; em[1253] = 0; 
    	em[1254] = 1266; em[1255] = 8; 
    	em[1256] = 1266; em[1257] = 16; 
    	em[1258] = 1266; em[1259] = 24; 
    	em[1260] = 1283; em[1261] = 40; 
    	em[1262] = 1288; em[1263] = 72; 
    	em[1264] = 1302; em[1265] = 80; 
    em[1266] = 1; em[1267] = 8; em[1268] = 1; /* 1266: pointer.struct.bignum_st */
    	em[1269] = 1271; em[1270] = 0; 
    em[1271] = 0; em[1272] = 24; em[1273] = 1; /* 1271: struct.bignum_st */
    	em[1274] = 1276; em[1275] = 0; 
    em[1276] = 8884099; em[1277] = 8; em[1278] = 2; /* 1276: pointer_to_array_of_pointers_to_stack */
    	em[1279] = 420; em[1280] = 0; 
    	em[1281] = 423; em[1282] = 12; 
    em[1283] = 0; em[1284] = 16; em[1285] = 1; /* 1283: struct.crypto_threadid_st */
    	em[1286] = 469; em[1287] = 0; 
    em[1288] = 1; em[1289] = 8; em[1290] = 1; /* 1288: pointer.struct.bn_mont_ctx_st */
    	em[1291] = 1293; em[1292] = 0; 
    em[1293] = 0; em[1294] = 96; em[1295] = 3; /* 1293: struct.bn_mont_ctx_st */
    	em[1296] = 1271; em[1297] = 8; 
    	em[1298] = 1271; em[1299] = 32; 
    	em[1300] = 1271; em[1301] = 56; 
    em[1302] = 8884097; em[1303] = 8; em[1304] = 0; /* 1302: pointer.func */
    em[1305] = 0; em[1306] = 56; em[1307] = 4; /* 1305: struct.evp_pkey_st */
    	em[1308] = 1316; em[1309] = 16; 
    	em[1310] = 665; em[1311] = 24; 
    	em[1312] = 1417; em[1313] = 32; 
    	em[1314] = 1430; em[1315] = 48; 
    em[1316] = 1; em[1317] = 8; em[1318] = 1; /* 1316: pointer.struct.evp_pkey_asn1_method_st */
    	em[1319] = 1321; em[1320] = 0; 
    em[1321] = 0; em[1322] = 208; em[1323] = 24; /* 1321: struct.evp_pkey_asn1_method_st */
    	em[1324] = 616; em[1325] = 16; 
    	em[1326] = 616; em[1327] = 24; 
    	em[1328] = 1372; em[1329] = 32; 
    	em[1330] = 1375; em[1331] = 40; 
    	em[1332] = 1378; em[1333] = 48; 
    	em[1334] = 1381; em[1335] = 56; 
    	em[1336] = 1384; em[1337] = 64; 
    	em[1338] = 1387; em[1339] = 72; 
    	em[1340] = 1381; em[1341] = 80; 
    	em[1342] = 1390; em[1343] = 88; 
    	em[1344] = 1390; em[1345] = 96; 
    	em[1346] = 1393; em[1347] = 104; 
    	em[1348] = 1396; em[1349] = 112; 
    	em[1350] = 1390; em[1351] = 120; 
    	em[1352] = 1399; em[1353] = 128; 
    	em[1354] = 1378; em[1355] = 136; 
    	em[1356] = 1381; em[1357] = 144; 
    	em[1358] = 1402; em[1359] = 152; 
    	em[1360] = 1405; em[1361] = 160; 
    	em[1362] = 1408; em[1363] = 168; 
    	em[1364] = 1393; em[1365] = 176; 
    	em[1366] = 1396; em[1367] = 184; 
    	em[1368] = 1411; em[1369] = 192; 
    	em[1370] = 1414; em[1371] = 200; 
    em[1372] = 8884097; em[1373] = 8; em[1374] = 0; /* 1372: pointer.func */
    em[1375] = 8884097; em[1376] = 8; em[1377] = 0; /* 1375: pointer.func */
    em[1378] = 8884097; em[1379] = 8; em[1380] = 0; /* 1378: pointer.func */
    em[1381] = 8884097; em[1382] = 8; em[1383] = 0; /* 1381: pointer.func */
    em[1384] = 8884097; em[1385] = 8; em[1386] = 0; /* 1384: pointer.func */
    em[1387] = 8884097; em[1388] = 8; em[1389] = 0; /* 1387: pointer.func */
    em[1390] = 8884097; em[1391] = 8; em[1392] = 0; /* 1390: pointer.func */
    em[1393] = 8884097; em[1394] = 8; em[1395] = 0; /* 1393: pointer.func */
    em[1396] = 8884097; em[1397] = 8; em[1398] = 0; /* 1396: pointer.func */
    em[1399] = 8884097; em[1400] = 8; em[1401] = 0; /* 1399: pointer.func */
    em[1402] = 8884097; em[1403] = 8; em[1404] = 0; /* 1402: pointer.func */
    em[1405] = 8884097; em[1406] = 8; em[1407] = 0; /* 1405: pointer.func */
    em[1408] = 8884097; em[1409] = 8; em[1410] = 0; /* 1408: pointer.func */
    em[1411] = 8884097; em[1412] = 8; em[1413] = 0; /* 1411: pointer.func */
    em[1414] = 8884097; em[1415] = 8; em[1416] = 0; /* 1414: pointer.func */
    em[1417] = 0; em[1418] = 8; em[1419] = 5; /* 1417: union.unknown */
    	em[1420] = 616; em[1421] = 0; 
    	em[1422] = 1147; em[1423] = 0; 
    	em[1424] = 1013; em[1425] = 0; 
    	em[1426] = 526; em[1427] = 0; 
    	em[1428] = 0; em[1429] = 0; 
    em[1430] = 1; em[1431] = 8; em[1432] = 1; /* 1430: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1433] = 1435; em[1434] = 0; 
    em[1435] = 0; em[1436] = 32; em[1437] = 2; /* 1435: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1438] = 1442; em[1439] = 8; 
    	em[1440] = 621; em[1441] = 24; 
    em[1442] = 8884099; em[1443] = 8; em[1444] = 2; /* 1442: pointer_to_array_of_pointers_to_stack */
    	em[1445] = 1449; em[1446] = 0; 
    	em[1447] = 423; em[1448] = 20; 
    em[1449] = 0; em[1450] = 8; em[1451] = 1; /* 1449: pointer.X509_ATTRIBUTE */
    	em[1452] = 1454; em[1453] = 0; 
    em[1454] = 0; em[1455] = 0; em[1456] = 1; /* 1454: X509_ATTRIBUTE */
    	em[1457] = 1459; em[1458] = 0; 
    em[1459] = 0; em[1460] = 24; em[1461] = 2; /* 1459: struct.x509_attributes_st */
    	em[1462] = 1466; em[1463] = 0; 
    	em[1464] = 1485; em[1465] = 16; 
    em[1466] = 1; em[1467] = 8; em[1468] = 1; /* 1466: pointer.struct.asn1_object_st */
    	em[1469] = 1471; em[1470] = 0; 
    em[1471] = 0; em[1472] = 40; em[1473] = 3; /* 1471: struct.asn1_object_st */
    	em[1474] = 648; em[1475] = 0; 
    	em[1476] = 648; em[1477] = 8; 
    	em[1478] = 1480; em[1479] = 24; 
    em[1480] = 1; em[1481] = 8; em[1482] = 1; /* 1480: pointer.unsigned char */
    	em[1483] = 443; em[1484] = 0; 
    em[1485] = 0; em[1486] = 8; em[1487] = 3; /* 1485: union.unknown */
    	em[1488] = 616; em[1489] = 0; 
    	em[1490] = 1494; em[1491] = 0; 
    	em[1492] = 1673; em[1493] = 0; 
    em[1494] = 1; em[1495] = 8; em[1496] = 1; /* 1494: pointer.struct.stack_st_ASN1_TYPE */
    	em[1497] = 1499; em[1498] = 0; 
    em[1499] = 0; em[1500] = 32; em[1501] = 2; /* 1499: struct.stack_st_fake_ASN1_TYPE */
    	em[1502] = 1506; em[1503] = 8; 
    	em[1504] = 621; em[1505] = 24; 
    em[1506] = 8884099; em[1507] = 8; em[1508] = 2; /* 1506: pointer_to_array_of_pointers_to_stack */
    	em[1509] = 1513; em[1510] = 0; 
    	em[1511] = 423; em[1512] = 20; 
    em[1513] = 0; em[1514] = 8; em[1515] = 1; /* 1513: pointer.ASN1_TYPE */
    	em[1516] = 1518; em[1517] = 0; 
    em[1518] = 0; em[1519] = 0; em[1520] = 1; /* 1518: ASN1_TYPE */
    	em[1521] = 1523; em[1522] = 0; 
    em[1523] = 0; em[1524] = 16; em[1525] = 1; /* 1523: struct.asn1_type_st */
    	em[1526] = 1528; em[1527] = 8; 
    em[1528] = 0; em[1529] = 8; em[1530] = 20; /* 1528: union.unknown */
    	em[1531] = 616; em[1532] = 0; 
    	em[1533] = 1571; em[1534] = 0; 
    	em[1535] = 1581; em[1536] = 0; 
    	em[1537] = 1595; em[1538] = 0; 
    	em[1539] = 1600; em[1540] = 0; 
    	em[1541] = 1605; em[1542] = 0; 
    	em[1543] = 1610; em[1544] = 0; 
    	em[1545] = 1615; em[1546] = 0; 
    	em[1547] = 1620; em[1548] = 0; 
    	em[1549] = 1625; em[1550] = 0; 
    	em[1551] = 1630; em[1552] = 0; 
    	em[1553] = 1635; em[1554] = 0; 
    	em[1555] = 1640; em[1556] = 0; 
    	em[1557] = 1645; em[1558] = 0; 
    	em[1559] = 1650; em[1560] = 0; 
    	em[1561] = 1655; em[1562] = 0; 
    	em[1563] = 1660; em[1564] = 0; 
    	em[1565] = 1571; em[1566] = 0; 
    	em[1567] = 1571; em[1568] = 0; 
    	em[1569] = 1665; em[1570] = 0; 
    em[1571] = 1; em[1572] = 8; em[1573] = 1; /* 1571: pointer.struct.asn1_string_st */
    	em[1574] = 1576; em[1575] = 0; 
    em[1576] = 0; em[1577] = 24; em[1578] = 1; /* 1576: struct.asn1_string_st */
    	em[1579] = 438; em[1580] = 8; 
    em[1581] = 1; em[1582] = 8; em[1583] = 1; /* 1581: pointer.struct.asn1_object_st */
    	em[1584] = 1586; em[1585] = 0; 
    em[1586] = 0; em[1587] = 40; em[1588] = 3; /* 1586: struct.asn1_object_st */
    	em[1589] = 648; em[1590] = 0; 
    	em[1591] = 648; em[1592] = 8; 
    	em[1593] = 1480; em[1594] = 24; 
    em[1595] = 1; em[1596] = 8; em[1597] = 1; /* 1595: pointer.struct.asn1_string_st */
    	em[1598] = 1576; em[1599] = 0; 
    em[1600] = 1; em[1601] = 8; em[1602] = 1; /* 1600: pointer.struct.asn1_string_st */
    	em[1603] = 1576; em[1604] = 0; 
    em[1605] = 1; em[1606] = 8; em[1607] = 1; /* 1605: pointer.struct.asn1_string_st */
    	em[1608] = 1576; em[1609] = 0; 
    em[1610] = 1; em[1611] = 8; em[1612] = 1; /* 1610: pointer.struct.asn1_string_st */
    	em[1613] = 1576; em[1614] = 0; 
    em[1615] = 1; em[1616] = 8; em[1617] = 1; /* 1615: pointer.struct.asn1_string_st */
    	em[1618] = 1576; em[1619] = 0; 
    em[1620] = 1; em[1621] = 8; em[1622] = 1; /* 1620: pointer.struct.asn1_string_st */
    	em[1623] = 1576; em[1624] = 0; 
    em[1625] = 1; em[1626] = 8; em[1627] = 1; /* 1625: pointer.struct.asn1_string_st */
    	em[1628] = 1576; em[1629] = 0; 
    em[1630] = 1; em[1631] = 8; em[1632] = 1; /* 1630: pointer.struct.asn1_string_st */
    	em[1633] = 1576; em[1634] = 0; 
    em[1635] = 1; em[1636] = 8; em[1637] = 1; /* 1635: pointer.struct.asn1_string_st */
    	em[1638] = 1576; em[1639] = 0; 
    em[1640] = 1; em[1641] = 8; em[1642] = 1; /* 1640: pointer.struct.asn1_string_st */
    	em[1643] = 1576; em[1644] = 0; 
    em[1645] = 1; em[1646] = 8; em[1647] = 1; /* 1645: pointer.struct.asn1_string_st */
    	em[1648] = 1576; em[1649] = 0; 
    em[1650] = 1; em[1651] = 8; em[1652] = 1; /* 1650: pointer.struct.asn1_string_st */
    	em[1653] = 1576; em[1654] = 0; 
    em[1655] = 1; em[1656] = 8; em[1657] = 1; /* 1655: pointer.struct.asn1_string_st */
    	em[1658] = 1576; em[1659] = 0; 
    em[1660] = 1; em[1661] = 8; em[1662] = 1; /* 1660: pointer.struct.asn1_string_st */
    	em[1663] = 1576; em[1664] = 0; 
    em[1665] = 1; em[1666] = 8; em[1667] = 1; /* 1665: pointer.struct.ASN1_VALUE_st */
    	em[1668] = 1670; em[1669] = 0; 
    em[1670] = 0; em[1671] = 0; em[1672] = 0; /* 1670: struct.ASN1_VALUE_st */
    em[1673] = 1; em[1674] = 8; em[1675] = 1; /* 1673: pointer.struct.asn1_type_st */
    	em[1676] = 1678; em[1677] = 0; 
    em[1678] = 0; em[1679] = 16; em[1680] = 1; /* 1678: struct.asn1_type_st */
    	em[1681] = 1683; em[1682] = 8; 
    em[1683] = 0; em[1684] = 8; em[1685] = 20; /* 1683: union.unknown */
    	em[1686] = 616; em[1687] = 0; 
    	em[1688] = 1726; em[1689] = 0; 
    	em[1690] = 1466; em[1691] = 0; 
    	em[1692] = 1736; em[1693] = 0; 
    	em[1694] = 1741; em[1695] = 0; 
    	em[1696] = 1746; em[1697] = 0; 
    	em[1698] = 1751; em[1699] = 0; 
    	em[1700] = 1756; em[1701] = 0; 
    	em[1702] = 1761; em[1703] = 0; 
    	em[1704] = 1766; em[1705] = 0; 
    	em[1706] = 1771; em[1707] = 0; 
    	em[1708] = 1776; em[1709] = 0; 
    	em[1710] = 1781; em[1711] = 0; 
    	em[1712] = 1786; em[1713] = 0; 
    	em[1714] = 1791; em[1715] = 0; 
    	em[1716] = 1796; em[1717] = 0; 
    	em[1718] = 1801; em[1719] = 0; 
    	em[1720] = 1726; em[1721] = 0; 
    	em[1722] = 1726; em[1723] = 0; 
    	em[1724] = 1806; em[1725] = 0; 
    em[1726] = 1; em[1727] = 8; em[1728] = 1; /* 1726: pointer.struct.asn1_string_st */
    	em[1729] = 1731; em[1730] = 0; 
    em[1731] = 0; em[1732] = 24; em[1733] = 1; /* 1731: struct.asn1_string_st */
    	em[1734] = 438; em[1735] = 8; 
    em[1736] = 1; em[1737] = 8; em[1738] = 1; /* 1736: pointer.struct.asn1_string_st */
    	em[1739] = 1731; em[1740] = 0; 
    em[1741] = 1; em[1742] = 8; em[1743] = 1; /* 1741: pointer.struct.asn1_string_st */
    	em[1744] = 1731; em[1745] = 0; 
    em[1746] = 1; em[1747] = 8; em[1748] = 1; /* 1746: pointer.struct.asn1_string_st */
    	em[1749] = 1731; em[1750] = 0; 
    em[1751] = 1; em[1752] = 8; em[1753] = 1; /* 1751: pointer.struct.asn1_string_st */
    	em[1754] = 1731; em[1755] = 0; 
    em[1756] = 1; em[1757] = 8; em[1758] = 1; /* 1756: pointer.struct.asn1_string_st */
    	em[1759] = 1731; em[1760] = 0; 
    em[1761] = 1; em[1762] = 8; em[1763] = 1; /* 1761: pointer.struct.asn1_string_st */
    	em[1764] = 1731; em[1765] = 0; 
    em[1766] = 1; em[1767] = 8; em[1768] = 1; /* 1766: pointer.struct.asn1_string_st */
    	em[1769] = 1731; em[1770] = 0; 
    em[1771] = 1; em[1772] = 8; em[1773] = 1; /* 1771: pointer.struct.asn1_string_st */
    	em[1774] = 1731; em[1775] = 0; 
    em[1776] = 1; em[1777] = 8; em[1778] = 1; /* 1776: pointer.struct.asn1_string_st */
    	em[1779] = 1731; em[1780] = 0; 
    em[1781] = 1; em[1782] = 8; em[1783] = 1; /* 1781: pointer.struct.asn1_string_st */
    	em[1784] = 1731; em[1785] = 0; 
    em[1786] = 1; em[1787] = 8; em[1788] = 1; /* 1786: pointer.struct.asn1_string_st */
    	em[1789] = 1731; em[1790] = 0; 
    em[1791] = 1; em[1792] = 8; em[1793] = 1; /* 1791: pointer.struct.asn1_string_st */
    	em[1794] = 1731; em[1795] = 0; 
    em[1796] = 1; em[1797] = 8; em[1798] = 1; /* 1796: pointer.struct.asn1_string_st */
    	em[1799] = 1731; em[1800] = 0; 
    em[1801] = 1; em[1802] = 8; em[1803] = 1; /* 1801: pointer.struct.asn1_string_st */
    	em[1804] = 1731; em[1805] = 0; 
    em[1806] = 1; em[1807] = 8; em[1808] = 1; /* 1806: pointer.struct.ASN1_VALUE_st */
    	em[1809] = 1811; em[1810] = 0; 
    em[1811] = 0; em[1812] = 0; em[1813] = 0; /* 1811: struct.ASN1_VALUE_st */
    em[1814] = 1; em[1815] = 8; em[1816] = 1; /* 1814: pointer.struct.asn1_string_st */
    	em[1817] = 1819; em[1818] = 0; 
    em[1819] = 0; em[1820] = 24; em[1821] = 1; /* 1819: struct.asn1_string_st */
    	em[1822] = 438; em[1823] = 8; 
    em[1824] = 1; em[1825] = 8; em[1826] = 1; /* 1824: pointer.struct.stack_st_ASN1_OBJECT */
    	em[1827] = 1829; em[1828] = 0; 
    em[1829] = 0; em[1830] = 32; em[1831] = 2; /* 1829: struct.stack_st_fake_ASN1_OBJECT */
    	em[1832] = 1836; em[1833] = 8; 
    	em[1834] = 621; em[1835] = 24; 
    em[1836] = 8884099; em[1837] = 8; em[1838] = 2; /* 1836: pointer_to_array_of_pointers_to_stack */
    	em[1839] = 1843; em[1840] = 0; 
    	em[1841] = 423; em[1842] = 20; 
    em[1843] = 0; em[1844] = 8; em[1845] = 1; /* 1843: pointer.ASN1_OBJECT */
    	em[1846] = 1848; em[1847] = 0; 
    em[1848] = 0; em[1849] = 0; em[1850] = 1; /* 1848: ASN1_OBJECT */
    	em[1851] = 1853; em[1852] = 0; 
    em[1853] = 0; em[1854] = 40; em[1855] = 3; /* 1853: struct.asn1_object_st */
    	em[1856] = 648; em[1857] = 0; 
    	em[1858] = 648; em[1859] = 8; 
    	em[1860] = 1480; em[1861] = 24; 
    em[1862] = 0; em[1863] = 40; em[1864] = 5; /* 1862: struct.x509_cert_aux_st */
    	em[1865] = 1824; em[1866] = 0; 
    	em[1867] = 1824; em[1868] = 8; 
    	em[1869] = 1814; em[1870] = 16; 
    	em[1871] = 1875; em[1872] = 24; 
    	em[1873] = 1880; em[1874] = 32; 
    em[1875] = 1; em[1876] = 8; em[1877] = 1; /* 1875: pointer.struct.asn1_string_st */
    	em[1878] = 1819; em[1879] = 0; 
    em[1880] = 1; em[1881] = 8; em[1882] = 1; /* 1880: pointer.struct.stack_st_X509_ALGOR */
    	em[1883] = 1885; em[1884] = 0; 
    em[1885] = 0; em[1886] = 32; em[1887] = 2; /* 1885: struct.stack_st_fake_X509_ALGOR */
    	em[1888] = 1892; em[1889] = 8; 
    	em[1890] = 621; em[1891] = 24; 
    em[1892] = 8884099; em[1893] = 8; em[1894] = 2; /* 1892: pointer_to_array_of_pointers_to_stack */
    	em[1895] = 1899; em[1896] = 0; 
    	em[1897] = 423; em[1898] = 20; 
    em[1899] = 0; em[1900] = 8; em[1901] = 1; /* 1899: pointer.X509_ALGOR */
    	em[1902] = 1904; em[1903] = 0; 
    em[1904] = 0; em[1905] = 0; em[1906] = 1; /* 1904: X509_ALGOR */
    	em[1907] = 1909; em[1908] = 0; 
    em[1909] = 0; em[1910] = 16; em[1911] = 2; /* 1909: struct.X509_algor_st */
    	em[1912] = 1916; em[1913] = 0; 
    	em[1914] = 1930; em[1915] = 8; 
    em[1916] = 1; em[1917] = 8; em[1918] = 1; /* 1916: pointer.struct.asn1_object_st */
    	em[1919] = 1921; em[1920] = 0; 
    em[1921] = 0; em[1922] = 40; em[1923] = 3; /* 1921: struct.asn1_object_st */
    	em[1924] = 648; em[1925] = 0; 
    	em[1926] = 648; em[1927] = 8; 
    	em[1928] = 1480; em[1929] = 24; 
    em[1930] = 1; em[1931] = 8; em[1932] = 1; /* 1930: pointer.struct.asn1_type_st */
    	em[1933] = 1935; em[1934] = 0; 
    em[1935] = 0; em[1936] = 16; em[1937] = 1; /* 1935: struct.asn1_type_st */
    	em[1938] = 1940; em[1939] = 8; 
    em[1940] = 0; em[1941] = 8; em[1942] = 20; /* 1940: union.unknown */
    	em[1943] = 616; em[1944] = 0; 
    	em[1945] = 1983; em[1946] = 0; 
    	em[1947] = 1916; em[1948] = 0; 
    	em[1949] = 1993; em[1950] = 0; 
    	em[1951] = 1998; em[1952] = 0; 
    	em[1953] = 2003; em[1954] = 0; 
    	em[1955] = 2008; em[1956] = 0; 
    	em[1957] = 2013; em[1958] = 0; 
    	em[1959] = 2018; em[1960] = 0; 
    	em[1961] = 2023; em[1962] = 0; 
    	em[1963] = 2028; em[1964] = 0; 
    	em[1965] = 2033; em[1966] = 0; 
    	em[1967] = 2038; em[1968] = 0; 
    	em[1969] = 2043; em[1970] = 0; 
    	em[1971] = 2048; em[1972] = 0; 
    	em[1973] = 2053; em[1974] = 0; 
    	em[1975] = 2058; em[1976] = 0; 
    	em[1977] = 1983; em[1978] = 0; 
    	em[1979] = 1983; em[1980] = 0; 
    	em[1981] = 2063; em[1982] = 0; 
    em[1983] = 1; em[1984] = 8; em[1985] = 1; /* 1983: pointer.struct.asn1_string_st */
    	em[1986] = 1988; em[1987] = 0; 
    em[1988] = 0; em[1989] = 24; em[1990] = 1; /* 1988: struct.asn1_string_st */
    	em[1991] = 438; em[1992] = 8; 
    em[1993] = 1; em[1994] = 8; em[1995] = 1; /* 1993: pointer.struct.asn1_string_st */
    	em[1996] = 1988; em[1997] = 0; 
    em[1998] = 1; em[1999] = 8; em[2000] = 1; /* 1998: pointer.struct.asn1_string_st */
    	em[2001] = 1988; em[2002] = 0; 
    em[2003] = 1; em[2004] = 8; em[2005] = 1; /* 2003: pointer.struct.asn1_string_st */
    	em[2006] = 1988; em[2007] = 0; 
    em[2008] = 1; em[2009] = 8; em[2010] = 1; /* 2008: pointer.struct.asn1_string_st */
    	em[2011] = 1988; em[2012] = 0; 
    em[2013] = 1; em[2014] = 8; em[2015] = 1; /* 2013: pointer.struct.asn1_string_st */
    	em[2016] = 1988; em[2017] = 0; 
    em[2018] = 1; em[2019] = 8; em[2020] = 1; /* 2018: pointer.struct.asn1_string_st */
    	em[2021] = 1988; em[2022] = 0; 
    em[2023] = 1; em[2024] = 8; em[2025] = 1; /* 2023: pointer.struct.asn1_string_st */
    	em[2026] = 1988; em[2027] = 0; 
    em[2028] = 1; em[2029] = 8; em[2030] = 1; /* 2028: pointer.struct.asn1_string_st */
    	em[2031] = 1988; em[2032] = 0; 
    em[2033] = 1; em[2034] = 8; em[2035] = 1; /* 2033: pointer.struct.asn1_string_st */
    	em[2036] = 1988; em[2037] = 0; 
    em[2038] = 1; em[2039] = 8; em[2040] = 1; /* 2038: pointer.struct.asn1_string_st */
    	em[2041] = 1988; em[2042] = 0; 
    em[2043] = 1; em[2044] = 8; em[2045] = 1; /* 2043: pointer.struct.asn1_string_st */
    	em[2046] = 1988; em[2047] = 0; 
    em[2048] = 1; em[2049] = 8; em[2050] = 1; /* 2048: pointer.struct.asn1_string_st */
    	em[2051] = 1988; em[2052] = 0; 
    em[2053] = 1; em[2054] = 8; em[2055] = 1; /* 2053: pointer.struct.asn1_string_st */
    	em[2056] = 1988; em[2057] = 0; 
    em[2058] = 1; em[2059] = 8; em[2060] = 1; /* 2058: pointer.struct.asn1_string_st */
    	em[2061] = 1988; em[2062] = 0; 
    em[2063] = 1; em[2064] = 8; em[2065] = 1; /* 2063: pointer.struct.ASN1_VALUE_st */
    	em[2066] = 2068; em[2067] = 0; 
    em[2068] = 0; em[2069] = 0; em[2070] = 0; /* 2068: struct.ASN1_VALUE_st */
    em[2071] = 1; em[2072] = 8; em[2073] = 1; /* 2071: pointer.struct.x509_cert_aux_st */
    	em[2074] = 1862; em[2075] = 0; 
    em[2076] = 0; em[2077] = 16; em[2078] = 2; /* 2076: struct.EDIPartyName_st */
    	em[2079] = 2083; em[2080] = 0; 
    	em[2081] = 2083; em[2082] = 8; 
    em[2083] = 1; em[2084] = 8; em[2085] = 1; /* 2083: pointer.struct.asn1_string_st */
    	em[2086] = 2088; em[2087] = 0; 
    em[2088] = 0; em[2089] = 24; em[2090] = 1; /* 2088: struct.asn1_string_st */
    	em[2091] = 438; em[2092] = 8; 
    em[2093] = 1; em[2094] = 8; em[2095] = 1; /* 2093: pointer.struct.EDIPartyName_st */
    	em[2096] = 2076; em[2097] = 0; 
    em[2098] = 0; em[2099] = 24; em[2100] = 1; /* 2098: struct.buf_mem_st */
    	em[2101] = 616; em[2102] = 8; 
    em[2103] = 1; em[2104] = 8; em[2105] = 1; /* 2103: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[2106] = 2108; em[2107] = 0; 
    em[2108] = 0; em[2109] = 32; em[2110] = 2; /* 2108: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[2111] = 2115; em[2112] = 8; 
    	em[2113] = 621; em[2114] = 24; 
    em[2115] = 8884099; em[2116] = 8; em[2117] = 2; /* 2115: pointer_to_array_of_pointers_to_stack */
    	em[2118] = 2122; em[2119] = 0; 
    	em[2120] = 423; em[2121] = 20; 
    em[2122] = 0; em[2123] = 8; em[2124] = 1; /* 2122: pointer.X509_NAME_ENTRY */
    	em[2125] = 2127; em[2126] = 0; 
    em[2127] = 0; em[2128] = 0; em[2129] = 1; /* 2127: X509_NAME_ENTRY */
    	em[2130] = 2132; em[2131] = 0; 
    em[2132] = 0; em[2133] = 24; em[2134] = 2; /* 2132: struct.X509_name_entry_st */
    	em[2135] = 2139; em[2136] = 0; 
    	em[2137] = 2153; em[2138] = 8; 
    em[2139] = 1; em[2140] = 8; em[2141] = 1; /* 2139: pointer.struct.asn1_object_st */
    	em[2142] = 2144; em[2143] = 0; 
    em[2144] = 0; em[2145] = 40; em[2146] = 3; /* 2144: struct.asn1_object_st */
    	em[2147] = 648; em[2148] = 0; 
    	em[2149] = 648; em[2150] = 8; 
    	em[2151] = 1480; em[2152] = 24; 
    em[2153] = 1; em[2154] = 8; em[2155] = 1; /* 2153: pointer.struct.asn1_string_st */
    	em[2156] = 2158; em[2157] = 0; 
    em[2158] = 0; em[2159] = 24; em[2160] = 1; /* 2158: struct.asn1_string_st */
    	em[2161] = 438; em[2162] = 8; 
    em[2163] = 1; em[2164] = 8; em[2165] = 1; /* 2163: pointer.struct.X509_name_st */
    	em[2166] = 2168; em[2167] = 0; 
    em[2168] = 0; em[2169] = 40; em[2170] = 3; /* 2168: struct.X509_name_st */
    	em[2171] = 2103; em[2172] = 0; 
    	em[2173] = 2177; em[2174] = 16; 
    	em[2175] = 438; em[2176] = 24; 
    em[2177] = 1; em[2178] = 8; em[2179] = 1; /* 2177: pointer.struct.buf_mem_st */
    	em[2180] = 2098; em[2181] = 0; 
    em[2182] = 1; em[2183] = 8; em[2184] = 1; /* 2182: pointer.struct.asn1_string_st */
    	em[2185] = 2088; em[2186] = 0; 
    em[2187] = 1; em[2188] = 8; em[2189] = 1; /* 2187: pointer.struct.asn1_string_st */
    	em[2190] = 2088; em[2191] = 0; 
    em[2192] = 1; em[2193] = 8; em[2194] = 1; /* 2192: pointer.struct.asn1_string_st */
    	em[2195] = 2088; em[2196] = 0; 
    em[2197] = 1; em[2198] = 8; em[2199] = 1; /* 2197: pointer.struct.asn1_string_st */
    	em[2200] = 2088; em[2201] = 0; 
    em[2202] = 1; em[2203] = 8; em[2204] = 1; /* 2202: pointer.struct.asn1_string_st */
    	em[2205] = 2088; em[2206] = 0; 
    em[2207] = 0; em[2208] = 8; em[2209] = 20; /* 2207: union.unknown */
    	em[2210] = 616; em[2211] = 0; 
    	em[2212] = 2083; em[2213] = 0; 
    	em[2214] = 2250; em[2215] = 0; 
    	em[2216] = 2264; em[2217] = 0; 
    	em[2218] = 2269; em[2219] = 0; 
    	em[2220] = 2274; em[2221] = 0; 
    	em[2222] = 2202; em[2223] = 0; 
    	em[2224] = 2279; em[2225] = 0; 
    	em[2226] = 2284; em[2227] = 0; 
    	em[2228] = 2289; em[2229] = 0; 
    	em[2230] = 2197; em[2231] = 0; 
    	em[2232] = 2192; em[2233] = 0; 
    	em[2234] = 2294; em[2235] = 0; 
    	em[2236] = 2187; em[2237] = 0; 
    	em[2238] = 2182; em[2239] = 0; 
    	em[2240] = 2299; em[2241] = 0; 
    	em[2242] = 2304; em[2243] = 0; 
    	em[2244] = 2083; em[2245] = 0; 
    	em[2246] = 2083; em[2247] = 0; 
    	em[2248] = 2309; em[2249] = 0; 
    em[2250] = 1; em[2251] = 8; em[2252] = 1; /* 2250: pointer.struct.asn1_object_st */
    	em[2253] = 2255; em[2254] = 0; 
    em[2255] = 0; em[2256] = 40; em[2257] = 3; /* 2255: struct.asn1_object_st */
    	em[2258] = 648; em[2259] = 0; 
    	em[2260] = 648; em[2261] = 8; 
    	em[2262] = 1480; em[2263] = 24; 
    em[2264] = 1; em[2265] = 8; em[2266] = 1; /* 2264: pointer.struct.asn1_string_st */
    	em[2267] = 2088; em[2268] = 0; 
    em[2269] = 1; em[2270] = 8; em[2271] = 1; /* 2269: pointer.struct.asn1_string_st */
    	em[2272] = 2088; em[2273] = 0; 
    em[2274] = 1; em[2275] = 8; em[2276] = 1; /* 2274: pointer.struct.asn1_string_st */
    	em[2277] = 2088; em[2278] = 0; 
    em[2279] = 1; em[2280] = 8; em[2281] = 1; /* 2279: pointer.struct.asn1_string_st */
    	em[2282] = 2088; em[2283] = 0; 
    em[2284] = 1; em[2285] = 8; em[2286] = 1; /* 2284: pointer.struct.asn1_string_st */
    	em[2287] = 2088; em[2288] = 0; 
    em[2289] = 1; em[2290] = 8; em[2291] = 1; /* 2289: pointer.struct.asn1_string_st */
    	em[2292] = 2088; em[2293] = 0; 
    em[2294] = 1; em[2295] = 8; em[2296] = 1; /* 2294: pointer.struct.asn1_string_st */
    	em[2297] = 2088; em[2298] = 0; 
    em[2299] = 1; em[2300] = 8; em[2301] = 1; /* 2299: pointer.struct.asn1_string_st */
    	em[2302] = 2088; em[2303] = 0; 
    em[2304] = 1; em[2305] = 8; em[2306] = 1; /* 2304: pointer.struct.asn1_string_st */
    	em[2307] = 2088; em[2308] = 0; 
    em[2309] = 1; em[2310] = 8; em[2311] = 1; /* 2309: pointer.struct.ASN1_VALUE_st */
    	em[2312] = 2314; em[2313] = 0; 
    em[2314] = 0; em[2315] = 0; em[2316] = 0; /* 2314: struct.ASN1_VALUE_st */
    em[2317] = 0; em[2318] = 16; em[2319] = 1; /* 2317: struct.GENERAL_NAME_st */
    	em[2320] = 2322; em[2321] = 8; 
    em[2322] = 0; em[2323] = 8; em[2324] = 15; /* 2322: union.unknown */
    	em[2325] = 616; em[2326] = 0; 
    	em[2327] = 2355; em[2328] = 0; 
    	em[2329] = 2289; em[2330] = 0; 
    	em[2331] = 2289; em[2332] = 0; 
    	em[2333] = 2367; em[2334] = 0; 
    	em[2335] = 2163; em[2336] = 0; 
    	em[2337] = 2093; em[2338] = 0; 
    	em[2339] = 2289; em[2340] = 0; 
    	em[2341] = 2202; em[2342] = 0; 
    	em[2343] = 2250; em[2344] = 0; 
    	em[2345] = 2202; em[2346] = 0; 
    	em[2347] = 2163; em[2348] = 0; 
    	em[2349] = 2289; em[2350] = 0; 
    	em[2351] = 2250; em[2352] = 0; 
    	em[2353] = 2367; em[2354] = 0; 
    em[2355] = 1; em[2356] = 8; em[2357] = 1; /* 2355: pointer.struct.otherName_st */
    	em[2358] = 2360; em[2359] = 0; 
    em[2360] = 0; em[2361] = 16; em[2362] = 2; /* 2360: struct.otherName_st */
    	em[2363] = 2250; em[2364] = 0; 
    	em[2365] = 2367; em[2366] = 8; 
    em[2367] = 1; em[2368] = 8; em[2369] = 1; /* 2367: pointer.struct.asn1_type_st */
    	em[2370] = 2372; em[2371] = 0; 
    em[2372] = 0; em[2373] = 16; em[2374] = 1; /* 2372: struct.asn1_type_st */
    	em[2375] = 2207; em[2376] = 8; 
    em[2377] = 0; em[2378] = 24; em[2379] = 3; /* 2377: struct.GENERAL_SUBTREE_st */
    	em[2380] = 2386; em[2381] = 0; 
    	em[2382] = 2264; em[2383] = 8; 
    	em[2384] = 2264; em[2385] = 16; 
    em[2386] = 1; em[2387] = 8; em[2388] = 1; /* 2386: pointer.struct.GENERAL_NAME_st */
    	em[2389] = 2317; em[2390] = 0; 
    em[2391] = 0; em[2392] = 0; em[2393] = 1; /* 2391: GENERAL_SUBTREE */
    	em[2394] = 2377; em[2395] = 0; 
    em[2396] = 0; em[2397] = 16; em[2398] = 2; /* 2396: struct.NAME_CONSTRAINTS_st */
    	em[2399] = 2403; em[2400] = 0; 
    	em[2401] = 2403; em[2402] = 8; 
    em[2403] = 1; em[2404] = 8; em[2405] = 1; /* 2403: pointer.struct.stack_st_GENERAL_SUBTREE */
    	em[2406] = 2408; em[2407] = 0; 
    em[2408] = 0; em[2409] = 32; em[2410] = 2; /* 2408: struct.stack_st_fake_GENERAL_SUBTREE */
    	em[2411] = 2415; em[2412] = 8; 
    	em[2413] = 621; em[2414] = 24; 
    em[2415] = 8884099; em[2416] = 8; em[2417] = 2; /* 2415: pointer_to_array_of_pointers_to_stack */
    	em[2418] = 2422; em[2419] = 0; 
    	em[2420] = 423; em[2421] = 20; 
    em[2422] = 0; em[2423] = 8; em[2424] = 1; /* 2422: pointer.GENERAL_SUBTREE */
    	em[2425] = 2391; em[2426] = 0; 
    em[2427] = 1; em[2428] = 8; em[2429] = 1; /* 2427: pointer.struct.NAME_CONSTRAINTS_st */
    	em[2430] = 2396; em[2431] = 0; 
    em[2432] = 1; em[2433] = 8; em[2434] = 1; /* 2432: pointer.struct.stack_st_GENERAL_NAME */
    	em[2435] = 2437; em[2436] = 0; 
    em[2437] = 0; em[2438] = 32; em[2439] = 2; /* 2437: struct.stack_st_fake_GENERAL_NAME */
    	em[2440] = 2444; em[2441] = 8; 
    	em[2442] = 621; em[2443] = 24; 
    em[2444] = 8884099; em[2445] = 8; em[2446] = 2; /* 2444: pointer_to_array_of_pointers_to_stack */
    	em[2447] = 2451; em[2448] = 0; 
    	em[2449] = 423; em[2450] = 20; 
    em[2451] = 0; em[2452] = 8; em[2453] = 1; /* 2451: pointer.GENERAL_NAME */
    	em[2454] = 2456; em[2455] = 0; 
    em[2456] = 0; em[2457] = 0; em[2458] = 1; /* 2456: GENERAL_NAME */
    	em[2459] = 2461; em[2460] = 0; 
    em[2461] = 0; em[2462] = 16; em[2463] = 1; /* 2461: struct.GENERAL_NAME_st */
    	em[2464] = 2466; em[2465] = 8; 
    em[2466] = 0; em[2467] = 8; em[2468] = 15; /* 2466: union.unknown */
    	em[2469] = 616; em[2470] = 0; 
    	em[2471] = 2499; em[2472] = 0; 
    	em[2473] = 2618; em[2474] = 0; 
    	em[2475] = 2618; em[2476] = 0; 
    	em[2477] = 2525; em[2478] = 0; 
    	em[2479] = 2666; em[2480] = 0; 
    	em[2481] = 2714; em[2482] = 0; 
    	em[2483] = 2618; em[2484] = 0; 
    	em[2485] = 2603; em[2486] = 0; 
    	em[2487] = 2511; em[2488] = 0; 
    	em[2489] = 2603; em[2490] = 0; 
    	em[2491] = 2666; em[2492] = 0; 
    	em[2493] = 2618; em[2494] = 0; 
    	em[2495] = 2511; em[2496] = 0; 
    	em[2497] = 2525; em[2498] = 0; 
    em[2499] = 1; em[2500] = 8; em[2501] = 1; /* 2499: pointer.struct.otherName_st */
    	em[2502] = 2504; em[2503] = 0; 
    em[2504] = 0; em[2505] = 16; em[2506] = 2; /* 2504: struct.otherName_st */
    	em[2507] = 2511; em[2508] = 0; 
    	em[2509] = 2525; em[2510] = 8; 
    em[2511] = 1; em[2512] = 8; em[2513] = 1; /* 2511: pointer.struct.asn1_object_st */
    	em[2514] = 2516; em[2515] = 0; 
    em[2516] = 0; em[2517] = 40; em[2518] = 3; /* 2516: struct.asn1_object_st */
    	em[2519] = 648; em[2520] = 0; 
    	em[2521] = 648; em[2522] = 8; 
    	em[2523] = 1480; em[2524] = 24; 
    em[2525] = 1; em[2526] = 8; em[2527] = 1; /* 2525: pointer.struct.asn1_type_st */
    	em[2528] = 2530; em[2529] = 0; 
    em[2530] = 0; em[2531] = 16; em[2532] = 1; /* 2530: struct.asn1_type_st */
    	em[2533] = 2535; em[2534] = 8; 
    em[2535] = 0; em[2536] = 8; em[2537] = 20; /* 2535: union.unknown */
    	em[2538] = 616; em[2539] = 0; 
    	em[2540] = 2578; em[2541] = 0; 
    	em[2542] = 2511; em[2543] = 0; 
    	em[2544] = 2588; em[2545] = 0; 
    	em[2546] = 2593; em[2547] = 0; 
    	em[2548] = 2598; em[2549] = 0; 
    	em[2550] = 2603; em[2551] = 0; 
    	em[2552] = 2608; em[2553] = 0; 
    	em[2554] = 2613; em[2555] = 0; 
    	em[2556] = 2618; em[2557] = 0; 
    	em[2558] = 2623; em[2559] = 0; 
    	em[2560] = 2628; em[2561] = 0; 
    	em[2562] = 2633; em[2563] = 0; 
    	em[2564] = 2638; em[2565] = 0; 
    	em[2566] = 2643; em[2567] = 0; 
    	em[2568] = 2648; em[2569] = 0; 
    	em[2570] = 2653; em[2571] = 0; 
    	em[2572] = 2578; em[2573] = 0; 
    	em[2574] = 2578; em[2575] = 0; 
    	em[2576] = 2658; em[2577] = 0; 
    em[2578] = 1; em[2579] = 8; em[2580] = 1; /* 2578: pointer.struct.asn1_string_st */
    	em[2581] = 2583; em[2582] = 0; 
    em[2583] = 0; em[2584] = 24; em[2585] = 1; /* 2583: struct.asn1_string_st */
    	em[2586] = 438; em[2587] = 8; 
    em[2588] = 1; em[2589] = 8; em[2590] = 1; /* 2588: pointer.struct.asn1_string_st */
    	em[2591] = 2583; em[2592] = 0; 
    em[2593] = 1; em[2594] = 8; em[2595] = 1; /* 2593: pointer.struct.asn1_string_st */
    	em[2596] = 2583; em[2597] = 0; 
    em[2598] = 1; em[2599] = 8; em[2600] = 1; /* 2598: pointer.struct.asn1_string_st */
    	em[2601] = 2583; em[2602] = 0; 
    em[2603] = 1; em[2604] = 8; em[2605] = 1; /* 2603: pointer.struct.asn1_string_st */
    	em[2606] = 2583; em[2607] = 0; 
    em[2608] = 1; em[2609] = 8; em[2610] = 1; /* 2608: pointer.struct.asn1_string_st */
    	em[2611] = 2583; em[2612] = 0; 
    em[2613] = 1; em[2614] = 8; em[2615] = 1; /* 2613: pointer.struct.asn1_string_st */
    	em[2616] = 2583; em[2617] = 0; 
    em[2618] = 1; em[2619] = 8; em[2620] = 1; /* 2618: pointer.struct.asn1_string_st */
    	em[2621] = 2583; em[2622] = 0; 
    em[2623] = 1; em[2624] = 8; em[2625] = 1; /* 2623: pointer.struct.asn1_string_st */
    	em[2626] = 2583; em[2627] = 0; 
    em[2628] = 1; em[2629] = 8; em[2630] = 1; /* 2628: pointer.struct.asn1_string_st */
    	em[2631] = 2583; em[2632] = 0; 
    em[2633] = 1; em[2634] = 8; em[2635] = 1; /* 2633: pointer.struct.asn1_string_st */
    	em[2636] = 2583; em[2637] = 0; 
    em[2638] = 1; em[2639] = 8; em[2640] = 1; /* 2638: pointer.struct.asn1_string_st */
    	em[2641] = 2583; em[2642] = 0; 
    em[2643] = 1; em[2644] = 8; em[2645] = 1; /* 2643: pointer.struct.asn1_string_st */
    	em[2646] = 2583; em[2647] = 0; 
    em[2648] = 1; em[2649] = 8; em[2650] = 1; /* 2648: pointer.struct.asn1_string_st */
    	em[2651] = 2583; em[2652] = 0; 
    em[2653] = 1; em[2654] = 8; em[2655] = 1; /* 2653: pointer.struct.asn1_string_st */
    	em[2656] = 2583; em[2657] = 0; 
    em[2658] = 1; em[2659] = 8; em[2660] = 1; /* 2658: pointer.struct.ASN1_VALUE_st */
    	em[2661] = 2663; em[2662] = 0; 
    em[2663] = 0; em[2664] = 0; em[2665] = 0; /* 2663: struct.ASN1_VALUE_st */
    em[2666] = 1; em[2667] = 8; em[2668] = 1; /* 2666: pointer.struct.X509_name_st */
    	em[2669] = 2671; em[2670] = 0; 
    em[2671] = 0; em[2672] = 40; em[2673] = 3; /* 2671: struct.X509_name_st */
    	em[2674] = 2680; em[2675] = 0; 
    	em[2676] = 2704; em[2677] = 16; 
    	em[2678] = 438; em[2679] = 24; 
    em[2680] = 1; em[2681] = 8; em[2682] = 1; /* 2680: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[2683] = 2685; em[2684] = 0; 
    em[2685] = 0; em[2686] = 32; em[2687] = 2; /* 2685: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[2688] = 2692; em[2689] = 8; 
    	em[2690] = 621; em[2691] = 24; 
    em[2692] = 8884099; em[2693] = 8; em[2694] = 2; /* 2692: pointer_to_array_of_pointers_to_stack */
    	em[2695] = 2699; em[2696] = 0; 
    	em[2697] = 423; em[2698] = 20; 
    em[2699] = 0; em[2700] = 8; em[2701] = 1; /* 2699: pointer.X509_NAME_ENTRY */
    	em[2702] = 2127; em[2703] = 0; 
    em[2704] = 1; em[2705] = 8; em[2706] = 1; /* 2704: pointer.struct.buf_mem_st */
    	em[2707] = 2709; em[2708] = 0; 
    em[2709] = 0; em[2710] = 24; em[2711] = 1; /* 2709: struct.buf_mem_st */
    	em[2712] = 616; em[2713] = 8; 
    em[2714] = 1; em[2715] = 8; em[2716] = 1; /* 2714: pointer.struct.EDIPartyName_st */
    	em[2717] = 2719; em[2718] = 0; 
    em[2719] = 0; em[2720] = 16; em[2721] = 2; /* 2719: struct.EDIPartyName_st */
    	em[2722] = 2578; em[2723] = 0; 
    	em[2724] = 2578; em[2725] = 8; 
    em[2726] = 0; em[2727] = 24; em[2728] = 1; /* 2726: struct.asn1_string_st */
    	em[2729] = 438; em[2730] = 8; 
    em[2731] = 1; em[2732] = 8; em[2733] = 1; /* 2731: pointer.struct.buf_mem_st */
    	em[2734] = 2736; em[2735] = 0; 
    em[2736] = 0; em[2737] = 24; em[2738] = 1; /* 2736: struct.buf_mem_st */
    	em[2739] = 616; em[2740] = 8; 
    em[2741] = 0; em[2742] = 40; em[2743] = 3; /* 2741: struct.X509_name_st */
    	em[2744] = 2750; em[2745] = 0; 
    	em[2746] = 2731; em[2747] = 16; 
    	em[2748] = 438; em[2749] = 24; 
    em[2750] = 1; em[2751] = 8; em[2752] = 1; /* 2750: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[2753] = 2755; em[2754] = 0; 
    em[2755] = 0; em[2756] = 32; em[2757] = 2; /* 2755: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[2758] = 2762; em[2759] = 8; 
    	em[2760] = 621; em[2761] = 24; 
    em[2762] = 8884099; em[2763] = 8; em[2764] = 2; /* 2762: pointer_to_array_of_pointers_to_stack */
    	em[2765] = 2769; em[2766] = 0; 
    	em[2767] = 423; em[2768] = 20; 
    em[2769] = 0; em[2770] = 8; em[2771] = 1; /* 2769: pointer.X509_NAME_ENTRY */
    	em[2772] = 2127; em[2773] = 0; 
    em[2774] = 1; em[2775] = 8; em[2776] = 1; /* 2774: pointer.struct.stack_st_ASN1_OBJECT */
    	em[2777] = 2779; em[2778] = 0; 
    em[2779] = 0; em[2780] = 32; em[2781] = 2; /* 2779: struct.stack_st_fake_ASN1_OBJECT */
    	em[2782] = 2786; em[2783] = 8; 
    	em[2784] = 621; em[2785] = 24; 
    em[2786] = 8884099; em[2787] = 8; em[2788] = 2; /* 2786: pointer_to_array_of_pointers_to_stack */
    	em[2789] = 2793; em[2790] = 0; 
    	em[2791] = 423; em[2792] = 20; 
    em[2793] = 0; em[2794] = 8; em[2795] = 1; /* 2793: pointer.ASN1_OBJECT */
    	em[2796] = 1848; em[2797] = 0; 
    em[2798] = 1; em[2799] = 8; em[2800] = 1; /* 2798: pointer.struct.stack_st_POLICYQUALINFO */
    	em[2801] = 2803; em[2802] = 0; 
    em[2803] = 0; em[2804] = 32; em[2805] = 2; /* 2803: struct.stack_st_fake_POLICYQUALINFO */
    	em[2806] = 2810; em[2807] = 8; 
    	em[2808] = 621; em[2809] = 24; 
    em[2810] = 8884099; em[2811] = 8; em[2812] = 2; /* 2810: pointer_to_array_of_pointers_to_stack */
    	em[2813] = 2817; em[2814] = 0; 
    	em[2815] = 423; em[2816] = 20; 
    em[2817] = 0; em[2818] = 8; em[2819] = 1; /* 2817: pointer.POLICYQUALINFO */
    	em[2820] = 2822; em[2821] = 0; 
    em[2822] = 0; em[2823] = 0; em[2824] = 1; /* 2822: POLICYQUALINFO */
    	em[2825] = 2827; em[2826] = 0; 
    em[2827] = 0; em[2828] = 16; em[2829] = 2; /* 2827: struct.POLICYQUALINFO_st */
    	em[2830] = 2834; em[2831] = 0; 
    	em[2832] = 2848; em[2833] = 8; 
    em[2834] = 1; em[2835] = 8; em[2836] = 1; /* 2834: pointer.struct.asn1_object_st */
    	em[2837] = 2839; em[2838] = 0; 
    em[2839] = 0; em[2840] = 40; em[2841] = 3; /* 2839: struct.asn1_object_st */
    	em[2842] = 648; em[2843] = 0; 
    	em[2844] = 648; em[2845] = 8; 
    	em[2846] = 1480; em[2847] = 24; 
    em[2848] = 0; em[2849] = 8; em[2850] = 3; /* 2848: union.unknown */
    	em[2851] = 2857; em[2852] = 0; 
    	em[2853] = 2867; em[2854] = 0; 
    	em[2855] = 2930; em[2856] = 0; 
    em[2857] = 1; em[2858] = 8; em[2859] = 1; /* 2857: pointer.struct.asn1_string_st */
    	em[2860] = 2862; em[2861] = 0; 
    em[2862] = 0; em[2863] = 24; em[2864] = 1; /* 2862: struct.asn1_string_st */
    	em[2865] = 438; em[2866] = 8; 
    em[2867] = 1; em[2868] = 8; em[2869] = 1; /* 2867: pointer.struct.USERNOTICE_st */
    	em[2870] = 2872; em[2871] = 0; 
    em[2872] = 0; em[2873] = 16; em[2874] = 2; /* 2872: struct.USERNOTICE_st */
    	em[2875] = 2879; em[2876] = 0; 
    	em[2877] = 2891; em[2878] = 8; 
    em[2879] = 1; em[2880] = 8; em[2881] = 1; /* 2879: pointer.struct.NOTICEREF_st */
    	em[2882] = 2884; em[2883] = 0; 
    em[2884] = 0; em[2885] = 16; em[2886] = 2; /* 2884: struct.NOTICEREF_st */
    	em[2887] = 2891; em[2888] = 0; 
    	em[2889] = 2896; em[2890] = 8; 
    em[2891] = 1; em[2892] = 8; em[2893] = 1; /* 2891: pointer.struct.asn1_string_st */
    	em[2894] = 2862; em[2895] = 0; 
    em[2896] = 1; em[2897] = 8; em[2898] = 1; /* 2896: pointer.struct.stack_st_ASN1_INTEGER */
    	em[2899] = 2901; em[2900] = 0; 
    em[2901] = 0; em[2902] = 32; em[2903] = 2; /* 2901: struct.stack_st_fake_ASN1_INTEGER */
    	em[2904] = 2908; em[2905] = 8; 
    	em[2906] = 621; em[2907] = 24; 
    em[2908] = 8884099; em[2909] = 8; em[2910] = 2; /* 2908: pointer_to_array_of_pointers_to_stack */
    	em[2911] = 2915; em[2912] = 0; 
    	em[2913] = 423; em[2914] = 20; 
    em[2915] = 0; em[2916] = 8; em[2917] = 1; /* 2915: pointer.ASN1_INTEGER */
    	em[2918] = 2920; em[2919] = 0; 
    em[2920] = 0; em[2921] = 0; em[2922] = 1; /* 2920: ASN1_INTEGER */
    	em[2923] = 2925; em[2924] = 0; 
    em[2925] = 0; em[2926] = 24; em[2927] = 1; /* 2925: struct.asn1_string_st */
    	em[2928] = 438; em[2929] = 8; 
    em[2930] = 1; em[2931] = 8; em[2932] = 1; /* 2930: pointer.struct.asn1_type_st */
    	em[2933] = 2935; em[2934] = 0; 
    em[2935] = 0; em[2936] = 16; em[2937] = 1; /* 2935: struct.asn1_type_st */
    	em[2938] = 2940; em[2939] = 8; 
    em[2940] = 0; em[2941] = 8; em[2942] = 20; /* 2940: union.unknown */
    	em[2943] = 616; em[2944] = 0; 
    	em[2945] = 2891; em[2946] = 0; 
    	em[2947] = 2834; em[2948] = 0; 
    	em[2949] = 2983; em[2950] = 0; 
    	em[2951] = 2988; em[2952] = 0; 
    	em[2953] = 2993; em[2954] = 0; 
    	em[2955] = 2998; em[2956] = 0; 
    	em[2957] = 3003; em[2958] = 0; 
    	em[2959] = 3008; em[2960] = 0; 
    	em[2961] = 2857; em[2962] = 0; 
    	em[2963] = 3013; em[2964] = 0; 
    	em[2965] = 3018; em[2966] = 0; 
    	em[2967] = 3023; em[2968] = 0; 
    	em[2969] = 3028; em[2970] = 0; 
    	em[2971] = 3033; em[2972] = 0; 
    	em[2973] = 3038; em[2974] = 0; 
    	em[2975] = 3043; em[2976] = 0; 
    	em[2977] = 2891; em[2978] = 0; 
    	em[2979] = 2891; em[2980] = 0; 
    	em[2981] = 2309; em[2982] = 0; 
    em[2983] = 1; em[2984] = 8; em[2985] = 1; /* 2983: pointer.struct.asn1_string_st */
    	em[2986] = 2862; em[2987] = 0; 
    em[2988] = 1; em[2989] = 8; em[2990] = 1; /* 2988: pointer.struct.asn1_string_st */
    	em[2991] = 2862; em[2992] = 0; 
    em[2993] = 1; em[2994] = 8; em[2995] = 1; /* 2993: pointer.struct.asn1_string_st */
    	em[2996] = 2862; em[2997] = 0; 
    em[2998] = 1; em[2999] = 8; em[3000] = 1; /* 2998: pointer.struct.asn1_string_st */
    	em[3001] = 2862; em[3002] = 0; 
    em[3003] = 1; em[3004] = 8; em[3005] = 1; /* 3003: pointer.struct.asn1_string_st */
    	em[3006] = 2862; em[3007] = 0; 
    em[3008] = 1; em[3009] = 8; em[3010] = 1; /* 3008: pointer.struct.asn1_string_st */
    	em[3011] = 2862; em[3012] = 0; 
    em[3013] = 1; em[3014] = 8; em[3015] = 1; /* 3013: pointer.struct.asn1_string_st */
    	em[3016] = 2862; em[3017] = 0; 
    em[3018] = 1; em[3019] = 8; em[3020] = 1; /* 3018: pointer.struct.asn1_string_st */
    	em[3021] = 2862; em[3022] = 0; 
    em[3023] = 1; em[3024] = 8; em[3025] = 1; /* 3023: pointer.struct.asn1_string_st */
    	em[3026] = 2862; em[3027] = 0; 
    em[3028] = 1; em[3029] = 8; em[3030] = 1; /* 3028: pointer.struct.asn1_string_st */
    	em[3031] = 2862; em[3032] = 0; 
    em[3033] = 1; em[3034] = 8; em[3035] = 1; /* 3033: pointer.struct.asn1_string_st */
    	em[3036] = 2862; em[3037] = 0; 
    em[3038] = 1; em[3039] = 8; em[3040] = 1; /* 3038: pointer.struct.asn1_string_st */
    	em[3041] = 2862; em[3042] = 0; 
    em[3043] = 1; em[3044] = 8; em[3045] = 1; /* 3043: pointer.struct.asn1_string_st */
    	em[3046] = 2862; em[3047] = 0; 
    em[3048] = 1; em[3049] = 8; em[3050] = 1; /* 3048: pointer.struct.asn1_object_st */
    	em[3051] = 3053; em[3052] = 0; 
    em[3053] = 0; em[3054] = 40; em[3055] = 3; /* 3053: struct.asn1_object_st */
    	em[3056] = 648; em[3057] = 0; 
    	em[3058] = 648; em[3059] = 8; 
    	em[3060] = 1480; em[3061] = 24; 
    em[3062] = 0; em[3063] = 32; em[3064] = 3; /* 3062: struct.X509_POLICY_DATA_st */
    	em[3065] = 3048; em[3066] = 8; 
    	em[3067] = 2798; em[3068] = 16; 
    	em[3069] = 2774; em[3070] = 24; 
    em[3071] = 0; em[3072] = 8; em[3073] = 2; /* 3071: union.unknown */
    	em[3074] = 3078; em[3075] = 0; 
    	em[3076] = 2750; em[3077] = 0; 
    em[3078] = 1; em[3079] = 8; em[3080] = 1; /* 3078: pointer.struct.stack_st_GENERAL_NAME */
    	em[3081] = 3083; em[3082] = 0; 
    em[3083] = 0; em[3084] = 32; em[3085] = 2; /* 3083: struct.stack_st_fake_GENERAL_NAME */
    	em[3086] = 3090; em[3087] = 8; 
    	em[3088] = 621; em[3089] = 24; 
    em[3090] = 8884099; em[3091] = 8; em[3092] = 2; /* 3090: pointer_to_array_of_pointers_to_stack */
    	em[3093] = 3097; em[3094] = 0; 
    	em[3095] = 423; em[3096] = 20; 
    em[3097] = 0; em[3098] = 8; em[3099] = 1; /* 3097: pointer.GENERAL_NAME */
    	em[3100] = 2456; em[3101] = 0; 
    em[3102] = 1; em[3103] = 8; em[3104] = 1; /* 3102: pointer.struct.stack_st_X509_POLICY_DATA */
    	em[3105] = 3107; em[3106] = 0; 
    em[3107] = 0; em[3108] = 32; em[3109] = 2; /* 3107: struct.stack_st_fake_X509_POLICY_DATA */
    	em[3110] = 3114; em[3111] = 8; 
    	em[3112] = 621; em[3113] = 24; 
    em[3114] = 8884099; em[3115] = 8; em[3116] = 2; /* 3114: pointer_to_array_of_pointers_to_stack */
    	em[3117] = 3121; em[3118] = 0; 
    	em[3119] = 423; em[3120] = 20; 
    em[3121] = 0; em[3122] = 8; em[3123] = 1; /* 3121: pointer.X509_POLICY_DATA */
    	em[3124] = 3126; em[3125] = 0; 
    em[3126] = 0; em[3127] = 0; em[3128] = 1; /* 3126: X509_POLICY_DATA */
    	em[3129] = 3062; em[3130] = 0; 
    em[3131] = 1; em[3132] = 8; em[3133] = 1; /* 3131: pointer.struct.asn1_object_st */
    	em[3134] = 3136; em[3135] = 0; 
    em[3136] = 0; em[3137] = 40; em[3138] = 3; /* 3136: struct.asn1_object_st */
    	em[3139] = 648; em[3140] = 0; 
    	em[3141] = 648; em[3142] = 8; 
    	em[3143] = 1480; em[3144] = 24; 
    em[3145] = 0; em[3146] = 32; em[3147] = 3; /* 3145: struct.X509_POLICY_DATA_st */
    	em[3148] = 3131; em[3149] = 8; 
    	em[3150] = 3154; em[3151] = 16; 
    	em[3152] = 3178; em[3153] = 24; 
    em[3154] = 1; em[3155] = 8; em[3156] = 1; /* 3154: pointer.struct.stack_st_POLICYQUALINFO */
    	em[3157] = 3159; em[3158] = 0; 
    em[3159] = 0; em[3160] = 32; em[3161] = 2; /* 3159: struct.stack_st_fake_POLICYQUALINFO */
    	em[3162] = 3166; em[3163] = 8; 
    	em[3164] = 621; em[3165] = 24; 
    em[3166] = 8884099; em[3167] = 8; em[3168] = 2; /* 3166: pointer_to_array_of_pointers_to_stack */
    	em[3169] = 3173; em[3170] = 0; 
    	em[3171] = 423; em[3172] = 20; 
    em[3173] = 0; em[3174] = 8; em[3175] = 1; /* 3173: pointer.POLICYQUALINFO */
    	em[3176] = 2822; em[3177] = 0; 
    em[3178] = 1; em[3179] = 8; em[3180] = 1; /* 3178: pointer.struct.stack_st_ASN1_OBJECT */
    	em[3181] = 3183; em[3182] = 0; 
    em[3183] = 0; em[3184] = 32; em[3185] = 2; /* 3183: struct.stack_st_fake_ASN1_OBJECT */
    	em[3186] = 3190; em[3187] = 8; 
    	em[3188] = 621; em[3189] = 24; 
    em[3190] = 8884099; em[3191] = 8; em[3192] = 2; /* 3190: pointer_to_array_of_pointers_to_stack */
    	em[3193] = 3197; em[3194] = 0; 
    	em[3195] = 423; em[3196] = 20; 
    em[3197] = 0; em[3198] = 8; em[3199] = 1; /* 3197: pointer.ASN1_OBJECT */
    	em[3200] = 1848; em[3201] = 0; 
    em[3202] = 0; em[3203] = 40; em[3204] = 2; /* 3202: struct.X509_POLICY_CACHE_st */
    	em[3205] = 3209; em[3206] = 0; 
    	em[3207] = 3102; em[3208] = 8; 
    em[3209] = 1; em[3210] = 8; em[3211] = 1; /* 3209: pointer.struct.X509_POLICY_DATA_st */
    	em[3212] = 3145; em[3213] = 0; 
    em[3214] = 1; em[3215] = 8; em[3216] = 1; /* 3214: pointer.struct.asn1_string_st */
    	em[3217] = 3219; em[3218] = 0; 
    em[3219] = 0; em[3220] = 24; em[3221] = 1; /* 3219: struct.asn1_string_st */
    	em[3222] = 438; em[3223] = 8; 
    em[3224] = 1; em[3225] = 8; em[3226] = 1; /* 3224: pointer.struct.stack_st_GENERAL_NAME */
    	em[3227] = 3229; em[3228] = 0; 
    em[3229] = 0; em[3230] = 32; em[3231] = 2; /* 3229: struct.stack_st_fake_GENERAL_NAME */
    	em[3232] = 3236; em[3233] = 8; 
    	em[3234] = 621; em[3235] = 24; 
    em[3236] = 8884099; em[3237] = 8; em[3238] = 2; /* 3236: pointer_to_array_of_pointers_to_stack */
    	em[3239] = 3243; em[3240] = 0; 
    	em[3241] = 423; em[3242] = 20; 
    em[3243] = 0; em[3244] = 8; em[3245] = 1; /* 3243: pointer.GENERAL_NAME */
    	em[3246] = 2456; em[3247] = 0; 
    em[3248] = 1; em[3249] = 8; em[3250] = 1; /* 3248: pointer.struct.asn1_string_st */
    	em[3251] = 3219; em[3252] = 0; 
    em[3253] = 1; em[3254] = 8; em[3255] = 1; /* 3253: pointer.struct.AUTHORITY_KEYID_st */
    	em[3256] = 3258; em[3257] = 0; 
    em[3258] = 0; em[3259] = 24; em[3260] = 3; /* 3258: struct.AUTHORITY_KEYID_st */
    	em[3261] = 3248; em[3262] = 0; 
    	em[3263] = 3224; em[3264] = 8; 
    	em[3265] = 3214; em[3266] = 16; 
    em[3267] = 0; em[3268] = 32; em[3269] = 1; /* 3267: struct.stack_st_void */
    	em[3270] = 3272; em[3271] = 0; 
    em[3272] = 0; em[3273] = 32; em[3274] = 2; /* 3272: struct.stack_st */
    	em[3275] = 611; em[3276] = 8; 
    	em[3277] = 621; em[3278] = 24; 
    em[3279] = 0; em[3280] = 16; em[3281] = 1; /* 3279: struct.crypto_ex_data_st */
    	em[3282] = 3284; em[3283] = 0; 
    em[3284] = 1; em[3285] = 8; em[3286] = 1; /* 3284: pointer.struct.stack_st_void */
    	em[3287] = 3267; em[3288] = 0; 
    em[3289] = 0; em[3290] = 40; em[3291] = 3; /* 3289: struct.asn1_object_st */
    	em[3292] = 648; em[3293] = 0; 
    	em[3294] = 648; em[3295] = 8; 
    	em[3296] = 1480; em[3297] = 24; 
    em[3298] = 0; em[3299] = 24; em[3300] = 2; /* 3298: struct.X509_extension_st */
    	em[3301] = 3305; em[3302] = 0; 
    	em[3303] = 3310; em[3304] = 16; 
    em[3305] = 1; em[3306] = 8; em[3307] = 1; /* 3305: pointer.struct.asn1_object_st */
    	em[3308] = 3289; em[3309] = 0; 
    em[3310] = 1; em[3311] = 8; em[3312] = 1; /* 3310: pointer.struct.asn1_string_st */
    	em[3313] = 3315; em[3314] = 0; 
    em[3315] = 0; em[3316] = 24; em[3317] = 1; /* 3315: struct.asn1_string_st */
    	em[3318] = 438; em[3319] = 8; 
    em[3320] = 0; em[3321] = 0; em[3322] = 1; /* 3320: X509_EXTENSION */
    	em[3323] = 3298; em[3324] = 0; 
    em[3325] = 1; em[3326] = 8; em[3327] = 1; /* 3325: pointer.struct.stack_st_X509_EXTENSION */
    	em[3328] = 3330; em[3329] = 0; 
    em[3330] = 0; em[3331] = 32; em[3332] = 2; /* 3330: struct.stack_st_fake_X509_EXTENSION */
    	em[3333] = 3337; em[3334] = 8; 
    	em[3335] = 621; em[3336] = 24; 
    em[3337] = 8884099; em[3338] = 8; em[3339] = 2; /* 3337: pointer_to_array_of_pointers_to_stack */
    	em[3340] = 3344; em[3341] = 0; 
    	em[3342] = 423; em[3343] = 20; 
    em[3344] = 0; em[3345] = 8; em[3346] = 1; /* 3344: pointer.X509_EXTENSION */
    	em[3347] = 3320; em[3348] = 0; 
    em[3349] = 1; em[3350] = 8; em[3351] = 1; /* 3349: pointer.struct.asn1_string_st */
    	em[3352] = 1819; em[3353] = 0; 
    em[3354] = 0; em[3355] = 24; em[3356] = 1; /* 3354: struct.ASN1_ENCODING_st */
    	em[3357] = 438; em[3358] = 0; 
    em[3359] = 0; em[3360] = 0; em[3361] = 1; /* 3359: DIST_POINT */
    	em[3362] = 3364; em[3363] = 0; 
    em[3364] = 0; em[3365] = 32; em[3366] = 3; /* 3364: struct.DIST_POINT_st */
    	em[3367] = 3373; em[3368] = 0; 
    	em[3369] = 3390; em[3370] = 8; 
    	em[3371] = 3078; em[3372] = 16; 
    em[3373] = 1; em[3374] = 8; em[3375] = 1; /* 3373: pointer.struct.DIST_POINT_NAME_st */
    	em[3376] = 3378; em[3377] = 0; 
    em[3378] = 0; em[3379] = 24; em[3380] = 2; /* 3378: struct.DIST_POINT_NAME_st */
    	em[3381] = 3071; em[3382] = 8; 
    	em[3383] = 3385; em[3384] = 16; 
    em[3385] = 1; em[3386] = 8; em[3387] = 1; /* 3385: pointer.struct.X509_name_st */
    	em[3388] = 2741; em[3389] = 0; 
    em[3390] = 1; em[3391] = 8; em[3392] = 1; /* 3390: pointer.struct.asn1_string_st */
    	em[3393] = 2726; em[3394] = 0; 
    em[3395] = 1; em[3396] = 8; em[3397] = 1; /* 3395: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[3398] = 3400; em[3399] = 0; 
    em[3400] = 0; em[3401] = 32; em[3402] = 2; /* 3400: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[3403] = 3407; em[3404] = 8; 
    	em[3405] = 621; em[3406] = 24; 
    em[3407] = 8884099; em[3408] = 8; em[3409] = 2; /* 3407: pointer_to_array_of_pointers_to_stack */
    	em[3410] = 3414; em[3411] = 0; 
    	em[3412] = 423; em[3413] = 20; 
    em[3414] = 0; em[3415] = 8; em[3416] = 1; /* 3414: pointer.X509_ATTRIBUTE */
    	em[3417] = 1454; em[3418] = 0; 
    em[3419] = 0; em[3420] = 8; em[3421] = 5; /* 3419: union.unknown */
    	em[3422] = 616; em[3423] = 0; 
    	em[3424] = 3432; em[3425] = 0; 
    	em[3426] = 3437; em[3427] = 0; 
    	em[3428] = 3442; em[3429] = 0; 
    	em[3430] = 3447; em[3431] = 0; 
    em[3432] = 1; em[3433] = 8; em[3434] = 1; /* 3432: pointer.struct.rsa_st */
    	em[3435] = 1152; em[3436] = 0; 
    em[3437] = 1; em[3438] = 8; em[3439] = 1; /* 3437: pointer.struct.dsa_st */
    	em[3440] = 1018; em[3441] = 0; 
    em[3442] = 1; em[3443] = 8; em[3444] = 1; /* 3442: pointer.struct.dh_st */
    	em[3445] = 531; em[3446] = 0; 
    em[3447] = 1; em[3448] = 8; em[3449] = 1; /* 3447: pointer.struct.ec_key_st */
    	em[3450] = 5; em[3451] = 0; 
    em[3452] = 1; em[3453] = 8; em[3454] = 1; /* 3452: pointer.struct.X509_val_st */
    	em[3455] = 3457; em[3456] = 0; 
    em[3457] = 0; em[3458] = 16; em[3459] = 2; /* 3457: struct.X509_val_st */
    	em[3460] = 3464; em[3461] = 0; 
    	em[3462] = 3464; em[3463] = 8; 
    em[3464] = 1; em[3465] = 8; em[3466] = 1; /* 3464: pointer.struct.asn1_string_st */
    	em[3467] = 1819; em[3468] = 0; 
    em[3469] = 1; em[3470] = 8; em[3471] = 1; /* 3469: pointer.struct.evp_pkey_st */
    	em[3472] = 1305; em[3473] = 0; 
    em[3474] = 1; em[3475] = 8; em[3476] = 1; /* 3474: pointer.struct.evp_pkey_asn1_method_st */
    	em[3477] = 1321; em[3478] = 0; 
    em[3479] = 0; em[3480] = 56; em[3481] = 4; /* 3479: struct.evp_pkey_st */
    	em[3482] = 3474; em[3483] = 16; 
    	em[3484] = 3490; em[3485] = 24; 
    	em[3486] = 3419; em[3487] = 32; 
    	em[3488] = 3395; em[3489] = 48; 
    em[3490] = 1; em[3491] = 8; em[3492] = 1; /* 3490: pointer.struct.engine_st */
    	em[3493] = 670; em[3494] = 0; 
    em[3495] = 1; em[3496] = 8; em[3497] = 1; /* 3495: pointer.struct.buf_mem_st */
    	em[3498] = 3500; em[3499] = 0; 
    em[3500] = 0; em[3501] = 24; em[3502] = 1; /* 3500: struct.buf_mem_st */
    	em[3503] = 616; em[3504] = 8; 
    em[3505] = 1; em[3506] = 8; em[3507] = 1; /* 3505: pointer.struct.stack_st_DIST_POINT */
    	em[3508] = 3510; em[3509] = 0; 
    em[3510] = 0; em[3511] = 32; em[3512] = 2; /* 3510: struct.stack_st_fake_DIST_POINT */
    	em[3513] = 3517; em[3514] = 8; 
    	em[3515] = 621; em[3516] = 24; 
    em[3517] = 8884099; em[3518] = 8; em[3519] = 2; /* 3517: pointer_to_array_of_pointers_to_stack */
    	em[3520] = 3524; em[3521] = 0; 
    	em[3522] = 423; em[3523] = 20; 
    em[3524] = 0; em[3525] = 8; em[3526] = 1; /* 3524: pointer.DIST_POINT */
    	em[3527] = 3359; em[3528] = 0; 
    em[3529] = 1; em[3530] = 8; em[3531] = 1; /* 3529: pointer.struct.x509_cinf_st */
    	em[3532] = 3534; em[3533] = 0; 
    em[3534] = 0; em[3535] = 104; em[3536] = 11; /* 3534: struct.x509_cinf_st */
    	em[3537] = 3559; em[3538] = 0; 
    	em[3539] = 3559; em[3540] = 8; 
    	em[3541] = 3564; em[3542] = 16; 
    	em[3543] = 3569; em[3544] = 24; 
    	em[3545] = 3452; em[3546] = 32; 
    	em[3547] = 3569; em[3548] = 40; 
    	em[3549] = 3607; em[3550] = 48; 
    	em[3551] = 3349; em[3552] = 56; 
    	em[3553] = 3349; em[3554] = 64; 
    	em[3555] = 3325; em[3556] = 72; 
    	em[3557] = 3354; em[3558] = 80; 
    em[3559] = 1; em[3560] = 8; em[3561] = 1; /* 3559: pointer.struct.asn1_string_st */
    	em[3562] = 1819; em[3563] = 0; 
    em[3564] = 1; em[3565] = 8; em[3566] = 1; /* 3564: pointer.struct.X509_algor_st */
    	em[3567] = 1909; em[3568] = 0; 
    em[3569] = 1; em[3570] = 8; em[3571] = 1; /* 3569: pointer.struct.X509_name_st */
    	em[3572] = 3574; em[3573] = 0; 
    em[3574] = 0; em[3575] = 40; em[3576] = 3; /* 3574: struct.X509_name_st */
    	em[3577] = 3583; em[3578] = 0; 
    	em[3579] = 3495; em[3580] = 16; 
    	em[3581] = 438; em[3582] = 24; 
    em[3583] = 1; em[3584] = 8; em[3585] = 1; /* 3583: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[3586] = 3588; em[3587] = 0; 
    em[3588] = 0; em[3589] = 32; em[3590] = 2; /* 3588: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[3591] = 3595; em[3592] = 8; 
    	em[3593] = 621; em[3594] = 24; 
    em[3595] = 8884099; em[3596] = 8; em[3597] = 2; /* 3595: pointer_to_array_of_pointers_to_stack */
    	em[3598] = 3602; em[3599] = 0; 
    	em[3600] = 423; em[3601] = 20; 
    em[3602] = 0; em[3603] = 8; em[3604] = 1; /* 3602: pointer.X509_NAME_ENTRY */
    	em[3605] = 2127; em[3606] = 0; 
    em[3607] = 1; em[3608] = 8; em[3609] = 1; /* 3607: pointer.struct.X509_pubkey_st */
    	em[3610] = 3612; em[3611] = 0; 
    em[3612] = 0; em[3613] = 24; em[3614] = 3; /* 3612: struct.X509_pubkey_st */
    	em[3615] = 3621; em[3616] = 0; 
    	em[3617] = 3626; em[3618] = 8; 
    	em[3619] = 3636; em[3620] = 16; 
    em[3621] = 1; em[3622] = 8; em[3623] = 1; /* 3621: pointer.struct.X509_algor_st */
    	em[3624] = 1909; em[3625] = 0; 
    em[3626] = 1; em[3627] = 8; em[3628] = 1; /* 3626: pointer.struct.asn1_string_st */
    	em[3629] = 3631; em[3630] = 0; 
    em[3631] = 0; em[3632] = 24; em[3633] = 1; /* 3631: struct.asn1_string_st */
    	em[3634] = 438; em[3635] = 8; 
    em[3636] = 1; em[3637] = 8; em[3638] = 1; /* 3636: pointer.struct.evp_pkey_st */
    	em[3639] = 3479; em[3640] = 0; 
    em[3641] = 0; em[3642] = 1; em[3643] = 0; /* 3641: char */
    em[3644] = 0; em[3645] = 184; em[3646] = 12; /* 3644: struct.x509_st */
    	em[3647] = 3529; em[3648] = 0; 
    	em[3649] = 3564; em[3650] = 8; 
    	em[3651] = 3349; em[3652] = 16; 
    	em[3653] = 616; em[3654] = 32; 
    	em[3655] = 3279; em[3656] = 40; 
    	em[3657] = 1875; em[3658] = 104; 
    	em[3659] = 3253; em[3660] = 112; 
    	em[3661] = 3671; em[3662] = 120; 
    	em[3663] = 3505; em[3664] = 128; 
    	em[3665] = 2432; em[3666] = 136; 
    	em[3667] = 2427; em[3668] = 144; 
    	em[3669] = 2071; em[3670] = 176; 
    em[3671] = 1; em[3672] = 8; em[3673] = 1; /* 3671: pointer.struct.X509_POLICY_CACHE_st */
    	em[3674] = 3202; em[3675] = 0; 
    em[3676] = 1; em[3677] = 8; em[3678] = 1; /* 3676: pointer.struct.x509_st */
    	em[3679] = 3644; em[3680] = 0; 
    args_addr->arg_entity_index[0] = 3676;
    args_addr->arg_entity_index[1] = 3469;
    args_addr->ret_entity_index = 423;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    EVP_PKEY * new_arg_b = *((EVP_PKEY * *)new_args->args[1]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_X509_check_private_key)(X509 *,EVP_PKEY *);
    orig_X509_check_private_key = dlsym(RTLD_NEXT, "X509_check_private_key");
    *new_ret_ptr = (*orig_X509_check_private_key)(new_arg_a,new_arg_b);

    syscall(889);

    free(args_addr);

    return ret;
}

