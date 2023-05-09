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

EVP_MD_CTX * bb_EVP_MD_CTX_create(void);

EVP_MD_CTX * EVP_MD_CTX_create(void) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_MD_CTX_create called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_MD_CTX_create();
    else {
        EVP_MD_CTX * (*orig_EVP_MD_CTX_create)(void);
        orig_EVP_MD_CTX_create = dlsym(RTLD_NEXT, "EVP_MD_CTX_create");
        return orig_EVP_MD_CTX_create();
    }
}

EVP_MD_CTX * bb_EVP_MD_CTX_create(void) 
{
    EVP_MD_CTX * ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 1; em[1] = 8; em[2] = 1; /* 0: pointer.int */
    	em[3] = 5; em[4] = 0; 
    em[5] = 0; em[6] = 4; em[7] = 0; /* 5: int */
    em[8] = 8884097; em[9] = 8; em[10] = 0; /* 8: pointer.func */
    em[11] = 1; em[12] = 8; em[13] = 1; /* 11: pointer.struct.ASN1_VALUE_st */
    	em[14] = 16; em[15] = 0; 
    em[16] = 0; em[17] = 0; em[18] = 0; /* 16: struct.ASN1_VALUE_st */
    em[19] = 1; em[20] = 8; em[21] = 1; /* 19: pointer.struct.asn1_string_st */
    	em[22] = 24; em[23] = 0; 
    em[24] = 0; em[25] = 24; em[26] = 1; /* 24: struct.asn1_string_st */
    	em[27] = 29; em[28] = 8; 
    em[29] = 1; em[30] = 8; em[31] = 1; /* 29: pointer.unsigned char */
    	em[32] = 34; em[33] = 0; 
    em[34] = 0; em[35] = 1; em[36] = 0; /* 34: unsigned char */
    em[37] = 1; em[38] = 8; em[39] = 1; /* 37: pointer.struct.asn1_string_st */
    	em[40] = 24; em[41] = 0; 
    em[42] = 1; em[43] = 8; em[44] = 1; /* 42: pointer.struct.asn1_string_st */
    	em[45] = 24; em[46] = 0; 
    em[47] = 1; em[48] = 8; em[49] = 1; /* 47: pointer.struct.asn1_string_st */
    	em[50] = 24; em[51] = 0; 
    em[52] = 1; em[53] = 8; em[54] = 1; /* 52: pointer.struct.asn1_string_st */
    	em[55] = 24; em[56] = 0; 
    em[57] = 1; em[58] = 8; em[59] = 1; /* 57: pointer.struct.asn1_string_st */
    	em[60] = 24; em[61] = 0; 
    em[62] = 1; em[63] = 8; em[64] = 1; /* 62: pointer.struct.asn1_string_st */
    	em[65] = 24; em[66] = 0; 
    em[67] = 1; em[68] = 8; em[69] = 1; /* 67: pointer.struct.asn1_string_st */
    	em[70] = 24; em[71] = 0; 
    em[72] = 1; em[73] = 8; em[74] = 1; /* 72: pointer.struct.asn1_string_st */
    	em[75] = 24; em[76] = 0; 
    em[77] = 0; em[78] = 8; em[79] = 20; /* 77: union.unknown */
    	em[80] = 120; em[81] = 0; 
    	em[82] = 125; em[83] = 0; 
    	em[84] = 130; em[85] = 0; 
    	em[86] = 154; em[87] = 0; 
    	em[88] = 72; em[89] = 0; 
    	em[90] = 159; em[91] = 0; 
    	em[92] = 67; em[93] = 0; 
    	em[94] = 164; em[95] = 0; 
    	em[96] = 62; em[97] = 0; 
    	em[98] = 57; em[99] = 0; 
    	em[100] = 52; em[101] = 0; 
    	em[102] = 47; em[103] = 0; 
    	em[104] = 42; em[105] = 0; 
    	em[106] = 169; em[107] = 0; 
    	em[108] = 37; em[109] = 0; 
    	em[110] = 174; em[111] = 0; 
    	em[112] = 19; em[113] = 0; 
    	em[114] = 125; em[115] = 0; 
    	em[116] = 125; em[117] = 0; 
    	em[118] = 11; em[119] = 0; 
    em[120] = 1; em[121] = 8; em[122] = 1; /* 120: pointer.char */
    	em[123] = 8884096; em[124] = 0; 
    em[125] = 1; em[126] = 8; em[127] = 1; /* 125: pointer.struct.asn1_string_st */
    	em[128] = 24; em[129] = 0; 
    em[130] = 1; em[131] = 8; em[132] = 1; /* 130: pointer.struct.asn1_object_st */
    	em[133] = 135; em[134] = 0; 
    em[135] = 0; em[136] = 40; em[137] = 3; /* 135: struct.asn1_object_st */
    	em[138] = 144; em[139] = 0; 
    	em[140] = 144; em[141] = 8; 
    	em[142] = 149; em[143] = 24; 
    em[144] = 1; em[145] = 8; em[146] = 1; /* 144: pointer.char */
    	em[147] = 8884096; em[148] = 0; 
    em[149] = 1; em[150] = 8; em[151] = 1; /* 149: pointer.unsigned char */
    	em[152] = 34; em[153] = 0; 
    em[154] = 1; em[155] = 8; em[156] = 1; /* 154: pointer.struct.asn1_string_st */
    	em[157] = 24; em[158] = 0; 
    em[159] = 1; em[160] = 8; em[161] = 1; /* 159: pointer.struct.asn1_string_st */
    	em[162] = 24; em[163] = 0; 
    em[164] = 1; em[165] = 8; em[166] = 1; /* 164: pointer.struct.asn1_string_st */
    	em[167] = 24; em[168] = 0; 
    em[169] = 1; em[170] = 8; em[171] = 1; /* 169: pointer.struct.asn1_string_st */
    	em[172] = 24; em[173] = 0; 
    em[174] = 1; em[175] = 8; em[176] = 1; /* 174: pointer.struct.asn1_string_st */
    	em[177] = 24; em[178] = 0; 
    em[179] = 0; em[180] = 16; em[181] = 1; /* 179: struct.asn1_type_st */
    	em[182] = 77; em[183] = 8; 
    em[184] = 1; em[185] = 8; em[186] = 1; /* 184: pointer.struct.ASN1_VALUE_st */
    	em[187] = 189; em[188] = 0; 
    em[189] = 0; em[190] = 0; em[191] = 0; /* 189: struct.ASN1_VALUE_st */
    em[192] = 1; em[193] = 8; em[194] = 1; /* 192: pointer.struct.asn1_string_st */
    	em[195] = 197; em[196] = 0; 
    em[197] = 0; em[198] = 24; em[199] = 1; /* 197: struct.asn1_string_st */
    	em[200] = 29; em[201] = 8; 
    em[202] = 1; em[203] = 8; em[204] = 1; /* 202: pointer.struct.asn1_string_st */
    	em[205] = 197; em[206] = 0; 
    em[207] = 1; em[208] = 8; em[209] = 1; /* 207: pointer.struct.asn1_string_st */
    	em[210] = 197; em[211] = 0; 
    em[212] = 1; em[213] = 8; em[214] = 1; /* 212: pointer.struct.asn1_string_st */
    	em[215] = 197; em[216] = 0; 
    em[217] = 1; em[218] = 8; em[219] = 1; /* 217: pointer.struct.asn1_string_st */
    	em[220] = 197; em[221] = 0; 
    em[222] = 1; em[223] = 8; em[224] = 1; /* 222: pointer.struct.asn1_string_st */
    	em[225] = 197; em[226] = 0; 
    em[227] = 0; em[228] = 40; em[229] = 3; /* 227: struct.asn1_object_st */
    	em[230] = 144; em[231] = 0; 
    	em[232] = 144; em[233] = 8; 
    	em[234] = 149; em[235] = 24; 
    em[236] = 1; em[237] = 8; em[238] = 1; /* 236: pointer.struct.asn1_string_st */
    	em[239] = 197; em[240] = 0; 
    em[241] = 0; em[242] = 0; em[243] = 1; /* 241: ASN1_TYPE */
    	em[244] = 246; em[245] = 0; 
    em[246] = 0; em[247] = 16; em[248] = 1; /* 246: struct.asn1_type_st */
    	em[249] = 251; em[250] = 8; 
    em[251] = 0; em[252] = 8; em[253] = 20; /* 251: union.unknown */
    	em[254] = 120; em[255] = 0; 
    	em[256] = 236; em[257] = 0; 
    	em[258] = 294; em[259] = 0; 
    	em[260] = 222; em[261] = 0; 
    	em[262] = 217; em[263] = 0; 
    	em[264] = 212; em[265] = 0; 
    	em[266] = 299; em[267] = 0; 
    	em[268] = 304; em[269] = 0; 
    	em[270] = 207; em[271] = 0; 
    	em[272] = 202; em[273] = 0; 
    	em[274] = 309; em[275] = 0; 
    	em[276] = 314; em[277] = 0; 
    	em[278] = 319; em[279] = 0; 
    	em[280] = 324; em[281] = 0; 
    	em[282] = 329; em[283] = 0; 
    	em[284] = 334; em[285] = 0; 
    	em[286] = 192; em[287] = 0; 
    	em[288] = 236; em[289] = 0; 
    	em[290] = 236; em[291] = 0; 
    	em[292] = 184; em[293] = 0; 
    em[294] = 1; em[295] = 8; em[296] = 1; /* 294: pointer.struct.asn1_object_st */
    	em[297] = 227; em[298] = 0; 
    em[299] = 1; em[300] = 8; em[301] = 1; /* 299: pointer.struct.asn1_string_st */
    	em[302] = 197; em[303] = 0; 
    em[304] = 1; em[305] = 8; em[306] = 1; /* 304: pointer.struct.asn1_string_st */
    	em[307] = 197; em[308] = 0; 
    em[309] = 1; em[310] = 8; em[311] = 1; /* 309: pointer.struct.asn1_string_st */
    	em[312] = 197; em[313] = 0; 
    em[314] = 1; em[315] = 8; em[316] = 1; /* 314: pointer.struct.asn1_string_st */
    	em[317] = 197; em[318] = 0; 
    em[319] = 1; em[320] = 8; em[321] = 1; /* 319: pointer.struct.asn1_string_st */
    	em[322] = 197; em[323] = 0; 
    em[324] = 1; em[325] = 8; em[326] = 1; /* 324: pointer.struct.asn1_string_st */
    	em[327] = 197; em[328] = 0; 
    em[329] = 1; em[330] = 8; em[331] = 1; /* 329: pointer.struct.asn1_string_st */
    	em[332] = 197; em[333] = 0; 
    em[334] = 1; em[335] = 8; em[336] = 1; /* 334: pointer.struct.asn1_string_st */
    	em[337] = 197; em[338] = 0; 
    em[339] = 0; em[340] = 96; em[341] = 3; /* 339: struct.bn_mont_ctx_st */
    	em[342] = 348; em[343] = 8; 
    	em[344] = 348; em[345] = 32; 
    	em[346] = 348; em[347] = 56; 
    em[348] = 0; em[349] = 24; em[350] = 1; /* 348: struct.bignum_st */
    	em[351] = 353; em[352] = 0; 
    em[353] = 8884099; em[354] = 8; em[355] = 2; /* 353: pointer_to_array_of_pointers_to_stack */
    	em[356] = 360; em[357] = 0; 
    	em[358] = 5; em[359] = 12; 
    em[360] = 0; em[361] = 8; em[362] = 0; /* 360: long unsigned int */
    em[363] = 8884097; em[364] = 8; em[365] = 0; /* 363: pointer.func */
    em[366] = 8884097; em[367] = 8; em[368] = 0; /* 366: pointer.func */
    em[369] = 1; em[370] = 8; em[371] = 1; /* 369: pointer.struct.ec_key_st */
    	em[372] = 374; em[373] = 0; 
    em[374] = 0; em[375] = 56; em[376] = 4; /* 374: struct.ec_key_st */
    	em[377] = 385; em[378] = 8; 
    	em[379] = 833; em[380] = 16; 
    	em[381] = 838; em[382] = 24; 
    	em[383] = 855; em[384] = 48; 
    em[385] = 1; em[386] = 8; em[387] = 1; /* 385: pointer.struct.ec_group_st */
    	em[388] = 390; em[389] = 0; 
    em[390] = 0; em[391] = 232; em[392] = 12; /* 390: struct.ec_group_st */
    	em[393] = 417; em[394] = 0; 
    	em[395] = 586; em[396] = 8; 
    	em[397] = 786; em[398] = 16; 
    	em[399] = 786; em[400] = 40; 
    	em[401] = 29; em[402] = 80; 
    	em[403] = 798; em[404] = 96; 
    	em[405] = 786; em[406] = 104; 
    	em[407] = 786; em[408] = 152; 
    	em[409] = 786; em[410] = 176; 
    	em[411] = 821; em[412] = 208; 
    	em[413] = 821; em[414] = 216; 
    	em[415] = 830; em[416] = 224; 
    em[417] = 1; em[418] = 8; em[419] = 1; /* 417: pointer.struct.ec_method_st */
    	em[420] = 422; em[421] = 0; 
    em[422] = 0; em[423] = 304; em[424] = 37; /* 422: struct.ec_method_st */
    	em[425] = 499; em[426] = 8; 
    	em[427] = 502; em[428] = 16; 
    	em[429] = 502; em[430] = 24; 
    	em[431] = 505; em[432] = 32; 
    	em[433] = 363; em[434] = 40; 
    	em[435] = 508; em[436] = 48; 
    	em[437] = 511; em[438] = 56; 
    	em[439] = 514; em[440] = 64; 
    	em[441] = 517; em[442] = 72; 
    	em[443] = 520; em[444] = 80; 
    	em[445] = 520; em[446] = 88; 
    	em[447] = 523; em[448] = 96; 
    	em[449] = 526; em[450] = 104; 
    	em[451] = 529; em[452] = 112; 
    	em[453] = 532; em[454] = 120; 
    	em[455] = 535; em[456] = 128; 
    	em[457] = 538; em[458] = 136; 
    	em[459] = 541; em[460] = 144; 
    	em[461] = 544; em[462] = 152; 
    	em[463] = 547; em[464] = 160; 
    	em[465] = 550; em[466] = 168; 
    	em[467] = 553; em[468] = 176; 
    	em[469] = 556; em[470] = 184; 
    	em[471] = 559; em[472] = 192; 
    	em[473] = 562; em[474] = 200; 
    	em[475] = 565; em[476] = 208; 
    	em[477] = 556; em[478] = 216; 
    	em[479] = 568; em[480] = 224; 
    	em[481] = 571; em[482] = 232; 
    	em[483] = 574; em[484] = 240; 
    	em[485] = 511; em[486] = 248; 
    	em[487] = 577; em[488] = 256; 
    	em[489] = 580; em[490] = 264; 
    	em[491] = 577; em[492] = 272; 
    	em[493] = 580; em[494] = 280; 
    	em[495] = 580; em[496] = 288; 
    	em[497] = 583; em[498] = 296; 
    em[499] = 8884097; em[500] = 8; em[501] = 0; /* 499: pointer.func */
    em[502] = 8884097; em[503] = 8; em[504] = 0; /* 502: pointer.func */
    em[505] = 8884097; em[506] = 8; em[507] = 0; /* 505: pointer.func */
    em[508] = 8884097; em[509] = 8; em[510] = 0; /* 508: pointer.func */
    em[511] = 8884097; em[512] = 8; em[513] = 0; /* 511: pointer.func */
    em[514] = 8884097; em[515] = 8; em[516] = 0; /* 514: pointer.func */
    em[517] = 8884097; em[518] = 8; em[519] = 0; /* 517: pointer.func */
    em[520] = 8884097; em[521] = 8; em[522] = 0; /* 520: pointer.func */
    em[523] = 8884097; em[524] = 8; em[525] = 0; /* 523: pointer.func */
    em[526] = 8884097; em[527] = 8; em[528] = 0; /* 526: pointer.func */
    em[529] = 8884097; em[530] = 8; em[531] = 0; /* 529: pointer.func */
    em[532] = 8884097; em[533] = 8; em[534] = 0; /* 532: pointer.func */
    em[535] = 8884097; em[536] = 8; em[537] = 0; /* 535: pointer.func */
    em[538] = 8884097; em[539] = 8; em[540] = 0; /* 538: pointer.func */
    em[541] = 8884097; em[542] = 8; em[543] = 0; /* 541: pointer.func */
    em[544] = 8884097; em[545] = 8; em[546] = 0; /* 544: pointer.func */
    em[547] = 8884097; em[548] = 8; em[549] = 0; /* 547: pointer.func */
    em[550] = 8884097; em[551] = 8; em[552] = 0; /* 550: pointer.func */
    em[553] = 8884097; em[554] = 8; em[555] = 0; /* 553: pointer.func */
    em[556] = 8884097; em[557] = 8; em[558] = 0; /* 556: pointer.func */
    em[559] = 8884097; em[560] = 8; em[561] = 0; /* 559: pointer.func */
    em[562] = 8884097; em[563] = 8; em[564] = 0; /* 562: pointer.func */
    em[565] = 8884097; em[566] = 8; em[567] = 0; /* 565: pointer.func */
    em[568] = 8884097; em[569] = 8; em[570] = 0; /* 568: pointer.func */
    em[571] = 8884097; em[572] = 8; em[573] = 0; /* 571: pointer.func */
    em[574] = 8884097; em[575] = 8; em[576] = 0; /* 574: pointer.func */
    em[577] = 8884097; em[578] = 8; em[579] = 0; /* 577: pointer.func */
    em[580] = 8884097; em[581] = 8; em[582] = 0; /* 580: pointer.func */
    em[583] = 8884097; em[584] = 8; em[585] = 0; /* 583: pointer.func */
    em[586] = 1; em[587] = 8; em[588] = 1; /* 586: pointer.struct.ec_point_st */
    	em[589] = 591; em[590] = 0; 
    em[591] = 0; em[592] = 88; em[593] = 4; /* 591: struct.ec_point_st */
    	em[594] = 602; em[595] = 0; 
    	em[596] = 774; em[597] = 8; 
    	em[598] = 774; em[599] = 32; 
    	em[600] = 774; em[601] = 56; 
    em[602] = 1; em[603] = 8; em[604] = 1; /* 602: pointer.struct.ec_method_st */
    	em[605] = 607; em[606] = 0; 
    em[607] = 0; em[608] = 304; em[609] = 37; /* 607: struct.ec_method_st */
    	em[610] = 684; em[611] = 8; 
    	em[612] = 687; em[613] = 16; 
    	em[614] = 687; em[615] = 24; 
    	em[616] = 690; em[617] = 32; 
    	em[618] = 693; em[619] = 40; 
    	em[620] = 696; em[621] = 48; 
    	em[622] = 699; em[623] = 56; 
    	em[624] = 702; em[625] = 64; 
    	em[626] = 705; em[627] = 72; 
    	em[628] = 708; em[629] = 80; 
    	em[630] = 708; em[631] = 88; 
    	em[632] = 711; em[633] = 96; 
    	em[634] = 714; em[635] = 104; 
    	em[636] = 717; em[637] = 112; 
    	em[638] = 720; em[639] = 120; 
    	em[640] = 723; em[641] = 128; 
    	em[642] = 726; em[643] = 136; 
    	em[644] = 729; em[645] = 144; 
    	em[646] = 732; em[647] = 152; 
    	em[648] = 735; em[649] = 160; 
    	em[650] = 738; em[651] = 168; 
    	em[652] = 741; em[653] = 176; 
    	em[654] = 744; em[655] = 184; 
    	em[656] = 747; em[657] = 192; 
    	em[658] = 750; em[659] = 200; 
    	em[660] = 753; em[661] = 208; 
    	em[662] = 744; em[663] = 216; 
    	em[664] = 756; em[665] = 224; 
    	em[666] = 759; em[667] = 232; 
    	em[668] = 762; em[669] = 240; 
    	em[670] = 699; em[671] = 248; 
    	em[672] = 765; em[673] = 256; 
    	em[674] = 768; em[675] = 264; 
    	em[676] = 765; em[677] = 272; 
    	em[678] = 768; em[679] = 280; 
    	em[680] = 768; em[681] = 288; 
    	em[682] = 771; em[683] = 296; 
    em[684] = 8884097; em[685] = 8; em[686] = 0; /* 684: pointer.func */
    em[687] = 8884097; em[688] = 8; em[689] = 0; /* 687: pointer.func */
    em[690] = 8884097; em[691] = 8; em[692] = 0; /* 690: pointer.func */
    em[693] = 8884097; em[694] = 8; em[695] = 0; /* 693: pointer.func */
    em[696] = 8884097; em[697] = 8; em[698] = 0; /* 696: pointer.func */
    em[699] = 8884097; em[700] = 8; em[701] = 0; /* 699: pointer.func */
    em[702] = 8884097; em[703] = 8; em[704] = 0; /* 702: pointer.func */
    em[705] = 8884097; em[706] = 8; em[707] = 0; /* 705: pointer.func */
    em[708] = 8884097; em[709] = 8; em[710] = 0; /* 708: pointer.func */
    em[711] = 8884097; em[712] = 8; em[713] = 0; /* 711: pointer.func */
    em[714] = 8884097; em[715] = 8; em[716] = 0; /* 714: pointer.func */
    em[717] = 8884097; em[718] = 8; em[719] = 0; /* 717: pointer.func */
    em[720] = 8884097; em[721] = 8; em[722] = 0; /* 720: pointer.func */
    em[723] = 8884097; em[724] = 8; em[725] = 0; /* 723: pointer.func */
    em[726] = 8884097; em[727] = 8; em[728] = 0; /* 726: pointer.func */
    em[729] = 8884097; em[730] = 8; em[731] = 0; /* 729: pointer.func */
    em[732] = 8884097; em[733] = 8; em[734] = 0; /* 732: pointer.func */
    em[735] = 8884097; em[736] = 8; em[737] = 0; /* 735: pointer.func */
    em[738] = 8884097; em[739] = 8; em[740] = 0; /* 738: pointer.func */
    em[741] = 8884097; em[742] = 8; em[743] = 0; /* 741: pointer.func */
    em[744] = 8884097; em[745] = 8; em[746] = 0; /* 744: pointer.func */
    em[747] = 8884097; em[748] = 8; em[749] = 0; /* 747: pointer.func */
    em[750] = 8884097; em[751] = 8; em[752] = 0; /* 750: pointer.func */
    em[753] = 8884097; em[754] = 8; em[755] = 0; /* 753: pointer.func */
    em[756] = 8884097; em[757] = 8; em[758] = 0; /* 756: pointer.func */
    em[759] = 8884097; em[760] = 8; em[761] = 0; /* 759: pointer.func */
    em[762] = 8884097; em[763] = 8; em[764] = 0; /* 762: pointer.func */
    em[765] = 8884097; em[766] = 8; em[767] = 0; /* 765: pointer.func */
    em[768] = 8884097; em[769] = 8; em[770] = 0; /* 768: pointer.func */
    em[771] = 8884097; em[772] = 8; em[773] = 0; /* 771: pointer.func */
    em[774] = 0; em[775] = 24; em[776] = 1; /* 774: struct.bignum_st */
    	em[777] = 779; em[778] = 0; 
    em[779] = 8884099; em[780] = 8; em[781] = 2; /* 779: pointer_to_array_of_pointers_to_stack */
    	em[782] = 360; em[783] = 0; 
    	em[784] = 5; em[785] = 12; 
    em[786] = 0; em[787] = 24; em[788] = 1; /* 786: struct.bignum_st */
    	em[789] = 791; em[790] = 0; 
    em[791] = 8884099; em[792] = 8; em[793] = 2; /* 791: pointer_to_array_of_pointers_to_stack */
    	em[794] = 360; em[795] = 0; 
    	em[796] = 5; em[797] = 12; 
    em[798] = 1; em[799] = 8; em[800] = 1; /* 798: pointer.struct.ec_extra_data_st */
    	em[801] = 803; em[802] = 0; 
    em[803] = 0; em[804] = 40; em[805] = 5; /* 803: struct.ec_extra_data_st */
    	em[806] = 816; em[807] = 0; 
    	em[808] = 821; em[809] = 8; 
    	em[810] = 824; em[811] = 16; 
    	em[812] = 827; em[813] = 24; 
    	em[814] = 827; em[815] = 32; 
    em[816] = 1; em[817] = 8; em[818] = 1; /* 816: pointer.struct.ec_extra_data_st */
    	em[819] = 803; em[820] = 0; 
    em[821] = 0; em[822] = 8; em[823] = 0; /* 821: pointer.void */
    em[824] = 8884097; em[825] = 8; em[826] = 0; /* 824: pointer.func */
    em[827] = 8884097; em[828] = 8; em[829] = 0; /* 827: pointer.func */
    em[830] = 8884097; em[831] = 8; em[832] = 0; /* 830: pointer.func */
    em[833] = 1; em[834] = 8; em[835] = 1; /* 833: pointer.struct.ec_point_st */
    	em[836] = 591; em[837] = 0; 
    em[838] = 1; em[839] = 8; em[840] = 1; /* 838: pointer.struct.bignum_st */
    	em[841] = 843; em[842] = 0; 
    em[843] = 0; em[844] = 24; em[845] = 1; /* 843: struct.bignum_st */
    	em[846] = 848; em[847] = 0; 
    em[848] = 8884099; em[849] = 8; em[850] = 2; /* 848: pointer_to_array_of_pointers_to_stack */
    	em[851] = 360; em[852] = 0; 
    	em[853] = 5; em[854] = 12; 
    em[855] = 1; em[856] = 8; em[857] = 1; /* 855: pointer.struct.ec_extra_data_st */
    	em[858] = 860; em[859] = 0; 
    em[860] = 0; em[861] = 40; em[862] = 5; /* 860: struct.ec_extra_data_st */
    	em[863] = 873; em[864] = 0; 
    	em[865] = 821; em[866] = 8; 
    	em[867] = 824; em[868] = 16; 
    	em[869] = 827; em[870] = 24; 
    	em[871] = 827; em[872] = 32; 
    em[873] = 1; em[874] = 8; em[875] = 1; /* 873: pointer.struct.ec_extra_data_st */
    	em[876] = 860; em[877] = 0; 
    em[878] = 8884097; em[879] = 8; em[880] = 0; /* 878: pointer.func */
    em[881] = 8884097; em[882] = 8; em[883] = 0; /* 881: pointer.func */
    em[884] = 8884097; em[885] = 8; em[886] = 0; /* 884: pointer.func */
    em[887] = 8884097; em[888] = 8; em[889] = 0; /* 887: pointer.func */
    em[890] = 0; em[891] = 112; em[892] = 13; /* 890: struct.rsa_meth_st */
    	em[893] = 144; em[894] = 0; 
    	em[895] = 884; em[896] = 8; 
    	em[897] = 884; em[898] = 16; 
    	em[899] = 884; em[900] = 24; 
    	em[901] = 884; em[902] = 32; 
    	em[903] = 919; em[904] = 40; 
    	em[905] = 922; em[906] = 48; 
    	em[907] = 878; em[908] = 56; 
    	em[909] = 878; em[910] = 64; 
    	em[911] = 120; em[912] = 80; 
    	em[913] = 925; em[914] = 88; 
    	em[915] = 928; em[916] = 96; 
    	em[917] = 366; em[918] = 104; 
    em[919] = 8884097; em[920] = 8; em[921] = 0; /* 919: pointer.func */
    em[922] = 8884097; em[923] = 8; em[924] = 0; /* 922: pointer.func */
    em[925] = 8884097; em[926] = 8; em[927] = 0; /* 925: pointer.func */
    em[928] = 8884097; em[929] = 8; em[930] = 0; /* 928: pointer.func */
    em[931] = 1; em[932] = 8; em[933] = 1; /* 931: pointer.struct.rsa_meth_st */
    	em[934] = 890; em[935] = 0; 
    em[936] = 8884097; em[937] = 8; em[938] = 0; /* 936: pointer.func */
    em[939] = 8884097; em[940] = 8; em[941] = 0; /* 939: pointer.func */
    em[942] = 0; em[943] = 168; em[944] = 17; /* 942: struct.rsa_st */
    	em[945] = 931; em[946] = 16; 
    	em[947] = 979; em[948] = 24; 
    	em[949] = 1316; em[950] = 32; 
    	em[951] = 1316; em[952] = 40; 
    	em[953] = 1316; em[954] = 48; 
    	em[955] = 1316; em[956] = 56; 
    	em[957] = 1316; em[958] = 64; 
    	em[959] = 1316; em[960] = 72; 
    	em[961] = 1316; em[962] = 80; 
    	em[963] = 1316; em[964] = 88; 
    	em[965] = 1321; em[966] = 96; 
    	em[967] = 1335; em[968] = 120; 
    	em[969] = 1335; em[970] = 128; 
    	em[971] = 1335; em[972] = 136; 
    	em[973] = 120; em[974] = 144; 
    	em[975] = 1340; em[976] = 152; 
    	em[977] = 1340; em[978] = 160; 
    em[979] = 1; em[980] = 8; em[981] = 1; /* 979: pointer.struct.engine_st */
    	em[982] = 984; em[983] = 0; 
    em[984] = 0; em[985] = 216; em[986] = 24; /* 984: struct.engine_st */
    	em[987] = 144; em[988] = 0; 
    	em[989] = 144; em[990] = 8; 
    	em[991] = 1035; em[992] = 16; 
    	em[993] = 1087; em[994] = 24; 
    	em[995] = 1138; em[996] = 32; 
    	em[997] = 1174; em[998] = 40; 
    	em[999] = 1191; em[1000] = 48; 
    	em[1001] = 1218; em[1002] = 56; 
    	em[1003] = 1253; em[1004] = 64; 
    	em[1005] = 1261; em[1006] = 72; 
    	em[1007] = 1264; em[1008] = 80; 
    	em[1009] = 1267; em[1010] = 88; 
    	em[1011] = 1270; em[1012] = 96; 
    	em[1013] = 1273; em[1014] = 104; 
    	em[1015] = 1273; em[1016] = 112; 
    	em[1017] = 1273; em[1018] = 120; 
    	em[1019] = 1276; em[1020] = 128; 
    	em[1021] = 939; em[1022] = 136; 
    	em[1023] = 939; em[1024] = 144; 
    	em[1025] = 1279; em[1026] = 152; 
    	em[1027] = 1282; em[1028] = 160; 
    	em[1029] = 1294; em[1030] = 184; 
    	em[1031] = 1311; em[1032] = 200; 
    	em[1033] = 1311; em[1034] = 208; 
    em[1035] = 1; em[1036] = 8; em[1037] = 1; /* 1035: pointer.struct.rsa_meth_st */
    	em[1038] = 1040; em[1039] = 0; 
    em[1040] = 0; em[1041] = 112; em[1042] = 13; /* 1040: struct.rsa_meth_st */
    	em[1043] = 144; em[1044] = 0; 
    	em[1045] = 881; em[1046] = 8; 
    	em[1047] = 881; em[1048] = 16; 
    	em[1049] = 881; em[1050] = 24; 
    	em[1051] = 881; em[1052] = 32; 
    	em[1053] = 1069; em[1054] = 40; 
    	em[1055] = 1072; em[1056] = 48; 
    	em[1057] = 1075; em[1058] = 56; 
    	em[1059] = 1075; em[1060] = 64; 
    	em[1061] = 120; em[1062] = 80; 
    	em[1063] = 1078; em[1064] = 88; 
    	em[1065] = 1081; em[1066] = 96; 
    	em[1067] = 1084; em[1068] = 104; 
    em[1069] = 8884097; em[1070] = 8; em[1071] = 0; /* 1069: pointer.func */
    em[1072] = 8884097; em[1073] = 8; em[1074] = 0; /* 1072: pointer.func */
    em[1075] = 8884097; em[1076] = 8; em[1077] = 0; /* 1075: pointer.func */
    em[1078] = 8884097; em[1079] = 8; em[1080] = 0; /* 1078: pointer.func */
    em[1081] = 8884097; em[1082] = 8; em[1083] = 0; /* 1081: pointer.func */
    em[1084] = 8884097; em[1085] = 8; em[1086] = 0; /* 1084: pointer.func */
    em[1087] = 1; em[1088] = 8; em[1089] = 1; /* 1087: pointer.struct.dsa_method */
    	em[1090] = 1092; em[1091] = 0; 
    em[1092] = 0; em[1093] = 96; em[1094] = 11; /* 1092: struct.dsa_method */
    	em[1095] = 144; em[1096] = 0; 
    	em[1097] = 1117; em[1098] = 8; 
    	em[1099] = 1120; em[1100] = 16; 
    	em[1101] = 1123; em[1102] = 24; 
    	em[1103] = 1126; em[1104] = 32; 
    	em[1105] = 1129; em[1106] = 40; 
    	em[1107] = 1132; em[1108] = 48; 
    	em[1109] = 1132; em[1110] = 56; 
    	em[1111] = 120; em[1112] = 72; 
    	em[1113] = 1135; em[1114] = 80; 
    	em[1115] = 1132; em[1116] = 88; 
    em[1117] = 8884097; em[1118] = 8; em[1119] = 0; /* 1117: pointer.func */
    em[1120] = 8884097; em[1121] = 8; em[1122] = 0; /* 1120: pointer.func */
    em[1123] = 8884097; em[1124] = 8; em[1125] = 0; /* 1123: pointer.func */
    em[1126] = 8884097; em[1127] = 8; em[1128] = 0; /* 1126: pointer.func */
    em[1129] = 8884097; em[1130] = 8; em[1131] = 0; /* 1129: pointer.func */
    em[1132] = 8884097; em[1133] = 8; em[1134] = 0; /* 1132: pointer.func */
    em[1135] = 8884097; em[1136] = 8; em[1137] = 0; /* 1135: pointer.func */
    em[1138] = 1; em[1139] = 8; em[1140] = 1; /* 1138: pointer.struct.dh_method */
    	em[1141] = 1143; em[1142] = 0; 
    em[1143] = 0; em[1144] = 72; em[1145] = 8; /* 1143: struct.dh_method */
    	em[1146] = 144; em[1147] = 0; 
    	em[1148] = 1162; em[1149] = 8; 
    	em[1150] = 1165; em[1151] = 16; 
    	em[1152] = 1168; em[1153] = 24; 
    	em[1154] = 1162; em[1155] = 32; 
    	em[1156] = 1162; em[1157] = 40; 
    	em[1158] = 120; em[1159] = 56; 
    	em[1160] = 1171; em[1161] = 64; 
    em[1162] = 8884097; em[1163] = 8; em[1164] = 0; /* 1162: pointer.func */
    em[1165] = 8884097; em[1166] = 8; em[1167] = 0; /* 1165: pointer.func */
    em[1168] = 8884097; em[1169] = 8; em[1170] = 0; /* 1168: pointer.func */
    em[1171] = 8884097; em[1172] = 8; em[1173] = 0; /* 1171: pointer.func */
    em[1174] = 1; em[1175] = 8; em[1176] = 1; /* 1174: pointer.struct.ecdh_method */
    	em[1177] = 1179; em[1178] = 0; 
    em[1179] = 0; em[1180] = 32; em[1181] = 3; /* 1179: struct.ecdh_method */
    	em[1182] = 144; em[1183] = 0; 
    	em[1184] = 1188; em[1185] = 8; 
    	em[1186] = 120; em[1187] = 24; 
    em[1188] = 8884097; em[1189] = 8; em[1190] = 0; /* 1188: pointer.func */
    em[1191] = 1; em[1192] = 8; em[1193] = 1; /* 1191: pointer.struct.ecdsa_method */
    	em[1194] = 1196; em[1195] = 0; 
    em[1196] = 0; em[1197] = 48; em[1198] = 5; /* 1196: struct.ecdsa_method */
    	em[1199] = 144; em[1200] = 0; 
    	em[1201] = 1209; em[1202] = 8; 
    	em[1203] = 1212; em[1204] = 16; 
    	em[1205] = 1215; em[1206] = 24; 
    	em[1207] = 120; em[1208] = 40; 
    em[1209] = 8884097; em[1210] = 8; em[1211] = 0; /* 1209: pointer.func */
    em[1212] = 8884097; em[1213] = 8; em[1214] = 0; /* 1212: pointer.func */
    em[1215] = 8884097; em[1216] = 8; em[1217] = 0; /* 1215: pointer.func */
    em[1218] = 1; em[1219] = 8; em[1220] = 1; /* 1218: pointer.struct.rand_meth_st */
    	em[1221] = 1223; em[1222] = 0; 
    em[1223] = 0; em[1224] = 48; em[1225] = 6; /* 1223: struct.rand_meth_st */
    	em[1226] = 1238; em[1227] = 0; 
    	em[1228] = 1241; em[1229] = 8; 
    	em[1230] = 1244; em[1231] = 16; 
    	em[1232] = 1247; em[1233] = 24; 
    	em[1234] = 1241; em[1235] = 32; 
    	em[1236] = 1250; em[1237] = 40; 
    em[1238] = 8884097; em[1239] = 8; em[1240] = 0; /* 1238: pointer.func */
    em[1241] = 8884097; em[1242] = 8; em[1243] = 0; /* 1241: pointer.func */
    em[1244] = 8884097; em[1245] = 8; em[1246] = 0; /* 1244: pointer.func */
    em[1247] = 8884097; em[1248] = 8; em[1249] = 0; /* 1247: pointer.func */
    em[1250] = 8884097; em[1251] = 8; em[1252] = 0; /* 1250: pointer.func */
    em[1253] = 1; em[1254] = 8; em[1255] = 1; /* 1253: pointer.struct.store_method_st */
    	em[1256] = 1258; em[1257] = 0; 
    em[1258] = 0; em[1259] = 0; em[1260] = 0; /* 1258: struct.store_method_st */
    em[1261] = 8884097; em[1262] = 8; em[1263] = 0; /* 1261: pointer.func */
    em[1264] = 8884097; em[1265] = 8; em[1266] = 0; /* 1264: pointer.func */
    em[1267] = 8884097; em[1268] = 8; em[1269] = 0; /* 1267: pointer.func */
    em[1270] = 8884097; em[1271] = 8; em[1272] = 0; /* 1270: pointer.func */
    em[1273] = 8884097; em[1274] = 8; em[1275] = 0; /* 1273: pointer.func */
    em[1276] = 8884097; em[1277] = 8; em[1278] = 0; /* 1276: pointer.func */
    em[1279] = 8884097; em[1280] = 8; em[1281] = 0; /* 1279: pointer.func */
    em[1282] = 1; em[1283] = 8; em[1284] = 1; /* 1282: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[1285] = 1287; em[1286] = 0; 
    em[1287] = 0; em[1288] = 32; em[1289] = 2; /* 1287: struct.ENGINE_CMD_DEFN_st */
    	em[1290] = 144; em[1291] = 8; 
    	em[1292] = 144; em[1293] = 16; 
    em[1294] = 0; em[1295] = 32; em[1296] = 2; /* 1294: struct.crypto_ex_data_st_fake */
    	em[1297] = 1301; em[1298] = 8; 
    	em[1299] = 1308; em[1300] = 24; 
    em[1301] = 8884099; em[1302] = 8; em[1303] = 2; /* 1301: pointer_to_array_of_pointers_to_stack */
    	em[1304] = 821; em[1305] = 0; 
    	em[1306] = 5; em[1307] = 20; 
    em[1308] = 8884097; em[1309] = 8; em[1310] = 0; /* 1308: pointer.func */
    em[1311] = 1; em[1312] = 8; em[1313] = 1; /* 1311: pointer.struct.engine_st */
    	em[1314] = 984; em[1315] = 0; 
    em[1316] = 1; em[1317] = 8; em[1318] = 1; /* 1316: pointer.struct.bignum_st */
    	em[1319] = 348; em[1320] = 0; 
    em[1321] = 0; em[1322] = 32; em[1323] = 2; /* 1321: struct.crypto_ex_data_st_fake */
    	em[1324] = 1328; em[1325] = 8; 
    	em[1326] = 1308; em[1327] = 24; 
    em[1328] = 8884099; em[1329] = 8; em[1330] = 2; /* 1328: pointer_to_array_of_pointers_to_stack */
    	em[1331] = 821; em[1332] = 0; 
    	em[1333] = 5; em[1334] = 20; 
    em[1335] = 1; em[1336] = 8; em[1337] = 1; /* 1335: pointer.struct.bn_mont_ctx_st */
    	em[1338] = 339; em[1339] = 0; 
    em[1340] = 1; em[1341] = 8; em[1342] = 1; /* 1340: pointer.struct.bn_blinding_st */
    	em[1343] = 1345; em[1344] = 0; 
    em[1345] = 0; em[1346] = 88; em[1347] = 7; /* 1345: struct.bn_blinding_st */
    	em[1348] = 1362; em[1349] = 0; 
    	em[1350] = 1362; em[1351] = 8; 
    	em[1352] = 1362; em[1353] = 16; 
    	em[1354] = 1362; em[1355] = 24; 
    	em[1356] = 1379; em[1357] = 40; 
    	em[1358] = 1384; em[1359] = 72; 
    	em[1360] = 1398; em[1361] = 80; 
    em[1362] = 1; em[1363] = 8; em[1364] = 1; /* 1362: pointer.struct.bignum_st */
    	em[1365] = 1367; em[1366] = 0; 
    em[1367] = 0; em[1368] = 24; em[1369] = 1; /* 1367: struct.bignum_st */
    	em[1370] = 1372; em[1371] = 0; 
    em[1372] = 8884099; em[1373] = 8; em[1374] = 2; /* 1372: pointer_to_array_of_pointers_to_stack */
    	em[1375] = 360; em[1376] = 0; 
    	em[1377] = 5; em[1378] = 12; 
    em[1379] = 0; em[1380] = 16; em[1381] = 1; /* 1379: struct.crypto_threadid_st */
    	em[1382] = 821; em[1383] = 0; 
    em[1384] = 1; em[1385] = 8; em[1386] = 1; /* 1384: pointer.struct.bn_mont_ctx_st */
    	em[1387] = 1389; em[1388] = 0; 
    em[1389] = 0; em[1390] = 96; em[1391] = 3; /* 1389: struct.bn_mont_ctx_st */
    	em[1392] = 1367; em[1393] = 8; 
    	em[1394] = 1367; em[1395] = 32; 
    	em[1396] = 1367; em[1397] = 56; 
    em[1398] = 8884097; em[1399] = 8; em[1400] = 0; /* 1398: pointer.func */
    em[1401] = 8884101; em[1402] = 8; em[1403] = 6; /* 1401: union.union_of_evp_pkey_st */
    	em[1404] = 821; em[1405] = 0; 
    	em[1406] = 1416; em[1407] = 6; 
    	em[1408] = 1421; em[1409] = 116; 
    	em[1410] = 1552; em[1411] = 28; 
    	em[1412] = 369; em[1413] = 408; 
    	em[1414] = 5; em[1415] = 0; 
    em[1416] = 1; em[1417] = 8; em[1418] = 1; /* 1416: pointer.struct.rsa_st */
    	em[1419] = 942; em[1420] = 0; 
    em[1421] = 1; em[1422] = 8; em[1423] = 1; /* 1421: pointer.struct.dsa_st */
    	em[1424] = 1426; em[1425] = 0; 
    em[1426] = 0; em[1427] = 136; em[1428] = 11; /* 1426: struct.dsa_st */
    	em[1429] = 1451; em[1430] = 24; 
    	em[1431] = 1451; em[1432] = 32; 
    	em[1433] = 1451; em[1434] = 40; 
    	em[1435] = 1451; em[1436] = 48; 
    	em[1437] = 1451; em[1438] = 56; 
    	em[1439] = 1451; em[1440] = 64; 
    	em[1441] = 1451; em[1442] = 72; 
    	em[1443] = 1468; em[1444] = 88; 
    	em[1445] = 1482; em[1446] = 104; 
    	em[1447] = 1496; em[1448] = 120; 
    	em[1449] = 1547; em[1450] = 128; 
    em[1451] = 1; em[1452] = 8; em[1453] = 1; /* 1451: pointer.struct.bignum_st */
    	em[1454] = 1456; em[1455] = 0; 
    em[1456] = 0; em[1457] = 24; em[1458] = 1; /* 1456: struct.bignum_st */
    	em[1459] = 1461; em[1460] = 0; 
    em[1461] = 8884099; em[1462] = 8; em[1463] = 2; /* 1461: pointer_to_array_of_pointers_to_stack */
    	em[1464] = 360; em[1465] = 0; 
    	em[1466] = 5; em[1467] = 12; 
    em[1468] = 1; em[1469] = 8; em[1470] = 1; /* 1468: pointer.struct.bn_mont_ctx_st */
    	em[1471] = 1473; em[1472] = 0; 
    em[1473] = 0; em[1474] = 96; em[1475] = 3; /* 1473: struct.bn_mont_ctx_st */
    	em[1476] = 1456; em[1477] = 8; 
    	em[1478] = 1456; em[1479] = 32; 
    	em[1480] = 1456; em[1481] = 56; 
    em[1482] = 0; em[1483] = 32; em[1484] = 2; /* 1482: struct.crypto_ex_data_st_fake */
    	em[1485] = 1489; em[1486] = 8; 
    	em[1487] = 1308; em[1488] = 24; 
    em[1489] = 8884099; em[1490] = 8; em[1491] = 2; /* 1489: pointer_to_array_of_pointers_to_stack */
    	em[1492] = 821; em[1493] = 0; 
    	em[1494] = 5; em[1495] = 20; 
    em[1496] = 1; em[1497] = 8; em[1498] = 1; /* 1496: pointer.struct.dsa_method */
    	em[1499] = 1501; em[1500] = 0; 
    em[1501] = 0; em[1502] = 96; em[1503] = 11; /* 1501: struct.dsa_method */
    	em[1504] = 144; em[1505] = 0; 
    	em[1506] = 1526; em[1507] = 8; 
    	em[1508] = 1529; em[1509] = 16; 
    	em[1510] = 1532; em[1511] = 24; 
    	em[1512] = 1535; em[1513] = 32; 
    	em[1514] = 1538; em[1515] = 40; 
    	em[1516] = 1541; em[1517] = 48; 
    	em[1518] = 1541; em[1519] = 56; 
    	em[1520] = 120; em[1521] = 72; 
    	em[1522] = 1544; em[1523] = 80; 
    	em[1524] = 1541; em[1525] = 88; 
    em[1526] = 8884097; em[1527] = 8; em[1528] = 0; /* 1526: pointer.func */
    em[1529] = 8884097; em[1530] = 8; em[1531] = 0; /* 1529: pointer.func */
    em[1532] = 8884097; em[1533] = 8; em[1534] = 0; /* 1532: pointer.func */
    em[1535] = 8884097; em[1536] = 8; em[1537] = 0; /* 1535: pointer.func */
    em[1538] = 8884097; em[1539] = 8; em[1540] = 0; /* 1538: pointer.func */
    em[1541] = 8884097; em[1542] = 8; em[1543] = 0; /* 1541: pointer.func */
    em[1544] = 8884097; em[1545] = 8; em[1546] = 0; /* 1544: pointer.func */
    em[1547] = 1; em[1548] = 8; em[1549] = 1; /* 1547: pointer.struct.engine_st */
    	em[1550] = 984; em[1551] = 0; 
    em[1552] = 1; em[1553] = 8; em[1554] = 1; /* 1552: pointer.struct.dh_st */
    	em[1555] = 1557; em[1556] = 0; 
    em[1557] = 0; em[1558] = 144; em[1559] = 12; /* 1557: struct.dh_st */
    	em[1560] = 1584; em[1561] = 8; 
    	em[1562] = 1584; em[1563] = 16; 
    	em[1564] = 1584; em[1565] = 32; 
    	em[1566] = 1584; em[1567] = 40; 
    	em[1568] = 1601; em[1569] = 56; 
    	em[1570] = 1584; em[1571] = 64; 
    	em[1572] = 1584; em[1573] = 72; 
    	em[1574] = 29; em[1575] = 80; 
    	em[1576] = 1584; em[1577] = 96; 
    	em[1578] = 1615; em[1579] = 112; 
    	em[1580] = 1629; em[1581] = 128; 
    	em[1582] = 1665; em[1583] = 136; 
    em[1584] = 1; em[1585] = 8; em[1586] = 1; /* 1584: pointer.struct.bignum_st */
    	em[1587] = 1589; em[1588] = 0; 
    em[1589] = 0; em[1590] = 24; em[1591] = 1; /* 1589: struct.bignum_st */
    	em[1592] = 1594; em[1593] = 0; 
    em[1594] = 8884099; em[1595] = 8; em[1596] = 2; /* 1594: pointer_to_array_of_pointers_to_stack */
    	em[1597] = 360; em[1598] = 0; 
    	em[1599] = 5; em[1600] = 12; 
    em[1601] = 1; em[1602] = 8; em[1603] = 1; /* 1601: pointer.struct.bn_mont_ctx_st */
    	em[1604] = 1606; em[1605] = 0; 
    em[1606] = 0; em[1607] = 96; em[1608] = 3; /* 1606: struct.bn_mont_ctx_st */
    	em[1609] = 1589; em[1610] = 8; 
    	em[1611] = 1589; em[1612] = 32; 
    	em[1613] = 1589; em[1614] = 56; 
    em[1615] = 0; em[1616] = 32; em[1617] = 2; /* 1615: struct.crypto_ex_data_st_fake */
    	em[1618] = 1622; em[1619] = 8; 
    	em[1620] = 1308; em[1621] = 24; 
    em[1622] = 8884099; em[1623] = 8; em[1624] = 2; /* 1622: pointer_to_array_of_pointers_to_stack */
    	em[1625] = 821; em[1626] = 0; 
    	em[1627] = 5; em[1628] = 20; 
    em[1629] = 1; em[1630] = 8; em[1631] = 1; /* 1629: pointer.struct.dh_method */
    	em[1632] = 1634; em[1633] = 0; 
    em[1634] = 0; em[1635] = 72; em[1636] = 8; /* 1634: struct.dh_method */
    	em[1637] = 144; em[1638] = 0; 
    	em[1639] = 1653; em[1640] = 8; 
    	em[1641] = 1656; em[1642] = 16; 
    	em[1643] = 1659; em[1644] = 24; 
    	em[1645] = 1653; em[1646] = 32; 
    	em[1647] = 1653; em[1648] = 40; 
    	em[1649] = 120; em[1650] = 56; 
    	em[1651] = 1662; em[1652] = 64; 
    em[1653] = 8884097; em[1654] = 8; em[1655] = 0; /* 1653: pointer.func */
    em[1656] = 8884097; em[1657] = 8; em[1658] = 0; /* 1656: pointer.func */
    em[1659] = 8884097; em[1660] = 8; em[1661] = 0; /* 1659: pointer.func */
    em[1662] = 8884097; em[1663] = 8; em[1664] = 0; /* 1662: pointer.func */
    em[1665] = 1; em[1666] = 8; em[1667] = 1; /* 1665: pointer.struct.engine_st */
    	em[1668] = 984; em[1669] = 0; 
    em[1670] = 8884097; em[1671] = 8; em[1672] = 0; /* 1670: pointer.func */
    em[1673] = 8884097; em[1674] = 8; em[1675] = 0; /* 1673: pointer.func */
    em[1676] = 8884097; em[1677] = 8; em[1678] = 0; /* 1676: pointer.func */
    em[1679] = 8884097; em[1680] = 8; em[1681] = 0; /* 1679: pointer.func */
    em[1682] = 8884099; em[1683] = 8; em[1684] = 2; /* 1682: pointer_to_array_of_pointers_to_stack */
    	em[1685] = 1689; em[1686] = 0; 
    	em[1687] = 5; em[1688] = 20; 
    em[1689] = 0; em[1690] = 8; em[1691] = 1; /* 1689: pointer.ASN1_TYPE */
    	em[1692] = 241; em[1693] = 0; 
    em[1694] = 0; em[1695] = 1; em[1696] = 0; /* 1694: char */
    em[1697] = 8884097; em[1698] = 8; em[1699] = 0; /* 1697: pointer.func */
    em[1700] = 8884097; em[1701] = 8; em[1702] = 0; /* 1700: pointer.func */
    em[1703] = 8884097; em[1704] = 8; em[1705] = 0; /* 1703: pointer.func */
    em[1706] = 8884097; em[1707] = 8; em[1708] = 0; /* 1706: pointer.func */
    em[1709] = 0; em[1710] = 208; em[1711] = 24; /* 1709: struct.evp_pkey_asn1_method_st */
    	em[1712] = 120; em[1713] = 16; 
    	em[1714] = 120; em[1715] = 24; 
    	em[1716] = 1676; em[1717] = 32; 
    	em[1718] = 1673; em[1719] = 40; 
    	em[1720] = 936; em[1721] = 48; 
    	em[1722] = 1700; em[1723] = 56; 
    	em[1724] = 1760; em[1725] = 64; 
    	em[1726] = 1763; em[1727] = 72; 
    	em[1728] = 1700; em[1729] = 80; 
    	em[1730] = 1766; em[1731] = 88; 
    	em[1732] = 1766; em[1733] = 96; 
    	em[1734] = 1769; em[1735] = 104; 
    	em[1736] = 1772; em[1737] = 112; 
    	em[1738] = 1766; em[1739] = 120; 
    	em[1740] = 1670; em[1741] = 128; 
    	em[1742] = 936; em[1743] = 136; 
    	em[1744] = 1700; em[1745] = 144; 
    	em[1746] = 1703; em[1747] = 152; 
    	em[1748] = 1775; em[1749] = 160; 
    	em[1750] = 1778; em[1751] = 168; 
    	em[1752] = 1769; em[1753] = 176; 
    	em[1754] = 1772; em[1755] = 184; 
    	em[1756] = 1781; em[1757] = 192; 
    	em[1758] = 1784; em[1759] = 200; 
    em[1760] = 8884097; em[1761] = 8; em[1762] = 0; /* 1760: pointer.func */
    em[1763] = 8884097; em[1764] = 8; em[1765] = 0; /* 1763: pointer.func */
    em[1766] = 8884097; em[1767] = 8; em[1768] = 0; /* 1766: pointer.func */
    em[1769] = 8884097; em[1770] = 8; em[1771] = 0; /* 1769: pointer.func */
    em[1772] = 8884097; em[1773] = 8; em[1774] = 0; /* 1772: pointer.func */
    em[1775] = 8884097; em[1776] = 8; em[1777] = 0; /* 1775: pointer.func */
    em[1778] = 8884097; em[1779] = 8; em[1780] = 0; /* 1778: pointer.func */
    em[1781] = 8884097; em[1782] = 8; em[1783] = 0; /* 1781: pointer.func */
    em[1784] = 8884097; em[1785] = 8; em[1786] = 0; /* 1784: pointer.func */
    em[1787] = 8884097; em[1788] = 8; em[1789] = 0; /* 1787: pointer.func */
    em[1790] = 8884097; em[1791] = 8; em[1792] = 0; /* 1790: pointer.func */
    em[1793] = 8884097; em[1794] = 8; em[1795] = 0; /* 1793: pointer.func */
    em[1796] = 1; em[1797] = 8; em[1798] = 1; /* 1796: pointer.struct.evp_pkey_method_st */
    	em[1799] = 1801; em[1800] = 0; 
    em[1801] = 0; em[1802] = 208; em[1803] = 25; /* 1801: struct.evp_pkey_method_st */
    	em[1804] = 1787; em[1805] = 8; 
    	em[1806] = 1854; em[1807] = 16; 
    	em[1808] = 1857; em[1809] = 24; 
    	em[1810] = 1787; em[1811] = 32; 
    	em[1812] = 1790; em[1813] = 40; 
    	em[1814] = 1787; em[1815] = 48; 
    	em[1816] = 1790; em[1817] = 56; 
    	em[1818] = 1787; em[1819] = 64; 
    	em[1820] = 1860; em[1821] = 72; 
    	em[1822] = 1787; em[1823] = 80; 
    	em[1824] = 1863; em[1825] = 88; 
    	em[1826] = 1787; em[1827] = 96; 
    	em[1828] = 1860; em[1829] = 104; 
    	em[1830] = 1866; em[1831] = 112; 
    	em[1832] = 1706; em[1833] = 120; 
    	em[1834] = 1866; em[1835] = 128; 
    	em[1836] = 1869; em[1837] = 136; 
    	em[1838] = 1787; em[1839] = 144; 
    	em[1840] = 1860; em[1841] = 152; 
    	em[1842] = 1787; em[1843] = 160; 
    	em[1844] = 1860; em[1845] = 168; 
    	em[1846] = 1787; em[1847] = 176; 
    	em[1848] = 1697; em[1849] = 184; 
    	em[1850] = 1872; em[1851] = 192; 
    	em[1852] = 1679; em[1853] = 200; 
    em[1854] = 8884097; em[1855] = 8; em[1856] = 0; /* 1854: pointer.func */
    em[1857] = 8884097; em[1858] = 8; em[1859] = 0; /* 1857: pointer.func */
    em[1860] = 8884097; em[1861] = 8; em[1862] = 0; /* 1860: pointer.func */
    em[1863] = 8884097; em[1864] = 8; em[1865] = 0; /* 1863: pointer.func */
    em[1866] = 8884097; em[1867] = 8; em[1868] = 0; /* 1866: pointer.func */
    em[1869] = 8884097; em[1870] = 8; em[1871] = 0; /* 1869: pointer.func */
    em[1872] = 8884097; em[1873] = 8; em[1874] = 0; /* 1872: pointer.func */
    em[1875] = 0; em[1876] = 80; em[1877] = 8; /* 1875: struct.evp_pkey_ctx_st */
    	em[1878] = 1796; em[1879] = 0; 
    	em[1880] = 1665; em[1881] = 8; 
    	em[1882] = 1894; em[1883] = 16; 
    	em[1884] = 1894; em[1885] = 24; 
    	em[1886] = 821; em[1887] = 40; 
    	em[1888] = 821; em[1889] = 48; 
    	em[1890] = 8; em[1891] = 56; 
    	em[1892] = 0; em[1893] = 64; 
    em[1894] = 1; em[1895] = 8; em[1896] = 1; /* 1894: pointer.struct.evp_pkey_st */
    	em[1897] = 1899; em[1898] = 0; 
    em[1899] = 0; em[1900] = 56; em[1901] = 4; /* 1899: struct.evp_pkey_st */
    	em[1902] = 1910; em[1903] = 16; 
    	em[1904] = 1665; em[1905] = 24; 
    	em[1906] = 1401; em[1907] = 32; 
    	em[1908] = 1915; em[1909] = 48; 
    em[1910] = 1; em[1911] = 8; em[1912] = 1; /* 1910: pointer.struct.evp_pkey_asn1_method_st */
    	em[1913] = 1709; em[1914] = 0; 
    em[1915] = 1; em[1916] = 8; em[1917] = 1; /* 1915: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1918] = 1920; em[1919] = 0; 
    em[1920] = 0; em[1921] = 32; em[1922] = 2; /* 1920: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1923] = 1927; em[1924] = 8; 
    	em[1925] = 1308; em[1926] = 24; 
    em[1927] = 8884099; em[1928] = 8; em[1929] = 2; /* 1927: pointer_to_array_of_pointers_to_stack */
    	em[1930] = 1934; em[1931] = 0; 
    	em[1932] = 5; em[1933] = 20; 
    em[1934] = 0; em[1935] = 8; em[1936] = 1; /* 1934: pointer.X509_ATTRIBUTE */
    	em[1937] = 1939; em[1938] = 0; 
    em[1939] = 0; em[1940] = 0; em[1941] = 1; /* 1939: X509_ATTRIBUTE */
    	em[1942] = 1944; em[1943] = 0; 
    em[1944] = 0; em[1945] = 24; em[1946] = 2; /* 1944: struct.x509_attributes_st */
    	em[1947] = 130; em[1948] = 0; 
    	em[1949] = 1951; em[1950] = 16; 
    em[1951] = 0; em[1952] = 8; em[1953] = 3; /* 1951: union.unknown */
    	em[1954] = 120; em[1955] = 0; 
    	em[1956] = 1960; em[1957] = 0; 
    	em[1958] = 1972; em[1959] = 0; 
    em[1960] = 1; em[1961] = 8; em[1962] = 1; /* 1960: pointer.struct.stack_st_ASN1_TYPE */
    	em[1963] = 1965; em[1964] = 0; 
    em[1965] = 0; em[1966] = 32; em[1967] = 2; /* 1965: struct.stack_st_fake_ASN1_TYPE */
    	em[1968] = 1682; em[1969] = 8; 
    	em[1970] = 1308; em[1971] = 24; 
    em[1972] = 1; em[1973] = 8; em[1974] = 1; /* 1972: pointer.struct.asn1_type_st */
    	em[1975] = 179; em[1976] = 0; 
    em[1977] = 1; em[1978] = 8; em[1979] = 1; /* 1977: pointer.struct.evp_pkey_ctx_st */
    	em[1980] = 1875; em[1981] = 0; 
    em[1982] = 1; em[1983] = 8; em[1984] = 1; /* 1982: pointer.struct.env_md_ctx_st */
    	em[1985] = 1987; em[1986] = 0; 
    em[1987] = 0; em[1988] = 48; em[1989] = 5; /* 1987: struct.env_md_ctx_st */
    	em[1990] = 2000; em[1991] = 0; 
    	em[1992] = 1665; em[1993] = 8; 
    	em[1994] = 821; em[1995] = 24; 
    	em[1996] = 1977; em[1997] = 32; 
    	em[1998] = 2027; em[1999] = 40; 
    em[2000] = 1; em[2001] = 8; em[2002] = 1; /* 2000: pointer.struct.env_md_st */
    	em[2003] = 2005; em[2004] = 0; 
    em[2005] = 0; em[2006] = 120; em[2007] = 8; /* 2005: struct.env_md_st */
    	em[2008] = 2024; em[2009] = 24; 
    	em[2010] = 2027; em[2011] = 32; 
    	em[2012] = 2030; em[2013] = 40; 
    	em[2014] = 887; em[2015] = 48; 
    	em[2016] = 2024; em[2017] = 56; 
    	em[2018] = 2033; em[2019] = 64; 
    	em[2020] = 1793; em[2021] = 72; 
    	em[2022] = 2036; em[2023] = 112; 
    em[2024] = 8884097; em[2025] = 8; em[2026] = 0; /* 2024: pointer.func */
    em[2027] = 8884097; em[2028] = 8; em[2029] = 0; /* 2027: pointer.func */
    em[2030] = 8884097; em[2031] = 8; em[2032] = 0; /* 2030: pointer.func */
    em[2033] = 8884097; em[2034] = 8; em[2035] = 0; /* 2033: pointer.func */
    em[2036] = 8884097; em[2037] = 8; em[2038] = 0; /* 2036: pointer.func */
    args_addr->ret_entity_index = 1982;
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * *new_ret_ptr = (EVP_MD_CTX * *)new_args->ret;

    EVP_MD_CTX * (*orig_EVP_MD_CTX_create)(void);
    orig_EVP_MD_CTX_create = dlsym(RTLD_NEXT, "EVP_MD_CTX_create");
    *new_ret_ptr = (*orig_EVP_MD_CTX_create)();

    syscall(889);

    free(args_addr);

    return ret;
}

