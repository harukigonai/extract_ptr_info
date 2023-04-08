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

int bb_EVP_DigestInit_ex(EVP_MD_CTX * arg_a,const EVP_MD * arg_b,ENGINE * arg_c);

int EVP_DigestInit_ex(EVP_MD_CTX * arg_a,const EVP_MD * arg_b,ENGINE * arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_DigestInit_ex called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_DigestInit_ex(arg_a,arg_b,arg_c);
    else {
        int (*orig_EVP_DigestInit_ex)(EVP_MD_CTX *,const EVP_MD *,ENGINE *);
        orig_EVP_DigestInit_ex = dlsym(RTLD_NEXT, "EVP_DigestInit_ex");
        return orig_EVP_DigestInit_ex(arg_a,arg_b,arg_c);
    }
}

int bb_EVP_DigestInit_ex(EVP_MD_CTX * arg_a,const EVP_MD * arg_b,ENGINE * arg_c) 
{
    int ret;

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
    em[77] = 1; em[78] = 8; em[79] = 1; /* 77: pointer.struct.asn1_string_st */
    	em[80] = 24; em[81] = 0; 
    em[82] = 0; em[83] = 8; em[84] = 20; /* 82: union.unknown */
    	em[85] = 125; em[86] = 0; 
    	em[87] = 130; em[88] = 0; 
    	em[89] = 135; em[90] = 0; 
    	em[91] = 159; em[92] = 0; 
    	em[93] = 77; em[94] = 0; 
    	em[95] = 72; em[96] = 0; 
    	em[97] = 67; em[98] = 0; 
    	em[99] = 164; em[100] = 0; 
    	em[101] = 62; em[102] = 0; 
    	em[103] = 57; em[104] = 0; 
    	em[105] = 52; em[106] = 0; 
    	em[107] = 47; em[108] = 0; 
    	em[109] = 42; em[110] = 0; 
    	em[111] = 169; em[112] = 0; 
    	em[113] = 37; em[114] = 0; 
    	em[115] = 174; em[116] = 0; 
    	em[117] = 19; em[118] = 0; 
    	em[119] = 130; em[120] = 0; 
    	em[121] = 130; em[122] = 0; 
    	em[123] = 11; em[124] = 0; 
    em[125] = 1; em[126] = 8; em[127] = 1; /* 125: pointer.char */
    	em[128] = 8884096; em[129] = 0; 
    em[130] = 1; em[131] = 8; em[132] = 1; /* 130: pointer.struct.asn1_string_st */
    	em[133] = 24; em[134] = 0; 
    em[135] = 1; em[136] = 8; em[137] = 1; /* 135: pointer.struct.asn1_object_st */
    	em[138] = 140; em[139] = 0; 
    em[140] = 0; em[141] = 40; em[142] = 3; /* 140: struct.asn1_object_st */
    	em[143] = 149; em[144] = 0; 
    	em[145] = 149; em[146] = 8; 
    	em[147] = 154; em[148] = 24; 
    em[149] = 1; em[150] = 8; em[151] = 1; /* 149: pointer.char */
    	em[152] = 8884096; em[153] = 0; 
    em[154] = 1; em[155] = 8; em[156] = 1; /* 154: pointer.unsigned char */
    	em[157] = 34; em[158] = 0; 
    em[159] = 1; em[160] = 8; em[161] = 1; /* 159: pointer.struct.asn1_string_st */
    	em[162] = 24; em[163] = 0; 
    em[164] = 1; em[165] = 8; em[166] = 1; /* 164: pointer.struct.asn1_string_st */
    	em[167] = 24; em[168] = 0; 
    em[169] = 1; em[170] = 8; em[171] = 1; /* 169: pointer.struct.asn1_string_st */
    	em[172] = 24; em[173] = 0; 
    em[174] = 1; em[175] = 8; em[176] = 1; /* 174: pointer.struct.asn1_string_st */
    	em[177] = 24; em[178] = 0; 
    em[179] = 0; em[180] = 16; em[181] = 1; /* 179: struct.asn1_type_st */
    	em[182] = 82; em[183] = 8; 
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
    	em[230] = 149; em[231] = 0; 
    	em[232] = 149; em[233] = 8; 
    	em[234] = 154; em[235] = 24; 
    em[236] = 1; em[237] = 8; em[238] = 1; /* 236: pointer.struct.asn1_object_st */
    	em[239] = 227; em[240] = 0; 
    em[241] = 1; em[242] = 8; em[243] = 1; /* 241: pointer.struct.asn1_string_st */
    	em[244] = 197; em[245] = 0; 
    em[246] = 0; em[247] = 0; em[248] = 1; /* 246: ASN1_TYPE */
    	em[249] = 251; em[250] = 0; 
    em[251] = 0; em[252] = 16; em[253] = 1; /* 251: struct.asn1_type_st */
    	em[254] = 256; em[255] = 8; 
    em[256] = 0; em[257] = 8; em[258] = 20; /* 256: union.unknown */
    	em[259] = 125; em[260] = 0; 
    	em[261] = 241; em[262] = 0; 
    	em[263] = 236; em[264] = 0; 
    	em[265] = 222; em[266] = 0; 
    	em[267] = 217; em[268] = 0; 
    	em[269] = 212; em[270] = 0; 
    	em[271] = 299; em[272] = 0; 
    	em[273] = 304; em[274] = 0; 
    	em[275] = 207; em[276] = 0; 
    	em[277] = 202; em[278] = 0; 
    	em[279] = 309; em[280] = 0; 
    	em[281] = 314; em[282] = 0; 
    	em[283] = 319; em[284] = 0; 
    	em[285] = 324; em[286] = 0; 
    	em[287] = 329; em[288] = 0; 
    	em[289] = 334; em[290] = 0; 
    	em[291] = 192; em[292] = 0; 
    	em[293] = 241; em[294] = 0; 
    	em[295] = 241; em[296] = 0; 
    	em[297] = 184; em[298] = 0; 
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
    em[878] = 1; em[879] = 8; em[880] = 1; /* 878: pointer.struct.bignum_st */
    	em[881] = 348; em[882] = 0; 
    em[883] = 8884097; em[884] = 8; em[885] = 0; /* 883: pointer.func */
    em[886] = 0; em[887] = 1; em[888] = 0; /* 886: char */
    em[889] = 8884097; em[890] = 8; em[891] = 0; /* 889: pointer.func */
    em[892] = 8884097; em[893] = 8; em[894] = 0; /* 892: pointer.func */
    em[895] = 8884097; em[896] = 8; em[897] = 0; /* 895: pointer.func */
    em[898] = 8884097; em[899] = 8; em[900] = 0; /* 898: pointer.func */
    em[901] = 8884097; em[902] = 8; em[903] = 0; /* 901: pointer.func */
    em[904] = 8884097; em[905] = 8; em[906] = 0; /* 904: pointer.func */
    em[907] = 0; em[908] = 112; em[909] = 13; /* 907: struct.rsa_meth_st */
    	em[910] = 149; em[911] = 0; 
    	em[912] = 901; em[913] = 8; 
    	em[914] = 901; em[915] = 16; 
    	em[916] = 901; em[917] = 24; 
    	em[918] = 901; em[919] = 32; 
    	em[920] = 936; em[921] = 40; 
    	em[922] = 939; em[923] = 48; 
    	em[924] = 889; em[925] = 56; 
    	em[926] = 889; em[927] = 64; 
    	em[928] = 125; em[929] = 80; 
    	em[930] = 883; em[931] = 88; 
    	em[932] = 942; em[933] = 96; 
    	em[934] = 366; em[935] = 104; 
    em[936] = 8884097; em[937] = 8; em[938] = 0; /* 936: pointer.func */
    em[939] = 8884097; em[940] = 8; em[941] = 0; /* 939: pointer.func */
    em[942] = 8884097; em[943] = 8; em[944] = 0; /* 942: pointer.func */
    em[945] = 1; em[946] = 8; em[947] = 1; /* 945: pointer.struct.rsa_meth_st */
    	em[948] = 907; em[949] = 0; 
    em[950] = 8884097; em[951] = 8; em[952] = 0; /* 950: pointer.func */
    em[953] = 8884097; em[954] = 8; em[955] = 0; /* 953: pointer.func */
    em[956] = 0; em[957] = 168; em[958] = 17; /* 956: struct.rsa_st */
    	em[959] = 945; em[960] = 16; 
    	em[961] = 993; em[962] = 24; 
    	em[963] = 878; em[964] = 32; 
    	em[965] = 878; em[966] = 40; 
    	em[967] = 878; em[968] = 48; 
    	em[969] = 878; em[970] = 56; 
    	em[971] = 878; em[972] = 64; 
    	em[973] = 878; em[974] = 72; 
    	em[975] = 878; em[976] = 80; 
    	em[977] = 878; em[978] = 88; 
    	em[979] = 1324; em[980] = 96; 
    	em[981] = 1338; em[982] = 120; 
    	em[983] = 1338; em[984] = 128; 
    	em[985] = 1338; em[986] = 136; 
    	em[987] = 125; em[988] = 144; 
    	em[989] = 1343; em[990] = 152; 
    	em[991] = 1343; em[992] = 160; 
    em[993] = 1; em[994] = 8; em[995] = 1; /* 993: pointer.struct.engine_st */
    	em[996] = 998; em[997] = 0; 
    em[998] = 0; em[999] = 216; em[1000] = 24; /* 998: struct.engine_st */
    	em[1001] = 149; em[1002] = 0; 
    	em[1003] = 149; em[1004] = 8; 
    	em[1005] = 1049; em[1006] = 16; 
    	em[1007] = 1101; em[1008] = 24; 
    	em[1009] = 1149; em[1010] = 32; 
    	em[1011] = 1182; em[1012] = 40; 
    	em[1013] = 1199; em[1014] = 48; 
    	em[1015] = 1226; em[1016] = 56; 
    	em[1017] = 1261; em[1018] = 64; 
    	em[1019] = 1269; em[1020] = 72; 
    	em[1021] = 1272; em[1022] = 80; 
    	em[1023] = 1275; em[1024] = 88; 
    	em[1025] = 1278; em[1026] = 96; 
    	em[1027] = 1281; em[1028] = 104; 
    	em[1029] = 1281; em[1030] = 112; 
    	em[1031] = 1281; em[1032] = 120; 
    	em[1033] = 1284; em[1034] = 128; 
    	em[1035] = 953; em[1036] = 136; 
    	em[1037] = 953; em[1038] = 144; 
    	em[1039] = 1287; em[1040] = 152; 
    	em[1041] = 1290; em[1042] = 160; 
    	em[1043] = 1302; em[1044] = 184; 
    	em[1045] = 1319; em[1046] = 200; 
    	em[1047] = 1319; em[1048] = 208; 
    em[1049] = 1; em[1050] = 8; em[1051] = 1; /* 1049: pointer.struct.rsa_meth_st */
    	em[1052] = 1054; em[1053] = 0; 
    em[1054] = 0; em[1055] = 112; em[1056] = 13; /* 1054: struct.rsa_meth_st */
    	em[1057] = 149; em[1058] = 0; 
    	em[1059] = 892; em[1060] = 8; 
    	em[1061] = 892; em[1062] = 16; 
    	em[1063] = 892; em[1064] = 24; 
    	em[1065] = 892; em[1066] = 32; 
    	em[1067] = 1083; em[1068] = 40; 
    	em[1069] = 1086; em[1070] = 48; 
    	em[1071] = 1089; em[1072] = 56; 
    	em[1073] = 1089; em[1074] = 64; 
    	em[1075] = 125; em[1076] = 80; 
    	em[1077] = 1092; em[1078] = 88; 
    	em[1079] = 1095; em[1080] = 96; 
    	em[1081] = 1098; em[1082] = 104; 
    em[1083] = 8884097; em[1084] = 8; em[1085] = 0; /* 1083: pointer.func */
    em[1086] = 8884097; em[1087] = 8; em[1088] = 0; /* 1086: pointer.func */
    em[1089] = 8884097; em[1090] = 8; em[1091] = 0; /* 1089: pointer.func */
    em[1092] = 8884097; em[1093] = 8; em[1094] = 0; /* 1092: pointer.func */
    em[1095] = 8884097; em[1096] = 8; em[1097] = 0; /* 1095: pointer.func */
    em[1098] = 8884097; em[1099] = 8; em[1100] = 0; /* 1098: pointer.func */
    em[1101] = 1; em[1102] = 8; em[1103] = 1; /* 1101: pointer.struct.dsa_method */
    	em[1104] = 1106; em[1105] = 0; 
    em[1106] = 0; em[1107] = 96; em[1108] = 11; /* 1106: struct.dsa_method */
    	em[1109] = 149; em[1110] = 0; 
    	em[1111] = 898; em[1112] = 8; 
    	em[1113] = 1131; em[1114] = 16; 
    	em[1115] = 1134; em[1116] = 24; 
    	em[1117] = 1137; em[1118] = 32; 
    	em[1119] = 1140; em[1120] = 40; 
    	em[1121] = 1143; em[1122] = 48; 
    	em[1123] = 1143; em[1124] = 56; 
    	em[1125] = 125; em[1126] = 72; 
    	em[1127] = 1146; em[1128] = 80; 
    	em[1129] = 1143; em[1130] = 88; 
    em[1131] = 8884097; em[1132] = 8; em[1133] = 0; /* 1131: pointer.func */
    em[1134] = 8884097; em[1135] = 8; em[1136] = 0; /* 1134: pointer.func */
    em[1137] = 8884097; em[1138] = 8; em[1139] = 0; /* 1137: pointer.func */
    em[1140] = 8884097; em[1141] = 8; em[1142] = 0; /* 1140: pointer.func */
    em[1143] = 8884097; em[1144] = 8; em[1145] = 0; /* 1143: pointer.func */
    em[1146] = 8884097; em[1147] = 8; em[1148] = 0; /* 1146: pointer.func */
    em[1149] = 1; em[1150] = 8; em[1151] = 1; /* 1149: pointer.struct.dh_method */
    	em[1152] = 1154; em[1153] = 0; 
    em[1154] = 0; em[1155] = 72; em[1156] = 8; /* 1154: struct.dh_method */
    	em[1157] = 149; em[1158] = 0; 
    	em[1159] = 1173; em[1160] = 8; 
    	em[1161] = 895; em[1162] = 16; 
    	em[1163] = 1176; em[1164] = 24; 
    	em[1165] = 1173; em[1166] = 32; 
    	em[1167] = 1173; em[1168] = 40; 
    	em[1169] = 125; em[1170] = 56; 
    	em[1171] = 1179; em[1172] = 64; 
    em[1173] = 8884097; em[1174] = 8; em[1175] = 0; /* 1173: pointer.func */
    em[1176] = 8884097; em[1177] = 8; em[1178] = 0; /* 1176: pointer.func */
    em[1179] = 8884097; em[1180] = 8; em[1181] = 0; /* 1179: pointer.func */
    em[1182] = 1; em[1183] = 8; em[1184] = 1; /* 1182: pointer.struct.ecdh_method */
    	em[1185] = 1187; em[1186] = 0; 
    em[1187] = 0; em[1188] = 32; em[1189] = 3; /* 1187: struct.ecdh_method */
    	em[1190] = 149; em[1191] = 0; 
    	em[1192] = 1196; em[1193] = 8; 
    	em[1194] = 125; em[1195] = 24; 
    em[1196] = 8884097; em[1197] = 8; em[1198] = 0; /* 1196: pointer.func */
    em[1199] = 1; em[1200] = 8; em[1201] = 1; /* 1199: pointer.struct.ecdsa_method */
    	em[1202] = 1204; em[1203] = 0; 
    em[1204] = 0; em[1205] = 48; em[1206] = 5; /* 1204: struct.ecdsa_method */
    	em[1207] = 149; em[1208] = 0; 
    	em[1209] = 1217; em[1210] = 8; 
    	em[1211] = 1220; em[1212] = 16; 
    	em[1213] = 1223; em[1214] = 24; 
    	em[1215] = 125; em[1216] = 40; 
    em[1217] = 8884097; em[1218] = 8; em[1219] = 0; /* 1217: pointer.func */
    em[1220] = 8884097; em[1221] = 8; em[1222] = 0; /* 1220: pointer.func */
    em[1223] = 8884097; em[1224] = 8; em[1225] = 0; /* 1223: pointer.func */
    em[1226] = 1; em[1227] = 8; em[1228] = 1; /* 1226: pointer.struct.rand_meth_st */
    	em[1229] = 1231; em[1230] = 0; 
    em[1231] = 0; em[1232] = 48; em[1233] = 6; /* 1231: struct.rand_meth_st */
    	em[1234] = 1246; em[1235] = 0; 
    	em[1236] = 1249; em[1237] = 8; 
    	em[1238] = 1252; em[1239] = 16; 
    	em[1240] = 1255; em[1241] = 24; 
    	em[1242] = 1249; em[1243] = 32; 
    	em[1244] = 1258; em[1245] = 40; 
    em[1246] = 8884097; em[1247] = 8; em[1248] = 0; /* 1246: pointer.func */
    em[1249] = 8884097; em[1250] = 8; em[1251] = 0; /* 1249: pointer.func */
    em[1252] = 8884097; em[1253] = 8; em[1254] = 0; /* 1252: pointer.func */
    em[1255] = 8884097; em[1256] = 8; em[1257] = 0; /* 1255: pointer.func */
    em[1258] = 8884097; em[1259] = 8; em[1260] = 0; /* 1258: pointer.func */
    em[1261] = 1; em[1262] = 8; em[1263] = 1; /* 1261: pointer.struct.store_method_st */
    	em[1264] = 1266; em[1265] = 0; 
    em[1266] = 0; em[1267] = 0; em[1268] = 0; /* 1266: struct.store_method_st */
    em[1269] = 8884097; em[1270] = 8; em[1271] = 0; /* 1269: pointer.func */
    em[1272] = 8884097; em[1273] = 8; em[1274] = 0; /* 1272: pointer.func */
    em[1275] = 8884097; em[1276] = 8; em[1277] = 0; /* 1275: pointer.func */
    em[1278] = 8884097; em[1279] = 8; em[1280] = 0; /* 1278: pointer.func */
    em[1281] = 8884097; em[1282] = 8; em[1283] = 0; /* 1281: pointer.func */
    em[1284] = 8884097; em[1285] = 8; em[1286] = 0; /* 1284: pointer.func */
    em[1287] = 8884097; em[1288] = 8; em[1289] = 0; /* 1287: pointer.func */
    em[1290] = 1; em[1291] = 8; em[1292] = 1; /* 1290: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[1293] = 1295; em[1294] = 0; 
    em[1295] = 0; em[1296] = 32; em[1297] = 2; /* 1295: struct.ENGINE_CMD_DEFN_st */
    	em[1298] = 149; em[1299] = 8; 
    	em[1300] = 149; em[1301] = 16; 
    em[1302] = 0; em[1303] = 32; em[1304] = 2; /* 1302: struct.crypto_ex_data_st_fake */
    	em[1305] = 1309; em[1306] = 8; 
    	em[1307] = 1316; em[1308] = 24; 
    em[1309] = 8884099; em[1310] = 8; em[1311] = 2; /* 1309: pointer_to_array_of_pointers_to_stack */
    	em[1312] = 821; em[1313] = 0; 
    	em[1314] = 5; em[1315] = 20; 
    em[1316] = 8884097; em[1317] = 8; em[1318] = 0; /* 1316: pointer.func */
    em[1319] = 1; em[1320] = 8; em[1321] = 1; /* 1319: pointer.struct.engine_st */
    	em[1322] = 998; em[1323] = 0; 
    em[1324] = 0; em[1325] = 32; em[1326] = 2; /* 1324: struct.crypto_ex_data_st_fake */
    	em[1327] = 1331; em[1328] = 8; 
    	em[1329] = 1316; em[1330] = 24; 
    em[1331] = 8884099; em[1332] = 8; em[1333] = 2; /* 1331: pointer_to_array_of_pointers_to_stack */
    	em[1334] = 821; em[1335] = 0; 
    	em[1336] = 5; em[1337] = 20; 
    em[1338] = 1; em[1339] = 8; em[1340] = 1; /* 1338: pointer.struct.bn_mont_ctx_st */
    	em[1341] = 339; em[1342] = 0; 
    em[1343] = 1; em[1344] = 8; em[1345] = 1; /* 1343: pointer.struct.bn_blinding_st */
    	em[1346] = 1348; em[1347] = 0; 
    em[1348] = 0; em[1349] = 88; em[1350] = 7; /* 1348: struct.bn_blinding_st */
    	em[1351] = 1365; em[1352] = 0; 
    	em[1353] = 1365; em[1354] = 8; 
    	em[1355] = 1365; em[1356] = 16; 
    	em[1357] = 1365; em[1358] = 24; 
    	em[1359] = 1382; em[1360] = 40; 
    	em[1361] = 1387; em[1362] = 72; 
    	em[1363] = 1401; em[1364] = 80; 
    em[1365] = 1; em[1366] = 8; em[1367] = 1; /* 1365: pointer.struct.bignum_st */
    	em[1368] = 1370; em[1369] = 0; 
    em[1370] = 0; em[1371] = 24; em[1372] = 1; /* 1370: struct.bignum_st */
    	em[1373] = 1375; em[1374] = 0; 
    em[1375] = 8884099; em[1376] = 8; em[1377] = 2; /* 1375: pointer_to_array_of_pointers_to_stack */
    	em[1378] = 360; em[1379] = 0; 
    	em[1380] = 5; em[1381] = 12; 
    em[1382] = 0; em[1383] = 16; em[1384] = 1; /* 1382: struct.crypto_threadid_st */
    	em[1385] = 821; em[1386] = 0; 
    em[1387] = 1; em[1388] = 8; em[1389] = 1; /* 1387: pointer.struct.bn_mont_ctx_st */
    	em[1390] = 1392; em[1391] = 0; 
    em[1392] = 0; em[1393] = 96; em[1394] = 3; /* 1392: struct.bn_mont_ctx_st */
    	em[1395] = 1370; em[1396] = 8; 
    	em[1397] = 1370; em[1398] = 32; 
    	em[1399] = 1370; em[1400] = 56; 
    em[1401] = 8884097; em[1402] = 8; em[1403] = 0; /* 1401: pointer.func */
    em[1404] = 8884097; em[1405] = 8; em[1406] = 0; /* 1404: pointer.func */
    em[1407] = 8884097; em[1408] = 8; em[1409] = 0; /* 1407: pointer.func */
    em[1410] = 8884097; em[1411] = 8; em[1412] = 0; /* 1410: pointer.func */
    em[1413] = 8884097; em[1414] = 8; em[1415] = 0; /* 1413: pointer.func */
    em[1416] = 1; em[1417] = 8; em[1418] = 1; /* 1416: pointer.struct.dh_method */
    	em[1419] = 1421; em[1420] = 0; 
    em[1421] = 0; em[1422] = 72; em[1423] = 8; /* 1421: struct.dh_method */
    	em[1424] = 149; em[1425] = 0; 
    	em[1426] = 1440; em[1427] = 8; 
    	em[1428] = 1443; em[1429] = 16; 
    	em[1430] = 1410; em[1431] = 24; 
    	em[1432] = 1440; em[1433] = 32; 
    	em[1434] = 1440; em[1435] = 40; 
    	em[1436] = 125; em[1437] = 56; 
    	em[1438] = 1446; em[1439] = 64; 
    em[1440] = 8884097; em[1441] = 8; em[1442] = 0; /* 1440: pointer.func */
    em[1443] = 8884097; em[1444] = 8; em[1445] = 0; /* 1443: pointer.func */
    em[1446] = 8884097; em[1447] = 8; em[1448] = 0; /* 1446: pointer.func */
    em[1449] = 8884097; em[1450] = 8; em[1451] = 0; /* 1449: pointer.func */
    em[1452] = 8884097; em[1453] = 8; em[1454] = 0; /* 1452: pointer.func */
    em[1455] = 8884097; em[1456] = 8; em[1457] = 0; /* 1455: pointer.func */
    em[1458] = 0; em[1459] = 208; em[1460] = 24; /* 1458: struct.evp_pkey_asn1_method_st */
    	em[1461] = 125; em[1462] = 16; 
    	em[1463] = 125; em[1464] = 24; 
    	em[1465] = 1455; em[1466] = 32; 
    	em[1467] = 1452; em[1468] = 40; 
    	em[1469] = 950; em[1470] = 48; 
    	em[1471] = 1509; em[1472] = 56; 
    	em[1473] = 1512; em[1474] = 64; 
    	em[1475] = 1515; em[1476] = 72; 
    	em[1477] = 1509; em[1478] = 80; 
    	em[1479] = 1518; em[1480] = 88; 
    	em[1481] = 1518; em[1482] = 96; 
    	em[1483] = 1521; em[1484] = 104; 
    	em[1485] = 1524; em[1486] = 112; 
    	em[1487] = 1518; em[1488] = 120; 
    	em[1489] = 1449; em[1490] = 128; 
    	em[1491] = 950; em[1492] = 136; 
    	em[1493] = 1509; em[1494] = 144; 
    	em[1495] = 1413; em[1496] = 152; 
    	em[1497] = 1527; em[1498] = 160; 
    	em[1499] = 1530; em[1500] = 168; 
    	em[1501] = 1521; em[1502] = 176; 
    	em[1503] = 1524; em[1504] = 184; 
    	em[1505] = 1533; em[1506] = 192; 
    	em[1507] = 1407; em[1508] = 200; 
    em[1509] = 8884097; em[1510] = 8; em[1511] = 0; /* 1509: pointer.func */
    em[1512] = 8884097; em[1513] = 8; em[1514] = 0; /* 1512: pointer.func */
    em[1515] = 8884097; em[1516] = 8; em[1517] = 0; /* 1515: pointer.func */
    em[1518] = 8884097; em[1519] = 8; em[1520] = 0; /* 1518: pointer.func */
    em[1521] = 8884097; em[1522] = 8; em[1523] = 0; /* 1521: pointer.func */
    em[1524] = 8884097; em[1525] = 8; em[1526] = 0; /* 1524: pointer.func */
    em[1527] = 8884097; em[1528] = 8; em[1529] = 0; /* 1527: pointer.func */
    em[1530] = 8884097; em[1531] = 8; em[1532] = 0; /* 1530: pointer.func */
    em[1533] = 8884097; em[1534] = 8; em[1535] = 0; /* 1533: pointer.func */
    em[1536] = 8884097; em[1537] = 8; em[1538] = 0; /* 1536: pointer.func */
    em[1539] = 8884097; em[1540] = 8; em[1541] = 0; /* 1539: pointer.func */
    em[1542] = 8884097; em[1543] = 8; em[1544] = 0; /* 1542: pointer.func */
    em[1545] = 1; em[1546] = 8; em[1547] = 1; /* 1545: pointer.struct.evp_pkey_method_st */
    	em[1548] = 1550; em[1549] = 0; 
    em[1550] = 0; em[1551] = 208; em[1552] = 25; /* 1550: struct.evp_pkey_method_st */
    	em[1553] = 1603; em[1554] = 8; 
    	em[1555] = 1606; em[1556] = 16; 
    	em[1557] = 1609; em[1558] = 24; 
    	em[1559] = 1603; em[1560] = 32; 
    	em[1561] = 1612; em[1562] = 40; 
    	em[1563] = 1603; em[1564] = 48; 
    	em[1565] = 1612; em[1566] = 56; 
    	em[1567] = 1603; em[1568] = 64; 
    	em[1569] = 1539; em[1570] = 72; 
    	em[1571] = 1603; em[1572] = 80; 
    	em[1573] = 1536; em[1574] = 88; 
    	em[1575] = 1603; em[1576] = 96; 
    	em[1577] = 1539; em[1578] = 104; 
    	em[1579] = 1615; em[1580] = 112; 
    	em[1581] = 1404; em[1582] = 120; 
    	em[1583] = 1615; em[1584] = 128; 
    	em[1585] = 1618; em[1586] = 136; 
    	em[1587] = 1603; em[1588] = 144; 
    	em[1589] = 1539; em[1590] = 152; 
    	em[1591] = 1603; em[1592] = 160; 
    	em[1593] = 1539; em[1594] = 168; 
    	em[1595] = 1603; em[1596] = 176; 
    	em[1597] = 1621; em[1598] = 184; 
    	em[1599] = 1624; em[1600] = 192; 
    	em[1601] = 1627; em[1602] = 200; 
    em[1603] = 8884097; em[1604] = 8; em[1605] = 0; /* 1603: pointer.func */
    em[1606] = 8884097; em[1607] = 8; em[1608] = 0; /* 1606: pointer.func */
    em[1609] = 8884097; em[1610] = 8; em[1611] = 0; /* 1609: pointer.func */
    em[1612] = 8884097; em[1613] = 8; em[1614] = 0; /* 1612: pointer.func */
    em[1615] = 8884097; em[1616] = 8; em[1617] = 0; /* 1615: pointer.func */
    em[1618] = 8884097; em[1619] = 8; em[1620] = 0; /* 1618: pointer.func */
    em[1621] = 8884097; em[1622] = 8; em[1623] = 0; /* 1621: pointer.func */
    em[1624] = 8884097; em[1625] = 8; em[1626] = 0; /* 1624: pointer.func */
    em[1627] = 8884097; em[1628] = 8; em[1629] = 0; /* 1627: pointer.func */
    em[1630] = 8884097; em[1631] = 8; em[1632] = 0; /* 1630: pointer.func */
    em[1633] = 1; em[1634] = 8; em[1635] = 1; /* 1633: pointer.struct.stack_st_ASN1_TYPE */
    	em[1636] = 1638; em[1637] = 0; 
    em[1638] = 0; em[1639] = 32; em[1640] = 2; /* 1638: struct.stack_st_fake_ASN1_TYPE */
    	em[1641] = 1645; em[1642] = 8; 
    	em[1643] = 1316; em[1644] = 24; 
    em[1645] = 8884099; em[1646] = 8; em[1647] = 2; /* 1645: pointer_to_array_of_pointers_to_stack */
    	em[1648] = 1652; em[1649] = 0; 
    	em[1650] = 5; em[1651] = 20; 
    em[1652] = 0; em[1653] = 8; em[1654] = 1; /* 1652: pointer.ASN1_TYPE */
    	em[1655] = 246; em[1656] = 0; 
    em[1657] = 0; em[1658] = 24; em[1659] = 1; /* 1657: struct.bignum_st */
    	em[1660] = 1662; em[1661] = 0; 
    em[1662] = 8884099; em[1663] = 8; em[1664] = 2; /* 1662: pointer_to_array_of_pointers_to_stack */
    	em[1665] = 360; em[1666] = 0; 
    	em[1667] = 5; em[1668] = 12; 
    em[1669] = 1; em[1670] = 8; em[1671] = 1; /* 1669: pointer.struct.evp_pkey_asn1_method_st */
    	em[1672] = 1458; em[1673] = 0; 
    em[1674] = 8884097; em[1675] = 8; em[1676] = 0; /* 1674: pointer.func */
    em[1677] = 0; em[1678] = 120; em[1679] = 8; /* 1677: struct.env_md_st */
    	em[1680] = 1674; em[1681] = 24; 
    	em[1682] = 1696; em[1683] = 32; 
    	em[1684] = 1699; em[1685] = 40; 
    	em[1686] = 904; em[1687] = 48; 
    	em[1688] = 1674; em[1689] = 56; 
    	em[1690] = 1702; em[1691] = 64; 
    	em[1692] = 1705; em[1693] = 72; 
    	em[1694] = 1630; em[1695] = 112; 
    em[1696] = 8884097; em[1697] = 8; em[1698] = 0; /* 1696: pointer.func */
    em[1699] = 8884097; em[1700] = 8; em[1701] = 0; /* 1699: pointer.func */
    em[1702] = 8884097; em[1703] = 8; em[1704] = 0; /* 1702: pointer.func */
    em[1705] = 8884097; em[1706] = 8; em[1707] = 0; /* 1705: pointer.func */
    em[1708] = 1; em[1709] = 8; em[1710] = 1; /* 1708: pointer.struct.dsa_st */
    	em[1711] = 1713; em[1712] = 0; 
    em[1713] = 0; em[1714] = 136; em[1715] = 11; /* 1713: struct.dsa_st */
    	em[1716] = 1738; em[1717] = 24; 
    	em[1718] = 1738; em[1719] = 32; 
    	em[1720] = 1738; em[1721] = 40; 
    	em[1722] = 1738; em[1723] = 48; 
    	em[1724] = 1738; em[1725] = 56; 
    	em[1726] = 1738; em[1727] = 64; 
    	em[1728] = 1738; em[1729] = 72; 
    	em[1730] = 1755; em[1731] = 88; 
    	em[1732] = 1769; em[1733] = 104; 
    	em[1734] = 1783; em[1735] = 120; 
    	em[1736] = 1831; em[1737] = 128; 
    em[1738] = 1; em[1739] = 8; em[1740] = 1; /* 1738: pointer.struct.bignum_st */
    	em[1741] = 1743; em[1742] = 0; 
    em[1743] = 0; em[1744] = 24; em[1745] = 1; /* 1743: struct.bignum_st */
    	em[1746] = 1748; em[1747] = 0; 
    em[1748] = 8884099; em[1749] = 8; em[1750] = 2; /* 1748: pointer_to_array_of_pointers_to_stack */
    	em[1751] = 360; em[1752] = 0; 
    	em[1753] = 5; em[1754] = 12; 
    em[1755] = 1; em[1756] = 8; em[1757] = 1; /* 1755: pointer.struct.bn_mont_ctx_st */
    	em[1758] = 1760; em[1759] = 0; 
    em[1760] = 0; em[1761] = 96; em[1762] = 3; /* 1760: struct.bn_mont_ctx_st */
    	em[1763] = 1743; em[1764] = 8; 
    	em[1765] = 1743; em[1766] = 32; 
    	em[1767] = 1743; em[1768] = 56; 
    em[1769] = 0; em[1770] = 32; em[1771] = 2; /* 1769: struct.crypto_ex_data_st_fake */
    	em[1772] = 1776; em[1773] = 8; 
    	em[1774] = 1316; em[1775] = 24; 
    em[1776] = 8884099; em[1777] = 8; em[1778] = 2; /* 1776: pointer_to_array_of_pointers_to_stack */
    	em[1779] = 821; em[1780] = 0; 
    	em[1781] = 5; em[1782] = 20; 
    em[1783] = 1; em[1784] = 8; em[1785] = 1; /* 1783: pointer.struct.dsa_method */
    	em[1786] = 1788; em[1787] = 0; 
    em[1788] = 0; em[1789] = 96; em[1790] = 11; /* 1788: struct.dsa_method */
    	em[1791] = 149; em[1792] = 0; 
    	em[1793] = 1813; em[1794] = 8; 
    	em[1795] = 1816; em[1796] = 16; 
    	em[1797] = 1819; em[1798] = 24; 
    	em[1799] = 1822; em[1800] = 32; 
    	em[1801] = 1825; em[1802] = 40; 
    	em[1803] = 1542; em[1804] = 48; 
    	em[1805] = 1542; em[1806] = 56; 
    	em[1807] = 125; em[1808] = 72; 
    	em[1809] = 1828; em[1810] = 80; 
    	em[1811] = 1542; em[1812] = 88; 
    em[1813] = 8884097; em[1814] = 8; em[1815] = 0; /* 1813: pointer.func */
    em[1816] = 8884097; em[1817] = 8; em[1818] = 0; /* 1816: pointer.func */
    em[1819] = 8884097; em[1820] = 8; em[1821] = 0; /* 1819: pointer.func */
    em[1822] = 8884097; em[1823] = 8; em[1824] = 0; /* 1822: pointer.func */
    em[1825] = 8884097; em[1826] = 8; em[1827] = 0; /* 1825: pointer.func */
    em[1828] = 8884097; em[1829] = 8; em[1830] = 0; /* 1828: pointer.func */
    em[1831] = 1; em[1832] = 8; em[1833] = 1; /* 1831: pointer.struct.engine_st */
    	em[1834] = 998; em[1835] = 0; 
    em[1836] = 0; em[1837] = 48; em[1838] = 5; /* 1836: struct.env_md_ctx_st */
    	em[1839] = 1849; em[1840] = 0; 
    	em[1841] = 1854; em[1842] = 8; 
    	em[1843] = 821; em[1844] = 24; 
    	em[1845] = 1859; em[1846] = 32; 
    	em[1847] = 1696; em[1848] = 40; 
    em[1849] = 1; em[1850] = 8; em[1851] = 1; /* 1849: pointer.struct.env_md_st */
    	em[1852] = 1677; em[1853] = 0; 
    em[1854] = 1; em[1855] = 8; em[1856] = 1; /* 1854: pointer.struct.engine_st */
    	em[1857] = 998; em[1858] = 0; 
    em[1859] = 1; em[1860] = 8; em[1861] = 1; /* 1859: pointer.struct.evp_pkey_ctx_st */
    	em[1862] = 1864; em[1863] = 0; 
    em[1864] = 0; em[1865] = 80; em[1866] = 8; /* 1864: struct.evp_pkey_ctx_st */
    	em[1867] = 1545; em[1868] = 0; 
    	em[1869] = 1854; em[1870] = 8; 
    	em[1871] = 1883; em[1872] = 16; 
    	em[1873] = 1883; em[1874] = 24; 
    	em[1875] = 821; em[1876] = 40; 
    	em[1877] = 821; em[1878] = 48; 
    	em[1879] = 8; em[1880] = 56; 
    	em[1881] = 0; em[1882] = 64; 
    em[1883] = 1; em[1884] = 8; em[1885] = 1; /* 1883: pointer.struct.evp_pkey_st */
    	em[1886] = 1888; em[1887] = 0; 
    em[1888] = 0; em[1889] = 56; em[1890] = 4; /* 1888: struct.evp_pkey_st */
    	em[1891] = 1669; em[1892] = 16; 
    	em[1893] = 1854; em[1894] = 24; 
    	em[1895] = 1899; em[1896] = 32; 
    	em[1897] = 1982; em[1898] = 48; 
    em[1899] = 0; em[1900] = 8; em[1901] = 5; /* 1899: union.unknown */
    	em[1902] = 125; em[1903] = 0; 
    	em[1904] = 1912; em[1905] = 0; 
    	em[1906] = 1708; em[1907] = 0; 
    	em[1908] = 1917; em[1909] = 0; 
    	em[1910] = 369; em[1911] = 0; 
    em[1912] = 1; em[1913] = 8; em[1914] = 1; /* 1912: pointer.struct.rsa_st */
    	em[1915] = 956; em[1916] = 0; 
    em[1917] = 1; em[1918] = 8; em[1919] = 1; /* 1917: pointer.struct.dh_st */
    	em[1920] = 1922; em[1921] = 0; 
    em[1922] = 0; em[1923] = 144; em[1924] = 12; /* 1922: struct.dh_st */
    	em[1925] = 1949; em[1926] = 8; 
    	em[1927] = 1949; em[1928] = 16; 
    	em[1929] = 1949; em[1930] = 32; 
    	em[1931] = 1949; em[1932] = 40; 
    	em[1933] = 1954; em[1934] = 56; 
    	em[1935] = 1949; em[1936] = 64; 
    	em[1937] = 1949; em[1938] = 72; 
    	em[1939] = 29; em[1940] = 80; 
    	em[1941] = 1949; em[1942] = 96; 
    	em[1943] = 1968; em[1944] = 112; 
    	em[1945] = 1416; em[1946] = 128; 
    	em[1947] = 1854; em[1948] = 136; 
    em[1949] = 1; em[1950] = 8; em[1951] = 1; /* 1949: pointer.struct.bignum_st */
    	em[1952] = 1657; em[1953] = 0; 
    em[1954] = 1; em[1955] = 8; em[1956] = 1; /* 1954: pointer.struct.bn_mont_ctx_st */
    	em[1957] = 1959; em[1958] = 0; 
    em[1959] = 0; em[1960] = 96; em[1961] = 3; /* 1959: struct.bn_mont_ctx_st */
    	em[1962] = 1657; em[1963] = 8; 
    	em[1964] = 1657; em[1965] = 32; 
    	em[1966] = 1657; em[1967] = 56; 
    em[1968] = 0; em[1969] = 32; em[1970] = 2; /* 1968: struct.crypto_ex_data_st_fake */
    	em[1971] = 1975; em[1972] = 8; 
    	em[1973] = 1316; em[1974] = 24; 
    em[1975] = 8884099; em[1976] = 8; em[1977] = 2; /* 1975: pointer_to_array_of_pointers_to_stack */
    	em[1978] = 821; em[1979] = 0; 
    	em[1980] = 5; em[1981] = 20; 
    em[1982] = 1; em[1983] = 8; em[1984] = 1; /* 1982: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1985] = 1987; em[1986] = 0; 
    em[1987] = 0; em[1988] = 32; em[1989] = 2; /* 1987: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1990] = 1994; em[1991] = 8; 
    	em[1992] = 1316; em[1993] = 24; 
    em[1994] = 8884099; em[1995] = 8; em[1996] = 2; /* 1994: pointer_to_array_of_pointers_to_stack */
    	em[1997] = 2001; em[1998] = 0; 
    	em[1999] = 5; em[2000] = 20; 
    em[2001] = 0; em[2002] = 8; em[2003] = 1; /* 2001: pointer.X509_ATTRIBUTE */
    	em[2004] = 2006; em[2005] = 0; 
    em[2006] = 0; em[2007] = 0; em[2008] = 1; /* 2006: X509_ATTRIBUTE */
    	em[2009] = 2011; em[2010] = 0; 
    em[2011] = 0; em[2012] = 24; em[2013] = 2; /* 2011: struct.x509_attributes_st */
    	em[2014] = 135; em[2015] = 0; 
    	em[2016] = 2018; em[2017] = 16; 
    em[2018] = 0; em[2019] = 8; em[2020] = 3; /* 2018: union.unknown */
    	em[2021] = 125; em[2022] = 0; 
    	em[2023] = 1633; em[2024] = 0; 
    	em[2025] = 2027; em[2026] = 0; 
    em[2027] = 1; em[2028] = 8; em[2029] = 1; /* 2027: pointer.struct.asn1_type_st */
    	em[2030] = 179; em[2031] = 0; 
    em[2032] = 1; em[2033] = 8; em[2034] = 1; /* 2032: pointer.struct.env_md_ctx_st */
    	em[2035] = 1836; em[2036] = 0; 
    args_addr->arg_entity_index[0] = 2032;
    args_addr->arg_entity_index[1] = 1849;
    args_addr->arg_entity_index[2] = 1854;
    args_addr->ret_entity_index = 5;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * new_arg_a = *((EVP_MD_CTX * *)new_args->args[0]);

    const EVP_MD * new_arg_b = *((const EVP_MD * *)new_args->args[1]);

    ENGINE * new_arg_c = *((ENGINE * *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_DigestInit_ex)(EVP_MD_CTX *,const EVP_MD *,ENGINE *);
    orig_EVP_DigestInit_ex = dlsym(RTLD_NEXT, "EVP_DigestInit_ex");
    *new_ret_ptr = (*orig_EVP_DigestInit_ex)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    free(args_addr);

    return ret;
}

