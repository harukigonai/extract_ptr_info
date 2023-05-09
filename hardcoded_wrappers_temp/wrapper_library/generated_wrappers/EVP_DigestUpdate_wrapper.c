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

int bb_EVP_DigestUpdate(EVP_MD_CTX * arg_a, const void * arg_b,size_t arg_c);

int EVP_DigestUpdate(EVP_MD_CTX * arg_a, const void * arg_b,size_t arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_DigestUpdate called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_DigestUpdate(arg_a,arg_b,arg_c);
    else {
        int (*orig_EVP_DigestUpdate)(EVP_MD_CTX *, const void *,size_t);
        orig_EVP_DigestUpdate = dlsym(RTLD_NEXT, "EVP_DigestUpdate");
        return orig_EVP_DigestUpdate(arg_a,arg_b,arg_c);
    }
}

int bb_EVP_DigestUpdate(EVP_MD_CTX * arg_a, const void * arg_b,size_t arg_c) 
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
    em[339] = 1; em[340] = 8; em[341] = 1; /* 339: pointer.struct.stack_st_ASN1_TYPE */
    	em[342] = 344; em[343] = 0; 
    em[344] = 0; em[345] = 32; em[346] = 2; /* 344: struct.stack_st_fake_ASN1_TYPE */
    	em[347] = 351; em[348] = 8; 
    	em[349] = 363; em[350] = 24; 
    em[351] = 8884099; em[352] = 8; em[353] = 2; /* 351: pointer_to_array_of_pointers_to_stack */
    	em[354] = 358; em[355] = 0; 
    	em[356] = 5; em[357] = 20; 
    em[358] = 0; em[359] = 8; em[360] = 1; /* 358: pointer.ASN1_TYPE */
    	em[361] = 241; em[362] = 0; 
    em[363] = 8884097; em[364] = 8; em[365] = 0; /* 363: pointer.func */
    em[366] = 0; em[367] = 96; em[368] = 3; /* 366: struct.bn_mont_ctx_st */
    	em[369] = 375; em[370] = 8; 
    	em[371] = 375; em[372] = 32; 
    	em[373] = 375; em[374] = 56; 
    em[375] = 0; em[376] = 24; em[377] = 1; /* 375: struct.bignum_st */
    	em[378] = 380; em[379] = 0; 
    em[380] = 8884099; em[381] = 8; em[382] = 2; /* 380: pointer_to_array_of_pointers_to_stack */
    	em[383] = 387; em[384] = 0; 
    	em[385] = 5; em[386] = 12; 
    em[387] = 0; em[388] = 8; em[389] = 0; /* 387: long unsigned int */
    em[390] = 8884097; em[391] = 8; em[392] = 0; /* 390: pointer.func */
    em[393] = 8884097; em[394] = 8; em[395] = 0; /* 393: pointer.func */
    em[396] = 1; em[397] = 8; em[398] = 1; /* 396: pointer.struct.ec_key_st */
    	em[399] = 401; em[400] = 0; 
    em[401] = 0; em[402] = 56; em[403] = 4; /* 401: struct.ec_key_st */
    	em[404] = 412; em[405] = 8; 
    	em[406] = 860; em[407] = 16; 
    	em[408] = 865; em[409] = 24; 
    	em[410] = 882; em[411] = 48; 
    em[412] = 1; em[413] = 8; em[414] = 1; /* 412: pointer.struct.ec_group_st */
    	em[415] = 417; em[416] = 0; 
    em[417] = 0; em[418] = 232; em[419] = 12; /* 417: struct.ec_group_st */
    	em[420] = 444; em[421] = 0; 
    	em[422] = 613; em[423] = 8; 
    	em[424] = 813; em[425] = 16; 
    	em[426] = 813; em[427] = 40; 
    	em[428] = 29; em[429] = 80; 
    	em[430] = 825; em[431] = 96; 
    	em[432] = 813; em[433] = 104; 
    	em[434] = 813; em[435] = 152; 
    	em[436] = 813; em[437] = 176; 
    	em[438] = 848; em[439] = 208; 
    	em[440] = 848; em[441] = 216; 
    	em[442] = 857; em[443] = 224; 
    em[444] = 1; em[445] = 8; em[446] = 1; /* 444: pointer.struct.ec_method_st */
    	em[447] = 449; em[448] = 0; 
    em[449] = 0; em[450] = 304; em[451] = 37; /* 449: struct.ec_method_st */
    	em[452] = 526; em[453] = 8; 
    	em[454] = 529; em[455] = 16; 
    	em[456] = 529; em[457] = 24; 
    	em[458] = 532; em[459] = 32; 
    	em[460] = 390; em[461] = 40; 
    	em[462] = 535; em[463] = 48; 
    	em[464] = 538; em[465] = 56; 
    	em[466] = 541; em[467] = 64; 
    	em[468] = 544; em[469] = 72; 
    	em[470] = 547; em[471] = 80; 
    	em[472] = 547; em[473] = 88; 
    	em[474] = 550; em[475] = 96; 
    	em[476] = 553; em[477] = 104; 
    	em[478] = 556; em[479] = 112; 
    	em[480] = 559; em[481] = 120; 
    	em[482] = 562; em[483] = 128; 
    	em[484] = 565; em[485] = 136; 
    	em[486] = 568; em[487] = 144; 
    	em[488] = 571; em[489] = 152; 
    	em[490] = 574; em[491] = 160; 
    	em[492] = 577; em[493] = 168; 
    	em[494] = 580; em[495] = 176; 
    	em[496] = 583; em[497] = 184; 
    	em[498] = 586; em[499] = 192; 
    	em[500] = 589; em[501] = 200; 
    	em[502] = 592; em[503] = 208; 
    	em[504] = 583; em[505] = 216; 
    	em[506] = 595; em[507] = 224; 
    	em[508] = 598; em[509] = 232; 
    	em[510] = 601; em[511] = 240; 
    	em[512] = 538; em[513] = 248; 
    	em[514] = 604; em[515] = 256; 
    	em[516] = 607; em[517] = 264; 
    	em[518] = 604; em[519] = 272; 
    	em[520] = 607; em[521] = 280; 
    	em[522] = 607; em[523] = 288; 
    	em[524] = 610; em[525] = 296; 
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
    em[586] = 8884097; em[587] = 8; em[588] = 0; /* 586: pointer.func */
    em[589] = 8884097; em[590] = 8; em[591] = 0; /* 589: pointer.func */
    em[592] = 8884097; em[593] = 8; em[594] = 0; /* 592: pointer.func */
    em[595] = 8884097; em[596] = 8; em[597] = 0; /* 595: pointer.func */
    em[598] = 8884097; em[599] = 8; em[600] = 0; /* 598: pointer.func */
    em[601] = 8884097; em[602] = 8; em[603] = 0; /* 601: pointer.func */
    em[604] = 8884097; em[605] = 8; em[606] = 0; /* 604: pointer.func */
    em[607] = 8884097; em[608] = 8; em[609] = 0; /* 607: pointer.func */
    em[610] = 8884097; em[611] = 8; em[612] = 0; /* 610: pointer.func */
    em[613] = 1; em[614] = 8; em[615] = 1; /* 613: pointer.struct.ec_point_st */
    	em[616] = 618; em[617] = 0; 
    em[618] = 0; em[619] = 88; em[620] = 4; /* 618: struct.ec_point_st */
    	em[621] = 629; em[622] = 0; 
    	em[623] = 801; em[624] = 8; 
    	em[625] = 801; em[626] = 32; 
    	em[627] = 801; em[628] = 56; 
    em[629] = 1; em[630] = 8; em[631] = 1; /* 629: pointer.struct.ec_method_st */
    	em[632] = 634; em[633] = 0; 
    em[634] = 0; em[635] = 304; em[636] = 37; /* 634: struct.ec_method_st */
    	em[637] = 711; em[638] = 8; 
    	em[639] = 714; em[640] = 16; 
    	em[641] = 714; em[642] = 24; 
    	em[643] = 717; em[644] = 32; 
    	em[645] = 720; em[646] = 40; 
    	em[647] = 723; em[648] = 48; 
    	em[649] = 726; em[650] = 56; 
    	em[651] = 729; em[652] = 64; 
    	em[653] = 732; em[654] = 72; 
    	em[655] = 735; em[656] = 80; 
    	em[657] = 735; em[658] = 88; 
    	em[659] = 738; em[660] = 96; 
    	em[661] = 741; em[662] = 104; 
    	em[663] = 744; em[664] = 112; 
    	em[665] = 747; em[666] = 120; 
    	em[667] = 750; em[668] = 128; 
    	em[669] = 753; em[670] = 136; 
    	em[671] = 756; em[672] = 144; 
    	em[673] = 759; em[674] = 152; 
    	em[675] = 762; em[676] = 160; 
    	em[677] = 765; em[678] = 168; 
    	em[679] = 768; em[680] = 176; 
    	em[681] = 771; em[682] = 184; 
    	em[683] = 774; em[684] = 192; 
    	em[685] = 777; em[686] = 200; 
    	em[687] = 780; em[688] = 208; 
    	em[689] = 771; em[690] = 216; 
    	em[691] = 783; em[692] = 224; 
    	em[693] = 786; em[694] = 232; 
    	em[695] = 789; em[696] = 240; 
    	em[697] = 726; em[698] = 248; 
    	em[699] = 792; em[700] = 256; 
    	em[701] = 795; em[702] = 264; 
    	em[703] = 792; em[704] = 272; 
    	em[705] = 795; em[706] = 280; 
    	em[707] = 795; em[708] = 288; 
    	em[709] = 798; em[710] = 296; 
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
    em[774] = 8884097; em[775] = 8; em[776] = 0; /* 774: pointer.func */
    em[777] = 8884097; em[778] = 8; em[779] = 0; /* 777: pointer.func */
    em[780] = 8884097; em[781] = 8; em[782] = 0; /* 780: pointer.func */
    em[783] = 8884097; em[784] = 8; em[785] = 0; /* 783: pointer.func */
    em[786] = 8884097; em[787] = 8; em[788] = 0; /* 786: pointer.func */
    em[789] = 8884097; em[790] = 8; em[791] = 0; /* 789: pointer.func */
    em[792] = 8884097; em[793] = 8; em[794] = 0; /* 792: pointer.func */
    em[795] = 8884097; em[796] = 8; em[797] = 0; /* 795: pointer.func */
    em[798] = 8884097; em[799] = 8; em[800] = 0; /* 798: pointer.func */
    em[801] = 0; em[802] = 24; em[803] = 1; /* 801: struct.bignum_st */
    	em[804] = 806; em[805] = 0; 
    em[806] = 8884099; em[807] = 8; em[808] = 2; /* 806: pointer_to_array_of_pointers_to_stack */
    	em[809] = 387; em[810] = 0; 
    	em[811] = 5; em[812] = 12; 
    em[813] = 0; em[814] = 24; em[815] = 1; /* 813: struct.bignum_st */
    	em[816] = 818; em[817] = 0; 
    em[818] = 8884099; em[819] = 8; em[820] = 2; /* 818: pointer_to_array_of_pointers_to_stack */
    	em[821] = 387; em[822] = 0; 
    	em[823] = 5; em[824] = 12; 
    em[825] = 1; em[826] = 8; em[827] = 1; /* 825: pointer.struct.ec_extra_data_st */
    	em[828] = 830; em[829] = 0; 
    em[830] = 0; em[831] = 40; em[832] = 5; /* 830: struct.ec_extra_data_st */
    	em[833] = 843; em[834] = 0; 
    	em[835] = 848; em[836] = 8; 
    	em[837] = 851; em[838] = 16; 
    	em[839] = 854; em[840] = 24; 
    	em[841] = 854; em[842] = 32; 
    em[843] = 1; em[844] = 8; em[845] = 1; /* 843: pointer.struct.ec_extra_data_st */
    	em[846] = 830; em[847] = 0; 
    em[848] = 0; em[849] = 8; em[850] = 0; /* 848: pointer.void */
    em[851] = 8884097; em[852] = 8; em[853] = 0; /* 851: pointer.func */
    em[854] = 8884097; em[855] = 8; em[856] = 0; /* 854: pointer.func */
    em[857] = 8884097; em[858] = 8; em[859] = 0; /* 857: pointer.func */
    em[860] = 1; em[861] = 8; em[862] = 1; /* 860: pointer.struct.ec_point_st */
    	em[863] = 618; em[864] = 0; 
    em[865] = 1; em[866] = 8; em[867] = 1; /* 865: pointer.struct.bignum_st */
    	em[868] = 870; em[869] = 0; 
    em[870] = 0; em[871] = 24; em[872] = 1; /* 870: struct.bignum_st */
    	em[873] = 875; em[874] = 0; 
    em[875] = 8884099; em[876] = 8; em[877] = 2; /* 875: pointer_to_array_of_pointers_to_stack */
    	em[878] = 387; em[879] = 0; 
    	em[880] = 5; em[881] = 12; 
    em[882] = 1; em[883] = 8; em[884] = 1; /* 882: pointer.struct.ec_extra_data_st */
    	em[885] = 887; em[886] = 0; 
    em[887] = 0; em[888] = 40; em[889] = 5; /* 887: struct.ec_extra_data_st */
    	em[890] = 900; em[891] = 0; 
    	em[892] = 848; em[893] = 8; 
    	em[894] = 851; em[895] = 16; 
    	em[896] = 854; em[897] = 24; 
    	em[898] = 854; em[899] = 32; 
    em[900] = 1; em[901] = 8; em[902] = 1; /* 900: pointer.struct.ec_extra_data_st */
    	em[903] = 887; em[904] = 0; 
    em[905] = 8884097; em[906] = 8; em[907] = 0; /* 905: pointer.func */
    em[908] = 8884097; em[909] = 8; em[910] = 0; /* 908: pointer.func */
    em[911] = 8884097; em[912] = 8; em[913] = 0; /* 911: pointer.func */
    em[914] = 8884097; em[915] = 8; em[916] = 0; /* 914: pointer.func */
    em[917] = 0; em[918] = 112; em[919] = 13; /* 917: struct.rsa_meth_st */
    	em[920] = 144; em[921] = 0; 
    	em[922] = 911; em[923] = 8; 
    	em[924] = 911; em[925] = 16; 
    	em[926] = 911; em[927] = 24; 
    	em[928] = 911; em[929] = 32; 
    	em[930] = 946; em[931] = 40; 
    	em[932] = 949; em[933] = 48; 
    	em[934] = 905; em[935] = 56; 
    	em[936] = 905; em[937] = 64; 
    	em[938] = 120; em[939] = 80; 
    	em[940] = 952; em[941] = 88; 
    	em[942] = 955; em[943] = 96; 
    	em[944] = 393; em[945] = 104; 
    em[946] = 8884097; em[947] = 8; em[948] = 0; /* 946: pointer.func */
    em[949] = 8884097; em[950] = 8; em[951] = 0; /* 949: pointer.func */
    em[952] = 8884097; em[953] = 8; em[954] = 0; /* 952: pointer.func */
    em[955] = 8884097; em[956] = 8; em[957] = 0; /* 955: pointer.func */
    em[958] = 1; em[959] = 8; em[960] = 1; /* 958: pointer.struct.rsa_meth_st */
    	em[961] = 917; em[962] = 0; 
    em[963] = 8884097; em[964] = 8; em[965] = 0; /* 963: pointer.func */
    em[966] = 8884097; em[967] = 8; em[968] = 0; /* 966: pointer.func */
    em[969] = 0; em[970] = 168; em[971] = 17; /* 969: struct.rsa_st */
    	em[972] = 958; em[973] = 16; 
    	em[974] = 1006; em[975] = 24; 
    	em[976] = 1340; em[977] = 32; 
    	em[978] = 1340; em[979] = 40; 
    	em[980] = 1340; em[981] = 48; 
    	em[982] = 1340; em[983] = 56; 
    	em[984] = 1340; em[985] = 64; 
    	em[986] = 1340; em[987] = 72; 
    	em[988] = 1340; em[989] = 80; 
    	em[990] = 1340; em[991] = 88; 
    	em[992] = 1345; em[993] = 96; 
    	em[994] = 1359; em[995] = 120; 
    	em[996] = 1359; em[997] = 128; 
    	em[998] = 1359; em[999] = 136; 
    	em[1000] = 120; em[1001] = 144; 
    	em[1002] = 1364; em[1003] = 152; 
    	em[1004] = 1364; em[1005] = 160; 
    em[1006] = 1; em[1007] = 8; em[1008] = 1; /* 1006: pointer.struct.engine_st */
    	em[1009] = 1011; em[1010] = 0; 
    em[1011] = 0; em[1012] = 216; em[1013] = 24; /* 1011: struct.engine_st */
    	em[1014] = 144; em[1015] = 0; 
    	em[1016] = 144; em[1017] = 8; 
    	em[1018] = 1062; em[1019] = 16; 
    	em[1020] = 1114; em[1021] = 24; 
    	em[1022] = 1165; em[1023] = 32; 
    	em[1024] = 1201; em[1025] = 40; 
    	em[1026] = 1218; em[1027] = 48; 
    	em[1028] = 1245; em[1029] = 56; 
    	em[1030] = 1280; em[1031] = 64; 
    	em[1032] = 1288; em[1033] = 72; 
    	em[1034] = 1291; em[1035] = 80; 
    	em[1036] = 1294; em[1037] = 88; 
    	em[1038] = 1297; em[1039] = 96; 
    	em[1040] = 1300; em[1041] = 104; 
    	em[1042] = 1300; em[1043] = 112; 
    	em[1044] = 1300; em[1045] = 120; 
    	em[1046] = 1303; em[1047] = 128; 
    	em[1048] = 966; em[1049] = 136; 
    	em[1050] = 966; em[1051] = 144; 
    	em[1052] = 1306; em[1053] = 152; 
    	em[1054] = 1309; em[1055] = 160; 
    	em[1056] = 1321; em[1057] = 184; 
    	em[1058] = 1335; em[1059] = 200; 
    	em[1060] = 1335; em[1061] = 208; 
    em[1062] = 1; em[1063] = 8; em[1064] = 1; /* 1062: pointer.struct.rsa_meth_st */
    	em[1065] = 1067; em[1066] = 0; 
    em[1067] = 0; em[1068] = 112; em[1069] = 13; /* 1067: struct.rsa_meth_st */
    	em[1070] = 144; em[1071] = 0; 
    	em[1072] = 908; em[1073] = 8; 
    	em[1074] = 908; em[1075] = 16; 
    	em[1076] = 908; em[1077] = 24; 
    	em[1078] = 908; em[1079] = 32; 
    	em[1080] = 1096; em[1081] = 40; 
    	em[1082] = 1099; em[1083] = 48; 
    	em[1084] = 1102; em[1085] = 56; 
    	em[1086] = 1102; em[1087] = 64; 
    	em[1088] = 120; em[1089] = 80; 
    	em[1090] = 1105; em[1091] = 88; 
    	em[1092] = 1108; em[1093] = 96; 
    	em[1094] = 1111; em[1095] = 104; 
    em[1096] = 8884097; em[1097] = 8; em[1098] = 0; /* 1096: pointer.func */
    em[1099] = 8884097; em[1100] = 8; em[1101] = 0; /* 1099: pointer.func */
    em[1102] = 8884097; em[1103] = 8; em[1104] = 0; /* 1102: pointer.func */
    em[1105] = 8884097; em[1106] = 8; em[1107] = 0; /* 1105: pointer.func */
    em[1108] = 8884097; em[1109] = 8; em[1110] = 0; /* 1108: pointer.func */
    em[1111] = 8884097; em[1112] = 8; em[1113] = 0; /* 1111: pointer.func */
    em[1114] = 1; em[1115] = 8; em[1116] = 1; /* 1114: pointer.struct.dsa_method */
    	em[1117] = 1119; em[1118] = 0; 
    em[1119] = 0; em[1120] = 96; em[1121] = 11; /* 1119: struct.dsa_method */
    	em[1122] = 144; em[1123] = 0; 
    	em[1124] = 1144; em[1125] = 8; 
    	em[1126] = 1147; em[1127] = 16; 
    	em[1128] = 1150; em[1129] = 24; 
    	em[1130] = 1153; em[1131] = 32; 
    	em[1132] = 1156; em[1133] = 40; 
    	em[1134] = 1159; em[1135] = 48; 
    	em[1136] = 1159; em[1137] = 56; 
    	em[1138] = 120; em[1139] = 72; 
    	em[1140] = 1162; em[1141] = 80; 
    	em[1142] = 1159; em[1143] = 88; 
    em[1144] = 8884097; em[1145] = 8; em[1146] = 0; /* 1144: pointer.func */
    em[1147] = 8884097; em[1148] = 8; em[1149] = 0; /* 1147: pointer.func */
    em[1150] = 8884097; em[1151] = 8; em[1152] = 0; /* 1150: pointer.func */
    em[1153] = 8884097; em[1154] = 8; em[1155] = 0; /* 1153: pointer.func */
    em[1156] = 8884097; em[1157] = 8; em[1158] = 0; /* 1156: pointer.func */
    em[1159] = 8884097; em[1160] = 8; em[1161] = 0; /* 1159: pointer.func */
    em[1162] = 8884097; em[1163] = 8; em[1164] = 0; /* 1162: pointer.func */
    em[1165] = 1; em[1166] = 8; em[1167] = 1; /* 1165: pointer.struct.dh_method */
    	em[1168] = 1170; em[1169] = 0; 
    em[1170] = 0; em[1171] = 72; em[1172] = 8; /* 1170: struct.dh_method */
    	em[1173] = 144; em[1174] = 0; 
    	em[1175] = 1189; em[1176] = 8; 
    	em[1177] = 1192; em[1178] = 16; 
    	em[1179] = 1195; em[1180] = 24; 
    	em[1181] = 1189; em[1182] = 32; 
    	em[1183] = 1189; em[1184] = 40; 
    	em[1185] = 120; em[1186] = 56; 
    	em[1187] = 1198; em[1188] = 64; 
    em[1189] = 8884097; em[1190] = 8; em[1191] = 0; /* 1189: pointer.func */
    em[1192] = 8884097; em[1193] = 8; em[1194] = 0; /* 1192: pointer.func */
    em[1195] = 8884097; em[1196] = 8; em[1197] = 0; /* 1195: pointer.func */
    em[1198] = 8884097; em[1199] = 8; em[1200] = 0; /* 1198: pointer.func */
    em[1201] = 1; em[1202] = 8; em[1203] = 1; /* 1201: pointer.struct.ecdh_method */
    	em[1204] = 1206; em[1205] = 0; 
    em[1206] = 0; em[1207] = 32; em[1208] = 3; /* 1206: struct.ecdh_method */
    	em[1209] = 144; em[1210] = 0; 
    	em[1211] = 1215; em[1212] = 8; 
    	em[1213] = 120; em[1214] = 24; 
    em[1215] = 8884097; em[1216] = 8; em[1217] = 0; /* 1215: pointer.func */
    em[1218] = 1; em[1219] = 8; em[1220] = 1; /* 1218: pointer.struct.ecdsa_method */
    	em[1221] = 1223; em[1222] = 0; 
    em[1223] = 0; em[1224] = 48; em[1225] = 5; /* 1223: struct.ecdsa_method */
    	em[1226] = 144; em[1227] = 0; 
    	em[1228] = 1236; em[1229] = 8; 
    	em[1230] = 1239; em[1231] = 16; 
    	em[1232] = 1242; em[1233] = 24; 
    	em[1234] = 120; em[1235] = 40; 
    em[1236] = 8884097; em[1237] = 8; em[1238] = 0; /* 1236: pointer.func */
    em[1239] = 8884097; em[1240] = 8; em[1241] = 0; /* 1239: pointer.func */
    em[1242] = 8884097; em[1243] = 8; em[1244] = 0; /* 1242: pointer.func */
    em[1245] = 1; em[1246] = 8; em[1247] = 1; /* 1245: pointer.struct.rand_meth_st */
    	em[1248] = 1250; em[1249] = 0; 
    em[1250] = 0; em[1251] = 48; em[1252] = 6; /* 1250: struct.rand_meth_st */
    	em[1253] = 1265; em[1254] = 0; 
    	em[1255] = 1268; em[1256] = 8; 
    	em[1257] = 1271; em[1258] = 16; 
    	em[1259] = 1274; em[1260] = 24; 
    	em[1261] = 1268; em[1262] = 32; 
    	em[1263] = 1277; em[1264] = 40; 
    em[1265] = 8884097; em[1266] = 8; em[1267] = 0; /* 1265: pointer.func */
    em[1268] = 8884097; em[1269] = 8; em[1270] = 0; /* 1268: pointer.func */
    em[1271] = 8884097; em[1272] = 8; em[1273] = 0; /* 1271: pointer.func */
    em[1274] = 8884097; em[1275] = 8; em[1276] = 0; /* 1274: pointer.func */
    em[1277] = 8884097; em[1278] = 8; em[1279] = 0; /* 1277: pointer.func */
    em[1280] = 1; em[1281] = 8; em[1282] = 1; /* 1280: pointer.struct.store_method_st */
    	em[1283] = 1285; em[1284] = 0; 
    em[1285] = 0; em[1286] = 0; em[1287] = 0; /* 1285: struct.store_method_st */
    em[1288] = 8884097; em[1289] = 8; em[1290] = 0; /* 1288: pointer.func */
    em[1291] = 8884097; em[1292] = 8; em[1293] = 0; /* 1291: pointer.func */
    em[1294] = 8884097; em[1295] = 8; em[1296] = 0; /* 1294: pointer.func */
    em[1297] = 8884097; em[1298] = 8; em[1299] = 0; /* 1297: pointer.func */
    em[1300] = 8884097; em[1301] = 8; em[1302] = 0; /* 1300: pointer.func */
    em[1303] = 8884097; em[1304] = 8; em[1305] = 0; /* 1303: pointer.func */
    em[1306] = 8884097; em[1307] = 8; em[1308] = 0; /* 1306: pointer.func */
    em[1309] = 1; em[1310] = 8; em[1311] = 1; /* 1309: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[1312] = 1314; em[1313] = 0; 
    em[1314] = 0; em[1315] = 32; em[1316] = 2; /* 1314: struct.ENGINE_CMD_DEFN_st */
    	em[1317] = 144; em[1318] = 8; 
    	em[1319] = 144; em[1320] = 16; 
    em[1321] = 0; em[1322] = 32; em[1323] = 2; /* 1321: struct.crypto_ex_data_st_fake */
    	em[1324] = 1328; em[1325] = 8; 
    	em[1326] = 363; em[1327] = 24; 
    em[1328] = 8884099; em[1329] = 8; em[1330] = 2; /* 1328: pointer_to_array_of_pointers_to_stack */
    	em[1331] = 848; em[1332] = 0; 
    	em[1333] = 5; em[1334] = 20; 
    em[1335] = 1; em[1336] = 8; em[1337] = 1; /* 1335: pointer.struct.engine_st */
    	em[1338] = 1011; em[1339] = 0; 
    em[1340] = 1; em[1341] = 8; em[1342] = 1; /* 1340: pointer.struct.bignum_st */
    	em[1343] = 375; em[1344] = 0; 
    em[1345] = 0; em[1346] = 32; em[1347] = 2; /* 1345: struct.crypto_ex_data_st_fake */
    	em[1348] = 1352; em[1349] = 8; 
    	em[1350] = 363; em[1351] = 24; 
    em[1352] = 8884099; em[1353] = 8; em[1354] = 2; /* 1352: pointer_to_array_of_pointers_to_stack */
    	em[1355] = 848; em[1356] = 0; 
    	em[1357] = 5; em[1358] = 20; 
    em[1359] = 1; em[1360] = 8; em[1361] = 1; /* 1359: pointer.struct.bn_mont_ctx_st */
    	em[1362] = 366; em[1363] = 0; 
    em[1364] = 1; em[1365] = 8; em[1366] = 1; /* 1364: pointer.struct.bn_blinding_st */
    	em[1367] = 1369; em[1368] = 0; 
    em[1369] = 0; em[1370] = 88; em[1371] = 7; /* 1369: struct.bn_blinding_st */
    	em[1372] = 1386; em[1373] = 0; 
    	em[1374] = 1386; em[1375] = 8; 
    	em[1376] = 1386; em[1377] = 16; 
    	em[1378] = 1386; em[1379] = 24; 
    	em[1380] = 1403; em[1381] = 40; 
    	em[1382] = 1408; em[1383] = 72; 
    	em[1384] = 1422; em[1385] = 80; 
    em[1386] = 1; em[1387] = 8; em[1388] = 1; /* 1386: pointer.struct.bignum_st */
    	em[1389] = 1391; em[1390] = 0; 
    em[1391] = 0; em[1392] = 24; em[1393] = 1; /* 1391: struct.bignum_st */
    	em[1394] = 1396; em[1395] = 0; 
    em[1396] = 8884099; em[1397] = 8; em[1398] = 2; /* 1396: pointer_to_array_of_pointers_to_stack */
    	em[1399] = 387; em[1400] = 0; 
    	em[1401] = 5; em[1402] = 12; 
    em[1403] = 0; em[1404] = 16; em[1405] = 1; /* 1403: struct.crypto_threadid_st */
    	em[1406] = 848; em[1407] = 0; 
    em[1408] = 1; em[1409] = 8; em[1410] = 1; /* 1408: pointer.struct.bn_mont_ctx_st */
    	em[1411] = 1413; em[1412] = 0; 
    em[1413] = 0; em[1414] = 96; em[1415] = 3; /* 1413: struct.bn_mont_ctx_st */
    	em[1416] = 1391; em[1417] = 8; 
    	em[1418] = 1391; em[1419] = 32; 
    	em[1420] = 1391; em[1421] = 56; 
    em[1422] = 8884097; em[1423] = 8; em[1424] = 0; /* 1422: pointer.func */
    em[1425] = 8884101; em[1426] = 8; em[1427] = 6; /* 1425: union.union_of_evp_pkey_st */
    	em[1428] = 848; em[1429] = 0; 
    	em[1430] = 1440; em[1431] = 6; 
    	em[1432] = 1445; em[1433] = 116; 
    	em[1434] = 1576; em[1435] = 28; 
    	em[1436] = 396; em[1437] = 408; 
    	em[1438] = 5; em[1439] = 0; 
    em[1440] = 1; em[1441] = 8; em[1442] = 1; /* 1440: pointer.struct.rsa_st */
    	em[1443] = 969; em[1444] = 0; 
    em[1445] = 1; em[1446] = 8; em[1447] = 1; /* 1445: pointer.struct.dsa_st */
    	em[1448] = 1450; em[1449] = 0; 
    em[1450] = 0; em[1451] = 136; em[1452] = 11; /* 1450: struct.dsa_st */
    	em[1453] = 1475; em[1454] = 24; 
    	em[1455] = 1475; em[1456] = 32; 
    	em[1457] = 1475; em[1458] = 40; 
    	em[1459] = 1475; em[1460] = 48; 
    	em[1461] = 1475; em[1462] = 56; 
    	em[1463] = 1475; em[1464] = 64; 
    	em[1465] = 1475; em[1466] = 72; 
    	em[1467] = 1492; em[1468] = 88; 
    	em[1469] = 1506; em[1470] = 104; 
    	em[1471] = 1520; em[1472] = 120; 
    	em[1473] = 1571; em[1474] = 128; 
    em[1475] = 1; em[1476] = 8; em[1477] = 1; /* 1475: pointer.struct.bignum_st */
    	em[1478] = 1480; em[1479] = 0; 
    em[1480] = 0; em[1481] = 24; em[1482] = 1; /* 1480: struct.bignum_st */
    	em[1483] = 1485; em[1484] = 0; 
    em[1485] = 8884099; em[1486] = 8; em[1487] = 2; /* 1485: pointer_to_array_of_pointers_to_stack */
    	em[1488] = 387; em[1489] = 0; 
    	em[1490] = 5; em[1491] = 12; 
    em[1492] = 1; em[1493] = 8; em[1494] = 1; /* 1492: pointer.struct.bn_mont_ctx_st */
    	em[1495] = 1497; em[1496] = 0; 
    em[1497] = 0; em[1498] = 96; em[1499] = 3; /* 1497: struct.bn_mont_ctx_st */
    	em[1500] = 1480; em[1501] = 8; 
    	em[1502] = 1480; em[1503] = 32; 
    	em[1504] = 1480; em[1505] = 56; 
    em[1506] = 0; em[1507] = 32; em[1508] = 2; /* 1506: struct.crypto_ex_data_st_fake */
    	em[1509] = 1513; em[1510] = 8; 
    	em[1511] = 363; em[1512] = 24; 
    em[1513] = 8884099; em[1514] = 8; em[1515] = 2; /* 1513: pointer_to_array_of_pointers_to_stack */
    	em[1516] = 848; em[1517] = 0; 
    	em[1518] = 5; em[1519] = 20; 
    em[1520] = 1; em[1521] = 8; em[1522] = 1; /* 1520: pointer.struct.dsa_method */
    	em[1523] = 1525; em[1524] = 0; 
    em[1525] = 0; em[1526] = 96; em[1527] = 11; /* 1525: struct.dsa_method */
    	em[1528] = 144; em[1529] = 0; 
    	em[1530] = 1550; em[1531] = 8; 
    	em[1532] = 1553; em[1533] = 16; 
    	em[1534] = 1556; em[1535] = 24; 
    	em[1536] = 1559; em[1537] = 32; 
    	em[1538] = 1562; em[1539] = 40; 
    	em[1540] = 1565; em[1541] = 48; 
    	em[1542] = 1565; em[1543] = 56; 
    	em[1544] = 120; em[1545] = 72; 
    	em[1546] = 1568; em[1547] = 80; 
    	em[1548] = 1565; em[1549] = 88; 
    em[1550] = 8884097; em[1551] = 8; em[1552] = 0; /* 1550: pointer.func */
    em[1553] = 8884097; em[1554] = 8; em[1555] = 0; /* 1553: pointer.func */
    em[1556] = 8884097; em[1557] = 8; em[1558] = 0; /* 1556: pointer.func */
    em[1559] = 8884097; em[1560] = 8; em[1561] = 0; /* 1559: pointer.func */
    em[1562] = 8884097; em[1563] = 8; em[1564] = 0; /* 1562: pointer.func */
    em[1565] = 8884097; em[1566] = 8; em[1567] = 0; /* 1565: pointer.func */
    em[1568] = 8884097; em[1569] = 8; em[1570] = 0; /* 1568: pointer.func */
    em[1571] = 1; em[1572] = 8; em[1573] = 1; /* 1571: pointer.struct.engine_st */
    	em[1574] = 1011; em[1575] = 0; 
    em[1576] = 1; em[1577] = 8; em[1578] = 1; /* 1576: pointer.struct.dh_st */
    	em[1579] = 1581; em[1580] = 0; 
    em[1581] = 0; em[1582] = 144; em[1583] = 12; /* 1581: struct.dh_st */
    	em[1584] = 1608; em[1585] = 8; 
    	em[1586] = 1608; em[1587] = 16; 
    	em[1588] = 1608; em[1589] = 32; 
    	em[1590] = 1608; em[1591] = 40; 
    	em[1592] = 1625; em[1593] = 56; 
    	em[1594] = 1608; em[1595] = 64; 
    	em[1596] = 1608; em[1597] = 72; 
    	em[1598] = 29; em[1599] = 80; 
    	em[1600] = 1608; em[1601] = 96; 
    	em[1602] = 1639; em[1603] = 112; 
    	em[1604] = 1653; em[1605] = 128; 
    	em[1606] = 1689; em[1607] = 136; 
    em[1608] = 1; em[1609] = 8; em[1610] = 1; /* 1608: pointer.struct.bignum_st */
    	em[1611] = 1613; em[1612] = 0; 
    em[1613] = 0; em[1614] = 24; em[1615] = 1; /* 1613: struct.bignum_st */
    	em[1616] = 1618; em[1617] = 0; 
    em[1618] = 8884099; em[1619] = 8; em[1620] = 2; /* 1618: pointer_to_array_of_pointers_to_stack */
    	em[1621] = 387; em[1622] = 0; 
    	em[1623] = 5; em[1624] = 12; 
    em[1625] = 1; em[1626] = 8; em[1627] = 1; /* 1625: pointer.struct.bn_mont_ctx_st */
    	em[1628] = 1630; em[1629] = 0; 
    em[1630] = 0; em[1631] = 96; em[1632] = 3; /* 1630: struct.bn_mont_ctx_st */
    	em[1633] = 1613; em[1634] = 8; 
    	em[1635] = 1613; em[1636] = 32; 
    	em[1637] = 1613; em[1638] = 56; 
    em[1639] = 0; em[1640] = 32; em[1641] = 2; /* 1639: struct.crypto_ex_data_st_fake */
    	em[1642] = 1646; em[1643] = 8; 
    	em[1644] = 363; em[1645] = 24; 
    em[1646] = 8884099; em[1647] = 8; em[1648] = 2; /* 1646: pointer_to_array_of_pointers_to_stack */
    	em[1649] = 848; em[1650] = 0; 
    	em[1651] = 5; em[1652] = 20; 
    em[1653] = 1; em[1654] = 8; em[1655] = 1; /* 1653: pointer.struct.dh_method */
    	em[1656] = 1658; em[1657] = 0; 
    em[1658] = 0; em[1659] = 72; em[1660] = 8; /* 1658: struct.dh_method */
    	em[1661] = 144; em[1662] = 0; 
    	em[1663] = 1677; em[1664] = 8; 
    	em[1665] = 1680; em[1666] = 16; 
    	em[1667] = 1683; em[1668] = 24; 
    	em[1669] = 1677; em[1670] = 32; 
    	em[1671] = 1677; em[1672] = 40; 
    	em[1673] = 120; em[1674] = 56; 
    	em[1675] = 1686; em[1676] = 64; 
    em[1677] = 8884097; em[1678] = 8; em[1679] = 0; /* 1677: pointer.func */
    em[1680] = 8884097; em[1681] = 8; em[1682] = 0; /* 1680: pointer.func */
    em[1683] = 8884097; em[1684] = 8; em[1685] = 0; /* 1683: pointer.func */
    em[1686] = 8884097; em[1687] = 8; em[1688] = 0; /* 1686: pointer.func */
    em[1689] = 1; em[1690] = 8; em[1691] = 1; /* 1689: pointer.struct.engine_st */
    	em[1692] = 1011; em[1693] = 0; 
    em[1694] = 8884097; em[1695] = 8; em[1696] = 0; /* 1694: pointer.func */
    em[1697] = 8884097; em[1698] = 8; em[1699] = 0; /* 1697: pointer.func */
    em[1700] = 8884097; em[1701] = 8; em[1702] = 0; /* 1700: pointer.func */
    em[1703] = 8884097; em[1704] = 8; em[1705] = 0; /* 1703: pointer.func */
    em[1706] = 0; em[1707] = 1; em[1708] = 0; /* 1706: char */
    em[1709] = 8884097; em[1710] = 8; em[1711] = 0; /* 1709: pointer.func */
    em[1712] = 8884097; em[1713] = 8; em[1714] = 0; /* 1712: pointer.func */
    em[1715] = 8884097; em[1716] = 8; em[1717] = 0; /* 1715: pointer.func */
    em[1718] = 8884097; em[1719] = 8; em[1720] = 0; /* 1718: pointer.func */
    em[1721] = 0; em[1722] = 208; em[1723] = 24; /* 1721: struct.evp_pkey_asn1_method_st */
    	em[1724] = 120; em[1725] = 16; 
    	em[1726] = 120; em[1727] = 24; 
    	em[1728] = 1700; em[1729] = 32; 
    	em[1730] = 1697; em[1731] = 40; 
    	em[1732] = 963; em[1733] = 48; 
    	em[1734] = 1712; em[1735] = 56; 
    	em[1736] = 1772; em[1737] = 64; 
    	em[1738] = 1775; em[1739] = 72; 
    	em[1740] = 1712; em[1741] = 80; 
    	em[1742] = 1778; em[1743] = 88; 
    	em[1744] = 1778; em[1745] = 96; 
    	em[1746] = 1781; em[1747] = 104; 
    	em[1748] = 1784; em[1749] = 112; 
    	em[1750] = 1778; em[1751] = 120; 
    	em[1752] = 1694; em[1753] = 128; 
    	em[1754] = 963; em[1755] = 136; 
    	em[1756] = 1712; em[1757] = 144; 
    	em[1758] = 1715; em[1759] = 152; 
    	em[1760] = 1787; em[1761] = 160; 
    	em[1762] = 1790; em[1763] = 168; 
    	em[1764] = 1781; em[1765] = 176; 
    	em[1766] = 1784; em[1767] = 184; 
    	em[1768] = 1793; em[1769] = 192; 
    	em[1770] = 1796; em[1771] = 200; 
    em[1772] = 8884097; em[1773] = 8; em[1774] = 0; /* 1772: pointer.func */
    em[1775] = 8884097; em[1776] = 8; em[1777] = 0; /* 1775: pointer.func */
    em[1778] = 8884097; em[1779] = 8; em[1780] = 0; /* 1778: pointer.func */
    em[1781] = 8884097; em[1782] = 8; em[1783] = 0; /* 1781: pointer.func */
    em[1784] = 8884097; em[1785] = 8; em[1786] = 0; /* 1784: pointer.func */
    em[1787] = 8884097; em[1788] = 8; em[1789] = 0; /* 1787: pointer.func */
    em[1790] = 8884097; em[1791] = 8; em[1792] = 0; /* 1790: pointer.func */
    em[1793] = 8884097; em[1794] = 8; em[1795] = 0; /* 1793: pointer.func */
    em[1796] = 8884097; em[1797] = 8; em[1798] = 0; /* 1796: pointer.func */
    em[1799] = 8884097; em[1800] = 8; em[1801] = 0; /* 1799: pointer.func */
    em[1802] = 8884097; em[1803] = 8; em[1804] = 0; /* 1802: pointer.func */
    em[1805] = 8884097; em[1806] = 8; em[1807] = 0; /* 1805: pointer.func */
    em[1808] = 1; em[1809] = 8; em[1810] = 1; /* 1808: pointer.struct.evp_pkey_method_st */
    	em[1811] = 1813; em[1812] = 0; 
    em[1813] = 0; em[1814] = 208; em[1815] = 25; /* 1813: struct.evp_pkey_method_st */
    	em[1816] = 1799; em[1817] = 8; 
    	em[1818] = 1866; em[1819] = 16; 
    	em[1820] = 1869; em[1821] = 24; 
    	em[1822] = 1799; em[1823] = 32; 
    	em[1824] = 1802; em[1825] = 40; 
    	em[1826] = 1799; em[1827] = 48; 
    	em[1828] = 1802; em[1829] = 56; 
    	em[1830] = 1799; em[1831] = 64; 
    	em[1832] = 1872; em[1833] = 72; 
    	em[1834] = 1799; em[1835] = 80; 
    	em[1836] = 1875; em[1837] = 88; 
    	em[1838] = 1799; em[1839] = 96; 
    	em[1840] = 1872; em[1841] = 104; 
    	em[1842] = 1878; em[1843] = 112; 
    	em[1844] = 1718; em[1845] = 120; 
    	em[1846] = 1878; em[1847] = 128; 
    	em[1848] = 1881; em[1849] = 136; 
    	em[1850] = 1799; em[1851] = 144; 
    	em[1852] = 1872; em[1853] = 152; 
    	em[1854] = 1799; em[1855] = 160; 
    	em[1856] = 1872; em[1857] = 168; 
    	em[1858] = 1799; em[1859] = 176; 
    	em[1860] = 1709; em[1861] = 184; 
    	em[1862] = 1884; em[1863] = 192; 
    	em[1864] = 1703; em[1865] = 200; 
    em[1866] = 8884097; em[1867] = 8; em[1868] = 0; /* 1866: pointer.func */
    em[1869] = 8884097; em[1870] = 8; em[1871] = 0; /* 1869: pointer.func */
    em[1872] = 8884097; em[1873] = 8; em[1874] = 0; /* 1872: pointer.func */
    em[1875] = 8884097; em[1876] = 8; em[1877] = 0; /* 1875: pointer.func */
    em[1878] = 8884097; em[1879] = 8; em[1880] = 0; /* 1878: pointer.func */
    em[1881] = 8884097; em[1882] = 8; em[1883] = 0; /* 1881: pointer.func */
    em[1884] = 8884097; em[1885] = 8; em[1886] = 0; /* 1884: pointer.func */
    em[1887] = 0; em[1888] = 80; em[1889] = 8; /* 1887: struct.evp_pkey_ctx_st */
    	em[1890] = 1808; em[1891] = 0; 
    	em[1892] = 1689; em[1893] = 8; 
    	em[1894] = 1906; em[1895] = 16; 
    	em[1896] = 1906; em[1897] = 24; 
    	em[1898] = 848; em[1899] = 40; 
    	em[1900] = 848; em[1901] = 48; 
    	em[1902] = 8; em[1903] = 56; 
    	em[1904] = 0; em[1905] = 64; 
    em[1906] = 1; em[1907] = 8; em[1908] = 1; /* 1906: pointer.struct.evp_pkey_st */
    	em[1909] = 1911; em[1910] = 0; 
    em[1911] = 0; em[1912] = 56; em[1913] = 4; /* 1911: struct.evp_pkey_st */
    	em[1914] = 1922; em[1915] = 16; 
    	em[1916] = 1689; em[1917] = 24; 
    	em[1918] = 1425; em[1919] = 32; 
    	em[1920] = 1927; em[1921] = 48; 
    em[1922] = 1; em[1923] = 8; em[1924] = 1; /* 1922: pointer.struct.evp_pkey_asn1_method_st */
    	em[1925] = 1721; em[1926] = 0; 
    em[1927] = 1; em[1928] = 8; em[1929] = 1; /* 1927: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1930] = 1932; em[1931] = 0; 
    em[1932] = 0; em[1933] = 32; em[1934] = 2; /* 1932: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1935] = 1939; em[1936] = 8; 
    	em[1937] = 363; em[1938] = 24; 
    em[1939] = 8884099; em[1940] = 8; em[1941] = 2; /* 1939: pointer_to_array_of_pointers_to_stack */
    	em[1942] = 1946; em[1943] = 0; 
    	em[1944] = 5; em[1945] = 20; 
    em[1946] = 0; em[1947] = 8; em[1948] = 1; /* 1946: pointer.X509_ATTRIBUTE */
    	em[1949] = 1951; em[1950] = 0; 
    em[1951] = 0; em[1952] = 0; em[1953] = 1; /* 1951: X509_ATTRIBUTE */
    	em[1954] = 1956; em[1955] = 0; 
    em[1956] = 0; em[1957] = 24; em[1958] = 2; /* 1956: struct.x509_attributes_st */
    	em[1959] = 130; em[1960] = 0; 
    	em[1961] = 1963; em[1962] = 16; 
    em[1963] = 0; em[1964] = 8; em[1965] = 3; /* 1963: union.unknown */
    	em[1966] = 120; em[1967] = 0; 
    	em[1968] = 339; em[1969] = 0; 
    	em[1970] = 1972; em[1971] = 0; 
    em[1972] = 1; em[1973] = 8; em[1974] = 1; /* 1972: pointer.struct.asn1_type_st */
    	em[1975] = 179; em[1976] = 0; 
    em[1977] = 1; em[1978] = 8; em[1979] = 1; /* 1977: pointer.struct.evp_pkey_ctx_st */
    	em[1980] = 1887; em[1981] = 0; 
    em[1982] = 8884097; em[1983] = 8; em[1984] = 0; /* 1982: pointer.func */
    em[1985] = 8884097; em[1986] = 8; em[1987] = 0; /* 1985: pointer.func */
    em[1988] = 8884097; em[1989] = 8; em[1990] = 0; /* 1988: pointer.func */
    em[1991] = 0; em[1992] = 120; em[1993] = 8; /* 1991: struct.env_md_st */
    	em[1994] = 2010; em[1995] = 24; 
    	em[1996] = 2013; em[1997] = 32; 
    	em[1998] = 1982; em[1999] = 40; 
    	em[2000] = 914; em[2001] = 48; 
    	em[2002] = 2010; em[2003] = 56; 
    	em[2004] = 1988; em[2005] = 64; 
    	em[2006] = 1805; em[2007] = 72; 
    	em[2008] = 1985; em[2009] = 112; 
    em[2010] = 8884097; em[2011] = 8; em[2012] = 0; /* 2010: pointer.func */
    em[2013] = 8884097; em[2014] = 8; em[2015] = 0; /* 2013: pointer.func */
    em[2016] = 1; em[2017] = 8; em[2018] = 1; /* 2016: pointer.struct.env_md_ctx_st */
    	em[2019] = 2021; em[2020] = 0; 
    em[2021] = 0; em[2022] = 48; em[2023] = 5; /* 2021: struct.env_md_ctx_st */
    	em[2024] = 2034; em[2025] = 0; 
    	em[2026] = 1689; em[2027] = 8; 
    	em[2028] = 848; em[2029] = 24; 
    	em[2030] = 1977; em[2031] = 32; 
    	em[2032] = 2013; em[2033] = 40; 
    em[2034] = 1; em[2035] = 8; em[2036] = 1; /* 2034: pointer.struct.env_md_st */
    	em[2037] = 1991; em[2038] = 0; 
    em[2039] = 0; em[2040] = 0; em[2041] = 0; /* 2039: size_t */
    args_addr->arg_entity_index[0] = 2016;
    args_addr->arg_entity_index[1] = 848;
    args_addr->arg_entity_index[2] = 2039;
    args_addr->ret_entity_index = 5;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * new_arg_a = *((EVP_MD_CTX * *)new_args->args[0]);

     const void * new_arg_b = *(( const void * *)new_args->args[1]);

    size_t new_arg_c = *((size_t *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_DigestUpdate)(EVP_MD_CTX *, const void *,size_t);
    orig_EVP_DigestUpdate = dlsym(RTLD_NEXT, "EVP_DigestUpdate");
    *new_ret_ptr = (*orig_EVP_DigestUpdate)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    free(args_addr);

    return ret;
}

