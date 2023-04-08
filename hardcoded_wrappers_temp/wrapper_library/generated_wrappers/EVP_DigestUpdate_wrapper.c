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
    em[339] = 1; em[340] = 8; em[341] = 1; /* 339: pointer.struct.stack_st_ASN1_TYPE */
    	em[342] = 344; em[343] = 0; 
    em[344] = 0; em[345] = 32; em[346] = 2; /* 344: struct.stack_st_fake_ASN1_TYPE */
    	em[347] = 351; em[348] = 8; 
    	em[349] = 363; em[350] = 24; 
    em[351] = 8884099; em[352] = 8; em[353] = 2; /* 351: pointer_to_array_of_pointers_to_stack */
    	em[354] = 358; em[355] = 0; 
    	em[356] = 5; em[357] = 20; 
    em[358] = 0; em[359] = 8; em[360] = 1; /* 358: pointer.ASN1_TYPE */
    	em[361] = 246; em[362] = 0; 
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
    em[905] = 1; em[906] = 8; em[907] = 1; /* 905: pointer.struct.bignum_st */
    	em[908] = 375; em[909] = 0; 
    em[910] = 8884097; em[911] = 8; em[912] = 0; /* 910: pointer.func */
    em[913] = 0; em[914] = 1; em[915] = 0; /* 913: char */
    em[916] = 8884097; em[917] = 8; em[918] = 0; /* 916: pointer.func */
    em[919] = 8884097; em[920] = 8; em[921] = 0; /* 919: pointer.func */
    em[922] = 8884097; em[923] = 8; em[924] = 0; /* 922: pointer.func */
    em[925] = 8884097; em[926] = 8; em[927] = 0; /* 925: pointer.func */
    em[928] = 8884097; em[929] = 8; em[930] = 0; /* 928: pointer.func */
    em[931] = 8884097; em[932] = 8; em[933] = 0; /* 931: pointer.func */
    em[934] = 0; em[935] = 112; em[936] = 13; /* 934: struct.rsa_meth_st */
    	em[937] = 149; em[938] = 0; 
    	em[939] = 928; em[940] = 8; 
    	em[941] = 928; em[942] = 16; 
    	em[943] = 928; em[944] = 24; 
    	em[945] = 928; em[946] = 32; 
    	em[947] = 963; em[948] = 40; 
    	em[949] = 966; em[950] = 48; 
    	em[951] = 916; em[952] = 56; 
    	em[953] = 916; em[954] = 64; 
    	em[955] = 125; em[956] = 80; 
    	em[957] = 910; em[958] = 88; 
    	em[959] = 969; em[960] = 96; 
    	em[961] = 393; em[962] = 104; 
    em[963] = 8884097; em[964] = 8; em[965] = 0; /* 963: pointer.func */
    em[966] = 8884097; em[967] = 8; em[968] = 0; /* 966: pointer.func */
    em[969] = 8884097; em[970] = 8; em[971] = 0; /* 969: pointer.func */
    em[972] = 1; em[973] = 8; em[974] = 1; /* 972: pointer.struct.rsa_meth_st */
    	em[975] = 934; em[976] = 0; 
    em[977] = 8884097; em[978] = 8; em[979] = 0; /* 977: pointer.func */
    em[980] = 8884097; em[981] = 8; em[982] = 0; /* 980: pointer.func */
    em[983] = 0; em[984] = 168; em[985] = 17; /* 983: struct.rsa_st */
    	em[986] = 972; em[987] = 16; 
    	em[988] = 1020; em[989] = 24; 
    	em[990] = 905; em[991] = 32; 
    	em[992] = 905; em[993] = 40; 
    	em[994] = 905; em[995] = 48; 
    	em[996] = 905; em[997] = 56; 
    	em[998] = 905; em[999] = 64; 
    	em[1000] = 905; em[1001] = 72; 
    	em[1002] = 905; em[1003] = 80; 
    	em[1004] = 905; em[1005] = 88; 
    	em[1006] = 1348; em[1007] = 96; 
    	em[1008] = 1362; em[1009] = 120; 
    	em[1010] = 1362; em[1011] = 128; 
    	em[1012] = 1362; em[1013] = 136; 
    	em[1014] = 125; em[1015] = 144; 
    	em[1016] = 1367; em[1017] = 152; 
    	em[1018] = 1367; em[1019] = 160; 
    em[1020] = 1; em[1021] = 8; em[1022] = 1; /* 1020: pointer.struct.engine_st */
    	em[1023] = 1025; em[1024] = 0; 
    em[1025] = 0; em[1026] = 216; em[1027] = 24; /* 1025: struct.engine_st */
    	em[1028] = 149; em[1029] = 0; 
    	em[1030] = 149; em[1031] = 8; 
    	em[1032] = 1076; em[1033] = 16; 
    	em[1034] = 1128; em[1035] = 24; 
    	em[1036] = 1176; em[1037] = 32; 
    	em[1038] = 1209; em[1039] = 40; 
    	em[1040] = 1226; em[1041] = 48; 
    	em[1042] = 1253; em[1043] = 56; 
    	em[1044] = 1288; em[1045] = 64; 
    	em[1046] = 1296; em[1047] = 72; 
    	em[1048] = 1299; em[1049] = 80; 
    	em[1050] = 1302; em[1051] = 88; 
    	em[1052] = 1305; em[1053] = 96; 
    	em[1054] = 1308; em[1055] = 104; 
    	em[1056] = 1308; em[1057] = 112; 
    	em[1058] = 1308; em[1059] = 120; 
    	em[1060] = 1311; em[1061] = 128; 
    	em[1062] = 980; em[1063] = 136; 
    	em[1064] = 980; em[1065] = 144; 
    	em[1066] = 1314; em[1067] = 152; 
    	em[1068] = 1317; em[1069] = 160; 
    	em[1070] = 1329; em[1071] = 184; 
    	em[1072] = 1343; em[1073] = 200; 
    	em[1074] = 1343; em[1075] = 208; 
    em[1076] = 1; em[1077] = 8; em[1078] = 1; /* 1076: pointer.struct.rsa_meth_st */
    	em[1079] = 1081; em[1080] = 0; 
    em[1081] = 0; em[1082] = 112; em[1083] = 13; /* 1081: struct.rsa_meth_st */
    	em[1084] = 149; em[1085] = 0; 
    	em[1086] = 919; em[1087] = 8; 
    	em[1088] = 919; em[1089] = 16; 
    	em[1090] = 919; em[1091] = 24; 
    	em[1092] = 919; em[1093] = 32; 
    	em[1094] = 1110; em[1095] = 40; 
    	em[1096] = 1113; em[1097] = 48; 
    	em[1098] = 1116; em[1099] = 56; 
    	em[1100] = 1116; em[1101] = 64; 
    	em[1102] = 125; em[1103] = 80; 
    	em[1104] = 1119; em[1105] = 88; 
    	em[1106] = 1122; em[1107] = 96; 
    	em[1108] = 1125; em[1109] = 104; 
    em[1110] = 8884097; em[1111] = 8; em[1112] = 0; /* 1110: pointer.func */
    em[1113] = 8884097; em[1114] = 8; em[1115] = 0; /* 1113: pointer.func */
    em[1116] = 8884097; em[1117] = 8; em[1118] = 0; /* 1116: pointer.func */
    em[1119] = 8884097; em[1120] = 8; em[1121] = 0; /* 1119: pointer.func */
    em[1122] = 8884097; em[1123] = 8; em[1124] = 0; /* 1122: pointer.func */
    em[1125] = 8884097; em[1126] = 8; em[1127] = 0; /* 1125: pointer.func */
    em[1128] = 1; em[1129] = 8; em[1130] = 1; /* 1128: pointer.struct.dsa_method */
    	em[1131] = 1133; em[1132] = 0; 
    em[1133] = 0; em[1134] = 96; em[1135] = 11; /* 1133: struct.dsa_method */
    	em[1136] = 149; em[1137] = 0; 
    	em[1138] = 925; em[1139] = 8; 
    	em[1140] = 1158; em[1141] = 16; 
    	em[1142] = 1161; em[1143] = 24; 
    	em[1144] = 1164; em[1145] = 32; 
    	em[1146] = 1167; em[1147] = 40; 
    	em[1148] = 1170; em[1149] = 48; 
    	em[1150] = 1170; em[1151] = 56; 
    	em[1152] = 125; em[1153] = 72; 
    	em[1154] = 1173; em[1155] = 80; 
    	em[1156] = 1170; em[1157] = 88; 
    em[1158] = 8884097; em[1159] = 8; em[1160] = 0; /* 1158: pointer.func */
    em[1161] = 8884097; em[1162] = 8; em[1163] = 0; /* 1161: pointer.func */
    em[1164] = 8884097; em[1165] = 8; em[1166] = 0; /* 1164: pointer.func */
    em[1167] = 8884097; em[1168] = 8; em[1169] = 0; /* 1167: pointer.func */
    em[1170] = 8884097; em[1171] = 8; em[1172] = 0; /* 1170: pointer.func */
    em[1173] = 8884097; em[1174] = 8; em[1175] = 0; /* 1173: pointer.func */
    em[1176] = 1; em[1177] = 8; em[1178] = 1; /* 1176: pointer.struct.dh_method */
    	em[1179] = 1181; em[1180] = 0; 
    em[1181] = 0; em[1182] = 72; em[1183] = 8; /* 1181: struct.dh_method */
    	em[1184] = 149; em[1185] = 0; 
    	em[1186] = 1200; em[1187] = 8; 
    	em[1188] = 922; em[1189] = 16; 
    	em[1190] = 1203; em[1191] = 24; 
    	em[1192] = 1200; em[1193] = 32; 
    	em[1194] = 1200; em[1195] = 40; 
    	em[1196] = 125; em[1197] = 56; 
    	em[1198] = 1206; em[1199] = 64; 
    em[1200] = 8884097; em[1201] = 8; em[1202] = 0; /* 1200: pointer.func */
    em[1203] = 8884097; em[1204] = 8; em[1205] = 0; /* 1203: pointer.func */
    em[1206] = 8884097; em[1207] = 8; em[1208] = 0; /* 1206: pointer.func */
    em[1209] = 1; em[1210] = 8; em[1211] = 1; /* 1209: pointer.struct.ecdh_method */
    	em[1212] = 1214; em[1213] = 0; 
    em[1214] = 0; em[1215] = 32; em[1216] = 3; /* 1214: struct.ecdh_method */
    	em[1217] = 149; em[1218] = 0; 
    	em[1219] = 1223; em[1220] = 8; 
    	em[1221] = 125; em[1222] = 24; 
    em[1223] = 8884097; em[1224] = 8; em[1225] = 0; /* 1223: pointer.func */
    em[1226] = 1; em[1227] = 8; em[1228] = 1; /* 1226: pointer.struct.ecdsa_method */
    	em[1229] = 1231; em[1230] = 0; 
    em[1231] = 0; em[1232] = 48; em[1233] = 5; /* 1231: struct.ecdsa_method */
    	em[1234] = 149; em[1235] = 0; 
    	em[1236] = 1244; em[1237] = 8; 
    	em[1238] = 1247; em[1239] = 16; 
    	em[1240] = 1250; em[1241] = 24; 
    	em[1242] = 125; em[1243] = 40; 
    em[1244] = 8884097; em[1245] = 8; em[1246] = 0; /* 1244: pointer.func */
    em[1247] = 8884097; em[1248] = 8; em[1249] = 0; /* 1247: pointer.func */
    em[1250] = 8884097; em[1251] = 8; em[1252] = 0; /* 1250: pointer.func */
    em[1253] = 1; em[1254] = 8; em[1255] = 1; /* 1253: pointer.struct.rand_meth_st */
    	em[1256] = 1258; em[1257] = 0; 
    em[1258] = 0; em[1259] = 48; em[1260] = 6; /* 1258: struct.rand_meth_st */
    	em[1261] = 1273; em[1262] = 0; 
    	em[1263] = 1276; em[1264] = 8; 
    	em[1265] = 1279; em[1266] = 16; 
    	em[1267] = 1282; em[1268] = 24; 
    	em[1269] = 1276; em[1270] = 32; 
    	em[1271] = 1285; em[1272] = 40; 
    em[1273] = 8884097; em[1274] = 8; em[1275] = 0; /* 1273: pointer.func */
    em[1276] = 8884097; em[1277] = 8; em[1278] = 0; /* 1276: pointer.func */
    em[1279] = 8884097; em[1280] = 8; em[1281] = 0; /* 1279: pointer.func */
    em[1282] = 8884097; em[1283] = 8; em[1284] = 0; /* 1282: pointer.func */
    em[1285] = 8884097; em[1286] = 8; em[1287] = 0; /* 1285: pointer.func */
    em[1288] = 1; em[1289] = 8; em[1290] = 1; /* 1288: pointer.struct.store_method_st */
    	em[1291] = 1293; em[1292] = 0; 
    em[1293] = 0; em[1294] = 0; em[1295] = 0; /* 1293: struct.store_method_st */
    em[1296] = 8884097; em[1297] = 8; em[1298] = 0; /* 1296: pointer.func */
    em[1299] = 8884097; em[1300] = 8; em[1301] = 0; /* 1299: pointer.func */
    em[1302] = 8884097; em[1303] = 8; em[1304] = 0; /* 1302: pointer.func */
    em[1305] = 8884097; em[1306] = 8; em[1307] = 0; /* 1305: pointer.func */
    em[1308] = 8884097; em[1309] = 8; em[1310] = 0; /* 1308: pointer.func */
    em[1311] = 8884097; em[1312] = 8; em[1313] = 0; /* 1311: pointer.func */
    em[1314] = 8884097; em[1315] = 8; em[1316] = 0; /* 1314: pointer.func */
    em[1317] = 1; em[1318] = 8; em[1319] = 1; /* 1317: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[1320] = 1322; em[1321] = 0; 
    em[1322] = 0; em[1323] = 32; em[1324] = 2; /* 1322: struct.ENGINE_CMD_DEFN_st */
    	em[1325] = 149; em[1326] = 8; 
    	em[1327] = 149; em[1328] = 16; 
    em[1329] = 0; em[1330] = 32; em[1331] = 2; /* 1329: struct.crypto_ex_data_st_fake */
    	em[1332] = 1336; em[1333] = 8; 
    	em[1334] = 363; em[1335] = 24; 
    em[1336] = 8884099; em[1337] = 8; em[1338] = 2; /* 1336: pointer_to_array_of_pointers_to_stack */
    	em[1339] = 848; em[1340] = 0; 
    	em[1341] = 5; em[1342] = 20; 
    em[1343] = 1; em[1344] = 8; em[1345] = 1; /* 1343: pointer.struct.engine_st */
    	em[1346] = 1025; em[1347] = 0; 
    em[1348] = 0; em[1349] = 32; em[1350] = 2; /* 1348: struct.crypto_ex_data_st_fake */
    	em[1351] = 1355; em[1352] = 8; 
    	em[1353] = 363; em[1354] = 24; 
    em[1355] = 8884099; em[1356] = 8; em[1357] = 2; /* 1355: pointer_to_array_of_pointers_to_stack */
    	em[1358] = 848; em[1359] = 0; 
    	em[1360] = 5; em[1361] = 20; 
    em[1362] = 1; em[1363] = 8; em[1364] = 1; /* 1362: pointer.struct.bn_mont_ctx_st */
    	em[1365] = 366; em[1366] = 0; 
    em[1367] = 1; em[1368] = 8; em[1369] = 1; /* 1367: pointer.struct.bn_blinding_st */
    	em[1370] = 1372; em[1371] = 0; 
    em[1372] = 0; em[1373] = 88; em[1374] = 7; /* 1372: struct.bn_blinding_st */
    	em[1375] = 1389; em[1376] = 0; 
    	em[1377] = 1389; em[1378] = 8; 
    	em[1379] = 1389; em[1380] = 16; 
    	em[1381] = 1389; em[1382] = 24; 
    	em[1383] = 1406; em[1384] = 40; 
    	em[1385] = 1411; em[1386] = 72; 
    	em[1387] = 1425; em[1388] = 80; 
    em[1389] = 1; em[1390] = 8; em[1391] = 1; /* 1389: pointer.struct.bignum_st */
    	em[1392] = 1394; em[1393] = 0; 
    em[1394] = 0; em[1395] = 24; em[1396] = 1; /* 1394: struct.bignum_st */
    	em[1397] = 1399; em[1398] = 0; 
    em[1399] = 8884099; em[1400] = 8; em[1401] = 2; /* 1399: pointer_to_array_of_pointers_to_stack */
    	em[1402] = 387; em[1403] = 0; 
    	em[1404] = 5; em[1405] = 12; 
    em[1406] = 0; em[1407] = 16; em[1408] = 1; /* 1406: struct.crypto_threadid_st */
    	em[1409] = 848; em[1410] = 0; 
    em[1411] = 1; em[1412] = 8; em[1413] = 1; /* 1411: pointer.struct.bn_mont_ctx_st */
    	em[1414] = 1416; em[1415] = 0; 
    em[1416] = 0; em[1417] = 96; em[1418] = 3; /* 1416: struct.bn_mont_ctx_st */
    	em[1419] = 1394; em[1420] = 8; 
    	em[1421] = 1394; em[1422] = 32; 
    	em[1423] = 1394; em[1424] = 56; 
    em[1425] = 8884097; em[1426] = 8; em[1427] = 0; /* 1425: pointer.func */
    em[1428] = 8884097; em[1429] = 8; em[1430] = 0; /* 1428: pointer.func */
    em[1431] = 8884097; em[1432] = 8; em[1433] = 0; /* 1431: pointer.func */
    em[1434] = 8884097; em[1435] = 8; em[1436] = 0; /* 1434: pointer.func */
    em[1437] = 8884097; em[1438] = 8; em[1439] = 0; /* 1437: pointer.func */
    em[1440] = 1; em[1441] = 8; em[1442] = 1; /* 1440: pointer.struct.dh_method */
    	em[1443] = 1445; em[1444] = 0; 
    em[1445] = 0; em[1446] = 72; em[1447] = 8; /* 1445: struct.dh_method */
    	em[1448] = 149; em[1449] = 0; 
    	em[1450] = 1464; em[1451] = 8; 
    	em[1452] = 1467; em[1453] = 16; 
    	em[1454] = 1434; em[1455] = 24; 
    	em[1456] = 1464; em[1457] = 32; 
    	em[1458] = 1464; em[1459] = 40; 
    	em[1460] = 125; em[1461] = 56; 
    	em[1462] = 1470; em[1463] = 64; 
    em[1464] = 8884097; em[1465] = 8; em[1466] = 0; /* 1464: pointer.func */
    em[1467] = 8884097; em[1468] = 8; em[1469] = 0; /* 1467: pointer.func */
    em[1470] = 8884097; em[1471] = 8; em[1472] = 0; /* 1470: pointer.func */
    em[1473] = 8884097; em[1474] = 8; em[1475] = 0; /* 1473: pointer.func */
    em[1476] = 8884097; em[1477] = 8; em[1478] = 0; /* 1476: pointer.func */
    em[1479] = 8884097; em[1480] = 8; em[1481] = 0; /* 1479: pointer.func */
    em[1482] = 0; em[1483] = 208; em[1484] = 24; /* 1482: struct.evp_pkey_asn1_method_st */
    	em[1485] = 125; em[1486] = 16; 
    	em[1487] = 125; em[1488] = 24; 
    	em[1489] = 1479; em[1490] = 32; 
    	em[1491] = 1476; em[1492] = 40; 
    	em[1493] = 977; em[1494] = 48; 
    	em[1495] = 1533; em[1496] = 56; 
    	em[1497] = 1536; em[1498] = 64; 
    	em[1499] = 1539; em[1500] = 72; 
    	em[1501] = 1533; em[1502] = 80; 
    	em[1503] = 1542; em[1504] = 88; 
    	em[1505] = 1542; em[1506] = 96; 
    	em[1507] = 1545; em[1508] = 104; 
    	em[1509] = 1548; em[1510] = 112; 
    	em[1511] = 1542; em[1512] = 120; 
    	em[1513] = 1473; em[1514] = 128; 
    	em[1515] = 977; em[1516] = 136; 
    	em[1517] = 1533; em[1518] = 144; 
    	em[1519] = 1437; em[1520] = 152; 
    	em[1521] = 1551; em[1522] = 160; 
    	em[1523] = 1554; em[1524] = 168; 
    	em[1525] = 1545; em[1526] = 176; 
    	em[1527] = 1548; em[1528] = 184; 
    	em[1529] = 1557; em[1530] = 192; 
    	em[1531] = 1431; em[1532] = 200; 
    em[1533] = 8884097; em[1534] = 8; em[1535] = 0; /* 1533: pointer.func */
    em[1536] = 8884097; em[1537] = 8; em[1538] = 0; /* 1536: pointer.func */
    em[1539] = 8884097; em[1540] = 8; em[1541] = 0; /* 1539: pointer.func */
    em[1542] = 8884097; em[1543] = 8; em[1544] = 0; /* 1542: pointer.func */
    em[1545] = 8884097; em[1546] = 8; em[1547] = 0; /* 1545: pointer.func */
    em[1548] = 8884097; em[1549] = 8; em[1550] = 0; /* 1548: pointer.func */
    em[1551] = 8884097; em[1552] = 8; em[1553] = 0; /* 1551: pointer.func */
    em[1554] = 8884097; em[1555] = 8; em[1556] = 0; /* 1554: pointer.func */
    em[1557] = 8884097; em[1558] = 8; em[1559] = 0; /* 1557: pointer.func */
    em[1560] = 8884097; em[1561] = 8; em[1562] = 0; /* 1560: pointer.func */
    em[1563] = 8884097; em[1564] = 8; em[1565] = 0; /* 1563: pointer.func */
    em[1566] = 8884097; em[1567] = 8; em[1568] = 0; /* 1566: pointer.func */
    em[1569] = 1; em[1570] = 8; em[1571] = 1; /* 1569: pointer.struct.evp_pkey_method_st */
    	em[1572] = 1574; em[1573] = 0; 
    em[1574] = 0; em[1575] = 208; em[1576] = 25; /* 1574: struct.evp_pkey_method_st */
    	em[1577] = 1627; em[1578] = 8; 
    	em[1579] = 1630; em[1580] = 16; 
    	em[1581] = 1633; em[1582] = 24; 
    	em[1583] = 1627; em[1584] = 32; 
    	em[1585] = 1636; em[1586] = 40; 
    	em[1587] = 1627; em[1588] = 48; 
    	em[1589] = 1636; em[1590] = 56; 
    	em[1591] = 1627; em[1592] = 64; 
    	em[1593] = 1563; em[1594] = 72; 
    	em[1595] = 1627; em[1596] = 80; 
    	em[1597] = 1560; em[1598] = 88; 
    	em[1599] = 1627; em[1600] = 96; 
    	em[1601] = 1563; em[1602] = 104; 
    	em[1603] = 1639; em[1604] = 112; 
    	em[1605] = 1428; em[1606] = 120; 
    	em[1607] = 1639; em[1608] = 128; 
    	em[1609] = 1642; em[1610] = 136; 
    	em[1611] = 1627; em[1612] = 144; 
    	em[1613] = 1563; em[1614] = 152; 
    	em[1615] = 1627; em[1616] = 160; 
    	em[1617] = 1563; em[1618] = 168; 
    	em[1619] = 1627; em[1620] = 176; 
    	em[1621] = 1645; em[1622] = 184; 
    	em[1623] = 1648; em[1624] = 192; 
    	em[1625] = 1651; em[1626] = 200; 
    em[1627] = 8884097; em[1628] = 8; em[1629] = 0; /* 1627: pointer.func */
    em[1630] = 8884097; em[1631] = 8; em[1632] = 0; /* 1630: pointer.func */
    em[1633] = 8884097; em[1634] = 8; em[1635] = 0; /* 1633: pointer.func */
    em[1636] = 8884097; em[1637] = 8; em[1638] = 0; /* 1636: pointer.func */
    em[1639] = 8884097; em[1640] = 8; em[1641] = 0; /* 1639: pointer.func */
    em[1642] = 8884097; em[1643] = 8; em[1644] = 0; /* 1642: pointer.func */
    em[1645] = 8884097; em[1646] = 8; em[1647] = 0; /* 1645: pointer.func */
    em[1648] = 8884097; em[1649] = 8; em[1650] = 0; /* 1648: pointer.func */
    em[1651] = 8884097; em[1652] = 8; em[1653] = 0; /* 1651: pointer.func */
    em[1654] = 0; em[1655] = 80; em[1656] = 8; /* 1654: struct.evp_pkey_ctx_st */
    	em[1657] = 1569; em[1658] = 0; 
    	em[1659] = 1673; em[1660] = 8; 
    	em[1661] = 1678; em[1662] = 16; 
    	em[1663] = 1678; em[1664] = 24; 
    	em[1665] = 848; em[1666] = 40; 
    	em[1667] = 848; em[1668] = 48; 
    	em[1669] = 8; em[1670] = 56; 
    	em[1671] = 0; em[1672] = 64; 
    em[1673] = 1; em[1674] = 8; em[1675] = 1; /* 1673: pointer.struct.engine_st */
    	em[1676] = 1025; em[1677] = 0; 
    em[1678] = 1; em[1679] = 8; em[1680] = 1; /* 1678: pointer.struct.evp_pkey_st */
    	em[1681] = 1683; em[1682] = 0; 
    em[1683] = 0; em[1684] = 56; em[1685] = 4; /* 1683: struct.evp_pkey_st */
    	em[1686] = 1694; em[1687] = 16; 
    	em[1688] = 1673; em[1689] = 24; 
    	em[1690] = 1699; em[1691] = 32; 
    	em[1692] = 1922; em[1693] = 48; 
    em[1694] = 1; em[1695] = 8; em[1696] = 1; /* 1694: pointer.struct.evp_pkey_asn1_method_st */
    	em[1697] = 1482; em[1698] = 0; 
    em[1699] = 0; em[1700] = 8; em[1701] = 5; /* 1699: union.unknown */
    	em[1702] = 125; em[1703] = 0; 
    	em[1704] = 1712; em[1705] = 0; 
    	em[1706] = 1717; em[1707] = 0; 
    	em[1708] = 1845; em[1709] = 0; 
    	em[1710] = 396; em[1711] = 0; 
    em[1712] = 1; em[1713] = 8; em[1714] = 1; /* 1712: pointer.struct.rsa_st */
    	em[1715] = 983; em[1716] = 0; 
    em[1717] = 1; em[1718] = 8; em[1719] = 1; /* 1717: pointer.struct.dsa_st */
    	em[1720] = 1722; em[1721] = 0; 
    em[1722] = 0; em[1723] = 136; em[1724] = 11; /* 1722: struct.dsa_st */
    	em[1725] = 1747; em[1726] = 24; 
    	em[1727] = 1747; em[1728] = 32; 
    	em[1729] = 1747; em[1730] = 40; 
    	em[1731] = 1747; em[1732] = 48; 
    	em[1733] = 1747; em[1734] = 56; 
    	em[1735] = 1747; em[1736] = 64; 
    	em[1737] = 1747; em[1738] = 72; 
    	em[1739] = 1764; em[1740] = 88; 
    	em[1741] = 1778; em[1742] = 104; 
    	em[1743] = 1792; em[1744] = 120; 
    	em[1745] = 1840; em[1746] = 128; 
    em[1747] = 1; em[1748] = 8; em[1749] = 1; /* 1747: pointer.struct.bignum_st */
    	em[1750] = 1752; em[1751] = 0; 
    em[1752] = 0; em[1753] = 24; em[1754] = 1; /* 1752: struct.bignum_st */
    	em[1755] = 1757; em[1756] = 0; 
    em[1757] = 8884099; em[1758] = 8; em[1759] = 2; /* 1757: pointer_to_array_of_pointers_to_stack */
    	em[1760] = 387; em[1761] = 0; 
    	em[1762] = 5; em[1763] = 12; 
    em[1764] = 1; em[1765] = 8; em[1766] = 1; /* 1764: pointer.struct.bn_mont_ctx_st */
    	em[1767] = 1769; em[1768] = 0; 
    em[1769] = 0; em[1770] = 96; em[1771] = 3; /* 1769: struct.bn_mont_ctx_st */
    	em[1772] = 1752; em[1773] = 8; 
    	em[1774] = 1752; em[1775] = 32; 
    	em[1776] = 1752; em[1777] = 56; 
    em[1778] = 0; em[1779] = 32; em[1780] = 2; /* 1778: struct.crypto_ex_data_st_fake */
    	em[1781] = 1785; em[1782] = 8; 
    	em[1783] = 363; em[1784] = 24; 
    em[1785] = 8884099; em[1786] = 8; em[1787] = 2; /* 1785: pointer_to_array_of_pointers_to_stack */
    	em[1788] = 848; em[1789] = 0; 
    	em[1790] = 5; em[1791] = 20; 
    em[1792] = 1; em[1793] = 8; em[1794] = 1; /* 1792: pointer.struct.dsa_method */
    	em[1795] = 1797; em[1796] = 0; 
    em[1797] = 0; em[1798] = 96; em[1799] = 11; /* 1797: struct.dsa_method */
    	em[1800] = 149; em[1801] = 0; 
    	em[1802] = 1822; em[1803] = 8; 
    	em[1804] = 1825; em[1805] = 16; 
    	em[1806] = 1828; em[1807] = 24; 
    	em[1808] = 1831; em[1809] = 32; 
    	em[1810] = 1834; em[1811] = 40; 
    	em[1812] = 1566; em[1813] = 48; 
    	em[1814] = 1566; em[1815] = 56; 
    	em[1816] = 125; em[1817] = 72; 
    	em[1818] = 1837; em[1819] = 80; 
    	em[1820] = 1566; em[1821] = 88; 
    em[1822] = 8884097; em[1823] = 8; em[1824] = 0; /* 1822: pointer.func */
    em[1825] = 8884097; em[1826] = 8; em[1827] = 0; /* 1825: pointer.func */
    em[1828] = 8884097; em[1829] = 8; em[1830] = 0; /* 1828: pointer.func */
    em[1831] = 8884097; em[1832] = 8; em[1833] = 0; /* 1831: pointer.func */
    em[1834] = 8884097; em[1835] = 8; em[1836] = 0; /* 1834: pointer.func */
    em[1837] = 8884097; em[1838] = 8; em[1839] = 0; /* 1837: pointer.func */
    em[1840] = 1; em[1841] = 8; em[1842] = 1; /* 1840: pointer.struct.engine_st */
    	em[1843] = 1025; em[1844] = 0; 
    em[1845] = 1; em[1846] = 8; em[1847] = 1; /* 1845: pointer.struct.dh_st */
    	em[1848] = 1850; em[1849] = 0; 
    em[1850] = 0; em[1851] = 144; em[1852] = 12; /* 1850: struct.dh_st */
    	em[1853] = 1877; em[1854] = 8; 
    	em[1855] = 1877; em[1856] = 16; 
    	em[1857] = 1877; em[1858] = 32; 
    	em[1859] = 1877; em[1860] = 40; 
    	em[1861] = 1894; em[1862] = 56; 
    	em[1863] = 1877; em[1864] = 64; 
    	em[1865] = 1877; em[1866] = 72; 
    	em[1867] = 29; em[1868] = 80; 
    	em[1869] = 1877; em[1870] = 96; 
    	em[1871] = 1908; em[1872] = 112; 
    	em[1873] = 1440; em[1874] = 128; 
    	em[1875] = 1673; em[1876] = 136; 
    em[1877] = 1; em[1878] = 8; em[1879] = 1; /* 1877: pointer.struct.bignum_st */
    	em[1880] = 1882; em[1881] = 0; 
    em[1882] = 0; em[1883] = 24; em[1884] = 1; /* 1882: struct.bignum_st */
    	em[1885] = 1887; em[1886] = 0; 
    em[1887] = 8884099; em[1888] = 8; em[1889] = 2; /* 1887: pointer_to_array_of_pointers_to_stack */
    	em[1890] = 387; em[1891] = 0; 
    	em[1892] = 5; em[1893] = 12; 
    em[1894] = 1; em[1895] = 8; em[1896] = 1; /* 1894: pointer.struct.bn_mont_ctx_st */
    	em[1897] = 1899; em[1898] = 0; 
    em[1899] = 0; em[1900] = 96; em[1901] = 3; /* 1899: struct.bn_mont_ctx_st */
    	em[1902] = 1882; em[1903] = 8; 
    	em[1904] = 1882; em[1905] = 32; 
    	em[1906] = 1882; em[1907] = 56; 
    em[1908] = 0; em[1909] = 32; em[1910] = 2; /* 1908: struct.crypto_ex_data_st_fake */
    	em[1911] = 1915; em[1912] = 8; 
    	em[1913] = 363; em[1914] = 24; 
    em[1915] = 8884099; em[1916] = 8; em[1917] = 2; /* 1915: pointer_to_array_of_pointers_to_stack */
    	em[1918] = 848; em[1919] = 0; 
    	em[1920] = 5; em[1921] = 20; 
    em[1922] = 1; em[1923] = 8; em[1924] = 1; /* 1922: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1925] = 1927; em[1926] = 0; 
    em[1927] = 0; em[1928] = 32; em[1929] = 2; /* 1927: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1930] = 1934; em[1931] = 8; 
    	em[1932] = 363; em[1933] = 24; 
    em[1934] = 8884099; em[1935] = 8; em[1936] = 2; /* 1934: pointer_to_array_of_pointers_to_stack */
    	em[1937] = 1941; em[1938] = 0; 
    	em[1939] = 5; em[1940] = 20; 
    em[1941] = 0; em[1942] = 8; em[1943] = 1; /* 1941: pointer.X509_ATTRIBUTE */
    	em[1944] = 1946; em[1945] = 0; 
    em[1946] = 0; em[1947] = 0; em[1948] = 1; /* 1946: X509_ATTRIBUTE */
    	em[1949] = 1951; em[1950] = 0; 
    em[1951] = 0; em[1952] = 24; em[1953] = 2; /* 1951: struct.x509_attributes_st */
    	em[1954] = 135; em[1955] = 0; 
    	em[1956] = 1958; em[1957] = 16; 
    em[1958] = 0; em[1959] = 8; em[1960] = 3; /* 1958: union.unknown */
    	em[1961] = 125; em[1962] = 0; 
    	em[1963] = 339; em[1964] = 0; 
    	em[1965] = 1967; em[1966] = 0; 
    em[1967] = 1; em[1968] = 8; em[1969] = 1; /* 1967: pointer.struct.asn1_type_st */
    	em[1970] = 179; em[1971] = 0; 
    em[1972] = 1; em[1973] = 8; em[1974] = 1; /* 1972: pointer.struct.evp_pkey_ctx_st */
    	em[1975] = 1654; em[1976] = 0; 
    em[1977] = 8884097; em[1978] = 8; em[1979] = 0; /* 1977: pointer.func */
    em[1980] = 8884097; em[1981] = 8; em[1982] = 0; /* 1980: pointer.func */
    em[1983] = 8884097; em[1984] = 8; em[1985] = 0; /* 1983: pointer.func */
    em[1986] = 0; em[1987] = 120; em[1988] = 8; /* 1986: struct.env_md_st */
    	em[1989] = 2005; em[1990] = 24; 
    	em[1991] = 2008; em[1992] = 32; 
    	em[1993] = 1977; em[1994] = 40; 
    	em[1995] = 931; em[1996] = 48; 
    	em[1997] = 2005; em[1998] = 56; 
    	em[1999] = 1980; em[2000] = 64; 
    	em[2001] = 2011; em[2002] = 72; 
    	em[2003] = 1983; em[2004] = 112; 
    em[2005] = 8884097; em[2006] = 8; em[2007] = 0; /* 2005: pointer.func */
    em[2008] = 8884097; em[2009] = 8; em[2010] = 0; /* 2008: pointer.func */
    em[2011] = 8884097; em[2012] = 8; em[2013] = 0; /* 2011: pointer.func */
    em[2014] = 1; em[2015] = 8; em[2016] = 1; /* 2014: pointer.struct.env_md_ctx_st */
    	em[2017] = 2019; em[2018] = 0; 
    em[2019] = 0; em[2020] = 48; em[2021] = 5; /* 2019: struct.env_md_ctx_st */
    	em[2022] = 2032; em[2023] = 0; 
    	em[2024] = 1673; em[2025] = 8; 
    	em[2026] = 848; em[2027] = 24; 
    	em[2028] = 1972; em[2029] = 32; 
    	em[2030] = 2008; em[2031] = 40; 
    em[2032] = 1; em[2033] = 8; em[2034] = 1; /* 2032: pointer.struct.env_md_st */
    	em[2035] = 1986; em[2036] = 0; 
    em[2037] = 0; em[2038] = 0; em[2039] = 0; /* 2037: size_t */
    args_addr->arg_entity_index[0] = 2014;
    args_addr->arg_entity_index[1] = 848;
    args_addr->arg_entity_index[2] = 2037;
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

