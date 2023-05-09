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

int bb_HMAC_Init_ex(HMAC_CTX * arg_a,const void * arg_b,int arg_c,const EVP_MD * arg_d,ENGINE * arg_e);

int HMAC_Init_ex(HMAC_CTX * arg_a,const void * arg_b,int arg_c,const EVP_MD * arg_d,ENGINE * arg_e) 
{
    unsigned long in_lib = syscall(890);
    printf("HMAC_Init_ex called %lu\n", in_lib);
    if (!in_lib)
        return bb_HMAC_Init_ex(arg_a,arg_b,arg_c,arg_d,arg_e);
    else {
        int (*orig_HMAC_Init_ex)(HMAC_CTX *,const void *,int,const EVP_MD *,ENGINE *);
        orig_HMAC_Init_ex = dlsym(RTLD_NEXT, "HMAC_Init_ex");
        return orig_HMAC_Init_ex(arg_a,arg_b,arg_c,arg_d,arg_e);
    }
}

int bb_HMAC_Init_ex(HMAC_CTX * arg_a,const void * arg_b,int arg_c,const EVP_MD * arg_d,ENGINE * arg_e) 
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
    em[184] = 1; em[185] = 8; em[186] = 1; /* 184: pointer.struct.asn1_string_st */
    	em[187] = 189; em[188] = 0; 
    em[189] = 0; em[190] = 24; em[191] = 1; /* 189: struct.asn1_string_st */
    	em[192] = 29; em[193] = 8; 
    em[194] = 1; em[195] = 8; em[196] = 1; /* 194: pointer.struct.asn1_string_st */
    	em[197] = 189; em[198] = 0; 
    em[199] = 1; em[200] = 8; em[201] = 1; /* 199: pointer.struct.asn1_string_st */
    	em[202] = 189; em[203] = 0; 
    em[204] = 1; em[205] = 8; em[206] = 1; /* 204: pointer.struct.asn1_string_st */
    	em[207] = 189; em[208] = 0; 
    em[209] = 1; em[210] = 8; em[211] = 1; /* 209: pointer.struct.asn1_string_st */
    	em[212] = 189; em[213] = 0; 
    em[214] = 1; em[215] = 8; em[216] = 1; /* 214: pointer.struct.asn1_string_st */
    	em[217] = 189; em[218] = 0; 
    em[219] = 0; em[220] = 40; em[221] = 3; /* 219: struct.asn1_object_st */
    	em[222] = 144; em[223] = 0; 
    	em[224] = 144; em[225] = 8; 
    	em[226] = 149; em[227] = 24; 
    em[228] = 1; em[229] = 8; em[230] = 1; /* 228: pointer.struct.asn1_string_st */
    	em[231] = 189; em[232] = 0; 
    em[233] = 0; em[234] = 0; em[235] = 1; /* 233: ASN1_TYPE */
    	em[236] = 238; em[237] = 0; 
    em[238] = 0; em[239] = 16; em[240] = 1; /* 238: struct.asn1_type_st */
    	em[241] = 243; em[242] = 8; 
    em[243] = 0; em[244] = 8; em[245] = 20; /* 243: union.unknown */
    	em[246] = 120; em[247] = 0; 
    	em[248] = 228; em[249] = 0; 
    	em[250] = 286; em[251] = 0; 
    	em[252] = 214; em[253] = 0; 
    	em[254] = 209; em[255] = 0; 
    	em[256] = 204; em[257] = 0; 
    	em[258] = 291; em[259] = 0; 
    	em[260] = 296; em[261] = 0; 
    	em[262] = 199; em[263] = 0; 
    	em[264] = 194; em[265] = 0; 
    	em[266] = 301; em[267] = 0; 
    	em[268] = 306; em[269] = 0; 
    	em[270] = 311; em[271] = 0; 
    	em[272] = 316; em[273] = 0; 
    	em[274] = 321; em[275] = 0; 
    	em[276] = 326; em[277] = 0; 
    	em[278] = 184; em[279] = 0; 
    	em[280] = 228; em[281] = 0; 
    	em[282] = 228; em[283] = 0; 
    	em[284] = 331; em[285] = 0; 
    em[286] = 1; em[287] = 8; em[288] = 1; /* 286: pointer.struct.asn1_object_st */
    	em[289] = 219; em[290] = 0; 
    em[291] = 1; em[292] = 8; em[293] = 1; /* 291: pointer.struct.asn1_string_st */
    	em[294] = 189; em[295] = 0; 
    em[296] = 1; em[297] = 8; em[298] = 1; /* 296: pointer.struct.asn1_string_st */
    	em[299] = 189; em[300] = 0; 
    em[301] = 1; em[302] = 8; em[303] = 1; /* 301: pointer.struct.asn1_string_st */
    	em[304] = 189; em[305] = 0; 
    em[306] = 1; em[307] = 8; em[308] = 1; /* 306: pointer.struct.asn1_string_st */
    	em[309] = 189; em[310] = 0; 
    em[311] = 1; em[312] = 8; em[313] = 1; /* 311: pointer.struct.asn1_string_st */
    	em[314] = 189; em[315] = 0; 
    em[316] = 1; em[317] = 8; em[318] = 1; /* 316: pointer.struct.asn1_string_st */
    	em[319] = 189; em[320] = 0; 
    em[321] = 1; em[322] = 8; em[323] = 1; /* 321: pointer.struct.asn1_string_st */
    	em[324] = 189; em[325] = 0; 
    em[326] = 1; em[327] = 8; em[328] = 1; /* 326: pointer.struct.asn1_string_st */
    	em[329] = 189; em[330] = 0; 
    em[331] = 1; em[332] = 8; em[333] = 1; /* 331: pointer.struct.ASN1_VALUE_st */
    	em[334] = 336; em[335] = 0; 
    em[336] = 0; em[337] = 0; em[338] = 0; /* 336: struct.ASN1_VALUE_st */
    em[339] = 1; em[340] = 8; em[341] = 1; /* 339: pointer.struct.stack_st_ASN1_TYPE */
    	em[342] = 344; em[343] = 0; 
    em[344] = 0; em[345] = 32; em[346] = 2; /* 344: struct.stack_st_fake_ASN1_TYPE */
    	em[347] = 351; em[348] = 8; 
    	em[349] = 363; em[350] = 24; 
    em[351] = 8884099; em[352] = 8; em[353] = 2; /* 351: pointer_to_array_of_pointers_to_stack */
    	em[354] = 358; em[355] = 0; 
    	em[356] = 5; em[357] = 20; 
    em[358] = 0; em[359] = 8; em[360] = 1; /* 358: pointer.ASN1_TYPE */
    	em[361] = 233; em[362] = 0; 
    em[363] = 8884097; em[364] = 8; em[365] = 0; /* 363: pointer.func */
    em[366] = 0; em[367] = 8; em[368] = 3; /* 366: union.unknown */
    	em[369] = 120; em[370] = 0; 
    	em[371] = 339; em[372] = 0; 
    	em[373] = 375; em[374] = 0; 
    em[375] = 1; em[376] = 8; em[377] = 1; /* 375: pointer.struct.asn1_type_st */
    	em[378] = 179; em[379] = 0; 
    em[380] = 8884097; em[381] = 8; em[382] = 0; /* 380: pointer.func */
    em[383] = 8884097; em[384] = 8; em[385] = 0; /* 383: pointer.func */
    em[386] = 1; em[387] = 8; em[388] = 1; /* 386: pointer.struct.ec_key_st */
    	em[389] = 391; em[390] = 0; 
    em[391] = 0; em[392] = 56; em[393] = 4; /* 391: struct.ec_key_st */
    	em[394] = 402; em[395] = 8; 
    	em[396] = 853; em[397] = 16; 
    	em[398] = 858; em[399] = 24; 
    	em[400] = 875; em[401] = 48; 
    em[402] = 1; em[403] = 8; em[404] = 1; /* 402: pointer.struct.ec_group_st */
    	em[405] = 407; em[406] = 0; 
    em[407] = 0; em[408] = 232; em[409] = 12; /* 407: struct.ec_group_st */
    	em[410] = 434; em[411] = 0; 
    	em[412] = 603; em[413] = 8; 
    	em[414] = 806; em[415] = 16; 
    	em[416] = 806; em[417] = 40; 
    	em[418] = 29; em[419] = 80; 
    	em[420] = 818; em[421] = 96; 
    	em[422] = 806; em[423] = 104; 
    	em[424] = 806; em[425] = 152; 
    	em[426] = 806; em[427] = 176; 
    	em[428] = 841; em[429] = 208; 
    	em[430] = 841; em[431] = 216; 
    	em[432] = 850; em[433] = 224; 
    em[434] = 1; em[435] = 8; em[436] = 1; /* 434: pointer.struct.ec_method_st */
    	em[437] = 439; em[438] = 0; 
    em[439] = 0; em[440] = 304; em[441] = 37; /* 439: struct.ec_method_st */
    	em[442] = 516; em[443] = 8; 
    	em[444] = 519; em[445] = 16; 
    	em[446] = 519; em[447] = 24; 
    	em[448] = 522; em[449] = 32; 
    	em[450] = 380; em[451] = 40; 
    	em[452] = 525; em[453] = 48; 
    	em[454] = 528; em[455] = 56; 
    	em[456] = 531; em[457] = 64; 
    	em[458] = 534; em[459] = 72; 
    	em[460] = 537; em[461] = 80; 
    	em[462] = 537; em[463] = 88; 
    	em[464] = 540; em[465] = 96; 
    	em[466] = 543; em[467] = 104; 
    	em[468] = 546; em[469] = 112; 
    	em[470] = 549; em[471] = 120; 
    	em[472] = 552; em[473] = 128; 
    	em[474] = 555; em[475] = 136; 
    	em[476] = 558; em[477] = 144; 
    	em[478] = 561; em[479] = 152; 
    	em[480] = 564; em[481] = 160; 
    	em[482] = 567; em[483] = 168; 
    	em[484] = 570; em[485] = 176; 
    	em[486] = 573; em[487] = 184; 
    	em[488] = 576; em[489] = 192; 
    	em[490] = 579; em[491] = 200; 
    	em[492] = 582; em[493] = 208; 
    	em[494] = 573; em[495] = 216; 
    	em[496] = 585; em[497] = 224; 
    	em[498] = 588; em[499] = 232; 
    	em[500] = 591; em[501] = 240; 
    	em[502] = 528; em[503] = 248; 
    	em[504] = 594; em[505] = 256; 
    	em[506] = 597; em[507] = 264; 
    	em[508] = 594; em[509] = 272; 
    	em[510] = 597; em[511] = 280; 
    	em[512] = 597; em[513] = 288; 
    	em[514] = 600; em[515] = 296; 
    em[516] = 8884097; em[517] = 8; em[518] = 0; /* 516: pointer.func */
    em[519] = 8884097; em[520] = 8; em[521] = 0; /* 519: pointer.func */
    em[522] = 8884097; em[523] = 8; em[524] = 0; /* 522: pointer.func */
    em[525] = 8884097; em[526] = 8; em[527] = 0; /* 525: pointer.func */
    em[528] = 8884097; em[529] = 8; em[530] = 0; /* 528: pointer.func */
    em[531] = 8884097; em[532] = 8; em[533] = 0; /* 531: pointer.func */
    em[534] = 8884097; em[535] = 8; em[536] = 0; /* 534: pointer.func */
    em[537] = 8884097; em[538] = 8; em[539] = 0; /* 537: pointer.func */
    em[540] = 8884097; em[541] = 8; em[542] = 0; /* 540: pointer.func */
    em[543] = 8884097; em[544] = 8; em[545] = 0; /* 543: pointer.func */
    em[546] = 8884097; em[547] = 8; em[548] = 0; /* 546: pointer.func */
    em[549] = 8884097; em[550] = 8; em[551] = 0; /* 549: pointer.func */
    em[552] = 8884097; em[553] = 8; em[554] = 0; /* 552: pointer.func */
    em[555] = 8884097; em[556] = 8; em[557] = 0; /* 555: pointer.func */
    em[558] = 8884097; em[559] = 8; em[560] = 0; /* 558: pointer.func */
    em[561] = 8884097; em[562] = 8; em[563] = 0; /* 561: pointer.func */
    em[564] = 8884097; em[565] = 8; em[566] = 0; /* 564: pointer.func */
    em[567] = 8884097; em[568] = 8; em[569] = 0; /* 567: pointer.func */
    em[570] = 8884097; em[571] = 8; em[572] = 0; /* 570: pointer.func */
    em[573] = 8884097; em[574] = 8; em[575] = 0; /* 573: pointer.func */
    em[576] = 8884097; em[577] = 8; em[578] = 0; /* 576: pointer.func */
    em[579] = 8884097; em[580] = 8; em[581] = 0; /* 579: pointer.func */
    em[582] = 8884097; em[583] = 8; em[584] = 0; /* 582: pointer.func */
    em[585] = 8884097; em[586] = 8; em[587] = 0; /* 585: pointer.func */
    em[588] = 8884097; em[589] = 8; em[590] = 0; /* 588: pointer.func */
    em[591] = 8884097; em[592] = 8; em[593] = 0; /* 591: pointer.func */
    em[594] = 8884097; em[595] = 8; em[596] = 0; /* 594: pointer.func */
    em[597] = 8884097; em[598] = 8; em[599] = 0; /* 597: pointer.func */
    em[600] = 8884097; em[601] = 8; em[602] = 0; /* 600: pointer.func */
    em[603] = 1; em[604] = 8; em[605] = 1; /* 603: pointer.struct.ec_point_st */
    	em[606] = 608; em[607] = 0; 
    em[608] = 0; em[609] = 88; em[610] = 4; /* 608: struct.ec_point_st */
    	em[611] = 619; em[612] = 0; 
    	em[613] = 791; em[614] = 8; 
    	em[615] = 791; em[616] = 32; 
    	em[617] = 791; em[618] = 56; 
    em[619] = 1; em[620] = 8; em[621] = 1; /* 619: pointer.struct.ec_method_st */
    	em[622] = 624; em[623] = 0; 
    em[624] = 0; em[625] = 304; em[626] = 37; /* 624: struct.ec_method_st */
    	em[627] = 701; em[628] = 8; 
    	em[629] = 704; em[630] = 16; 
    	em[631] = 704; em[632] = 24; 
    	em[633] = 707; em[634] = 32; 
    	em[635] = 710; em[636] = 40; 
    	em[637] = 713; em[638] = 48; 
    	em[639] = 716; em[640] = 56; 
    	em[641] = 719; em[642] = 64; 
    	em[643] = 722; em[644] = 72; 
    	em[645] = 725; em[646] = 80; 
    	em[647] = 725; em[648] = 88; 
    	em[649] = 728; em[650] = 96; 
    	em[651] = 731; em[652] = 104; 
    	em[653] = 734; em[654] = 112; 
    	em[655] = 737; em[656] = 120; 
    	em[657] = 740; em[658] = 128; 
    	em[659] = 743; em[660] = 136; 
    	em[661] = 746; em[662] = 144; 
    	em[663] = 749; em[664] = 152; 
    	em[665] = 752; em[666] = 160; 
    	em[667] = 755; em[668] = 168; 
    	em[669] = 758; em[670] = 176; 
    	em[671] = 761; em[672] = 184; 
    	em[673] = 764; em[674] = 192; 
    	em[675] = 767; em[676] = 200; 
    	em[677] = 770; em[678] = 208; 
    	em[679] = 761; em[680] = 216; 
    	em[681] = 773; em[682] = 224; 
    	em[683] = 776; em[684] = 232; 
    	em[685] = 779; em[686] = 240; 
    	em[687] = 716; em[688] = 248; 
    	em[689] = 782; em[690] = 256; 
    	em[691] = 785; em[692] = 264; 
    	em[693] = 782; em[694] = 272; 
    	em[695] = 785; em[696] = 280; 
    	em[697] = 785; em[698] = 288; 
    	em[699] = 788; em[700] = 296; 
    em[701] = 8884097; em[702] = 8; em[703] = 0; /* 701: pointer.func */
    em[704] = 8884097; em[705] = 8; em[706] = 0; /* 704: pointer.func */
    em[707] = 8884097; em[708] = 8; em[709] = 0; /* 707: pointer.func */
    em[710] = 8884097; em[711] = 8; em[712] = 0; /* 710: pointer.func */
    em[713] = 8884097; em[714] = 8; em[715] = 0; /* 713: pointer.func */
    em[716] = 8884097; em[717] = 8; em[718] = 0; /* 716: pointer.func */
    em[719] = 8884097; em[720] = 8; em[721] = 0; /* 719: pointer.func */
    em[722] = 8884097; em[723] = 8; em[724] = 0; /* 722: pointer.func */
    em[725] = 8884097; em[726] = 8; em[727] = 0; /* 725: pointer.func */
    em[728] = 8884097; em[729] = 8; em[730] = 0; /* 728: pointer.func */
    em[731] = 8884097; em[732] = 8; em[733] = 0; /* 731: pointer.func */
    em[734] = 8884097; em[735] = 8; em[736] = 0; /* 734: pointer.func */
    em[737] = 8884097; em[738] = 8; em[739] = 0; /* 737: pointer.func */
    em[740] = 8884097; em[741] = 8; em[742] = 0; /* 740: pointer.func */
    em[743] = 8884097; em[744] = 8; em[745] = 0; /* 743: pointer.func */
    em[746] = 8884097; em[747] = 8; em[748] = 0; /* 746: pointer.func */
    em[749] = 8884097; em[750] = 8; em[751] = 0; /* 749: pointer.func */
    em[752] = 8884097; em[753] = 8; em[754] = 0; /* 752: pointer.func */
    em[755] = 8884097; em[756] = 8; em[757] = 0; /* 755: pointer.func */
    em[758] = 8884097; em[759] = 8; em[760] = 0; /* 758: pointer.func */
    em[761] = 8884097; em[762] = 8; em[763] = 0; /* 761: pointer.func */
    em[764] = 8884097; em[765] = 8; em[766] = 0; /* 764: pointer.func */
    em[767] = 8884097; em[768] = 8; em[769] = 0; /* 767: pointer.func */
    em[770] = 8884097; em[771] = 8; em[772] = 0; /* 770: pointer.func */
    em[773] = 8884097; em[774] = 8; em[775] = 0; /* 773: pointer.func */
    em[776] = 8884097; em[777] = 8; em[778] = 0; /* 776: pointer.func */
    em[779] = 8884097; em[780] = 8; em[781] = 0; /* 779: pointer.func */
    em[782] = 8884097; em[783] = 8; em[784] = 0; /* 782: pointer.func */
    em[785] = 8884097; em[786] = 8; em[787] = 0; /* 785: pointer.func */
    em[788] = 8884097; em[789] = 8; em[790] = 0; /* 788: pointer.func */
    em[791] = 0; em[792] = 24; em[793] = 1; /* 791: struct.bignum_st */
    	em[794] = 796; em[795] = 0; 
    em[796] = 8884099; em[797] = 8; em[798] = 2; /* 796: pointer_to_array_of_pointers_to_stack */
    	em[799] = 803; em[800] = 0; 
    	em[801] = 5; em[802] = 12; 
    em[803] = 0; em[804] = 8; em[805] = 0; /* 803: long unsigned int */
    em[806] = 0; em[807] = 24; em[808] = 1; /* 806: struct.bignum_st */
    	em[809] = 811; em[810] = 0; 
    em[811] = 8884099; em[812] = 8; em[813] = 2; /* 811: pointer_to_array_of_pointers_to_stack */
    	em[814] = 803; em[815] = 0; 
    	em[816] = 5; em[817] = 12; 
    em[818] = 1; em[819] = 8; em[820] = 1; /* 818: pointer.struct.ec_extra_data_st */
    	em[821] = 823; em[822] = 0; 
    em[823] = 0; em[824] = 40; em[825] = 5; /* 823: struct.ec_extra_data_st */
    	em[826] = 836; em[827] = 0; 
    	em[828] = 841; em[829] = 8; 
    	em[830] = 844; em[831] = 16; 
    	em[832] = 847; em[833] = 24; 
    	em[834] = 847; em[835] = 32; 
    em[836] = 1; em[837] = 8; em[838] = 1; /* 836: pointer.struct.ec_extra_data_st */
    	em[839] = 823; em[840] = 0; 
    em[841] = 0; em[842] = 8; em[843] = 0; /* 841: pointer.void */
    em[844] = 8884097; em[845] = 8; em[846] = 0; /* 844: pointer.func */
    em[847] = 8884097; em[848] = 8; em[849] = 0; /* 847: pointer.func */
    em[850] = 8884097; em[851] = 8; em[852] = 0; /* 850: pointer.func */
    em[853] = 1; em[854] = 8; em[855] = 1; /* 853: pointer.struct.ec_point_st */
    	em[856] = 608; em[857] = 0; 
    em[858] = 1; em[859] = 8; em[860] = 1; /* 858: pointer.struct.bignum_st */
    	em[861] = 863; em[862] = 0; 
    em[863] = 0; em[864] = 24; em[865] = 1; /* 863: struct.bignum_st */
    	em[866] = 868; em[867] = 0; 
    em[868] = 8884099; em[869] = 8; em[870] = 2; /* 868: pointer_to_array_of_pointers_to_stack */
    	em[871] = 803; em[872] = 0; 
    	em[873] = 5; em[874] = 12; 
    em[875] = 1; em[876] = 8; em[877] = 1; /* 875: pointer.struct.ec_extra_data_st */
    	em[878] = 880; em[879] = 0; 
    em[880] = 0; em[881] = 40; em[882] = 5; /* 880: struct.ec_extra_data_st */
    	em[883] = 893; em[884] = 0; 
    	em[885] = 841; em[886] = 8; 
    	em[887] = 844; em[888] = 16; 
    	em[889] = 847; em[890] = 24; 
    	em[891] = 847; em[892] = 32; 
    em[893] = 1; em[894] = 8; em[895] = 1; /* 893: pointer.struct.ec_extra_data_st */
    	em[896] = 880; em[897] = 0; 
    em[898] = 0; em[899] = 24; em[900] = 1; /* 898: struct.bignum_st */
    	em[901] = 903; em[902] = 0; 
    em[903] = 8884099; em[904] = 8; em[905] = 2; /* 903: pointer_to_array_of_pointers_to_stack */
    	em[906] = 803; em[907] = 0; 
    	em[908] = 5; em[909] = 12; 
    em[910] = 8884097; em[911] = 8; em[912] = 0; /* 910: pointer.func */
    em[913] = 8884097; em[914] = 8; em[915] = 0; /* 913: pointer.func */
    em[916] = 0; em[917] = 112; em[918] = 13; /* 916: struct.rsa_meth_st */
    	em[919] = 144; em[920] = 0; 
    	em[921] = 945; em[922] = 8; 
    	em[923] = 945; em[924] = 16; 
    	em[925] = 945; em[926] = 24; 
    	em[927] = 945; em[928] = 32; 
    	em[929] = 948; em[930] = 40; 
    	em[931] = 951; em[932] = 48; 
    	em[933] = 910; em[934] = 56; 
    	em[935] = 910; em[936] = 64; 
    	em[937] = 120; em[938] = 80; 
    	em[939] = 954; em[940] = 88; 
    	em[941] = 957; em[942] = 96; 
    	em[943] = 383; em[944] = 104; 
    em[945] = 8884097; em[946] = 8; em[947] = 0; /* 945: pointer.func */
    em[948] = 8884097; em[949] = 8; em[950] = 0; /* 948: pointer.func */
    em[951] = 8884097; em[952] = 8; em[953] = 0; /* 951: pointer.func */
    em[954] = 8884097; em[955] = 8; em[956] = 0; /* 954: pointer.func */
    em[957] = 8884097; em[958] = 8; em[959] = 0; /* 957: pointer.func */
    em[960] = 0; em[961] = 168; em[962] = 17; /* 960: struct.rsa_st */
    	em[963] = 997; em[964] = 16; 
    	em[965] = 1002; em[966] = 24; 
    	em[967] = 1339; em[968] = 32; 
    	em[969] = 1339; em[970] = 40; 
    	em[971] = 1339; em[972] = 48; 
    	em[973] = 1339; em[974] = 56; 
    	em[975] = 1339; em[976] = 64; 
    	em[977] = 1339; em[978] = 72; 
    	em[979] = 1339; em[980] = 80; 
    	em[981] = 1339; em[982] = 88; 
    	em[983] = 1344; em[984] = 96; 
    	em[985] = 1358; em[986] = 120; 
    	em[987] = 1358; em[988] = 128; 
    	em[989] = 1358; em[990] = 136; 
    	em[991] = 120; em[992] = 144; 
    	em[993] = 1372; em[994] = 152; 
    	em[995] = 1372; em[996] = 160; 
    em[997] = 1; em[998] = 8; em[999] = 1; /* 997: pointer.struct.rsa_meth_st */
    	em[1000] = 916; em[1001] = 0; 
    em[1002] = 1; em[1003] = 8; em[1004] = 1; /* 1002: pointer.struct.engine_st */
    	em[1005] = 1007; em[1006] = 0; 
    em[1007] = 0; em[1008] = 216; em[1009] = 24; /* 1007: struct.engine_st */
    	em[1010] = 144; em[1011] = 0; 
    	em[1012] = 144; em[1013] = 8; 
    	em[1014] = 1058; em[1015] = 16; 
    	em[1016] = 1110; em[1017] = 24; 
    	em[1018] = 1161; em[1019] = 32; 
    	em[1020] = 1197; em[1021] = 40; 
    	em[1022] = 1214; em[1023] = 48; 
    	em[1024] = 1241; em[1025] = 56; 
    	em[1026] = 1276; em[1027] = 64; 
    	em[1028] = 1284; em[1029] = 72; 
    	em[1030] = 1287; em[1031] = 80; 
    	em[1032] = 1290; em[1033] = 88; 
    	em[1034] = 1293; em[1035] = 96; 
    	em[1036] = 1296; em[1037] = 104; 
    	em[1038] = 1296; em[1039] = 112; 
    	em[1040] = 1296; em[1041] = 120; 
    	em[1042] = 1299; em[1043] = 128; 
    	em[1044] = 1302; em[1045] = 136; 
    	em[1046] = 1302; em[1047] = 144; 
    	em[1048] = 1305; em[1049] = 152; 
    	em[1050] = 1308; em[1051] = 160; 
    	em[1052] = 1320; em[1053] = 184; 
    	em[1054] = 1334; em[1055] = 200; 
    	em[1056] = 1334; em[1057] = 208; 
    em[1058] = 1; em[1059] = 8; em[1060] = 1; /* 1058: pointer.struct.rsa_meth_st */
    	em[1061] = 1063; em[1062] = 0; 
    em[1063] = 0; em[1064] = 112; em[1065] = 13; /* 1063: struct.rsa_meth_st */
    	em[1066] = 144; em[1067] = 0; 
    	em[1068] = 913; em[1069] = 8; 
    	em[1070] = 913; em[1071] = 16; 
    	em[1072] = 913; em[1073] = 24; 
    	em[1074] = 913; em[1075] = 32; 
    	em[1076] = 1092; em[1077] = 40; 
    	em[1078] = 1095; em[1079] = 48; 
    	em[1080] = 1098; em[1081] = 56; 
    	em[1082] = 1098; em[1083] = 64; 
    	em[1084] = 120; em[1085] = 80; 
    	em[1086] = 1101; em[1087] = 88; 
    	em[1088] = 1104; em[1089] = 96; 
    	em[1090] = 1107; em[1091] = 104; 
    em[1092] = 8884097; em[1093] = 8; em[1094] = 0; /* 1092: pointer.func */
    em[1095] = 8884097; em[1096] = 8; em[1097] = 0; /* 1095: pointer.func */
    em[1098] = 8884097; em[1099] = 8; em[1100] = 0; /* 1098: pointer.func */
    em[1101] = 8884097; em[1102] = 8; em[1103] = 0; /* 1101: pointer.func */
    em[1104] = 8884097; em[1105] = 8; em[1106] = 0; /* 1104: pointer.func */
    em[1107] = 8884097; em[1108] = 8; em[1109] = 0; /* 1107: pointer.func */
    em[1110] = 1; em[1111] = 8; em[1112] = 1; /* 1110: pointer.struct.dsa_method */
    	em[1113] = 1115; em[1114] = 0; 
    em[1115] = 0; em[1116] = 96; em[1117] = 11; /* 1115: struct.dsa_method */
    	em[1118] = 144; em[1119] = 0; 
    	em[1120] = 1140; em[1121] = 8; 
    	em[1122] = 1143; em[1123] = 16; 
    	em[1124] = 1146; em[1125] = 24; 
    	em[1126] = 1149; em[1127] = 32; 
    	em[1128] = 1152; em[1129] = 40; 
    	em[1130] = 1155; em[1131] = 48; 
    	em[1132] = 1155; em[1133] = 56; 
    	em[1134] = 120; em[1135] = 72; 
    	em[1136] = 1158; em[1137] = 80; 
    	em[1138] = 1155; em[1139] = 88; 
    em[1140] = 8884097; em[1141] = 8; em[1142] = 0; /* 1140: pointer.func */
    em[1143] = 8884097; em[1144] = 8; em[1145] = 0; /* 1143: pointer.func */
    em[1146] = 8884097; em[1147] = 8; em[1148] = 0; /* 1146: pointer.func */
    em[1149] = 8884097; em[1150] = 8; em[1151] = 0; /* 1149: pointer.func */
    em[1152] = 8884097; em[1153] = 8; em[1154] = 0; /* 1152: pointer.func */
    em[1155] = 8884097; em[1156] = 8; em[1157] = 0; /* 1155: pointer.func */
    em[1158] = 8884097; em[1159] = 8; em[1160] = 0; /* 1158: pointer.func */
    em[1161] = 1; em[1162] = 8; em[1163] = 1; /* 1161: pointer.struct.dh_method */
    	em[1164] = 1166; em[1165] = 0; 
    em[1166] = 0; em[1167] = 72; em[1168] = 8; /* 1166: struct.dh_method */
    	em[1169] = 144; em[1170] = 0; 
    	em[1171] = 1185; em[1172] = 8; 
    	em[1173] = 1188; em[1174] = 16; 
    	em[1175] = 1191; em[1176] = 24; 
    	em[1177] = 1185; em[1178] = 32; 
    	em[1179] = 1185; em[1180] = 40; 
    	em[1181] = 120; em[1182] = 56; 
    	em[1183] = 1194; em[1184] = 64; 
    em[1185] = 8884097; em[1186] = 8; em[1187] = 0; /* 1185: pointer.func */
    em[1188] = 8884097; em[1189] = 8; em[1190] = 0; /* 1188: pointer.func */
    em[1191] = 8884097; em[1192] = 8; em[1193] = 0; /* 1191: pointer.func */
    em[1194] = 8884097; em[1195] = 8; em[1196] = 0; /* 1194: pointer.func */
    em[1197] = 1; em[1198] = 8; em[1199] = 1; /* 1197: pointer.struct.ecdh_method */
    	em[1200] = 1202; em[1201] = 0; 
    em[1202] = 0; em[1203] = 32; em[1204] = 3; /* 1202: struct.ecdh_method */
    	em[1205] = 144; em[1206] = 0; 
    	em[1207] = 1211; em[1208] = 8; 
    	em[1209] = 120; em[1210] = 24; 
    em[1211] = 8884097; em[1212] = 8; em[1213] = 0; /* 1211: pointer.func */
    em[1214] = 1; em[1215] = 8; em[1216] = 1; /* 1214: pointer.struct.ecdsa_method */
    	em[1217] = 1219; em[1218] = 0; 
    em[1219] = 0; em[1220] = 48; em[1221] = 5; /* 1219: struct.ecdsa_method */
    	em[1222] = 144; em[1223] = 0; 
    	em[1224] = 1232; em[1225] = 8; 
    	em[1226] = 1235; em[1227] = 16; 
    	em[1228] = 1238; em[1229] = 24; 
    	em[1230] = 120; em[1231] = 40; 
    em[1232] = 8884097; em[1233] = 8; em[1234] = 0; /* 1232: pointer.func */
    em[1235] = 8884097; em[1236] = 8; em[1237] = 0; /* 1235: pointer.func */
    em[1238] = 8884097; em[1239] = 8; em[1240] = 0; /* 1238: pointer.func */
    em[1241] = 1; em[1242] = 8; em[1243] = 1; /* 1241: pointer.struct.rand_meth_st */
    	em[1244] = 1246; em[1245] = 0; 
    em[1246] = 0; em[1247] = 48; em[1248] = 6; /* 1246: struct.rand_meth_st */
    	em[1249] = 1261; em[1250] = 0; 
    	em[1251] = 1264; em[1252] = 8; 
    	em[1253] = 1267; em[1254] = 16; 
    	em[1255] = 1270; em[1256] = 24; 
    	em[1257] = 1264; em[1258] = 32; 
    	em[1259] = 1273; em[1260] = 40; 
    em[1261] = 8884097; em[1262] = 8; em[1263] = 0; /* 1261: pointer.func */
    em[1264] = 8884097; em[1265] = 8; em[1266] = 0; /* 1264: pointer.func */
    em[1267] = 8884097; em[1268] = 8; em[1269] = 0; /* 1267: pointer.func */
    em[1270] = 8884097; em[1271] = 8; em[1272] = 0; /* 1270: pointer.func */
    em[1273] = 8884097; em[1274] = 8; em[1275] = 0; /* 1273: pointer.func */
    em[1276] = 1; em[1277] = 8; em[1278] = 1; /* 1276: pointer.struct.store_method_st */
    	em[1279] = 1281; em[1280] = 0; 
    em[1281] = 0; em[1282] = 0; em[1283] = 0; /* 1281: struct.store_method_st */
    em[1284] = 8884097; em[1285] = 8; em[1286] = 0; /* 1284: pointer.func */
    em[1287] = 8884097; em[1288] = 8; em[1289] = 0; /* 1287: pointer.func */
    em[1290] = 8884097; em[1291] = 8; em[1292] = 0; /* 1290: pointer.func */
    em[1293] = 8884097; em[1294] = 8; em[1295] = 0; /* 1293: pointer.func */
    em[1296] = 8884097; em[1297] = 8; em[1298] = 0; /* 1296: pointer.func */
    em[1299] = 8884097; em[1300] = 8; em[1301] = 0; /* 1299: pointer.func */
    em[1302] = 8884097; em[1303] = 8; em[1304] = 0; /* 1302: pointer.func */
    em[1305] = 8884097; em[1306] = 8; em[1307] = 0; /* 1305: pointer.func */
    em[1308] = 1; em[1309] = 8; em[1310] = 1; /* 1308: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[1311] = 1313; em[1312] = 0; 
    em[1313] = 0; em[1314] = 32; em[1315] = 2; /* 1313: struct.ENGINE_CMD_DEFN_st */
    	em[1316] = 144; em[1317] = 8; 
    	em[1318] = 144; em[1319] = 16; 
    em[1320] = 0; em[1321] = 32; em[1322] = 2; /* 1320: struct.crypto_ex_data_st_fake */
    	em[1323] = 1327; em[1324] = 8; 
    	em[1325] = 363; em[1326] = 24; 
    em[1327] = 8884099; em[1328] = 8; em[1329] = 2; /* 1327: pointer_to_array_of_pointers_to_stack */
    	em[1330] = 841; em[1331] = 0; 
    	em[1332] = 5; em[1333] = 20; 
    em[1334] = 1; em[1335] = 8; em[1336] = 1; /* 1334: pointer.struct.engine_st */
    	em[1337] = 1007; em[1338] = 0; 
    em[1339] = 1; em[1340] = 8; em[1341] = 1; /* 1339: pointer.struct.bignum_st */
    	em[1342] = 898; em[1343] = 0; 
    em[1344] = 0; em[1345] = 32; em[1346] = 2; /* 1344: struct.crypto_ex_data_st_fake */
    	em[1347] = 1351; em[1348] = 8; 
    	em[1349] = 363; em[1350] = 24; 
    em[1351] = 8884099; em[1352] = 8; em[1353] = 2; /* 1351: pointer_to_array_of_pointers_to_stack */
    	em[1354] = 841; em[1355] = 0; 
    	em[1356] = 5; em[1357] = 20; 
    em[1358] = 1; em[1359] = 8; em[1360] = 1; /* 1358: pointer.struct.bn_mont_ctx_st */
    	em[1361] = 1363; em[1362] = 0; 
    em[1363] = 0; em[1364] = 96; em[1365] = 3; /* 1363: struct.bn_mont_ctx_st */
    	em[1366] = 898; em[1367] = 8; 
    	em[1368] = 898; em[1369] = 32; 
    	em[1370] = 898; em[1371] = 56; 
    em[1372] = 1; em[1373] = 8; em[1374] = 1; /* 1372: pointer.struct.bn_blinding_st */
    	em[1375] = 1377; em[1376] = 0; 
    em[1377] = 0; em[1378] = 88; em[1379] = 7; /* 1377: struct.bn_blinding_st */
    	em[1380] = 1394; em[1381] = 0; 
    	em[1382] = 1394; em[1383] = 8; 
    	em[1384] = 1394; em[1385] = 16; 
    	em[1386] = 1394; em[1387] = 24; 
    	em[1388] = 1411; em[1389] = 40; 
    	em[1390] = 1416; em[1391] = 72; 
    	em[1392] = 1430; em[1393] = 80; 
    em[1394] = 1; em[1395] = 8; em[1396] = 1; /* 1394: pointer.struct.bignum_st */
    	em[1397] = 1399; em[1398] = 0; 
    em[1399] = 0; em[1400] = 24; em[1401] = 1; /* 1399: struct.bignum_st */
    	em[1402] = 1404; em[1403] = 0; 
    em[1404] = 8884099; em[1405] = 8; em[1406] = 2; /* 1404: pointer_to_array_of_pointers_to_stack */
    	em[1407] = 803; em[1408] = 0; 
    	em[1409] = 5; em[1410] = 12; 
    em[1411] = 0; em[1412] = 16; em[1413] = 1; /* 1411: struct.crypto_threadid_st */
    	em[1414] = 841; em[1415] = 0; 
    em[1416] = 1; em[1417] = 8; em[1418] = 1; /* 1416: pointer.struct.bn_mont_ctx_st */
    	em[1419] = 1421; em[1420] = 0; 
    em[1421] = 0; em[1422] = 96; em[1423] = 3; /* 1421: struct.bn_mont_ctx_st */
    	em[1424] = 1399; em[1425] = 8; 
    	em[1426] = 1399; em[1427] = 32; 
    	em[1428] = 1399; em[1429] = 56; 
    em[1430] = 8884097; em[1431] = 8; em[1432] = 0; /* 1430: pointer.func */
    em[1433] = 8884101; em[1434] = 8; em[1435] = 6; /* 1433: union.union_of_evp_pkey_st */
    	em[1436] = 841; em[1437] = 0; 
    	em[1438] = 1448; em[1439] = 6; 
    	em[1440] = 1453; em[1441] = 116; 
    	em[1442] = 1584; em[1443] = 28; 
    	em[1444] = 386; em[1445] = 408; 
    	em[1446] = 5; em[1447] = 0; 
    em[1448] = 1; em[1449] = 8; em[1450] = 1; /* 1448: pointer.struct.rsa_st */
    	em[1451] = 960; em[1452] = 0; 
    em[1453] = 1; em[1454] = 8; em[1455] = 1; /* 1453: pointer.struct.dsa_st */
    	em[1456] = 1458; em[1457] = 0; 
    em[1458] = 0; em[1459] = 136; em[1460] = 11; /* 1458: struct.dsa_st */
    	em[1461] = 1483; em[1462] = 24; 
    	em[1463] = 1483; em[1464] = 32; 
    	em[1465] = 1483; em[1466] = 40; 
    	em[1467] = 1483; em[1468] = 48; 
    	em[1469] = 1483; em[1470] = 56; 
    	em[1471] = 1483; em[1472] = 64; 
    	em[1473] = 1483; em[1474] = 72; 
    	em[1475] = 1500; em[1476] = 88; 
    	em[1477] = 1514; em[1478] = 104; 
    	em[1479] = 1528; em[1480] = 120; 
    	em[1481] = 1579; em[1482] = 128; 
    em[1483] = 1; em[1484] = 8; em[1485] = 1; /* 1483: pointer.struct.bignum_st */
    	em[1486] = 1488; em[1487] = 0; 
    em[1488] = 0; em[1489] = 24; em[1490] = 1; /* 1488: struct.bignum_st */
    	em[1491] = 1493; em[1492] = 0; 
    em[1493] = 8884099; em[1494] = 8; em[1495] = 2; /* 1493: pointer_to_array_of_pointers_to_stack */
    	em[1496] = 803; em[1497] = 0; 
    	em[1498] = 5; em[1499] = 12; 
    em[1500] = 1; em[1501] = 8; em[1502] = 1; /* 1500: pointer.struct.bn_mont_ctx_st */
    	em[1503] = 1505; em[1504] = 0; 
    em[1505] = 0; em[1506] = 96; em[1507] = 3; /* 1505: struct.bn_mont_ctx_st */
    	em[1508] = 1488; em[1509] = 8; 
    	em[1510] = 1488; em[1511] = 32; 
    	em[1512] = 1488; em[1513] = 56; 
    em[1514] = 0; em[1515] = 32; em[1516] = 2; /* 1514: struct.crypto_ex_data_st_fake */
    	em[1517] = 1521; em[1518] = 8; 
    	em[1519] = 363; em[1520] = 24; 
    em[1521] = 8884099; em[1522] = 8; em[1523] = 2; /* 1521: pointer_to_array_of_pointers_to_stack */
    	em[1524] = 841; em[1525] = 0; 
    	em[1526] = 5; em[1527] = 20; 
    em[1528] = 1; em[1529] = 8; em[1530] = 1; /* 1528: pointer.struct.dsa_method */
    	em[1531] = 1533; em[1532] = 0; 
    em[1533] = 0; em[1534] = 96; em[1535] = 11; /* 1533: struct.dsa_method */
    	em[1536] = 144; em[1537] = 0; 
    	em[1538] = 1558; em[1539] = 8; 
    	em[1540] = 1561; em[1541] = 16; 
    	em[1542] = 1564; em[1543] = 24; 
    	em[1544] = 1567; em[1545] = 32; 
    	em[1546] = 1570; em[1547] = 40; 
    	em[1548] = 1573; em[1549] = 48; 
    	em[1550] = 1573; em[1551] = 56; 
    	em[1552] = 120; em[1553] = 72; 
    	em[1554] = 1576; em[1555] = 80; 
    	em[1556] = 1573; em[1557] = 88; 
    em[1558] = 8884097; em[1559] = 8; em[1560] = 0; /* 1558: pointer.func */
    em[1561] = 8884097; em[1562] = 8; em[1563] = 0; /* 1561: pointer.func */
    em[1564] = 8884097; em[1565] = 8; em[1566] = 0; /* 1564: pointer.func */
    em[1567] = 8884097; em[1568] = 8; em[1569] = 0; /* 1567: pointer.func */
    em[1570] = 8884097; em[1571] = 8; em[1572] = 0; /* 1570: pointer.func */
    em[1573] = 8884097; em[1574] = 8; em[1575] = 0; /* 1573: pointer.func */
    em[1576] = 8884097; em[1577] = 8; em[1578] = 0; /* 1576: pointer.func */
    em[1579] = 1; em[1580] = 8; em[1581] = 1; /* 1579: pointer.struct.engine_st */
    	em[1582] = 1007; em[1583] = 0; 
    em[1584] = 1; em[1585] = 8; em[1586] = 1; /* 1584: pointer.struct.dh_st */
    	em[1587] = 1589; em[1588] = 0; 
    em[1589] = 0; em[1590] = 144; em[1591] = 12; /* 1589: struct.dh_st */
    	em[1592] = 1616; em[1593] = 8; 
    	em[1594] = 1616; em[1595] = 16; 
    	em[1596] = 1616; em[1597] = 32; 
    	em[1598] = 1616; em[1599] = 40; 
    	em[1600] = 1633; em[1601] = 56; 
    	em[1602] = 1616; em[1603] = 64; 
    	em[1604] = 1616; em[1605] = 72; 
    	em[1606] = 29; em[1607] = 80; 
    	em[1608] = 1616; em[1609] = 96; 
    	em[1610] = 1647; em[1611] = 112; 
    	em[1612] = 1661; em[1613] = 128; 
    	em[1614] = 1697; em[1615] = 136; 
    em[1616] = 1; em[1617] = 8; em[1618] = 1; /* 1616: pointer.struct.bignum_st */
    	em[1619] = 1621; em[1620] = 0; 
    em[1621] = 0; em[1622] = 24; em[1623] = 1; /* 1621: struct.bignum_st */
    	em[1624] = 1626; em[1625] = 0; 
    em[1626] = 8884099; em[1627] = 8; em[1628] = 2; /* 1626: pointer_to_array_of_pointers_to_stack */
    	em[1629] = 803; em[1630] = 0; 
    	em[1631] = 5; em[1632] = 12; 
    em[1633] = 1; em[1634] = 8; em[1635] = 1; /* 1633: pointer.struct.bn_mont_ctx_st */
    	em[1636] = 1638; em[1637] = 0; 
    em[1638] = 0; em[1639] = 96; em[1640] = 3; /* 1638: struct.bn_mont_ctx_st */
    	em[1641] = 1621; em[1642] = 8; 
    	em[1643] = 1621; em[1644] = 32; 
    	em[1645] = 1621; em[1646] = 56; 
    em[1647] = 0; em[1648] = 32; em[1649] = 2; /* 1647: struct.crypto_ex_data_st_fake */
    	em[1650] = 1654; em[1651] = 8; 
    	em[1652] = 363; em[1653] = 24; 
    em[1654] = 8884099; em[1655] = 8; em[1656] = 2; /* 1654: pointer_to_array_of_pointers_to_stack */
    	em[1657] = 841; em[1658] = 0; 
    	em[1659] = 5; em[1660] = 20; 
    em[1661] = 1; em[1662] = 8; em[1663] = 1; /* 1661: pointer.struct.dh_method */
    	em[1664] = 1666; em[1665] = 0; 
    em[1666] = 0; em[1667] = 72; em[1668] = 8; /* 1666: struct.dh_method */
    	em[1669] = 144; em[1670] = 0; 
    	em[1671] = 1685; em[1672] = 8; 
    	em[1673] = 1688; em[1674] = 16; 
    	em[1675] = 1691; em[1676] = 24; 
    	em[1677] = 1685; em[1678] = 32; 
    	em[1679] = 1685; em[1680] = 40; 
    	em[1681] = 120; em[1682] = 56; 
    	em[1683] = 1694; em[1684] = 64; 
    em[1685] = 8884097; em[1686] = 8; em[1687] = 0; /* 1685: pointer.func */
    em[1688] = 8884097; em[1689] = 8; em[1690] = 0; /* 1688: pointer.func */
    em[1691] = 8884097; em[1692] = 8; em[1693] = 0; /* 1691: pointer.func */
    em[1694] = 8884097; em[1695] = 8; em[1696] = 0; /* 1694: pointer.func */
    em[1697] = 1; em[1698] = 8; em[1699] = 1; /* 1697: pointer.struct.engine_st */
    	em[1700] = 1007; em[1701] = 0; 
    em[1702] = 8884097; em[1703] = 8; em[1704] = 0; /* 1702: pointer.func */
    em[1705] = 8884097; em[1706] = 8; em[1707] = 0; /* 1705: pointer.func */
    em[1708] = 1; em[1709] = 8; em[1710] = 1; /* 1708: pointer.struct.evp_pkey_asn1_method_st */
    	em[1711] = 1713; em[1712] = 0; 
    em[1713] = 0; em[1714] = 208; em[1715] = 24; /* 1713: struct.evp_pkey_asn1_method_st */
    	em[1716] = 120; em[1717] = 16; 
    	em[1718] = 120; em[1719] = 24; 
    	em[1720] = 1705; em[1721] = 32; 
    	em[1722] = 1764; em[1723] = 40; 
    	em[1724] = 1767; em[1725] = 48; 
    	em[1726] = 1770; em[1727] = 56; 
    	em[1728] = 1773; em[1729] = 64; 
    	em[1730] = 1776; em[1731] = 72; 
    	em[1732] = 1770; em[1733] = 80; 
    	em[1734] = 1779; em[1735] = 88; 
    	em[1736] = 1779; em[1737] = 96; 
    	em[1738] = 1702; em[1739] = 104; 
    	em[1740] = 1782; em[1741] = 112; 
    	em[1742] = 1779; em[1743] = 120; 
    	em[1744] = 1785; em[1745] = 128; 
    	em[1746] = 1767; em[1747] = 136; 
    	em[1748] = 1770; em[1749] = 144; 
    	em[1750] = 1788; em[1751] = 152; 
    	em[1752] = 1791; em[1753] = 160; 
    	em[1754] = 1794; em[1755] = 168; 
    	em[1756] = 1702; em[1757] = 176; 
    	em[1758] = 1782; em[1759] = 184; 
    	em[1760] = 1797; em[1761] = 192; 
    	em[1762] = 1800; em[1763] = 200; 
    em[1764] = 8884097; em[1765] = 8; em[1766] = 0; /* 1764: pointer.func */
    em[1767] = 8884097; em[1768] = 8; em[1769] = 0; /* 1767: pointer.func */
    em[1770] = 8884097; em[1771] = 8; em[1772] = 0; /* 1770: pointer.func */
    em[1773] = 8884097; em[1774] = 8; em[1775] = 0; /* 1773: pointer.func */
    em[1776] = 8884097; em[1777] = 8; em[1778] = 0; /* 1776: pointer.func */
    em[1779] = 8884097; em[1780] = 8; em[1781] = 0; /* 1779: pointer.func */
    em[1782] = 8884097; em[1783] = 8; em[1784] = 0; /* 1782: pointer.func */
    em[1785] = 8884097; em[1786] = 8; em[1787] = 0; /* 1785: pointer.func */
    em[1788] = 8884097; em[1789] = 8; em[1790] = 0; /* 1788: pointer.func */
    em[1791] = 8884097; em[1792] = 8; em[1793] = 0; /* 1791: pointer.func */
    em[1794] = 8884097; em[1795] = 8; em[1796] = 0; /* 1794: pointer.func */
    em[1797] = 8884097; em[1798] = 8; em[1799] = 0; /* 1797: pointer.func */
    em[1800] = 8884097; em[1801] = 8; em[1802] = 0; /* 1800: pointer.func */
    em[1803] = 8884097; em[1804] = 8; em[1805] = 0; /* 1803: pointer.func */
    em[1806] = 0; em[1807] = 1; em[1808] = 0; /* 1806: char */
    em[1809] = 8884097; em[1810] = 8; em[1811] = 0; /* 1809: pointer.func */
    em[1812] = 8884097; em[1813] = 8; em[1814] = 0; /* 1812: pointer.func */
    em[1815] = 8884097; em[1816] = 8; em[1817] = 0; /* 1815: pointer.func */
    em[1818] = 8884097; em[1819] = 8; em[1820] = 0; /* 1818: pointer.func */
    em[1821] = 8884097; em[1822] = 8; em[1823] = 0; /* 1821: pointer.func */
    em[1824] = 1; em[1825] = 8; em[1826] = 1; /* 1824: pointer.struct.evp_pkey_method_st */
    	em[1827] = 1829; em[1828] = 0; 
    em[1829] = 0; em[1830] = 208; em[1831] = 25; /* 1829: struct.evp_pkey_method_st */
    	em[1832] = 1815; em[1833] = 8; 
    	em[1834] = 1882; em[1835] = 16; 
    	em[1836] = 1885; em[1837] = 24; 
    	em[1838] = 1815; em[1839] = 32; 
    	em[1840] = 1821; em[1841] = 40; 
    	em[1842] = 1815; em[1843] = 48; 
    	em[1844] = 1821; em[1845] = 56; 
    	em[1846] = 1815; em[1847] = 64; 
    	em[1848] = 1888; em[1849] = 72; 
    	em[1850] = 1815; em[1851] = 80; 
    	em[1852] = 1891; em[1853] = 88; 
    	em[1854] = 1815; em[1855] = 96; 
    	em[1856] = 1888; em[1857] = 104; 
    	em[1858] = 1894; em[1859] = 112; 
    	em[1860] = 1812; em[1861] = 120; 
    	em[1862] = 1894; em[1863] = 128; 
    	em[1864] = 1897; em[1865] = 136; 
    	em[1866] = 1815; em[1867] = 144; 
    	em[1868] = 1888; em[1869] = 152; 
    	em[1870] = 1815; em[1871] = 160; 
    	em[1872] = 1888; em[1873] = 168; 
    	em[1874] = 1815; em[1875] = 176; 
    	em[1876] = 1809; em[1877] = 184; 
    	em[1878] = 1900; em[1879] = 192; 
    	em[1880] = 1803; em[1881] = 200; 
    em[1882] = 8884097; em[1883] = 8; em[1884] = 0; /* 1882: pointer.func */
    em[1885] = 8884097; em[1886] = 8; em[1887] = 0; /* 1885: pointer.func */
    em[1888] = 8884097; em[1889] = 8; em[1890] = 0; /* 1888: pointer.func */
    em[1891] = 8884097; em[1892] = 8; em[1893] = 0; /* 1891: pointer.func */
    em[1894] = 8884097; em[1895] = 8; em[1896] = 0; /* 1894: pointer.func */
    em[1897] = 8884097; em[1898] = 8; em[1899] = 0; /* 1897: pointer.func */
    em[1900] = 8884097; em[1901] = 8; em[1902] = 0; /* 1900: pointer.func */
    em[1903] = 8884097; em[1904] = 8; em[1905] = 0; /* 1903: pointer.func */
    em[1906] = 0; em[1907] = 48; em[1908] = 5; /* 1906: struct.env_md_ctx_st */
    	em[1909] = 1919; em[1910] = 0; 
    	em[1911] = 1958; em[1912] = 8; 
    	em[1913] = 841; em[1914] = 24; 
    	em[1915] = 1963; em[1916] = 32; 
    	em[1917] = 1946; em[1918] = 40; 
    em[1919] = 1; em[1920] = 8; em[1921] = 1; /* 1919: pointer.struct.env_md_st */
    	em[1922] = 1924; em[1923] = 0; 
    em[1924] = 0; em[1925] = 120; em[1926] = 8; /* 1924: struct.env_md_st */
    	em[1927] = 1943; em[1928] = 24; 
    	em[1929] = 1946; em[1930] = 32; 
    	em[1931] = 1949; em[1932] = 40; 
    	em[1933] = 1952; em[1934] = 48; 
    	em[1935] = 1943; em[1936] = 56; 
    	em[1937] = 1955; em[1938] = 64; 
    	em[1939] = 1818; em[1940] = 72; 
    	em[1941] = 1903; em[1942] = 112; 
    em[1943] = 8884097; em[1944] = 8; em[1945] = 0; /* 1943: pointer.func */
    em[1946] = 8884097; em[1947] = 8; em[1948] = 0; /* 1946: pointer.func */
    em[1949] = 8884097; em[1950] = 8; em[1951] = 0; /* 1949: pointer.func */
    em[1952] = 8884097; em[1953] = 8; em[1954] = 0; /* 1952: pointer.func */
    em[1955] = 8884097; em[1956] = 8; em[1957] = 0; /* 1955: pointer.func */
    em[1958] = 1; em[1959] = 8; em[1960] = 1; /* 1958: pointer.struct.engine_st */
    	em[1961] = 1007; em[1962] = 0; 
    em[1963] = 1; em[1964] = 8; em[1965] = 1; /* 1963: pointer.struct.evp_pkey_ctx_st */
    	em[1966] = 1968; em[1967] = 0; 
    em[1968] = 0; em[1969] = 80; em[1970] = 8; /* 1968: struct.evp_pkey_ctx_st */
    	em[1971] = 1824; em[1972] = 0; 
    	em[1973] = 1697; em[1974] = 8; 
    	em[1975] = 1987; em[1976] = 16; 
    	em[1977] = 1987; em[1978] = 24; 
    	em[1979] = 841; em[1980] = 40; 
    	em[1981] = 841; em[1982] = 48; 
    	em[1983] = 8; em[1984] = 56; 
    	em[1985] = 0; em[1986] = 64; 
    em[1987] = 1; em[1988] = 8; em[1989] = 1; /* 1987: pointer.struct.evp_pkey_st */
    	em[1990] = 1992; em[1991] = 0; 
    em[1992] = 0; em[1993] = 56; em[1994] = 4; /* 1992: struct.evp_pkey_st */
    	em[1995] = 1708; em[1996] = 16; 
    	em[1997] = 1697; em[1998] = 24; 
    	em[1999] = 1433; em[2000] = 32; 
    	em[2001] = 2003; em[2002] = 48; 
    em[2003] = 1; em[2004] = 8; em[2005] = 1; /* 2003: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[2006] = 2008; em[2007] = 0; 
    em[2008] = 0; em[2009] = 32; em[2010] = 2; /* 2008: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[2011] = 2015; em[2012] = 8; 
    	em[2013] = 363; em[2014] = 24; 
    em[2015] = 8884099; em[2016] = 8; em[2017] = 2; /* 2015: pointer_to_array_of_pointers_to_stack */
    	em[2018] = 2022; em[2019] = 0; 
    	em[2020] = 5; em[2021] = 20; 
    em[2022] = 0; em[2023] = 8; em[2024] = 1; /* 2022: pointer.X509_ATTRIBUTE */
    	em[2025] = 2027; em[2026] = 0; 
    em[2027] = 0; em[2028] = 0; em[2029] = 1; /* 2027: X509_ATTRIBUTE */
    	em[2030] = 2032; em[2031] = 0; 
    em[2032] = 0; em[2033] = 24; em[2034] = 2; /* 2032: struct.x509_attributes_st */
    	em[2035] = 130; em[2036] = 0; 
    	em[2037] = 366; em[2038] = 16; 
    em[2039] = 1; em[2040] = 8; em[2041] = 1; /* 2039: pointer.struct.hmac_ctx_st */
    	em[2042] = 2044; em[2043] = 0; 
    em[2044] = 0; em[2045] = 288; em[2046] = 4; /* 2044: struct.hmac_ctx_st */
    	em[2047] = 1919; em[2048] = 0; 
    	em[2049] = 1906; em[2050] = 8; 
    	em[2051] = 1906; em[2052] = 56; 
    	em[2053] = 1906; em[2054] = 104; 
    args_addr->arg_entity_index[0] = 2039;
    args_addr->arg_entity_index[1] = 841;
    args_addr->arg_entity_index[2] = 5;
    args_addr->arg_entity_index[3] = 1919;
    args_addr->arg_entity_index[4] = 1958;
    args_addr->ret_entity_index = 5;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_arg(args_addr, arg_e);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    HMAC_CTX * new_arg_a = *((HMAC_CTX * *)new_args->args[0]);

    const void * new_arg_b = *((const void * *)new_args->args[1]);

    int new_arg_c = *((int *)new_args->args[2]);

    const EVP_MD * new_arg_d = *((const EVP_MD * *)new_args->args[3]);

    ENGINE * new_arg_e = *((ENGINE * *)new_args->args[4]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_HMAC_Init_ex)(HMAC_CTX *,const void *,int,const EVP_MD *,ENGINE *);
    orig_HMAC_Init_ex = dlsym(RTLD_NEXT, "HMAC_Init_ex");
    *new_ret_ptr = (*orig_HMAC_Init_ex)(new_arg_a,new_arg_b,new_arg_c,new_arg_d,new_arg_e);

    syscall(889);

    free(args_addr);

    return ret;
}

