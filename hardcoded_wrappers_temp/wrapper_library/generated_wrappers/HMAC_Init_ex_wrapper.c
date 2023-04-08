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
    	em[222] = 149; em[223] = 0; 
    	em[224] = 149; em[225] = 8; 
    	em[226] = 154; em[227] = 24; 
    em[228] = 1; em[229] = 8; em[230] = 1; /* 228: pointer.struct.asn1_object_st */
    	em[231] = 219; em[232] = 0; 
    em[233] = 1; em[234] = 8; em[235] = 1; /* 233: pointer.struct.asn1_string_st */
    	em[236] = 189; em[237] = 0; 
    em[238] = 0; em[239] = 0; em[240] = 1; /* 238: ASN1_TYPE */
    	em[241] = 243; em[242] = 0; 
    em[243] = 0; em[244] = 16; em[245] = 1; /* 243: struct.asn1_type_st */
    	em[246] = 248; em[247] = 8; 
    em[248] = 0; em[249] = 8; em[250] = 20; /* 248: union.unknown */
    	em[251] = 125; em[252] = 0; 
    	em[253] = 233; em[254] = 0; 
    	em[255] = 228; em[256] = 0; 
    	em[257] = 214; em[258] = 0; 
    	em[259] = 209; em[260] = 0; 
    	em[261] = 204; em[262] = 0; 
    	em[263] = 291; em[264] = 0; 
    	em[265] = 296; em[266] = 0; 
    	em[267] = 199; em[268] = 0; 
    	em[269] = 194; em[270] = 0; 
    	em[271] = 301; em[272] = 0; 
    	em[273] = 306; em[274] = 0; 
    	em[275] = 311; em[276] = 0; 
    	em[277] = 316; em[278] = 0; 
    	em[279] = 321; em[280] = 0; 
    	em[281] = 326; em[282] = 0; 
    	em[283] = 184; em[284] = 0; 
    	em[285] = 233; em[286] = 0; 
    	em[287] = 233; em[288] = 0; 
    	em[289] = 331; em[290] = 0; 
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
    	em[361] = 238; em[362] = 0; 
    em[363] = 8884097; em[364] = 8; em[365] = 0; /* 363: pointer.func */
    em[366] = 0; em[367] = 8; em[368] = 3; /* 366: union.unknown */
    	em[369] = 125; em[370] = 0; 
    	em[371] = 339; em[372] = 0; 
    	em[373] = 375; em[374] = 0; 
    em[375] = 1; em[376] = 8; em[377] = 1; /* 375: pointer.struct.asn1_type_st */
    	em[378] = 179; em[379] = 0; 
    em[380] = 0; em[381] = 8; em[382] = 0; /* 380: long unsigned int */
    em[383] = 8884097; em[384] = 8; em[385] = 0; /* 383: pointer.func */
    em[386] = 8884097; em[387] = 8; em[388] = 0; /* 386: pointer.func */
    em[389] = 1; em[390] = 8; em[391] = 1; /* 389: pointer.struct.ec_key_st */
    	em[392] = 394; em[393] = 0; 
    em[394] = 0; em[395] = 56; em[396] = 4; /* 394: struct.ec_key_st */
    	em[397] = 405; em[398] = 8; 
    	em[399] = 853; em[400] = 16; 
    	em[401] = 858; em[402] = 24; 
    	em[403] = 875; em[404] = 48; 
    em[405] = 1; em[406] = 8; em[407] = 1; /* 405: pointer.struct.ec_group_st */
    	em[408] = 410; em[409] = 0; 
    em[410] = 0; em[411] = 232; em[412] = 12; /* 410: struct.ec_group_st */
    	em[413] = 437; em[414] = 0; 
    	em[415] = 606; em[416] = 8; 
    	em[417] = 806; em[418] = 16; 
    	em[419] = 806; em[420] = 40; 
    	em[421] = 29; em[422] = 80; 
    	em[423] = 818; em[424] = 96; 
    	em[425] = 806; em[426] = 104; 
    	em[427] = 806; em[428] = 152; 
    	em[429] = 806; em[430] = 176; 
    	em[431] = 841; em[432] = 208; 
    	em[433] = 841; em[434] = 216; 
    	em[435] = 850; em[436] = 224; 
    em[437] = 1; em[438] = 8; em[439] = 1; /* 437: pointer.struct.ec_method_st */
    	em[440] = 442; em[441] = 0; 
    em[442] = 0; em[443] = 304; em[444] = 37; /* 442: struct.ec_method_st */
    	em[445] = 519; em[446] = 8; 
    	em[447] = 522; em[448] = 16; 
    	em[449] = 522; em[450] = 24; 
    	em[451] = 525; em[452] = 32; 
    	em[453] = 383; em[454] = 40; 
    	em[455] = 528; em[456] = 48; 
    	em[457] = 531; em[458] = 56; 
    	em[459] = 534; em[460] = 64; 
    	em[461] = 537; em[462] = 72; 
    	em[463] = 540; em[464] = 80; 
    	em[465] = 540; em[466] = 88; 
    	em[467] = 543; em[468] = 96; 
    	em[469] = 546; em[470] = 104; 
    	em[471] = 549; em[472] = 112; 
    	em[473] = 552; em[474] = 120; 
    	em[475] = 555; em[476] = 128; 
    	em[477] = 558; em[478] = 136; 
    	em[479] = 561; em[480] = 144; 
    	em[481] = 564; em[482] = 152; 
    	em[483] = 567; em[484] = 160; 
    	em[485] = 570; em[486] = 168; 
    	em[487] = 573; em[488] = 176; 
    	em[489] = 576; em[490] = 184; 
    	em[491] = 579; em[492] = 192; 
    	em[493] = 582; em[494] = 200; 
    	em[495] = 585; em[496] = 208; 
    	em[497] = 576; em[498] = 216; 
    	em[499] = 588; em[500] = 224; 
    	em[501] = 591; em[502] = 232; 
    	em[503] = 594; em[504] = 240; 
    	em[505] = 531; em[506] = 248; 
    	em[507] = 597; em[508] = 256; 
    	em[509] = 600; em[510] = 264; 
    	em[511] = 597; em[512] = 272; 
    	em[513] = 600; em[514] = 280; 
    	em[515] = 600; em[516] = 288; 
    	em[517] = 603; em[518] = 296; 
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
    em[603] = 8884097; em[604] = 8; em[605] = 0; /* 603: pointer.func */
    em[606] = 1; em[607] = 8; em[608] = 1; /* 606: pointer.struct.ec_point_st */
    	em[609] = 611; em[610] = 0; 
    em[611] = 0; em[612] = 88; em[613] = 4; /* 611: struct.ec_point_st */
    	em[614] = 622; em[615] = 0; 
    	em[616] = 794; em[617] = 8; 
    	em[618] = 794; em[619] = 32; 
    	em[620] = 794; em[621] = 56; 
    em[622] = 1; em[623] = 8; em[624] = 1; /* 622: pointer.struct.ec_method_st */
    	em[625] = 627; em[626] = 0; 
    em[627] = 0; em[628] = 304; em[629] = 37; /* 627: struct.ec_method_st */
    	em[630] = 704; em[631] = 8; 
    	em[632] = 707; em[633] = 16; 
    	em[634] = 707; em[635] = 24; 
    	em[636] = 710; em[637] = 32; 
    	em[638] = 713; em[639] = 40; 
    	em[640] = 716; em[641] = 48; 
    	em[642] = 719; em[643] = 56; 
    	em[644] = 722; em[645] = 64; 
    	em[646] = 725; em[647] = 72; 
    	em[648] = 728; em[649] = 80; 
    	em[650] = 728; em[651] = 88; 
    	em[652] = 731; em[653] = 96; 
    	em[654] = 734; em[655] = 104; 
    	em[656] = 737; em[657] = 112; 
    	em[658] = 740; em[659] = 120; 
    	em[660] = 743; em[661] = 128; 
    	em[662] = 746; em[663] = 136; 
    	em[664] = 749; em[665] = 144; 
    	em[666] = 752; em[667] = 152; 
    	em[668] = 755; em[669] = 160; 
    	em[670] = 758; em[671] = 168; 
    	em[672] = 761; em[673] = 176; 
    	em[674] = 764; em[675] = 184; 
    	em[676] = 767; em[677] = 192; 
    	em[678] = 770; em[679] = 200; 
    	em[680] = 773; em[681] = 208; 
    	em[682] = 764; em[683] = 216; 
    	em[684] = 776; em[685] = 224; 
    	em[686] = 779; em[687] = 232; 
    	em[688] = 782; em[689] = 240; 
    	em[690] = 719; em[691] = 248; 
    	em[692] = 785; em[693] = 256; 
    	em[694] = 788; em[695] = 264; 
    	em[696] = 785; em[697] = 272; 
    	em[698] = 788; em[699] = 280; 
    	em[700] = 788; em[701] = 288; 
    	em[702] = 791; em[703] = 296; 
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
    em[791] = 8884097; em[792] = 8; em[793] = 0; /* 791: pointer.func */
    em[794] = 0; em[795] = 24; em[796] = 1; /* 794: struct.bignum_st */
    	em[797] = 799; em[798] = 0; 
    em[799] = 8884099; em[800] = 8; em[801] = 2; /* 799: pointer_to_array_of_pointers_to_stack */
    	em[802] = 380; em[803] = 0; 
    	em[804] = 5; em[805] = 12; 
    em[806] = 0; em[807] = 24; em[808] = 1; /* 806: struct.bignum_st */
    	em[809] = 811; em[810] = 0; 
    em[811] = 8884099; em[812] = 8; em[813] = 2; /* 811: pointer_to_array_of_pointers_to_stack */
    	em[814] = 380; em[815] = 0; 
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
    	em[856] = 611; em[857] = 0; 
    em[858] = 1; em[859] = 8; em[860] = 1; /* 858: pointer.struct.bignum_st */
    	em[861] = 863; em[862] = 0; 
    em[863] = 0; em[864] = 24; em[865] = 1; /* 863: struct.bignum_st */
    	em[866] = 868; em[867] = 0; 
    em[868] = 8884099; em[869] = 8; em[870] = 2; /* 868: pointer_to_array_of_pointers_to_stack */
    	em[871] = 380; em[872] = 0; 
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
    em[898] = 1; em[899] = 8; em[900] = 1; /* 898: pointer.struct.bignum_st */
    	em[901] = 903; em[902] = 0; 
    em[903] = 0; em[904] = 24; em[905] = 1; /* 903: struct.bignum_st */
    	em[906] = 908; em[907] = 0; 
    em[908] = 8884099; em[909] = 8; em[910] = 2; /* 908: pointer_to_array_of_pointers_to_stack */
    	em[911] = 380; em[912] = 0; 
    	em[913] = 5; em[914] = 12; 
    em[915] = 8884097; em[916] = 8; em[917] = 0; /* 915: pointer.func */
    em[918] = 0; em[919] = 1; em[920] = 0; /* 918: char */
    em[921] = 8884097; em[922] = 8; em[923] = 0; /* 921: pointer.func */
    em[924] = 8884097; em[925] = 8; em[926] = 0; /* 924: pointer.func */
    em[927] = 8884097; em[928] = 8; em[929] = 0; /* 927: pointer.func */
    em[930] = 0; em[931] = 112; em[932] = 13; /* 930: struct.rsa_meth_st */
    	em[933] = 149; em[934] = 0; 
    	em[935] = 959; em[936] = 8; 
    	em[937] = 959; em[938] = 16; 
    	em[939] = 959; em[940] = 24; 
    	em[941] = 959; em[942] = 32; 
    	em[943] = 962; em[944] = 40; 
    	em[945] = 965; em[946] = 48; 
    	em[947] = 921; em[948] = 56; 
    	em[949] = 921; em[950] = 64; 
    	em[951] = 125; em[952] = 80; 
    	em[953] = 915; em[954] = 88; 
    	em[955] = 968; em[956] = 96; 
    	em[957] = 386; em[958] = 104; 
    em[959] = 8884097; em[960] = 8; em[961] = 0; /* 959: pointer.func */
    em[962] = 8884097; em[963] = 8; em[964] = 0; /* 962: pointer.func */
    em[965] = 8884097; em[966] = 8; em[967] = 0; /* 965: pointer.func */
    em[968] = 8884097; em[969] = 8; em[970] = 0; /* 968: pointer.func */
    em[971] = 0; em[972] = 168; em[973] = 17; /* 971: struct.rsa_st */
    	em[974] = 1008; em[975] = 16; 
    	em[976] = 1013; em[977] = 24; 
    	em[978] = 898; em[979] = 32; 
    	em[980] = 898; em[981] = 40; 
    	em[982] = 898; em[983] = 48; 
    	em[984] = 898; em[985] = 56; 
    	em[986] = 898; em[987] = 64; 
    	em[988] = 898; em[989] = 72; 
    	em[990] = 898; em[991] = 80; 
    	em[992] = 898; em[993] = 88; 
    	em[994] = 1347; em[995] = 96; 
    	em[996] = 1361; em[997] = 120; 
    	em[998] = 1361; em[999] = 128; 
    	em[1000] = 1361; em[1001] = 136; 
    	em[1002] = 125; em[1003] = 144; 
    	em[1004] = 1375; em[1005] = 152; 
    	em[1006] = 1375; em[1007] = 160; 
    em[1008] = 1; em[1009] = 8; em[1010] = 1; /* 1008: pointer.struct.rsa_meth_st */
    	em[1011] = 930; em[1012] = 0; 
    em[1013] = 1; em[1014] = 8; em[1015] = 1; /* 1013: pointer.struct.engine_st */
    	em[1016] = 1018; em[1017] = 0; 
    em[1018] = 0; em[1019] = 216; em[1020] = 24; /* 1018: struct.engine_st */
    	em[1021] = 149; em[1022] = 0; 
    	em[1023] = 149; em[1024] = 8; 
    	em[1025] = 1069; em[1026] = 16; 
    	em[1027] = 1121; em[1028] = 24; 
    	em[1029] = 1172; em[1030] = 32; 
    	em[1031] = 1205; em[1032] = 40; 
    	em[1033] = 1222; em[1034] = 48; 
    	em[1035] = 1249; em[1036] = 56; 
    	em[1037] = 1284; em[1038] = 64; 
    	em[1039] = 1292; em[1040] = 72; 
    	em[1041] = 1295; em[1042] = 80; 
    	em[1043] = 1298; em[1044] = 88; 
    	em[1045] = 1301; em[1046] = 96; 
    	em[1047] = 1304; em[1048] = 104; 
    	em[1049] = 1304; em[1050] = 112; 
    	em[1051] = 1304; em[1052] = 120; 
    	em[1053] = 1307; em[1054] = 128; 
    	em[1055] = 1310; em[1056] = 136; 
    	em[1057] = 1310; em[1058] = 144; 
    	em[1059] = 1313; em[1060] = 152; 
    	em[1061] = 1316; em[1062] = 160; 
    	em[1063] = 1328; em[1064] = 184; 
    	em[1065] = 1342; em[1066] = 200; 
    	em[1067] = 1342; em[1068] = 208; 
    em[1069] = 1; em[1070] = 8; em[1071] = 1; /* 1069: pointer.struct.rsa_meth_st */
    	em[1072] = 1074; em[1073] = 0; 
    em[1074] = 0; em[1075] = 112; em[1076] = 13; /* 1074: struct.rsa_meth_st */
    	em[1077] = 149; em[1078] = 0; 
    	em[1079] = 924; em[1080] = 8; 
    	em[1081] = 924; em[1082] = 16; 
    	em[1083] = 924; em[1084] = 24; 
    	em[1085] = 924; em[1086] = 32; 
    	em[1087] = 1103; em[1088] = 40; 
    	em[1089] = 1106; em[1090] = 48; 
    	em[1091] = 1109; em[1092] = 56; 
    	em[1093] = 1109; em[1094] = 64; 
    	em[1095] = 125; em[1096] = 80; 
    	em[1097] = 1112; em[1098] = 88; 
    	em[1099] = 1115; em[1100] = 96; 
    	em[1101] = 1118; em[1102] = 104; 
    em[1103] = 8884097; em[1104] = 8; em[1105] = 0; /* 1103: pointer.func */
    em[1106] = 8884097; em[1107] = 8; em[1108] = 0; /* 1106: pointer.func */
    em[1109] = 8884097; em[1110] = 8; em[1111] = 0; /* 1109: pointer.func */
    em[1112] = 8884097; em[1113] = 8; em[1114] = 0; /* 1112: pointer.func */
    em[1115] = 8884097; em[1116] = 8; em[1117] = 0; /* 1115: pointer.func */
    em[1118] = 8884097; em[1119] = 8; em[1120] = 0; /* 1118: pointer.func */
    em[1121] = 1; em[1122] = 8; em[1123] = 1; /* 1121: pointer.struct.dsa_method */
    	em[1124] = 1126; em[1125] = 0; 
    em[1126] = 0; em[1127] = 96; em[1128] = 11; /* 1126: struct.dsa_method */
    	em[1129] = 149; em[1130] = 0; 
    	em[1131] = 1151; em[1132] = 8; 
    	em[1133] = 1154; em[1134] = 16; 
    	em[1135] = 1157; em[1136] = 24; 
    	em[1137] = 1160; em[1138] = 32; 
    	em[1139] = 1163; em[1140] = 40; 
    	em[1141] = 1166; em[1142] = 48; 
    	em[1143] = 1166; em[1144] = 56; 
    	em[1145] = 125; em[1146] = 72; 
    	em[1147] = 1169; em[1148] = 80; 
    	em[1149] = 1166; em[1150] = 88; 
    em[1151] = 8884097; em[1152] = 8; em[1153] = 0; /* 1151: pointer.func */
    em[1154] = 8884097; em[1155] = 8; em[1156] = 0; /* 1154: pointer.func */
    em[1157] = 8884097; em[1158] = 8; em[1159] = 0; /* 1157: pointer.func */
    em[1160] = 8884097; em[1161] = 8; em[1162] = 0; /* 1160: pointer.func */
    em[1163] = 8884097; em[1164] = 8; em[1165] = 0; /* 1163: pointer.func */
    em[1166] = 8884097; em[1167] = 8; em[1168] = 0; /* 1166: pointer.func */
    em[1169] = 8884097; em[1170] = 8; em[1171] = 0; /* 1169: pointer.func */
    em[1172] = 1; em[1173] = 8; em[1174] = 1; /* 1172: pointer.struct.dh_method */
    	em[1175] = 1177; em[1176] = 0; 
    em[1177] = 0; em[1178] = 72; em[1179] = 8; /* 1177: struct.dh_method */
    	em[1180] = 149; em[1181] = 0; 
    	em[1182] = 1196; em[1183] = 8; 
    	em[1184] = 927; em[1185] = 16; 
    	em[1186] = 1199; em[1187] = 24; 
    	em[1188] = 1196; em[1189] = 32; 
    	em[1190] = 1196; em[1191] = 40; 
    	em[1192] = 125; em[1193] = 56; 
    	em[1194] = 1202; em[1195] = 64; 
    em[1196] = 8884097; em[1197] = 8; em[1198] = 0; /* 1196: pointer.func */
    em[1199] = 8884097; em[1200] = 8; em[1201] = 0; /* 1199: pointer.func */
    em[1202] = 8884097; em[1203] = 8; em[1204] = 0; /* 1202: pointer.func */
    em[1205] = 1; em[1206] = 8; em[1207] = 1; /* 1205: pointer.struct.ecdh_method */
    	em[1208] = 1210; em[1209] = 0; 
    em[1210] = 0; em[1211] = 32; em[1212] = 3; /* 1210: struct.ecdh_method */
    	em[1213] = 149; em[1214] = 0; 
    	em[1215] = 1219; em[1216] = 8; 
    	em[1217] = 125; em[1218] = 24; 
    em[1219] = 8884097; em[1220] = 8; em[1221] = 0; /* 1219: pointer.func */
    em[1222] = 1; em[1223] = 8; em[1224] = 1; /* 1222: pointer.struct.ecdsa_method */
    	em[1225] = 1227; em[1226] = 0; 
    em[1227] = 0; em[1228] = 48; em[1229] = 5; /* 1227: struct.ecdsa_method */
    	em[1230] = 149; em[1231] = 0; 
    	em[1232] = 1240; em[1233] = 8; 
    	em[1234] = 1243; em[1235] = 16; 
    	em[1236] = 1246; em[1237] = 24; 
    	em[1238] = 125; em[1239] = 40; 
    em[1240] = 8884097; em[1241] = 8; em[1242] = 0; /* 1240: pointer.func */
    em[1243] = 8884097; em[1244] = 8; em[1245] = 0; /* 1243: pointer.func */
    em[1246] = 8884097; em[1247] = 8; em[1248] = 0; /* 1246: pointer.func */
    em[1249] = 1; em[1250] = 8; em[1251] = 1; /* 1249: pointer.struct.rand_meth_st */
    	em[1252] = 1254; em[1253] = 0; 
    em[1254] = 0; em[1255] = 48; em[1256] = 6; /* 1254: struct.rand_meth_st */
    	em[1257] = 1269; em[1258] = 0; 
    	em[1259] = 1272; em[1260] = 8; 
    	em[1261] = 1275; em[1262] = 16; 
    	em[1263] = 1278; em[1264] = 24; 
    	em[1265] = 1272; em[1266] = 32; 
    	em[1267] = 1281; em[1268] = 40; 
    em[1269] = 8884097; em[1270] = 8; em[1271] = 0; /* 1269: pointer.func */
    em[1272] = 8884097; em[1273] = 8; em[1274] = 0; /* 1272: pointer.func */
    em[1275] = 8884097; em[1276] = 8; em[1277] = 0; /* 1275: pointer.func */
    em[1278] = 8884097; em[1279] = 8; em[1280] = 0; /* 1278: pointer.func */
    em[1281] = 8884097; em[1282] = 8; em[1283] = 0; /* 1281: pointer.func */
    em[1284] = 1; em[1285] = 8; em[1286] = 1; /* 1284: pointer.struct.store_method_st */
    	em[1287] = 1289; em[1288] = 0; 
    em[1289] = 0; em[1290] = 0; em[1291] = 0; /* 1289: struct.store_method_st */
    em[1292] = 8884097; em[1293] = 8; em[1294] = 0; /* 1292: pointer.func */
    em[1295] = 8884097; em[1296] = 8; em[1297] = 0; /* 1295: pointer.func */
    em[1298] = 8884097; em[1299] = 8; em[1300] = 0; /* 1298: pointer.func */
    em[1301] = 8884097; em[1302] = 8; em[1303] = 0; /* 1301: pointer.func */
    em[1304] = 8884097; em[1305] = 8; em[1306] = 0; /* 1304: pointer.func */
    em[1307] = 8884097; em[1308] = 8; em[1309] = 0; /* 1307: pointer.func */
    em[1310] = 8884097; em[1311] = 8; em[1312] = 0; /* 1310: pointer.func */
    em[1313] = 8884097; em[1314] = 8; em[1315] = 0; /* 1313: pointer.func */
    em[1316] = 1; em[1317] = 8; em[1318] = 1; /* 1316: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[1319] = 1321; em[1320] = 0; 
    em[1321] = 0; em[1322] = 32; em[1323] = 2; /* 1321: struct.ENGINE_CMD_DEFN_st */
    	em[1324] = 149; em[1325] = 8; 
    	em[1326] = 149; em[1327] = 16; 
    em[1328] = 0; em[1329] = 32; em[1330] = 2; /* 1328: struct.crypto_ex_data_st_fake */
    	em[1331] = 1335; em[1332] = 8; 
    	em[1333] = 363; em[1334] = 24; 
    em[1335] = 8884099; em[1336] = 8; em[1337] = 2; /* 1335: pointer_to_array_of_pointers_to_stack */
    	em[1338] = 841; em[1339] = 0; 
    	em[1340] = 5; em[1341] = 20; 
    em[1342] = 1; em[1343] = 8; em[1344] = 1; /* 1342: pointer.struct.engine_st */
    	em[1345] = 1018; em[1346] = 0; 
    em[1347] = 0; em[1348] = 32; em[1349] = 2; /* 1347: struct.crypto_ex_data_st_fake */
    	em[1350] = 1354; em[1351] = 8; 
    	em[1352] = 363; em[1353] = 24; 
    em[1354] = 8884099; em[1355] = 8; em[1356] = 2; /* 1354: pointer_to_array_of_pointers_to_stack */
    	em[1357] = 841; em[1358] = 0; 
    	em[1359] = 5; em[1360] = 20; 
    em[1361] = 1; em[1362] = 8; em[1363] = 1; /* 1361: pointer.struct.bn_mont_ctx_st */
    	em[1364] = 1366; em[1365] = 0; 
    em[1366] = 0; em[1367] = 96; em[1368] = 3; /* 1366: struct.bn_mont_ctx_st */
    	em[1369] = 903; em[1370] = 8; 
    	em[1371] = 903; em[1372] = 32; 
    	em[1373] = 903; em[1374] = 56; 
    em[1375] = 1; em[1376] = 8; em[1377] = 1; /* 1375: pointer.struct.bn_blinding_st */
    	em[1378] = 1380; em[1379] = 0; 
    em[1380] = 0; em[1381] = 88; em[1382] = 7; /* 1380: struct.bn_blinding_st */
    	em[1383] = 1397; em[1384] = 0; 
    	em[1385] = 1397; em[1386] = 8; 
    	em[1387] = 1397; em[1388] = 16; 
    	em[1389] = 1397; em[1390] = 24; 
    	em[1391] = 1414; em[1392] = 40; 
    	em[1393] = 1419; em[1394] = 72; 
    	em[1395] = 1433; em[1396] = 80; 
    em[1397] = 1; em[1398] = 8; em[1399] = 1; /* 1397: pointer.struct.bignum_st */
    	em[1400] = 1402; em[1401] = 0; 
    em[1402] = 0; em[1403] = 24; em[1404] = 1; /* 1402: struct.bignum_st */
    	em[1405] = 1407; em[1406] = 0; 
    em[1407] = 8884099; em[1408] = 8; em[1409] = 2; /* 1407: pointer_to_array_of_pointers_to_stack */
    	em[1410] = 380; em[1411] = 0; 
    	em[1412] = 5; em[1413] = 12; 
    em[1414] = 0; em[1415] = 16; em[1416] = 1; /* 1414: struct.crypto_threadid_st */
    	em[1417] = 841; em[1418] = 0; 
    em[1419] = 1; em[1420] = 8; em[1421] = 1; /* 1419: pointer.struct.bn_mont_ctx_st */
    	em[1422] = 1424; em[1423] = 0; 
    em[1424] = 0; em[1425] = 96; em[1426] = 3; /* 1424: struct.bn_mont_ctx_st */
    	em[1427] = 1402; em[1428] = 8; 
    	em[1429] = 1402; em[1430] = 32; 
    	em[1431] = 1402; em[1432] = 56; 
    em[1433] = 8884097; em[1434] = 8; em[1435] = 0; /* 1433: pointer.func */
    em[1436] = 8884097; em[1437] = 8; em[1438] = 0; /* 1436: pointer.func */
    em[1439] = 8884097; em[1440] = 8; em[1441] = 0; /* 1439: pointer.func */
    em[1442] = 8884097; em[1443] = 8; em[1444] = 0; /* 1442: pointer.func */
    em[1445] = 1; em[1446] = 8; em[1447] = 1; /* 1445: pointer.struct.dh_method */
    	em[1448] = 1450; em[1449] = 0; 
    em[1450] = 0; em[1451] = 72; em[1452] = 8; /* 1450: struct.dh_method */
    	em[1453] = 149; em[1454] = 0; 
    	em[1455] = 1469; em[1456] = 8; 
    	em[1457] = 1472; em[1458] = 16; 
    	em[1459] = 1475; em[1460] = 24; 
    	em[1461] = 1469; em[1462] = 32; 
    	em[1463] = 1469; em[1464] = 40; 
    	em[1465] = 125; em[1466] = 56; 
    	em[1467] = 1478; em[1468] = 64; 
    em[1469] = 8884097; em[1470] = 8; em[1471] = 0; /* 1469: pointer.func */
    em[1472] = 8884097; em[1473] = 8; em[1474] = 0; /* 1472: pointer.func */
    em[1475] = 8884097; em[1476] = 8; em[1477] = 0; /* 1475: pointer.func */
    em[1478] = 8884097; em[1479] = 8; em[1480] = 0; /* 1478: pointer.func */
    em[1481] = 8884097; em[1482] = 8; em[1483] = 0; /* 1481: pointer.func */
    em[1484] = 0; em[1485] = 208; em[1486] = 24; /* 1484: struct.evp_pkey_asn1_method_st */
    	em[1487] = 125; em[1488] = 16; 
    	em[1489] = 125; em[1490] = 24; 
    	em[1491] = 1481; em[1492] = 32; 
    	em[1493] = 1535; em[1494] = 40; 
    	em[1495] = 1538; em[1496] = 48; 
    	em[1497] = 1541; em[1498] = 56; 
    	em[1499] = 1544; em[1500] = 64; 
    	em[1501] = 1547; em[1502] = 72; 
    	em[1503] = 1541; em[1504] = 80; 
    	em[1505] = 1550; em[1506] = 88; 
    	em[1507] = 1550; em[1508] = 96; 
    	em[1509] = 1553; em[1510] = 104; 
    	em[1511] = 1556; em[1512] = 112; 
    	em[1513] = 1550; em[1514] = 120; 
    	em[1515] = 1559; em[1516] = 128; 
    	em[1517] = 1538; em[1518] = 136; 
    	em[1519] = 1541; em[1520] = 144; 
    	em[1521] = 1442; em[1522] = 152; 
    	em[1523] = 1562; em[1524] = 160; 
    	em[1525] = 1565; em[1526] = 168; 
    	em[1527] = 1553; em[1528] = 176; 
    	em[1529] = 1556; em[1530] = 184; 
    	em[1531] = 1568; em[1532] = 192; 
    	em[1533] = 1439; em[1534] = 200; 
    em[1535] = 8884097; em[1536] = 8; em[1537] = 0; /* 1535: pointer.func */
    em[1538] = 8884097; em[1539] = 8; em[1540] = 0; /* 1538: pointer.func */
    em[1541] = 8884097; em[1542] = 8; em[1543] = 0; /* 1541: pointer.func */
    em[1544] = 8884097; em[1545] = 8; em[1546] = 0; /* 1544: pointer.func */
    em[1547] = 8884097; em[1548] = 8; em[1549] = 0; /* 1547: pointer.func */
    em[1550] = 8884097; em[1551] = 8; em[1552] = 0; /* 1550: pointer.func */
    em[1553] = 8884097; em[1554] = 8; em[1555] = 0; /* 1553: pointer.func */
    em[1556] = 8884097; em[1557] = 8; em[1558] = 0; /* 1556: pointer.func */
    em[1559] = 8884097; em[1560] = 8; em[1561] = 0; /* 1559: pointer.func */
    em[1562] = 8884097; em[1563] = 8; em[1564] = 0; /* 1562: pointer.func */
    em[1565] = 8884097; em[1566] = 8; em[1567] = 0; /* 1565: pointer.func */
    em[1568] = 8884097; em[1569] = 8; em[1570] = 0; /* 1568: pointer.func */
    em[1571] = 1; em[1572] = 8; em[1573] = 1; /* 1571: pointer.struct.evp_pkey_asn1_method_st */
    	em[1574] = 1484; em[1575] = 0; 
    em[1576] = 1; em[1577] = 8; em[1578] = 1; /* 1576: pointer.struct.engine_st */
    	em[1579] = 1018; em[1580] = 0; 
    em[1581] = 8884097; em[1582] = 8; em[1583] = 0; /* 1581: pointer.func */
    em[1584] = 8884097; em[1585] = 8; em[1586] = 0; /* 1584: pointer.func */
    em[1587] = 8884097; em[1588] = 8; em[1589] = 0; /* 1587: pointer.func */
    em[1590] = 8884097; em[1591] = 8; em[1592] = 0; /* 1590: pointer.func */
    em[1593] = 1; em[1594] = 8; em[1595] = 1; /* 1593: pointer.struct.evp_pkey_method_st */
    	em[1596] = 1598; em[1597] = 0; 
    em[1598] = 0; em[1599] = 208; em[1600] = 25; /* 1598: struct.evp_pkey_method_st */
    	em[1601] = 1651; em[1602] = 8; 
    	em[1603] = 1654; em[1604] = 16; 
    	em[1605] = 1657; em[1606] = 24; 
    	em[1607] = 1651; em[1608] = 32; 
    	em[1609] = 1660; em[1610] = 40; 
    	em[1611] = 1651; em[1612] = 48; 
    	em[1613] = 1660; em[1614] = 56; 
    	em[1615] = 1651; em[1616] = 64; 
    	em[1617] = 1587; em[1618] = 72; 
    	em[1619] = 1651; em[1620] = 80; 
    	em[1621] = 1584; em[1622] = 88; 
    	em[1623] = 1651; em[1624] = 96; 
    	em[1625] = 1587; em[1626] = 104; 
    	em[1627] = 1581; em[1628] = 112; 
    	em[1629] = 1436; em[1630] = 120; 
    	em[1631] = 1581; em[1632] = 128; 
    	em[1633] = 1663; em[1634] = 136; 
    	em[1635] = 1651; em[1636] = 144; 
    	em[1637] = 1587; em[1638] = 152; 
    	em[1639] = 1651; em[1640] = 160; 
    	em[1641] = 1587; em[1642] = 168; 
    	em[1643] = 1651; em[1644] = 176; 
    	em[1645] = 1666; em[1646] = 184; 
    	em[1647] = 1669; em[1648] = 192; 
    	em[1649] = 1672; em[1650] = 200; 
    em[1651] = 8884097; em[1652] = 8; em[1653] = 0; /* 1651: pointer.func */
    em[1654] = 8884097; em[1655] = 8; em[1656] = 0; /* 1654: pointer.func */
    em[1657] = 8884097; em[1658] = 8; em[1659] = 0; /* 1657: pointer.func */
    em[1660] = 8884097; em[1661] = 8; em[1662] = 0; /* 1660: pointer.func */
    em[1663] = 8884097; em[1664] = 8; em[1665] = 0; /* 1663: pointer.func */
    em[1666] = 8884097; em[1667] = 8; em[1668] = 0; /* 1666: pointer.func */
    em[1669] = 8884097; em[1670] = 8; em[1671] = 0; /* 1669: pointer.func */
    em[1672] = 8884097; em[1673] = 8; em[1674] = 0; /* 1672: pointer.func */
    em[1675] = 1; em[1676] = 8; em[1677] = 1; /* 1675: pointer.struct.bn_mont_ctx_st */
    	em[1678] = 1680; em[1679] = 0; 
    em[1680] = 0; em[1681] = 96; em[1682] = 3; /* 1680: struct.bn_mont_ctx_st */
    	em[1683] = 1689; em[1684] = 8; 
    	em[1685] = 1689; em[1686] = 32; 
    	em[1687] = 1689; em[1688] = 56; 
    em[1689] = 0; em[1690] = 24; em[1691] = 1; /* 1689: struct.bignum_st */
    	em[1692] = 1694; em[1693] = 0; 
    em[1694] = 8884099; em[1695] = 8; em[1696] = 2; /* 1694: pointer_to_array_of_pointers_to_stack */
    	em[1697] = 380; em[1698] = 0; 
    	em[1699] = 5; em[1700] = 12; 
    em[1701] = 8884097; em[1702] = 8; em[1703] = 0; /* 1701: pointer.func */
    em[1704] = 0; em[1705] = 48; em[1706] = 5; /* 1704: struct.env_md_ctx_st */
    	em[1707] = 1717; em[1708] = 0; 
    	em[1709] = 1759; em[1710] = 8; 
    	em[1711] = 841; em[1712] = 24; 
    	em[1713] = 1764; em[1714] = 32; 
    	em[1715] = 1744; em[1716] = 40; 
    em[1717] = 1; em[1718] = 8; em[1719] = 1; /* 1717: pointer.struct.env_md_st */
    	em[1720] = 1722; em[1721] = 0; 
    em[1722] = 0; em[1723] = 120; em[1724] = 8; /* 1722: struct.env_md_st */
    	em[1725] = 1741; em[1726] = 24; 
    	em[1727] = 1744; em[1728] = 32; 
    	em[1729] = 1747; em[1730] = 40; 
    	em[1731] = 1750; em[1732] = 48; 
    	em[1733] = 1741; em[1734] = 56; 
    	em[1735] = 1753; em[1736] = 64; 
    	em[1737] = 1756; em[1738] = 72; 
    	em[1739] = 1701; em[1740] = 112; 
    em[1741] = 8884097; em[1742] = 8; em[1743] = 0; /* 1741: pointer.func */
    em[1744] = 8884097; em[1745] = 8; em[1746] = 0; /* 1744: pointer.func */
    em[1747] = 8884097; em[1748] = 8; em[1749] = 0; /* 1747: pointer.func */
    em[1750] = 8884097; em[1751] = 8; em[1752] = 0; /* 1750: pointer.func */
    em[1753] = 8884097; em[1754] = 8; em[1755] = 0; /* 1753: pointer.func */
    em[1756] = 8884097; em[1757] = 8; em[1758] = 0; /* 1756: pointer.func */
    em[1759] = 1; em[1760] = 8; em[1761] = 1; /* 1759: pointer.struct.engine_st */
    	em[1762] = 1018; em[1763] = 0; 
    em[1764] = 1; em[1765] = 8; em[1766] = 1; /* 1764: pointer.struct.evp_pkey_ctx_st */
    	em[1767] = 1769; em[1768] = 0; 
    em[1769] = 0; em[1770] = 80; em[1771] = 8; /* 1769: struct.evp_pkey_ctx_st */
    	em[1772] = 1593; em[1773] = 0; 
    	em[1774] = 1576; em[1775] = 8; 
    	em[1776] = 1788; em[1777] = 16; 
    	em[1778] = 1788; em[1779] = 24; 
    	em[1780] = 841; em[1781] = 40; 
    	em[1782] = 841; em[1783] = 48; 
    	em[1784] = 8; em[1785] = 56; 
    	em[1786] = 0; em[1787] = 64; 
    em[1788] = 1; em[1789] = 8; em[1790] = 1; /* 1788: pointer.struct.evp_pkey_st */
    	em[1791] = 1793; em[1792] = 0; 
    em[1793] = 0; em[1794] = 56; em[1795] = 4; /* 1793: struct.evp_pkey_st */
    	em[1796] = 1571; em[1797] = 16; 
    	em[1798] = 1576; em[1799] = 24; 
    	em[1800] = 1804; em[1801] = 32; 
    	em[1802] = 2001; em[1803] = 48; 
    em[1804] = 0; em[1805] = 8; em[1806] = 5; /* 1804: union.unknown */
    	em[1807] = 125; em[1808] = 0; 
    	em[1809] = 1817; em[1810] = 0; 
    	em[1811] = 1822; em[1812] = 0; 
    	em[1813] = 1924; em[1814] = 0; 
    	em[1815] = 389; em[1816] = 0; 
    em[1817] = 1; em[1818] = 8; em[1819] = 1; /* 1817: pointer.struct.rsa_st */
    	em[1820] = 971; em[1821] = 0; 
    em[1822] = 1; em[1823] = 8; em[1824] = 1; /* 1822: pointer.struct.dsa_st */
    	em[1825] = 1827; em[1826] = 0; 
    em[1827] = 0; em[1828] = 136; em[1829] = 11; /* 1827: struct.dsa_st */
    	em[1830] = 1852; em[1831] = 24; 
    	em[1832] = 1852; em[1833] = 32; 
    	em[1834] = 1852; em[1835] = 40; 
    	em[1836] = 1852; em[1837] = 48; 
    	em[1838] = 1852; em[1839] = 56; 
    	em[1840] = 1852; em[1841] = 64; 
    	em[1842] = 1852; em[1843] = 72; 
    	em[1844] = 1675; em[1845] = 88; 
    	em[1846] = 1857; em[1847] = 104; 
    	em[1848] = 1871; em[1849] = 120; 
    	em[1850] = 1919; em[1851] = 128; 
    em[1852] = 1; em[1853] = 8; em[1854] = 1; /* 1852: pointer.struct.bignum_st */
    	em[1855] = 1689; em[1856] = 0; 
    em[1857] = 0; em[1858] = 32; em[1859] = 2; /* 1857: struct.crypto_ex_data_st_fake */
    	em[1860] = 1864; em[1861] = 8; 
    	em[1862] = 363; em[1863] = 24; 
    em[1864] = 8884099; em[1865] = 8; em[1866] = 2; /* 1864: pointer_to_array_of_pointers_to_stack */
    	em[1867] = 841; em[1868] = 0; 
    	em[1869] = 5; em[1870] = 20; 
    em[1871] = 1; em[1872] = 8; em[1873] = 1; /* 1871: pointer.struct.dsa_method */
    	em[1874] = 1876; em[1875] = 0; 
    em[1876] = 0; em[1877] = 96; em[1878] = 11; /* 1876: struct.dsa_method */
    	em[1879] = 149; em[1880] = 0; 
    	em[1881] = 1901; em[1882] = 8; 
    	em[1883] = 1904; em[1884] = 16; 
    	em[1885] = 1907; em[1886] = 24; 
    	em[1887] = 1910; em[1888] = 32; 
    	em[1889] = 1913; em[1890] = 40; 
    	em[1891] = 1590; em[1892] = 48; 
    	em[1893] = 1590; em[1894] = 56; 
    	em[1895] = 125; em[1896] = 72; 
    	em[1897] = 1916; em[1898] = 80; 
    	em[1899] = 1590; em[1900] = 88; 
    em[1901] = 8884097; em[1902] = 8; em[1903] = 0; /* 1901: pointer.func */
    em[1904] = 8884097; em[1905] = 8; em[1906] = 0; /* 1904: pointer.func */
    em[1907] = 8884097; em[1908] = 8; em[1909] = 0; /* 1907: pointer.func */
    em[1910] = 8884097; em[1911] = 8; em[1912] = 0; /* 1910: pointer.func */
    em[1913] = 8884097; em[1914] = 8; em[1915] = 0; /* 1913: pointer.func */
    em[1916] = 8884097; em[1917] = 8; em[1918] = 0; /* 1916: pointer.func */
    em[1919] = 1; em[1920] = 8; em[1921] = 1; /* 1919: pointer.struct.engine_st */
    	em[1922] = 1018; em[1923] = 0; 
    em[1924] = 1; em[1925] = 8; em[1926] = 1; /* 1924: pointer.struct.dh_st */
    	em[1927] = 1929; em[1928] = 0; 
    em[1929] = 0; em[1930] = 144; em[1931] = 12; /* 1929: struct.dh_st */
    	em[1932] = 1956; em[1933] = 8; 
    	em[1934] = 1956; em[1935] = 16; 
    	em[1936] = 1956; em[1937] = 32; 
    	em[1938] = 1956; em[1939] = 40; 
    	em[1940] = 1973; em[1941] = 56; 
    	em[1942] = 1956; em[1943] = 64; 
    	em[1944] = 1956; em[1945] = 72; 
    	em[1946] = 29; em[1947] = 80; 
    	em[1948] = 1956; em[1949] = 96; 
    	em[1950] = 1987; em[1951] = 112; 
    	em[1952] = 1445; em[1953] = 128; 
    	em[1954] = 1576; em[1955] = 136; 
    em[1956] = 1; em[1957] = 8; em[1958] = 1; /* 1956: pointer.struct.bignum_st */
    	em[1959] = 1961; em[1960] = 0; 
    em[1961] = 0; em[1962] = 24; em[1963] = 1; /* 1961: struct.bignum_st */
    	em[1964] = 1966; em[1965] = 0; 
    em[1966] = 8884099; em[1967] = 8; em[1968] = 2; /* 1966: pointer_to_array_of_pointers_to_stack */
    	em[1969] = 380; em[1970] = 0; 
    	em[1971] = 5; em[1972] = 12; 
    em[1973] = 1; em[1974] = 8; em[1975] = 1; /* 1973: pointer.struct.bn_mont_ctx_st */
    	em[1976] = 1978; em[1977] = 0; 
    em[1978] = 0; em[1979] = 96; em[1980] = 3; /* 1978: struct.bn_mont_ctx_st */
    	em[1981] = 1961; em[1982] = 8; 
    	em[1983] = 1961; em[1984] = 32; 
    	em[1985] = 1961; em[1986] = 56; 
    em[1987] = 0; em[1988] = 32; em[1989] = 2; /* 1987: struct.crypto_ex_data_st_fake */
    	em[1990] = 1994; em[1991] = 8; 
    	em[1992] = 363; em[1993] = 24; 
    em[1994] = 8884099; em[1995] = 8; em[1996] = 2; /* 1994: pointer_to_array_of_pointers_to_stack */
    	em[1997] = 841; em[1998] = 0; 
    	em[1999] = 5; em[2000] = 20; 
    em[2001] = 1; em[2002] = 8; em[2003] = 1; /* 2001: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[2004] = 2006; em[2005] = 0; 
    em[2006] = 0; em[2007] = 32; em[2008] = 2; /* 2006: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[2009] = 2013; em[2010] = 8; 
    	em[2011] = 363; em[2012] = 24; 
    em[2013] = 8884099; em[2014] = 8; em[2015] = 2; /* 2013: pointer_to_array_of_pointers_to_stack */
    	em[2016] = 2020; em[2017] = 0; 
    	em[2018] = 5; em[2019] = 20; 
    em[2020] = 0; em[2021] = 8; em[2022] = 1; /* 2020: pointer.X509_ATTRIBUTE */
    	em[2023] = 2025; em[2024] = 0; 
    em[2025] = 0; em[2026] = 0; em[2027] = 1; /* 2025: X509_ATTRIBUTE */
    	em[2028] = 2030; em[2029] = 0; 
    em[2030] = 0; em[2031] = 24; em[2032] = 2; /* 2030: struct.x509_attributes_st */
    	em[2033] = 135; em[2034] = 0; 
    	em[2035] = 366; em[2036] = 16; 
    em[2037] = 1; em[2038] = 8; em[2039] = 1; /* 2037: pointer.struct.hmac_ctx_st */
    	em[2040] = 2042; em[2041] = 0; 
    em[2042] = 0; em[2043] = 288; em[2044] = 4; /* 2042: struct.hmac_ctx_st */
    	em[2045] = 1717; em[2046] = 0; 
    	em[2047] = 1704; em[2048] = 8; 
    	em[2049] = 1704; em[2050] = 56; 
    	em[2051] = 1704; em[2052] = 104; 
    args_addr->arg_entity_index[0] = 2037;
    args_addr->arg_entity_index[1] = 841;
    args_addr->arg_entity_index[2] = 5;
    args_addr->arg_entity_index[3] = 1717;
    args_addr->arg_entity_index[4] = 1759;
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

