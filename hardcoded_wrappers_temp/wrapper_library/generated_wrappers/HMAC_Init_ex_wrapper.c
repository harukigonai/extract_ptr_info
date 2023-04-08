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
    em[0] = 8884097; em[1] = 8; em[2] = 0; /* 0: pointer.func */
    em[3] = 1; em[4] = 8; em[5] = 1; /* 3: pointer.struct.ASN1_VALUE_st */
    	em[6] = 8; em[7] = 0; 
    em[8] = 0; em[9] = 0; em[10] = 0; /* 8: struct.ASN1_VALUE_st */
    em[11] = 1; em[12] = 8; em[13] = 1; /* 11: pointer.struct.asn1_string_st */
    	em[14] = 16; em[15] = 0; 
    em[16] = 0; em[17] = 24; em[18] = 1; /* 16: struct.asn1_string_st */
    	em[19] = 21; em[20] = 8; 
    em[21] = 1; em[22] = 8; em[23] = 1; /* 21: pointer.unsigned char */
    	em[24] = 26; em[25] = 0; 
    em[26] = 0; em[27] = 1; em[28] = 0; /* 26: unsigned char */
    em[29] = 1; em[30] = 8; em[31] = 1; /* 29: pointer.struct.asn1_string_st */
    	em[32] = 16; em[33] = 0; 
    em[34] = 1; em[35] = 8; em[36] = 1; /* 34: pointer.struct.asn1_string_st */
    	em[37] = 16; em[38] = 0; 
    em[39] = 1; em[40] = 8; em[41] = 1; /* 39: pointer.struct.asn1_string_st */
    	em[42] = 16; em[43] = 0; 
    em[44] = 1; em[45] = 8; em[46] = 1; /* 44: pointer.struct.asn1_string_st */
    	em[47] = 16; em[48] = 0; 
    em[49] = 1; em[50] = 8; em[51] = 1; /* 49: pointer.struct.asn1_string_st */
    	em[52] = 16; em[53] = 0; 
    em[54] = 1; em[55] = 8; em[56] = 1; /* 54: pointer.struct.asn1_string_st */
    	em[57] = 16; em[58] = 0; 
    em[59] = 1; em[60] = 8; em[61] = 1; /* 59: pointer.struct.asn1_string_st */
    	em[62] = 16; em[63] = 0; 
    em[64] = 1; em[65] = 8; em[66] = 1; /* 64: pointer.struct.asn1_string_st */
    	em[67] = 16; em[68] = 0; 
    em[69] = 1; em[70] = 8; em[71] = 1; /* 69: pointer.struct.asn1_string_st */
    	em[72] = 16; em[73] = 0; 
    em[74] = 0; em[75] = 16; em[76] = 1; /* 74: struct.asn1_type_st */
    	em[77] = 79; em[78] = 8; 
    em[79] = 0; em[80] = 8; em[81] = 20; /* 79: union.unknown */
    	em[82] = 122; em[83] = 0; 
    	em[84] = 69; em[85] = 0; 
    	em[86] = 127; em[87] = 0; 
    	em[88] = 151; em[89] = 0; 
    	em[90] = 64; em[91] = 0; 
    	em[92] = 156; em[93] = 0; 
    	em[94] = 59; em[95] = 0; 
    	em[96] = 161; em[97] = 0; 
    	em[98] = 54; em[99] = 0; 
    	em[100] = 49; em[101] = 0; 
    	em[102] = 44; em[103] = 0; 
    	em[104] = 39; em[105] = 0; 
    	em[106] = 166; em[107] = 0; 
    	em[108] = 34; em[109] = 0; 
    	em[110] = 29; em[111] = 0; 
    	em[112] = 171; em[113] = 0; 
    	em[114] = 11; em[115] = 0; 
    	em[116] = 69; em[117] = 0; 
    	em[118] = 69; em[119] = 0; 
    	em[120] = 3; em[121] = 0; 
    em[122] = 1; em[123] = 8; em[124] = 1; /* 122: pointer.char */
    	em[125] = 8884096; em[126] = 0; 
    em[127] = 1; em[128] = 8; em[129] = 1; /* 127: pointer.struct.asn1_object_st */
    	em[130] = 132; em[131] = 0; 
    em[132] = 0; em[133] = 40; em[134] = 3; /* 132: struct.asn1_object_st */
    	em[135] = 141; em[136] = 0; 
    	em[137] = 141; em[138] = 8; 
    	em[139] = 146; em[140] = 24; 
    em[141] = 1; em[142] = 8; em[143] = 1; /* 141: pointer.char */
    	em[144] = 8884096; em[145] = 0; 
    em[146] = 1; em[147] = 8; em[148] = 1; /* 146: pointer.unsigned char */
    	em[149] = 26; em[150] = 0; 
    em[151] = 1; em[152] = 8; em[153] = 1; /* 151: pointer.struct.asn1_string_st */
    	em[154] = 16; em[155] = 0; 
    em[156] = 1; em[157] = 8; em[158] = 1; /* 156: pointer.struct.asn1_string_st */
    	em[159] = 16; em[160] = 0; 
    em[161] = 1; em[162] = 8; em[163] = 1; /* 161: pointer.struct.asn1_string_st */
    	em[164] = 16; em[165] = 0; 
    em[166] = 1; em[167] = 8; em[168] = 1; /* 166: pointer.struct.asn1_string_st */
    	em[169] = 16; em[170] = 0; 
    em[171] = 1; em[172] = 8; em[173] = 1; /* 171: pointer.struct.asn1_string_st */
    	em[174] = 16; em[175] = 0; 
    em[176] = 0; em[177] = 0; em[178] = 0; /* 176: struct.ASN1_VALUE_st */
    em[179] = 1; em[180] = 8; em[181] = 1; /* 179: pointer.struct.asn1_string_st */
    	em[182] = 184; em[183] = 0; 
    em[184] = 0; em[185] = 24; em[186] = 1; /* 184: struct.asn1_string_st */
    	em[187] = 21; em[188] = 8; 
    em[189] = 1; em[190] = 8; em[191] = 1; /* 189: pointer.struct.asn1_string_st */
    	em[192] = 184; em[193] = 0; 
    em[194] = 1; em[195] = 8; em[196] = 1; /* 194: pointer.struct.asn1_string_st */
    	em[197] = 184; em[198] = 0; 
    em[199] = 1; em[200] = 8; em[201] = 1; /* 199: pointer.struct.asn1_string_st */
    	em[202] = 184; em[203] = 0; 
    em[204] = 1; em[205] = 8; em[206] = 1; /* 204: pointer.struct.asn1_string_st */
    	em[207] = 184; em[208] = 0; 
    em[209] = 1; em[210] = 8; em[211] = 1; /* 209: pointer.struct.asn1_string_st */
    	em[212] = 184; em[213] = 0; 
    em[214] = 1; em[215] = 8; em[216] = 1; /* 214: pointer.struct.asn1_string_st */
    	em[217] = 184; em[218] = 0; 
    em[219] = 1; em[220] = 8; em[221] = 1; /* 219: pointer.struct.asn1_string_st */
    	em[222] = 184; em[223] = 0; 
    em[224] = 0; em[225] = 40; em[226] = 3; /* 224: struct.asn1_object_st */
    	em[227] = 141; em[228] = 0; 
    	em[229] = 141; em[230] = 8; 
    	em[231] = 146; em[232] = 24; 
    em[233] = 1; em[234] = 8; em[235] = 1; /* 233: pointer.struct.asn1_string_st */
    	em[236] = 184; em[237] = 0; 
    em[238] = 0; em[239] = 0; em[240] = 1; /* 238: ASN1_TYPE */
    	em[241] = 243; em[242] = 0; 
    em[243] = 0; em[244] = 16; em[245] = 1; /* 243: struct.asn1_type_st */
    	em[246] = 248; em[247] = 8; 
    em[248] = 0; em[249] = 8; em[250] = 20; /* 248: union.unknown */
    	em[251] = 122; em[252] = 0; 
    	em[253] = 233; em[254] = 0; 
    	em[255] = 291; em[256] = 0; 
    	em[257] = 219; em[258] = 0; 
    	em[259] = 214; em[260] = 0; 
    	em[261] = 209; em[262] = 0; 
    	em[263] = 204; em[264] = 0; 
    	em[265] = 296; em[266] = 0; 
    	em[267] = 301; em[268] = 0; 
    	em[269] = 199; em[270] = 0; 
    	em[271] = 194; em[272] = 0; 
    	em[273] = 306; em[274] = 0; 
    	em[275] = 311; em[276] = 0; 
    	em[277] = 316; em[278] = 0; 
    	em[279] = 189; em[280] = 0; 
    	em[281] = 321; em[282] = 0; 
    	em[283] = 179; em[284] = 0; 
    	em[285] = 233; em[286] = 0; 
    	em[287] = 233; em[288] = 0; 
    	em[289] = 326; em[290] = 0; 
    em[291] = 1; em[292] = 8; em[293] = 1; /* 291: pointer.struct.asn1_object_st */
    	em[294] = 224; em[295] = 0; 
    em[296] = 1; em[297] = 8; em[298] = 1; /* 296: pointer.struct.asn1_string_st */
    	em[299] = 184; em[300] = 0; 
    em[301] = 1; em[302] = 8; em[303] = 1; /* 301: pointer.struct.asn1_string_st */
    	em[304] = 184; em[305] = 0; 
    em[306] = 1; em[307] = 8; em[308] = 1; /* 306: pointer.struct.asn1_string_st */
    	em[309] = 184; em[310] = 0; 
    em[311] = 1; em[312] = 8; em[313] = 1; /* 311: pointer.struct.asn1_string_st */
    	em[314] = 184; em[315] = 0; 
    em[316] = 1; em[317] = 8; em[318] = 1; /* 316: pointer.struct.asn1_string_st */
    	em[319] = 184; em[320] = 0; 
    em[321] = 1; em[322] = 8; em[323] = 1; /* 321: pointer.struct.asn1_string_st */
    	em[324] = 184; em[325] = 0; 
    em[326] = 1; em[327] = 8; em[328] = 1; /* 326: pointer.struct.ASN1_VALUE_st */
    	em[329] = 176; em[330] = 0; 
    em[331] = 1; em[332] = 8; em[333] = 1; /* 331: pointer.struct.stack_st_ASN1_TYPE */
    	em[334] = 336; em[335] = 0; 
    em[336] = 0; em[337] = 32; em[338] = 2; /* 336: struct.stack_st_fake_ASN1_TYPE */
    	em[339] = 343; em[340] = 8; 
    	em[341] = 358; em[342] = 24; 
    em[343] = 8884099; em[344] = 8; em[345] = 2; /* 343: pointer_to_array_of_pointers_to_stack */
    	em[346] = 350; em[347] = 0; 
    	em[348] = 355; em[349] = 20; 
    em[350] = 0; em[351] = 8; em[352] = 1; /* 350: pointer.ASN1_TYPE */
    	em[353] = 238; em[354] = 0; 
    em[355] = 0; em[356] = 4; em[357] = 0; /* 355: int */
    em[358] = 8884097; em[359] = 8; em[360] = 0; /* 358: pointer.func */
    em[361] = 0; em[362] = 8; em[363] = 3; /* 361: union.unknown */
    	em[364] = 122; em[365] = 0; 
    	em[366] = 331; em[367] = 0; 
    	em[368] = 370; em[369] = 0; 
    em[370] = 1; em[371] = 8; em[372] = 1; /* 370: pointer.struct.asn1_type_st */
    	em[373] = 74; em[374] = 0; 
    em[375] = 8884097; em[376] = 8; em[377] = 0; /* 375: pointer.func */
    em[378] = 1; em[379] = 8; em[380] = 1; /* 378: pointer.struct.ec_key_st */
    	em[381] = 383; em[382] = 0; 
    em[383] = 0; em[384] = 56; em[385] = 4; /* 383: struct.ec_key_st */
    	em[386] = 394; em[387] = 8; 
    	em[388] = 848; em[389] = 16; 
    	em[390] = 853; em[391] = 24; 
    	em[392] = 870; em[393] = 48; 
    em[394] = 1; em[395] = 8; em[396] = 1; /* 394: pointer.struct.ec_group_st */
    	em[397] = 399; em[398] = 0; 
    em[399] = 0; em[400] = 232; em[401] = 12; /* 399: struct.ec_group_st */
    	em[402] = 426; em[403] = 0; 
    	em[404] = 598; em[405] = 8; 
    	em[406] = 801; em[407] = 16; 
    	em[408] = 801; em[409] = 40; 
    	em[410] = 21; em[411] = 80; 
    	em[412] = 813; em[413] = 96; 
    	em[414] = 801; em[415] = 104; 
    	em[416] = 801; em[417] = 152; 
    	em[418] = 801; em[419] = 176; 
    	em[420] = 836; em[421] = 208; 
    	em[422] = 836; em[423] = 216; 
    	em[424] = 845; em[425] = 224; 
    em[426] = 1; em[427] = 8; em[428] = 1; /* 426: pointer.struct.ec_method_st */
    	em[429] = 431; em[430] = 0; 
    em[431] = 0; em[432] = 304; em[433] = 37; /* 431: struct.ec_method_st */
    	em[434] = 508; em[435] = 8; 
    	em[436] = 511; em[437] = 16; 
    	em[438] = 511; em[439] = 24; 
    	em[440] = 514; em[441] = 32; 
    	em[442] = 517; em[443] = 40; 
    	em[444] = 520; em[445] = 48; 
    	em[446] = 523; em[447] = 56; 
    	em[448] = 526; em[449] = 64; 
    	em[450] = 529; em[451] = 72; 
    	em[452] = 532; em[453] = 80; 
    	em[454] = 532; em[455] = 88; 
    	em[456] = 535; em[457] = 96; 
    	em[458] = 538; em[459] = 104; 
    	em[460] = 541; em[461] = 112; 
    	em[462] = 544; em[463] = 120; 
    	em[464] = 547; em[465] = 128; 
    	em[466] = 550; em[467] = 136; 
    	em[468] = 553; em[469] = 144; 
    	em[470] = 556; em[471] = 152; 
    	em[472] = 559; em[473] = 160; 
    	em[474] = 562; em[475] = 168; 
    	em[476] = 565; em[477] = 176; 
    	em[478] = 568; em[479] = 184; 
    	em[480] = 571; em[481] = 192; 
    	em[482] = 574; em[483] = 200; 
    	em[484] = 577; em[485] = 208; 
    	em[486] = 568; em[487] = 216; 
    	em[488] = 580; em[489] = 224; 
    	em[490] = 583; em[491] = 232; 
    	em[492] = 586; em[493] = 240; 
    	em[494] = 523; em[495] = 248; 
    	em[496] = 589; em[497] = 256; 
    	em[498] = 592; em[499] = 264; 
    	em[500] = 589; em[501] = 272; 
    	em[502] = 592; em[503] = 280; 
    	em[504] = 592; em[505] = 288; 
    	em[506] = 595; em[507] = 296; 
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
    em[586] = 8884097; em[587] = 8; em[588] = 0; /* 586: pointer.func */
    em[589] = 8884097; em[590] = 8; em[591] = 0; /* 589: pointer.func */
    em[592] = 8884097; em[593] = 8; em[594] = 0; /* 592: pointer.func */
    em[595] = 8884097; em[596] = 8; em[597] = 0; /* 595: pointer.func */
    em[598] = 1; em[599] = 8; em[600] = 1; /* 598: pointer.struct.ec_point_st */
    	em[601] = 603; em[602] = 0; 
    em[603] = 0; em[604] = 88; em[605] = 4; /* 603: struct.ec_point_st */
    	em[606] = 614; em[607] = 0; 
    	em[608] = 786; em[609] = 8; 
    	em[610] = 786; em[611] = 32; 
    	em[612] = 786; em[613] = 56; 
    em[614] = 1; em[615] = 8; em[616] = 1; /* 614: pointer.struct.ec_method_st */
    	em[617] = 619; em[618] = 0; 
    em[619] = 0; em[620] = 304; em[621] = 37; /* 619: struct.ec_method_st */
    	em[622] = 696; em[623] = 8; 
    	em[624] = 699; em[625] = 16; 
    	em[626] = 699; em[627] = 24; 
    	em[628] = 702; em[629] = 32; 
    	em[630] = 705; em[631] = 40; 
    	em[632] = 708; em[633] = 48; 
    	em[634] = 711; em[635] = 56; 
    	em[636] = 714; em[637] = 64; 
    	em[638] = 717; em[639] = 72; 
    	em[640] = 720; em[641] = 80; 
    	em[642] = 720; em[643] = 88; 
    	em[644] = 723; em[645] = 96; 
    	em[646] = 726; em[647] = 104; 
    	em[648] = 729; em[649] = 112; 
    	em[650] = 732; em[651] = 120; 
    	em[652] = 735; em[653] = 128; 
    	em[654] = 738; em[655] = 136; 
    	em[656] = 741; em[657] = 144; 
    	em[658] = 744; em[659] = 152; 
    	em[660] = 747; em[661] = 160; 
    	em[662] = 750; em[663] = 168; 
    	em[664] = 753; em[665] = 176; 
    	em[666] = 756; em[667] = 184; 
    	em[668] = 759; em[669] = 192; 
    	em[670] = 762; em[671] = 200; 
    	em[672] = 765; em[673] = 208; 
    	em[674] = 756; em[675] = 216; 
    	em[676] = 768; em[677] = 224; 
    	em[678] = 771; em[679] = 232; 
    	em[680] = 774; em[681] = 240; 
    	em[682] = 711; em[683] = 248; 
    	em[684] = 777; em[685] = 256; 
    	em[686] = 780; em[687] = 264; 
    	em[688] = 777; em[689] = 272; 
    	em[690] = 780; em[691] = 280; 
    	em[692] = 780; em[693] = 288; 
    	em[694] = 783; em[695] = 296; 
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
    em[774] = 8884097; em[775] = 8; em[776] = 0; /* 774: pointer.func */
    em[777] = 8884097; em[778] = 8; em[779] = 0; /* 777: pointer.func */
    em[780] = 8884097; em[781] = 8; em[782] = 0; /* 780: pointer.func */
    em[783] = 8884097; em[784] = 8; em[785] = 0; /* 783: pointer.func */
    em[786] = 0; em[787] = 24; em[788] = 1; /* 786: struct.bignum_st */
    	em[789] = 791; em[790] = 0; 
    em[791] = 8884099; em[792] = 8; em[793] = 2; /* 791: pointer_to_array_of_pointers_to_stack */
    	em[794] = 798; em[795] = 0; 
    	em[796] = 355; em[797] = 12; 
    em[798] = 0; em[799] = 8; em[800] = 0; /* 798: long unsigned int */
    em[801] = 0; em[802] = 24; em[803] = 1; /* 801: struct.bignum_st */
    	em[804] = 806; em[805] = 0; 
    em[806] = 8884099; em[807] = 8; em[808] = 2; /* 806: pointer_to_array_of_pointers_to_stack */
    	em[809] = 798; em[810] = 0; 
    	em[811] = 355; em[812] = 12; 
    em[813] = 1; em[814] = 8; em[815] = 1; /* 813: pointer.struct.ec_extra_data_st */
    	em[816] = 818; em[817] = 0; 
    em[818] = 0; em[819] = 40; em[820] = 5; /* 818: struct.ec_extra_data_st */
    	em[821] = 831; em[822] = 0; 
    	em[823] = 836; em[824] = 8; 
    	em[825] = 839; em[826] = 16; 
    	em[827] = 842; em[828] = 24; 
    	em[829] = 842; em[830] = 32; 
    em[831] = 1; em[832] = 8; em[833] = 1; /* 831: pointer.struct.ec_extra_data_st */
    	em[834] = 818; em[835] = 0; 
    em[836] = 0; em[837] = 8; em[838] = 0; /* 836: pointer.void */
    em[839] = 8884097; em[840] = 8; em[841] = 0; /* 839: pointer.func */
    em[842] = 8884097; em[843] = 8; em[844] = 0; /* 842: pointer.func */
    em[845] = 8884097; em[846] = 8; em[847] = 0; /* 845: pointer.func */
    em[848] = 1; em[849] = 8; em[850] = 1; /* 848: pointer.struct.ec_point_st */
    	em[851] = 603; em[852] = 0; 
    em[853] = 1; em[854] = 8; em[855] = 1; /* 853: pointer.struct.bignum_st */
    	em[856] = 858; em[857] = 0; 
    em[858] = 0; em[859] = 24; em[860] = 1; /* 858: struct.bignum_st */
    	em[861] = 863; em[862] = 0; 
    em[863] = 8884099; em[864] = 8; em[865] = 2; /* 863: pointer_to_array_of_pointers_to_stack */
    	em[866] = 798; em[867] = 0; 
    	em[868] = 355; em[869] = 12; 
    em[870] = 1; em[871] = 8; em[872] = 1; /* 870: pointer.struct.ec_extra_data_st */
    	em[873] = 875; em[874] = 0; 
    em[875] = 0; em[876] = 40; em[877] = 5; /* 875: struct.ec_extra_data_st */
    	em[878] = 888; em[879] = 0; 
    	em[880] = 836; em[881] = 8; 
    	em[882] = 839; em[883] = 16; 
    	em[884] = 842; em[885] = 24; 
    	em[886] = 842; em[887] = 32; 
    em[888] = 1; em[889] = 8; em[890] = 1; /* 888: pointer.struct.ec_extra_data_st */
    	em[891] = 875; em[892] = 0; 
    em[893] = 0; em[894] = 24; em[895] = 1; /* 893: struct.bignum_st */
    	em[896] = 898; em[897] = 0; 
    em[898] = 8884099; em[899] = 8; em[900] = 2; /* 898: pointer_to_array_of_pointers_to_stack */
    	em[901] = 798; em[902] = 0; 
    	em[903] = 355; em[904] = 12; 
    em[905] = 8884097; em[906] = 8; em[907] = 0; /* 905: pointer.func */
    em[908] = 0; em[909] = 208; em[910] = 24; /* 908: struct.evp_pkey_asn1_method_st */
    	em[911] = 122; em[912] = 16; 
    	em[913] = 122; em[914] = 24; 
    	em[915] = 959; em[916] = 32; 
    	em[917] = 962; em[918] = 40; 
    	em[919] = 965; em[920] = 48; 
    	em[921] = 968; em[922] = 56; 
    	em[923] = 971; em[924] = 64; 
    	em[925] = 974; em[926] = 72; 
    	em[927] = 968; em[928] = 80; 
    	em[929] = 977; em[930] = 88; 
    	em[931] = 977; em[932] = 96; 
    	em[933] = 980; em[934] = 104; 
    	em[935] = 983; em[936] = 112; 
    	em[937] = 977; em[938] = 120; 
    	em[939] = 905; em[940] = 128; 
    	em[941] = 965; em[942] = 136; 
    	em[943] = 968; em[944] = 144; 
    	em[945] = 986; em[946] = 152; 
    	em[947] = 989; em[948] = 160; 
    	em[949] = 992; em[950] = 168; 
    	em[951] = 980; em[952] = 176; 
    	em[953] = 983; em[954] = 184; 
    	em[955] = 995; em[956] = 192; 
    	em[957] = 998; em[958] = 200; 
    em[959] = 8884097; em[960] = 8; em[961] = 0; /* 959: pointer.func */
    em[962] = 8884097; em[963] = 8; em[964] = 0; /* 962: pointer.func */
    em[965] = 8884097; em[966] = 8; em[967] = 0; /* 965: pointer.func */
    em[968] = 8884097; em[969] = 8; em[970] = 0; /* 968: pointer.func */
    em[971] = 8884097; em[972] = 8; em[973] = 0; /* 971: pointer.func */
    em[974] = 8884097; em[975] = 8; em[976] = 0; /* 974: pointer.func */
    em[977] = 8884097; em[978] = 8; em[979] = 0; /* 977: pointer.func */
    em[980] = 8884097; em[981] = 8; em[982] = 0; /* 980: pointer.func */
    em[983] = 8884097; em[984] = 8; em[985] = 0; /* 983: pointer.func */
    em[986] = 8884097; em[987] = 8; em[988] = 0; /* 986: pointer.func */
    em[989] = 8884097; em[990] = 8; em[991] = 0; /* 989: pointer.func */
    em[992] = 8884097; em[993] = 8; em[994] = 0; /* 992: pointer.func */
    em[995] = 8884097; em[996] = 8; em[997] = 0; /* 995: pointer.func */
    em[998] = 8884097; em[999] = 8; em[1000] = 0; /* 998: pointer.func */
    em[1001] = 8884097; em[1002] = 8; em[1003] = 0; /* 1001: pointer.func */
    em[1004] = 8884097; em[1005] = 8; em[1006] = 0; /* 1004: pointer.func */
    em[1007] = 8884097; em[1008] = 8; em[1009] = 0; /* 1007: pointer.func */
    em[1010] = 0; em[1011] = 112; em[1012] = 13; /* 1010: struct.rsa_meth_st */
    	em[1013] = 141; em[1014] = 0; 
    	em[1015] = 1039; em[1016] = 8; 
    	em[1017] = 1039; em[1018] = 16; 
    	em[1019] = 1039; em[1020] = 24; 
    	em[1021] = 1039; em[1022] = 32; 
    	em[1023] = 1042; em[1024] = 40; 
    	em[1025] = 1007; em[1026] = 48; 
    	em[1027] = 1001; em[1028] = 56; 
    	em[1029] = 1001; em[1030] = 64; 
    	em[1031] = 122; em[1032] = 80; 
    	em[1033] = 1045; em[1034] = 88; 
    	em[1035] = 1048; em[1036] = 96; 
    	em[1037] = 375; em[1038] = 104; 
    em[1039] = 8884097; em[1040] = 8; em[1041] = 0; /* 1039: pointer.func */
    em[1042] = 8884097; em[1043] = 8; em[1044] = 0; /* 1042: pointer.func */
    em[1045] = 8884097; em[1046] = 8; em[1047] = 0; /* 1045: pointer.func */
    em[1048] = 8884097; em[1049] = 8; em[1050] = 0; /* 1048: pointer.func */
    em[1051] = 0; em[1052] = 168; em[1053] = 17; /* 1051: struct.rsa_st */
    	em[1054] = 1088; em[1055] = 16; 
    	em[1056] = 1093; em[1057] = 24; 
    	em[1058] = 1430; em[1059] = 32; 
    	em[1060] = 1430; em[1061] = 40; 
    	em[1062] = 1430; em[1063] = 48; 
    	em[1064] = 1430; em[1065] = 56; 
    	em[1066] = 1430; em[1067] = 64; 
    	em[1068] = 1430; em[1069] = 72; 
    	em[1070] = 1430; em[1071] = 80; 
    	em[1072] = 1430; em[1073] = 88; 
    	em[1074] = 1435; em[1075] = 96; 
    	em[1076] = 1449; em[1077] = 120; 
    	em[1078] = 1449; em[1079] = 128; 
    	em[1080] = 1449; em[1081] = 136; 
    	em[1082] = 122; em[1083] = 144; 
    	em[1084] = 1463; em[1085] = 152; 
    	em[1086] = 1463; em[1087] = 160; 
    em[1088] = 1; em[1089] = 8; em[1090] = 1; /* 1088: pointer.struct.rsa_meth_st */
    	em[1091] = 1010; em[1092] = 0; 
    em[1093] = 1; em[1094] = 8; em[1095] = 1; /* 1093: pointer.struct.engine_st */
    	em[1096] = 1098; em[1097] = 0; 
    em[1098] = 0; em[1099] = 216; em[1100] = 24; /* 1098: struct.engine_st */
    	em[1101] = 141; em[1102] = 0; 
    	em[1103] = 141; em[1104] = 8; 
    	em[1105] = 1149; em[1106] = 16; 
    	em[1107] = 1201; em[1108] = 24; 
    	em[1109] = 1252; em[1110] = 32; 
    	em[1111] = 1288; em[1112] = 40; 
    	em[1113] = 1305; em[1114] = 48; 
    	em[1115] = 1332; em[1116] = 56; 
    	em[1117] = 1367; em[1118] = 64; 
    	em[1119] = 1375; em[1120] = 72; 
    	em[1121] = 1378; em[1122] = 80; 
    	em[1123] = 1381; em[1124] = 88; 
    	em[1125] = 1384; em[1126] = 96; 
    	em[1127] = 1387; em[1128] = 104; 
    	em[1129] = 1387; em[1130] = 112; 
    	em[1131] = 1387; em[1132] = 120; 
    	em[1133] = 1390; em[1134] = 128; 
    	em[1135] = 1393; em[1136] = 136; 
    	em[1137] = 1393; em[1138] = 144; 
    	em[1139] = 1396; em[1140] = 152; 
    	em[1141] = 1399; em[1142] = 160; 
    	em[1143] = 1411; em[1144] = 184; 
    	em[1145] = 1425; em[1146] = 200; 
    	em[1147] = 1425; em[1148] = 208; 
    em[1149] = 1; em[1150] = 8; em[1151] = 1; /* 1149: pointer.struct.rsa_meth_st */
    	em[1152] = 1154; em[1153] = 0; 
    em[1154] = 0; em[1155] = 112; em[1156] = 13; /* 1154: struct.rsa_meth_st */
    	em[1157] = 141; em[1158] = 0; 
    	em[1159] = 1004; em[1160] = 8; 
    	em[1161] = 1004; em[1162] = 16; 
    	em[1163] = 1004; em[1164] = 24; 
    	em[1165] = 1004; em[1166] = 32; 
    	em[1167] = 1183; em[1168] = 40; 
    	em[1169] = 1186; em[1170] = 48; 
    	em[1171] = 1189; em[1172] = 56; 
    	em[1173] = 1189; em[1174] = 64; 
    	em[1175] = 122; em[1176] = 80; 
    	em[1177] = 1192; em[1178] = 88; 
    	em[1179] = 1195; em[1180] = 96; 
    	em[1181] = 1198; em[1182] = 104; 
    em[1183] = 8884097; em[1184] = 8; em[1185] = 0; /* 1183: pointer.func */
    em[1186] = 8884097; em[1187] = 8; em[1188] = 0; /* 1186: pointer.func */
    em[1189] = 8884097; em[1190] = 8; em[1191] = 0; /* 1189: pointer.func */
    em[1192] = 8884097; em[1193] = 8; em[1194] = 0; /* 1192: pointer.func */
    em[1195] = 8884097; em[1196] = 8; em[1197] = 0; /* 1195: pointer.func */
    em[1198] = 8884097; em[1199] = 8; em[1200] = 0; /* 1198: pointer.func */
    em[1201] = 1; em[1202] = 8; em[1203] = 1; /* 1201: pointer.struct.dsa_method */
    	em[1204] = 1206; em[1205] = 0; 
    em[1206] = 0; em[1207] = 96; em[1208] = 11; /* 1206: struct.dsa_method */
    	em[1209] = 141; em[1210] = 0; 
    	em[1211] = 1231; em[1212] = 8; 
    	em[1213] = 1234; em[1214] = 16; 
    	em[1215] = 1237; em[1216] = 24; 
    	em[1217] = 1240; em[1218] = 32; 
    	em[1219] = 1243; em[1220] = 40; 
    	em[1221] = 1246; em[1222] = 48; 
    	em[1223] = 1246; em[1224] = 56; 
    	em[1225] = 122; em[1226] = 72; 
    	em[1227] = 1249; em[1228] = 80; 
    	em[1229] = 1246; em[1230] = 88; 
    em[1231] = 8884097; em[1232] = 8; em[1233] = 0; /* 1231: pointer.func */
    em[1234] = 8884097; em[1235] = 8; em[1236] = 0; /* 1234: pointer.func */
    em[1237] = 8884097; em[1238] = 8; em[1239] = 0; /* 1237: pointer.func */
    em[1240] = 8884097; em[1241] = 8; em[1242] = 0; /* 1240: pointer.func */
    em[1243] = 8884097; em[1244] = 8; em[1245] = 0; /* 1243: pointer.func */
    em[1246] = 8884097; em[1247] = 8; em[1248] = 0; /* 1246: pointer.func */
    em[1249] = 8884097; em[1250] = 8; em[1251] = 0; /* 1249: pointer.func */
    em[1252] = 1; em[1253] = 8; em[1254] = 1; /* 1252: pointer.struct.dh_method */
    	em[1255] = 1257; em[1256] = 0; 
    em[1257] = 0; em[1258] = 72; em[1259] = 8; /* 1257: struct.dh_method */
    	em[1260] = 141; em[1261] = 0; 
    	em[1262] = 1276; em[1263] = 8; 
    	em[1264] = 1279; em[1265] = 16; 
    	em[1266] = 1282; em[1267] = 24; 
    	em[1268] = 1276; em[1269] = 32; 
    	em[1270] = 1276; em[1271] = 40; 
    	em[1272] = 122; em[1273] = 56; 
    	em[1274] = 1285; em[1275] = 64; 
    em[1276] = 8884097; em[1277] = 8; em[1278] = 0; /* 1276: pointer.func */
    em[1279] = 8884097; em[1280] = 8; em[1281] = 0; /* 1279: pointer.func */
    em[1282] = 8884097; em[1283] = 8; em[1284] = 0; /* 1282: pointer.func */
    em[1285] = 8884097; em[1286] = 8; em[1287] = 0; /* 1285: pointer.func */
    em[1288] = 1; em[1289] = 8; em[1290] = 1; /* 1288: pointer.struct.ecdh_method */
    	em[1291] = 1293; em[1292] = 0; 
    em[1293] = 0; em[1294] = 32; em[1295] = 3; /* 1293: struct.ecdh_method */
    	em[1296] = 141; em[1297] = 0; 
    	em[1298] = 1302; em[1299] = 8; 
    	em[1300] = 122; em[1301] = 24; 
    em[1302] = 8884097; em[1303] = 8; em[1304] = 0; /* 1302: pointer.func */
    em[1305] = 1; em[1306] = 8; em[1307] = 1; /* 1305: pointer.struct.ecdsa_method */
    	em[1308] = 1310; em[1309] = 0; 
    em[1310] = 0; em[1311] = 48; em[1312] = 5; /* 1310: struct.ecdsa_method */
    	em[1313] = 141; em[1314] = 0; 
    	em[1315] = 1323; em[1316] = 8; 
    	em[1317] = 1326; em[1318] = 16; 
    	em[1319] = 1329; em[1320] = 24; 
    	em[1321] = 122; em[1322] = 40; 
    em[1323] = 8884097; em[1324] = 8; em[1325] = 0; /* 1323: pointer.func */
    em[1326] = 8884097; em[1327] = 8; em[1328] = 0; /* 1326: pointer.func */
    em[1329] = 8884097; em[1330] = 8; em[1331] = 0; /* 1329: pointer.func */
    em[1332] = 1; em[1333] = 8; em[1334] = 1; /* 1332: pointer.struct.rand_meth_st */
    	em[1335] = 1337; em[1336] = 0; 
    em[1337] = 0; em[1338] = 48; em[1339] = 6; /* 1337: struct.rand_meth_st */
    	em[1340] = 1352; em[1341] = 0; 
    	em[1342] = 1355; em[1343] = 8; 
    	em[1344] = 1358; em[1345] = 16; 
    	em[1346] = 1361; em[1347] = 24; 
    	em[1348] = 1355; em[1349] = 32; 
    	em[1350] = 1364; em[1351] = 40; 
    em[1352] = 8884097; em[1353] = 8; em[1354] = 0; /* 1352: pointer.func */
    em[1355] = 8884097; em[1356] = 8; em[1357] = 0; /* 1355: pointer.func */
    em[1358] = 8884097; em[1359] = 8; em[1360] = 0; /* 1358: pointer.func */
    em[1361] = 8884097; em[1362] = 8; em[1363] = 0; /* 1361: pointer.func */
    em[1364] = 8884097; em[1365] = 8; em[1366] = 0; /* 1364: pointer.func */
    em[1367] = 1; em[1368] = 8; em[1369] = 1; /* 1367: pointer.struct.store_method_st */
    	em[1370] = 1372; em[1371] = 0; 
    em[1372] = 0; em[1373] = 0; em[1374] = 0; /* 1372: struct.store_method_st */
    em[1375] = 8884097; em[1376] = 8; em[1377] = 0; /* 1375: pointer.func */
    em[1378] = 8884097; em[1379] = 8; em[1380] = 0; /* 1378: pointer.func */
    em[1381] = 8884097; em[1382] = 8; em[1383] = 0; /* 1381: pointer.func */
    em[1384] = 8884097; em[1385] = 8; em[1386] = 0; /* 1384: pointer.func */
    em[1387] = 8884097; em[1388] = 8; em[1389] = 0; /* 1387: pointer.func */
    em[1390] = 8884097; em[1391] = 8; em[1392] = 0; /* 1390: pointer.func */
    em[1393] = 8884097; em[1394] = 8; em[1395] = 0; /* 1393: pointer.func */
    em[1396] = 8884097; em[1397] = 8; em[1398] = 0; /* 1396: pointer.func */
    em[1399] = 1; em[1400] = 8; em[1401] = 1; /* 1399: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[1402] = 1404; em[1403] = 0; 
    em[1404] = 0; em[1405] = 32; em[1406] = 2; /* 1404: struct.ENGINE_CMD_DEFN_st */
    	em[1407] = 141; em[1408] = 8; 
    	em[1409] = 141; em[1410] = 16; 
    em[1411] = 0; em[1412] = 32; em[1413] = 2; /* 1411: struct.crypto_ex_data_st_fake */
    	em[1414] = 1418; em[1415] = 8; 
    	em[1416] = 358; em[1417] = 24; 
    em[1418] = 8884099; em[1419] = 8; em[1420] = 2; /* 1418: pointer_to_array_of_pointers_to_stack */
    	em[1421] = 836; em[1422] = 0; 
    	em[1423] = 355; em[1424] = 20; 
    em[1425] = 1; em[1426] = 8; em[1427] = 1; /* 1425: pointer.struct.engine_st */
    	em[1428] = 1098; em[1429] = 0; 
    em[1430] = 1; em[1431] = 8; em[1432] = 1; /* 1430: pointer.struct.bignum_st */
    	em[1433] = 893; em[1434] = 0; 
    em[1435] = 0; em[1436] = 32; em[1437] = 2; /* 1435: struct.crypto_ex_data_st_fake */
    	em[1438] = 1442; em[1439] = 8; 
    	em[1440] = 358; em[1441] = 24; 
    em[1442] = 8884099; em[1443] = 8; em[1444] = 2; /* 1442: pointer_to_array_of_pointers_to_stack */
    	em[1445] = 836; em[1446] = 0; 
    	em[1447] = 355; em[1448] = 20; 
    em[1449] = 1; em[1450] = 8; em[1451] = 1; /* 1449: pointer.struct.bn_mont_ctx_st */
    	em[1452] = 1454; em[1453] = 0; 
    em[1454] = 0; em[1455] = 96; em[1456] = 3; /* 1454: struct.bn_mont_ctx_st */
    	em[1457] = 893; em[1458] = 8; 
    	em[1459] = 893; em[1460] = 32; 
    	em[1461] = 893; em[1462] = 56; 
    em[1463] = 1; em[1464] = 8; em[1465] = 1; /* 1463: pointer.struct.bn_blinding_st */
    	em[1466] = 1468; em[1467] = 0; 
    em[1468] = 0; em[1469] = 88; em[1470] = 7; /* 1468: struct.bn_blinding_st */
    	em[1471] = 1485; em[1472] = 0; 
    	em[1473] = 1485; em[1474] = 8; 
    	em[1475] = 1485; em[1476] = 16; 
    	em[1477] = 1485; em[1478] = 24; 
    	em[1479] = 1502; em[1480] = 40; 
    	em[1481] = 1507; em[1482] = 72; 
    	em[1483] = 1521; em[1484] = 80; 
    em[1485] = 1; em[1486] = 8; em[1487] = 1; /* 1485: pointer.struct.bignum_st */
    	em[1488] = 1490; em[1489] = 0; 
    em[1490] = 0; em[1491] = 24; em[1492] = 1; /* 1490: struct.bignum_st */
    	em[1493] = 1495; em[1494] = 0; 
    em[1495] = 8884099; em[1496] = 8; em[1497] = 2; /* 1495: pointer_to_array_of_pointers_to_stack */
    	em[1498] = 798; em[1499] = 0; 
    	em[1500] = 355; em[1501] = 12; 
    em[1502] = 0; em[1503] = 16; em[1504] = 1; /* 1502: struct.crypto_threadid_st */
    	em[1505] = 836; em[1506] = 0; 
    em[1507] = 1; em[1508] = 8; em[1509] = 1; /* 1507: pointer.struct.bn_mont_ctx_st */
    	em[1510] = 1512; em[1511] = 0; 
    em[1512] = 0; em[1513] = 96; em[1514] = 3; /* 1512: struct.bn_mont_ctx_st */
    	em[1515] = 1490; em[1516] = 8; 
    	em[1517] = 1490; em[1518] = 32; 
    	em[1519] = 1490; em[1520] = 56; 
    em[1521] = 8884097; em[1522] = 8; em[1523] = 0; /* 1521: pointer.func */
    em[1524] = 1; em[1525] = 8; em[1526] = 1; /* 1524: pointer.struct.bn_mont_ctx_st */
    	em[1527] = 1529; em[1528] = 0; 
    em[1529] = 0; em[1530] = 96; em[1531] = 3; /* 1529: struct.bn_mont_ctx_st */
    	em[1532] = 1538; em[1533] = 8; 
    	em[1534] = 1538; em[1535] = 32; 
    	em[1536] = 1538; em[1537] = 56; 
    em[1538] = 0; em[1539] = 24; em[1540] = 1; /* 1538: struct.bignum_st */
    	em[1541] = 1543; em[1542] = 0; 
    em[1543] = 8884099; em[1544] = 8; em[1545] = 2; /* 1543: pointer_to_array_of_pointers_to_stack */
    	em[1546] = 798; em[1547] = 0; 
    	em[1548] = 355; em[1549] = 12; 
    em[1550] = 8884097; em[1551] = 8; em[1552] = 0; /* 1550: pointer.func */
    em[1553] = 1; em[1554] = 8; em[1555] = 1; /* 1553: pointer.struct.evp_pkey_asn1_method_st */
    	em[1556] = 908; em[1557] = 0; 
    em[1558] = 0; em[1559] = 56; em[1560] = 4; /* 1558: struct.evp_pkey_st */
    	em[1561] = 1553; em[1562] = 16; 
    	em[1563] = 1569; em[1564] = 24; 
    	em[1565] = 1574; em[1566] = 32; 
    	em[1567] = 1812; em[1568] = 48; 
    em[1569] = 1; em[1570] = 8; em[1571] = 1; /* 1569: pointer.struct.engine_st */
    	em[1572] = 1098; em[1573] = 0; 
    em[1574] = 8884101; em[1575] = 8; em[1576] = 6; /* 1574: union.union_of_evp_pkey_st */
    	em[1577] = 836; em[1578] = 0; 
    	em[1579] = 1589; em[1580] = 6; 
    	em[1581] = 1594; em[1582] = 116; 
    	em[1583] = 1725; em[1584] = 28; 
    	em[1585] = 378; em[1586] = 408; 
    	em[1587] = 355; em[1588] = 0; 
    em[1589] = 1; em[1590] = 8; em[1591] = 1; /* 1589: pointer.struct.rsa_st */
    	em[1592] = 1051; em[1593] = 0; 
    em[1594] = 1; em[1595] = 8; em[1596] = 1; /* 1594: pointer.struct.dsa_st */
    	em[1597] = 1599; em[1598] = 0; 
    em[1599] = 0; em[1600] = 136; em[1601] = 11; /* 1599: struct.dsa_st */
    	em[1602] = 1624; em[1603] = 24; 
    	em[1604] = 1624; em[1605] = 32; 
    	em[1606] = 1624; em[1607] = 40; 
    	em[1608] = 1624; em[1609] = 48; 
    	em[1610] = 1624; em[1611] = 56; 
    	em[1612] = 1624; em[1613] = 64; 
    	em[1614] = 1624; em[1615] = 72; 
    	em[1616] = 1641; em[1617] = 88; 
    	em[1618] = 1655; em[1619] = 104; 
    	em[1620] = 1669; em[1621] = 120; 
    	em[1622] = 1720; em[1623] = 128; 
    em[1624] = 1; em[1625] = 8; em[1626] = 1; /* 1624: pointer.struct.bignum_st */
    	em[1627] = 1629; em[1628] = 0; 
    em[1629] = 0; em[1630] = 24; em[1631] = 1; /* 1629: struct.bignum_st */
    	em[1632] = 1634; em[1633] = 0; 
    em[1634] = 8884099; em[1635] = 8; em[1636] = 2; /* 1634: pointer_to_array_of_pointers_to_stack */
    	em[1637] = 798; em[1638] = 0; 
    	em[1639] = 355; em[1640] = 12; 
    em[1641] = 1; em[1642] = 8; em[1643] = 1; /* 1641: pointer.struct.bn_mont_ctx_st */
    	em[1644] = 1646; em[1645] = 0; 
    em[1646] = 0; em[1647] = 96; em[1648] = 3; /* 1646: struct.bn_mont_ctx_st */
    	em[1649] = 1629; em[1650] = 8; 
    	em[1651] = 1629; em[1652] = 32; 
    	em[1653] = 1629; em[1654] = 56; 
    em[1655] = 0; em[1656] = 32; em[1657] = 2; /* 1655: struct.crypto_ex_data_st_fake */
    	em[1658] = 1662; em[1659] = 8; 
    	em[1660] = 358; em[1661] = 24; 
    em[1662] = 8884099; em[1663] = 8; em[1664] = 2; /* 1662: pointer_to_array_of_pointers_to_stack */
    	em[1665] = 836; em[1666] = 0; 
    	em[1667] = 355; em[1668] = 20; 
    em[1669] = 1; em[1670] = 8; em[1671] = 1; /* 1669: pointer.struct.dsa_method */
    	em[1672] = 1674; em[1673] = 0; 
    em[1674] = 0; em[1675] = 96; em[1676] = 11; /* 1674: struct.dsa_method */
    	em[1677] = 141; em[1678] = 0; 
    	em[1679] = 1699; em[1680] = 8; 
    	em[1681] = 1702; em[1682] = 16; 
    	em[1683] = 1705; em[1684] = 24; 
    	em[1685] = 1708; em[1686] = 32; 
    	em[1687] = 1711; em[1688] = 40; 
    	em[1689] = 1714; em[1690] = 48; 
    	em[1691] = 1714; em[1692] = 56; 
    	em[1693] = 122; em[1694] = 72; 
    	em[1695] = 1717; em[1696] = 80; 
    	em[1697] = 1714; em[1698] = 88; 
    em[1699] = 8884097; em[1700] = 8; em[1701] = 0; /* 1699: pointer.func */
    em[1702] = 8884097; em[1703] = 8; em[1704] = 0; /* 1702: pointer.func */
    em[1705] = 8884097; em[1706] = 8; em[1707] = 0; /* 1705: pointer.func */
    em[1708] = 8884097; em[1709] = 8; em[1710] = 0; /* 1708: pointer.func */
    em[1711] = 8884097; em[1712] = 8; em[1713] = 0; /* 1711: pointer.func */
    em[1714] = 8884097; em[1715] = 8; em[1716] = 0; /* 1714: pointer.func */
    em[1717] = 8884097; em[1718] = 8; em[1719] = 0; /* 1717: pointer.func */
    em[1720] = 1; em[1721] = 8; em[1722] = 1; /* 1720: pointer.struct.engine_st */
    	em[1723] = 1098; em[1724] = 0; 
    em[1725] = 1; em[1726] = 8; em[1727] = 1; /* 1725: pointer.struct.dh_st */
    	em[1728] = 1730; em[1729] = 0; 
    em[1730] = 0; em[1731] = 144; em[1732] = 12; /* 1730: struct.dh_st */
    	em[1733] = 1757; em[1734] = 8; 
    	em[1735] = 1757; em[1736] = 16; 
    	em[1737] = 1757; em[1738] = 32; 
    	em[1739] = 1757; em[1740] = 40; 
    	em[1741] = 1524; em[1742] = 56; 
    	em[1743] = 1757; em[1744] = 64; 
    	em[1745] = 1757; em[1746] = 72; 
    	em[1747] = 21; em[1748] = 80; 
    	em[1749] = 1757; em[1750] = 96; 
    	em[1751] = 1762; em[1752] = 112; 
    	em[1753] = 1776; em[1754] = 128; 
    	em[1755] = 1569; em[1756] = 136; 
    em[1757] = 1; em[1758] = 8; em[1759] = 1; /* 1757: pointer.struct.bignum_st */
    	em[1760] = 1538; em[1761] = 0; 
    em[1762] = 0; em[1763] = 32; em[1764] = 2; /* 1762: struct.crypto_ex_data_st_fake */
    	em[1765] = 1769; em[1766] = 8; 
    	em[1767] = 358; em[1768] = 24; 
    em[1769] = 8884099; em[1770] = 8; em[1771] = 2; /* 1769: pointer_to_array_of_pointers_to_stack */
    	em[1772] = 836; em[1773] = 0; 
    	em[1774] = 355; em[1775] = 20; 
    em[1776] = 1; em[1777] = 8; em[1778] = 1; /* 1776: pointer.struct.dh_method */
    	em[1779] = 1781; em[1780] = 0; 
    em[1781] = 0; em[1782] = 72; em[1783] = 8; /* 1781: struct.dh_method */
    	em[1784] = 141; em[1785] = 0; 
    	em[1786] = 1800; em[1787] = 8; 
    	em[1788] = 1803; em[1789] = 16; 
    	em[1790] = 1806; em[1791] = 24; 
    	em[1792] = 1800; em[1793] = 32; 
    	em[1794] = 1800; em[1795] = 40; 
    	em[1796] = 122; em[1797] = 56; 
    	em[1798] = 1809; em[1799] = 64; 
    em[1800] = 8884097; em[1801] = 8; em[1802] = 0; /* 1800: pointer.func */
    em[1803] = 8884097; em[1804] = 8; em[1805] = 0; /* 1803: pointer.func */
    em[1806] = 8884097; em[1807] = 8; em[1808] = 0; /* 1806: pointer.func */
    em[1809] = 8884097; em[1810] = 8; em[1811] = 0; /* 1809: pointer.func */
    em[1812] = 1; em[1813] = 8; em[1814] = 1; /* 1812: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1815] = 1817; em[1816] = 0; 
    em[1817] = 0; em[1818] = 32; em[1819] = 2; /* 1817: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1820] = 1824; em[1821] = 8; 
    	em[1822] = 358; em[1823] = 24; 
    em[1824] = 8884099; em[1825] = 8; em[1826] = 2; /* 1824: pointer_to_array_of_pointers_to_stack */
    	em[1827] = 1831; em[1828] = 0; 
    	em[1829] = 355; em[1830] = 20; 
    em[1831] = 0; em[1832] = 8; em[1833] = 1; /* 1831: pointer.X509_ATTRIBUTE */
    	em[1834] = 1836; em[1835] = 0; 
    em[1836] = 0; em[1837] = 0; em[1838] = 1; /* 1836: X509_ATTRIBUTE */
    	em[1839] = 1841; em[1840] = 0; 
    em[1841] = 0; em[1842] = 24; em[1843] = 2; /* 1841: struct.x509_attributes_st */
    	em[1844] = 127; em[1845] = 0; 
    	em[1846] = 361; em[1847] = 16; 
    em[1848] = 8884097; em[1849] = 8; em[1850] = 0; /* 1848: pointer.func */
    em[1851] = 8884097; em[1852] = 8; em[1853] = 0; /* 1851: pointer.func */
    em[1854] = 0; em[1855] = 1; em[1856] = 0; /* 1854: char */
    em[1857] = 8884097; em[1858] = 8; em[1859] = 0; /* 1857: pointer.func */
    em[1860] = 1; em[1861] = 8; em[1862] = 1; /* 1860: pointer.struct.evp_pkey_method_st */
    	em[1863] = 1865; em[1864] = 0; 
    em[1865] = 0; em[1866] = 208; em[1867] = 25; /* 1865: struct.evp_pkey_method_st */
    	em[1868] = 1918; em[1869] = 8; 
    	em[1870] = 1921; em[1871] = 16; 
    	em[1872] = 1924; em[1873] = 24; 
    	em[1874] = 1918; em[1875] = 32; 
    	em[1876] = 1927; em[1877] = 40; 
    	em[1878] = 1918; em[1879] = 48; 
    	em[1880] = 1927; em[1881] = 56; 
    	em[1882] = 1918; em[1883] = 64; 
    	em[1884] = 1930; em[1885] = 72; 
    	em[1886] = 1918; em[1887] = 80; 
    	em[1888] = 1933; em[1889] = 88; 
    	em[1890] = 1918; em[1891] = 96; 
    	em[1892] = 1930; em[1893] = 104; 
    	em[1894] = 1936; em[1895] = 112; 
    	em[1896] = 1848; em[1897] = 120; 
    	em[1898] = 1936; em[1899] = 128; 
    	em[1900] = 1939; em[1901] = 136; 
    	em[1902] = 1918; em[1903] = 144; 
    	em[1904] = 1930; em[1905] = 152; 
    	em[1906] = 1918; em[1907] = 160; 
    	em[1908] = 1930; em[1909] = 168; 
    	em[1910] = 1918; em[1911] = 176; 
    	em[1912] = 1857; em[1913] = 184; 
    	em[1914] = 1942; em[1915] = 192; 
    	em[1916] = 1851; em[1917] = 200; 
    em[1918] = 8884097; em[1919] = 8; em[1920] = 0; /* 1918: pointer.func */
    em[1921] = 8884097; em[1922] = 8; em[1923] = 0; /* 1921: pointer.func */
    em[1924] = 8884097; em[1925] = 8; em[1926] = 0; /* 1924: pointer.func */
    em[1927] = 8884097; em[1928] = 8; em[1929] = 0; /* 1927: pointer.func */
    em[1930] = 8884097; em[1931] = 8; em[1932] = 0; /* 1930: pointer.func */
    em[1933] = 8884097; em[1934] = 8; em[1935] = 0; /* 1933: pointer.func */
    em[1936] = 8884097; em[1937] = 8; em[1938] = 0; /* 1936: pointer.func */
    em[1939] = 8884097; em[1940] = 8; em[1941] = 0; /* 1939: pointer.func */
    em[1942] = 8884097; em[1943] = 8; em[1944] = 0; /* 1942: pointer.func */
    em[1945] = 8884097; em[1946] = 8; em[1947] = 0; /* 1945: pointer.func */
    em[1948] = 0; em[1949] = 48; em[1950] = 5; /* 1948: struct.env_md_ctx_st */
    	em[1951] = 1961; em[1952] = 0; 
    	em[1953] = 2000; em[1954] = 8; 
    	em[1955] = 836; em[1956] = 24; 
    	em[1957] = 2005; em[1958] = 32; 
    	em[1959] = 1988; em[1960] = 40; 
    em[1961] = 1; em[1962] = 8; em[1963] = 1; /* 1961: pointer.struct.env_md_st */
    	em[1964] = 1966; em[1965] = 0; 
    em[1966] = 0; em[1967] = 120; em[1968] = 8; /* 1966: struct.env_md_st */
    	em[1969] = 1985; em[1970] = 24; 
    	em[1971] = 1988; em[1972] = 32; 
    	em[1973] = 1991; em[1974] = 40; 
    	em[1975] = 1994; em[1976] = 48; 
    	em[1977] = 1985; em[1978] = 56; 
    	em[1979] = 1997; em[1980] = 64; 
    	em[1981] = 1550; em[1982] = 72; 
    	em[1983] = 1945; em[1984] = 112; 
    em[1985] = 8884097; em[1986] = 8; em[1987] = 0; /* 1985: pointer.func */
    em[1988] = 8884097; em[1989] = 8; em[1990] = 0; /* 1988: pointer.func */
    em[1991] = 8884097; em[1992] = 8; em[1993] = 0; /* 1991: pointer.func */
    em[1994] = 8884097; em[1995] = 8; em[1996] = 0; /* 1994: pointer.func */
    em[1997] = 8884097; em[1998] = 8; em[1999] = 0; /* 1997: pointer.func */
    em[2000] = 1; em[2001] = 8; em[2002] = 1; /* 2000: pointer.struct.engine_st */
    	em[2003] = 1098; em[2004] = 0; 
    em[2005] = 1; em[2006] = 8; em[2007] = 1; /* 2005: pointer.struct.evp_pkey_ctx_st */
    	em[2008] = 2010; em[2009] = 0; 
    em[2010] = 0; em[2011] = 80; em[2012] = 8; /* 2010: struct.evp_pkey_ctx_st */
    	em[2013] = 1860; em[2014] = 0; 
    	em[2015] = 1569; em[2016] = 8; 
    	em[2017] = 2029; em[2018] = 16; 
    	em[2019] = 2029; em[2020] = 24; 
    	em[2021] = 836; em[2022] = 40; 
    	em[2023] = 836; em[2024] = 48; 
    	em[2025] = 0; em[2026] = 56; 
    	em[2027] = 2034; em[2028] = 64; 
    em[2029] = 1; em[2030] = 8; em[2031] = 1; /* 2029: pointer.struct.evp_pkey_st */
    	em[2032] = 1558; em[2033] = 0; 
    em[2034] = 1; em[2035] = 8; em[2036] = 1; /* 2034: pointer.int */
    	em[2037] = 355; em[2038] = 0; 
    em[2039] = 1; em[2040] = 8; em[2041] = 1; /* 2039: pointer.struct.hmac_ctx_st */
    	em[2042] = 2044; em[2043] = 0; 
    em[2044] = 0; em[2045] = 288; em[2046] = 4; /* 2044: struct.hmac_ctx_st */
    	em[2047] = 1961; em[2048] = 0; 
    	em[2049] = 1948; em[2050] = 8; 
    	em[2051] = 1948; em[2052] = 56; 
    	em[2053] = 1948; em[2054] = 104; 
    args_addr->arg_entity_index[0] = 2039;
    args_addr->arg_entity_index[1] = 836;
    args_addr->arg_entity_index[2] = 355;
    args_addr->arg_entity_index[3] = 1961;
    args_addr->arg_entity_index[4] = 2000;
    args_addr->ret_entity_index = 355;
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

