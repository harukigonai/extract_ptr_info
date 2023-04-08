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
    	em[88] = 64; em[89] = 0; 
    	em[90] = 59; em[91] = 0; 
    	em[92] = 54; em[93] = 0; 
    	em[94] = 49; em[95] = 0; 
    	em[96] = 151; em[97] = 0; 
    	em[98] = 44; em[99] = 0; 
    	em[100] = 39; em[101] = 0; 
    	em[102] = 34; em[103] = 0; 
    	em[104] = 29; em[105] = 0; 
    	em[106] = 156; em[107] = 0; 
    	em[108] = 161; em[109] = 0; 
    	em[110] = 166; em[111] = 0; 
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
    em[176] = 1; em[177] = 8; em[178] = 1; /* 176: pointer.struct.ASN1_VALUE_st */
    	em[179] = 181; em[180] = 0; 
    em[181] = 0; em[182] = 0; em[183] = 0; /* 181: struct.ASN1_VALUE_st */
    em[184] = 1; em[185] = 8; em[186] = 1; /* 184: pointer.struct.asn1_string_st */
    	em[187] = 189; em[188] = 0; 
    em[189] = 0; em[190] = 24; em[191] = 1; /* 189: struct.asn1_string_st */
    	em[192] = 21; em[193] = 8; 
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
    em[219] = 1; em[220] = 8; em[221] = 1; /* 219: pointer.struct.asn1_string_st */
    	em[222] = 189; em[223] = 0; 
    em[224] = 1; em[225] = 8; em[226] = 1; /* 224: pointer.struct.asn1_string_st */
    	em[227] = 189; em[228] = 0; 
    em[229] = 1; em[230] = 8; em[231] = 1; /* 229: pointer.struct.asn1_string_st */
    	em[232] = 189; em[233] = 0; 
    em[234] = 0; em[235] = 40; em[236] = 3; /* 234: struct.asn1_object_st */
    	em[237] = 141; em[238] = 0; 
    	em[239] = 141; em[240] = 8; 
    	em[241] = 146; em[242] = 24; 
    em[243] = 1; em[244] = 8; em[245] = 1; /* 243: pointer.struct.asn1_string_st */
    	em[246] = 189; em[247] = 0; 
    em[248] = 0; em[249] = 8; em[250] = 20; /* 248: union.unknown */
    	em[251] = 122; em[252] = 0; 
    	em[253] = 243; em[254] = 0; 
    	em[255] = 291; em[256] = 0; 
    	em[257] = 229; em[258] = 0; 
    	em[259] = 224; em[260] = 0; 
    	em[261] = 219; em[262] = 0; 
    	em[263] = 214; em[264] = 0; 
    	em[265] = 296; em[266] = 0; 
    	em[267] = 301; em[268] = 0; 
    	em[269] = 209; em[270] = 0; 
    	em[271] = 204; em[272] = 0; 
    	em[273] = 199; em[274] = 0; 
    	em[275] = 306; em[276] = 0; 
    	em[277] = 311; em[278] = 0; 
    	em[279] = 194; em[280] = 0; 
    	em[281] = 316; em[282] = 0; 
    	em[283] = 184; em[284] = 0; 
    	em[285] = 243; em[286] = 0; 
    	em[287] = 243; em[288] = 0; 
    	em[289] = 176; em[290] = 0; 
    em[291] = 1; em[292] = 8; em[293] = 1; /* 291: pointer.struct.asn1_object_st */
    	em[294] = 234; em[295] = 0; 
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
    em[321] = 0; em[322] = 16; em[323] = 1; /* 321: struct.asn1_type_st */
    	em[324] = 248; em[325] = 8; 
    em[326] = 1; em[327] = 8; em[328] = 1; /* 326: pointer.struct.stack_st_ASN1_TYPE */
    	em[329] = 331; em[330] = 0; 
    em[331] = 0; em[332] = 32; em[333] = 2; /* 331: struct.stack_st_fake_ASN1_TYPE */
    	em[334] = 338; em[335] = 8; 
    	em[336] = 358; em[337] = 24; 
    em[338] = 8884099; em[339] = 8; em[340] = 2; /* 338: pointer_to_array_of_pointers_to_stack */
    	em[341] = 345; em[342] = 0; 
    	em[343] = 355; em[344] = 20; 
    em[345] = 0; em[346] = 8; em[347] = 1; /* 345: pointer.ASN1_TYPE */
    	em[348] = 350; em[349] = 0; 
    em[350] = 0; em[351] = 0; em[352] = 1; /* 350: ASN1_TYPE */
    	em[353] = 321; em[354] = 0; 
    em[355] = 0; em[356] = 4; em[357] = 0; /* 355: int */
    em[358] = 8884097; em[359] = 8; em[360] = 0; /* 358: pointer.func */
    em[361] = 0; em[362] = 96; em[363] = 3; /* 361: struct.bn_mont_ctx_st */
    	em[364] = 370; em[365] = 8; 
    	em[366] = 370; em[367] = 32; 
    	em[368] = 370; em[369] = 56; 
    em[370] = 0; em[371] = 24; em[372] = 1; /* 370: struct.bignum_st */
    	em[373] = 375; em[374] = 0; 
    em[375] = 8884099; em[376] = 8; em[377] = 2; /* 375: pointer_to_array_of_pointers_to_stack */
    	em[378] = 382; em[379] = 0; 
    	em[380] = 355; em[381] = 12; 
    em[382] = 0; em[383] = 8; em[384] = 0; /* 382: long unsigned int */
    em[385] = 1; em[386] = 8; em[387] = 1; /* 385: pointer.struct.ec_method_st */
    	em[388] = 390; em[389] = 0; 
    em[390] = 0; em[391] = 304; em[392] = 37; /* 390: struct.ec_method_st */
    	em[393] = 467; em[394] = 8; 
    	em[395] = 470; em[396] = 16; 
    	em[397] = 470; em[398] = 24; 
    	em[399] = 473; em[400] = 32; 
    	em[401] = 476; em[402] = 40; 
    	em[403] = 479; em[404] = 48; 
    	em[405] = 482; em[406] = 56; 
    	em[407] = 485; em[408] = 64; 
    	em[409] = 488; em[410] = 72; 
    	em[411] = 491; em[412] = 80; 
    	em[413] = 491; em[414] = 88; 
    	em[415] = 494; em[416] = 96; 
    	em[417] = 497; em[418] = 104; 
    	em[419] = 500; em[420] = 112; 
    	em[421] = 503; em[422] = 120; 
    	em[423] = 506; em[424] = 128; 
    	em[425] = 509; em[426] = 136; 
    	em[427] = 512; em[428] = 144; 
    	em[429] = 515; em[430] = 152; 
    	em[431] = 518; em[432] = 160; 
    	em[433] = 521; em[434] = 168; 
    	em[435] = 524; em[436] = 176; 
    	em[437] = 527; em[438] = 184; 
    	em[439] = 530; em[440] = 192; 
    	em[441] = 533; em[442] = 200; 
    	em[443] = 536; em[444] = 208; 
    	em[445] = 527; em[446] = 216; 
    	em[447] = 539; em[448] = 224; 
    	em[449] = 542; em[450] = 232; 
    	em[451] = 545; em[452] = 240; 
    	em[453] = 482; em[454] = 248; 
    	em[455] = 548; em[456] = 256; 
    	em[457] = 551; em[458] = 264; 
    	em[459] = 548; em[460] = 272; 
    	em[461] = 551; em[462] = 280; 
    	em[463] = 551; em[464] = 288; 
    	em[465] = 554; em[466] = 296; 
    em[467] = 8884097; em[468] = 8; em[469] = 0; /* 467: pointer.func */
    em[470] = 8884097; em[471] = 8; em[472] = 0; /* 470: pointer.func */
    em[473] = 8884097; em[474] = 8; em[475] = 0; /* 473: pointer.func */
    em[476] = 8884097; em[477] = 8; em[478] = 0; /* 476: pointer.func */
    em[479] = 8884097; em[480] = 8; em[481] = 0; /* 479: pointer.func */
    em[482] = 8884097; em[483] = 8; em[484] = 0; /* 482: pointer.func */
    em[485] = 8884097; em[486] = 8; em[487] = 0; /* 485: pointer.func */
    em[488] = 8884097; em[489] = 8; em[490] = 0; /* 488: pointer.func */
    em[491] = 8884097; em[492] = 8; em[493] = 0; /* 491: pointer.func */
    em[494] = 8884097; em[495] = 8; em[496] = 0; /* 494: pointer.func */
    em[497] = 8884097; em[498] = 8; em[499] = 0; /* 497: pointer.func */
    em[500] = 8884097; em[501] = 8; em[502] = 0; /* 500: pointer.func */
    em[503] = 8884097; em[504] = 8; em[505] = 0; /* 503: pointer.func */
    em[506] = 8884097; em[507] = 8; em[508] = 0; /* 506: pointer.func */
    em[509] = 8884097; em[510] = 8; em[511] = 0; /* 509: pointer.func */
    em[512] = 8884097; em[513] = 8; em[514] = 0; /* 512: pointer.func */
    em[515] = 8884097; em[516] = 8; em[517] = 0; /* 515: pointer.func */
    em[518] = 8884097; em[519] = 8; em[520] = 0; /* 518: pointer.func */
    em[521] = 8884097; em[522] = 8; em[523] = 0; /* 521: pointer.func */
    em[524] = 8884097; em[525] = 8; em[526] = 0; /* 524: pointer.func */
    em[527] = 8884097; em[528] = 8; em[529] = 0; /* 527: pointer.func */
    em[530] = 8884097; em[531] = 8; em[532] = 0; /* 530: pointer.func */
    em[533] = 8884097; em[534] = 8; em[535] = 0; /* 533: pointer.func */
    em[536] = 8884097; em[537] = 8; em[538] = 0; /* 536: pointer.func */
    em[539] = 8884097; em[540] = 8; em[541] = 0; /* 539: pointer.func */
    em[542] = 8884097; em[543] = 8; em[544] = 0; /* 542: pointer.func */
    em[545] = 8884097; em[546] = 8; em[547] = 0; /* 545: pointer.func */
    em[548] = 8884097; em[549] = 8; em[550] = 0; /* 548: pointer.func */
    em[551] = 8884097; em[552] = 8; em[553] = 0; /* 551: pointer.func */
    em[554] = 8884097; em[555] = 8; em[556] = 0; /* 554: pointer.func */
    em[557] = 8884097; em[558] = 8; em[559] = 0; /* 557: pointer.func */
    em[560] = 1; em[561] = 8; em[562] = 1; /* 560: pointer.struct.bignum_st */
    	em[563] = 370; em[564] = 0; 
    em[565] = 8884097; em[566] = 8; em[567] = 0; /* 565: pointer.func */
    em[568] = 8884097; em[569] = 8; em[570] = 0; /* 568: pointer.func */
    em[571] = 0; em[572] = 8; em[573] = 0; /* 571: pointer.void */
    em[574] = 0; em[575] = 168; em[576] = 17; /* 574: struct.rsa_st */
    	em[577] = 611; em[578] = 16; 
    	em[579] = 660; em[580] = 24; 
    	em[581] = 560; em[582] = 32; 
    	em[583] = 560; em[584] = 40; 
    	em[585] = 560; em[586] = 48; 
    	em[587] = 560; em[588] = 56; 
    	em[589] = 560; em[590] = 64; 
    	em[591] = 560; em[592] = 72; 
    	em[593] = 560; em[594] = 80; 
    	em[595] = 560; em[596] = 88; 
    	em[597] = 1000; em[598] = 96; 
    	em[599] = 1014; em[600] = 120; 
    	em[601] = 1014; em[602] = 128; 
    	em[603] = 1014; em[604] = 136; 
    	em[605] = 122; em[606] = 144; 
    	em[607] = 1019; em[608] = 152; 
    	em[609] = 1019; em[610] = 160; 
    em[611] = 1; em[612] = 8; em[613] = 1; /* 611: pointer.struct.rsa_meth_st */
    	em[614] = 616; em[615] = 0; 
    em[616] = 0; em[617] = 112; em[618] = 13; /* 616: struct.rsa_meth_st */
    	em[619] = 141; em[620] = 0; 
    	em[621] = 645; em[622] = 8; 
    	em[623] = 645; em[624] = 16; 
    	em[625] = 645; em[626] = 24; 
    	em[627] = 645; em[628] = 32; 
    	em[629] = 648; em[630] = 40; 
    	em[631] = 651; em[632] = 48; 
    	em[633] = 568; em[634] = 56; 
    	em[635] = 568; em[636] = 64; 
    	em[637] = 122; em[638] = 80; 
    	em[639] = 654; em[640] = 88; 
    	em[641] = 657; em[642] = 96; 
    	em[643] = 565; em[644] = 104; 
    em[645] = 8884097; em[646] = 8; em[647] = 0; /* 645: pointer.func */
    em[648] = 8884097; em[649] = 8; em[650] = 0; /* 648: pointer.func */
    em[651] = 8884097; em[652] = 8; em[653] = 0; /* 651: pointer.func */
    em[654] = 8884097; em[655] = 8; em[656] = 0; /* 654: pointer.func */
    em[657] = 8884097; em[658] = 8; em[659] = 0; /* 657: pointer.func */
    em[660] = 1; em[661] = 8; em[662] = 1; /* 660: pointer.struct.engine_st */
    	em[663] = 665; em[664] = 0; 
    em[665] = 0; em[666] = 216; em[667] = 24; /* 665: struct.engine_st */
    	em[668] = 141; em[669] = 0; 
    	em[670] = 141; em[671] = 8; 
    	em[672] = 716; em[673] = 16; 
    	em[674] = 771; em[675] = 24; 
    	em[676] = 822; em[677] = 32; 
    	em[678] = 858; em[679] = 40; 
    	em[680] = 875; em[681] = 48; 
    	em[682] = 902; em[683] = 56; 
    	em[684] = 937; em[685] = 64; 
    	em[686] = 945; em[687] = 72; 
    	em[688] = 948; em[689] = 80; 
    	em[690] = 951; em[691] = 88; 
    	em[692] = 954; em[693] = 96; 
    	em[694] = 957; em[695] = 104; 
    	em[696] = 957; em[697] = 112; 
    	em[698] = 957; em[699] = 120; 
    	em[700] = 960; em[701] = 128; 
    	em[702] = 963; em[703] = 136; 
    	em[704] = 963; em[705] = 144; 
    	em[706] = 966; em[707] = 152; 
    	em[708] = 969; em[709] = 160; 
    	em[710] = 981; em[711] = 184; 
    	em[712] = 995; em[713] = 200; 
    	em[714] = 995; em[715] = 208; 
    em[716] = 1; em[717] = 8; em[718] = 1; /* 716: pointer.struct.rsa_meth_st */
    	em[719] = 721; em[720] = 0; 
    em[721] = 0; em[722] = 112; em[723] = 13; /* 721: struct.rsa_meth_st */
    	em[724] = 141; em[725] = 0; 
    	em[726] = 750; em[727] = 8; 
    	em[728] = 750; em[729] = 16; 
    	em[730] = 750; em[731] = 24; 
    	em[732] = 750; em[733] = 32; 
    	em[734] = 753; em[735] = 40; 
    	em[736] = 756; em[737] = 48; 
    	em[738] = 759; em[739] = 56; 
    	em[740] = 759; em[741] = 64; 
    	em[742] = 122; em[743] = 80; 
    	em[744] = 762; em[745] = 88; 
    	em[746] = 765; em[747] = 96; 
    	em[748] = 768; em[749] = 104; 
    em[750] = 8884097; em[751] = 8; em[752] = 0; /* 750: pointer.func */
    em[753] = 8884097; em[754] = 8; em[755] = 0; /* 753: pointer.func */
    em[756] = 8884097; em[757] = 8; em[758] = 0; /* 756: pointer.func */
    em[759] = 8884097; em[760] = 8; em[761] = 0; /* 759: pointer.func */
    em[762] = 8884097; em[763] = 8; em[764] = 0; /* 762: pointer.func */
    em[765] = 8884097; em[766] = 8; em[767] = 0; /* 765: pointer.func */
    em[768] = 8884097; em[769] = 8; em[770] = 0; /* 768: pointer.func */
    em[771] = 1; em[772] = 8; em[773] = 1; /* 771: pointer.struct.dsa_method */
    	em[774] = 776; em[775] = 0; 
    em[776] = 0; em[777] = 96; em[778] = 11; /* 776: struct.dsa_method */
    	em[779] = 141; em[780] = 0; 
    	em[781] = 801; em[782] = 8; 
    	em[783] = 804; em[784] = 16; 
    	em[785] = 807; em[786] = 24; 
    	em[787] = 810; em[788] = 32; 
    	em[789] = 813; em[790] = 40; 
    	em[791] = 816; em[792] = 48; 
    	em[793] = 816; em[794] = 56; 
    	em[795] = 122; em[796] = 72; 
    	em[797] = 819; em[798] = 80; 
    	em[799] = 816; em[800] = 88; 
    em[801] = 8884097; em[802] = 8; em[803] = 0; /* 801: pointer.func */
    em[804] = 8884097; em[805] = 8; em[806] = 0; /* 804: pointer.func */
    em[807] = 8884097; em[808] = 8; em[809] = 0; /* 807: pointer.func */
    em[810] = 8884097; em[811] = 8; em[812] = 0; /* 810: pointer.func */
    em[813] = 8884097; em[814] = 8; em[815] = 0; /* 813: pointer.func */
    em[816] = 8884097; em[817] = 8; em[818] = 0; /* 816: pointer.func */
    em[819] = 8884097; em[820] = 8; em[821] = 0; /* 819: pointer.func */
    em[822] = 1; em[823] = 8; em[824] = 1; /* 822: pointer.struct.dh_method */
    	em[825] = 827; em[826] = 0; 
    em[827] = 0; em[828] = 72; em[829] = 8; /* 827: struct.dh_method */
    	em[830] = 141; em[831] = 0; 
    	em[832] = 846; em[833] = 8; 
    	em[834] = 849; em[835] = 16; 
    	em[836] = 852; em[837] = 24; 
    	em[838] = 846; em[839] = 32; 
    	em[840] = 846; em[841] = 40; 
    	em[842] = 122; em[843] = 56; 
    	em[844] = 855; em[845] = 64; 
    em[846] = 8884097; em[847] = 8; em[848] = 0; /* 846: pointer.func */
    em[849] = 8884097; em[850] = 8; em[851] = 0; /* 849: pointer.func */
    em[852] = 8884097; em[853] = 8; em[854] = 0; /* 852: pointer.func */
    em[855] = 8884097; em[856] = 8; em[857] = 0; /* 855: pointer.func */
    em[858] = 1; em[859] = 8; em[860] = 1; /* 858: pointer.struct.ecdh_method */
    	em[861] = 863; em[862] = 0; 
    em[863] = 0; em[864] = 32; em[865] = 3; /* 863: struct.ecdh_method */
    	em[866] = 141; em[867] = 0; 
    	em[868] = 872; em[869] = 8; 
    	em[870] = 122; em[871] = 24; 
    em[872] = 8884097; em[873] = 8; em[874] = 0; /* 872: pointer.func */
    em[875] = 1; em[876] = 8; em[877] = 1; /* 875: pointer.struct.ecdsa_method */
    	em[878] = 880; em[879] = 0; 
    em[880] = 0; em[881] = 48; em[882] = 5; /* 880: struct.ecdsa_method */
    	em[883] = 141; em[884] = 0; 
    	em[885] = 893; em[886] = 8; 
    	em[887] = 896; em[888] = 16; 
    	em[889] = 899; em[890] = 24; 
    	em[891] = 122; em[892] = 40; 
    em[893] = 8884097; em[894] = 8; em[895] = 0; /* 893: pointer.func */
    em[896] = 8884097; em[897] = 8; em[898] = 0; /* 896: pointer.func */
    em[899] = 8884097; em[900] = 8; em[901] = 0; /* 899: pointer.func */
    em[902] = 1; em[903] = 8; em[904] = 1; /* 902: pointer.struct.rand_meth_st */
    	em[905] = 907; em[906] = 0; 
    em[907] = 0; em[908] = 48; em[909] = 6; /* 907: struct.rand_meth_st */
    	em[910] = 922; em[911] = 0; 
    	em[912] = 925; em[913] = 8; 
    	em[914] = 928; em[915] = 16; 
    	em[916] = 931; em[917] = 24; 
    	em[918] = 925; em[919] = 32; 
    	em[920] = 934; em[921] = 40; 
    em[922] = 8884097; em[923] = 8; em[924] = 0; /* 922: pointer.func */
    em[925] = 8884097; em[926] = 8; em[927] = 0; /* 925: pointer.func */
    em[928] = 8884097; em[929] = 8; em[930] = 0; /* 928: pointer.func */
    em[931] = 8884097; em[932] = 8; em[933] = 0; /* 931: pointer.func */
    em[934] = 8884097; em[935] = 8; em[936] = 0; /* 934: pointer.func */
    em[937] = 1; em[938] = 8; em[939] = 1; /* 937: pointer.struct.store_method_st */
    	em[940] = 942; em[941] = 0; 
    em[942] = 0; em[943] = 0; em[944] = 0; /* 942: struct.store_method_st */
    em[945] = 8884097; em[946] = 8; em[947] = 0; /* 945: pointer.func */
    em[948] = 8884097; em[949] = 8; em[950] = 0; /* 948: pointer.func */
    em[951] = 8884097; em[952] = 8; em[953] = 0; /* 951: pointer.func */
    em[954] = 8884097; em[955] = 8; em[956] = 0; /* 954: pointer.func */
    em[957] = 8884097; em[958] = 8; em[959] = 0; /* 957: pointer.func */
    em[960] = 8884097; em[961] = 8; em[962] = 0; /* 960: pointer.func */
    em[963] = 8884097; em[964] = 8; em[965] = 0; /* 963: pointer.func */
    em[966] = 8884097; em[967] = 8; em[968] = 0; /* 966: pointer.func */
    em[969] = 1; em[970] = 8; em[971] = 1; /* 969: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[972] = 974; em[973] = 0; 
    em[974] = 0; em[975] = 32; em[976] = 2; /* 974: struct.ENGINE_CMD_DEFN_st */
    	em[977] = 141; em[978] = 8; 
    	em[979] = 141; em[980] = 16; 
    em[981] = 0; em[982] = 32; em[983] = 2; /* 981: struct.crypto_ex_data_st_fake */
    	em[984] = 988; em[985] = 8; 
    	em[986] = 358; em[987] = 24; 
    em[988] = 8884099; em[989] = 8; em[990] = 2; /* 988: pointer_to_array_of_pointers_to_stack */
    	em[991] = 571; em[992] = 0; 
    	em[993] = 355; em[994] = 20; 
    em[995] = 1; em[996] = 8; em[997] = 1; /* 995: pointer.struct.engine_st */
    	em[998] = 665; em[999] = 0; 
    em[1000] = 0; em[1001] = 32; em[1002] = 2; /* 1000: struct.crypto_ex_data_st_fake */
    	em[1003] = 1007; em[1004] = 8; 
    	em[1005] = 358; em[1006] = 24; 
    em[1007] = 8884099; em[1008] = 8; em[1009] = 2; /* 1007: pointer_to_array_of_pointers_to_stack */
    	em[1010] = 571; em[1011] = 0; 
    	em[1012] = 355; em[1013] = 20; 
    em[1014] = 1; em[1015] = 8; em[1016] = 1; /* 1014: pointer.struct.bn_mont_ctx_st */
    	em[1017] = 361; em[1018] = 0; 
    em[1019] = 1; em[1020] = 8; em[1021] = 1; /* 1019: pointer.struct.bn_blinding_st */
    	em[1022] = 1024; em[1023] = 0; 
    em[1024] = 0; em[1025] = 88; em[1026] = 7; /* 1024: struct.bn_blinding_st */
    	em[1027] = 1041; em[1028] = 0; 
    	em[1029] = 1041; em[1030] = 8; 
    	em[1031] = 1041; em[1032] = 16; 
    	em[1033] = 1041; em[1034] = 24; 
    	em[1035] = 1058; em[1036] = 40; 
    	em[1037] = 1063; em[1038] = 72; 
    	em[1039] = 1077; em[1040] = 80; 
    em[1041] = 1; em[1042] = 8; em[1043] = 1; /* 1041: pointer.struct.bignum_st */
    	em[1044] = 1046; em[1045] = 0; 
    em[1046] = 0; em[1047] = 24; em[1048] = 1; /* 1046: struct.bignum_st */
    	em[1049] = 1051; em[1050] = 0; 
    em[1051] = 8884099; em[1052] = 8; em[1053] = 2; /* 1051: pointer_to_array_of_pointers_to_stack */
    	em[1054] = 382; em[1055] = 0; 
    	em[1056] = 355; em[1057] = 12; 
    em[1058] = 0; em[1059] = 16; em[1060] = 1; /* 1058: struct.crypto_threadid_st */
    	em[1061] = 571; em[1062] = 0; 
    em[1063] = 1; em[1064] = 8; em[1065] = 1; /* 1063: pointer.struct.bn_mont_ctx_st */
    	em[1066] = 1068; em[1067] = 0; 
    em[1068] = 0; em[1069] = 96; em[1070] = 3; /* 1068: struct.bn_mont_ctx_st */
    	em[1071] = 1046; em[1072] = 8; 
    	em[1073] = 1046; em[1074] = 32; 
    	em[1075] = 1046; em[1076] = 56; 
    em[1077] = 8884097; em[1078] = 8; em[1079] = 0; /* 1077: pointer.func */
    em[1080] = 8884097; em[1081] = 8; em[1082] = 0; /* 1080: pointer.func */
    em[1083] = 8884097; em[1084] = 8; em[1085] = 0; /* 1083: pointer.func */
    em[1086] = 8884097; em[1087] = 8; em[1088] = 0; /* 1086: pointer.func */
    em[1089] = 8884097; em[1090] = 8; em[1091] = 0; /* 1089: pointer.func */
    em[1092] = 0; em[1093] = 208; em[1094] = 24; /* 1092: struct.evp_pkey_asn1_method_st */
    	em[1095] = 122; em[1096] = 16; 
    	em[1097] = 122; em[1098] = 24; 
    	em[1099] = 1143; em[1100] = 32; 
    	em[1101] = 1146; em[1102] = 40; 
    	em[1103] = 1149; em[1104] = 48; 
    	em[1105] = 1152; em[1106] = 56; 
    	em[1107] = 1155; em[1108] = 64; 
    	em[1109] = 1158; em[1110] = 72; 
    	em[1111] = 1152; em[1112] = 80; 
    	em[1113] = 1086; em[1114] = 88; 
    	em[1115] = 1086; em[1116] = 96; 
    	em[1117] = 1161; em[1118] = 104; 
    	em[1119] = 1164; em[1120] = 112; 
    	em[1121] = 1086; em[1122] = 120; 
    	em[1123] = 1089; em[1124] = 128; 
    	em[1125] = 1149; em[1126] = 136; 
    	em[1127] = 1152; em[1128] = 144; 
    	em[1129] = 1167; em[1130] = 152; 
    	em[1131] = 1170; em[1132] = 160; 
    	em[1133] = 1083; em[1134] = 168; 
    	em[1135] = 1161; em[1136] = 176; 
    	em[1137] = 1164; em[1138] = 184; 
    	em[1139] = 1173; em[1140] = 192; 
    	em[1141] = 1176; em[1142] = 200; 
    em[1143] = 8884097; em[1144] = 8; em[1145] = 0; /* 1143: pointer.func */
    em[1146] = 8884097; em[1147] = 8; em[1148] = 0; /* 1146: pointer.func */
    em[1149] = 8884097; em[1150] = 8; em[1151] = 0; /* 1149: pointer.func */
    em[1152] = 8884097; em[1153] = 8; em[1154] = 0; /* 1152: pointer.func */
    em[1155] = 8884097; em[1156] = 8; em[1157] = 0; /* 1155: pointer.func */
    em[1158] = 8884097; em[1159] = 8; em[1160] = 0; /* 1158: pointer.func */
    em[1161] = 8884097; em[1162] = 8; em[1163] = 0; /* 1161: pointer.func */
    em[1164] = 8884097; em[1165] = 8; em[1166] = 0; /* 1164: pointer.func */
    em[1167] = 8884097; em[1168] = 8; em[1169] = 0; /* 1167: pointer.func */
    em[1170] = 8884097; em[1171] = 8; em[1172] = 0; /* 1170: pointer.func */
    em[1173] = 8884097; em[1174] = 8; em[1175] = 0; /* 1173: pointer.func */
    em[1176] = 8884097; em[1177] = 8; em[1178] = 0; /* 1176: pointer.func */
    em[1179] = 8884097; em[1180] = 8; em[1181] = 0; /* 1179: pointer.func */
    em[1182] = 1; em[1183] = 8; em[1184] = 1; /* 1182: pointer.struct.bignum_st */
    	em[1185] = 1187; em[1186] = 0; 
    em[1187] = 0; em[1188] = 24; em[1189] = 1; /* 1187: struct.bignum_st */
    	em[1190] = 1192; em[1191] = 0; 
    em[1192] = 8884099; em[1193] = 8; em[1194] = 2; /* 1192: pointer_to_array_of_pointers_to_stack */
    	em[1195] = 382; em[1196] = 0; 
    	em[1197] = 355; em[1198] = 12; 
    em[1199] = 8884097; em[1200] = 8; em[1201] = 0; /* 1199: pointer.func */
    em[1202] = 8884097; em[1203] = 8; em[1204] = 0; /* 1202: pointer.func */
    em[1205] = 1; em[1206] = 8; em[1207] = 1; /* 1205: pointer.struct.rsa_st */
    	em[1208] = 574; em[1209] = 0; 
    em[1210] = 8884097; em[1211] = 8; em[1212] = 0; /* 1210: pointer.func */
    em[1213] = 8884097; em[1214] = 8; em[1215] = 0; /* 1213: pointer.func */
    em[1216] = 8884097; em[1217] = 8; em[1218] = 0; /* 1216: pointer.func */
    em[1219] = 8884097; em[1220] = 8; em[1221] = 0; /* 1219: pointer.func */
    em[1222] = 0; em[1223] = 208; em[1224] = 25; /* 1222: struct.evp_pkey_method_st */
    	em[1225] = 1219; em[1226] = 8; 
    	em[1227] = 1275; em[1228] = 16; 
    	em[1229] = 1278; em[1230] = 24; 
    	em[1231] = 1219; em[1232] = 32; 
    	em[1233] = 1281; em[1234] = 40; 
    	em[1235] = 1219; em[1236] = 48; 
    	em[1237] = 1281; em[1238] = 56; 
    	em[1239] = 1219; em[1240] = 64; 
    	em[1241] = 1284; em[1242] = 72; 
    	em[1243] = 1219; em[1244] = 80; 
    	em[1245] = 1287; em[1246] = 88; 
    	em[1247] = 1219; em[1248] = 96; 
    	em[1249] = 1284; em[1250] = 104; 
    	em[1251] = 1290; em[1252] = 112; 
    	em[1253] = 1213; em[1254] = 120; 
    	em[1255] = 1290; em[1256] = 128; 
    	em[1257] = 1210; em[1258] = 136; 
    	em[1259] = 1219; em[1260] = 144; 
    	em[1261] = 1284; em[1262] = 152; 
    	em[1263] = 1219; em[1264] = 160; 
    	em[1265] = 1284; em[1266] = 168; 
    	em[1267] = 1219; em[1268] = 176; 
    	em[1269] = 1293; em[1270] = 184; 
    	em[1271] = 1296; em[1272] = 192; 
    	em[1273] = 1299; em[1274] = 200; 
    em[1275] = 8884097; em[1276] = 8; em[1277] = 0; /* 1275: pointer.func */
    em[1278] = 8884097; em[1279] = 8; em[1280] = 0; /* 1278: pointer.func */
    em[1281] = 8884097; em[1282] = 8; em[1283] = 0; /* 1281: pointer.func */
    em[1284] = 8884097; em[1285] = 8; em[1286] = 0; /* 1284: pointer.func */
    em[1287] = 8884097; em[1288] = 8; em[1289] = 0; /* 1287: pointer.func */
    em[1290] = 8884097; em[1291] = 8; em[1292] = 0; /* 1290: pointer.func */
    em[1293] = 8884097; em[1294] = 8; em[1295] = 0; /* 1293: pointer.func */
    em[1296] = 8884097; em[1297] = 8; em[1298] = 0; /* 1296: pointer.func */
    em[1299] = 8884097; em[1300] = 8; em[1301] = 0; /* 1299: pointer.func */
    em[1302] = 1; em[1303] = 8; em[1304] = 1; /* 1302: pointer.struct.evp_pkey_ctx_st */
    	em[1305] = 1307; em[1306] = 0; 
    em[1307] = 0; em[1308] = 80; em[1309] = 8; /* 1307: struct.evp_pkey_ctx_st */
    	em[1310] = 1326; em[1311] = 0; 
    	em[1312] = 1331; em[1313] = 8; 
    	em[1314] = 1336; em[1315] = 16; 
    	em[1316] = 1336; em[1317] = 24; 
    	em[1318] = 571; em[1319] = 40; 
    	em[1320] = 571; em[1321] = 48; 
    	em[1322] = 0; em[1323] = 56; 
    	em[1324] = 1976; em[1325] = 64; 
    em[1326] = 1; em[1327] = 8; em[1328] = 1; /* 1326: pointer.struct.evp_pkey_method_st */
    	em[1329] = 1222; em[1330] = 0; 
    em[1331] = 1; em[1332] = 8; em[1333] = 1; /* 1331: pointer.struct.engine_st */
    	em[1334] = 665; em[1335] = 0; 
    em[1336] = 1; em[1337] = 8; em[1338] = 1; /* 1336: pointer.struct.evp_pkey_st */
    	em[1339] = 1341; em[1340] = 0; 
    em[1341] = 0; em[1342] = 56; em[1343] = 4; /* 1341: struct.evp_pkey_st */
    	em[1344] = 1352; em[1345] = 16; 
    	em[1346] = 1331; em[1347] = 24; 
    	em[1348] = 1357; em[1349] = 32; 
    	em[1350] = 1926; em[1351] = 48; 
    em[1352] = 1; em[1353] = 8; em[1354] = 1; /* 1352: pointer.struct.evp_pkey_asn1_method_st */
    	em[1355] = 1092; em[1356] = 0; 
    em[1357] = 0; em[1358] = 8; em[1359] = 6; /* 1357: union.union_of_evp_pkey_st */
    	em[1360] = 571; em[1361] = 0; 
    	em[1362] = 1205; em[1363] = 6; 
    	em[1364] = 1372; em[1365] = 116; 
    	em[1366] = 1483; em[1367] = 28; 
    	em[1368] = 1601; em[1369] = 408; 
    	em[1370] = 355; em[1371] = 0; 
    em[1372] = 1; em[1373] = 8; em[1374] = 1; /* 1372: pointer.struct.dsa_st */
    	em[1375] = 1377; em[1376] = 0; 
    em[1377] = 0; em[1378] = 136; em[1379] = 11; /* 1377: struct.dsa_st */
    	em[1380] = 1182; em[1381] = 24; 
    	em[1382] = 1182; em[1383] = 32; 
    	em[1384] = 1182; em[1385] = 40; 
    	em[1386] = 1182; em[1387] = 48; 
    	em[1388] = 1182; em[1389] = 56; 
    	em[1390] = 1182; em[1391] = 64; 
    	em[1392] = 1182; em[1393] = 72; 
    	em[1394] = 1402; em[1395] = 88; 
    	em[1396] = 1416; em[1397] = 104; 
    	em[1398] = 1430; em[1399] = 120; 
    	em[1400] = 1478; em[1401] = 128; 
    em[1402] = 1; em[1403] = 8; em[1404] = 1; /* 1402: pointer.struct.bn_mont_ctx_st */
    	em[1405] = 1407; em[1406] = 0; 
    em[1407] = 0; em[1408] = 96; em[1409] = 3; /* 1407: struct.bn_mont_ctx_st */
    	em[1410] = 1187; em[1411] = 8; 
    	em[1412] = 1187; em[1413] = 32; 
    	em[1414] = 1187; em[1415] = 56; 
    em[1416] = 0; em[1417] = 32; em[1418] = 2; /* 1416: struct.crypto_ex_data_st_fake */
    	em[1419] = 1423; em[1420] = 8; 
    	em[1421] = 358; em[1422] = 24; 
    em[1423] = 8884099; em[1424] = 8; em[1425] = 2; /* 1423: pointer_to_array_of_pointers_to_stack */
    	em[1426] = 571; em[1427] = 0; 
    	em[1428] = 355; em[1429] = 20; 
    em[1430] = 1; em[1431] = 8; em[1432] = 1; /* 1430: pointer.struct.dsa_method */
    	em[1433] = 1435; em[1434] = 0; 
    em[1435] = 0; em[1436] = 96; em[1437] = 11; /* 1435: struct.dsa_method */
    	em[1438] = 141; em[1439] = 0; 
    	em[1440] = 1460; em[1441] = 8; 
    	em[1442] = 1463; em[1443] = 16; 
    	em[1444] = 1466; em[1445] = 24; 
    	em[1446] = 557; em[1447] = 32; 
    	em[1448] = 1469; em[1449] = 40; 
    	em[1450] = 1472; em[1451] = 48; 
    	em[1452] = 1472; em[1453] = 56; 
    	em[1454] = 122; em[1455] = 72; 
    	em[1456] = 1475; em[1457] = 80; 
    	em[1458] = 1472; em[1459] = 88; 
    em[1460] = 8884097; em[1461] = 8; em[1462] = 0; /* 1460: pointer.func */
    em[1463] = 8884097; em[1464] = 8; em[1465] = 0; /* 1463: pointer.func */
    em[1466] = 8884097; em[1467] = 8; em[1468] = 0; /* 1466: pointer.func */
    em[1469] = 8884097; em[1470] = 8; em[1471] = 0; /* 1469: pointer.func */
    em[1472] = 8884097; em[1473] = 8; em[1474] = 0; /* 1472: pointer.func */
    em[1475] = 8884097; em[1476] = 8; em[1477] = 0; /* 1475: pointer.func */
    em[1478] = 1; em[1479] = 8; em[1480] = 1; /* 1478: pointer.struct.engine_st */
    	em[1481] = 665; em[1482] = 0; 
    em[1483] = 1; em[1484] = 8; em[1485] = 1; /* 1483: pointer.struct.dh_st */
    	em[1486] = 1488; em[1487] = 0; 
    em[1488] = 0; em[1489] = 144; em[1490] = 12; /* 1488: struct.dh_st */
    	em[1491] = 1515; em[1492] = 8; 
    	em[1493] = 1515; em[1494] = 16; 
    	em[1495] = 1515; em[1496] = 32; 
    	em[1497] = 1515; em[1498] = 40; 
    	em[1499] = 1532; em[1500] = 56; 
    	em[1501] = 1515; em[1502] = 64; 
    	em[1503] = 1515; em[1504] = 72; 
    	em[1505] = 21; em[1506] = 80; 
    	em[1507] = 1515; em[1508] = 96; 
    	em[1509] = 1546; em[1510] = 112; 
    	em[1511] = 1560; em[1512] = 128; 
    	em[1513] = 1596; em[1514] = 136; 
    em[1515] = 1; em[1516] = 8; em[1517] = 1; /* 1515: pointer.struct.bignum_st */
    	em[1518] = 1520; em[1519] = 0; 
    em[1520] = 0; em[1521] = 24; em[1522] = 1; /* 1520: struct.bignum_st */
    	em[1523] = 1525; em[1524] = 0; 
    em[1525] = 8884099; em[1526] = 8; em[1527] = 2; /* 1525: pointer_to_array_of_pointers_to_stack */
    	em[1528] = 382; em[1529] = 0; 
    	em[1530] = 355; em[1531] = 12; 
    em[1532] = 1; em[1533] = 8; em[1534] = 1; /* 1532: pointer.struct.bn_mont_ctx_st */
    	em[1535] = 1537; em[1536] = 0; 
    em[1537] = 0; em[1538] = 96; em[1539] = 3; /* 1537: struct.bn_mont_ctx_st */
    	em[1540] = 1520; em[1541] = 8; 
    	em[1542] = 1520; em[1543] = 32; 
    	em[1544] = 1520; em[1545] = 56; 
    em[1546] = 0; em[1547] = 32; em[1548] = 2; /* 1546: struct.crypto_ex_data_st_fake */
    	em[1549] = 1553; em[1550] = 8; 
    	em[1551] = 358; em[1552] = 24; 
    em[1553] = 8884099; em[1554] = 8; em[1555] = 2; /* 1553: pointer_to_array_of_pointers_to_stack */
    	em[1556] = 571; em[1557] = 0; 
    	em[1558] = 355; em[1559] = 20; 
    em[1560] = 1; em[1561] = 8; em[1562] = 1; /* 1560: pointer.struct.dh_method */
    	em[1563] = 1565; em[1564] = 0; 
    em[1565] = 0; em[1566] = 72; em[1567] = 8; /* 1565: struct.dh_method */
    	em[1568] = 141; em[1569] = 0; 
    	em[1570] = 1584; em[1571] = 8; 
    	em[1572] = 1587; em[1573] = 16; 
    	em[1574] = 1590; em[1575] = 24; 
    	em[1576] = 1584; em[1577] = 32; 
    	em[1578] = 1584; em[1579] = 40; 
    	em[1580] = 122; em[1581] = 56; 
    	em[1582] = 1593; em[1583] = 64; 
    em[1584] = 8884097; em[1585] = 8; em[1586] = 0; /* 1584: pointer.func */
    em[1587] = 8884097; em[1588] = 8; em[1589] = 0; /* 1587: pointer.func */
    em[1590] = 8884097; em[1591] = 8; em[1592] = 0; /* 1590: pointer.func */
    em[1593] = 8884097; em[1594] = 8; em[1595] = 0; /* 1593: pointer.func */
    em[1596] = 1; em[1597] = 8; em[1598] = 1; /* 1596: pointer.struct.engine_st */
    	em[1599] = 665; em[1600] = 0; 
    em[1601] = 1; em[1602] = 8; em[1603] = 1; /* 1601: pointer.struct.ec_key_st */
    	em[1604] = 1606; em[1605] = 0; 
    em[1606] = 0; em[1607] = 56; em[1608] = 4; /* 1606: struct.ec_key_st */
    	em[1609] = 1617; em[1610] = 8; 
    	em[1611] = 1881; em[1612] = 16; 
    	em[1613] = 1886; em[1614] = 24; 
    	em[1615] = 1903; em[1616] = 48; 
    em[1617] = 1; em[1618] = 8; em[1619] = 1; /* 1617: pointer.struct.ec_group_st */
    	em[1620] = 1622; em[1621] = 0; 
    em[1622] = 0; em[1623] = 232; em[1624] = 12; /* 1622: struct.ec_group_st */
    	em[1625] = 1649; em[1626] = 0; 
    	em[1627] = 1809; em[1628] = 8; 
    	em[1629] = 1837; em[1630] = 16; 
    	em[1631] = 1837; em[1632] = 40; 
    	em[1633] = 21; em[1634] = 80; 
    	em[1635] = 1849; em[1636] = 96; 
    	em[1637] = 1837; em[1638] = 104; 
    	em[1639] = 1837; em[1640] = 152; 
    	em[1641] = 1837; em[1642] = 176; 
    	em[1643] = 571; em[1644] = 208; 
    	em[1645] = 571; em[1646] = 216; 
    	em[1647] = 1878; em[1648] = 224; 
    em[1649] = 1; em[1650] = 8; em[1651] = 1; /* 1649: pointer.struct.ec_method_st */
    	em[1652] = 1654; em[1653] = 0; 
    em[1654] = 0; em[1655] = 304; em[1656] = 37; /* 1654: struct.ec_method_st */
    	em[1657] = 1731; em[1658] = 8; 
    	em[1659] = 1734; em[1660] = 16; 
    	em[1661] = 1734; em[1662] = 24; 
    	em[1663] = 1737; em[1664] = 32; 
    	em[1665] = 1740; em[1666] = 40; 
    	em[1667] = 1199; em[1668] = 48; 
    	em[1669] = 1743; em[1670] = 56; 
    	em[1671] = 1746; em[1672] = 64; 
    	em[1673] = 1216; em[1674] = 72; 
    	em[1675] = 1749; em[1676] = 80; 
    	em[1677] = 1749; em[1678] = 88; 
    	em[1679] = 1080; em[1680] = 96; 
    	em[1681] = 1752; em[1682] = 104; 
    	em[1683] = 1755; em[1684] = 112; 
    	em[1685] = 1758; em[1686] = 120; 
    	em[1687] = 1761; em[1688] = 128; 
    	em[1689] = 1764; em[1690] = 136; 
    	em[1691] = 1767; em[1692] = 144; 
    	em[1693] = 1770; em[1694] = 152; 
    	em[1695] = 1773; em[1696] = 160; 
    	em[1697] = 1776; em[1698] = 168; 
    	em[1699] = 1779; em[1700] = 176; 
    	em[1701] = 1782; em[1702] = 184; 
    	em[1703] = 1785; em[1704] = 192; 
    	em[1705] = 1788; em[1706] = 200; 
    	em[1707] = 1791; em[1708] = 208; 
    	em[1709] = 1782; em[1710] = 216; 
    	em[1711] = 1794; em[1712] = 224; 
    	em[1713] = 1797; em[1714] = 232; 
    	em[1715] = 1800; em[1716] = 240; 
    	em[1717] = 1743; em[1718] = 248; 
    	em[1719] = 1803; em[1720] = 256; 
    	em[1721] = 1806; em[1722] = 264; 
    	em[1723] = 1803; em[1724] = 272; 
    	em[1725] = 1806; em[1726] = 280; 
    	em[1727] = 1806; em[1728] = 288; 
    	em[1729] = 1202; em[1730] = 296; 
    em[1731] = 8884097; em[1732] = 8; em[1733] = 0; /* 1731: pointer.func */
    em[1734] = 8884097; em[1735] = 8; em[1736] = 0; /* 1734: pointer.func */
    em[1737] = 8884097; em[1738] = 8; em[1739] = 0; /* 1737: pointer.func */
    em[1740] = 8884097; em[1741] = 8; em[1742] = 0; /* 1740: pointer.func */
    em[1743] = 8884097; em[1744] = 8; em[1745] = 0; /* 1743: pointer.func */
    em[1746] = 8884097; em[1747] = 8; em[1748] = 0; /* 1746: pointer.func */
    em[1749] = 8884097; em[1750] = 8; em[1751] = 0; /* 1749: pointer.func */
    em[1752] = 8884097; em[1753] = 8; em[1754] = 0; /* 1752: pointer.func */
    em[1755] = 8884097; em[1756] = 8; em[1757] = 0; /* 1755: pointer.func */
    em[1758] = 8884097; em[1759] = 8; em[1760] = 0; /* 1758: pointer.func */
    em[1761] = 8884097; em[1762] = 8; em[1763] = 0; /* 1761: pointer.func */
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
    em[1806] = 8884097; em[1807] = 8; em[1808] = 0; /* 1806: pointer.func */
    em[1809] = 1; em[1810] = 8; em[1811] = 1; /* 1809: pointer.struct.ec_point_st */
    	em[1812] = 1814; em[1813] = 0; 
    em[1814] = 0; em[1815] = 88; em[1816] = 4; /* 1814: struct.ec_point_st */
    	em[1817] = 385; em[1818] = 0; 
    	em[1819] = 1825; em[1820] = 8; 
    	em[1821] = 1825; em[1822] = 32; 
    	em[1823] = 1825; em[1824] = 56; 
    em[1825] = 0; em[1826] = 24; em[1827] = 1; /* 1825: struct.bignum_st */
    	em[1828] = 1830; em[1829] = 0; 
    em[1830] = 8884099; em[1831] = 8; em[1832] = 2; /* 1830: pointer_to_array_of_pointers_to_stack */
    	em[1833] = 382; em[1834] = 0; 
    	em[1835] = 355; em[1836] = 12; 
    em[1837] = 0; em[1838] = 24; em[1839] = 1; /* 1837: struct.bignum_st */
    	em[1840] = 1842; em[1841] = 0; 
    em[1842] = 8884099; em[1843] = 8; em[1844] = 2; /* 1842: pointer_to_array_of_pointers_to_stack */
    	em[1845] = 382; em[1846] = 0; 
    	em[1847] = 355; em[1848] = 12; 
    em[1849] = 1; em[1850] = 8; em[1851] = 1; /* 1849: pointer.struct.ec_extra_data_st */
    	em[1852] = 1854; em[1853] = 0; 
    em[1854] = 0; em[1855] = 40; em[1856] = 5; /* 1854: struct.ec_extra_data_st */
    	em[1857] = 1867; em[1858] = 0; 
    	em[1859] = 571; em[1860] = 8; 
    	em[1861] = 1872; em[1862] = 16; 
    	em[1863] = 1875; em[1864] = 24; 
    	em[1865] = 1875; em[1866] = 32; 
    em[1867] = 1; em[1868] = 8; em[1869] = 1; /* 1867: pointer.struct.ec_extra_data_st */
    	em[1870] = 1854; em[1871] = 0; 
    em[1872] = 8884097; em[1873] = 8; em[1874] = 0; /* 1872: pointer.func */
    em[1875] = 8884097; em[1876] = 8; em[1877] = 0; /* 1875: pointer.func */
    em[1878] = 8884097; em[1879] = 8; em[1880] = 0; /* 1878: pointer.func */
    em[1881] = 1; em[1882] = 8; em[1883] = 1; /* 1881: pointer.struct.ec_point_st */
    	em[1884] = 1814; em[1885] = 0; 
    em[1886] = 1; em[1887] = 8; em[1888] = 1; /* 1886: pointer.struct.bignum_st */
    	em[1889] = 1891; em[1890] = 0; 
    em[1891] = 0; em[1892] = 24; em[1893] = 1; /* 1891: struct.bignum_st */
    	em[1894] = 1896; em[1895] = 0; 
    em[1896] = 8884099; em[1897] = 8; em[1898] = 2; /* 1896: pointer_to_array_of_pointers_to_stack */
    	em[1899] = 382; em[1900] = 0; 
    	em[1901] = 355; em[1902] = 12; 
    em[1903] = 1; em[1904] = 8; em[1905] = 1; /* 1903: pointer.struct.ec_extra_data_st */
    	em[1906] = 1908; em[1907] = 0; 
    em[1908] = 0; em[1909] = 40; em[1910] = 5; /* 1908: struct.ec_extra_data_st */
    	em[1911] = 1921; em[1912] = 0; 
    	em[1913] = 571; em[1914] = 8; 
    	em[1915] = 1872; em[1916] = 16; 
    	em[1917] = 1875; em[1918] = 24; 
    	em[1919] = 1875; em[1920] = 32; 
    em[1921] = 1; em[1922] = 8; em[1923] = 1; /* 1921: pointer.struct.ec_extra_data_st */
    	em[1924] = 1908; em[1925] = 0; 
    em[1926] = 1; em[1927] = 8; em[1928] = 1; /* 1926: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1929] = 1931; em[1930] = 0; 
    em[1931] = 0; em[1932] = 32; em[1933] = 2; /* 1931: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1934] = 1938; em[1935] = 8; 
    	em[1936] = 358; em[1937] = 24; 
    em[1938] = 8884099; em[1939] = 8; em[1940] = 2; /* 1938: pointer_to_array_of_pointers_to_stack */
    	em[1941] = 1945; em[1942] = 0; 
    	em[1943] = 355; em[1944] = 20; 
    em[1945] = 0; em[1946] = 8; em[1947] = 1; /* 1945: pointer.X509_ATTRIBUTE */
    	em[1948] = 1950; em[1949] = 0; 
    em[1950] = 0; em[1951] = 0; em[1952] = 1; /* 1950: X509_ATTRIBUTE */
    	em[1953] = 1955; em[1954] = 0; 
    em[1955] = 0; em[1956] = 24; em[1957] = 2; /* 1955: struct.x509_attributes_st */
    	em[1958] = 127; em[1959] = 0; 
    	em[1960] = 1962; em[1961] = 16; 
    em[1962] = 0; em[1963] = 8; em[1964] = 3; /* 1962: union.unknown */
    	em[1965] = 122; em[1966] = 0; 
    	em[1967] = 326; em[1968] = 0; 
    	em[1969] = 1971; em[1970] = 0; 
    em[1971] = 1; em[1972] = 8; em[1973] = 1; /* 1971: pointer.struct.asn1_type_st */
    	em[1974] = 74; em[1975] = 0; 
    em[1976] = 1; em[1977] = 8; em[1978] = 1; /* 1976: pointer.int */
    	em[1979] = 355; em[1980] = 0; 
    em[1981] = 8884097; em[1982] = 8; em[1983] = 0; /* 1981: pointer.func */
    em[1984] = 8884097; em[1985] = 8; em[1986] = 0; /* 1984: pointer.func */
    em[1987] = 0; em[1988] = 48; em[1989] = 5; /* 1987: struct.env_md_ctx_st */
    	em[1990] = 2000; em[1991] = 0; 
    	em[1992] = 1331; em[1993] = 8; 
    	em[1994] = 571; em[1995] = 24; 
    	em[1996] = 1302; em[1997] = 32; 
    	em[1998] = 2024; em[1999] = 40; 
    em[2000] = 1; em[2001] = 8; em[2002] = 1; /* 2000: pointer.struct.env_md_st */
    	em[2003] = 2005; em[2004] = 0; 
    em[2005] = 0; em[2006] = 120; em[2007] = 8; /* 2005: struct.env_md_st */
    	em[2008] = 1984; em[2009] = 24; 
    	em[2010] = 2024; em[2011] = 32; 
    	em[2012] = 2027; em[2013] = 40; 
    	em[2014] = 2030; em[2015] = 48; 
    	em[2016] = 1984; em[2017] = 56; 
    	em[2018] = 1981; em[2019] = 64; 
    	em[2020] = 1179; em[2021] = 72; 
    	em[2022] = 2033; em[2023] = 112; 
    em[2024] = 8884097; em[2025] = 8; em[2026] = 0; /* 2024: pointer.func */
    em[2027] = 8884097; em[2028] = 8; em[2029] = 0; /* 2027: pointer.func */
    em[2030] = 8884097; em[2031] = 8; em[2032] = 0; /* 2030: pointer.func */
    em[2033] = 8884097; em[2034] = 8; em[2035] = 0; /* 2033: pointer.func */
    em[2036] = 0; em[2037] = 1; em[2038] = 0; /* 2036: char */
    em[2039] = 1; em[2040] = 8; em[2041] = 1; /* 2039: pointer.struct.env_md_ctx_st */
    	em[2042] = 1987; em[2043] = 0; 
    args_addr->arg_entity_index[0] = 2039;
    args_addr->arg_entity_index[1] = 2000;
    args_addr->arg_entity_index[2] = 1331;
    args_addr->ret_entity_index = 355;
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

