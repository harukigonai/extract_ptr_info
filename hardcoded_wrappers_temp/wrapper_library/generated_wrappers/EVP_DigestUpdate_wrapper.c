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
    em[361] = 0; em[362] = 8; em[363] = 3; /* 361: union.unknown */
    	em[364] = 122; em[365] = 0; 
    	em[366] = 326; em[367] = 0; 
    	em[368] = 370; em[369] = 0; 
    em[370] = 1; em[371] = 8; em[372] = 1; /* 370: pointer.struct.asn1_type_st */
    	em[373] = 74; em[374] = 0; 
    em[375] = 0; em[376] = 96; em[377] = 3; /* 375: struct.bn_mont_ctx_st */
    	em[378] = 384; em[379] = 8; 
    	em[380] = 384; em[381] = 32; 
    	em[382] = 384; em[383] = 56; 
    em[384] = 0; em[385] = 24; em[386] = 1; /* 384: struct.bignum_st */
    	em[387] = 389; em[388] = 0; 
    em[389] = 8884099; em[390] = 8; em[391] = 2; /* 389: pointer_to_array_of_pointers_to_stack */
    	em[392] = 396; em[393] = 0; 
    	em[394] = 355; em[395] = 12; 
    em[396] = 0; em[397] = 8; em[398] = 0; /* 396: long unsigned int */
    em[399] = 1; em[400] = 8; em[401] = 1; /* 399: pointer.struct.ec_method_st */
    	em[402] = 404; em[403] = 0; 
    em[404] = 0; em[405] = 304; em[406] = 37; /* 404: struct.ec_method_st */
    	em[407] = 481; em[408] = 8; 
    	em[409] = 484; em[410] = 16; 
    	em[411] = 484; em[412] = 24; 
    	em[413] = 487; em[414] = 32; 
    	em[415] = 490; em[416] = 40; 
    	em[417] = 493; em[418] = 48; 
    	em[419] = 496; em[420] = 56; 
    	em[421] = 499; em[422] = 64; 
    	em[423] = 502; em[424] = 72; 
    	em[425] = 505; em[426] = 80; 
    	em[427] = 505; em[428] = 88; 
    	em[429] = 508; em[430] = 96; 
    	em[431] = 511; em[432] = 104; 
    	em[433] = 514; em[434] = 112; 
    	em[435] = 517; em[436] = 120; 
    	em[437] = 520; em[438] = 128; 
    	em[439] = 523; em[440] = 136; 
    	em[441] = 526; em[442] = 144; 
    	em[443] = 529; em[444] = 152; 
    	em[445] = 532; em[446] = 160; 
    	em[447] = 535; em[448] = 168; 
    	em[449] = 538; em[450] = 176; 
    	em[451] = 541; em[452] = 184; 
    	em[453] = 544; em[454] = 192; 
    	em[455] = 547; em[456] = 200; 
    	em[457] = 550; em[458] = 208; 
    	em[459] = 541; em[460] = 216; 
    	em[461] = 553; em[462] = 224; 
    	em[463] = 556; em[464] = 232; 
    	em[465] = 559; em[466] = 240; 
    	em[467] = 496; em[468] = 248; 
    	em[469] = 562; em[470] = 256; 
    	em[471] = 565; em[472] = 264; 
    	em[473] = 562; em[474] = 272; 
    	em[475] = 565; em[476] = 280; 
    	em[477] = 565; em[478] = 288; 
    	em[479] = 568; em[480] = 296; 
    em[481] = 8884097; em[482] = 8; em[483] = 0; /* 481: pointer.func */
    em[484] = 8884097; em[485] = 8; em[486] = 0; /* 484: pointer.func */
    em[487] = 8884097; em[488] = 8; em[489] = 0; /* 487: pointer.func */
    em[490] = 8884097; em[491] = 8; em[492] = 0; /* 490: pointer.func */
    em[493] = 8884097; em[494] = 8; em[495] = 0; /* 493: pointer.func */
    em[496] = 8884097; em[497] = 8; em[498] = 0; /* 496: pointer.func */
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
    em[574] = 1; em[575] = 8; em[576] = 1; /* 574: pointer.struct.bignum_st */
    	em[577] = 384; em[578] = 0; 
    em[579] = 8884097; em[580] = 8; em[581] = 0; /* 579: pointer.func */
    em[582] = 8884097; em[583] = 8; em[584] = 0; /* 582: pointer.func */
    em[585] = 0; em[586] = 8; em[587] = 0; /* 585: pointer.void */
    em[588] = 0; em[589] = 168; em[590] = 17; /* 588: struct.rsa_st */
    	em[591] = 625; em[592] = 16; 
    	em[593] = 674; em[594] = 24; 
    	em[595] = 574; em[596] = 32; 
    	em[597] = 574; em[598] = 40; 
    	em[599] = 574; em[600] = 48; 
    	em[601] = 574; em[602] = 56; 
    	em[603] = 574; em[604] = 64; 
    	em[605] = 574; em[606] = 72; 
    	em[607] = 574; em[608] = 80; 
    	em[609] = 574; em[610] = 88; 
    	em[611] = 1014; em[612] = 96; 
    	em[613] = 1028; em[614] = 120; 
    	em[615] = 1028; em[616] = 128; 
    	em[617] = 1028; em[618] = 136; 
    	em[619] = 122; em[620] = 144; 
    	em[621] = 1033; em[622] = 152; 
    	em[623] = 1033; em[624] = 160; 
    em[625] = 1; em[626] = 8; em[627] = 1; /* 625: pointer.struct.rsa_meth_st */
    	em[628] = 630; em[629] = 0; 
    em[630] = 0; em[631] = 112; em[632] = 13; /* 630: struct.rsa_meth_st */
    	em[633] = 141; em[634] = 0; 
    	em[635] = 659; em[636] = 8; 
    	em[637] = 659; em[638] = 16; 
    	em[639] = 659; em[640] = 24; 
    	em[641] = 659; em[642] = 32; 
    	em[643] = 662; em[644] = 40; 
    	em[645] = 665; em[646] = 48; 
    	em[647] = 582; em[648] = 56; 
    	em[649] = 582; em[650] = 64; 
    	em[651] = 122; em[652] = 80; 
    	em[653] = 668; em[654] = 88; 
    	em[655] = 671; em[656] = 96; 
    	em[657] = 579; em[658] = 104; 
    em[659] = 8884097; em[660] = 8; em[661] = 0; /* 659: pointer.func */
    em[662] = 8884097; em[663] = 8; em[664] = 0; /* 662: pointer.func */
    em[665] = 8884097; em[666] = 8; em[667] = 0; /* 665: pointer.func */
    em[668] = 8884097; em[669] = 8; em[670] = 0; /* 668: pointer.func */
    em[671] = 8884097; em[672] = 8; em[673] = 0; /* 671: pointer.func */
    em[674] = 1; em[675] = 8; em[676] = 1; /* 674: pointer.struct.engine_st */
    	em[677] = 679; em[678] = 0; 
    em[679] = 0; em[680] = 216; em[681] = 24; /* 679: struct.engine_st */
    	em[682] = 141; em[683] = 0; 
    	em[684] = 141; em[685] = 8; 
    	em[686] = 730; em[687] = 16; 
    	em[688] = 785; em[689] = 24; 
    	em[690] = 836; em[691] = 32; 
    	em[692] = 872; em[693] = 40; 
    	em[694] = 889; em[695] = 48; 
    	em[696] = 916; em[697] = 56; 
    	em[698] = 951; em[699] = 64; 
    	em[700] = 959; em[701] = 72; 
    	em[702] = 962; em[703] = 80; 
    	em[704] = 965; em[705] = 88; 
    	em[706] = 968; em[707] = 96; 
    	em[708] = 971; em[709] = 104; 
    	em[710] = 971; em[711] = 112; 
    	em[712] = 971; em[713] = 120; 
    	em[714] = 974; em[715] = 128; 
    	em[716] = 977; em[717] = 136; 
    	em[718] = 977; em[719] = 144; 
    	em[720] = 980; em[721] = 152; 
    	em[722] = 983; em[723] = 160; 
    	em[724] = 995; em[725] = 184; 
    	em[726] = 1009; em[727] = 200; 
    	em[728] = 1009; em[729] = 208; 
    em[730] = 1; em[731] = 8; em[732] = 1; /* 730: pointer.struct.rsa_meth_st */
    	em[733] = 735; em[734] = 0; 
    em[735] = 0; em[736] = 112; em[737] = 13; /* 735: struct.rsa_meth_st */
    	em[738] = 141; em[739] = 0; 
    	em[740] = 764; em[741] = 8; 
    	em[742] = 764; em[743] = 16; 
    	em[744] = 764; em[745] = 24; 
    	em[746] = 764; em[747] = 32; 
    	em[748] = 767; em[749] = 40; 
    	em[750] = 770; em[751] = 48; 
    	em[752] = 773; em[753] = 56; 
    	em[754] = 773; em[755] = 64; 
    	em[756] = 122; em[757] = 80; 
    	em[758] = 776; em[759] = 88; 
    	em[760] = 779; em[761] = 96; 
    	em[762] = 782; em[763] = 104; 
    em[764] = 8884097; em[765] = 8; em[766] = 0; /* 764: pointer.func */
    em[767] = 8884097; em[768] = 8; em[769] = 0; /* 767: pointer.func */
    em[770] = 8884097; em[771] = 8; em[772] = 0; /* 770: pointer.func */
    em[773] = 8884097; em[774] = 8; em[775] = 0; /* 773: pointer.func */
    em[776] = 8884097; em[777] = 8; em[778] = 0; /* 776: pointer.func */
    em[779] = 8884097; em[780] = 8; em[781] = 0; /* 779: pointer.func */
    em[782] = 8884097; em[783] = 8; em[784] = 0; /* 782: pointer.func */
    em[785] = 1; em[786] = 8; em[787] = 1; /* 785: pointer.struct.dsa_method */
    	em[788] = 790; em[789] = 0; 
    em[790] = 0; em[791] = 96; em[792] = 11; /* 790: struct.dsa_method */
    	em[793] = 141; em[794] = 0; 
    	em[795] = 815; em[796] = 8; 
    	em[797] = 818; em[798] = 16; 
    	em[799] = 821; em[800] = 24; 
    	em[801] = 824; em[802] = 32; 
    	em[803] = 827; em[804] = 40; 
    	em[805] = 830; em[806] = 48; 
    	em[807] = 830; em[808] = 56; 
    	em[809] = 122; em[810] = 72; 
    	em[811] = 833; em[812] = 80; 
    	em[813] = 830; em[814] = 88; 
    em[815] = 8884097; em[816] = 8; em[817] = 0; /* 815: pointer.func */
    em[818] = 8884097; em[819] = 8; em[820] = 0; /* 818: pointer.func */
    em[821] = 8884097; em[822] = 8; em[823] = 0; /* 821: pointer.func */
    em[824] = 8884097; em[825] = 8; em[826] = 0; /* 824: pointer.func */
    em[827] = 8884097; em[828] = 8; em[829] = 0; /* 827: pointer.func */
    em[830] = 8884097; em[831] = 8; em[832] = 0; /* 830: pointer.func */
    em[833] = 8884097; em[834] = 8; em[835] = 0; /* 833: pointer.func */
    em[836] = 1; em[837] = 8; em[838] = 1; /* 836: pointer.struct.dh_method */
    	em[839] = 841; em[840] = 0; 
    em[841] = 0; em[842] = 72; em[843] = 8; /* 841: struct.dh_method */
    	em[844] = 141; em[845] = 0; 
    	em[846] = 860; em[847] = 8; 
    	em[848] = 863; em[849] = 16; 
    	em[850] = 866; em[851] = 24; 
    	em[852] = 860; em[853] = 32; 
    	em[854] = 860; em[855] = 40; 
    	em[856] = 122; em[857] = 56; 
    	em[858] = 869; em[859] = 64; 
    em[860] = 8884097; em[861] = 8; em[862] = 0; /* 860: pointer.func */
    em[863] = 8884097; em[864] = 8; em[865] = 0; /* 863: pointer.func */
    em[866] = 8884097; em[867] = 8; em[868] = 0; /* 866: pointer.func */
    em[869] = 8884097; em[870] = 8; em[871] = 0; /* 869: pointer.func */
    em[872] = 1; em[873] = 8; em[874] = 1; /* 872: pointer.struct.ecdh_method */
    	em[875] = 877; em[876] = 0; 
    em[877] = 0; em[878] = 32; em[879] = 3; /* 877: struct.ecdh_method */
    	em[880] = 141; em[881] = 0; 
    	em[882] = 886; em[883] = 8; 
    	em[884] = 122; em[885] = 24; 
    em[886] = 8884097; em[887] = 8; em[888] = 0; /* 886: pointer.func */
    em[889] = 1; em[890] = 8; em[891] = 1; /* 889: pointer.struct.ecdsa_method */
    	em[892] = 894; em[893] = 0; 
    em[894] = 0; em[895] = 48; em[896] = 5; /* 894: struct.ecdsa_method */
    	em[897] = 141; em[898] = 0; 
    	em[899] = 907; em[900] = 8; 
    	em[901] = 910; em[902] = 16; 
    	em[903] = 913; em[904] = 24; 
    	em[905] = 122; em[906] = 40; 
    em[907] = 8884097; em[908] = 8; em[909] = 0; /* 907: pointer.func */
    em[910] = 8884097; em[911] = 8; em[912] = 0; /* 910: pointer.func */
    em[913] = 8884097; em[914] = 8; em[915] = 0; /* 913: pointer.func */
    em[916] = 1; em[917] = 8; em[918] = 1; /* 916: pointer.struct.rand_meth_st */
    	em[919] = 921; em[920] = 0; 
    em[921] = 0; em[922] = 48; em[923] = 6; /* 921: struct.rand_meth_st */
    	em[924] = 936; em[925] = 0; 
    	em[926] = 939; em[927] = 8; 
    	em[928] = 942; em[929] = 16; 
    	em[930] = 945; em[931] = 24; 
    	em[932] = 939; em[933] = 32; 
    	em[934] = 948; em[935] = 40; 
    em[936] = 8884097; em[937] = 8; em[938] = 0; /* 936: pointer.func */
    em[939] = 8884097; em[940] = 8; em[941] = 0; /* 939: pointer.func */
    em[942] = 8884097; em[943] = 8; em[944] = 0; /* 942: pointer.func */
    em[945] = 8884097; em[946] = 8; em[947] = 0; /* 945: pointer.func */
    em[948] = 8884097; em[949] = 8; em[950] = 0; /* 948: pointer.func */
    em[951] = 1; em[952] = 8; em[953] = 1; /* 951: pointer.struct.store_method_st */
    	em[954] = 956; em[955] = 0; 
    em[956] = 0; em[957] = 0; em[958] = 0; /* 956: struct.store_method_st */
    em[959] = 8884097; em[960] = 8; em[961] = 0; /* 959: pointer.func */
    em[962] = 8884097; em[963] = 8; em[964] = 0; /* 962: pointer.func */
    em[965] = 8884097; em[966] = 8; em[967] = 0; /* 965: pointer.func */
    em[968] = 8884097; em[969] = 8; em[970] = 0; /* 968: pointer.func */
    em[971] = 8884097; em[972] = 8; em[973] = 0; /* 971: pointer.func */
    em[974] = 8884097; em[975] = 8; em[976] = 0; /* 974: pointer.func */
    em[977] = 8884097; em[978] = 8; em[979] = 0; /* 977: pointer.func */
    em[980] = 8884097; em[981] = 8; em[982] = 0; /* 980: pointer.func */
    em[983] = 1; em[984] = 8; em[985] = 1; /* 983: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[986] = 988; em[987] = 0; 
    em[988] = 0; em[989] = 32; em[990] = 2; /* 988: struct.ENGINE_CMD_DEFN_st */
    	em[991] = 141; em[992] = 8; 
    	em[993] = 141; em[994] = 16; 
    em[995] = 0; em[996] = 32; em[997] = 2; /* 995: struct.crypto_ex_data_st_fake */
    	em[998] = 1002; em[999] = 8; 
    	em[1000] = 358; em[1001] = 24; 
    em[1002] = 8884099; em[1003] = 8; em[1004] = 2; /* 1002: pointer_to_array_of_pointers_to_stack */
    	em[1005] = 585; em[1006] = 0; 
    	em[1007] = 355; em[1008] = 20; 
    em[1009] = 1; em[1010] = 8; em[1011] = 1; /* 1009: pointer.struct.engine_st */
    	em[1012] = 679; em[1013] = 0; 
    em[1014] = 0; em[1015] = 32; em[1016] = 2; /* 1014: struct.crypto_ex_data_st_fake */
    	em[1017] = 1021; em[1018] = 8; 
    	em[1019] = 358; em[1020] = 24; 
    em[1021] = 8884099; em[1022] = 8; em[1023] = 2; /* 1021: pointer_to_array_of_pointers_to_stack */
    	em[1024] = 585; em[1025] = 0; 
    	em[1026] = 355; em[1027] = 20; 
    em[1028] = 1; em[1029] = 8; em[1030] = 1; /* 1028: pointer.struct.bn_mont_ctx_st */
    	em[1031] = 375; em[1032] = 0; 
    em[1033] = 1; em[1034] = 8; em[1035] = 1; /* 1033: pointer.struct.bn_blinding_st */
    	em[1036] = 1038; em[1037] = 0; 
    em[1038] = 0; em[1039] = 88; em[1040] = 7; /* 1038: struct.bn_blinding_st */
    	em[1041] = 1055; em[1042] = 0; 
    	em[1043] = 1055; em[1044] = 8; 
    	em[1045] = 1055; em[1046] = 16; 
    	em[1047] = 1055; em[1048] = 24; 
    	em[1049] = 1072; em[1050] = 40; 
    	em[1051] = 1077; em[1052] = 72; 
    	em[1053] = 1091; em[1054] = 80; 
    em[1055] = 1; em[1056] = 8; em[1057] = 1; /* 1055: pointer.struct.bignum_st */
    	em[1058] = 1060; em[1059] = 0; 
    em[1060] = 0; em[1061] = 24; em[1062] = 1; /* 1060: struct.bignum_st */
    	em[1063] = 1065; em[1064] = 0; 
    em[1065] = 8884099; em[1066] = 8; em[1067] = 2; /* 1065: pointer_to_array_of_pointers_to_stack */
    	em[1068] = 396; em[1069] = 0; 
    	em[1070] = 355; em[1071] = 12; 
    em[1072] = 0; em[1073] = 16; em[1074] = 1; /* 1072: struct.crypto_threadid_st */
    	em[1075] = 585; em[1076] = 0; 
    em[1077] = 1; em[1078] = 8; em[1079] = 1; /* 1077: pointer.struct.bn_mont_ctx_st */
    	em[1080] = 1082; em[1081] = 0; 
    em[1082] = 0; em[1083] = 96; em[1084] = 3; /* 1082: struct.bn_mont_ctx_st */
    	em[1085] = 1060; em[1086] = 8; 
    	em[1087] = 1060; em[1088] = 32; 
    	em[1089] = 1060; em[1090] = 56; 
    em[1091] = 8884097; em[1092] = 8; em[1093] = 0; /* 1091: pointer.func */
    em[1094] = 8884097; em[1095] = 8; em[1096] = 0; /* 1094: pointer.func */
    em[1097] = 8884097; em[1098] = 8; em[1099] = 0; /* 1097: pointer.func */
    em[1100] = 8884097; em[1101] = 8; em[1102] = 0; /* 1100: pointer.func */
    em[1103] = 8884097; em[1104] = 8; em[1105] = 0; /* 1103: pointer.func */
    em[1106] = 0; em[1107] = 208; em[1108] = 24; /* 1106: struct.evp_pkey_asn1_method_st */
    	em[1109] = 122; em[1110] = 16; 
    	em[1111] = 122; em[1112] = 24; 
    	em[1113] = 1157; em[1114] = 32; 
    	em[1115] = 1160; em[1116] = 40; 
    	em[1117] = 1163; em[1118] = 48; 
    	em[1119] = 1166; em[1120] = 56; 
    	em[1121] = 1169; em[1122] = 64; 
    	em[1123] = 1172; em[1124] = 72; 
    	em[1125] = 1166; em[1126] = 80; 
    	em[1127] = 1100; em[1128] = 88; 
    	em[1129] = 1100; em[1130] = 96; 
    	em[1131] = 1175; em[1132] = 104; 
    	em[1133] = 1178; em[1134] = 112; 
    	em[1135] = 1100; em[1136] = 120; 
    	em[1137] = 1103; em[1138] = 128; 
    	em[1139] = 1163; em[1140] = 136; 
    	em[1141] = 1166; em[1142] = 144; 
    	em[1143] = 1181; em[1144] = 152; 
    	em[1145] = 1184; em[1146] = 160; 
    	em[1147] = 1097; em[1148] = 168; 
    	em[1149] = 1175; em[1150] = 176; 
    	em[1151] = 1178; em[1152] = 184; 
    	em[1153] = 1187; em[1154] = 192; 
    	em[1155] = 1190; em[1156] = 200; 
    em[1157] = 8884097; em[1158] = 8; em[1159] = 0; /* 1157: pointer.func */
    em[1160] = 8884097; em[1161] = 8; em[1162] = 0; /* 1160: pointer.func */
    em[1163] = 8884097; em[1164] = 8; em[1165] = 0; /* 1163: pointer.func */
    em[1166] = 8884097; em[1167] = 8; em[1168] = 0; /* 1166: pointer.func */
    em[1169] = 8884097; em[1170] = 8; em[1171] = 0; /* 1169: pointer.func */
    em[1172] = 8884097; em[1173] = 8; em[1174] = 0; /* 1172: pointer.func */
    em[1175] = 8884097; em[1176] = 8; em[1177] = 0; /* 1175: pointer.func */
    em[1178] = 8884097; em[1179] = 8; em[1180] = 0; /* 1178: pointer.func */
    em[1181] = 8884097; em[1182] = 8; em[1183] = 0; /* 1181: pointer.func */
    em[1184] = 8884097; em[1185] = 8; em[1186] = 0; /* 1184: pointer.func */
    em[1187] = 8884097; em[1188] = 8; em[1189] = 0; /* 1187: pointer.func */
    em[1190] = 8884097; em[1191] = 8; em[1192] = 0; /* 1190: pointer.func */
    em[1193] = 8884097; em[1194] = 8; em[1195] = 0; /* 1193: pointer.func */
    em[1196] = 1; em[1197] = 8; em[1198] = 1; /* 1196: pointer.struct.bignum_st */
    	em[1199] = 1201; em[1200] = 0; 
    em[1201] = 0; em[1202] = 24; em[1203] = 1; /* 1201: struct.bignum_st */
    	em[1204] = 1206; em[1205] = 0; 
    em[1206] = 8884099; em[1207] = 8; em[1208] = 2; /* 1206: pointer_to_array_of_pointers_to_stack */
    	em[1209] = 396; em[1210] = 0; 
    	em[1211] = 355; em[1212] = 12; 
    em[1213] = 8884097; em[1214] = 8; em[1215] = 0; /* 1213: pointer.func */
    em[1216] = 8884097; em[1217] = 8; em[1218] = 0; /* 1216: pointer.func */
    em[1219] = 1; em[1220] = 8; em[1221] = 1; /* 1219: pointer.struct.rsa_st */
    	em[1222] = 588; em[1223] = 0; 
    em[1224] = 8884097; em[1225] = 8; em[1226] = 0; /* 1224: pointer.func */
    em[1227] = 8884097; em[1228] = 8; em[1229] = 0; /* 1227: pointer.func */
    em[1230] = 8884097; em[1231] = 8; em[1232] = 0; /* 1230: pointer.func */
    em[1233] = 8884097; em[1234] = 8; em[1235] = 0; /* 1233: pointer.func */
    em[1236] = 0; em[1237] = 208; em[1238] = 25; /* 1236: struct.evp_pkey_method_st */
    	em[1239] = 1233; em[1240] = 8; 
    	em[1241] = 1289; em[1242] = 16; 
    	em[1243] = 1292; em[1244] = 24; 
    	em[1245] = 1233; em[1246] = 32; 
    	em[1247] = 1295; em[1248] = 40; 
    	em[1249] = 1233; em[1250] = 48; 
    	em[1251] = 1295; em[1252] = 56; 
    	em[1253] = 1233; em[1254] = 64; 
    	em[1255] = 1298; em[1256] = 72; 
    	em[1257] = 1233; em[1258] = 80; 
    	em[1259] = 1301; em[1260] = 88; 
    	em[1261] = 1233; em[1262] = 96; 
    	em[1263] = 1298; em[1264] = 104; 
    	em[1265] = 1304; em[1266] = 112; 
    	em[1267] = 1227; em[1268] = 120; 
    	em[1269] = 1304; em[1270] = 128; 
    	em[1271] = 1224; em[1272] = 136; 
    	em[1273] = 1233; em[1274] = 144; 
    	em[1275] = 1298; em[1276] = 152; 
    	em[1277] = 1233; em[1278] = 160; 
    	em[1279] = 1298; em[1280] = 168; 
    	em[1281] = 1233; em[1282] = 176; 
    	em[1283] = 1307; em[1284] = 184; 
    	em[1285] = 1310; em[1286] = 192; 
    	em[1287] = 1313; em[1288] = 200; 
    em[1289] = 8884097; em[1290] = 8; em[1291] = 0; /* 1289: pointer.func */
    em[1292] = 8884097; em[1293] = 8; em[1294] = 0; /* 1292: pointer.func */
    em[1295] = 8884097; em[1296] = 8; em[1297] = 0; /* 1295: pointer.func */
    em[1298] = 8884097; em[1299] = 8; em[1300] = 0; /* 1298: pointer.func */
    em[1301] = 8884097; em[1302] = 8; em[1303] = 0; /* 1301: pointer.func */
    em[1304] = 8884097; em[1305] = 8; em[1306] = 0; /* 1304: pointer.func */
    em[1307] = 8884097; em[1308] = 8; em[1309] = 0; /* 1307: pointer.func */
    em[1310] = 8884097; em[1311] = 8; em[1312] = 0; /* 1310: pointer.func */
    em[1313] = 8884097; em[1314] = 8; em[1315] = 0; /* 1313: pointer.func */
    em[1316] = 1; em[1317] = 8; em[1318] = 1; /* 1316: pointer.struct.evp_pkey_ctx_st */
    	em[1319] = 1321; em[1320] = 0; 
    em[1321] = 0; em[1322] = 80; em[1323] = 8; /* 1321: struct.evp_pkey_ctx_st */
    	em[1324] = 1340; em[1325] = 0; 
    	em[1326] = 1345; em[1327] = 8; 
    	em[1328] = 1350; em[1329] = 16; 
    	em[1330] = 1350; em[1331] = 24; 
    	em[1332] = 585; em[1333] = 40; 
    	em[1334] = 585; em[1335] = 48; 
    	em[1336] = 0; em[1337] = 56; 
    	em[1338] = 1976; em[1339] = 64; 
    em[1340] = 1; em[1341] = 8; em[1342] = 1; /* 1340: pointer.struct.evp_pkey_method_st */
    	em[1343] = 1236; em[1344] = 0; 
    em[1345] = 1; em[1346] = 8; em[1347] = 1; /* 1345: pointer.struct.engine_st */
    	em[1348] = 679; em[1349] = 0; 
    em[1350] = 1; em[1351] = 8; em[1352] = 1; /* 1350: pointer.struct.evp_pkey_st */
    	em[1353] = 1355; em[1354] = 0; 
    em[1355] = 0; em[1356] = 56; em[1357] = 4; /* 1355: struct.evp_pkey_st */
    	em[1358] = 1366; em[1359] = 16; 
    	em[1360] = 1345; em[1361] = 24; 
    	em[1362] = 1371; em[1363] = 32; 
    	em[1364] = 1940; em[1365] = 48; 
    em[1366] = 1; em[1367] = 8; em[1368] = 1; /* 1366: pointer.struct.evp_pkey_asn1_method_st */
    	em[1369] = 1106; em[1370] = 0; 
    em[1371] = 0; em[1372] = 8; em[1373] = 6; /* 1371: union.union_of_evp_pkey_st */
    	em[1374] = 585; em[1375] = 0; 
    	em[1376] = 1219; em[1377] = 6; 
    	em[1378] = 1386; em[1379] = 116; 
    	em[1380] = 1497; em[1381] = 28; 
    	em[1382] = 1615; em[1383] = 408; 
    	em[1384] = 355; em[1385] = 0; 
    em[1386] = 1; em[1387] = 8; em[1388] = 1; /* 1386: pointer.struct.dsa_st */
    	em[1389] = 1391; em[1390] = 0; 
    em[1391] = 0; em[1392] = 136; em[1393] = 11; /* 1391: struct.dsa_st */
    	em[1394] = 1196; em[1395] = 24; 
    	em[1396] = 1196; em[1397] = 32; 
    	em[1398] = 1196; em[1399] = 40; 
    	em[1400] = 1196; em[1401] = 48; 
    	em[1402] = 1196; em[1403] = 56; 
    	em[1404] = 1196; em[1405] = 64; 
    	em[1406] = 1196; em[1407] = 72; 
    	em[1408] = 1416; em[1409] = 88; 
    	em[1410] = 1430; em[1411] = 104; 
    	em[1412] = 1444; em[1413] = 120; 
    	em[1414] = 1492; em[1415] = 128; 
    em[1416] = 1; em[1417] = 8; em[1418] = 1; /* 1416: pointer.struct.bn_mont_ctx_st */
    	em[1419] = 1421; em[1420] = 0; 
    em[1421] = 0; em[1422] = 96; em[1423] = 3; /* 1421: struct.bn_mont_ctx_st */
    	em[1424] = 1201; em[1425] = 8; 
    	em[1426] = 1201; em[1427] = 32; 
    	em[1428] = 1201; em[1429] = 56; 
    em[1430] = 0; em[1431] = 32; em[1432] = 2; /* 1430: struct.crypto_ex_data_st_fake */
    	em[1433] = 1437; em[1434] = 8; 
    	em[1435] = 358; em[1436] = 24; 
    em[1437] = 8884099; em[1438] = 8; em[1439] = 2; /* 1437: pointer_to_array_of_pointers_to_stack */
    	em[1440] = 585; em[1441] = 0; 
    	em[1442] = 355; em[1443] = 20; 
    em[1444] = 1; em[1445] = 8; em[1446] = 1; /* 1444: pointer.struct.dsa_method */
    	em[1447] = 1449; em[1448] = 0; 
    em[1449] = 0; em[1450] = 96; em[1451] = 11; /* 1449: struct.dsa_method */
    	em[1452] = 141; em[1453] = 0; 
    	em[1454] = 1474; em[1455] = 8; 
    	em[1456] = 1477; em[1457] = 16; 
    	em[1458] = 1480; em[1459] = 24; 
    	em[1460] = 571; em[1461] = 32; 
    	em[1462] = 1483; em[1463] = 40; 
    	em[1464] = 1486; em[1465] = 48; 
    	em[1466] = 1486; em[1467] = 56; 
    	em[1468] = 122; em[1469] = 72; 
    	em[1470] = 1489; em[1471] = 80; 
    	em[1472] = 1486; em[1473] = 88; 
    em[1474] = 8884097; em[1475] = 8; em[1476] = 0; /* 1474: pointer.func */
    em[1477] = 8884097; em[1478] = 8; em[1479] = 0; /* 1477: pointer.func */
    em[1480] = 8884097; em[1481] = 8; em[1482] = 0; /* 1480: pointer.func */
    em[1483] = 8884097; em[1484] = 8; em[1485] = 0; /* 1483: pointer.func */
    em[1486] = 8884097; em[1487] = 8; em[1488] = 0; /* 1486: pointer.func */
    em[1489] = 8884097; em[1490] = 8; em[1491] = 0; /* 1489: pointer.func */
    em[1492] = 1; em[1493] = 8; em[1494] = 1; /* 1492: pointer.struct.engine_st */
    	em[1495] = 679; em[1496] = 0; 
    em[1497] = 1; em[1498] = 8; em[1499] = 1; /* 1497: pointer.struct.dh_st */
    	em[1500] = 1502; em[1501] = 0; 
    em[1502] = 0; em[1503] = 144; em[1504] = 12; /* 1502: struct.dh_st */
    	em[1505] = 1529; em[1506] = 8; 
    	em[1507] = 1529; em[1508] = 16; 
    	em[1509] = 1529; em[1510] = 32; 
    	em[1511] = 1529; em[1512] = 40; 
    	em[1513] = 1546; em[1514] = 56; 
    	em[1515] = 1529; em[1516] = 64; 
    	em[1517] = 1529; em[1518] = 72; 
    	em[1519] = 21; em[1520] = 80; 
    	em[1521] = 1529; em[1522] = 96; 
    	em[1523] = 1560; em[1524] = 112; 
    	em[1525] = 1574; em[1526] = 128; 
    	em[1527] = 1610; em[1528] = 136; 
    em[1529] = 1; em[1530] = 8; em[1531] = 1; /* 1529: pointer.struct.bignum_st */
    	em[1532] = 1534; em[1533] = 0; 
    em[1534] = 0; em[1535] = 24; em[1536] = 1; /* 1534: struct.bignum_st */
    	em[1537] = 1539; em[1538] = 0; 
    em[1539] = 8884099; em[1540] = 8; em[1541] = 2; /* 1539: pointer_to_array_of_pointers_to_stack */
    	em[1542] = 396; em[1543] = 0; 
    	em[1544] = 355; em[1545] = 12; 
    em[1546] = 1; em[1547] = 8; em[1548] = 1; /* 1546: pointer.struct.bn_mont_ctx_st */
    	em[1549] = 1551; em[1550] = 0; 
    em[1551] = 0; em[1552] = 96; em[1553] = 3; /* 1551: struct.bn_mont_ctx_st */
    	em[1554] = 1534; em[1555] = 8; 
    	em[1556] = 1534; em[1557] = 32; 
    	em[1558] = 1534; em[1559] = 56; 
    em[1560] = 0; em[1561] = 32; em[1562] = 2; /* 1560: struct.crypto_ex_data_st_fake */
    	em[1563] = 1567; em[1564] = 8; 
    	em[1565] = 358; em[1566] = 24; 
    em[1567] = 8884099; em[1568] = 8; em[1569] = 2; /* 1567: pointer_to_array_of_pointers_to_stack */
    	em[1570] = 585; em[1571] = 0; 
    	em[1572] = 355; em[1573] = 20; 
    em[1574] = 1; em[1575] = 8; em[1576] = 1; /* 1574: pointer.struct.dh_method */
    	em[1577] = 1579; em[1578] = 0; 
    em[1579] = 0; em[1580] = 72; em[1581] = 8; /* 1579: struct.dh_method */
    	em[1582] = 141; em[1583] = 0; 
    	em[1584] = 1598; em[1585] = 8; 
    	em[1586] = 1601; em[1587] = 16; 
    	em[1588] = 1604; em[1589] = 24; 
    	em[1590] = 1598; em[1591] = 32; 
    	em[1592] = 1598; em[1593] = 40; 
    	em[1594] = 122; em[1595] = 56; 
    	em[1596] = 1607; em[1597] = 64; 
    em[1598] = 8884097; em[1599] = 8; em[1600] = 0; /* 1598: pointer.func */
    em[1601] = 8884097; em[1602] = 8; em[1603] = 0; /* 1601: pointer.func */
    em[1604] = 8884097; em[1605] = 8; em[1606] = 0; /* 1604: pointer.func */
    em[1607] = 8884097; em[1608] = 8; em[1609] = 0; /* 1607: pointer.func */
    em[1610] = 1; em[1611] = 8; em[1612] = 1; /* 1610: pointer.struct.engine_st */
    	em[1613] = 679; em[1614] = 0; 
    em[1615] = 1; em[1616] = 8; em[1617] = 1; /* 1615: pointer.struct.ec_key_st */
    	em[1618] = 1620; em[1619] = 0; 
    em[1620] = 0; em[1621] = 56; em[1622] = 4; /* 1620: struct.ec_key_st */
    	em[1623] = 1631; em[1624] = 8; 
    	em[1625] = 1895; em[1626] = 16; 
    	em[1627] = 1900; em[1628] = 24; 
    	em[1629] = 1917; em[1630] = 48; 
    em[1631] = 1; em[1632] = 8; em[1633] = 1; /* 1631: pointer.struct.ec_group_st */
    	em[1634] = 1636; em[1635] = 0; 
    em[1636] = 0; em[1637] = 232; em[1638] = 12; /* 1636: struct.ec_group_st */
    	em[1639] = 1663; em[1640] = 0; 
    	em[1641] = 1823; em[1642] = 8; 
    	em[1643] = 1851; em[1644] = 16; 
    	em[1645] = 1851; em[1646] = 40; 
    	em[1647] = 21; em[1648] = 80; 
    	em[1649] = 1863; em[1650] = 96; 
    	em[1651] = 1851; em[1652] = 104; 
    	em[1653] = 1851; em[1654] = 152; 
    	em[1655] = 1851; em[1656] = 176; 
    	em[1657] = 585; em[1658] = 208; 
    	em[1659] = 585; em[1660] = 216; 
    	em[1661] = 1892; em[1662] = 224; 
    em[1663] = 1; em[1664] = 8; em[1665] = 1; /* 1663: pointer.struct.ec_method_st */
    	em[1666] = 1668; em[1667] = 0; 
    em[1668] = 0; em[1669] = 304; em[1670] = 37; /* 1668: struct.ec_method_st */
    	em[1671] = 1745; em[1672] = 8; 
    	em[1673] = 1748; em[1674] = 16; 
    	em[1675] = 1748; em[1676] = 24; 
    	em[1677] = 1751; em[1678] = 32; 
    	em[1679] = 1754; em[1680] = 40; 
    	em[1681] = 1213; em[1682] = 48; 
    	em[1683] = 1757; em[1684] = 56; 
    	em[1685] = 1760; em[1686] = 64; 
    	em[1687] = 1230; em[1688] = 72; 
    	em[1689] = 1763; em[1690] = 80; 
    	em[1691] = 1763; em[1692] = 88; 
    	em[1693] = 1094; em[1694] = 96; 
    	em[1695] = 1766; em[1696] = 104; 
    	em[1697] = 1769; em[1698] = 112; 
    	em[1699] = 1772; em[1700] = 120; 
    	em[1701] = 1775; em[1702] = 128; 
    	em[1703] = 1778; em[1704] = 136; 
    	em[1705] = 1781; em[1706] = 144; 
    	em[1707] = 1784; em[1708] = 152; 
    	em[1709] = 1787; em[1710] = 160; 
    	em[1711] = 1790; em[1712] = 168; 
    	em[1713] = 1793; em[1714] = 176; 
    	em[1715] = 1796; em[1716] = 184; 
    	em[1717] = 1799; em[1718] = 192; 
    	em[1719] = 1802; em[1720] = 200; 
    	em[1721] = 1805; em[1722] = 208; 
    	em[1723] = 1796; em[1724] = 216; 
    	em[1725] = 1808; em[1726] = 224; 
    	em[1727] = 1811; em[1728] = 232; 
    	em[1729] = 1814; em[1730] = 240; 
    	em[1731] = 1757; em[1732] = 248; 
    	em[1733] = 1817; em[1734] = 256; 
    	em[1735] = 1820; em[1736] = 264; 
    	em[1737] = 1817; em[1738] = 272; 
    	em[1739] = 1820; em[1740] = 280; 
    	em[1741] = 1820; em[1742] = 288; 
    	em[1743] = 1216; em[1744] = 296; 
    em[1745] = 8884097; em[1746] = 8; em[1747] = 0; /* 1745: pointer.func */
    em[1748] = 8884097; em[1749] = 8; em[1750] = 0; /* 1748: pointer.func */
    em[1751] = 8884097; em[1752] = 8; em[1753] = 0; /* 1751: pointer.func */
    em[1754] = 8884097; em[1755] = 8; em[1756] = 0; /* 1754: pointer.func */
    em[1757] = 8884097; em[1758] = 8; em[1759] = 0; /* 1757: pointer.func */
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
    em[1796] = 8884097; em[1797] = 8; em[1798] = 0; /* 1796: pointer.func */
    em[1799] = 8884097; em[1800] = 8; em[1801] = 0; /* 1799: pointer.func */
    em[1802] = 8884097; em[1803] = 8; em[1804] = 0; /* 1802: pointer.func */
    em[1805] = 8884097; em[1806] = 8; em[1807] = 0; /* 1805: pointer.func */
    em[1808] = 8884097; em[1809] = 8; em[1810] = 0; /* 1808: pointer.func */
    em[1811] = 8884097; em[1812] = 8; em[1813] = 0; /* 1811: pointer.func */
    em[1814] = 8884097; em[1815] = 8; em[1816] = 0; /* 1814: pointer.func */
    em[1817] = 8884097; em[1818] = 8; em[1819] = 0; /* 1817: pointer.func */
    em[1820] = 8884097; em[1821] = 8; em[1822] = 0; /* 1820: pointer.func */
    em[1823] = 1; em[1824] = 8; em[1825] = 1; /* 1823: pointer.struct.ec_point_st */
    	em[1826] = 1828; em[1827] = 0; 
    em[1828] = 0; em[1829] = 88; em[1830] = 4; /* 1828: struct.ec_point_st */
    	em[1831] = 399; em[1832] = 0; 
    	em[1833] = 1839; em[1834] = 8; 
    	em[1835] = 1839; em[1836] = 32; 
    	em[1837] = 1839; em[1838] = 56; 
    em[1839] = 0; em[1840] = 24; em[1841] = 1; /* 1839: struct.bignum_st */
    	em[1842] = 1844; em[1843] = 0; 
    em[1844] = 8884099; em[1845] = 8; em[1846] = 2; /* 1844: pointer_to_array_of_pointers_to_stack */
    	em[1847] = 396; em[1848] = 0; 
    	em[1849] = 355; em[1850] = 12; 
    em[1851] = 0; em[1852] = 24; em[1853] = 1; /* 1851: struct.bignum_st */
    	em[1854] = 1856; em[1855] = 0; 
    em[1856] = 8884099; em[1857] = 8; em[1858] = 2; /* 1856: pointer_to_array_of_pointers_to_stack */
    	em[1859] = 396; em[1860] = 0; 
    	em[1861] = 355; em[1862] = 12; 
    em[1863] = 1; em[1864] = 8; em[1865] = 1; /* 1863: pointer.struct.ec_extra_data_st */
    	em[1866] = 1868; em[1867] = 0; 
    em[1868] = 0; em[1869] = 40; em[1870] = 5; /* 1868: struct.ec_extra_data_st */
    	em[1871] = 1881; em[1872] = 0; 
    	em[1873] = 585; em[1874] = 8; 
    	em[1875] = 1886; em[1876] = 16; 
    	em[1877] = 1889; em[1878] = 24; 
    	em[1879] = 1889; em[1880] = 32; 
    em[1881] = 1; em[1882] = 8; em[1883] = 1; /* 1881: pointer.struct.ec_extra_data_st */
    	em[1884] = 1868; em[1885] = 0; 
    em[1886] = 8884097; em[1887] = 8; em[1888] = 0; /* 1886: pointer.func */
    em[1889] = 8884097; em[1890] = 8; em[1891] = 0; /* 1889: pointer.func */
    em[1892] = 8884097; em[1893] = 8; em[1894] = 0; /* 1892: pointer.func */
    em[1895] = 1; em[1896] = 8; em[1897] = 1; /* 1895: pointer.struct.ec_point_st */
    	em[1898] = 1828; em[1899] = 0; 
    em[1900] = 1; em[1901] = 8; em[1902] = 1; /* 1900: pointer.struct.bignum_st */
    	em[1903] = 1905; em[1904] = 0; 
    em[1905] = 0; em[1906] = 24; em[1907] = 1; /* 1905: struct.bignum_st */
    	em[1908] = 1910; em[1909] = 0; 
    em[1910] = 8884099; em[1911] = 8; em[1912] = 2; /* 1910: pointer_to_array_of_pointers_to_stack */
    	em[1913] = 396; em[1914] = 0; 
    	em[1915] = 355; em[1916] = 12; 
    em[1917] = 1; em[1918] = 8; em[1919] = 1; /* 1917: pointer.struct.ec_extra_data_st */
    	em[1920] = 1922; em[1921] = 0; 
    em[1922] = 0; em[1923] = 40; em[1924] = 5; /* 1922: struct.ec_extra_data_st */
    	em[1925] = 1935; em[1926] = 0; 
    	em[1927] = 585; em[1928] = 8; 
    	em[1929] = 1886; em[1930] = 16; 
    	em[1931] = 1889; em[1932] = 24; 
    	em[1933] = 1889; em[1934] = 32; 
    em[1935] = 1; em[1936] = 8; em[1937] = 1; /* 1935: pointer.struct.ec_extra_data_st */
    	em[1938] = 1922; em[1939] = 0; 
    em[1940] = 1; em[1941] = 8; em[1942] = 1; /* 1940: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1943] = 1945; em[1944] = 0; 
    em[1945] = 0; em[1946] = 32; em[1947] = 2; /* 1945: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1948] = 1952; em[1949] = 8; 
    	em[1950] = 358; em[1951] = 24; 
    em[1952] = 8884099; em[1953] = 8; em[1954] = 2; /* 1952: pointer_to_array_of_pointers_to_stack */
    	em[1955] = 1959; em[1956] = 0; 
    	em[1957] = 355; em[1958] = 20; 
    em[1959] = 0; em[1960] = 8; em[1961] = 1; /* 1959: pointer.X509_ATTRIBUTE */
    	em[1962] = 1964; em[1963] = 0; 
    em[1964] = 0; em[1965] = 0; em[1966] = 1; /* 1964: X509_ATTRIBUTE */
    	em[1967] = 1969; em[1968] = 0; 
    em[1969] = 0; em[1970] = 24; em[1971] = 2; /* 1969: struct.x509_attributes_st */
    	em[1972] = 127; em[1973] = 0; 
    	em[1974] = 361; em[1975] = 16; 
    em[1976] = 1; em[1977] = 8; em[1978] = 1; /* 1976: pointer.int */
    	em[1979] = 355; em[1980] = 0; 
    em[1981] = 0; em[1982] = 1; em[1983] = 0; /* 1981: char */
    em[1984] = 8884097; em[1985] = 8; em[1986] = 0; /* 1984: pointer.func */
    em[1987] = 8884097; em[1988] = 8; em[1989] = 0; /* 1987: pointer.func */
    em[1990] = 8884097; em[1991] = 8; em[1992] = 0; /* 1990: pointer.func */
    em[1993] = 0; em[1994] = 48; em[1995] = 5; /* 1993: struct.env_md_ctx_st */
    	em[1996] = 2006; em[1997] = 0; 
    	em[1998] = 1345; em[1999] = 8; 
    	em[2000] = 585; em[2001] = 24; 
    	em[2002] = 1316; em[2003] = 32; 
    	em[2004] = 1987; em[2005] = 40; 
    em[2006] = 1; em[2007] = 8; em[2008] = 1; /* 2006: pointer.struct.env_md_st */
    	em[2009] = 2011; em[2010] = 0; 
    em[2011] = 0; em[2012] = 120; em[2013] = 8; /* 2011: struct.env_md_st */
    	em[2014] = 2030; em[2015] = 24; 
    	em[2016] = 1987; em[2017] = 32; 
    	em[2018] = 2033; em[2019] = 40; 
    	em[2020] = 1990; em[2021] = 48; 
    	em[2022] = 2030; em[2023] = 56; 
    	em[2024] = 1984; em[2025] = 64; 
    	em[2026] = 1193; em[2027] = 72; 
    	em[2028] = 2036; em[2029] = 112; 
    em[2030] = 8884097; em[2031] = 8; em[2032] = 0; /* 2030: pointer.func */
    em[2033] = 8884097; em[2034] = 8; em[2035] = 0; /* 2033: pointer.func */
    em[2036] = 8884097; em[2037] = 8; em[2038] = 0; /* 2036: pointer.func */
    em[2039] = 0; em[2040] = 0; em[2041] = 0; /* 2039: size_t */
    em[2042] = 1; em[2043] = 8; em[2044] = 1; /* 2042: pointer.struct.env_md_ctx_st */
    	em[2045] = 1993; em[2046] = 0; 
    args_addr->arg_entity_index[0] = 2042;
    args_addr->arg_entity_index[1] = 585;
    args_addr->arg_entity_index[2] = 2039;
    args_addr->ret_entity_index = 355;
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

