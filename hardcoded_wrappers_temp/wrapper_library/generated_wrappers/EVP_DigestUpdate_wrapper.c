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
    em[179] = 1; em[180] = 8; em[181] = 1; /* 179: pointer.struct.ASN1_VALUE_st */
    	em[182] = 176; em[183] = 0; 
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
    em[229] = 0; em[230] = 40; em[231] = 3; /* 229: struct.asn1_object_st */
    	em[232] = 141; em[233] = 0; 
    	em[234] = 141; em[235] = 8; 
    	em[236] = 146; em[237] = 24; 
    em[238] = 1; em[239] = 8; em[240] = 1; /* 238: pointer.struct.asn1_string_st */
    	em[241] = 189; em[242] = 0; 
    em[243] = 0; em[244] = 0; em[245] = 1; /* 243: ASN1_TYPE */
    	em[246] = 248; em[247] = 0; 
    em[248] = 0; em[249] = 16; em[250] = 1; /* 248: struct.asn1_type_st */
    	em[251] = 253; em[252] = 8; 
    em[253] = 0; em[254] = 8; em[255] = 20; /* 253: union.unknown */
    	em[256] = 122; em[257] = 0; 
    	em[258] = 238; em[259] = 0; 
    	em[260] = 296; em[261] = 0; 
    	em[262] = 224; em[263] = 0; 
    	em[264] = 219; em[265] = 0; 
    	em[266] = 214; em[267] = 0; 
    	em[268] = 209; em[269] = 0; 
    	em[270] = 301; em[271] = 0; 
    	em[272] = 306; em[273] = 0; 
    	em[274] = 204; em[275] = 0; 
    	em[276] = 199; em[277] = 0; 
    	em[278] = 311; em[279] = 0; 
    	em[280] = 316; em[281] = 0; 
    	em[282] = 321; em[283] = 0; 
    	em[284] = 194; em[285] = 0; 
    	em[286] = 326; em[287] = 0; 
    	em[288] = 184; em[289] = 0; 
    	em[290] = 238; em[291] = 0; 
    	em[292] = 238; em[293] = 0; 
    	em[294] = 179; em[295] = 0; 
    em[296] = 1; em[297] = 8; em[298] = 1; /* 296: pointer.struct.asn1_object_st */
    	em[299] = 229; em[300] = 0; 
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
    em[331] = 1; em[332] = 8; em[333] = 1; /* 331: pointer.struct.stack_st_ASN1_TYPE */
    	em[334] = 336; em[335] = 0; 
    em[336] = 0; em[337] = 32; em[338] = 2; /* 336: struct.stack_st_fake_ASN1_TYPE */
    	em[339] = 343; em[340] = 8; 
    	em[341] = 358; em[342] = 24; 
    em[343] = 8884099; em[344] = 8; em[345] = 2; /* 343: pointer_to_array_of_pointers_to_stack */
    	em[346] = 350; em[347] = 0; 
    	em[348] = 355; em[349] = 20; 
    em[350] = 0; em[351] = 8; em[352] = 1; /* 350: pointer.ASN1_TYPE */
    	em[353] = 243; em[354] = 0; 
    em[355] = 0; em[356] = 4; em[357] = 0; /* 355: int */
    em[358] = 8884097; em[359] = 8; em[360] = 0; /* 358: pointer.func */
    em[361] = 8884097; em[362] = 8; em[363] = 0; /* 361: pointer.func */
    em[364] = 1; em[365] = 8; em[366] = 1; /* 364: pointer.struct.ec_key_st */
    	em[367] = 369; em[368] = 0; 
    em[369] = 0; em[370] = 56; em[371] = 4; /* 369: struct.ec_key_st */
    	em[372] = 380; em[373] = 8; 
    	em[374] = 834; em[375] = 16; 
    	em[376] = 839; em[377] = 24; 
    	em[378] = 856; em[379] = 48; 
    em[380] = 1; em[381] = 8; em[382] = 1; /* 380: pointer.struct.ec_group_st */
    	em[383] = 385; em[384] = 0; 
    em[385] = 0; em[386] = 232; em[387] = 12; /* 385: struct.ec_group_st */
    	em[388] = 412; em[389] = 0; 
    	em[390] = 584; em[391] = 8; 
    	em[392] = 787; em[393] = 16; 
    	em[394] = 787; em[395] = 40; 
    	em[396] = 21; em[397] = 80; 
    	em[398] = 799; em[399] = 96; 
    	em[400] = 787; em[401] = 104; 
    	em[402] = 787; em[403] = 152; 
    	em[404] = 787; em[405] = 176; 
    	em[406] = 822; em[407] = 208; 
    	em[408] = 822; em[409] = 216; 
    	em[410] = 831; em[411] = 224; 
    em[412] = 1; em[413] = 8; em[414] = 1; /* 412: pointer.struct.ec_method_st */
    	em[415] = 417; em[416] = 0; 
    em[417] = 0; em[418] = 304; em[419] = 37; /* 417: struct.ec_method_st */
    	em[420] = 494; em[421] = 8; 
    	em[422] = 497; em[423] = 16; 
    	em[424] = 497; em[425] = 24; 
    	em[426] = 500; em[427] = 32; 
    	em[428] = 503; em[429] = 40; 
    	em[430] = 506; em[431] = 48; 
    	em[432] = 509; em[433] = 56; 
    	em[434] = 512; em[435] = 64; 
    	em[436] = 515; em[437] = 72; 
    	em[438] = 518; em[439] = 80; 
    	em[440] = 518; em[441] = 88; 
    	em[442] = 521; em[443] = 96; 
    	em[444] = 524; em[445] = 104; 
    	em[446] = 527; em[447] = 112; 
    	em[448] = 530; em[449] = 120; 
    	em[450] = 533; em[451] = 128; 
    	em[452] = 536; em[453] = 136; 
    	em[454] = 539; em[455] = 144; 
    	em[456] = 542; em[457] = 152; 
    	em[458] = 545; em[459] = 160; 
    	em[460] = 548; em[461] = 168; 
    	em[462] = 551; em[463] = 176; 
    	em[464] = 554; em[465] = 184; 
    	em[466] = 557; em[467] = 192; 
    	em[468] = 560; em[469] = 200; 
    	em[470] = 563; em[471] = 208; 
    	em[472] = 554; em[473] = 216; 
    	em[474] = 566; em[475] = 224; 
    	em[476] = 569; em[477] = 232; 
    	em[478] = 572; em[479] = 240; 
    	em[480] = 509; em[481] = 248; 
    	em[482] = 575; em[483] = 256; 
    	em[484] = 578; em[485] = 264; 
    	em[486] = 575; em[487] = 272; 
    	em[488] = 578; em[489] = 280; 
    	em[490] = 578; em[491] = 288; 
    	em[492] = 581; em[493] = 296; 
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
    em[560] = 8884097; em[561] = 8; em[562] = 0; /* 560: pointer.func */
    em[563] = 8884097; em[564] = 8; em[565] = 0; /* 563: pointer.func */
    em[566] = 8884097; em[567] = 8; em[568] = 0; /* 566: pointer.func */
    em[569] = 8884097; em[570] = 8; em[571] = 0; /* 569: pointer.func */
    em[572] = 8884097; em[573] = 8; em[574] = 0; /* 572: pointer.func */
    em[575] = 8884097; em[576] = 8; em[577] = 0; /* 575: pointer.func */
    em[578] = 8884097; em[579] = 8; em[580] = 0; /* 578: pointer.func */
    em[581] = 8884097; em[582] = 8; em[583] = 0; /* 581: pointer.func */
    em[584] = 1; em[585] = 8; em[586] = 1; /* 584: pointer.struct.ec_point_st */
    	em[587] = 589; em[588] = 0; 
    em[589] = 0; em[590] = 88; em[591] = 4; /* 589: struct.ec_point_st */
    	em[592] = 600; em[593] = 0; 
    	em[594] = 772; em[595] = 8; 
    	em[596] = 772; em[597] = 32; 
    	em[598] = 772; em[599] = 56; 
    em[600] = 1; em[601] = 8; em[602] = 1; /* 600: pointer.struct.ec_method_st */
    	em[603] = 605; em[604] = 0; 
    em[605] = 0; em[606] = 304; em[607] = 37; /* 605: struct.ec_method_st */
    	em[608] = 682; em[609] = 8; 
    	em[610] = 685; em[611] = 16; 
    	em[612] = 685; em[613] = 24; 
    	em[614] = 688; em[615] = 32; 
    	em[616] = 691; em[617] = 40; 
    	em[618] = 694; em[619] = 48; 
    	em[620] = 697; em[621] = 56; 
    	em[622] = 700; em[623] = 64; 
    	em[624] = 703; em[625] = 72; 
    	em[626] = 706; em[627] = 80; 
    	em[628] = 706; em[629] = 88; 
    	em[630] = 709; em[631] = 96; 
    	em[632] = 712; em[633] = 104; 
    	em[634] = 715; em[635] = 112; 
    	em[636] = 718; em[637] = 120; 
    	em[638] = 721; em[639] = 128; 
    	em[640] = 724; em[641] = 136; 
    	em[642] = 727; em[643] = 144; 
    	em[644] = 730; em[645] = 152; 
    	em[646] = 733; em[647] = 160; 
    	em[648] = 736; em[649] = 168; 
    	em[650] = 739; em[651] = 176; 
    	em[652] = 742; em[653] = 184; 
    	em[654] = 745; em[655] = 192; 
    	em[656] = 748; em[657] = 200; 
    	em[658] = 751; em[659] = 208; 
    	em[660] = 742; em[661] = 216; 
    	em[662] = 754; em[663] = 224; 
    	em[664] = 757; em[665] = 232; 
    	em[666] = 760; em[667] = 240; 
    	em[668] = 697; em[669] = 248; 
    	em[670] = 763; em[671] = 256; 
    	em[672] = 766; em[673] = 264; 
    	em[674] = 763; em[675] = 272; 
    	em[676] = 766; em[677] = 280; 
    	em[678] = 766; em[679] = 288; 
    	em[680] = 769; em[681] = 296; 
    em[682] = 8884097; em[683] = 8; em[684] = 0; /* 682: pointer.func */
    em[685] = 8884097; em[686] = 8; em[687] = 0; /* 685: pointer.func */
    em[688] = 8884097; em[689] = 8; em[690] = 0; /* 688: pointer.func */
    em[691] = 8884097; em[692] = 8; em[693] = 0; /* 691: pointer.func */
    em[694] = 8884097; em[695] = 8; em[696] = 0; /* 694: pointer.func */
    em[697] = 8884097; em[698] = 8; em[699] = 0; /* 697: pointer.func */
    em[700] = 8884097; em[701] = 8; em[702] = 0; /* 700: pointer.func */
    em[703] = 8884097; em[704] = 8; em[705] = 0; /* 703: pointer.func */
    em[706] = 8884097; em[707] = 8; em[708] = 0; /* 706: pointer.func */
    em[709] = 8884097; em[710] = 8; em[711] = 0; /* 709: pointer.func */
    em[712] = 8884097; em[713] = 8; em[714] = 0; /* 712: pointer.func */
    em[715] = 8884097; em[716] = 8; em[717] = 0; /* 715: pointer.func */
    em[718] = 8884097; em[719] = 8; em[720] = 0; /* 718: pointer.func */
    em[721] = 8884097; em[722] = 8; em[723] = 0; /* 721: pointer.func */
    em[724] = 8884097; em[725] = 8; em[726] = 0; /* 724: pointer.func */
    em[727] = 8884097; em[728] = 8; em[729] = 0; /* 727: pointer.func */
    em[730] = 8884097; em[731] = 8; em[732] = 0; /* 730: pointer.func */
    em[733] = 8884097; em[734] = 8; em[735] = 0; /* 733: pointer.func */
    em[736] = 8884097; em[737] = 8; em[738] = 0; /* 736: pointer.func */
    em[739] = 8884097; em[740] = 8; em[741] = 0; /* 739: pointer.func */
    em[742] = 8884097; em[743] = 8; em[744] = 0; /* 742: pointer.func */
    em[745] = 8884097; em[746] = 8; em[747] = 0; /* 745: pointer.func */
    em[748] = 8884097; em[749] = 8; em[750] = 0; /* 748: pointer.func */
    em[751] = 8884097; em[752] = 8; em[753] = 0; /* 751: pointer.func */
    em[754] = 8884097; em[755] = 8; em[756] = 0; /* 754: pointer.func */
    em[757] = 8884097; em[758] = 8; em[759] = 0; /* 757: pointer.func */
    em[760] = 8884097; em[761] = 8; em[762] = 0; /* 760: pointer.func */
    em[763] = 8884097; em[764] = 8; em[765] = 0; /* 763: pointer.func */
    em[766] = 8884097; em[767] = 8; em[768] = 0; /* 766: pointer.func */
    em[769] = 8884097; em[770] = 8; em[771] = 0; /* 769: pointer.func */
    em[772] = 0; em[773] = 24; em[774] = 1; /* 772: struct.bignum_st */
    	em[775] = 777; em[776] = 0; 
    em[777] = 8884099; em[778] = 8; em[779] = 2; /* 777: pointer_to_array_of_pointers_to_stack */
    	em[780] = 784; em[781] = 0; 
    	em[782] = 355; em[783] = 12; 
    em[784] = 0; em[785] = 8; em[786] = 0; /* 784: long unsigned int */
    em[787] = 0; em[788] = 24; em[789] = 1; /* 787: struct.bignum_st */
    	em[790] = 792; em[791] = 0; 
    em[792] = 8884099; em[793] = 8; em[794] = 2; /* 792: pointer_to_array_of_pointers_to_stack */
    	em[795] = 784; em[796] = 0; 
    	em[797] = 355; em[798] = 12; 
    em[799] = 1; em[800] = 8; em[801] = 1; /* 799: pointer.struct.ec_extra_data_st */
    	em[802] = 804; em[803] = 0; 
    em[804] = 0; em[805] = 40; em[806] = 5; /* 804: struct.ec_extra_data_st */
    	em[807] = 817; em[808] = 0; 
    	em[809] = 822; em[810] = 8; 
    	em[811] = 825; em[812] = 16; 
    	em[813] = 828; em[814] = 24; 
    	em[815] = 828; em[816] = 32; 
    em[817] = 1; em[818] = 8; em[819] = 1; /* 817: pointer.struct.ec_extra_data_st */
    	em[820] = 804; em[821] = 0; 
    em[822] = 0; em[823] = 8; em[824] = 0; /* 822: pointer.void */
    em[825] = 8884097; em[826] = 8; em[827] = 0; /* 825: pointer.func */
    em[828] = 8884097; em[829] = 8; em[830] = 0; /* 828: pointer.func */
    em[831] = 8884097; em[832] = 8; em[833] = 0; /* 831: pointer.func */
    em[834] = 1; em[835] = 8; em[836] = 1; /* 834: pointer.struct.ec_point_st */
    	em[837] = 589; em[838] = 0; 
    em[839] = 1; em[840] = 8; em[841] = 1; /* 839: pointer.struct.bignum_st */
    	em[842] = 844; em[843] = 0; 
    em[844] = 0; em[845] = 24; em[846] = 1; /* 844: struct.bignum_st */
    	em[847] = 849; em[848] = 0; 
    em[849] = 8884099; em[850] = 8; em[851] = 2; /* 849: pointer_to_array_of_pointers_to_stack */
    	em[852] = 784; em[853] = 0; 
    	em[854] = 355; em[855] = 12; 
    em[856] = 1; em[857] = 8; em[858] = 1; /* 856: pointer.struct.ec_extra_data_st */
    	em[859] = 861; em[860] = 0; 
    em[861] = 0; em[862] = 40; em[863] = 5; /* 861: struct.ec_extra_data_st */
    	em[864] = 874; em[865] = 0; 
    	em[866] = 822; em[867] = 8; 
    	em[868] = 825; em[869] = 16; 
    	em[870] = 828; em[871] = 24; 
    	em[872] = 828; em[873] = 32; 
    em[874] = 1; em[875] = 8; em[876] = 1; /* 874: pointer.struct.ec_extra_data_st */
    	em[877] = 861; em[878] = 0; 
    em[879] = 0; em[880] = 24; em[881] = 1; /* 879: struct.bignum_st */
    	em[882] = 884; em[883] = 0; 
    em[884] = 8884099; em[885] = 8; em[886] = 2; /* 884: pointer_to_array_of_pointers_to_stack */
    	em[887] = 784; em[888] = 0; 
    	em[889] = 355; em[890] = 12; 
    em[891] = 8884097; em[892] = 8; em[893] = 0; /* 891: pointer.func */
    em[894] = 0; em[895] = 208; em[896] = 24; /* 894: struct.evp_pkey_asn1_method_st */
    	em[897] = 122; em[898] = 16; 
    	em[899] = 122; em[900] = 24; 
    	em[901] = 945; em[902] = 32; 
    	em[903] = 948; em[904] = 40; 
    	em[905] = 951; em[906] = 48; 
    	em[907] = 954; em[908] = 56; 
    	em[909] = 957; em[910] = 64; 
    	em[911] = 960; em[912] = 72; 
    	em[913] = 954; em[914] = 80; 
    	em[915] = 963; em[916] = 88; 
    	em[917] = 963; em[918] = 96; 
    	em[919] = 966; em[920] = 104; 
    	em[921] = 969; em[922] = 112; 
    	em[923] = 963; em[924] = 120; 
    	em[925] = 891; em[926] = 128; 
    	em[927] = 951; em[928] = 136; 
    	em[929] = 954; em[930] = 144; 
    	em[931] = 972; em[932] = 152; 
    	em[933] = 975; em[934] = 160; 
    	em[935] = 978; em[936] = 168; 
    	em[937] = 966; em[938] = 176; 
    	em[939] = 969; em[940] = 184; 
    	em[941] = 981; em[942] = 192; 
    	em[943] = 984; em[944] = 200; 
    em[945] = 8884097; em[946] = 8; em[947] = 0; /* 945: pointer.func */
    em[948] = 8884097; em[949] = 8; em[950] = 0; /* 948: pointer.func */
    em[951] = 8884097; em[952] = 8; em[953] = 0; /* 951: pointer.func */
    em[954] = 8884097; em[955] = 8; em[956] = 0; /* 954: pointer.func */
    em[957] = 8884097; em[958] = 8; em[959] = 0; /* 957: pointer.func */
    em[960] = 8884097; em[961] = 8; em[962] = 0; /* 960: pointer.func */
    em[963] = 8884097; em[964] = 8; em[965] = 0; /* 963: pointer.func */
    em[966] = 8884097; em[967] = 8; em[968] = 0; /* 966: pointer.func */
    em[969] = 8884097; em[970] = 8; em[971] = 0; /* 969: pointer.func */
    em[972] = 8884097; em[973] = 8; em[974] = 0; /* 972: pointer.func */
    em[975] = 8884097; em[976] = 8; em[977] = 0; /* 975: pointer.func */
    em[978] = 8884097; em[979] = 8; em[980] = 0; /* 978: pointer.func */
    em[981] = 8884097; em[982] = 8; em[983] = 0; /* 981: pointer.func */
    em[984] = 8884097; em[985] = 8; em[986] = 0; /* 984: pointer.func */
    em[987] = 8884097; em[988] = 8; em[989] = 0; /* 987: pointer.func */
    em[990] = 8884097; em[991] = 8; em[992] = 0; /* 990: pointer.func */
    em[993] = 8884097; em[994] = 8; em[995] = 0; /* 993: pointer.func */
    em[996] = 8884097; em[997] = 8; em[998] = 0; /* 996: pointer.func */
    em[999] = 8884097; em[1000] = 8; em[1001] = 0; /* 999: pointer.func */
    em[1002] = 8884097; em[1003] = 8; em[1004] = 0; /* 1002: pointer.func */
    em[1005] = 0; em[1006] = 112; em[1007] = 13; /* 1005: struct.rsa_meth_st */
    	em[1008] = 141; em[1009] = 0; 
    	em[1010] = 999; em[1011] = 8; 
    	em[1012] = 999; em[1013] = 16; 
    	em[1014] = 999; em[1015] = 24; 
    	em[1016] = 999; em[1017] = 32; 
    	em[1018] = 1034; em[1019] = 40; 
    	em[1020] = 993; em[1021] = 48; 
    	em[1022] = 987; em[1023] = 56; 
    	em[1024] = 987; em[1025] = 64; 
    	em[1026] = 122; em[1027] = 80; 
    	em[1028] = 1037; em[1029] = 88; 
    	em[1030] = 1040; em[1031] = 96; 
    	em[1032] = 361; em[1033] = 104; 
    em[1034] = 8884097; em[1035] = 8; em[1036] = 0; /* 1034: pointer.func */
    em[1037] = 8884097; em[1038] = 8; em[1039] = 0; /* 1037: pointer.func */
    em[1040] = 8884097; em[1041] = 8; em[1042] = 0; /* 1040: pointer.func */
    em[1043] = 1; em[1044] = 8; em[1045] = 1; /* 1043: pointer.struct.rsa_meth_st */
    	em[1046] = 1005; em[1047] = 0; 
    em[1048] = 8884097; em[1049] = 8; em[1050] = 0; /* 1048: pointer.func */
    em[1051] = 0; em[1052] = 168; em[1053] = 17; /* 1051: struct.rsa_st */
    	em[1054] = 1043; em[1055] = 16; 
    	em[1056] = 1088; em[1057] = 24; 
    	em[1058] = 1419; em[1059] = 32; 
    	em[1060] = 1419; em[1061] = 40; 
    	em[1062] = 1419; em[1063] = 48; 
    	em[1064] = 1419; em[1065] = 56; 
    	em[1066] = 1419; em[1067] = 64; 
    	em[1068] = 1419; em[1069] = 72; 
    	em[1070] = 1419; em[1071] = 80; 
    	em[1072] = 1419; em[1073] = 88; 
    	em[1074] = 1424; em[1075] = 96; 
    	em[1076] = 1438; em[1077] = 120; 
    	em[1078] = 1438; em[1079] = 128; 
    	em[1080] = 1438; em[1081] = 136; 
    	em[1082] = 122; em[1083] = 144; 
    	em[1084] = 1452; em[1085] = 152; 
    	em[1086] = 1452; em[1087] = 160; 
    em[1088] = 1; em[1089] = 8; em[1090] = 1; /* 1088: pointer.struct.engine_st */
    	em[1091] = 1093; em[1092] = 0; 
    em[1093] = 0; em[1094] = 216; em[1095] = 24; /* 1093: struct.engine_st */
    	em[1096] = 141; em[1097] = 0; 
    	em[1098] = 141; em[1099] = 8; 
    	em[1100] = 1144; em[1101] = 16; 
    	em[1102] = 1196; em[1103] = 24; 
    	em[1104] = 1244; em[1105] = 32; 
    	em[1106] = 1280; em[1107] = 40; 
    	em[1108] = 1297; em[1109] = 48; 
    	em[1110] = 1324; em[1111] = 56; 
    	em[1112] = 1359; em[1113] = 64; 
    	em[1114] = 1367; em[1115] = 72; 
    	em[1116] = 1370; em[1117] = 80; 
    	em[1118] = 1373; em[1119] = 88; 
    	em[1120] = 1376; em[1121] = 96; 
    	em[1122] = 1379; em[1123] = 104; 
    	em[1124] = 1379; em[1125] = 112; 
    	em[1126] = 1379; em[1127] = 120; 
    	em[1128] = 1382; em[1129] = 128; 
    	em[1130] = 1048; em[1131] = 136; 
    	em[1132] = 1048; em[1133] = 144; 
    	em[1134] = 1385; em[1135] = 152; 
    	em[1136] = 1388; em[1137] = 160; 
    	em[1138] = 1400; em[1139] = 184; 
    	em[1140] = 1414; em[1141] = 200; 
    	em[1142] = 1414; em[1143] = 208; 
    em[1144] = 1; em[1145] = 8; em[1146] = 1; /* 1144: pointer.struct.rsa_meth_st */
    	em[1147] = 1149; em[1148] = 0; 
    em[1149] = 0; em[1150] = 112; em[1151] = 13; /* 1149: struct.rsa_meth_st */
    	em[1152] = 141; em[1153] = 0; 
    	em[1154] = 990; em[1155] = 8; 
    	em[1156] = 990; em[1157] = 16; 
    	em[1158] = 990; em[1159] = 24; 
    	em[1160] = 990; em[1161] = 32; 
    	em[1162] = 1178; em[1163] = 40; 
    	em[1164] = 1181; em[1165] = 48; 
    	em[1166] = 1184; em[1167] = 56; 
    	em[1168] = 1184; em[1169] = 64; 
    	em[1170] = 122; em[1171] = 80; 
    	em[1172] = 1187; em[1173] = 88; 
    	em[1174] = 1190; em[1175] = 96; 
    	em[1176] = 1193; em[1177] = 104; 
    em[1178] = 8884097; em[1179] = 8; em[1180] = 0; /* 1178: pointer.func */
    em[1181] = 8884097; em[1182] = 8; em[1183] = 0; /* 1181: pointer.func */
    em[1184] = 8884097; em[1185] = 8; em[1186] = 0; /* 1184: pointer.func */
    em[1187] = 8884097; em[1188] = 8; em[1189] = 0; /* 1187: pointer.func */
    em[1190] = 8884097; em[1191] = 8; em[1192] = 0; /* 1190: pointer.func */
    em[1193] = 8884097; em[1194] = 8; em[1195] = 0; /* 1193: pointer.func */
    em[1196] = 1; em[1197] = 8; em[1198] = 1; /* 1196: pointer.struct.dsa_method */
    	em[1199] = 1201; em[1200] = 0; 
    em[1201] = 0; em[1202] = 96; em[1203] = 11; /* 1201: struct.dsa_method */
    	em[1204] = 141; em[1205] = 0; 
    	em[1206] = 996; em[1207] = 8; 
    	em[1208] = 1226; em[1209] = 16; 
    	em[1210] = 1229; em[1211] = 24; 
    	em[1212] = 1232; em[1213] = 32; 
    	em[1214] = 1235; em[1215] = 40; 
    	em[1216] = 1238; em[1217] = 48; 
    	em[1218] = 1238; em[1219] = 56; 
    	em[1220] = 122; em[1221] = 72; 
    	em[1222] = 1241; em[1223] = 80; 
    	em[1224] = 1238; em[1225] = 88; 
    em[1226] = 8884097; em[1227] = 8; em[1228] = 0; /* 1226: pointer.func */
    em[1229] = 8884097; em[1230] = 8; em[1231] = 0; /* 1229: pointer.func */
    em[1232] = 8884097; em[1233] = 8; em[1234] = 0; /* 1232: pointer.func */
    em[1235] = 8884097; em[1236] = 8; em[1237] = 0; /* 1235: pointer.func */
    em[1238] = 8884097; em[1239] = 8; em[1240] = 0; /* 1238: pointer.func */
    em[1241] = 8884097; em[1242] = 8; em[1243] = 0; /* 1241: pointer.func */
    em[1244] = 1; em[1245] = 8; em[1246] = 1; /* 1244: pointer.struct.dh_method */
    	em[1247] = 1249; em[1248] = 0; 
    em[1249] = 0; em[1250] = 72; em[1251] = 8; /* 1249: struct.dh_method */
    	em[1252] = 141; em[1253] = 0; 
    	em[1254] = 1268; em[1255] = 8; 
    	em[1256] = 1271; em[1257] = 16; 
    	em[1258] = 1274; em[1259] = 24; 
    	em[1260] = 1268; em[1261] = 32; 
    	em[1262] = 1268; em[1263] = 40; 
    	em[1264] = 122; em[1265] = 56; 
    	em[1266] = 1277; em[1267] = 64; 
    em[1268] = 8884097; em[1269] = 8; em[1270] = 0; /* 1268: pointer.func */
    em[1271] = 8884097; em[1272] = 8; em[1273] = 0; /* 1271: pointer.func */
    em[1274] = 8884097; em[1275] = 8; em[1276] = 0; /* 1274: pointer.func */
    em[1277] = 8884097; em[1278] = 8; em[1279] = 0; /* 1277: pointer.func */
    em[1280] = 1; em[1281] = 8; em[1282] = 1; /* 1280: pointer.struct.ecdh_method */
    	em[1283] = 1285; em[1284] = 0; 
    em[1285] = 0; em[1286] = 32; em[1287] = 3; /* 1285: struct.ecdh_method */
    	em[1288] = 141; em[1289] = 0; 
    	em[1290] = 1294; em[1291] = 8; 
    	em[1292] = 122; em[1293] = 24; 
    em[1294] = 8884097; em[1295] = 8; em[1296] = 0; /* 1294: pointer.func */
    em[1297] = 1; em[1298] = 8; em[1299] = 1; /* 1297: pointer.struct.ecdsa_method */
    	em[1300] = 1302; em[1301] = 0; 
    em[1302] = 0; em[1303] = 48; em[1304] = 5; /* 1302: struct.ecdsa_method */
    	em[1305] = 141; em[1306] = 0; 
    	em[1307] = 1315; em[1308] = 8; 
    	em[1309] = 1318; em[1310] = 16; 
    	em[1311] = 1321; em[1312] = 24; 
    	em[1313] = 122; em[1314] = 40; 
    em[1315] = 8884097; em[1316] = 8; em[1317] = 0; /* 1315: pointer.func */
    em[1318] = 8884097; em[1319] = 8; em[1320] = 0; /* 1318: pointer.func */
    em[1321] = 8884097; em[1322] = 8; em[1323] = 0; /* 1321: pointer.func */
    em[1324] = 1; em[1325] = 8; em[1326] = 1; /* 1324: pointer.struct.rand_meth_st */
    	em[1327] = 1329; em[1328] = 0; 
    em[1329] = 0; em[1330] = 48; em[1331] = 6; /* 1329: struct.rand_meth_st */
    	em[1332] = 1344; em[1333] = 0; 
    	em[1334] = 1347; em[1335] = 8; 
    	em[1336] = 1350; em[1337] = 16; 
    	em[1338] = 1353; em[1339] = 24; 
    	em[1340] = 1347; em[1341] = 32; 
    	em[1342] = 1356; em[1343] = 40; 
    em[1344] = 8884097; em[1345] = 8; em[1346] = 0; /* 1344: pointer.func */
    em[1347] = 8884097; em[1348] = 8; em[1349] = 0; /* 1347: pointer.func */
    em[1350] = 8884097; em[1351] = 8; em[1352] = 0; /* 1350: pointer.func */
    em[1353] = 8884097; em[1354] = 8; em[1355] = 0; /* 1353: pointer.func */
    em[1356] = 8884097; em[1357] = 8; em[1358] = 0; /* 1356: pointer.func */
    em[1359] = 1; em[1360] = 8; em[1361] = 1; /* 1359: pointer.struct.store_method_st */
    	em[1362] = 1364; em[1363] = 0; 
    em[1364] = 0; em[1365] = 0; em[1366] = 0; /* 1364: struct.store_method_st */
    em[1367] = 8884097; em[1368] = 8; em[1369] = 0; /* 1367: pointer.func */
    em[1370] = 8884097; em[1371] = 8; em[1372] = 0; /* 1370: pointer.func */
    em[1373] = 8884097; em[1374] = 8; em[1375] = 0; /* 1373: pointer.func */
    em[1376] = 8884097; em[1377] = 8; em[1378] = 0; /* 1376: pointer.func */
    em[1379] = 8884097; em[1380] = 8; em[1381] = 0; /* 1379: pointer.func */
    em[1382] = 8884097; em[1383] = 8; em[1384] = 0; /* 1382: pointer.func */
    em[1385] = 8884097; em[1386] = 8; em[1387] = 0; /* 1385: pointer.func */
    em[1388] = 1; em[1389] = 8; em[1390] = 1; /* 1388: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[1391] = 1393; em[1392] = 0; 
    em[1393] = 0; em[1394] = 32; em[1395] = 2; /* 1393: struct.ENGINE_CMD_DEFN_st */
    	em[1396] = 141; em[1397] = 8; 
    	em[1398] = 141; em[1399] = 16; 
    em[1400] = 0; em[1401] = 32; em[1402] = 2; /* 1400: struct.crypto_ex_data_st_fake */
    	em[1403] = 1407; em[1404] = 8; 
    	em[1405] = 358; em[1406] = 24; 
    em[1407] = 8884099; em[1408] = 8; em[1409] = 2; /* 1407: pointer_to_array_of_pointers_to_stack */
    	em[1410] = 822; em[1411] = 0; 
    	em[1412] = 355; em[1413] = 20; 
    em[1414] = 1; em[1415] = 8; em[1416] = 1; /* 1414: pointer.struct.engine_st */
    	em[1417] = 1093; em[1418] = 0; 
    em[1419] = 1; em[1420] = 8; em[1421] = 1; /* 1419: pointer.struct.bignum_st */
    	em[1422] = 879; em[1423] = 0; 
    em[1424] = 0; em[1425] = 32; em[1426] = 2; /* 1424: struct.crypto_ex_data_st_fake */
    	em[1427] = 1431; em[1428] = 8; 
    	em[1429] = 358; em[1430] = 24; 
    em[1431] = 8884099; em[1432] = 8; em[1433] = 2; /* 1431: pointer_to_array_of_pointers_to_stack */
    	em[1434] = 822; em[1435] = 0; 
    	em[1436] = 355; em[1437] = 20; 
    em[1438] = 1; em[1439] = 8; em[1440] = 1; /* 1438: pointer.struct.bn_mont_ctx_st */
    	em[1441] = 1443; em[1442] = 0; 
    em[1443] = 0; em[1444] = 96; em[1445] = 3; /* 1443: struct.bn_mont_ctx_st */
    	em[1446] = 879; em[1447] = 8; 
    	em[1448] = 879; em[1449] = 32; 
    	em[1450] = 879; em[1451] = 56; 
    em[1452] = 1; em[1453] = 8; em[1454] = 1; /* 1452: pointer.struct.bn_blinding_st */
    	em[1455] = 1457; em[1456] = 0; 
    em[1457] = 0; em[1458] = 88; em[1459] = 7; /* 1457: struct.bn_blinding_st */
    	em[1460] = 1474; em[1461] = 0; 
    	em[1462] = 1474; em[1463] = 8; 
    	em[1464] = 1474; em[1465] = 16; 
    	em[1466] = 1474; em[1467] = 24; 
    	em[1468] = 1491; em[1469] = 40; 
    	em[1470] = 1496; em[1471] = 72; 
    	em[1472] = 1510; em[1473] = 80; 
    em[1474] = 1; em[1475] = 8; em[1476] = 1; /* 1474: pointer.struct.bignum_st */
    	em[1477] = 1479; em[1478] = 0; 
    em[1479] = 0; em[1480] = 24; em[1481] = 1; /* 1479: struct.bignum_st */
    	em[1482] = 1484; em[1483] = 0; 
    em[1484] = 8884099; em[1485] = 8; em[1486] = 2; /* 1484: pointer_to_array_of_pointers_to_stack */
    	em[1487] = 784; em[1488] = 0; 
    	em[1489] = 355; em[1490] = 12; 
    em[1491] = 0; em[1492] = 16; em[1493] = 1; /* 1491: struct.crypto_threadid_st */
    	em[1494] = 822; em[1495] = 0; 
    em[1496] = 1; em[1497] = 8; em[1498] = 1; /* 1496: pointer.struct.bn_mont_ctx_st */
    	em[1499] = 1501; em[1500] = 0; 
    em[1501] = 0; em[1502] = 96; em[1503] = 3; /* 1501: struct.bn_mont_ctx_st */
    	em[1504] = 1479; em[1505] = 8; 
    	em[1506] = 1479; em[1507] = 32; 
    	em[1508] = 1479; em[1509] = 56; 
    em[1510] = 8884097; em[1511] = 8; em[1512] = 0; /* 1510: pointer.func */
    em[1513] = 1; em[1514] = 8; em[1515] = 1; /* 1513: pointer.struct.bn_mont_ctx_st */
    	em[1516] = 1518; em[1517] = 0; 
    em[1518] = 0; em[1519] = 96; em[1520] = 3; /* 1518: struct.bn_mont_ctx_st */
    	em[1521] = 1527; em[1522] = 8; 
    	em[1523] = 1527; em[1524] = 32; 
    	em[1525] = 1527; em[1526] = 56; 
    em[1527] = 0; em[1528] = 24; em[1529] = 1; /* 1527: struct.bignum_st */
    	em[1530] = 1532; em[1531] = 0; 
    em[1532] = 8884099; em[1533] = 8; em[1534] = 2; /* 1532: pointer_to_array_of_pointers_to_stack */
    	em[1535] = 784; em[1536] = 0; 
    	em[1537] = 355; em[1538] = 12; 
    em[1539] = 8884097; em[1540] = 8; em[1541] = 0; /* 1539: pointer.func */
    em[1542] = 1; em[1543] = 8; em[1544] = 1; /* 1542: pointer.struct.dh_method */
    	em[1545] = 1547; em[1546] = 0; 
    em[1547] = 0; em[1548] = 72; em[1549] = 8; /* 1547: struct.dh_method */
    	em[1550] = 141; em[1551] = 0; 
    	em[1552] = 1566; em[1553] = 8; 
    	em[1554] = 1569; em[1555] = 16; 
    	em[1556] = 1572; em[1557] = 24; 
    	em[1558] = 1566; em[1559] = 32; 
    	em[1560] = 1566; em[1561] = 40; 
    	em[1562] = 122; em[1563] = 56; 
    	em[1564] = 1575; em[1565] = 64; 
    em[1566] = 8884097; em[1567] = 8; em[1568] = 0; /* 1566: pointer.func */
    em[1569] = 8884097; em[1570] = 8; em[1571] = 0; /* 1569: pointer.func */
    em[1572] = 8884097; em[1573] = 8; em[1574] = 0; /* 1572: pointer.func */
    em[1575] = 8884097; em[1576] = 8; em[1577] = 0; /* 1575: pointer.func */
    em[1578] = 0; em[1579] = 56; em[1580] = 4; /* 1578: struct.evp_pkey_st */
    	em[1581] = 1589; em[1582] = 16; 
    	em[1583] = 1594; em[1584] = 24; 
    	em[1585] = 1599; em[1586] = 32; 
    	em[1587] = 1801; em[1588] = 48; 
    em[1589] = 1; em[1590] = 8; em[1591] = 1; /* 1589: pointer.struct.evp_pkey_asn1_method_st */
    	em[1592] = 894; em[1593] = 0; 
    em[1594] = 1; em[1595] = 8; em[1596] = 1; /* 1594: pointer.struct.engine_st */
    	em[1597] = 1093; em[1598] = 0; 
    em[1599] = 8884101; em[1600] = 8; em[1601] = 6; /* 1599: union.union_of_evp_pkey_st */
    	em[1602] = 822; em[1603] = 0; 
    	em[1604] = 1614; em[1605] = 6; 
    	em[1606] = 1619; em[1607] = 116; 
    	em[1608] = 1750; em[1609] = 28; 
    	em[1610] = 364; em[1611] = 408; 
    	em[1612] = 355; em[1613] = 0; 
    em[1614] = 1; em[1615] = 8; em[1616] = 1; /* 1614: pointer.struct.rsa_st */
    	em[1617] = 1051; em[1618] = 0; 
    em[1619] = 1; em[1620] = 8; em[1621] = 1; /* 1619: pointer.struct.dsa_st */
    	em[1622] = 1624; em[1623] = 0; 
    em[1624] = 0; em[1625] = 136; em[1626] = 11; /* 1624: struct.dsa_st */
    	em[1627] = 1649; em[1628] = 24; 
    	em[1629] = 1649; em[1630] = 32; 
    	em[1631] = 1649; em[1632] = 40; 
    	em[1633] = 1649; em[1634] = 48; 
    	em[1635] = 1649; em[1636] = 56; 
    	em[1637] = 1649; em[1638] = 64; 
    	em[1639] = 1649; em[1640] = 72; 
    	em[1641] = 1666; em[1642] = 88; 
    	em[1643] = 1680; em[1644] = 104; 
    	em[1645] = 1694; em[1646] = 120; 
    	em[1647] = 1745; em[1648] = 128; 
    em[1649] = 1; em[1650] = 8; em[1651] = 1; /* 1649: pointer.struct.bignum_st */
    	em[1652] = 1654; em[1653] = 0; 
    em[1654] = 0; em[1655] = 24; em[1656] = 1; /* 1654: struct.bignum_st */
    	em[1657] = 1659; em[1658] = 0; 
    em[1659] = 8884099; em[1660] = 8; em[1661] = 2; /* 1659: pointer_to_array_of_pointers_to_stack */
    	em[1662] = 784; em[1663] = 0; 
    	em[1664] = 355; em[1665] = 12; 
    em[1666] = 1; em[1667] = 8; em[1668] = 1; /* 1666: pointer.struct.bn_mont_ctx_st */
    	em[1669] = 1671; em[1670] = 0; 
    em[1671] = 0; em[1672] = 96; em[1673] = 3; /* 1671: struct.bn_mont_ctx_st */
    	em[1674] = 1654; em[1675] = 8; 
    	em[1676] = 1654; em[1677] = 32; 
    	em[1678] = 1654; em[1679] = 56; 
    em[1680] = 0; em[1681] = 32; em[1682] = 2; /* 1680: struct.crypto_ex_data_st_fake */
    	em[1683] = 1687; em[1684] = 8; 
    	em[1685] = 358; em[1686] = 24; 
    em[1687] = 8884099; em[1688] = 8; em[1689] = 2; /* 1687: pointer_to_array_of_pointers_to_stack */
    	em[1690] = 822; em[1691] = 0; 
    	em[1692] = 355; em[1693] = 20; 
    em[1694] = 1; em[1695] = 8; em[1696] = 1; /* 1694: pointer.struct.dsa_method */
    	em[1697] = 1699; em[1698] = 0; 
    em[1699] = 0; em[1700] = 96; em[1701] = 11; /* 1699: struct.dsa_method */
    	em[1702] = 141; em[1703] = 0; 
    	em[1704] = 1724; em[1705] = 8; 
    	em[1706] = 1727; em[1707] = 16; 
    	em[1708] = 1730; em[1709] = 24; 
    	em[1710] = 1733; em[1711] = 32; 
    	em[1712] = 1736; em[1713] = 40; 
    	em[1714] = 1739; em[1715] = 48; 
    	em[1716] = 1739; em[1717] = 56; 
    	em[1718] = 122; em[1719] = 72; 
    	em[1720] = 1742; em[1721] = 80; 
    	em[1722] = 1739; em[1723] = 88; 
    em[1724] = 8884097; em[1725] = 8; em[1726] = 0; /* 1724: pointer.func */
    em[1727] = 8884097; em[1728] = 8; em[1729] = 0; /* 1727: pointer.func */
    em[1730] = 8884097; em[1731] = 8; em[1732] = 0; /* 1730: pointer.func */
    em[1733] = 8884097; em[1734] = 8; em[1735] = 0; /* 1733: pointer.func */
    em[1736] = 8884097; em[1737] = 8; em[1738] = 0; /* 1736: pointer.func */
    em[1739] = 8884097; em[1740] = 8; em[1741] = 0; /* 1739: pointer.func */
    em[1742] = 8884097; em[1743] = 8; em[1744] = 0; /* 1742: pointer.func */
    em[1745] = 1; em[1746] = 8; em[1747] = 1; /* 1745: pointer.struct.engine_st */
    	em[1748] = 1093; em[1749] = 0; 
    em[1750] = 1; em[1751] = 8; em[1752] = 1; /* 1750: pointer.struct.dh_st */
    	em[1753] = 1755; em[1754] = 0; 
    em[1755] = 0; em[1756] = 144; em[1757] = 12; /* 1755: struct.dh_st */
    	em[1758] = 1782; em[1759] = 8; 
    	em[1760] = 1782; em[1761] = 16; 
    	em[1762] = 1782; em[1763] = 32; 
    	em[1764] = 1782; em[1765] = 40; 
    	em[1766] = 1513; em[1767] = 56; 
    	em[1768] = 1782; em[1769] = 64; 
    	em[1770] = 1782; em[1771] = 72; 
    	em[1772] = 21; em[1773] = 80; 
    	em[1774] = 1782; em[1775] = 96; 
    	em[1776] = 1787; em[1777] = 112; 
    	em[1778] = 1542; em[1779] = 128; 
    	em[1780] = 1594; em[1781] = 136; 
    em[1782] = 1; em[1783] = 8; em[1784] = 1; /* 1782: pointer.struct.bignum_st */
    	em[1785] = 1527; em[1786] = 0; 
    em[1787] = 0; em[1788] = 32; em[1789] = 2; /* 1787: struct.crypto_ex_data_st_fake */
    	em[1790] = 1794; em[1791] = 8; 
    	em[1792] = 358; em[1793] = 24; 
    em[1794] = 8884099; em[1795] = 8; em[1796] = 2; /* 1794: pointer_to_array_of_pointers_to_stack */
    	em[1797] = 822; em[1798] = 0; 
    	em[1799] = 355; em[1800] = 20; 
    em[1801] = 1; em[1802] = 8; em[1803] = 1; /* 1801: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1804] = 1806; em[1805] = 0; 
    em[1806] = 0; em[1807] = 32; em[1808] = 2; /* 1806: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1809] = 1813; em[1810] = 8; 
    	em[1811] = 358; em[1812] = 24; 
    em[1813] = 8884099; em[1814] = 8; em[1815] = 2; /* 1813: pointer_to_array_of_pointers_to_stack */
    	em[1816] = 1820; em[1817] = 0; 
    	em[1818] = 355; em[1819] = 20; 
    em[1820] = 0; em[1821] = 8; em[1822] = 1; /* 1820: pointer.X509_ATTRIBUTE */
    	em[1823] = 1825; em[1824] = 0; 
    em[1825] = 0; em[1826] = 0; em[1827] = 1; /* 1825: X509_ATTRIBUTE */
    	em[1828] = 1830; em[1829] = 0; 
    em[1830] = 0; em[1831] = 24; em[1832] = 2; /* 1830: struct.x509_attributes_st */
    	em[1833] = 127; em[1834] = 0; 
    	em[1835] = 1837; em[1836] = 16; 
    em[1837] = 0; em[1838] = 8; em[1839] = 3; /* 1837: union.unknown */
    	em[1840] = 122; em[1841] = 0; 
    	em[1842] = 331; em[1843] = 0; 
    	em[1844] = 1846; em[1845] = 0; 
    em[1846] = 1; em[1847] = 8; em[1848] = 1; /* 1846: pointer.struct.asn1_type_st */
    	em[1849] = 74; em[1850] = 0; 
    em[1851] = 8884097; em[1852] = 8; em[1853] = 0; /* 1851: pointer.func */
    em[1854] = 8884097; em[1855] = 8; em[1856] = 0; /* 1854: pointer.func */
    em[1857] = 8884097; em[1858] = 8; em[1859] = 0; /* 1857: pointer.func */
    em[1860] = 0; em[1861] = 1; em[1862] = 0; /* 1860: char */
    em[1863] = 8884097; em[1864] = 8; em[1865] = 0; /* 1863: pointer.func */
    em[1866] = 1; em[1867] = 8; em[1868] = 1; /* 1866: pointer.struct.evp_pkey_ctx_st */
    	em[1869] = 1871; em[1870] = 0; 
    em[1871] = 0; em[1872] = 80; em[1873] = 8; /* 1871: struct.evp_pkey_ctx_st */
    	em[1874] = 1890; em[1875] = 0; 
    	em[1876] = 1594; em[1877] = 8; 
    	em[1878] = 1972; em[1879] = 16; 
    	em[1880] = 1972; em[1881] = 24; 
    	em[1882] = 822; em[1883] = 40; 
    	em[1884] = 822; em[1885] = 48; 
    	em[1886] = 0; em[1887] = 56; 
    	em[1888] = 1977; em[1889] = 64; 
    em[1890] = 1; em[1891] = 8; em[1892] = 1; /* 1890: pointer.struct.evp_pkey_method_st */
    	em[1893] = 1895; em[1894] = 0; 
    em[1895] = 0; em[1896] = 208; em[1897] = 25; /* 1895: struct.evp_pkey_method_st */
    	em[1898] = 1948; em[1899] = 8; 
    	em[1900] = 1951; em[1901] = 16; 
    	em[1902] = 1954; em[1903] = 24; 
    	em[1904] = 1948; em[1905] = 32; 
    	em[1906] = 1957; em[1907] = 40; 
    	em[1908] = 1948; em[1909] = 48; 
    	em[1910] = 1957; em[1911] = 56; 
    	em[1912] = 1948; em[1913] = 64; 
    	em[1914] = 1960; em[1915] = 72; 
    	em[1916] = 1948; em[1917] = 80; 
    	em[1918] = 1963; em[1919] = 88; 
    	em[1920] = 1948; em[1921] = 96; 
    	em[1922] = 1960; em[1923] = 104; 
    	em[1924] = 1966; em[1925] = 112; 
    	em[1926] = 1851; em[1927] = 120; 
    	em[1928] = 1966; em[1929] = 128; 
    	em[1930] = 1969; em[1931] = 136; 
    	em[1932] = 1948; em[1933] = 144; 
    	em[1934] = 1960; em[1935] = 152; 
    	em[1936] = 1948; em[1937] = 160; 
    	em[1938] = 1960; em[1939] = 168; 
    	em[1940] = 1948; em[1941] = 176; 
    	em[1942] = 1863; em[1943] = 184; 
    	em[1944] = 1857; em[1945] = 192; 
    	em[1946] = 1854; em[1947] = 200; 
    em[1948] = 8884097; em[1949] = 8; em[1950] = 0; /* 1948: pointer.func */
    em[1951] = 8884097; em[1952] = 8; em[1953] = 0; /* 1951: pointer.func */
    em[1954] = 8884097; em[1955] = 8; em[1956] = 0; /* 1954: pointer.func */
    em[1957] = 8884097; em[1958] = 8; em[1959] = 0; /* 1957: pointer.func */
    em[1960] = 8884097; em[1961] = 8; em[1962] = 0; /* 1960: pointer.func */
    em[1963] = 8884097; em[1964] = 8; em[1965] = 0; /* 1963: pointer.func */
    em[1966] = 8884097; em[1967] = 8; em[1968] = 0; /* 1966: pointer.func */
    em[1969] = 8884097; em[1970] = 8; em[1971] = 0; /* 1969: pointer.func */
    em[1972] = 1; em[1973] = 8; em[1974] = 1; /* 1972: pointer.struct.evp_pkey_st */
    	em[1975] = 1578; em[1976] = 0; 
    em[1977] = 1; em[1978] = 8; em[1979] = 1; /* 1977: pointer.int */
    	em[1980] = 355; em[1981] = 0; 
    em[1982] = 8884097; em[1983] = 8; em[1984] = 0; /* 1982: pointer.func */
    em[1985] = 8884097; em[1986] = 8; em[1987] = 0; /* 1985: pointer.func */
    em[1988] = 8884097; em[1989] = 8; em[1990] = 0; /* 1988: pointer.func */
    em[1991] = 0; em[1992] = 48; em[1993] = 5; /* 1991: struct.env_md_ctx_st */
    	em[1994] = 2004; em[1995] = 0; 
    	em[1996] = 1594; em[1997] = 8; 
    	em[1998] = 822; em[1999] = 24; 
    	em[2000] = 1866; em[2001] = 32; 
    	em[2002] = 2031; em[2003] = 40; 
    em[2004] = 1; em[2005] = 8; em[2006] = 1; /* 2004: pointer.struct.env_md_st */
    	em[2007] = 2009; em[2008] = 0; 
    em[2009] = 0; em[2010] = 120; em[2011] = 8; /* 2009: struct.env_md_st */
    	em[2012] = 2028; em[2013] = 24; 
    	em[2014] = 2031; em[2015] = 32; 
    	em[2016] = 1982; em[2017] = 40; 
    	em[2018] = 1002; em[2019] = 48; 
    	em[2020] = 2028; em[2021] = 56; 
    	em[2022] = 1985; em[2023] = 64; 
    	em[2024] = 1539; em[2025] = 72; 
    	em[2026] = 1988; em[2027] = 112; 
    em[2028] = 8884097; em[2029] = 8; em[2030] = 0; /* 2028: pointer.func */
    em[2031] = 8884097; em[2032] = 8; em[2033] = 0; /* 2031: pointer.func */
    em[2034] = 0; em[2035] = 0; em[2036] = 0; /* 2034: size_t */
    em[2037] = 1; em[2038] = 8; em[2039] = 1; /* 2037: pointer.struct.env_md_ctx_st */
    	em[2040] = 1991; em[2041] = 0; 
    args_addr->arg_entity_index[0] = 2037;
    args_addr->arg_entity_index[1] = 822;
    args_addr->arg_entity_index[2] = 2034;
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

