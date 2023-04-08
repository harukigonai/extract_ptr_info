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

void bb_EVP_MD_CTX_destroy(EVP_MD_CTX * arg_a);

void EVP_MD_CTX_destroy(EVP_MD_CTX * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_MD_CTX_destroy called %lu\n", in_lib);
    if (!in_lib)
        bb_EVP_MD_CTX_destroy(arg_a);
    else {
        void (*orig_EVP_MD_CTX_destroy)(EVP_MD_CTX *);
        orig_EVP_MD_CTX_destroy = dlsym(RTLD_NEXT, "EVP_MD_CTX_destroy");
        orig_EVP_MD_CTX_destroy(arg_a);
    }
}

void bb_EVP_MD_CTX_destroy(EVP_MD_CTX * arg_a) 
{
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
    em[331] = 8884097; em[332] = 8; em[333] = 0; /* 331: pointer.func */
    em[334] = 1; em[335] = 8; em[336] = 1; /* 334: pointer.struct.ec_key_st */
    	em[337] = 339; em[338] = 0; 
    em[339] = 0; em[340] = 56; em[341] = 4; /* 339: struct.ec_key_st */
    	em[342] = 350; em[343] = 8; 
    	em[344] = 807; em[345] = 16; 
    	em[346] = 812; em[347] = 24; 
    	em[348] = 829; em[349] = 48; 
    em[350] = 1; em[351] = 8; em[352] = 1; /* 350: pointer.struct.ec_group_st */
    	em[353] = 355; em[354] = 0; 
    em[355] = 0; em[356] = 232; em[357] = 12; /* 355: struct.ec_group_st */
    	em[358] = 382; em[359] = 0; 
    	em[360] = 554; em[361] = 8; 
    	em[362] = 760; em[363] = 16; 
    	em[364] = 760; em[365] = 40; 
    	em[366] = 21; em[367] = 80; 
    	em[368] = 772; em[369] = 96; 
    	em[370] = 760; em[371] = 104; 
    	em[372] = 760; em[373] = 152; 
    	em[374] = 760; em[375] = 176; 
    	em[376] = 795; em[377] = 208; 
    	em[378] = 795; em[379] = 216; 
    	em[380] = 804; em[381] = 224; 
    em[382] = 1; em[383] = 8; em[384] = 1; /* 382: pointer.struct.ec_method_st */
    	em[385] = 387; em[386] = 0; 
    em[387] = 0; em[388] = 304; em[389] = 37; /* 387: struct.ec_method_st */
    	em[390] = 464; em[391] = 8; 
    	em[392] = 467; em[393] = 16; 
    	em[394] = 467; em[395] = 24; 
    	em[396] = 470; em[397] = 32; 
    	em[398] = 473; em[399] = 40; 
    	em[400] = 476; em[401] = 48; 
    	em[402] = 479; em[403] = 56; 
    	em[404] = 482; em[405] = 64; 
    	em[406] = 485; em[407] = 72; 
    	em[408] = 488; em[409] = 80; 
    	em[410] = 488; em[411] = 88; 
    	em[412] = 491; em[413] = 96; 
    	em[414] = 494; em[415] = 104; 
    	em[416] = 497; em[417] = 112; 
    	em[418] = 500; em[419] = 120; 
    	em[420] = 503; em[421] = 128; 
    	em[422] = 506; em[423] = 136; 
    	em[424] = 509; em[425] = 144; 
    	em[426] = 512; em[427] = 152; 
    	em[428] = 515; em[429] = 160; 
    	em[430] = 518; em[431] = 168; 
    	em[432] = 521; em[433] = 176; 
    	em[434] = 524; em[435] = 184; 
    	em[436] = 527; em[437] = 192; 
    	em[438] = 530; em[439] = 200; 
    	em[440] = 533; em[441] = 208; 
    	em[442] = 524; em[443] = 216; 
    	em[444] = 536; em[445] = 224; 
    	em[446] = 539; em[447] = 232; 
    	em[448] = 542; em[449] = 240; 
    	em[450] = 479; em[451] = 248; 
    	em[452] = 545; em[453] = 256; 
    	em[454] = 548; em[455] = 264; 
    	em[456] = 545; em[457] = 272; 
    	em[458] = 548; em[459] = 280; 
    	em[460] = 548; em[461] = 288; 
    	em[462] = 551; em[463] = 296; 
    em[464] = 8884097; em[465] = 8; em[466] = 0; /* 464: pointer.func */
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
    em[554] = 1; em[555] = 8; em[556] = 1; /* 554: pointer.struct.ec_point_st */
    	em[557] = 559; em[558] = 0; 
    em[559] = 0; em[560] = 88; em[561] = 4; /* 559: struct.ec_point_st */
    	em[562] = 570; em[563] = 0; 
    	em[564] = 742; em[565] = 8; 
    	em[566] = 742; em[567] = 32; 
    	em[568] = 742; em[569] = 56; 
    em[570] = 1; em[571] = 8; em[572] = 1; /* 570: pointer.struct.ec_method_st */
    	em[573] = 575; em[574] = 0; 
    em[575] = 0; em[576] = 304; em[577] = 37; /* 575: struct.ec_method_st */
    	em[578] = 652; em[579] = 8; 
    	em[580] = 655; em[581] = 16; 
    	em[582] = 655; em[583] = 24; 
    	em[584] = 658; em[585] = 32; 
    	em[586] = 661; em[587] = 40; 
    	em[588] = 664; em[589] = 48; 
    	em[590] = 667; em[591] = 56; 
    	em[592] = 670; em[593] = 64; 
    	em[594] = 673; em[595] = 72; 
    	em[596] = 676; em[597] = 80; 
    	em[598] = 676; em[599] = 88; 
    	em[600] = 679; em[601] = 96; 
    	em[602] = 682; em[603] = 104; 
    	em[604] = 685; em[605] = 112; 
    	em[606] = 688; em[607] = 120; 
    	em[608] = 691; em[609] = 128; 
    	em[610] = 694; em[611] = 136; 
    	em[612] = 697; em[613] = 144; 
    	em[614] = 700; em[615] = 152; 
    	em[616] = 703; em[617] = 160; 
    	em[618] = 706; em[619] = 168; 
    	em[620] = 709; em[621] = 176; 
    	em[622] = 712; em[623] = 184; 
    	em[624] = 715; em[625] = 192; 
    	em[626] = 718; em[627] = 200; 
    	em[628] = 721; em[629] = 208; 
    	em[630] = 712; em[631] = 216; 
    	em[632] = 724; em[633] = 224; 
    	em[634] = 727; em[635] = 232; 
    	em[636] = 730; em[637] = 240; 
    	em[638] = 667; em[639] = 248; 
    	em[640] = 733; em[641] = 256; 
    	em[642] = 736; em[643] = 264; 
    	em[644] = 733; em[645] = 272; 
    	em[646] = 736; em[647] = 280; 
    	em[648] = 736; em[649] = 288; 
    	em[650] = 739; em[651] = 296; 
    em[652] = 8884097; em[653] = 8; em[654] = 0; /* 652: pointer.func */
    em[655] = 8884097; em[656] = 8; em[657] = 0; /* 655: pointer.func */
    em[658] = 8884097; em[659] = 8; em[660] = 0; /* 658: pointer.func */
    em[661] = 8884097; em[662] = 8; em[663] = 0; /* 661: pointer.func */
    em[664] = 8884097; em[665] = 8; em[666] = 0; /* 664: pointer.func */
    em[667] = 8884097; em[668] = 8; em[669] = 0; /* 667: pointer.func */
    em[670] = 8884097; em[671] = 8; em[672] = 0; /* 670: pointer.func */
    em[673] = 8884097; em[674] = 8; em[675] = 0; /* 673: pointer.func */
    em[676] = 8884097; em[677] = 8; em[678] = 0; /* 676: pointer.func */
    em[679] = 8884097; em[680] = 8; em[681] = 0; /* 679: pointer.func */
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
    em[742] = 0; em[743] = 24; em[744] = 1; /* 742: struct.bignum_st */
    	em[745] = 747; em[746] = 0; 
    em[747] = 8884099; em[748] = 8; em[749] = 2; /* 747: pointer_to_array_of_pointers_to_stack */
    	em[750] = 754; em[751] = 0; 
    	em[752] = 757; em[753] = 12; 
    em[754] = 0; em[755] = 8; em[756] = 0; /* 754: long unsigned int */
    em[757] = 0; em[758] = 4; em[759] = 0; /* 757: int */
    em[760] = 0; em[761] = 24; em[762] = 1; /* 760: struct.bignum_st */
    	em[763] = 765; em[764] = 0; 
    em[765] = 8884099; em[766] = 8; em[767] = 2; /* 765: pointer_to_array_of_pointers_to_stack */
    	em[768] = 754; em[769] = 0; 
    	em[770] = 757; em[771] = 12; 
    em[772] = 1; em[773] = 8; em[774] = 1; /* 772: pointer.struct.ec_extra_data_st */
    	em[775] = 777; em[776] = 0; 
    em[777] = 0; em[778] = 40; em[779] = 5; /* 777: struct.ec_extra_data_st */
    	em[780] = 790; em[781] = 0; 
    	em[782] = 795; em[783] = 8; 
    	em[784] = 798; em[785] = 16; 
    	em[786] = 801; em[787] = 24; 
    	em[788] = 801; em[789] = 32; 
    em[790] = 1; em[791] = 8; em[792] = 1; /* 790: pointer.struct.ec_extra_data_st */
    	em[793] = 777; em[794] = 0; 
    em[795] = 0; em[796] = 8; em[797] = 0; /* 795: pointer.void */
    em[798] = 8884097; em[799] = 8; em[800] = 0; /* 798: pointer.func */
    em[801] = 8884097; em[802] = 8; em[803] = 0; /* 801: pointer.func */
    em[804] = 8884097; em[805] = 8; em[806] = 0; /* 804: pointer.func */
    em[807] = 1; em[808] = 8; em[809] = 1; /* 807: pointer.struct.ec_point_st */
    	em[810] = 559; em[811] = 0; 
    em[812] = 1; em[813] = 8; em[814] = 1; /* 812: pointer.struct.bignum_st */
    	em[815] = 817; em[816] = 0; 
    em[817] = 0; em[818] = 24; em[819] = 1; /* 817: struct.bignum_st */
    	em[820] = 822; em[821] = 0; 
    em[822] = 8884099; em[823] = 8; em[824] = 2; /* 822: pointer_to_array_of_pointers_to_stack */
    	em[825] = 754; em[826] = 0; 
    	em[827] = 757; em[828] = 12; 
    em[829] = 1; em[830] = 8; em[831] = 1; /* 829: pointer.struct.ec_extra_data_st */
    	em[832] = 834; em[833] = 0; 
    em[834] = 0; em[835] = 40; em[836] = 5; /* 834: struct.ec_extra_data_st */
    	em[837] = 847; em[838] = 0; 
    	em[839] = 795; em[840] = 8; 
    	em[841] = 798; em[842] = 16; 
    	em[843] = 801; em[844] = 24; 
    	em[845] = 801; em[846] = 32; 
    em[847] = 1; em[848] = 8; em[849] = 1; /* 847: pointer.struct.ec_extra_data_st */
    	em[850] = 834; em[851] = 0; 
    em[852] = 0; em[853] = 24; em[854] = 1; /* 852: struct.bignum_st */
    	em[855] = 857; em[856] = 0; 
    em[857] = 8884099; em[858] = 8; em[859] = 2; /* 857: pointer_to_array_of_pointers_to_stack */
    	em[860] = 754; em[861] = 0; 
    	em[862] = 757; em[863] = 12; 
    em[864] = 8884097; em[865] = 8; em[866] = 0; /* 864: pointer.func */
    em[867] = 0; em[868] = 208; em[869] = 24; /* 867: struct.evp_pkey_asn1_method_st */
    	em[870] = 122; em[871] = 16; 
    	em[872] = 122; em[873] = 24; 
    	em[874] = 918; em[875] = 32; 
    	em[876] = 921; em[877] = 40; 
    	em[878] = 924; em[879] = 48; 
    	em[880] = 927; em[881] = 56; 
    	em[882] = 930; em[883] = 64; 
    	em[884] = 933; em[885] = 72; 
    	em[886] = 927; em[887] = 80; 
    	em[888] = 936; em[889] = 88; 
    	em[890] = 936; em[891] = 96; 
    	em[892] = 939; em[893] = 104; 
    	em[894] = 942; em[895] = 112; 
    	em[896] = 936; em[897] = 120; 
    	em[898] = 864; em[899] = 128; 
    	em[900] = 924; em[901] = 136; 
    	em[902] = 927; em[903] = 144; 
    	em[904] = 945; em[905] = 152; 
    	em[906] = 948; em[907] = 160; 
    	em[908] = 951; em[909] = 168; 
    	em[910] = 939; em[911] = 176; 
    	em[912] = 942; em[913] = 184; 
    	em[914] = 954; em[915] = 192; 
    	em[916] = 957; em[917] = 200; 
    em[918] = 8884097; em[919] = 8; em[920] = 0; /* 918: pointer.func */
    em[921] = 8884097; em[922] = 8; em[923] = 0; /* 921: pointer.func */
    em[924] = 8884097; em[925] = 8; em[926] = 0; /* 924: pointer.func */
    em[927] = 8884097; em[928] = 8; em[929] = 0; /* 927: pointer.func */
    em[930] = 8884097; em[931] = 8; em[932] = 0; /* 930: pointer.func */
    em[933] = 8884097; em[934] = 8; em[935] = 0; /* 933: pointer.func */
    em[936] = 8884097; em[937] = 8; em[938] = 0; /* 936: pointer.func */
    em[939] = 8884097; em[940] = 8; em[941] = 0; /* 939: pointer.func */
    em[942] = 8884097; em[943] = 8; em[944] = 0; /* 942: pointer.func */
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
    em[978] = 0; em[979] = 112; em[980] = 13; /* 978: struct.rsa_meth_st */
    	em[981] = 141; em[982] = 0; 
    	em[983] = 972; em[984] = 8; 
    	em[985] = 972; em[986] = 16; 
    	em[987] = 972; em[988] = 24; 
    	em[989] = 972; em[990] = 32; 
    	em[991] = 1007; em[992] = 40; 
    	em[993] = 966; em[994] = 48; 
    	em[995] = 960; em[996] = 56; 
    	em[997] = 960; em[998] = 64; 
    	em[999] = 122; em[1000] = 80; 
    	em[1001] = 1010; em[1002] = 88; 
    	em[1003] = 1013; em[1004] = 96; 
    	em[1005] = 331; em[1006] = 104; 
    em[1007] = 8884097; em[1008] = 8; em[1009] = 0; /* 1007: pointer.func */
    em[1010] = 8884097; em[1011] = 8; em[1012] = 0; /* 1010: pointer.func */
    em[1013] = 8884097; em[1014] = 8; em[1015] = 0; /* 1013: pointer.func */
    em[1016] = 1; em[1017] = 8; em[1018] = 1; /* 1016: pointer.struct.rsa_meth_st */
    	em[1019] = 978; em[1020] = 0; 
    em[1021] = 8884097; em[1022] = 8; em[1023] = 0; /* 1021: pointer.func */
    em[1024] = 0; em[1025] = 168; em[1026] = 17; /* 1024: struct.rsa_st */
    	em[1027] = 1016; em[1028] = 16; 
    	em[1029] = 1061; em[1030] = 24; 
    	em[1031] = 1395; em[1032] = 32; 
    	em[1033] = 1395; em[1034] = 40; 
    	em[1035] = 1395; em[1036] = 48; 
    	em[1037] = 1395; em[1038] = 56; 
    	em[1039] = 1395; em[1040] = 64; 
    	em[1041] = 1395; em[1042] = 72; 
    	em[1043] = 1395; em[1044] = 80; 
    	em[1045] = 1395; em[1046] = 88; 
    	em[1047] = 1400; em[1048] = 96; 
    	em[1049] = 1414; em[1050] = 120; 
    	em[1051] = 1414; em[1052] = 128; 
    	em[1053] = 1414; em[1054] = 136; 
    	em[1055] = 122; em[1056] = 144; 
    	em[1057] = 1428; em[1058] = 152; 
    	em[1059] = 1428; em[1060] = 160; 
    em[1061] = 1; em[1062] = 8; em[1063] = 1; /* 1061: pointer.struct.engine_st */
    	em[1064] = 1066; em[1065] = 0; 
    em[1066] = 0; em[1067] = 216; em[1068] = 24; /* 1066: struct.engine_st */
    	em[1069] = 141; em[1070] = 0; 
    	em[1071] = 141; em[1072] = 8; 
    	em[1073] = 1117; em[1074] = 16; 
    	em[1075] = 1169; em[1076] = 24; 
    	em[1077] = 1217; em[1078] = 32; 
    	em[1079] = 1253; em[1080] = 40; 
    	em[1081] = 1270; em[1082] = 48; 
    	em[1083] = 1297; em[1084] = 56; 
    	em[1085] = 1332; em[1086] = 64; 
    	em[1087] = 1340; em[1088] = 72; 
    	em[1089] = 1343; em[1090] = 80; 
    	em[1091] = 1346; em[1092] = 88; 
    	em[1093] = 1349; em[1094] = 96; 
    	em[1095] = 1352; em[1096] = 104; 
    	em[1097] = 1352; em[1098] = 112; 
    	em[1099] = 1352; em[1100] = 120; 
    	em[1101] = 1355; em[1102] = 128; 
    	em[1103] = 1021; em[1104] = 136; 
    	em[1105] = 1021; em[1106] = 144; 
    	em[1107] = 1358; em[1108] = 152; 
    	em[1109] = 1361; em[1110] = 160; 
    	em[1111] = 1373; em[1112] = 184; 
    	em[1113] = 1390; em[1114] = 200; 
    	em[1115] = 1390; em[1116] = 208; 
    em[1117] = 1; em[1118] = 8; em[1119] = 1; /* 1117: pointer.struct.rsa_meth_st */
    	em[1120] = 1122; em[1121] = 0; 
    em[1122] = 0; em[1123] = 112; em[1124] = 13; /* 1122: struct.rsa_meth_st */
    	em[1125] = 141; em[1126] = 0; 
    	em[1127] = 963; em[1128] = 8; 
    	em[1129] = 963; em[1130] = 16; 
    	em[1131] = 963; em[1132] = 24; 
    	em[1133] = 963; em[1134] = 32; 
    	em[1135] = 1151; em[1136] = 40; 
    	em[1137] = 1154; em[1138] = 48; 
    	em[1139] = 1157; em[1140] = 56; 
    	em[1141] = 1157; em[1142] = 64; 
    	em[1143] = 122; em[1144] = 80; 
    	em[1145] = 1160; em[1146] = 88; 
    	em[1147] = 1163; em[1148] = 96; 
    	em[1149] = 1166; em[1150] = 104; 
    em[1151] = 8884097; em[1152] = 8; em[1153] = 0; /* 1151: pointer.func */
    em[1154] = 8884097; em[1155] = 8; em[1156] = 0; /* 1154: pointer.func */
    em[1157] = 8884097; em[1158] = 8; em[1159] = 0; /* 1157: pointer.func */
    em[1160] = 8884097; em[1161] = 8; em[1162] = 0; /* 1160: pointer.func */
    em[1163] = 8884097; em[1164] = 8; em[1165] = 0; /* 1163: pointer.func */
    em[1166] = 8884097; em[1167] = 8; em[1168] = 0; /* 1166: pointer.func */
    em[1169] = 1; em[1170] = 8; em[1171] = 1; /* 1169: pointer.struct.dsa_method */
    	em[1172] = 1174; em[1173] = 0; 
    em[1174] = 0; em[1175] = 96; em[1176] = 11; /* 1174: struct.dsa_method */
    	em[1177] = 141; em[1178] = 0; 
    	em[1179] = 969; em[1180] = 8; 
    	em[1181] = 1199; em[1182] = 16; 
    	em[1183] = 1202; em[1184] = 24; 
    	em[1185] = 1205; em[1186] = 32; 
    	em[1187] = 1208; em[1188] = 40; 
    	em[1189] = 1211; em[1190] = 48; 
    	em[1191] = 1211; em[1192] = 56; 
    	em[1193] = 122; em[1194] = 72; 
    	em[1195] = 1214; em[1196] = 80; 
    	em[1197] = 1211; em[1198] = 88; 
    em[1199] = 8884097; em[1200] = 8; em[1201] = 0; /* 1199: pointer.func */
    em[1202] = 8884097; em[1203] = 8; em[1204] = 0; /* 1202: pointer.func */
    em[1205] = 8884097; em[1206] = 8; em[1207] = 0; /* 1205: pointer.func */
    em[1208] = 8884097; em[1209] = 8; em[1210] = 0; /* 1208: pointer.func */
    em[1211] = 8884097; em[1212] = 8; em[1213] = 0; /* 1211: pointer.func */
    em[1214] = 8884097; em[1215] = 8; em[1216] = 0; /* 1214: pointer.func */
    em[1217] = 1; em[1218] = 8; em[1219] = 1; /* 1217: pointer.struct.dh_method */
    	em[1220] = 1222; em[1221] = 0; 
    em[1222] = 0; em[1223] = 72; em[1224] = 8; /* 1222: struct.dh_method */
    	em[1225] = 141; em[1226] = 0; 
    	em[1227] = 1241; em[1228] = 8; 
    	em[1229] = 1244; em[1230] = 16; 
    	em[1231] = 1247; em[1232] = 24; 
    	em[1233] = 1241; em[1234] = 32; 
    	em[1235] = 1241; em[1236] = 40; 
    	em[1237] = 122; em[1238] = 56; 
    	em[1239] = 1250; em[1240] = 64; 
    em[1241] = 8884097; em[1242] = 8; em[1243] = 0; /* 1241: pointer.func */
    em[1244] = 8884097; em[1245] = 8; em[1246] = 0; /* 1244: pointer.func */
    em[1247] = 8884097; em[1248] = 8; em[1249] = 0; /* 1247: pointer.func */
    em[1250] = 8884097; em[1251] = 8; em[1252] = 0; /* 1250: pointer.func */
    em[1253] = 1; em[1254] = 8; em[1255] = 1; /* 1253: pointer.struct.ecdh_method */
    	em[1256] = 1258; em[1257] = 0; 
    em[1258] = 0; em[1259] = 32; em[1260] = 3; /* 1258: struct.ecdh_method */
    	em[1261] = 141; em[1262] = 0; 
    	em[1263] = 1267; em[1264] = 8; 
    	em[1265] = 122; em[1266] = 24; 
    em[1267] = 8884097; em[1268] = 8; em[1269] = 0; /* 1267: pointer.func */
    em[1270] = 1; em[1271] = 8; em[1272] = 1; /* 1270: pointer.struct.ecdsa_method */
    	em[1273] = 1275; em[1274] = 0; 
    em[1275] = 0; em[1276] = 48; em[1277] = 5; /* 1275: struct.ecdsa_method */
    	em[1278] = 141; em[1279] = 0; 
    	em[1280] = 1288; em[1281] = 8; 
    	em[1282] = 1291; em[1283] = 16; 
    	em[1284] = 1294; em[1285] = 24; 
    	em[1286] = 122; em[1287] = 40; 
    em[1288] = 8884097; em[1289] = 8; em[1290] = 0; /* 1288: pointer.func */
    em[1291] = 8884097; em[1292] = 8; em[1293] = 0; /* 1291: pointer.func */
    em[1294] = 8884097; em[1295] = 8; em[1296] = 0; /* 1294: pointer.func */
    em[1297] = 1; em[1298] = 8; em[1299] = 1; /* 1297: pointer.struct.rand_meth_st */
    	em[1300] = 1302; em[1301] = 0; 
    em[1302] = 0; em[1303] = 48; em[1304] = 6; /* 1302: struct.rand_meth_st */
    	em[1305] = 1317; em[1306] = 0; 
    	em[1307] = 1320; em[1308] = 8; 
    	em[1309] = 1323; em[1310] = 16; 
    	em[1311] = 1326; em[1312] = 24; 
    	em[1313] = 1320; em[1314] = 32; 
    	em[1315] = 1329; em[1316] = 40; 
    em[1317] = 8884097; em[1318] = 8; em[1319] = 0; /* 1317: pointer.func */
    em[1320] = 8884097; em[1321] = 8; em[1322] = 0; /* 1320: pointer.func */
    em[1323] = 8884097; em[1324] = 8; em[1325] = 0; /* 1323: pointer.func */
    em[1326] = 8884097; em[1327] = 8; em[1328] = 0; /* 1326: pointer.func */
    em[1329] = 8884097; em[1330] = 8; em[1331] = 0; /* 1329: pointer.func */
    em[1332] = 1; em[1333] = 8; em[1334] = 1; /* 1332: pointer.struct.store_method_st */
    	em[1335] = 1337; em[1336] = 0; 
    em[1337] = 0; em[1338] = 0; em[1339] = 0; /* 1337: struct.store_method_st */
    em[1340] = 8884097; em[1341] = 8; em[1342] = 0; /* 1340: pointer.func */
    em[1343] = 8884097; em[1344] = 8; em[1345] = 0; /* 1343: pointer.func */
    em[1346] = 8884097; em[1347] = 8; em[1348] = 0; /* 1346: pointer.func */
    em[1349] = 8884097; em[1350] = 8; em[1351] = 0; /* 1349: pointer.func */
    em[1352] = 8884097; em[1353] = 8; em[1354] = 0; /* 1352: pointer.func */
    em[1355] = 8884097; em[1356] = 8; em[1357] = 0; /* 1355: pointer.func */
    em[1358] = 8884097; em[1359] = 8; em[1360] = 0; /* 1358: pointer.func */
    em[1361] = 1; em[1362] = 8; em[1363] = 1; /* 1361: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[1364] = 1366; em[1365] = 0; 
    em[1366] = 0; em[1367] = 32; em[1368] = 2; /* 1366: struct.ENGINE_CMD_DEFN_st */
    	em[1369] = 141; em[1370] = 8; 
    	em[1371] = 141; em[1372] = 16; 
    em[1373] = 0; em[1374] = 32; em[1375] = 2; /* 1373: struct.crypto_ex_data_st_fake */
    	em[1376] = 1380; em[1377] = 8; 
    	em[1378] = 1387; em[1379] = 24; 
    em[1380] = 8884099; em[1381] = 8; em[1382] = 2; /* 1380: pointer_to_array_of_pointers_to_stack */
    	em[1383] = 795; em[1384] = 0; 
    	em[1385] = 757; em[1386] = 20; 
    em[1387] = 8884097; em[1388] = 8; em[1389] = 0; /* 1387: pointer.func */
    em[1390] = 1; em[1391] = 8; em[1392] = 1; /* 1390: pointer.struct.engine_st */
    	em[1393] = 1066; em[1394] = 0; 
    em[1395] = 1; em[1396] = 8; em[1397] = 1; /* 1395: pointer.struct.bignum_st */
    	em[1398] = 852; em[1399] = 0; 
    em[1400] = 0; em[1401] = 32; em[1402] = 2; /* 1400: struct.crypto_ex_data_st_fake */
    	em[1403] = 1407; em[1404] = 8; 
    	em[1405] = 1387; em[1406] = 24; 
    em[1407] = 8884099; em[1408] = 8; em[1409] = 2; /* 1407: pointer_to_array_of_pointers_to_stack */
    	em[1410] = 795; em[1411] = 0; 
    	em[1412] = 757; em[1413] = 20; 
    em[1414] = 1; em[1415] = 8; em[1416] = 1; /* 1414: pointer.struct.bn_mont_ctx_st */
    	em[1417] = 1419; em[1418] = 0; 
    em[1419] = 0; em[1420] = 96; em[1421] = 3; /* 1419: struct.bn_mont_ctx_st */
    	em[1422] = 852; em[1423] = 8; 
    	em[1424] = 852; em[1425] = 32; 
    	em[1426] = 852; em[1427] = 56; 
    em[1428] = 1; em[1429] = 8; em[1430] = 1; /* 1428: pointer.struct.bn_blinding_st */
    	em[1431] = 1433; em[1432] = 0; 
    em[1433] = 0; em[1434] = 88; em[1435] = 7; /* 1433: struct.bn_blinding_st */
    	em[1436] = 1450; em[1437] = 0; 
    	em[1438] = 1450; em[1439] = 8; 
    	em[1440] = 1450; em[1441] = 16; 
    	em[1442] = 1450; em[1443] = 24; 
    	em[1444] = 1467; em[1445] = 40; 
    	em[1446] = 1472; em[1447] = 72; 
    	em[1448] = 1486; em[1449] = 80; 
    em[1450] = 1; em[1451] = 8; em[1452] = 1; /* 1450: pointer.struct.bignum_st */
    	em[1453] = 1455; em[1454] = 0; 
    em[1455] = 0; em[1456] = 24; em[1457] = 1; /* 1455: struct.bignum_st */
    	em[1458] = 1460; em[1459] = 0; 
    em[1460] = 8884099; em[1461] = 8; em[1462] = 2; /* 1460: pointer_to_array_of_pointers_to_stack */
    	em[1463] = 754; em[1464] = 0; 
    	em[1465] = 757; em[1466] = 12; 
    em[1467] = 0; em[1468] = 16; em[1469] = 1; /* 1467: struct.crypto_threadid_st */
    	em[1470] = 795; em[1471] = 0; 
    em[1472] = 1; em[1473] = 8; em[1474] = 1; /* 1472: pointer.struct.bn_mont_ctx_st */
    	em[1475] = 1477; em[1476] = 0; 
    em[1477] = 0; em[1478] = 96; em[1479] = 3; /* 1477: struct.bn_mont_ctx_st */
    	em[1480] = 1455; em[1481] = 8; 
    	em[1482] = 1455; em[1483] = 32; 
    	em[1484] = 1455; em[1485] = 56; 
    em[1486] = 8884097; em[1487] = 8; em[1488] = 0; /* 1486: pointer.func */
    em[1489] = 1; em[1490] = 8; em[1491] = 1; /* 1489: pointer.struct.bn_mont_ctx_st */
    	em[1492] = 1494; em[1493] = 0; 
    em[1494] = 0; em[1495] = 96; em[1496] = 3; /* 1494: struct.bn_mont_ctx_st */
    	em[1497] = 1503; em[1498] = 8; 
    	em[1499] = 1503; em[1500] = 32; 
    	em[1501] = 1503; em[1502] = 56; 
    em[1503] = 0; em[1504] = 24; em[1505] = 1; /* 1503: struct.bignum_st */
    	em[1506] = 1508; em[1507] = 0; 
    em[1508] = 8884099; em[1509] = 8; em[1510] = 2; /* 1508: pointer_to_array_of_pointers_to_stack */
    	em[1511] = 754; em[1512] = 0; 
    	em[1513] = 757; em[1514] = 12; 
    em[1515] = 8884097; em[1516] = 8; em[1517] = 0; /* 1515: pointer.func */
    em[1518] = 1; em[1519] = 8; em[1520] = 1; /* 1518: pointer.struct.dh_method */
    	em[1521] = 1523; em[1522] = 0; 
    em[1523] = 0; em[1524] = 72; em[1525] = 8; /* 1523: struct.dh_method */
    	em[1526] = 141; em[1527] = 0; 
    	em[1528] = 1542; em[1529] = 8; 
    	em[1530] = 1545; em[1531] = 16; 
    	em[1532] = 1548; em[1533] = 24; 
    	em[1534] = 1542; em[1535] = 32; 
    	em[1536] = 1542; em[1537] = 40; 
    	em[1538] = 122; em[1539] = 56; 
    	em[1540] = 1551; em[1541] = 64; 
    em[1542] = 8884097; em[1543] = 8; em[1544] = 0; /* 1542: pointer.func */
    em[1545] = 8884097; em[1546] = 8; em[1547] = 0; /* 1545: pointer.func */
    em[1548] = 8884097; em[1549] = 8; em[1550] = 0; /* 1548: pointer.func */
    em[1551] = 8884097; em[1552] = 8; em[1553] = 0; /* 1551: pointer.func */
    em[1554] = 0; em[1555] = 56; em[1556] = 4; /* 1554: struct.evp_pkey_st */
    	em[1557] = 1565; em[1558] = 16; 
    	em[1559] = 1570; em[1560] = 24; 
    	em[1561] = 1575; em[1562] = 32; 
    	em[1563] = 1777; em[1564] = 48; 
    em[1565] = 1; em[1566] = 8; em[1567] = 1; /* 1565: pointer.struct.evp_pkey_asn1_method_st */
    	em[1568] = 867; em[1569] = 0; 
    em[1570] = 1; em[1571] = 8; em[1572] = 1; /* 1570: pointer.struct.engine_st */
    	em[1573] = 1066; em[1574] = 0; 
    em[1575] = 8884101; em[1576] = 8; em[1577] = 6; /* 1575: union.union_of_evp_pkey_st */
    	em[1578] = 795; em[1579] = 0; 
    	em[1580] = 1590; em[1581] = 6; 
    	em[1582] = 1595; em[1583] = 116; 
    	em[1584] = 1726; em[1585] = 28; 
    	em[1586] = 334; em[1587] = 408; 
    	em[1588] = 757; em[1589] = 0; 
    em[1590] = 1; em[1591] = 8; em[1592] = 1; /* 1590: pointer.struct.rsa_st */
    	em[1593] = 1024; em[1594] = 0; 
    em[1595] = 1; em[1596] = 8; em[1597] = 1; /* 1595: pointer.struct.dsa_st */
    	em[1598] = 1600; em[1599] = 0; 
    em[1600] = 0; em[1601] = 136; em[1602] = 11; /* 1600: struct.dsa_st */
    	em[1603] = 1625; em[1604] = 24; 
    	em[1605] = 1625; em[1606] = 32; 
    	em[1607] = 1625; em[1608] = 40; 
    	em[1609] = 1625; em[1610] = 48; 
    	em[1611] = 1625; em[1612] = 56; 
    	em[1613] = 1625; em[1614] = 64; 
    	em[1615] = 1625; em[1616] = 72; 
    	em[1617] = 1642; em[1618] = 88; 
    	em[1619] = 1656; em[1620] = 104; 
    	em[1621] = 1670; em[1622] = 120; 
    	em[1623] = 1721; em[1624] = 128; 
    em[1625] = 1; em[1626] = 8; em[1627] = 1; /* 1625: pointer.struct.bignum_st */
    	em[1628] = 1630; em[1629] = 0; 
    em[1630] = 0; em[1631] = 24; em[1632] = 1; /* 1630: struct.bignum_st */
    	em[1633] = 1635; em[1634] = 0; 
    em[1635] = 8884099; em[1636] = 8; em[1637] = 2; /* 1635: pointer_to_array_of_pointers_to_stack */
    	em[1638] = 754; em[1639] = 0; 
    	em[1640] = 757; em[1641] = 12; 
    em[1642] = 1; em[1643] = 8; em[1644] = 1; /* 1642: pointer.struct.bn_mont_ctx_st */
    	em[1645] = 1647; em[1646] = 0; 
    em[1647] = 0; em[1648] = 96; em[1649] = 3; /* 1647: struct.bn_mont_ctx_st */
    	em[1650] = 1630; em[1651] = 8; 
    	em[1652] = 1630; em[1653] = 32; 
    	em[1654] = 1630; em[1655] = 56; 
    em[1656] = 0; em[1657] = 32; em[1658] = 2; /* 1656: struct.crypto_ex_data_st_fake */
    	em[1659] = 1663; em[1660] = 8; 
    	em[1661] = 1387; em[1662] = 24; 
    em[1663] = 8884099; em[1664] = 8; em[1665] = 2; /* 1663: pointer_to_array_of_pointers_to_stack */
    	em[1666] = 795; em[1667] = 0; 
    	em[1668] = 757; em[1669] = 20; 
    em[1670] = 1; em[1671] = 8; em[1672] = 1; /* 1670: pointer.struct.dsa_method */
    	em[1673] = 1675; em[1674] = 0; 
    em[1675] = 0; em[1676] = 96; em[1677] = 11; /* 1675: struct.dsa_method */
    	em[1678] = 141; em[1679] = 0; 
    	em[1680] = 1700; em[1681] = 8; 
    	em[1682] = 1703; em[1683] = 16; 
    	em[1684] = 1706; em[1685] = 24; 
    	em[1686] = 1709; em[1687] = 32; 
    	em[1688] = 1712; em[1689] = 40; 
    	em[1690] = 1715; em[1691] = 48; 
    	em[1692] = 1715; em[1693] = 56; 
    	em[1694] = 122; em[1695] = 72; 
    	em[1696] = 1718; em[1697] = 80; 
    	em[1698] = 1715; em[1699] = 88; 
    em[1700] = 8884097; em[1701] = 8; em[1702] = 0; /* 1700: pointer.func */
    em[1703] = 8884097; em[1704] = 8; em[1705] = 0; /* 1703: pointer.func */
    em[1706] = 8884097; em[1707] = 8; em[1708] = 0; /* 1706: pointer.func */
    em[1709] = 8884097; em[1710] = 8; em[1711] = 0; /* 1709: pointer.func */
    em[1712] = 8884097; em[1713] = 8; em[1714] = 0; /* 1712: pointer.func */
    em[1715] = 8884097; em[1716] = 8; em[1717] = 0; /* 1715: pointer.func */
    em[1718] = 8884097; em[1719] = 8; em[1720] = 0; /* 1718: pointer.func */
    em[1721] = 1; em[1722] = 8; em[1723] = 1; /* 1721: pointer.struct.engine_st */
    	em[1724] = 1066; em[1725] = 0; 
    em[1726] = 1; em[1727] = 8; em[1728] = 1; /* 1726: pointer.struct.dh_st */
    	em[1729] = 1731; em[1730] = 0; 
    em[1731] = 0; em[1732] = 144; em[1733] = 12; /* 1731: struct.dh_st */
    	em[1734] = 1758; em[1735] = 8; 
    	em[1736] = 1758; em[1737] = 16; 
    	em[1738] = 1758; em[1739] = 32; 
    	em[1740] = 1758; em[1741] = 40; 
    	em[1742] = 1489; em[1743] = 56; 
    	em[1744] = 1758; em[1745] = 64; 
    	em[1746] = 1758; em[1747] = 72; 
    	em[1748] = 21; em[1749] = 80; 
    	em[1750] = 1758; em[1751] = 96; 
    	em[1752] = 1763; em[1753] = 112; 
    	em[1754] = 1518; em[1755] = 128; 
    	em[1756] = 1570; em[1757] = 136; 
    em[1758] = 1; em[1759] = 8; em[1760] = 1; /* 1758: pointer.struct.bignum_st */
    	em[1761] = 1503; em[1762] = 0; 
    em[1763] = 0; em[1764] = 32; em[1765] = 2; /* 1763: struct.crypto_ex_data_st_fake */
    	em[1766] = 1770; em[1767] = 8; 
    	em[1768] = 1387; em[1769] = 24; 
    em[1770] = 8884099; em[1771] = 8; em[1772] = 2; /* 1770: pointer_to_array_of_pointers_to_stack */
    	em[1773] = 795; em[1774] = 0; 
    	em[1775] = 757; em[1776] = 20; 
    em[1777] = 1; em[1778] = 8; em[1779] = 1; /* 1777: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1780] = 1782; em[1781] = 0; 
    em[1782] = 0; em[1783] = 32; em[1784] = 2; /* 1782: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1785] = 1789; em[1786] = 8; 
    	em[1787] = 1387; em[1788] = 24; 
    em[1789] = 8884099; em[1790] = 8; em[1791] = 2; /* 1789: pointer_to_array_of_pointers_to_stack */
    	em[1792] = 1796; em[1793] = 0; 
    	em[1794] = 757; em[1795] = 20; 
    em[1796] = 0; em[1797] = 8; em[1798] = 1; /* 1796: pointer.X509_ATTRIBUTE */
    	em[1799] = 1801; em[1800] = 0; 
    em[1801] = 0; em[1802] = 0; em[1803] = 1; /* 1801: X509_ATTRIBUTE */
    	em[1804] = 1806; em[1805] = 0; 
    em[1806] = 0; em[1807] = 24; em[1808] = 2; /* 1806: struct.x509_attributes_st */
    	em[1809] = 127; em[1810] = 0; 
    	em[1811] = 1813; em[1812] = 16; 
    em[1813] = 0; em[1814] = 8; em[1815] = 3; /* 1813: union.unknown */
    	em[1816] = 122; em[1817] = 0; 
    	em[1818] = 1822; em[1819] = 0; 
    	em[1820] = 1846; em[1821] = 0; 
    em[1822] = 1; em[1823] = 8; em[1824] = 1; /* 1822: pointer.struct.stack_st_ASN1_TYPE */
    	em[1825] = 1827; em[1826] = 0; 
    em[1827] = 0; em[1828] = 32; em[1829] = 2; /* 1827: struct.stack_st_fake_ASN1_TYPE */
    	em[1830] = 1834; em[1831] = 8; 
    	em[1832] = 1387; em[1833] = 24; 
    em[1834] = 8884099; em[1835] = 8; em[1836] = 2; /* 1834: pointer_to_array_of_pointers_to_stack */
    	em[1837] = 1841; em[1838] = 0; 
    	em[1839] = 757; em[1840] = 20; 
    em[1841] = 0; em[1842] = 8; em[1843] = 1; /* 1841: pointer.ASN1_TYPE */
    	em[1844] = 243; em[1845] = 0; 
    em[1846] = 1; em[1847] = 8; em[1848] = 1; /* 1846: pointer.struct.asn1_type_st */
    	em[1849] = 74; em[1850] = 0; 
    em[1851] = 8884097; em[1852] = 8; em[1853] = 0; /* 1851: pointer.func */
    em[1854] = 8884097; em[1855] = 8; em[1856] = 0; /* 1854: pointer.func */
    em[1857] = 8884097; em[1858] = 8; em[1859] = 0; /* 1857: pointer.func */
    em[1860] = 0; em[1861] = 1; em[1862] = 0; /* 1860: char */
    em[1863] = 8884097; em[1864] = 8; em[1865] = 0; /* 1863: pointer.func */
    em[1866] = 1; em[1867] = 8; em[1868] = 1; /* 1866: pointer.struct.evp_pkey_st */
    	em[1869] = 1554; em[1870] = 0; 
    em[1871] = 1; em[1872] = 8; em[1873] = 1; /* 1871: pointer.struct.evp_pkey_ctx_st */
    	em[1874] = 1876; em[1875] = 0; 
    em[1876] = 0; em[1877] = 80; em[1878] = 8; /* 1876: struct.evp_pkey_ctx_st */
    	em[1879] = 1895; em[1880] = 0; 
    	em[1881] = 1570; em[1882] = 8; 
    	em[1883] = 1866; em[1884] = 16; 
    	em[1885] = 1866; em[1886] = 24; 
    	em[1887] = 795; em[1888] = 40; 
    	em[1889] = 795; em[1890] = 48; 
    	em[1891] = 0; em[1892] = 56; 
    	em[1893] = 1977; em[1894] = 64; 
    em[1895] = 1; em[1896] = 8; em[1897] = 1; /* 1895: pointer.struct.evp_pkey_method_st */
    	em[1898] = 1900; em[1899] = 0; 
    em[1900] = 0; em[1901] = 208; em[1902] = 25; /* 1900: struct.evp_pkey_method_st */
    	em[1903] = 1953; em[1904] = 8; 
    	em[1905] = 1956; em[1906] = 16; 
    	em[1907] = 1959; em[1908] = 24; 
    	em[1909] = 1953; em[1910] = 32; 
    	em[1911] = 1962; em[1912] = 40; 
    	em[1913] = 1953; em[1914] = 48; 
    	em[1915] = 1962; em[1916] = 56; 
    	em[1917] = 1953; em[1918] = 64; 
    	em[1919] = 1965; em[1920] = 72; 
    	em[1921] = 1953; em[1922] = 80; 
    	em[1923] = 1968; em[1924] = 88; 
    	em[1925] = 1953; em[1926] = 96; 
    	em[1927] = 1965; em[1928] = 104; 
    	em[1929] = 1971; em[1930] = 112; 
    	em[1931] = 1851; em[1932] = 120; 
    	em[1933] = 1971; em[1934] = 128; 
    	em[1935] = 1974; em[1936] = 136; 
    	em[1937] = 1953; em[1938] = 144; 
    	em[1939] = 1965; em[1940] = 152; 
    	em[1941] = 1953; em[1942] = 160; 
    	em[1943] = 1965; em[1944] = 168; 
    	em[1945] = 1953; em[1946] = 176; 
    	em[1947] = 1863; em[1948] = 184; 
    	em[1949] = 1857; em[1950] = 192; 
    	em[1951] = 1854; em[1952] = 200; 
    em[1953] = 8884097; em[1954] = 8; em[1955] = 0; /* 1953: pointer.func */
    em[1956] = 8884097; em[1957] = 8; em[1958] = 0; /* 1956: pointer.func */
    em[1959] = 8884097; em[1960] = 8; em[1961] = 0; /* 1959: pointer.func */
    em[1962] = 8884097; em[1963] = 8; em[1964] = 0; /* 1962: pointer.func */
    em[1965] = 8884097; em[1966] = 8; em[1967] = 0; /* 1965: pointer.func */
    em[1968] = 8884097; em[1969] = 8; em[1970] = 0; /* 1968: pointer.func */
    em[1971] = 8884097; em[1972] = 8; em[1973] = 0; /* 1971: pointer.func */
    em[1974] = 8884097; em[1975] = 8; em[1976] = 0; /* 1974: pointer.func */
    em[1977] = 1; em[1978] = 8; em[1979] = 1; /* 1977: pointer.int */
    	em[1980] = 757; em[1981] = 0; 
    em[1982] = 1; em[1983] = 8; em[1984] = 1; /* 1982: pointer.struct.env_md_ctx_st */
    	em[1985] = 1987; em[1986] = 0; 
    em[1987] = 0; em[1988] = 48; em[1989] = 5; /* 1987: struct.env_md_ctx_st */
    	em[1990] = 2000; em[1991] = 0; 
    	em[1992] = 1570; em[1993] = 8; 
    	em[1994] = 795; em[1995] = 24; 
    	em[1996] = 1871; em[1997] = 32; 
    	em[1998] = 2027; em[1999] = 40; 
    em[2000] = 1; em[2001] = 8; em[2002] = 1; /* 2000: pointer.struct.env_md_st */
    	em[2003] = 2005; em[2004] = 0; 
    em[2005] = 0; em[2006] = 120; em[2007] = 8; /* 2005: struct.env_md_st */
    	em[2008] = 2024; em[2009] = 24; 
    	em[2010] = 2027; em[2011] = 32; 
    	em[2012] = 2030; em[2013] = 40; 
    	em[2014] = 975; em[2015] = 48; 
    	em[2016] = 2024; em[2017] = 56; 
    	em[2018] = 2033; em[2019] = 64; 
    	em[2020] = 1515; em[2021] = 72; 
    	em[2022] = 2036; em[2023] = 112; 
    em[2024] = 8884097; em[2025] = 8; em[2026] = 0; /* 2024: pointer.func */
    em[2027] = 8884097; em[2028] = 8; em[2029] = 0; /* 2027: pointer.func */
    em[2030] = 8884097; em[2031] = 8; em[2032] = 0; /* 2030: pointer.func */
    em[2033] = 8884097; em[2034] = 8; em[2035] = 0; /* 2033: pointer.func */
    em[2036] = 8884097; em[2037] = 8; em[2038] = 0; /* 2036: pointer.func */
    args_addr->arg_entity_index[0] = 1982;
    args_addr->ret_entity_index = -1;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * new_arg_a = *((EVP_MD_CTX * *)new_args->args[0]);

    void (*orig_EVP_MD_CTX_destroy)(EVP_MD_CTX *);
    orig_EVP_MD_CTX_destroy = dlsym(RTLD_NEXT, "EVP_MD_CTX_destroy");
    (*orig_EVP_MD_CTX_destroy)(new_arg_a);

    syscall(889);

    free(args_addr);

}

