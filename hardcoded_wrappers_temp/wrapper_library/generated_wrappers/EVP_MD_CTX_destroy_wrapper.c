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
    em[82] = 1; em[83] = 8; em[84] = 1; /* 82: pointer.struct.asn1_string_st */
    	em[85] = 24; em[86] = 0; 
    em[87] = 0; em[88] = 8; em[89] = 20; /* 87: union.unknown */
    	em[90] = 130; em[91] = 0; 
    	em[92] = 82; em[93] = 0; 
    	em[94] = 135; em[95] = 0; 
    	em[96] = 159; em[97] = 0; 
    	em[98] = 77; em[99] = 0; 
    	em[100] = 72; em[101] = 0; 
    	em[102] = 67; em[103] = 0; 
    	em[104] = 62; em[105] = 0; 
    	em[106] = 57; em[107] = 0; 
    	em[108] = 52; em[109] = 0; 
    	em[110] = 47; em[111] = 0; 
    	em[112] = 42; em[113] = 0; 
    	em[114] = 37; em[115] = 0; 
    	em[116] = 164; em[117] = 0; 
    	em[118] = 169; em[119] = 0; 
    	em[120] = 174; em[121] = 0; 
    	em[122] = 19; em[123] = 0; 
    	em[124] = 82; em[125] = 0; 
    	em[126] = 82; em[127] = 0; 
    	em[128] = 11; em[129] = 0; 
    em[130] = 1; em[131] = 8; em[132] = 1; /* 130: pointer.char */
    	em[133] = 8884096; em[134] = 0; 
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
    	em[182] = 87; em[183] = 8; 
    em[184] = 0; em[185] = 0; em[186] = 0; /* 184: struct.ASN1_VALUE_st */
    em[187] = 1; em[188] = 8; em[189] = 1; /* 187: pointer.struct.ASN1_VALUE_st */
    	em[190] = 184; em[191] = 0; 
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
    em[227] = 1; em[228] = 8; em[229] = 1; /* 227: pointer.struct.asn1_string_st */
    	em[230] = 197; em[231] = 0; 
    em[232] = 1; em[233] = 8; em[234] = 1; /* 232: pointer.struct.asn1_string_st */
    	em[235] = 197; em[236] = 0; 
    em[237] = 1; em[238] = 8; em[239] = 1; /* 237: pointer.struct.asn1_string_st */
    	em[240] = 197; em[241] = 0; 
    em[242] = 1; em[243] = 8; em[244] = 1; /* 242: pointer.struct.asn1_string_st */
    	em[245] = 197; em[246] = 0; 
    em[247] = 1; em[248] = 8; em[249] = 1; /* 247: pointer.struct.asn1_string_st */
    	em[250] = 197; em[251] = 0; 
    em[252] = 0; em[253] = 40; em[254] = 3; /* 252: struct.asn1_object_st */
    	em[255] = 149; em[256] = 0; 
    	em[257] = 149; em[258] = 8; 
    	em[259] = 154; em[260] = 24; 
    em[261] = 1; em[262] = 8; em[263] = 1; /* 261: pointer.struct.asn1_string_st */
    	em[264] = 197; em[265] = 0; 
    em[266] = 0; em[267] = 16; em[268] = 1; /* 266: struct.asn1_type_st */
    	em[269] = 271; em[270] = 8; 
    em[271] = 0; em[272] = 8; em[273] = 20; /* 271: union.unknown */
    	em[274] = 130; em[275] = 0; 
    	em[276] = 261; em[277] = 0; 
    	em[278] = 314; em[279] = 0; 
    	em[280] = 242; em[281] = 0; 
    	em[282] = 237; em[283] = 0; 
    	em[284] = 232; em[285] = 0; 
    	em[286] = 227; em[287] = 0; 
    	em[288] = 222; em[289] = 0; 
    	em[290] = 319; em[291] = 0; 
    	em[292] = 217; em[293] = 0; 
    	em[294] = 324; em[295] = 0; 
    	em[296] = 212; em[297] = 0; 
    	em[298] = 247; em[299] = 0; 
    	em[300] = 207; em[301] = 0; 
    	em[302] = 202; em[303] = 0; 
    	em[304] = 192; em[305] = 0; 
    	em[306] = 329; em[307] = 0; 
    	em[308] = 261; em[309] = 0; 
    	em[310] = 261; em[311] = 0; 
    	em[312] = 187; em[313] = 0; 
    em[314] = 1; em[315] = 8; em[316] = 1; /* 314: pointer.struct.asn1_object_st */
    	em[317] = 252; em[318] = 0; 
    em[319] = 1; em[320] = 8; em[321] = 1; /* 319: pointer.struct.asn1_string_st */
    	em[322] = 197; em[323] = 0; 
    em[324] = 1; em[325] = 8; em[326] = 1; /* 324: pointer.struct.asn1_string_st */
    	em[327] = 197; em[328] = 0; 
    em[329] = 1; em[330] = 8; em[331] = 1; /* 329: pointer.struct.asn1_string_st */
    	em[332] = 197; em[333] = 0; 
    em[334] = 0; em[335] = 0; em[336] = 1; /* 334: ASN1_TYPE */
    	em[337] = 266; em[338] = 0; 
    em[339] = 1; em[340] = 8; em[341] = 1; /* 339: pointer.struct.stack_st_ASN1_TYPE */
    	em[342] = 344; em[343] = 0; 
    em[344] = 0; em[345] = 32; em[346] = 2; /* 344: struct.stack_st_fake_ASN1_TYPE */
    	em[347] = 351; em[348] = 8; 
    	em[349] = 363; em[350] = 24; 
    em[351] = 8884099; em[352] = 8; em[353] = 2; /* 351: pointer_to_array_of_pointers_to_stack */
    	em[354] = 358; em[355] = 0; 
    	em[356] = 5; em[357] = 20; 
    em[358] = 0; em[359] = 8; em[360] = 1; /* 358: pointer.ASN1_TYPE */
    	em[361] = 334; em[362] = 0; 
    em[363] = 8884097; em[364] = 8; em[365] = 0; /* 363: pointer.func */
    em[366] = 0; em[367] = 8; em[368] = 0; /* 366: long unsigned int */
    em[369] = 1; em[370] = 8; em[371] = 1; /* 369: pointer.struct.engine_st */
    	em[372] = 374; em[373] = 0; 
    em[374] = 0; em[375] = 216; em[376] = 24; /* 374: struct.engine_st */
    	em[377] = 149; em[378] = 0; 
    	em[379] = 149; em[380] = 8; 
    	em[381] = 425; em[382] = 16; 
    	em[383] = 480; em[384] = 24; 
    	em[385] = 531; em[386] = 32; 
    	em[387] = 567; em[388] = 40; 
    	em[389] = 584; em[390] = 48; 
    	em[391] = 611; em[392] = 56; 
    	em[393] = 646; em[394] = 64; 
    	em[395] = 654; em[396] = 72; 
    	em[397] = 657; em[398] = 80; 
    	em[399] = 660; em[400] = 88; 
    	em[401] = 663; em[402] = 96; 
    	em[403] = 666; em[404] = 104; 
    	em[405] = 666; em[406] = 112; 
    	em[407] = 666; em[408] = 120; 
    	em[409] = 669; em[410] = 128; 
    	em[411] = 672; em[412] = 136; 
    	em[413] = 672; em[414] = 144; 
    	em[415] = 675; em[416] = 152; 
    	em[417] = 678; em[418] = 160; 
    	em[419] = 690; em[420] = 184; 
    	em[421] = 707; em[422] = 200; 
    	em[423] = 707; em[424] = 208; 
    em[425] = 1; em[426] = 8; em[427] = 1; /* 425: pointer.struct.rsa_meth_st */
    	em[428] = 430; em[429] = 0; 
    em[430] = 0; em[431] = 112; em[432] = 13; /* 430: struct.rsa_meth_st */
    	em[433] = 149; em[434] = 0; 
    	em[435] = 459; em[436] = 8; 
    	em[437] = 459; em[438] = 16; 
    	em[439] = 459; em[440] = 24; 
    	em[441] = 459; em[442] = 32; 
    	em[443] = 462; em[444] = 40; 
    	em[445] = 465; em[446] = 48; 
    	em[447] = 468; em[448] = 56; 
    	em[449] = 468; em[450] = 64; 
    	em[451] = 130; em[452] = 80; 
    	em[453] = 471; em[454] = 88; 
    	em[455] = 474; em[456] = 96; 
    	em[457] = 477; em[458] = 104; 
    em[459] = 8884097; em[460] = 8; em[461] = 0; /* 459: pointer.func */
    em[462] = 8884097; em[463] = 8; em[464] = 0; /* 462: pointer.func */
    em[465] = 8884097; em[466] = 8; em[467] = 0; /* 465: pointer.func */
    em[468] = 8884097; em[469] = 8; em[470] = 0; /* 468: pointer.func */
    em[471] = 8884097; em[472] = 8; em[473] = 0; /* 471: pointer.func */
    em[474] = 8884097; em[475] = 8; em[476] = 0; /* 474: pointer.func */
    em[477] = 8884097; em[478] = 8; em[479] = 0; /* 477: pointer.func */
    em[480] = 1; em[481] = 8; em[482] = 1; /* 480: pointer.struct.dsa_method */
    	em[483] = 485; em[484] = 0; 
    em[485] = 0; em[486] = 96; em[487] = 11; /* 485: struct.dsa_method */
    	em[488] = 149; em[489] = 0; 
    	em[490] = 510; em[491] = 8; 
    	em[492] = 513; em[493] = 16; 
    	em[494] = 516; em[495] = 24; 
    	em[496] = 519; em[497] = 32; 
    	em[498] = 522; em[499] = 40; 
    	em[500] = 525; em[501] = 48; 
    	em[502] = 525; em[503] = 56; 
    	em[504] = 130; em[505] = 72; 
    	em[506] = 528; em[507] = 80; 
    	em[508] = 525; em[509] = 88; 
    em[510] = 8884097; em[511] = 8; em[512] = 0; /* 510: pointer.func */
    em[513] = 8884097; em[514] = 8; em[515] = 0; /* 513: pointer.func */
    em[516] = 8884097; em[517] = 8; em[518] = 0; /* 516: pointer.func */
    em[519] = 8884097; em[520] = 8; em[521] = 0; /* 519: pointer.func */
    em[522] = 8884097; em[523] = 8; em[524] = 0; /* 522: pointer.func */
    em[525] = 8884097; em[526] = 8; em[527] = 0; /* 525: pointer.func */
    em[528] = 8884097; em[529] = 8; em[530] = 0; /* 528: pointer.func */
    em[531] = 1; em[532] = 8; em[533] = 1; /* 531: pointer.struct.dh_method */
    	em[534] = 536; em[535] = 0; 
    em[536] = 0; em[537] = 72; em[538] = 8; /* 536: struct.dh_method */
    	em[539] = 149; em[540] = 0; 
    	em[541] = 555; em[542] = 8; 
    	em[543] = 558; em[544] = 16; 
    	em[545] = 561; em[546] = 24; 
    	em[547] = 555; em[548] = 32; 
    	em[549] = 555; em[550] = 40; 
    	em[551] = 130; em[552] = 56; 
    	em[553] = 564; em[554] = 64; 
    em[555] = 8884097; em[556] = 8; em[557] = 0; /* 555: pointer.func */
    em[558] = 8884097; em[559] = 8; em[560] = 0; /* 558: pointer.func */
    em[561] = 8884097; em[562] = 8; em[563] = 0; /* 561: pointer.func */
    em[564] = 8884097; em[565] = 8; em[566] = 0; /* 564: pointer.func */
    em[567] = 1; em[568] = 8; em[569] = 1; /* 567: pointer.struct.ecdh_method */
    	em[570] = 572; em[571] = 0; 
    em[572] = 0; em[573] = 32; em[574] = 3; /* 572: struct.ecdh_method */
    	em[575] = 149; em[576] = 0; 
    	em[577] = 581; em[578] = 8; 
    	em[579] = 130; em[580] = 24; 
    em[581] = 8884097; em[582] = 8; em[583] = 0; /* 581: pointer.func */
    em[584] = 1; em[585] = 8; em[586] = 1; /* 584: pointer.struct.ecdsa_method */
    	em[587] = 589; em[588] = 0; 
    em[589] = 0; em[590] = 48; em[591] = 5; /* 589: struct.ecdsa_method */
    	em[592] = 149; em[593] = 0; 
    	em[594] = 602; em[595] = 8; 
    	em[596] = 605; em[597] = 16; 
    	em[598] = 608; em[599] = 24; 
    	em[600] = 130; em[601] = 40; 
    em[602] = 8884097; em[603] = 8; em[604] = 0; /* 602: pointer.func */
    em[605] = 8884097; em[606] = 8; em[607] = 0; /* 605: pointer.func */
    em[608] = 8884097; em[609] = 8; em[610] = 0; /* 608: pointer.func */
    em[611] = 1; em[612] = 8; em[613] = 1; /* 611: pointer.struct.rand_meth_st */
    	em[614] = 616; em[615] = 0; 
    em[616] = 0; em[617] = 48; em[618] = 6; /* 616: struct.rand_meth_st */
    	em[619] = 631; em[620] = 0; 
    	em[621] = 634; em[622] = 8; 
    	em[623] = 637; em[624] = 16; 
    	em[625] = 640; em[626] = 24; 
    	em[627] = 634; em[628] = 32; 
    	em[629] = 643; em[630] = 40; 
    em[631] = 8884097; em[632] = 8; em[633] = 0; /* 631: pointer.func */
    em[634] = 8884097; em[635] = 8; em[636] = 0; /* 634: pointer.func */
    em[637] = 8884097; em[638] = 8; em[639] = 0; /* 637: pointer.func */
    em[640] = 8884097; em[641] = 8; em[642] = 0; /* 640: pointer.func */
    em[643] = 8884097; em[644] = 8; em[645] = 0; /* 643: pointer.func */
    em[646] = 1; em[647] = 8; em[648] = 1; /* 646: pointer.struct.store_method_st */
    	em[649] = 651; em[650] = 0; 
    em[651] = 0; em[652] = 0; em[653] = 0; /* 651: struct.store_method_st */
    em[654] = 8884097; em[655] = 8; em[656] = 0; /* 654: pointer.func */
    em[657] = 8884097; em[658] = 8; em[659] = 0; /* 657: pointer.func */
    em[660] = 8884097; em[661] = 8; em[662] = 0; /* 660: pointer.func */
    em[663] = 8884097; em[664] = 8; em[665] = 0; /* 663: pointer.func */
    em[666] = 8884097; em[667] = 8; em[668] = 0; /* 666: pointer.func */
    em[669] = 8884097; em[670] = 8; em[671] = 0; /* 669: pointer.func */
    em[672] = 8884097; em[673] = 8; em[674] = 0; /* 672: pointer.func */
    em[675] = 8884097; em[676] = 8; em[677] = 0; /* 675: pointer.func */
    em[678] = 1; em[679] = 8; em[680] = 1; /* 678: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[681] = 683; em[682] = 0; 
    em[683] = 0; em[684] = 32; em[685] = 2; /* 683: struct.ENGINE_CMD_DEFN_st */
    	em[686] = 149; em[687] = 8; 
    	em[688] = 149; em[689] = 16; 
    em[690] = 0; em[691] = 32; em[692] = 2; /* 690: struct.crypto_ex_data_st_fake */
    	em[693] = 697; em[694] = 8; 
    	em[695] = 363; em[696] = 24; 
    em[697] = 8884099; em[698] = 8; em[699] = 2; /* 697: pointer_to_array_of_pointers_to_stack */
    	em[700] = 704; em[701] = 0; 
    	em[702] = 5; em[703] = 20; 
    em[704] = 0; em[705] = 8; em[706] = 0; /* 704: pointer.void */
    em[707] = 1; em[708] = 8; em[709] = 1; /* 707: pointer.struct.engine_st */
    	em[710] = 374; em[711] = 0; 
    em[712] = 8884097; em[713] = 8; em[714] = 0; /* 712: pointer.func */
    em[715] = 8884097; em[716] = 8; em[717] = 0; /* 715: pointer.func */
    em[718] = 8884097; em[719] = 8; em[720] = 0; /* 718: pointer.func */
    em[721] = 8884097; em[722] = 8; em[723] = 0; /* 721: pointer.func */
    em[724] = 8884097; em[725] = 8; em[726] = 0; /* 724: pointer.func */
    em[727] = 0; em[728] = 112; em[729] = 13; /* 727: struct.rsa_meth_st */
    	em[730] = 149; em[731] = 0; 
    	em[732] = 721; em[733] = 8; 
    	em[734] = 721; em[735] = 16; 
    	em[736] = 721; em[737] = 24; 
    	em[738] = 721; em[739] = 32; 
    	em[740] = 718; em[741] = 40; 
    	em[742] = 715; em[743] = 48; 
    	em[744] = 756; em[745] = 56; 
    	em[746] = 756; em[747] = 64; 
    	em[748] = 130; em[749] = 80; 
    	em[750] = 759; em[751] = 88; 
    	em[752] = 762; em[753] = 96; 
    	em[754] = 712; em[755] = 104; 
    em[756] = 8884097; em[757] = 8; em[758] = 0; /* 756: pointer.func */
    em[759] = 8884097; em[760] = 8; em[761] = 0; /* 759: pointer.func */
    em[762] = 8884097; em[763] = 8; em[764] = 0; /* 762: pointer.func */
    em[765] = 0; em[766] = 1; em[767] = 0; /* 765: char */
    em[768] = 0; em[769] = 24; em[770] = 1; /* 768: struct.bignum_st */
    	em[771] = 773; em[772] = 0; 
    em[773] = 8884099; em[774] = 8; em[775] = 2; /* 773: pointer_to_array_of_pointers_to_stack */
    	em[776] = 366; em[777] = 0; 
    	em[778] = 5; em[779] = 12; 
    em[780] = 0; em[781] = 8; em[782] = 5; /* 780: union.unknown */
    	em[783] = 130; em[784] = 0; 
    	em[785] = 793; em[786] = 0; 
    	em[787] = 946; em[788] = 0; 
    	em[789] = 1077; em[790] = 0; 
    	em[791] = 1195; em[792] = 0; 
    em[793] = 1; em[794] = 8; em[795] = 1; /* 793: pointer.struct.rsa_st */
    	em[796] = 798; em[797] = 0; 
    em[798] = 0; em[799] = 168; em[800] = 17; /* 798: struct.rsa_st */
    	em[801] = 835; em[802] = 16; 
    	em[803] = 369; em[804] = 24; 
    	em[805] = 840; em[806] = 32; 
    	em[807] = 840; em[808] = 40; 
    	em[809] = 840; em[810] = 48; 
    	em[811] = 840; em[812] = 56; 
    	em[813] = 840; em[814] = 64; 
    	em[815] = 840; em[816] = 72; 
    	em[817] = 840; em[818] = 80; 
    	em[819] = 840; em[820] = 88; 
    	em[821] = 857; em[822] = 96; 
    	em[823] = 871; em[824] = 120; 
    	em[825] = 871; em[826] = 128; 
    	em[827] = 871; em[828] = 136; 
    	em[829] = 130; em[830] = 144; 
    	em[831] = 885; em[832] = 152; 
    	em[833] = 885; em[834] = 160; 
    em[835] = 1; em[836] = 8; em[837] = 1; /* 835: pointer.struct.rsa_meth_st */
    	em[838] = 727; em[839] = 0; 
    em[840] = 1; em[841] = 8; em[842] = 1; /* 840: pointer.struct.bignum_st */
    	em[843] = 845; em[844] = 0; 
    em[845] = 0; em[846] = 24; em[847] = 1; /* 845: struct.bignum_st */
    	em[848] = 850; em[849] = 0; 
    em[850] = 8884099; em[851] = 8; em[852] = 2; /* 850: pointer_to_array_of_pointers_to_stack */
    	em[853] = 366; em[854] = 0; 
    	em[855] = 5; em[856] = 12; 
    em[857] = 0; em[858] = 32; em[859] = 2; /* 857: struct.crypto_ex_data_st_fake */
    	em[860] = 864; em[861] = 8; 
    	em[862] = 363; em[863] = 24; 
    em[864] = 8884099; em[865] = 8; em[866] = 2; /* 864: pointer_to_array_of_pointers_to_stack */
    	em[867] = 704; em[868] = 0; 
    	em[869] = 5; em[870] = 20; 
    em[871] = 1; em[872] = 8; em[873] = 1; /* 871: pointer.struct.bn_mont_ctx_st */
    	em[874] = 876; em[875] = 0; 
    em[876] = 0; em[877] = 96; em[878] = 3; /* 876: struct.bn_mont_ctx_st */
    	em[879] = 845; em[880] = 8; 
    	em[881] = 845; em[882] = 32; 
    	em[883] = 845; em[884] = 56; 
    em[885] = 1; em[886] = 8; em[887] = 1; /* 885: pointer.struct.bn_blinding_st */
    	em[888] = 890; em[889] = 0; 
    em[890] = 0; em[891] = 88; em[892] = 7; /* 890: struct.bn_blinding_st */
    	em[893] = 907; em[894] = 0; 
    	em[895] = 907; em[896] = 8; 
    	em[897] = 907; em[898] = 16; 
    	em[899] = 907; em[900] = 24; 
    	em[901] = 924; em[902] = 40; 
    	em[903] = 929; em[904] = 72; 
    	em[905] = 943; em[906] = 80; 
    em[907] = 1; em[908] = 8; em[909] = 1; /* 907: pointer.struct.bignum_st */
    	em[910] = 912; em[911] = 0; 
    em[912] = 0; em[913] = 24; em[914] = 1; /* 912: struct.bignum_st */
    	em[915] = 917; em[916] = 0; 
    em[917] = 8884099; em[918] = 8; em[919] = 2; /* 917: pointer_to_array_of_pointers_to_stack */
    	em[920] = 366; em[921] = 0; 
    	em[922] = 5; em[923] = 12; 
    em[924] = 0; em[925] = 16; em[926] = 1; /* 924: struct.crypto_threadid_st */
    	em[927] = 704; em[928] = 0; 
    em[929] = 1; em[930] = 8; em[931] = 1; /* 929: pointer.struct.bn_mont_ctx_st */
    	em[932] = 934; em[933] = 0; 
    em[934] = 0; em[935] = 96; em[936] = 3; /* 934: struct.bn_mont_ctx_st */
    	em[937] = 912; em[938] = 8; 
    	em[939] = 912; em[940] = 32; 
    	em[941] = 912; em[942] = 56; 
    em[943] = 8884097; em[944] = 8; em[945] = 0; /* 943: pointer.func */
    em[946] = 1; em[947] = 8; em[948] = 1; /* 946: pointer.struct.dsa_st */
    	em[949] = 951; em[950] = 0; 
    em[951] = 0; em[952] = 136; em[953] = 11; /* 951: struct.dsa_st */
    	em[954] = 976; em[955] = 24; 
    	em[956] = 976; em[957] = 32; 
    	em[958] = 976; em[959] = 40; 
    	em[960] = 976; em[961] = 48; 
    	em[962] = 976; em[963] = 56; 
    	em[964] = 976; em[965] = 64; 
    	em[966] = 976; em[967] = 72; 
    	em[968] = 993; em[969] = 88; 
    	em[970] = 1007; em[971] = 104; 
    	em[972] = 1021; em[973] = 120; 
    	em[974] = 1072; em[975] = 128; 
    em[976] = 1; em[977] = 8; em[978] = 1; /* 976: pointer.struct.bignum_st */
    	em[979] = 981; em[980] = 0; 
    em[981] = 0; em[982] = 24; em[983] = 1; /* 981: struct.bignum_st */
    	em[984] = 986; em[985] = 0; 
    em[986] = 8884099; em[987] = 8; em[988] = 2; /* 986: pointer_to_array_of_pointers_to_stack */
    	em[989] = 366; em[990] = 0; 
    	em[991] = 5; em[992] = 12; 
    em[993] = 1; em[994] = 8; em[995] = 1; /* 993: pointer.struct.bn_mont_ctx_st */
    	em[996] = 998; em[997] = 0; 
    em[998] = 0; em[999] = 96; em[1000] = 3; /* 998: struct.bn_mont_ctx_st */
    	em[1001] = 981; em[1002] = 8; 
    	em[1003] = 981; em[1004] = 32; 
    	em[1005] = 981; em[1006] = 56; 
    em[1007] = 0; em[1008] = 32; em[1009] = 2; /* 1007: struct.crypto_ex_data_st_fake */
    	em[1010] = 1014; em[1011] = 8; 
    	em[1012] = 363; em[1013] = 24; 
    em[1014] = 8884099; em[1015] = 8; em[1016] = 2; /* 1014: pointer_to_array_of_pointers_to_stack */
    	em[1017] = 704; em[1018] = 0; 
    	em[1019] = 5; em[1020] = 20; 
    em[1021] = 1; em[1022] = 8; em[1023] = 1; /* 1021: pointer.struct.dsa_method */
    	em[1024] = 1026; em[1025] = 0; 
    em[1026] = 0; em[1027] = 96; em[1028] = 11; /* 1026: struct.dsa_method */
    	em[1029] = 149; em[1030] = 0; 
    	em[1031] = 1051; em[1032] = 8; 
    	em[1033] = 1054; em[1034] = 16; 
    	em[1035] = 1057; em[1036] = 24; 
    	em[1037] = 1060; em[1038] = 32; 
    	em[1039] = 1063; em[1040] = 40; 
    	em[1041] = 1066; em[1042] = 48; 
    	em[1043] = 1066; em[1044] = 56; 
    	em[1045] = 130; em[1046] = 72; 
    	em[1047] = 1069; em[1048] = 80; 
    	em[1049] = 1066; em[1050] = 88; 
    em[1051] = 8884097; em[1052] = 8; em[1053] = 0; /* 1051: pointer.func */
    em[1054] = 8884097; em[1055] = 8; em[1056] = 0; /* 1054: pointer.func */
    em[1057] = 8884097; em[1058] = 8; em[1059] = 0; /* 1057: pointer.func */
    em[1060] = 8884097; em[1061] = 8; em[1062] = 0; /* 1060: pointer.func */
    em[1063] = 8884097; em[1064] = 8; em[1065] = 0; /* 1063: pointer.func */
    em[1066] = 8884097; em[1067] = 8; em[1068] = 0; /* 1066: pointer.func */
    em[1069] = 8884097; em[1070] = 8; em[1071] = 0; /* 1069: pointer.func */
    em[1072] = 1; em[1073] = 8; em[1074] = 1; /* 1072: pointer.struct.engine_st */
    	em[1075] = 374; em[1076] = 0; 
    em[1077] = 1; em[1078] = 8; em[1079] = 1; /* 1077: pointer.struct.dh_st */
    	em[1080] = 1082; em[1081] = 0; 
    em[1082] = 0; em[1083] = 144; em[1084] = 12; /* 1082: struct.dh_st */
    	em[1085] = 1109; em[1086] = 8; 
    	em[1087] = 1109; em[1088] = 16; 
    	em[1089] = 1109; em[1090] = 32; 
    	em[1091] = 1109; em[1092] = 40; 
    	em[1093] = 1126; em[1094] = 56; 
    	em[1095] = 1109; em[1096] = 64; 
    	em[1097] = 1109; em[1098] = 72; 
    	em[1099] = 29; em[1100] = 80; 
    	em[1101] = 1109; em[1102] = 96; 
    	em[1103] = 1140; em[1104] = 112; 
    	em[1105] = 1154; em[1106] = 128; 
    	em[1107] = 1190; em[1108] = 136; 
    em[1109] = 1; em[1110] = 8; em[1111] = 1; /* 1109: pointer.struct.bignum_st */
    	em[1112] = 1114; em[1113] = 0; 
    em[1114] = 0; em[1115] = 24; em[1116] = 1; /* 1114: struct.bignum_st */
    	em[1117] = 1119; em[1118] = 0; 
    em[1119] = 8884099; em[1120] = 8; em[1121] = 2; /* 1119: pointer_to_array_of_pointers_to_stack */
    	em[1122] = 366; em[1123] = 0; 
    	em[1124] = 5; em[1125] = 12; 
    em[1126] = 1; em[1127] = 8; em[1128] = 1; /* 1126: pointer.struct.bn_mont_ctx_st */
    	em[1129] = 1131; em[1130] = 0; 
    em[1131] = 0; em[1132] = 96; em[1133] = 3; /* 1131: struct.bn_mont_ctx_st */
    	em[1134] = 1114; em[1135] = 8; 
    	em[1136] = 1114; em[1137] = 32; 
    	em[1138] = 1114; em[1139] = 56; 
    em[1140] = 0; em[1141] = 32; em[1142] = 2; /* 1140: struct.crypto_ex_data_st_fake */
    	em[1143] = 1147; em[1144] = 8; 
    	em[1145] = 363; em[1146] = 24; 
    em[1147] = 8884099; em[1148] = 8; em[1149] = 2; /* 1147: pointer_to_array_of_pointers_to_stack */
    	em[1150] = 704; em[1151] = 0; 
    	em[1152] = 5; em[1153] = 20; 
    em[1154] = 1; em[1155] = 8; em[1156] = 1; /* 1154: pointer.struct.dh_method */
    	em[1157] = 1159; em[1158] = 0; 
    em[1159] = 0; em[1160] = 72; em[1161] = 8; /* 1159: struct.dh_method */
    	em[1162] = 149; em[1163] = 0; 
    	em[1164] = 1178; em[1165] = 8; 
    	em[1166] = 1181; em[1167] = 16; 
    	em[1168] = 1184; em[1169] = 24; 
    	em[1170] = 1178; em[1171] = 32; 
    	em[1172] = 1178; em[1173] = 40; 
    	em[1174] = 130; em[1175] = 56; 
    	em[1176] = 1187; em[1177] = 64; 
    em[1178] = 8884097; em[1179] = 8; em[1180] = 0; /* 1178: pointer.func */
    em[1181] = 8884097; em[1182] = 8; em[1183] = 0; /* 1181: pointer.func */
    em[1184] = 8884097; em[1185] = 8; em[1186] = 0; /* 1184: pointer.func */
    em[1187] = 8884097; em[1188] = 8; em[1189] = 0; /* 1187: pointer.func */
    em[1190] = 1; em[1191] = 8; em[1192] = 1; /* 1190: pointer.struct.engine_st */
    	em[1193] = 374; em[1194] = 0; 
    em[1195] = 1; em[1196] = 8; em[1197] = 1; /* 1195: pointer.struct.ec_key_st */
    	em[1198] = 1200; em[1199] = 0; 
    em[1200] = 0; em[1201] = 56; em[1202] = 4; /* 1200: struct.ec_key_st */
    	em[1203] = 1211; em[1204] = 8; 
    	em[1205] = 1644; em[1206] = 16; 
    	em[1207] = 1649; em[1208] = 24; 
    	em[1209] = 1666; em[1210] = 48; 
    em[1211] = 1; em[1212] = 8; em[1213] = 1; /* 1211: pointer.struct.ec_group_st */
    	em[1214] = 1216; em[1215] = 0; 
    em[1216] = 0; em[1217] = 232; em[1218] = 12; /* 1216: struct.ec_group_st */
    	em[1219] = 1243; em[1220] = 0; 
    	em[1221] = 1412; em[1222] = 8; 
    	em[1223] = 1600; em[1224] = 16; 
    	em[1225] = 1600; em[1226] = 40; 
    	em[1227] = 29; em[1228] = 80; 
    	em[1229] = 1612; em[1230] = 96; 
    	em[1231] = 1600; em[1232] = 104; 
    	em[1233] = 1600; em[1234] = 152; 
    	em[1235] = 1600; em[1236] = 176; 
    	em[1237] = 704; em[1238] = 208; 
    	em[1239] = 704; em[1240] = 216; 
    	em[1241] = 1641; em[1242] = 224; 
    em[1243] = 1; em[1244] = 8; em[1245] = 1; /* 1243: pointer.struct.ec_method_st */
    	em[1246] = 1248; em[1247] = 0; 
    em[1248] = 0; em[1249] = 304; em[1250] = 37; /* 1248: struct.ec_method_st */
    	em[1251] = 1325; em[1252] = 8; 
    	em[1253] = 1328; em[1254] = 16; 
    	em[1255] = 1328; em[1256] = 24; 
    	em[1257] = 1331; em[1258] = 32; 
    	em[1259] = 1334; em[1260] = 40; 
    	em[1261] = 1337; em[1262] = 48; 
    	em[1263] = 1340; em[1264] = 56; 
    	em[1265] = 1343; em[1266] = 64; 
    	em[1267] = 1346; em[1268] = 72; 
    	em[1269] = 1349; em[1270] = 80; 
    	em[1271] = 1349; em[1272] = 88; 
    	em[1273] = 1352; em[1274] = 96; 
    	em[1275] = 1355; em[1276] = 104; 
    	em[1277] = 1358; em[1278] = 112; 
    	em[1279] = 1361; em[1280] = 120; 
    	em[1281] = 1364; em[1282] = 128; 
    	em[1283] = 1367; em[1284] = 136; 
    	em[1285] = 1370; em[1286] = 144; 
    	em[1287] = 1373; em[1288] = 152; 
    	em[1289] = 1376; em[1290] = 160; 
    	em[1291] = 1379; em[1292] = 168; 
    	em[1293] = 1382; em[1294] = 176; 
    	em[1295] = 1385; em[1296] = 184; 
    	em[1297] = 1388; em[1298] = 192; 
    	em[1299] = 1391; em[1300] = 200; 
    	em[1301] = 1394; em[1302] = 208; 
    	em[1303] = 1385; em[1304] = 216; 
    	em[1305] = 1397; em[1306] = 224; 
    	em[1307] = 1400; em[1308] = 232; 
    	em[1309] = 724; em[1310] = 240; 
    	em[1311] = 1340; em[1312] = 248; 
    	em[1313] = 1403; em[1314] = 256; 
    	em[1315] = 1406; em[1316] = 264; 
    	em[1317] = 1403; em[1318] = 272; 
    	em[1319] = 1406; em[1320] = 280; 
    	em[1321] = 1406; em[1322] = 288; 
    	em[1323] = 1409; em[1324] = 296; 
    em[1325] = 8884097; em[1326] = 8; em[1327] = 0; /* 1325: pointer.func */
    em[1328] = 8884097; em[1329] = 8; em[1330] = 0; /* 1328: pointer.func */
    em[1331] = 8884097; em[1332] = 8; em[1333] = 0; /* 1331: pointer.func */
    em[1334] = 8884097; em[1335] = 8; em[1336] = 0; /* 1334: pointer.func */
    em[1337] = 8884097; em[1338] = 8; em[1339] = 0; /* 1337: pointer.func */
    em[1340] = 8884097; em[1341] = 8; em[1342] = 0; /* 1340: pointer.func */
    em[1343] = 8884097; em[1344] = 8; em[1345] = 0; /* 1343: pointer.func */
    em[1346] = 8884097; em[1347] = 8; em[1348] = 0; /* 1346: pointer.func */
    em[1349] = 8884097; em[1350] = 8; em[1351] = 0; /* 1349: pointer.func */
    em[1352] = 8884097; em[1353] = 8; em[1354] = 0; /* 1352: pointer.func */
    em[1355] = 8884097; em[1356] = 8; em[1357] = 0; /* 1355: pointer.func */
    em[1358] = 8884097; em[1359] = 8; em[1360] = 0; /* 1358: pointer.func */
    em[1361] = 8884097; em[1362] = 8; em[1363] = 0; /* 1361: pointer.func */
    em[1364] = 8884097; em[1365] = 8; em[1366] = 0; /* 1364: pointer.func */
    em[1367] = 8884097; em[1368] = 8; em[1369] = 0; /* 1367: pointer.func */
    em[1370] = 8884097; em[1371] = 8; em[1372] = 0; /* 1370: pointer.func */
    em[1373] = 8884097; em[1374] = 8; em[1375] = 0; /* 1373: pointer.func */
    em[1376] = 8884097; em[1377] = 8; em[1378] = 0; /* 1376: pointer.func */
    em[1379] = 8884097; em[1380] = 8; em[1381] = 0; /* 1379: pointer.func */
    em[1382] = 8884097; em[1383] = 8; em[1384] = 0; /* 1382: pointer.func */
    em[1385] = 8884097; em[1386] = 8; em[1387] = 0; /* 1385: pointer.func */
    em[1388] = 8884097; em[1389] = 8; em[1390] = 0; /* 1388: pointer.func */
    em[1391] = 8884097; em[1392] = 8; em[1393] = 0; /* 1391: pointer.func */
    em[1394] = 8884097; em[1395] = 8; em[1396] = 0; /* 1394: pointer.func */
    em[1397] = 8884097; em[1398] = 8; em[1399] = 0; /* 1397: pointer.func */
    em[1400] = 8884097; em[1401] = 8; em[1402] = 0; /* 1400: pointer.func */
    em[1403] = 8884097; em[1404] = 8; em[1405] = 0; /* 1403: pointer.func */
    em[1406] = 8884097; em[1407] = 8; em[1408] = 0; /* 1406: pointer.func */
    em[1409] = 8884097; em[1410] = 8; em[1411] = 0; /* 1409: pointer.func */
    em[1412] = 1; em[1413] = 8; em[1414] = 1; /* 1412: pointer.struct.ec_point_st */
    	em[1415] = 1417; em[1416] = 0; 
    em[1417] = 0; em[1418] = 88; em[1419] = 4; /* 1417: struct.ec_point_st */
    	em[1420] = 1428; em[1421] = 0; 
    	em[1422] = 768; em[1423] = 8; 
    	em[1424] = 768; em[1425] = 32; 
    	em[1426] = 768; em[1427] = 56; 
    em[1428] = 1; em[1429] = 8; em[1430] = 1; /* 1428: pointer.struct.ec_method_st */
    	em[1431] = 1433; em[1432] = 0; 
    em[1433] = 0; em[1434] = 304; em[1435] = 37; /* 1433: struct.ec_method_st */
    	em[1436] = 1510; em[1437] = 8; 
    	em[1438] = 1513; em[1439] = 16; 
    	em[1440] = 1513; em[1441] = 24; 
    	em[1442] = 1516; em[1443] = 32; 
    	em[1444] = 1519; em[1445] = 40; 
    	em[1446] = 1522; em[1447] = 48; 
    	em[1448] = 1525; em[1449] = 56; 
    	em[1450] = 1528; em[1451] = 64; 
    	em[1452] = 1531; em[1453] = 72; 
    	em[1454] = 1534; em[1455] = 80; 
    	em[1456] = 1534; em[1457] = 88; 
    	em[1458] = 1537; em[1459] = 96; 
    	em[1460] = 1540; em[1461] = 104; 
    	em[1462] = 1543; em[1463] = 112; 
    	em[1464] = 1546; em[1465] = 120; 
    	em[1466] = 1549; em[1467] = 128; 
    	em[1468] = 1552; em[1469] = 136; 
    	em[1470] = 1555; em[1471] = 144; 
    	em[1472] = 1558; em[1473] = 152; 
    	em[1474] = 1561; em[1475] = 160; 
    	em[1476] = 1564; em[1477] = 168; 
    	em[1478] = 1567; em[1479] = 176; 
    	em[1480] = 1570; em[1481] = 184; 
    	em[1482] = 1573; em[1483] = 192; 
    	em[1484] = 1576; em[1485] = 200; 
    	em[1486] = 1579; em[1487] = 208; 
    	em[1488] = 1570; em[1489] = 216; 
    	em[1490] = 1582; em[1491] = 224; 
    	em[1492] = 1585; em[1493] = 232; 
    	em[1494] = 1588; em[1495] = 240; 
    	em[1496] = 1525; em[1497] = 248; 
    	em[1498] = 1591; em[1499] = 256; 
    	em[1500] = 1594; em[1501] = 264; 
    	em[1502] = 1591; em[1503] = 272; 
    	em[1504] = 1594; em[1505] = 280; 
    	em[1506] = 1594; em[1507] = 288; 
    	em[1508] = 1597; em[1509] = 296; 
    em[1510] = 8884097; em[1511] = 8; em[1512] = 0; /* 1510: pointer.func */
    em[1513] = 8884097; em[1514] = 8; em[1515] = 0; /* 1513: pointer.func */
    em[1516] = 8884097; em[1517] = 8; em[1518] = 0; /* 1516: pointer.func */
    em[1519] = 8884097; em[1520] = 8; em[1521] = 0; /* 1519: pointer.func */
    em[1522] = 8884097; em[1523] = 8; em[1524] = 0; /* 1522: pointer.func */
    em[1525] = 8884097; em[1526] = 8; em[1527] = 0; /* 1525: pointer.func */
    em[1528] = 8884097; em[1529] = 8; em[1530] = 0; /* 1528: pointer.func */
    em[1531] = 8884097; em[1532] = 8; em[1533] = 0; /* 1531: pointer.func */
    em[1534] = 8884097; em[1535] = 8; em[1536] = 0; /* 1534: pointer.func */
    em[1537] = 8884097; em[1538] = 8; em[1539] = 0; /* 1537: pointer.func */
    em[1540] = 8884097; em[1541] = 8; em[1542] = 0; /* 1540: pointer.func */
    em[1543] = 8884097; em[1544] = 8; em[1545] = 0; /* 1543: pointer.func */
    em[1546] = 8884097; em[1547] = 8; em[1548] = 0; /* 1546: pointer.func */
    em[1549] = 8884097; em[1550] = 8; em[1551] = 0; /* 1549: pointer.func */
    em[1552] = 8884097; em[1553] = 8; em[1554] = 0; /* 1552: pointer.func */
    em[1555] = 8884097; em[1556] = 8; em[1557] = 0; /* 1555: pointer.func */
    em[1558] = 8884097; em[1559] = 8; em[1560] = 0; /* 1558: pointer.func */
    em[1561] = 8884097; em[1562] = 8; em[1563] = 0; /* 1561: pointer.func */
    em[1564] = 8884097; em[1565] = 8; em[1566] = 0; /* 1564: pointer.func */
    em[1567] = 8884097; em[1568] = 8; em[1569] = 0; /* 1567: pointer.func */
    em[1570] = 8884097; em[1571] = 8; em[1572] = 0; /* 1570: pointer.func */
    em[1573] = 8884097; em[1574] = 8; em[1575] = 0; /* 1573: pointer.func */
    em[1576] = 8884097; em[1577] = 8; em[1578] = 0; /* 1576: pointer.func */
    em[1579] = 8884097; em[1580] = 8; em[1581] = 0; /* 1579: pointer.func */
    em[1582] = 8884097; em[1583] = 8; em[1584] = 0; /* 1582: pointer.func */
    em[1585] = 8884097; em[1586] = 8; em[1587] = 0; /* 1585: pointer.func */
    em[1588] = 8884097; em[1589] = 8; em[1590] = 0; /* 1588: pointer.func */
    em[1591] = 8884097; em[1592] = 8; em[1593] = 0; /* 1591: pointer.func */
    em[1594] = 8884097; em[1595] = 8; em[1596] = 0; /* 1594: pointer.func */
    em[1597] = 8884097; em[1598] = 8; em[1599] = 0; /* 1597: pointer.func */
    em[1600] = 0; em[1601] = 24; em[1602] = 1; /* 1600: struct.bignum_st */
    	em[1603] = 1605; em[1604] = 0; 
    em[1605] = 8884099; em[1606] = 8; em[1607] = 2; /* 1605: pointer_to_array_of_pointers_to_stack */
    	em[1608] = 366; em[1609] = 0; 
    	em[1610] = 5; em[1611] = 12; 
    em[1612] = 1; em[1613] = 8; em[1614] = 1; /* 1612: pointer.struct.ec_extra_data_st */
    	em[1615] = 1617; em[1616] = 0; 
    em[1617] = 0; em[1618] = 40; em[1619] = 5; /* 1617: struct.ec_extra_data_st */
    	em[1620] = 1630; em[1621] = 0; 
    	em[1622] = 704; em[1623] = 8; 
    	em[1624] = 1635; em[1625] = 16; 
    	em[1626] = 1638; em[1627] = 24; 
    	em[1628] = 1638; em[1629] = 32; 
    em[1630] = 1; em[1631] = 8; em[1632] = 1; /* 1630: pointer.struct.ec_extra_data_st */
    	em[1633] = 1617; em[1634] = 0; 
    em[1635] = 8884097; em[1636] = 8; em[1637] = 0; /* 1635: pointer.func */
    em[1638] = 8884097; em[1639] = 8; em[1640] = 0; /* 1638: pointer.func */
    em[1641] = 8884097; em[1642] = 8; em[1643] = 0; /* 1641: pointer.func */
    em[1644] = 1; em[1645] = 8; em[1646] = 1; /* 1644: pointer.struct.ec_point_st */
    	em[1647] = 1417; em[1648] = 0; 
    em[1649] = 1; em[1650] = 8; em[1651] = 1; /* 1649: pointer.struct.bignum_st */
    	em[1652] = 1654; em[1653] = 0; 
    em[1654] = 0; em[1655] = 24; em[1656] = 1; /* 1654: struct.bignum_st */
    	em[1657] = 1659; em[1658] = 0; 
    em[1659] = 8884099; em[1660] = 8; em[1661] = 2; /* 1659: pointer_to_array_of_pointers_to_stack */
    	em[1662] = 366; em[1663] = 0; 
    	em[1664] = 5; em[1665] = 12; 
    em[1666] = 1; em[1667] = 8; em[1668] = 1; /* 1666: pointer.struct.ec_extra_data_st */
    	em[1669] = 1671; em[1670] = 0; 
    em[1671] = 0; em[1672] = 40; em[1673] = 5; /* 1671: struct.ec_extra_data_st */
    	em[1674] = 1684; em[1675] = 0; 
    	em[1676] = 704; em[1677] = 8; 
    	em[1678] = 1635; em[1679] = 16; 
    	em[1680] = 1638; em[1681] = 24; 
    	em[1682] = 1638; em[1683] = 32; 
    em[1684] = 1; em[1685] = 8; em[1686] = 1; /* 1684: pointer.struct.ec_extra_data_st */
    	em[1687] = 1671; em[1688] = 0; 
    em[1689] = 8884097; em[1690] = 8; em[1691] = 0; /* 1689: pointer.func */
    em[1692] = 0; em[1693] = 56; em[1694] = 4; /* 1692: struct.evp_pkey_st */
    	em[1695] = 1703; em[1696] = 16; 
    	em[1697] = 1801; em[1698] = 24; 
    	em[1699] = 780; em[1700] = 32; 
    	em[1701] = 1806; em[1702] = 48; 
    em[1703] = 1; em[1704] = 8; em[1705] = 1; /* 1703: pointer.struct.evp_pkey_asn1_method_st */
    	em[1706] = 1708; em[1707] = 0; 
    em[1708] = 0; em[1709] = 208; em[1710] = 24; /* 1708: struct.evp_pkey_asn1_method_st */
    	em[1711] = 130; em[1712] = 16; 
    	em[1713] = 130; em[1714] = 24; 
    	em[1715] = 1759; em[1716] = 32; 
    	em[1717] = 1762; em[1718] = 40; 
    	em[1719] = 1765; em[1720] = 48; 
    	em[1721] = 1689; em[1722] = 56; 
    	em[1723] = 1768; em[1724] = 64; 
    	em[1725] = 1771; em[1726] = 72; 
    	em[1727] = 1689; em[1728] = 80; 
    	em[1729] = 1774; em[1730] = 88; 
    	em[1731] = 1774; em[1732] = 96; 
    	em[1733] = 1777; em[1734] = 104; 
    	em[1735] = 1780; em[1736] = 112; 
    	em[1737] = 1774; em[1738] = 120; 
    	em[1739] = 1783; em[1740] = 128; 
    	em[1741] = 1765; em[1742] = 136; 
    	em[1743] = 1689; em[1744] = 144; 
    	em[1745] = 1786; em[1746] = 152; 
    	em[1747] = 1789; em[1748] = 160; 
    	em[1749] = 1792; em[1750] = 168; 
    	em[1751] = 1777; em[1752] = 176; 
    	em[1753] = 1780; em[1754] = 184; 
    	em[1755] = 1795; em[1756] = 192; 
    	em[1757] = 1798; em[1758] = 200; 
    em[1759] = 8884097; em[1760] = 8; em[1761] = 0; /* 1759: pointer.func */
    em[1762] = 8884097; em[1763] = 8; em[1764] = 0; /* 1762: pointer.func */
    em[1765] = 8884097; em[1766] = 8; em[1767] = 0; /* 1765: pointer.func */
    em[1768] = 8884097; em[1769] = 8; em[1770] = 0; /* 1768: pointer.func */
    em[1771] = 8884097; em[1772] = 8; em[1773] = 0; /* 1771: pointer.func */
    em[1774] = 8884097; em[1775] = 8; em[1776] = 0; /* 1774: pointer.func */
    em[1777] = 8884097; em[1778] = 8; em[1779] = 0; /* 1777: pointer.func */
    em[1780] = 8884097; em[1781] = 8; em[1782] = 0; /* 1780: pointer.func */
    em[1783] = 8884097; em[1784] = 8; em[1785] = 0; /* 1783: pointer.func */
    em[1786] = 8884097; em[1787] = 8; em[1788] = 0; /* 1786: pointer.func */
    em[1789] = 8884097; em[1790] = 8; em[1791] = 0; /* 1789: pointer.func */
    em[1792] = 8884097; em[1793] = 8; em[1794] = 0; /* 1792: pointer.func */
    em[1795] = 8884097; em[1796] = 8; em[1797] = 0; /* 1795: pointer.func */
    em[1798] = 8884097; em[1799] = 8; em[1800] = 0; /* 1798: pointer.func */
    em[1801] = 1; em[1802] = 8; em[1803] = 1; /* 1801: pointer.struct.engine_st */
    	em[1804] = 374; em[1805] = 0; 
    em[1806] = 1; em[1807] = 8; em[1808] = 1; /* 1806: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1809] = 1811; em[1810] = 0; 
    em[1811] = 0; em[1812] = 32; em[1813] = 2; /* 1811: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1814] = 1818; em[1815] = 8; 
    	em[1816] = 363; em[1817] = 24; 
    em[1818] = 8884099; em[1819] = 8; em[1820] = 2; /* 1818: pointer_to_array_of_pointers_to_stack */
    	em[1821] = 1825; em[1822] = 0; 
    	em[1823] = 5; em[1824] = 20; 
    em[1825] = 0; em[1826] = 8; em[1827] = 1; /* 1825: pointer.X509_ATTRIBUTE */
    	em[1828] = 1830; em[1829] = 0; 
    em[1830] = 0; em[1831] = 0; em[1832] = 1; /* 1830: X509_ATTRIBUTE */
    	em[1833] = 1835; em[1834] = 0; 
    em[1835] = 0; em[1836] = 24; em[1837] = 2; /* 1835: struct.x509_attributes_st */
    	em[1838] = 135; em[1839] = 0; 
    	em[1840] = 1842; em[1841] = 16; 
    em[1842] = 0; em[1843] = 8; em[1844] = 3; /* 1842: union.unknown */
    	em[1845] = 130; em[1846] = 0; 
    	em[1847] = 339; em[1848] = 0; 
    	em[1849] = 1851; em[1850] = 0; 
    em[1851] = 1; em[1852] = 8; em[1853] = 1; /* 1851: pointer.struct.asn1_type_st */
    	em[1854] = 179; em[1855] = 0; 
    em[1856] = 8884097; em[1857] = 8; em[1858] = 0; /* 1856: pointer.func */
    em[1859] = 8884097; em[1860] = 8; em[1861] = 0; /* 1859: pointer.func */
    em[1862] = 8884097; em[1863] = 8; em[1864] = 0; /* 1862: pointer.func */
    em[1865] = 8884097; em[1866] = 8; em[1867] = 0; /* 1865: pointer.func */
    em[1868] = 8884097; em[1869] = 8; em[1870] = 0; /* 1868: pointer.func */
    em[1871] = 1; em[1872] = 8; em[1873] = 1; /* 1871: pointer.struct.evp_pkey_ctx_st */
    	em[1874] = 1876; em[1875] = 0; 
    em[1876] = 0; em[1877] = 80; em[1878] = 8; /* 1876: struct.evp_pkey_ctx_st */
    	em[1879] = 1895; em[1880] = 0; 
    	em[1881] = 1801; em[1882] = 8; 
    	em[1883] = 1974; em[1884] = 16; 
    	em[1885] = 1974; em[1886] = 24; 
    	em[1887] = 704; em[1888] = 40; 
    	em[1889] = 704; em[1890] = 48; 
    	em[1891] = 8; em[1892] = 56; 
    	em[1893] = 0; em[1894] = 64; 
    em[1895] = 1; em[1896] = 8; em[1897] = 1; /* 1895: pointer.struct.evp_pkey_method_st */
    	em[1898] = 1900; em[1899] = 0; 
    em[1900] = 0; em[1901] = 208; em[1902] = 25; /* 1900: struct.evp_pkey_method_st */
    	em[1903] = 1953; em[1904] = 8; 
    	em[1905] = 1956; em[1906] = 16; 
    	em[1907] = 1868; em[1908] = 24; 
    	em[1909] = 1953; em[1910] = 32; 
    	em[1911] = 1959; em[1912] = 40; 
    	em[1913] = 1953; em[1914] = 48; 
    	em[1915] = 1959; em[1916] = 56; 
    	em[1917] = 1953; em[1918] = 64; 
    	em[1919] = 1865; em[1920] = 72; 
    	em[1921] = 1953; em[1922] = 80; 
    	em[1923] = 1862; em[1924] = 88; 
    	em[1925] = 1953; em[1926] = 96; 
    	em[1927] = 1865; em[1928] = 104; 
    	em[1929] = 1962; em[1930] = 112; 
    	em[1931] = 1859; em[1932] = 120; 
    	em[1933] = 1962; em[1934] = 128; 
    	em[1935] = 1965; em[1936] = 136; 
    	em[1937] = 1953; em[1938] = 144; 
    	em[1939] = 1865; em[1940] = 152; 
    	em[1941] = 1953; em[1942] = 160; 
    	em[1943] = 1865; em[1944] = 168; 
    	em[1945] = 1953; em[1946] = 176; 
    	em[1947] = 1968; em[1948] = 184; 
    	em[1949] = 1971; em[1950] = 192; 
    	em[1951] = 1856; em[1952] = 200; 
    em[1953] = 8884097; em[1954] = 8; em[1955] = 0; /* 1953: pointer.func */
    em[1956] = 8884097; em[1957] = 8; em[1958] = 0; /* 1956: pointer.func */
    em[1959] = 8884097; em[1960] = 8; em[1961] = 0; /* 1959: pointer.func */
    em[1962] = 8884097; em[1963] = 8; em[1964] = 0; /* 1962: pointer.func */
    em[1965] = 8884097; em[1966] = 8; em[1967] = 0; /* 1965: pointer.func */
    em[1968] = 8884097; em[1969] = 8; em[1970] = 0; /* 1968: pointer.func */
    em[1971] = 8884097; em[1972] = 8; em[1973] = 0; /* 1971: pointer.func */
    em[1974] = 1; em[1975] = 8; em[1976] = 1; /* 1974: pointer.struct.evp_pkey_st */
    	em[1977] = 1692; em[1978] = 0; 
    em[1979] = 8884097; em[1980] = 8; em[1981] = 0; /* 1979: pointer.func */
    em[1982] = 0; em[1983] = 48; em[1984] = 5; /* 1982: struct.env_md_ctx_st */
    	em[1985] = 1995; em[1986] = 0; 
    	em[1987] = 1801; em[1988] = 8; 
    	em[1989] = 704; em[1990] = 24; 
    	em[1991] = 1871; em[1992] = 32; 
    	em[1993] = 2022; em[1994] = 40; 
    em[1995] = 1; em[1996] = 8; em[1997] = 1; /* 1995: pointer.struct.env_md_st */
    	em[1998] = 2000; em[1999] = 0; 
    em[2000] = 0; em[2001] = 120; em[2002] = 8; /* 2000: struct.env_md_st */
    	em[2003] = 2019; em[2004] = 24; 
    	em[2005] = 2022; em[2006] = 32; 
    	em[2007] = 2025; em[2008] = 40; 
    	em[2009] = 1979; em[2010] = 48; 
    	em[2011] = 2019; em[2012] = 56; 
    	em[2013] = 2028; em[2014] = 64; 
    	em[2015] = 2031; em[2016] = 72; 
    	em[2017] = 2034; em[2018] = 112; 
    em[2019] = 8884097; em[2020] = 8; em[2021] = 0; /* 2019: pointer.func */
    em[2022] = 8884097; em[2023] = 8; em[2024] = 0; /* 2022: pointer.func */
    em[2025] = 8884097; em[2026] = 8; em[2027] = 0; /* 2025: pointer.func */
    em[2028] = 8884097; em[2029] = 8; em[2030] = 0; /* 2028: pointer.func */
    em[2031] = 8884097; em[2032] = 8; em[2033] = 0; /* 2031: pointer.func */
    em[2034] = 8884097; em[2035] = 8; em[2036] = 0; /* 2034: pointer.func */
    em[2037] = 1; em[2038] = 8; em[2039] = 1; /* 2037: pointer.struct.env_md_ctx_st */
    	em[2040] = 1982; em[2041] = 0; 
    args_addr->arg_entity_index[0] = 2037;
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

