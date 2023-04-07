#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <unistd.h>
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
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 1; em[1] = 8; em[2] = 1; /* 0: pointer.int */
    	em[3] = 5; em[4] = 0; 
    em[5] = 0; em[6] = 4; em[7] = 0; /* 5: int */
    em[8] = 8884097; em[9] = 8; em[10] = 0; /* 8: pointer.func */
    em[11] = 0; em[12] = 0; em[13] = 0; /* 11: struct.ASN1_VALUE_st */
    em[14] = 1; em[15] = 8; em[16] = 1; /* 14: pointer.struct.ASN1_VALUE_st */
    	em[17] = 11; em[18] = 0; 
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
    em[72] = 0; em[73] = 16; em[74] = 1; /* 72: struct.asn1_type_st */
    	em[75] = 77; em[76] = 8; 
    em[77] = 0; em[78] = 8; em[79] = 20; /* 77: union.unknown */
    	em[80] = 120; em[81] = 0; 
    	em[82] = 67; em[83] = 0; 
    	em[84] = 125; em[85] = 0; 
    	em[86] = 149; em[87] = 0; 
    	em[88] = 62; em[89] = 0; 
    	em[90] = 154; em[91] = 0; 
    	em[92] = 57; em[93] = 0; 
    	em[94] = 159; em[95] = 0; 
    	em[96] = 52; em[97] = 0; 
    	em[98] = 47; em[99] = 0; 
    	em[100] = 42; em[101] = 0; 
    	em[102] = 37; em[103] = 0; 
    	em[104] = 164; em[105] = 0; 
    	em[106] = 169; em[107] = 0; 
    	em[108] = 174; em[109] = 0; 
    	em[110] = 179; em[111] = 0; 
    	em[112] = 19; em[113] = 0; 
    	em[114] = 67; em[115] = 0; 
    	em[116] = 67; em[117] = 0; 
    	em[118] = 14; em[119] = 0; 
    em[120] = 1; em[121] = 8; em[122] = 1; /* 120: pointer.char */
    	em[123] = 8884096; em[124] = 0; 
    em[125] = 1; em[126] = 8; em[127] = 1; /* 125: pointer.struct.asn1_object_st */
    	em[128] = 130; em[129] = 0; 
    em[130] = 0; em[131] = 40; em[132] = 3; /* 130: struct.asn1_object_st */
    	em[133] = 139; em[134] = 0; 
    	em[135] = 139; em[136] = 8; 
    	em[137] = 144; em[138] = 24; 
    em[139] = 1; em[140] = 8; em[141] = 1; /* 139: pointer.char */
    	em[142] = 8884096; em[143] = 0; 
    em[144] = 1; em[145] = 8; em[146] = 1; /* 144: pointer.unsigned char */
    	em[147] = 34; em[148] = 0; 
    em[149] = 1; em[150] = 8; em[151] = 1; /* 149: pointer.struct.asn1_string_st */
    	em[152] = 24; em[153] = 0; 
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
    em[179] = 1; em[180] = 8; em[181] = 1; /* 179: pointer.struct.asn1_string_st */
    	em[182] = 24; em[183] = 0; 
    em[184] = 0; em[185] = 0; em[186] = 0; /* 184: struct.ASN1_VALUE_st */
    em[187] = 1; em[188] = 8; em[189] = 1; /* 187: pointer.struct.asn1_string_st */
    	em[190] = 192; em[191] = 0; 
    em[192] = 0; em[193] = 24; em[194] = 1; /* 192: struct.asn1_string_st */
    	em[195] = 29; em[196] = 8; 
    em[197] = 1; em[198] = 8; em[199] = 1; /* 197: pointer.struct.asn1_string_st */
    	em[200] = 192; em[201] = 0; 
    em[202] = 1; em[203] = 8; em[204] = 1; /* 202: pointer.struct.asn1_string_st */
    	em[205] = 192; em[206] = 0; 
    em[207] = 1; em[208] = 8; em[209] = 1; /* 207: pointer.struct.asn1_string_st */
    	em[210] = 192; em[211] = 0; 
    em[212] = 1; em[213] = 8; em[214] = 1; /* 212: pointer.struct.asn1_string_st */
    	em[215] = 192; em[216] = 0; 
    em[217] = 1; em[218] = 8; em[219] = 1; /* 217: pointer.struct.asn1_string_st */
    	em[220] = 192; em[221] = 0; 
    em[222] = 1; em[223] = 8; em[224] = 1; /* 222: pointer.struct.asn1_string_st */
    	em[225] = 192; em[226] = 0; 
    em[227] = 1; em[228] = 8; em[229] = 1; /* 227: pointer.struct.asn1_string_st */
    	em[230] = 192; em[231] = 0; 
    em[232] = 0; em[233] = 0; em[234] = 1; /* 232: ASN1_TYPE */
    	em[235] = 237; em[236] = 0; 
    em[237] = 0; em[238] = 16; em[239] = 1; /* 237: struct.asn1_type_st */
    	em[240] = 242; em[241] = 8; 
    em[242] = 0; em[243] = 8; em[244] = 20; /* 242: union.unknown */
    	em[245] = 120; em[246] = 0; 
    	em[247] = 227; em[248] = 0; 
    	em[249] = 285; em[250] = 0; 
    	em[251] = 222; em[252] = 0; 
    	em[253] = 299; em[254] = 0; 
    	em[255] = 217; em[256] = 0; 
    	em[257] = 304; em[258] = 0; 
    	em[259] = 212; em[260] = 0; 
    	em[261] = 309; em[262] = 0; 
    	em[263] = 207; em[264] = 0; 
    	em[265] = 314; em[266] = 0; 
    	em[267] = 319; em[268] = 0; 
    	em[269] = 324; em[270] = 0; 
    	em[271] = 329; em[272] = 0; 
    	em[273] = 202; em[274] = 0; 
    	em[275] = 197; em[276] = 0; 
    	em[277] = 187; em[278] = 0; 
    	em[279] = 227; em[280] = 0; 
    	em[281] = 227; em[282] = 0; 
    	em[283] = 334; em[284] = 0; 
    em[285] = 1; em[286] = 8; em[287] = 1; /* 285: pointer.struct.asn1_object_st */
    	em[288] = 290; em[289] = 0; 
    em[290] = 0; em[291] = 40; em[292] = 3; /* 290: struct.asn1_object_st */
    	em[293] = 139; em[294] = 0; 
    	em[295] = 139; em[296] = 8; 
    	em[297] = 144; em[298] = 24; 
    em[299] = 1; em[300] = 8; em[301] = 1; /* 299: pointer.struct.asn1_string_st */
    	em[302] = 192; em[303] = 0; 
    em[304] = 1; em[305] = 8; em[306] = 1; /* 304: pointer.struct.asn1_string_st */
    	em[307] = 192; em[308] = 0; 
    em[309] = 1; em[310] = 8; em[311] = 1; /* 309: pointer.struct.asn1_string_st */
    	em[312] = 192; em[313] = 0; 
    em[314] = 1; em[315] = 8; em[316] = 1; /* 314: pointer.struct.asn1_string_st */
    	em[317] = 192; em[318] = 0; 
    em[319] = 1; em[320] = 8; em[321] = 1; /* 319: pointer.struct.asn1_string_st */
    	em[322] = 192; em[323] = 0; 
    em[324] = 1; em[325] = 8; em[326] = 1; /* 324: pointer.struct.asn1_string_st */
    	em[327] = 192; em[328] = 0; 
    em[329] = 1; em[330] = 8; em[331] = 1; /* 329: pointer.struct.asn1_string_st */
    	em[332] = 192; em[333] = 0; 
    em[334] = 1; em[335] = 8; em[336] = 1; /* 334: pointer.struct.ASN1_VALUE_st */
    	em[337] = 184; em[338] = 0; 
    em[339] = 1; em[340] = 8; em[341] = 1; /* 339: pointer.struct.stack_st_ASN1_TYPE */
    	em[342] = 344; em[343] = 0; 
    em[344] = 0; em[345] = 32; em[346] = 2; /* 344: struct.stack_st_fake_ASN1_TYPE */
    	em[347] = 351; em[348] = 8; 
    	em[349] = 363; em[350] = 24; 
    em[351] = 8884099; em[352] = 8; em[353] = 2; /* 351: pointer_to_array_of_pointers_to_stack */
    	em[354] = 358; em[355] = 0; 
    	em[356] = 5; em[357] = 20; 
    em[358] = 0; em[359] = 8; em[360] = 1; /* 358: pointer.ASN1_TYPE */
    	em[361] = 232; em[362] = 0; 
    em[363] = 8884097; em[364] = 8; em[365] = 0; /* 363: pointer.func */
    em[366] = 0; em[367] = 24; em[368] = 2; /* 366: struct.x509_attributes_st */
    	em[369] = 125; em[370] = 0; 
    	em[371] = 373; em[372] = 16; 
    em[373] = 0; em[374] = 8; em[375] = 3; /* 373: union.unknown */
    	em[376] = 120; em[377] = 0; 
    	em[378] = 339; em[379] = 0; 
    	em[380] = 382; em[381] = 0; 
    em[382] = 1; em[383] = 8; em[384] = 1; /* 382: pointer.struct.asn1_type_st */
    	em[385] = 72; em[386] = 0; 
    em[387] = 1; em[388] = 8; em[389] = 1; /* 387: pointer.struct.ec_extra_data_st */
    	em[390] = 392; em[391] = 0; 
    em[392] = 0; em[393] = 40; em[394] = 5; /* 392: struct.ec_extra_data_st */
    	em[395] = 387; em[396] = 0; 
    	em[397] = 405; em[398] = 8; 
    	em[399] = 408; em[400] = 16; 
    	em[401] = 411; em[402] = 24; 
    	em[403] = 411; em[404] = 32; 
    em[405] = 0; em[406] = 8; em[407] = 0; /* 405: pointer.void */
    em[408] = 8884097; em[409] = 8; em[410] = 0; /* 408: pointer.func */
    em[411] = 8884097; em[412] = 8; em[413] = 0; /* 411: pointer.func */
    em[414] = 1; em[415] = 8; em[416] = 1; /* 414: pointer.struct.ec_extra_data_st */
    	em[417] = 392; em[418] = 0; 
    em[419] = 0; em[420] = 24; em[421] = 1; /* 419: struct.bignum_st */
    	em[422] = 424; em[423] = 0; 
    em[424] = 8884099; em[425] = 8; em[426] = 2; /* 424: pointer_to_array_of_pointers_to_stack */
    	em[427] = 431; em[428] = 0; 
    	em[429] = 5; em[430] = 12; 
    em[431] = 0; em[432] = 4; em[433] = 0; /* 431: unsigned int */
    em[434] = 1; em[435] = 8; em[436] = 1; /* 434: pointer.struct.bignum_st */
    	em[437] = 419; em[438] = 0; 
    em[439] = 1; em[440] = 8; em[441] = 1; /* 439: pointer.struct.ec_point_st */
    	em[442] = 444; em[443] = 0; 
    em[444] = 0; em[445] = 88; em[446] = 4; /* 444: struct.ec_point_st */
    	em[447] = 455; em[448] = 0; 
    	em[449] = 627; em[450] = 8; 
    	em[451] = 627; em[452] = 32; 
    	em[453] = 627; em[454] = 56; 
    em[455] = 1; em[456] = 8; em[457] = 1; /* 455: pointer.struct.ec_method_st */
    	em[458] = 460; em[459] = 0; 
    em[460] = 0; em[461] = 304; em[462] = 37; /* 460: struct.ec_method_st */
    	em[463] = 537; em[464] = 8; 
    	em[465] = 540; em[466] = 16; 
    	em[467] = 540; em[468] = 24; 
    	em[469] = 543; em[470] = 32; 
    	em[471] = 546; em[472] = 40; 
    	em[473] = 549; em[474] = 48; 
    	em[475] = 552; em[476] = 56; 
    	em[477] = 555; em[478] = 64; 
    	em[479] = 558; em[480] = 72; 
    	em[481] = 561; em[482] = 80; 
    	em[483] = 561; em[484] = 88; 
    	em[485] = 564; em[486] = 96; 
    	em[487] = 567; em[488] = 104; 
    	em[489] = 570; em[490] = 112; 
    	em[491] = 573; em[492] = 120; 
    	em[493] = 576; em[494] = 128; 
    	em[495] = 579; em[496] = 136; 
    	em[497] = 582; em[498] = 144; 
    	em[499] = 585; em[500] = 152; 
    	em[501] = 588; em[502] = 160; 
    	em[503] = 591; em[504] = 168; 
    	em[505] = 594; em[506] = 176; 
    	em[507] = 597; em[508] = 184; 
    	em[509] = 600; em[510] = 192; 
    	em[511] = 603; em[512] = 200; 
    	em[513] = 606; em[514] = 208; 
    	em[515] = 597; em[516] = 216; 
    	em[517] = 609; em[518] = 224; 
    	em[519] = 612; em[520] = 232; 
    	em[521] = 615; em[522] = 240; 
    	em[523] = 552; em[524] = 248; 
    	em[525] = 618; em[526] = 256; 
    	em[527] = 621; em[528] = 264; 
    	em[529] = 618; em[530] = 272; 
    	em[531] = 621; em[532] = 280; 
    	em[533] = 621; em[534] = 288; 
    	em[535] = 624; em[536] = 296; 
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
    em[606] = 8884097; em[607] = 8; em[608] = 0; /* 606: pointer.func */
    em[609] = 8884097; em[610] = 8; em[611] = 0; /* 609: pointer.func */
    em[612] = 8884097; em[613] = 8; em[614] = 0; /* 612: pointer.func */
    em[615] = 8884097; em[616] = 8; em[617] = 0; /* 615: pointer.func */
    em[618] = 8884097; em[619] = 8; em[620] = 0; /* 618: pointer.func */
    em[621] = 8884097; em[622] = 8; em[623] = 0; /* 621: pointer.func */
    em[624] = 8884097; em[625] = 8; em[626] = 0; /* 624: pointer.func */
    em[627] = 0; em[628] = 24; em[629] = 1; /* 627: struct.bignum_st */
    	em[630] = 632; em[631] = 0; 
    em[632] = 8884099; em[633] = 8; em[634] = 2; /* 632: pointer_to_array_of_pointers_to_stack */
    	em[635] = 431; em[636] = 0; 
    	em[637] = 5; em[638] = 12; 
    em[639] = 8884097; em[640] = 8; em[641] = 0; /* 639: pointer.func */
    em[642] = 8884097; em[643] = 8; em[644] = 0; /* 642: pointer.func */
    em[645] = 0; em[646] = 24; em[647] = 1; /* 645: struct.bignum_st */
    	em[648] = 650; em[649] = 0; 
    em[650] = 8884099; em[651] = 8; em[652] = 2; /* 650: pointer_to_array_of_pointers_to_stack */
    	em[653] = 431; em[654] = 0; 
    	em[655] = 5; em[656] = 12; 
    em[657] = 0; em[658] = 208; em[659] = 24; /* 657: struct.evp_pkey_asn1_method_st */
    	em[660] = 120; em[661] = 16; 
    	em[662] = 120; em[663] = 24; 
    	em[664] = 708; em[665] = 32; 
    	em[666] = 711; em[667] = 40; 
    	em[668] = 714; em[669] = 48; 
    	em[670] = 717; em[671] = 56; 
    	em[672] = 720; em[673] = 64; 
    	em[674] = 723; em[675] = 72; 
    	em[676] = 717; em[677] = 80; 
    	em[678] = 726; em[679] = 88; 
    	em[680] = 726; em[681] = 96; 
    	em[682] = 729; em[683] = 104; 
    	em[684] = 732; em[685] = 112; 
    	em[686] = 726; em[687] = 120; 
    	em[688] = 735; em[689] = 128; 
    	em[690] = 714; em[691] = 136; 
    	em[692] = 717; em[693] = 144; 
    	em[694] = 738; em[695] = 152; 
    	em[696] = 741; em[697] = 160; 
    	em[698] = 744; em[699] = 168; 
    	em[700] = 729; em[701] = 176; 
    	em[702] = 732; em[703] = 184; 
    	em[704] = 747; em[705] = 192; 
    	em[706] = 750; em[707] = 200; 
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
    em[765] = 0; em[766] = 32; em[767] = 2; /* 765: struct.stack_st */
    	em[768] = 772; em[769] = 8; 
    	em[770] = 363; em[771] = 24; 
    em[772] = 1; em[773] = 8; em[774] = 1; /* 772: pointer.pointer.char */
    	em[775] = 120; em[776] = 0; 
    em[777] = 8884097; em[778] = 8; em[779] = 0; /* 777: pointer.func */
    em[780] = 8884097; em[781] = 8; em[782] = 0; /* 780: pointer.func */
    em[783] = 0; em[784] = 112; em[785] = 13; /* 783: struct.rsa_meth_st */
    	em[786] = 139; em[787] = 0; 
    	em[788] = 812; em[789] = 8; 
    	em[790] = 812; em[791] = 16; 
    	em[792] = 812; em[793] = 24; 
    	em[794] = 812; em[795] = 32; 
    	em[796] = 815; em[797] = 40; 
    	em[798] = 818; em[799] = 48; 
    	em[800] = 753; em[801] = 56; 
    	em[802] = 753; em[803] = 64; 
    	em[804] = 120; em[805] = 80; 
    	em[806] = 821; em[807] = 88; 
    	em[808] = 824; em[809] = 96; 
    	em[810] = 642; em[811] = 104; 
    em[812] = 8884097; em[813] = 8; em[814] = 0; /* 812: pointer.func */
    em[815] = 8884097; em[816] = 8; em[817] = 0; /* 815: pointer.func */
    em[818] = 8884097; em[819] = 8; em[820] = 0; /* 818: pointer.func */
    em[821] = 8884097; em[822] = 8; em[823] = 0; /* 821: pointer.func */
    em[824] = 8884097; em[825] = 8; em[826] = 0; /* 824: pointer.func */
    em[827] = 1; em[828] = 8; em[829] = 1; /* 827: pointer.struct.rsa_meth_st */
    	em[830] = 783; em[831] = 0; 
    em[832] = 8884097; em[833] = 8; em[834] = 0; /* 832: pointer.func */
    em[835] = 0; em[836] = 168; em[837] = 17; /* 835: struct.rsa_st */
    	em[838] = 827; em[839] = 16; 
    	em[840] = 872; em[841] = 24; 
    	em[842] = 1211; em[843] = 32; 
    	em[844] = 1211; em[845] = 40; 
    	em[846] = 1211; em[847] = 48; 
    	em[848] = 1211; em[849] = 56; 
    	em[850] = 1211; em[851] = 64; 
    	em[852] = 1211; em[853] = 72; 
    	em[854] = 1211; em[855] = 80; 
    	em[856] = 1211; em[857] = 88; 
    	em[858] = 1216; em[859] = 96; 
    	em[860] = 1231; em[861] = 120; 
    	em[862] = 1231; em[863] = 128; 
    	em[864] = 1231; em[865] = 136; 
    	em[866] = 120; em[867] = 144; 
    	em[868] = 1245; em[869] = 152; 
    	em[870] = 1245; em[871] = 160; 
    em[872] = 1; em[873] = 8; em[874] = 1; /* 872: pointer.struct.engine_st */
    	em[875] = 877; em[876] = 0; 
    em[877] = 0; em[878] = 216; em[879] = 24; /* 877: struct.engine_st */
    	em[880] = 139; em[881] = 0; 
    	em[882] = 139; em[883] = 8; 
    	em[884] = 928; em[885] = 16; 
    	em[886] = 980; em[887] = 24; 
    	em[888] = 1028; em[889] = 32; 
    	em[890] = 1064; em[891] = 40; 
    	em[892] = 1081; em[893] = 48; 
    	em[894] = 1108; em[895] = 56; 
    	em[896] = 1143; em[897] = 64; 
    	em[898] = 1151; em[899] = 72; 
    	em[900] = 1154; em[901] = 80; 
    	em[902] = 1157; em[903] = 88; 
    	em[904] = 1160; em[905] = 96; 
    	em[906] = 1163; em[907] = 104; 
    	em[908] = 1163; em[909] = 112; 
    	em[910] = 1163; em[911] = 120; 
    	em[912] = 1166; em[913] = 128; 
    	em[914] = 832; em[915] = 136; 
    	em[916] = 832; em[917] = 144; 
    	em[918] = 1169; em[919] = 152; 
    	em[920] = 1172; em[921] = 160; 
    	em[922] = 1184; em[923] = 184; 
    	em[924] = 1206; em[925] = 200; 
    	em[926] = 1206; em[927] = 208; 
    em[928] = 1; em[929] = 8; em[930] = 1; /* 928: pointer.struct.rsa_meth_st */
    	em[931] = 933; em[932] = 0; 
    em[933] = 0; em[934] = 112; em[935] = 13; /* 933: struct.rsa_meth_st */
    	em[936] = 139; em[937] = 0; 
    	em[938] = 756; em[939] = 8; 
    	em[940] = 756; em[941] = 16; 
    	em[942] = 756; em[943] = 24; 
    	em[944] = 756; em[945] = 32; 
    	em[946] = 962; em[947] = 40; 
    	em[948] = 965; em[949] = 48; 
    	em[950] = 968; em[951] = 56; 
    	em[952] = 968; em[953] = 64; 
    	em[954] = 120; em[955] = 80; 
    	em[956] = 971; em[957] = 88; 
    	em[958] = 974; em[959] = 96; 
    	em[960] = 977; em[961] = 104; 
    em[962] = 8884097; em[963] = 8; em[964] = 0; /* 962: pointer.func */
    em[965] = 8884097; em[966] = 8; em[967] = 0; /* 965: pointer.func */
    em[968] = 8884097; em[969] = 8; em[970] = 0; /* 968: pointer.func */
    em[971] = 8884097; em[972] = 8; em[973] = 0; /* 971: pointer.func */
    em[974] = 8884097; em[975] = 8; em[976] = 0; /* 974: pointer.func */
    em[977] = 8884097; em[978] = 8; em[979] = 0; /* 977: pointer.func */
    em[980] = 1; em[981] = 8; em[982] = 1; /* 980: pointer.struct.dsa_method */
    	em[983] = 985; em[984] = 0; 
    em[985] = 0; em[986] = 96; em[987] = 11; /* 985: struct.dsa_method */
    	em[988] = 139; em[989] = 0; 
    	em[990] = 759; em[991] = 8; 
    	em[992] = 1010; em[993] = 16; 
    	em[994] = 1013; em[995] = 24; 
    	em[996] = 1016; em[997] = 32; 
    	em[998] = 1019; em[999] = 40; 
    	em[1000] = 1022; em[1001] = 48; 
    	em[1002] = 1022; em[1003] = 56; 
    	em[1004] = 120; em[1005] = 72; 
    	em[1006] = 1025; em[1007] = 80; 
    	em[1008] = 1022; em[1009] = 88; 
    em[1010] = 8884097; em[1011] = 8; em[1012] = 0; /* 1010: pointer.func */
    em[1013] = 8884097; em[1014] = 8; em[1015] = 0; /* 1013: pointer.func */
    em[1016] = 8884097; em[1017] = 8; em[1018] = 0; /* 1016: pointer.func */
    em[1019] = 8884097; em[1020] = 8; em[1021] = 0; /* 1019: pointer.func */
    em[1022] = 8884097; em[1023] = 8; em[1024] = 0; /* 1022: pointer.func */
    em[1025] = 8884097; em[1026] = 8; em[1027] = 0; /* 1025: pointer.func */
    em[1028] = 1; em[1029] = 8; em[1030] = 1; /* 1028: pointer.struct.dh_method */
    	em[1031] = 1033; em[1032] = 0; 
    em[1033] = 0; em[1034] = 72; em[1035] = 8; /* 1033: struct.dh_method */
    	em[1036] = 139; em[1037] = 0; 
    	em[1038] = 1052; em[1039] = 8; 
    	em[1040] = 1055; em[1041] = 16; 
    	em[1042] = 1058; em[1043] = 24; 
    	em[1044] = 1052; em[1045] = 32; 
    	em[1046] = 1052; em[1047] = 40; 
    	em[1048] = 120; em[1049] = 56; 
    	em[1050] = 1061; em[1051] = 64; 
    em[1052] = 8884097; em[1053] = 8; em[1054] = 0; /* 1052: pointer.func */
    em[1055] = 8884097; em[1056] = 8; em[1057] = 0; /* 1055: pointer.func */
    em[1058] = 8884097; em[1059] = 8; em[1060] = 0; /* 1058: pointer.func */
    em[1061] = 8884097; em[1062] = 8; em[1063] = 0; /* 1061: pointer.func */
    em[1064] = 1; em[1065] = 8; em[1066] = 1; /* 1064: pointer.struct.ecdh_method */
    	em[1067] = 1069; em[1068] = 0; 
    em[1069] = 0; em[1070] = 32; em[1071] = 3; /* 1069: struct.ecdh_method */
    	em[1072] = 139; em[1073] = 0; 
    	em[1074] = 1078; em[1075] = 8; 
    	em[1076] = 120; em[1077] = 24; 
    em[1078] = 8884097; em[1079] = 8; em[1080] = 0; /* 1078: pointer.func */
    em[1081] = 1; em[1082] = 8; em[1083] = 1; /* 1081: pointer.struct.ecdsa_method */
    	em[1084] = 1086; em[1085] = 0; 
    em[1086] = 0; em[1087] = 48; em[1088] = 5; /* 1086: struct.ecdsa_method */
    	em[1089] = 139; em[1090] = 0; 
    	em[1091] = 1099; em[1092] = 8; 
    	em[1093] = 1102; em[1094] = 16; 
    	em[1095] = 1105; em[1096] = 24; 
    	em[1097] = 120; em[1098] = 40; 
    em[1099] = 8884097; em[1100] = 8; em[1101] = 0; /* 1099: pointer.func */
    em[1102] = 8884097; em[1103] = 8; em[1104] = 0; /* 1102: pointer.func */
    em[1105] = 8884097; em[1106] = 8; em[1107] = 0; /* 1105: pointer.func */
    em[1108] = 1; em[1109] = 8; em[1110] = 1; /* 1108: pointer.struct.rand_meth_st */
    	em[1111] = 1113; em[1112] = 0; 
    em[1113] = 0; em[1114] = 48; em[1115] = 6; /* 1113: struct.rand_meth_st */
    	em[1116] = 1128; em[1117] = 0; 
    	em[1118] = 1131; em[1119] = 8; 
    	em[1120] = 1134; em[1121] = 16; 
    	em[1122] = 1137; em[1123] = 24; 
    	em[1124] = 1131; em[1125] = 32; 
    	em[1126] = 1140; em[1127] = 40; 
    em[1128] = 8884097; em[1129] = 8; em[1130] = 0; /* 1128: pointer.func */
    em[1131] = 8884097; em[1132] = 8; em[1133] = 0; /* 1131: pointer.func */
    em[1134] = 8884097; em[1135] = 8; em[1136] = 0; /* 1134: pointer.func */
    em[1137] = 8884097; em[1138] = 8; em[1139] = 0; /* 1137: pointer.func */
    em[1140] = 8884097; em[1141] = 8; em[1142] = 0; /* 1140: pointer.func */
    em[1143] = 1; em[1144] = 8; em[1145] = 1; /* 1143: pointer.struct.store_method_st */
    	em[1146] = 1148; em[1147] = 0; 
    em[1148] = 0; em[1149] = 0; em[1150] = 0; /* 1148: struct.store_method_st */
    em[1151] = 8884097; em[1152] = 8; em[1153] = 0; /* 1151: pointer.func */
    em[1154] = 8884097; em[1155] = 8; em[1156] = 0; /* 1154: pointer.func */
    em[1157] = 8884097; em[1158] = 8; em[1159] = 0; /* 1157: pointer.func */
    em[1160] = 8884097; em[1161] = 8; em[1162] = 0; /* 1160: pointer.func */
    em[1163] = 8884097; em[1164] = 8; em[1165] = 0; /* 1163: pointer.func */
    em[1166] = 8884097; em[1167] = 8; em[1168] = 0; /* 1166: pointer.func */
    em[1169] = 8884097; em[1170] = 8; em[1171] = 0; /* 1169: pointer.func */
    em[1172] = 1; em[1173] = 8; em[1174] = 1; /* 1172: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[1175] = 1177; em[1176] = 0; 
    em[1177] = 0; em[1178] = 32; em[1179] = 2; /* 1177: struct.ENGINE_CMD_DEFN_st */
    	em[1180] = 139; em[1181] = 8; 
    	em[1182] = 139; em[1183] = 16; 
    em[1184] = 0; em[1185] = 16; em[1186] = 1; /* 1184: struct.crypto_ex_data_st */
    	em[1187] = 1189; em[1188] = 0; 
    em[1189] = 1; em[1190] = 8; em[1191] = 1; /* 1189: pointer.struct.stack_st_void */
    	em[1192] = 1194; em[1193] = 0; 
    em[1194] = 0; em[1195] = 32; em[1196] = 1; /* 1194: struct.stack_st_void */
    	em[1197] = 1199; em[1198] = 0; 
    em[1199] = 0; em[1200] = 32; em[1201] = 2; /* 1199: struct.stack_st */
    	em[1202] = 772; em[1203] = 8; 
    	em[1204] = 363; em[1205] = 24; 
    em[1206] = 1; em[1207] = 8; em[1208] = 1; /* 1206: pointer.struct.engine_st */
    	em[1209] = 877; em[1210] = 0; 
    em[1211] = 1; em[1212] = 8; em[1213] = 1; /* 1211: pointer.struct.bignum_st */
    	em[1214] = 645; em[1215] = 0; 
    em[1216] = 0; em[1217] = 16; em[1218] = 1; /* 1216: struct.crypto_ex_data_st */
    	em[1219] = 1221; em[1220] = 0; 
    em[1221] = 1; em[1222] = 8; em[1223] = 1; /* 1221: pointer.struct.stack_st_void */
    	em[1224] = 1226; em[1225] = 0; 
    em[1226] = 0; em[1227] = 32; em[1228] = 1; /* 1226: struct.stack_st_void */
    	em[1229] = 765; em[1230] = 0; 
    em[1231] = 1; em[1232] = 8; em[1233] = 1; /* 1231: pointer.struct.bn_mont_ctx_st */
    	em[1234] = 1236; em[1235] = 0; 
    em[1236] = 0; em[1237] = 96; em[1238] = 3; /* 1236: struct.bn_mont_ctx_st */
    	em[1239] = 645; em[1240] = 8; 
    	em[1241] = 645; em[1242] = 32; 
    	em[1243] = 645; em[1244] = 56; 
    em[1245] = 1; em[1246] = 8; em[1247] = 1; /* 1245: pointer.struct.bn_blinding_st */
    	em[1248] = 1250; em[1249] = 0; 
    em[1250] = 0; em[1251] = 88; em[1252] = 7; /* 1250: struct.bn_blinding_st */
    	em[1253] = 1267; em[1254] = 0; 
    	em[1255] = 1267; em[1256] = 8; 
    	em[1257] = 1267; em[1258] = 16; 
    	em[1259] = 1267; em[1260] = 24; 
    	em[1261] = 1284; em[1262] = 40; 
    	em[1263] = 1289; em[1264] = 72; 
    	em[1265] = 1303; em[1266] = 80; 
    em[1267] = 1; em[1268] = 8; em[1269] = 1; /* 1267: pointer.struct.bignum_st */
    	em[1270] = 1272; em[1271] = 0; 
    em[1272] = 0; em[1273] = 24; em[1274] = 1; /* 1272: struct.bignum_st */
    	em[1275] = 1277; em[1276] = 0; 
    em[1277] = 8884099; em[1278] = 8; em[1279] = 2; /* 1277: pointer_to_array_of_pointers_to_stack */
    	em[1280] = 431; em[1281] = 0; 
    	em[1282] = 5; em[1283] = 12; 
    em[1284] = 0; em[1285] = 16; em[1286] = 1; /* 1284: struct.crypto_threadid_st */
    	em[1287] = 405; em[1288] = 0; 
    em[1289] = 1; em[1290] = 8; em[1291] = 1; /* 1289: pointer.struct.bn_mont_ctx_st */
    	em[1292] = 1294; em[1293] = 0; 
    em[1294] = 0; em[1295] = 96; em[1296] = 3; /* 1294: struct.bn_mont_ctx_st */
    	em[1297] = 1272; em[1298] = 8; 
    	em[1299] = 1272; em[1300] = 32; 
    	em[1301] = 1272; em[1302] = 56; 
    em[1303] = 8884097; em[1304] = 8; em[1305] = 0; /* 1303: pointer.func */
    em[1306] = 8884097; em[1307] = 8; em[1308] = 0; /* 1306: pointer.func */
    em[1309] = 8884097; em[1310] = 8; em[1311] = 0; /* 1309: pointer.func */
    em[1312] = 1; em[1313] = 8; em[1314] = 1; /* 1312: pointer.struct.dh_method */
    	em[1315] = 1317; em[1316] = 0; 
    em[1317] = 0; em[1318] = 72; em[1319] = 8; /* 1317: struct.dh_method */
    	em[1320] = 139; em[1321] = 0; 
    	em[1322] = 1336; em[1323] = 8; 
    	em[1324] = 1339; em[1325] = 16; 
    	em[1326] = 1342; em[1327] = 24; 
    	em[1328] = 1336; em[1329] = 32; 
    	em[1330] = 1336; em[1331] = 40; 
    	em[1332] = 120; em[1333] = 56; 
    	em[1334] = 1345; em[1335] = 64; 
    em[1336] = 8884097; em[1337] = 8; em[1338] = 0; /* 1336: pointer.func */
    em[1339] = 8884097; em[1340] = 8; em[1341] = 0; /* 1339: pointer.func */
    em[1342] = 8884097; em[1343] = 8; em[1344] = 0; /* 1342: pointer.func */
    em[1345] = 8884097; em[1346] = 8; em[1347] = 0; /* 1345: pointer.func */
    em[1348] = 0; em[1349] = 56; em[1350] = 4; /* 1348: struct.evp_pkey_st */
    	em[1351] = 1359; em[1352] = 16; 
    	em[1353] = 1364; em[1354] = 24; 
    	em[1355] = 1369; em[1356] = 32; 
    	em[1357] = 1862; em[1358] = 48; 
    em[1359] = 1; em[1360] = 8; em[1361] = 1; /* 1359: pointer.struct.evp_pkey_asn1_method_st */
    	em[1362] = 657; em[1363] = 0; 
    em[1364] = 1; em[1365] = 8; em[1366] = 1; /* 1364: pointer.struct.engine_st */
    	em[1367] = 877; em[1368] = 0; 
    em[1369] = 0; em[1370] = 8; em[1371] = 5; /* 1369: union.unknown */
    	em[1372] = 120; em[1373] = 0; 
    	em[1374] = 1382; em[1375] = 0; 
    	em[1376] = 1387; em[1377] = 0; 
    	em[1378] = 1526; em[1379] = 0; 
    	em[1380] = 1611; em[1381] = 0; 
    em[1382] = 1; em[1383] = 8; em[1384] = 1; /* 1382: pointer.struct.rsa_st */
    	em[1385] = 835; em[1386] = 0; 
    em[1387] = 1; em[1388] = 8; em[1389] = 1; /* 1387: pointer.struct.dsa_st */
    	em[1390] = 1392; em[1391] = 0; 
    em[1392] = 0; em[1393] = 136; em[1394] = 11; /* 1392: struct.dsa_st */
    	em[1395] = 1417; em[1396] = 24; 
    	em[1397] = 1417; em[1398] = 32; 
    	em[1399] = 1417; em[1400] = 40; 
    	em[1401] = 1417; em[1402] = 48; 
    	em[1403] = 1417; em[1404] = 56; 
    	em[1405] = 1417; em[1406] = 64; 
    	em[1407] = 1417; em[1408] = 72; 
    	em[1409] = 1434; em[1410] = 88; 
    	em[1411] = 1448; em[1412] = 104; 
    	em[1413] = 1470; em[1414] = 120; 
    	em[1415] = 1521; em[1416] = 128; 
    em[1417] = 1; em[1418] = 8; em[1419] = 1; /* 1417: pointer.struct.bignum_st */
    	em[1420] = 1422; em[1421] = 0; 
    em[1422] = 0; em[1423] = 24; em[1424] = 1; /* 1422: struct.bignum_st */
    	em[1425] = 1427; em[1426] = 0; 
    em[1427] = 8884099; em[1428] = 8; em[1429] = 2; /* 1427: pointer_to_array_of_pointers_to_stack */
    	em[1430] = 431; em[1431] = 0; 
    	em[1432] = 5; em[1433] = 12; 
    em[1434] = 1; em[1435] = 8; em[1436] = 1; /* 1434: pointer.struct.bn_mont_ctx_st */
    	em[1437] = 1439; em[1438] = 0; 
    em[1439] = 0; em[1440] = 96; em[1441] = 3; /* 1439: struct.bn_mont_ctx_st */
    	em[1442] = 1422; em[1443] = 8; 
    	em[1444] = 1422; em[1445] = 32; 
    	em[1446] = 1422; em[1447] = 56; 
    em[1448] = 0; em[1449] = 16; em[1450] = 1; /* 1448: struct.crypto_ex_data_st */
    	em[1451] = 1453; em[1452] = 0; 
    em[1453] = 1; em[1454] = 8; em[1455] = 1; /* 1453: pointer.struct.stack_st_void */
    	em[1456] = 1458; em[1457] = 0; 
    em[1458] = 0; em[1459] = 32; em[1460] = 1; /* 1458: struct.stack_st_void */
    	em[1461] = 1463; em[1462] = 0; 
    em[1463] = 0; em[1464] = 32; em[1465] = 2; /* 1463: struct.stack_st */
    	em[1466] = 772; em[1467] = 8; 
    	em[1468] = 363; em[1469] = 24; 
    em[1470] = 1; em[1471] = 8; em[1472] = 1; /* 1470: pointer.struct.dsa_method */
    	em[1473] = 1475; em[1474] = 0; 
    em[1475] = 0; em[1476] = 96; em[1477] = 11; /* 1475: struct.dsa_method */
    	em[1478] = 139; em[1479] = 0; 
    	em[1480] = 1500; em[1481] = 8; 
    	em[1482] = 1503; em[1483] = 16; 
    	em[1484] = 1506; em[1485] = 24; 
    	em[1486] = 1509; em[1487] = 32; 
    	em[1488] = 1512; em[1489] = 40; 
    	em[1490] = 1515; em[1491] = 48; 
    	em[1492] = 1515; em[1493] = 56; 
    	em[1494] = 120; em[1495] = 72; 
    	em[1496] = 1518; em[1497] = 80; 
    	em[1498] = 1515; em[1499] = 88; 
    em[1500] = 8884097; em[1501] = 8; em[1502] = 0; /* 1500: pointer.func */
    em[1503] = 8884097; em[1504] = 8; em[1505] = 0; /* 1503: pointer.func */
    em[1506] = 8884097; em[1507] = 8; em[1508] = 0; /* 1506: pointer.func */
    em[1509] = 8884097; em[1510] = 8; em[1511] = 0; /* 1509: pointer.func */
    em[1512] = 8884097; em[1513] = 8; em[1514] = 0; /* 1512: pointer.func */
    em[1515] = 8884097; em[1516] = 8; em[1517] = 0; /* 1515: pointer.func */
    em[1518] = 8884097; em[1519] = 8; em[1520] = 0; /* 1518: pointer.func */
    em[1521] = 1; em[1522] = 8; em[1523] = 1; /* 1521: pointer.struct.engine_st */
    	em[1524] = 877; em[1525] = 0; 
    em[1526] = 1; em[1527] = 8; em[1528] = 1; /* 1526: pointer.struct.dh_st */
    	em[1529] = 1531; em[1530] = 0; 
    em[1531] = 0; em[1532] = 144; em[1533] = 12; /* 1531: struct.dh_st */
    	em[1534] = 1558; em[1535] = 8; 
    	em[1536] = 1558; em[1537] = 16; 
    	em[1538] = 1558; em[1539] = 32; 
    	em[1540] = 1558; em[1541] = 40; 
    	em[1542] = 1575; em[1543] = 56; 
    	em[1544] = 1558; em[1545] = 64; 
    	em[1546] = 1558; em[1547] = 72; 
    	em[1548] = 29; em[1549] = 80; 
    	em[1550] = 1558; em[1551] = 96; 
    	em[1552] = 1589; em[1553] = 112; 
    	em[1554] = 1312; em[1555] = 128; 
    	em[1556] = 1364; em[1557] = 136; 
    em[1558] = 1; em[1559] = 8; em[1560] = 1; /* 1558: pointer.struct.bignum_st */
    	em[1561] = 1563; em[1562] = 0; 
    em[1563] = 0; em[1564] = 24; em[1565] = 1; /* 1563: struct.bignum_st */
    	em[1566] = 1568; em[1567] = 0; 
    em[1568] = 8884099; em[1569] = 8; em[1570] = 2; /* 1568: pointer_to_array_of_pointers_to_stack */
    	em[1571] = 431; em[1572] = 0; 
    	em[1573] = 5; em[1574] = 12; 
    em[1575] = 1; em[1576] = 8; em[1577] = 1; /* 1575: pointer.struct.bn_mont_ctx_st */
    	em[1578] = 1580; em[1579] = 0; 
    em[1580] = 0; em[1581] = 96; em[1582] = 3; /* 1580: struct.bn_mont_ctx_st */
    	em[1583] = 1563; em[1584] = 8; 
    	em[1585] = 1563; em[1586] = 32; 
    	em[1587] = 1563; em[1588] = 56; 
    em[1589] = 0; em[1590] = 16; em[1591] = 1; /* 1589: struct.crypto_ex_data_st */
    	em[1592] = 1594; em[1593] = 0; 
    em[1594] = 1; em[1595] = 8; em[1596] = 1; /* 1594: pointer.struct.stack_st_void */
    	em[1597] = 1599; em[1598] = 0; 
    em[1599] = 0; em[1600] = 32; em[1601] = 1; /* 1599: struct.stack_st_void */
    	em[1602] = 1604; em[1603] = 0; 
    em[1604] = 0; em[1605] = 32; em[1606] = 2; /* 1604: struct.stack_st */
    	em[1607] = 772; em[1608] = 8; 
    	em[1609] = 363; em[1610] = 24; 
    em[1611] = 1; em[1612] = 8; em[1613] = 1; /* 1611: pointer.struct.ec_key_st */
    	em[1614] = 1616; em[1615] = 0; 
    em[1616] = 0; em[1617] = 56; em[1618] = 4; /* 1616: struct.ec_key_st */
    	em[1619] = 1627; em[1620] = 8; 
    	em[1621] = 439; em[1622] = 16; 
    	em[1623] = 434; em[1624] = 24; 
    	em[1625] = 414; em[1626] = 48; 
    em[1627] = 1; em[1628] = 8; em[1629] = 1; /* 1627: pointer.struct.ec_group_st */
    	em[1630] = 1632; em[1631] = 0; 
    em[1632] = 0; em[1633] = 232; em[1634] = 12; /* 1632: struct.ec_group_st */
    	em[1635] = 1659; em[1636] = 0; 
    	em[1637] = 1822; em[1638] = 8; 
    	em[1639] = 1827; em[1640] = 16; 
    	em[1641] = 1827; em[1642] = 40; 
    	em[1643] = 29; em[1644] = 80; 
    	em[1645] = 1839; em[1646] = 96; 
    	em[1647] = 1827; em[1648] = 104; 
    	em[1649] = 1827; em[1650] = 152; 
    	em[1651] = 1827; em[1652] = 176; 
    	em[1653] = 405; em[1654] = 208; 
    	em[1655] = 405; em[1656] = 216; 
    	em[1657] = 639; em[1658] = 224; 
    em[1659] = 1; em[1660] = 8; em[1661] = 1; /* 1659: pointer.struct.ec_method_st */
    	em[1662] = 1664; em[1663] = 0; 
    em[1664] = 0; em[1665] = 304; em[1666] = 37; /* 1664: struct.ec_method_st */
    	em[1667] = 1741; em[1668] = 8; 
    	em[1669] = 1744; em[1670] = 16; 
    	em[1671] = 1744; em[1672] = 24; 
    	em[1673] = 1747; em[1674] = 32; 
    	em[1675] = 1309; em[1676] = 40; 
    	em[1677] = 1750; em[1678] = 48; 
    	em[1679] = 1753; em[1680] = 56; 
    	em[1681] = 1756; em[1682] = 64; 
    	em[1683] = 1759; em[1684] = 72; 
    	em[1685] = 1762; em[1686] = 80; 
    	em[1687] = 1762; em[1688] = 88; 
    	em[1689] = 1765; em[1690] = 96; 
    	em[1691] = 1768; em[1692] = 104; 
    	em[1693] = 1771; em[1694] = 112; 
    	em[1695] = 1774; em[1696] = 120; 
    	em[1697] = 1777; em[1698] = 128; 
    	em[1699] = 1780; em[1700] = 136; 
    	em[1701] = 777; em[1702] = 144; 
    	em[1703] = 1783; em[1704] = 152; 
    	em[1705] = 1786; em[1706] = 160; 
    	em[1707] = 1789; em[1708] = 168; 
    	em[1709] = 1792; em[1710] = 176; 
    	em[1711] = 1795; em[1712] = 184; 
    	em[1713] = 1798; em[1714] = 192; 
    	em[1715] = 1801; em[1716] = 200; 
    	em[1717] = 1804; em[1718] = 208; 
    	em[1719] = 1795; em[1720] = 216; 
    	em[1721] = 780; em[1722] = 224; 
    	em[1723] = 1807; em[1724] = 232; 
    	em[1725] = 1810; em[1726] = 240; 
    	em[1727] = 1753; em[1728] = 248; 
    	em[1729] = 1813; em[1730] = 256; 
    	em[1731] = 1816; em[1732] = 264; 
    	em[1733] = 1813; em[1734] = 272; 
    	em[1735] = 1816; em[1736] = 280; 
    	em[1737] = 1816; em[1738] = 288; 
    	em[1739] = 1819; em[1740] = 296; 
    em[1741] = 8884097; em[1742] = 8; em[1743] = 0; /* 1741: pointer.func */
    em[1744] = 8884097; em[1745] = 8; em[1746] = 0; /* 1744: pointer.func */
    em[1747] = 8884097; em[1748] = 8; em[1749] = 0; /* 1747: pointer.func */
    em[1750] = 8884097; em[1751] = 8; em[1752] = 0; /* 1750: pointer.func */
    em[1753] = 8884097; em[1754] = 8; em[1755] = 0; /* 1753: pointer.func */
    em[1756] = 8884097; em[1757] = 8; em[1758] = 0; /* 1756: pointer.func */
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
    em[1801] = 8884097; em[1802] = 8; em[1803] = 0; /* 1801: pointer.func */
    em[1804] = 8884097; em[1805] = 8; em[1806] = 0; /* 1804: pointer.func */
    em[1807] = 8884097; em[1808] = 8; em[1809] = 0; /* 1807: pointer.func */
    em[1810] = 8884097; em[1811] = 8; em[1812] = 0; /* 1810: pointer.func */
    em[1813] = 8884097; em[1814] = 8; em[1815] = 0; /* 1813: pointer.func */
    em[1816] = 8884097; em[1817] = 8; em[1818] = 0; /* 1816: pointer.func */
    em[1819] = 8884097; em[1820] = 8; em[1821] = 0; /* 1819: pointer.func */
    em[1822] = 1; em[1823] = 8; em[1824] = 1; /* 1822: pointer.struct.ec_point_st */
    	em[1825] = 444; em[1826] = 0; 
    em[1827] = 0; em[1828] = 24; em[1829] = 1; /* 1827: struct.bignum_st */
    	em[1830] = 1832; em[1831] = 0; 
    em[1832] = 8884099; em[1833] = 8; em[1834] = 2; /* 1832: pointer_to_array_of_pointers_to_stack */
    	em[1835] = 431; em[1836] = 0; 
    	em[1837] = 5; em[1838] = 12; 
    em[1839] = 1; em[1840] = 8; em[1841] = 1; /* 1839: pointer.struct.ec_extra_data_st */
    	em[1842] = 1844; em[1843] = 0; 
    em[1844] = 0; em[1845] = 40; em[1846] = 5; /* 1844: struct.ec_extra_data_st */
    	em[1847] = 1857; em[1848] = 0; 
    	em[1849] = 405; em[1850] = 8; 
    	em[1851] = 408; em[1852] = 16; 
    	em[1853] = 411; em[1854] = 24; 
    	em[1855] = 411; em[1856] = 32; 
    em[1857] = 1; em[1858] = 8; em[1859] = 1; /* 1857: pointer.struct.ec_extra_data_st */
    	em[1860] = 1844; em[1861] = 0; 
    em[1862] = 1; em[1863] = 8; em[1864] = 1; /* 1862: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1865] = 1867; em[1866] = 0; 
    em[1867] = 0; em[1868] = 32; em[1869] = 2; /* 1867: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1870] = 1874; em[1871] = 8; 
    	em[1872] = 363; em[1873] = 24; 
    em[1874] = 8884099; em[1875] = 8; em[1876] = 2; /* 1874: pointer_to_array_of_pointers_to_stack */
    	em[1877] = 1881; em[1878] = 0; 
    	em[1879] = 5; em[1880] = 20; 
    em[1881] = 0; em[1882] = 8; em[1883] = 1; /* 1881: pointer.X509_ATTRIBUTE */
    	em[1884] = 1886; em[1885] = 0; 
    em[1886] = 0; em[1887] = 0; em[1888] = 1; /* 1886: X509_ATTRIBUTE */
    	em[1889] = 366; em[1890] = 0; 
    em[1891] = 1; em[1892] = 8; em[1893] = 1; /* 1891: pointer.struct.evp_pkey_st */
    	em[1894] = 1348; em[1895] = 0; 
    em[1896] = 8884097; em[1897] = 8; em[1898] = 0; /* 1896: pointer.func */
    em[1899] = 8884097; em[1900] = 8; em[1901] = 0; /* 1899: pointer.func */
    em[1902] = 8884097; em[1903] = 8; em[1904] = 0; /* 1902: pointer.func */
    em[1905] = 0; em[1906] = 1; em[1907] = 0; /* 1905: char */
    em[1908] = 8884097; em[1909] = 8; em[1910] = 0; /* 1908: pointer.func */
    em[1911] = 8884097; em[1912] = 8; em[1913] = 0; /* 1911: pointer.func */
    em[1914] = 8884097; em[1915] = 8; em[1916] = 0; /* 1914: pointer.func */
    em[1917] = 8884097; em[1918] = 8; em[1919] = 0; /* 1917: pointer.func */
    em[1920] = 8884097; em[1921] = 8; em[1922] = 0; /* 1920: pointer.func */
    em[1923] = 8884097; em[1924] = 8; em[1925] = 0; /* 1923: pointer.func */
    em[1926] = 0; em[1927] = 120; em[1928] = 8; /* 1926: struct.env_md_st */
    	em[1929] = 1923; em[1930] = 24; 
    	em[1931] = 1945; em[1932] = 32; 
    	em[1933] = 1920; em[1934] = 40; 
    	em[1935] = 762; em[1936] = 48; 
    	em[1937] = 1923; em[1938] = 56; 
    	em[1939] = 1948; em[1940] = 64; 
    	em[1941] = 1306; em[1942] = 72; 
    	em[1943] = 1917; em[1944] = 112; 
    em[1945] = 8884097; em[1946] = 8; em[1947] = 0; /* 1945: pointer.func */
    em[1948] = 8884097; em[1949] = 8; em[1950] = 0; /* 1948: pointer.func */
    em[1951] = 0; em[1952] = 48; em[1953] = 5; /* 1951: struct.env_md_ctx_st */
    	em[1954] = 1964; em[1955] = 0; 
    	em[1956] = 1364; em[1957] = 8; 
    	em[1958] = 405; em[1959] = 24; 
    	em[1960] = 1969; em[1961] = 32; 
    	em[1962] = 1945; em[1963] = 40; 
    em[1964] = 1; em[1965] = 8; em[1966] = 1; /* 1964: pointer.struct.env_md_st */
    	em[1967] = 1926; em[1968] = 0; 
    em[1969] = 1; em[1970] = 8; em[1971] = 1; /* 1969: pointer.struct.evp_pkey_ctx_st */
    	em[1972] = 1974; em[1973] = 0; 
    em[1974] = 0; em[1975] = 80; em[1976] = 8; /* 1974: struct.evp_pkey_ctx_st */
    	em[1977] = 1993; em[1978] = 0; 
    	em[1979] = 1364; em[1980] = 8; 
    	em[1981] = 1891; em[1982] = 16; 
    	em[1983] = 1891; em[1984] = 24; 
    	em[1985] = 405; em[1986] = 40; 
    	em[1987] = 405; em[1988] = 48; 
    	em[1989] = 8; em[1990] = 56; 
    	em[1991] = 0; em[1992] = 64; 
    em[1993] = 1; em[1994] = 8; em[1995] = 1; /* 1993: pointer.struct.evp_pkey_method_st */
    	em[1996] = 1998; em[1997] = 0; 
    em[1998] = 0; em[1999] = 208; em[2000] = 25; /* 1998: struct.evp_pkey_method_st */
    	em[2001] = 1914; em[2002] = 8; 
    	em[2003] = 2051; em[2004] = 16; 
    	em[2005] = 2054; em[2006] = 24; 
    	em[2007] = 1914; em[2008] = 32; 
    	em[2009] = 1902; em[2010] = 40; 
    	em[2011] = 1914; em[2012] = 48; 
    	em[2013] = 1902; em[2014] = 56; 
    	em[2015] = 1914; em[2016] = 64; 
    	em[2017] = 2057; em[2018] = 72; 
    	em[2019] = 1914; em[2020] = 80; 
    	em[2021] = 2060; em[2022] = 88; 
    	em[2023] = 1914; em[2024] = 96; 
    	em[2025] = 2057; em[2026] = 104; 
    	em[2027] = 2063; em[2028] = 112; 
    	em[2029] = 1911; em[2030] = 120; 
    	em[2031] = 2063; em[2032] = 128; 
    	em[2033] = 2066; em[2034] = 136; 
    	em[2035] = 1914; em[2036] = 144; 
    	em[2037] = 2057; em[2038] = 152; 
    	em[2039] = 1914; em[2040] = 160; 
    	em[2041] = 2057; em[2042] = 168; 
    	em[2043] = 1914; em[2044] = 176; 
    	em[2045] = 1908; em[2046] = 184; 
    	em[2047] = 1899; em[2048] = 192; 
    	em[2049] = 1896; em[2050] = 200; 
    em[2051] = 8884097; em[2052] = 8; em[2053] = 0; /* 2051: pointer.func */
    em[2054] = 8884097; em[2055] = 8; em[2056] = 0; /* 2054: pointer.func */
    em[2057] = 8884097; em[2058] = 8; em[2059] = 0; /* 2057: pointer.func */
    em[2060] = 8884097; em[2061] = 8; em[2062] = 0; /* 2060: pointer.func */
    em[2063] = 8884097; em[2064] = 8; em[2065] = 0; /* 2063: pointer.func */
    em[2066] = 8884097; em[2067] = 8; em[2068] = 0; /* 2066: pointer.func */
    em[2069] = 1; em[2070] = 8; em[2071] = 1; /* 2069: pointer.struct.env_md_ctx_st */
    	em[2072] = 1951; em[2073] = 0; 
    args_addr->arg_entity_index[0] = 2069;
    args_addr->arg_entity_index[1] = 1964;
    args_addr->arg_entity_index[2] = 1364;
    args_addr->ret_entity_index = 5;
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

