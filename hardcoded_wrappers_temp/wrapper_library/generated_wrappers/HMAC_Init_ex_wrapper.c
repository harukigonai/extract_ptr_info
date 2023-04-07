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
    em[645] = 8884097; em[646] = 8; em[647] = 0; /* 645: pointer.func */
    em[648] = 8884097; em[649] = 8; em[650] = 0; /* 648: pointer.func */
    em[651] = 0; em[652] = 32; em[653] = 2; /* 651: struct.stack_st */
    	em[654] = 658; em[655] = 8; 
    	em[656] = 363; em[657] = 24; 
    em[658] = 1; em[659] = 8; em[660] = 1; /* 658: pointer.pointer.char */
    	em[661] = 120; em[662] = 0; 
    em[663] = 8884097; em[664] = 8; em[665] = 0; /* 663: pointer.func */
    em[666] = 8884097; em[667] = 8; em[668] = 0; /* 666: pointer.func */
    em[669] = 0; em[670] = 112; em[671] = 13; /* 669: struct.rsa_meth_st */
    	em[672] = 139; em[673] = 0; 
    	em[674] = 698; em[675] = 8; 
    	em[676] = 698; em[677] = 16; 
    	em[678] = 698; em[679] = 24; 
    	em[680] = 698; em[681] = 32; 
    	em[682] = 701; em[683] = 40; 
    	em[684] = 704; em[685] = 48; 
    	em[686] = 645; em[687] = 56; 
    	em[688] = 645; em[689] = 64; 
    	em[690] = 120; em[691] = 80; 
    	em[692] = 707; em[693] = 88; 
    	em[694] = 710; em[695] = 96; 
    	em[696] = 642; em[697] = 104; 
    em[698] = 8884097; em[699] = 8; em[700] = 0; /* 698: pointer.func */
    em[701] = 8884097; em[702] = 8; em[703] = 0; /* 701: pointer.func */
    em[704] = 8884097; em[705] = 8; em[706] = 0; /* 704: pointer.func */
    em[707] = 8884097; em[708] = 8; em[709] = 0; /* 707: pointer.func */
    em[710] = 8884097; em[711] = 8; em[712] = 0; /* 710: pointer.func */
    em[713] = 0; em[714] = 168; em[715] = 17; /* 713: struct.rsa_st */
    	em[716] = 750; em[717] = 16; 
    	em[718] = 755; em[719] = 24; 
    	em[720] = 1100; em[721] = 32; 
    	em[722] = 1100; em[723] = 40; 
    	em[724] = 1100; em[725] = 48; 
    	em[726] = 1100; em[727] = 56; 
    	em[728] = 1100; em[729] = 64; 
    	em[730] = 1100; em[731] = 72; 
    	em[732] = 1100; em[733] = 80; 
    	em[734] = 1100; em[735] = 88; 
    	em[736] = 1117; em[737] = 96; 
    	em[738] = 1132; em[739] = 120; 
    	em[740] = 1132; em[741] = 128; 
    	em[742] = 1132; em[743] = 136; 
    	em[744] = 120; em[745] = 144; 
    	em[746] = 1146; em[747] = 152; 
    	em[748] = 1146; em[749] = 160; 
    em[750] = 1; em[751] = 8; em[752] = 1; /* 750: pointer.struct.rsa_meth_st */
    	em[753] = 669; em[754] = 0; 
    em[755] = 1; em[756] = 8; em[757] = 1; /* 755: pointer.struct.engine_st */
    	em[758] = 760; em[759] = 0; 
    em[760] = 0; em[761] = 216; em[762] = 24; /* 760: struct.engine_st */
    	em[763] = 139; em[764] = 0; 
    	em[765] = 139; em[766] = 8; 
    	em[767] = 811; em[768] = 16; 
    	em[769] = 863; em[770] = 24; 
    	em[771] = 914; em[772] = 32; 
    	em[773] = 950; em[774] = 40; 
    	em[775] = 967; em[776] = 48; 
    	em[777] = 994; em[778] = 56; 
    	em[779] = 1029; em[780] = 64; 
    	em[781] = 1037; em[782] = 72; 
    	em[783] = 1040; em[784] = 80; 
    	em[785] = 1043; em[786] = 88; 
    	em[787] = 1046; em[788] = 96; 
    	em[789] = 1049; em[790] = 104; 
    	em[791] = 1049; em[792] = 112; 
    	em[793] = 1049; em[794] = 120; 
    	em[795] = 1052; em[796] = 128; 
    	em[797] = 1055; em[798] = 136; 
    	em[799] = 1055; em[800] = 144; 
    	em[801] = 1058; em[802] = 152; 
    	em[803] = 1061; em[804] = 160; 
    	em[805] = 1073; em[806] = 184; 
    	em[807] = 1095; em[808] = 200; 
    	em[809] = 1095; em[810] = 208; 
    em[811] = 1; em[812] = 8; em[813] = 1; /* 811: pointer.struct.rsa_meth_st */
    	em[814] = 816; em[815] = 0; 
    em[816] = 0; em[817] = 112; em[818] = 13; /* 816: struct.rsa_meth_st */
    	em[819] = 139; em[820] = 0; 
    	em[821] = 648; em[822] = 8; 
    	em[823] = 648; em[824] = 16; 
    	em[825] = 648; em[826] = 24; 
    	em[827] = 648; em[828] = 32; 
    	em[829] = 845; em[830] = 40; 
    	em[831] = 848; em[832] = 48; 
    	em[833] = 851; em[834] = 56; 
    	em[835] = 851; em[836] = 64; 
    	em[837] = 120; em[838] = 80; 
    	em[839] = 854; em[840] = 88; 
    	em[841] = 857; em[842] = 96; 
    	em[843] = 860; em[844] = 104; 
    em[845] = 8884097; em[846] = 8; em[847] = 0; /* 845: pointer.func */
    em[848] = 8884097; em[849] = 8; em[850] = 0; /* 848: pointer.func */
    em[851] = 8884097; em[852] = 8; em[853] = 0; /* 851: pointer.func */
    em[854] = 8884097; em[855] = 8; em[856] = 0; /* 854: pointer.func */
    em[857] = 8884097; em[858] = 8; em[859] = 0; /* 857: pointer.func */
    em[860] = 8884097; em[861] = 8; em[862] = 0; /* 860: pointer.func */
    em[863] = 1; em[864] = 8; em[865] = 1; /* 863: pointer.struct.dsa_method */
    	em[866] = 868; em[867] = 0; 
    em[868] = 0; em[869] = 96; em[870] = 11; /* 868: struct.dsa_method */
    	em[871] = 139; em[872] = 0; 
    	em[873] = 893; em[874] = 8; 
    	em[875] = 896; em[876] = 16; 
    	em[877] = 899; em[878] = 24; 
    	em[879] = 902; em[880] = 32; 
    	em[881] = 905; em[882] = 40; 
    	em[883] = 908; em[884] = 48; 
    	em[885] = 908; em[886] = 56; 
    	em[887] = 120; em[888] = 72; 
    	em[889] = 911; em[890] = 80; 
    	em[891] = 908; em[892] = 88; 
    em[893] = 8884097; em[894] = 8; em[895] = 0; /* 893: pointer.func */
    em[896] = 8884097; em[897] = 8; em[898] = 0; /* 896: pointer.func */
    em[899] = 8884097; em[900] = 8; em[901] = 0; /* 899: pointer.func */
    em[902] = 8884097; em[903] = 8; em[904] = 0; /* 902: pointer.func */
    em[905] = 8884097; em[906] = 8; em[907] = 0; /* 905: pointer.func */
    em[908] = 8884097; em[909] = 8; em[910] = 0; /* 908: pointer.func */
    em[911] = 8884097; em[912] = 8; em[913] = 0; /* 911: pointer.func */
    em[914] = 1; em[915] = 8; em[916] = 1; /* 914: pointer.struct.dh_method */
    	em[917] = 919; em[918] = 0; 
    em[919] = 0; em[920] = 72; em[921] = 8; /* 919: struct.dh_method */
    	em[922] = 139; em[923] = 0; 
    	em[924] = 938; em[925] = 8; 
    	em[926] = 941; em[927] = 16; 
    	em[928] = 944; em[929] = 24; 
    	em[930] = 938; em[931] = 32; 
    	em[932] = 938; em[933] = 40; 
    	em[934] = 120; em[935] = 56; 
    	em[936] = 947; em[937] = 64; 
    em[938] = 8884097; em[939] = 8; em[940] = 0; /* 938: pointer.func */
    em[941] = 8884097; em[942] = 8; em[943] = 0; /* 941: pointer.func */
    em[944] = 8884097; em[945] = 8; em[946] = 0; /* 944: pointer.func */
    em[947] = 8884097; em[948] = 8; em[949] = 0; /* 947: pointer.func */
    em[950] = 1; em[951] = 8; em[952] = 1; /* 950: pointer.struct.ecdh_method */
    	em[953] = 955; em[954] = 0; 
    em[955] = 0; em[956] = 32; em[957] = 3; /* 955: struct.ecdh_method */
    	em[958] = 139; em[959] = 0; 
    	em[960] = 964; em[961] = 8; 
    	em[962] = 120; em[963] = 24; 
    em[964] = 8884097; em[965] = 8; em[966] = 0; /* 964: pointer.func */
    em[967] = 1; em[968] = 8; em[969] = 1; /* 967: pointer.struct.ecdsa_method */
    	em[970] = 972; em[971] = 0; 
    em[972] = 0; em[973] = 48; em[974] = 5; /* 972: struct.ecdsa_method */
    	em[975] = 139; em[976] = 0; 
    	em[977] = 985; em[978] = 8; 
    	em[979] = 988; em[980] = 16; 
    	em[981] = 991; em[982] = 24; 
    	em[983] = 120; em[984] = 40; 
    em[985] = 8884097; em[986] = 8; em[987] = 0; /* 985: pointer.func */
    em[988] = 8884097; em[989] = 8; em[990] = 0; /* 988: pointer.func */
    em[991] = 8884097; em[992] = 8; em[993] = 0; /* 991: pointer.func */
    em[994] = 1; em[995] = 8; em[996] = 1; /* 994: pointer.struct.rand_meth_st */
    	em[997] = 999; em[998] = 0; 
    em[999] = 0; em[1000] = 48; em[1001] = 6; /* 999: struct.rand_meth_st */
    	em[1002] = 1014; em[1003] = 0; 
    	em[1004] = 1017; em[1005] = 8; 
    	em[1006] = 1020; em[1007] = 16; 
    	em[1008] = 1023; em[1009] = 24; 
    	em[1010] = 1017; em[1011] = 32; 
    	em[1012] = 1026; em[1013] = 40; 
    em[1014] = 8884097; em[1015] = 8; em[1016] = 0; /* 1014: pointer.func */
    em[1017] = 8884097; em[1018] = 8; em[1019] = 0; /* 1017: pointer.func */
    em[1020] = 8884097; em[1021] = 8; em[1022] = 0; /* 1020: pointer.func */
    em[1023] = 8884097; em[1024] = 8; em[1025] = 0; /* 1023: pointer.func */
    em[1026] = 8884097; em[1027] = 8; em[1028] = 0; /* 1026: pointer.func */
    em[1029] = 1; em[1030] = 8; em[1031] = 1; /* 1029: pointer.struct.store_method_st */
    	em[1032] = 1034; em[1033] = 0; 
    em[1034] = 0; em[1035] = 0; em[1036] = 0; /* 1034: struct.store_method_st */
    em[1037] = 8884097; em[1038] = 8; em[1039] = 0; /* 1037: pointer.func */
    em[1040] = 8884097; em[1041] = 8; em[1042] = 0; /* 1040: pointer.func */
    em[1043] = 8884097; em[1044] = 8; em[1045] = 0; /* 1043: pointer.func */
    em[1046] = 8884097; em[1047] = 8; em[1048] = 0; /* 1046: pointer.func */
    em[1049] = 8884097; em[1050] = 8; em[1051] = 0; /* 1049: pointer.func */
    em[1052] = 8884097; em[1053] = 8; em[1054] = 0; /* 1052: pointer.func */
    em[1055] = 8884097; em[1056] = 8; em[1057] = 0; /* 1055: pointer.func */
    em[1058] = 8884097; em[1059] = 8; em[1060] = 0; /* 1058: pointer.func */
    em[1061] = 1; em[1062] = 8; em[1063] = 1; /* 1061: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[1064] = 1066; em[1065] = 0; 
    em[1066] = 0; em[1067] = 32; em[1068] = 2; /* 1066: struct.ENGINE_CMD_DEFN_st */
    	em[1069] = 139; em[1070] = 8; 
    	em[1071] = 139; em[1072] = 16; 
    em[1073] = 0; em[1074] = 16; em[1075] = 1; /* 1073: struct.crypto_ex_data_st */
    	em[1076] = 1078; em[1077] = 0; 
    em[1078] = 1; em[1079] = 8; em[1080] = 1; /* 1078: pointer.struct.stack_st_void */
    	em[1081] = 1083; em[1082] = 0; 
    em[1083] = 0; em[1084] = 32; em[1085] = 1; /* 1083: struct.stack_st_void */
    	em[1086] = 1088; em[1087] = 0; 
    em[1088] = 0; em[1089] = 32; em[1090] = 2; /* 1088: struct.stack_st */
    	em[1091] = 658; em[1092] = 8; 
    	em[1093] = 363; em[1094] = 24; 
    em[1095] = 1; em[1096] = 8; em[1097] = 1; /* 1095: pointer.struct.engine_st */
    	em[1098] = 760; em[1099] = 0; 
    em[1100] = 1; em[1101] = 8; em[1102] = 1; /* 1100: pointer.struct.bignum_st */
    	em[1103] = 1105; em[1104] = 0; 
    em[1105] = 0; em[1106] = 24; em[1107] = 1; /* 1105: struct.bignum_st */
    	em[1108] = 1110; em[1109] = 0; 
    em[1110] = 8884099; em[1111] = 8; em[1112] = 2; /* 1110: pointer_to_array_of_pointers_to_stack */
    	em[1113] = 431; em[1114] = 0; 
    	em[1115] = 5; em[1116] = 12; 
    em[1117] = 0; em[1118] = 16; em[1119] = 1; /* 1117: struct.crypto_ex_data_st */
    	em[1120] = 1122; em[1121] = 0; 
    em[1122] = 1; em[1123] = 8; em[1124] = 1; /* 1122: pointer.struct.stack_st_void */
    	em[1125] = 1127; em[1126] = 0; 
    em[1127] = 0; em[1128] = 32; em[1129] = 1; /* 1127: struct.stack_st_void */
    	em[1130] = 651; em[1131] = 0; 
    em[1132] = 1; em[1133] = 8; em[1134] = 1; /* 1132: pointer.struct.bn_mont_ctx_st */
    	em[1135] = 1137; em[1136] = 0; 
    em[1137] = 0; em[1138] = 96; em[1139] = 3; /* 1137: struct.bn_mont_ctx_st */
    	em[1140] = 1105; em[1141] = 8; 
    	em[1142] = 1105; em[1143] = 32; 
    	em[1144] = 1105; em[1145] = 56; 
    em[1146] = 1; em[1147] = 8; em[1148] = 1; /* 1146: pointer.struct.bn_blinding_st */
    	em[1149] = 1151; em[1150] = 0; 
    em[1151] = 0; em[1152] = 88; em[1153] = 7; /* 1151: struct.bn_blinding_st */
    	em[1154] = 1168; em[1155] = 0; 
    	em[1156] = 1168; em[1157] = 8; 
    	em[1158] = 1168; em[1159] = 16; 
    	em[1160] = 1168; em[1161] = 24; 
    	em[1162] = 1185; em[1163] = 40; 
    	em[1164] = 1190; em[1165] = 72; 
    	em[1166] = 1204; em[1167] = 80; 
    em[1168] = 1; em[1169] = 8; em[1170] = 1; /* 1168: pointer.struct.bignum_st */
    	em[1171] = 1173; em[1172] = 0; 
    em[1173] = 0; em[1174] = 24; em[1175] = 1; /* 1173: struct.bignum_st */
    	em[1176] = 1178; em[1177] = 0; 
    em[1178] = 8884099; em[1179] = 8; em[1180] = 2; /* 1178: pointer_to_array_of_pointers_to_stack */
    	em[1181] = 431; em[1182] = 0; 
    	em[1183] = 5; em[1184] = 12; 
    em[1185] = 0; em[1186] = 16; em[1187] = 1; /* 1185: struct.crypto_threadid_st */
    	em[1188] = 405; em[1189] = 0; 
    em[1190] = 1; em[1191] = 8; em[1192] = 1; /* 1190: pointer.struct.bn_mont_ctx_st */
    	em[1193] = 1195; em[1194] = 0; 
    em[1195] = 0; em[1196] = 96; em[1197] = 3; /* 1195: struct.bn_mont_ctx_st */
    	em[1198] = 1173; em[1199] = 8; 
    	em[1200] = 1173; em[1201] = 32; 
    	em[1202] = 1173; em[1203] = 56; 
    em[1204] = 8884097; em[1205] = 8; em[1206] = 0; /* 1204: pointer.func */
    em[1207] = 8884097; em[1208] = 8; em[1209] = 0; /* 1207: pointer.func */
    em[1210] = 0; em[1211] = 208; em[1212] = 24; /* 1210: struct.evp_pkey_asn1_method_st */
    	em[1213] = 120; em[1214] = 16; 
    	em[1215] = 120; em[1216] = 24; 
    	em[1217] = 1261; em[1218] = 32; 
    	em[1219] = 1264; em[1220] = 40; 
    	em[1221] = 1267; em[1222] = 48; 
    	em[1223] = 1270; em[1224] = 56; 
    	em[1225] = 1273; em[1226] = 64; 
    	em[1227] = 1276; em[1228] = 72; 
    	em[1229] = 1270; em[1230] = 80; 
    	em[1231] = 1207; em[1232] = 88; 
    	em[1233] = 1207; em[1234] = 96; 
    	em[1235] = 1279; em[1236] = 104; 
    	em[1237] = 1282; em[1238] = 112; 
    	em[1239] = 1207; em[1240] = 120; 
    	em[1241] = 1285; em[1242] = 128; 
    	em[1243] = 1267; em[1244] = 136; 
    	em[1245] = 1270; em[1246] = 144; 
    	em[1247] = 1288; em[1248] = 152; 
    	em[1249] = 1291; em[1250] = 160; 
    	em[1251] = 1294; em[1252] = 168; 
    	em[1253] = 1279; em[1254] = 176; 
    	em[1255] = 1282; em[1256] = 184; 
    	em[1257] = 1297; em[1258] = 192; 
    	em[1259] = 1300; em[1260] = 200; 
    em[1261] = 8884097; em[1262] = 8; em[1263] = 0; /* 1261: pointer.func */
    em[1264] = 8884097; em[1265] = 8; em[1266] = 0; /* 1264: pointer.func */
    em[1267] = 8884097; em[1268] = 8; em[1269] = 0; /* 1267: pointer.func */
    em[1270] = 8884097; em[1271] = 8; em[1272] = 0; /* 1270: pointer.func */
    em[1273] = 8884097; em[1274] = 8; em[1275] = 0; /* 1273: pointer.func */
    em[1276] = 8884097; em[1277] = 8; em[1278] = 0; /* 1276: pointer.func */
    em[1279] = 8884097; em[1280] = 8; em[1281] = 0; /* 1279: pointer.func */
    em[1282] = 8884097; em[1283] = 8; em[1284] = 0; /* 1282: pointer.func */
    em[1285] = 8884097; em[1286] = 8; em[1287] = 0; /* 1285: pointer.func */
    em[1288] = 8884097; em[1289] = 8; em[1290] = 0; /* 1288: pointer.func */
    em[1291] = 8884097; em[1292] = 8; em[1293] = 0; /* 1291: pointer.func */
    em[1294] = 8884097; em[1295] = 8; em[1296] = 0; /* 1294: pointer.func */
    em[1297] = 8884097; em[1298] = 8; em[1299] = 0; /* 1297: pointer.func */
    em[1300] = 8884097; em[1301] = 8; em[1302] = 0; /* 1300: pointer.func */
    em[1303] = 8884097; em[1304] = 8; em[1305] = 0; /* 1303: pointer.func */
    em[1306] = 1; em[1307] = 8; em[1308] = 1; /* 1306: pointer.struct.evp_pkey_asn1_method_st */
    	em[1309] = 1210; em[1310] = 0; 
    em[1311] = 0; em[1312] = 56; em[1313] = 4; /* 1311: struct.evp_pkey_st */
    	em[1314] = 1306; em[1315] = 16; 
    	em[1316] = 1322; em[1317] = 24; 
    	em[1318] = 1327; em[1319] = 32; 
    	em[1320] = 1859; em[1321] = 48; 
    em[1322] = 1; em[1323] = 8; em[1324] = 1; /* 1322: pointer.struct.engine_st */
    	em[1325] = 760; em[1326] = 0; 
    em[1327] = 0; em[1328] = 8; em[1329] = 5; /* 1327: union.unknown */
    	em[1330] = 120; em[1331] = 0; 
    	em[1332] = 1340; em[1333] = 0; 
    	em[1334] = 1345; em[1335] = 0; 
    	em[1336] = 1484; em[1337] = 0; 
    	em[1338] = 1605; em[1339] = 0; 
    em[1340] = 1; em[1341] = 8; em[1342] = 1; /* 1340: pointer.struct.rsa_st */
    	em[1343] = 713; em[1344] = 0; 
    em[1345] = 1; em[1346] = 8; em[1347] = 1; /* 1345: pointer.struct.dsa_st */
    	em[1348] = 1350; em[1349] = 0; 
    em[1350] = 0; em[1351] = 136; em[1352] = 11; /* 1350: struct.dsa_st */
    	em[1353] = 1375; em[1354] = 24; 
    	em[1355] = 1375; em[1356] = 32; 
    	em[1357] = 1375; em[1358] = 40; 
    	em[1359] = 1375; em[1360] = 48; 
    	em[1361] = 1375; em[1362] = 56; 
    	em[1363] = 1375; em[1364] = 64; 
    	em[1365] = 1375; em[1366] = 72; 
    	em[1367] = 1392; em[1368] = 88; 
    	em[1369] = 1406; em[1370] = 104; 
    	em[1371] = 1428; em[1372] = 120; 
    	em[1373] = 1479; em[1374] = 128; 
    em[1375] = 1; em[1376] = 8; em[1377] = 1; /* 1375: pointer.struct.bignum_st */
    	em[1378] = 1380; em[1379] = 0; 
    em[1380] = 0; em[1381] = 24; em[1382] = 1; /* 1380: struct.bignum_st */
    	em[1383] = 1385; em[1384] = 0; 
    em[1385] = 8884099; em[1386] = 8; em[1387] = 2; /* 1385: pointer_to_array_of_pointers_to_stack */
    	em[1388] = 431; em[1389] = 0; 
    	em[1390] = 5; em[1391] = 12; 
    em[1392] = 1; em[1393] = 8; em[1394] = 1; /* 1392: pointer.struct.bn_mont_ctx_st */
    	em[1395] = 1397; em[1396] = 0; 
    em[1397] = 0; em[1398] = 96; em[1399] = 3; /* 1397: struct.bn_mont_ctx_st */
    	em[1400] = 1380; em[1401] = 8; 
    	em[1402] = 1380; em[1403] = 32; 
    	em[1404] = 1380; em[1405] = 56; 
    em[1406] = 0; em[1407] = 16; em[1408] = 1; /* 1406: struct.crypto_ex_data_st */
    	em[1409] = 1411; em[1410] = 0; 
    em[1411] = 1; em[1412] = 8; em[1413] = 1; /* 1411: pointer.struct.stack_st_void */
    	em[1414] = 1416; em[1415] = 0; 
    em[1416] = 0; em[1417] = 32; em[1418] = 1; /* 1416: struct.stack_st_void */
    	em[1419] = 1421; em[1420] = 0; 
    em[1421] = 0; em[1422] = 32; em[1423] = 2; /* 1421: struct.stack_st */
    	em[1424] = 658; em[1425] = 8; 
    	em[1426] = 363; em[1427] = 24; 
    em[1428] = 1; em[1429] = 8; em[1430] = 1; /* 1428: pointer.struct.dsa_method */
    	em[1431] = 1433; em[1432] = 0; 
    em[1433] = 0; em[1434] = 96; em[1435] = 11; /* 1433: struct.dsa_method */
    	em[1436] = 139; em[1437] = 0; 
    	em[1438] = 1458; em[1439] = 8; 
    	em[1440] = 1461; em[1441] = 16; 
    	em[1442] = 1464; em[1443] = 24; 
    	em[1444] = 1467; em[1445] = 32; 
    	em[1446] = 1470; em[1447] = 40; 
    	em[1448] = 1473; em[1449] = 48; 
    	em[1450] = 1473; em[1451] = 56; 
    	em[1452] = 120; em[1453] = 72; 
    	em[1454] = 1476; em[1455] = 80; 
    	em[1456] = 1473; em[1457] = 88; 
    em[1458] = 8884097; em[1459] = 8; em[1460] = 0; /* 1458: pointer.func */
    em[1461] = 8884097; em[1462] = 8; em[1463] = 0; /* 1461: pointer.func */
    em[1464] = 8884097; em[1465] = 8; em[1466] = 0; /* 1464: pointer.func */
    em[1467] = 8884097; em[1468] = 8; em[1469] = 0; /* 1467: pointer.func */
    em[1470] = 8884097; em[1471] = 8; em[1472] = 0; /* 1470: pointer.func */
    em[1473] = 8884097; em[1474] = 8; em[1475] = 0; /* 1473: pointer.func */
    em[1476] = 8884097; em[1477] = 8; em[1478] = 0; /* 1476: pointer.func */
    em[1479] = 1; em[1480] = 8; em[1481] = 1; /* 1479: pointer.struct.engine_st */
    	em[1482] = 760; em[1483] = 0; 
    em[1484] = 1; em[1485] = 8; em[1486] = 1; /* 1484: pointer.struct.dh_st */
    	em[1487] = 1489; em[1488] = 0; 
    em[1489] = 0; em[1490] = 144; em[1491] = 12; /* 1489: struct.dh_st */
    	em[1492] = 1516; em[1493] = 8; 
    	em[1494] = 1516; em[1495] = 16; 
    	em[1496] = 1516; em[1497] = 32; 
    	em[1498] = 1516; em[1499] = 40; 
    	em[1500] = 1533; em[1501] = 56; 
    	em[1502] = 1516; em[1503] = 64; 
    	em[1504] = 1516; em[1505] = 72; 
    	em[1506] = 29; em[1507] = 80; 
    	em[1508] = 1516; em[1509] = 96; 
    	em[1510] = 1547; em[1511] = 112; 
    	em[1512] = 1569; em[1513] = 128; 
    	em[1514] = 1322; em[1515] = 136; 
    em[1516] = 1; em[1517] = 8; em[1518] = 1; /* 1516: pointer.struct.bignum_st */
    	em[1519] = 1521; em[1520] = 0; 
    em[1521] = 0; em[1522] = 24; em[1523] = 1; /* 1521: struct.bignum_st */
    	em[1524] = 1526; em[1525] = 0; 
    em[1526] = 8884099; em[1527] = 8; em[1528] = 2; /* 1526: pointer_to_array_of_pointers_to_stack */
    	em[1529] = 431; em[1530] = 0; 
    	em[1531] = 5; em[1532] = 12; 
    em[1533] = 1; em[1534] = 8; em[1535] = 1; /* 1533: pointer.struct.bn_mont_ctx_st */
    	em[1536] = 1538; em[1537] = 0; 
    em[1538] = 0; em[1539] = 96; em[1540] = 3; /* 1538: struct.bn_mont_ctx_st */
    	em[1541] = 1521; em[1542] = 8; 
    	em[1543] = 1521; em[1544] = 32; 
    	em[1545] = 1521; em[1546] = 56; 
    em[1547] = 0; em[1548] = 16; em[1549] = 1; /* 1547: struct.crypto_ex_data_st */
    	em[1550] = 1552; em[1551] = 0; 
    em[1552] = 1; em[1553] = 8; em[1554] = 1; /* 1552: pointer.struct.stack_st_void */
    	em[1555] = 1557; em[1556] = 0; 
    em[1557] = 0; em[1558] = 32; em[1559] = 1; /* 1557: struct.stack_st_void */
    	em[1560] = 1562; em[1561] = 0; 
    em[1562] = 0; em[1563] = 32; em[1564] = 2; /* 1562: struct.stack_st */
    	em[1565] = 658; em[1566] = 8; 
    	em[1567] = 363; em[1568] = 24; 
    em[1569] = 1; em[1570] = 8; em[1571] = 1; /* 1569: pointer.struct.dh_method */
    	em[1572] = 1574; em[1573] = 0; 
    em[1574] = 0; em[1575] = 72; em[1576] = 8; /* 1574: struct.dh_method */
    	em[1577] = 139; em[1578] = 0; 
    	em[1579] = 1593; em[1580] = 8; 
    	em[1581] = 1596; em[1582] = 16; 
    	em[1583] = 1599; em[1584] = 24; 
    	em[1585] = 1593; em[1586] = 32; 
    	em[1587] = 1593; em[1588] = 40; 
    	em[1589] = 120; em[1590] = 56; 
    	em[1591] = 1602; em[1592] = 64; 
    em[1593] = 8884097; em[1594] = 8; em[1595] = 0; /* 1593: pointer.func */
    em[1596] = 8884097; em[1597] = 8; em[1598] = 0; /* 1596: pointer.func */
    em[1599] = 8884097; em[1600] = 8; em[1601] = 0; /* 1599: pointer.func */
    em[1602] = 8884097; em[1603] = 8; em[1604] = 0; /* 1602: pointer.func */
    em[1605] = 1; em[1606] = 8; em[1607] = 1; /* 1605: pointer.struct.ec_key_st */
    	em[1608] = 1610; em[1609] = 0; 
    em[1610] = 0; em[1611] = 56; em[1612] = 4; /* 1610: struct.ec_key_st */
    	em[1613] = 1621; em[1614] = 8; 
    	em[1615] = 439; em[1616] = 16; 
    	em[1617] = 434; em[1618] = 24; 
    	em[1619] = 414; em[1620] = 48; 
    em[1621] = 1; em[1622] = 8; em[1623] = 1; /* 1621: pointer.struct.ec_group_st */
    	em[1624] = 1626; em[1625] = 0; 
    em[1626] = 0; em[1627] = 232; em[1628] = 12; /* 1626: struct.ec_group_st */
    	em[1629] = 1653; em[1630] = 0; 
    	em[1631] = 1819; em[1632] = 8; 
    	em[1633] = 1824; em[1634] = 16; 
    	em[1635] = 1824; em[1636] = 40; 
    	em[1637] = 29; em[1638] = 80; 
    	em[1639] = 1836; em[1640] = 96; 
    	em[1641] = 1824; em[1642] = 104; 
    	em[1643] = 1824; em[1644] = 152; 
    	em[1645] = 1824; em[1646] = 176; 
    	em[1647] = 405; em[1648] = 208; 
    	em[1649] = 405; em[1650] = 216; 
    	em[1651] = 639; em[1652] = 224; 
    em[1653] = 1; em[1654] = 8; em[1655] = 1; /* 1653: pointer.struct.ec_method_st */
    	em[1656] = 1658; em[1657] = 0; 
    em[1658] = 0; em[1659] = 304; em[1660] = 37; /* 1658: struct.ec_method_st */
    	em[1661] = 1735; em[1662] = 8; 
    	em[1663] = 1738; em[1664] = 16; 
    	em[1665] = 1738; em[1666] = 24; 
    	em[1667] = 1741; em[1668] = 32; 
    	em[1669] = 1744; em[1670] = 40; 
    	em[1671] = 1747; em[1672] = 48; 
    	em[1673] = 1750; em[1674] = 56; 
    	em[1675] = 1753; em[1676] = 64; 
    	em[1677] = 1756; em[1678] = 72; 
    	em[1679] = 1759; em[1680] = 80; 
    	em[1681] = 1759; em[1682] = 88; 
    	em[1683] = 1762; em[1684] = 96; 
    	em[1685] = 1765; em[1686] = 104; 
    	em[1687] = 1768; em[1688] = 112; 
    	em[1689] = 1771; em[1690] = 120; 
    	em[1691] = 1774; em[1692] = 128; 
    	em[1693] = 1777; em[1694] = 136; 
    	em[1695] = 663; em[1696] = 144; 
    	em[1697] = 1780; em[1698] = 152; 
    	em[1699] = 1783; em[1700] = 160; 
    	em[1701] = 1786; em[1702] = 168; 
    	em[1703] = 1789; em[1704] = 176; 
    	em[1705] = 1792; em[1706] = 184; 
    	em[1707] = 1795; em[1708] = 192; 
    	em[1709] = 1798; em[1710] = 200; 
    	em[1711] = 1801; em[1712] = 208; 
    	em[1713] = 1792; em[1714] = 216; 
    	em[1715] = 666; em[1716] = 224; 
    	em[1717] = 1804; em[1718] = 232; 
    	em[1719] = 1807; em[1720] = 240; 
    	em[1721] = 1750; em[1722] = 248; 
    	em[1723] = 1810; em[1724] = 256; 
    	em[1725] = 1813; em[1726] = 264; 
    	em[1727] = 1810; em[1728] = 272; 
    	em[1729] = 1813; em[1730] = 280; 
    	em[1731] = 1813; em[1732] = 288; 
    	em[1733] = 1816; em[1734] = 296; 
    em[1735] = 8884097; em[1736] = 8; em[1737] = 0; /* 1735: pointer.func */
    em[1738] = 8884097; em[1739] = 8; em[1740] = 0; /* 1738: pointer.func */
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
    em[1819] = 1; em[1820] = 8; em[1821] = 1; /* 1819: pointer.struct.ec_point_st */
    	em[1822] = 444; em[1823] = 0; 
    em[1824] = 0; em[1825] = 24; em[1826] = 1; /* 1824: struct.bignum_st */
    	em[1827] = 1829; em[1828] = 0; 
    em[1829] = 8884099; em[1830] = 8; em[1831] = 2; /* 1829: pointer_to_array_of_pointers_to_stack */
    	em[1832] = 431; em[1833] = 0; 
    	em[1834] = 5; em[1835] = 12; 
    em[1836] = 1; em[1837] = 8; em[1838] = 1; /* 1836: pointer.struct.ec_extra_data_st */
    	em[1839] = 1841; em[1840] = 0; 
    em[1841] = 0; em[1842] = 40; em[1843] = 5; /* 1841: struct.ec_extra_data_st */
    	em[1844] = 1854; em[1845] = 0; 
    	em[1846] = 405; em[1847] = 8; 
    	em[1848] = 408; em[1849] = 16; 
    	em[1850] = 411; em[1851] = 24; 
    	em[1852] = 411; em[1853] = 32; 
    em[1854] = 1; em[1855] = 8; em[1856] = 1; /* 1854: pointer.struct.ec_extra_data_st */
    	em[1857] = 1841; em[1858] = 0; 
    em[1859] = 1; em[1860] = 8; em[1861] = 1; /* 1859: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1862] = 1864; em[1863] = 0; 
    em[1864] = 0; em[1865] = 32; em[1866] = 2; /* 1864: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1867] = 1871; em[1868] = 8; 
    	em[1869] = 363; em[1870] = 24; 
    em[1871] = 8884099; em[1872] = 8; em[1873] = 2; /* 1871: pointer_to_array_of_pointers_to_stack */
    	em[1874] = 1878; em[1875] = 0; 
    	em[1876] = 5; em[1877] = 20; 
    em[1878] = 0; em[1879] = 8; em[1880] = 1; /* 1878: pointer.X509_ATTRIBUTE */
    	em[1881] = 1883; em[1882] = 0; 
    em[1883] = 0; em[1884] = 0; em[1885] = 1; /* 1883: X509_ATTRIBUTE */
    	em[1886] = 366; em[1887] = 0; 
    em[1888] = 1; em[1889] = 8; em[1890] = 1; /* 1888: pointer.struct.evp_pkey_st */
    	em[1891] = 1311; em[1892] = 0; 
    em[1893] = 8884097; em[1894] = 8; em[1895] = 0; /* 1893: pointer.func */
    em[1896] = 0; em[1897] = 1; em[1898] = 0; /* 1896: char */
    em[1899] = 8884097; em[1900] = 8; em[1901] = 0; /* 1899: pointer.func */
    em[1902] = 8884097; em[1903] = 8; em[1904] = 0; /* 1902: pointer.func */
    em[1905] = 8884097; em[1906] = 8; em[1907] = 0; /* 1905: pointer.func */
    em[1908] = 0; em[1909] = 288; em[1910] = 4; /* 1908: struct.hmac_ctx_st */
    	em[1911] = 1919; em[1912] = 0; 
    	em[1913] = 1961; em[1914] = 8; 
    	em[1915] = 1961; em[1916] = 56; 
    	em[1917] = 1961; em[1918] = 104; 
    em[1919] = 1; em[1920] = 8; em[1921] = 1; /* 1919: pointer.struct.env_md_st */
    	em[1922] = 1924; em[1923] = 0; 
    em[1924] = 0; em[1925] = 120; em[1926] = 8; /* 1924: struct.env_md_st */
    	em[1927] = 1943; em[1928] = 24; 
    	em[1929] = 1946; em[1930] = 32; 
    	em[1931] = 1949; em[1932] = 40; 
    	em[1933] = 1952; em[1934] = 48; 
    	em[1935] = 1943; em[1936] = 56; 
    	em[1937] = 1955; em[1938] = 64; 
    	em[1939] = 1303; em[1940] = 72; 
    	em[1941] = 1958; em[1942] = 112; 
    em[1943] = 8884097; em[1944] = 8; em[1945] = 0; /* 1943: pointer.func */
    em[1946] = 8884097; em[1947] = 8; em[1948] = 0; /* 1946: pointer.func */
    em[1949] = 8884097; em[1950] = 8; em[1951] = 0; /* 1949: pointer.func */
    em[1952] = 8884097; em[1953] = 8; em[1954] = 0; /* 1952: pointer.func */
    em[1955] = 8884097; em[1956] = 8; em[1957] = 0; /* 1955: pointer.func */
    em[1958] = 8884097; em[1959] = 8; em[1960] = 0; /* 1958: pointer.func */
    em[1961] = 0; em[1962] = 48; em[1963] = 5; /* 1961: struct.env_md_ctx_st */
    	em[1964] = 1919; em[1965] = 0; 
    	em[1966] = 1974; em[1967] = 8; 
    	em[1968] = 405; em[1969] = 24; 
    	em[1970] = 1979; em[1971] = 32; 
    	em[1972] = 1946; em[1973] = 40; 
    em[1974] = 1; em[1975] = 8; em[1976] = 1; /* 1974: pointer.struct.engine_st */
    	em[1977] = 760; em[1978] = 0; 
    em[1979] = 1; em[1980] = 8; em[1981] = 1; /* 1979: pointer.struct.evp_pkey_ctx_st */
    	em[1982] = 1984; em[1983] = 0; 
    em[1984] = 0; em[1985] = 80; em[1986] = 8; /* 1984: struct.evp_pkey_ctx_st */
    	em[1987] = 2003; em[1988] = 0; 
    	em[1989] = 1322; em[1990] = 8; 
    	em[1991] = 1888; em[1992] = 16; 
    	em[1993] = 1888; em[1994] = 24; 
    	em[1995] = 405; em[1996] = 40; 
    	em[1997] = 405; em[1998] = 48; 
    	em[1999] = 8; em[2000] = 56; 
    	em[2001] = 0; em[2002] = 64; 
    em[2003] = 1; em[2004] = 8; em[2005] = 1; /* 2003: pointer.struct.evp_pkey_method_st */
    	em[2006] = 2008; em[2007] = 0; 
    em[2008] = 0; em[2009] = 208; em[2010] = 25; /* 2008: struct.evp_pkey_method_st */
    	em[2011] = 1905; em[2012] = 8; 
    	em[2013] = 2061; em[2014] = 16; 
    	em[2015] = 2064; em[2016] = 24; 
    	em[2017] = 1905; em[2018] = 32; 
    	em[2019] = 2067; em[2020] = 40; 
    	em[2021] = 1905; em[2022] = 48; 
    	em[2023] = 2067; em[2024] = 56; 
    	em[2025] = 1905; em[2026] = 64; 
    	em[2027] = 2070; em[2028] = 72; 
    	em[2029] = 1905; em[2030] = 80; 
    	em[2031] = 2073; em[2032] = 88; 
    	em[2033] = 1905; em[2034] = 96; 
    	em[2035] = 2070; em[2036] = 104; 
    	em[2037] = 2076; em[2038] = 112; 
    	em[2039] = 1902; em[2040] = 120; 
    	em[2041] = 2076; em[2042] = 128; 
    	em[2043] = 2079; em[2044] = 136; 
    	em[2045] = 1905; em[2046] = 144; 
    	em[2047] = 2070; em[2048] = 152; 
    	em[2049] = 1905; em[2050] = 160; 
    	em[2051] = 2070; em[2052] = 168; 
    	em[2053] = 1905; em[2054] = 176; 
    	em[2055] = 1899; em[2056] = 184; 
    	em[2057] = 2082; em[2058] = 192; 
    	em[2059] = 1893; em[2060] = 200; 
    em[2061] = 8884097; em[2062] = 8; em[2063] = 0; /* 2061: pointer.func */
    em[2064] = 8884097; em[2065] = 8; em[2066] = 0; /* 2064: pointer.func */
    em[2067] = 8884097; em[2068] = 8; em[2069] = 0; /* 2067: pointer.func */
    em[2070] = 8884097; em[2071] = 8; em[2072] = 0; /* 2070: pointer.func */
    em[2073] = 8884097; em[2074] = 8; em[2075] = 0; /* 2073: pointer.func */
    em[2076] = 8884097; em[2077] = 8; em[2078] = 0; /* 2076: pointer.func */
    em[2079] = 8884097; em[2080] = 8; em[2081] = 0; /* 2079: pointer.func */
    em[2082] = 8884097; em[2083] = 8; em[2084] = 0; /* 2082: pointer.func */
    em[2085] = 1; em[2086] = 8; em[2087] = 1; /* 2085: pointer.struct.hmac_ctx_st */
    	em[2088] = 1908; em[2089] = 0; 
    args_addr->arg_entity_index[0] = 2085;
    args_addr->arg_entity_index[1] = 405;
    args_addr->arg_entity_index[2] = 5;
    args_addr->arg_entity_index[3] = 1919;
    args_addr->arg_entity_index[4] = 1974;
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

