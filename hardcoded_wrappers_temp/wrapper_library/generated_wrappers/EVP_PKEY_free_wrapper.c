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

void bb_EVP_PKEY_free(EVP_PKEY * arg_a);

void EVP_PKEY_free(EVP_PKEY * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_PKEY_free called %lu\n", in_lib);
    if (!in_lib)
        bb_EVP_PKEY_free(arg_a);
    else {
        void (*orig_EVP_PKEY_free)(EVP_PKEY *);
        orig_EVP_PKEY_free = dlsym(RTLD_NEXT, "EVP_PKEY_free");
        orig_EVP_PKEY_free(arg_a);
    }
}

void bb_EVP_PKEY_free(EVP_PKEY * arg_a) 
{
    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 1; em[1] = 8; em[2] = 1; /* 0: pointer.struct.ASN1_VALUE_st */
    	em[3] = 5; em[4] = 0; 
    em[5] = 0; em[6] = 0; em[7] = 0; /* 5: struct.ASN1_VALUE_st */
    em[8] = 1; em[9] = 8; em[10] = 1; /* 8: pointer.struct.asn1_string_st */
    	em[11] = 13; em[12] = 0; 
    em[13] = 0; em[14] = 24; em[15] = 1; /* 13: struct.asn1_string_st */
    	em[16] = 18; em[17] = 8; 
    em[18] = 1; em[19] = 8; em[20] = 1; /* 18: pointer.unsigned char */
    	em[21] = 23; em[22] = 0; 
    em[23] = 0; em[24] = 1; em[25] = 0; /* 23: unsigned char */
    em[26] = 1; em[27] = 8; em[28] = 1; /* 26: pointer.struct.asn1_string_st */
    	em[29] = 13; em[30] = 0; 
    em[31] = 1; em[32] = 8; em[33] = 1; /* 31: pointer.struct.asn1_string_st */
    	em[34] = 13; em[35] = 0; 
    em[36] = 1; em[37] = 8; em[38] = 1; /* 36: pointer.struct.asn1_string_st */
    	em[39] = 13; em[40] = 0; 
    em[41] = 1; em[42] = 8; em[43] = 1; /* 41: pointer.struct.asn1_string_st */
    	em[44] = 13; em[45] = 0; 
    em[46] = 1; em[47] = 8; em[48] = 1; /* 46: pointer.struct.asn1_string_st */
    	em[49] = 13; em[50] = 0; 
    em[51] = 1; em[52] = 8; em[53] = 1; /* 51: pointer.struct.asn1_string_st */
    	em[54] = 13; em[55] = 0; 
    em[56] = 1; em[57] = 8; em[58] = 1; /* 56: pointer.struct.asn1_string_st */
    	em[59] = 13; em[60] = 0; 
    em[61] = 1; em[62] = 8; em[63] = 1; /* 61: pointer.struct.asn1_string_st */
    	em[64] = 13; em[65] = 0; 
    em[66] = 1; em[67] = 8; em[68] = 1; /* 66: pointer.struct.asn1_string_st */
    	em[69] = 13; em[70] = 0; 
    em[71] = 1; em[72] = 8; em[73] = 1; /* 71: pointer.struct.asn1_string_st */
    	em[74] = 13; em[75] = 0; 
    em[76] = 1; em[77] = 8; em[78] = 1; /* 76: pointer.struct.asn1_string_st */
    	em[79] = 13; em[80] = 0; 
    em[81] = 1; em[82] = 8; em[83] = 1; /* 81: pointer.struct.asn1_string_st */
    	em[84] = 13; em[85] = 0; 
    em[86] = 0; em[87] = 16; em[88] = 1; /* 86: struct.asn1_type_st */
    	em[89] = 91; em[90] = 8; 
    em[91] = 0; em[92] = 8; em[93] = 20; /* 91: union.unknown */
    	em[94] = 134; em[95] = 0; 
    	em[96] = 81; em[97] = 0; 
    	em[98] = 139; em[99] = 0; 
    	em[100] = 163; em[101] = 0; 
    	em[102] = 76; em[103] = 0; 
    	em[104] = 71; em[105] = 0; 
    	em[106] = 66; em[107] = 0; 
    	em[108] = 61; em[109] = 0; 
    	em[110] = 168; em[111] = 0; 
    	em[112] = 56; em[113] = 0; 
    	em[114] = 51; em[115] = 0; 
    	em[116] = 46; em[117] = 0; 
    	em[118] = 41; em[119] = 0; 
    	em[120] = 36; em[121] = 0; 
    	em[122] = 31; em[123] = 0; 
    	em[124] = 26; em[125] = 0; 
    	em[126] = 8; em[127] = 0; 
    	em[128] = 81; em[129] = 0; 
    	em[130] = 81; em[131] = 0; 
    	em[132] = 0; em[133] = 0; 
    em[134] = 1; em[135] = 8; em[136] = 1; /* 134: pointer.char */
    	em[137] = 8884096; em[138] = 0; 
    em[139] = 1; em[140] = 8; em[141] = 1; /* 139: pointer.struct.asn1_object_st */
    	em[142] = 144; em[143] = 0; 
    em[144] = 0; em[145] = 40; em[146] = 3; /* 144: struct.asn1_object_st */
    	em[147] = 153; em[148] = 0; 
    	em[149] = 153; em[150] = 8; 
    	em[151] = 158; em[152] = 24; 
    em[153] = 1; em[154] = 8; em[155] = 1; /* 153: pointer.char */
    	em[156] = 8884096; em[157] = 0; 
    em[158] = 1; em[159] = 8; em[160] = 1; /* 158: pointer.unsigned char */
    	em[161] = 23; em[162] = 0; 
    em[163] = 1; em[164] = 8; em[165] = 1; /* 163: pointer.struct.asn1_string_st */
    	em[166] = 13; em[167] = 0; 
    em[168] = 1; em[169] = 8; em[170] = 1; /* 168: pointer.struct.asn1_string_st */
    	em[171] = 13; em[172] = 0; 
    em[173] = 1; em[174] = 8; em[175] = 1; /* 173: pointer.struct.ASN1_VALUE_st */
    	em[176] = 178; em[177] = 0; 
    em[178] = 0; em[179] = 0; em[180] = 0; /* 178: struct.ASN1_VALUE_st */
    em[181] = 1; em[182] = 8; em[183] = 1; /* 181: pointer.struct.asn1_string_st */
    	em[184] = 186; em[185] = 0; 
    em[186] = 0; em[187] = 24; em[188] = 1; /* 186: struct.asn1_string_st */
    	em[189] = 18; em[190] = 8; 
    em[191] = 1; em[192] = 8; em[193] = 1; /* 191: pointer.struct.dh_st */
    	em[194] = 196; em[195] = 0; 
    em[196] = 0; em[197] = 144; em[198] = 12; /* 196: struct.dh_st */
    	em[199] = 223; em[200] = 8; 
    	em[201] = 223; em[202] = 16; 
    	em[203] = 223; em[204] = 32; 
    	em[205] = 223; em[206] = 40; 
    	em[207] = 246; em[208] = 56; 
    	em[209] = 223; em[210] = 64; 
    	em[211] = 223; em[212] = 72; 
    	em[213] = 18; em[214] = 80; 
    	em[215] = 223; em[216] = 96; 
    	em[217] = 260; em[218] = 112; 
    	em[219] = 290; em[220] = 128; 
    	em[221] = 326; em[222] = 136; 
    em[223] = 1; em[224] = 8; em[225] = 1; /* 223: pointer.struct.bignum_st */
    	em[226] = 228; em[227] = 0; 
    em[228] = 0; em[229] = 24; em[230] = 1; /* 228: struct.bignum_st */
    	em[231] = 233; em[232] = 0; 
    em[233] = 8884099; em[234] = 8; em[235] = 2; /* 233: pointer_to_array_of_pointers_to_stack */
    	em[236] = 240; em[237] = 0; 
    	em[238] = 243; em[239] = 12; 
    em[240] = 0; em[241] = 8; em[242] = 0; /* 240: long unsigned int */
    em[243] = 0; em[244] = 4; em[245] = 0; /* 243: int */
    em[246] = 1; em[247] = 8; em[248] = 1; /* 246: pointer.struct.bn_mont_ctx_st */
    	em[249] = 251; em[250] = 0; 
    em[251] = 0; em[252] = 96; em[253] = 3; /* 251: struct.bn_mont_ctx_st */
    	em[254] = 228; em[255] = 8; 
    	em[256] = 228; em[257] = 32; 
    	em[258] = 228; em[259] = 56; 
    em[260] = 0; em[261] = 16; em[262] = 1; /* 260: struct.crypto_ex_data_st */
    	em[263] = 265; em[264] = 0; 
    em[265] = 1; em[266] = 8; em[267] = 1; /* 265: pointer.struct.stack_st_void */
    	em[268] = 270; em[269] = 0; 
    em[270] = 0; em[271] = 32; em[272] = 1; /* 270: struct.stack_st_void */
    	em[273] = 275; em[274] = 0; 
    em[275] = 0; em[276] = 32; em[277] = 2; /* 275: struct.stack_st */
    	em[278] = 282; em[279] = 8; 
    	em[280] = 287; em[281] = 24; 
    em[282] = 1; em[283] = 8; em[284] = 1; /* 282: pointer.pointer.char */
    	em[285] = 134; em[286] = 0; 
    em[287] = 8884097; em[288] = 8; em[289] = 0; /* 287: pointer.func */
    em[290] = 1; em[291] = 8; em[292] = 1; /* 290: pointer.struct.dh_method */
    	em[293] = 295; em[294] = 0; 
    em[295] = 0; em[296] = 72; em[297] = 8; /* 295: struct.dh_method */
    	em[298] = 153; em[299] = 0; 
    	em[300] = 314; em[301] = 8; 
    	em[302] = 317; em[303] = 16; 
    	em[304] = 320; em[305] = 24; 
    	em[306] = 314; em[307] = 32; 
    	em[308] = 314; em[309] = 40; 
    	em[310] = 134; em[311] = 56; 
    	em[312] = 323; em[313] = 64; 
    em[314] = 8884097; em[315] = 8; em[316] = 0; /* 314: pointer.func */
    em[317] = 8884097; em[318] = 8; em[319] = 0; /* 317: pointer.func */
    em[320] = 8884097; em[321] = 8; em[322] = 0; /* 320: pointer.func */
    em[323] = 8884097; em[324] = 8; em[325] = 0; /* 323: pointer.func */
    em[326] = 1; em[327] = 8; em[328] = 1; /* 326: pointer.struct.engine_st */
    	em[329] = 331; em[330] = 0; 
    em[331] = 0; em[332] = 216; em[333] = 24; /* 331: struct.engine_st */
    	em[334] = 153; em[335] = 0; 
    	em[336] = 153; em[337] = 8; 
    	em[338] = 382; em[339] = 16; 
    	em[340] = 437; em[341] = 24; 
    	em[342] = 488; em[343] = 32; 
    	em[344] = 524; em[345] = 40; 
    	em[346] = 541; em[347] = 48; 
    	em[348] = 568; em[349] = 56; 
    	em[350] = 603; em[351] = 64; 
    	em[352] = 611; em[353] = 72; 
    	em[354] = 614; em[355] = 80; 
    	em[356] = 617; em[357] = 88; 
    	em[358] = 620; em[359] = 96; 
    	em[360] = 623; em[361] = 104; 
    	em[362] = 623; em[363] = 112; 
    	em[364] = 623; em[365] = 120; 
    	em[366] = 626; em[367] = 128; 
    	em[368] = 629; em[369] = 136; 
    	em[370] = 629; em[371] = 144; 
    	em[372] = 632; em[373] = 152; 
    	em[374] = 635; em[375] = 160; 
    	em[376] = 647; em[377] = 184; 
    	em[378] = 669; em[379] = 200; 
    	em[380] = 669; em[381] = 208; 
    em[382] = 1; em[383] = 8; em[384] = 1; /* 382: pointer.struct.rsa_meth_st */
    	em[385] = 387; em[386] = 0; 
    em[387] = 0; em[388] = 112; em[389] = 13; /* 387: struct.rsa_meth_st */
    	em[390] = 153; em[391] = 0; 
    	em[392] = 416; em[393] = 8; 
    	em[394] = 416; em[395] = 16; 
    	em[396] = 416; em[397] = 24; 
    	em[398] = 416; em[399] = 32; 
    	em[400] = 419; em[401] = 40; 
    	em[402] = 422; em[403] = 48; 
    	em[404] = 425; em[405] = 56; 
    	em[406] = 425; em[407] = 64; 
    	em[408] = 134; em[409] = 80; 
    	em[410] = 428; em[411] = 88; 
    	em[412] = 431; em[413] = 96; 
    	em[414] = 434; em[415] = 104; 
    em[416] = 8884097; em[417] = 8; em[418] = 0; /* 416: pointer.func */
    em[419] = 8884097; em[420] = 8; em[421] = 0; /* 419: pointer.func */
    em[422] = 8884097; em[423] = 8; em[424] = 0; /* 422: pointer.func */
    em[425] = 8884097; em[426] = 8; em[427] = 0; /* 425: pointer.func */
    em[428] = 8884097; em[429] = 8; em[430] = 0; /* 428: pointer.func */
    em[431] = 8884097; em[432] = 8; em[433] = 0; /* 431: pointer.func */
    em[434] = 8884097; em[435] = 8; em[436] = 0; /* 434: pointer.func */
    em[437] = 1; em[438] = 8; em[439] = 1; /* 437: pointer.struct.dsa_method */
    	em[440] = 442; em[441] = 0; 
    em[442] = 0; em[443] = 96; em[444] = 11; /* 442: struct.dsa_method */
    	em[445] = 153; em[446] = 0; 
    	em[447] = 467; em[448] = 8; 
    	em[449] = 470; em[450] = 16; 
    	em[451] = 473; em[452] = 24; 
    	em[453] = 476; em[454] = 32; 
    	em[455] = 479; em[456] = 40; 
    	em[457] = 482; em[458] = 48; 
    	em[459] = 482; em[460] = 56; 
    	em[461] = 134; em[462] = 72; 
    	em[463] = 485; em[464] = 80; 
    	em[465] = 482; em[466] = 88; 
    em[467] = 8884097; em[468] = 8; em[469] = 0; /* 467: pointer.func */
    em[470] = 8884097; em[471] = 8; em[472] = 0; /* 470: pointer.func */
    em[473] = 8884097; em[474] = 8; em[475] = 0; /* 473: pointer.func */
    em[476] = 8884097; em[477] = 8; em[478] = 0; /* 476: pointer.func */
    em[479] = 8884097; em[480] = 8; em[481] = 0; /* 479: pointer.func */
    em[482] = 8884097; em[483] = 8; em[484] = 0; /* 482: pointer.func */
    em[485] = 8884097; em[486] = 8; em[487] = 0; /* 485: pointer.func */
    em[488] = 1; em[489] = 8; em[490] = 1; /* 488: pointer.struct.dh_method */
    	em[491] = 493; em[492] = 0; 
    em[493] = 0; em[494] = 72; em[495] = 8; /* 493: struct.dh_method */
    	em[496] = 153; em[497] = 0; 
    	em[498] = 512; em[499] = 8; 
    	em[500] = 515; em[501] = 16; 
    	em[502] = 518; em[503] = 24; 
    	em[504] = 512; em[505] = 32; 
    	em[506] = 512; em[507] = 40; 
    	em[508] = 134; em[509] = 56; 
    	em[510] = 521; em[511] = 64; 
    em[512] = 8884097; em[513] = 8; em[514] = 0; /* 512: pointer.func */
    em[515] = 8884097; em[516] = 8; em[517] = 0; /* 515: pointer.func */
    em[518] = 8884097; em[519] = 8; em[520] = 0; /* 518: pointer.func */
    em[521] = 8884097; em[522] = 8; em[523] = 0; /* 521: pointer.func */
    em[524] = 1; em[525] = 8; em[526] = 1; /* 524: pointer.struct.ecdh_method */
    	em[527] = 529; em[528] = 0; 
    em[529] = 0; em[530] = 32; em[531] = 3; /* 529: struct.ecdh_method */
    	em[532] = 153; em[533] = 0; 
    	em[534] = 538; em[535] = 8; 
    	em[536] = 134; em[537] = 24; 
    em[538] = 8884097; em[539] = 8; em[540] = 0; /* 538: pointer.func */
    em[541] = 1; em[542] = 8; em[543] = 1; /* 541: pointer.struct.ecdsa_method */
    	em[544] = 546; em[545] = 0; 
    em[546] = 0; em[547] = 48; em[548] = 5; /* 546: struct.ecdsa_method */
    	em[549] = 153; em[550] = 0; 
    	em[551] = 559; em[552] = 8; 
    	em[553] = 562; em[554] = 16; 
    	em[555] = 565; em[556] = 24; 
    	em[557] = 134; em[558] = 40; 
    em[559] = 8884097; em[560] = 8; em[561] = 0; /* 559: pointer.func */
    em[562] = 8884097; em[563] = 8; em[564] = 0; /* 562: pointer.func */
    em[565] = 8884097; em[566] = 8; em[567] = 0; /* 565: pointer.func */
    em[568] = 1; em[569] = 8; em[570] = 1; /* 568: pointer.struct.rand_meth_st */
    	em[571] = 573; em[572] = 0; 
    em[573] = 0; em[574] = 48; em[575] = 6; /* 573: struct.rand_meth_st */
    	em[576] = 588; em[577] = 0; 
    	em[578] = 591; em[579] = 8; 
    	em[580] = 594; em[581] = 16; 
    	em[582] = 597; em[583] = 24; 
    	em[584] = 591; em[585] = 32; 
    	em[586] = 600; em[587] = 40; 
    em[588] = 8884097; em[589] = 8; em[590] = 0; /* 588: pointer.func */
    em[591] = 8884097; em[592] = 8; em[593] = 0; /* 591: pointer.func */
    em[594] = 8884097; em[595] = 8; em[596] = 0; /* 594: pointer.func */
    em[597] = 8884097; em[598] = 8; em[599] = 0; /* 597: pointer.func */
    em[600] = 8884097; em[601] = 8; em[602] = 0; /* 600: pointer.func */
    em[603] = 1; em[604] = 8; em[605] = 1; /* 603: pointer.struct.store_method_st */
    	em[606] = 608; em[607] = 0; 
    em[608] = 0; em[609] = 0; em[610] = 0; /* 608: struct.store_method_st */
    em[611] = 8884097; em[612] = 8; em[613] = 0; /* 611: pointer.func */
    em[614] = 8884097; em[615] = 8; em[616] = 0; /* 614: pointer.func */
    em[617] = 8884097; em[618] = 8; em[619] = 0; /* 617: pointer.func */
    em[620] = 8884097; em[621] = 8; em[622] = 0; /* 620: pointer.func */
    em[623] = 8884097; em[624] = 8; em[625] = 0; /* 623: pointer.func */
    em[626] = 8884097; em[627] = 8; em[628] = 0; /* 626: pointer.func */
    em[629] = 8884097; em[630] = 8; em[631] = 0; /* 629: pointer.func */
    em[632] = 8884097; em[633] = 8; em[634] = 0; /* 632: pointer.func */
    em[635] = 1; em[636] = 8; em[637] = 1; /* 635: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[638] = 640; em[639] = 0; 
    em[640] = 0; em[641] = 32; em[642] = 2; /* 640: struct.ENGINE_CMD_DEFN_st */
    	em[643] = 153; em[644] = 8; 
    	em[645] = 153; em[646] = 16; 
    em[647] = 0; em[648] = 16; em[649] = 1; /* 647: struct.crypto_ex_data_st */
    	em[650] = 652; em[651] = 0; 
    em[652] = 1; em[653] = 8; em[654] = 1; /* 652: pointer.struct.stack_st_void */
    	em[655] = 657; em[656] = 0; 
    em[657] = 0; em[658] = 32; em[659] = 1; /* 657: struct.stack_st_void */
    	em[660] = 662; em[661] = 0; 
    em[662] = 0; em[663] = 32; em[664] = 2; /* 662: struct.stack_st */
    	em[665] = 282; em[666] = 8; 
    	em[667] = 287; em[668] = 24; 
    em[669] = 1; em[670] = 8; em[671] = 1; /* 669: pointer.struct.engine_st */
    	em[672] = 331; em[673] = 0; 
    em[674] = 8884097; em[675] = 8; em[676] = 0; /* 674: pointer.func */
    em[677] = 8884097; em[678] = 8; em[679] = 0; /* 677: pointer.func */
    em[680] = 0; em[681] = 136; em[682] = 11; /* 680: struct.dsa_st */
    	em[683] = 705; em[684] = 24; 
    	em[685] = 705; em[686] = 32; 
    	em[687] = 705; em[688] = 40; 
    	em[689] = 705; em[690] = 48; 
    	em[691] = 705; em[692] = 56; 
    	em[693] = 705; em[694] = 64; 
    	em[695] = 705; em[696] = 72; 
    	em[697] = 722; em[698] = 88; 
    	em[699] = 736; em[700] = 104; 
    	em[701] = 758; em[702] = 120; 
    	em[703] = 326; em[704] = 128; 
    em[705] = 1; em[706] = 8; em[707] = 1; /* 705: pointer.struct.bignum_st */
    	em[708] = 710; em[709] = 0; 
    em[710] = 0; em[711] = 24; em[712] = 1; /* 710: struct.bignum_st */
    	em[713] = 715; em[714] = 0; 
    em[715] = 8884099; em[716] = 8; em[717] = 2; /* 715: pointer_to_array_of_pointers_to_stack */
    	em[718] = 240; em[719] = 0; 
    	em[720] = 243; em[721] = 12; 
    em[722] = 1; em[723] = 8; em[724] = 1; /* 722: pointer.struct.bn_mont_ctx_st */
    	em[725] = 727; em[726] = 0; 
    em[727] = 0; em[728] = 96; em[729] = 3; /* 727: struct.bn_mont_ctx_st */
    	em[730] = 710; em[731] = 8; 
    	em[732] = 710; em[733] = 32; 
    	em[734] = 710; em[735] = 56; 
    em[736] = 0; em[737] = 16; em[738] = 1; /* 736: struct.crypto_ex_data_st */
    	em[739] = 741; em[740] = 0; 
    em[741] = 1; em[742] = 8; em[743] = 1; /* 741: pointer.struct.stack_st_void */
    	em[744] = 746; em[745] = 0; 
    em[746] = 0; em[747] = 32; em[748] = 1; /* 746: struct.stack_st_void */
    	em[749] = 751; em[750] = 0; 
    em[751] = 0; em[752] = 32; em[753] = 2; /* 751: struct.stack_st */
    	em[754] = 282; em[755] = 8; 
    	em[756] = 287; em[757] = 24; 
    em[758] = 1; em[759] = 8; em[760] = 1; /* 758: pointer.struct.dsa_method */
    	em[761] = 763; em[762] = 0; 
    em[763] = 0; em[764] = 96; em[765] = 11; /* 763: struct.dsa_method */
    	em[766] = 153; em[767] = 0; 
    	em[768] = 788; em[769] = 8; 
    	em[770] = 791; em[771] = 16; 
    	em[772] = 794; em[773] = 24; 
    	em[774] = 674; em[775] = 32; 
    	em[776] = 797; em[777] = 40; 
    	em[778] = 800; em[779] = 48; 
    	em[780] = 800; em[781] = 56; 
    	em[782] = 134; em[783] = 72; 
    	em[784] = 803; em[785] = 80; 
    	em[786] = 800; em[787] = 88; 
    em[788] = 8884097; em[789] = 8; em[790] = 0; /* 788: pointer.func */
    em[791] = 8884097; em[792] = 8; em[793] = 0; /* 791: pointer.func */
    em[794] = 8884097; em[795] = 8; em[796] = 0; /* 794: pointer.func */
    em[797] = 8884097; em[798] = 8; em[799] = 0; /* 797: pointer.func */
    em[800] = 8884097; em[801] = 8; em[802] = 0; /* 800: pointer.func */
    em[803] = 8884097; em[804] = 8; em[805] = 0; /* 803: pointer.func */
    em[806] = 1; em[807] = 8; em[808] = 1; /* 806: pointer.struct.bignum_st */
    	em[809] = 811; em[810] = 0; 
    em[811] = 0; em[812] = 24; em[813] = 1; /* 811: struct.bignum_st */
    	em[814] = 816; em[815] = 0; 
    em[816] = 8884099; em[817] = 8; em[818] = 2; /* 816: pointer_to_array_of_pointers_to_stack */
    	em[819] = 240; em[820] = 0; 
    	em[821] = 243; em[822] = 12; 
    em[823] = 0; em[824] = 8; em[825] = 0; /* 823: pointer.void */
    em[826] = 0; em[827] = 88; em[828] = 7; /* 826: struct.bn_blinding_st */
    	em[829] = 806; em[830] = 0; 
    	em[831] = 806; em[832] = 8; 
    	em[833] = 806; em[834] = 16; 
    	em[835] = 806; em[836] = 24; 
    	em[837] = 843; em[838] = 40; 
    	em[839] = 848; em[840] = 72; 
    	em[841] = 862; em[842] = 80; 
    em[843] = 0; em[844] = 16; em[845] = 1; /* 843: struct.crypto_threadid_st */
    	em[846] = 823; em[847] = 0; 
    em[848] = 1; em[849] = 8; em[850] = 1; /* 848: pointer.struct.bn_mont_ctx_st */
    	em[851] = 853; em[852] = 0; 
    em[853] = 0; em[854] = 96; em[855] = 3; /* 853: struct.bn_mont_ctx_st */
    	em[856] = 811; em[857] = 8; 
    	em[858] = 811; em[859] = 32; 
    	em[860] = 811; em[861] = 56; 
    em[862] = 8884097; em[863] = 8; em[864] = 0; /* 862: pointer.func */
    em[865] = 8884097; em[866] = 8; em[867] = 0; /* 865: pointer.func */
    em[868] = 1; em[869] = 8; em[870] = 1; /* 868: pointer.struct.bn_blinding_st */
    	em[871] = 826; em[872] = 0; 
    em[873] = 0; em[874] = 8; em[875] = 5; /* 873: union.unknown */
    	em[876] = 134; em[877] = 0; 
    	em[878] = 886; em[879] = 0; 
    	em[880] = 983; em[881] = 0; 
    	em[882] = 191; em[883] = 0; 
    	em[884] = 988; em[885] = 0; 
    em[886] = 1; em[887] = 8; em[888] = 1; /* 886: pointer.struct.rsa_st */
    	em[889] = 891; em[890] = 0; 
    em[891] = 0; em[892] = 168; em[893] = 17; /* 891: struct.rsa_st */
    	em[894] = 928; em[895] = 16; 
    	em[896] = 326; em[897] = 24; 
    	em[898] = 705; em[899] = 32; 
    	em[900] = 705; em[901] = 40; 
    	em[902] = 705; em[903] = 48; 
    	em[904] = 705; em[905] = 56; 
    	em[906] = 705; em[907] = 64; 
    	em[908] = 705; em[909] = 72; 
    	em[910] = 705; em[911] = 80; 
    	em[912] = 705; em[913] = 88; 
    	em[914] = 736; em[915] = 96; 
    	em[916] = 722; em[917] = 120; 
    	em[918] = 722; em[919] = 128; 
    	em[920] = 722; em[921] = 136; 
    	em[922] = 134; em[923] = 144; 
    	em[924] = 868; em[925] = 152; 
    	em[926] = 868; em[927] = 160; 
    em[928] = 1; em[929] = 8; em[930] = 1; /* 928: pointer.struct.rsa_meth_st */
    	em[931] = 933; em[932] = 0; 
    em[933] = 0; em[934] = 112; em[935] = 13; /* 933: struct.rsa_meth_st */
    	em[936] = 153; em[937] = 0; 
    	em[938] = 962; em[939] = 8; 
    	em[940] = 962; em[941] = 16; 
    	em[942] = 962; em[943] = 24; 
    	em[944] = 962; em[945] = 32; 
    	em[946] = 965; em[947] = 40; 
    	em[948] = 968; em[949] = 48; 
    	em[950] = 971; em[951] = 56; 
    	em[952] = 971; em[953] = 64; 
    	em[954] = 134; em[955] = 80; 
    	em[956] = 974; em[957] = 88; 
    	em[958] = 977; em[959] = 96; 
    	em[960] = 980; em[961] = 104; 
    em[962] = 8884097; em[963] = 8; em[964] = 0; /* 962: pointer.func */
    em[965] = 8884097; em[966] = 8; em[967] = 0; /* 965: pointer.func */
    em[968] = 8884097; em[969] = 8; em[970] = 0; /* 968: pointer.func */
    em[971] = 8884097; em[972] = 8; em[973] = 0; /* 971: pointer.func */
    em[974] = 8884097; em[975] = 8; em[976] = 0; /* 974: pointer.func */
    em[977] = 8884097; em[978] = 8; em[979] = 0; /* 977: pointer.func */
    em[980] = 8884097; em[981] = 8; em[982] = 0; /* 980: pointer.func */
    em[983] = 1; em[984] = 8; em[985] = 1; /* 983: pointer.struct.dsa_st */
    	em[986] = 680; em[987] = 0; 
    em[988] = 1; em[989] = 8; em[990] = 1; /* 988: pointer.struct.ec_key_st */
    	em[991] = 993; em[992] = 0; 
    em[993] = 0; em[994] = 56; em[995] = 4; /* 993: struct.ec_key_st */
    	em[996] = 1004; em[997] = 8; 
    	em[998] = 1446; em[999] = 16; 
    	em[1000] = 1451; em[1001] = 24; 
    	em[1002] = 1468; em[1003] = 48; 
    em[1004] = 1; em[1005] = 8; em[1006] = 1; /* 1004: pointer.struct.ec_group_st */
    	em[1007] = 1009; em[1008] = 0; 
    em[1009] = 0; em[1010] = 232; em[1011] = 12; /* 1009: struct.ec_group_st */
    	em[1012] = 1036; em[1013] = 0; 
    	em[1014] = 1202; em[1015] = 8; 
    	em[1016] = 1402; em[1017] = 16; 
    	em[1018] = 1402; em[1019] = 40; 
    	em[1020] = 18; em[1021] = 80; 
    	em[1022] = 1414; em[1023] = 96; 
    	em[1024] = 1402; em[1025] = 104; 
    	em[1026] = 1402; em[1027] = 152; 
    	em[1028] = 1402; em[1029] = 176; 
    	em[1030] = 823; em[1031] = 208; 
    	em[1032] = 823; em[1033] = 216; 
    	em[1034] = 1443; em[1035] = 224; 
    em[1036] = 1; em[1037] = 8; em[1038] = 1; /* 1036: pointer.struct.ec_method_st */
    	em[1039] = 1041; em[1040] = 0; 
    em[1041] = 0; em[1042] = 304; em[1043] = 37; /* 1041: struct.ec_method_st */
    	em[1044] = 1118; em[1045] = 8; 
    	em[1046] = 677; em[1047] = 16; 
    	em[1048] = 677; em[1049] = 24; 
    	em[1050] = 1121; em[1051] = 32; 
    	em[1052] = 1124; em[1053] = 40; 
    	em[1054] = 1127; em[1055] = 48; 
    	em[1056] = 1130; em[1057] = 56; 
    	em[1058] = 1133; em[1059] = 64; 
    	em[1060] = 1136; em[1061] = 72; 
    	em[1062] = 1139; em[1063] = 80; 
    	em[1064] = 1139; em[1065] = 88; 
    	em[1066] = 1142; em[1067] = 96; 
    	em[1068] = 1145; em[1069] = 104; 
    	em[1070] = 1148; em[1071] = 112; 
    	em[1072] = 1151; em[1073] = 120; 
    	em[1074] = 1154; em[1075] = 128; 
    	em[1076] = 1157; em[1077] = 136; 
    	em[1078] = 1160; em[1079] = 144; 
    	em[1080] = 1163; em[1081] = 152; 
    	em[1082] = 1166; em[1083] = 160; 
    	em[1084] = 1169; em[1085] = 168; 
    	em[1086] = 1172; em[1087] = 176; 
    	em[1088] = 1175; em[1089] = 184; 
    	em[1090] = 1178; em[1091] = 192; 
    	em[1092] = 1181; em[1093] = 200; 
    	em[1094] = 1184; em[1095] = 208; 
    	em[1096] = 1175; em[1097] = 216; 
    	em[1098] = 865; em[1099] = 224; 
    	em[1100] = 1187; em[1101] = 232; 
    	em[1102] = 1190; em[1103] = 240; 
    	em[1104] = 1130; em[1105] = 248; 
    	em[1106] = 1193; em[1107] = 256; 
    	em[1108] = 1196; em[1109] = 264; 
    	em[1110] = 1193; em[1111] = 272; 
    	em[1112] = 1196; em[1113] = 280; 
    	em[1114] = 1196; em[1115] = 288; 
    	em[1116] = 1199; em[1117] = 296; 
    em[1118] = 8884097; em[1119] = 8; em[1120] = 0; /* 1118: pointer.func */
    em[1121] = 8884097; em[1122] = 8; em[1123] = 0; /* 1121: pointer.func */
    em[1124] = 8884097; em[1125] = 8; em[1126] = 0; /* 1124: pointer.func */
    em[1127] = 8884097; em[1128] = 8; em[1129] = 0; /* 1127: pointer.func */
    em[1130] = 8884097; em[1131] = 8; em[1132] = 0; /* 1130: pointer.func */
    em[1133] = 8884097; em[1134] = 8; em[1135] = 0; /* 1133: pointer.func */
    em[1136] = 8884097; em[1137] = 8; em[1138] = 0; /* 1136: pointer.func */
    em[1139] = 8884097; em[1140] = 8; em[1141] = 0; /* 1139: pointer.func */
    em[1142] = 8884097; em[1143] = 8; em[1144] = 0; /* 1142: pointer.func */
    em[1145] = 8884097; em[1146] = 8; em[1147] = 0; /* 1145: pointer.func */
    em[1148] = 8884097; em[1149] = 8; em[1150] = 0; /* 1148: pointer.func */
    em[1151] = 8884097; em[1152] = 8; em[1153] = 0; /* 1151: pointer.func */
    em[1154] = 8884097; em[1155] = 8; em[1156] = 0; /* 1154: pointer.func */
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
    em[1196] = 8884097; em[1197] = 8; em[1198] = 0; /* 1196: pointer.func */
    em[1199] = 8884097; em[1200] = 8; em[1201] = 0; /* 1199: pointer.func */
    em[1202] = 1; em[1203] = 8; em[1204] = 1; /* 1202: pointer.struct.ec_point_st */
    	em[1205] = 1207; em[1206] = 0; 
    em[1207] = 0; em[1208] = 88; em[1209] = 4; /* 1207: struct.ec_point_st */
    	em[1210] = 1218; em[1211] = 0; 
    	em[1212] = 1390; em[1213] = 8; 
    	em[1214] = 1390; em[1215] = 32; 
    	em[1216] = 1390; em[1217] = 56; 
    em[1218] = 1; em[1219] = 8; em[1220] = 1; /* 1218: pointer.struct.ec_method_st */
    	em[1221] = 1223; em[1222] = 0; 
    em[1223] = 0; em[1224] = 304; em[1225] = 37; /* 1223: struct.ec_method_st */
    	em[1226] = 1300; em[1227] = 8; 
    	em[1228] = 1303; em[1229] = 16; 
    	em[1230] = 1303; em[1231] = 24; 
    	em[1232] = 1306; em[1233] = 32; 
    	em[1234] = 1309; em[1235] = 40; 
    	em[1236] = 1312; em[1237] = 48; 
    	em[1238] = 1315; em[1239] = 56; 
    	em[1240] = 1318; em[1241] = 64; 
    	em[1242] = 1321; em[1243] = 72; 
    	em[1244] = 1324; em[1245] = 80; 
    	em[1246] = 1324; em[1247] = 88; 
    	em[1248] = 1327; em[1249] = 96; 
    	em[1250] = 1330; em[1251] = 104; 
    	em[1252] = 1333; em[1253] = 112; 
    	em[1254] = 1336; em[1255] = 120; 
    	em[1256] = 1339; em[1257] = 128; 
    	em[1258] = 1342; em[1259] = 136; 
    	em[1260] = 1345; em[1261] = 144; 
    	em[1262] = 1348; em[1263] = 152; 
    	em[1264] = 1351; em[1265] = 160; 
    	em[1266] = 1354; em[1267] = 168; 
    	em[1268] = 1357; em[1269] = 176; 
    	em[1270] = 1360; em[1271] = 184; 
    	em[1272] = 1363; em[1273] = 192; 
    	em[1274] = 1366; em[1275] = 200; 
    	em[1276] = 1369; em[1277] = 208; 
    	em[1278] = 1360; em[1279] = 216; 
    	em[1280] = 1372; em[1281] = 224; 
    	em[1282] = 1375; em[1283] = 232; 
    	em[1284] = 1378; em[1285] = 240; 
    	em[1286] = 1315; em[1287] = 248; 
    	em[1288] = 1381; em[1289] = 256; 
    	em[1290] = 1384; em[1291] = 264; 
    	em[1292] = 1381; em[1293] = 272; 
    	em[1294] = 1384; em[1295] = 280; 
    	em[1296] = 1384; em[1297] = 288; 
    	em[1298] = 1387; em[1299] = 296; 
    em[1300] = 8884097; em[1301] = 8; em[1302] = 0; /* 1300: pointer.func */
    em[1303] = 8884097; em[1304] = 8; em[1305] = 0; /* 1303: pointer.func */
    em[1306] = 8884097; em[1307] = 8; em[1308] = 0; /* 1306: pointer.func */
    em[1309] = 8884097; em[1310] = 8; em[1311] = 0; /* 1309: pointer.func */
    em[1312] = 8884097; em[1313] = 8; em[1314] = 0; /* 1312: pointer.func */
    em[1315] = 8884097; em[1316] = 8; em[1317] = 0; /* 1315: pointer.func */
    em[1318] = 8884097; em[1319] = 8; em[1320] = 0; /* 1318: pointer.func */
    em[1321] = 8884097; em[1322] = 8; em[1323] = 0; /* 1321: pointer.func */
    em[1324] = 8884097; em[1325] = 8; em[1326] = 0; /* 1324: pointer.func */
    em[1327] = 8884097; em[1328] = 8; em[1329] = 0; /* 1327: pointer.func */
    em[1330] = 8884097; em[1331] = 8; em[1332] = 0; /* 1330: pointer.func */
    em[1333] = 8884097; em[1334] = 8; em[1335] = 0; /* 1333: pointer.func */
    em[1336] = 8884097; em[1337] = 8; em[1338] = 0; /* 1336: pointer.func */
    em[1339] = 8884097; em[1340] = 8; em[1341] = 0; /* 1339: pointer.func */
    em[1342] = 8884097; em[1343] = 8; em[1344] = 0; /* 1342: pointer.func */
    em[1345] = 8884097; em[1346] = 8; em[1347] = 0; /* 1345: pointer.func */
    em[1348] = 8884097; em[1349] = 8; em[1350] = 0; /* 1348: pointer.func */
    em[1351] = 8884097; em[1352] = 8; em[1353] = 0; /* 1351: pointer.func */
    em[1354] = 8884097; em[1355] = 8; em[1356] = 0; /* 1354: pointer.func */
    em[1357] = 8884097; em[1358] = 8; em[1359] = 0; /* 1357: pointer.func */
    em[1360] = 8884097; em[1361] = 8; em[1362] = 0; /* 1360: pointer.func */
    em[1363] = 8884097; em[1364] = 8; em[1365] = 0; /* 1363: pointer.func */
    em[1366] = 8884097; em[1367] = 8; em[1368] = 0; /* 1366: pointer.func */
    em[1369] = 8884097; em[1370] = 8; em[1371] = 0; /* 1369: pointer.func */
    em[1372] = 8884097; em[1373] = 8; em[1374] = 0; /* 1372: pointer.func */
    em[1375] = 8884097; em[1376] = 8; em[1377] = 0; /* 1375: pointer.func */
    em[1378] = 8884097; em[1379] = 8; em[1380] = 0; /* 1378: pointer.func */
    em[1381] = 8884097; em[1382] = 8; em[1383] = 0; /* 1381: pointer.func */
    em[1384] = 8884097; em[1385] = 8; em[1386] = 0; /* 1384: pointer.func */
    em[1387] = 8884097; em[1388] = 8; em[1389] = 0; /* 1387: pointer.func */
    em[1390] = 0; em[1391] = 24; em[1392] = 1; /* 1390: struct.bignum_st */
    	em[1393] = 1395; em[1394] = 0; 
    em[1395] = 8884099; em[1396] = 8; em[1397] = 2; /* 1395: pointer_to_array_of_pointers_to_stack */
    	em[1398] = 240; em[1399] = 0; 
    	em[1400] = 243; em[1401] = 12; 
    em[1402] = 0; em[1403] = 24; em[1404] = 1; /* 1402: struct.bignum_st */
    	em[1405] = 1407; em[1406] = 0; 
    em[1407] = 8884099; em[1408] = 8; em[1409] = 2; /* 1407: pointer_to_array_of_pointers_to_stack */
    	em[1410] = 240; em[1411] = 0; 
    	em[1412] = 243; em[1413] = 12; 
    em[1414] = 1; em[1415] = 8; em[1416] = 1; /* 1414: pointer.struct.ec_extra_data_st */
    	em[1417] = 1419; em[1418] = 0; 
    em[1419] = 0; em[1420] = 40; em[1421] = 5; /* 1419: struct.ec_extra_data_st */
    	em[1422] = 1432; em[1423] = 0; 
    	em[1424] = 823; em[1425] = 8; 
    	em[1426] = 1437; em[1427] = 16; 
    	em[1428] = 1440; em[1429] = 24; 
    	em[1430] = 1440; em[1431] = 32; 
    em[1432] = 1; em[1433] = 8; em[1434] = 1; /* 1432: pointer.struct.ec_extra_data_st */
    	em[1435] = 1419; em[1436] = 0; 
    em[1437] = 8884097; em[1438] = 8; em[1439] = 0; /* 1437: pointer.func */
    em[1440] = 8884097; em[1441] = 8; em[1442] = 0; /* 1440: pointer.func */
    em[1443] = 8884097; em[1444] = 8; em[1445] = 0; /* 1443: pointer.func */
    em[1446] = 1; em[1447] = 8; em[1448] = 1; /* 1446: pointer.struct.ec_point_st */
    	em[1449] = 1207; em[1450] = 0; 
    em[1451] = 1; em[1452] = 8; em[1453] = 1; /* 1451: pointer.struct.bignum_st */
    	em[1454] = 1456; em[1455] = 0; 
    em[1456] = 0; em[1457] = 24; em[1458] = 1; /* 1456: struct.bignum_st */
    	em[1459] = 1461; em[1460] = 0; 
    em[1461] = 8884099; em[1462] = 8; em[1463] = 2; /* 1461: pointer_to_array_of_pointers_to_stack */
    	em[1464] = 240; em[1465] = 0; 
    	em[1466] = 243; em[1467] = 12; 
    em[1468] = 1; em[1469] = 8; em[1470] = 1; /* 1468: pointer.struct.ec_extra_data_st */
    	em[1471] = 1473; em[1472] = 0; 
    em[1473] = 0; em[1474] = 40; em[1475] = 5; /* 1473: struct.ec_extra_data_st */
    	em[1476] = 1486; em[1477] = 0; 
    	em[1478] = 823; em[1479] = 8; 
    	em[1480] = 1437; em[1481] = 16; 
    	em[1482] = 1440; em[1483] = 24; 
    	em[1484] = 1440; em[1485] = 32; 
    em[1486] = 1; em[1487] = 8; em[1488] = 1; /* 1486: pointer.struct.ec_extra_data_st */
    	em[1489] = 1473; em[1490] = 0; 
    em[1491] = 1; em[1492] = 8; em[1493] = 1; /* 1491: pointer.struct.asn1_string_st */
    	em[1494] = 186; em[1495] = 0; 
    em[1496] = 8884099; em[1497] = 8; em[1498] = 2; /* 1496: pointer_to_array_of_pointers_to_stack */
    	em[1499] = 1503; em[1500] = 0; 
    	em[1501] = 243; em[1502] = 20; 
    em[1503] = 0; em[1504] = 8; em[1505] = 1; /* 1503: pointer.ASN1_TYPE */
    	em[1506] = 1508; em[1507] = 0; 
    em[1508] = 0; em[1509] = 0; em[1510] = 1; /* 1508: ASN1_TYPE */
    	em[1511] = 1513; em[1512] = 0; 
    em[1513] = 0; em[1514] = 16; em[1515] = 1; /* 1513: struct.asn1_type_st */
    	em[1516] = 1518; em[1517] = 8; 
    em[1518] = 0; em[1519] = 8; em[1520] = 20; /* 1518: union.unknown */
    	em[1521] = 134; em[1522] = 0; 
    	em[1523] = 1561; em[1524] = 0; 
    	em[1525] = 1566; em[1526] = 0; 
    	em[1527] = 1580; em[1528] = 0; 
    	em[1529] = 1585; em[1530] = 0; 
    	em[1531] = 1590; em[1532] = 0; 
    	em[1533] = 1491; em[1534] = 0; 
    	em[1535] = 1595; em[1536] = 0; 
    	em[1537] = 1600; em[1538] = 0; 
    	em[1539] = 1605; em[1540] = 0; 
    	em[1541] = 1610; em[1542] = 0; 
    	em[1543] = 1615; em[1544] = 0; 
    	em[1545] = 1620; em[1546] = 0; 
    	em[1547] = 1625; em[1548] = 0; 
    	em[1549] = 1630; em[1550] = 0; 
    	em[1551] = 1635; em[1552] = 0; 
    	em[1553] = 181; em[1554] = 0; 
    	em[1555] = 1561; em[1556] = 0; 
    	em[1557] = 1561; em[1558] = 0; 
    	em[1559] = 173; em[1560] = 0; 
    em[1561] = 1; em[1562] = 8; em[1563] = 1; /* 1561: pointer.struct.asn1_string_st */
    	em[1564] = 186; em[1565] = 0; 
    em[1566] = 1; em[1567] = 8; em[1568] = 1; /* 1566: pointer.struct.asn1_object_st */
    	em[1569] = 1571; em[1570] = 0; 
    em[1571] = 0; em[1572] = 40; em[1573] = 3; /* 1571: struct.asn1_object_st */
    	em[1574] = 153; em[1575] = 0; 
    	em[1576] = 153; em[1577] = 8; 
    	em[1578] = 158; em[1579] = 24; 
    em[1580] = 1; em[1581] = 8; em[1582] = 1; /* 1580: pointer.struct.asn1_string_st */
    	em[1583] = 186; em[1584] = 0; 
    em[1585] = 1; em[1586] = 8; em[1587] = 1; /* 1585: pointer.struct.asn1_string_st */
    	em[1588] = 186; em[1589] = 0; 
    em[1590] = 1; em[1591] = 8; em[1592] = 1; /* 1590: pointer.struct.asn1_string_st */
    	em[1593] = 186; em[1594] = 0; 
    em[1595] = 1; em[1596] = 8; em[1597] = 1; /* 1595: pointer.struct.asn1_string_st */
    	em[1598] = 186; em[1599] = 0; 
    em[1600] = 1; em[1601] = 8; em[1602] = 1; /* 1600: pointer.struct.asn1_string_st */
    	em[1603] = 186; em[1604] = 0; 
    em[1605] = 1; em[1606] = 8; em[1607] = 1; /* 1605: pointer.struct.asn1_string_st */
    	em[1608] = 186; em[1609] = 0; 
    em[1610] = 1; em[1611] = 8; em[1612] = 1; /* 1610: pointer.struct.asn1_string_st */
    	em[1613] = 186; em[1614] = 0; 
    em[1615] = 1; em[1616] = 8; em[1617] = 1; /* 1615: pointer.struct.asn1_string_st */
    	em[1618] = 186; em[1619] = 0; 
    em[1620] = 1; em[1621] = 8; em[1622] = 1; /* 1620: pointer.struct.asn1_string_st */
    	em[1623] = 186; em[1624] = 0; 
    em[1625] = 1; em[1626] = 8; em[1627] = 1; /* 1625: pointer.struct.asn1_string_st */
    	em[1628] = 186; em[1629] = 0; 
    em[1630] = 1; em[1631] = 8; em[1632] = 1; /* 1630: pointer.struct.asn1_string_st */
    	em[1633] = 186; em[1634] = 0; 
    em[1635] = 1; em[1636] = 8; em[1637] = 1; /* 1635: pointer.struct.asn1_string_st */
    	em[1638] = 186; em[1639] = 0; 
    em[1640] = 8884097; em[1641] = 8; em[1642] = 0; /* 1640: pointer.func */
    em[1643] = 1; em[1644] = 8; em[1645] = 1; /* 1643: pointer.struct.evp_pkey_asn1_method_st */
    	em[1646] = 1648; em[1647] = 0; 
    em[1648] = 0; em[1649] = 208; em[1650] = 24; /* 1648: struct.evp_pkey_asn1_method_st */
    	em[1651] = 134; em[1652] = 16; 
    	em[1653] = 134; em[1654] = 24; 
    	em[1655] = 1699; em[1656] = 32; 
    	em[1657] = 1702; em[1658] = 40; 
    	em[1659] = 1705; em[1660] = 48; 
    	em[1661] = 1708; em[1662] = 56; 
    	em[1663] = 1711; em[1664] = 64; 
    	em[1665] = 1714; em[1666] = 72; 
    	em[1667] = 1708; em[1668] = 80; 
    	em[1669] = 1717; em[1670] = 88; 
    	em[1671] = 1717; em[1672] = 96; 
    	em[1673] = 1720; em[1674] = 104; 
    	em[1675] = 1723; em[1676] = 112; 
    	em[1677] = 1717; em[1678] = 120; 
    	em[1679] = 1640; em[1680] = 128; 
    	em[1681] = 1705; em[1682] = 136; 
    	em[1683] = 1708; em[1684] = 144; 
    	em[1685] = 1726; em[1686] = 152; 
    	em[1687] = 1729; em[1688] = 160; 
    	em[1689] = 1732; em[1690] = 168; 
    	em[1691] = 1720; em[1692] = 176; 
    	em[1693] = 1723; em[1694] = 184; 
    	em[1695] = 1735; em[1696] = 192; 
    	em[1697] = 1738; em[1698] = 200; 
    em[1699] = 8884097; em[1700] = 8; em[1701] = 0; /* 1699: pointer.func */
    em[1702] = 8884097; em[1703] = 8; em[1704] = 0; /* 1702: pointer.func */
    em[1705] = 8884097; em[1706] = 8; em[1707] = 0; /* 1705: pointer.func */
    em[1708] = 8884097; em[1709] = 8; em[1710] = 0; /* 1708: pointer.func */
    em[1711] = 8884097; em[1712] = 8; em[1713] = 0; /* 1711: pointer.func */
    em[1714] = 8884097; em[1715] = 8; em[1716] = 0; /* 1714: pointer.func */
    em[1717] = 8884097; em[1718] = 8; em[1719] = 0; /* 1717: pointer.func */
    em[1720] = 8884097; em[1721] = 8; em[1722] = 0; /* 1720: pointer.func */
    em[1723] = 8884097; em[1724] = 8; em[1725] = 0; /* 1723: pointer.func */
    em[1726] = 8884097; em[1727] = 8; em[1728] = 0; /* 1726: pointer.func */
    em[1729] = 8884097; em[1730] = 8; em[1731] = 0; /* 1729: pointer.func */
    em[1732] = 8884097; em[1733] = 8; em[1734] = 0; /* 1732: pointer.func */
    em[1735] = 8884097; em[1736] = 8; em[1737] = 0; /* 1735: pointer.func */
    em[1738] = 8884097; em[1739] = 8; em[1740] = 0; /* 1738: pointer.func */
    em[1741] = 1; em[1742] = 8; em[1743] = 1; /* 1741: pointer.struct.engine_st */
    	em[1744] = 331; em[1745] = 0; 
    em[1746] = 1; em[1747] = 8; em[1748] = 1; /* 1746: pointer.struct.evp_pkey_st */
    	em[1749] = 1751; em[1750] = 0; 
    em[1751] = 0; em[1752] = 56; em[1753] = 4; /* 1751: struct.evp_pkey_st */
    	em[1754] = 1643; em[1755] = 16; 
    	em[1756] = 1741; em[1757] = 24; 
    	em[1758] = 873; em[1759] = 32; 
    	em[1760] = 1762; em[1761] = 48; 
    em[1762] = 1; em[1763] = 8; em[1764] = 1; /* 1762: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1765] = 1767; em[1766] = 0; 
    em[1767] = 0; em[1768] = 32; em[1769] = 2; /* 1767: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1770] = 1774; em[1771] = 8; 
    	em[1772] = 287; em[1773] = 24; 
    em[1774] = 8884099; em[1775] = 8; em[1776] = 2; /* 1774: pointer_to_array_of_pointers_to_stack */
    	em[1777] = 1781; em[1778] = 0; 
    	em[1779] = 243; em[1780] = 20; 
    em[1781] = 0; em[1782] = 8; em[1783] = 1; /* 1781: pointer.X509_ATTRIBUTE */
    	em[1784] = 1786; em[1785] = 0; 
    em[1786] = 0; em[1787] = 0; em[1788] = 1; /* 1786: X509_ATTRIBUTE */
    	em[1789] = 1791; em[1790] = 0; 
    em[1791] = 0; em[1792] = 24; em[1793] = 2; /* 1791: struct.x509_attributes_st */
    	em[1794] = 139; em[1795] = 0; 
    	em[1796] = 1798; em[1797] = 16; 
    em[1798] = 0; em[1799] = 8; em[1800] = 3; /* 1798: union.unknown */
    	em[1801] = 134; em[1802] = 0; 
    	em[1803] = 1807; em[1804] = 0; 
    	em[1805] = 1819; em[1806] = 0; 
    em[1807] = 1; em[1808] = 8; em[1809] = 1; /* 1807: pointer.struct.stack_st_ASN1_TYPE */
    	em[1810] = 1812; em[1811] = 0; 
    em[1812] = 0; em[1813] = 32; em[1814] = 2; /* 1812: struct.stack_st_fake_ASN1_TYPE */
    	em[1815] = 1496; em[1816] = 8; 
    	em[1817] = 287; em[1818] = 24; 
    em[1819] = 1; em[1820] = 8; em[1821] = 1; /* 1819: pointer.struct.asn1_type_st */
    	em[1822] = 86; em[1823] = 0; 
    em[1824] = 0; em[1825] = 1; em[1826] = 0; /* 1824: char */
    args_addr->arg_entity_index[0] = 1746;
    args_addr->ret_entity_index = -1;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_PKEY * new_arg_a = *((EVP_PKEY * *)new_args->args[0]);

    void (*orig_EVP_PKEY_free)(EVP_PKEY *);
    orig_EVP_PKEY_free = dlsym(RTLD_NEXT, "EVP_PKEY_free");
    (*orig_EVP_PKEY_free)(new_arg_a);

    syscall(889);

    free(args_addr);

}

