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

int bb_X509_check_private_key(X509 * arg_a,EVP_PKEY * arg_b);

int X509_check_private_key(X509 * arg_a,EVP_PKEY * arg_b) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_check_private_key called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_check_private_key(arg_a,arg_b);
    else {
        int (*orig_X509_check_private_key)(X509 *,EVP_PKEY *);
        orig_X509_check_private_key = dlsym(RTLD_NEXT, "X509_check_private_key");
        return orig_X509_check_private_key(arg_a,arg_b);
    }
}

int bb_X509_check_private_key(X509 * arg_a,EVP_PKEY * arg_b) 
{
    int ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 1; em[1] = 8; em[2] = 1; /* 0: pointer.struct.dsa_st */
    	em[3] = 5; em[4] = 0; 
    em[5] = 0; em[6] = 136; em[7] = 11; /* 5: struct.dsa_st */
    	em[8] = 30; em[9] = 24; 
    	em[10] = 30; em[11] = 32; 
    	em[12] = 30; em[13] = 40; 
    	em[14] = 30; em[15] = 48; 
    	em[16] = 30; em[17] = 56; 
    	em[18] = 30; em[19] = 64; 
    	em[20] = 30; em[21] = 72; 
    	em[22] = 53; em[23] = 88; 
    	em[24] = 67; em[25] = 104; 
    	em[26] = 87; em[27] = 120; 
    	em[28] = 148; em[29] = 128; 
    em[30] = 1; em[31] = 8; em[32] = 1; /* 30: pointer.struct.bignum_st */
    	em[33] = 35; em[34] = 0; 
    em[35] = 0; em[36] = 24; em[37] = 1; /* 35: struct.bignum_st */
    	em[38] = 40; em[39] = 0; 
    em[40] = 8884099; em[41] = 8; em[42] = 2; /* 40: pointer_to_array_of_pointers_to_stack */
    	em[43] = 47; em[44] = 0; 
    	em[45] = 50; em[46] = 12; 
    em[47] = 0; em[48] = 8; em[49] = 0; /* 47: long unsigned int */
    em[50] = 0; em[51] = 4; em[52] = 0; /* 50: int */
    em[53] = 1; em[54] = 8; em[55] = 1; /* 53: pointer.struct.bn_mont_ctx_st */
    	em[56] = 58; em[57] = 0; 
    em[58] = 0; em[59] = 96; em[60] = 3; /* 58: struct.bn_mont_ctx_st */
    	em[61] = 35; em[62] = 8; 
    	em[63] = 35; em[64] = 32; 
    	em[65] = 35; em[66] = 56; 
    em[67] = 0; em[68] = 32; em[69] = 2; /* 67: struct.crypto_ex_data_st_fake */
    	em[70] = 74; em[71] = 8; 
    	em[72] = 84; em[73] = 24; 
    em[74] = 8884099; em[75] = 8; em[76] = 2; /* 74: pointer_to_array_of_pointers_to_stack */
    	em[77] = 81; em[78] = 0; 
    	em[79] = 50; em[80] = 20; 
    em[81] = 0; em[82] = 8; em[83] = 0; /* 81: pointer.void */
    em[84] = 8884097; em[85] = 8; em[86] = 0; /* 84: pointer.func */
    em[87] = 1; em[88] = 8; em[89] = 1; /* 87: pointer.struct.dsa_method */
    	em[90] = 92; em[91] = 0; 
    em[92] = 0; em[93] = 96; em[94] = 11; /* 92: struct.dsa_method */
    	em[95] = 117; em[96] = 0; 
    	em[97] = 122; em[98] = 8; 
    	em[99] = 125; em[100] = 16; 
    	em[101] = 128; em[102] = 24; 
    	em[103] = 131; em[104] = 32; 
    	em[105] = 134; em[106] = 40; 
    	em[107] = 137; em[108] = 48; 
    	em[109] = 137; em[110] = 56; 
    	em[111] = 140; em[112] = 72; 
    	em[113] = 145; em[114] = 80; 
    	em[115] = 137; em[116] = 88; 
    em[117] = 1; em[118] = 8; em[119] = 1; /* 117: pointer.char */
    	em[120] = 8884096; em[121] = 0; 
    em[122] = 8884097; em[123] = 8; em[124] = 0; /* 122: pointer.func */
    em[125] = 8884097; em[126] = 8; em[127] = 0; /* 125: pointer.func */
    em[128] = 8884097; em[129] = 8; em[130] = 0; /* 128: pointer.func */
    em[131] = 8884097; em[132] = 8; em[133] = 0; /* 131: pointer.func */
    em[134] = 8884097; em[135] = 8; em[136] = 0; /* 134: pointer.func */
    em[137] = 8884097; em[138] = 8; em[139] = 0; /* 137: pointer.func */
    em[140] = 1; em[141] = 8; em[142] = 1; /* 140: pointer.char */
    	em[143] = 8884096; em[144] = 0; 
    em[145] = 8884097; em[146] = 8; em[147] = 0; /* 145: pointer.func */
    em[148] = 1; em[149] = 8; em[150] = 1; /* 148: pointer.struct.engine_st */
    	em[151] = 153; em[152] = 0; 
    em[153] = 0; em[154] = 216; em[155] = 24; /* 153: struct.engine_st */
    	em[156] = 117; em[157] = 0; 
    	em[158] = 117; em[159] = 8; 
    	em[160] = 204; em[161] = 16; 
    	em[162] = 259; em[163] = 24; 
    	em[164] = 310; em[165] = 32; 
    	em[166] = 346; em[167] = 40; 
    	em[168] = 363; em[169] = 48; 
    	em[170] = 390; em[171] = 56; 
    	em[172] = 425; em[173] = 64; 
    	em[174] = 433; em[175] = 72; 
    	em[176] = 436; em[177] = 80; 
    	em[178] = 439; em[179] = 88; 
    	em[180] = 442; em[181] = 96; 
    	em[182] = 445; em[183] = 104; 
    	em[184] = 445; em[185] = 112; 
    	em[186] = 445; em[187] = 120; 
    	em[188] = 448; em[189] = 128; 
    	em[190] = 451; em[191] = 136; 
    	em[192] = 451; em[193] = 144; 
    	em[194] = 454; em[195] = 152; 
    	em[196] = 457; em[197] = 160; 
    	em[198] = 469; em[199] = 184; 
    	em[200] = 483; em[201] = 200; 
    	em[202] = 483; em[203] = 208; 
    em[204] = 1; em[205] = 8; em[206] = 1; /* 204: pointer.struct.rsa_meth_st */
    	em[207] = 209; em[208] = 0; 
    em[209] = 0; em[210] = 112; em[211] = 13; /* 209: struct.rsa_meth_st */
    	em[212] = 117; em[213] = 0; 
    	em[214] = 238; em[215] = 8; 
    	em[216] = 238; em[217] = 16; 
    	em[218] = 238; em[219] = 24; 
    	em[220] = 238; em[221] = 32; 
    	em[222] = 241; em[223] = 40; 
    	em[224] = 244; em[225] = 48; 
    	em[226] = 247; em[227] = 56; 
    	em[228] = 247; em[229] = 64; 
    	em[230] = 140; em[231] = 80; 
    	em[232] = 250; em[233] = 88; 
    	em[234] = 253; em[235] = 96; 
    	em[236] = 256; em[237] = 104; 
    em[238] = 8884097; em[239] = 8; em[240] = 0; /* 238: pointer.func */
    em[241] = 8884097; em[242] = 8; em[243] = 0; /* 241: pointer.func */
    em[244] = 8884097; em[245] = 8; em[246] = 0; /* 244: pointer.func */
    em[247] = 8884097; em[248] = 8; em[249] = 0; /* 247: pointer.func */
    em[250] = 8884097; em[251] = 8; em[252] = 0; /* 250: pointer.func */
    em[253] = 8884097; em[254] = 8; em[255] = 0; /* 253: pointer.func */
    em[256] = 8884097; em[257] = 8; em[258] = 0; /* 256: pointer.func */
    em[259] = 1; em[260] = 8; em[261] = 1; /* 259: pointer.struct.dsa_method */
    	em[262] = 264; em[263] = 0; 
    em[264] = 0; em[265] = 96; em[266] = 11; /* 264: struct.dsa_method */
    	em[267] = 117; em[268] = 0; 
    	em[269] = 289; em[270] = 8; 
    	em[271] = 292; em[272] = 16; 
    	em[273] = 295; em[274] = 24; 
    	em[275] = 298; em[276] = 32; 
    	em[277] = 301; em[278] = 40; 
    	em[279] = 304; em[280] = 48; 
    	em[281] = 304; em[282] = 56; 
    	em[283] = 140; em[284] = 72; 
    	em[285] = 307; em[286] = 80; 
    	em[287] = 304; em[288] = 88; 
    em[289] = 8884097; em[290] = 8; em[291] = 0; /* 289: pointer.func */
    em[292] = 8884097; em[293] = 8; em[294] = 0; /* 292: pointer.func */
    em[295] = 8884097; em[296] = 8; em[297] = 0; /* 295: pointer.func */
    em[298] = 8884097; em[299] = 8; em[300] = 0; /* 298: pointer.func */
    em[301] = 8884097; em[302] = 8; em[303] = 0; /* 301: pointer.func */
    em[304] = 8884097; em[305] = 8; em[306] = 0; /* 304: pointer.func */
    em[307] = 8884097; em[308] = 8; em[309] = 0; /* 307: pointer.func */
    em[310] = 1; em[311] = 8; em[312] = 1; /* 310: pointer.struct.dh_method */
    	em[313] = 315; em[314] = 0; 
    em[315] = 0; em[316] = 72; em[317] = 8; /* 315: struct.dh_method */
    	em[318] = 117; em[319] = 0; 
    	em[320] = 334; em[321] = 8; 
    	em[322] = 337; em[323] = 16; 
    	em[324] = 340; em[325] = 24; 
    	em[326] = 334; em[327] = 32; 
    	em[328] = 334; em[329] = 40; 
    	em[330] = 140; em[331] = 56; 
    	em[332] = 343; em[333] = 64; 
    em[334] = 8884097; em[335] = 8; em[336] = 0; /* 334: pointer.func */
    em[337] = 8884097; em[338] = 8; em[339] = 0; /* 337: pointer.func */
    em[340] = 8884097; em[341] = 8; em[342] = 0; /* 340: pointer.func */
    em[343] = 8884097; em[344] = 8; em[345] = 0; /* 343: pointer.func */
    em[346] = 1; em[347] = 8; em[348] = 1; /* 346: pointer.struct.ecdh_method */
    	em[349] = 351; em[350] = 0; 
    em[351] = 0; em[352] = 32; em[353] = 3; /* 351: struct.ecdh_method */
    	em[354] = 117; em[355] = 0; 
    	em[356] = 360; em[357] = 8; 
    	em[358] = 140; em[359] = 24; 
    em[360] = 8884097; em[361] = 8; em[362] = 0; /* 360: pointer.func */
    em[363] = 1; em[364] = 8; em[365] = 1; /* 363: pointer.struct.ecdsa_method */
    	em[366] = 368; em[367] = 0; 
    em[368] = 0; em[369] = 48; em[370] = 5; /* 368: struct.ecdsa_method */
    	em[371] = 117; em[372] = 0; 
    	em[373] = 381; em[374] = 8; 
    	em[375] = 384; em[376] = 16; 
    	em[377] = 387; em[378] = 24; 
    	em[379] = 140; em[380] = 40; 
    em[381] = 8884097; em[382] = 8; em[383] = 0; /* 381: pointer.func */
    em[384] = 8884097; em[385] = 8; em[386] = 0; /* 384: pointer.func */
    em[387] = 8884097; em[388] = 8; em[389] = 0; /* 387: pointer.func */
    em[390] = 1; em[391] = 8; em[392] = 1; /* 390: pointer.struct.rand_meth_st */
    	em[393] = 395; em[394] = 0; 
    em[395] = 0; em[396] = 48; em[397] = 6; /* 395: struct.rand_meth_st */
    	em[398] = 410; em[399] = 0; 
    	em[400] = 413; em[401] = 8; 
    	em[402] = 416; em[403] = 16; 
    	em[404] = 419; em[405] = 24; 
    	em[406] = 413; em[407] = 32; 
    	em[408] = 422; em[409] = 40; 
    em[410] = 8884097; em[411] = 8; em[412] = 0; /* 410: pointer.func */
    em[413] = 8884097; em[414] = 8; em[415] = 0; /* 413: pointer.func */
    em[416] = 8884097; em[417] = 8; em[418] = 0; /* 416: pointer.func */
    em[419] = 8884097; em[420] = 8; em[421] = 0; /* 419: pointer.func */
    em[422] = 8884097; em[423] = 8; em[424] = 0; /* 422: pointer.func */
    em[425] = 1; em[426] = 8; em[427] = 1; /* 425: pointer.struct.store_method_st */
    	em[428] = 430; em[429] = 0; 
    em[430] = 0; em[431] = 0; em[432] = 0; /* 430: struct.store_method_st */
    em[433] = 8884097; em[434] = 8; em[435] = 0; /* 433: pointer.func */
    em[436] = 8884097; em[437] = 8; em[438] = 0; /* 436: pointer.func */
    em[439] = 8884097; em[440] = 8; em[441] = 0; /* 439: pointer.func */
    em[442] = 8884097; em[443] = 8; em[444] = 0; /* 442: pointer.func */
    em[445] = 8884097; em[446] = 8; em[447] = 0; /* 445: pointer.func */
    em[448] = 8884097; em[449] = 8; em[450] = 0; /* 448: pointer.func */
    em[451] = 8884097; em[452] = 8; em[453] = 0; /* 451: pointer.func */
    em[454] = 8884097; em[455] = 8; em[456] = 0; /* 454: pointer.func */
    em[457] = 1; em[458] = 8; em[459] = 1; /* 457: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[460] = 462; em[461] = 0; 
    em[462] = 0; em[463] = 32; em[464] = 2; /* 462: struct.ENGINE_CMD_DEFN_st */
    	em[465] = 117; em[466] = 8; 
    	em[467] = 117; em[468] = 16; 
    em[469] = 0; em[470] = 32; em[471] = 2; /* 469: struct.crypto_ex_data_st_fake */
    	em[472] = 476; em[473] = 8; 
    	em[474] = 84; em[475] = 24; 
    em[476] = 8884099; em[477] = 8; em[478] = 2; /* 476: pointer_to_array_of_pointers_to_stack */
    	em[479] = 81; em[480] = 0; 
    	em[481] = 50; em[482] = 20; 
    em[483] = 1; em[484] = 8; em[485] = 1; /* 483: pointer.struct.engine_st */
    	em[486] = 153; em[487] = 0; 
    em[488] = 0; em[489] = 0; em[490] = 1; /* 488: X509_ALGOR */
    	em[491] = 493; em[492] = 0; 
    em[493] = 0; em[494] = 16; em[495] = 2; /* 493: struct.X509_algor_st */
    	em[496] = 500; em[497] = 0; 
    	em[498] = 522; em[499] = 8; 
    em[500] = 1; em[501] = 8; em[502] = 1; /* 500: pointer.struct.asn1_object_st */
    	em[503] = 505; em[504] = 0; 
    em[505] = 0; em[506] = 40; em[507] = 3; /* 505: struct.asn1_object_st */
    	em[508] = 117; em[509] = 0; 
    	em[510] = 117; em[511] = 8; 
    	em[512] = 514; em[513] = 24; 
    em[514] = 1; em[515] = 8; em[516] = 1; /* 514: pointer.unsigned char */
    	em[517] = 519; em[518] = 0; 
    em[519] = 0; em[520] = 1; em[521] = 0; /* 519: unsigned char */
    em[522] = 1; em[523] = 8; em[524] = 1; /* 522: pointer.struct.asn1_type_st */
    	em[525] = 527; em[526] = 0; 
    em[527] = 0; em[528] = 16; em[529] = 1; /* 527: struct.asn1_type_st */
    	em[530] = 532; em[531] = 8; 
    em[532] = 0; em[533] = 8; em[534] = 20; /* 532: union.unknown */
    	em[535] = 140; em[536] = 0; 
    	em[537] = 575; em[538] = 0; 
    	em[539] = 500; em[540] = 0; 
    	em[541] = 590; em[542] = 0; 
    	em[543] = 595; em[544] = 0; 
    	em[545] = 600; em[546] = 0; 
    	em[547] = 605; em[548] = 0; 
    	em[549] = 610; em[550] = 0; 
    	em[551] = 615; em[552] = 0; 
    	em[553] = 620; em[554] = 0; 
    	em[555] = 625; em[556] = 0; 
    	em[557] = 630; em[558] = 0; 
    	em[559] = 635; em[560] = 0; 
    	em[561] = 640; em[562] = 0; 
    	em[563] = 645; em[564] = 0; 
    	em[565] = 650; em[566] = 0; 
    	em[567] = 655; em[568] = 0; 
    	em[569] = 575; em[570] = 0; 
    	em[571] = 575; em[572] = 0; 
    	em[573] = 660; em[574] = 0; 
    em[575] = 1; em[576] = 8; em[577] = 1; /* 575: pointer.struct.asn1_string_st */
    	em[578] = 580; em[579] = 0; 
    em[580] = 0; em[581] = 24; em[582] = 1; /* 580: struct.asn1_string_st */
    	em[583] = 585; em[584] = 8; 
    em[585] = 1; em[586] = 8; em[587] = 1; /* 585: pointer.unsigned char */
    	em[588] = 519; em[589] = 0; 
    em[590] = 1; em[591] = 8; em[592] = 1; /* 590: pointer.struct.asn1_string_st */
    	em[593] = 580; em[594] = 0; 
    em[595] = 1; em[596] = 8; em[597] = 1; /* 595: pointer.struct.asn1_string_st */
    	em[598] = 580; em[599] = 0; 
    em[600] = 1; em[601] = 8; em[602] = 1; /* 600: pointer.struct.asn1_string_st */
    	em[603] = 580; em[604] = 0; 
    em[605] = 1; em[606] = 8; em[607] = 1; /* 605: pointer.struct.asn1_string_st */
    	em[608] = 580; em[609] = 0; 
    em[610] = 1; em[611] = 8; em[612] = 1; /* 610: pointer.struct.asn1_string_st */
    	em[613] = 580; em[614] = 0; 
    em[615] = 1; em[616] = 8; em[617] = 1; /* 615: pointer.struct.asn1_string_st */
    	em[618] = 580; em[619] = 0; 
    em[620] = 1; em[621] = 8; em[622] = 1; /* 620: pointer.struct.asn1_string_st */
    	em[623] = 580; em[624] = 0; 
    em[625] = 1; em[626] = 8; em[627] = 1; /* 625: pointer.struct.asn1_string_st */
    	em[628] = 580; em[629] = 0; 
    em[630] = 1; em[631] = 8; em[632] = 1; /* 630: pointer.struct.asn1_string_st */
    	em[633] = 580; em[634] = 0; 
    em[635] = 1; em[636] = 8; em[637] = 1; /* 635: pointer.struct.asn1_string_st */
    	em[638] = 580; em[639] = 0; 
    em[640] = 1; em[641] = 8; em[642] = 1; /* 640: pointer.struct.asn1_string_st */
    	em[643] = 580; em[644] = 0; 
    em[645] = 1; em[646] = 8; em[647] = 1; /* 645: pointer.struct.asn1_string_st */
    	em[648] = 580; em[649] = 0; 
    em[650] = 1; em[651] = 8; em[652] = 1; /* 650: pointer.struct.asn1_string_st */
    	em[653] = 580; em[654] = 0; 
    em[655] = 1; em[656] = 8; em[657] = 1; /* 655: pointer.struct.asn1_string_st */
    	em[658] = 580; em[659] = 0; 
    em[660] = 1; em[661] = 8; em[662] = 1; /* 660: pointer.struct.ASN1_VALUE_st */
    	em[663] = 665; em[664] = 0; 
    em[665] = 0; em[666] = 0; em[667] = 0; /* 665: struct.ASN1_VALUE_st */
    em[668] = 1; em[669] = 8; em[670] = 1; /* 668: pointer.struct.stack_st_X509_ALGOR */
    	em[671] = 673; em[672] = 0; 
    em[673] = 0; em[674] = 32; em[675] = 2; /* 673: struct.stack_st_fake_X509_ALGOR */
    	em[676] = 680; em[677] = 8; 
    	em[678] = 84; em[679] = 24; 
    em[680] = 8884099; em[681] = 8; em[682] = 2; /* 680: pointer_to_array_of_pointers_to_stack */
    	em[683] = 687; em[684] = 0; 
    	em[685] = 50; em[686] = 20; 
    em[687] = 0; em[688] = 8; em[689] = 1; /* 687: pointer.X509_ALGOR */
    	em[690] = 488; em[691] = 0; 
    em[692] = 1; em[693] = 8; em[694] = 1; /* 692: pointer.struct.asn1_string_st */
    	em[695] = 697; em[696] = 0; 
    em[697] = 0; em[698] = 24; em[699] = 1; /* 697: struct.asn1_string_st */
    	em[700] = 585; em[701] = 8; 
    em[702] = 1; em[703] = 8; em[704] = 1; /* 702: pointer.struct.stack_st_ASN1_OBJECT */
    	em[705] = 707; em[706] = 0; 
    em[707] = 0; em[708] = 32; em[709] = 2; /* 707: struct.stack_st_fake_ASN1_OBJECT */
    	em[710] = 714; em[711] = 8; 
    	em[712] = 84; em[713] = 24; 
    em[714] = 8884099; em[715] = 8; em[716] = 2; /* 714: pointer_to_array_of_pointers_to_stack */
    	em[717] = 721; em[718] = 0; 
    	em[719] = 50; em[720] = 20; 
    em[721] = 0; em[722] = 8; em[723] = 1; /* 721: pointer.ASN1_OBJECT */
    	em[724] = 726; em[725] = 0; 
    em[726] = 0; em[727] = 0; em[728] = 1; /* 726: ASN1_OBJECT */
    	em[729] = 731; em[730] = 0; 
    em[731] = 0; em[732] = 40; em[733] = 3; /* 731: struct.asn1_object_st */
    	em[734] = 117; em[735] = 0; 
    	em[736] = 117; em[737] = 8; 
    	em[738] = 514; em[739] = 24; 
    em[740] = 0; em[741] = 40; em[742] = 5; /* 740: struct.x509_cert_aux_st */
    	em[743] = 702; em[744] = 0; 
    	em[745] = 702; em[746] = 8; 
    	em[747] = 692; em[748] = 16; 
    	em[749] = 753; em[750] = 24; 
    	em[751] = 668; em[752] = 32; 
    em[753] = 1; em[754] = 8; em[755] = 1; /* 753: pointer.struct.asn1_string_st */
    	em[756] = 697; em[757] = 0; 
    em[758] = 0; em[759] = 16; em[760] = 2; /* 758: struct.EDIPartyName_st */
    	em[761] = 765; em[762] = 0; 
    	em[763] = 765; em[764] = 8; 
    em[765] = 1; em[766] = 8; em[767] = 1; /* 765: pointer.struct.asn1_string_st */
    	em[768] = 770; em[769] = 0; 
    em[770] = 0; em[771] = 24; em[772] = 1; /* 770: struct.asn1_string_st */
    	em[773] = 585; em[774] = 8; 
    em[775] = 1; em[776] = 8; em[777] = 1; /* 775: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[778] = 780; em[779] = 0; 
    em[780] = 0; em[781] = 32; em[782] = 2; /* 780: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[783] = 787; em[784] = 8; 
    	em[785] = 84; em[786] = 24; 
    em[787] = 8884099; em[788] = 8; em[789] = 2; /* 787: pointer_to_array_of_pointers_to_stack */
    	em[790] = 794; em[791] = 0; 
    	em[792] = 50; em[793] = 20; 
    em[794] = 0; em[795] = 8; em[796] = 1; /* 794: pointer.X509_NAME_ENTRY */
    	em[797] = 799; em[798] = 0; 
    em[799] = 0; em[800] = 0; em[801] = 1; /* 799: X509_NAME_ENTRY */
    	em[802] = 804; em[803] = 0; 
    em[804] = 0; em[805] = 24; em[806] = 2; /* 804: struct.X509_name_entry_st */
    	em[807] = 811; em[808] = 0; 
    	em[809] = 825; em[810] = 8; 
    em[811] = 1; em[812] = 8; em[813] = 1; /* 811: pointer.struct.asn1_object_st */
    	em[814] = 816; em[815] = 0; 
    em[816] = 0; em[817] = 40; em[818] = 3; /* 816: struct.asn1_object_st */
    	em[819] = 117; em[820] = 0; 
    	em[821] = 117; em[822] = 8; 
    	em[823] = 514; em[824] = 24; 
    em[825] = 1; em[826] = 8; em[827] = 1; /* 825: pointer.struct.asn1_string_st */
    	em[828] = 830; em[829] = 0; 
    em[830] = 0; em[831] = 24; em[832] = 1; /* 830: struct.asn1_string_st */
    	em[833] = 585; em[834] = 8; 
    em[835] = 1; em[836] = 8; em[837] = 1; /* 835: pointer.struct.X509_name_st */
    	em[838] = 840; em[839] = 0; 
    em[840] = 0; em[841] = 40; em[842] = 3; /* 840: struct.X509_name_st */
    	em[843] = 775; em[844] = 0; 
    	em[845] = 849; em[846] = 16; 
    	em[847] = 585; em[848] = 24; 
    em[849] = 1; em[850] = 8; em[851] = 1; /* 849: pointer.struct.buf_mem_st */
    	em[852] = 854; em[853] = 0; 
    em[854] = 0; em[855] = 24; em[856] = 1; /* 854: struct.buf_mem_st */
    	em[857] = 140; em[858] = 8; 
    em[859] = 1; em[860] = 8; em[861] = 1; /* 859: pointer.struct.asn1_string_st */
    	em[862] = 770; em[863] = 0; 
    em[864] = 1; em[865] = 8; em[866] = 1; /* 864: pointer.struct.asn1_string_st */
    	em[867] = 770; em[868] = 0; 
    em[869] = 1; em[870] = 8; em[871] = 1; /* 869: pointer.struct.asn1_string_st */
    	em[872] = 770; em[873] = 0; 
    em[874] = 1; em[875] = 8; em[876] = 1; /* 874: pointer.struct.asn1_string_st */
    	em[877] = 770; em[878] = 0; 
    em[879] = 1; em[880] = 8; em[881] = 1; /* 879: pointer.struct.asn1_string_st */
    	em[882] = 770; em[883] = 0; 
    em[884] = 1; em[885] = 8; em[886] = 1; /* 884: pointer.struct.asn1_string_st */
    	em[887] = 770; em[888] = 0; 
    em[889] = 0; em[890] = 40; em[891] = 3; /* 889: struct.asn1_object_st */
    	em[892] = 117; em[893] = 0; 
    	em[894] = 117; em[895] = 8; 
    	em[896] = 514; em[897] = 24; 
    em[898] = 1; em[899] = 8; em[900] = 1; /* 898: pointer.struct.asn1_object_st */
    	em[901] = 889; em[902] = 0; 
    em[903] = 0; em[904] = 16; em[905] = 2; /* 903: struct.otherName_st */
    	em[906] = 898; em[907] = 0; 
    	em[908] = 910; em[909] = 8; 
    em[910] = 1; em[911] = 8; em[912] = 1; /* 910: pointer.struct.asn1_type_st */
    	em[913] = 915; em[914] = 0; 
    em[915] = 0; em[916] = 16; em[917] = 1; /* 915: struct.asn1_type_st */
    	em[918] = 920; em[919] = 8; 
    em[920] = 0; em[921] = 8; em[922] = 20; /* 920: union.unknown */
    	em[923] = 140; em[924] = 0; 
    	em[925] = 765; em[926] = 0; 
    	em[927] = 898; em[928] = 0; 
    	em[929] = 963; em[930] = 0; 
    	em[931] = 968; em[932] = 0; 
    	em[933] = 973; em[934] = 0; 
    	em[935] = 884; em[936] = 0; 
    	em[937] = 978; em[938] = 0; 
    	em[939] = 879; em[940] = 0; 
    	em[941] = 983; em[942] = 0; 
    	em[943] = 874; em[944] = 0; 
    	em[945] = 869; em[946] = 0; 
    	em[947] = 988; em[948] = 0; 
    	em[949] = 864; em[950] = 0; 
    	em[951] = 859; em[952] = 0; 
    	em[953] = 993; em[954] = 0; 
    	em[955] = 998; em[956] = 0; 
    	em[957] = 765; em[958] = 0; 
    	em[959] = 765; em[960] = 0; 
    	em[961] = 1003; em[962] = 0; 
    em[963] = 1; em[964] = 8; em[965] = 1; /* 963: pointer.struct.asn1_string_st */
    	em[966] = 770; em[967] = 0; 
    em[968] = 1; em[969] = 8; em[970] = 1; /* 968: pointer.struct.asn1_string_st */
    	em[971] = 770; em[972] = 0; 
    em[973] = 1; em[974] = 8; em[975] = 1; /* 973: pointer.struct.asn1_string_st */
    	em[976] = 770; em[977] = 0; 
    em[978] = 1; em[979] = 8; em[980] = 1; /* 978: pointer.struct.asn1_string_st */
    	em[981] = 770; em[982] = 0; 
    em[983] = 1; em[984] = 8; em[985] = 1; /* 983: pointer.struct.asn1_string_st */
    	em[986] = 770; em[987] = 0; 
    em[988] = 1; em[989] = 8; em[990] = 1; /* 988: pointer.struct.asn1_string_st */
    	em[991] = 770; em[992] = 0; 
    em[993] = 1; em[994] = 8; em[995] = 1; /* 993: pointer.struct.asn1_string_st */
    	em[996] = 770; em[997] = 0; 
    em[998] = 1; em[999] = 8; em[1000] = 1; /* 998: pointer.struct.asn1_string_st */
    	em[1001] = 770; em[1002] = 0; 
    em[1003] = 1; em[1004] = 8; em[1005] = 1; /* 1003: pointer.struct.ASN1_VALUE_st */
    	em[1006] = 1008; em[1007] = 0; 
    em[1008] = 0; em[1009] = 0; em[1010] = 0; /* 1008: struct.ASN1_VALUE_st */
    em[1011] = 0; em[1012] = 16; em[1013] = 1; /* 1011: struct.GENERAL_NAME_st */
    	em[1014] = 1016; em[1015] = 8; 
    em[1016] = 0; em[1017] = 8; em[1018] = 15; /* 1016: union.unknown */
    	em[1019] = 140; em[1020] = 0; 
    	em[1021] = 1049; em[1022] = 0; 
    	em[1023] = 983; em[1024] = 0; 
    	em[1025] = 983; em[1026] = 0; 
    	em[1027] = 910; em[1028] = 0; 
    	em[1029] = 835; em[1030] = 0; 
    	em[1031] = 1054; em[1032] = 0; 
    	em[1033] = 983; em[1034] = 0; 
    	em[1035] = 884; em[1036] = 0; 
    	em[1037] = 898; em[1038] = 0; 
    	em[1039] = 884; em[1040] = 0; 
    	em[1041] = 835; em[1042] = 0; 
    	em[1043] = 983; em[1044] = 0; 
    	em[1045] = 898; em[1046] = 0; 
    	em[1047] = 910; em[1048] = 0; 
    em[1049] = 1; em[1050] = 8; em[1051] = 1; /* 1049: pointer.struct.otherName_st */
    	em[1052] = 903; em[1053] = 0; 
    em[1054] = 1; em[1055] = 8; em[1056] = 1; /* 1054: pointer.struct.EDIPartyName_st */
    	em[1057] = 758; em[1058] = 0; 
    em[1059] = 1; em[1060] = 8; em[1061] = 1; /* 1059: pointer.struct.GENERAL_NAME_st */
    	em[1062] = 1011; em[1063] = 0; 
    em[1064] = 0; em[1065] = 24; em[1066] = 3; /* 1064: struct.GENERAL_SUBTREE_st */
    	em[1067] = 1059; em[1068] = 0; 
    	em[1069] = 963; em[1070] = 8; 
    	em[1071] = 963; em[1072] = 16; 
    em[1073] = 0; em[1074] = 0; em[1075] = 1; /* 1073: GENERAL_SUBTREE */
    	em[1076] = 1064; em[1077] = 0; 
    em[1078] = 1; em[1079] = 8; em[1080] = 1; /* 1078: pointer.struct.stack_st_GENERAL_SUBTREE */
    	em[1081] = 1083; em[1082] = 0; 
    em[1083] = 0; em[1084] = 32; em[1085] = 2; /* 1083: struct.stack_st_fake_GENERAL_SUBTREE */
    	em[1086] = 1090; em[1087] = 8; 
    	em[1088] = 84; em[1089] = 24; 
    em[1090] = 8884099; em[1091] = 8; em[1092] = 2; /* 1090: pointer_to_array_of_pointers_to_stack */
    	em[1093] = 1097; em[1094] = 0; 
    	em[1095] = 50; em[1096] = 20; 
    em[1097] = 0; em[1098] = 8; em[1099] = 1; /* 1097: pointer.GENERAL_SUBTREE */
    	em[1100] = 1073; em[1101] = 0; 
    em[1102] = 0; em[1103] = 16; em[1104] = 2; /* 1102: struct.NAME_CONSTRAINTS_st */
    	em[1105] = 1078; em[1106] = 0; 
    	em[1107] = 1078; em[1108] = 8; 
    em[1109] = 1; em[1110] = 8; em[1111] = 1; /* 1109: pointer.struct.NAME_CONSTRAINTS_st */
    	em[1112] = 1102; em[1113] = 0; 
    em[1114] = 1; em[1115] = 8; em[1116] = 1; /* 1114: pointer.struct.stack_st_GENERAL_NAME */
    	em[1117] = 1119; em[1118] = 0; 
    em[1119] = 0; em[1120] = 32; em[1121] = 2; /* 1119: struct.stack_st_fake_GENERAL_NAME */
    	em[1122] = 1126; em[1123] = 8; 
    	em[1124] = 84; em[1125] = 24; 
    em[1126] = 8884099; em[1127] = 8; em[1128] = 2; /* 1126: pointer_to_array_of_pointers_to_stack */
    	em[1129] = 1133; em[1130] = 0; 
    	em[1131] = 50; em[1132] = 20; 
    em[1133] = 0; em[1134] = 8; em[1135] = 1; /* 1133: pointer.GENERAL_NAME */
    	em[1136] = 1138; em[1137] = 0; 
    em[1138] = 0; em[1139] = 0; em[1140] = 1; /* 1138: GENERAL_NAME */
    	em[1141] = 1143; em[1142] = 0; 
    em[1143] = 0; em[1144] = 16; em[1145] = 1; /* 1143: struct.GENERAL_NAME_st */
    	em[1146] = 1148; em[1147] = 8; 
    em[1148] = 0; em[1149] = 8; em[1150] = 15; /* 1148: union.unknown */
    	em[1151] = 140; em[1152] = 0; 
    	em[1153] = 1181; em[1154] = 0; 
    	em[1155] = 1300; em[1156] = 0; 
    	em[1157] = 1300; em[1158] = 0; 
    	em[1159] = 1207; em[1160] = 0; 
    	em[1161] = 1348; em[1162] = 0; 
    	em[1163] = 1396; em[1164] = 0; 
    	em[1165] = 1300; em[1166] = 0; 
    	em[1167] = 1285; em[1168] = 0; 
    	em[1169] = 1193; em[1170] = 0; 
    	em[1171] = 1285; em[1172] = 0; 
    	em[1173] = 1348; em[1174] = 0; 
    	em[1175] = 1300; em[1176] = 0; 
    	em[1177] = 1193; em[1178] = 0; 
    	em[1179] = 1207; em[1180] = 0; 
    em[1181] = 1; em[1182] = 8; em[1183] = 1; /* 1181: pointer.struct.otherName_st */
    	em[1184] = 1186; em[1185] = 0; 
    em[1186] = 0; em[1187] = 16; em[1188] = 2; /* 1186: struct.otherName_st */
    	em[1189] = 1193; em[1190] = 0; 
    	em[1191] = 1207; em[1192] = 8; 
    em[1193] = 1; em[1194] = 8; em[1195] = 1; /* 1193: pointer.struct.asn1_object_st */
    	em[1196] = 1198; em[1197] = 0; 
    em[1198] = 0; em[1199] = 40; em[1200] = 3; /* 1198: struct.asn1_object_st */
    	em[1201] = 117; em[1202] = 0; 
    	em[1203] = 117; em[1204] = 8; 
    	em[1205] = 514; em[1206] = 24; 
    em[1207] = 1; em[1208] = 8; em[1209] = 1; /* 1207: pointer.struct.asn1_type_st */
    	em[1210] = 1212; em[1211] = 0; 
    em[1212] = 0; em[1213] = 16; em[1214] = 1; /* 1212: struct.asn1_type_st */
    	em[1215] = 1217; em[1216] = 8; 
    em[1217] = 0; em[1218] = 8; em[1219] = 20; /* 1217: union.unknown */
    	em[1220] = 140; em[1221] = 0; 
    	em[1222] = 1260; em[1223] = 0; 
    	em[1224] = 1193; em[1225] = 0; 
    	em[1226] = 1270; em[1227] = 0; 
    	em[1228] = 1275; em[1229] = 0; 
    	em[1230] = 1280; em[1231] = 0; 
    	em[1232] = 1285; em[1233] = 0; 
    	em[1234] = 1290; em[1235] = 0; 
    	em[1236] = 1295; em[1237] = 0; 
    	em[1238] = 1300; em[1239] = 0; 
    	em[1240] = 1305; em[1241] = 0; 
    	em[1242] = 1310; em[1243] = 0; 
    	em[1244] = 1315; em[1245] = 0; 
    	em[1246] = 1320; em[1247] = 0; 
    	em[1248] = 1325; em[1249] = 0; 
    	em[1250] = 1330; em[1251] = 0; 
    	em[1252] = 1335; em[1253] = 0; 
    	em[1254] = 1260; em[1255] = 0; 
    	em[1256] = 1260; em[1257] = 0; 
    	em[1258] = 1340; em[1259] = 0; 
    em[1260] = 1; em[1261] = 8; em[1262] = 1; /* 1260: pointer.struct.asn1_string_st */
    	em[1263] = 1265; em[1264] = 0; 
    em[1265] = 0; em[1266] = 24; em[1267] = 1; /* 1265: struct.asn1_string_st */
    	em[1268] = 585; em[1269] = 8; 
    em[1270] = 1; em[1271] = 8; em[1272] = 1; /* 1270: pointer.struct.asn1_string_st */
    	em[1273] = 1265; em[1274] = 0; 
    em[1275] = 1; em[1276] = 8; em[1277] = 1; /* 1275: pointer.struct.asn1_string_st */
    	em[1278] = 1265; em[1279] = 0; 
    em[1280] = 1; em[1281] = 8; em[1282] = 1; /* 1280: pointer.struct.asn1_string_st */
    	em[1283] = 1265; em[1284] = 0; 
    em[1285] = 1; em[1286] = 8; em[1287] = 1; /* 1285: pointer.struct.asn1_string_st */
    	em[1288] = 1265; em[1289] = 0; 
    em[1290] = 1; em[1291] = 8; em[1292] = 1; /* 1290: pointer.struct.asn1_string_st */
    	em[1293] = 1265; em[1294] = 0; 
    em[1295] = 1; em[1296] = 8; em[1297] = 1; /* 1295: pointer.struct.asn1_string_st */
    	em[1298] = 1265; em[1299] = 0; 
    em[1300] = 1; em[1301] = 8; em[1302] = 1; /* 1300: pointer.struct.asn1_string_st */
    	em[1303] = 1265; em[1304] = 0; 
    em[1305] = 1; em[1306] = 8; em[1307] = 1; /* 1305: pointer.struct.asn1_string_st */
    	em[1308] = 1265; em[1309] = 0; 
    em[1310] = 1; em[1311] = 8; em[1312] = 1; /* 1310: pointer.struct.asn1_string_st */
    	em[1313] = 1265; em[1314] = 0; 
    em[1315] = 1; em[1316] = 8; em[1317] = 1; /* 1315: pointer.struct.asn1_string_st */
    	em[1318] = 1265; em[1319] = 0; 
    em[1320] = 1; em[1321] = 8; em[1322] = 1; /* 1320: pointer.struct.asn1_string_st */
    	em[1323] = 1265; em[1324] = 0; 
    em[1325] = 1; em[1326] = 8; em[1327] = 1; /* 1325: pointer.struct.asn1_string_st */
    	em[1328] = 1265; em[1329] = 0; 
    em[1330] = 1; em[1331] = 8; em[1332] = 1; /* 1330: pointer.struct.asn1_string_st */
    	em[1333] = 1265; em[1334] = 0; 
    em[1335] = 1; em[1336] = 8; em[1337] = 1; /* 1335: pointer.struct.asn1_string_st */
    	em[1338] = 1265; em[1339] = 0; 
    em[1340] = 1; em[1341] = 8; em[1342] = 1; /* 1340: pointer.struct.ASN1_VALUE_st */
    	em[1343] = 1345; em[1344] = 0; 
    em[1345] = 0; em[1346] = 0; em[1347] = 0; /* 1345: struct.ASN1_VALUE_st */
    em[1348] = 1; em[1349] = 8; em[1350] = 1; /* 1348: pointer.struct.X509_name_st */
    	em[1351] = 1353; em[1352] = 0; 
    em[1353] = 0; em[1354] = 40; em[1355] = 3; /* 1353: struct.X509_name_st */
    	em[1356] = 1362; em[1357] = 0; 
    	em[1358] = 1386; em[1359] = 16; 
    	em[1360] = 585; em[1361] = 24; 
    em[1362] = 1; em[1363] = 8; em[1364] = 1; /* 1362: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[1365] = 1367; em[1366] = 0; 
    em[1367] = 0; em[1368] = 32; em[1369] = 2; /* 1367: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[1370] = 1374; em[1371] = 8; 
    	em[1372] = 84; em[1373] = 24; 
    em[1374] = 8884099; em[1375] = 8; em[1376] = 2; /* 1374: pointer_to_array_of_pointers_to_stack */
    	em[1377] = 1381; em[1378] = 0; 
    	em[1379] = 50; em[1380] = 20; 
    em[1381] = 0; em[1382] = 8; em[1383] = 1; /* 1381: pointer.X509_NAME_ENTRY */
    	em[1384] = 799; em[1385] = 0; 
    em[1386] = 1; em[1387] = 8; em[1388] = 1; /* 1386: pointer.struct.buf_mem_st */
    	em[1389] = 1391; em[1390] = 0; 
    em[1391] = 0; em[1392] = 24; em[1393] = 1; /* 1391: struct.buf_mem_st */
    	em[1394] = 140; em[1395] = 8; 
    em[1396] = 1; em[1397] = 8; em[1398] = 1; /* 1396: pointer.struct.EDIPartyName_st */
    	em[1399] = 1401; em[1400] = 0; 
    em[1401] = 0; em[1402] = 16; em[1403] = 2; /* 1401: struct.EDIPartyName_st */
    	em[1404] = 1260; em[1405] = 0; 
    	em[1406] = 1260; em[1407] = 8; 
    em[1408] = 0; em[1409] = 24; em[1410] = 1; /* 1408: struct.asn1_string_st */
    	em[1411] = 585; em[1412] = 8; 
    em[1413] = 1; em[1414] = 8; em[1415] = 1; /* 1413: pointer.struct.buf_mem_st */
    	em[1416] = 1418; em[1417] = 0; 
    em[1418] = 0; em[1419] = 24; em[1420] = 1; /* 1418: struct.buf_mem_st */
    	em[1421] = 140; em[1422] = 8; 
    em[1423] = 0; em[1424] = 40; em[1425] = 3; /* 1423: struct.X509_name_st */
    	em[1426] = 1432; em[1427] = 0; 
    	em[1428] = 1413; em[1429] = 16; 
    	em[1430] = 585; em[1431] = 24; 
    em[1432] = 1; em[1433] = 8; em[1434] = 1; /* 1432: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[1435] = 1437; em[1436] = 0; 
    em[1437] = 0; em[1438] = 32; em[1439] = 2; /* 1437: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[1440] = 1444; em[1441] = 8; 
    	em[1442] = 84; em[1443] = 24; 
    em[1444] = 8884099; em[1445] = 8; em[1446] = 2; /* 1444: pointer_to_array_of_pointers_to_stack */
    	em[1447] = 1451; em[1448] = 0; 
    	em[1449] = 50; em[1450] = 20; 
    em[1451] = 0; em[1452] = 8; em[1453] = 1; /* 1451: pointer.X509_NAME_ENTRY */
    	em[1454] = 799; em[1455] = 0; 
    em[1456] = 1; em[1457] = 8; em[1458] = 1; /* 1456: pointer.struct.DIST_POINT_NAME_st */
    	em[1459] = 1461; em[1460] = 0; 
    em[1461] = 0; em[1462] = 24; em[1463] = 2; /* 1461: struct.DIST_POINT_NAME_st */
    	em[1464] = 1468; em[1465] = 8; 
    	em[1466] = 1499; em[1467] = 16; 
    em[1468] = 0; em[1469] = 8; em[1470] = 2; /* 1468: union.unknown */
    	em[1471] = 1475; em[1472] = 0; 
    	em[1473] = 1432; em[1474] = 0; 
    em[1475] = 1; em[1476] = 8; em[1477] = 1; /* 1475: pointer.struct.stack_st_GENERAL_NAME */
    	em[1478] = 1480; em[1479] = 0; 
    em[1480] = 0; em[1481] = 32; em[1482] = 2; /* 1480: struct.stack_st_fake_GENERAL_NAME */
    	em[1483] = 1487; em[1484] = 8; 
    	em[1485] = 84; em[1486] = 24; 
    em[1487] = 8884099; em[1488] = 8; em[1489] = 2; /* 1487: pointer_to_array_of_pointers_to_stack */
    	em[1490] = 1494; em[1491] = 0; 
    	em[1492] = 50; em[1493] = 20; 
    em[1494] = 0; em[1495] = 8; em[1496] = 1; /* 1494: pointer.GENERAL_NAME */
    	em[1497] = 1138; em[1498] = 0; 
    em[1499] = 1; em[1500] = 8; em[1501] = 1; /* 1499: pointer.struct.X509_name_st */
    	em[1502] = 1423; em[1503] = 0; 
    em[1504] = 0; em[1505] = 0; em[1506] = 1; /* 1504: X509_POLICY_DATA */
    	em[1507] = 1509; em[1508] = 0; 
    em[1509] = 0; em[1510] = 32; em[1511] = 3; /* 1509: struct.X509_POLICY_DATA_st */
    	em[1512] = 1518; em[1513] = 8; 
    	em[1514] = 1532; em[1515] = 16; 
    	em[1516] = 1782; em[1517] = 24; 
    em[1518] = 1; em[1519] = 8; em[1520] = 1; /* 1518: pointer.struct.asn1_object_st */
    	em[1521] = 1523; em[1522] = 0; 
    em[1523] = 0; em[1524] = 40; em[1525] = 3; /* 1523: struct.asn1_object_st */
    	em[1526] = 117; em[1527] = 0; 
    	em[1528] = 117; em[1529] = 8; 
    	em[1530] = 514; em[1531] = 24; 
    em[1532] = 1; em[1533] = 8; em[1534] = 1; /* 1532: pointer.struct.stack_st_POLICYQUALINFO */
    	em[1535] = 1537; em[1536] = 0; 
    em[1537] = 0; em[1538] = 32; em[1539] = 2; /* 1537: struct.stack_st_fake_POLICYQUALINFO */
    	em[1540] = 1544; em[1541] = 8; 
    	em[1542] = 84; em[1543] = 24; 
    em[1544] = 8884099; em[1545] = 8; em[1546] = 2; /* 1544: pointer_to_array_of_pointers_to_stack */
    	em[1547] = 1551; em[1548] = 0; 
    	em[1549] = 50; em[1550] = 20; 
    em[1551] = 0; em[1552] = 8; em[1553] = 1; /* 1551: pointer.POLICYQUALINFO */
    	em[1554] = 1556; em[1555] = 0; 
    em[1556] = 0; em[1557] = 0; em[1558] = 1; /* 1556: POLICYQUALINFO */
    	em[1559] = 1561; em[1560] = 0; 
    em[1561] = 0; em[1562] = 16; em[1563] = 2; /* 1561: struct.POLICYQUALINFO_st */
    	em[1564] = 1568; em[1565] = 0; 
    	em[1566] = 1582; em[1567] = 8; 
    em[1568] = 1; em[1569] = 8; em[1570] = 1; /* 1568: pointer.struct.asn1_object_st */
    	em[1571] = 1573; em[1572] = 0; 
    em[1573] = 0; em[1574] = 40; em[1575] = 3; /* 1573: struct.asn1_object_st */
    	em[1576] = 117; em[1577] = 0; 
    	em[1578] = 117; em[1579] = 8; 
    	em[1580] = 514; em[1581] = 24; 
    em[1582] = 0; em[1583] = 8; em[1584] = 3; /* 1582: union.unknown */
    	em[1585] = 1591; em[1586] = 0; 
    	em[1587] = 1601; em[1588] = 0; 
    	em[1589] = 1664; em[1590] = 0; 
    em[1591] = 1; em[1592] = 8; em[1593] = 1; /* 1591: pointer.struct.asn1_string_st */
    	em[1594] = 1596; em[1595] = 0; 
    em[1596] = 0; em[1597] = 24; em[1598] = 1; /* 1596: struct.asn1_string_st */
    	em[1599] = 585; em[1600] = 8; 
    em[1601] = 1; em[1602] = 8; em[1603] = 1; /* 1601: pointer.struct.USERNOTICE_st */
    	em[1604] = 1606; em[1605] = 0; 
    em[1606] = 0; em[1607] = 16; em[1608] = 2; /* 1606: struct.USERNOTICE_st */
    	em[1609] = 1613; em[1610] = 0; 
    	em[1611] = 1625; em[1612] = 8; 
    em[1613] = 1; em[1614] = 8; em[1615] = 1; /* 1613: pointer.struct.NOTICEREF_st */
    	em[1616] = 1618; em[1617] = 0; 
    em[1618] = 0; em[1619] = 16; em[1620] = 2; /* 1618: struct.NOTICEREF_st */
    	em[1621] = 1625; em[1622] = 0; 
    	em[1623] = 1630; em[1624] = 8; 
    em[1625] = 1; em[1626] = 8; em[1627] = 1; /* 1625: pointer.struct.asn1_string_st */
    	em[1628] = 1596; em[1629] = 0; 
    em[1630] = 1; em[1631] = 8; em[1632] = 1; /* 1630: pointer.struct.stack_st_ASN1_INTEGER */
    	em[1633] = 1635; em[1634] = 0; 
    em[1635] = 0; em[1636] = 32; em[1637] = 2; /* 1635: struct.stack_st_fake_ASN1_INTEGER */
    	em[1638] = 1642; em[1639] = 8; 
    	em[1640] = 84; em[1641] = 24; 
    em[1642] = 8884099; em[1643] = 8; em[1644] = 2; /* 1642: pointer_to_array_of_pointers_to_stack */
    	em[1645] = 1649; em[1646] = 0; 
    	em[1647] = 50; em[1648] = 20; 
    em[1649] = 0; em[1650] = 8; em[1651] = 1; /* 1649: pointer.ASN1_INTEGER */
    	em[1652] = 1654; em[1653] = 0; 
    em[1654] = 0; em[1655] = 0; em[1656] = 1; /* 1654: ASN1_INTEGER */
    	em[1657] = 1659; em[1658] = 0; 
    em[1659] = 0; em[1660] = 24; em[1661] = 1; /* 1659: struct.asn1_string_st */
    	em[1662] = 585; em[1663] = 8; 
    em[1664] = 1; em[1665] = 8; em[1666] = 1; /* 1664: pointer.struct.asn1_type_st */
    	em[1667] = 1669; em[1668] = 0; 
    em[1669] = 0; em[1670] = 16; em[1671] = 1; /* 1669: struct.asn1_type_st */
    	em[1672] = 1674; em[1673] = 8; 
    em[1674] = 0; em[1675] = 8; em[1676] = 20; /* 1674: union.unknown */
    	em[1677] = 140; em[1678] = 0; 
    	em[1679] = 1625; em[1680] = 0; 
    	em[1681] = 1568; em[1682] = 0; 
    	em[1683] = 1717; em[1684] = 0; 
    	em[1685] = 1722; em[1686] = 0; 
    	em[1687] = 1727; em[1688] = 0; 
    	em[1689] = 1732; em[1690] = 0; 
    	em[1691] = 1737; em[1692] = 0; 
    	em[1693] = 1742; em[1694] = 0; 
    	em[1695] = 1591; em[1696] = 0; 
    	em[1697] = 1747; em[1698] = 0; 
    	em[1699] = 1752; em[1700] = 0; 
    	em[1701] = 1757; em[1702] = 0; 
    	em[1703] = 1762; em[1704] = 0; 
    	em[1705] = 1767; em[1706] = 0; 
    	em[1707] = 1772; em[1708] = 0; 
    	em[1709] = 1777; em[1710] = 0; 
    	em[1711] = 1625; em[1712] = 0; 
    	em[1713] = 1625; em[1714] = 0; 
    	em[1715] = 1003; em[1716] = 0; 
    em[1717] = 1; em[1718] = 8; em[1719] = 1; /* 1717: pointer.struct.asn1_string_st */
    	em[1720] = 1596; em[1721] = 0; 
    em[1722] = 1; em[1723] = 8; em[1724] = 1; /* 1722: pointer.struct.asn1_string_st */
    	em[1725] = 1596; em[1726] = 0; 
    em[1727] = 1; em[1728] = 8; em[1729] = 1; /* 1727: pointer.struct.asn1_string_st */
    	em[1730] = 1596; em[1731] = 0; 
    em[1732] = 1; em[1733] = 8; em[1734] = 1; /* 1732: pointer.struct.asn1_string_st */
    	em[1735] = 1596; em[1736] = 0; 
    em[1737] = 1; em[1738] = 8; em[1739] = 1; /* 1737: pointer.struct.asn1_string_st */
    	em[1740] = 1596; em[1741] = 0; 
    em[1742] = 1; em[1743] = 8; em[1744] = 1; /* 1742: pointer.struct.asn1_string_st */
    	em[1745] = 1596; em[1746] = 0; 
    em[1747] = 1; em[1748] = 8; em[1749] = 1; /* 1747: pointer.struct.asn1_string_st */
    	em[1750] = 1596; em[1751] = 0; 
    em[1752] = 1; em[1753] = 8; em[1754] = 1; /* 1752: pointer.struct.asn1_string_st */
    	em[1755] = 1596; em[1756] = 0; 
    em[1757] = 1; em[1758] = 8; em[1759] = 1; /* 1757: pointer.struct.asn1_string_st */
    	em[1760] = 1596; em[1761] = 0; 
    em[1762] = 1; em[1763] = 8; em[1764] = 1; /* 1762: pointer.struct.asn1_string_st */
    	em[1765] = 1596; em[1766] = 0; 
    em[1767] = 1; em[1768] = 8; em[1769] = 1; /* 1767: pointer.struct.asn1_string_st */
    	em[1770] = 1596; em[1771] = 0; 
    em[1772] = 1; em[1773] = 8; em[1774] = 1; /* 1772: pointer.struct.asn1_string_st */
    	em[1775] = 1596; em[1776] = 0; 
    em[1777] = 1; em[1778] = 8; em[1779] = 1; /* 1777: pointer.struct.asn1_string_st */
    	em[1780] = 1596; em[1781] = 0; 
    em[1782] = 1; em[1783] = 8; em[1784] = 1; /* 1782: pointer.struct.stack_st_ASN1_OBJECT */
    	em[1785] = 1787; em[1786] = 0; 
    em[1787] = 0; em[1788] = 32; em[1789] = 2; /* 1787: struct.stack_st_fake_ASN1_OBJECT */
    	em[1790] = 1794; em[1791] = 8; 
    	em[1792] = 84; em[1793] = 24; 
    em[1794] = 8884099; em[1795] = 8; em[1796] = 2; /* 1794: pointer_to_array_of_pointers_to_stack */
    	em[1797] = 1801; em[1798] = 0; 
    	em[1799] = 50; em[1800] = 20; 
    em[1801] = 0; em[1802] = 8; em[1803] = 1; /* 1801: pointer.ASN1_OBJECT */
    	em[1804] = 726; em[1805] = 0; 
    em[1806] = 1; em[1807] = 8; em[1808] = 1; /* 1806: pointer.struct.stack_st_X509_POLICY_DATA */
    	em[1809] = 1811; em[1810] = 0; 
    em[1811] = 0; em[1812] = 32; em[1813] = 2; /* 1811: struct.stack_st_fake_X509_POLICY_DATA */
    	em[1814] = 1818; em[1815] = 8; 
    	em[1816] = 84; em[1817] = 24; 
    em[1818] = 8884099; em[1819] = 8; em[1820] = 2; /* 1818: pointer_to_array_of_pointers_to_stack */
    	em[1821] = 1825; em[1822] = 0; 
    	em[1823] = 50; em[1824] = 20; 
    em[1825] = 0; em[1826] = 8; em[1827] = 1; /* 1825: pointer.X509_POLICY_DATA */
    	em[1828] = 1504; em[1829] = 0; 
    em[1830] = 1; em[1831] = 8; em[1832] = 1; /* 1830: pointer.struct.stack_st_ASN1_OBJECT */
    	em[1833] = 1835; em[1834] = 0; 
    em[1835] = 0; em[1836] = 32; em[1837] = 2; /* 1835: struct.stack_st_fake_ASN1_OBJECT */
    	em[1838] = 1842; em[1839] = 8; 
    	em[1840] = 84; em[1841] = 24; 
    em[1842] = 8884099; em[1843] = 8; em[1844] = 2; /* 1842: pointer_to_array_of_pointers_to_stack */
    	em[1845] = 1849; em[1846] = 0; 
    	em[1847] = 50; em[1848] = 20; 
    em[1849] = 0; em[1850] = 8; em[1851] = 1; /* 1849: pointer.ASN1_OBJECT */
    	em[1852] = 726; em[1853] = 0; 
    em[1854] = 1; em[1855] = 8; em[1856] = 1; /* 1854: pointer.struct.stack_st_POLICYQUALINFO */
    	em[1857] = 1859; em[1858] = 0; 
    em[1859] = 0; em[1860] = 32; em[1861] = 2; /* 1859: struct.stack_st_fake_POLICYQUALINFO */
    	em[1862] = 1866; em[1863] = 8; 
    	em[1864] = 84; em[1865] = 24; 
    em[1866] = 8884099; em[1867] = 8; em[1868] = 2; /* 1866: pointer_to_array_of_pointers_to_stack */
    	em[1869] = 1873; em[1870] = 0; 
    	em[1871] = 50; em[1872] = 20; 
    em[1873] = 0; em[1874] = 8; em[1875] = 1; /* 1873: pointer.POLICYQUALINFO */
    	em[1876] = 1556; em[1877] = 0; 
    em[1878] = 0; em[1879] = 56; em[1880] = 4; /* 1878: struct.evp_pkey_st */
    	em[1881] = 1889; em[1882] = 16; 
    	em[1883] = 1990; em[1884] = 24; 
    	em[1885] = 1995; em[1886] = 32; 
    	em[1887] = 2845; em[1888] = 48; 
    em[1889] = 1; em[1890] = 8; em[1891] = 1; /* 1889: pointer.struct.evp_pkey_asn1_method_st */
    	em[1892] = 1894; em[1893] = 0; 
    em[1894] = 0; em[1895] = 208; em[1896] = 24; /* 1894: struct.evp_pkey_asn1_method_st */
    	em[1897] = 140; em[1898] = 16; 
    	em[1899] = 140; em[1900] = 24; 
    	em[1901] = 1945; em[1902] = 32; 
    	em[1903] = 1948; em[1904] = 40; 
    	em[1905] = 1951; em[1906] = 48; 
    	em[1907] = 1954; em[1908] = 56; 
    	em[1909] = 1957; em[1910] = 64; 
    	em[1911] = 1960; em[1912] = 72; 
    	em[1913] = 1954; em[1914] = 80; 
    	em[1915] = 1963; em[1916] = 88; 
    	em[1917] = 1963; em[1918] = 96; 
    	em[1919] = 1966; em[1920] = 104; 
    	em[1921] = 1969; em[1922] = 112; 
    	em[1923] = 1963; em[1924] = 120; 
    	em[1925] = 1972; em[1926] = 128; 
    	em[1927] = 1951; em[1928] = 136; 
    	em[1929] = 1954; em[1930] = 144; 
    	em[1931] = 1975; em[1932] = 152; 
    	em[1933] = 1978; em[1934] = 160; 
    	em[1935] = 1981; em[1936] = 168; 
    	em[1937] = 1966; em[1938] = 176; 
    	em[1939] = 1969; em[1940] = 184; 
    	em[1941] = 1984; em[1942] = 192; 
    	em[1943] = 1987; em[1944] = 200; 
    em[1945] = 8884097; em[1946] = 8; em[1947] = 0; /* 1945: pointer.func */
    em[1948] = 8884097; em[1949] = 8; em[1950] = 0; /* 1948: pointer.func */
    em[1951] = 8884097; em[1952] = 8; em[1953] = 0; /* 1951: pointer.func */
    em[1954] = 8884097; em[1955] = 8; em[1956] = 0; /* 1954: pointer.func */
    em[1957] = 8884097; em[1958] = 8; em[1959] = 0; /* 1957: pointer.func */
    em[1960] = 8884097; em[1961] = 8; em[1962] = 0; /* 1960: pointer.func */
    em[1963] = 8884097; em[1964] = 8; em[1965] = 0; /* 1963: pointer.func */
    em[1966] = 8884097; em[1967] = 8; em[1968] = 0; /* 1966: pointer.func */
    em[1969] = 8884097; em[1970] = 8; em[1971] = 0; /* 1969: pointer.func */
    em[1972] = 8884097; em[1973] = 8; em[1974] = 0; /* 1972: pointer.func */
    em[1975] = 8884097; em[1976] = 8; em[1977] = 0; /* 1975: pointer.func */
    em[1978] = 8884097; em[1979] = 8; em[1980] = 0; /* 1978: pointer.func */
    em[1981] = 8884097; em[1982] = 8; em[1983] = 0; /* 1981: pointer.func */
    em[1984] = 8884097; em[1985] = 8; em[1986] = 0; /* 1984: pointer.func */
    em[1987] = 8884097; em[1988] = 8; em[1989] = 0; /* 1987: pointer.func */
    em[1990] = 1; em[1991] = 8; em[1992] = 1; /* 1990: pointer.struct.engine_st */
    	em[1993] = 153; em[1994] = 0; 
    em[1995] = 0; em[1996] = 8; em[1997] = 6; /* 1995: union.union_of_evp_pkey_st */
    	em[1998] = 81; em[1999] = 0; 
    	em[2000] = 2010; em[2001] = 6; 
    	em[2002] = 0; em[2003] = 116; 
    	em[2004] = 2218; em[2005] = 28; 
    	em[2006] = 2336; em[2007] = 408; 
    	em[2008] = 50; em[2009] = 0; 
    em[2010] = 1; em[2011] = 8; em[2012] = 1; /* 2010: pointer.struct.rsa_st */
    	em[2013] = 2015; em[2014] = 0; 
    em[2015] = 0; em[2016] = 168; em[2017] = 17; /* 2015: struct.rsa_st */
    	em[2018] = 2052; em[2019] = 16; 
    	em[2020] = 2107; em[2021] = 24; 
    	em[2022] = 2112; em[2023] = 32; 
    	em[2024] = 2112; em[2025] = 40; 
    	em[2026] = 2112; em[2027] = 48; 
    	em[2028] = 2112; em[2029] = 56; 
    	em[2030] = 2112; em[2031] = 64; 
    	em[2032] = 2112; em[2033] = 72; 
    	em[2034] = 2112; em[2035] = 80; 
    	em[2036] = 2112; em[2037] = 88; 
    	em[2038] = 2129; em[2039] = 96; 
    	em[2040] = 2143; em[2041] = 120; 
    	em[2042] = 2143; em[2043] = 128; 
    	em[2044] = 2143; em[2045] = 136; 
    	em[2046] = 140; em[2047] = 144; 
    	em[2048] = 2157; em[2049] = 152; 
    	em[2050] = 2157; em[2051] = 160; 
    em[2052] = 1; em[2053] = 8; em[2054] = 1; /* 2052: pointer.struct.rsa_meth_st */
    	em[2055] = 2057; em[2056] = 0; 
    em[2057] = 0; em[2058] = 112; em[2059] = 13; /* 2057: struct.rsa_meth_st */
    	em[2060] = 117; em[2061] = 0; 
    	em[2062] = 2086; em[2063] = 8; 
    	em[2064] = 2086; em[2065] = 16; 
    	em[2066] = 2086; em[2067] = 24; 
    	em[2068] = 2086; em[2069] = 32; 
    	em[2070] = 2089; em[2071] = 40; 
    	em[2072] = 2092; em[2073] = 48; 
    	em[2074] = 2095; em[2075] = 56; 
    	em[2076] = 2095; em[2077] = 64; 
    	em[2078] = 140; em[2079] = 80; 
    	em[2080] = 2098; em[2081] = 88; 
    	em[2082] = 2101; em[2083] = 96; 
    	em[2084] = 2104; em[2085] = 104; 
    em[2086] = 8884097; em[2087] = 8; em[2088] = 0; /* 2086: pointer.func */
    em[2089] = 8884097; em[2090] = 8; em[2091] = 0; /* 2089: pointer.func */
    em[2092] = 8884097; em[2093] = 8; em[2094] = 0; /* 2092: pointer.func */
    em[2095] = 8884097; em[2096] = 8; em[2097] = 0; /* 2095: pointer.func */
    em[2098] = 8884097; em[2099] = 8; em[2100] = 0; /* 2098: pointer.func */
    em[2101] = 8884097; em[2102] = 8; em[2103] = 0; /* 2101: pointer.func */
    em[2104] = 8884097; em[2105] = 8; em[2106] = 0; /* 2104: pointer.func */
    em[2107] = 1; em[2108] = 8; em[2109] = 1; /* 2107: pointer.struct.engine_st */
    	em[2110] = 153; em[2111] = 0; 
    em[2112] = 1; em[2113] = 8; em[2114] = 1; /* 2112: pointer.struct.bignum_st */
    	em[2115] = 2117; em[2116] = 0; 
    em[2117] = 0; em[2118] = 24; em[2119] = 1; /* 2117: struct.bignum_st */
    	em[2120] = 2122; em[2121] = 0; 
    em[2122] = 8884099; em[2123] = 8; em[2124] = 2; /* 2122: pointer_to_array_of_pointers_to_stack */
    	em[2125] = 47; em[2126] = 0; 
    	em[2127] = 50; em[2128] = 12; 
    em[2129] = 0; em[2130] = 32; em[2131] = 2; /* 2129: struct.crypto_ex_data_st_fake */
    	em[2132] = 2136; em[2133] = 8; 
    	em[2134] = 84; em[2135] = 24; 
    em[2136] = 8884099; em[2137] = 8; em[2138] = 2; /* 2136: pointer_to_array_of_pointers_to_stack */
    	em[2139] = 81; em[2140] = 0; 
    	em[2141] = 50; em[2142] = 20; 
    em[2143] = 1; em[2144] = 8; em[2145] = 1; /* 2143: pointer.struct.bn_mont_ctx_st */
    	em[2146] = 2148; em[2147] = 0; 
    em[2148] = 0; em[2149] = 96; em[2150] = 3; /* 2148: struct.bn_mont_ctx_st */
    	em[2151] = 2117; em[2152] = 8; 
    	em[2153] = 2117; em[2154] = 32; 
    	em[2155] = 2117; em[2156] = 56; 
    em[2157] = 1; em[2158] = 8; em[2159] = 1; /* 2157: pointer.struct.bn_blinding_st */
    	em[2160] = 2162; em[2161] = 0; 
    em[2162] = 0; em[2163] = 88; em[2164] = 7; /* 2162: struct.bn_blinding_st */
    	em[2165] = 2179; em[2166] = 0; 
    	em[2167] = 2179; em[2168] = 8; 
    	em[2169] = 2179; em[2170] = 16; 
    	em[2171] = 2179; em[2172] = 24; 
    	em[2173] = 2196; em[2174] = 40; 
    	em[2175] = 2201; em[2176] = 72; 
    	em[2177] = 2215; em[2178] = 80; 
    em[2179] = 1; em[2180] = 8; em[2181] = 1; /* 2179: pointer.struct.bignum_st */
    	em[2182] = 2184; em[2183] = 0; 
    em[2184] = 0; em[2185] = 24; em[2186] = 1; /* 2184: struct.bignum_st */
    	em[2187] = 2189; em[2188] = 0; 
    em[2189] = 8884099; em[2190] = 8; em[2191] = 2; /* 2189: pointer_to_array_of_pointers_to_stack */
    	em[2192] = 47; em[2193] = 0; 
    	em[2194] = 50; em[2195] = 12; 
    em[2196] = 0; em[2197] = 16; em[2198] = 1; /* 2196: struct.crypto_threadid_st */
    	em[2199] = 81; em[2200] = 0; 
    em[2201] = 1; em[2202] = 8; em[2203] = 1; /* 2201: pointer.struct.bn_mont_ctx_st */
    	em[2204] = 2206; em[2205] = 0; 
    em[2206] = 0; em[2207] = 96; em[2208] = 3; /* 2206: struct.bn_mont_ctx_st */
    	em[2209] = 2184; em[2210] = 8; 
    	em[2211] = 2184; em[2212] = 32; 
    	em[2213] = 2184; em[2214] = 56; 
    em[2215] = 8884097; em[2216] = 8; em[2217] = 0; /* 2215: pointer.func */
    em[2218] = 1; em[2219] = 8; em[2220] = 1; /* 2218: pointer.struct.dh_st */
    	em[2221] = 2223; em[2222] = 0; 
    em[2223] = 0; em[2224] = 144; em[2225] = 12; /* 2223: struct.dh_st */
    	em[2226] = 2250; em[2227] = 8; 
    	em[2228] = 2250; em[2229] = 16; 
    	em[2230] = 2250; em[2231] = 32; 
    	em[2232] = 2250; em[2233] = 40; 
    	em[2234] = 2267; em[2235] = 56; 
    	em[2236] = 2250; em[2237] = 64; 
    	em[2238] = 2250; em[2239] = 72; 
    	em[2240] = 585; em[2241] = 80; 
    	em[2242] = 2250; em[2243] = 96; 
    	em[2244] = 2281; em[2245] = 112; 
    	em[2246] = 2295; em[2247] = 128; 
    	em[2248] = 2331; em[2249] = 136; 
    em[2250] = 1; em[2251] = 8; em[2252] = 1; /* 2250: pointer.struct.bignum_st */
    	em[2253] = 2255; em[2254] = 0; 
    em[2255] = 0; em[2256] = 24; em[2257] = 1; /* 2255: struct.bignum_st */
    	em[2258] = 2260; em[2259] = 0; 
    em[2260] = 8884099; em[2261] = 8; em[2262] = 2; /* 2260: pointer_to_array_of_pointers_to_stack */
    	em[2263] = 47; em[2264] = 0; 
    	em[2265] = 50; em[2266] = 12; 
    em[2267] = 1; em[2268] = 8; em[2269] = 1; /* 2267: pointer.struct.bn_mont_ctx_st */
    	em[2270] = 2272; em[2271] = 0; 
    em[2272] = 0; em[2273] = 96; em[2274] = 3; /* 2272: struct.bn_mont_ctx_st */
    	em[2275] = 2255; em[2276] = 8; 
    	em[2277] = 2255; em[2278] = 32; 
    	em[2279] = 2255; em[2280] = 56; 
    em[2281] = 0; em[2282] = 32; em[2283] = 2; /* 2281: struct.crypto_ex_data_st_fake */
    	em[2284] = 2288; em[2285] = 8; 
    	em[2286] = 84; em[2287] = 24; 
    em[2288] = 8884099; em[2289] = 8; em[2290] = 2; /* 2288: pointer_to_array_of_pointers_to_stack */
    	em[2291] = 81; em[2292] = 0; 
    	em[2293] = 50; em[2294] = 20; 
    em[2295] = 1; em[2296] = 8; em[2297] = 1; /* 2295: pointer.struct.dh_method */
    	em[2298] = 2300; em[2299] = 0; 
    em[2300] = 0; em[2301] = 72; em[2302] = 8; /* 2300: struct.dh_method */
    	em[2303] = 117; em[2304] = 0; 
    	em[2305] = 2319; em[2306] = 8; 
    	em[2307] = 2322; em[2308] = 16; 
    	em[2309] = 2325; em[2310] = 24; 
    	em[2311] = 2319; em[2312] = 32; 
    	em[2313] = 2319; em[2314] = 40; 
    	em[2315] = 140; em[2316] = 56; 
    	em[2317] = 2328; em[2318] = 64; 
    em[2319] = 8884097; em[2320] = 8; em[2321] = 0; /* 2319: pointer.func */
    em[2322] = 8884097; em[2323] = 8; em[2324] = 0; /* 2322: pointer.func */
    em[2325] = 8884097; em[2326] = 8; em[2327] = 0; /* 2325: pointer.func */
    em[2328] = 8884097; em[2329] = 8; em[2330] = 0; /* 2328: pointer.func */
    em[2331] = 1; em[2332] = 8; em[2333] = 1; /* 2331: pointer.struct.engine_st */
    	em[2334] = 153; em[2335] = 0; 
    em[2336] = 1; em[2337] = 8; em[2338] = 1; /* 2336: pointer.struct.ec_key_st */
    	em[2339] = 2341; em[2340] = 0; 
    em[2341] = 0; em[2342] = 56; em[2343] = 4; /* 2341: struct.ec_key_st */
    	em[2344] = 2352; em[2345] = 8; 
    	em[2346] = 2800; em[2347] = 16; 
    	em[2348] = 2805; em[2349] = 24; 
    	em[2350] = 2822; em[2351] = 48; 
    em[2352] = 1; em[2353] = 8; em[2354] = 1; /* 2352: pointer.struct.ec_group_st */
    	em[2355] = 2357; em[2356] = 0; 
    em[2357] = 0; em[2358] = 232; em[2359] = 12; /* 2357: struct.ec_group_st */
    	em[2360] = 2384; em[2361] = 0; 
    	em[2362] = 2556; em[2363] = 8; 
    	em[2364] = 2756; em[2365] = 16; 
    	em[2366] = 2756; em[2367] = 40; 
    	em[2368] = 585; em[2369] = 80; 
    	em[2370] = 2768; em[2371] = 96; 
    	em[2372] = 2756; em[2373] = 104; 
    	em[2374] = 2756; em[2375] = 152; 
    	em[2376] = 2756; em[2377] = 176; 
    	em[2378] = 81; em[2379] = 208; 
    	em[2380] = 81; em[2381] = 216; 
    	em[2382] = 2797; em[2383] = 224; 
    em[2384] = 1; em[2385] = 8; em[2386] = 1; /* 2384: pointer.struct.ec_method_st */
    	em[2387] = 2389; em[2388] = 0; 
    em[2389] = 0; em[2390] = 304; em[2391] = 37; /* 2389: struct.ec_method_st */
    	em[2392] = 2466; em[2393] = 8; 
    	em[2394] = 2469; em[2395] = 16; 
    	em[2396] = 2469; em[2397] = 24; 
    	em[2398] = 2472; em[2399] = 32; 
    	em[2400] = 2475; em[2401] = 40; 
    	em[2402] = 2478; em[2403] = 48; 
    	em[2404] = 2481; em[2405] = 56; 
    	em[2406] = 2484; em[2407] = 64; 
    	em[2408] = 2487; em[2409] = 72; 
    	em[2410] = 2490; em[2411] = 80; 
    	em[2412] = 2490; em[2413] = 88; 
    	em[2414] = 2493; em[2415] = 96; 
    	em[2416] = 2496; em[2417] = 104; 
    	em[2418] = 2499; em[2419] = 112; 
    	em[2420] = 2502; em[2421] = 120; 
    	em[2422] = 2505; em[2423] = 128; 
    	em[2424] = 2508; em[2425] = 136; 
    	em[2426] = 2511; em[2427] = 144; 
    	em[2428] = 2514; em[2429] = 152; 
    	em[2430] = 2517; em[2431] = 160; 
    	em[2432] = 2520; em[2433] = 168; 
    	em[2434] = 2523; em[2435] = 176; 
    	em[2436] = 2526; em[2437] = 184; 
    	em[2438] = 2529; em[2439] = 192; 
    	em[2440] = 2532; em[2441] = 200; 
    	em[2442] = 2535; em[2443] = 208; 
    	em[2444] = 2526; em[2445] = 216; 
    	em[2446] = 2538; em[2447] = 224; 
    	em[2448] = 2541; em[2449] = 232; 
    	em[2450] = 2544; em[2451] = 240; 
    	em[2452] = 2481; em[2453] = 248; 
    	em[2454] = 2547; em[2455] = 256; 
    	em[2456] = 2550; em[2457] = 264; 
    	em[2458] = 2547; em[2459] = 272; 
    	em[2460] = 2550; em[2461] = 280; 
    	em[2462] = 2550; em[2463] = 288; 
    	em[2464] = 2553; em[2465] = 296; 
    em[2466] = 8884097; em[2467] = 8; em[2468] = 0; /* 2466: pointer.func */
    em[2469] = 8884097; em[2470] = 8; em[2471] = 0; /* 2469: pointer.func */
    em[2472] = 8884097; em[2473] = 8; em[2474] = 0; /* 2472: pointer.func */
    em[2475] = 8884097; em[2476] = 8; em[2477] = 0; /* 2475: pointer.func */
    em[2478] = 8884097; em[2479] = 8; em[2480] = 0; /* 2478: pointer.func */
    em[2481] = 8884097; em[2482] = 8; em[2483] = 0; /* 2481: pointer.func */
    em[2484] = 8884097; em[2485] = 8; em[2486] = 0; /* 2484: pointer.func */
    em[2487] = 8884097; em[2488] = 8; em[2489] = 0; /* 2487: pointer.func */
    em[2490] = 8884097; em[2491] = 8; em[2492] = 0; /* 2490: pointer.func */
    em[2493] = 8884097; em[2494] = 8; em[2495] = 0; /* 2493: pointer.func */
    em[2496] = 8884097; em[2497] = 8; em[2498] = 0; /* 2496: pointer.func */
    em[2499] = 8884097; em[2500] = 8; em[2501] = 0; /* 2499: pointer.func */
    em[2502] = 8884097; em[2503] = 8; em[2504] = 0; /* 2502: pointer.func */
    em[2505] = 8884097; em[2506] = 8; em[2507] = 0; /* 2505: pointer.func */
    em[2508] = 8884097; em[2509] = 8; em[2510] = 0; /* 2508: pointer.func */
    em[2511] = 8884097; em[2512] = 8; em[2513] = 0; /* 2511: pointer.func */
    em[2514] = 8884097; em[2515] = 8; em[2516] = 0; /* 2514: pointer.func */
    em[2517] = 8884097; em[2518] = 8; em[2519] = 0; /* 2517: pointer.func */
    em[2520] = 8884097; em[2521] = 8; em[2522] = 0; /* 2520: pointer.func */
    em[2523] = 8884097; em[2524] = 8; em[2525] = 0; /* 2523: pointer.func */
    em[2526] = 8884097; em[2527] = 8; em[2528] = 0; /* 2526: pointer.func */
    em[2529] = 8884097; em[2530] = 8; em[2531] = 0; /* 2529: pointer.func */
    em[2532] = 8884097; em[2533] = 8; em[2534] = 0; /* 2532: pointer.func */
    em[2535] = 8884097; em[2536] = 8; em[2537] = 0; /* 2535: pointer.func */
    em[2538] = 8884097; em[2539] = 8; em[2540] = 0; /* 2538: pointer.func */
    em[2541] = 8884097; em[2542] = 8; em[2543] = 0; /* 2541: pointer.func */
    em[2544] = 8884097; em[2545] = 8; em[2546] = 0; /* 2544: pointer.func */
    em[2547] = 8884097; em[2548] = 8; em[2549] = 0; /* 2547: pointer.func */
    em[2550] = 8884097; em[2551] = 8; em[2552] = 0; /* 2550: pointer.func */
    em[2553] = 8884097; em[2554] = 8; em[2555] = 0; /* 2553: pointer.func */
    em[2556] = 1; em[2557] = 8; em[2558] = 1; /* 2556: pointer.struct.ec_point_st */
    	em[2559] = 2561; em[2560] = 0; 
    em[2561] = 0; em[2562] = 88; em[2563] = 4; /* 2561: struct.ec_point_st */
    	em[2564] = 2572; em[2565] = 0; 
    	em[2566] = 2744; em[2567] = 8; 
    	em[2568] = 2744; em[2569] = 32; 
    	em[2570] = 2744; em[2571] = 56; 
    em[2572] = 1; em[2573] = 8; em[2574] = 1; /* 2572: pointer.struct.ec_method_st */
    	em[2575] = 2577; em[2576] = 0; 
    em[2577] = 0; em[2578] = 304; em[2579] = 37; /* 2577: struct.ec_method_st */
    	em[2580] = 2654; em[2581] = 8; 
    	em[2582] = 2657; em[2583] = 16; 
    	em[2584] = 2657; em[2585] = 24; 
    	em[2586] = 2660; em[2587] = 32; 
    	em[2588] = 2663; em[2589] = 40; 
    	em[2590] = 2666; em[2591] = 48; 
    	em[2592] = 2669; em[2593] = 56; 
    	em[2594] = 2672; em[2595] = 64; 
    	em[2596] = 2675; em[2597] = 72; 
    	em[2598] = 2678; em[2599] = 80; 
    	em[2600] = 2678; em[2601] = 88; 
    	em[2602] = 2681; em[2603] = 96; 
    	em[2604] = 2684; em[2605] = 104; 
    	em[2606] = 2687; em[2607] = 112; 
    	em[2608] = 2690; em[2609] = 120; 
    	em[2610] = 2693; em[2611] = 128; 
    	em[2612] = 2696; em[2613] = 136; 
    	em[2614] = 2699; em[2615] = 144; 
    	em[2616] = 2702; em[2617] = 152; 
    	em[2618] = 2705; em[2619] = 160; 
    	em[2620] = 2708; em[2621] = 168; 
    	em[2622] = 2711; em[2623] = 176; 
    	em[2624] = 2714; em[2625] = 184; 
    	em[2626] = 2717; em[2627] = 192; 
    	em[2628] = 2720; em[2629] = 200; 
    	em[2630] = 2723; em[2631] = 208; 
    	em[2632] = 2714; em[2633] = 216; 
    	em[2634] = 2726; em[2635] = 224; 
    	em[2636] = 2729; em[2637] = 232; 
    	em[2638] = 2732; em[2639] = 240; 
    	em[2640] = 2669; em[2641] = 248; 
    	em[2642] = 2735; em[2643] = 256; 
    	em[2644] = 2738; em[2645] = 264; 
    	em[2646] = 2735; em[2647] = 272; 
    	em[2648] = 2738; em[2649] = 280; 
    	em[2650] = 2738; em[2651] = 288; 
    	em[2652] = 2741; em[2653] = 296; 
    em[2654] = 8884097; em[2655] = 8; em[2656] = 0; /* 2654: pointer.func */
    em[2657] = 8884097; em[2658] = 8; em[2659] = 0; /* 2657: pointer.func */
    em[2660] = 8884097; em[2661] = 8; em[2662] = 0; /* 2660: pointer.func */
    em[2663] = 8884097; em[2664] = 8; em[2665] = 0; /* 2663: pointer.func */
    em[2666] = 8884097; em[2667] = 8; em[2668] = 0; /* 2666: pointer.func */
    em[2669] = 8884097; em[2670] = 8; em[2671] = 0; /* 2669: pointer.func */
    em[2672] = 8884097; em[2673] = 8; em[2674] = 0; /* 2672: pointer.func */
    em[2675] = 8884097; em[2676] = 8; em[2677] = 0; /* 2675: pointer.func */
    em[2678] = 8884097; em[2679] = 8; em[2680] = 0; /* 2678: pointer.func */
    em[2681] = 8884097; em[2682] = 8; em[2683] = 0; /* 2681: pointer.func */
    em[2684] = 8884097; em[2685] = 8; em[2686] = 0; /* 2684: pointer.func */
    em[2687] = 8884097; em[2688] = 8; em[2689] = 0; /* 2687: pointer.func */
    em[2690] = 8884097; em[2691] = 8; em[2692] = 0; /* 2690: pointer.func */
    em[2693] = 8884097; em[2694] = 8; em[2695] = 0; /* 2693: pointer.func */
    em[2696] = 8884097; em[2697] = 8; em[2698] = 0; /* 2696: pointer.func */
    em[2699] = 8884097; em[2700] = 8; em[2701] = 0; /* 2699: pointer.func */
    em[2702] = 8884097; em[2703] = 8; em[2704] = 0; /* 2702: pointer.func */
    em[2705] = 8884097; em[2706] = 8; em[2707] = 0; /* 2705: pointer.func */
    em[2708] = 8884097; em[2709] = 8; em[2710] = 0; /* 2708: pointer.func */
    em[2711] = 8884097; em[2712] = 8; em[2713] = 0; /* 2711: pointer.func */
    em[2714] = 8884097; em[2715] = 8; em[2716] = 0; /* 2714: pointer.func */
    em[2717] = 8884097; em[2718] = 8; em[2719] = 0; /* 2717: pointer.func */
    em[2720] = 8884097; em[2721] = 8; em[2722] = 0; /* 2720: pointer.func */
    em[2723] = 8884097; em[2724] = 8; em[2725] = 0; /* 2723: pointer.func */
    em[2726] = 8884097; em[2727] = 8; em[2728] = 0; /* 2726: pointer.func */
    em[2729] = 8884097; em[2730] = 8; em[2731] = 0; /* 2729: pointer.func */
    em[2732] = 8884097; em[2733] = 8; em[2734] = 0; /* 2732: pointer.func */
    em[2735] = 8884097; em[2736] = 8; em[2737] = 0; /* 2735: pointer.func */
    em[2738] = 8884097; em[2739] = 8; em[2740] = 0; /* 2738: pointer.func */
    em[2741] = 8884097; em[2742] = 8; em[2743] = 0; /* 2741: pointer.func */
    em[2744] = 0; em[2745] = 24; em[2746] = 1; /* 2744: struct.bignum_st */
    	em[2747] = 2749; em[2748] = 0; 
    em[2749] = 8884099; em[2750] = 8; em[2751] = 2; /* 2749: pointer_to_array_of_pointers_to_stack */
    	em[2752] = 47; em[2753] = 0; 
    	em[2754] = 50; em[2755] = 12; 
    em[2756] = 0; em[2757] = 24; em[2758] = 1; /* 2756: struct.bignum_st */
    	em[2759] = 2761; em[2760] = 0; 
    em[2761] = 8884099; em[2762] = 8; em[2763] = 2; /* 2761: pointer_to_array_of_pointers_to_stack */
    	em[2764] = 47; em[2765] = 0; 
    	em[2766] = 50; em[2767] = 12; 
    em[2768] = 1; em[2769] = 8; em[2770] = 1; /* 2768: pointer.struct.ec_extra_data_st */
    	em[2771] = 2773; em[2772] = 0; 
    em[2773] = 0; em[2774] = 40; em[2775] = 5; /* 2773: struct.ec_extra_data_st */
    	em[2776] = 2786; em[2777] = 0; 
    	em[2778] = 81; em[2779] = 8; 
    	em[2780] = 2791; em[2781] = 16; 
    	em[2782] = 2794; em[2783] = 24; 
    	em[2784] = 2794; em[2785] = 32; 
    em[2786] = 1; em[2787] = 8; em[2788] = 1; /* 2786: pointer.struct.ec_extra_data_st */
    	em[2789] = 2773; em[2790] = 0; 
    em[2791] = 8884097; em[2792] = 8; em[2793] = 0; /* 2791: pointer.func */
    em[2794] = 8884097; em[2795] = 8; em[2796] = 0; /* 2794: pointer.func */
    em[2797] = 8884097; em[2798] = 8; em[2799] = 0; /* 2797: pointer.func */
    em[2800] = 1; em[2801] = 8; em[2802] = 1; /* 2800: pointer.struct.ec_point_st */
    	em[2803] = 2561; em[2804] = 0; 
    em[2805] = 1; em[2806] = 8; em[2807] = 1; /* 2805: pointer.struct.bignum_st */
    	em[2808] = 2810; em[2809] = 0; 
    em[2810] = 0; em[2811] = 24; em[2812] = 1; /* 2810: struct.bignum_st */
    	em[2813] = 2815; em[2814] = 0; 
    em[2815] = 8884099; em[2816] = 8; em[2817] = 2; /* 2815: pointer_to_array_of_pointers_to_stack */
    	em[2818] = 47; em[2819] = 0; 
    	em[2820] = 50; em[2821] = 12; 
    em[2822] = 1; em[2823] = 8; em[2824] = 1; /* 2822: pointer.struct.ec_extra_data_st */
    	em[2825] = 2827; em[2826] = 0; 
    em[2827] = 0; em[2828] = 40; em[2829] = 5; /* 2827: struct.ec_extra_data_st */
    	em[2830] = 2840; em[2831] = 0; 
    	em[2832] = 81; em[2833] = 8; 
    	em[2834] = 2791; em[2835] = 16; 
    	em[2836] = 2794; em[2837] = 24; 
    	em[2838] = 2794; em[2839] = 32; 
    em[2840] = 1; em[2841] = 8; em[2842] = 1; /* 2840: pointer.struct.ec_extra_data_st */
    	em[2843] = 2827; em[2844] = 0; 
    em[2845] = 1; em[2846] = 8; em[2847] = 1; /* 2845: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[2848] = 2850; em[2849] = 0; 
    em[2850] = 0; em[2851] = 32; em[2852] = 2; /* 2850: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[2853] = 2857; em[2854] = 8; 
    	em[2855] = 84; em[2856] = 24; 
    em[2857] = 8884099; em[2858] = 8; em[2859] = 2; /* 2857: pointer_to_array_of_pointers_to_stack */
    	em[2860] = 2864; em[2861] = 0; 
    	em[2862] = 50; em[2863] = 20; 
    em[2864] = 0; em[2865] = 8; em[2866] = 1; /* 2864: pointer.X509_ATTRIBUTE */
    	em[2867] = 2869; em[2868] = 0; 
    em[2869] = 0; em[2870] = 0; em[2871] = 1; /* 2869: X509_ATTRIBUTE */
    	em[2872] = 2874; em[2873] = 0; 
    em[2874] = 0; em[2875] = 24; em[2876] = 2; /* 2874: struct.x509_attributes_st */
    	em[2877] = 2881; em[2878] = 0; 
    	em[2879] = 2895; em[2880] = 16; 
    em[2881] = 1; em[2882] = 8; em[2883] = 1; /* 2881: pointer.struct.asn1_object_st */
    	em[2884] = 2886; em[2885] = 0; 
    em[2886] = 0; em[2887] = 40; em[2888] = 3; /* 2886: struct.asn1_object_st */
    	em[2889] = 117; em[2890] = 0; 
    	em[2891] = 117; em[2892] = 8; 
    	em[2893] = 514; em[2894] = 24; 
    em[2895] = 0; em[2896] = 8; em[2897] = 3; /* 2895: union.unknown */
    	em[2898] = 140; em[2899] = 0; 
    	em[2900] = 2904; em[2901] = 0; 
    	em[2902] = 3083; em[2903] = 0; 
    em[2904] = 1; em[2905] = 8; em[2906] = 1; /* 2904: pointer.struct.stack_st_ASN1_TYPE */
    	em[2907] = 2909; em[2908] = 0; 
    em[2909] = 0; em[2910] = 32; em[2911] = 2; /* 2909: struct.stack_st_fake_ASN1_TYPE */
    	em[2912] = 2916; em[2913] = 8; 
    	em[2914] = 84; em[2915] = 24; 
    em[2916] = 8884099; em[2917] = 8; em[2918] = 2; /* 2916: pointer_to_array_of_pointers_to_stack */
    	em[2919] = 2923; em[2920] = 0; 
    	em[2921] = 50; em[2922] = 20; 
    em[2923] = 0; em[2924] = 8; em[2925] = 1; /* 2923: pointer.ASN1_TYPE */
    	em[2926] = 2928; em[2927] = 0; 
    em[2928] = 0; em[2929] = 0; em[2930] = 1; /* 2928: ASN1_TYPE */
    	em[2931] = 2933; em[2932] = 0; 
    em[2933] = 0; em[2934] = 16; em[2935] = 1; /* 2933: struct.asn1_type_st */
    	em[2936] = 2938; em[2937] = 8; 
    em[2938] = 0; em[2939] = 8; em[2940] = 20; /* 2938: union.unknown */
    	em[2941] = 140; em[2942] = 0; 
    	em[2943] = 2981; em[2944] = 0; 
    	em[2945] = 2991; em[2946] = 0; 
    	em[2947] = 3005; em[2948] = 0; 
    	em[2949] = 3010; em[2950] = 0; 
    	em[2951] = 3015; em[2952] = 0; 
    	em[2953] = 3020; em[2954] = 0; 
    	em[2955] = 3025; em[2956] = 0; 
    	em[2957] = 3030; em[2958] = 0; 
    	em[2959] = 3035; em[2960] = 0; 
    	em[2961] = 3040; em[2962] = 0; 
    	em[2963] = 3045; em[2964] = 0; 
    	em[2965] = 3050; em[2966] = 0; 
    	em[2967] = 3055; em[2968] = 0; 
    	em[2969] = 3060; em[2970] = 0; 
    	em[2971] = 3065; em[2972] = 0; 
    	em[2973] = 3070; em[2974] = 0; 
    	em[2975] = 2981; em[2976] = 0; 
    	em[2977] = 2981; em[2978] = 0; 
    	em[2979] = 3075; em[2980] = 0; 
    em[2981] = 1; em[2982] = 8; em[2983] = 1; /* 2981: pointer.struct.asn1_string_st */
    	em[2984] = 2986; em[2985] = 0; 
    em[2986] = 0; em[2987] = 24; em[2988] = 1; /* 2986: struct.asn1_string_st */
    	em[2989] = 585; em[2990] = 8; 
    em[2991] = 1; em[2992] = 8; em[2993] = 1; /* 2991: pointer.struct.asn1_object_st */
    	em[2994] = 2996; em[2995] = 0; 
    em[2996] = 0; em[2997] = 40; em[2998] = 3; /* 2996: struct.asn1_object_st */
    	em[2999] = 117; em[3000] = 0; 
    	em[3001] = 117; em[3002] = 8; 
    	em[3003] = 514; em[3004] = 24; 
    em[3005] = 1; em[3006] = 8; em[3007] = 1; /* 3005: pointer.struct.asn1_string_st */
    	em[3008] = 2986; em[3009] = 0; 
    em[3010] = 1; em[3011] = 8; em[3012] = 1; /* 3010: pointer.struct.asn1_string_st */
    	em[3013] = 2986; em[3014] = 0; 
    em[3015] = 1; em[3016] = 8; em[3017] = 1; /* 3015: pointer.struct.asn1_string_st */
    	em[3018] = 2986; em[3019] = 0; 
    em[3020] = 1; em[3021] = 8; em[3022] = 1; /* 3020: pointer.struct.asn1_string_st */
    	em[3023] = 2986; em[3024] = 0; 
    em[3025] = 1; em[3026] = 8; em[3027] = 1; /* 3025: pointer.struct.asn1_string_st */
    	em[3028] = 2986; em[3029] = 0; 
    em[3030] = 1; em[3031] = 8; em[3032] = 1; /* 3030: pointer.struct.asn1_string_st */
    	em[3033] = 2986; em[3034] = 0; 
    em[3035] = 1; em[3036] = 8; em[3037] = 1; /* 3035: pointer.struct.asn1_string_st */
    	em[3038] = 2986; em[3039] = 0; 
    em[3040] = 1; em[3041] = 8; em[3042] = 1; /* 3040: pointer.struct.asn1_string_st */
    	em[3043] = 2986; em[3044] = 0; 
    em[3045] = 1; em[3046] = 8; em[3047] = 1; /* 3045: pointer.struct.asn1_string_st */
    	em[3048] = 2986; em[3049] = 0; 
    em[3050] = 1; em[3051] = 8; em[3052] = 1; /* 3050: pointer.struct.asn1_string_st */
    	em[3053] = 2986; em[3054] = 0; 
    em[3055] = 1; em[3056] = 8; em[3057] = 1; /* 3055: pointer.struct.asn1_string_st */
    	em[3058] = 2986; em[3059] = 0; 
    em[3060] = 1; em[3061] = 8; em[3062] = 1; /* 3060: pointer.struct.asn1_string_st */
    	em[3063] = 2986; em[3064] = 0; 
    em[3065] = 1; em[3066] = 8; em[3067] = 1; /* 3065: pointer.struct.asn1_string_st */
    	em[3068] = 2986; em[3069] = 0; 
    em[3070] = 1; em[3071] = 8; em[3072] = 1; /* 3070: pointer.struct.asn1_string_st */
    	em[3073] = 2986; em[3074] = 0; 
    em[3075] = 1; em[3076] = 8; em[3077] = 1; /* 3075: pointer.struct.ASN1_VALUE_st */
    	em[3078] = 3080; em[3079] = 0; 
    em[3080] = 0; em[3081] = 0; em[3082] = 0; /* 3080: struct.ASN1_VALUE_st */
    em[3083] = 1; em[3084] = 8; em[3085] = 1; /* 3083: pointer.struct.asn1_type_st */
    	em[3086] = 3088; em[3087] = 0; 
    em[3088] = 0; em[3089] = 16; em[3090] = 1; /* 3088: struct.asn1_type_st */
    	em[3091] = 3093; em[3092] = 8; 
    em[3093] = 0; em[3094] = 8; em[3095] = 20; /* 3093: union.unknown */
    	em[3096] = 140; em[3097] = 0; 
    	em[3098] = 3136; em[3099] = 0; 
    	em[3100] = 2881; em[3101] = 0; 
    	em[3102] = 3146; em[3103] = 0; 
    	em[3104] = 3151; em[3105] = 0; 
    	em[3106] = 3156; em[3107] = 0; 
    	em[3108] = 3161; em[3109] = 0; 
    	em[3110] = 3166; em[3111] = 0; 
    	em[3112] = 3171; em[3113] = 0; 
    	em[3114] = 3176; em[3115] = 0; 
    	em[3116] = 3181; em[3117] = 0; 
    	em[3118] = 3186; em[3119] = 0; 
    	em[3120] = 3191; em[3121] = 0; 
    	em[3122] = 3196; em[3123] = 0; 
    	em[3124] = 3201; em[3125] = 0; 
    	em[3126] = 3206; em[3127] = 0; 
    	em[3128] = 3211; em[3129] = 0; 
    	em[3130] = 3136; em[3131] = 0; 
    	em[3132] = 3136; em[3133] = 0; 
    	em[3134] = 660; em[3135] = 0; 
    em[3136] = 1; em[3137] = 8; em[3138] = 1; /* 3136: pointer.struct.asn1_string_st */
    	em[3139] = 3141; em[3140] = 0; 
    em[3141] = 0; em[3142] = 24; em[3143] = 1; /* 3141: struct.asn1_string_st */
    	em[3144] = 585; em[3145] = 8; 
    em[3146] = 1; em[3147] = 8; em[3148] = 1; /* 3146: pointer.struct.asn1_string_st */
    	em[3149] = 3141; em[3150] = 0; 
    em[3151] = 1; em[3152] = 8; em[3153] = 1; /* 3151: pointer.struct.asn1_string_st */
    	em[3154] = 3141; em[3155] = 0; 
    em[3156] = 1; em[3157] = 8; em[3158] = 1; /* 3156: pointer.struct.asn1_string_st */
    	em[3159] = 3141; em[3160] = 0; 
    em[3161] = 1; em[3162] = 8; em[3163] = 1; /* 3161: pointer.struct.asn1_string_st */
    	em[3164] = 3141; em[3165] = 0; 
    em[3166] = 1; em[3167] = 8; em[3168] = 1; /* 3166: pointer.struct.asn1_string_st */
    	em[3169] = 3141; em[3170] = 0; 
    em[3171] = 1; em[3172] = 8; em[3173] = 1; /* 3171: pointer.struct.asn1_string_st */
    	em[3174] = 3141; em[3175] = 0; 
    em[3176] = 1; em[3177] = 8; em[3178] = 1; /* 3176: pointer.struct.asn1_string_st */
    	em[3179] = 3141; em[3180] = 0; 
    em[3181] = 1; em[3182] = 8; em[3183] = 1; /* 3181: pointer.struct.asn1_string_st */
    	em[3184] = 3141; em[3185] = 0; 
    em[3186] = 1; em[3187] = 8; em[3188] = 1; /* 3186: pointer.struct.asn1_string_st */
    	em[3189] = 3141; em[3190] = 0; 
    em[3191] = 1; em[3192] = 8; em[3193] = 1; /* 3191: pointer.struct.asn1_string_st */
    	em[3194] = 3141; em[3195] = 0; 
    em[3196] = 1; em[3197] = 8; em[3198] = 1; /* 3196: pointer.struct.asn1_string_st */
    	em[3199] = 3141; em[3200] = 0; 
    em[3201] = 1; em[3202] = 8; em[3203] = 1; /* 3201: pointer.struct.asn1_string_st */
    	em[3204] = 3141; em[3205] = 0; 
    em[3206] = 1; em[3207] = 8; em[3208] = 1; /* 3206: pointer.struct.asn1_string_st */
    	em[3209] = 3141; em[3210] = 0; 
    em[3211] = 1; em[3212] = 8; em[3213] = 1; /* 3211: pointer.struct.asn1_string_st */
    	em[3214] = 3141; em[3215] = 0; 
    em[3216] = 0; em[3217] = 32; em[3218] = 3; /* 3216: struct.X509_POLICY_DATA_st */
    	em[3219] = 1568; em[3220] = 8; 
    	em[3221] = 1854; em[3222] = 16; 
    	em[3223] = 1830; em[3224] = 24; 
    em[3225] = 1; em[3226] = 8; em[3227] = 1; /* 3225: pointer.struct.X509_POLICY_DATA_st */
    	em[3228] = 3216; em[3229] = 0; 
    em[3230] = 1; em[3231] = 8; em[3232] = 1; /* 3230: pointer.struct.AUTHORITY_KEYID_st */
    	em[3233] = 3235; em[3234] = 0; 
    em[3235] = 0; em[3236] = 24; em[3237] = 3; /* 3235: struct.AUTHORITY_KEYID_st */
    	em[3238] = 3244; em[3239] = 0; 
    	em[3240] = 3254; em[3241] = 8; 
    	em[3242] = 3278; em[3243] = 16; 
    em[3244] = 1; em[3245] = 8; em[3246] = 1; /* 3244: pointer.struct.asn1_string_st */
    	em[3247] = 3249; em[3248] = 0; 
    em[3249] = 0; em[3250] = 24; em[3251] = 1; /* 3249: struct.asn1_string_st */
    	em[3252] = 585; em[3253] = 8; 
    em[3254] = 1; em[3255] = 8; em[3256] = 1; /* 3254: pointer.struct.stack_st_GENERAL_NAME */
    	em[3257] = 3259; em[3258] = 0; 
    em[3259] = 0; em[3260] = 32; em[3261] = 2; /* 3259: struct.stack_st_fake_GENERAL_NAME */
    	em[3262] = 3266; em[3263] = 8; 
    	em[3264] = 84; em[3265] = 24; 
    em[3266] = 8884099; em[3267] = 8; em[3268] = 2; /* 3266: pointer_to_array_of_pointers_to_stack */
    	em[3269] = 3273; em[3270] = 0; 
    	em[3271] = 50; em[3272] = 20; 
    em[3273] = 0; em[3274] = 8; em[3275] = 1; /* 3273: pointer.GENERAL_NAME */
    	em[3276] = 1138; em[3277] = 0; 
    em[3278] = 1; em[3279] = 8; em[3280] = 1; /* 3278: pointer.struct.asn1_string_st */
    	em[3281] = 3249; em[3282] = 0; 
    em[3283] = 1; em[3284] = 8; em[3285] = 1; /* 3283: pointer.struct.asn1_string_st */
    	em[3286] = 3288; em[3287] = 0; 
    em[3288] = 0; em[3289] = 24; em[3290] = 1; /* 3288: struct.asn1_string_st */
    	em[3291] = 585; em[3292] = 8; 
    em[3293] = 1; em[3294] = 8; em[3295] = 1; /* 3293: pointer.struct.asn1_object_st */
    	em[3296] = 3298; em[3297] = 0; 
    em[3298] = 0; em[3299] = 40; em[3300] = 3; /* 3298: struct.asn1_object_st */
    	em[3301] = 117; em[3302] = 0; 
    	em[3303] = 117; em[3304] = 8; 
    	em[3305] = 514; em[3306] = 24; 
    em[3307] = 0; em[3308] = 24; em[3309] = 2; /* 3307: struct.X509_extension_st */
    	em[3310] = 3293; em[3311] = 0; 
    	em[3312] = 3283; em[3313] = 16; 
    em[3314] = 0; em[3315] = 0; em[3316] = 1; /* 3314: X509_EXTENSION */
    	em[3317] = 3307; em[3318] = 0; 
    em[3319] = 1; em[3320] = 8; em[3321] = 1; /* 3319: pointer.struct.stack_st_X509_EXTENSION */
    	em[3322] = 3324; em[3323] = 0; 
    em[3324] = 0; em[3325] = 32; em[3326] = 2; /* 3324: struct.stack_st_fake_X509_EXTENSION */
    	em[3327] = 3331; em[3328] = 8; 
    	em[3329] = 84; em[3330] = 24; 
    em[3331] = 8884099; em[3332] = 8; em[3333] = 2; /* 3331: pointer_to_array_of_pointers_to_stack */
    	em[3334] = 3338; em[3335] = 0; 
    	em[3336] = 50; em[3337] = 20; 
    em[3338] = 0; em[3339] = 8; em[3340] = 1; /* 3338: pointer.X509_EXTENSION */
    	em[3341] = 3314; em[3342] = 0; 
    em[3343] = 1; em[3344] = 8; em[3345] = 1; /* 3343: pointer.struct.asn1_string_st */
    	em[3346] = 697; em[3347] = 0; 
    em[3348] = 0; em[3349] = 24; em[3350] = 1; /* 3348: struct.ASN1_ENCODING_st */
    	em[3351] = 585; em[3352] = 0; 
    em[3353] = 1; em[3354] = 8; em[3355] = 1; /* 3353: pointer.struct.asn1_string_st */
    	em[3356] = 1408; em[3357] = 0; 
    em[3358] = 1; em[3359] = 8; em[3360] = 1; /* 3358: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[3361] = 3363; em[3362] = 0; 
    em[3363] = 0; em[3364] = 32; em[3365] = 2; /* 3363: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[3366] = 3370; em[3367] = 8; 
    	em[3368] = 84; em[3369] = 24; 
    em[3370] = 8884099; em[3371] = 8; em[3372] = 2; /* 3370: pointer_to_array_of_pointers_to_stack */
    	em[3373] = 3377; em[3374] = 0; 
    	em[3375] = 50; em[3376] = 20; 
    em[3377] = 0; em[3378] = 8; em[3379] = 1; /* 3377: pointer.X509_ATTRIBUTE */
    	em[3380] = 2869; em[3381] = 0; 
    em[3382] = 0; em[3383] = 32; em[3384] = 3; /* 3382: struct.DIST_POINT_st */
    	em[3385] = 1456; em[3386] = 0; 
    	em[3387] = 3353; em[3388] = 8; 
    	em[3389] = 1475; em[3390] = 16; 
    em[3391] = 1; em[3392] = 8; em[3393] = 1; /* 3391: pointer.struct.X509_algor_st */
    	em[3394] = 493; em[3395] = 0; 
    em[3396] = 1; em[3397] = 8; em[3398] = 1; /* 3396: pointer.struct.X509_val_st */
    	em[3399] = 3401; em[3400] = 0; 
    em[3401] = 0; em[3402] = 16; em[3403] = 2; /* 3401: struct.X509_val_st */
    	em[3404] = 3408; em[3405] = 0; 
    	em[3406] = 3408; em[3407] = 8; 
    em[3408] = 1; em[3409] = 8; em[3410] = 1; /* 3408: pointer.struct.asn1_string_st */
    	em[3411] = 697; em[3412] = 0; 
    em[3413] = 1; em[3414] = 8; em[3415] = 1; /* 3413: pointer.struct.evp_pkey_st */
    	em[3416] = 1878; em[3417] = 0; 
    em[3418] = 1; em[3419] = 8; em[3420] = 1; /* 3418: pointer.struct.x509_st */
    	em[3421] = 3423; em[3422] = 0; 
    em[3423] = 0; em[3424] = 184; em[3425] = 12; /* 3423: struct.x509_st */
    	em[3426] = 3450; em[3427] = 0; 
    	em[3428] = 3485; em[3429] = 8; 
    	em[3430] = 3343; em[3431] = 16; 
    	em[3432] = 140; em[3433] = 32; 
    	em[3434] = 3598; em[3435] = 40; 
    	em[3436] = 753; em[3437] = 104; 
    	em[3438] = 3230; em[3439] = 112; 
    	em[3440] = 3612; em[3441] = 120; 
    	em[3442] = 3624; em[3443] = 128; 
    	em[3444] = 1114; em[3445] = 136; 
    	em[3446] = 1109; em[3447] = 144; 
    	em[3448] = 3653; em[3449] = 176; 
    em[3450] = 1; em[3451] = 8; em[3452] = 1; /* 3450: pointer.struct.x509_cinf_st */
    	em[3453] = 3455; em[3454] = 0; 
    em[3455] = 0; em[3456] = 104; em[3457] = 11; /* 3455: struct.x509_cinf_st */
    	em[3458] = 3480; em[3459] = 0; 
    	em[3460] = 3480; em[3461] = 8; 
    	em[3462] = 3485; em[3463] = 16; 
    	em[3464] = 3490; em[3465] = 24; 
    	em[3466] = 3396; em[3467] = 32; 
    	em[3468] = 3490; em[3469] = 40; 
    	em[3470] = 3538; em[3471] = 48; 
    	em[3472] = 3343; em[3473] = 56; 
    	em[3474] = 3343; em[3475] = 64; 
    	em[3476] = 3319; em[3477] = 72; 
    	em[3478] = 3348; em[3479] = 80; 
    em[3480] = 1; em[3481] = 8; em[3482] = 1; /* 3480: pointer.struct.asn1_string_st */
    	em[3483] = 697; em[3484] = 0; 
    em[3485] = 1; em[3486] = 8; em[3487] = 1; /* 3485: pointer.struct.X509_algor_st */
    	em[3488] = 493; em[3489] = 0; 
    em[3490] = 1; em[3491] = 8; em[3492] = 1; /* 3490: pointer.struct.X509_name_st */
    	em[3493] = 3495; em[3494] = 0; 
    em[3495] = 0; em[3496] = 40; em[3497] = 3; /* 3495: struct.X509_name_st */
    	em[3498] = 3504; em[3499] = 0; 
    	em[3500] = 3528; em[3501] = 16; 
    	em[3502] = 585; em[3503] = 24; 
    em[3504] = 1; em[3505] = 8; em[3506] = 1; /* 3504: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[3507] = 3509; em[3508] = 0; 
    em[3509] = 0; em[3510] = 32; em[3511] = 2; /* 3509: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[3512] = 3516; em[3513] = 8; 
    	em[3514] = 84; em[3515] = 24; 
    em[3516] = 8884099; em[3517] = 8; em[3518] = 2; /* 3516: pointer_to_array_of_pointers_to_stack */
    	em[3519] = 3523; em[3520] = 0; 
    	em[3521] = 50; em[3522] = 20; 
    em[3523] = 0; em[3524] = 8; em[3525] = 1; /* 3523: pointer.X509_NAME_ENTRY */
    	em[3526] = 799; em[3527] = 0; 
    em[3528] = 1; em[3529] = 8; em[3530] = 1; /* 3528: pointer.struct.buf_mem_st */
    	em[3531] = 3533; em[3532] = 0; 
    em[3533] = 0; em[3534] = 24; em[3535] = 1; /* 3533: struct.buf_mem_st */
    	em[3536] = 140; em[3537] = 8; 
    em[3538] = 1; em[3539] = 8; em[3540] = 1; /* 3538: pointer.struct.X509_pubkey_st */
    	em[3541] = 3543; em[3542] = 0; 
    em[3543] = 0; em[3544] = 24; em[3545] = 3; /* 3543: struct.X509_pubkey_st */
    	em[3546] = 3391; em[3547] = 0; 
    	em[3548] = 600; em[3549] = 8; 
    	em[3550] = 3552; em[3551] = 16; 
    em[3552] = 1; em[3553] = 8; em[3554] = 1; /* 3552: pointer.struct.evp_pkey_st */
    	em[3555] = 3557; em[3556] = 0; 
    em[3557] = 0; em[3558] = 56; em[3559] = 4; /* 3557: struct.evp_pkey_st */
    	em[3560] = 1889; em[3561] = 16; 
    	em[3562] = 1990; em[3563] = 24; 
    	em[3564] = 3568; em[3565] = 32; 
    	em[3566] = 3358; em[3567] = 48; 
    em[3568] = 0; em[3569] = 8; em[3570] = 6; /* 3568: union.union_of_evp_pkey_st */
    	em[3571] = 81; em[3572] = 0; 
    	em[3573] = 3583; em[3574] = 6; 
    	em[3575] = 3588; em[3576] = 116; 
    	em[3577] = 3593; em[3578] = 28; 
    	em[3579] = 2336; em[3580] = 408; 
    	em[3581] = 50; em[3582] = 0; 
    em[3583] = 1; em[3584] = 8; em[3585] = 1; /* 3583: pointer.struct.rsa_st */
    	em[3586] = 2015; em[3587] = 0; 
    em[3588] = 1; em[3589] = 8; em[3590] = 1; /* 3588: pointer.struct.dsa_st */
    	em[3591] = 5; em[3592] = 0; 
    em[3593] = 1; em[3594] = 8; em[3595] = 1; /* 3593: pointer.struct.dh_st */
    	em[3596] = 2223; em[3597] = 0; 
    em[3598] = 0; em[3599] = 32; em[3600] = 2; /* 3598: struct.crypto_ex_data_st_fake */
    	em[3601] = 3605; em[3602] = 8; 
    	em[3603] = 84; em[3604] = 24; 
    em[3605] = 8884099; em[3606] = 8; em[3607] = 2; /* 3605: pointer_to_array_of_pointers_to_stack */
    	em[3608] = 81; em[3609] = 0; 
    	em[3610] = 50; em[3611] = 20; 
    em[3612] = 1; em[3613] = 8; em[3614] = 1; /* 3612: pointer.struct.X509_POLICY_CACHE_st */
    	em[3615] = 3617; em[3616] = 0; 
    em[3617] = 0; em[3618] = 40; em[3619] = 2; /* 3617: struct.X509_POLICY_CACHE_st */
    	em[3620] = 3225; em[3621] = 0; 
    	em[3622] = 1806; em[3623] = 8; 
    em[3624] = 1; em[3625] = 8; em[3626] = 1; /* 3624: pointer.struct.stack_st_DIST_POINT */
    	em[3627] = 3629; em[3628] = 0; 
    em[3629] = 0; em[3630] = 32; em[3631] = 2; /* 3629: struct.stack_st_fake_DIST_POINT */
    	em[3632] = 3636; em[3633] = 8; 
    	em[3634] = 84; em[3635] = 24; 
    em[3636] = 8884099; em[3637] = 8; em[3638] = 2; /* 3636: pointer_to_array_of_pointers_to_stack */
    	em[3639] = 3643; em[3640] = 0; 
    	em[3641] = 50; em[3642] = 20; 
    em[3643] = 0; em[3644] = 8; em[3645] = 1; /* 3643: pointer.DIST_POINT */
    	em[3646] = 3648; em[3647] = 0; 
    em[3648] = 0; em[3649] = 0; em[3650] = 1; /* 3648: DIST_POINT */
    	em[3651] = 3382; em[3652] = 0; 
    em[3653] = 1; em[3654] = 8; em[3655] = 1; /* 3653: pointer.struct.x509_cert_aux_st */
    	em[3656] = 740; em[3657] = 0; 
    em[3658] = 0; em[3659] = 1; em[3660] = 0; /* 3658: char */
    args_addr->arg_entity_index[0] = 3418;
    args_addr->arg_entity_index[1] = 3413;
    args_addr->ret_entity_index = 50;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    EVP_PKEY * new_arg_b = *((EVP_PKEY * *)new_args->args[1]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_X509_check_private_key)(X509 *,EVP_PKEY *);
    orig_X509_check_private_key = dlsym(RTLD_NEXT, "X509_check_private_key");
    *new_ret_ptr = (*orig_X509_check_private_key)(new_arg_a,new_arg_b);

    syscall(889);

    free(args_addr);

    return ret;
}

