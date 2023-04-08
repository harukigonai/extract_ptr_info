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
    em[0] = 1; em[1] = 8; em[2] = 1; /* 0: pointer.struct.ec_key_st */
    	em[3] = 5; em[4] = 0; 
    em[5] = 0; em[6] = 56; em[7] = 4; /* 5: struct.ec_key_st */
    	em[8] = 16; em[9] = 8; 
    	em[10] = 297; em[11] = 16; 
    	em[12] = 302; em[13] = 24; 
    	em[14] = 319; em[15] = 48; 
    em[16] = 1; em[17] = 8; em[18] = 1; /* 16: pointer.struct.ec_group_st */
    	em[19] = 21; em[20] = 0; 
    em[21] = 0; em[22] = 232; em[23] = 12; /* 21: struct.ec_group_st */
    	em[24] = 48; em[25] = 0; 
    	em[26] = 220; em[27] = 8; 
    	em[28] = 236; em[29] = 16; 
    	em[30] = 236; em[31] = 40; 
    	em[32] = 254; em[33] = 80; 
    	em[34] = 262; em[35] = 96; 
    	em[36] = 236; em[37] = 104; 
    	em[38] = 236; em[39] = 152; 
    	em[40] = 236; em[41] = 176; 
    	em[42] = 285; em[43] = 208; 
    	em[44] = 285; em[45] = 216; 
    	em[46] = 294; em[47] = 224; 
    em[48] = 1; em[49] = 8; em[50] = 1; /* 48: pointer.struct.ec_method_st */
    	em[51] = 53; em[52] = 0; 
    em[53] = 0; em[54] = 304; em[55] = 37; /* 53: struct.ec_method_st */
    	em[56] = 130; em[57] = 8; 
    	em[58] = 133; em[59] = 16; 
    	em[60] = 133; em[61] = 24; 
    	em[62] = 136; em[63] = 32; 
    	em[64] = 139; em[65] = 40; 
    	em[66] = 142; em[67] = 48; 
    	em[68] = 145; em[69] = 56; 
    	em[70] = 148; em[71] = 64; 
    	em[72] = 151; em[73] = 72; 
    	em[74] = 154; em[75] = 80; 
    	em[76] = 154; em[77] = 88; 
    	em[78] = 157; em[79] = 96; 
    	em[80] = 160; em[81] = 104; 
    	em[82] = 163; em[83] = 112; 
    	em[84] = 166; em[85] = 120; 
    	em[86] = 169; em[87] = 128; 
    	em[88] = 172; em[89] = 136; 
    	em[90] = 175; em[91] = 144; 
    	em[92] = 178; em[93] = 152; 
    	em[94] = 181; em[95] = 160; 
    	em[96] = 184; em[97] = 168; 
    	em[98] = 187; em[99] = 176; 
    	em[100] = 190; em[101] = 184; 
    	em[102] = 193; em[103] = 192; 
    	em[104] = 196; em[105] = 200; 
    	em[106] = 199; em[107] = 208; 
    	em[108] = 190; em[109] = 216; 
    	em[110] = 202; em[111] = 224; 
    	em[112] = 205; em[113] = 232; 
    	em[114] = 208; em[115] = 240; 
    	em[116] = 145; em[117] = 248; 
    	em[118] = 211; em[119] = 256; 
    	em[120] = 214; em[121] = 264; 
    	em[122] = 211; em[123] = 272; 
    	em[124] = 214; em[125] = 280; 
    	em[126] = 214; em[127] = 288; 
    	em[128] = 217; em[129] = 296; 
    em[130] = 8884097; em[131] = 8; em[132] = 0; /* 130: pointer.func */
    em[133] = 8884097; em[134] = 8; em[135] = 0; /* 133: pointer.func */
    em[136] = 8884097; em[137] = 8; em[138] = 0; /* 136: pointer.func */
    em[139] = 8884097; em[140] = 8; em[141] = 0; /* 139: pointer.func */
    em[142] = 8884097; em[143] = 8; em[144] = 0; /* 142: pointer.func */
    em[145] = 8884097; em[146] = 8; em[147] = 0; /* 145: pointer.func */
    em[148] = 8884097; em[149] = 8; em[150] = 0; /* 148: pointer.func */
    em[151] = 8884097; em[152] = 8; em[153] = 0; /* 151: pointer.func */
    em[154] = 8884097; em[155] = 8; em[156] = 0; /* 154: pointer.func */
    em[157] = 8884097; em[158] = 8; em[159] = 0; /* 157: pointer.func */
    em[160] = 8884097; em[161] = 8; em[162] = 0; /* 160: pointer.func */
    em[163] = 8884097; em[164] = 8; em[165] = 0; /* 163: pointer.func */
    em[166] = 8884097; em[167] = 8; em[168] = 0; /* 166: pointer.func */
    em[169] = 8884097; em[170] = 8; em[171] = 0; /* 169: pointer.func */
    em[172] = 8884097; em[173] = 8; em[174] = 0; /* 172: pointer.func */
    em[175] = 8884097; em[176] = 8; em[177] = 0; /* 175: pointer.func */
    em[178] = 8884097; em[179] = 8; em[180] = 0; /* 178: pointer.func */
    em[181] = 8884097; em[182] = 8; em[183] = 0; /* 181: pointer.func */
    em[184] = 8884097; em[185] = 8; em[186] = 0; /* 184: pointer.func */
    em[187] = 8884097; em[188] = 8; em[189] = 0; /* 187: pointer.func */
    em[190] = 8884097; em[191] = 8; em[192] = 0; /* 190: pointer.func */
    em[193] = 8884097; em[194] = 8; em[195] = 0; /* 193: pointer.func */
    em[196] = 8884097; em[197] = 8; em[198] = 0; /* 196: pointer.func */
    em[199] = 8884097; em[200] = 8; em[201] = 0; /* 199: pointer.func */
    em[202] = 8884097; em[203] = 8; em[204] = 0; /* 202: pointer.func */
    em[205] = 8884097; em[206] = 8; em[207] = 0; /* 205: pointer.func */
    em[208] = 8884097; em[209] = 8; em[210] = 0; /* 208: pointer.func */
    em[211] = 8884097; em[212] = 8; em[213] = 0; /* 211: pointer.func */
    em[214] = 8884097; em[215] = 8; em[216] = 0; /* 214: pointer.func */
    em[217] = 8884097; em[218] = 8; em[219] = 0; /* 217: pointer.func */
    em[220] = 1; em[221] = 8; em[222] = 1; /* 220: pointer.struct.ec_point_st */
    	em[223] = 225; em[224] = 0; 
    em[225] = 0; em[226] = 88; em[227] = 4; /* 225: struct.ec_point_st */
    	em[228] = 48; em[229] = 0; 
    	em[230] = 236; em[231] = 8; 
    	em[232] = 236; em[233] = 32; 
    	em[234] = 236; em[235] = 56; 
    em[236] = 0; em[237] = 24; em[238] = 1; /* 236: struct.bignum_st */
    	em[239] = 241; em[240] = 0; 
    em[241] = 8884099; em[242] = 8; em[243] = 2; /* 241: pointer_to_array_of_pointers_to_stack */
    	em[244] = 248; em[245] = 0; 
    	em[246] = 251; em[247] = 12; 
    em[248] = 0; em[249] = 8; em[250] = 0; /* 248: long unsigned int */
    em[251] = 0; em[252] = 4; em[253] = 0; /* 251: int */
    em[254] = 1; em[255] = 8; em[256] = 1; /* 254: pointer.unsigned char */
    	em[257] = 259; em[258] = 0; 
    em[259] = 0; em[260] = 1; em[261] = 0; /* 259: unsigned char */
    em[262] = 1; em[263] = 8; em[264] = 1; /* 262: pointer.struct.ec_extra_data_st */
    	em[265] = 267; em[266] = 0; 
    em[267] = 0; em[268] = 40; em[269] = 5; /* 267: struct.ec_extra_data_st */
    	em[270] = 280; em[271] = 0; 
    	em[272] = 285; em[273] = 8; 
    	em[274] = 288; em[275] = 16; 
    	em[276] = 291; em[277] = 24; 
    	em[278] = 291; em[279] = 32; 
    em[280] = 1; em[281] = 8; em[282] = 1; /* 280: pointer.struct.ec_extra_data_st */
    	em[283] = 267; em[284] = 0; 
    em[285] = 0; em[286] = 8; em[287] = 0; /* 285: pointer.void */
    em[288] = 8884097; em[289] = 8; em[290] = 0; /* 288: pointer.func */
    em[291] = 8884097; em[292] = 8; em[293] = 0; /* 291: pointer.func */
    em[294] = 8884097; em[295] = 8; em[296] = 0; /* 294: pointer.func */
    em[297] = 1; em[298] = 8; em[299] = 1; /* 297: pointer.struct.ec_point_st */
    	em[300] = 225; em[301] = 0; 
    em[302] = 1; em[303] = 8; em[304] = 1; /* 302: pointer.struct.bignum_st */
    	em[305] = 307; em[306] = 0; 
    em[307] = 0; em[308] = 24; em[309] = 1; /* 307: struct.bignum_st */
    	em[310] = 312; em[311] = 0; 
    em[312] = 8884099; em[313] = 8; em[314] = 2; /* 312: pointer_to_array_of_pointers_to_stack */
    	em[315] = 248; em[316] = 0; 
    	em[317] = 251; em[318] = 12; 
    em[319] = 1; em[320] = 8; em[321] = 1; /* 319: pointer.struct.ec_extra_data_st */
    	em[322] = 324; em[323] = 0; 
    em[324] = 0; em[325] = 40; em[326] = 5; /* 324: struct.ec_extra_data_st */
    	em[327] = 337; em[328] = 0; 
    	em[329] = 285; em[330] = 8; 
    	em[331] = 288; em[332] = 16; 
    	em[333] = 291; em[334] = 24; 
    	em[335] = 291; em[336] = 32; 
    em[337] = 1; em[338] = 8; em[339] = 1; /* 337: pointer.struct.ec_extra_data_st */
    	em[340] = 324; em[341] = 0; 
    em[342] = 1; em[343] = 8; em[344] = 1; /* 342: pointer.struct.dh_st */
    	em[345] = 347; em[346] = 0; 
    em[347] = 0; em[348] = 144; em[349] = 12; /* 347: struct.dh_st */
    	em[350] = 374; em[351] = 8; 
    	em[352] = 374; em[353] = 16; 
    	em[354] = 374; em[355] = 32; 
    	em[356] = 374; em[357] = 40; 
    	em[358] = 391; em[359] = 56; 
    	em[360] = 374; em[361] = 64; 
    	em[362] = 374; em[363] = 72; 
    	em[364] = 254; em[365] = 80; 
    	em[366] = 374; em[367] = 96; 
    	em[368] = 405; em[369] = 112; 
    	em[370] = 422; em[371] = 128; 
    	em[372] = 468; em[373] = 136; 
    em[374] = 1; em[375] = 8; em[376] = 1; /* 374: pointer.struct.bignum_st */
    	em[377] = 379; em[378] = 0; 
    em[379] = 0; em[380] = 24; em[381] = 1; /* 379: struct.bignum_st */
    	em[382] = 384; em[383] = 0; 
    em[384] = 8884099; em[385] = 8; em[386] = 2; /* 384: pointer_to_array_of_pointers_to_stack */
    	em[387] = 248; em[388] = 0; 
    	em[389] = 251; em[390] = 12; 
    em[391] = 1; em[392] = 8; em[393] = 1; /* 391: pointer.struct.bn_mont_ctx_st */
    	em[394] = 396; em[395] = 0; 
    em[396] = 0; em[397] = 96; em[398] = 3; /* 396: struct.bn_mont_ctx_st */
    	em[399] = 379; em[400] = 8; 
    	em[401] = 379; em[402] = 32; 
    	em[403] = 379; em[404] = 56; 
    em[405] = 0; em[406] = 32; em[407] = 2; /* 405: struct.crypto_ex_data_st_fake */
    	em[408] = 412; em[409] = 8; 
    	em[410] = 419; em[411] = 24; 
    em[412] = 8884099; em[413] = 8; em[414] = 2; /* 412: pointer_to_array_of_pointers_to_stack */
    	em[415] = 285; em[416] = 0; 
    	em[417] = 251; em[418] = 20; 
    em[419] = 8884097; em[420] = 8; em[421] = 0; /* 419: pointer.func */
    em[422] = 1; em[423] = 8; em[424] = 1; /* 422: pointer.struct.dh_method */
    	em[425] = 427; em[426] = 0; 
    em[427] = 0; em[428] = 72; em[429] = 8; /* 427: struct.dh_method */
    	em[430] = 446; em[431] = 0; 
    	em[432] = 451; em[433] = 8; 
    	em[434] = 454; em[435] = 16; 
    	em[436] = 457; em[437] = 24; 
    	em[438] = 451; em[439] = 32; 
    	em[440] = 451; em[441] = 40; 
    	em[442] = 460; em[443] = 56; 
    	em[444] = 465; em[445] = 64; 
    em[446] = 1; em[447] = 8; em[448] = 1; /* 446: pointer.char */
    	em[449] = 8884096; em[450] = 0; 
    em[451] = 8884097; em[452] = 8; em[453] = 0; /* 451: pointer.func */
    em[454] = 8884097; em[455] = 8; em[456] = 0; /* 454: pointer.func */
    em[457] = 8884097; em[458] = 8; em[459] = 0; /* 457: pointer.func */
    em[460] = 1; em[461] = 8; em[462] = 1; /* 460: pointer.char */
    	em[463] = 8884096; em[464] = 0; 
    em[465] = 8884097; em[466] = 8; em[467] = 0; /* 465: pointer.func */
    em[468] = 1; em[469] = 8; em[470] = 1; /* 468: pointer.struct.engine_st */
    	em[471] = 473; em[472] = 0; 
    em[473] = 0; em[474] = 216; em[475] = 24; /* 473: struct.engine_st */
    	em[476] = 446; em[477] = 0; 
    	em[478] = 446; em[479] = 8; 
    	em[480] = 524; em[481] = 16; 
    	em[482] = 579; em[483] = 24; 
    	em[484] = 630; em[485] = 32; 
    	em[486] = 666; em[487] = 40; 
    	em[488] = 683; em[489] = 48; 
    	em[490] = 710; em[491] = 56; 
    	em[492] = 745; em[493] = 64; 
    	em[494] = 753; em[495] = 72; 
    	em[496] = 756; em[497] = 80; 
    	em[498] = 759; em[499] = 88; 
    	em[500] = 762; em[501] = 96; 
    	em[502] = 765; em[503] = 104; 
    	em[504] = 765; em[505] = 112; 
    	em[506] = 765; em[507] = 120; 
    	em[508] = 768; em[509] = 128; 
    	em[510] = 771; em[511] = 136; 
    	em[512] = 771; em[513] = 144; 
    	em[514] = 774; em[515] = 152; 
    	em[516] = 777; em[517] = 160; 
    	em[518] = 789; em[519] = 184; 
    	em[520] = 803; em[521] = 200; 
    	em[522] = 803; em[523] = 208; 
    em[524] = 1; em[525] = 8; em[526] = 1; /* 524: pointer.struct.rsa_meth_st */
    	em[527] = 529; em[528] = 0; 
    em[529] = 0; em[530] = 112; em[531] = 13; /* 529: struct.rsa_meth_st */
    	em[532] = 446; em[533] = 0; 
    	em[534] = 558; em[535] = 8; 
    	em[536] = 558; em[537] = 16; 
    	em[538] = 558; em[539] = 24; 
    	em[540] = 558; em[541] = 32; 
    	em[542] = 561; em[543] = 40; 
    	em[544] = 564; em[545] = 48; 
    	em[546] = 567; em[547] = 56; 
    	em[548] = 567; em[549] = 64; 
    	em[550] = 460; em[551] = 80; 
    	em[552] = 570; em[553] = 88; 
    	em[554] = 573; em[555] = 96; 
    	em[556] = 576; em[557] = 104; 
    em[558] = 8884097; em[559] = 8; em[560] = 0; /* 558: pointer.func */
    em[561] = 8884097; em[562] = 8; em[563] = 0; /* 561: pointer.func */
    em[564] = 8884097; em[565] = 8; em[566] = 0; /* 564: pointer.func */
    em[567] = 8884097; em[568] = 8; em[569] = 0; /* 567: pointer.func */
    em[570] = 8884097; em[571] = 8; em[572] = 0; /* 570: pointer.func */
    em[573] = 8884097; em[574] = 8; em[575] = 0; /* 573: pointer.func */
    em[576] = 8884097; em[577] = 8; em[578] = 0; /* 576: pointer.func */
    em[579] = 1; em[580] = 8; em[581] = 1; /* 579: pointer.struct.dsa_method */
    	em[582] = 584; em[583] = 0; 
    em[584] = 0; em[585] = 96; em[586] = 11; /* 584: struct.dsa_method */
    	em[587] = 446; em[588] = 0; 
    	em[589] = 609; em[590] = 8; 
    	em[591] = 612; em[592] = 16; 
    	em[593] = 615; em[594] = 24; 
    	em[595] = 618; em[596] = 32; 
    	em[597] = 621; em[598] = 40; 
    	em[599] = 624; em[600] = 48; 
    	em[601] = 624; em[602] = 56; 
    	em[603] = 460; em[604] = 72; 
    	em[605] = 627; em[606] = 80; 
    	em[607] = 624; em[608] = 88; 
    em[609] = 8884097; em[610] = 8; em[611] = 0; /* 609: pointer.func */
    em[612] = 8884097; em[613] = 8; em[614] = 0; /* 612: pointer.func */
    em[615] = 8884097; em[616] = 8; em[617] = 0; /* 615: pointer.func */
    em[618] = 8884097; em[619] = 8; em[620] = 0; /* 618: pointer.func */
    em[621] = 8884097; em[622] = 8; em[623] = 0; /* 621: pointer.func */
    em[624] = 8884097; em[625] = 8; em[626] = 0; /* 624: pointer.func */
    em[627] = 8884097; em[628] = 8; em[629] = 0; /* 627: pointer.func */
    em[630] = 1; em[631] = 8; em[632] = 1; /* 630: pointer.struct.dh_method */
    	em[633] = 635; em[634] = 0; 
    em[635] = 0; em[636] = 72; em[637] = 8; /* 635: struct.dh_method */
    	em[638] = 446; em[639] = 0; 
    	em[640] = 654; em[641] = 8; 
    	em[642] = 657; em[643] = 16; 
    	em[644] = 660; em[645] = 24; 
    	em[646] = 654; em[647] = 32; 
    	em[648] = 654; em[649] = 40; 
    	em[650] = 460; em[651] = 56; 
    	em[652] = 663; em[653] = 64; 
    em[654] = 8884097; em[655] = 8; em[656] = 0; /* 654: pointer.func */
    em[657] = 8884097; em[658] = 8; em[659] = 0; /* 657: pointer.func */
    em[660] = 8884097; em[661] = 8; em[662] = 0; /* 660: pointer.func */
    em[663] = 8884097; em[664] = 8; em[665] = 0; /* 663: pointer.func */
    em[666] = 1; em[667] = 8; em[668] = 1; /* 666: pointer.struct.ecdh_method */
    	em[669] = 671; em[670] = 0; 
    em[671] = 0; em[672] = 32; em[673] = 3; /* 671: struct.ecdh_method */
    	em[674] = 446; em[675] = 0; 
    	em[676] = 680; em[677] = 8; 
    	em[678] = 460; em[679] = 24; 
    em[680] = 8884097; em[681] = 8; em[682] = 0; /* 680: pointer.func */
    em[683] = 1; em[684] = 8; em[685] = 1; /* 683: pointer.struct.ecdsa_method */
    	em[686] = 688; em[687] = 0; 
    em[688] = 0; em[689] = 48; em[690] = 5; /* 688: struct.ecdsa_method */
    	em[691] = 446; em[692] = 0; 
    	em[693] = 701; em[694] = 8; 
    	em[695] = 704; em[696] = 16; 
    	em[697] = 707; em[698] = 24; 
    	em[699] = 460; em[700] = 40; 
    em[701] = 8884097; em[702] = 8; em[703] = 0; /* 701: pointer.func */
    em[704] = 8884097; em[705] = 8; em[706] = 0; /* 704: pointer.func */
    em[707] = 8884097; em[708] = 8; em[709] = 0; /* 707: pointer.func */
    em[710] = 1; em[711] = 8; em[712] = 1; /* 710: pointer.struct.rand_meth_st */
    	em[713] = 715; em[714] = 0; 
    em[715] = 0; em[716] = 48; em[717] = 6; /* 715: struct.rand_meth_st */
    	em[718] = 730; em[719] = 0; 
    	em[720] = 733; em[721] = 8; 
    	em[722] = 736; em[723] = 16; 
    	em[724] = 739; em[725] = 24; 
    	em[726] = 733; em[727] = 32; 
    	em[728] = 742; em[729] = 40; 
    em[730] = 8884097; em[731] = 8; em[732] = 0; /* 730: pointer.func */
    em[733] = 8884097; em[734] = 8; em[735] = 0; /* 733: pointer.func */
    em[736] = 8884097; em[737] = 8; em[738] = 0; /* 736: pointer.func */
    em[739] = 8884097; em[740] = 8; em[741] = 0; /* 739: pointer.func */
    em[742] = 8884097; em[743] = 8; em[744] = 0; /* 742: pointer.func */
    em[745] = 1; em[746] = 8; em[747] = 1; /* 745: pointer.struct.store_method_st */
    	em[748] = 750; em[749] = 0; 
    em[750] = 0; em[751] = 0; em[752] = 0; /* 750: struct.store_method_st */
    em[753] = 8884097; em[754] = 8; em[755] = 0; /* 753: pointer.func */
    em[756] = 8884097; em[757] = 8; em[758] = 0; /* 756: pointer.func */
    em[759] = 8884097; em[760] = 8; em[761] = 0; /* 759: pointer.func */
    em[762] = 8884097; em[763] = 8; em[764] = 0; /* 762: pointer.func */
    em[765] = 8884097; em[766] = 8; em[767] = 0; /* 765: pointer.func */
    em[768] = 8884097; em[769] = 8; em[770] = 0; /* 768: pointer.func */
    em[771] = 8884097; em[772] = 8; em[773] = 0; /* 771: pointer.func */
    em[774] = 8884097; em[775] = 8; em[776] = 0; /* 774: pointer.func */
    em[777] = 1; em[778] = 8; em[779] = 1; /* 777: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[780] = 782; em[781] = 0; 
    em[782] = 0; em[783] = 32; em[784] = 2; /* 782: struct.ENGINE_CMD_DEFN_st */
    	em[785] = 446; em[786] = 8; 
    	em[787] = 446; em[788] = 16; 
    em[789] = 0; em[790] = 32; em[791] = 2; /* 789: struct.crypto_ex_data_st_fake */
    	em[792] = 796; em[793] = 8; 
    	em[794] = 419; em[795] = 24; 
    em[796] = 8884099; em[797] = 8; em[798] = 2; /* 796: pointer_to_array_of_pointers_to_stack */
    	em[799] = 285; em[800] = 0; 
    	em[801] = 251; em[802] = 20; 
    em[803] = 1; em[804] = 8; em[805] = 1; /* 803: pointer.struct.engine_st */
    	em[806] = 473; em[807] = 0; 
    em[808] = 1; em[809] = 8; em[810] = 1; /* 808: pointer.struct.dsa_st */
    	em[811] = 813; em[812] = 0; 
    em[813] = 0; em[814] = 136; em[815] = 11; /* 813: struct.dsa_st */
    	em[816] = 838; em[817] = 24; 
    	em[818] = 838; em[819] = 32; 
    	em[820] = 838; em[821] = 40; 
    	em[822] = 838; em[823] = 48; 
    	em[824] = 838; em[825] = 56; 
    	em[826] = 838; em[827] = 64; 
    	em[828] = 838; em[829] = 72; 
    	em[830] = 855; em[831] = 88; 
    	em[832] = 869; em[833] = 104; 
    	em[834] = 883; em[835] = 120; 
    	em[836] = 934; em[837] = 128; 
    em[838] = 1; em[839] = 8; em[840] = 1; /* 838: pointer.struct.bignum_st */
    	em[841] = 843; em[842] = 0; 
    em[843] = 0; em[844] = 24; em[845] = 1; /* 843: struct.bignum_st */
    	em[846] = 848; em[847] = 0; 
    em[848] = 8884099; em[849] = 8; em[850] = 2; /* 848: pointer_to_array_of_pointers_to_stack */
    	em[851] = 248; em[852] = 0; 
    	em[853] = 251; em[854] = 12; 
    em[855] = 1; em[856] = 8; em[857] = 1; /* 855: pointer.struct.bn_mont_ctx_st */
    	em[858] = 860; em[859] = 0; 
    em[860] = 0; em[861] = 96; em[862] = 3; /* 860: struct.bn_mont_ctx_st */
    	em[863] = 843; em[864] = 8; 
    	em[865] = 843; em[866] = 32; 
    	em[867] = 843; em[868] = 56; 
    em[869] = 0; em[870] = 32; em[871] = 2; /* 869: struct.crypto_ex_data_st_fake */
    	em[872] = 876; em[873] = 8; 
    	em[874] = 419; em[875] = 24; 
    em[876] = 8884099; em[877] = 8; em[878] = 2; /* 876: pointer_to_array_of_pointers_to_stack */
    	em[879] = 285; em[880] = 0; 
    	em[881] = 251; em[882] = 20; 
    em[883] = 1; em[884] = 8; em[885] = 1; /* 883: pointer.struct.dsa_method */
    	em[886] = 888; em[887] = 0; 
    em[888] = 0; em[889] = 96; em[890] = 11; /* 888: struct.dsa_method */
    	em[891] = 446; em[892] = 0; 
    	em[893] = 913; em[894] = 8; 
    	em[895] = 916; em[896] = 16; 
    	em[897] = 919; em[898] = 24; 
    	em[899] = 922; em[900] = 32; 
    	em[901] = 925; em[902] = 40; 
    	em[903] = 928; em[904] = 48; 
    	em[905] = 928; em[906] = 56; 
    	em[907] = 460; em[908] = 72; 
    	em[909] = 931; em[910] = 80; 
    	em[911] = 928; em[912] = 88; 
    em[913] = 8884097; em[914] = 8; em[915] = 0; /* 913: pointer.func */
    em[916] = 8884097; em[917] = 8; em[918] = 0; /* 916: pointer.func */
    em[919] = 8884097; em[920] = 8; em[921] = 0; /* 919: pointer.func */
    em[922] = 8884097; em[923] = 8; em[924] = 0; /* 922: pointer.func */
    em[925] = 8884097; em[926] = 8; em[927] = 0; /* 925: pointer.func */
    em[928] = 8884097; em[929] = 8; em[930] = 0; /* 928: pointer.func */
    em[931] = 8884097; em[932] = 8; em[933] = 0; /* 931: pointer.func */
    em[934] = 1; em[935] = 8; em[936] = 1; /* 934: pointer.struct.engine_st */
    	em[937] = 473; em[938] = 0; 
    em[939] = 1; em[940] = 8; em[941] = 1; /* 939: pointer.struct.rsa_st */
    	em[942] = 944; em[943] = 0; 
    em[944] = 0; em[945] = 168; em[946] = 17; /* 944: struct.rsa_st */
    	em[947] = 981; em[948] = 16; 
    	em[949] = 468; em[950] = 24; 
    	em[951] = 374; em[952] = 32; 
    	em[953] = 374; em[954] = 40; 
    	em[955] = 374; em[956] = 48; 
    	em[957] = 374; em[958] = 56; 
    	em[959] = 374; em[960] = 64; 
    	em[961] = 374; em[962] = 72; 
    	em[963] = 374; em[964] = 80; 
    	em[965] = 374; em[966] = 88; 
    	em[967] = 1036; em[968] = 96; 
    	em[969] = 391; em[970] = 120; 
    	em[971] = 391; em[972] = 128; 
    	em[973] = 391; em[974] = 136; 
    	em[975] = 460; em[976] = 144; 
    	em[977] = 1050; em[978] = 152; 
    	em[979] = 1050; em[980] = 160; 
    em[981] = 1; em[982] = 8; em[983] = 1; /* 981: pointer.struct.rsa_meth_st */
    	em[984] = 986; em[985] = 0; 
    em[986] = 0; em[987] = 112; em[988] = 13; /* 986: struct.rsa_meth_st */
    	em[989] = 446; em[990] = 0; 
    	em[991] = 1015; em[992] = 8; 
    	em[993] = 1015; em[994] = 16; 
    	em[995] = 1015; em[996] = 24; 
    	em[997] = 1015; em[998] = 32; 
    	em[999] = 1018; em[1000] = 40; 
    	em[1001] = 1021; em[1002] = 48; 
    	em[1003] = 1024; em[1004] = 56; 
    	em[1005] = 1024; em[1006] = 64; 
    	em[1007] = 460; em[1008] = 80; 
    	em[1009] = 1027; em[1010] = 88; 
    	em[1011] = 1030; em[1012] = 96; 
    	em[1013] = 1033; em[1014] = 104; 
    em[1015] = 8884097; em[1016] = 8; em[1017] = 0; /* 1015: pointer.func */
    em[1018] = 8884097; em[1019] = 8; em[1020] = 0; /* 1018: pointer.func */
    em[1021] = 8884097; em[1022] = 8; em[1023] = 0; /* 1021: pointer.func */
    em[1024] = 8884097; em[1025] = 8; em[1026] = 0; /* 1024: pointer.func */
    em[1027] = 8884097; em[1028] = 8; em[1029] = 0; /* 1027: pointer.func */
    em[1030] = 8884097; em[1031] = 8; em[1032] = 0; /* 1030: pointer.func */
    em[1033] = 8884097; em[1034] = 8; em[1035] = 0; /* 1033: pointer.func */
    em[1036] = 0; em[1037] = 32; em[1038] = 2; /* 1036: struct.crypto_ex_data_st_fake */
    	em[1039] = 1043; em[1040] = 8; 
    	em[1041] = 419; em[1042] = 24; 
    em[1043] = 8884099; em[1044] = 8; em[1045] = 2; /* 1043: pointer_to_array_of_pointers_to_stack */
    	em[1046] = 285; em[1047] = 0; 
    	em[1048] = 251; em[1049] = 20; 
    em[1050] = 1; em[1051] = 8; em[1052] = 1; /* 1050: pointer.struct.bn_blinding_st */
    	em[1053] = 1055; em[1054] = 0; 
    em[1055] = 0; em[1056] = 88; em[1057] = 7; /* 1055: struct.bn_blinding_st */
    	em[1058] = 1072; em[1059] = 0; 
    	em[1060] = 1072; em[1061] = 8; 
    	em[1062] = 1072; em[1063] = 16; 
    	em[1064] = 1072; em[1065] = 24; 
    	em[1066] = 1089; em[1067] = 40; 
    	em[1068] = 1094; em[1069] = 72; 
    	em[1070] = 1108; em[1071] = 80; 
    em[1072] = 1; em[1073] = 8; em[1074] = 1; /* 1072: pointer.struct.bignum_st */
    	em[1075] = 1077; em[1076] = 0; 
    em[1077] = 0; em[1078] = 24; em[1079] = 1; /* 1077: struct.bignum_st */
    	em[1080] = 1082; em[1081] = 0; 
    em[1082] = 8884099; em[1083] = 8; em[1084] = 2; /* 1082: pointer_to_array_of_pointers_to_stack */
    	em[1085] = 248; em[1086] = 0; 
    	em[1087] = 251; em[1088] = 12; 
    em[1089] = 0; em[1090] = 16; em[1091] = 1; /* 1089: struct.crypto_threadid_st */
    	em[1092] = 285; em[1093] = 0; 
    em[1094] = 1; em[1095] = 8; em[1096] = 1; /* 1094: pointer.struct.bn_mont_ctx_st */
    	em[1097] = 1099; em[1098] = 0; 
    em[1099] = 0; em[1100] = 96; em[1101] = 3; /* 1099: struct.bn_mont_ctx_st */
    	em[1102] = 1077; em[1103] = 8; 
    	em[1104] = 1077; em[1105] = 32; 
    	em[1106] = 1077; em[1107] = 56; 
    em[1108] = 8884097; em[1109] = 8; em[1110] = 0; /* 1108: pointer.func */
    em[1111] = 0; em[1112] = 56; em[1113] = 4; /* 1111: struct.evp_pkey_st */
    	em[1114] = 1122; em[1115] = 16; 
    	em[1116] = 468; em[1117] = 24; 
    	em[1118] = 1223; em[1119] = 32; 
    	em[1120] = 1238; em[1121] = 48; 
    em[1122] = 1; em[1123] = 8; em[1124] = 1; /* 1122: pointer.struct.evp_pkey_asn1_method_st */
    	em[1125] = 1127; em[1126] = 0; 
    em[1127] = 0; em[1128] = 208; em[1129] = 24; /* 1127: struct.evp_pkey_asn1_method_st */
    	em[1130] = 460; em[1131] = 16; 
    	em[1132] = 460; em[1133] = 24; 
    	em[1134] = 1178; em[1135] = 32; 
    	em[1136] = 1181; em[1137] = 40; 
    	em[1138] = 1184; em[1139] = 48; 
    	em[1140] = 1187; em[1141] = 56; 
    	em[1142] = 1190; em[1143] = 64; 
    	em[1144] = 1193; em[1145] = 72; 
    	em[1146] = 1187; em[1147] = 80; 
    	em[1148] = 1196; em[1149] = 88; 
    	em[1150] = 1196; em[1151] = 96; 
    	em[1152] = 1199; em[1153] = 104; 
    	em[1154] = 1202; em[1155] = 112; 
    	em[1156] = 1196; em[1157] = 120; 
    	em[1158] = 1205; em[1159] = 128; 
    	em[1160] = 1184; em[1161] = 136; 
    	em[1162] = 1187; em[1163] = 144; 
    	em[1164] = 1208; em[1165] = 152; 
    	em[1166] = 1211; em[1167] = 160; 
    	em[1168] = 1214; em[1169] = 168; 
    	em[1170] = 1199; em[1171] = 176; 
    	em[1172] = 1202; em[1173] = 184; 
    	em[1174] = 1217; em[1175] = 192; 
    	em[1176] = 1220; em[1177] = 200; 
    em[1178] = 8884097; em[1179] = 8; em[1180] = 0; /* 1178: pointer.func */
    em[1181] = 8884097; em[1182] = 8; em[1183] = 0; /* 1181: pointer.func */
    em[1184] = 8884097; em[1185] = 8; em[1186] = 0; /* 1184: pointer.func */
    em[1187] = 8884097; em[1188] = 8; em[1189] = 0; /* 1187: pointer.func */
    em[1190] = 8884097; em[1191] = 8; em[1192] = 0; /* 1190: pointer.func */
    em[1193] = 8884097; em[1194] = 8; em[1195] = 0; /* 1193: pointer.func */
    em[1196] = 8884097; em[1197] = 8; em[1198] = 0; /* 1196: pointer.func */
    em[1199] = 8884097; em[1200] = 8; em[1201] = 0; /* 1199: pointer.func */
    em[1202] = 8884097; em[1203] = 8; em[1204] = 0; /* 1202: pointer.func */
    em[1205] = 8884097; em[1206] = 8; em[1207] = 0; /* 1205: pointer.func */
    em[1208] = 8884097; em[1209] = 8; em[1210] = 0; /* 1208: pointer.func */
    em[1211] = 8884097; em[1212] = 8; em[1213] = 0; /* 1211: pointer.func */
    em[1214] = 8884097; em[1215] = 8; em[1216] = 0; /* 1214: pointer.func */
    em[1217] = 8884097; em[1218] = 8; em[1219] = 0; /* 1217: pointer.func */
    em[1220] = 8884097; em[1221] = 8; em[1222] = 0; /* 1220: pointer.func */
    em[1223] = 8884101; em[1224] = 8; em[1225] = 6; /* 1223: union.union_of_evp_pkey_st */
    	em[1226] = 285; em[1227] = 0; 
    	em[1228] = 939; em[1229] = 6; 
    	em[1230] = 808; em[1231] = 116; 
    	em[1232] = 342; em[1233] = 28; 
    	em[1234] = 0; em[1235] = 408; 
    	em[1236] = 251; em[1237] = 0; 
    em[1238] = 1; em[1239] = 8; em[1240] = 1; /* 1238: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1241] = 1243; em[1242] = 0; 
    em[1243] = 0; em[1244] = 32; em[1245] = 2; /* 1243: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1246] = 1250; em[1247] = 8; 
    	em[1248] = 419; em[1249] = 24; 
    em[1250] = 8884099; em[1251] = 8; em[1252] = 2; /* 1250: pointer_to_array_of_pointers_to_stack */
    	em[1253] = 1257; em[1254] = 0; 
    	em[1255] = 251; em[1256] = 20; 
    em[1257] = 0; em[1258] = 8; em[1259] = 1; /* 1257: pointer.X509_ATTRIBUTE */
    	em[1260] = 1262; em[1261] = 0; 
    em[1262] = 0; em[1263] = 0; em[1264] = 1; /* 1262: X509_ATTRIBUTE */
    	em[1265] = 1267; em[1266] = 0; 
    em[1267] = 0; em[1268] = 24; em[1269] = 2; /* 1267: struct.x509_attributes_st */
    	em[1270] = 1274; em[1271] = 0; 
    	em[1272] = 1293; em[1273] = 16; 
    em[1274] = 1; em[1275] = 8; em[1276] = 1; /* 1274: pointer.struct.asn1_object_st */
    	em[1277] = 1279; em[1278] = 0; 
    em[1279] = 0; em[1280] = 40; em[1281] = 3; /* 1279: struct.asn1_object_st */
    	em[1282] = 446; em[1283] = 0; 
    	em[1284] = 446; em[1285] = 8; 
    	em[1286] = 1288; em[1287] = 24; 
    em[1288] = 1; em[1289] = 8; em[1290] = 1; /* 1288: pointer.unsigned char */
    	em[1291] = 259; em[1292] = 0; 
    em[1293] = 0; em[1294] = 8; em[1295] = 3; /* 1293: union.unknown */
    	em[1296] = 460; em[1297] = 0; 
    	em[1298] = 1302; em[1299] = 0; 
    	em[1300] = 1481; em[1301] = 0; 
    em[1302] = 1; em[1303] = 8; em[1304] = 1; /* 1302: pointer.struct.stack_st_ASN1_TYPE */
    	em[1305] = 1307; em[1306] = 0; 
    em[1307] = 0; em[1308] = 32; em[1309] = 2; /* 1307: struct.stack_st_fake_ASN1_TYPE */
    	em[1310] = 1314; em[1311] = 8; 
    	em[1312] = 419; em[1313] = 24; 
    em[1314] = 8884099; em[1315] = 8; em[1316] = 2; /* 1314: pointer_to_array_of_pointers_to_stack */
    	em[1317] = 1321; em[1318] = 0; 
    	em[1319] = 251; em[1320] = 20; 
    em[1321] = 0; em[1322] = 8; em[1323] = 1; /* 1321: pointer.ASN1_TYPE */
    	em[1324] = 1326; em[1325] = 0; 
    em[1326] = 0; em[1327] = 0; em[1328] = 1; /* 1326: ASN1_TYPE */
    	em[1329] = 1331; em[1330] = 0; 
    em[1331] = 0; em[1332] = 16; em[1333] = 1; /* 1331: struct.asn1_type_st */
    	em[1334] = 1336; em[1335] = 8; 
    em[1336] = 0; em[1337] = 8; em[1338] = 20; /* 1336: union.unknown */
    	em[1339] = 460; em[1340] = 0; 
    	em[1341] = 1379; em[1342] = 0; 
    	em[1343] = 1389; em[1344] = 0; 
    	em[1345] = 1403; em[1346] = 0; 
    	em[1347] = 1408; em[1348] = 0; 
    	em[1349] = 1413; em[1350] = 0; 
    	em[1351] = 1418; em[1352] = 0; 
    	em[1353] = 1423; em[1354] = 0; 
    	em[1355] = 1428; em[1356] = 0; 
    	em[1357] = 1433; em[1358] = 0; 
    	em[1359] = 1438; em[1360] = 0; 
    	em[1361] = 1443; em[1362] = 0; 
    	em[1363] = 1448; em[1364] = 0; 
    	em[1365] = 1453; em[1366] = 0; 
    	em[1367] = 1458; em[1368] = 0; 
    	em[1369] = 1463; em[1370] = 0; 
    	em[1371] = 1468; em[1372] = 0; 
    	em[1373] = 1379; em[1374] = 0; 
    	em[1375] = 1379; em[1376] = 0; 
    	em[1377] = 1473; em[1378] = 0; 
    em[1379] = 1; em[1380] = 8; em[1381] = 1; /* 1379: pointer.struct.asn1_string_st */
    	em[1382] = 1384; em[1383] = 0; 
    em[1384] = 0; em[1385] = 24; em[1386] = 1; /* 1384: struct.asn1_string_st */
    	em[1387] = 254; em[1388] = 8; 
    em[1389] = 1; em[1390] = 8; em[1391] = 1; /* 1389: pointer.struct.asn1_object_st */
    	em[1392] = 1394; em[1393] = 0; 
    em[1394] = 0; em[1395] = 40; em[1396] = 3; /* 1394: struct.asn1_object_st */
    	em[1397] = 446; em[1398] = 0; 
    	em[1399] = 446; em[1400] = 8; 
    	em[1401] = 1288; em[1402] = 24; 
    em[1403] = 1; em[1404] = 8; em[1405] = 1; /* 1403: pointer.struct.asn1_string_st */
    	em[1406] = 1384; em[1407] = 0; 
    em[1408] = 1; em[1409] = 8; em[1410] = 1; /* 1408: pointer.struct.asn1_string_st */
    	em[1411] = 1384; em[1412] = 0; 
    em[1413] = 1; em[1414] = 8; em[1415] = 1; /* 1413: pointer.struct.asn1_string_st */
    	em[1416] = 1384; em[1417] = 0; 
    em[1418] = 1; em[1419] = 8; em[1420] = 1; /* 1418: pointer.struct.asn1_string_st */
    	em[1421] = 1384; em[1422] = 0; 
    em[1423] = 1; em[1424] = 8; em[1425] = 1; /* 1423: pointer.struct.asn1_string_st */
    	em[1426] = 1384; em[1427] = 0; 
    em[1428] = 1; em[1429] = 8; em[1430] = 1; /* 1428: pointer.struct.asn1_string_st */
    	em[1431] = 1384; em[1432] = 0; 
    em[1433] = 1; em[1434] = 8; em[1435] = 1; /* 1433: pointer.struct.asn1_string_st */
    	em[1436] = 1384; em[1437] = 0; 
    em[1438] = 1; em[1439] = 8; em[1440] = 1; /* 1438: pointer.struct.asn1_string_st */
    	em[1441] = 1384; em[1442] = 0; 
    em[1443] = 1; em[1444] = 8; em[1445] = 1; /* 1443: pointer.struct.asn1_string_st */
    	em[1446] = 1384; em[1447] = 0; 
    em[1448] = 1; em[1449] = 8; em[1450] = 1; /* 1448: pointer.struct.asn1_string_st */
    	em[1451] = 1384; em[1452] = 0; 
    em[1453] = 1; em[1454] = 8; em[1455] = 1; /* 1453: pointer.struct.asn1_string_st */
    	em[1456] = 1384; em[1457] = 0; 
    em[1458] = 1; em[1459] = 8; em[1460] = 1; /* 1458: pointer.struct.asn1_string_st */
    	em[1461] = 1384; em[1462] = 0; 
    em[1463] = 1; em[1464] = 8; em[1465] = 1; /* 1463: pointer.struct.asn1_string_st */
    	em[1466] = 1384; em[1467] = 0; 
    em[1468] = 1; em[1469] = 8; em[1470] = 1; /* 1468: pointer.struct.asn1_string_st */
    	em[1471] = 1384; em[1472] = 0; 
    em[1473] = 1; em[1474] = 8; em[1475] = 1; /* 1473: pointer.struct.ASN1_VALUE_st */
    	em[1476] = 1478; em[1477] = 0; 
    em[1478] = 0; em[1479] = 0; em[1480] = 0; /* 1478: struct.ASN1_VALUE_st */
    em[1481] = 1; em[1482] = 8; em[1483] = 1; /* 1481: pointer.struct.asn1_type_st */
    	em[1484] = 1486; em[1485] = 0; 
    em[1486] = 0; em[1487] = 16; em[1488] = 1; /* 1486: struct.asn1_type_st */
    	em[1489] = 1491; em[1490] = 8; 
    em[1491] = 0; em[1492] = 8; em[1493] = 20; /* 1491: union.unknown */
    	em[1494] = 460; em[1495] = 0; 
    	em[1496] = 1534; em[1497] = 0; 
    	em[1498] = 1274; em[1499] = 0; 
    	em[1500] = 1544; em[1501] = 0; 
    	em[1502] = 1549; em[1503] = 0; 
    	em[1504] = 1554; em[1505] = 0; 
    	em[1506] = 1559; em[1507] = 0; 
    	em[1508] = 1564; em[1509] = 0; 
    	em[1510] = 1569; em[1511] = 0; 
    	em[1512] = 1574; em[1513] = 0; 
    	em[1514] = 1579; em[1515] = 0; 
    	em[1516] = 1584; em[1517] = 0; 
    	em[1518] = 1589; em[1519] = 0; 
    	em[1520] = 1594; em[1521] = 0; 
    	em[1522] = 1599; em[1523] = 0; 
    	em[1524] = 1604; em[1525] = 0; 
    	em[1526] = 1609; em[1527] = 0; 
    	em[1528] = 1534; em[1529] = 0; 
    	em[1530] = 1534; em[1531] = 0; 
    	em[1532] = 1614; em[1533] = 0; 
    em[1534] = 1; em[1535] = 8; em[1536] = 1; /* 1534: pointer.struct.asn1_string_st */
    	em[1537] = 1539; em[1538] = 0; 
    em[1539] = 0; em[1540] = 24; em[1541] = 1; /* 1539: struct.asn1_string_st */
    	em[1542] = 254; em[1543] = 8; 
    em[1544] = 1; em[1545] = 8; em[1546] = 1; /* 1544: pointer.struct.asn1_string_st */
    	em[1547] = 1539; em[1548] = 0; 
    em[1549] = 1; em[1550] = 8; em[1551] = 1; /* 1549: pointer.struct.asn1_string_st */
    	em[1552] = 1539; em[1553] = 0; 
    em[1554] = 1; em[1555] = 8; em[1556] = 1; /* 1554: pointer.struct.asn1_string_st */
    	em[1557] = 1539; em[1558] = 0; 
    em[1559] = 1; em[1560] = 8; em[1561] = 1; /* 1559: pointer.struct.asn1_string_st */
    	em[1562] = 1539; em[1563] = 0; 
    em[1564] = 1; em[1565] = 8; em[1566] = 1; /* 1564: pointer.struct.asn1_string_st */
    	em[1567] = 1539; em[1568] = 0; 
    em[1569] = 1; em[1570] = 8; em[1571] = 1; /* 1569: pointer.struct.asn1_string_st */
    	em[1572] = 1539; em[1573] = 0; 
    em[1574] = 1; em[1575] = 8; em[1576] = 1; /* 1574: pointer.struct.asn1_string_st */
    	em[1577] = 1539; em[1578] = 0; 
    em[1579] = 1; em[1580] = 8; em[1581] = 1; /* 1579: pointer.struct.asn1_string_st */
    	em[1582] = 1539; em[1583] = 0; 
    em[1584] = 1; em[1585] = 8; em[1586] = 1; /* 1584: pointer.struct.asn1_string_st */
    	em[1587] = 1539; em[1588] = 0; 
    em[1589] = 1; em[1590] = 8; em[1591] = 1; /* 1589: pointer.struct.asn1_string_st */
    	em[1592] = 1539; em[1593] = 0; 
    em[1594] = 1; em[1595] = 8; em[1596] = 1; /* 1594: pointer.struct.asn1_string_st */
    	em[1597] = 1539; em[1598] = 0; 
    em[1599] = 1; em[1600] = 8; em[1601] = 1; /* 1599: pointer.struct.asn1_string_st */
    	em[1602] = 1539; em[1603] = 0; 
    em[1604] = 1; em[1605] = 8; em[1606] = 1; /* 1604: pointer.struct.asn1_string_st */
    	em[1607] = 1539; em[1608] = 0; 
    em[1609] = 1; em[1610] = 8; em[1611] = 1; /* 1609: pointer.struct.asn1_string_st */
    	em[1612] = 1539; em[1613] = 0; 
    em[1614] = 1; em[1615] = 8; em[1616] = 1; /* 1614: pointer.struct.ASN1_VALUE_st */
    	em[1617] = 1619; em[1618] = 0; 
    em[1619] = 0; em[1620] = 0; em[1621] = 0; /* 1619: struct.ASN1_VALUE_st */
    em[1622] = 1; em[1623] = 8; em[1624] = 1; /* 1622: pointer.struct.stack_st_X509_ALGOR */
    	em[1625] = 1627; em[1626] = 0; 
    em[1627] = 0; em[1628] = 32; em[1629] = 2; /* 1627: struct.stack_st_fake_X509_ALGOR */
    	em[1630] = 1634; em[1631] = 8; 
    	em[1632] = 419; em[1633] = 24; 
    em[1634] = 8884099; em[1635] = 8; em[1636] = 2; /* 1634: pointer_to_array_of_pointers_to_stack */
    	em[1637] = 1641; em[1638] = 0; 
    	em[1639] = 251; em[1640] = 20; 
    em[1641] = 0; em[1642] = 8; em[1643] = 1; /* 1641: pointer.X509_ALGOR */
    	em[1644] = 1646; em[1645] = 0; 
    em[1646] = 0; em[1647] = 0; em[1648] = 1; /* 1646: X509_ALGOR */
    	em[1649] = 1651; em[1650] = 0; 
    em[1651] = 0; em[1652] = 16; em[1653] = 2; /* 1651: struct.X509_algor_st */
    	em[1654] = 1658; em[1655] = 0; 
    	em[1656] = 1672; em[1657] = 8; 
    em[1658] = 1; em[1659] = 8; em[1660] = 1; /* 1658: pointer.struct.asn1_object_st */
    	em[1661] = 1663; em[1662] = 0; 
    em[1663] = 0; em[1664] = 40; em[1665] = 3; /* 1663: struct.asn1_object_st */
    	em[1666] = 446; em[1667] = 0; 
    	em[1668] = 446; em[1669] = 8; 
    	em[1670] = 1288; em[1671] = 24; 
    em[1672] = 1; em[1673] = 8; em[1674] = 1; /* 1672: pointer.struct.asn1_type_st */
    	em[1675] = 1677; em[1676] = 0; 
    em[1677] = 0; em[1678] = 16; em[1679] = 1; /* 1677: struct.asn1_type_st */
    	em[1680] = 1682; em[1681] = 8; 
    em[1682] = 0; em[1683] = 8; em[1684] = 20; /* 1682: union.unknown */
    	em[1685] = 460; em[1686] = 0; 
    	em[1687] = 1725; em[1688] = 0; 
    	em[1689] = 1658; em[1690] = 0; 
    	em[1691] = 1735; em[1692] = 0; 
    	em[1693] = 1740; em[1694] = 0; 
    	em[1695] = 1745; em[1696] = 0; 
    	em[1697] = 1750; em[1698] = 0; 
    	em[1699] = 1755; em[1700] = 0; 
    	em[1701] = 1760; em[1702] = 0; 
    	em[1703] = 1765; em[1704] = 0; 
    	em[1705] = 1770; em[1706] = 0; 
    	em[1707] = 1775; em[1708] = 0; 
    	em[1709] = 1780; em[1710] = 0; 
    	em[1711] = 1785; em[1712] = 0; 
    	em[1713] = 1790; em[1714] = 0; 
    	em[1715] = 1795; em[1716] = 0; 
    	em[1717] = 1800; em[1718] = 0; 
    	em[1719] = 1725; em[1720] = 0; 
    	em[1721] = 1725; em[1722] = 0; 
    	em[1723] = 1805; em[1724] = 0; 
    em[1725] = 1; em[1726] = 8; em[1727] = 1; /* 1725: pointer.struct.asn1_string_st */
    	em[1728] = 1730; em[1729] = 0; 
    em[1730] = 0; em[1731] = 24; em[1732] = 1; /* 1730: struct.asn1_string_st */
    	em[1733] = 254; em[1734] = 8; 
    em[1735] = 1; em[1736] = 8; em[1737] = 1; /* 1735: pointer.struct.asn1_string_st */
    	em[1738] = 1730; em[1739] = 0; 
    em[1740] = 1; em[1741] = 8; em[1742] = 1; /* 1740: pointer.struct.asn1_string_st */
    	em[1743] = 1730; em[1744] = 0; 
    em[1745] = 1; em[1746] = 8; em[1747] = 1; /* 1745: pointer.struct.asn1_string_st */
    	em[1748] = 1730; em[1749] = 0; 
    em[1750] = 1; em[1751] = 8; em[1752] = 1; /* 1750: pointer.struct.asn1_string_st */
    	em[1753] = 1730; em[1754] = 0; 
    em[1755] = 1; em[1756] = 8; em[1757] = 1; /* 1755: pointer.struct.asn1_string_st */
    	em[1758] = 1730; em[1759] = 0; 
    em[1760] = 1; em[1761] = 8; em[1762] = 1; /* 1760: pointer.struct.asn1_string_st */
    	em[1763] = 1730; em[1764] = 0; 
    em[1765] = 1; em[1766] = 8; em[1767] = 1; /* 1765: pointer.struct.asn1_string_st */
    	em[1768] = 1730; em[1769] = 0; 
    em[1770] = 1; em[1771] = 8; em[1772] = 1; /* 1770: pointer.struct.asn1_string_st */
    	em[1773] = 1730; em[1774] = 0; 
    em[1775] = 1; em[1776] = 8; em[1777] = 1; /* 1775: pointer.struct.asn1_string_st */
    	em[1778] = 1730; em[1779] = 0; 
    em[1780] = 1; em[1781] = 8; em[1782] = 1; /* 1780: pointer.struct.asn1_string_st */
    	em[1783] = 1730; em[1784] = 0; 
    em[1785] = 1; em[1786] = 8; em[1787] = 1; /* 1785: pointer.struct.asn1_string_st */
    	em[1788] = 1730; em[1789] = 0; 
    em[1790] = 1; em[1791] = 8; em[1792] = 1; /* 1790: pointer.struct.asn1_string_st */
    	em[1793] = 1730; em[1794] = 0; 
    em[1795] = 1; em[1796] = 8; em[1797] = 1; /* 1795: pointer.struct.asn1_string_st */
    	em[1798] = 1730; em[1799] = 0; 
    em[1800] = 1; em[1801] = 8; em[1802] = 1; /* 1800: pointer.struct.asn1_string_st */
    	em[1803] = 1730; em[1804] = 0; 
    em[1805] = 1; em[1806] = 8; em[1807] = 1; /* 1805: pointer.struct.ASN1_VALUE_st */
    	em[1808] = 1810; em[1809] = 0; 
    em[1810] = 0; em[1811] = 0; em[1812] = 0; /* 1810: struct.ASN1_VALUE_st */
    em[1813] = 1; em[1814] = 8; em[1815] = 1; /* 1813: pointer.struct.stack_st_ASN1_OBJECT */
    	em[1816] = 1818; em[1817] = 0; 
    em[1818] = 0; em[1819] = 32; em[1820] = 2; /* 1818: struct.stack_st_fake_ASN1_OBJECT */
    	em[1821] = 1825; em[1822] = 8; 
    	em[1823] = 419; em[1824] = 24; 
    em[1825] = 8884099; em[1826] = 8; em[1827] = 2; /* 1825: pointer_to_array_of_pointers_to_stack */
    	em[1828] = 1832; em[1829] = 0; 
    	em[1830] = 251; em[1831] = 20; 
    em[1832] = 0; em[1833] = 8; em[1834] = 1; /* 1832: pointer.ASN1_OBJECT */
    	em[1835] = 1837; em[1836] = 0; 
    em[1837] = 0; em[1838] = 0; em[1839] = 1; /* 1837: ASN1_OBJECT */
    	em[1840] = 1842; em[1841] = 0; 
    em[1842] = 0; em[1843] = 40; em[1844] = 3; /* 1842: struct.asn1_object_st */
    	em[1845] = 446; em[1846] = 0; 
    	em[1847] = 446; em[1848] = 8; 
    	em[1849] = 1288; em[1850] = 24; 
    em[1851] = 0; em[1852] = 40; em[1853] = 5; /* 1851: struct.x509_cert_aux_st */
    	em[1854] = 1813; em[1855] = 0; 
    	em[1856] = 1813; em[1857] = 8; 
    	em[1858] = 1864; em[1859] = 16; 
    	em[1860] = 1874; em[1861] = 24; 
    	em[1862] = 1622; em[1863] = 32; 
    em[1864] = 1; em[1865] = 8; em[1866] = 1; /* 1864: pointer.struct.asn1_string_st */
    	em[1867] = 1869; em[1868] = 0; 
    em[1869] = 0; em[1870] = 24; em[1871] = 1; /* 1869: struct.asn1_string_st */
    	em[1872] = 254; em[1873] = 8; 
    em[1874] = 1; em[1875] = 8; em[1876] = 1; /* 1874: pointer.struct.asn1_string_st */
    	em[1877] = 1869; em[1878] = 0; 
    em[1879] = 1; em[1880] = 8; em[1881] = 1; /* 1879: pointer.struct.x509_cert_aux_st */
    	em[1882] = 1851; em[1883] = 0; 
    em[1884] = 1; em[1885] = 8; em[1886] = 1; /* 1884: pointer.struct.EDIPartyName_st */
    	em[1887] = 1889; em[1888] = 0; 
    em[1889] = 0; em[1890] = 16; em[1891] = 2; /* 1889: struct.EDIPartyName_st */
    	em[1892] = 1896; em[1893] = 0; 
    	em[1894] = 1896; em[1895] = 8; 
    em[1896] = 1; em[1897] = 8; em[1898] = 1; /* 1896: pointer.struct.asn1_string_st */
    	em[1899] = 1901; em[1900] = 0; 
    em[1901] = 0; em[1902] = 24; em[1903] = 1; /* 1901: struct.asn1_string_st */
    	em[1904] = 254; em[1905] = 8; 
    em[1906] = 0; em[1907] = 24; em[1908] = 1; /* 1906: struct.buf_mem_st */
    	em[1909] = 460; em[1910] = 8; 
    em[1911] = 1; em[1912] = 8; em[1913] = 1; /* 1911: pointer.struct.X509_name_st */
    	em[1914] = 1916; em[1915] = 0; 
    em[1916] = 0; em[1917] = 40; em[1918] = 3; /* 1916: struct.X509_name_st */
    	em[1919] = 1925; em[1920] = 0; 
    	em[1921] = 1985; em[1922] = 16; 
    	em[1923] = 254; em[1924] = 24; 
    em[1925] = 1; em[1926] = 8; em[1927] = 1; /* 1925: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[1928] = 1930; em[1929] = 0; 
    em[1930] = 0; em[1931] = 32; em[1932] = 2; /* 1930: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[1933] = 1937; em[1934] = 8; 
    	em[1935] = 419; em[1936] = 24; 
    em[1937] = 8884099; em[1938] = 8; em[1939] = 2; /* 1937: pointer_to_array_of_pointers_to_stack */
    	em[1940] = 1944; em[1941] = 0; 
    	em[1942] = 251; em[1943] = 20; 
    em[1944] = 0; em[1945] = 8; em[1946] = 1; /* 1944: pointer.X509_NAME_ENTRY */
    	em[1947] = 1949; em[1948] = 0; 
    em[1949] = 0; em[1950] = 0; em[1951] = 1; /* 1949: X509_NAME_ENTRY */
    	em[1952] = 1954; em[1953] = 0; 
    em[1954] = 0; em[1955] = 24; em[1956] = 2; /* 1954: struct.X509_name_entry_st */
    	em[1957] = 1961; em[1958] = 0; 
    	em[1959] = 1975; em[1960] = 8; 
    em[1961] = 1; em[1962] = 8; em[1963] = 1; /* 1961: pointer.struct.asn1_object_st */
    	em[1964] = 1966; em[1965] = 0; 
    em[1966] = 0; em[1967] = 40; em[1968] = 3; /* 1966: struct.asn1_object_st */
    	em[1969] = 446; em[1970] = 0; 
    	em[1971] = 446; em[1972] = 8; 
    	em[1973] = 1288; em[1974] = 24; 
    em[1975] = 1; em[1976] = 8; em[1977] = 1; /* 1975: pointer.struct.asn1_string_st */
    	em[1978] = 1980; em[1979] = 0; 
    em[1980] = 0; em[1981] = 24; em[1982] = 1; /* 1980: struct.asn1_string_st */
    	em[1983] = 254; em[1984] = 8; 
    em[1985] = 1; em[1986] = 8; em[1987] = 1; /* 1985: pointer.struct.buf_mem_st */
    	em[1988] = 1906; em[1989] = 0; 
    em[1990] = 1; em[1991] = 8; em[1992] = 1; /* 1990: pointer.struct.asn1_string_st */
    	em[1993] = 1901; em[1994] = 0; 
    em[1995] = 1; em[1996] = 8; em[1997] = 1; /* 1995: pointer.struct.asn1_string_st */
    	em[1998] = 1901; em[1999] = 0; 
    em[2000] = 1; em[2001] = 8; em[2002] = 1; /* 2000: pointer.struct.asn1_string_st */
    	em[2003] = 1901; em[2004] = 0; 
    em[2005] = 1; em[2006] = 8; em[2007] = 1; /* 2005: pointer.struct.asn1_string_st */
    	em[2008] = 1901; em[2009] = 0; 
    em[2010] = 1; em[2011] = 8; em[2012] = 1; /* 2010: pointer.struct.asn1_string_st */
    	em[2013] = 1901; em[2014] = 0; 
    em[2015] = 1; em[2016] = 8; em[2017] = 1; /* 2015: pointer.struct.asn1_string_st */
    	em[2018] = 1901; em[2019] = 0; 
    em[2020] = 0; em[2021] = 40; em[2022] = 3; /* 2020: struct.asn1_object_st */
    	em[2023] = 446; em[2024] = 0; 
    	em[2025] = 446; em[2026] = 8; 
    	em[2027] = 1288; em[2028] = 24; 
    em[2029] = 1; em[2030] = 8; em[2031] = 1; /* 2029: pointer.struct.asn1_object_st */
    	em[2032] = 2020; em[2033] = 0; 
    em[2034] = 0; em[2035] = 16; em[2036] = 2; /* 2034: struct.otherName_st */
    	em[2037] = 2029; em[2038] = 0; 
    	em[2039] = 2041; em[2040] = 8; 
    em[2041] = 1; em[2042] = 8; em[2043] = 1; /* 2041: pointer.struct.asn1_type_st */
    	em[2044] = 2046; em[2045] = 0; 
    em[2046] = 0; em[2047] = 16; em[2048] = 1; /* 2046: struct.asn1_type_st */
    	em[2049] = 2051; em[2050] = 8; 
    em[2051] = 0; em[2052] = 8; em[2053] = 20; /* 2051: union.unknown */
    	em[2054] = 460; em[2055] = 0; 
    	em[2056] = 1896; em[2057] = 0; 
    	em[2058] = 2029; em[2059] = 0; 
    	em[2060] = 2094; em[2061] = 0; 
    	em[2062] = 2099; em[2063] = 0; 
    	em[2064] = 2104; em[2065] = 0; 
    	em[2066] = 2015; em[2067] = 0; 
    	em[2068] = 2010; em[2069] = 0; 
    	em[2070] = 2005; em[2071] = 0; 
    	em[2072] = 2109; em[2073] = 0; 
    	em[2074] = 2114; em[2075] = 0; 
    	em[2076] = 2119; em[2077] = 0; 
    	em[2078] = 2000; em[2079] = 0; 
    	em[2080] = 1995; em[2081] = 0; 
    	em[2082] = 1990; em[2083] = 0; 
    	em[2084] = 2124; em[2085] = 0; 
    	em[2086] = 2129; em[2087] = 0; 
    	em[2088] = 1896; em[2089] = 0; 
    	em[2090] = 1896; em[2091] = 0; 
    	em[2092] = 1473; em[2093] = 0; 
    em[2094] = 1; em[2095] = 8; em[2096] = 1; /* 2094: pointer.struct.asn1_string_st */
    	em[2097] = 1901; em[2098] = 0; 
    em[2099] = 1; em[2100] = 8; em[2101] = 1; /* 2099: pointer.struct.asn1_string_st */
    	em[2102] = 1901; em[2103] = 0; 
    em[2104] = 1; em[2105] = 8; em[2106] = 1; /* 2104: pointer.struct.asn1_string_st */
    	em[2107] = 1901; em[2108] = 0; 
    em[2109] = 1; em[2110] = 8; em[2111] = 1; /* 2109: pointer.struct.asn1_string_st */
    	em[2112] = 1901; em[2113] = 0; 
    em[2114] = 1; em[2115] = 8; em[2116] = 1; /* 2114: pointer.struct.asn1_string_st */
    	em[2117] = 1901; em[2118] = 0; 
    em[2119] = 1; em[2120] = 8; em[2121] = 1; /* 2119: pointer.struct.asn1_string_st */
    	em[2122] = 1901; em[2123] = 0; 
    em[2124] = 1; em[2125] = 8; em[2126] = 1; /* 2124: pointer.struct.asn1_string_st */
    	em[2127] = 1901; em[2128] = 0; 
    em[2129] = 1; em[2130] = 8; em[2131] = 1; /* 2129: pointer.struct.asn1_string_st */
    	em[2132] = 1901; em[2133] = 0; 
    em[2134] = 0; em[2135] = 16; em[2136] = 1; /* 2134: struct.GENERAL_NAME_st */
    	em[2137] = 2139; em[2138] = 8; 
    em[2139] = 0; em[2140] = 8; em[2141] = 15; /* 2139: union.unknown */
    	em[2142] = 460; em[2143] = 0; 
    	em[2144] = 2172; em[2145] = 0; 
    	em[2146] = 2109; em[2147] = 0; 
    	em[2148] = 2109; em[2149] = 0; 
    	em[2150] = 2041; em[2151] = 0; 
    	em[2152] = 1911; em[2153] = 0; 
    	em[2154] = 1884; em[2155] = 0; 
    	em[2156] = 2109; em[2157] = 0; 
    	em[2158] = 2015; em[2159] = 0; 
    	em[2160] = 2029; em[2161] = 0; 
    	em[2162] = 2015; em[2163] = 0; 
    	em[2164] = 1911; em[2165] = 0; 
    	em[2166] = 2109; em[2167] = 0; 
    	em[2168] = 2029; em[2169] = 0; 
    	em[2170] = 2041; em[2171] = 0; 
    em[2172] = 1; em[2173] = 8; em[2174] = 1; /* 2172: pointer.struct.otherName_st */
    	em[2175] = 2034; em[2176] = 0; 
    em[2177] = 1; em[2178] = 8; em[2179] = 1; /* 2177: pointer.struct.GENERAL_NAME_st */
    	em[2180] = 2134; em[2181] = 0; 
    em[2182] = 0; em[2183] = 24; em[2184] = 3; /* 2182: struct.GENERAL_SUBTREE_st */
    	em[2185] = 2177; em[2186] = 0; 
    	em[2187] = 2094; em[2188] = 8; 
    	em[2189] = 2094; em[2190] = 16; 
    em[2191] = 0; em[2192] = 0; em[2193] = 1; /* 2191: GENERAL_SUBTREE */
    	em[2194] = 2182; em[2195] = 0; 
    em[2196] = 0; em[2197] = 16; em[2198] = 2; /* 2196: struct.NAME_CONSTRAINTS_st */
    	em[2199] = 2203; em[2200] = 0; 
    	em[2201] = 2203; em[2202] = 8; 
    em[2203] = 1; em[2204] = 8; em[2205] = 1; /* 2203: pointer.struct.stack_st_GENERAL_SUBTREE */
    	em[2206] = 2208; em[2207] = 0; 
    em[2208] = 0; em[2209] = 32; em[2210] = 2; /* 2208: struct.stack_st_fake_GENERAL_SUBTREE */
    	em[2211] = 2215; em[2212] = 8; 
    	em[2213] = 419; em[2214] = 24; 
    em[2215] = 8884099; em[2216] = 8; em[2217] = 2; /* 2215: pointer_to_array_of_pointers_to_stack */
    	em[2218] = 2222; em[2219] = 0; 
    	em[2220] = 251; em[2221] = 20; 
    em[2222] = 0; em[2223] = 8; em[2224] = 1; /* 2222: pointer.GENERAL_SUBTREE */
    	em[2225] = 2191; em[2226] = 0; 
    em[2227] = 1; em[2228] = 8; em[2229] = 1; /* 2227: pointer.struct.asn1_string_st */
    	em[2230] = 2232; em[2231] = 0; 
    em[2232] = 0; em[2233] = 24; em[2234] = 1; /* 2232: struct.asn1_string_st */
    	em[2235] = 254; em[2236] = 8; 
    em[2237] = 1; em[2238] = 8; em[2239] = 1; /* 2237: pointer.struct.buf_mem_st */
    	em[2240] = 2242; em[2241] = 0; 
    em[2242] = 0; em[2243] = 24; em[2244] = 1; /* 2242: struct.buf_mem_st */
    	em[2245] = 460; em[2246] = 8; 
    em[2247] = 0; em[2248] = 40; em[2249] = 3; /* 2247: struct.X509_name_st */
    	em[2250] = 2256; em[2251] = 0; 
    	em[2252] = 2237; em[2253] = 16; 
    	em[2254] = 254; em[2255] = 24; 
    em[2256] = 1; em[2257] = 8; em[2258] = 1; /* 2256: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[2259] = 2261; em[2260] = 0; 
    em[2261] = 0; em[2262] = 32; em[2263] = 2; /* 2261: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[2264] = 2268; em[2265] = 8; 
    	em[2266] = 419; em[2267] = 24; 
    em[2268] = 8884099; em[2269] = 8; em[2270] = 2; /* 2268: pointer_to_array_of_pointers_to_stack */
    	em[2271] = 2275; em[2272] = 0; 
    	em[2273] = 251; em[2274] = 20; 
    em[2275] = 0; em[2276] = 8; em[2277] = 1; /* 2275: pointer.X509_NAME_ENTRY */
    	em[2278] = 1949; em[2279] = 0; 
    em[2280] = 1; em[2281] = 8; em[2282] = 1; /* 2280: pointer.struct.DIST_POINT_NAME_st */
    	em[2283] = 2285; em[2284] = 0; 
    em[2285] = 0; em[2286] = 24; em[2287] = 2; /* 2285: struct.DIST_POINT_NAME_st */
    	em[2288] = 2292; em[2289] = 8; 
    	em[2290] = 2593; em[2291] = 16; 
    em[2292] = 0; em[2293] = 8; em[2294] = 2; /* 2292: union.unknown */
    	em[2295] = 2299; em[2296] = 0; 
    	em[2297] = 2256; em[2298] = 0; 
    em[2299] = 1; em[2300] = 8; em[2301] = 1; /* 2299: pointer.struct.stack_st_GENERAL_NAME */
    	em[2302] = 2304; em[2303] = 0; 
    em[2304] = 0; em[2305] = 32; em[2306] = 2; /* 2304: struct.stack_st_fake_GENERAL_NAME */
    	em[2307] = 2311; em[2308] = 8; 
    	em[2309] = 419; em[2310] = 24; 
    em[2311] = 8884099; em[2312] = 8; em[2313] = 2; /* 2311: pointer_to_array_of_pointers_to_stack */
    	em[2314] = 2318; em[2315] = 0; 
    	em[2316] = 251; em[2317] = 20; 
    em[2318] = 0; em[2319] = 8; em[2320] = 1; /* 2318: pointer.GENERAL_NAME */
    	em[2321] = 2323; em[2322] = 0; 
    em[2323] = 0; em[2324] = 0; em[2325] = 1; /* 2323: GENERAL_NAME */
    	em[2326] = 2328; em[2327] = 0; 
    em[2328] = 0; em[2329] = 16; em[2330] = 1; /* 2328: struct.GENERAL_NAME_st */
    	em[2331] = 2333; em[2332] = 8; 
    em[2333] = 0; em[2334] = 8; em[2335] = 15; /* 2333: union.unknown */
    	em[2336] = 460; em[2337] = 0; 
    	em[2338] = 2366; em[2339] = 0; 
    	em[2340] = 2485; em[2341] = 0; 
    	em[2342] = 2485; em[2343] = 0; 
    	em[2344] = 2392; em[2345] = 0; 
    	em[2346] = 2533; em[2347] = 0; 
    	em[2348] = 2581; em[2349] = 0; 
    	em[2350] = 2485; em[2351] = 0; 
    	em[2352] = 2470; em[2353] = 0; 
    	em[2354] = 2378; em[2355] = 0; 
    	em[2356] = 2470; em[2357] = 0; 
    	em[2358] = 2533; em[2359] = 0; 
    	em[2360] = 2485; em[2361] = 0; 
    	em[2362] = 2378; em[2363] = 0; 
    	em[2364] = 2392; em[2365] = 0; 
    em[2366] = 1; em[2367] = 8; em[2368] = 1; /* 2366: pointer.struct.otherName_st */
    	em[2369] = 2371; em[2370] = 0; 
    em[2371] = 0; em[2372] = 16; em[2373] = 2; /* 2371: struct.otherName_st */
    	em[2374] = 2378; em[2375] = 0; 
    	em[2376] = 2392; em[2377] = 8; 
    em[2378] = 1; em[2379] = 8; em[2380] = 1; /* 2378: pointer.struct.asn1_object_st */
    	em[2381] = 2383; em[2382] = 0; 
    em[2383] = 0; em[2384] = 40; em[2385] = 3; /* 2383: struct.asn1_object_st */
    	em[2386] = 446; em[2387] = 0; 
    	em[2388] = 446; em[2389] = 8; 
    	em[2390] = 1288; em[2391] = 24; 
    em[2392] = 1; em[2393] = 8; em[2394] = 1; /* 2392: pointer.struct.asn1_type_st */
    	em[2395] = 2397; em[2396] = 0; 
    em[2397] = 0; em[2398] = 16; em[2399] = 1; /* 2397: struct.asn1_type_st */
    	em[2400] = 2402; em[2401] = 8; 
    em[2402] = 0; em[2403] = 8; em[2404] = 20; /* 2402: union.unknown */
    	em[2405] = 460; em[2406] = 0; 
    	em[2407] = 2445; em[2408] = 0; 
    	em[2409] = 2378; em[2410] = 0; 
    	em[2411] = 2455; em[2412] = 0; 
    	em[2413] = 2460; em[2414] = 0; 
    	em[2415] = 2465; em[2416] = 0; 
    	em[2417] = 2470; em[2418] = 0; 
    	em[2419] = 2475; em[2420] = 0; 
    	em[2421] = 2480; em[2422] = 0; 
    	em[2423] = 2485; em[2424] = 0; 
    	em[2425] = 2490; em[2426] = 0; 
    	em[2427] = 2495; em[2428] = 0; 
    	em[2429] = 2500; em[2430] = 0; 
    	em[2431] = 2505; em[2432] = 0; 
    	em[2433] = 2510; em[2434] = 0; 
    	em[2435] = 2515; em[2436] = 0; 
    	em[2437] = 2520; em[2438] = 0; 
    	em[2439] = 2445; em[2440] = 0; 
    	em[2441] = 2445; em[2442] = 0; 
    	em[2443] = 2525; em[2444] = 0; 
    em[2445] = 1; em[2446] = 8; em[2447] = 1; /* 2445: pointer.struct.asn1_string_st */
    	em[2448] = 2450; em[2449] = 0; 
    em[2450] = 0; em[2451] = 24; em[2452] = 1; /* 2450: struct.asn1_string_st */
    	em[2453] = 254; em[2454] = 8; 
    em[2455] = 1; em[2456] = 8; em[2457] = 1; /* 2455: pointer.struct.asn1_string_st */
    	em[2458] = 2450; em[2459] = 0; 
    em[2460] = 1; em[2461] = 8; em[2462] = 1; /* 2460: pointer.struct.asn1_string_st */
    	em[2463] = 2450; em[2464] = 0; 
    em[2465] = 1; em[2466] = 8; em[2467] = 1; /* 2465: pointer.struct.asn1_string_st */
    	em[2468] = 2450; em[2469] = 0; 
    em[2470] = 1; em[2471] = 8; em[2472] = 1; /* 2470: pointer.struct.asn1_string_st */
    	em[2473] = 2450; em[2474] = 0; 
    em[2475] = 1; em[2476] = 8; em[2477] = 1; /* 2475: pointer.struct.asn1_string_st */
    	em[2478] = 2450; em[2479] = 0; 
    em[2480] = 1; em[2481] = 8; em[2482] = 1; /* 2480: pointer.struct.asn1_string_st */
    	em[2483] = 2450; em[2484] = 0; 
    em[2485] = 1; em[2486] = 8; em[2487] = 1; /* 2485: pointer.struct.asn1_string_st */
    	em[2488] = 2450; em[2489] = 0; 
    em[2490] = 1; em[2491] = 8; em[2492] = 1; /* 2490: pointer.struct.asn1_string_st */
    	em[2493] = 2450; em[2494] = 0; 
    em[2495] = 1; em[2496] = 8; em[2497] = 1; /* 2495: pointer.struct.asn1_string_st */
    	em[2498] = 2450; em[2499] = 0; 
    em[2500] = 1; em[2501] = 8; em[2502] = 1; /* 2500: pointer.struct.asn1_string_st */
    	em[2503] = 2450; em[2504] = 0; 
    em[2505] = 1; em[2506] = 8; em[2507] = 1; /* 2505: pointer.struct.asn1_string_st */
    	em[2508] = 2450; em[2509] = 0; 
    em[2510] = 1; em[2511] = 8; em[2512] = 1; /* 2510: pointer.struct.asn1_string_st */
    	em[2513] = 2450; em[2514] = 0; 
    em[2515] = 1; em[2516] = 8; em[2517] = 1; /* 2515: pointer.struct.asn1_string_st */
    	em[2518] = 2450; em[2519] = 0; 
    em[2520] = 1; em[2521] = 8; em[2522] = 1; /* 2520: pointer.struct.asn1_string_st */
    	em[2523] = 2450; em[2524] = 0; 
    em[2525] = 1; em[2526] = 8; em[2527] = 1; /* 2525: pointer.struct.ASN1_VALUE_st */
    	em[2528] = 2530; em[2529] = 0; 
    em[2530] = 0; em[2531] = 0; em[2532] = 0; /* 2530: struct.ASN1_VALUE_st */
    em[2533] = 1; em[2534] = 8; em[2535] = 1; /* 2533: pointer.struct.X509_name_st */
    	em[2536] = 2538; em[2537] = 0; 
    em[2538] = 0; em[2539] = 40; em[2540] = 3; /* 2538: struct.X509_name_st */
    	em[2541] = 2547; em[2542] = 0; 
    	em[2543] = 2571; em[2544] = 16; 
    	em[2545] = 254; em[2546] = 24; 
    em[2547] = 1; em[2548] = 8; em[2549] = 1; /* 2547: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[2550] = 2552; em[2551] = 0; 
    em[2552] = 0; em[2553] = 32; em[2554] = 2; /* 2552: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[2555] = 2559; em[2556] = 8; 
    	em[2557] = 419; em[2558] = 24; 
    em[2559] = 8884099; em[2560] = 8; em[2561] = 2; /* 2559: pointer_to_array_of_pointers_to_stack */
    	em[2562] = 2566; em[2563] = 0; 
    	em[2564] = 251; em[2565] = 20; 
    em[2566] = 0; em[2567] = 8; em[2568] = 1; /* 2566: pointer.X509_NAME_ENTRY */
    	em[2569] = 1949; em[2570] = 0; 
    em[2571] = 1; em[2572] = 8; em[2573] = 1; /* 2571: pointer.struct.buf_mem_st */
    	em[2574] = 2576; em[2575] = 0; 
    em[2576] = 0; em[2577] = 24; em[2578] = 1; /* 2576: struct.buf_mem_st */
    	em[2579] = 460; em[2580] = 8; 
    em[2581] = 1; em[2582] = 8; em[2583] = 1; /* 2581: pointer.struct.EDIPartyName_st */
    	em[2584] = 2586; em[2585] = 0; 
    em[2586] = 0; em[2587] = 16; em[2588] = 2; /* 2586: struct.EDIPartyName_st */
    	em[2589] = 2445; em[2590] = 0; 
    	em[2591] = 2445; em[2592] = 8; 
    em[2593] = 1; em[2594] = 8; em[2595] = 1; /* 2593: pointer.struct.X509_name_st */
    	em[2596] = 2247; em[2597] = 0; 
    em[2598] = 0; em[2599] = 0; em[2600] = 1; /* 2598: DIST_POINT */
    	em[2601] = 2603; em[2602] = 0; 
    em[2603] = 0; em[2604] = 32; em[2605] = 3; /* 2603: struct.DIST_POINT_st */
    	em[2606] = 2280; em[2607] = 0; 
    	em[2608] = 2227; em[2609] = 8; 
    	em[2610] = 2299; em[2611] = 16; 
    em[2612] = 1; em[2613] = 8; em[2614] = 1; /* 2612: pointer.struct.stack_st_X509_POLICY_DATA */
    	em[2615] = 2617; em[2616] = 0; 
    em[2617] = 0; em[2618] = 32; em[2619] = 2; /* 2617: struct.stack_st_fake_X509_POLICY_DATA */
    	em[2620] = 2624; em[2621] = 8; 
    	em[2622] = 419; em[2623] = 24; 
    em[2624] = 8884099; em[2625] = 8; em[2626] = 2; /* 2624: pointer_to_array_of_pointers_to_stack */
    	em[2627] = 2631; em[2628] = 0; 
    	em[2629] = 251; em[2630] = 20; 
    em[2631] = 0; em[2632] = 8; em[2633] = 1; /* 2631: pointer.X509_POLICY_DATA */
    	em[2634] = 2636; em[2635] = 0; 
    em[2636] = 0; em[2637] = 0; em[2638] = 1; /* 2636: X509_POLICY_DATA */
    	em[2639] = 2641; em[2640] = 0; 
    em[2641] = 0; em[2642] = 32; em[2643] = 3; /* 2641: struct.X509_POLICY_DATA_st */
    	em[2644] = 2650; em[2645] = 8; 
    	em[2646] = 2664; em[2647] = 16; 
    	em[2648] = 2914; em[2649] = 24; 
    em[2650] = 1; em[2651] = 8; em[2652] = 1; /* 2650: pointer.struct.asn1_object_st */
    	em[2653] = 2655; em[2654] = 0; 
    em[2655] = 0; em[2656] = 40; em[2657] = 3; /* 2655: struct.asn1_object_st */
    	em[2658] = 446; em[2659] = 0; 
    	em[2660] = 446; em[2661] = 8; 
    	em[2662] = 1288; em[2663] = 24; 
    em[2664] = 1; em[2665] = 8; em[2666] = 1; /* 2664: pointer.struct.stack_st_POLICYQUALINFO */
    	em[2667] = 2669; em[2668] = 0; 
    em[2669] = 0; em[2670] = 32; em[2671] = 2; /* 2669: struct.stack_st_fake_POLICYQUALINFO */
    	em[2672] = 2676; em[2673] = 8; 
    	em[2674] = 419; em[2675] = 24; 
    em[2676] = 8884099; em[2677] = 8; em[2678] = 2; /* 2676: pointer_to_array_of_pointers_to_stack */
    	em[2679] = 2683; em[2680] = 0; 
    	em[2681] = 251; em[2682] = 20; 
    em[2683] = 0; em[2684] = 8; em[2685] = 1; /* 2683: pointer.POLICYQUALINFO */
    	em[2686] = 2688; em[2687] = 0; 
    em[2688] = 0; em[2689] = 0; em[2690] = 1; /* 2688: POLICYQUALINFO */
    	em[2691] = 2693; em[2692] = 0; 
    em[2693] = 0; em[2694] = 16; em[2695] = 2; /* 2693: struct.POLICYQUALINFO_st */
    	em[2696] = 2700; em[2697] = 0; 
    	em[2698] = 2714; em[2699] = 8; 
    em[2700] = 1; em[2701] = 8; em[2702] = 1; /* 2700: pointer.struct.asn1_object_st */
    	em[2703] = 2705; em[2704] = 0; 
    em[2705] = 0; em[2706] = 40; em[2707] = 3; /* 2705: struct.asn1_object_st */
    	em[2708] = 446; em[2709] = 0; 
    	em[2710] = 446; em[2711] = 8; 
    	em[2712] = 1288; em[2713] = 24; 
    em[2714] = 0; em[2715] = 8; em[2716] = 3; /* 2714: union.unknown */
    	em[2717] = 2723; em[2718] = 0; 
    	em[2719] = 2733; em[2720] = 0; 
    	em[2721] = 2796; em[2722] = 0; 
    em[2723] = 1; em[2724] = 8; em[2725] = 1; /* 2723: pointer.struct.asn1_string_st */
    	em[2726] = 2728; em[2727] = 0; 
    em[2728] = 0; em[2729] = 24; em[2730] = 1; /* 2728: struct.asn1_string_st */
    	em[2731] = 254; em[2732] = 8; 
    em[2733] = 1; em[2734] = 8; em[2735] = 1; /* 2733: pointer.struct.USERNOTICE_st */
    	em[2736] = 2738; em[2737] = 0; 
    em[2738] = 0; em[2739] = 16; em[2740] = 2; /* 2738: struct.USERNOTICE_st */
    	em[2741] = 2745; em[2742] = 0; 
    	em[2743] = 2757; em[2744] = 8; 
    em[2745] = 1; em[2746] = 8; em[2747] = 1; /* 2745: pointer.struct.NOTICEREF_st */
    	em[2748] = 2750; em[2749] = 0; 
    em[2750] = 0; em[2751] = 16; em[2752] = 2; /* 2750: struct.NOTICEREF_st */
    	em[2753] = 2757; em[2754] = 0; 
    	em[2755] = 2762; em[2756] = 8; 
    em[2757] = 1; em[2758] = 8; em[2759] = 1; /* 2757: pointer.struct.asn1_string_st */
    	em[2760] = 2728; em[2761] = 0; 
    em[2762] = 1; em[2763] = 8; em[2764] = 1; /* 2762: pointer.struct.stack_st_ASN1_INTEGER */
    	em[2765] = 2767; em[2766] = 0; 
    em[2767] = 0; em[2768] = 32; em[2769] = 2; /* 2767: struct.stack_st_fake_ASN1_INTEGER */
    	em[2770] = 2774; em[2771] = 8; 
    	em[2772] = 419; em[2773] = 24; 
    em[2774] = 8884099; em[2775] = 8; em[2776] = 2; /* 2774: pointer_to_array_of_pointers_to_stack */
    	em[2777] = 2781; em[2778] = 0; 
    	em[2779] = 251; em[2780] = 20; 
    em[2781] = 0; em[2782] = 8; em[2783] = 1; /* 2781: pointer.ASN1_INTEGER */
    	em[2784] = 2786; em[2785] = 0; 
    em[2786] = 0; em[2787] = 0; em[2788] = 1; /* 2786: ASN1_INTEGER */
    	em[2789] = 2791; em[2790] = 0; 
    em[2791] = 0; em[2792] = 24; em[2793] = 1; /* 2791: struct.asn1_string_st */
    	em[2794] = 254; em[2795] = 8; 
    em[2796] = 1; em[2797] = 8; em[2798] = 1; /* 2796: pointer.struct.asn1_type_st */
    	em[2799] = 2801; em[2800] = 0; 
    em[2801] = 0; em[2802] = 16; em[2803] = 1; /* 2801: struct.asn1_type_st */
    	em[2804] = 2806; em[2805] = 8; 
    em[2806] = 0; em[2807] = 8; em[2808] = 20; /* 2806: union.unknown */
    	em[2809] = 460; em[2810] = 0; 
    	em[2811] = 2757; em[2812] = 0; 
    	em[2813] = 2700; em[2814] = 0; 
    	em[2815] = 2849; em[2816] = 0; 
    	em[2817] = 2854; em[2818] = 0; 
    	em[2819] = 2859; em[2820] = 0; 
    	em[2821] = 2864; em[2822] = 0; 
    	em[2823] = 2869; em[2824] = 0; 
    	em[2825] = 2874; em[2826] = 0; 
    	em[2827] = 2723; em[2828] = 0; 
    	em[2829] = 2879; em[2830] = 0; 
    	em[2831] = 2884; em[2832] = 0; 
    	em[2833] = 2889; em[2834] = 0; 
    	em[2835] = 2894; em[2836] = 0; 
    	em[2837] = 2899; em[2838] = 0; 
    	em[2839] = 2904; em[2840] = 0; 
    	em[2841] = 2909; em[2842] = 0; 
    	em[2843] = 2757; em[2844] = 0; 
    	em[2845] = 2757; em[2846] = 0; 
    	em[2847] = 1473; em[2848] = 0; 
    em[2849] = 1; em[2850] = 8; em[2851] = 1; /* 2849: pointer.struct.asn1_string_st */
    	em[2852] = 2728; em[2853] = 0; 
    em[2854] = 1; em[2855] = 8; em[2856] = 1; /* 2854: pointer.struct.asn1_string_st */
    	em[2857] = 2728; em[2858] = 0; 
    em[2859] = 1; em[2860] = 8; em[2861] = 1; /* 2859: pointer.struct.asn1_string_st */
    	em[2862] = 2728; em[2863] = 0; 
    em[2864] = 1; em[2865] = 8; em[2866] = 1; /* 2864: pointer.struct.asn1_string_st */
    	em[2867] = 2728; em[2868] = 0; 
    em[2869] = 1; em[2870] = 8; em[2871] = 1; /* 2869: pointer.struct.asn1_string_st */
    	em[2872] = 2728; em[2873] = 0; 
    em[2874] = 1; em[2875] = 8; em[2876] = 1; /* 2874: pointer.struct.asn1_string_st */
    	em[2877] = 2728; em[2878] = 0; 
    em[2879] = 1; em[2880] = 8; em[2881] = 1; /* 2879: pointer.struct.asn1_string_st */
    	em[2882] = 2728; em[2883] = 0; 
    em[2884] = 1; em[2885] = 8; em[2886] = 1; /* 2884: pointer.struct.asn1_string_st */
    	em[2887] = 2728; em[2888] = 0; 
    em[2889] = 1; em[2890] = 8; em[2891] = 1; /* 2889: pointer.struct.asn1_string_st */
    	em[2892] = 2728; em[2893] = 0; 
    em[2894] = 1; em[2895] = 8; em[2896] = 1; /* 2894: pointer.struct.asn1_string_st */
    	em[2897] = 2728; em[2898] = 0; 
    em[2899] = 1; em[2900] = 8; em[2901] = 1; /* 2899: pointer.struct.asn1_string_st */
    	em[2902] = 2728; em[2903] = 0; 
    em[2904] = 1; em[2905] = 8; em[2906] = 1; /* 2904: pointer.struct.asn1_string_st */
    	em[2907] = 2728; em[2908] = 0; 
    em[2909] = 1; em[2910] = 8; em[2911] = 1; /* 2909: pointer.struct.asn1_string_st */
    	em[2912] = 2728; em[2913] = 0; 
    em[2914] = 1; em[2915] = 8; em[2916] = 1; /* 2914: pointer.struct.stack_st_ASN1_OBJECT */
    	em[2917] = 2919; em[2918] = 0; 
    em[2919] = 0; em[2920] = 32; em[2921] = 2; /* 2919: struct.stack_st_fake_ASN1_OBJECT */
    	em[2922] = 2926; em[2923] = 8; 
    	em[2924] = 419; em[2925] = 24; 
    em[2926] = 8884099; em[2927] = 8; em[2928] = 2; /* 2926: pointer_to_array_of_pointers_to_stack */
    	em[2929] = 2933; em[2930] = 0; 
    	em[2931] = 251; em[2932] = 20; 
    em[2933] = 0; em[2934] = 8; em[2935] = 1; /* 2933: pointer.ASN1_OBJECT */
    	em[2936] = 1837; em[2937] = 0; 
    em[2938] = 1; em[2939] = 8; em[2940] = 1; /* 2938: pointer.struct.asn1_string_st */
    	em[2941] = 2943; em[2942] = 0; 
    em[2943] = 0; em[2944] = 24; em[2945] = 1; /* 2943: struct.asn1_string_st */
    	em[2946] = 254; em[2947] = 8; 
    em[2948] = 1; em[2949] = 8; em[2950] = 1; /* 2948: pointer.struct.asn1_string_st */
    	em[2951] = 2943; em[2952] = 0; 
    em[2953] = 1; em[2954] = 8; em[2955] = 1; /* 2953: pointer.struct.AUTHORITY_KEYID_st */
    	em[2956] = 2958; em[2957] = 0; 
    em[2958] = 0; em[2959] = 24; em[2960] = 3; /* 2958: struct.AUTHORITY_KEYID_st */
    	em[2961] = 2948; em[2962] = 0; 
    	em[2963] = 2967; em[2964] = 8; 
    	em[2965] = 2938; em[2966] = 16; 
    em[2967] = 1; em[2968] = 8; em[2969] = 1; /* 2967: pointer.struct.stack_st_GENERAL_NAME */
    	em[2970] = 2972; em[2971] = 0; 
    em[2972] = 0; em[2973] = 32; em[2974] = 2; /* 2972: struct.stack_st_fake_GENERAL_NAME */
    	em[2975] = 2979; em[2976] = 8; 
    	em[2977] = 419; em[2978] = 24; 
    em[2979] = 8884099; em[2980] = 8; em[2981] = 2; /* 2979: pointer_to_array_of_pointers_to_stack */
    	em[2982] = 2986; em[2983] = 0; 
    	em[2984] = 251; em[2985] = 20; 
    em[2986] = 0; em[2987] = 8; em[2988] = 1; /* 2986: pointer.GENERAL_NAME */
    	em[2989] = 2323; em[2990] = 0; 
    em[2991] = 0; em[2992] = 24; em[2993] = 1; /* 2991: struct.ASN1_ENCODING_st */
    	em[2994] = 254; em[2995] = 0; 
    em[2996] = 0; em[2997] = 40; em[2998] = 3; /* 2996: struct.asn1_object_st */
    	em[2999] = 446; em[3000] = 0; 
    	em[3001] = 446; em[3002] = 8; 
    	em[3003] = 1288; em[3004] = 24; 
    em[3005] = 1; em[3006] = 8; em[3007] = 1; /* 3005: pointer.struct.asn1_object_st */
    	em[3008] = 2996; em[3009] = 0; 
    em[3010] = 1; em[3011] = 8; em[3012] = 1; /* 3010: pointer.struct.asn1_string_st */
    	em[3013] = 1869; em[3014] = 0; 
    em[3015] = 0; em[3016] = 0; em[3017] = 1; /* 3015: X509_EXTENSION */
    	em[3018] = 3020; em[3019] = 0; 
    em[3020] = 0; em[3021] = 24; em[3022] = 2; /* 3020: struct.X509_extension_st */
    	em[3023] = 3005; em[3024] = 0; 
    	em[3025] = 3027; em[3026] = 16; 
    em[3027] = 1; em[3028] = 8; em[3029] = 1; /* 3027: pointer.struct.asn1_string_st */
    	em[3030] = 3032; em[3031] = 0; 
    em[3032] = 0; em[3033] = 24; em[3034] = 1; /* 3032: struct.asn1_string_st */
    	em[3035] = 254; em[3036] = 8; 
    em[3037] = 1; em[3038] = 8; em[3039] = 1; /* 3037: pointer.struct.X509_POLICY_DATA_st */
    	em[3040] = 2641; em[3041] = 0; 
    em[3042] = 0; em[3043] = 40; em[3044] = 2; /* 3042: struct.X509_POLICY_CACHE_st */
    	em[3045] = 3037; em[3046] = 0; 
    	em[3047] = 2612; em[3048] = 8; 
    em[3049] = 1; em[3050] = 8; em[3051] = 1; /* 3049: pointer.struct.evp_pkey_st */
    	em[3052] = 1111; em[3053] = 0; 
    em[3054] = 1; em[3055] = 8; em[3056] = 1; /* 3054: pointer.struct.x509_st */
    	em[3057] = 3059; em[3058] = 0; 
    em[3059] = 0; em[3060] = 184; em[3061] = 12; /* 3059: struct.x509_st */
    	em[3062] = 3086; em[3063] = 0; 
    	em[3064] = 3121; em[3065] = 8; 
    	em[3066] = 3010; em[3067] = 16; 
    	em[3068] = 460; em[3069] = 32; 
    	em[3070] = 3324; em[3071] = 40; 
    	em[3072] = 1874; em[3073] = 104; 
    	em[3074] = 2953; em[3075] = 112; 
    	em[3076] = 3338; em[3077] = 120; 
    	em[3078] = 3343; em[3079] = 128; 
    	em[3080] = 3367; em[3081] = 136; 
    	em[3082] = 3391; em[3083] = 144; 
    	em[3084] = 1879; em[3085] = 176; 
    em[3086] = 1; em[3087] = 8; em[3088] = 1; /* 3086: pointer.struct.x509_cinf_st */
    	em[3089] = 3091; em[3090] = 0; 
    em[3091] = 0; em[3092] = 104; em[3093] = 11; /* 3091: struct.x509_cinf_st */
    	em[3094] = 3116; em[3095] = 0; 
    	em[3096] = 3116; em[3097] = 8; 
    	em[3098] = 3121; em[3099] = 16; 
    	em[3100] = 3126; em[3101] = 24; 
    	em[3102] = 3174; em[3103] = 32; 
    	em[3104] = 3126; em[3105] = 40; 
    	em[3106] = 3191; em[3107] = 48; 
    	em[3108] = 3010; em[3109] = 56; 
    	em[3110] = 3010; em[3111] = 64; 
    	em[3112] = 3300; em[3113] = 72; 
    	em[3114] = 2991; em[3115] = 80; 
    em[3116] = 1; em[3117] = 8; em[3118] = 1; /* 3116: pointer.struct.asn1_string_st */
    	em[3119] = 1869; em[3120] = 0; 
    em[3121] = 1; em[3122] = 8; em[3123] = 1; /* 3121: pointer.struct.X509_algor_st */
    	em[3124] = 1651; em[3125] = 0; 
    em[3126] = 1; em[3127] = 8; em[3128] = 1; /* 3126: pointer.struct.X509_name_st */
    	em[3129] = 3131; em[3130] = 0; 
    em[3131] = 0; em[3132] = 40; em[3133] = 3; /* 3131: struct.X509_name_st */
    	em[3134] = 3140; em[3135] = 0; 
    	em[3136] = 3164; em[3137] = 16; 
    	em[3138] = 254; em[3139] = 24; 
    em[3140] = 1; em[3141] = 8; em[3142] = 1; /* 3140: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[3143] = 3145; em[3144] = 0; 
    em[3145] = 0; em[3146] = 32; em[3147] = 2; /* 3145: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[3148] = 3152; em[3149] = 8; 
    	em[3150] = 419; em[3151] = 24; 
    em[3152] = 8884099; em[3153] = 8; em[3154] = 2; /* 3152: pointer_to_array_of_pointers_to_stack */
    	em[3155] = 3159; em[3156] = 0; 
    	em[3157] = 251; em[3158] = 20; 
    em[3159] = 0; em[3160] = 8; em[3161] = 1; /* 3159: pointer.X509_NAME_ENTRY */
    	em[3162] = 1949; em[3163] = 0; 
    em[3164] = 1; em[3165] = 8; em[3166] = 1; /* 3164: pointer.struct.buf_mem_st */
    	em[3167] = 3169; em[3168] = 0; 
    em[3169] = 0; em[3170] = 24; em[3171] = 1; /* 3169: struct.buf_mem_st */
    	em[3172] = 460; em[3173] = 8; 
    em[3174] = 1; em[3175] = 8; em[3176] = 1; /* 3174: pointer.struct.X509_val_st */
    	em[3177] = 3179; em[3178] = 0; 
    em[3179] = 0; em[3180] = 16; em[3181] = 2; /* 3179: struct.X509_val_st */
    	em[3182] = 3186; em[3183] = 0; 
    	em[3184] = 3186; em[3185] = 8; 
    em[3186] = 1; em[3187] = 8; em[3188] = 1; /* 3186: pointer.struct.asn1_string_st */
    	em[3189] = 1869; em[3190] = 0; 
    em[3191] = 1; em[3192] = 8; em[3193] = 1; /* 3191: pointer.struct.X509_pubkey_st */
    	em[3194] = 3196; em[3195] = 0; 
    em[3196] = 0; em[3197] = 24; em[3198] = 3; /* 3196: struct.X509_pubkey_st */
    	em[3199] = 3205; em[3200] = 0; 
    	em[3201] = 3210; em[3202] = 8; 
    	em[3203] = 3215; em[3204] = 16; 
    em[3205] = 1; em[3206] = 8; em[3207] = 1; /* 3205: pointer.struct.X509_algor_st */
    	em[3208] = 1651; em[3209] = 0; 
    em[3210] = 1; em[3211] = 8; em[3212] = 1; /* 3210: pointer.struct.asn1_string_st */
    	em[3213] = 2791; em[3214] = 0; 
    em[3215] = 1; em[3216] = 8; em[3217] = 1; /* 3215: pointer.struct.evp_pkey_st */
    	em[3218] = 3220; em[3219] = 0; 
    em[3220] = 0; em[3221] = 56; em[3222] = 4; /* 3220: struct.evp_pkey_st */
    	em[3223] = 3231; em[3224] = 16; 
    	em[3225] = 3236; em[3226] = 24; 
    	em[3227] = 3241; em[3228] = 32; 
    	em[3229] = 3276; em[3230] = 48; 
    em[3231] = 1; em[3232] = 8; em[3233] = 1; /* 3231: pointer.struct.evp_pkey_asn1_method_st */
    	em[3234] = 1127; em[3235] = 0; 
    em[3236] = 1; em[3237] = 8; em[3238] = 1; /* 3236: pointer.struct.engine_st */
    	em[3239] = 473; em[3240] = 0; 
    em[3241] = 8884101; em[3242] = 8; em[3243] = 6; /* 3241: union.union_of_evp_pkey_st */
    	em[3244] = 285; em[3245] = 0; 
    	em[3246] = 3256; em[3247] = 6; 
    	em[3248] = 3261; em[3249] = 116; 
    	em[3250] = 3266; em[3251] = 28; 
    	em[3252] = 3271; em[3253] = 408; 
    	em[3254] = 251; em[3255] = 0; 
    em[3256] = 1; em[3257] = 8; em[3258] = 1; /* 3256: pointer.struct.rsa_st */
    	em[3259] = 944; em[3260] = 0; 
    em[3261] = 1; em[3262] = 8; em[3263] = 1; /* 3261: pointer.struct.dsa_st */
    	em[3264] = 813; em[3265] = 0; 
    em[3266] = 1; em[3267] = 8; em[3268] = 1; /* 3266: pointer.struct.dh_st */
    	em[3269] = 347; em[3270] = 0; 
    em[3271] = 1; em[3272] = 8; em[3273] = 1; /* 3271: pointer.struct.ec_key_st */
    	em[3274] = 5; em[3275] = 0; 
    em[3276] = 1; em[3277] = 8; em[3278] = 1; /* 3276: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[3279] = 3281; em[3280] = 0; 
    em[3281] = 0; em[3282] = 32; em[3283] = 2; /* 3281: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[3284] = 3288; em[3285] = 8; 
    	em[3286] = 419; em[3287] = 24; 
    em[3288] = 8884099; em[3289] = 8; em[3290] = 2; /* 3288: pointer_to_array_of_pointers_to_stack */
    	em[3291] = 3295; em[3292] = 0; 
    	em[3293] = 251; em[3294] = 20; 
    em[3295] = 0; em[3296] = 8; em[3297] = 1; /* 3295: pointer.X509_ATTRIBUTE */
    	em[3298] = 1262; em[3299] = 0; 
    em[3300] = 1; em[3301] = 8; em[3302] = 1; /* 3300: pointer.struct.stack_st_X509_EXTENSION */
    	em[3303] = 3305; em[3304] = 0; 
    em[3305] = 0; em[3306] = 32; em[3307] = 2; /* 3305: struct.stack_st_fake_X509_EXTENSION */
    	em[3308] = 3312; em[3309] = 8; 
    	em[3310] = 419; em[3311] = 24; 
    em[3312] = 8884099; em[3313] = 8; em[3314] = 2; /* 3312: pointer_to_array_of_pointers_to_stack */
    	em[3315] = 3319; em[3316] = 0; 
    	em[3317] = 251; em[3318] = 20; 
    em[3319] = 0; em[3320] = 8; em[3321] = 1; /* 3319: pointer.X509_EXTENSION */
    	em[3322] = 3015; em[3323] = 0; 
    em[3324] = 0; em[3325] = 32; em[3326] = 2; /* 3324: struct.crypto_ex_data_st_fake */
    	em[3327] = 3331; em[3328] = 8; 
    	em[3329] = 419; em[3330] = 24; 
    em[3331] = 8884099; em[3332] = 8; em[3333] = 2; /* 3331: pointer_to_array_of_pointers_to_stack */
    	em[3334] = 285; em[3335] = 0; 
    	em[3336] = 251; em[3337] = 20; 
    em[3338] = 1; em[3339] = 8; em[3340] = 1; /* 3338: pointer.struct.X509_POLICY_CACHE_st */
    	em[3341] = 3042; em[3342] = 0; 
    em[3343] = 1; em[3344] = 8; em[3345] = 1; /* 3343: pointer.struct.stack_st_DIST_POINT */
    	em[3346] = 3348; em[3347] = 0; 
    em[3348] = 0; em[3349] = 32; em[3350] = 2; /* 3348: struct.stack_st_fake_DIST_POINT */
    	em[3351] = 3355; em[3352] = 8; 
    	em[3353] = 419; em[3354] = 24; 
    em[3355] = 8884099; em[3356] = 8; em[3357] = 2; /* 3355: pointer_to_array_of_pointers_to_stack */
    	em[3358] = 3362; em[3359] = 0; 
    	em[3360] = 251; em[3361] = 20; 
    em[3362] = 0; em[3363] = 8; em[3364] = 1; /* 3362: pointer.DIST_POINT */
    	em[3365] = 2598; em[3366] = 0; 
    em[3367] = 1; em[3368] = 8; em[3369] = 1; /* 3367: pointer.struct.stack_st_GENERAL_NAME */
    	em[3370] = 3372; em[3371] = 0; 
    em[3372] = 0; em[3373] = 32; em[3374] = 2; /* 3372: struct.stack_st_fake_GENERAL_NAME */
    	em[3375] = 3379; em[3376] = 8; 
    	em[3377] = 419; em[3378] = 24; 
    em[3379] = 8884099; em[3380] = 8; em[3381] = 2; /* 3379: pointer_to_array_of_pointers_to_stack */
    	em[3382] = 3386; em[3383] = 0; 
    	em[3384] = 251; em[3385] = 20; 
    em[3386] = 0; em[3387] = 8; em[3388] = 1; /* 3386: pointer.GENERAL_NAME */
    	em[3389] = 2323; em[3390] = 0; 
    em[3391] = 1; em[3392] = 8; em[3393] = 1; /* 3391: pointer.struct.NAME_CONSTRAINTS_st */
    	em[3394] = 2196; em[3395] = 0; 
    em[3396] = 0; em[3397] = 1; em[3398] = 0; /* 3396: char */
    args_addr->arg_entity_index[0] = 3054;
    args_addr->arg_entity_index[1] = 3049;
    args_addr->ret_entity_index = 251;
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

