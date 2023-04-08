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

void * bb_X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d);

void * X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_get_ext_d2i called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_get_ext_d2i(arg_a,arg_b,arg_c,arg_d);
    else {
        void * (*orig_X509_get_ext_d2i)(X509 *,int,int *,int *);
        orig_X509_get_ext_d2i = dlsym(RTLD_NEXT, "X509_get_ext_d2i");
        return orig_X509_get_ext_d2i(arg_a,arg_b,arg_c,arg_d);
    }
}

void * bb_X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d) 
{
    void * ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 1; em[1] = 8; em[2] = 1; /* 0: pointer.struct.x509_cert_aux_st */
    	em[3] = 5; em[4] = 0; 
    em[5] = 0; em[6] = 40; em[7] = 5; /* 5: struct.x509_cert_aux_st */
    	em[8] = 18; em[9] = 0; 
    	em[10] = 18; em[11] = 8; 
    	em[12] = 75; em[13] = 16; 
    	em[14] = 90; em[15] = 24; 
    	em[16] = 95; em[17] = 32; 
    em[18] = 1; em[19] = 8; em[20] = 1; /* 18: pointer.struct.stack_st_ASN1_OBJECT */
    	em[21] = 23; em[22] = 0; 
    em[23] = 0; em[24] = 32; em[25] = 2; /* 23: struct.stack_st_fake_ASN1_OBJECT */
    	em[26] = 30; em[27] = 8; 
    	em[28] = 72; em[29] = 24; 
    em[30] = 8884099; em[31] = 8; em[32] = 2; /* 30: pointer_to_array_of_pointers_to_stack */
    	em[33] = 37; em[34] = 0; 
    	em[35] = 69; em[36] = 20; 
    em[37] = 0; em[38] = 8; em[39] = 1; /* 37: pointer.ASN1_OBJECT */
    	em[40] = 42; em[41] = 0; 
    em[42] = 0; em[43] = 0; em[44] = 1; /* 42: ASN1_OBJECT */
    	em[45] = 47; em[46] = 0; 
    em[47] = 0; em[48] = 40; em[49] = 3; /* 47: struct.asn1_object_st */
    	em[50] = 56; em[51] = 0; 
    	em[52] = 56; em[53] = 8; 
    	em[54] = 61; em[55] = 24; 
    em[56] = 1; em[57] = 8; em[58] = 1; /* 56: pointer.char */
    	em[59] = 8884096; em[60] = 0; 
    em[61] = 1; em[62] = 8; em[63] = 1; /* 61: pointer.unsigned char */
    	em[64] = 66; em[65] = 0; 
    em[66] = 0; em[67] = 1; em[68] = 0; /* 66: unsigned char */
    em[69] = 0; em[70] = 4; em[71] = 0; /* 69: int */
    em[72] = 8884097; em[73] = 8; em[74] = 0; /* 72: pointer.func */
    em[75] = 1; em[76] = 8; em[77] = 1; /* 75: pointer.struct.asn1_string_st */
    	em[78] = 80; em[79] = 0; 
    em[80] = 0; em[81] = 24; em[82] = 1; /* 80: struct.asn1_string_st */
    	em[83] = 85; em[84] = 8; 
    em[85] = 1; em[86] = 8; em[87] = 1; /* 85: pointer.unsigned char */
    	em[88] = 66; em[89] = 0; 
    em[90] = 1; em[91] = 8; em[92] = 1; /* 90: pointer.struct.asn1_string_st */
    	em[93] = 80; em[94] = 0; 
    em[95] = 1; em[96] = 8; em[97] = 1; /* 95: pointer.struct.stack_st_X509_ALGOR */
    	em[98] = 100; em[99] = 0; 
    em[100] = 0; em[101] = 32; em[102] = 2; /* 100: struct.stack_st_fake_X509_ALGOR */
    	em[103] = 107; em[104] = 8; 
    	em[105] = 72; em[106] = 24; 
    em[107] = 8884099; em[108] = 8; em[109] = 2; /* 107: pointer_to_array_of_pointers_to_stack */
    	em[110] = 114; em[111] = 0; 
    	em[112] = 69; em[113] = 20; 
    em[114] = 0; em[115] = 8; em[116] = 1; /* 114: pointer.X509_ALGOR */
    	em[117] = 119; em[118] = 0; 
    em[119] = 0; em[120] = 0; em[121] = 1; /* 119: X509_ALGOR */
    	em[122] = 124; em[123] = 0; 
    em[124] = 0; em[125] = 16; em[126] = 2; /* 124: struct.X509_algor_st */
    	em[127] = 131; em[128] = 0; 
    	em[129] = 145; em[130] = 8; 
    em[131] = 1; em[132] = 8; em[133] = 1; /* 131: pointer.struct.asn1_object_st */
    	em[134] = 136; em[135] = 0; 
    em[136] = 0; em[137] = 40; em[138] = 3; /* 136: struct.asn1_object_st */
    	em[139] = 56; em[140] = 0; 
    	em[141] = 56; em[142] = 8; 
    	em[143] = 61; em[144] = 24; 
    em[145] = 1; em[146] = 8; em[147] = 1; /* 145: pointer.struct.asn1_type_st */
    	em[148] = 150; em[149] = 0; 
    em[150] = 0; em[151] = 16; em[152] = 1; /* 150: struct.asn1_type_st */
    	em[153] = 155; em[154] = 8; 
    em[155] = 0; em[156] = 8; em[157] = 20; /* 155: union.unknown */
    	em[158] = 198; em[159] = 0; 
    	em[160] = 203; em[161] = 0; 
    	em[162] = 131; em[163] = 0; 
    	em[164] = 213; em[165] = 0; 
    	em[166] = 218; em[167] = 0; 
    	em[168] = 223; em[169] = 0; 
    	em[170] = 228; em[171] = 0; 
    	em[172] = 233; em[173] = 0; 
    	em[174] = 238; em[175] = 0; 
    	em[176] = 243; em[177] = 0; 
    	em[178] = 248; em[179] = 0; 
    	em[180] = 253; em[181] = 0; 
    	em[182] = 258; em[183] = 0; 
    	em[184] = 263; em[185] = 0; 
    	em[186] = 268; em[187] = 0; 
    	em[188] = 273; em[189] = 0; 
    	em[190] = 278; em[191] = 0; 
    	em[192] = 203; em[193] = 0; 
    	em[194] = 203; em[195] = 0; 
    	em[196] = 283; em[197] = 0; 
    em[198] = 1; em[199] = 8; em[200] = 1; /* 198: pointer.char */
    	em[201] = 8884096; em[202] = 0; 
    em[203] = 1; em[204] = 8; em[205] = 1; /* 203: pointer.struct.asn1_string_st */
    	em[206] = 208; em[207] = 0; 
    em[208] = 0; em[209] = 24; em[210] = 1; /* 208: struct.asn1_string_st */
    	em[211] = 85; em[212] = 8; 
    em[213] = 1; em[214] = 8; em[215] = 1; /* 213: pointer.struct.asn1_string_st */
    	em[216] = 208; em[217] = 0; 
    em[218] = 1; em[219] = 8; em[220] = 1; /* 218: pointer.struct.asn1_string_st */
    	em[221] = 208; em[222] = 0; 
    em[223] = 1; em[224] = 8; em[225] = 1; /* 223: pointer.struct.asn1_string_st */
    	em[226] = 208; em[227] = 0; 
    em[228] = 1; em[229] = 8; em[230] = 1; /* 228: pointer.struct.asn1_string_st */
    	em[231] = 208; em[232] = 0; 
    em[233] = 1; em[234] = 8; em[235] = 1; /* 233: pointer.struct.asn1_string_st */
    	em[236] = 208; em[237] = 0; 
    em[238] = 1; em[239] = 8; em[240] = 1; /* 238: pointer.struct.asn1_string_st */
    	em[241] = 208; em[242] = 0; 
    em[243] = 1; em[244] = 8; em[245] = 1; /* 243: pointer.struct.asn1_string_st */
    	em[246] = 208; em[247] = 0; 
    em[248] = 1; em[249] = 8; em[250] = 1; /* 248: pointer.struct.asn1_string_st */
    	em[251] = 208; em[252] = 0; 
    em[253] = 1; em[254] = 8; em[255] = 1; /* 253: pointer.struct.asn1_string_st */
    	em[256] = 208; em[257] = 0; 
    em[258] = 1; em[259] = 8; em[260] = 1; /* 258: pointer.struct.asn1_string_st */
    	em[261] = 208; em[262] = 0; 
    em[263] = 1; em[264] = 8; em[265] = 1; /* 263: pointer.struct.asn1_string_st */
    	em[266] = 208; em[267] = 0; 
    em[268] = 1; em[269] = 8; em[270] = 1; /* 268: pointer.struct.asn1_string_st */
    	em[271] = 208; em[272] = 0; 
    em[273] = 1; em[274] = 8; em[275] = 1; /* 273: pointer.struct.asn1_string_st */
    	em[276] = 208; em[277] = 0; 
    em[278] = 1; em[279] = 8; em[280] = 1; /* 278: pointer.struct.asn1_string_st */
    	em[281] = 208; em[282] = 0; 
    em[283] = 1; em[284] = 8; em[285] = 1; /* 283: pointer.struct.ASN1_VALUE_st */
    	em[286] = 288; em[287] = 0; 
    em[288] = 0; em[289] = 0; em[290] = 0; /* 288: struct.ASN1_VALUE_st */
    em[291] = 1; em[292] = 8; em[293] = 1; /* 291: pointer.struct.EDIPartyName_st */
    	em[294] = 296; em[295] = 0; 
    em[296] = 0; em[297] = 16; em[298] = 2; /* 296: struct.EDIPartyName_st */
    	em[299] = 303; em[300] = 0; 
    	em[301] = 303; em[302] = 8; 
    em[303] = 1; em[304] = 8; em[305] = 1; /* 303: pointer.struct.asn1_string_st */
    	em[306] = 308; em[307] = 0; 
    em[308] = 0; em[309] = 24; em[310] = 1; /* 308: struct.asn1_string_st */
    	em[311] = 85; em[312] = 8; 
    em[313] = 0; em[314] = 24; em[315] = 1; /* 313: struct.buf_mem_st */
    	em[316] = 198; em[317] = 8; 
    em[318] = 1; em[319] = 8; em[320] = 1; /* 318: pointer.struct.X509_name_st */
    	em[321] = 323; em[322] = 0; 
    em[323] = 0; em[324] = 40; em[325] = 3; /* 323: struct.X509_name_st */
    	em[326] = 332; em[327] = 0; 
    	em[328] = 392; em[329] = 16; 
    	em[330] = 85; em[331] = 24; 
    em[332] = 1; em[333] = 8; em[334] = 1; /* 332: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[335] = 337; em[336] = 0; 
    em[337] = 0; em[338] = 32; em[339] = 2; /* 337: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[340] = 344; em[341] = 8; 
    	em[342] = 72; em[343] = 24; 
    em[344] = 8884099; em[345] = 8; em[346] = 2; /* 344: pointer_to_array_of_pointers_to_stack */
    	em[347] = 351; em[348] = 0; 
    	em[349] = 69; em[350] = 20; 
    em[351] = 0; em[352] = 8; em[353] = 1; /* 351: pointer.X509_NAME_ENTRY */
    	em[354] = 356; em[355] = 0; 
    em[356] = 0; em[357] = 0; em[358] = 1; /* 356: X509_NAME_ENTRY */
    	em[359] = 361; em[360] = 0; 
    em[361] = 0; em[362] = 24; em[363] = 2; /* 361: struct.X509_name_entry_st */
    	em[364] = 368; em[365] = 0; 
    	em[366] = 382; em[367] = 8; 
    em[368] = 1; em[369] = 8; em[370] = 1; /* 368: pointer.struct.asn1_object_st */
    	em[371] = 373; em[372] = 0; 
    em[373] = 0; em[374] = 40; em[375] = 3; /* 373: struct.asn1_object_st */
    	em[376] = 56; em[377] = 0; 
    	em[378] = 56; em[379] = 8; 
    	em[380] = 61; em[381] = 24; 
    em[382] = 1; em[383] = 8; em[384] = 1; /* 382: pointer.struct.asn1_string_st */
    	em[385] = 387; em[386] = 0; 
    em[387] = 0; em[388] = 24; em[389] = 1; /* 387: struct.asn1_string_st */
    	em[390] = 85; em[391] = 8; 
    em[392] = 1; em[393] = 8; em[394] = 1; /* 392: pointer.struct.buf_mem_st */
    	em[395] = 313; em[396] = 0; 
    em[397] = 1; em[398] = 8; em[399] = 1; /* 397: pointer.struct.asn1_string_st */
    	em[400] = 308; em[401] = 0; 
    em[402] = 1; em[403] = 8; em[404] = 1; /* 402: pointer.struct.asn1_string_st */
    	em[405] = 308; em[406] = 0; 
    em[407] = 1; em[408] = 8; em[409] = 1; /* 407: pointer.struct.asn1_string_st */
    	em[410] = 308; em[411] = 0; 
    em[412] = 1; em[413] = 8; em[414] = 1; /* 412: pointer.struct.asn1_string_st */
    	em[415] = 308; em[416] = 0; 
    em[417] = 0; em[418] = 16; em[419] = 1; /* 417: struct.asn1_type_st */
    	em[420] = 422; em[421] = 8; 
    em[422] = 0; em[423] = 8; em[424] = 20; /* 422: union.unknown */
    	em[425] = 198; em[426] = 0; 
    	em[427] = 303; em[428] = 0; 
    	em[429] = 465; em[430] = 0; 
    	em[431] = 479; em[432] = 0; 
    	em[433] = 484; em[434] = 0; 
    	em[435] = 489; em[436] = 0; 
    	em[437] = 412; em[438] = 0; 
    	em[439] = 494; em[440] = 0; 
    	em[441] = 407; em[442] = 0; 
    	em[443] = 499; em[444] = 0; 
    	em[445] = 504; em[446] = 0; 
    	em[447] = 509; em[448] = 0; 
    	em[449] = 402; em[450] = 0; 
    	em[451] = 514; em[452] = 0; 
    	em[453] = 397; em[454] = 0; 
    	em[455] = 519; em[456] = 0; 
    	em[457] = 524; em[458] = 0; 
    	em[459] = 303; em[460] = 0; 
    	em[461] = 303; em[462] = 0; 
    	em[463] = 529; em[464] = 0; 
    em[465] = 1; em[466] = 8; em[467] = 1; /* 465: pointer.struct.asn1_object_st */
    	em[468] = 470; em[469] = 0; 
    em[470] = 0; em[471] = 40; em[472] = 3; /* 470: struct.asn1_object_st */
    	em[473] = 56; em[474] = 0; 
    	em[475] = 56; em[476] = 8; 
    	em[477] = 61; em[478] = 24; 
    em[479] = 1; em[480] = 8; em[481] = 1; /* 479: pointer.struct.asn1_string_st */
    	em[482] = 308; em[483] = 0; 
    em[484] = 1; em[485] = 8; em[486] = 1; /* 484: pointer.struct.asn1_string_st */
    	em[487] = 308; em[488] = 0; 
    em[489] = 1; em[490] = 8; em[491] = 1; /* 489: pointer.struct.asn1_string_st */
    	em[492] = 308; em[493] = 0; 
    em[494] = 1; em[495] = 8; em[496] = 1; /* 494: pointer.struct.asn1_string_st */
    	em[497] = 308; em[498] = 0; 
    em[499] = 1; em[500] = 8; em[501] = 1; /* 499: pointer.struct.asn1_string_st */
    	em[502] = 308; em[503] = 0; 
    em[504] = 1; em[505] = 8; em[506] = 1; /* 504: pointer.struct.asn1_string_st */
    	em[507] = 308; em[508] = 0; 
    em[509] = 1; em[510] = 8; em[511] = 1; /* 509: pointer.struct.asn1_string_st */
    	em[512] = 308; em[513] = 0; 
    em[514] = 1; em[515] = 8; em[516] = 1; /* 514: pointer.struct.asn1_string_st */
    	em[517] = 308; em[518] = 0; 
    em[519] = 1; em[520] = 8; em[521] = 1; /* 519: pointer.struct.asn1_string_st */
    	em[522] = 308; em[523] = 0; 
    em[524] = 1; em[525] = 8; em[526] = 1; /* 524: pointer.struct.asn1_string_st */
    	em[527] = 308; em[528] = 0; 
    em[529] = 1; em[530] = 8; em[531] = 1; /* 529: pointer.struct.ASN1_VALUE_st */
    	em[532] = 534; em[533] = 0; 
    em[534] = 0; em[535] = 0; em[536] = 0; /* 534: struct.ASN1_VALUE_st */
    em[537] = 0; em[538] = 16; em[539] = 2; /* 537: struct.otherName_st */
    	em[540] = 465; em[541] = 0; 
    	em[542] = 544; em[543] = 8; 
    em[544] = 1; em[545] = 8; em[546] = 1; /* 544: pointer.struct.asn1_type_st */
    	em[547] = 417; em[548] = 0; 
    em[549] = 0; em[550] = 16; em[551] = 1; /* 549: struct.GENERAL_NAME_st */
    	em[552] = 554; em[553] = 8; 
    em[554] = 0; em[555] = 8; em[556] = 15; /* 554: union.unknown */
    	em[557] = 198; em[558] = 0; 
    	em[559] = 587; em[560] = 0; 
    	em[561] = 499; em[562] = 0; 
    	em[563] = 499; em[564] = 0; 
    	em[565] = 544; em[566] = 0; 
    	em[567] = 318; em[568] = 0; 
    	em[569] = 291; em[570] = 0; 
    	em[571] = 499; em[572] = 0; 
    	em[573] = 412; em[574] = 0; 
    	em[575] = 465; em[576] = 0; 
    	em[577] = 412; em[578] = 0; 
    	em[579] = 318; em[580] = 0; 
    	em[581] = 499; em[582] = 0; 
    	em[583] = 465; em[584] = 0; 
    	em[585] = 544; em[586] = 0; 
    em[587] = 1; em[588] = 8; em[589] = 1; /* 587: pointer.struct.otherName_st */
    	em[590] = 537; em[591] = 0; 
    em[592] = 1; em[593] = 8; em[594] = 1; /* 592: pointer.struct.GENERAL_NAME_st */
    	em[595] = 549; em[596] = 0; 
    em[597] = 0; em[598] = 0; em[599] = 1; /* 597: GENERAL_SUBTREE */
    	em[600] = 602; em[601] = 0; 
    em[602] = 0; em[603] = 24; em[604] = 3; /* 602: struct.GENERAL_SUBTREE_st */
    	em[605] = 592; em[606] = 0; 
    	em[607] = 479; em[608] = 8; 
    	em[609] = 479; em[610] = 16; 
    em[611] = 0; em[612] = 16; em[613] = 2; /* 611: struct.NAME_CONSTRAINTS_st */
    	em[614] = 618; em[615] = 0; 
    	em[616] = 618; em[617] = 8; 
    em[618] = 1; em[619] = 8; em[620] = 1; /* 618: pointer.struct.stack_st_GENERAL_SUBTREE */
    	em[621] = 623; em[622] = 0; 
    em[623] = 0; em[624] = 32; em[625] = 2; /* 623: struct.stack_st_fake_GENERAL_SUBTREE */
    	em[626] = 630; em[627] = 8; 
    	em[628] = 72; em[629] = 24; 
    em[630] = 8884099; em[631] = 8; em[632] = 2; /* 630: pointer_to_array_of_pointers_to_stack */
    	em[633] = 637; em[634] = 0; 
    	em[635] = 69; em[636] = 20; 
    em[637] = 0; em[638] = 8; em[639] = 1; /* 637: pointer.GENERAL_SUBTREE */
    	em[640] = 597; em[641] = 0; 
    em[642] = 1; em[643] = 8; em[644] = 1; /* 642: pointer.struct.NAME_CONSTRAINTS_st */
    	em[645] = 611; em[646] = 0; 
    em[647] = 1; em[648] = 8; em[649] = 1; /* 647: pointer.struct.stack_st_GENERAL_NAME */
    	em[650] = 652; em[651] = 0; 
    em[652] = 0; em[653] = 32; em[654] = 2; /* 652: struct.stack_st_fake_GENERAL_NAME */
    	em[655] = 659; em[656] = 8; 
    	em[657] = 72; em[658] = 24; 
    em[659] = 8884099; em[660] = 8; em[661] = 2; /* 659: pointer_to_array_of_pointers_to_stack */
    	em[662] = 666; em[663] = 0; 
    	em[664] = 69; em[665] = 20; 
    em[666] = 0; em[667] = 8; em[668] = 1; /* 666: pointer.GENERAL_NAME */
    	em[669] = 671; em[670] = 0; 
    em[671] = 0; em[672] = 0; em[673] = 1; /* 671: GENERAL_NAME */
    	em[674] = 676; em[675] = 0; 
    em[676] = 0; em[677] = 16; em[678] = 1; /* 676: struct.GENERAL_NAME_st */
    	em[679] = 681; em[680] = 8; 
    em[681] = 0; em[682] = 8; em[683] = 15; /* 681: union.unknown */
    	em[684] = 198; em[685] = 0; 
    	em[686] = 714; em[687] = 0; 
    	em[688] = 833; em[689] = 0; 
    	em[690] = 833; em[691] = 0; 
    	em[692] = 740; em[693] = 0; 
    	em[694] = 881; em[695] = 0; 
    	em[696] = 929; em[697] = 0; 
    	em[698] = 833; em[699] = 0; 
    	em[700] = 818; em[701] = 0; 
    	em[702] = 726; em[703] = 0; 
    	em[704] = 818; em[705] = 0; 
    	em[706] = 881; em[707] = 0; 
    	em[708] = 833; em[709] = 0; 
    	em[710] = 726; em[711] = 0; 
    	em[712] = 740; em[713] = 0; 
    em[714] = 1; em[715] = 8; em[716] = 1; /* 714: pointer.struct.otherName_st */
    	em[717] = 719; em[718] = 0; 
    em[719] = 0; em[720] = 16; em[721] = 2; /* 719: struct.otherName_st */
    	em[722] = 726; em[723] = 0; 
    	em[724] = 740; em[725] = 8; 
    em[726] = 1; em[727] = 8; em[728] = 1; /* 726: pointer.struct.asn1_object_st */
    	em[729] = 731; em[730] = 0; 
    em[731] = 0; em[732] = 40; em[733] = 3; /* 731: struct.asn1_object_st */
    	em[734] = 56; em[735] = 0; 
    	em[736] = 56; em[737] = 8; 
    	em[738] = 61; em[739] = 24; 
    em[740] = 1; em[741] = 8; em[742] = 1; /* 740: pointer.struct.asn1_type_st */
    	em[743] = 745; em[744] = 0; 
    em[745] = 0; em[746] = 16; em[747] = 1; /* 745: struct.asn1_type_st */
    	em[748] = 750; em[749] = 8; 
    em[750] = 0; em[751] = 8; em[752] = 20; /* 750: union.unknown */
    	em[753] = 198; em[754] = 0; 
    	em[755] = 793; em[756] = 0; 
    	em[757] = 726; em[758] = 0; 
    	em[759] = 803; em[760] = 0; 
    	em[761] = 808; em[762] = 0; 
    	em[763] = 813; em[764] = 0; 
    	em[765] = 818; em[766] = 0; 
    	em[767] = 823; em[768] = 0; 
    	em[769] = 828; em[770] = 0; 
    	em[771] = 833; em[772] = 0; 
    	em[773] = 838; em[774] = 0; 
    	em[775] = 843; em[776] = 0; 
    	em[777] = 848; em[778] = 0; 
    	em[779] = 853; em[780] = 0; 
    	em[781] = 858; em[782] = 0; 
    	em[783] = 863; em[784] = 0; 
    	em[785] = 868; em[786] = 0; 
    	em[787] = 793; em[788] = 0; 
    	em[789] = 793; em[790] = 0; 
    	em[791] = 873; em[792] = 0; 
    em[793] = 1; em[794] = 8; em[795] = 1; /* 793: pointer.struct.asn1_string_st */
    	em[796] = 798; em[797] = 0; 
    em[798] = 0; em[799] = 24; em[800] = 1; /* 798: struct.asn1_string_st */
    	em[801] = 85; em[802] = 8; 
    em[803] = 1; em[804] = 8; em[805] = 1; /* 803: pointer.struct.asn1_string_st */
    	em[806] = 798; em[807] = 0; 
    em[808] = 1; em[809] = 8; em[810] = 1; /* 808: pointer.struct.asn1_string_st */
    	em[811] = 798; em[812] = 0; 
    em[813] = 1; em[814] = 8; em[815] = 1; /* 813: pointer.struct.asn1_string_st */
    	em[816] = 798; em[817] = 0; 
    em[818] = 1; em[819] = 8; em[820] = 1; /* 818: pointer.struct.asn1_string_st */
    	em[821] = 798; em[822] = 0; 
    em[823] = 1; em[824] = 8; em[825] = 1; /* 823: pointer.struct.asn1_string_st */
    	em[826] = 798; em[827] = 0; 
    em[828] = 1; em[829] = 8; em[830] = 1; /* 828: pointer.struct.asn1_string_st */
    	em[831] = 798; em[832] = 0; 
    em[833] = 1; em[834] = 8; em[835] = 1; /* 833: pointer.struct.asn1_string_st */
    	em[836] = 798; em[837] = 0; 
    em[838] = 1; em[839] = 8; em[840] = 1; /* 838: pointer.struct.asn1_string_st */
    	em[841] = 798; em[842] = 0; 
    em[843] = 1; em[844] = 8; em[845] = 1; /* 843: pointer.struct.asn1_string_st */
    	em[846] = 798; em[847] = 0; 
    em[848] = 1; em[849] = 8; em[850] = 1; /* 848: pointer.struct.asn1_string_st */
    	em[851] = 798; em[852] = 0; 
    em[853] = 1; em[854] = 8; em[855] = 1; /* 853: pointer.struct.asn1_string_st */
    	em[856] = 798; em[857] = 0; 
    em[858] = 1; em[859] = 8; em[860] = 1; /* 858: pointer.struct.asn1_string_st */
    	em[861] = 798; em[862] = 0; 
    em[863] = 1; em[864] = 8; em[865] = 1; /* 863: pointer.struct.asn1_string_st */
    	em[866] = 798; em[867] = 0; 
    em[868] = 1; em[869] = 8; em[870] = 1; /* 868: pointer.struct.asn1_string_st */
    	em[871] = 798; em[872] = 0; 
    em[873] = 1; em[874] = 8; em[875] = 1; /* 873: pointer.struct.ASN1_VALUE_st */
    	em[876] = 878; em[877] = 0; 
    em[878] = 0; em[879] = 0; em[880] = 0; /* 878: struct.ASN1_VALUE_st */
    em[881] = 1; em[882] = 8; em[883] = 1; /* 881: pointer.struct.X509_name_st */
    	em[884] = 886; em[885] = 0; 
    em[886] = 0; em[887] = 40; em[888] = 3; /* 886: struct.X509_name_st */
    	em[889] = 895; em[890] = 0; 
    	em[891] = 919; em[892] = 16; 
    	em[893] = 85; em[894] = 24; 
    em[895] = 1; em[896] = 8; em[897] = 1; /* 895: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[898] = 900; em[899] = 0; 
    em[900] = 0; em[901] = 32; em[902] = 2; /* 900: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[903] = 907; em[904] = 8; 
    	em[905] = 72; em[906] = 24; 
    em[907] = 8884099; em[908] = 8; em[909] = 2; /* 907: pointer_to_array_of_pointers_to_stack */
    	em[910] = 914; em[911] = 0; 
    	em[912] = 69; em[913] = 20; 
    em[914] = 0; em[915] = 8; em[916] = 1; /* 914: pointer.X509_NAME_ENTRY */
    	em[917] = 356; em[918] = 0; 
    em[919] = 1; em[920] = 8; em[921] = 1; /* 919: pointer.struct.buf_mem_st */
    	em[922] = 924; em[923] = 0; 
    em[924] = 0; em[925] = 24; em[926] = 1; /* 924: struct.buf_mem_st */
    	em[927] = 198; em[928] = 8; 
    em[929] = 1; em[930] = 8; em[931] = 1; /* 929: pointer.struct.EDIPartyName_st */
    	em[932] = 934; em[933] = 0; 
    em[934] = 0; em[935] = 16; em[936] = 2; /* 934: struct.EDIPartyName_st */
    	em[937] = 793; em[938] = 0; 
    	em[939] = 793; em[940] = 8; 
    em[941] = 1; em[942] = 8; em[943] = 1; /* 941: pointer.struct.asn1_string_st */
    	em[944] = 946; em[945] = 0; 
    em[946] = 0; em[947] = 24; em[948] = 1; /* 946: struct.asn1_string_st */
    	em[949] = 85; em[950] = 8; 
    em[951] = 1; em[952] = 8; em[953] = 1; /* 951: pointer.struct.buf_mem_st */
    	em[954] = 956; em[955] = 0; 
    em[956] = 0; em[957] = 24; em[958] = 1; /* 956: struct.buf_mem_st */
    	em[959] = 198; em[960] = 8; 
    em[961] = 0; em[962] = 40; em[963] = 3; /* 961: struct.X509_name_st */
    	em[964] = 970; em[965] = 0; 
    	em[966] = 951; em[967] = 16; 
    	em[968] = 85; em[969] = 24; 
    em[970] = 1; em[971] = 8; em[972] = 1; /* 970: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[973] = 975; em[974] = 0; 
    em[975] = 0; em[976] = 32; em[977] = 2; /* 975: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[978] = 982; em[979] = 8; 
    	em[980] = 72; em[981] = 24; 
    em[982] = 8884099; em[983] = 8; em[984] = 2; /* 982: pointer_to_array_of_pointers_to_stack */
    	em[985] = 989; em[986] = 0; 
    	em[987] = 69; em[988] = 20; 
    em[989] = 0; em[990] = 8; em[991] = 1; /* 989: pointer.X509_NAME_ENTRY */
    	em[992] = 356; em[993] = 0; 
    em[994] = 1; em[995] = 8; em[996] = 1; /* 994: pointer.struct.DIST_POINT_NAME_st */
    	em[997] = 999; em[998] = 0; 
    em[999] = 0; em[1000] = 24; em[1001] = 2; /* 999: struct.DIST_POINT_NAME_st */
    	em[1002] = 1006; em[1003] = 8; 
    	em[1004] = 1037; em[1005] = 16; 
    em[1006] = 0; em[1007] = 8; em[1008] = 2; /* 1006: union.unknown */
    	em[1009] = 1013; em[1010] = 0; 
    	em[1011] = 970; em[1012] = 0; 
    em[1013] = 1; em[1014] = 8; em[1015] = 1; /* 1013: pointer.struct.stack_st_GENERAL_NAME */
    	em[1016] = 1018; em[1017] = 0; 
    em[1018] = 0; em[1019] = 32; em[1020] = 2; /* 1018: struct.stack_st_fake_GENERAL_NAME */
    	em[1021] = 1025; em[1022] = 8; 
    	em[1023] = 72; em[1024] = 24; 
    em[1025] = 8884099; em[1026] = 8; em[1027] = 2; /* 1025: pointer_to_array_of_pointers_to_stack */
    	em[1028] = 1032; em[1029] = 0; 
    	em[1030] = 69; em[1031] = 20; 
    em[1032] = 0; em[1033] = 8; em[1034] = 1; /* 1032: pointer.GENERAL_NAME */
    	em[1035] = 671; em[1036] = 0; 
    em[1037] = 1; em[1038] = 8; em[1039] = 1; /* 1037: pointer.struct.X509_name_st */
    	em[1040] = 961; em[1041] = 0; 
    em[1042] = 0; em[1043] = 0; em[1044] = 1; /* 1042: DIST_POINT */
    	em[1045] = 1047; em[1046] = 0; 
    em[1047] = 0; em[1048] = 32; em[1049] = 3; /* 1047: struct.DIST_POINT_st */
    	em[1050] = 994; em[1051] = 0; 
    	em[1052] = 941; em[1053] = 8; 
    	em[1054] = 1013; em[1055] = 16; 
    em[1056] = 1; em[1057] = 8; em[1058] = 1; /* 1056: pointer.struct.stack_st_DIST_POINT */
    	em[1059] = 1061; em[1060] = 0; 
    em[1061] = 0; em[1062] = 32; em[1063] = 2; /* 1061: struct.stack_st_fake_DIST_POINT */
    	em[1064] = 1068; em[1065] = 8; 
    	em[1066] = 72; em[1067] = 24; 
    em[1068] = 8884099; em[1069] = 8; em[1070] = 2; /* 1068: pointer_to_array_of_pointers_to_stack */
    	em[1071] = 1075; em[1072] = 0; 
    	em[1073] = 69; em[1074] = 20; 
    em[1075] = 0; em[1076] = 8; em[1077] = 1; /* 1075: pointer.DIST_POINT */
    	em[1078] = 1042; em[1079] = 0; 
    em[1080] = 1; em[1081] = 8; em[1082] = 1; /* 1080: pointer.struct.stack_st_X509_POLICY_DATA */
    	em[1083] = 1085; em[1084] = 0; 
    em[1085] = 0; em[1086] = 32; em[1087] = 2; /* 1085: struct.stack_st_fake_X509_POLICY_DATA */
    	em[1088] = 1092; em[1089] = 8; 
    	em[1090] = 72; em[1091] = 24; 
    em[1092] = 8884099; em[1093] = 8; em[1094] = 2; /* 1092: pointer_to_array_of_pointers_to_stack */
    	em[1095] = 1099; em[1096] = 0; 
    	em[1097] = 69; em[1098] = 20; 
    em[1099] = 0; em[1100] = 8; em[1101] = 1; /* 1099: pointer.X509_POLICY_DATA */
    	em[1102] = 1104; em[1103] = 0; 
    em[1104] = 0; em[1105] = 0; em[1106] = 1; /* 1104: X509_POLICY_DATA */
    	em[1107] = 1109; em[1108] = 0; 
    em[1109] = 0; em[1110] = 32; em[1111] = 3; /* 1109: struct.X509_POLICY_DATA_st */
    	em[1112] = 1118; em[1113] = 8; 
    	em[1114] = 1132; em[1115] = 16; 
    	em[1116] = 1382; em[1117] = 24; 
    em[1118] = 1; em[1119] = 8; em[1120] = 1; /* 1118: pointer.struct.asn1_object_st */
    	em[1121] = 1123; em[1122] = 0; 
    em[1123] = 0; em[1124] = 40; em[1125] = 3; /* 1123: struct.asn1_object_st */
    	em[1126] = 56; em[1127] = 0; 
    	em[1128] = 56; em[1129] = 8; 
    	em[1130] = 61; em[1131] = 24; 
    em[1132] = 1; em[1133] = 8; em[1134] = 1; /* 1132: pointer.struct.stack_st_POLICYQUALINFO */
    	em[1135] = 1137; em[1136] = 0; 
    em[1137] = 0; em[1138] = 32; em[1139] = 2; /* 1137: struct.stack_st_fake_POLICYQUALINFO */
    	em[1140] = 1144; em[1141] = 8; 
    	em[1142] = 72; em[1143] = 24; 
    em[1144] = 8884099; em[1145] = 8; em[1146] = 2; /* 1144: pointer_to_array_of_pointers_to_stack */
    	em[1147] = 1151; em[1148] = 0; 
    	em[1149] = 69; em[1150] = 20; 
    em[1151] = 0; em[1152] = 8; em[1153] = 1; /* 1151: pointer.POLICYQUALINFO */
    	em[1154] = 1156; em[1155] = 0; 
    em[1156] = 0; em[1157] = 0; em[1158] = 1; /* 1156: POLICYQUALINFO */
    	em[1159] = 1161; em[1160] = 0; 
    em[1161] = 0; em[1162] = 16; em[1163] = 2; /* 1161: struct.POLICYQUALINFO_st */
    	em[1164] = 1168; em[1165] = 0; 
    	em[1166] = 1182; em[1167] = 8; 
    em[1168] = 1; em[1169] = 8; em[1170] = 1; /* 1168: pointer.struct.asn1_object_st */
    	em[1171] = 1173; em[1172] = 0; 
    em[1173] = 0; em[1174] = 40; em[1175] = 3; /* 1173: struct.asn1_object_st */
    	em[1176] = 56; em[1177] = 0; 
    	em[1178] = 56; em[1179] = 8; 
    	em[1180] = 61; em[1181] = 24; 
    em[1182] = 0; em[1183] = 8; em[1184] = 3; /* 1182: union.unknown */
    	em[1185] = 1191; em[1186] = 0; 
    	em[1187] = 1201; em[1188] = 0; 
    	em[1189] = 1264; em[1190] = 0; 
    em[1191] = 1; em[1192] = 8; em[1193] = 1; /* 1191: pointer.struct.asn1_string_st */
    	em[1194] = 1196; em[1195] = 0; 
    em[1196] = 0; em[1197] = 24; em[1198] = 1; /* 1196: struct.asn1_string_st */
    	em[1199] = 85; em[1200] = 8; 
    em[1201] = 1; em[1202] = 8; em[1203] = 1; /* 1201: pointer.struct.USERNOTICE_st */
    	em[1204] = 1206; em[1205] = 0; 
    em[1206] = 0; em[1207] = 16; em[1208] = 2; /* 1206: struct.USERNOTICE_st */
    	em[1209] = 1213; em[1210] = 0; 
    	em[1211] = 1225; em[1212] = 8; 
    em[1213] = 1; em[1214] = 8; em[1215] = 1; /* 1213: pointer.struct.NOTICEREF_st */
    	em[1216] = 1218; em[1217] = 0; 
    em[1218] = 0; em[1219] = 16; em[1220] = 2; /* 1218: struct.NOTICEREF_st */
    	em[1221] = 1225; em[1222] = 0; 
    	em[1223] = 1230; em[1224] = 8; 
    em[1225] = 1; em[1226] = 8; em[1227] = 1; /* 1225: pointer.struct.asn1_string_st */
    	em[1228] = 1196; em[1229] = 0; 
    em[1230] = 1; em[1231] = 8; em[1232] = 1; /* 1230: pointer.struct.stack_st_ASN1_INTEGER */
    	em[1233] = 1235; em[1234] = 0; 
    em[1235] = 0; em[1236] = 32; em[1237] = 2; /* 1235: struct.stack_st_fake_ASN1_INTEGER */
    	em[1238] = 1242; em[1239] = 8; 
    	em[1240] = 72; em[1241] = 24; 
    em[1242] = 8884099; em[1243] = 8; em[1244] = 2; /* 1242: pointer_to_array_of_pointers_to_stack */
    	em[1245] = 1249; em[1246] = 0; 
    	em[1247] = 69; em[1248] = 20; 
    em[1249] = 0; em[1250] = 8; em[1251] = 1; /* 1249: pointer.ASN1_INTEGER */
    	em[1252] = 1254; em[1253] = 0; 
    em[1254] = 0; em[1255] = 0; em[1256] = 1; /* 1254: ASN1_INTEGER */
    	em[1257] = 1259; em[1258] = 0; 
    em[1259] = 0; em[1260] = 24; em[1261] = 1; /* 1259: struct.asn1_string_st */
    	em[1262] = 85; em[1263] = 8; 
    em[1264] = 1; em[1265] = 8; em[1266] = 1; /* 1264: pointer.struct.asn1_type_st */
    	em[1267] = 1269; em[1268] = 0; 
    em[1269] = 0; em[1270] = 16; em[1271] = 1; /* 1269: struct.asn1_type_st */
    	em[1272] = 1274; em[1273] = 8; 
    em[1274] = 0; em[1275] = 8; em[1276] = 20; /* 1274: union.unknown */
    	em[1277] = 198; em[1278] = 0; 
    	em[1279] = 1225; em[1280] = 0; 
    	em[1281] = 1168; em[1282] = 0; 
    	em[1283] = 1317; em[1284] = 0; 
    	em[1285] = 1322; em[1286] = 0; 
    	em[1287] = 1327; em[1288] = 0; 
    	em[1289] = 1332; em[1290] = 0; 
    	em[1291] = 1337; em[1292] = 0; 
    	em[1293] = 1342; em[1294] = 0; 
    	em[1295] = 1191; em[1296] = 0; 
    	em[1297] = 1347; em[1298] = 0; 
    	em[1299] = 1352; em[1300] = 0; 
    	em[1301] = 1357; em[1302] = 0; 
    	em[1303] = 1362; em[1304] = 0; 
    	em[1305] = 1367; em[1306] = 0; 
    	em[1307] = 1372; em[1308] = 0; 
    	em[1309] = 1377; em[1310] = 0; 
    	em[1311] = 1225; em[1312] = 0; 
    	em[1313] = 1225; em[1314] = 0; 
    	em[1315] = 529; em[1316] = 0; 
    em[1317] = 1; em[1318] = 8; em[1319] = 1; /* 1317: pointer.struct.asn1_string_st */
    	em[1320] = 1196; em[1321] = 0; 
    em[1322] = 1; em[1323] = 8; em[1324] = 1; /* 1322: pointer.struct.asn1_string_st */
    	em[1325] = 1196; em[1326] = 0; 
    em[1327] = 1; em[1328] = 8; em[1329] = 1; /* 1327: pointer.struct.asn1_string_st */
    	em[1330] = 1196; em[1331] = 0; 
    em[1332] = 1; em[1333] = 8; em[1334] = 1; /* 1332: pointer.struct.asn1_string_st */
    	em[1335] = 1196; em[1336] = 0; 
    em[1337] = 1; em[1338] = 8; em[1339] = 1; /* 1337: pointer.struct.asn1_string_st */
    	em[1340] = 1196; em[1341] = 0; 
    em[1342] = 1; em[1343] = 8; em[1344] = 1; /* 1342: pointer.struct.asn1_string_st */
    	em[1345] = 1196; em[1346] = 0; 
    em[1347] = 1; em[1348] = 8; em[1349] = 1; /* 1347: pointer.struct.asn1_string_st */
    	em[1350] = 1196; em[1351] = 0; 
    em[1352] = 1; em[1353] = 8; em[1354] = 1; /* 1352: pointer.struct.asn1_string_st */
    	em[1355] = 1196; em[1356] = 0; 
    em[1357] = 1; em[1358] = 8; em[1359] = 1; /* 1357: pointer.struct.asn1_string_st */
    	em[1360] = 1196; em[1361] = 0; 
    em[1362] = 1; em[1363] = 8; em[1364] = 1; /* 1362: pointer.struct.asn1_string_st */
    	em[1365] = 1196; em[1366] = 0; 
    em[1367] = 1; em[1368] = 8; em[1369] = 1; /* 1367: pointer.struct.asn1_string_st */
    	em[1370] = 1196; em[1371] = 0; 
    em[1372] = 1; em[1373] = 8; em[1374] = 1; /* 1372: pointer.struct.asn1_string_st */
    	em[1375] = 1196; em[1376] = 0; 
    em[1377] = 1; em[1378] = 8; em[1379] = 1; /* 1377: pointer.struct.asn1_string_st */
    	em[1380] = 1196; em[1381] = 0; 
    em[1382] = 1; em[1383] = 8; em[1384] = 1; /* 1382: pointer.struct.stack_st_ASN1_OBJECT */
    	em[1385] = 1387; em[1386] = 0; 
    em[1387] = 0; em[1388] = 32; em[1389] = 2; /* 1387: struct.stack_st_fake_ASN1_OBJECT */
    	em[1390] = 1394; em[1391] = 8; 
    	em[1392] = 72; em[1393] = 24; 
    em[1394] = 8884099; em[1395] = 8; em[1396] = 2; /* 1394: pointer_to_array_of_pointers_to_stack */
    	em[1397] = 1401; em[1398] = 0; 
    	em[1399] = 69; em[1400] = 20; 
    em[1401] = 0; em[1402] = 8; em[1403] = 1; /* 1401: pointer.ASN1_OBJECT */
    	em[1404] = 42; em[1405] = 0; 
    em[1406] = 1; em[1407] = 8; em[1408] = 1; /* 1406: pointer.struct.asn1_string_st */
    	em[1409] = 1411; em[1410] = 0; 
    em[1411] = 0; em[1412] = 24; em[1413] = 1; /* 1411: struct.asn1_string_st */
    	em[1414] = 85; em[1415] = 8; 
    em[1416] = 1; em[1417] = 8; em[1418] = 1; /* 1416: pointer.struct.asn1_string_st */
    	em[1419] = 1411; em[1420] = 0; 
    em[1421] = 0; em[1422] = 40; em[1423] = 3; /* 1421: struct.asn1_object_st */
    	em[1424] = 56; em[1425] = 0; 
    	em[1426] = 56; em[1427] = 8; 
    	em[1428] = 61; em[1429] = 24; 
    em[1430] = 1; em[1431] = 8; em[1432] = 1; /* 1430: pointer.struct.asn1_object_st */
    	em[1433] = 1421; em[1434] = 0; 
    em[1435] = 1; em[1436] = 8; em[1437] = 1; /* 1435: pointer.struct.stack_st_X509_EXTENSION */
    	em[1438] = 1440; em[1439] = 0; 
    em[1440] = 0; em[1441] = 32; em[1442] = 2; /* 1440: struct.stack_st_fake_X509_EXTENSION */
    	em[1443] = 1447; em[1444] = 8; 
    	em[1445] = 72; em[1446] = 24; 
    em[1447] = 8884099; em[1448] = 8; em[1449] = 2; /* 1447: pointer_to_array_of_pointers_to_stack */
    	em[1450] = 1454; em[1451] = 0; 
    	em[1452] = 69; em[1453] = 20; 
    em[1454] = 0; em[1455] = 8; em[1456] = 1; /* 1454: pointer.X509_EXTENSION */
    	em[1457] = 1459; em[1458] = 0; 
    em[1459] = 0; em[1460] = 0; em[1461] = 1; /* 1459: X509_EXTENSION */
    	em[1462] = 1464; em[1463] = 0; 
    em[1464] = 0; em[1465] = 24; em[1466] = 2; /* 1464: struct.X509_extension_st */
    	em[1467] = 1430; em[1468] = 0; 
    	em[1469] = 1471; em[1470] = 16; 
    em[1471] = 1; em[1472] = 8; em[1473] = 1; /* 1471: pointer.struct.asn1_string_st */
    	em[1474] = 1476; em[1475] = 0; 
    em[1476] = 0; em[1477] = 24; em[1478] = 1; /* 1476: struct.asn1_string_st */
    	em[1479] = 85; em[1480] = 8; 
    em[1481] = 0; em[1482] = 0; em[1483] = 0; /* 1481: struct.ASN1_VALUE_st */
    em[1484] = 1; em[1485] = 8; em[1486] = 1; /* 1484: pointer.struct.ASN1_VALUE_st */
    	em[1487] = 1481; em[1488] = 0; 
    em[1489] = 1; em[1490] = 8; em[1491] = 1; /* 1489: pointer.struct.asn1_string_st */
    	em[1492] = 1494; em[1493] = 0; 
    em[1494] = 0; em[1495] = 24; em[1496] = 1; /* 1494: struct.asn1_string_st */
    	em[1497] = 85; em[1498] = 8; 
    em[1499] = 1; em[1500] = 8; em[1501] = 1; /* 1499: pointer.struct.asn1_string_st */
    	em[1502] = 1494; em[1503] = 0; 
    em[1504] = 1; em[1505] = 8; em[1506] = 1; /* 1504: pointer.struct.asn1_string_st */
    	em[1507] = 1494; em[1508] = 0; 
    em[1509] = 1; em[1510] = 8; em[1511] = 1; /* 1509: pointer.struct.asn1_string_st */
    	em[1512] = 1494; em[1513] = 0; 
    em[1514] = 1; em[1515] = 8; em[1516] = 1; /* 1514: pointer.struct.asn1_string_st */
    	em[1517] = 1494; em[1518] = 0; 
    em[1519] = 1; em[1520] = 8; em[1521] = 1; /* 1519: pointer.struct.asn1_string_st */
    	em[1522] = 1494; em[1523] = 0; 
    em[1524] = 1; em[1525] = 8; em[1526] = 1; /* 1524: pointer.struct.asn1_string_st */
    	em[1527] = 1494; em[1528] = 0; 
    em[1529] = 1; em[1530] = 8; em[1531] = 1; /* 1529: pointer.struct.asn1_string_st */
    	em[1532] = 1494; em[1533] = 0; 
    em[1534] = 0; em[1535] = 8; em[1536] = 20; /* 1534: union.unknown */
    	em[1537] = 198; em[1538] = 0; 
    	em[1539] = 1577; em[1540] = 0; 
    	em[1541] = 1582; em[1542] = 0; 
    	em[1543] = 1529; em[1544] = 0; 
    	em[1545] = 1596; em[1546] = 0; 
    	em[1547] = 1524; em[1548] = 0; 
    	em[1549] = 1601; em[1550] = 0; 
    	em[1551] = 1606; em[1552] = 0; 
    	em[1553] = 1519; em[1554] = 0; 
    	em[1555] = 1514; em[1556] = 0; 
    	em[1557] = 1509; em[1558] = 0; 
    	em[1559] = 1504; em[1560] = 0; 
    	em[1561] = 1499; em[1562] = 0; 
    	em[1563] = 1611; em[1564] = 0; 
    	em[1565] = 1616; em[1566] = 0; 
    	em[1567] = 1621; em[1568] = 0; 
    	em[1569] = 1489; em[1570] = 0; 
    	em[1571] = 1577; em[1572] = 0; 
    	em[1573] = 1577; em[1574] = 0; 
    	em[1575] = 1484; em[1576] = 0; 
    em[1577] = 1; em[1578] = 8; em[1579] = 1; /* 1577: pointer.struct.asn1_string_st */
    	em[1580] = 1494; em[1581] = 0; 
    em[1582] = 1; em[1583] = 8; em[1584] = 1; /* 1582: pointer.struct.asn1_object_st */
    	em[1585] = 1587; em[1586] = 0; 
    em[1587] = 0; em[1588] = 40; em[1589] = 3; /* 1587: struct.asn1_object_st */
    	em[1590] = 56; em[1591] = 0; 
    	em[1592] = 56; em[1593] = 8; 
    	em[1594] = 61; em[1595] = 24; 
    em[1596] = 1; em[1597] = 8; em[1598] = 1; /* 1596: pointer.struct.asn1_string_st */
    	em[1599] = 1494; em[1600] = 0; 
    em[1601] = 1; em[1602] = 8; em[1603] = 1; /* 1601: pointer.struct.asn1_string_st */
    	em[1604] = 1494; em[1605] = 0; 
    em[1606] = 1; em[1607] = 8; em[1608] = 1; /* 1606: pointer.struct.asn1_string_st */
    	em[1609] = 1494; em[1610] = 0; 
    em[1611] = 1; em[1612] = 8; em[1613] = 1; /* 1611: pointer.struct.asn1_string_st */
    	em[1614] = 1494; em[1615] = 0; 
    em[1616] = 1; em[1617] = 8; em[1618] = 1; /* 1616: pointer.struct.asn1_string_st */
    	em[1619] = 1494; em[1620] = 0; 
    em[1621] = 1; em[1622] = 8; em[1623] = 1; /* 1621: pointer.struct.asn1_string_st */
    	em[1624] = 1494; em[1625] = 0; 
    em[1626] = 0; em[1627] = 16; em[1628] = 1; /* 1626: struct.asn1_type_st */
    	em[1629] = 1534; em[1630] = 8; 
    em[1631] = 1; em[1632] = 8; em[1633] = 1; /* 1631: pointer.struct.asn1_type_st */
    	em[1634] = 1626; em[1635] = 0; 
    em[1636] = 1; em[1637] = 8; em[1638] = 1; /* 1636: pointer.struct.asn1_string_st */
    	em[1639] = 1641; em[1640] = 0; 
    em[1641] = 0; em[1642] = 24; em[1643] = 1; /* 1641: struct.asn1_string_st */
    	em[1644] = 85; em[1645] = 8; 
    em[1646] = 1; em[1647] = 8; em[1648] = 1; /* 1646: pointer.struct.asn1_string_st */
    	em[1649] = 1641; em[1650] = 0; 
    em[1651] = 1; em[1652] = 8; em[1653] = 1; /* 1651: pointer.struct.asn1_string_st */
    	em[1654] = 1641; em[1655] = 0; 
    em[1656] = 1; em[1657] = 8; em[1658] = 1; /* 1656: pointer.struct.asn1_string_st */
    	em[1659] = 1641; em[1660] = 0; 
    em[1661] = 1; em[1662] = 8; em[1663] = 1; /* 1661: pointer.struct.asn1_string_st */
    	em[1664] = 1641; em[1665] = 0; 
    em[1666] = 1; em[1667] = 8; em[1668] = 1; /* 1666: pointer.struct.asn1_string_st */
    	em[1669] = 1641; em[1670] = 0; 
    em[1671] = 1; em[1672] = 8; em[1673] = 1; /* 1671: pointer.struct.asn1_string_st */
    	em[1674] = 1641; em[1675] = 0; 
    em[1676] = 8884097; em[1677] = 8; em[1678] = 0; /* 1676: pointer.func */
    em[1679] = 8884097; em[1680] = 8; em[1681] = 0; /* 1679: pointer.func */
    em[1682] = 0; em[1683] = 24; em[1684] = 3; /* 1682: struct.X509_pubkey_st */
    	em[1685] = 1691; em[1686] = 0; 
    	em[1687] = 1696; em[1688] = 8; 
    	em[1689] = 1701; em[1690] = 16; 
    em[1691] = 1; em[1692] = 8; em[1693] = 1; /* 1691: pointer.struct.X509_algor_st */
    	em[1694] = 124; em[1695] = 0; 
    em[1696] = 1; em[1697] = 8; em[1698] = 1; /* 1696: pointer.struct.asn1_string_st */
    	em[1699] = 1259; em[1700] = 0; 
    em[1701] = 1; em[1702] = 8; em[1703] = 1; /* 1701: pointer.struct.evp_pkey_st */
    	em[1704] = 1706; em[1705] = 0; 
    em[1706] = 0; em[1707] = 56; em[1708] = 4; /* 1706: struct.evp_pkey_st */
    	em[1709] = 1717; em[1710] = 16; 
    	em[1711] = 1818; em[1712] = 24; 
    	em[1713] = 2155; em[1714] = 32; 
    	em[1715] = 2919; em[1716] = 48; 
    em[1717] = 1; em[1718] = 8; em[1719] = 1; /* 1717: pointer.struct.evp_pkey_asn1_method_st */
    	em[1720] = 1722; em[1721] = 0; 
    em[1722] = 0; em[1723] = 208; em[1724] = 24; /* 1722: struct.evp_pkey_asn1_method_st */
    	em[1725] = 198; em[1726] = 16; 
    	em[1727] = 198; em[1728] = 24; 
    	em[1729] = 1773; em[1730] = 32; 
    	em[1731] = 1776; em[1732] = 40; 
    	em[1733] = 1779; em[1734] = 48; 
    	em[1735] = 1782; em[1736] = 56; 
    	em[1737] = 1785; em[1738] = 64; 
    	em[1739] = 1788; em[1740] = 72; 
    	em[1741] = 1782; em[1742] = 80; 
    	em[1743] = 1791; em[1744] = 88; 
    	em[1745] = 1791; em[1746] = 96; 
    	em[1747] = 1794; em[1748] = 104; 
    	em[1749] = 1797; em[1750] = 112; 
    	em[1751] = 1791; em[1752] = 120; 
    	em[1753] = 1800; em[1754] = 128; 
    	em[1755] = 1779; em[1756] = 136; 
    	em[1757] = 1782; em[1758] = 144; 
    	em[1759] = 1803; em[1760] = 152; 
    	em[1761] = 1806; em[1762] = 160; 
    	em[1763] = 1809; em[1764] = 168; 
    	em[1765] = 1794; em[1766] = 176; 
    	em[1767] = 1797; em[1768] = 184; 
    	em[1769] = 1812; em[1770] = 192; 
    	em[1771] = 1815; em[1772] = 200; 
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
    em[1809] = 8884097; em[1810] = 8; em[1811] = 0; /* 1809: pointer.func */
    em[1812] = 8884097; em[1813] = 8; em[1814] = 0; /* 1812: pointer.func */
    em[1815] = 8884097; em[1816] = 8; em[1817] = 0; /* 1815: pointer.func */
    em[1818] = 1; em[1819] = 8; em[1820] = 1; /* 1818: pointer.struct.engine_st */
    	em[1821] = 1823; em[1822] = 0; 
    em[1823] = 0; em[1824] = 216; em[1825] = 24; /* 1823: struct.engine_st */
    	em[1826] = 56; em[1827] = 0; 
    	em[1828] = 56; em[1829] = 8; 
    	em[1830] = 1874; em[1831] = 16; 
    	em[1832] = 1929; em[1833] = 24; 
    	em[1834] = 1977; em[1835] = 32; 
    	em[1836] = 2013; em[1837] = 40; 
    	em[1838] = 2030; em[1839] = 48; 
    	em[1840] = 2057; em[1841] = 56; 
    	em[1842] = 2089; em[1843] = 64; 
    	em[1844] = 2097; em[1845] = 72; 
    	em[1846] = 2100; em[1847] = 80; 
    	em[1848] = 2103; em[1849] = 88; 
    	em[1850] = 2106; em[1851] = 96; 
    	em[1852] = 2109; em[1853] = 104; 
    	em[1854] = 2109; em[1855] = 112; 
    	em[1856] = 2109; em[1857] = 120; 
    	em[1858] = 2112; em[1859] = 128; 
    	em[1860] = 2115; em[1861] = 136; 
    	em[1862] = 2115; em[1863] = 144; 
    	em[1864] = 2118; em[1865] = 152; 
    	em[1866] = 2121; em[1867] = 160; 
    	em[1868] = 2133; em[1869] = 184; 
    	em[1870] = 2150; em[1871] = 200; 
    	em[1872] = 2150; em[1873] = 208; 
    em[1874] = 1; em[1875] = 8; em[1876] = 1; /* 1874: pointer.struct.rsa_meth_st */
    	em[1877] = 1879; em[1878] = 0; 
    em[1879] = 0; em[1880] = 112; em[1881] = 13; /* 1879: struct.rsa_meth_st */
    	em[1882] = 56; em[1883] = 0; 
    	em[1884] = 1908; em[1885] = 8; 
    	em[1886] = 1908; em[1887] = 16; 
    	em[1888] = 1908; em[1889] = 24; 
    	em[1890] = 1908; em[1891] = 32; 
    	em[1892] = 1911; em[1893] = 40; 
    	em[1894] = 1914; em[1895] = 48; 
    	em[1896] = 1917; em[1897] = 56; 
    	em[1898] = 1917; em[1899] = 64; 
    	em[1900] = 198; em[1901] = 80; 
    	em[1902] = 1920; em[1903] = 88; 
    	em[1904] = 1923; em[1905] = 96; 
    	em[1906] = 1926; em[1907] = 104; 
    em[1908] = 8884097; em[1909] = 8; em[1910] = 0; /* 1908: pointer.func */
    em[1911] = 8884097; em[1912] = 8; em[1913] = 0; /* 1911: pointer.func */
    em[1914] = 8884097; em[1915] = 8; em[1916] = 0; /* 1914: pointer.func */
    em[1917] = 8884097; em[1918] = 8; em[1919] = 0; /* 1917: pointer.func */
    em[1920] = 8884097; em[1921] = 8; em[1922] = 0; /* 1920: pointer.func */
    em[1923] = 8884097; em[1924] = 8; em[1925] = 0; /* 1923: pointer.func */
    em[1926] = 8884097; em[1927] = 8; em[1928] = 0; /* 1926: pointer.func */
    em[1929] = 1; em[1930] = 8; em[1931] = 1; /* 1929: pointer.struct.dsa_method */
    	em[1932] = 1934; em[1933] = 0; 
    em[1934] = 0; em[1935] = 96; em[1936] = 11; /* 1934: struct.dsa_method */
    	em[1937] = 56; em[1938] = 0; 
    	em[1939] = 1959; em[1940] = 8; 
    	em[1941] = 1962; em[1942] = 16; 
    	em[1943] = 1965; em[1944] = 24; 
    	em[1945] = 1968; em[1946] = 32; 
    	em[1947] = 1971; em[1948] = 40; 
    	em[1949] = 1679; em[1950] = 48; 
    	em[1951] = 1679; em[1952] = 56; 
    	em[1953] = 198; em[1954] = 72; 
    	em[1955] = 1974; em[1956] = 80; 
    	em[1957] = 1679; em[1958] = 88; 
    em[1959] = 8884097; em[1960] = 8; em[1961] = 0; /* 1959: pointer.func */
    em[1962] = 8884097; em[1963] = 8; em[1964] = 0; /* 1962: pointer.func */
    em[1965] = 8884097; em[1966] = 8; em[1967] = 0; /* 1965: pointer.func */
    em[1968] = 8884097; em[1969] = 8; em[1970] = 0; /* 1968: pointer.func */
    em[1971] = 8884097; em[1972] = 8; em[1973] = 0; /* 1971: pointer.func */
    em[1974] = 8884097; em[1975] = 8; em[1976] = 0; /* 1974: pointer.func */
    em[1977] = 1; em[1978] = 8; em[1979] = 1; /* 1977: pointer.struct.dh_method */
    	em[1980] = 1982; em[1981] = 0; 
    em[1982] = 0; em[1983] = 72; em[1984] = 8; /* 1982: struct.dh_method */
    	em[1985] = 56; em[1986] = 0; 
    	em[1987] = 2001; em[1988] = 8; 
    	em[1989] = 2004; em[1990] = 16; 
    	em[1991] = 2007; em[1992] = 24; 
    	em[1993] = 2001; em[1994] = 32; 
    	em[1995] = 2001; em[1996] = 40; 
    	em[1997] = 198; em[1998] = 56; 
    	em[1999] = 2010; em[2000] = 64; 
    em[2001] = 8884097; em[2002] = 8; em[2003] = 0; /* 2001: pointer.func */
    em[2004] = 8884097; em[2005] = 8; em[2006] = 0; /* 2004: pointer.func */
    em[2007] = 8884097; em[2008] = 8; em[2009] = 0; /* 2007: pointer.func */
    em[2010] = 8884097; em[2011] = 8; em[2012] = 0; /* 2010: pointer.func */
    em[2013] = 1; em[2014] = 8; em[2015] = 1; /* 2013: pointer.struct.ecdh_method */
    	em[2016] = 2018; em[2017] = 0; 
    em[2018] = 0; em[2019] = 32; em[2020] = 3; /* 2018: struct.ecdh_method */
    	em[2021] = 56; em[2022] = 0; 
    	em[2023] = 2027; em[2024] = 8; 
    	em[2025] = 198; em[2026] = 24; 
    em[2027] = 8884097; em[2028] = 8; em[2029] = 0; /* 2027: pointer.func */
    em[2030] = 1; em[2031] = 8; em[2032] = 1; /* 2030: pointer.struct.ecdsa_method */
    	em[2033] = 2035; em[2034] = 0; 
    em[2035] = 0; em[2036] = 48; em[2037] = 5; /* 2035: struct.ecdsa_method */
    	em[2038] = 56; em[2039] = 0; 
    	em[2040] = 2048; em[2041] = 8; 
    	em[2042] = 2051; em[2043] = 16; 
    	em[2044] = 2054; em[2045] = 24; 
    	em[2046] = 198; em[2047] = 40; 
    em[2048] = 8884097; em[2049] = 8; em[2050] = 0; /* 2048: pointer.func */
    em[2051] = 8884097; em[2052] = 8; em[2053] = 0; /* 2051: pointer.func */
    em[2054] = 8884097; em[2055] = 8; em[2056] = 0; /* 2054: pointer.func */
    em[2057] = 1; em[2058] = 8; em[2059] = 1; /* 2057: pointer.struct.rand_meth_st */
    	em[2060] = 2062; em[2061] = 0; 
    em[2062] = 0; em[2063] = 48; em[2064] = 6; /* 2062: struct.rand_meth_st */
    	em[2065] = 2077; em[2066] = 0; 
    	em[2067] = 2080; em[2068] = 8; 
    	em[2069] = 2083; em[2070] = 16; 
    	em[2071] = 2086; em[2072] = 24; 
    	em[2073] = 2080; em[2074] = 32; 
    	em[2075] = 1676; em[2076] = 40; 
    em[2077] = 8884097; em[2078] = 8; em[2079] = 0; /* 2077: pointer.func */
    em[2080] = 8884097; em[2081] = 8; em[2082] = 0; /* 2080: pointer.func */
    em[2083] = 8884097; em[2084] = 8; em[2085] = 0; /* 2083: pointer.func */
    em[2086] = 8884097; em[2087] = 8; em[2088] = 0; /* 2086: pointer.func */
    em[2089] = 1; em[2090] = 8; em[2091] = 1; /* 2089: pointer.struct.store_method_st */
    	em[2092] = 2094; em[2093] = 0; 
    em[2094] = 0; em[2095] = 0; em[2096] = 0; /* 2094: struct.store_method_st */
    em[2097] = 8884097; em[2098] = 8; em[2099] = 0; /* 2097: pointer.func */
    em[2100] = 8884097; em[2101] = 8; em[2102] = 0; /* 2100: pointer.func */
    em[2103] = 8884097; em[2104] = 8; em[2105] = 0; /* 2103: pointer.func */
    em[2106] = 8884097; em[2107] = 8; em[2108] = 0; /* 2106: pointer.func */
    em[2109] = 8884097; em[2110] = 8; em[2111] = 0; /* 2109: pointer.func */
    em[2112] = 8884097; em[2113] = 8; em[2114] = 0; /* 2112: pointer.func */
    em[2115] = 8884097; em[2116] = 8; em[2117] = 0; /* 2115: pointer.func */
    em[2118] = 8884097; em[2119] = 8; em[2120] = 0; /* 2118: pointer.func */
    em[2121] = 1; em[2122] = 8; em[2123] = 1; /* 2121: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[2124] = 2126; em[2125] = 0; 
    em[2126] = 0; em[2127] = 32; em[2128] = 2; /* 2126: struct.ENGINE_CMD_DEFN_st */
    	em[2129] = 56; em[2130] = 8; 
    	em[2131] = 56; em[2132] = 16; 
    em[2133] = 0; em[2134] = 32; em[2135] = 2; /* 2133: struct.crypto_ex_data_st_fake */
    	em[2136] = 2140; em[2137] = 8; 
    	em[2138] = 72; em[2139] = 24; 
    em[2140] = 8884099; em[2141] = 8; em[2142] = 2; /* 2140: pointer_to_array_of_pointers_to_stack */
    	em[2143] = 2147; em[2144] = 0; 
    	em[2145] = 69; em[2146] = 20; 
    em[2147] = 0; em[2148] = 8; em[2149] = 0; /* 2147: pointer.void */
    em[2150] = 1; em[2151] = 8; em[2152] = 1; /* 2150: pointer.struct.engine_st */
    	em[2153] = 1823; em[2154] = 0; 
    em[2155] = 8884101; em[2156] = 8; em[2157] = 6; /* 2155: union.union_of_evp_pkey_st */
    	em[2158] = 2147; em[2159] = 0; 
    	em[2160] = 2170; em[2161] = 6; 
    	em[2162] = 2381; em[2163] = 116; 
    	em[2164] = 2512; em[2165] = 28; 
    	em[2166] = 2594; em[2167] = 408; 
    	em[2168] = 69; em[2169] = 0; 
    em[2170] = 1; em[2171] = 8; em[2172] = 1; /* 2170: pointer.struct.rsa_st */
    	em[2173] = 2175; em[2174] = 0; 
    em[2175] = 0; em[2176] = 168; em[2177] = 17; /* 2175: struct.rsa_st */
    	em[2178] = 2212; em[2179] = 16; 
    	em[2180] = 2267; em[2181] = 24; 
    	em[2182] = 2272; em[2183] = 32; 
    	em[2184] = 2272; em[2185] = 40; 
    	em[2186] = 2272; em[2187] = 48; 
    	em[2188] = 2272; em[2189] = 56; 
    	em[2190] = 2272; em[2191] = 64; 
    	em[2192] = 2272; em[2193] = 72; 
    	em[2194] = 2272; em[2195] = 80; 
    	em[2196] = 2272; em[2197] = 88; 
    	em[2198] = 2292; em[2199] = 96; 
    	em[2200] = 2306; em[2201] = 120; 
    	em[2202] = 2306; em[2203] = 128; 
    	em[2204] = 2306; em[2205] = 136; 
    	em[2206] = 198; em[2207] = 144; 
    	em[2208] = 2320; em[2209] = 152; 
    	em[2210] = 2320; em[2211] = 160; 
    em[2212] = 1; em[2213] = 8; em[2214] = 1; /* 2212: pointer.struct.rsa_meth_st */
    	em[2215] = 2217; em[2216] = 0; 
    em[2217] = 0; em[2218] = 112; em[2219] = 13; /* 2217: struct.rsa_meth_st */
    	em[2220] = 56; em[2221] = 0; 
    	em[2222] = 2246; em[2223] = 8; 
    	em[2224] = 2246; em[2225] = 16; 
    	em[2226] = 2246; em[2227] = 24; 
    	em[2228] = 2246; em[2229] = 32; 
    	em[2230] = 2249; em[2231] = 40; 
    	em[2232] = 2252; em[2233] = 48; 
    	em[2234] = 2255; em[2235] = 56; 
    	em[2236] = 2255; em[2237] = 64; 
    	em[2238] = 198; em[2239] = 80; 
    	em[2240] = 2258; em[2241] = 88; 
    	em[2242] = 2261; em[2243] = 96; 
    	em[2244] = 2264; em[2245] = 104; 
    em[2246] = 8884097; em[2247] = 8; em[2248] = 0; /* 2246: pointer.func */
    em[2249] = 8884097; em[2250] = 8; em[2251] = 0; /* 2249: pointer.func */
    em[2252] = 8884097; em[2253] = 8; em[2254] = 0; /* 2252: pointer.func */
    em[2255] = 8884097; em[2256] = 8; em[2257] = 0; /* 2255: pointer.func */
    em[2258] = 8884097; em[2259] = 8; em[2260] = 0; /* 2258: pointer.func */
    em[2261] = 8884097; em[2262] = 8; em[2263] = 0; /* 2261: pointer.func */
    em[2264] = 8884097; em[2265] = 8; em[2266] = 0; /* 2264: pointer.func */
    em[2267] = 1; em[2268] = 8; em[2269] = 1; /* 2267: pointer.struct.engine_st */
    	em[2270] = 1823; em[2271] = 0; 
    em[2272] = 1; em[2273] = 8; em[2274] = 1; /* 2272: pointer.struct.bignum_st */
    	em[2275] = 2277; em[2276] = 0; 
    em[2277] = 0; em[2278] = 24; em[2279] = 1; /* 2277: struct.bignum_st */
    	em[2280] = 2282; em[2281] = 0; 
    em[2282] = 8884099; em[2283] = 8; em[2284] = 2; /* 2282: pointer_to_array_of_pointers_to_stack */
    	em[2285] = 2289; em[2286] = 0; 
    	em[2287] = 69; em[2288] = 12; 
    em[2289] = 0; em[2290] = 8; em[2291] = 0; /* 2289: long unsigned int */
    em[2292] = 0; em[2293] = 32; em[2294] = 2; /* 2292: struct.crypto_ex_data_st_fake */
    	em[2295] = 2299; em[2296] = 8; 
    	em[2297] = 72; em[2298] = 24; 
    em[2299] = 8884099; em[2300] = 8; em[2301] = 2; /* 2299: pointer_to_array_of_pointers_to_stack */
    	em[2302] = 2147; em[2303] = 0; 
    	em[2304] = 69; em[2305] = 20; 
    em[2306] = 1; em[2307] = 8; em[2308] = 1; /* 2306: pointer.struct.bn_mont_ctx_st */
    	em[2309] = 2311; em[2310] = 0; 
    em[2311] = 0; em[2312] = 96; em[2313] = 3; /* 2311: struct.bn_mont_ctx_st */
    	em[2314] = 2277; em[2315] = 8; 
    	em[2316] = 2277; em[2317] = 32; 
    	em[2318] = 2277; em[2319] = 56; 
    em[2320] = 1; em[2321] = 8; em[2322] = 1; /* 2320: pointer.struct.bn_blinding_st */
    	em[2323] = 2325; em[2324] = 0; 
    em[2325] = 0; em[2326] = 88; em[2327] = 7; /* 2325: struct.bn_blinding_st */
    	em[2328] = 2342; em[2329] = 0; 
    	em[2330] = 2342; em[2331] = 8; 
    	em[2332] = 2342; em[2333] = 16; 
    	em[2334] = 2342; em[2335] = 24; 
    	em[2336] = 2359; em[2337] = 40; 
    	em[2338] = 2364; em[2339] = 72; 
    	em[2340] = 2378; em[2341] = 80; 
    em[2342] = 1; em[2343] = 8; em[2344] = 1; /* 2342: pointer.struct.bignum_st */
    	em[2345] = 2347; em[2346] = 0; 
    em[2347] = 0; em[2348] = 24; em[2349] = 1; /* 2347: struct.bignum_st */
    	em[2350] = 2352; em[2351] = 0; 
    em[2352] = 8884099; em[2353] = 8; em[2354] = 2; /* 2352: pointer_to_array_of_pointers_to_stack */
    	em[2355] = 2289; em[2356] = 0; 
    	em[2357] = 69; em[2358] = 12; 
    em[2359] = 0; em[2360] = 16; em[2361] = 1; /* 2359: struct.crypto_threadid_st */
    	em[2362] = 2147; em[2363] = 0; 
    em[2364] = 1; em[2365] = 8; em[2366] = 1; /* 2364: pointer.struct.bn_mont_ctx_st */
    	em[2367] = 2369; em[2368] = 0; 
    em[2369] = 0; em[2370] = 96; em[2371] = 3; /* 2369: struct.bn_mont_ctx_st */
    	em[2372] = 2347; em[2373] = 8; 
    	em[2374] = 2347; em[2375] = 32; 
    	em[2376] = 2347; em[2377] = 56; 
    em[2378] = 8884097; em[2379] = 8; em[2380] = 0; /* 2378: pointer.func */
    em[2381] = 1; em[2382] = 8; em[2383] = 1; /* 2381: pointer.struct.dsa_st */
    	em[2384] = 2386; em[2385] = 0; 
    em[2386] = 0; em[2387] = 136; em[2388] = 11; /* 2386: struct.dsa_st */
    	em[2389] = 2411; em[2390] = 24; 
    	em[2391] = 2411; em[2392] = 32; 
    	em[2393] = 2411; em[2394] = 40; 
    	em[2395] = 2411; em[2396] = 48; 
    	em[2397] = 2411; em[2398] = 56; 
    	em[2399] = 2411; em[2400] = 64; 
    	em[2401] = 2411; em[2402] = 72; 
    	em[2403] = 2428; em[2404] = 88; 
    	em[2405] = 2442; em[2406] = 104; 
    	em[2407] = 2456; em[2408] = 120; 
    	em[2409] = 2507; em[2410] = 128; 
    em[2411] = 1; em[2412] = 8; em[2413] = 1; /* 2411: pointer.struct.bignum_st */
    	em[2414] = 2416; em[2415] = 0; 
    em[2416] = 0; em[2417] = 24; em[2418] = 1; /* 2416: struct.bignum_st */
    	em[2419] = 2421; em[2420] = 0; 
    em[2421] = 8884099; em[2422] = 8; em[2423] = 2; /* 2421: pointer_to_array_of_pointers_to_stack */
    	em[2424] = 2289; em[2425] = 0; 
    	em[2426] = 69; em[2427] = 12; 
    em[2428] = 1; em[2429] = 8; em[2430] = 1; /* 2428: pointer.struct.bn_mont_ctx_st */
    	em[2431] = 2433; em[2432] = 0; 
    em[2433] = 0; em[2434] = 96; em[2435] = 3; /* 2433: struct.bn_mont_ctx_st */
    	em[2436] = 2416; em[2437] = 8; 
    	em[2438] = 2416; em[2439] = 32; 
    	em[2440] = 2416; em[2441] = 56; 
    em[2442] = 0; em[2443] = 32; em[2444] = 2; /* 2442: struct.crypto_ex_data_st_fake */
    	em[2445] = 2449; em[2446] = 8; 
    	em[2447] = 72; em[2448] = 24; 
    em[2449] = 8884099; em[2450] = 8; em[2451] = 2; /* 2449: pointer_to_array_of_pointers_to_stack */
    	em[2452] = 2147; em[2453] = 0; 
    	em[2454] = 69; em[2455] = 20; 
    em[2456] = 1; em[2457] = 8; em[2458] = 1; /* 2456: pointer.struct.dsa_method */
    	em[2459] = 2461; em[2460] = 0; 
    em[2461] = 0; em[2462] = 96; em[2463] = 11; /* 2461: struct.dsa_method */
    	em[2464] = 56; em[2465] = 0; 
    	em[2466] = 2486; em[2467] = 8; 
    	em[2468] = 2489; em[2469] = 16; 
    	em[2470] = 2492; em[2471] = 24; 
    	em[2472] = 2495; em[2473] = 32; 
    	em[2474] = 2498; em[2475] = 40; 
    	em[2476] = 2501; em[2477] = 48; 
    	em[2478] = 2501; em[2479] = 56; 
    	em[2480] = 198; em[2481] = 72; 
    	em[2482] = 2504; em[2483] = 80; 
    	em[2484] = 2501; em[2485] = 88; 
    em[2486] = 8884097; em[2487] = 8; em[2488] = 0; /* 2486: pointer.func */
    em[2489] = 8884097; em[2490] = 8; em[2491] = 0; /* 2489: pointer.func */
    em[2492] = 8884097; em[2493] = 8; em[2494] = 0; /* 2492: pointer.func */
    em[2495] = 8884097; em[2496] = 8; em[2497] = 0; /* 2495: pointer.func */
    em[2498] = 8884097; em[2499] = 8; em[2500] = 0; /* 2498: pointer.func */
    em[2501] = 8884097; em[2502] = 8; em[2503] = 0; /* 2501: pointer.func */
    em[2504] = 8884097; em[2505] = 8; em[2506] = 0; /* 2504: pointer.func */
    em[2507] = 1; em[2508] = 8; em[2509] = 1; /* 2507: pointer.struct.engine_st */
    	em[2510] = 1823; em[2511] = 0; 
    em[2512] = 1; em[2513] = 8; em[2514] = 1; /* 2512: pointer.struct.dh_st */
    	em[2515] = 2517; em[2516] = 0; 
    em[2517] = 0; em[2518] = 144; em[2519] = 12; /* 2517: struct.dh_st */
    	em[2520] = 2272; em[2521] = 8; 
    	em[2522] = 2272; em[2523] = 16; 
    	em[2524] = 2272; em[2525] = 32; 
    	em[2526] = 2272; em[2527] = 40; 
    	em[2528] = 2306; em[2529] = 56; 
    	em[2530] = 2272; em[2531] = 64; 
    	em[2532] = 2272; em[2533] = 72; 
    	em[2534] = 85; em[2535] = 80; 
    	em[2536] = 2272; em[2537] = 96; 
    	em[2538] = 2544; em[2539] = 112; 
    	em[2540] = 2558; em[2541] = 128; 
    	em[2542] = 2267; em[2543] = 136; 
    em[2544] = 0; em[2545] = 32; em[2546] = 2; /* 2544: struct.crypto_ex_data_st_fake */
    	em[2547] = 2551; em[2548] = 8; 
    	em[2549] = 72; em[2550] = 24; 
    em[2551] = 8884099; em[2552] = 8; em[2553] = 2; /* 2551: pointer_to_array_of_pointers_to_stack */
    	em[2554] = 2147; em[2555] = 0; 
    	em[2556] = 69; em[2557] = 20; 
    em[2558] = 1; em[2559] = 8; em[2560] = 1; /* 2558: pointer.struct.dh_method */
    	em[2561] = 2563; em[2562] = 0; 
    em[2563] = 0; em[2564] = 72; em[2565] = 8; /* 2563: struct.dh_method */
    	em[2566] = 56; em[2567] = 0; 
    	em[2568] = 2582; em[2569] = 8; 
    	em[2570] = 2585; em[2571] = 16; 
    	em[2572] = 2588; em[2573] = 24; 
    	em[2574] = 2582; em[2575] = 32; 
    	em[2576] = 2582; em[2577] = 40; 
    	em[2578] = 198; em[2579] = 56; 
    	em[2580] = 2591; em[2581] = 64; 
    em[2582] = 8884097; em[2583] = 8; em[2584] = 0; /* 2582: pointer.func */
    em[2585] = 8884097; em[2586] = 8; em[2587] = 0; /* 2585: pointer.func */
    em[2588] = 8884097; em[2589] = 8; em[2590] = 0; /* 2588: pointer.func */
    em[2591] = 8884097; em[2592] = 8; em[2593] = 0; /* 2591: pointer.func */
    em[2594] = 1; em[2595] = 8; em[2596] = 1; /* 2594: pointer.struct.ec_key_st */
    	em[2597] = 2599; em[2598] = 0; 
    em[2599] = 0; em[2600] = 56; em[2601] = 4; /* 2599: struct.ec_key_st */
    	em[2602] = 2610; em[2603] = 8; 
    	em[2604] = 2874; em[2605] = 16; 
    	em[2606] = 2879; em[2607] = 24; 
    	em[2608] = 2896; em[2609] = 48; 
    em[2610] = 1; em[2611] = 8; em[2612] = 1; /* 2610: pointer.struct.ec_group_st */
    	em[2613] = 2615; em[2614] = 0; 
    em[2615] = 0; em[2616] = 232; em[2617] = 12; /* 2615: struct.ec_group_st */
    	em[2618] = 2642; em[2619] = 0; 
    	em[2620] = 2814; em[2621] = 8; 
    	em[2622] = 2830; em[2623] = 16; 
    	em[2624] = 2830; em[2625] = 40; 
    	em[2626] = 85; em[2627] = 80; 
    	em[2628] = 2842; em[2629] = 96; 
    	em[2630] = 2830; em[2631] = 104; 
    	em[2632] = 2830; em[2633] = 152; 
    	em[2634] = 2830; em[2635] = 176; 
    	em[2636] = 2147; em[2637] = 208; 
    	em[2638] = 2147; em[2639] = 216; 
    	em[2640] = 2871; em[2641] = 224; 
    em[2642] = 1; em[2643] = 8; em[2644] = 1; /* 2642: pointer.struct.ec_method_st */
    	em[2645] = 2647; em[2646] = 0; 
    em[2647] = 0; em[2648] = 304; em[2649] = 37; /* 2647: struct.ec_method_st */
    	em[2650] = 2724; em[2651] = 8; 
    	em[2652] = 2727; em[2653] = 16; 
    	em[2654] = 2727; em[2655] = 24; 
    	em[2656] = 2730; em[2657] = 32; 
    	em[2658] = 2733; em[2659] = 40; 
    	em[2660] = 2736; em[2661] = 48; 
    	em[2662] = 2739; em[2663] = 56; 
    	em[2664] = 2742; em[2665] = 64; 
    	em[2666] = 2745; em[2667] = 72; 
    	em[2668] = 2748; em[2669] = 80; 
    	em[2670] = 2748; em[2671] = 88; 
    	em[2672] = 2751; em[2673] = 96; 
    	em[2674] = 2754; em[2675] = 104; 
    	em[2676] = 2757; em[2677] = 112; 
    	em[2678] = 2760; em[2679] = 120; 
    	em[2680] = 2763; em[2681] = 128; 
    	em[2682] = 2766; em[2683] = 136; 
    	em[2684] = 2769; em[2685] = 144; 
    	em[2686] = 2772; em[2687] = 152; 
    	em[2688] = 2775; em[2689] = 160; 
    	em[2690] = 2778; em[2691] = 168; 
    	em[2692] = 2781; em[2693] = 176; 
    	em[2694] = 2784; em[2695] = 184; 
    	em[2696] = 2787; em[2697] = 192; 
    	em[2698] = 2790; em[2699] = 200; 
    	em[2700] = 2793; em[2701] = 208; 
    	em[2702] = 2784; em[2703] = 216; 
    	em[2704] = 2796; em[2705] = 224; 
    	em[2706] = 2799; em[2707] = 232; 
    	em[2708] = 2802; em[2709] = 240; 
    	em[2710] = 2739; em[2711] = 248; 
    	em[2712] = 2805; em[2713] = 256; 
    	em[2714] = 2808; em[2715] = 264; 
    	em[2716] = 2805; em[2717] = 272; 
    	em[2718] = 2808; em[2719] = 280; 
    	em[2720] = 2808; em[2721] = 288; 
    	em[2722] = 2811; em[2723] = 296; 
    em[2724] = 8884097; em[2725] = 8; em[2726] = 0; /* 2724: pointer.func */
    em[2727] = 8884097; em[2728] = 8; em[2729] = 0; /* 2727: pointer.func */
    em[2730] = 8884097; em[2731] = 8; em[2732] = 0; /* 2730: pointer.func */
    em[2733] = 8884097; em[2734] = 8; em[2735] = 0; /* 2733: pointer.func */
    em[2736] = 8884097; em[2737] = 8; em[2738] = 0; /* 2736: pointer.func */
    em[2739] = 8884097; em[2740] = 8; em[2741] = 0; /* 2739: pointer.func */
    em[2742] = 8884097; em[2743] = 8; em[2744] = 0; /* 2742: pointer.func */
    em[2745] = 8884097; em[2746] = 8; em[2747] = 0; /* 2745: pointer.func */
    em[2748] = 8884097; em[2749] = 8; em[2750] = 0; /* 2748: pointer.func */
    em[2751] = 8884097; em[2752] = 8; em[2753] = 0; /* 2751: pointer.func */
    em[2754] = 8884097; em[2755] = 8; em[2756] = 0; /* 2754: pointer.func */
    em[2757] = 8884097; em[2758] = 8; em[2759] = 0; /* 2757: pointer.func */
    em[2760] = 8884097; em[2761] = 8; em[2762] = 0; /* 2760: pointer.func */
    em[2763] = 8884097; em[2764] = 8; em[2765] = 0; /* 2763: pointer.func */
    em[2766] = 8884097; em[2767] = 8; em[2768] = 0; /* 2766: pointer.func */
    em[2769] = 8884097; em[2770] = 8; em[2771] = 0; /* 2769: pointer.func */
    em[2772] = 8884097; em[2773] = 8; em[2774] = 0; /* 2772: pointer.func */
    em[2775] = 8884097; em[2776] = 8; em[2777] = 0; /* 2775: pointer.func */
    em[2778] = 8884097; em[2779] = 8; em[2780] = 0; /* 2778: pointer.func */
    em[2781] = 8884097; em[2782] = 8; em[2783] = 0; /* 2781: pointer.func */
    em[2784] = 8884097; em[2785] = 8; em[2786] = 0; /* 2784: pointer.func */
    em[2787] = 8884097; em[2788] = 8; em[2789] = 0; /* 2787: pointer.func */
    em[2790] = 8884097; em[2791] = 8; em[2792] = 0; /* 2790: pointer.func */
    em[2793] = 8884097; em[2794] = 8; em[2795] = 0; /* 2793: pointer.func */
    em[2796] = 8884097; em[2797] = 8; em[2798] = 0; /* 2796: pointer.func */
    em[2799] = 8884097; em[2800] = 8; em[2801] = 0; /* 2799: pointer.func */
    em[2802] = 8884097; em[2803] = 8; em[2804] = 0; /* 2802: pointer.func */
    em[2805] = 8884097; em[2806] = 8; em[2807] = 0; /* 2805: pointer.func */
    em[2808] = 8884097; em[2809] = 8; em[2810] = 0; /* 2808: pointer.func */
    em[2811] = 8884097; em[2812] = 8; em[2813] = 0; /* 2811: pointer.func */
    em[2814] = 1; em[2815] = 8; em[2816] = 1; /* 2814: pointer.struct.ec_point_st */
    	em[2817] = 2819; em[2818] = 0; 
    em[2819] = 0; em[2820] = 88; em[2821] = 4; /* 2819: struct.ec_point_st */
    	em[2822] = 2642; em[2823] = 0; 
    	em[2824] = 2830; em[2825] = 8; 
    	em[2826] = 2830; em[2827] = 32; 
    	em[2828] = 2830; em[2829] = 56; 
    em[2830] = 0; em[2831] = 24; em[2832] = 1; /* 2830: struct.bignum_st */
    	em[2833] = 2835; em[2834] = 0; 
    em[2835] = 8884099; em[2836] = 8; em[2837] = 2; /* 2835: pointer_to_array_of_pointers_to_stack */
    	em[2838] = 2289; em[2839] = 0; 
    	em[2840] = 69; em[2841] = 12; 
    em[2842] = 1; em[2843] = 8; em[2844] = 1; /* 2842: pointer.struct.ec_extra_data_st */
    	em[2845] = 2847; em[2846] = 0; 
    em[2847] = 0; em[2848] = 40; em[2849] = 5; /* 2847: struct.ec_extra_data_st */
    	em[2850] = 2860; em[2851] = 0; 
    	em[2852] = 2147; em[2853] = 8; 
    	em[2854] = 2865; em[2855] = 16; 
    	em[2856] = 2868; em[2857] = 24; 
    	em[2858] = 2868; em[2859] = 32; 
    em[2860] = 1; em[2861] = 8; em[2862] = 1; /* 2860: pointer.struct.ec_extra_data_st */
    	em[2863] = 2847; em[2864] = 0; 
    em[2865] = 8884097; em[2866] = 8; em[2867] = 0; /* 2865: pointer.func */
    em[2868] = 8884097; em[2869] = 8; em[2870] = 0; /* 2868: pointer.func */
    em[2871] = 8884097; em[2872] = 8; em[2873] = 0; /* 2871: pointer.func */
    em[2874] = 1; em[2875] = 8; em[2876] = 1; /* 2874: pointer.struct.ec_point_st */
    	em[2877] = 2819; em[2878] = 0; 
    em[2879] = 1; em[2880] = 8; em[2881] = 1; /* 2879: pointer.struct.bignum_st */
    	em[2882] = 2884; em[2883] = 0; 
    em[2884] = 0; em[2885] = 24; em[2886] = 1; /* 2884: struct.bignum_st */
    	em[2887] = 2889; em[2888] = 0; 
    em[2889] = 8884099; em[2890] = 8; em[2891] = 2; /* 2889: pointer_to_array_of_pointers_to_stack */
    	em[2892] = 2289; em[2893] = 0; 
    	em[2894] = 69; em[2895] = 12; 
    em[2896] = 1; em[2897] = 8; em[2898] = 1; /* 2896: pointer.struct.ec_extra_data_st */
    	em[2899] = 2901; em[2900] = 0; 
    em[2901] = 0; em[2902] = 40; em[2903] = 5; /* 2901: struct.ec_extra_data_st */
    	em[2904] = 2914; em[2905] = 0; 
    	em[2906] = 2147; em[2907] = 8; 
    	em[2908] = 2865; em[2909] = 16; 
    	em[2910] = 2868; em[2911] = 24; 
    	em[2912] = 2868; em[2913] = 32; 
    em[2914] = 1; em[2915] = 8; em[2916] = 1; /* 2914: pointer.struct.ec_extra_data_st */
    	em[2917] = 2901; em[2918] = 0; 
    em[2919] = 1; em[2920] = 8; em[2921] = 1; /* 2919: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[2922] = 2924; em[2923] = 0; 
    em[2924] = 0; em[2925] = 32; em[2926] = 2; /* 2924: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[2927] = 2931; em[2928] = 8; 
    	em[2929] = 72; em[2930] = 24; 
    em[2931] = 8884099; em[2932] = 8; em[2933] = 2; /* 2931: pointer_to_array_of_pointers_to_stack */
    	em[2934] = 2938; em[2935] = 0; 
    	em[2936] = 69; em[2937] = 20; 
    em[2938] = 0; em[2939] = 8; em[2940] = 1; /* 2938: pointer.X509_ATTRIBUTE */
    	em[2941] = 2943; em[2942] = 0; 
    em[2943] = 0; em[2944] = 0; em[2945] = 1; /* 2943: X509_ATTRIBUTE */
    	em[2946] = 2948; em[2947] = 0; 
    em[2948] = 0; em[2949] = 24; em[2950] = 2; /* 2948: struct.x509_attributes_st */
    	em[2951] = 1582; em[2952] = 0; 
    	em[2953] = 2955; em[2954] = 16; 
    em[2955] = 0; em[2956] = 8; em[2957] = 3; /* 2955: union.unknown */
    	em[2958] = 198; em[2959] = 0; 
    	em[2960] = 2964; em[2961] = 0; 
    	em[2962] = 1631; em[2963] = 0; 
    em[2964] = 1; em[2965] = 8; em[2966] = 1; /* 2964: pointer.struct.stack_st_ASN1_TYPE */
    	em[2967] = 2969; em[2968] = 0; 
    em[2969] = 0; em[2970] = 32; em[2971] = 2; /* 2969: struct.stack_st_fake_ASN1_TYPE */
    	em[2972] = 2976; em[2973] = 8; 
    	em[2974] = 72; em[2975] = 24; 
    em[2976] = 8884099; em[2977] = 8; em[2978] = 2; /* 2976: pointer_to_array_of_pointers_to_stack */
    	em[2979] = 2983; em[2980] = 0; 
    	em[2981] = 69; em[2982] = 20; 
    em[2983] = 0; em[2984] = 8; em[2985] = 1; /* 2983: pointer.ASN1_TYPE */
    	em[2986] = 2988; em[2987] = 0; 
    em[2988] = 0; em[2989] = 0; em[2990] = 1; /* 2988: ASN1_TYPE */
    	em[2991] = 2993; em[2992] = 0; 
    em[2993] = 0; em[2994] = 16; em[2995] = 1; /* 2993: struct.asn1_type_st */
    	em[2996] = 2998; em[2997] = 8; 
    em[2998] = 0; em[2999] = 8; em[3000] = 20; /* 2998: union.unknown */
    	em[3001] = 198; em[3002] = 0; 
    	em[3003] = 3041; em[3004] = 0; 
    	em[3005] = 3046; em[3006] = 0; 
    	em[3007] = 3060; em[3008] = 0; 
    	em[3009] = 3065; em[3010] = 0; 
    	em[3011] = 3070; em[3012] = 0; 
    	em[3013] = 3075; em[3014] = 0; 
    	em[3015] = 3080; em[3016] = 0; 
    	em[3017] = 3085; em[3018] = 0; 
    	em[3019] = 1671; em[3020] = 0; 
    	em[3021] = 1666; em[3022] = 0; 
    	em[3023] = 1661; em[3024] = 0; 
    	em[3025] = 1656; em[3026] = 0; 
    	em[3027] = 1651; em[3028] = 0; 
    	em[3029] = 1646; em[3030] = 0; 
    	em[3031] = 1636; em[3032] = 0; 
    	em[3033] = 3090; em[3034] = 0; 
    	em[3035] = 3041; em[3036] = 0; 
    	em[3037] = 3041; em[3038] = 0; 
    	em[3039] = 529; em[3040] = 0; 
    em[3041] = 1; em[3042] = 8; em[3043] = 1; /* 3041: pointer.struct.asn1_string_st */
    	em[3044] = 1641; em[3045] = 0; 
    em[3046] = 1; em[3047] = 8; em[3048] = 1; /* 3046: pointer.struct.asn1_object_st */
    	em[3049] = 3051; em[3050] = 0; 
    em[3051] = 0; em[3052] = 40; em[3053] = 3; /* 3051: struct.asn1_object_st */
    	em[3054] = 56; em[3055] = 0; 
    	em[3056] = 56; em[3057] = 8; 
    	em[3058] = 61; em[3059] = 24; 
    em[3060] = 1; em[3061] = 8; em[3062] = 1; /* 3060: pointer.struct.asn1_string_st */
    	em[3063] = 1641; em[3064] = 0; 
    em[3065] = 1; em[3066] = 8; em[3067] = 1; /* 3065: pointer.struct.asn1_string_st */
    	em[3068] = 1641; em[3069] = 0; 
    em[3070] = 1; em[3071] = 8; em[3072] = 1; /* 3070: pointer.struct.asn1_string_st */
    	em[3073] = 1641; em[3074] = 0; 
    em[3075] = 1; em[3076] = 8; em[3077] = 1; /* 3075: pointer.struct.asn1_string_st */
    	em[3078] = 1641; em[3079] = 0; 
    em[3080] = 1; em[3081] = 8; em[3082] = 1; /* 3080: pointer.struct.asn1_string_st */
    	em[3083] = 1641; em[3084] = 0; 
    em[3085] = 1; em[3086] = 8; em[3087] = 1; /* 3085: pointer.struct.asn1_string_st */
    	em[3088] = 1641; em[3089] = 0; 
    em[3090] = 1; em[3091] = 8; em[3092] = 1; /* 3090: pointer.struct.asn1_string_st */
    	em[3093] = 1641; em[3094] = 0; 
    em[3095] = 1; em[3096] = 8; em[3097] = 1; /* 3095: pointer.struct.X509_POLICY_DATA_st */
    	em[3098] = 1109; em[3099] = 0; 
    em[3100] = 0; em[3101] = 40; em[3102] = 2; /* 3100: struct.X509_POLICY_CACHE_st */
    	em[3103] = 3095; em[3104] = 0; 
    	em[3105] = 1080; em[3106] = 8; 
    em[3107] = 1; em[3108] = 8; em[3109] = 1; /* 3107: pointer.struct.X509_val_st */
    	em[3110] = 3112; em[3111] = 0; 
    em[3112] = 0; em[3113] = 16; em[3114] = 2; /* 3112: struct.X509_val_st */
    	em[3115] = 3119; em[3116] = 0; 
    	em[3117] = 3119; em[3118] = 8; 
    em[3119] = 1; em[3120] = 8; em[3121] = 1; /* 3119: pointer.struct.asn1_string_st */
    	em[3122] = 80; em[3123] = 0; 
    em[3124] = 0; em[3125] = 184; em[3126] = 12; /* 3124: struct.x509_st */
    	em[3127] = 3151; em[3128] = 0; 
    	em[3129] = 3186; em[3130] = 8; 
    	em[3131] = 3244; em[3132] = 16; 
    	em[3133] = 198; em[3134] = 32; 
    	em[3135] = 3254; em[3136] = 40; 
    	em[3137] = 90; em[3138] = 104; 
    	em[3139] = 3268; em[3140] = 112; 
    	em[3141] = 3306; em[3142] = 120; 
    	em[3143] = 1056; em[3144] = 128; 
    	em[3145] = 647; em[3146] = 136; 
    	em[3147] = 642; em[3148] = 144; 
    	em[3149] = 0; em[3150] = 176; 
    em[3151] = 1; em[3152] = 8; em[3153] = 1; /* 3151: pointer.struct.x509_cinf_st */
    	em[3154] = 3156; em[3155] = 0; 
    em[3156] = 0; em[3157] = 104; em[3158] = 11; /* 3156: struct.x509_cinf_st */
    	em[3159] = 3181; em[3160] = 0; 
    	em[3161] = 3181; em[3162] = 8; 
    	em[3163] = 3186; em[3164] = 16; 
    	em[3165] = 3191; em[3166] = 24; 
    	em[3167] = 3107; em[3168] = 32; 
    	em[3169] = 3191; em[3170] = 40; 
    	em[3171] = 3239; em[3172] = 48; 
    	em[3173] = 3244; em[3174] = 56; 
    	em[3175] = 3244; em[3176] = 64; 
    	em[3177] = 1435; em[3178] = 72; 
    	em[3179] = 3249; em[3180] = 80; 
    em[3181] = 1; em[3182] = 8; em[3183] = 1; /* 3181: pointer.struct.asn1_string_st */
    	em[3184] = 80; em[3185] = 0; 
    em[3186] = 1; em[3187] = 8; em[3188] = 1; /* 3186: pointer.struct.X509_algor_st */
    	em[3189] = 124; em[3190] = 0; 
    em[3191] = 1; em[3192] = 8; em[3193] = 1; /* 3191: pointer.struct.X509_name_st */
    	em[3194] = 3196; em[3195] = 0; 
    em[3196] = 0; em[3197] = 40; em[3198] = 3; /* 3196: struct.X509_name_st */
    	em[3199] = 3205; em[3200] = 0; 
    	em[3201] = 3229; em[3202] = 16; 
    	em[3203] = 85; em[3204] = 24; 
    em[3205] = 1; em[3206] = 8; em[3207] = 1; /* 3205: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[3208] = 3210; em[3209] = 0; 
    em[3210] = 0; em[3211] = 32; em[3212] = 2; /* 3210: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[3213] = 3217; em[3214] = 8; 
    	em[3215] = 72; em[3216] = 24; 
    em[3217] = 8884099; em[3218] = 8; em[3219] = 2; /* 3217: pointer_to_array_of_pointers_to_stack */
    	em[3220] = 3224; em[3221] = 0; 
    	em[3222] = 69; em[3223] = 20; 
    em[3224] = 0; em[3225] = 8; em[3226] = 1; /* 3224: pointer.X509_NAME_ENTRY */
    	em[3227] = 356; em[3228] = 0; 
    em[3229] = 1; em[3230] = 8; em[3231] = 1; /* 3229: pointer.struct.buf_mem_st */
    	em[3232] = 3234; em[3233] = 0; 
    em[3234] = 0; em[3235] = 24; em[3236] = 1; /* 3234: struct.buf_mem_st */
    	em[3237] = 198; em[3238] = 8; 
    em[3239] = 1; em[3240] = 8; em[3241] = 1; /* 3239: pointer.struct.X509_pubkey_st */
    	em[3242] = 1682; em[3243] = 0; 
    em[3244] = 1; em[3245] = 8; em[3246] = 1; /* 3244: pointer.struct.asn1_string_st */
    	em[3247] = 80; em[3248] = 0; 
    em[3249] = 0; em[3250] = 24; em[3251] = 1; /* 3249: struct.ASN1_ENCODING_st */
    	em[3252] = 85; em[3253] = 0; 
    em[3254] = 0; em[3255] = 32; em[3256] = 2; /* 3254: struct.crypto_ex_data_st_fake */
    	em[3257] = 3261; em[3258] = 8; 
    	em[3259] = 72; em[3260] = 24; 
    em[3261] = 8884099; em[3262] = 8; em[3263] = 2; /* 3261: pointer_to_array_of_pointers_to_stack */
    	em[3264] = 2147; em[3265] = 0; 
    	em[3266] = 69; em[3267] = 20; 
    em[3268] = 1; em[3269] = 8; em[3270] = 1; /* 3268: pointer.struct.AUTHORITY_KEYID_st */
    	em[3271] = 3273; em[3272] = 0; 
    em[3273] = 0; em[3274] = 24; em[3275] = 3; /* 3273: struct.AUTHORITY_KEYID_st */
    	em[3276] = 1416; em[3277] = 0; 
    	em[3278] = 3282; em[3279] = 8; 
    	em[3280] = 1406; em[3281] = 16; 
    em[3282] = 1; em[3283] = 8; em[3284] = 1; /* 3282: pointer.struct.stack_st_GENERAL_NAME */
    	em[3285] = 3287; em[3286] = 0; 
    em[3287] = 0; em[3288] = 32; em[3289] = 2; /* 3287: struct.stack_st_fake_GENERAL_NAME */
    	em[3290] = 3294; em[3291] = 8; 
    	em[3292] = 72; em[3293] = 24; 
    em[3294] = 8884099; em[3295] = 8; em[3296] = 2; /* 3294: pointer_to_array_of_pointers_to_stack */
    	em[3297] = 3301; em[3298] = 0; 
    	em[3299] = 69; em[3300] = 20; 
    em[3301] = 0; em[3302] = 8; em[3303] = 1; /* 3301: pointer.GENERAL_NAME */
    	em[3304] = 671; em[3305] = 0; 
    em[3306] = 1; em[3307] = 8; em[3308] = 1; /* 3306: pointer.struct.X509_POLICY_CACHE_st */
    	em[3309] = 3100; em[3310] = 0; 
    em[3311] = 1; em[3312] = 8; em[3313] = 1; /* 3311: pointer.int */
    	em[3314] = 69; em[3315] = 0; 
    em[3316] = 1; em[3317] = 8; em[3318] = 1; /* 3316: pointer.struct.x509_st */
    	em[3319] = 3124; em[3320] = 0; 
    em[3321] = 0; em[3322] = 1; em[3323] = 0; /* 3321: char */
    args_addr->arg_entity_index[0] = 3316;
    args_addr->arg_entity_index[1] = 69;
    args_addr->arg_entity_index[2] = 3311;
    args_addr->arg_entity_index[3] = 3311;
    args_addr->ret_entity_index = 2147;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    int new_arg_b = *((int *)new_args->args[1]);

    int * new_arg_c = *((int * *)new_args->args[2]);

    int * new_arg_d = *((int * *)new_args->args[3]);

    void * *new_ret_ptr = (void * *)new_args->ret;

    void * (*orig_X509_get_ext_d2i)(X509 *,int,int *,int *);
    orig_X509_get_ext_d2i = dlsym(RTLD_NEXT, "X509_get_ext_d2i");
    *new_ret_ptr = (*orig_X509_get_ext_d2i)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    free(args_addr);

    return ret;
}

