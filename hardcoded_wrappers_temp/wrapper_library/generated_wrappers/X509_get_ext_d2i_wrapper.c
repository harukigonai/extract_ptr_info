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
    em[0] = 0; em[1] = 0; em[2] = 1; /* 0: X509_ALGOR */
    	em[3] = 5; em[4] = 0; 
    em[5] = 0; em[6] = 16; em[7] = 2; /* 5: struct.X509_algor_st */
    	em[8] = 12; em[9] = 0; 
    	em[10] = 39; em[11] = 8; 
    em[12] = 1; em[13] = 8; em[14] = 1; /* 12: pointer.struct.asn1_object_st */
    	em[15] = 17; em[16] = 0; 
    em[17] = 0; em[18] = 40; em[19] = 3; /* 17: struct.asn1_object_st */
    	em[20] = 26; em[21] = 0; 
    	em[22] = 26; em[23] = 8; 
    	em[24] = 31; em[25] = 24; 
    em[26] = 1; em[27] = 8; em[28] = 1; /* 26: pointer.char */
    	em[29] = 8884096; em[30] = 0; 
    em[31] = 1; em[32] = 8; em[33] = 1; /* 31: pointer.unsigned char */
    	em[34] = 36; em[35] = 0; 
    em[36] = 0; em[37] = 1; em[38] = 0; /* 36: unsigned char */
    em[39] = 1; em[40] = 8; em[41] = 1; /* 39: pointer.struct.asn1_type_st */
    	em[42] = 44; em[43] = 0; 
    em[44] = 0; em[45] = 16; em[46] = 1; /* 44: struct.asn1_type_st */
    	em[47] = 49; em[48] = 8; 
    em[49] = 0; em[50] = 8; em[51] = 20; /* 49: union.unknown */
    	em[52] = 92; em[53] = 0; 
    	em[54] = 97; em[55] = 0; 
    	em[56] = 12; em[57] = 0; 
    	em[58] = 112; em[59] = 0; 
    	em[60] = 117; em[61] = 0; 
    	em[62] = 122; em[63] = 0; 
    	em[64] = 127; em[65] = 0; 
    	em[66] = 132; em[67] = 0; 
    	em[68] = 137; em[69] = 0; 
    	em[70] = 142; em[71] = 0; 
    	em[72] = 147; em[73] = 0; 
    	em[74] = 152; em[75] = 0; 
    	em[76] = 157; em[77] = 0; 
    	em[78] = 162; em[79] = 0; 
    	em[80] = 167; em[81] = 0; 
    	em[82] = 172; em[83] = 0; 
    	em[84] = 177; em[85] = 0; 
    	em[86] = 97; em[87] = 0; 
    	em[88] = 97; em[89] = 0; 
    	em[90] = 182; em[91] = 0; 
    em[92] = 1; em[93] = 8; em[94] = 1; /* 92: pointer.char */
    	em[95] = 8884096; em[96] = 0; 
    em[97] = 1; em[98] = 8; em[99] = 1; /* 97: pointer.struct.asn1_string_st */
    	em[100] = 102; em[101] = 0; 
    em[102] = 0; em[103] = 24; em[104] = 1; /* 102: struct.asn1_string_st */
    	em[105] = 107; em[106] = 8; 
    em[107] = 1; em[108] = 8; em[109] = 1; /* 107: pointer.unsigned char */
    	em[110] = 36; em[111] = 0; 
    em[112] = 1; em[113] = 8; em[114] = 1; /* 112: pointer.struct.asn1_string_st */
    	em[115] = 102; em[116] = 0; 
    em[117] = 1; em[118] = 8; em[119] = 1; /* 117: pointer.struct.asn1_string_st */
    	em[120] = 102; em[121] = 0; 
    em[122] = 1; em[123] = 8; em[124] = 1; /* 122: pointer.struct.asn1_string_st */
    	em[125] = 102; em[126] = 0; 
    em[127] = 1; em[128] = 8; em[129] = 1; /* 127: pointer.struct.asn1_string_st */
    	em[130] = 102; em[131] = 0; 
    em[132] = 1; em[133] = 8; em[134] = 1; /* 132: pointer.struct.asn1_string_st */
    	em[135] = 102; em[136] = 0; 
    em[137] = 1; em[138] = 8; em[139] = 1; /* 137: pointer.struct.asn1_string_st */
    	em[140] = 102; em[141] = 0; 
    em[142] = 1; em[143] = 8; em[144] = 1; /* 142: pointer.struct.asn1_string_st */
    	em[145] = 102; em[146] = 0; 
    em[147] = 1; em[148] = 8; em[149] = 1; /* 147: pointer.struct.asn1_string_st */
    	em[150] = 102; em[151] = 0; 
    em[152] = 1; em[153] = 8; em[154] = 1; /* 152: pointer.struct.asn1_string_st */
    	em[155] = 102; em[156] = 0; 
    em[157] = 1; em[158] = 8; em[159] = 1; /* 157: pointer.struct.asn1_string_st */
    	em[160] = 102; em[161] = 0; 
    em[162] = 1; em[163] = 8; em[164] = 1; /* 162: pointer.struct.asn1_string_st */
    	em[165] = 102; em[166] = 0; 
    em[167] = 1; em[168] = 8; em[169] = 1; /* 167: pointer.struct.asn1_string_st */
    	em[170] = 102; em[171] = 0; 
    em[172] = 1; em[173] = 8; em[174] = 1; /* 172: pointer.struct.asn1_string_st */
    	em[175] = 102; em[176] = 0; 
    em[177] = 1; em[178] = 8; em[179] = 1; /* 177: pointer.struct.asn1_string_st */
    	em[180] = 102; em[181] = 0; 
    em[182] = 1; em[183] = 8; em[184] = 1; /* 182: pointer.struct.ASN1_VALUE_st */
    	em[185] = 187; em[186] = 0; 
    em[187] = 0; em[188] = 0; em[189] = 0; /* 187: struct.ASN1_VALUE_st */
    em[190] = 1; em[191] = 8; em[192] = 1; /* 190: pointer.struct.stack_st_X509_ALGOR */
    	em[193] = 195; em[194] = 0; 
    em[195] = 0; em[196] = 32; em[197] = 2; /* 195: struct.stack_st_fake_X509_ALGOR */
    	em[198] = 202; em[199] = 8; 
    	em[200] = 217; em[201] = 24; 
    em[202] = 8884099; em[203] = 8; em[204] = 2; /* 202: pointer_to_array_of_pointers_to_stack */
    	em[205] = 209; em[206] = 0; 
    	em[207] = 214; em[208] = 20; 
    em[209] = 0; em[210] = 8; em[211] = 1; /* 209: pointer.X509_ALGOR */
    	em[212] = 0; em[213] = 0; 
    em[214] = 0; em[215] = 4; em[216] = 0; /* 214: int */
    em[217] = 8884097; em[218] = 8; em[219] = 0; /* 217: pointer.func */
    em[220] = 1; em[221] = 8; em[222] = 1; /* 220: pointer.struct.stack_st_ASN1_OBJECT */
    	em[223] = 225; em[224] = 0; 
    em[225] = 0; em[226] = 32; em[227] = 2; /* 225: struct.stack_st_fake_ASN1_OBJECT */
    	em[228] = 232; em[229] = 8; 
    	em[230] = 217; em[231] = 24; 
    em[232] = 8884099; em[233] = 8; em[234] = 2; /* 232: pointer_to_array_of_pointers_to_stack */
    	em[235] = 239; em[236] = 0; 
    	em[237] = 214; em[238] = 20; 
    em[239] = 0; em[240] = 8; em[241] = 1; /* 239: pointer.ASN1_OBJECT */
    	em[242] = 244; em[243] = 0; 
    em[244] = 0; em[245] = 0; em[246] = 1; /* 244: ASN1_OBJECT */
    	em[247] = 249; em[248] = 0; 
    em[249] = 0; em[250] = 40; em[251] = 3; /* 249: struct.asn1_object_st */
    	em[252] = 26; em[253] = 0; 
    	em[254] = 26; em[255] = 8; 
    	em[256] = 31; em[257] = 24; 
    em[258] = 1; em[259] = 8; em[260] = 1; /* 258: pointer.struct.x509_cert_aux_st */
    	em[261] = 263; em[262] = 0; 
    em[263] = 0; em[264] = 40; em[265] = 5; /* 263: struct.x509_cert_aux_st */
    	em[266] = 220; em[267] = 0; 
    	em[268] = 220; em[269] = 8; 
    	em[270] = 276; em[271] = 16; 
    	em[272] = 286; em[273] = 24; 
    	em[274] = 190; em[275] = 32; 
    em[276] = 1; em[277] = 8; em[278] = 1; /* 276: pointer.struct.asn1_string_st */
    	em[279] = 281; em[280] = 0; 
    em[281] = 0; em[282] = 24; em[283] = 1; /* 281: struct.asn1_string_st */
    	em[284] = 107; em[285] = 8; 
    em[286] = 1; em[287] = 8; em[288] = 1; /* 286: pointer.struct.asn1_string_st */
    	em[289] = 281; em[290] = 0; 
    em[291] = 1; em[292] = 8; em[293] = 1; /* 291: pointer.struct.EDIPartyName_st */
    	em[294] = 296; em[295] = 0; 
    em[296] = 0; em[297] = 16; em[298] = 2; /* 296: struct.EDIPartyName_st */
    	em[299] = 303; em[300] = 0; 
    	em[301] = 303; em[302] = 8; 
    em[303] = 1; em[304] = 8; em[305] = 1; /* 303: pointer.struct.asn1_string_st */
    	em[306] = 308; em[307] = 0; 
    em[308] = 0; em[309] = 24; em[310] = 1; /* 308: struct.asn1_string_st */
    	em[311] = 107; em[312] = 8; 
    em[313] = 1; em[314] = 8; em[315] = 1; /* 313: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[316] = 318; em[317] = 0; 
    em[318] = 0; em[319] = 32; em[320] = 2; /* 318: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[321] = 325; em[322] = 8; 
    	em[323] = 217; em[324] = 24; 
    em[325] = 8884099; em[326] = 8; em[327] = 2; /* 325: pointer_to_array_of_pointers_to_stack */
    	em[328] = 332; em[329] = 0; 
    	em[330] = 214; em[331] = 20; 
    em[332] = 0; em[333] = 8; em[334] = 1; /* 332: pointer.X509_NAME_ENTRY */
    	em[335] = 337; em[336] = 0; 
    em[337] = 0; em[338] = 0; em[339] = 1; /* 337: X509_NAME_ENTRY */
    	em[340] = 342; em[341] = 0; 
    em[342] = 0; em[343] = 24; em[344] = 2; /* 342: struct.X509_name_entry_st */
    	em[345] = 349; em[346] = 0; 
    	em[347] = 363; em[348] = 8; 
    em[349] = 1; em[350] = 8; em[351] = 1; /* 349: pointer.struct.asn1_object_st */
    	em[352] = 354; em[353] = 0; 
    em[354] = 0; em[355] = 40; em[356] = 3; /* 354: struct.asn1_object_st */
    	em[357] = 26; em[358] = 0; 
    	em[359] = 26; em[360] = 8; 
    	em[361] = 31; em[362] = 24; 
    em[363] = 1; em[364] = 8; em[365] = 1; /* 363: pointer.struct.asn1_string_st */
    	em[366] = 368; em[367] = 0; 
    em[368] = 0; em[369] = 24; em[370] = 1; /* 368: struct.asn1_string_st */
    	em[371] = 107; em[372] = 8; 
    em[373] = 0; em[374] = 40; em[375] = 3; /* 373: struct.X509_name_st */
    	em[376] = 313; em[377] = 0; 
    	em[378] = 382; em[379] = 16; 
    	em[380] = 107; em[381] = 24; 
    em[382] = 1; em[383] = 8; em[384] = 1; /* 382: pointer.struct.buf_mem_st */
    	em[385] = 387; em[386] = 0; 
    em[387] = 0; em[388] = 24; em[389] = 1; /* 387: struct.buf_mem_st */
    	em[390] = 92; em[391] = 8; 
    em[392] = 1; em[393] = 8; em[394] = 1; /* 392: pointer.struct.X509_name_st */
    	em[395] = 373; em[396] = 0; 
    em[397] = 1; em[398] = 8; em[399] = 1; /* 397: pointer.struct.asn1_string_st */
    	em[400] = 308; em[401] = 0; 
    em[402] = 1; em[403] = 8; em[404] = 1; /* 402: pointer.struct.asn1_string_st */
    	em[405] = 308; em[406] = 0; 
    em[407] = 1; em[408] = 8; em[409] = 1; /* 407: pointer.struct.asn1_string_st */
    	em[410] = 308; em[411] = 0; 
    em[412] = 1; em[413] = 8; em[414] = 1; /* 412: pointer.struct.asn1_string_st */
    	em[415] = 308; em[416] = 0; 
    em[417] = 1; em[418] = 8; em[419] = 1; /* 417: pointer.struct.asn1_string_st */
    	em[420] = 308; em[421] = 0; 
    em[422] = 0; em[423] = 8; em[424] = 20; /* 422: union.unknown */
    	em[425] = 92; em[426] = 0; 
    	em[427] = 303; em[428] = 0; 
    	em[429] = 465; em[430] = 0; 
    	em[431] = 479; em[432] = 0; 
    	em[433] = 484; em[434] = 0; 
    	em[435] = 489; em[436] = 0; 
    	em[437] = 417; em[438] = 0; 
    	em[439] = 494; em[440] = 0; 
    	em[441] = 412; em[442] = 0; 
    	em[443] = 499; em[444] = 0; 
    	em[445] = 407; em[446] = 0; 
    	em[447] = 402; em[448] = 0; 
    	em[449] = 504; em[450] = 0; 
    	em[451] = 509; em[452] = 0; 
    	em[453] = 397; em[454] = 0; 
    	em[455] = 514; em[456] = 0; 
    	em[457] = 519; em[458] = 0; 
    	em[459] = 303; em[460] = 0; 
    	em[461] = 303; em[462] = 0; 
    	em[463] = 524; em[464] = 0; 
    em[465] = 1; em[466] = 8; em[467] = 1; /* 465: pointer.struct.asn1_object_st */
    	em[468] = 470; em[469] = 0; 
    em[470] = 0; em[471] = 40; em[472] = 3; /* 470: struct.asn1_object_st */
    	em[473] = 26; em[474] = 0; 
    	em[475] = 26; em[476] = 8; 
    	em[477] = 31; em[478] = 24; 
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
    em[524] = 1; em[525] = 8; em[526] = 1; /* 524: pointer.struct.ASN1_VALUE_st */
    	em[527] = 529; em[528] = 0; 
    em[529] = 0; em[530] = 0; em[531] = 0; /* 529: struct.ASN1_VALUE_st */
    em[532] = 1; em[533] = 8; em[534] = 1; /* 532: pointer.struct.otherName_st */
    	em[535] = 537; em[536] = 0; 
    em[537] = 0; em[538] = 16; em[539] = 2; /* 537: struct.otherName_st */
    	em[540] = 465; em[541] = 0; 
    	em[542] = 544; em[543] = 8; 
    em[544] = 1; em[545] = 8; em[546] = 1; /* 544: pointer.struct.asn1_type_st */
    	em[547] = 549; em[548] = 0; 
    em[549] = 0; em[550] = 16; em[551] = 1; /* 549: struct.asn1_type_st */
    	em[552] = 422; em[553] = 8; 
    em[554] = 0; em[555] = 16; em[556] = 1; /* 554: struct.GENERAL_NAME_st */
    	em[557] = 559; em[558] = 8; 
    em[559] = 0; em[560] = 8; em[561] = 15; /* 559: union.unknown */
    	em[562] = 92; em[563] = 0; 
    	em[564] = 532; em[565] = 0; 
    	em[566] = 499; em[567] = 0; 
    	em[568] = 499; em[569] = 0; 
    	em[570] = 544; em[571] = 0; 
    	em[572] = 392; em[573] = 0; 
    	em[574] = 291; em[575] = 0; 
    	em[576] = 499; em[577] = 0; 
    	em[578] = 417; em[579] = 0; 
    	em[580] = 465; em[581] = 0; 
    	em[582] = 417; em[583] = 0; 
    	em[584] = 392; em[585] = 0; 
    	em[586] = 499; em[587] = 0; 
    	em[588] = 465; em[589] = 0; 
    	em[590] = 544; em[591] = 0; 
    em[592] = 1; em[593] = 8; em[594] = 1; /* 592: pointer.struct.GENERAL_NAME_st */
    	em[595] = 554; em[596] = 0; 
    em[597] = 1; em[598] = 8; em[599] = 1; /* 597: pointer.struct.NAME_CONSTRAINTS_st */
    	em[600] = 602; em[601] = 0; 
    em[602] = 0; em[603] = 16; em[604] = 2; /* 602: struct.NAME_CONSTRAINTS_st */
    	em[605] = 609; em[606] = 0; 
    	em[607] = 609; em[608] = 8; 
    em[609] = 1; em[610] = 8; em[611] = 1; /* 609: pointer.struct.stack_st_GENERAL_SUBTREE */
    	em[612] = 614; em[613] = 0; 
    em[614] = 0; em[615] = 32; em[616] = 2; /* 614: struct.stack_st_fake_GENERAL_SUBTREE */
    	em[617] = 621; em[618] = 8; 
    	em[619] = 217; em[620] = 24; 
    em[621] = 8884099; em[622] = 8; em[623] = 2; /* 621: pointer_to_array_of_pointers_to_stack */
    	em[624] = 628; em[625] = 0; 
    	em[626] = 214; em[627] = 20; 
    em[628] = 0; em[629] = 8; em[630] = 1; /* 628: pointer.GENERAL_SUBTREE */
    	em[631] = 633; em[632] = 0; 
    em[633] = 0; em[634] = 0; em[635] = 1; /* 633: GENERAL_SUBTREE */
    	em[636] = 638; em[637] = 0; 
    em[638] = 0; em[639] = 24; em[640] = 3; /* 638: struct.GENERAL_SUBTREE_st */
    	em[641] = 592; em[642] = 0; 
    	em[643] = 479; em[644] = 8; 
    	em[645] = 479; em[646] = 16; 
    em[647] = 1; em[648] = 8; em[649] = 1; /* 647: pointer.struct.stack_st_GENERAL_NAME */
    	em[650] = 652; em[651] = 0; 
    em[652] = 0; em[653] = 32; em[654] = 2; /* 652: struct.stack_st_fake_GENERAL_NAME */
    	em[655] = 659; em[656] = 8; 
    	em[657] = 217; em[658] = 24; 
    em[659] = 8884099; em[660] = 8; em[661] = 2; /* 659: pointer_to_array_of_pointers_to_stack */
    	em[662] = 666; em[663] = 0; 
    	em[664] = 214; em[665] = 20; 
    em[666] = 0; em[667] = 8; em[668] = 1; /* 666: pointer.GENERAL_NAME */
    	em[669] = 671; em[670] = 0; 
    em[671] = 0; em[672] = 0; em[673] = 1; /* 671: GENERAL_NAME */
    	em[674] = 676; em[675] = 0; 
    em[676] = 0; em[677] = 16; em[678] = 1; /* 676: struct.GENERAL_NAME_st */
    	em[679] = 681; em[680] = 8; 
    em[681] = 0; em[682] = 8; em[683] = 15; /* 681: union.unknown */
    	em[684] = 92; em[685] = 0; 
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
    	em[734] = 26; em[735] = 0; 
    	em[736] = 26; em[737] = 8; 
    	em[738] = 31; em[739] = 24; 
    em[740] = 1; em[741] = 8; em[742] = 1; /* 740: pointer.struct.asn1_type_st */
    	em[743] = 745; em[744] = 0; 
    em[745] = 0; em[746] = 16; em[747] = 1; /* 745: struct.asn1_type_st */
    	em[748] = 750; em[749] = 8; 
    em[750] = 0; em[751] = 8; em[752] = 20; /* 750: union.unknown */
    	em[753] = 92; em[754] = 0; 
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
    	em[801] = 107; em[802] = 8; 
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
    	em[893] = 107; em[894] = 24; 
    em[895] = 1; em[896] = 8; em[897] = 1; /* 895: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[898] = 900; em[899] = 0; 
    em[900] = 0; em[901] = 32; em[902] = 2; /* 900: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[903] = 907; em[904] = 8; 
    	em[905] = 217; em[906] = 24; 
    em[907] = 8884099; em[908] = 8; em[909] = 2; /* 907: pointer_to_array_of_pointers_to_stack */
    	em[910] = 914; em[911] = 0; 
    	em[912] = 214; em[913] = 20; 
    em[914] = 0; em[915] = 8; em[916] = 1; /* 914: pointer.X509_NAME_ENTRY */
    	em[917] = 337; em[918] = 0; 
    em[919] = 1; em[920] = 8; em[921] = 1; /* 919: pointer.struct.buf_mem_st */
    	em[922] = 924; em[923] = 0; 
    em[924] = 0; em[925] = 24; em[926] = 1; /* 924: struct.buf_mem_st */
    	em[927] = 92; em[928] = 8; 
    em[929] = 1; em[930] = 8; em[931] = 1; /* 929: pointer.struct.EDIPartyName_st */
    	em[932] = 934; em[933] = 0; 
    em[934] = 0; em[935] = 16; em[936] = 2; /* 934: struct.EDIPartyName_st */
    	em[937] = 793; em[938] = 0; 
    	em[939] = 793; em[940] = 8; 
    em[941] = 0; em[942] = 24; em[943] = 1; /* 941: struct.asn1_string_st */
    	em[944] = 107; em[945] = 8; 
    em[946] = 1; em[947] = 8; em[948] = 1; /* 946: pointer.struct.buf_mem_st */
    	em[949] = 951; em[950] = 0; 
    em[951] = 0; em[952] = 24; em[953] = 1; /* 951: struct.buf_mem_st */
    	em[954] = 92; em[955] = 8; 
    em[956] = 0; em[957] = 8; em[958] = 2; /* 956: union.unknown */
    	em[959] = 963; em[960] = 0; 
    	em[961] = 987; em[962] = 0; 
    em[963] = 1; em[964] = 8; em[965] = 1; /* 963: pointer.struct.stack_st_GENERAL_NAME */
    	em[966] = 968; em[967] = 0; 
    em[968] = 0; em[969] = 32; em[970] = 2; /* 968: struct.stack_st_fake_GENERAL_NAME */
    	em[971] = 975; em[972] = 8; 
    	em[973] = 217; em[974] = 24; 
    em[975] = 8884099; em[976] = 8; em[977] = 2; /* 975: pointer_to_array_of_pointers_to_stack */
    	em[978] = 982; em[979] = 0; 
    	em[980] = 214; em[981] = 20; 
    em[982] = 0; em[983] = 8; em[984] = 1; /* 982: pointer.GENERAL_NAME */
    	em[985] = 671; em[986] = 0; 
    em[987] = 1; em[988] = 8; em[989] = 1; /* 987: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[990] = 992; em[991] = 0; 
    em[992] = 0; em[993] = 32; em[994] = 2; /* 992: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[995] = 999; em[996] = 8; 
    	em[997] = 217; em[998] = 24; 
    em[999] = 8884099; em[1000] = 8; em[1001] = 2; /* 999: pointer_to_array_of_pointers_to_stack */
    	em[1002] = 1006; em[1003] = 0; 
    	em[1004] = 214; em[1005] = 20; 
    em[1006] = 0; em[1007] = 8; em[1008] = 1; /* 1006: pointer.X509_NAME_ENTRY */
    	em[1009] = 337; em[1010] = 0; 
    em[1011] = 0; em[1012] = 24; em[1013] = 2; /* 1011: struct.DIST_POINT_NAME_st */
    	em[1014] = 956; em[1015] = 8; 
    	em[1016] = 1018; em[1017] = 16; 
    em[1018] = 1; em[1019] = 8; em[1020] = 1; /* 1018: pointer.struct.X509_name_st */
    	em[1021] = 1023; em[1022] = 0; 
    em[1023] = 0; em[1024] = 40; em[1025] = 3; /* 1023: struct.X509_name_st */
    	em[1026] = 987; em[1027] = 0; 
    	em[1028] = 946; em[1029] = 16; 
    	em[1030] = 107; em[1031] = 24; 
    em[1032] = 1; em[1033] = 8; em[1034] = 1; /* 1032: pointer.struct.DIST_POINT_NAME_st */
    	em[1035] = 1011; em[1036] = 0; 
    em[1037] = 1; em[1038] = 8; em[1039] = 1; /* 1037: pointer.struct.stack_st_DIST_POINT */
    	em[1040] = 1042; em[1041] = 0; 
    em[1042] = 0; em[1043] = 32; em[1044] = 2; /* 1042: struct.stack_st_fake_DIST_POINT */
    	em[1045] = 1049; em[1046] = 8; 
    	em[1047] = 217; em[1048] = 24; 
    em[1049] = 8884099; em[1050] = 8; em[1051] = 2; /* 1049: pointer_to_array_of_pointers_to_stack */
    	em[1052] = 1056; em[1053] = 0; 
    	em[1054] = 214; em[1055] = 20; 
    em[1056] = 0; em[1057] = 8; em[1058] = 1; /* 1056: pointer.DIST_POINT */
    	em[1059] = 1061; em[1060] = 0; 
    em[1061] = 0; em[1062] = 0; em[1063] = 1; /* 1061: DIST_POINT */
    	em[1064] = 1066; em[1065] = 0; 
    em[1066] = 0; em[1067] = 32; em[1068] = 3; /* 1066: struct.DIST_POINT_st */
    	em[1069] = 1032; em[1070] = 0; 
    	em[1071] = 1075; em[1072] = 8; 
    	em[1073] = 963; em[1074] = 16; 
    em[1075] = 1; em[1076] = 8; em[1077] = 1; /* 1075: pointer.struct.asn1_string_st */
    	em[1078] = 941; em[1079] = 0; 
    em[1080] = 0; em[1081] = 32; em[1082] = 3; /* 1080: struct.X509_POLICY_DATA_st */
    	em[1083] = 1089; em[1084] = 8; 
    	em[1085] = 1103; em[1086] = 16; 
    	em[1087] = 1348; em[1088] = 24; 
    em[1089] = 1; em[1090] = 8; em[1091] = 1; /* 1089: pointer.struct.asn1_object_st */
    	em[1092] = 1094; em[1093] = 0; 
    em[1094] = 0; em[1095] = 40; em[1096] = 3; /* 1094: struct.asn1_object_st */
    	em[1097] = 26; em[1098] = 0; 
    	em[1099] = 26; em[1100] = 8; 
    	em[1101] = 31; em[1102] = 24; 
    em[1103] = 1; em[1104] = 8; em[1105] = 1; /* 1103: pointer.struct.stack_st_POLICYQUALINFO */
    	em[1106] = 1108; em[1107] = 0; 
    em[1108] = 0; em[1109] = 32; em[1110] = 2; /* 1108: struct.stack_st_fake_POLICYQUALINFO */
    	em[1111] = 1115; em[1112] = 8; 
    	em[1113] = 217; em[1114] = 24; 
    em[1115] = 8884099; em[1116] = 8; em[1117] = 2; /* 1115: pointer_to_array_of_pointers_to_stack */
    	em[1118] = 1122; em[1119] = 0; 
    	em[1120] = 214; em[1121] = 20; 
    em[1122] = 0; em[1123] = 8; em[1124] = 1; /* 1122: pointer.POLICYQUALINFO */
    	em[1125] = 1127; em[1126] = 0; 
    em[1127] = 0; em[1128] = 0; em[1129] = 1; /* 1127: POLICYQUALINFO */
    	em[1130] = 1132; em[1131] = 0; 
    em[1132] = 0; em[1133] = 16; em[1134] = 2; /* 1132: struct.POLICYQUALINFO_st */
    	em[1135] = 1139; em[1136] = 0; 
    	em[1137] = 1153; em[1138] = 8; 
    em[1139] = 1; em[1140] = 8; em[1141] = 1; /* 1139: pointer.struct.asn1_object_st */
    	em[1142] = 1144; em[1143] = 0; 
    em[1144] = 0; em[1145] = 40; em[1146] = 3; /* 1144: struct.asn1_object_st */
    	em[1147] = 26; em[1148] = 0; 
    	em[1149] = 26; em[1150] = 8; 
    	em[1151] = 31; em[1152] = 24; 
    em[1153] = 0; em[1154] = 8; em[1155] = 3; /* 1153: union.unknown */
    	em[1156] = 1162; em[1157] = 0; 
    	em[1158] = 1172; em[1159] = 0; 
    	em[1160] = 1230; em[1161] = 0; 
    em[1162] = 1; em[1163] = 8; em[1164] = 1; /* 1162: pointer.struct.asn1_string_st */
    	em[1165] = 1167; em[1166] = 0; 
    em[1167] = 0; em[1168] = 24; em[1169] = 1; /* 1167: struct.asn1_string_st */
    	em[1170] = 107; em[1171] = 8; 
    em[1172] = 1; em[1173] = 8; em[1174] = 1; /* 1172: pointer.struct.USERNOTICE_st */
    	em[1175] = 1177; em[1176] = 0; 
    em[1177] = 0; em[1178] = 16; em[1179] = 2; /* 1177: struct.USERNOTICE_st */
    	em[1180] = 1184; em[1181] = 0; 
    	em[1182] = 1196; em[1183] = 8; 
    em[1184] = 1; em[1185] = 8; em[1186] = 1; /* 1184: pointer.struct.NOTICEREF_st */
    	em[1187] = 1189; em[1188] = 0; 
    em[1189] = 0; em[1190] = 16; em[1191] = 2; /* 1189: struct.NOTICEREF_st */
    	em[1192] = 1196; em[1193] = 0; 
    	em[1194] = 1201; em[1195] = 8; 
    em[1196] = 1; em[1197] = 8; em[1198] = 1; /* 1196: pointer.struct.asn1_string_st */
    	em[1199] = 1167; em[1200] = 0; 
    em[1201] = 1; em[1202] = 8; em[1203] = 1; /* 1201: pointer.struct.stack_st_ASN1_INTEGER */
    	em[1204] = 1206; em[1205] = 0; 
    em[1206] = 0; em[1207] = 32; em[1208] = 2; /* 1206: struct.stack_st_fake_ASN1_INTEGER */
    	em[1209] = 1213; em[1210] = 8; 
    	em[1211] = 217; em[1212] = 24; 
    em[1213] = 8884099; em[1214] = 8; em[1215] = 2; /* 1213: pointer_to_array_of_pointers_to_stack */
    	em[1216] = 1220; em[1217] = 0; 
    	em[1218] = 214; em[1219] = 20; 
    em[1220] = 0; em[1221] = 8; em[1222] = 1; /* 1220: pointer.ASN1_INTEGER */
    	em[1223] = 1225; em[1224] = 0; 
    em[1225] = 0; em[1226] = 0; em[1227] = 1; /* 1225: ASN1_INTEGER */
    	em[1228] = 102; em[1229] = 0; 
    em[1230] = 1; em[1231] = 8; em[1232] = 1; /* 1230: pointer.struct.asn1_type_st */
    	em[1233] = 1235; em[1234] = 0; 
    em[1235] = 0; em[1236] = 16; em[1237] = 1; /* 1235: struct.asn1_type_st */
    	em[1238] = 1240; em[1239] = 8; 
    em[1240] = 0; em[1241] = 8; em[1242] = 20; /* 1240: union.unknown */
    	em[1243] = 92; em[1244] = 0; 
    	em[1245] = 1196; em[1246] = 0; 
    	em[1247] = 1139; em[1248] = 0; 
    	em[1249] = 1283; em[1250] = 0; 
    	em[1251] = 1288; em[1252] = 0; 
    	em[1253] = 1293; em[1254] = 0; 
    	em[1255] = 1298; em[1256] = 0; 
    	em[1257] = 1303; em[1258] = 0; 
    	em[1259] = 1308; em[1260] = 0; 
    	em[1261] = 1162; em[1262] = 0; 
    	em[1263] = 1313; em[1264] = 0; 
    	em[1265] = 1318; em[1266] = 0; 
    	em[1267] = 1323; em[1268] = 0; 
    	em[1269] = 1328; em[1270] = 0; 
    	em[1271] = 1333; em[1272] = 0; 
    	em[1273] = 1338; em[1274] = 0; 
    	em[1275] = 1343; em[1276] = 0; 
    	em[1277] = 1196; em[1278] = 0; 
    	em[1279] = 1196; em[1280] = 0; 
    	em[1281] = 524; em[1282] = 0; 
    em[1283] = 1; em[1284] = 8; em[1285] = 1; /* 1283: pointer.struct.asn1_string_st */
    	em[1286] = 1167; em[1287] = 0; 
    em[1288] = 1; em[1289] = 8; em[1290] = 1; /* 1288: pointer.struct.asn1_string_st */
    	em[1291] = 1167; em[1292] = 0; 
    em[1293] = 1; em[1294] = 8; em[1295] = 1; /* 1293: pointer.struct.asn1_string_st */
    	em[1296] = 1167; em[1297] = 0; 
    em[1298] = 1; em[1299] = 8; em[1300] = 1; /* 1298: pointer.struct.asn1_string_st */
    	em[1301] = 1167; em[1302] = 0; 
    em[1303] = 1; em[1304] = 8; em[1305] = 1; /* 1303: pointer.struct.asn1_string_st */
    	em[1306] = 1167; em[1307] = 0; 
    em[1308] = 1; em[1309] = 8; em[1310] = 1; /* 1308: pointer.struct.asn1_string_st */
    	em[1311] = 1167; em[1312] = 0; 
    em[1313] = 1; em[1314] = 8; em[1315] = 1; /* 1313: pointer.struct.asn1_string_st */
    	em[1316] = 1167; em[1317] = 0; 
    em[1318] = 1; em[1319] = 8; em[1320] = 1; /* 1318: pointer.struct.asn1_string_st */
    	em[1321] = 1167; em[1322] = 0; 
    em[1323] = 1; em[1324] = 8; em[1325] = 1; /* 1323: pointer.struct.asn1_string_st */
    	em[1326] = 1167; em[1327] = 0; 
    em[1328] = 1; em[1329] = 8; em[1330] = 1; /* 1328: pointer.struct.asn1_string_st */
    	em[1331] = 1167; em[1332] = 0; 
    em[1333] = 1; em[1334] = 8; em[1335] = 1; /* 1333: pointer.struct.asn1_string_st */
    	em[1336] = 1167; em[1337] = 0; 
    em[1338] = 1; em[1339] = 8; em[1340] = 1; /* 1338: pointer.struct.asn1_string_st */
    	em[1341] = 1167; em[1342] = 0; 
    em[1343] = 1; em[1344] = 8; em[1345] = 1; /* 1343: pointer.struct.asn1_string_st */
    	em[1346] = 1167; em[1347] = 0; 
    em[1348] = 1; em[1349] = 8; em[1350] = 1; /* 1348: pointer.struct.stack_st_ASN1_OBJECT */
    	em[1351] = 1353; em[1352] = 0; 
    em[1353] = 0; em[1354] = 32; em[1355] = 2; /* 1353: struct.stack_st_fake_ASN1_OBJECT */
    	em[1356] = 1360; em[1357] = 8; 
    	em[1358] = 217; em[1359] = 24; 
    em[1360] = 8884099; em[1361] = 8; em[1362] = 2; /* 1360: pointer_to_array_of_pointers_to_stack */
    	em[1363] = 1367; em[1364] = 0; 
    	em[1365] = 214; em[1366] = 20; 
    em[1367] = 0; em[1368] = 8; em[1369] = 1; /* 1367: pointer.ASN1_OBJECT */
    	em[1370] = 244; em[1371] = 0; 
    em[1372] = 1; em[1373] = 8; em[1374] = 1; /* 1372: pointer.struct.stack_st_X509_POLICY_DATA */
    	em[1375] = 1377; em[1376] = 0; 
    em[1377] = 0; em[1378] = 32; em[1379] = 2; /* 1377: struct.stack_st_fake_X509_POLICY_DATA */
    	em[1380] = 1384; em[1381] = 8; 
    	em[1382] = 217; em[1383] = 24; 
    em[1384] = 8884099; em[1385] = 8; em[1386] = 2; /* 1384: pointer_to_array_of_pointers_to_stack */
    	em[1387] = 1391; em[1388] = 0; 
    	em[1389] = 214; em[1390] = 20; 
    em[1391] = 0; em[1392] = 8; em[1393] = 1; /* 1391: pointer.X509_POLICY_DATA */
    	em[1394] = 1396; em[1395] = 0; 
    em[1396] = 0; em[1397] = 0; em[1398] = 1; /* 1396: X509_POLICY_DATA */
    	em[1399] = 1080; em[1400] = 0; 
    em[1401] = 1; em[1402] = 8; em[1403] = 1; /* 1401: pointer.struct.stack_st_ASN1_OBJECT */
    	em[1404] = 1406; em[1405] = 0; 
    em[1406] = 0; em[1407] = 32; em[1408] = 2; /* 1406: struct.stack_st_fake_ASN1_OBJECT */
    	em[1409] = 1413; em[1410] = 8; 
    	em[1411] = 217; em[1412] = 24; 
    em[1413] = 8884099; em[1414] = 8; em[1415] = 2; /* 1413: pointer_to_array_of_pointers_to_stack */
    	em[1416] = 1420; em[1417] = 0; 
    	em[1418] = 214; em[1419] = 20; 
    em[1420] = 0; em[1421] = 8; em[1422] = 1; /* 1420: pointer.ASN1_OBJECT */
    	em[1423] = 244; em[1424] = 0; 
    em[1425] = 1; em[1426] = 8; em[1427] = 1; /* 1425: pointer.struct.stack_st_POLICYQUALINFO */
    	em[1428] = 1430; em[1429] = 0; 
    em[1430] = 0; em[1431] = 32; em[1432] = 2; /* 1430: struct.stack_st_fake_POLICYQUALINFO */
    	em[1433] = 1437; em[1434] = 8; 
    	em[1435] = 217; em[1436] = 24; 
    em[1437] = 8884099; em[1438] = 8; em[1439] = 2; /* 1437: pointer_to_array_of_pointers_to_stack */
    	em[1440] = 1444; em[1441] = 0; 
    	em[1442] = 214; em[1443] = 20; 
    em[1444] = 0; em[1445] = 8; em[1446] = 1; /* 1444: pointer.POLICYQUALINFO */
    	em[1447] = 1127; em[1448] = 0; 
    em[1449] = 0; em[1450] = 40; em[1451] = 3; /* 1449: struct.asn1_object_st */
    	em[1452] = 26; em[1453] = 0; 
    	em[1454] = 26; em[1455] = 8; 
    	em[1456] = 31; em[1457] = 24; 
    em[1458] = 0; em[1459] = 32; em[1460] = 3; /* 1458: struct.X509_POLICY_DATA_st */
    	em[1461] = 1467; em[1462] = 8; 
    	em[1463] = 1425; em[1464] = 16; 
    	em[1465] = 1401; em[1466] = 24; 
    em[1467] = 1; em[1468] = 8; em[1469] = 1; /* 1467: pointer.struct.asn1_object_st */
    	em[1470] = 1449; em[1471] = 0; 
    em[1472] = 1; em[1473] = 8; em[1474] = 1; /* 1472: pointer.struct.X509_POLICY_DATA_st */
    	em[1475] = 1458; em[1476] = 0; 
    em[1477] = 0; em[1478] = 40; em[1479] = 2; /* 1477: struct.X509_POLICY_CACHE_st */
    	em[1480] = 1472; em[1481] = 0; 
    	em[1482] = 1372; em[1483] = 8; 
    em[1484] = 1; em[1485] = 8; em[1486] = 1; /* 1484: pointer.struct.asn1_string_st */
    	em[1487] = 1489; em[1488] = 0; 
    em[1489] = 0; em[1490] = 24; em[1491] = 1; /* 1489: struct.asn1_string_st */
    	em[1492] = 107; em[1493] = 8; 
    em[1494] = 1; em[1495] = 8; em[1496] = 1; /* 1494: pointer.struct.stack_st_GENERAL_NAME */
    	em[1497] = 1499; em[1498] = 0; 
    em[1499] = 0; em[1500] = 32; em[1501] = 2; /* 1499: struct.stack_st_fake_GENERAL_NAME */
    	em[1502] = 1506; em[1503] = 8; 
    	em[1504] = 217; em[1505] = 24; 
    em[1506] = 8884099; em[1507] = 8; em[1508] = 2; /* 1506: pointer_to_array_of_pointers_to_stack */
    	em[1509] = 1513; em[1510] = 0; 
    	em[1511] = 214; em[1512] = 20; 
    em[1513] = 0; em[1514] = 8; em[1515] = 1; /* 1513: pointer.GENERAL_NAME */
    	em[1516] = 671; em[1517] = 0; 
    em[1518] = 1; em[1519] = 8; em[1520] = 1; /* 1518: pointer.struct.asn1_string_st */
    	em[1521] = 1489; em[1522] = 0; 
    em[1523] = 0; em[1524] = 40; em[1525] = 3; /* 1523: struct.asn1_object_st */
    	em[1526] = 26; em[1527] = 0; 
    	em[1528] = 26; em[1529] = 8; 
    	em[1530] = 31; em[1531] = 24; 
    em[1532] = 1; em[1533] = 8; em[1534] = 1; /* 1532: pointer.struct.asn1_object_st */
    	em[1535] = 1523; em[1536] = 0; 
    em[1537] = 0; em[1538] = 24; em[1539] = 2; /* 1537: struct.X509_extension_st */
    	em[1540] = 1532; em[1541] = 0; 
    	em[1542] = 286; em[1543] = 16; 
    em[1544] = 0; em[1545] = 0; em[1546] = 1; /* 1544: X509_EXTENSION */
    	em[1547] = 1537; em[1548] = 0; 
    em[1549] = 1; em[1550] = 8; em[1551] = 1; /* 1549: pointer.struct.stack_st_X509_EXTENSION */
    	em[1552] = 1554; em[1553] = 0; 
    em[1554] = 0; em[1555] = 32; em[1556] = 2; /* 1554: struct.stack_st_fake_X509_EXTENSION */
    	em[1557] = 1561; em[1558] = 8; 
    	em[1559] = 217; em[1560] = 24; 
    em[1561] = 8884099; em[1562] = 8; em[1563] = 2; /* 1561: pointer_to_array_of_pointers_to_stack */
    	em[1564] = 1568; em[1565] = 0; 
    	em[1566] = 214; em[1567] = 20; 
    em[1568] = 0; em[1569] = 8; em[1570] = 1; /* 1568: pointer.X509_EXTENSION */
    	em[1571] = 1544; em[1572] = 0; 
    em[1573] = 1; em[1574] = 8; em[1575] = 1; /* 1573: pointer.struct.asn1_string_st */
    	em[1576] = 281; em[1577] = 0; 
    em[1578] = 1; em[1579] = 8; em[1580] = 1; /* 1578: pointer.struct.asn1_string_st */
    	em[1581] = 1583; em[1582] = 0; 
    em[1583] = 0; em[1584] = 24; em[1585] = 1; /* 1583: struct.asn1_string_st */
    	em[1586] = 107; em[1587] = 8; 
    em[1588] = 1; em[1589] = 8; em[1590] = 1; /* 1588: pointer.struct.asn1_string_st */
    	em[1591] = 1583; em[1592] = 0; 
    em[1593] = 1; em[1594] = 8; em[1595] = 1; /* 1593: pointer.struct.asn1_string_st */
    	em[1596] = 1583; em[1597] = 0; 
    em[1598] = 1; em[1599] = 8; em[1600] = 1; /* 1598: pointer.struct.asn1_string_st */
    	em[1601] = 1583; em[1602] = 0; 
    em[1603] = 1; em[1604] = 8; em[1605] = 1; /* 1603: pointer.struct.asn1_string_st */
    	em[1606] = 1583; em[1607] = 0; 
    em[1608] = 1; em[1609] = 8; em[1610] = 1; /* 1608: pointer.struct.asn1_string_st */
    	em[1611] = 1583; em[1612] = 0; 
    em[1613] = 1; em[1614] = 8; em[1615] = 1; /* 1613: pointer.struct.asn1_string_st */
    	em[1616] = 1583; em[1617] = 0; 
    em[1618] = 1; em[1619] = 8; em[1620] = 1; /* 1618: pointer.struct.asn1_string_st */
    	em[1621] = 1583; em[1622] = 0; 
    em[1623] = 1; em[1624] = 8; em[1625] = 1; /* 1623: pointer.struct.asn1_string_st */
    	em[1626] = 1583; em[1627] = 0; 
    em[1628] = 1; em[1629] = 8; em[1630] = 1; /* 1628: pointer.struct.asn1_string_st */
    	em[1631] = 1583; em[1632] = 0; 
    em[1633] = 0; em[1634] = 16; em[1635] = 1; /* 1633: struct.asn1_type_st */
    	em[1636] = 1638; em[1637] = 8; 
    em[1638] = 0; em[1639] = 8; em[1640] = 20; /* 1638: union.unknown */
    	em[1641] = 92; em[1642] = 0; 
    	em[1643] = 1628; em[1644] = 0; 
    	em[1645] = 1681; em[1646] = 0; 
    	em[1647] = 1695; em[1648] = 0; 
    	em[1649] = 1623; em[1650] = 0; 
    	em[1651] = 1700; em[1652] = 0; 
    	em[1653] = 1618; em[1654] = 0; 
    	em[1655] = 1705; em[1656] = 0; 
    	em[1657] = 1613; em[1658] = 0; 
    	em[1659] = 1608; em[1660] = 0; 
    	em[1661] = 1603; em[1662] = 0; 
    	em[1663] = 1598; em[1664] = 0; 
    	em[1665] = 1710; em[1666] = 0; 
    	em[1667] = 1593; em[1668] = 0; 
    	em[1669] = 1588; em[1670] = 0; 
    	em[1671] = 1715; em[1672] = 0; 
    	em[1673] = 1578; em[1674] = 0; 
    	em[1675] = 1628; em[1676] = 0; 
    	em[1677] = 1628; em[1678] = 0; 
    	em[1679] = 182; em[1680] = 0; 
    em[1681] = 1; em[1682] = 8; em[1683] = 1; /* 1681: pointer.struct.asn1_object_st */
    	em[1684] = 1686; em[1685] = 0; 
    em[1686] = 0; em[1687] = 40; em[1688] = 3; /* 1686: struct.asn1_object_st */
    	em[1689] = 26; em[1690] = 0; 
    	em[1691] = 26; em[1692] = 8; 
    	em[1693] = 31; em[1694] = 24; 
    em[1695] = 1; em[1696] = 8; em[1697] = 1; /* 1695: pointer.struct.asn1_string_st */
    	em[1698] = 1583; em[1699] = 0; 
    em[1700] = 1; em[1701] = 8; em[1702] = 1; /* 1700: pointer.struct.asn1_string_st */
    	em[1703] = 1583; em[1704] = 0; 
    em[1705] = 1; em[1706] = 8; em[1707] = 1; /* 1705: pointer.struct.asn1_string_st */
    	em[1708] = 1583; em[1709] = 0; 
    em[1710] = 1; em[1711] = 8; em[1712] = 1; /* 1710: pointer.struct.asn1_string_st */
    	em[1713] = 1583; em[1714] = 0; 
    em[1715] = 1; em[1716] = 8; em[1717] = 1; /* 1715: pointer.struct.asn1_string_st */
    	em[1718] = 1583; em[1719] = 0; 
    em[1720] = 1; em[1721] = 8; em[1722] = 1; /* 1720: pointer.struct.ASN1_VALUE_st */
    	em[1723] = 1725; em[1724] = 0; 
    em[1725] = 0; em[1726] = 0; em[1727] = 0; /* 1725: struct.ASN1_VALUE_st */
    em[1728] = 1; em[1729] = 8; em[1730] = 1; /* 1728: pointer.struct.asn1_string_st */
    	em[1731] = 1733; em[1732] = 0; 
    em[1733] = 0; em[1734] = 24; em[1735] = 1; /* 1733: struct.asn1_string_st */
    	em[1736] = 107; em[1737] = 8; 
    em[1738] = 1; em[1739] = 8; em[1740] = 1; /* 1738: pointer.struct.asn1_string_st */
    	em[1741] = 1733; em[1742] = 0; 
    em[1743] = 1; em[1744] = 8; em[1745] = 1; /* 1743: pointer.struct.asn1_string_st */
    	em[1746] = 1733; em[1747] = 0; 
    em[1748] = 1; em[1749] = 8; em[1750] = 1; /* 1748: pointer.struct.asn1_string_st */
    	em[1751] = 1733; em[1752] = 0; 
    em[1753] = 1; em[1754] = 8; em[1755] = 1; /* 1753: pointer.struct.asn1_string_st */
    	em[1756] = 1733; em[1757] = 0; 
    em[1758] = 1; em[1759] = 8; em[1760] = 1; /* 1758: pointer.struct.asn1_string_st */
    	em[1761] = 1733; em[1762] = 0; 
    em[1763] = 1; em[1764] = 8; em[1765] = 1; /* 1763: pointer.struct.asn1_string_st */
    	em[1766] = 1733; em[1767] = 0; 
    em[1768] = 0; em[1769] = 40; em[1770] = 3; /* 1768: struct.asn1_object_st */
    	em[1771] = 26; em[1772] = 0; 
    	em[1773] = 26; em[1774] = 8; 
    	em[1775] = 31; em[1776] = 24; 
    em[1777] = 1; em[1778] = 8; em[1779] = 1; /* 1777: pointer.struct.asn1_object_st */
    	em[1780] = 1768; em[1781] = 0; 
    em[1782] = 1; em[1783] = 8; em[1784] = 1; /* 1782: pointer.struct.asn1_string_st */
    	em[1785] = 1733; em[1786] = 0; 
    em[1787] = 1; em[1788] = 8; em[1789] = 1; /* 1787: pointer.struct.stack_st_ASN1_TYPE */
    	em[1790] = 1792; em[1791] = 0; 
    em[1792] = 0; em[1793] = 32; em[1794] = 2; /* 1792: struct.stack_st_fake_ASN1_TYPE */
    	em[1795] = 1799; em[1796] = 8; 
    	em[1797] = 217; em[1798] = 24; 
    em[1799] = 8884099; em[1800] = 8; em[1801] = 2; /* 1799: pointer_to_array_of_pointers_to_stack */
    	em[1802] = 1806; em[1803] = 0; 
    	em[1804] = 214; em[1805] = 20; 
    em[1806] = 0; em[1807] = 8; em[1808] = 1; /* 1806: pointer.ASN1_TYPE */
    	em[1809] = 1811; em[1810] = 0; 
    em[1811] = 0; em[1812] = 0; em[1813] = 1; /* 1811: ASN1_TYPE */
    	em[1814] = 1816; em[1815] = 0; 
    em[1816] = 0; em[1817] = 16; em[1818] = 1; /* 1816: struct.asn1_type_st */
    	em[1819] = 1821; em[1820] = 8; 
    em[1821] = 0; em[1822] = 8; em[1823] = 20; /* 1821: union.unknown */
    	em[1824] = 92; em[1825] = 0; 
    	em[1826] = 1782; em[1827] = 0; 
    	em[1828] = 1777; em[1829] = 0; 
    	em[1830] = 1763; em[1831] = 0; 
    	em[1832] = 1758; em[1833] = 0; 
    	em[1834] = 1864; em[1835] = 0; 
    	em[1836] = 1753; em[1837] = 0; 
    	em[1838] = 1869; em[1839] = 0; 
    	em[1840] = 1874; em[1841] = 0; 
    	em[1842] = 1748; em[1843] = 0; 
    	em[1844] = 1743; em[1845] = 0; 
    	em[1846] = 1879; em[1847] = 0; 
    	em[1848] = 1884; em[1849] = 0; 
    	em[1850] = 1889; em[1851] = 0; 
    	em[1852] = 1738; em[1853] = 0; 
    	em[1854] = 1894; em[1855] = 0; 
    	em[1856] = 1728; em[1857] = 0; 
    	em[1858] = 1782; em[1859] = 0; 
    	em[1860] = 1782; em[1861] = 0; 
    	em[1862] = 1720; em[1863] = 0; 
    em[1864] = 1; em[1865] = 8; em[1866] = 1; /* 1864: pointer.struct.asn1_string_st */
    	em[1867] = 1733; em[1868] = 0; 
    em[1869] = 1; em[1870] = 8; em[1871] = 1; /* 1869: pointer.struct.asn1_string_st */
    	em[1872] = 1733; em[1873] = 0; 
    em[1874] = 1; em[1875] = 8; em[1876] = 1; /* 1874: pointer.struct.asn1_string_st */
    	em[1877] = 1733; em[1878] = 0; 
    em[1879] = 1; em[1880] = 8; em[1881] = 1; /* 1879: pointer.struct.asn1_string_st */
    	em[1882] = 1733; em[1883] = 0; 
    em[1884] = 1; em[1885] = 8; em[1886] = 1; /* 1884: pointer.struct.asn1_string_st */
    	em[1887] = 1733; em[1888] = 0; 
    em[1889] = 1; em[1890] = 8; em[1891] = 1; /* 1889: pointer.struct.asn1_string_st */
    	em[1892] = 1733; em[1893] = 0; 
    em[1894] = 1; em[1895] = 8; em[1896] = 1; /* 1894: pointer.struct.asn1_string_st */
    	em[1897] = 1733; em[1898] = 0; 
    em[1899] = 0; em[1900] = 8; em[1901] = 3; /* 1899: union.unknown */
    	em[1902] = 92; em[1903] = 0; 
    	em[1904] = 1787; em[1905] = 0; 
    	em[1906] = 1908; em[1907] = 0; 
    em[1908] = 1; em[1909] = 8; em[1910] = 1; /* 1908: pointer.struct.asn1_type_st */
    	em[1911] = 1633; em[1912] = 0; 
    em[1913] = 0; em[1914] = 24; em[1915] = 2; /* 1913: struct.x509_attributes_st */
    	em[1916] = 1681; em[1917] = 0; 
    	em[1918] = 1899; em[1919] = 16; 
    em[1920] = 1; em[1921] = 8; em[1922] = 1; /* 1920: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1923] = 1925; em[1924] = 0; 
    em[1925] = 0; em[1926] = 32; em[1927] = 2; /* 1925: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1928] = 1932; em[1929] = 8; 
    	em[1930] = 217; em[1931] = 24; 
    em[1932] = 8884099; em[1933] = 8; em[1934] = 2; /* 1932: pointer_to_array_of_pointers_to_stack */
    	em[1935] = 1939; em[1936] = 0; 
    	em[1937] = 214; em[1938] = 20; 
    em[1939] = 0; em[1940] = 8; em[1941] = 1; /* 1939: pointer.X509_ATTRIBUTE */
    	em[1942] = 1944; em[1943] = 0; 
    em[1944] = 0; em[1945] = 0; em[1946] = 1; /* 1944: X509_ATTRIBUTE */
    	em[1947] = 1913; em[1948] = 0; 
    em[1949] = 0; em[1950] = 40; em[1951] = 5; /* 1949: struct.ec_extra_data_st */
    	em[1952] = 1962; em[1953] = 0; 
    	em[1954] = 1967; em[1955] = 8; 
    	em[1956] = 1970; em[1957] = 16; 
    	em[1958] = 1973; em[1959] = 24; 
    	em[1960] = 1973; em[1961] = 32; 
    em[1962] = 1; em[1963] = 8; em[1964] = 1; /* 1962: pointer.struct.ec_extra_data_st */
    	em[1965] = 1949; em[1966] = 0; 
    em[1967] = 0; em[1968] = 8; em[1969] = 0; /* 1967: pointer.void */
    em[1970] = 8884097; em[1971] = 8; em[1972] = 0; /* 1970: pointer.func */
    em[1973] = 8884097; em[1974] = 8; em[1975] = 0; /* 1973: pointer.func */
    em[1976] = 1; em[1977] = 8; em[1978] = 1; /* 1976: pointer.struct.ec_extra_data_st */
    	em[1979] = 1949; em[1980] = 0; 
    em[1981] = 0; em[1982] = 24; em[1983] = 1; /* 1981: struct.bignum_st */
    	em[1984] = 1986; em[1985] = 0; 
    em[1986] = 8884099; em[1987] = 8; em[1988] = 2; /* 1986: pointer_to_array_of_pointers_to_stack */
    	em[1989] = 1993; em[1990] = 0; 
    	em[1991] = 214; em[1992] = 12; 
    em[1993] = 0; em[1994] = 8; em[1995] = 0; /* 1993: long unsigned int */
    em[1996] = 1; em[1997] = 8; em[1998] = 1; /* 1996: pointer.struct.bignum_st */
    	em[1999] = 1981; em[2000] = 0; 
    em[2001] = 1; em[2002] = 8; em[2003] = 1; /* 2001: pointer.struct.ec_point_st */
    	em[2004] = 2006; em[2005] = 0; 
    em[2006] = 0; em[2007] = 88; em[2008] = 4; /* 2006: struct.ec_point_st */
    	em[2009] = 2017; em[2010] = 0; 
    	em[2011] = 2189; em[2012] = 8; 
    	em[2013] = 2189; em[2014] = 32; 
    	em[2015] = 2189; em[2016] = 56; 
    em[2017] = 1; em[2018] = 8; em[2019] = 1; /* 2017: pointer.struct.ec_method_st */
    	em[2020] = 2022; em[2021] = 0; 
    em[2022] = 0; em[2023] = 304; em[2024] = 37; /* 2022: struct.ec_method_st */
    	em[2025] = 2099; em[2026] = 8; 
    	em[2027] = 2102; em[2028] = 16; 
    	em[2029] = 2102; em[2030] = 24; 
    	em[2031] = 2105; em[2032] = 32; 
    	em[2033] = 2108; em[2034] = 40; 
    	em[2035] = 2111; em[2036] = 48; 
    	em[2037] = 2114; em[2038] = 56; 
    	em[2039] = 2117; em[2040] = 64; 
    	em[2041] = 2120; em[2042] = 72; 
    	em[2043] = 2123; em[2044] = 80; 
    	em[2045] = 2123; em[2046] = 88; 
    	em[2047] = 2126; em[2048] = 96; 
    	em[2049] = 2129; em[2050] = 104; 
    	em[2051] = 2132; em[2052] = 112; 
    	em[2053] = 2135; em[2054] = 120; 
    	em[2055] = 2138; em[2056] = 128; 
    	em[2057] = 2141; em[2058] = 136; 
    	em[2059] = 2144; em[2060] = 144; 
    	em[2061] = 2147; em[2062] = 152; 
    	em[2063] = 2150; em[2064] = 160; 
    	em[2065] = 2153; em[2066] = 168; 
    	em[2067] = 2156; em[2068] = 176; 
    	em[2069] = 2159; em[2070] = 184; 
    	em[2071] = 2162; em[2072] = 192; 
    	em[2073] = 2165; em[2074] = 200; 
    	em[2075] = 2168; em[2076] = 208; 
    	em[2077] = 2159; em[2078] = 216; 
    	em[2079] = 2171; em[2080] = 224; 
    	em[2081] = 2174; em[2082] = 232; 
    	em[2083] = 2177; em[2084] = 240; 
    	em[2085] = 2114; em[2086] = 248; 
    	em[2087] = 2180; em[2088] = 256; 
    	em[2089] = 2183; em[2090] = 264; 
    	em[2091] = 2180; em[2092] = 272; 
    	em[2093] = 2183; em[2094] = 280; 
    	em[2095] = 2183; em[2096] = 288; 
    	em[2097] = 2186; em[2098] = 296; 
    em[2099] = 8884097; em[2100] = 8; em[2101] = 0; /* 2099: pointer.func */
    em[2102] = 8884097; em[2103] = 8; em[2104] = 0; /* 2102: pointer.func */
    em[2105] = 8884097; em[2106] = 8; em[2107] = 0; /* 2105: pointer.func */
    em[2108] = 8884097; em[2109] = 8; em[2110] = 0; /* 2108: pointer.func */
    em[2111] = 8884097; em[2112] = 8; em[2113] = 0; /* 2111: pointer.func */
    em[2114] = 8884097; em[2115] = 8; em[2116] = 0; /* 2114: pointer.func */
    em[2117] = 8884097; em[2118] = 8; em[2119] = 0; /* 2117: pointer.func */
    em[2120] = 8884097; em[2121] = 8; em[2122] = 0; /* 2120: pointer.func */
    em[2123] = 8884097; em[2124] = 8; em[2125] = 0; /* 2123: pointer.func */
    em[2126] = 8884097; em[2127] = 8; em[2128] = 0; /* 2126: pointer.func */
    em[2129] = 8884097; em[2130] = 8; em[2131] = 0; /* 2129: pointer.func */
    em[2132] = 8884097; em[2133] = 8; em[2134] = 0; /* 2132: pointer.func */
    em[2135] = 8884097; em[2136] = 8; em[2137] = 0; /* 2135: pointer.func */
    em[2138] = 8884097; em[2139] = 8; em[2140] = 0; /* 2138: pointer.func */
    em[2141] = 8884097; em[2142] = 8; em[2143] = 0; /* 2141: pointer.func */
    em[2144] = 8884097; em[2145] = 8; em[2146] = 0; /* 2144: pointer.func */
    em[2147] = 8884097; em[2148] = 8; em[2149] = 0; /* 2147: pointer.func */
    em[2150] = 8884097; em[2151] = 8; em[2152] = 0; /* 2150: pointer.func */
    em[2153] = 8884097; em[2154] = 8; em[2155] = 0; /* 2153: pointer.func */
    em[2156] = 8884097; em[2157] = 8; em[2158] = 0; /* 2156: pointer.func */
    em[2159] = 8884097; em[2160] = 8; em[2161] = 0; /* 2159: pointer.func */
    em[2162] = 8884097; em[2163] = 8; em[2164] = 0; /* 2162: pointer.func */
    em[2165] = 8884097; em[2166] = 8; em[2167] = 0; /* 2165: pointer.func */
    em[2168] = 8884097; em[2169] = 8; em[2170] = 0; /* 2168: pointer.func */
    em[2171] = 8884097; em[2172] = 8; em[2173] = 0; /* 2171: pointer.func */
    em[2174] = 8884097; em[2175] = 8; em[2176] = 0; /* 2174: pointer.func */
    em[2177] = 8884097; em[2178] = 8; em[2179] = 0; /* 2177: pointer.func */
    em[2180] = 8884097; em[2181] = 8; em[2182] = 0; /* 2180: pointer.func */
    em[2183] = 8884097; em[2184] = 8; em[2185] = 0; /* 2183: pointer.func */
    em[2186] = 8884097; em[2187] = 8; em[2188] = 0; /* 2186: pointer.func */
    em[2189] = 0; em[2190] = 24; em[2191] = 1; /* 2189: struct.bignum_st */
    	em[2192] = 2194; em[2193] = 0; 
    em[2194] = 8884099; em[2195] = 8; em[2196] = 2; /* 2194: pointer_to_array_of_pointers_to_stack */
    	em[2197] = 1993; em[2198] = 0; 
    	em[2199] = 214; em[2200] = 12; 
    em[2201] = 8884097; em[2202] = 8; em[2203] = 0; /* 2201: pointer.func */
    em[2204] = 1; em[2205] = 8; em[2206] = 1; /* 2204: pointer.struct.ec_extra_data_st */
    	em[2207] = 2209; em[2208] = 0; 
    em[2209] = 0; em[2210] = 40; em[2211] = 5; /* 2209: struct.ec_extra_data_st */
    	em[2212] = 2204; em[2213] = 0; 
    	em[2214] = 1967; em[2215] = 8; 
    	em[2216] = 1970; em[2217] = 16; 
    	em[2218] = 1973; em[2219] = 24; 
    	em[2220] = 1973; em[2221] = 32; 
    em[2222] = 1; em[2223] = 8; em[2224] = 1; /* 2222: pointer.struct.ec_extra_data_st */
    	em[2225] = 2209; em[2226] = 0; 
    em[2227] = 8884097; em[2228] = 8; em[2229] = 0; /* 2227: pointer.func */
    em[2230] = 8884097; em[2231] = 8; em[2232] = 0; /* 2230: pointer.func */
    em[2233] = 8884097; em[2234] = 8; em[2235] = 0; /* 2233: pointer.func */
    em[2236] = 8884097; em[2237] = 8; em[2238] = 0; /* 2236: pointer.func */
    em[2239] = 8884097; em[2240] = 8; em[2241] = 0; /* 2239: pointer.func */
    em[2242] = 1; em[2243] = 8; em[2244] = 1; /* 2242: pointer.struct.X509_val_st */
    	em[2245] = 2247; em[2246] = 0; 
    em[2247] = 0; em[2248] = 16; em[2249] = 2; /* 2247: struct.X509_val_st */
    	em[2250] = 2254; em[2251] = 0; 
    	em[2252] = 2254; em[2253] = 8; 
    em[2254] = 1; em[2255] = 8; em[2256] = 1; /* 2254: pointer.struct.asn1_string_st */
    	em[2257] = 281; em[2258] = 0; 
    em[2259] = 8884097; em[2260] = 8; em[2261] = 0; /* 2259: pointer.func */
    em[2262] = 8884097; em[2263] = 8; em[2264] = 0; /* 2262: pointer.func */
    em[2265] = 8884097; em[2266] = 8; em[2267] = 0; /* 2265: pointer.func */
    em[2268] = 8884097; em[2269] = 8; em[2270] = 0; /* 2268: pointer.func */
    em[2271] = 8884097; em[2272] = 8; em[2273] = 0; /* 2271: pointer.func */
    em[2274] = 8884097; em[2275] = 8; em[2276] = 0; /* 2274: pointer.func */
    em[2277] = 8884097; em[2278] = 8; em[2279] = 0; /* 2277: pointer.func */
    em[2280] = 0; em[2281] = 48; em[2282] = 6; /* 2280: struct.rand_meth_st */
    	em[2283] = 2295; em[2284] = 0; 
    	em[2285] = 2298; em[2286] = 8; 
    	em[2287] = 2301; em[2288] = 16; 
    	em[2289] = 2233; em[2290] = 24; 
    	em[2291] = 2298; em[2292] = 32; 
    	em[2293] = 2230; em[2294] = 40; 
    em[2295] = 8884097; em[2296] = 8; em[2297] = 0; /* 2295: pointer.func */
    em[2298] = 8884097; em[2299] = 8; em[2300] = 0; /* 2298: pointer.func */
    em[2301] = 8884097; em[2302] = 8; em[2303] = 0; /* 2301: pointer.func */
    em[2304] = 1; em[2305] = 8; em[2306] = 1; /* 2304: pointer.struct.engine_st */
    	em[2307] = 2309; em[2308] = 0; 
    em[2309] = 0; em[2310] = 216; em[2311] = 24; /* 2309: struct.engine_st */
    	em[2312] = 26; em[2313] = 0; 
    	em[2314] = 26; em[2315] = 8; 
    	em[2316] = 2360; em[2317] = 16; 
    	em[2318] = 2412; em[2319] = 24; 
    	em[2320] = 2460; em[2321] = 32; 
    	em[2322] = 2490; em[2323] = 40; 
    	em[2324] = 2507; em[2325] = 48; 
    	em[2326] = 2528; em[2327] = 56; 
    	em[2328] = 2533; em[2329] = 64; 
    	em[2330] = 2227; em[2331] = 72; 
    	em[2332] = 2541; em[2333] = 80; 
    	em[2334] = 2544; em[2335] = 88; 
    	em[2336] = 2547; em[2337] = 96; 
    	em[2338] = 2550; em[2339] = 104; 
    	em[2340] = 2550; em[2341] = 112; 
    	em[2342] = 2550; em[2343] = 120; 
    	em[2344] = 2553; em[2345] = 128; 
    	em[2346] = 2556; em[2347] = 136; 
    	em[2348] = 2556; em[2349] = 144; 
    	em[2350] = 2559; em[2351] = 152; 
    	em[2352] = 2562; em[2353] = 160; 
    	em[2354] = 2574; em[2355] = 184; 
    	em[2356] = 2588; em[2357] = 200; 
    	em[2358] = 2588; em[2359] = 208; 
    em[2360] = 1; em[2361] = 8; em[2362] = 1; /* 2360: pointer.struct.rsa_meth_st */
    	em[2363] = 2365; em[2364] = 0; 
    em[2365] = 0; em[2366] = 112; em[2367] = 13; /* 2365: struct.rsa_meth_st */
    	em[2368] = 26; em[2369] = 0; 
    	em[2370] = 2394; em[2371] = 8; 
    	em[2372] = 2394; em[2373] = 16; 
    	em[2374] = 2394; em[2375] = 24; 
    	em[2376] = 2394; em[2377] = 32; 
    	em[2378] = 2397; em[2379] = 40; 
    	em[2380] = 2400; em[2381] = 48; 
    	em[2382] = 2236; em[2383] = 56; 
    	em[2384] = 2236; em[2385] = 64; 
    	em[2386] = 92; em[2387] = 80; 
    	em[2388] = 2403; em[2389] = 88; 
    	em[2390] = 2406; em[2391] = 96; 
    	em[2392] = 2409; em[2393] = 104; 
    em[2394] = 8884097; em[2395] = 8; em[2396] = 0; /* 2394: pointer.func */
    em[2397] = 8884097; em[2398] = 8; em[2399] = 0; /* 2397: pointer.func */
    em[2400] = 8884097; em[2401] = 8; em[2402] = 0; /* 2400: pointer.func */
    em[2403] = 8884097; em[2404] = 8; em[2405] = 0; /* 2403: pointer.func */
    em[2406] = 8884097; em[2407] = 8; em[2408] = 0; /* 2406: pointer.func */
    em[2409] = 8884097; em[2410] = 8; em[2411] = 0; /* 2409: pointer.func */
    em[2412] = 1; em[2413] = 8; em[2414] = 1; /* 2412: pointer.struct.dsa_method */
    	em[2415] = 2417; em[2416] = 0; 
    em[2417] = 0; em[2418] = 96; em[2419] = 11; /* 2417: struct.dsa_method */
    	em[2420] = 26; em[2421] = 0; 
    	em[2422] = 2442; em[2423] = 8; 
    	em[2424] = 2445; em[2425] = 16; 
    	em[2426] = 2448; em[2427] = 24; 
    	em[2428] = 2451; em[2429] = 32; 
    	em[2430] = 2274; em[2431] = 40; 
    	em[2432] = 2454; em[2433] = 48; 
    	em[2434] = 2454; em[2435] = 56; 
    	em[2436] = 92; em[2437] = 72; 
    	em[2438] = 2457; em[2439] = 80; 
    	em[2440] = 2454; em[2441] = 88; 
    em[2442] = 8884097; em[2443] = 8; em[2444] = 0; /* 2442: pointer.func */
    em[2445] = 8884097; em[2446] = 8; em[2447] = 0; /* 2445: pointer.func */
    em[2448] = 8884097; em[2449] = 8; em[2450] = 0; /* 2448: pointer.func */
    em[2451] = 8884097; em[2452] = 8; em[2453] = 0; /* 2451: pointer.func */
    em[2454] = 8884097; em[2455] = 8; em[2456] = 0; /* 2454: pointer.func */
    em[2457] = 8884097; em[2458] = 8; em[2459] = 0; /* 2457: pointer.func */
    em[2460] = 1; em[2461] = 8; em[2462] = 1; /* 2460: pointer.struct.dh_method */
    	em[2463] = 2465; em[2464] = 0; 
    em[2465] = 0; em[2466] = 72; em[2467] = 8; /* 2465: struct.dh_method */
    	em[2468] = 26; em[2469] = 0; 
    	em[2470] = 2484; em[2471] = 8; 
    	em[2472] = 2487; em[2473] = 16; 
    	em[2474] = 2277; em[2475] = 24; 
    	em[2476] = 2484; em[2477] = 32; 
    	em[2478] = 2484; em[2479] = 40; 
    	em[2480] = 92; em[2481] = 56; 
    	em[2482] = 2271; em[2483] = 64; 
    em[2484] = 8884097; em[2485] = 8; em[2486] = 0; /* 2484: pointer.func */
    em[2487] = 8884097; em[2488] = 8; em[2489] = 0; /* 2487: pointer.func */
    em[2490] = 1; em[2491] = 8; em[2492] = 1; /* 2490: pointer.struct.ecdh_method */
    	em[2493] = 2495; em[2494] = 0; 
    em[2495] = 0; em[2496] = 32; em[2497] = 3; /* 2495: struct.ecdh_method */
    	em[2498] = 26; em[2499] = 0; 
    	em[2500] = 2504; em[2501] = 8; 
    	em[2502] = 92; em[2503] = 24; 
    em[2504] = 8884097; em[2505] = 8; em[2506] = 0; /* 2504: pointer.func */
    em[2507] = 1; em[2508] = 8; em[2509] = 1; /* 2507: pointer.struct.ecdsa_method */
    	em[2510] = 2512; em[2511] = 0; 
    em[2512] = 0; em[2513] = 48; em[2514] = 5; /* 2512: struct.ecdsa_method */
    	em[2515] = 26; em[2516] = 0; 
    	em[2517] = 2265; em[2518] = 8; 
    	em[2519] = 2262; em[2520] = 16; 
    	em[2521] = 2525; em[2522] = 24; 
    	em[2523] = 92; em[2524] = 40; 
    em[2525] = 8884097; em[2526] = 8; em[2527] = 0; /* 2525: pointer.func */
    em[2528] = 1; em[2529] = 8; em[2530] = 1; /* 2528: pointer.struct.rand_meth_st */
    	em[2531] = 2280; em[2532] = 0; 
    em[2533] = 1; em[2534] = 8; em[2535] = 1; /* 2533: pointer.struct.store_method_st */
    	em[2536] = 2538; em[2537] = 0; 
    em[2538] = 0; em[2539] = 0; em[2540] = 0; /* 2538: struct.store_method_st */
    em[2541] = 8884097; em[2542] = 8; em[2543] = 0; /* 2541: pointer.func */
    em[2544] = 8884097; em[2545] = 8; em[2546] = 0; /* 2544: pointer.func */
    em[2547] = 8884097; em[2548] = 8; em[2549] = 0; /* 2547: pointer.func */
    em[2550] = 8884097; em[2551] = 8; em[2552] = 0; /* 2550: pointer.func */
    em[2553] = 8884097; em[2554] = 8; em[2555] = 0; /* 2553: pointer.func */
    em[2556] = 8884097; em[2557] = 8; em[2558] = 0; /* 2556: pointer.func */
    em[2559] = 8884097; em[2560] = 8; em[2561] = 0; /* 2559: pointer.func */
    em[2562] = 1; em[2563] = 8; em[2564] = 1; /* 2562: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[2565] = 2567; em[2566] = 0; 
    em[2567] = 0; em[2568] = 32; em[2569] = 2; /* 2567: struct.ENGINE_CMD_DEFN_st */
    	em[2570] = 26; em[2571] = 8; 
    	em[2572] = 26; em[2573] = 16; 
    em[2574] = 0; em[2575] = 32; em[2576] = 2; /* 2574: struct.crypto_ex_data_st_fake */
    	em[2577] = 2581; em[2578] = 8; 
    	em[2579] = 217; em[2580] = 24; 
    em[2581] = 8884099; em[2582] = 8; em[2583] = 2; /* 2581: pointer_to_array_of_pointers_to_stack */
    	em[2584] = 1967; em[2585] = 0; 
    	em[2586] = 214; em[2587] = 20; 
    em[2588] = 1; em[2589] = 8; em[2590] = 1; /* 2588: pointer.struct.engine_st */
    	em[2591] = 2309; em[2592] = 0; 
    em[2593] = 0; em[2594] = 24; em[2595] = 1; /* 2593: struct.bignum_st */
    	em[2596] = 2598; em[2597] = 0; 
    em[2598] = 8884099; em[2599] = 8; em[2600] = 2; /* 2598: pointer_to_array_of_pointers_to_stack */
    	em[2601] = 1993; em[2602] = 0; 
    	em[2603] = 214; em[2604] = 12; 
    em[2605] = 8884097; em[2606] = 8; em[2607] = 0; /* 2605: pointer.func */
    em[2608] = 8884097; em[2609] = 8; em[2610] = 0; /* 2608: pointer.func */
    em[2611] = 8884097; em[2612] = 8; em[2613] = 0; /* 2611: pointer.func */
    em[2614] = 8884097; em[2615] = 8; em[2616] = 0; /* 2614: pointer.func */
    em[2617] = 8884097; em[2618] = 8; em[2619] = 0; /* 2617: pointer.func */
    em[2620] = 8884097; em[2621] = 8; em[2622] = 0; /* 2620: pointer.func */
    em[2623] = 8884097; em[2624] = 8; em[2625] = 0; /* 2623: pointer.func */
    em[2626] = 0; em[2627] = 56; em[2628] = 4; /* 2626: struct.evp_pkey_st */
    	em[2629] = 2637; em[2630] = 16; 
    	em[2631] = 2726; em[2632] = 24; 
    	em[2633] = 2731; em[2634] = 32; 
    	em[2635] = 1920; em[2636] = 48; 
    em[2637] = 1; em[2638] = 8; em[2639] = 1; /* 2637: pointer.struct.evp_pkey_asn1_method_st */
    	em[2640] = 2642; em[2641] = 0; 
    em[2642] = 0; em[2643] = 208; em[2644] = 24; /* 2642: struct.evp_pkey_asn1_method_st */
    	em[2645] = 92; em[2646] = 16; 
    	em[2647] = 92; em[2648] = 24; 
    	em[2649] = 2693; em[2650] = 32; 
    	em[2651] = 2696; em[2652] = 40; 
    	em[2653] = 2699; em[2654] = 48; 
    	em[2655] = 2702; em[2656] = 56; 
    	em[2657] = 2705; em[2658] = 64; 
    	em[2659] = 2708; em[2660] = 72; 
    	em[2661] = 2702; em[2662] = 80; 
    	em[2663] = 2608; em[2664] = 88; 
    	em[2665] = 2608; em[2666] = 96; 
    	em[2667] = 2711; em[2668] = 104; 
    	em[2669] = 2623; em[2670] = 112; 
    	em[2671] = 2608; em[2672] = 120; 
    	em[2673] = 2714; em[2674] = 128; 
    	em[2675] = 2699; em[2676] = 136; 
    	em[2677] = 2702; em[2678] = 144; 
    	em[2679] = 2717; em[2680] = 152; 
    	em[2681] = 2720; em[2682] = 160; 
    	em[2683] = 2620; em[2684] = 168; 
    	em[2685] = 2711; em[2686] = 176; 
    	em[2687] = 2623; em[2688] = 184; 
    	em[2689] = 2239; em[2690] = 192; 
    	em[2691] = 2723; em[2692] = 200; 
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
    em[2726] = 1; em[2727] = 8; em[2728] = 1; /* 2726: pointer.struct.engine_st */
    	em[2729] = 2309; em[2730] = 0; 
    em[2731] = 8884101; em[2732] = 8; em[2733] = 6; /* 2731: union.union_of_evp_pkey_st */
    	em[2734] = 1967; em[2735] = 0; 
    	em[2736] = 2746; em[2737] = 6; 
    	em[2738] = 2948; em[2739] = 116; 
    	em[2740] = 3079; em[2741] = 28; 
    	em[2742] = 3192; em[2743] = 408; 
    	em[2744] = 214; em[2745] = 0; 
    em[2746] = 1; em[2747] = 8; em[2748] = 1; /* 2746: pointer.struct.rsa_st */
    	em[2749] = 2751; em[2750] = 0; 
    em[2751] = 0; em[2752] = 168; em[2753] = 17; /* 2751: struct.rsa_st */
    	em[2754] = 2788; em[2755] = 16; 
    	em[2756] = 2837; em[2757] = 24; 
    	em[2758] = 2842; em[2759] = 32; 
    	em[2760] = 2842; em[2761] = 40; 
    	em[2762] = 2842; em[2763] = 48; 
    	em[2764] = 2842; em[2765] = 56; 
    	em[2766] = 2842; em[2767] = 64; 
    	em[2768] = 2842; em[2769] = 72; 
    	em[2770] = 2842; em[2771] = 80; 
    	em[2772] = 2842; em[2773] = 88; 
    	em[2774] = 2859; em[2775] = 96; 
    	em[2776] = 2873; em[2777] = 120; 
    	em[2778] = 2873; em[2779] = 128; 
    	em[2780] = 2873; em[2781] = 136; 
    	em[2782] = 92; em[2783] = 144; 
    	em[2784] = 2887; em[2785] = 152; 
    	em[2786] = 2887; em[2787] = 160; 
    em[2788] = 1; em[2789] = 8; em[2790] = 1; /* 2788: pointer.struct.rsa_meth_st */
    	em[2791] = 2793; em[2792] = 0; 
    em[2793] = 0; em[2794] = 112; em[2795] = 13; /* 2793: struct.rsa_meth_st */
    	em[2796] = 26; em[2797] = 0; 
    	em[2798] = 2822; em[2799] = 8; 
    	em[2800] = 2822; em[2801] = 16; 
    	em[2802] = 2822; em[2803] = 24; 
    	em[2804] = 2822; em[2805] = 32; 
    	em[2806] = 2825; em[2807] = 40; 
    	em[2808] = 2605; em[2809] = 48; 
    	em[2810] = 2828; em[2811] = 56; 
    	em[2812] = 2828; em[2813] = 64; 
    	em[2814] = 92; em[2815] = 80; 
    	em[2816] = 2831; em[2817] = 88; 
    	em[2818] = 2611; em[2819] = 96; 
    	em[2820] = 2834; em[2821] = 104; 
    em[2822] = 8884097; em[2823] = 8; em[2824] = 0; /* 2822: pointer.func */
    em[2825] = 8884097; em[2826] = 8; em[2827] = 0; /* 2825: pointer.func */
    em[2828] = 8884097; em[2829] = 8; em[2830] = 0; /* 2828: pointer.func */
    em[2831] = 8884097; em[2832] = 8; em[2833] = 0; /* 2831: pointer.func */
    em[2834] = 8884097; em[2835] = 8; em[2836] = 0; /* 2834: pointer.func */
    em[2837] = 1; em[2838] = 8; em[2839] = 1; /* 2837: pointer.struct.engine_st */
    	em[2840] = 2309; em[2841] = 0; 
    em[2842] = 1; em[2843] = 8; em[2844] = 1; /* 2842: pointer.struct.bignum_st */
    	em[2845] = 2847; em[2846] = 0; 
    em[2847] = 0; em[2848] = 24; em[2849] = 1; /* 2847: struct.bignum_st */
    	em[2850] = 2852; em[2851] = 0; 
    em[2852] = 8884099; em[2853] = 8; em[2854] = 2; /* 2852: pointer_to_array_of_pointers_to_stack */
    	em[2855] = 1993; em[2856] = 0; 
    	em[2857] = 214; em[2858] = 12; 
    em[2859] = 0; em[2860] = 32; em[2861] = 2; /* 2859: struct.crypto_ex_data_st_fake */
    	em[2862] = 2866; em[2863] = 8; 
    	em[2864] = 217; em[2865] = 24; 
    em[2866] = 8884099; em[2867] = 8; em[2868] = 2; /* 2866: pointer_to_array_of_pointers_to_stack */
    	em[2869] = 1967; em[2870] = 0; 
    	em[2871] = 214; em[2872] = 20; 
    em[2873] = 1; em[2874] = 8; em[2875] = 1; /* 2873: pointer.struct.bn_mont_ctx_st */
    	em[2876] = 2878; em[2877] = 0; 
    em[2878] = 0; em[2879] = 96; em[2880] = 3; /* 2878: struct.bn_mont_ctx_st */
    	em[2881] = 2847; em[2882] = 8; 
    	em[2883] = 2847; em[2884] = 32; 
    	em[2885] = 2847; em[2886] = 56; 
    em[2887] = 1; em[2888] = 8; em[2889] = 1; /* 2887: pointer.struct.bn_blinding_st */
    	em[2890] = 2892; em[2891] = 0; 
    em[2892] = 0; em[2893] = 88; em[2894] = 7; /* 2892: struct.bn_blinding_st */
    	em[2895] = 2909; em[2896] = 0; 
    	em[2897] = 2909; em[2898] = 8; 
    	em[2899] = 2909; em[2900] = 16; 
    	em[2901] = 2909; em[2902] = 24; 
    	em[2903] = 2926; em[2904] = 40; 
    	em[2905] = 2931; em[2906] = 72; 
    	em[2907] = 2945; em[2908] = 80; 
    em[2909] = 1; em[2910] = 8; em[2911] = 1; /* 2909: pointer.struct.bignum_st */
    	em[2912] = 2914; em[2913] = 0; 
    em[2914] = 0; em[2915] = 24; em[2916] = 1; /* 2914: struct.bignum_st */
    	em[2917] = 2919; em[2918] = 0; 
    em[2919] = 8884099; em[2920] = 8; em[2921] = 2; /* 2919: pointer_to_array_of_pointers_to_stack */
    	em[2922] = 1993; em[2923] = 0; 
    	em[2924] = 214; em[2925] = 12; 
    em[2926] = 0; em[2927] = 16; em[2928] = 1; /* 2926: struct.crypto_threadid_st */
    	em[2929] = 1967; em[2930] = 0; 
    em[2931] = 1; em[2932] = 8; em[2933] = 1; /* 2931: pointer.struct.bn_mont_ctx_st */
    	em[2934] = 2936; em[2935] = 0; 
    em[2936] = 0; em[2937] = 96; em[2938] = 3; /* 2936: struct.bn_mont_ctx_st */
    	em[2939] = 2914; em[2940] = 8; 
    	em[2941] = 2914; em[2942] = 32; 
    	em[2943] = 2914; em[2944] = 56; 
    em[2945] = 8884097; em[2946] = 8; em[2947] = 0; /* 2945: pointer.func */
    em[2948] = 1; em[2949] = 8; em[2950] = 1; /* 2948: pointer.struct.dsa_st */
    	em[2951] = 2953; em[2952] = 0; 
    em[2953] = 0; em[2954] = 136; em[2955] = 11; /* 2953: struct.dsa_st */
    	em[2956] = 2978; em[2957] = 24; 
    	em[2958] = 2978; em[2959] = 32; 
    	em[2960] = 2978; em[2961] = 40; 
    	em[2962] = 2978; em[2963] = 48; 
    	em[2964] = 2978; em[2965] = 56; 
    	em[2966] = 2978; em[2967] = 64; 
    	em[2968] = 2978; em[2969] = 72; 
    	em[2970] = 2995; em[2971] = 88; 
    	em[2972] = 3009; em[2973] = 104; 
    	em[2974] = 3023; em[2975] = 120; 
    	em[2976] = 3074; em[2977] = 128; 
    em[2978] = 1; em[2979] = 8; em[2980] = 1; /* 2978: pointer.struct.bignum_st */
    	em[2981] = 2983; em[2982] = 0; 
    em[2983] = 0; em[2984] = 24; em[2985] = 1; /* 2983: struct.bignum_st */
    	em[2986] = 2988; em[2987] = 0; 
    em[2988] = 8884099; em[2989] = 8; em[2990] = 2; /* 2988: pointer_to_array_of_pointers_to_stack */
    	em[2991] = 1993; em[2992] = 0; 
    	em[2993] = 214; em[2994] = 12; 
    em[2995] = 1; em[2996] = 8; em[2997] = 1; /* 2995: pointer.struct.bn_mont_ctx_st */
    	em[2998] = 3000; em[2999] = 0; 
    em[3000] = 0; em[3001] = 96; em[3002] = 3; /* 3000: struct.bn_mont_ctx_st */
    	em[3003] = 2983; em[3004] = 8; 
    	em[3005] = 2983; em[3006] = 32; 
    	em[3007] = 2983; em[3008] = 56; 
    em[3009] = 0; em[3010] = 32; em[3011] = 2; /* 3009: struct.crypto_ex_data_st_fake */
    	em[3012] = 3016; em[3013] = 8; 
    	em[3014] = 217; em[3015] = 24; 
    em[3016] = 8884099; em[3017] = 8; em[3018] = 2; /* 3016: pointer_to_array_of_pointers_to_stack */
    	em[3019] = 1967; em[3020] = 0; 
    	em[3021] = 214; em[3022] = 20; 
    em[3023] = 1; em[3024] = 8; em[3025] = 1; /* 3023: pointer.struct.dsa_method */
    	em[3026] = 3028; em[3027] = 0; 
    em[3028] = 0; em[3029] = 96; em[3030] = 11; /* 3028: struct.dsa_method */
    	em[3031] = 26; em[3032] = 0; 
    	em[3033] = 3053; em[3034] = 8; 
    	em[3035] = 3056; em[3036] = 16; 
    	em[3037] = 3059; em[3038] = 24; 
    	em[3039] = 3062; em[3040] = 32; 
    	em[3041] = 3065; em[3042] = 40; 
    	em[3043] = 3068; em[3044] = 48; 
    	em[3045] = 3068; em[3046] = 56; 
    	em[3047] = 92; em[3048] = 72; 
    	em[3049] = 3071; em[3050] = 80; 
    	em[3051] = 3068; em[3052] = 88; 
    em[3053] = 8884097; em[3054] = 8; em[3055] = 0; /* 3053: pointer.func */
    em[3056] = 8884097; em[3057] = 8; em[3058] = 0; /* 3056: pointer.func */
    em[3059] = 8884097; em[3060] = 8; em[3061] = 0; /* 3059: pointer.func */
    em[3062] = 8884097; em[3063] = 8; em[3064] = 0; /* 3062: pointer.func */
    em[3065] = 8884097; em[3066] = 8; em[3067] = 0; /* 3065: pointer.func */
    em[3068] = 8884097; em[3069] = 8; em[3070] = 0; /* 3068: pointer.func */
    em[3071] = 8884097; em[3072] = 8; em[3073] = 0; /* 3071: pointer.func */
    em[3074] = 1; em[3075] = 8; em[3076] = 1; /* 3074: pointer.struct.engine_st */
    	em[3077] = 2309; em[3078] = 0; 
    em[3079] = 1; em[3080] = 8; em[3081] = 1; /* 3079: pointer.struct.dh_st */
    	em[3082] = 3084; em[3083] = 0; 
    em[3084] = 0; em[3085] = 144; em[3086] = 12; /* 3084: struct.dh_st */
    	em[3087] = 3111; em[3088] = 8; 
    	em[3089] = 3111; em[3090] = 16; 
    	em[3091] = 3111; em[3092] = 32; 
    	em[3093] = 3111; em[3094] = 40; 
    	em[3095] = 3128; em[3096] = 56; 
    	em[3097] = 3111; em[3098] = 64; 
    	em[3099] = 3111; em[3100] = 72; 
    	em[3101] = 107; em[3102] = 80; 
    	em[3103] = 3111; em[3104] = 96; 
    	em[3105] = 3142; em[3106] = 112; 
    	em[3107] = 3156; em[3108] = 128; 
    	em[3109] = 2304; em[3110] = 136; 
    em[3111] = 1; em[3112] = 8; em[3113] = 1; /* 3111: pointer.struct.bignum_st */
    	em[3114] = 3116; em[3115] = 0; 
    em[3116] = 0; em[3117] = 24; em[3118] = 1; /* 3116: struct.bignum_st */
    	em[3119] = 3121; em[3120] = 0; 
    em[3121] = 8884099; em[3122] = 8; em[3123] = 2; /* 3121: pointer_to_array_of_pointers_to_stack */
    	em[3124] = 1993; em[3125] = 0; 
    	em[3126] = 214; em[3127] = 12; 
    em[3128] = 1; em[3129] = 8; em[3130] = 1; /* 3128: pointer.struct.bn_mont_ctx_st */
    	em[3131] = 3133; em[3132] = 0; 
    em[3133] = 0; em[3134] = 96; em[3135] = 3; /* 3133: struct.bn_mont_ctx_st */
    	em[3136] = 3116; em[3137] = 8; 
    	em[3138] = 3116; em[3139] = 32; 
    	em[3140] = 3116; em[3141] = 56; 
    em[3142] = 0; em[3143] = 32; em[3144] = 2; /* 3142: struct.crypto_ex_data_st_fake */
    	em[3145] = 3149; em[3146] = 8; 
    	em[3147] = 217; em[3148] = 24; 
    em[3149] = 8884099; em[3150] = 8; em[3151] = 2; /* 3149: pointer_to_array_of_pointers_to_stack */
    	em[3152] = 1967; em[3153] = 0; 
    	em[3154] = 214; em[3155] = 20; 
    em[3156] = 1; em[3157] = 8; em[3158] = 1; /* 3156: pointer.struct.dh_method */
    	em[3159] = 3161; em[3160] = 0; 
    em[3161] = 0; em[3162] = 72; em[3163] = 8; /* 3161: struct.dh_method */
    	em[3164] = 26; em[3165] = 0; 
    	em[3166] = 3180; em[3167] = 8; 
    	em[3168] = 3183; em[3169] = 16; 
    	em[3170] = 3186; em[3171] = 24; 
    	em[3172] = 3180; em[3173] = 32; 
    	em[3174] = 3180; em[3175] = 40; 
    	em[3176] = 92; em[3177] = 56; 
    	em[3178] = 3189; em[3179] = 64; 
    em[3180] = 8884097; em[3181] = 8; em[3182] = 0; /* 3180: pointer.func */
    em[3183] = 8884097; em[3184] = 8; em[3185] = 0; /* 3183: pointer.func */
    em[3186] = 8884097; em[3187] = 8; em[3188] = 0; /* 3186: pointer.func */
    em[3189] = 8884097; em[3190] = 8; em[3191] = 0; /* 3189: pointer.func */
    em[3192] = 1; em[3193] = 8; em[3194] = 1; /* 3192: pointer.struct.ec_key_st */
    	em[3195] = 3197; em[3196] = 0; 
    em[3197] = 0; em[3198] = 56; em[3199] = 4; /* 3197: struct.ec_key_st */
    	em[3200] = 3208; em[3201] = 8; 
    	em[3202] = 2001; em[3203] = 16; 
    	em[3204] = 1996; em[3205] = 24; 
    	em[3206] = 1976; em[3207] = 48; 
    em[3208] = 1; em[3209] = 8; em[3210] = 1; /* 3208: pointer.struct.ec_group_st */
    	em[3211] = 3213; em[3212] = 0; 
    em[3213] = 0; em[3214] = 232; em[3215] = 12; /* 3213: struct.ec_group_st */
    	em[3216] = 3240; em[3217] = 0; 
    	em[3218] = 3400; em[3219] = 8; 
    	em[3220] = 2593; em[3221] = 16; 
    	em[3222] = 2593; em[3223] = 40; 
    	em[3224] = 107; em[3225] = 80; 
    	em[3226] = 2222; em[3227] = 96; 
    	em[3228] = 2593; em[3229] = 104; 
    	em[3230] = 2593; em[3231] = 152; 
    	em[3232] = 2593; em[3233] = 176; 
    	em[3234] = 1967; em[3235] = 208; 
    	em[3236] = 1967; em[3237] = 216; 
    	em[3238] = 2201; em[3239] = 224; 
    em[3240] = 1; em[3241] = 8; em[3242] = 1; /* 3240: pointer.struct.ec_method_st */
    	em[3243] = 3245; em[3244] = 0; 
    em[3245] = 0; em[3246] = 304; em[3247] = 37; /* 3245: struct.ec_method_st */
    	em[3248] = 3322; em[3249] = 8; 
    	em[3250] = 2614; em[3251] = 16; 
    	em[3252] = 2614; em[3253] = 24; 
    	em[3254] = 3325; em[3255] = 32; 
    	em[3256] = 2268; em[3257] = 40; 
    	em[3258] = 3328; em[3259] = 48; 
    	em[3260] = 3331; em[3261] = 56; 
    	em[3262] = 3334; em[3263] = 64; 
    	em[3264] = 3337; em[3265] = 72; 
    	em[3266] = 3340; em[3267] = 80; 
    	em[3268] = 3340; em[3269] = 88; 
    	em[3270] = 3343; em[3271] = 96; 
    	em[3272] = 3346; em[3273] = 104; 
    	em[3274] = 3349; em[3275] = 112; 
    	em[3276] = 3352; em[3277] = 120; 
    	em[3278] = 3355; em[3279] = 128; 
    	em[3280] = 3358; em[3281] = 136; 
    	em[3282] = 2259; em[3283] = 144; 
    	em[3284] = 3361; em[3285] = 152; 
    	em[3286] = 3364; em[3287] = 160; 
    	em[3288] = 3367; em[3289] = 168; 
    	em[3290] = 3370; em[3291] = 176; 
    	em[3292] = 2617; em[3293] = 184; 
    	em[3294] = 3373; em[3295] = 192; 
    	em[3296] = 3376; em[3297] = 200; 
    	em[3298] = 3379; em[3299] = 208; 
    	em[3300] = 2617; em[3301] = 216; 
    	em[3302] = 3382; em[3303] = 224; 
    	em[3304] = 3385; em[3305] = 232; 
    	em[3306] = 3388; em[3307] = 240; 
    	em[3308] = 3331; em[3309] = 248; 
    	em[3310] = 3391; em[3311] = 256; 
    	em[3312] = 3394; em[3313] = 264; 
    	em[3314] = 3391; em[3315] = 272; 
    	em[3316] = 3394; em[3317] = 280; 
    	em[3318] = 3394; em[3319] = 288; 
    	em[3320] = 3397; em[3321] = 296; 
    em[3322] = 8884097; em[3323] = 8; em[3324] = 0; /* 3322: pointer.func */
    em[3325] = 8884097; em[3326] = 8; em[3327] = 0; /* 3325: pointer.func */
    em[3328] = 8884097; em[3329] = 8; em[3330] = 0; /* 3328: pointer.func */
    em[3331] = 8884097; em[3332] = 8; em[3333] = 0; /* 3331: pointer.func */
    em[3334] = 8884097; em[3335] = 8; em[3336] = 0; /* 3334: pointer.func */
    em[3337] = 8884097; em[3338] = 8; em[3339] = 0; /* 3337: pointer.func */
    em[3340] = 8884097; em[3341] = 8; em[3342] = 0; /* 3340: pointer.func */
    em[3343] = 8884097; em[3344] = 8; em[3345] = 0; /* 3343: pointer.func */
    em[3346] = 8884097; em[3347] = 8; em[3348] = 0; /* 3346: pointer.func */
    em[3349] = 8884097; em[3350] = 8; em[3351] = 0; /* 3349: pointer.func */
    em[3352] = 8884097; em[3353] = 8; em[3354] = 0; /* 3352: pointer.func */
    em[3355] = 8884097; em[3356] = 8; em[3357] = 0; /* 3355: pointer.func */
    em[3358] = 8884097; em[3359] = 8; em[3360] = 0; /* 3358: pointer.func */
    em[3361] = 8884097; em[3362] = 8; em[3363] = 0; /* 3361: pointer.func */
    em[3364] = 8884097; em[3365] = 8; em[3366] = 0; /* 3364: pointer.func */
    em[3367] = 8884097; em[3368] = 8; em[3369] = 0; /* 3367: pointer.func */
    em[3370] = 8884097; em[3371] = 8; em[3372] = 0; /* 3370: pointer.func */
    em[3373] = 8884097; em[3374] = 8; em[3375] = 0; /* 3373: pointer.func */
    em[3376] = 8884097; em[3377] = 8; em[3378] = 0; /* 3376: pointer.func */
    em[3379] = 8884097; em[3380] = 8; em[3381] = 0; /* 3379: pointer.func */
    em[3382] = 8884097; em[3383] = 8; em[3384] = 0; /* 3382: pointer.func */
    em[3385] = 8884097; em[3386] = 8; em[3387] = 0; /* 3385: pointer.func */
    em[3388] = 8884097; em[3389] = 8; em[3390] = 0; /* 3388: pointer.func */
    em[3391] = 8884097; em[3392] = 8; em[3393] = 0; /* 3391: pointer.func */
    em[3394] = 8884097; em[3395] = 8; em[3396] = 0; /* 3394: pointer.func */
    em[3397] = 8884097; em[3398] = 8; em[3399] = 0; /* 3397: pointer.func */
    em[3400] = 1; em[3401] = 8; em[3402] = 1; /* 3400: pointer.struct.ec_point_st */
    	em[3403] = 2006; em[3404] = 0; 
    em[3405] = 1; em[3406] = 8; em[3407] = 1; /* 3405: pointer.struct.evp_pkey_st */
    	em[3408] = 2626; em[3409] = 0; 
    em[3410] = 0; em[3411] = 24; em[3412] = 1; /* 3410: struct.asn1_string_st */
    	em[3413] = 107; em[3414] = 8; 
    em[3415] = 1; em[3416] = 8; em[3417] = 1; /* 3415: pointer.struct.X509_algor_st */
    	em[3418] = 5; em[3419] = 0; 
    em[3420] = 1; em[3421] = 8; em[3422] = 1; /* 3420: pointer.struct.AUTHORITY_KEYID_st */
    	em[3423] = 3425; em[3424] = 0; 
    em[3425] = 0; em[3426] = 24; em[3427] = 3; /* 3425: struct.AUTHORITY_KEYID_st */
    	em[3428] = 1518; em[3429] = 0; 
    	em[3430] = 1494; em[3431] = 8; 
    	em[3432] = 1484; em[3433] = 16; 
    em[3434] = 1; em[3435] = 8; em[3436] = 1; /* 3434: pointer.struct.asn1_string_st */
    	em[3437] = 3410; em[3438] = 0; 
    em[3439] = 0; em[3440] = 24; em[3441] = 3; /* 3439: struct.X509_pubkey_st */
    	em[3442] = 3415; em[3443] = 0; 
    	em[3444] = 3434; em[3445] = 8; 
    	em[3446] = 3405; em[3447] = 16; 
    em[3448] = 1; em[3449] = 8; em[3450] = 1; /* 3448: pointer.struct.buf_mem_st */
    	em[3451] = 3453; em[3452] = 0; 
    em[3453] = 0; em[3454] = 24; em[3455] = 1; /* 3453: struct.buf_mem_st */
    	em[3456] = 92; em[3457] = 8; 
    em[3458] = 0; em[3459] = 1; em[3460] = 0; /* 3458: char */
    em[3461] = 1; em[3462] = 8; em[3463] = 1; /* 3461: pointer.struct.x509_cinf_st */
    	em[3464] = 3466; em[3465] = 0; 
    em[3466] = 0; em[3467] = 104; em[3468] = 11; /* 3466: struct.x509_cinf_st */
    	em[3469] = 3491; em[3470] = 0; 
    	em[3471] = 3491; em[3472] = 8; 
    	em[3473] = 3496; em[3474] = 16; 
    	em[3475] = 3501; em[3476] = 24; 
    	em[3477] = 2242; em[3478] = 32; 
    	em[3479] = 3501; em[3480] = 40; 
    	em[3481] = 3539; em[3482] = 48; 
    	em[3483] = 1573; em[3484] = 56; 
    	em[3485] = 1573; em[3486] = 64; 
    	em[3487] = 1549; em[3488] = 72; 
    	em[3489] = 3544; em[3490] = 80; 
    em[3491] = 1; em[3492] = 8; em[3493] = 1; /* 3491: pointer.struct.asn1_string_st */
    	em[3494] = 281; em[3495] = 0; 
    em[3496] = 1; em[3497] = 8; em[3498] = 1; /* 3496: pointer.struct.X509_algor_st */
    	em[3499] = 5; em[3500] = 0; 
    em[3501] = 1; em[3502] = 8; em[3503] = 1; /* 3501: pointer.struct.X509_name_st */
    	em[3504] = 3506; em[3505] = 0; 
    em[3506] = 0; em[3507] = 40; em[3508] = 3; /* 3506: struct.X509_name_st */
    	em[3509] = 3515; em[3510] = 0; 
    	em[3511] = 3448; em[3512] = 16; 
    	em[3513] = 107; em[3514] = 24; 
    em[3515] = 1; em[3516] = 8; em[3517] = 1; /* 3515: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[3518] = 3520; em[3519] = 0; 
    em[3520] = 0; em[3521] = 32; em[3522] = 2; /* 3520: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[3523] = 3527; em[3524] = 8; 
    	em[3525] = 217; em[3526] = 24; 
    em[3527] = 8884099; em[3528] = 8; em[3529] = 2; /* 3527: pointer_to_array_of_pointers_to_stack */
    	em[3530] = 3534; em[3531] = 0; 
    	em[3532] = 214; em[3533] = 20; 
    em[3534] = 0; em[3535] = 8; em[3536] = 1; /* 3534: pointer.X509_NAME_ENTRY */
    	em[3537] = 337; em[3538] = 0; 
    em[3539] = 1; em[3540] = 8; em[3541] = 1; /* 3539: pointer.struct.X509_pubkey_st */
    	em[3542] = 3439; em[3543] = 0; 
    em[3544] = 0; em[3545] = 24; em[3546] = 1; /* 3544: struct.ASN1_ENCODING_st */
    	em[3547] = 107; em[3548] = 0; 
    em[3549] = 1; em[3550] = 8; em[3551] = 1; /* 3549: pointer.struct.x509_st */
    	em[3552] = 3554; em[3553] = 0; 
    em[3554] = 0; em[3555] = 184; em[3556] = 12; /* 3554: struct.x509_st */
    	em[3557] = 3461; em[3558] = 0; 
    	em[3559] = 3496; em[3560] = 8; 
    	em[3561] = 1573; em[3562] = 16; 
    	em[3563] = 92; em[3564] = 32; 
    	em[3565] = 3581; em[3566] = 40; 
    	em[3567] = 286; em[3568] = 104; 
    	em[3569] = 3420; em[3570] = 112; 
    	em[3571] = 3595; em[3572] = 120; 
    	em[3573] = 1037; em[3574] = 128; 
    	em[3575] = 647; em[3576] = 136; 
    	em[3577] = 597; em[3578] = 144; 
    	em[3579] = 258; em[3580] = 176; 
    em[3581] = 0; em[3582] = 32; em[3583] = 2; /* 3581: struct.crypto_ex_data_st_fake */
    	em[3584] = 3588; em[3585] = 8; 
    	em[3586] = 217; em[3587] = 24; 
    em[3588] = 8884099; em[3589] = 8; em[3590] = 2; /* 3588: pointer_to_array_of_pointers_to_stack */
    	em[3591] = 1967; em[3592] = 0; 
    	em[3593] = 214; em[3594] = 20; 
    em[3595] = 1; em[3596] = 8; em[3597] = 1; /* 3595: pointer.struct.X509_POLICY_CACHE_st */
    	em[3598] = 1477; em[3599] = 0; 
    em[3600] = 1; em[3601] = 8; em[3602] = 1; /* 3600: pointer.int */
    	em[3603] = 214; em[3604] = 0; 
    args_addr->arg_entity_index[0] = 3549;
    args_addr->arg_entity_index[1] = 214;
    args_addr->arg_entity_index[2] = 3600;
    args_addr->arg_entity_index[3] = 3600;
    args_addr->ret_entity_index = 1967;
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

