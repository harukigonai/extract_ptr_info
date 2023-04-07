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
    em[190] = 1; em[191] = 8; em[192] = 1; /* 190: pointer.struct.stack_st_ASN1_OBJECT */
    	em[193] = 195; em[194] = 0; 
    em[195] = 0; em[196] = 32; em[197] = 2; /* 195: struct.stack_st_fake_ASN1_OBJECT */
    	em[198] = 202; em[199] = 8; 
    	em[200] = 231; em[201] = 24; 
    em[202] = 8884099; em[203] = 8; em[204] = 2; /* 202: pointer_to_array_of_pointers_to_stack */
    	em[205] = 209; em[206] = 0; 
    	em[207] = 228; em[208] = 20; 
    em[209] = 0; em[210] = 8; em[211] = 1; /* 209: pointer.ASN1_OBJECT */
    	em[212] = 214; em[213] = 0; 
    em[214] = 0; em[215] = 0; em[216] = 1; /* 214: ASN1_OBJECT */
    	em[217] = 219; em[218] = 0; 
    em[219] = 0; em[220] = 40; em[221] = 3; /* 219: struct.asn1_object_st */
    	em[222] = 26; em[223] = 0; 
    	em[224] = 26; em[225] = 8; 
    	em[226] = 31; em[227] = 24; 
    em[228] = 0; em[229] = 4; em[230] = 0; /* 228: int */
    em[231] = 8884097; em[232] = 8; em[233] = 0; /* 231: pointer.func */
    em[234] = 1; em[235] = 8; em[236] = 1; /* 234: pointer.struct.x509_cert_aux_st */
    	em[237] = 239; em[238] = 0; 
    em[239] = 0; em[240] = 40; em[241] = 5; /* 239: struct.x509_cert_aux_st */
    	em[242] = 190; em[243] = 0; 
    	em[244] = 190; em[245] = 8; 
    	em[246] = 252; em[247] = 16; 
    	em[248] = 262; em[249] = 24; 
    	em[250] = 267; em[251] = 32; 
    em[252] = 1; em[253] = 8; em[254] = 1; /* 252: pointer.struct.asn1_string_st */
    	em[255] = 257; em[256] = 0; 
    em[257] = 0; em[258] = 24; em[259] = 1; /* 257: struct.asn1_string_st */
    	em[260] = 107; em[261] = 8; 
    em[262] = 1; em[263] = 8; em[264] = 1; /* 262: pointer.struct.asn1_string_st */
    	em[265] = 257; em[266] = 0; 
    em[267] = 1; em[268] = 8; em[269] = 1; /* 267: pointer.struct.stack_st_X509_ALGOR */
    	em[270] = 272; em[271] = 0; 
    em[272] = 0; em[273] = 32; em[274] = 2; /* 272: struct.stack_st_fake_X509_ALGOR */
    	em[275] = 279; em[276] = 8; 
    	em[277] = 231; em[278] = 24; 
    em[279] = 8884099; em[280] = 8; em[281] = 2; /* 279: pointer_to_array_of_pointers_to_stack */
    	em[282] = 286; em[283] = 0; 
    	em[284] = 228; em[285] = 20; 
    em[286] = 0; em[287] = 8; em[288] = 1; /* 286: pointer.X509_ALGOR */
    	em[289] = 0; em[290] = 0; 
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
    	em[323] = 231; em[324] = 24; 
    em[325] = 8884099; em[326] = 8; em[327] = 2; /* 325: pointer_to_array_of_pointers_to_stack */
    	em[328] = 332; em[329] = 0; 
    	em[330] = 228; em[331] = 20; 
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
    em[422] = 1; em[423] = 8; em[424] = 1; /* 422: pointer.struct.asn1_string_st */
    	em[425] = 308; em[426] = 0; 
    em[427] = 0; em[428] = 8; em[429] = 20; /* 427: union.unknown */
    	em[430] = 92; em[431] = 0; 
    	em[432] = 303; em[433] = 0; 
    	em[434] = 470; em[435] = 0; 
    	em[436] = 484; em[437] = 0; 
    	em[438] = 489; em[439] = 0; 
    	em[440] = 494; em[441] = 0; 
    	em[442] = 422; em[443] = 0; 
    	em[444] = 499; em[445] = 0; 
    	em[446] = 417; em[447] = 0; 
    	em[448] = 504; em[449] = 0; 
    	em[450] = 412; em[451] = 0; 
    	em[452] = 407; em[453] = 0; 
    	em[454] = 509; em[455] = 0; 
    	em[456] = 514; em[457] = 0; 
    	em[458] = 402; em[459] = 0; 
    	em[460] = 519; em[461] = 0; 
    	em[462] = 397; em[463] = 0; 
    	em[464] = 303; em[465] = 0; 
    	em[466] = 303; em[467] = 0; 
    	em[468] = 524; em[469] = 0; 
    em[470] = 1; em[471] = 8; em[472] = 1; /* 470: pointer.struct.asn1_object_st */
    	em[473] = 475; em[474] = 0; 
    em[475] = 0; em[476] = 40; em[477] = 3; /* 475: struct.asn1_object_st */
    	em[478] = 26; em[479] = 0; 
    	em[480] = 26; em[481] = 8; 
    	em[482] = 31; em[483] = 24; 
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
    	em[540] = 470; em[541] = 0; 
    	em[542] = 544; em[543] = 8; 
    em[544] = 1; em[545] = 8; em[546] = 1; /* 544: pointer.struct.asn1_type_st */
    	em[547] = 549; em[548] = 0; 
    em[549] = 0; em[550] = 16; em[551] = 1; /* 549: struct.asn1_type_st */
    	em[552] = 427; em[553] = 8; 
    em[554] = 0; em[555] = 16; em[556] = 1; /* 554: struct.GENERAL_NAME_st */
    	em[557] = 559; em[558] = 8; 
    em[559] = 0; em[560] = 8; em[561] = 15; /* 559: union.unknown */
    	em[562] = 92; em[563] = 0; 
    	em[564] = 532; em[565] = 0; 
    	em[566] = 504; em[567] = 0; 
    	em[568] = 504; em[569] = 0; 
    	em[570] = 544; em[571] = 0; 
    	em[572] = 392; em[573] = 0; 
    	em[574] = 291; em[575] = 0; 
    	em[576] = 504; em[577] = 0; 
    	em[578] = 422; em[579] = 0; 
    	em[580] = 470; em[581] = 0; 
    	em[582] = 422; em[583] = 0; 
    	em[584] = 392; em[585] = 0; 
    	em[586] = 504; em[587] = 0; 
    	em[588] = 470; em[589] = 0; 
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
    	em[619] = 231; em[620] = 24; 
    em[621] = 8884099; em[622] = 8; em[623] = 2; /* 621: pointer_to_array_of_pointers_to_stack */
    	em[624] = 628; em[625] = 0; 
    	em[626] = 228; em[627] = 20; 
    em[628] = 0; em[629] = 8; em[630] = 1; /* 628: pointer.GENERAL_SUBTREE */
    	em[631] = 633; em[632] = 0; 
    em[633] = 0; em[634] = 0; em[635] = 1; /* 633: GENERAL_SUBTREE */
    	em[636] = 638; em[637] = 0; 
    em[638] = 0; em[639] = 24; em[640] = 3; /* 638: struct.GENERAL_SUBTREE_st */
    	em[641] = 592; em[642] = 0; 
    	em[643] = 484; em[644] = 8; 
    	em[645] = 484; em[646] = 16; 
    em[647] = 1; em[648] = 8; em[649] = 1; /* 647: pointer.struct.stack_st_GENERAL_NAME */
    	em[650] = 652; em[651] = 0; 
    em[652] = 0; em[653] = 32; em[654] = 2; /* 652: struct.stack_st_fake_GENERAL_NAME */
    	em[655] = 659; em[656] = 8; 
    	em[657] = 231; em[658] = 24; 
    em[659] = 8884099; em[660] = 8; em[661] = 2; /* 659: pointer_to_array_of_pointers_to_stack */
    	em[662] = 666; em[663] = 0; 
    	em[664] = 228; em[665] = 20; 
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
    	em[905] = 231; em[906] = 24; 
    em[907] = 8884099; em[908] = 8; em[909] = 2; /* 907: pointer_to_array_of_pointers_to_stack */
    	em[910] = 914; em[911] = 0; 
    	em[912] = 228; em[913] = 20; 
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
    em[956] = 1; em[957] = 8; em[958] = 1; /* 956: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[959] = 961; em[960] = 0; 
    em[961] = 0; em[962] = 32; em[963] = 2; /* 961: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[964] = 968; em[965] = 8; 
    	em[966] = 231; em[967] = 24; 
    em[968] = 8884099; em[969] = 8; em[970] = 2; /* 968: pointer_to_array_of_pointers_to_stack */
    	em[971] = 975; em[972] = 0; 
    	em[973] = 228; em[974] = 20; 
    em[975] = 0; em[976] = 8; em[977] = 1; /* 975: pointer.X509_NAME_ENTRY */
    	em[978] = 337; em[979] = 0; 
    em[980] = 1; em[981] = 8; em[982] = 1; /* 980: pointer.struct.stack_st_GENERAL_NAME */
    	em[983] = 985; em[984] = 0; 
    em[985] = 0; em[986] = 32; em[987] = 2; /* 985: struct.stack_st_fake_GENERAL_NAME */
    	em[988] = 992; em[989] = 8; 
    	em[990] = 231; em[991] = 24; 
    em[992] = 8884099; em[993] = 8; em[994] = 2; /* 992: pointer_to_array_of_pointers_to_stack */
    	em[995] = 999; em[996] = 0; 
    	em[997] = 228; em[998] = 20; 
    em[999] = 0; em[1000] = 8; em[1001] = 1; /* 999: pointer.GENERAL_NAME */
    	em[1002] = 671; em[1003] = 0; 
    em[1004] = 0; em[1005] = 8; em[1006] = 2; /* 1004: union.unknown */
    	em[1007] = 980; em[1008] = 0; 
    	em[1009] = 956; em[1010] = 0; 
    em[1011] = 0; em[1012] = 24; em[1013] = 2; /* 1011: struct.DIST_POINT_NAME_st */
    	em[1014] = 1004; em[1015] = 8; 
    	em[1016] = 1018; em[1017] = 16; 
    em[1018] = 1; em[1019] = 8; em[1020] = 1; /* 1018: pointer.struct.X509_name_st */
    	em[1021] = 1023; em[1022] = 0; 
    em[1023] = 0; em[1024] = 40; em[1025] = 3; /* 1023: struct.X509_name_st */
    	em[1026] = 956; em[1027] = 0; 
    	em[1028] = 946; em[1029] = 16; 
    	em[1030] = 107; em[1031] = 24; 
    em[1032] = 0; em[1033] = 0; em[1034] = 1; /* 1032: DIST_POINT */
    	em[1035] = 1037; em[1036] = 0; 
    em[1037] = 0; em[1038] = 32; em[1039] = 3; /* 1037: struct.DIST_POINT_st */
    	em[1040] = 1046; em[1041] = 0; 
    	em[1042] = 1051; em[1043] = 8; 
    	em[1044] = 980; em[1045] = 16; 
    em[1046] = 1; em[1047] = 8; em[1048] = 1; /* 1046: pointer.struct.DIST_POINT_NAME_st */
    	em[1049] = 1011; em[1050] = 0; 
    em[1051] = 1; em[1052] = 8; em[1053] = 1; /* 1051: pointer.struct.asn1_string_st */
    	em[1054] = 941; em[1055] = 0; 
    em[1056] = 1; em[1057] = 8; em[1058] = 1; /* 1056: pointer.struct.stack_st_DIST_POINT */
    	em[1059] = 1061; em[1060] = 0; 
    em[1061] = 0; em[1062] = 32; em[1063] = 2; /* 1061: struct.stack_st_fake_DIST_POINT */
    	em[1064] = 1068; em[1065] = 8; 
    	em[1066] = 231; em[1067] = 24; 
    em[1068] = 8884099; em[1069] = 8; em[1070] = 2; /* 1068: pointer_to_array_of_pointers_to_stack */
    	em[1071] = 1075; em[1072] = 0; 
    	em[1073] = 228; em[1074] = 20; 
    em[1075] = 0; em[1076] = 8; em[1077] = 1; /* 1075: pointer.DIST_POINT */
    	em[1078] = 1032; em[1079] = 0; 
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
    	em[1113] = 231; em[1114] = 24; 
    em[1115] = 8884099; em[1116] = 8; em[1117] = 2; /* 1115: pointer_to_array_of_pointers_to_stack */
    	em[1118] = 1122; em[1119] = 0; 
    	em[1120] = 228; em[1121] = 20; 
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
    	em[1211] = 231; em[1212] = 24; 
    em[1213] = 8884099; em[1214] = 8; em[1215] = 2; /* 1213: pointer_to_array_of_pointers_to_stack */
    	em[1216] = 1220; em[1217] = 0; 
    	em[1218] = 228; em[1219] = 20; 
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
    	em[1358] = 231; em[1359] = 24; 
    em[1360] = 8884099; em[1361] = 8; em[1362] = 2; /* 1360: pointer_to_array_of_pointers_to_stack */
    	em[1363] = 1367; em[1364] = 0; 
    	em[1365] = 228; em[1366] = 20; 
    em[1367] = 0; em[1368] = 8; em[1369] = 1; /* 1367: pointer.ASN1_OBJECT */
    	em[1370] = 214; em[1371] = 0; 
    em[1372] = 1; em[1373] = 8; em[1374] = 1; /* 1372: pointer.struct.stack_st_X509_POLICY_DATA */
    	em[1375] = 1377; em[1376] = 0; 
    em[1377] = 0; em[1378] = 32; em[1379] = 2; /* 1377: struct.stack_st_fake_X509_POLICY_DATA */
    	em[1380] = 1384; em[1381] = 8; 
    	em[1382] = 231; em[1383] = 24; 
    em[1384] = 8884099; em[1385] = 8; em[1386] = 2; /* 1384: pointer_to_array_of_pointers_to_stack */
    	em[1387] = 1391; em[1388] = 0; 
    	em[1389] = 228; em[1390] = 20; 
    em[1391] = 0; em[1392] = 8; em[1393] = 1; /* 1391: pointer.X509_POLICY_DATA */
    	em[1394] = 1396; em[1395] = 0; 
    em[1396] = 0; em[1397] = 0; em[1398] = 1; /* 1396: X509_POLICY_DATA */
    	em[1399] = 1080; em[1400] = 0; 
    em[1401] = 1; em[1402] = 8; em[1403] = 1; /* 1401: pointer.struct.stack_st_ASN1_OBJECT */
    	em[1404] = 1406; em[1405] = 0; 
    em[1406] = 0; em[1407] = 32; em[1408] = 2; /* 1406: struct.stack_st_fake_ASN1_OBJECT */
    	em[1409] = 1413; em[1410] = 8; 
    	em[1411] = 231; em[1412] = 24; 
    em[1413] = 8884099; em[1414] = 8; em[1415] = 2; /* 1413: pointer_to_array_of_pointers_to_stack */
    	em[1416] = 1420; em[1417] = 0; 
    	em[1418] = 228; em[1419] = 20; 
    em[1420] = 0; em[1421] = 8; em[1422] = 1; /* 1420: pointer.ASN1_OBJECT */
    	em[1423] = 214; em[1424] = 0; 
    em[1425] = 1; em[1426] = 8; em[1427] = 1; /* 1425: pointer.struct.stack_st_POLICYQUALINFO */
    	em[1428] = 1430; em[1429] = 0; 
    em[1430] = 0; em[1431] = 32; em[1432] = 2; /* 1430: struct.stack_st_fake_POLICYQUALINFO */
    	em[1433] = 1437; em[1434] = 8; 
    	em[1435] = 231; em[1436] = 24; 
    em[1437] = 8884099; em[1438] = 8; em[1439] = 2; /* 1437: pointer_to_array_of_pointers_to_stack */
    	em[1440] = 1444; em[1441] = 0; 
    	em[1442] = 228; em[1443] = 20; 
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
    em[1484] = 1; em[1485] = 8; em[1486] = 1; /* 1484: pointer.struct.stack_st_GENERAL_NAME */
    	em[1487] = 1489; em[1488] = 0; 
    em[1489] = 0; em[1490] = 32; em[1491] = 2; /* 1489: struct.stack_st_fake_GENERAL_NAME */
    	em[1492] = 1496; em[1493] = 8; 
    	em[1494] = 231; em[1495] = 24; 
    em[1496] = 8884099; em[1497] = 8; em[1498] = 2; /* 1496: pointer_to_array_of_pointers_to_stack */
    	em[1499] = 1503; em[1500] = 0; 
    	em[1501] = 228; em[1502] = 20; 
    em[1503] = 0; em[1504] = 8; em[1505] = 1; /* 1503: pointer.GENERAL_NAME */
    	em[1506] = 671; em[1507] = 0; 
    em[1508] = 1; em[1509] = 8; em[1510] = 1; /* 1508: pointer.struct.asn1_string_st */
    	em[1511] = 1513; em[1512] = 0; 
    em[1513] = 0; em[1514] = 24; em[1515] = 1; /* 1513: struct.asn1_string_st */
    	em[1516] = 107; em[1517] = 8; 
    em[1518] = 0; em[1519] = 32; em[1520] = 1; /* 1518: struct.stack_st_void */
    	em[1521] = 1523; em[1522] = 0; 
    em[1523] = 0; em[1524] = 32; em[1525] = 2; /* 1523: struct.stack_st */
    	em[1526] = 1530; em[1527] = 8; 
    	em[1528] = 231; em[1529] = 24; 
    em[1530] = 1; em[1531] = 8; em[1532] = 1; /* 1530: pointer.pointer.char */
    	em[1533] = 92; em[1534] = 0; 
    em[1535] = 1; em[1536] = 8; em[1537] = 1; /* 1535: pointer.struct.stack_st_void */
    	em[1538] = 1518; em[1539] = 0; 
    em[1540] = 0; em[1541] = 16; em[1542] = 1; /* 1540: struct.crypto_ex_data_st */
    	em[1543] = 1535; em[1544] = 0; 
    em[1545] = 0; em[1546] = 40; em[1547] = 3; /* 1545: struct.asn1_object_st */
    	em[1548] = 26; em[1549] = 0; 
    	em[1550] = 26; em[1551] = 8; 
    	em[1552] = 31; em[1553] = 24; 
    em[1554] = 1; em[1555] = 8; em[1556] = 1; /* 1554: pointer.struct.asn1_object_st */
    	em[1557] = 1545; em[1558] = 0; 
    em[1559] = 0; em[1560] = 24; em[1561] = 2; /* 1559: struct.X509_extension_st */
    	em[1562] = 1554; em[1563] = 0; 
    	em[1564] = 262; em[1565] = 16; 
    em[1566] = 0; em[1567] = 0; em[1568] = 1; /* 1566: X509_EXTENSION */
    	em[1569] = 1559; em[1570] = 0; 
    em[1571] = 1; em[1572] = 8; em[1573] = 1; /* 1571: pointer.struct.stack_st_X509_EXTENSION */
    	em[1574] = 1576; em[1575] = 0; 
    em[1576] = 0; em[1577] = 32; em[1578] = 2; /* 1576: struct.stack_st_fake_X509_EXTENSION */
    	em[1579] = 1583; em[1580] = 8; 
    	em[1581] = 231; em[1582] = 24; 
    em[1583] = 8884099; em[1584] = 8; em[1585] = 2; /* 1583: pointer_to_array_of_pointers_to_stack */
    	em[1586] = 1590; em[1587] = 0; 
    	em[1588] = 228; em[1589] = 20; 
    em[1590] = 0; em[1591] = 8; em[1592] = 1; /* 1590: pointer.X509_EXTENSION */
    	em[1593] = 1566; em[1594] = 0; 
    em[1595] = 1; em[1596] = 8; em[1597] = 1; /* 1595: pointer.struct.asn1_string_st */
    	em[1598] = 257; em[1599] = 0; 
    em[1600] = 1; em[1601] = 8; em[1602] = 1; /* 1600: pointer.struct.asn1_string_st */
    	em[1603] = 1605; em[1604] = 0; 
    em[1605] = 0; em[1606] = 24; em[1607] = 1; /* 1605: struct.asn1_string_st */
    	em[1608] = 107; em[1609] = 8; 
    em[1610] = 1; em[1611] = 8; em[1612] = 1; /* 1610: pointer.struct.asn1_string_st */
    	em[1613] = 1605; em[1614] = 0; 
    em[1615] = 1; em[1616] = 8; em[1617] = 1; /* 1615: pointer.struct.asn1_string_st */
    	em[1618] = 1605; em[1619] = 0; 
    em[1620] = 1; em[1621] = 8; em[1622] = 1; /* 1620: pointer.struct.asn1_string_st */
    	em[1623] = 1605; em[1624] = 0; 
    em[1625] = 1; em[1626] = 8; em[1627] = 1; /* 1625: pointer.struct.asn1_string_st */
    	em[1628] = 1605; em[1629] = 0; 
    em[1630] = 1; em[1631] = 8; em[1632] = 1; /* 1630: pointer.struct.asn1_string_st */
    	em[1633] = 1605; em[1634] = 0; 
    em[1635] = 1; em[1636] = 8; em[1637] = 1; /* 1635: pointer.struct.asn1_string_st */
    	em[1638] = 1605; em[1639] = 0; 
    em[1640] = 1; em[1641] = 8; em[1642] = 1; /* 1640: pointer.struct.asn1_string_st */
    	em[1643] = 1605; em[1644] = 0; 
    em[1645] = 0; em[1646] = 16; em[1647] = 1; /* 1645: struct.asn1_type_st */
    	em[1648] = 1650; em[1649] = 8; 
    em[1650] = 0; em[1651] = 8; em[1652] = 20; /* 1650: union.unknown */
    	em[1653] = 92; em[1654] = 0; 
    	em[1655] = 1640; em[1656] = 0; 
    	em[1657] = 1693; em[1658] = 0; 
    	em[1659] = 1707; em[1660] = 0; 
    	em[1661] = 1635; em[1662] = 0; 
    	em[1663] = 1712; em[1664] = 0; 
    	em[1665] = 1630; em[1666] = 0; 
    	em[1667] = 1717; em[1668] = 0; 
    	em[1669] = 1625; em[1670] = 0; 
    	em[1671] = 1620; em[1672] = 0; 
    	em[1673] = 1615; em[1674] = 0; 
    	em[1675] = 1610; em[1676] = 0; 
    	em[1677] = 1722; em[1678] = 0; 
    	em[1679] = 1727; em[1680] = 0; 
    	em[1681] = 1732; em[1682] = 0; 
    	em[1683] = 1737; em[1684] = 0; 
    	em[1685] = 1600; em[1686] = 0; 
    	em[1687] = 1640; em[1688] = 0; 
    	em[1689] = 1640; em[1690] = 0; 
    	em[1691] = 182; em[1692] = 0; 
    em[1693] = 1; em[1694] = 8; em[1695] = 1; /* 1693: pointer.struct.asn1_object_st */
    	em[1696] = 1698; em[1697] = 0; 
    em[1698] = 0; em[1699] = 40; em[1700] = 3; /* 1698: struct.asn1_object_st */
    	em[1701] = 26; em[1702] = 0; 
    	em[1703] = 26; em[1704] = 8; 
    	em[1705] = 31; em[1706] = 24; 
    em[1707] = 1; em[1708] = 8; em[1709] = 1; /* 1707: pointer.struct.asn1_string_st */
    	em[1710] = 1605; em[1711] = 0; 
    em[1712] = 1; em[1713] = 8; em[1714] = 1; /* 1712: pointer.struct.asn1_string_st */
    	em[1715] = 1605; em[1716] = 0; 
    em[1717] = 1; em[1718] = 8; em[1719] = 1; /* 1717: pointer.struct.asn1_string_st */
    	em[1720] = 1605; em[1721] = 0; 
    em[1722] = 1; em[1723] = 8; em[1724] = 1; /* 1722: pointer.struct.asn1_string_st */
    	em[1725] = 1605; em[1726] = 0; 
    em[1727] = 1; em[1728] = 8; em[1729] = 1; /* 1727: pointer.struct.asn1_string_st */
    	em[1730] = 1605; em[1731] = 0; 
    em[1732] = 1; em[1733] = 8; em[1734] = 1; /* 1732: pointer.struct.asn1_string_st */
    	em[1735] = 1605; em[1736] = 0; 
    em[1737] = 1; em[1738] = 8; em[1739] = 1; /* 1737: pointer.struct.asn1_string_st */
    	em[1740] = 1605; em[1741] = 0; 
    em[1742] = 1; em[1743] = 8; em[1744] = 1; /* 1742: pointer.struct.asn1_string_st */
    	em[1745] = 1747; em[1746] = 0; 
    em[1747] = 0; em[1748] = 24; em[1749] = 1; /* 1747: struct.asn1_string_st */
    	em[1750] = 107; em[1751] = 8; 
    em[1752] = 1; em[1753] = 8; em[1754] = 1; /* 1752: pointer.struct.asn1_string_st */
    	em[1755] = 1747; em[1756] = 0; 
    em[1757] = 1; em[1758] = 8; em[1759] = 1; /* 1757: pointer.struct.asn1_string_st */
    	em[1760] = 1747; em[1761] = 0; 
    em[1762] = 1; em[1763] = 8; em[1764] = 1; /* 1762: pointer.struct.asn1_string_st */
    	em[1765] = 1747; em[1766] = 0; 
    em[1767] = 1; em[1768] = 8; em[1769] = 1; /* 1767: pointer.struct.asn1_string_st */
    	em[1770] = 1747; em[1771] = 0; 
    em[1772] = 1; em[1773] = 8; em[1774] = 1; /* 1772: pointer.struct.asn1_object_st */
    	em[1775] = 1777; em[1776] = 0; 
    em[1777] = 0; em[1778] = 40; em[1779] = 3; /* 1777: struct.asn1_object_st */
    	em[1780] = 26; em[1781] = 0; 
    	em[1782] = 26; em[1783] = 8; 
    	em[1784] = 31; em[1785] = 24; 
    em[1786] = 1; em[1787] = 8; em[1788] = 1; /* 1786: pointer.struct.asn1_string_st */
    	em[1789] = 1747; em[1790] = 0; 
    em[1791] = 1; em[1792] = 8; em[1793] = 1; /* 1791: pointer.struct.stack_st_ASN1_TYPE */
    	em[1794] = 1796; em[1795] = 0; 
    em[1796] = 0; em[1797] = 32; em[1798] = 2; /* 1796: struct.stack_st_fake_ASN1_TYPE */
    	em[1799] = 1803; em[1800] = 8; 
    	em[1801] = 231; em[1802] = 24; 
    em[1803] = 8884099; em[1804] = 8; em[1805] = 2; /* 1803: pointer_to_array_of_pointers_to_stack */
    	em[1806] = 1810; em[1807] = 0; 
    	em[1808] = 228; em[1809] = 20; 
    em[1810] = 0; em[1811] = 8; em[1812] = 1; /* 1810: pointer.ASN1_TYPE */
    	em[1813] = 1815; em[1814] = 0; 
    em[1815] = 0; em[1816] = 0; em[1817] = 1; /* 1815: ASN1_TYPE */
    	em[1818] = 1820; em[1819] = 0; 
    em[1820] = 0; em[1821] = 16; em[1822] = 1; /* 1820: struct.asn1_type_st */
    	em[1823] = 1825; em[1824] = 8; 
    em[1825] = 0; em[1826] = 8; em[1827] = 20; /* 1825: union.unknown */
    	em[1828] = 92; em[1829] = 0; 
    	em[1830] = 1786; em[1831] = 0; 
    	em[1832] = 1772; em[1833] = 0; 
    	em[1834] = 1767; em[1835] = 0; 
    	em[1836] = 1868; em[1837] = 0; 
    	em[1838] = 1873; em[1839] = 0; 
    	em[1840] = 1878; em[1841] = 0; 
    	em[1842] = 1883; em[1843] = 0; 
    	em[1844] = 1888; em[1845] = 0; 
    	em[1846] = 1762; em[1847] = 0; 
    	em[1848] = 1893; em[1849] = 0; 
    	em[1850] = 1898; em[1851] = 0; 
    	em[1852] = 1903; em[1853] = 0; 
    	em[1854] = 1908; em[1855] = 0; 
    	em[1856] = 1757; em[1857] = 0; 
    	em[1858] = 1752; em[1859] = 0; 
    	em[1860] = 1742; em[1861] = 0; 
    	em[1862] = 1786; em[1863] = 0; 
    	em[1864] = 1786; em[1865] = 0; 
    	em[1866] = 1913; em[1867] = 0; 
    em[1868] = 1; em[1869] = 8; em[1870] = 1; /* 1868: pointer.struct.asn1_string_st */
    	em[1871] = 1747; em[1872] = 0; 
    em[1873] = 1; em[1874] = 8; em[1875] = 1; /* 1873: pointer.struct.asn1_string_st */
    	em[1876] = 1747; em[1877] = 0; 
    em[1878] = 1; em[1879] = 8; em[1880] = 1; /* 1878: pointer.struct.asn1_string_st */
    	em[1881] = 1747; em[1882] = 0; 
    em[1883] = 1; em[1884] = 8; em[1885] = 1; /* 1883: pointer.struct.asn1_string_st */
    	em[1886] = 1747; em[1887] = 0; 
    em[1888] = 1; em[1889] = 8; em[1890] = 1; /* 1888: pointer.struct.asn1_string_st */
    	em[1891] = 1747; em[1892] = 0; 
    em[1893] = 1; em[1894] = 8; em[1895] = 1; /* 1893: pointer.struct.asn1_string_st */
    	em[1896] = 1747; em[1897] = 0; 
    em[1898] = 1; em[1899] = 8; em[1900] = 1; /* 1898: pointer.struct.asn1_string_st */
    	em[1901] = 1747; em[1902] = 0; 
    em[1903] = 1; em[1904] = 8; em[1905] = 1; /* 1903: pointer.struct.asn1_string_st */
    	em[1906] = 1747; em[1907] = 0; 
    em[1908] = 1; em[1909] = 8; em[1910] = 1; /* 1908: pointer.struct.asn1_string_st */
    	em[1911] = 1747; em[1912] = 0; 
    em[1913] = 1; em[1914] = 8; em[1915] = 1; /* 1913: pointer.struct.ASN1_VALUE_st */
    	em[1916] = 1918; em[1917] = 0; 
    em[1918] = 0; em[1919] = 0; em[1920] = 0; /* 1918: struct.ASN1_VALUE_st */
    em[1921] = 0; em[1922] = 24; em[1923] = 2; /* 1921: struct.x509_attributes_st */
    	em[1924] = 1693; em[1925] = 0; 
    	em[1926] = 1928; em[1927] = 16; 
    em[1928] = 0; em[1929] = 8; em[1930] = 3; /* 1928: union.unknown */
    	em[1931] = 92; em[1932] = 0; 
    	em[1933] = 1791; em[1934] = 0; 
    	em[1935] = 1937; em[1936] = 0; 
    em[1937] = 1; em[1938] = 8; em[1939] = 1; /* 1937: pointer.struct.asn1_type_st */
    	em[1940] = 1645; em[1941] = 0; 
    em[1942] = 1; em[1943] = 8; em[1944] = 1; /* 1942: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1945] = 1947; em[1946] = 0; 
    em[1947] = 0; em[1948] = 32; em[1949] = 2; /* 1947: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1950] = 1954; em[1951] = 8; 
    	em[1952] = 231; em[1953] = 24; 
    em[1954] = 8884099; em[1955] = 8; em[1956] = 2; /* 1954: pointer_to_array_of_pointers_to_stack */
    	em[1957] = 1961; em[1958] = 0; 
    	em[1959] = 228; em[1960] = 20; 
    em[1961] = 0; em[1962] = 8; em[1963] = 1; /* 1961: pointer.X509_ATTRIBUTE */
    	em[1964] = 1966; em[1965] = 0; 
    em[1966] = 0; em[1967] = 0; em[1968] = 1; /* 1966: X509_ATTRIBUTE */
    	em[1969] = 1921; em[1970] = 0; 
    em[1971] = 1; em[1972] = 8; em[1973] = 1; /* 1971: pointer.struct.ec_extra_data_st */
    	em[1974] = 1976; em[1975] = 0; 
    em[1976] = 0; em[1977] = 40; em[1978] = 5; /* 1976: struct.ec_extra_data_st */
    	em[1979] = 1971; em[1980] = 0; 
    	em[1981] = 1989; em[1982] = 8; 
    	em[1983] = 1992; em[1984] = 16; 
    	em[1985] = 1995; em[1986] = 24; 
    	em[1987] = 1995; em[1988] = 32; 
    em[1989] = 0; em[1990] = 8; em[1991] = 0; /* 1989: pointer.void */
    em[1992] = 8884097; em[1993] = 8; em[1994] = 0; /* 1992: pointer.func */
    em[1995] = 8884097; em[1996] = 8; em[1997] = 0; /* 1995: pointer.func */
    em[1998] = 1; em[1999] = 8; em[2000] = 1; /* 1998: pointer.struct.ec_extra_data_st */
    	em[2001] = 1976; em[2002] = 0; 
    em[2003] = 0; em[2004] = 24; em[2005] = 1; /* 2003: struct.bignum_st */
    	em[2006] = 2008; em[2007] = 0; 
    em[2008] = 8884099; em[2009] = 8; em[2010] = 2; /* 2008: pointer_to_array_of_pointers_to_stack */
    	em[2011] = 2015; em[2012] = 0; 
    	em[2013] = 228; em[2014] = 12; 
    em[2015] = 0; em[2016] = 4; em[2017] = 0; /* 2015: unsigned int */
    em[2018] = 1; em[2019] = 8; em[2020] = 1; /* 2018: pointer.struct.bignum_st */
    	em[2021] = 2003; em[2022] = 0; 
    em[2023] = 1; em[2024] = 8; em[2025] = 1; /* 2023: pointer.struct.ec_point_st */
    	em[2026] = 2028; em[2027] = 0; 
    em[2028] = 0; em[2029] = 88; em[2030] = 4; /* 2028: struct.ec_point_st */
    	em[2031] = 2039; em[2032] = 0; 
    	em[2033] = 2211; em[2034] = 8; 
    	em[2035] = 2211; em[2036] = 32; 
    	em[2037] = 2211; em[2038] = 56; 
    em[2039] = 1; em[2040] = 8; em[2041] = 1; /* 2039: pointer.struct.ec_method_st */
    	em[2042] = 2044; em[2043] = 0; 
    em[2044] = 0; em[2045] = 304; em[2046] = 37; /* 2044: struct.ec_method_st */
    	em[2047] = 2121; em[2048] = 8; 
    	em[2049] = 2124; em[2050] = 16; 
    	em[2051] = 2124; em[2052] = 24; 
    	em[2053] = 2127; em[2054] = 32; 
    	em[2055] = 2130; em[2056] = 40; 
    	em[2057] = 2133; em[2058] = 48; 
    	em[2059] = 2136; em[2060] = 56; 
    	em[2061] = 2139; em[2062] = 64; 
    	em[2063] = 2142; em[2064] = 72; 
    	em[2065] = 2145; em[2066] = 80; 
    	em[2067] = 2145; em[2068] = 88; 
    	em[2069] = 2148; em[2070] = 96; 
    	em[2071] = 2151; em[2072] = 104; 
    	em[2073] = 2154; em[2074] = 112; 
    	em[2075] = 2157; em[2076] = 120; 
    	em[2077] = 2160; em[2078] = 128; 
    	em[2079] = 2163; em[2080] = 136; 
    	em[2081] = 2166; em[2082] = 144; 
    	em[2083] = 2169; em[2084] = 152; 
    	em[2085] = 2172; em[2086] = 160; 
    	em[2087] = 2175; em[2088] = 168; 
    	em[2089] = 2178; em[2090] = 176; 
    	em[2091] = 2181; em[2092] = 184; 
    	em[2093] = 2184; em[2094] = 192; 
    	em[2095] = 2187; em[2096] = 200; 
    	em[2097] = 2190; em[2098] = 208; 
    	em[2099] = 2181; em[2100] = 216; 
    	em[2101] = 2193; em[2102] = 224; 
    	em[2103] = 2196; em[2104] = 232; 
    	em[2105] = 2199; em[2106] = 240; 
    	em[2107] = 2136; em[2108] = 248; 
    	em[2109] = 2202; em[2110] = 256; 
    	em[2111] = 2205; em[2112] = 264; 
    	em[2113] = 2202; em[2114] = 272; 
    	em[2115] = 2205; em[2116] = 280; 
    	em[2117] = 2205; em[2118] = 288; 
    	em[2119] = 2208; em[2120] = 296; 
    em[2121] = 8884097; em[2122] = 8; em[2123] = 0; /* 2121: pointer.func */
    em[2124] = 8884097; em[2125] = 8; em[2126] = 0; /* 2124: pointer.func */
    em[2127] = 8884097; em[2128] = 8; em[2129] = 0; /* 2127: pointer.func */
    em[2130] = 8884097; em[2131] = 8; em[2132] = 0; /* 2130: pointer.func */
    em[2133] = 8884097; em[2134] = 8; em[2135] = 0; /* 2133: pointer.func */
    em[2136] = 8884097; em[2137] = 8; em[2138] = 0; /* 2136: pointer.func */
    em[2139] = 8884097; em[2140] = 8; em[2141] = 0; /* 2139: pointer.func */
    em[2142] = 8884097; em[2143] = 8; em[2144] = 0; /* 2142: pointer.func */
    em[2145] = 8884097; em[2146] = 8; em[2147] = 0; /* 2145: pointer.func */
    em[2148] = 8884097; em[2149] = 8; em[2150] = 0; /* 2148: pointer.func */
    em[2151] = 8884097; em[2152] = 8; em[2153] = 0; /* 2151: pointer.func */
    em[2154] = 8884097; em[2155] = 8; em[2156] = 0; /* 2154: pointer.func */
    em[2157] = 8884097; em[2158] = 8; em[2159] = 0; /* 2157: pointer.func */
    em[2160] = 8884097; em[2161] = 8; em[2162] = 0; /* 2160: pointer.func */
    em[2163] = 8884097; em[2164] = 8; em[2165] = 0; /* 2163: pointer.func */
    em[2166] = 8884097; em[2167] = 8; em[2168] = 0; /* 2166: pointer.func */
    em[2169] = 8884097; em[2170] = 8; em[2171] = 0; /* 2169: pointer.func */
    em[2172] = 8884097; em[2173] = 8; em[2174] = 0; /* 2172: pointer.func */
    em[2175] = 8884097; em[2176] = 8; em[2177] = 0; /* 2175: pointer.func */
    em[2178] = 8884097; em[2179] = 8; em[2180] = 0; /* 2178: pointer.func */
    em[2181] = 8884097; em[2182] = 8; em[2183] = 0; /* 2181: pointer.func */
    em[2184] = 8884097; em[2185] = 8; em[2186] = 0; /* 2184: pointer.func */
    em[2187] = 8884097; em[2188] = 8; em[2189] = 0; /* 2187: pointer.func */
    em[2190] = 8884097; em[2191] = 8; em[2192] = 0; /* 2190: pointer.func */
    em[2193] = 8884097; em[2194] = 8; em[2195] = 0; /* 2193: pointer.func */
    em[2196] = 8884097; em[2197] = 8; em[2198] = 0; /* 2196: pointer.func */
    em[2199] = 8884097; em[2200] = 8; em[2201] = 0; /* 2199: pointer.func */
    em[2202] = 8884097; em[2203] = 8; em[2204] = 0; /* 2202: pointer.func */
    em[2205] = 8884097; em[2206] = 8; em[2207] = 0; /* 2205: pointer.func */
    em[2208] = 8884097; em[2209] = 8; em[2210] = 0; /* 2208: pointer.func */
    em[2211] = 0; em[2212] = 24; em[2213] = 1; /* 2211: struct.bignum_st */
    	em[2214] = 2216; em[2215] = 0; 
    em[2216] = 8884099; em[2217] = 8; em[2218] = 2; /* 2216: pointer_to_array_of_pointers_to_stack */
    	em[2219] = 2015; em[2220] = 0; 
    	em[2221] = 228; em[2222] = 12; 
    em[2223] = 8884097; em[2224] = 8; em[2225] = 0; /* 2223: pointer.func */
    em[2226] = 1; em[2227] = 8; em[2228] = 1; /* 2226: pointer.struct.ec_extra_data_st */
    	em[2229] = 2231; em[2230] = 0; 
    em[2231] = 0; em[2232] = 40; em[2233] = 5; /* 2231: struct.ec_extra_data_st */
    	em[2234] = 2226; em[2235] = 0; 
    	em[2236] = 1989; em[2237] = 8; 
    	em[2238] = 1992; em[2239] = 16; 
    	em[2240] = 1995; em[2241] = 24; 
    	em[2242] = 1995; em[2243] = 32; 
    em[2244] = 1; em[2245] = 8; em[2246] = 1; /* 2244: pointer.struct.ec_extra_data_st */
    	em[2247] = 2231; em[2248] = 0; 
    em[2249] = 0; em[2250] = 24; em[2251] = 1; /* 2249: struct.bignum_st */
    	em[2252] = 2254; em[2253] = 0; 
    em[2254] = 8884099; em[2255] = 8; em[2256] = 2; /* 2254: pointer_to_array_of_pointers_to_stack */
    	em[2257] = 2015; em[2258] = 0; 
    	em[2259] = 228; em[2260] = 12; 
    em[2261] = 1; em[2262] = 8; em[2263] = 1; /* 2261: pointer.struct.asn1_string_st */
    	em[2264] = 1513; em[2265] = 0; 
    em[2266] = 8884097; em[2267] = 8; em[2268] = 0; /* 2266: pointer.func */
    em[2269] = 8884097; em[2270] = 8; em[2271] = 0; /* 2269: pointer.func */
    em[2272] = 8884097; em[2273] = 8; em[2274] = 0; /* 2272: pointer.func */
    em[2275] = 8884097; em[2276] = 8; em[2277] = 0; /* 2275: pointer.func */
    em[2278] = 8884097; em[2279] = 8; em[2280] = 0; /* 2278: pointer.func */
    em[2281] = 8884097; em[2282] = 8; em[2283] = 0; /* 2281: pointer.func */
    em[2284] = 1; em[2285] = 8; em[2286] = 1; /* 2284: pointer.struct.X509_val_st */
    	em[2287] = 2289; em[2288] = 0; 
    em[2289] = 0; em[2290] = 16; em[2291] = 2; /* 2289: struct.X509_val_st */
    	em[2292] = 2296; em[2293] = 0; 
    	em[2294] = 2296; em[2295] = 8; 
    em[2296] = 1; em[2297] = 8; em[2298] = 1; /* 2296: pointer.struct.asn1_string_st */
    	em[2299] = 257; em[2300] = 0; 
    em[2301] = 8884097; em[2302] = 8; em[2303] = 0; /* 2301: pointer.func */
    em[2304] = 8884097; em[2305] = 8; em[2306] = 0; /* 2304: pointer.func */
    em[2307] = 8884097; em[2308] = 8; em[2309] = 0; /* 2307: pointer.func */
    em[2310] = 1; em[2311] = 8; em[2312] = 1; /* 2310: pointer.struct.dh_method */
    	em[2313] = 2315; em[2314] = 0; 
    em[2315] = 0; em[2316] = 72; em[2317] = 8; /* 2315: struct.dh_method */
    	em[2318] = 26; em[2319] = 0; 
    	em[2320] = 2334; em[2321] = 8; 
    	em[2322] = 2337; em[2323] = 16; 
    	em[2324] = 2307; em[2325] = 24; 
    	em[2326] = 2334; em[2327] = 32; 
    	em[2328] = 2334; em[2329] = 40; 
    	em[2330] = 92; em[2331] = 56; 
    	em[2332] = 2340; em[2333] = 64; 
    em[2334] = 8884097; em[2335] = 8; em[2336] = 0; /* 2334: pointer.func */
    em[2337] = 8884097; em[2338] = 8; em[2339] = 0; /* 2337: pointer.func */
    em[2340] = 8884097; em[2341] = 8; em[2342] = 0; /* 2340: pointer.func */
    em[2343] = 8884097; em[2344] = 8; em[2345] = 0; /* 2343: pointer.func */
    em[2346] = 8884097; em[2347] = 8; em[2348] = 0; /* 2346: pointer.func */
    em[2349] = 8884097; em[2350] = 8; em[2351] = 0; /* 2349: pointer.func */
    em[2352] = 8884097; em[2353] = 8; em[2354] = 0; /* 2352: pointer.func */
    em[2355] = 8884097; em[2356] = 8; em[2357] = 0; /* 2355: pointer.func */
    em[2358] = 8884097; em[2359] = 8; em[2360] = 0; /* 2358: pointer.func */
    em[2361] = 0; em[2362] = 96; em[2363] = 11; /* 2361: struct.dsa_method */
    	em[2364] = 26; em[2365] = 0; 
    	em[2366] = 2355; em[2367] = 8; 
    	em[2368] = 2386; em[2369] = 16; 
    	em[2370] = 2352; em[2371] = 24; 
    	em[2372] = 2349; em[2373] = 32; 
    	em[2374] = 2304; em[2375] = 40; 
    	em[2376] = 2346; em[2377] = 48; 
    	em[2378] = 2346; em[2379] = 56; 
    	em[2380] = 92; em[2381] = 72; 
    	em[2382] = 2389; em[2383] = 80; 
    	em[2384] = 2346; em[2385] = 88; 
    em[2386] = 8884097; em[2387] = 8; em[2388] = 0; /* 2386: pointer.func */
    em[2389] = 8884097; em[2390] = 8; em[2391] = 0; /* 2389: pointer.func */
    em[2392] = 0; em[2393] = 32; em[2394] = 3; /* 2392: struct.ecdh_method */
    	em[2395] = 26; em[2396] = 0; 
    	em[2397] = 2401; em[2398] = 8; 
    	em[2399] = 92; em[2400] = 24; 
    em[2401] = 8884097; em[2402] = 8; em[2403] = 0; /* 2401: pointer.func */
    em[2404] = 8884097; em[2405] = 8; em[2406] = 0; /* 2404: pointer.func */
    em[2407] = 8884097; em[2408] = 8; em[2409] = 0; /* 2407: pointer.func */
    em[2410] = 1; em[2411] = 8; em[2412] = 1; /* 2410: pointer.struct.dsa_method */
    	em[2413] = 2361; em[2414] = 0; 
    em[2415] = 8884097; em[2416] = 8; em[2417] = 0; /* 2415: pointer.func */
    em[2418] = 0; em[2419] = 32; em[2420] = 2; /* 2418: struct.stack_st */
    	em[2421] = 1530; em[2422] = 8; 
    	em[2423] = 231; em[2424] = 24; 
    em[2425] = 8884097; em[2426] = 8; em[2427] = 0; /* 2425: pointer.func */
    em[2428] = 0; em[2429] = 112; em[2430] = 13; /* 2428: struct.rsa_meth_st */
    	em[2431] = 26; em[2432] = 0; 
    	em[2433] = 2457; em[2434] = 8; 
    	em[2435] = 2457; em[2436] = 16; 
    	em[2437] = 2457; em[2438] = 24; 
    	em[2439] = 2457; em[2440] = 32; 
    	em[2441] = 2425; em[2442] = 40; 
    	em[2443] = 2460; em[2444] = 48; 
    	em[2445] = 2278; em[2446] = 56; 
    	em[2447] = 2278; em[2448] = 64; 
    	em[2449] = 92; em[2450] = 80; 
    	em[2451] = 2463; em[2452] = 88; 
    	em[2453] = 2415; em[2454] = 96; 
    	em[2455] = 2466; em[2456] = 104; 
    em[2457] = 8884097; em[2458] = 8; em[2459] = 0; /* 2457: pointer.func */
    em[2460] = 8884097; em[2461] = 8; em[2462] = 0; /* 2460: pointer.func */
    em[2463] = 8884097; em[2464] = 8; em[2465] = 0; /* 2463: pointer.func */
    em[2466] = 8884097; em[2467] = 8; em[2468] = 0; /* 2466: pointer.func */
    em[2469] = 1; em[2470] = 8; em[2471] = 1; /* 2469: pointer.struct.rsa_meth_st */
    	em[2472] = 2428; em[2473] = 0; 
    em[2474] = 1; em[2475] = 8; em[2476] = 1; /* 2474: pointer.struct.ec_method_st */
    	em[2477] = 2479; em[2478] = 0; 
    em[2479] = 0; em[2480] = 304; em[2481] = 37; /* 2479: struct.ec_method_st */
    	em[2482] = 2556; em[2483] = 8; 
    	em[2484] = 2559; em[2485] = 16; 
    	em[2486] = 2559; em[2487] = 24; 
    	em[2488] = 2562; em[2489] = 32; 
    	em[2490] = 2565; em[2491] = 40; 
    	em[2492] = 2568; em[2493] = 48; 
    	em[2494] = 2571; em[2495] = 56; 
    	em[2496] = 2574; em[2497] = 64; 
    	em[2498] = 2577; em[2499] = 72; 
    	em[2500] = 2580; em[2501] = 80; 
    	em[2502] = 2580; em[2503] = 88; 
    	em[2504] = 2583; em[2505] = 96; 
    	em[2506] = 2586; em[2507] = 104; 
    	em[2508] = 2589; em[2509] = 112; 
    	em[2510] = 2592; em[2511] = 120; 
    	em[2512] = 2272; em[2513] = 128; 
    	em[2514] = 2595; em[2515] = 136; 
    	em[2516] = 2598; em[2517] = 144; 
    	em[2518] = 2601; em[2519] = 152; 
    	em[2520] = 2604; em[2521] = 160; 
    	em[2522] = 2607; em[2523] = 168; 
    	em[2524] = 2610; em[2525] = 176; 
    	em[2526] = 2613; em[2527] = 184; 
    	em[2528] = 2616; em[2529] = 192; 
    	em[2530] = 2619; em[2531] = 200; 
    	em[2532] = 2622; em[2533] = 208; 
    	em[2534] = 2613; em[2535] = 216; 
    	em[2536] = 2625; em[2537] = 224; 
    	em[2538] = 2628; em[2539] = 232; 
    	em[2540] = 2631; em[2541] = 240; 
    	em[2542] = 2571; em[2543] = 248; 
    	em[2544] = 2634; em[2545] = 256; 
    	em[2546] = 2637; em[2547] = 264; 
    	em[2548] = 2634; em[2549] = 272; 
    	em[2550] = 2637; em[2551] = 280; 
    	em[2552] = 2637; em[2553] = 288; 
    	em[2554] = 2640; em[2555] = 296; 
    em[2556] = 8884097; em[2557] = 8; em[2558] = 0; /* 2556: pointer.func */
    em[2559] = 8884097; em[2560] = 8; em[2561] = 0; /* 2559: pointer.func */
    em[2562] = 8884097; em[2563] = 8; em[2564] = 0; /* 2562: pointer.func */
    em[2565] = 8884097; em[2566] = 8; em[2567] = 0; /* 2565: pointer.func */
    em[2568] = 8884097; em[2569] = 8; em[2570] = 0; /* 2568: pointer.func */
    em[2571] = 8884097; em[2572] = 8; em[2573] = 0; /* 2571: pointer.func */
    em[2574] = 8884097; em[2575] = 8; em[2576] = 0; /* 2574: pointer.func */
    em[2577] = 8884097; em[2578] = 8; em[2579] = 0; /* 2577: pointer.func */
    em[2580] = 8884097; em[2581] = 8; em[2582] = 0; /* 2580: pointer.func */
    em[2583] = 8884097; em[2584] = 8; em[2585] = 0; /* 2583: pointer.func */
    em[2586] = 8884097; em[2587] = 8; em[2588] = 0; /* 2586: pointer.func */
    em[2589] = 8884097; em[2590] = 8; em[2591] = 0; /* 2589: pointer.func */
    em[2592] = 8884097; em[2593] = 8; em[2594] = 0; /* 2592: pointer.func */
    em[2595] = 8884097; em[2596] = 8; em[2597] = 0; /* 2595: pointer.func */
    em[2598] = 8884097; em[2599] = 8; em[2600] = 0; /* 2598: pointer.func */
    em[2601] = 8884097; em[2602] = 8; em[2603] = 0; /* 2601: pointer.func */
    em[2604] = 8884097; em[2605] = 8; em[2606] = 0; /* 2604: pointer.func */
    em[2607] = 8884097; em[2608] = 8; em[2609] = 0; /* 2607: pointer.func */
    em[2610] = 8884097; em[2611] = 8; em[2612] = 0; /* 2610: pointer.func */
    em[2613] = 8884097; em[2614] = 8; em[2615] = 0; /* 2613: pointer.func */
    em[2616] = 8884097; em[2617] = 8; em[2618] = 0; /* 2616: pointer.func */
    em[2619] = 8884097; em[2620] = 8; em[2621] = 0; /* 2619: pointer.func */
    em[2622] = 8884097; em[2623] = 8; em[2624] = 0; /* 2622: pointer.func */
    em[2625] = 8884097; em[2626] = 8; em[2627] = 0; /* 2625: pointer.func */
    em[2628] = 8884097; em[2629] = 8; em[2630] = 0; /* 2628: pointer.func */
    em[2631] = 8884097; em[2632] = 8; em[2633] = 0; /* 2631: pointer.func */
    em[2634] = 8884097; em[2635] = 8; em[2636] = 0; /* 2634: pointer.func */
    em[2637] = 8884097; em[2638] = 8; em[2639] = 0; /* 2637: pointer.func */
    em[2640] = 8884097; em[2641] = 8; em[2642] = 0; /* 2640: pointer.func */
    em[2643] = 8884097; em[2644] = 8; em[2645] = 0; /* 2643: pointer.func */
    em[2646] = 0; em[2647] = 48; em[2648] = 5; /* 2646: struct.ecdsa_method */
    	em[2649] = 26; em[2650] = 0; 
    	em[2651] = 2659; em[2652] = 8; 
    	em[2653] = 2301; em[2654] = 16; 
    	em[2655] = 2662; em[2656] = 24; 
    	em[2657] = 92; em[2658] = 40; 
    em[2659] = 8884097; em[2660] = 8; em[2661] = 0; /* 2659: pointer.func */
    em[2662] = 8884097; em[2663] = 8; em[2664] = 0; /* 2662: pointer.func */
    em[2665] = 8884097; em[2666] = 8; em[2667] = 0; /* 2665: pointer.func */
    em[2668] = 0; em[2669] = 56; em[2670] = 4; /* 2668: struct.evp_pkey_st */
    	em[2671] = 2679; em[2672] = 16; 
    	em[2673] = 2768; em[2674] = 24; 
    	em[2675] = 2928; em[2676] = 32; 
    	em[2677] = 1942; em[2678] = 48; 
    em[2679] = 1; em[2680] = 8; em[2681] = 1; /* 2679: pointer.struct.evp_pkey_asn1_method_st */
    	em[2682] = 2684; em[2683] = 0; 
    em[2684] = 0; em[2685] = 208; em[2686] = 24; /* 2684: struct.evp_pkey_asn1_method_st */
    	em[2687] = 92; em[2688] = 16; 
    	em[2689] = 92; em[2690] = 24; 
    	em[2691] = 2735; em[2692] = 32; 
    	em[2693] = 2738; em[2694] = 40; 
    	em[2695] = 2741; em[2696] = 48; 
    	em[2697] = 2744; em[2698] = 56; 
    	em[2699] = 2747; em[2700] = 64; 
    	em[2701] = 2750; em[2702] = 72; 
    	em[2703] = 2744; em[2704] = 80; 
    	em[2705] = 2404; em[2706] = 88; 
    	em[2707] = 2404; em[2708] = 96; 
    	em[2709] = 2753; em[2710] = 104; 
    	em[2711] = 2665; em[2712] = 112; 
    	em[2713] = 2404; em[2714] = 120; 
    	em[2715] = 2756; em[2716] = 128; 
    	em[2717] = 2741; em[2718] = 136; 
    	em[2719] = 2744; em[2720] = 144; 
    	em[2721] = 2759; em[2722] = 152; 
    	em[2723] = 2762; em[2724] = 160; 
    	em[2725] = 2643; em[2726] = 168; 
    	em[2727] = 2753; em[2728] = 176; 
    	em[2729] = 2665; em[2730] = 184; 
    	em[2731] = 2281; em[2732] = 192; 
    	em[2733] = 2765; em[2734] = 200; 
    em[2735] = 8884097; em[2736] = 8; em[2737] = 0; /* 2735: pointer.func */
    em[2738] = 8884097; em[2739] = 8; em[2740] = 0; /* 2738: pointer.func */
    em[2741] = 8884097; em[2742] = 8; em[2743] = 0; /* 2741: pointer.func */
    em[2744] = 8884097; em[2745] = 8; em[2746] = 0; /* 2744: pointer.func */
    em[2747] = 8884097; em[2748] = 8; em[2749] = 0; /* 2747: pointer.func */
    em[2750] = 8884097; em[2751] = 8; em[2752] = 0; /* 2750: pointer.func */
    em[2753] = 8884097; em[2754] = 8; em[2755] = 0; /* 2753: pointer.func */
    em[2756] = 8884097; em[2757] = 8; em[2758] = 0; /* 2756: pointer.func */
    em[2759] = 8884097; em[2760] = 8; em[2761] = 0; /* 2759: pointer.func */
    em[2762] = 8884097; em[2763] = 8; em[2764] = 0; /* 2762: pointer.func */
    em[2765] = 8884097; em[2766] = 8; em[2767] = 0; /* 2765: pointer.func */
    em[2768] = 1; em[2769] = 8; em[2770] = 1; /* 2768: pointer.struct.engine_st */
    	em[2771] = 2773; em[2772] = 0; 
    em[2773] = 0; em[2774] = 216; em[2775] = 24; /* 2773: struct.engine_st */
    	em[2776] = 26; em[2777] = 0; 
    	em[2778] = 26; em[2779] = 8; 
    	em[2780] = 2469; em[2781] = 16; 
    	em[2782] = 2410; em[2783] = 24; 
    	em[2784] = 2310; em[2785] = 32; 
    	em[2786] = 2824; em[2787] = 40; 
    	em[2788] = 2829; em[2789] = 48; 
    	em[2790] = 2834; em[2791] = 56; 
    	em[2792] = 2860; em[2793] = 64; 
    	em[2794] = 2266; em[2795] = 72; 
    	em[2796] = 2868; em[2797] = 80; 
    	em[2798] = 2871; em[2799] = 88; 
    	em[2800] = 2874; em[2801] = 96; 
    	em[2802] = 2877; em[2803] = 104; 
    	em[2804] = 2877; em[2805] = 112; 
    	em[2806] = 2877; em[2807] = 120; 
    	em[2808] = 2880; em[2809] = 128; 
    	em[2810] = 2883; em[2811] = 136; 
    	em[2812] = 2883; em[2813] = 144; 
    	em[2814] = 2886; em[2815] = 152; 
    	em[2816] = 2889; em[2817] = 160; 
    	em[2818] = 2901; em[2819] = 184; 
    	em[2820] = 2923; em[2821] = 200; 
    	em[2822] = 2923; em[2823] = 208; 
    em[2824] = 1; em[2825] = 8; em[2826] = 1; /* 2824: pointer.struct.ecdh_method */
    	em[2827] = 2392; em[2828] = 0; 
    em[2829] = 1; em[2830] = 8; em[2831] = 1; /* 2829: pointer.struct.ecdsa_method */
    	em[2832] = 2646; em[2833] = 0; 
    em[2834] = 1; em[2835] = 8; em[2836] = 1; /* 2834: pointer.struct.rand_meth_st */
    	em[2837] = 2839; em[2838] = 0; 
    em[2839] = 0; em[2840] = 48; em[2841] = 6; /* 2839: struct.rand_meth_st */
    	em[2842] = 2343; em[2843] = 0; 
    	em[2844] = 2854; em[2845] = 8; 
    	em[2846] = 2857; em[2847] = 16; 
    	em[2848] = 2275; em[2849] = 24; 
    	em[2850] = 2854; em[2851] = 32; 
    	em[2852] = 2269; em[2853] = 40; 
    em[2854] = 8884097; em[2855] = 8; em[2856] = 0; /* 2854: pointer.func */
    em[2857] = 8884097; em[2858] = 8; em[2859] = 0; /* 2857: pointer.func */
    em[2860] = 1; em[2861] = 8; em[2862] = 1; /* 2860: pointer.struct.store_method_st */
    	em[2863] = 2865; em[2864] = 0; 
    em[2865] = 0; em[2866] = 0; em[2867] = 0; /* 2865: struct.store_method_st */
    em[2868] = 8884097; em[2869] = 8; em[2870] = 0; /* 2868: pointer.func */
    em[2871] = 8884097; em[2872] = 8; em[2873] = 0; /* 2871: pointer.func */
    em[2874] = 8884097; em[2875] = 8; em[2876] = 0; /* 2874: pointer.func */
    em[2877] = 8884097; em[2878] = 8; em[2879] = 0; /* 2877: pointer.func */
    em[2880] = 8884097; em[2881] = 8; em[2882] = 0; /* 2880: pointer.func */
    em[2883] = 8884097; em[2884] = 8; em[2885] = 0; /* 2883: pointer.func */
    em[2886] = 8884097; em[2887] = 8; em[2888] = 0; /* 2886: pointer.func */
    em[2889] = 1; em[2890] = 8; em[2891] = 1; /* 2889: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[2892] = 2894; em[2893] = 0; 
    em[2894] = 0; em[2895] = 32; em[2896] = 2; /* 2894: struct.ENGINE_CMD_DEFN_st */
    	em[2897] = 26; em[2898] = 8; 
    	em[2899] = 26; em[2900] = 16; 
    em[2901] = 0; em[2902] = 16; em[2903] = 1; /* 2901: struct.crypto_ex_data_st */
    	em[2904] = 2906; em[2905] = 0; 
    em[2906] = 1; em[2907] = 8; em[2908] = 1; /* 2906: pointer.struct.stack_st_void */
    	em[2909] = 2911; em[2910] = 0; 
    em[2911] = 0; em[2912] = 32; em[2913] = 1; /* 2911: struct.stack_st_void */
    	em[2914] = 2916; em[2915] = 0; 
    em[2916] = 0; em[2917] = 32; em[2918] = 2; /* 2916: struct.stack_st */
    	em[2919] = 1530; em[2920] = 8; 
    	em[2921] = 231; em[2922] = 24; 
    em[2923] = 1; em[2924] = 8; em[2925] = 1; /* 2923: pointer.struct.engine_st */
    	em[2926] = 2773; em[2927] = 0; 
    em[2928] = 0; em[2929] = 8; em[2930] = 5; /* 2928: union.unknown */
    	em[2931] = 92; em[2932] = 0; 
    	em[2933] = 2941; em[2934] = 0; 
    	em[2935] = 3151; em[2936] = 0; 
    	em[2937] = 3283; em[2938] = 0; 
    	em[2939] = 3409; em[2940] = 0; 
    em[2941] = 1; em[2942] = 8; em[2943] = 1; /* 2941: pointer.struct.rsa_st */
    	em[2944] = 2946; em[2945] = 0; 
    em[2946] = 0; em[2947] = 168; em[2948] = 17; /* 2946: struct.rsa_st */
    	em[2949] = 2983; em[2950] = 16; 
    	em[2951] = 3032; em[2952] = 24; 
    	em[2953] = 3037; em[2954] = 32; 
    	em[2955] = 3037; em[2956] = 40; 
    	em[2957] = 3037; em[2958] = 48; 
    	em[2959] = 3037; em[2960] = 56; 
    	em[2961] = 3037; em[2962] = 64; 
    	em[2963] = 3037; em[2964] = 72; 
    	em[2965] = 3037; em[2966] = 80; 
    	em[2967] = 3037; em[2968] = 88; 
    	em[2969] = 3054; em[2970] = 96; 
    	em[2971] = 3076; em[2972] = 120; 
    	em[2973] = 3076; em[2974] = 128; 
    	em[2975] = 3076; em[2976] = 136; 
    	em[2977] = 92; em[2978] = 144; 
    	em[2979] = 3090; em[2980] = 152; 
    	em[2981] = 3090; em[2982] = 160; 
    em[2983] = 1; em[2984] = 8; em[2985] = 1; /* 2983: pointer.struct.rsa_meth_st */
    	em[2986] = 2988; em[2987] = 0; 
    em[2988] = 0; em[2989] = 112; em[2990] = 13; /* 2988: struct.rsa_meth_st */
    	em[2991] = 26; em[2992] = 0; 
    	em[2993] = 3017; em[2994] = 8; 
    	em[2995] = 3017; em[2996] = 16; 
    	em[2997] = 3017; em[2998] = 24; 
    	em[2999] = 3017; em[3000] = 32; 
    	em[3001] = 3020; em[3002] = 40; 
    	em[3003] = 2358; em[3004] = 48; 
    	em[3005] = 3023; em[3006] = 56; 
    	em[3007] = 3023; em[3008] = 64; 
    	em[3009] = 92; em[3010] = 80; 
    	em[3011] = 3026; em[3012] = 88; 
    	em[3013] = 2407; em[3014] = 96; 
    	em[3015] = 3029; em[3016] = 104; 
    em[3017] = 8884097; em[3018] = 8; em[3019] = 0; /* 3017: pointer.func */
    em[3020] = 8884097; em[3021] = 8; em[3022] = 0; /* 3020: pointer.func */
    em[3023] = 8884097; em[3024] = 8; em[3025] = 0; /* 3023: pointer.func */
    em[3026] = 8884097; em[3027] = 8; em[3028] = 0; /* 3026: pointer.func */
    em[3029] = 8884097; em[3030] = 8; em[3031] = 0; /* 3029: pointer.func */
    em[3032] = 1; em[3033] = 8; em[3034] = 1; /* 3032: pointer.struct.engine_st */
    	em[3035] = 2773; em[3036] = 0; 
    em[3037] = 1; em[3038] = 8; em[3039] = 1; /* 3037: pointer.struct.bignum_st */
    	em[3040] = 3042; em[3041] = 0; 
    em[3042] = 0; em[3043] = 24; em[3044] = 1; /* 3042: struct.bignum_st */
    	em[3045] = 3047; em[3046] = 0; 
    em[3047] = 8884099; em[3048] = 8; em[3049] = 2; /* 3047: pointer_to_array_of_pointers_to_stack */
    	em[3050] = 2015; em[3051] = 0; 
    	em[3052] = 228; em[3053] = 12; 
    em[3054] = 0; em[3055] = 16; em[3056] = 1; /* 3054: struct.crypto_ex_data_st */
    	em[3057] = 3059; em[3058] = 0; 
    em[3059] = 1; em[3060] = 8; em[3061] = 1; /* 3059: pointer.struct.stack_st_void */
    	em[3062] = 3064; em[3063] = 0; 
    em[3064] = 0; em[3065] = 32; em[3066] = 1; /* 3064: struct.stack_st_void */
    	em[3067] = 3069; em[3068] = 0; 
    em[3069] = 0; em[3070] = 32; em[3071] = 2; /* 3069: struct.stack_st */
    	em[3072] = 1530; em[3073] = 8; 
    	em[3074] = 231; em[3075] = 24; 
    em[3076] = 1; em[3077] = 8; em[3078] = 1; /* 3076: pointer.struct.bn_mont_ctx_st */
    	em[3079] = 3081; em[3080] = 0; 
    em[3081] = 0; em[3082] = 96; em[3083] = 3; /* 3081: struct.bn_mont_ctx_st */
    	em[3084] = 3042; em[3085] = 8; 
    	em[3086] = 3042; em[3087] = 32; 
    	em[3088] = 3042; em[3089] = 56; 
    em[3090] = 1; em[3091] = 8; em[3092] = 1; /* 3090: pointer.struct.bn_blinding_st */
    	em[3093] = 3095; em[3094] = 0; 
    em[3095] = 0; em[3096] = 88; em[3097] = 7; /* 3095: struct.bn_blinding_st */
    	em[3098] = 3112; em[3099] = 0; 
    	em[3100] = 3112; em[3101] = 8; 
    	em[3102] = 3112; em[3103] = 16; 
    	em[3104] = 3112; em[3105] = 24; 
    	em[3106] = 3129; em[3107] = 40; 
    	em[3108] = 3134; em[3109] = 72; 
    	em[3110] = 3148; em[3111] = 80; 
    em[3112] = 1; em[3113] = 8; em[3114] = 1; /* 3112: pointer.struct.bignum_st */
    	em[3115] = 3117; em[3116] = 0; 
    em[3117] = 0; em[3118] = 24; em[3119] = 1; /* 3117: struct.bignum_st */
    	em[3120] = 3122; em[3121] = 0; 
    em[3122] = 8884099; em[3123] = 8; em[3124] = 2; /* 3122: pointer_to_array_of_pointers_to_stack */
    	em[3125] = 2015; em[3126] = 0; 
    	em[3127] = 228; em[3128] = 12; 
    em[3129] = 0; em[3130] = 16; em[3131] = 1; /* 3129: struct.crypto_threadid_st */
    	em[3132] = 1989; em[3133] = 0; 
    em[3134] = 1; em[3135] = 8; em[3136] = 1; /* 3134: pointer.struct.bn_mont_ctx_st */
    	em[3137] = 3139; em[3138] = 0; 
    em[3139] = 0; em[3140] = 96; em[3141] = 3; /* 3139: struct.bn_mont_ctx_st */
    	em[3142] = 3117; em[3143] = 8; 
    	em[3144] = 3117; em[3145] = 32; 
    	em[3146] = 3117; em[3147] = 56; 
    em[3148] = 8884097; em[3149] = 8; em[3150] = 0; /* 3148: pointer.func */
    em[3151] = 1; em[3152] = 8; em[3153] = 1; /* 3151: pointer.struct.dsa_st */
    	em[3154] = 3156; em[3155] = 0; 
    em[3156] = 0; em[3157] = 136; em[3158] = 11; /* 3156: struct.dsa_st */
    	em[3159] = 3181; em[3160] = 24; 
    	em[3161] = 3181; em[3162] = 32; 
    	em[3163] = 3181; em[3164] = 40; 
    	em[3165] = 3181; em[3166] = 48; 
    	em[3167] = 3181; em[3168] = 56; 
    	em[3169] = 3181; em[3170] = 64; 
    	em[3171] = 3181; em[3172] = 72; 
    	em[3173] = 3198; em[3174] = 88; 
    	em[3175] = 3212; em[3176] = 104; 
    	em[3177] = 3227; em[3178] = 120; 
    	em[3179] = 3278; em[3180] = 128; 
    em[3181] = 1; em[3182] = 8; em[3183] = 1; /* 3181: pointer.struct.bignum_st */
    	em[3184] = 3186; em[3185] = 0; 
    em[3186] = 0; em[3187] = 24; em[3188] = 1; /* 3186: struct.bignum_st */
    	em[3189] = 3191; em[3190] = 0; 
    em[3191] = 8884099; em[3192] = 8; em[3193] = 2; /* 3191: pointer_to_array_of_pointers_to_stack */
    	em[3194] = 2015; em[3195] = 0; 
    	em[3196] = 228; em[3197] = 12; 
    em[3198] = 1; em[3199] = 8; em[3200] = 1; /* 3198: pointer.struct.bn_mont_ctx_st */
    	em[3201] = 3203; em[3202] = 0; 
    em[3203] = 0; em[3204] = 96; em[3205] = 3; /* 3203: struct.bn_mont_ctx_st */
    	em[3206] = 3186; em[3207] = 8; 
    	em[3208] = 3186; em[3209] = 32; 
    	em[3210] = 3186; em[3211] = 56; 
    em[3212] = 0; em[3213] = 16; em[3214] = 1; /* 3212: struct.crypto_ex_data_st */
    	em[3215] = 3217; em[3216] = 0; 
    em[3217] = 1; em[3218] = 8; em[3219] = 1; /* 3217: pointer.struct.stack_st_void */
    	em[3220] = 3222; em[3221] = 0; 
    em[3222] = 0; em[3223] = 32; em[3224] = 1; /* 3222: struct.stack_st_void */
    	em[3225] = 2418; em[3226] = 0; 
    em[3227] = 1; em[3228] = 8; em[3229] = 1; /* 3227: pointer.struct.dsa_method */
    	em[3230] = 3232; em[3231] = 0; 
    em[3232] = 0; em[3233] = 96; em[3234] = 11; /* 3232: struct.dsa_method */
    	em[3235] = 26; em[3236] = 0; 
    	em[3237] = 3257; em[3238] = 8; 
    	em[3239] = 3260; em[3240] = 16; 
    	em[3241] = 3263; em[3242] = 24; 
    	em[3243] = 3266; em[3244] = 32; 
    	em[3245] = 3269; em[3246] = 40; 
    	em[3247] = 3272; em[3248] = 48; 
    	em[3249] = 3272; em[3250] = 56; 
    	em[3251] = 92; em[3252] = 72; 
    	em[3253] = 3275; em[3254] = 80; 
    	em[3255] = 3272; em[3256] = 88; 
    em[3257] = 8884097; em[3258] = 8; em[3259] = 0; /* 3257: pointer.func */
    em[3260] = 8884097; em[3261] = 8; em[3262] = 0; /* 3260: pointer.func */
    em[3263] = 8884097; em[3264] = 8; em[3265] = 0; /* 3263: pointer.func */
    em[3266] = 8884097; em[3267] = 8; em[3268] = 0; /* 3266: pointer.func */
    em[3269] = 8884097; em[3270] = 8; em[3271] = 0; /* 3269: pointer.func */
    em[3272] = 8884097; em[3273] = 8; em[3274] = 0; /* 3272: pointer.func */
    em[3275] = 8884097; em[3276] = 8; em[3277] = 0; /* 3275: pointer.func */
    em[3278] = 1; em[3279] = 8; em[3280] = 1; /* 3278: pointer.struct.engine_st */
    	em[3281] = 2773; em[3282] = 0; 
    em[3283] = 1; em[3284] = 8; em[3285] = 1; /* 3283: pointer.struct.dh_st */
    	em[3286] = 3288; em[3287] = 0; 
    em[3288] = 0; em[3289] = 144; em[3290] = 12; /* 3288: struct.dh_st */
    	em[3291] = 3315; em[3292] = 8; 
    	em[3293] = 3315; em[3294] = 16; 
    	em[3295] = 3315; em[3296] = 32; 
    	em[3297] = 3315; em[3298] = 40; 
    	em[3299] = 3332; em[3300] = 56; 
    	em[3301] = 3315; em[3302] = 64; 
    	em[3303] = 3315; em[3304] = 72; 
    	em[3305] = 107; em[3306] = 80; 
    	em[3307] = 3315; em[3308] = 96; 
    	em[3309] = 3346; em[3310] = 112; 
    	em[3311] = 3368; em[3312] = 128; 
    	em[3313] = 3404; em[3314] = 136; 
    em[3315] = 1; em[3316] = 8; em[3317] = 1; /* 3315: pointer.struct.bignum_st */
    	em[3318] = 3320; em[3319] = 0; 
    em[3320] = 0; em[3321] = 24; em[3322] = 1; /* 3320: struct.bignum_st */
    	em[3323] = 3325; em[3324] = 0; 
    em[3325] = 8884099; em[3326] = 8; em[3327] = 2; /* 3325: pointer_to_array_of_pointers_to_stack */
    	em[3328] = 2015; em[3329] = 0; 
    	em[3330] = 228; em[3331] = 12; 
    em[3332] = 1; em[3333] = 8; em[3334] = 1; /* 3332: pointer.struct.bn_mont_ctx_st */
    	em[3335] = 3337; em[3336] = 0; 
    em[3337] = 0; em[3338] = 96; em[3339] = 3; /* 3337: struct.bn_mont_ctx_st */
    	em[3340] = 3320; em[3341] = 8; 
    	em[3342] = 3320; em[3343] = 32; 
    	em[3344] = 3320; em[3345] = 56; 
    em[3346] = 0; em[3347] = 16; em[3348] = 1; /* 3346: struct.crypto_ex_data_st */
    	em[3349] = 3351; em[3350] = 0; 
    em[3351] = 1; em[3352] = 8; em[3353] = 1; /* 3351: pointer.struct.stack_st_void */
    	em[3354] = 3356; em[3355] = 0; 
    em[3356] = 0; em[3357] = 32; em[3358] = 1; /* 3356: struct.stack_st_void */
    	em[3359] = 3361; em[3360] = 0; 
    em[3361] = 0; em[3362] = 32; em[3363] = 2; /* 3361: struct.stack_st */
    	em[3364] = 1530; em[3365] = 8; 
    	em[3366] = 231; em[3367] = 24; 
    em[3368] = 1; em[3369] = 8; em[3370] = 1; /* 3368: pointer.struct.dh_method */
    	em[3371] = 3373; em[3372] = 0; 
    em[3373] = 0; em[3374] = 72; em[3375] = 8; /* 3373: struct.dh_method */
    	em[3376] = 26; em[3377] = 0; 
    	em[3378] = 3392; em[3379] = 8; 
    	em[3380] = 3395; em[3381] = 16; 
    	em[3382] = 3398; em[3383] = 24; 
    	em[3384] = 3392; em[3385] = 32; 
    	em[3386] = 3392; em[3387] = 40; 
    	em[3388] = 92; em[3389] = 56; 
    	em[3390] = 3401; em[3391] = 64; 
    em[3392] = 8884097; em[3393] = 8; em[3394] = 0; /* 3392: pointer.func */
    em[3395] = 8884097; em[3396] = 8; em[3397] = 0; /* 3395: pointer.func */
    em[3398] = 8884097; em[3399] = 8; em[3400] = 0; /* 3398: pointer.func */
    em[3401] = 8884097; em[3402] = 8; em[3403] = 0; /* 3401: pointer.func */
    em[3404] = 1; em[3405] = 8; em[3406] = 1; /* 3404: pointer.struct.engine_st */
    	em[3407] = 2773; em[3408] = 0; 
    em[3409] = 1; em[3410] = 8; em[3411] = 1; /* 3409: pointer.struct.ec_key_st */
    	em[3412] = 3414; em[3413] = 0; 
    em[3414] = 0; em[3415] = 56; em[3416] = 4; /* 3414: struct.ec_key_st */
    	em[3417] = 3425; em[3418] = 8; 
    	em[3419] = 2023; em[3420] = 16; 
    	em[3421] = 2018; em[3422] = 24; 
    	em[3423] = 1998; em[3424] = 48; 
    em[3425] = 1; em[3426] = 8; em[3427] = 1; /* 3425: pointer.struct.ec_group_st */
    	em[3428] = 3430; em[3429] = 0; 
    em[3430] = 0; em[3431] = 232; em[3432] = 12; /* 3430: struct.ec_group_st */
    	em[3433] = 2474; em[3434] = 0; 
    	em[3435] = 3457; em[3436] = 8; 
    	em[3437] = 2249; em[3438] = 16; 
    	em[3439] = 2249; em[3440] = 40; 
    	em[3441] = 107; em[3442] = 80; 
    	em[3443] = 2244; em[3444] = 96; 
    	em[3445] = 2249; em[3446] = 104; 
    	em[3447] = 2249; em[3448] = 152; 
    	em[3449] = 2249; em[3450] = 176; 
    	em[3451] = 1989; em[3452] = 208; 
    	em[3453] = 1989; em[3454] = 216; 
    	em[3455] = 2223; em[3456] = 224; 
    em[3457] = 1; em[3458] = 8; em[3459] = 1; /* 3457: pointer.struct.ec_point_st */
    	em[3460] = 2028; em[3461] = 0; 
    em[3462] = 1; em[3463] = 8; em[3464] = 1; /* 3462: pointer.struct.evp_pkey_st */
    	em[3465] = 2668; em[3466] = 0; 
    em[3467] = 0; em[3468] = 24; em[3469] = 1; /* 3467: struct.asn1_string_st */
    	em[3470] = 107; em[3471] = 8; 
    em[3472] = 1; em[3473] = 8; em[3474] = 1; /* 3472: pointer.struct.AUTHORITY_KEYID_st */
    	em[3475] = 3477; em[3476] = 0; 
    em[3477] = 0; em[3478] = 24; em[3479] = 3; /* 3477: struct.AUTHORITY_KEYID_st */
    	em[3480] = 1508; em[3481] = 0; 
    	em[3482] = 1484; em[3483] = 8; 
    	em[3484] = 2261; em[3485] = 16; 
    em[3486] = 1; em[3487] = 8; em[3488] = 1; /* 3486: pointer.struct.asn1_string_st */
    	em[3489] = 3467; em[3490] = 0; 
    em[3491] = 0; em[3492] = 24; em[3493] = 3; /* 3491: struct.X509_pubkey_st */
    	em[3494] = 3500; em[3495] = 0; 
    	em[3496] = 3486; em[3497] = 8; 
    	em[3498] = 3462; em[3499] = 16; 
    em[3500] = 1; em[3501] = 8; em[3502] = 1; /* 3500: pointer.struct.X509_algor_st */
    	em[3503] = 5; em[3504] = 0; 
    em[3505] = 0; em[3506] = 184; em[3507] = 12; /* 3505: struct.x509_st */
    	em[3508] = 3532; em[3509] = 0; 
    	em[3510] = 3567; em[3511] = 8; 
    	em[3512] = 1595; em[3513] = 16; 
    	em[3514] = 92; em[3515] = 32; 
    	em[3516] = 1540; em[3517] = 40; 
    	em[3518] = 262; em[3519] = 104; 
    	em[3520] = 3472; em[3521] = 112; 
    	em[3522] = 3630; em[3523] = 120; 
    	em[3524] = 1056; em[3525] = 128; 
    	em[3526] = 647; em[3527] = 136; 
    	em[3528] = 597; em[3529] = 144; 
    	em[3530] = 234; em[3531] = 176; 
    em[3532] = 1; em[3533] = 8; em[3534] = 1; /* 3532: pointer.struct.x509_cinf_st */
    	em[3535] = 3537; em[3536] = 0; 
    em[3537] = 0; em[3538] = 104; em[3539] = 11; /* 3537: struct.x509_cinf_st */
    	em[3540] = 3562; em[3541] = 0; 
    	em[3542] = 3562; em[3543] = 8; 
    	em[3544] = 3567; em[3545] = 16; 
    	em[3546] = 3572; em[3547] = 24; 
    	em[3548] = 2284; em[3549] = 32; 
    	em[3550] = 3572; em[3551] = 40; 
    	em[3552] = 3620; em[3553] = 48; 
    	em[3554] = 1595; em[3555] = 56; 
    	em[3556] = 1595; em[3557] = 64; 
    	em[3558] = 1571; em[3559] = 72; 
    	em[3560] = 3625; em[3561] = 80; 
    em[3562] = 1; em[3563] = 8; em[3564] = 1; /* 3562: pointer.struct.asn1_string_st */
    	em[3565] = 257; em[3566] = 0; 
    em[3567] = 1; em[3568] = 8; em[3569] = 1; /* 3567: pointer.struct.X509_algor_st */
    	em[3570] = 5; em[3571] = 0; 
    em[3572] = 1; em[3573] = 8; em[3574] = 1; /* 3572: pointer.struct.X509_name_st */
    	em[3575] = 3577; em[3576] = 0; 
    em[3577] = 0; em[3578] = 40; em[3579] = 3; /* 3577: struct.X509_name_st */
    	em[3580] = 3586; em[3581] = 0; 
    	em[3582] = 3610; em[3583] = 16; 
    	em[3584] = 107; em[3585] = 24; 
    em[3586] = 1; em[3587] = 8; em[3588] = 1; /* 3586: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[3589] = 3591; em[3590] = 0; 
    em[3591] = 0; em[3592] = 32; em[3593] = 2; /* 3591: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[3594] = 3598; em[3595] = 8; 
    	em[3596] = 231; em[3597] = 24; 
    em[3598] = 8884099; em[3599] = 8; em[3600] = 2; /* 3598: pointer_to_array_of_pointers_to_stack */
    	em[3601] = 3605; em[3602] = 0; 
    	em[3603] = 228; em[3604] = 20; 
    em[3605] = 0; em[3606] = 8; em[3607] = 1; /* 3605: pointer.X509_NAME_ENTRY */
    	em[3608] = 337; em[3609] = 0; 
    em[3610] = 1; em[3611] = 8; em[3612] = 1; /* 3610: pointer.struct.buf_mem_st */
    	em[3613] = 3615; em[3614] = 0; 
    em[3615] = 0; em[3616] = 24; em[3617] = 1; /* 3615: struct.buf_mem_st */
    	em[3618] = 92; em[3619] = 8; 
    em[3620] = 1; em[3621] = 8; em[3622] = 1; /* 3620: pointer.struct.X509_pubkey_st */
    	em[3623] = 3491; em[3624] = 0; 
    em[3625] = 0; em[3626] = 24; em[3627] = 1; /* 3625: struct.ASN1_ENCODING_st */
    	em[3628] = 107; em[3629] = 0; 
    em[3630] = 1; em[3631] = 8; em[3632] = 1; /* 3630: pointer.struct.X509_POLICY_CACHE_st */
    	em[3633] = 1477; em[3634] = 0; 
    em[3635] = 1; em[3636] = 8; em[3637] = 1; /* 3635: pointer.int */
    	em[3638] = 228; em[3639] = 0; 
    em[3640] = 0; em[3641] = 1; em[3642] = 0; /* 3640: char */
    em[3643] = 1; em[3644] = 8; em[3645] = 1; /* 3643: pointer.struct.x509_st */
    	em[3646] = 3505; em[3647] = 0; 
    args_addr->arg_entity_index[0] = 3643;
    args_addr->arg_entity_index[1] = 228;
    args_addr->arg_entity_index[2] = 3635;
    args_addr->arg_entity_index[3] = 3635;
    args_addr->ret_entity_index = 1989;
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

