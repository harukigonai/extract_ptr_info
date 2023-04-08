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

void bb_EC_GROUP_free(EC_GROUP * arg_a);

void EC_GROUP_free(EC_GROUP * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EC_GROUP_free called %lu\n", in_lib);
    if (!in_lib)
        bb_EC_GROUP_free(arg_a);
    else {
        void (*orig_EC_GROUP_free)(EC_GROUP *);
        orig_EC_GROUP_free = dlsym(RTLD_NEXT, "EC_GROUP_free");
        orig_EC_GROUP_free(arg_a);
    }
}

void bb_EC_GROUP_free(EC_GROUP * arg_a) 
{
    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 8884097; em[1] = 8; em[2] = 0; /* 0: pointer.func */
    em[3] = 8884097; em[4] = 8; em[5] = 0; /* 3: pointer.func */
    em[6] = 0; em[7] = 8; em[8] = 0; /* 6: pointer.void */
    em[9] = 1; em[10] = 8; em[11] = 1; /* 9: pointer.struct.ec_extra_data_st */
    	em[12] = 14; em[13] = 0; 
    em[14] = 0; em[15] = 40; em[16] = 5; /* 14: struct.ec_extra_data_st */
    	em[17] = 9; em[18] = 0; 
    	em[19] = 6; em[20] = 8; 
    	em[21] = 3; em[22] = 16; 
    	em[23] = 27; em[24] = 24; 
    	em[25] = 27; em[26] = 32; 
    em[27] = 8884097; em[28] = 8; em[29] = 0; /* 27: pointer.func */
    em[30] = 1; em[31] = 8; em[32] = 1; /* 30: pointer.struct.ec_extra_data_st */
    	em[33] = 14; em[34] = 0; 
    em[35] = 0; em[36] = 24; em[37] = 1; /* 35: struct.bignum_st */
    	em[38] = 40; em[39] = 0; 
    em[40] = 8884099; em[41] = 8; em[42] = 2; /* 40: pointer_to_array_of_pointers_to_stack */
    	em[43] = 47; em[44] = 0; 
    	em[45] = 50; em[46] = 12; 
    em[47] = 0; em[48] = 8; em[49] = 0; /* 47: long unsigned int */
    em[50] = 0; em[51] = 4; em[52] = 0; /* 50: int */
    em[53] = 8884097; em[54] = 8; em[55] = 0; /* 53: pointer.func */
    em[56] = 8884097; em[57] = 8; em[58] = 0; /* 56: pointer.func */
    em[59] = 8884097; em[60] = 8; em[61] = 0; /* 59: pointer.func */
    em[62] = 8884097; em[63] = 8; em[64] = 0; /* 62: pointer.func */
    em[65] = 8884097; em[66] = 8; em[67] = 0; /* 65: pointer.func */
    em[68] = 8884097; em[69] = 8; em[70] = 0; /* 68: pointer.func */
    em[71] = 8884097; em[72] = 8; em[73] = 0; /* 71: pointer.func */
    em[74] = 8884097; em[75] = 8; em[76] = 0; /* 74: pointer.func */
    em[77] = 8884097; em[78] = 8; em[79] = 0; /* 77: pointer.func */
    em[80] = 8884097; em[81] = 8; em[82] = 0; /* 80: pointer.func */
    em[83] = 8884097; em[84] = 8; em[85] = 0; /* 83: pointer.func */
    em[86] = 8884097; em[87] = 8; em[88] = 0; /* 86: pointer.func */
    em[89] = 8884097; em[90] = 8; em[91] = 0; /* 89: pointer.func */
    em[92] = 8884097; em[93] = 8; em[94] = 0; /* 92: pointer.func */
    em[95] = 8884097; em[96] = 8; em[97] = 0; /* 95: pointer.func */
    em[98] = 8884097; em[99] = 8; em[100] = 0; /* 98: pointer.func */
    em[101] = 1; em[102] = 8; em[103] = 1; /* 101: pointer.struct.ec_group_st */
    	em[104] = 106; em[105] = 0; 
    em[106] = 0; em[107] = 232; em[108] = 12; /* 106: struct.ec_group_st */
    	em[109] = 133; em[110] = 0; 
    	em[111] = 281; em[112] = 8; 
    	em[113] = 35; em[114] = 16; 
    	em[115] = 35; em[116] = 40; 
    	em[117] = 457; em[118] = 80; 
    	em[119] = 30; em[120] = 96; 
    	em[121] = 35; em[122] = 104; 
    	em[123] = 35; em[124] = 152; 
    	em[125] = 35; em[126] = 176; 
    	em[127] = 6; em[128] = 208; 
    	em[129] = 6; em[130] = 216; 
    	em[131] = 0; em[132] = 224; 
    em[133] = 1; em[134] = 8; em[135] = 1; /* 133: pointer.struct.ec_method_st */
    	em[136] = 138; em[137] = 0; 
    em[138] = 0; em[139] = 304; em[140] = 37; /* 138: struct.ec_method_st */
    	em[141] = 215; em[142] = 8; 
    	em[143] = 218; em[144] = 16; 
    	em[145] = 218; em[146] = 24; 
    	em[147] = 221; em[148] = 32; 
    	em[149] = 224; em[150] = 40; 
    	em[151] = 227; em[152] = 48; 
    	em[153] = 230; em[154] = 56; 
    	em[155] = 233; em[156] = 64; 
    	em[157] = 236; em[158] = 72; 
    	em[159] = 83; em[160] = 80; 
    	em[161] = 83; em[162] = 88; 
    	em[163] = 239; em[164] = 96; 
    	em[165] = 242; em[166] = 104; 
    	em[167] = 245; em[168] = 112; 
    	em[169] = 248; em[170] = 120; 
    	em[171] = 251; em[172] = 128; 
    	em[173] = 254; em[174] = 136; 
    	em[175] = 98; em[176] = 144; 
    	em[177] = 89; em[178] = 152; 
    	em[179] = 257; em[180] = 160; 
    	em[181] = 80; em[182] = 168; 
    	em[183] = 77; em[184] = 176; 
    	em[185] = 260; em[186] = 184; 
    	em[187] = 74; em[188] = 192; 
    	em[189] = 92; em[190] = 200; 
    	em[191] = 263; em[192] = 208; 
    	em[193] = 260; em[194] = 216; 
    	em[195] = 71; em[196] = 224; 
    	em[197] = 266; em[198] = 232; 
    	em[199] = 269; em[200] = 240; 
    	em[201] = 230; em[202] = 248; 
    	em[203] = 272; em[204] = 256; 
    	em[205] = 275; em[206] = 264; 
    	em[207] = 272; em[208] = 272; 
    	em[209] = 275; em[210] = 280; 
    	em[211] = 275; em[212] = 288; 
    	em[213] = 278; em[214] = 296; 
    em[215] = 8884097; em[216] = 8; em[217] = 0; /* 215: pointer.func */
    em[218] = 8884097; em[219] = 8; em[220] = 0; /* 218: pointer.func */
    em[221] = 8884097; em[222] = 8; em[223] = 0; /* 221: pointer.func */
    em[224] = 8884097; em[225] = 8; em[226] = 0; /* 224: pointer.func */
    em[227] = 8884097; em[228] = 8; em[229] = 0; /* 227: pointer.func */
    em[230] = 8884097; em[231] = 8; em[232] = 0; /* 230: pointer.func */
    em[233] = 8884097; em[234] = 8; em[235] = 0; /* 233: pointer.func */
    em[236] = 8884097; em[237] = 8; em[238] = 0; /* 236: pointer.func */
    em[239] = 8884097; em[240] = 8; em[241] = 0; /* 239: pointer.func */
    em[242] = 8884097; em[243] = 8; em[244] = 0; /* 242: pointer.func */
    em[245] = 8884097; em[246] = 8; em[247] = 0; /* 245: pointer.func */
    em[248] = 8884097; em[249] = 8; em[250] = 0; /* 248: pointer.func */
    em[251] = 8884097; em[252] = 8; em[253] = 0; /* 251: pointer.func */
    em[254] = 8884097; em[255] = 8; em[256] = 0; /* 254: pointer.func */
    em[257] = 8884097; em[258] = 8; em[259] = 0; /* 257: pointer.func */
    em[260] = 8884097; em[261] = 8; em[262] = 0; /* 260: pointer.func */
    em[263] = 8884097; em[264] = 8; em[265] = 0; /* 263: pointer.func */
    em[266] = 8884097; em[267] = 8; em[268] = 0; /* 266: pointer.func */
    em[269] = 8884097; em[270] = 8; em[271] = 0; /* 269: pointer.func */
    em[272] = 8884097; em[273] = 8; em[274] = 0; /* 272: pointer.func */
    em[275] = 8884097; em[276] = 8; em[277] = 0; /* 275: pointer.func */
    em[278] = 8884097; em[279] = 8; em[280] = 0; /* 278: pointer.func */
    em[281] = 1; em[282] = 8; em[283] = 1; /* 281: pointer.struct.ec_point_st */
    	em[284] = 286; em[285] = 0; 
    em[286] = 0; em[287] = 88; em[288] = 4; /* 286: struct.ec_point_st */
    	em[289] = 297; em[290] = 0; 
    	em[291] = 445; em[292] = 8; 
    	em[293] = 445; em[294] = 32; 
    	em[295] = 445; em[296] = 56; 
    em[297] = 1; em[298] = 8; em[299] = 1; /* 297: pointer.struct.ec_method_st */
    	em[300] = 302; em[301] = 0; 
    em[302] = 0; em[303] = 304; em[304] = 37; /* 302: struct.ec_method_st */
    	em[305] = 379; em[306] = 8; 
    	em[307] = 86; em[308] = 16; 
    	em[309] = 86; em[310] = 24; 
    	em[311] = 382; em[312] = 32; 
    	em[313] = 385; em[314] = 40; 
    	em[315] = 388; em[316] = 48; 
    	em[317] = 391; em[318] = 56; 
    	em[319] = 394; em[320] = 64; 
    	em[321] = 397; em[322] = 72; 
    	em[323] = 400; em[324] = 80; 
    	em[325] = 400; em[326] = 88; 
    	em[327] = 403; em[328] = 96; 
    	em[329] = 406; em[330] = 104; 
    	em[331] = 409; em[332] = 112; 
    	em[333] = 412; em[334] = 120; 
    	em[335] = 415; em[336] = 128; 
    	em[337] = 418; em[338] = 136; 
    	em[339] = 421; em[340] = 144; 
    	em[341] = 424; em[342] = 152; 
    	em[343] = 95; em[344] = 160; 
    	em[345] = 427; em[346] = 168; 
    	em[347] = 430; em[348] = 176; 
    	em[349] = 433; em[350] = 184; 
    	em[351] = 68; em[352] = 192; 
    	em[353] = 65; em[354] = 200; 
    	em[355] = 436; em[356] = 208; 
    	em[357] = 433; em[358] = 216; 
    	em[359] = 439; em[360] = 224; 
    	em[361] = 62; em[362] = 232; 
    	em[363] = 59; em[364] = 240; 
    	em[365] = 391; em[366] = 248; 
    	em[367] = 56; em[368] = 256; 
    	em[369] = 442; em[370] = 264; 
    	em[371] = 56; em[372] = 272; 
    	em[373] = 442; em[374] = 280; 
    	em[375] = 442; em[376] = 288; 
    	em[377] = 53; em[378] = 296; 
    em[379] = 8884097; em[380] = 8; em[381] = 0; /* 379: pointer.func */
    em[382] = 8884097; em[383] = 8; em[384] = 0; /* 382: pointer.func */
    em[385] = 8884097; em[386] = 8; em[387] = 0; /* 385: pointer.func */
    em[388] = 8884097; em[389] = 8; em[390] = 0; /* 388: pointer.func */
    em[391] = 8884097; em[392] = 8; em[393] = 0; /* 391: pointer.func */
    em[394] = 8884097; em[395] = 8; em[396] = 0; /* 394: pointer.func */
    em[397] = 8884097; em[398] = 8; em[399] = 0; /* 397: pointer.func */
    em[400] = 8884097; em[401] = 8; em[402] = 0; /* 400: pointer.func */
    em[403] = 8884097; em[404] = 8; em[405] = 0; /* 403: pointer.func */
    em[406] = 8884097; em[407] = 8; em[408] = 0; /* 406: pointer.func */
    em[409] = 8884097; em[410] = 8; em[411] = 0; /* 409: pointer.func */
    em[412] = 8884097; em[413] = 8; em[414] = 0; /* 412: pointer.func */
    em[415] = 8884097; em[416] = 8; em[417] = 0; /* 415: pointer.func */
    em[418] = 8884097; em[419] = 8; em[420] = 0; /* 418: pointer.func */
    em[421] = 8884097; em[422] = 8; em[423] = 0; /* 421: pointer.func */
    em[424] = 8884097; em[425] = 8; em[426] = 0; /* 424: pointer.func */
    em[427] = 8884097; em[428] = 8; em[429] = 0; /* 427: pointer.func */
    em[430] = 8884097; em[431] = 8; em[432] = 0; /* 430: pointer.func */
    em[433] = 8884097; em[434] = 8; em[435] = 0; /* 433: pointer.func */
    em[436] = 8884097; em[437] = 8; em[438] = 0; /* 436: pointer.func */
    em[439] = 8884097; em[440] = 8; em[441] = 0; /* 439: pointer.func */
    em[442] = 8884097; em[443] = 8; em[444] = 0; /* 442: pointer.func */
    em[445] = 0; em[446] = 24; em[447] = 1; /* 445: struct.bignum_st */
    	em[448] = 450; em[449] = 0; 
    em[450] = 8884099; em[451] = 8; em[452] = 2; /* 450: pointer_to_array_of_pointers_to_stack */
    	em[453] = 47; em[454] = 0; 
    	em[455] = 50; em[456] = 12; 
    em[457] = 1; em[458] = 8; em[459] = 1; /* 457: pointer.unsigned char */
    	em[460] = 462; em[461] = 0; 
    em[462] = 0; em[463] = 1; em[464] = 0; /* 462: unsigned char */
    args_addr->arg_entity_index[0] = 101;
    args_addr->ret_entity_index = -1;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EC_GROUP * new_arg_a = *((EC_GROUP * *)new_args->args[0]);

    void (*orig_EC_GROUP_free)(EC_GROUP *);
    orig_EC_GROUP_free = dlsym(RTLD_NEXT, "EC_GROUP_free");
    (*orig_EC_GROUP_free)(new_arg_a);

    syscall(889);

    free(args_addr);

}

