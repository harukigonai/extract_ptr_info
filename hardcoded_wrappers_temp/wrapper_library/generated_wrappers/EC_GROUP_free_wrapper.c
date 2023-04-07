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
    em[3] = 1; em[4] = 8; em[5] = 1; /* 3: pointer.struct.ec_extra_data_st */
    	em[6] = 8; em[7] = 0; 
    em[8] = 0; em[9] = 40; em[10] = 5; /* 8: struct.ec_extra_data_st */
    	em[11] = 3; em[12] = 0; 
    	em[13] = 21; em[14] = 8; 
    	em[15] = 24; em[16] = 16; 
    	em[17] = 27; em[18] = 24; 
    	em[19] = 27; em[20] = 32; 
    em[21] = 0; em[22] = 8; em[23] = 0; /* 21: pointer.void */
    em[24] = 8884097; em[25] = 8; em[26] = 0; /* 24: pointer.func */
    em[27] = 8884097; em[28] = 8; em[29] = 0; /* 27: pointer.func */
    em[30] = 0; em[31] = 4; em[32] = 0; /* 30: int */
    em[33] = 8884097; em[34] = 8; em[35] = 0; /* 33: pointer.func */
    em[36] = 8884097; em[37] = 8; em[38] = 0; /* 36: pointer.func */
    em[39] = 8884097; em[40] = 8; em[41] = 0; /* 39: pointer.func */
    em[42] = 8884097; em[43] = 8; em[44] = 0; /* 42: pointer.func */
    em[45] = 8884097; em[46] = 8; em[47] = 0; /* 45: pointer.func */
    em[48] = 8884097; em[49] = 8; em[50] = 0; /* 48: pointer.func */
    em[51] = 8884097; em[52] = 8; em[53] = 0; /* 51: pointer.func */
    em[54] = 8884097; em[55] = 8; em[56] = 0; /* 54: pointer.func */
    em[57] = 8884097; em[58] = 8; em[59] = 0; /* 57: pointer.func */
    em[60] = 8884097; em[61] = 8; em[62] = 0; /* 60: pointer.func */
    em[63] = 8884097; em[64] = 8; em[65] = 0; /* 63: pointer.func */
    em[66] = 8884097; em[67] = 8; em[68] = 0; /* 66: pointer.func */
    em[69] = 1; em[70] = 8; em[71] = 1; /* 69: pointer.struct.ec_point_st */
    	em[72] = 74; em[73] = 0; 
    em[74] = 0; em[75] = 88; em[76] = 4; /* 74: struct.ec_point_st */
    	em[77] = 85; em[78] = 0; 
    	em[79] = 233; em[80] = 8; 
    	em[81] = 233; em[82] = 32; 
    	em[83] = 233; em[84] = 56; 
    em[85] = 1; em[86] = 8; em[87] = 1; /* 85: pointer.struct.ec_method_st */
    	em[88] = 90; em[89] = 0; 
    em[90] = 0; em[91] = 304; em[92] = 37; /* 90: struct.ec_method_st */
    	em[93] = 167; em[94] = 8; 
    	em[95] = 170; em[96] = 16; 
    	em[97] = 170; em[98] = 24; 
    	em[99] = 173; em[100] = 32; 
    	em[101] = 176; em[102] = 40; 
    	em[103] = 179; em[104] = 48; 
    	em[105] = 182; em[106] = 56; 
    	em[107] = 185; em[108] = 64; 
    	em[109] = 188; em[110] = 72; 
    	em[111] = 191; em[112] = 80; 
    	em[113] = 191; em[114] = 88; 
    	em[115] = 194; em[116] = 96; 
    	em[117] = 197; em[118] = 104; 
    	em[119] = 200; em[120] = 112; 
    	em[121] = 203; em[122] = 120; 
    	em[123] = 206; em[124] = 128; 
    	em[125] = 209; em[126] = 136; 
    	em[127] = 212; em[128] = 144; 
    	em[129] = 215; em[130] = 152; 
    	em[131] = 218; em[132] = 160; 
    	em[133] = 221; em[134] = 168; 
    	em[135] = 224; em[136] = 176; 
    	em[137] = 227; em[138] = 184; 
    	em[139] = 54; em[140] = 192; 
    	em[141] = 51; em[142] = 200; 
    	em[143] = 48; em[144] = 208; 
    	em[145] = 227; em[146] = 216; 
    	em[147] = 45; em[148] = 224; 
    	em[149] = 42; em[150] = 232; 
    	em[151] = 39; em[152] = 240; 
    	em[153] = 182; em[154] = 248; 
    	em[155] = 36; em[156] = 256; 
    	em[157] = 230; em[158] = 264; 
    	em[159] = 36; em[160] = 272; 
    	em[161] = 230; em[162] = 280; 
    	em[163] = 230; em[164] = 288; 
    	em[165] = 33; em[166] = 296; 
    em[167] = 8884097; em[168] = 8; em[169] = 0; /* 167: pointer.func */
    em[170] = 8884097; em[171] = 8; em[172] = 0; /* 170: pointer.func */
    em[173] = 8884097; em[174] = 8; em[175] = 0; /* 173: pointer.func */
    em[176] = 8884097; em[177] = 8; em[178] = 0; /* 176: pointer.func */
    em[179] = 8884097; em[180] = 8; em[181] = 0; /* 179: pointer.func */
    em[182] = 8884097; em[183] = 8; em[184] = 0; /* 182: pointer.func */
    em[185] = 8884097; em[186] = 8; em[187] = 0; /* 185: pointer.func */
    em[188] = 8884097; em[189] = 8; em[190] = 0; /* 188: pointer.func */
    em[191] = 8884097; em[192] = 8; em[193] = 0; /* 191: pointer.func */
    em[194] = 8884097; em[195] = 8; em[196] = 0; /* 194: pointer.func */
    em[197] = 8884097; em[198] = 8; em[199] = 0; /* 197: pointer.func */
    em[200] = 8884097; em[201] = 8; em[202] = 0; /* 200: pointer.func */
    em[203] = 8884097; em[204] = 8; em[205] = 0; /* 203: pointer.func */
    em[206] = 8884097; em[207] = 8; em[208] = 0; /* 206: pointer.func */
    em[209] = 8884097; em[210] = 8; em[211] = 0; /* 209: pointer.func */
    em[212] = 8884097; em[213] = 8; em[214] = 0; /* 212: pointer.func */
    em[215] = 8884097; em[216] = 8; em[217] = 0; /* 215: pointer.func */
    em[218] = 8884097; em[219] = 8; em[220] = 0; /* 218: pointer.func */
    em[221] = 8884097; em[222] = 8; em[223] = 0; /* 221: pointer.func */
    em[224] = 8884097; em[225] = 8; em[226] = 0; /* 224: pointer.func */
    em[227] = 8884097; em[228] = 8; em[229] = 0; /* 227: pointer.func */
    em[230] = 8884097; em[231] = 8; em[232] = 0; /* 230: pointer.func */
    em[233] = 0; em[234] = 24; em[235] = 1; /* 233: struct.bignum_st */
    	em[236] = 238; em[237] = 0; 
    em[238] = 8884099; em[239] = 8; em[240] = 2; /* 238: pointer_to_array_of_pointers_to_stack */
    	em[241] = 245; em[242] = 0; 
    	em[243] = 30; em[244] = 12; 
    em[245] = 0; em[246] = 8; em[247] = 0; /* 245: long unsigned int */
    em[248] = 1; em[249] = 8; em[250] = 1; /* 248: pointer.unsigned char */
    	em[251] = 253; em[252] = 0; 
    em[253] = 0; em[254] = 1; em[255] = 0; /* 253: unsigned char */
    em[256] = 8884097; em[257] = 8; em[258] = 0; /* 256: pointer.func */
    em[259] = 8884097; em[260] = 8; em[261] = 0; /* 259: pointer.func */
    em[262] = 8884097; em[263] = 8; em[264] = 0; /* 262: pointer.func */
    em[265] = 0; em[266] = 24; em[267] = 1; /* 265: struct.bignum_st */
    	em[268] = 270; em[269] = 0; 
    em[270] = 8884099; em[271] = 8; em[272] = 2; /* 270: pointer_to_array_of_pointers_to_stack */
    	em[273] = 245; em[274] = 0; 
    	em[275] = 30; em[276] = 12; 
    em[277] = 8884097; em[278] = 8; em[279] = 0; /* 277: pointer.func */
    em[280] = 8884097; em[281] = 8; em[282] = 0; /* 280: pointer.func */
    em[283] = 8884097; em[284] = 8; em[285] = 0; /* 283: pointer.func */
    em[286] = 8884097; em[287] = 8; em[288] = 0; /* 286: pointer.func */
    em[289] = 8884097; em[290] = 8; em[291] = 0; /* 289: pointer.func */
    em[292] = 0; em[293] = 232; em[294] = 12; /* 292: struct.ec_group_st */
    	em[295] = 319; em[296] = 0; 
    	em[297] = 69; em[298] = 8; 
    	em[299] = 265; em[300] = 16; 
    	em[301] = 265; em[302] = 40; 
    	em[303] = 248; em[304] = 80; 
    	em[305] = 455; em[306] = 96; 
    	em[307] = 265; em[308] = 104; 
    	em[309] = 265; em[310] = 152; 
    	em[311] = 265; em[312] = 176; 
    	em[313] = 21; em[314] = 208; 
    	em[315] = 21; em[316] = 216; 
    	em[317] = 0; em[318] = 224; 
    em[319] = 1; em[320] = 8; em[321] = 1; /* 319: pointer.struct.ec_method_st */
    	em[322] = 324; em[323] = 0; 
    em[324] = 0; em[325] = 304; em[326] = 37; /* 324: struct.ec_method_st */
    	em[327] = 66; em[328] = 8; 
    	em[329] = 401; em[330] = 16; 
    	em[331] = 401; em[332] = 24; 
    	em[333] = 404; em[334] = 32; 
    	em[335] = 63; em[336] = 40; 
    	em[337] = 283; em[338] = 48; 
    	em[339] = 407; em[340] = 56; 
    	em[341] = 259; em[342] = 64; 
    	em[343] = 410; em[344] = 72; 
    	em[345] = 413; em[346] = 80; 
    	em[347] = 413; em[348] = 88; 
    	em[349] = 289; em[350] = 96; 
    	em[351] = 416; em[352] = 104; 
    	em[353] = 419; em[354] = 112; 
    	em[355] = 277; em[356] = 120; 
    	em[357] = 422; em[358] = 128; 
    	em[359] = 256; em[360] = 136; 
    	em[361] = 286; em[362] = 144; 
    	em[363] = 60; em[364] = 152; 
    	em[365] = 280; em[366] = 160; 
    	em[367] = 262; em[368] = 168; 
    	em[369] = 425; em[370] = 176; 
    	em[371] = 428; em[372] = 184; 
    	em[373] = 431; em[374] = 192; 
    	em[375] = 57; em[376] = 200; 
    	em[377] = 434; em[378] = 208; 
    	em[379] = 428; em[380] = 216; 
    	em[381] = 437; em[382] = 224; 
    	em[383] = 440; em[384] = 232; 
    	em[385] = 443; em[386] = 240; 
    	em[387] = 407; em[388] = 248; 
    	em[389] = 446; em[390] = 256; 
    	em[391] = 449; em[392] = 264; 
    	em[393] = 446; em[394] = 272; 
    	em[395] = 449; em[396] = 280; 
    	em[397] = 449; em[398] = 288; 
    	em[399] = 452; em[400] = 296; 
    em[401] = 8884097; em[402] = 8; em[403] = 0; /* 401: pointer.func */
    em[404] = 8884097; em[405] = 8; em[406] = 0; /* 404: pointer.func */
    em[407] = 8884097; em[408] = 8; em[409] = 0; /* 407: pointer.func */
    em[410] = 8884097; em[411] = 8; em[412] = 0; /* 410: pointer.func */
    em[413] = 8884097; em[414] = 8; em[415] = 0; /* 413: pointer.func */
    em[416] = 8884097; em[417] = 8; em[418] = 0; /* 416: pointer.func */
    em[419] = 8884097; em[420] = 8; em[421] = 0; /* 419: pointer.func */
    em[422] = 8884097; em[423] = 8; em[424] = 0; /* 422: pointer.func */
    em[425] = 8884097; em[426] = 8; em[427] = 0; /* 425: pointer.func */
    em[428] = 8884097; em[429] = 8; em[430] = 0; /* 428: pointer.func */
    em[431] = 8884097; em[432] = 8; em[433] = 0; /* 431: pointer.func */
    em[434] = 8884097; em[435] = 8; em[436] = 0; /* 434: pointer.func */
    em[437] = 8884097; em[438] = 8; em[439] = 0; /* 437: pointer.func */
    em[440] = 8884097; em[441] = 8; em[442] = 0; /* 440: pointer.func */
    em[443] = 8884097; em[444] = 8; em[445] = 0; /* 443: pointer.func */
    em[446] = 8884097; em[447] = 8; em[448] = 0; /* 446: pointer.func */
    em[449] = 8884097; em[450] = 8; em[451] = 0; /* 449: pointer.func */
    em[452] = 8884097; em[453] = 8; em[454] = 0; /* 452: pointer.func */
    em[455] = 1; em[456] = 8; em[457] = 1; /* 455: pointer.struct.ec_extra_data_st */
    	em[458] = 8; em[459] = 0; 
    em[460] = 1; em[461] = 8; em[462] = 1; /* 460: pointer.struct.ec_group_st */
    	em[463] = 292; em[464] = 0; 
    args_addr->arg_entity_index[0] = 460;
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

