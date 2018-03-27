    .set noreorder

#include "pspstub.s"

    STUB_START "sceAmctrl_driver",0x00090000,0x00030005
    STUB_FUNC 0x525B8218,sceDrmBBMacInit
    STUB_FUNC 0x58163FBE,sceDrmBBMacUpdate
    STUB_FUNC 0xEF95A213,sceDrmBBMacFinal
    STUB_END
