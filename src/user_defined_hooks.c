#include "../include/user_defined_hooks.h"

static void ld_bypass_handler(uc_engine *uc, uint64_t address, uint32_t size, void *user_data){
    uint64_t rip;
    UC_ERR_CHECK(uc_reg_read(uc, X86_REG_RIP, &rip));
    success("Hooked at 0x%lx", rip);
    rip = MMAP_ADDRESS + 0x23894ULL;
    success("RIP = 0x%lx", rip);
    UC_ERR_CHECK(uc_reg_write(uc, X86_REG_RIP, &rip));
}

void register_user_defined_hooks(uc_engine * uc){ 
    uc_hook ld_bypass;
    uint64_t address = MMAP_ADDRESS + 0x2388EULL;
    UC_ERR_CHECK(uc_hook_add(uc, &ld_bypass, UC_HOOK_CODE, (void *)ld_bypass_handler, NULL, address, address));
} // user defined hooks here