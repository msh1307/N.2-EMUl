#include "main.h"

int got_sigill = 0;
void _interrupt(uc_engine *uc, uint32_t intno, void *user_data){
    if (intno == 6) {
        uc_emu_stop(uc);
        got_sigill = 1;
    }
}

int main(int argc, char ** argv){
    if (argc < 2){
        failure("Usage ./app.out filename [argv, argv1, ...] -- [env1, env2, ...]");
        return -1;
    }
    void * bin = NULL; 
    int fd = open(argv[1], O_RDONLY);
    char * loader_path = get_interpreter(fd, &bin);
    if (!loader_path){
        failure("Failed to extract the interpreter path");
        return -1;
    }
    success("Loader path: %s", loader_path);
    int interpreter_fd = open(loader_path, O_RDONLY);
    free(loader_path);
    if (interpreter_fd < 0){
        failure("Loader not found");
        return -1;
    }
    uc_engine *uc;
    uc_hook uh_trap;
    uc_err err_uc = uc_open (UC_ARCH_X86, UC_MODE_64, &uc);
    if (err_uc != UC_ERR_OK){
        failure("Cannot initialize unicorn");
        return -1;
    }
    int err = emul_load(uc, interpreter_fd, LD_BASE);
    if (err < 0){
        failure("Failed to load interpreter");
        return -1;
    }
    err = emul_load(uc, fd, BIN_BASE);
    if (err < 0){
        failure("Failed to load binary");
        return -1;
    }
    close(interpreter_fd);
    close(fd);

    struct user_ctx * ctx; 
    if (emul_setup_user_ctx(&ctx, argc, argv) < 0){
        failure("Failed to setup user ctx");
        return -1;
    }
    if (emul_setup_stack(uc, ctx) < 0){
        failure("Failed to setup program stack");
        return -1;
    }
    free(ctx -> envp);
    free(ctx -> argv);
    free(ctx);

    // size = UC_BUG_WRITE_SIZE;
    // buf = malloc (size);
    // uc_mem_map(uc,LD_BASE , size, UC_PROT_ALL);
    // if (!buf) {
    //     fprintf (stderr, "Cannot allocate\n");
    //     return 1;
    // }
    // memset (buf, 0, size);
    // if (!uc_mem_map(uc, UC_BUG_WRITE_ADDR, size, UC_PROT_ALL)) {
    //     uc_mem_write(uc, UC_BUG_WRITE_ADDR,
    //             (const uint8_t*)"\xff\xff\xff\xff\xff\xff\xff\xff", 8);
    // }
    // uc_hook_add(uc, &uh_trap, UC_HOOK_INTR, _interrupt, NULL, 1, 0);
    // uc_emu_start(uc, UC_BUG_WRITE_ADDR, UC_BUG_WRITE_ADDR+8, 0, 1);
    // uc_close(uc);
    // printf ("Correct: %s\n", got_sigill? "YES": "NO");
    // return got_sigill? 0: 1;

}
