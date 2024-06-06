#include "../include/main.h"

int main(int argc, char ** argv){
    struct emul_ctx * ctx; 
    void * bin = NULL; 
    if (argc < 2){
        failure("Usage ./app.out filename [argv, argv1, ...] -- [env1, env2, ...]");
        return -1;
    }

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
    uint64_t bin_base = BIN_BASE;
    uint64_t ld_base = LD_BASE;
    if (emul_setup_emul_ctx(&ctx, argc, argv) < 0){
        failure("Failed to setup emul ctx");
        return -1;
    }
    uc_engine *uc;
    uc_err err_uc = UC_ERR_CHECK(uc_open (UC_ARCH_X86, UC_MODE_64, &uc));
    if (err_uc != UC_ERR_OK){
        failure("Cannot initialize unicorn");
        return -1;
    }
    
    int err = interp_load(uc, interpreter_fd, ld_base, ctx);
    if (err < 0){
        failure("Failed to load interpreter");
        return -1;
    }

    err = bin_load(uc, fd, bin_base, ctx);
    if (err < 0){
        failure("Failed to load binary");
        return -1;
    }
    close(interpreter_fd);
    close(fd);

    
    if (emul_setup_stack(uc, ctx) < 0){
        failure("Failed to setup program stack");
        return -1;
    }

    if (emul_run(uc, ctx) < 0){
        failure("Failed to run the binary");
        return -1;
    }

    free(ctx -> envp); // ctx -> envp can be NULL ptr. but it doesn't matter.
    free(ctx -> argv);
    free(ctx -> fd);
    free(ctx);

}
