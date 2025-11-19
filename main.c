#include "scanner.h"

int main(int argc, char *argv[]) {
    if (argc<2) {
        printf("Uso: %s rules [arquivo]\n", argv[0]);
        printf("Exemplos:\n");
        printf("  %s rules                    # Teste todos arquivos\n", argv[0]);
        printf("  %s rules malware_test.bin   # Teste arquivo especifico\n", argv[0]);
        return 1;
    }
    
    if (strcmp(argv[1], "rules")==0) {
        create_test_file();
    
        if (argc==3) {
            run_rules_test(argv[2]);
        } else {
            run_rules_test(NULL);
        }
        return 0;
    }
    if(strcmp(argv[1], "--scan-dir")==0) {
        if(argc<3){
            printf("Erro: faltou o diretorio.\n");
            printf("Uso: %s --scan-dir <path>\n", argv[0]);
            return 1;
        }
        run_rules_test(NULL);
        scan_directory(argv[2]);
        return 0;
    }
    
    printf("Erro: comando desconhecido '%s'\n", argv[1]);
    return 1;
}


