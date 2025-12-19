#include "scanner.h"

int total_files_scanned = 0;
int total_threats_found = 0;
clock_t scan_start, scan_end;

void show_scan_summary() {
    scan_end = clock();
    double scan_time = (double)(scan_end - scan_start) / CLOCKS_PER_SEC;
    
    printf(GREEN "\n=== RESUMO DA VARREDURA ===\n" RESET);
    printf("Arquivos escaneados: %d\n", total_files_scanned);
    printf("Ameaças detectadas: %d\n", total_threats_found);
    printf("Tempo de varredura: %.2f segundos\n", scan_time);
    printf("Taxa de detecção: %.1f%%\n", total_files_scanned>0 ? 
           (float)total_threats_found / total_files_scanned * 100 : 0);
}

int main(int argc, char *argv[]) {
    if (argc<2) {
        printf("\033[2J\033[H");
        printf("\033[36mScanner de Regras (educacional)\033[0m\n");
        printf("Uso: %s <comando> [argumentos]\n", argv[0]);
        printf("Comandos:\n");
        printf("  rules                    # Teste todos arquivos de teste\n");
        printf("  rules <arquivo>          # Teste arquivo especifico\n");
        printf("  --scan-dir <diretorio>   # Varredura recursiva em diretorio\n");
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
 
        if (load_signatures("rules.txt")<0) {
            printf("Nao foi possivel carregar regras\n");
            return 1;
        }
        
        scan_start = clock();
        total_files_scanned=0;
        total_threats_found=0;
        
        printf(GREEN "[+] INICIANDO VARREDURA EM: %s\n" RESET, argv[2]);
        scan_directory(argv[2]);
        show_scan_summary();
        
        return 0;
    }
    
    printf("Erro: comando desconhecido '%s'\n", argv[1]);
    return 1;
}


