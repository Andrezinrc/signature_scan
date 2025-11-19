#include "scanner.h"
#include <dirent.h>
#include <sys/stat.h>

uint8_t eicar_signature[EICAR_SIZE] = {
    0x58,0x35,0x4F,0x21,0x50,0x25,0x40,0x41,
    0x50,0x5B,0x34,0x5C,0x50,0x5A,0x58,0x35,
    0x34,0x28,0x50,0x5E,0x29,0x37,0x43,0x43,
    0x29,0x37,0x7D,0x24,0x45,0x49,0x43,0x41,
    0x52,0x2D,0x53,0x54,0x41,0x4E,0x44,0x41,
    0x52,0x44,0x2D,0x41,0x4E,0x54,0x49,0x56,
    0x49,0x52,0x55,0x53,0x2D,0x54,0x45,0x53,
    0x54,0x2D,0x46,0x49,0x4C,0x45,0x21,0x24,
    0x48,0x2B,0x48,0x2A
};

signature_t signatures[MAX_SIGNATURES];
int signature_count = 0;

int load_signatures(const char* rules_file) {
    FILE* file = fopen(rules_file, "r");
    if (!file) {
        printf("Erro ao abrir arquivo de regras: %s\n", rules_file);
        return -1;
    }

    char line[512];
    signature_count = 0;

    while (fgets(line, sizeof(line), file) && signature_count < MAX_SIGNATURES) {
        line[strcspn(line, "\n")]=0;
        
        if (strlen(line)==0 || line[0]=='#') {
            continue;
        }

        char* equals = strchr(line, '=');
        if (!equals) {
            continue;
        }

        *equals = '\0';
        char* rule_name = line;
        char* hex_pattern = equals + 1;

        signatures[signature_count].pattern_len=0;
        strncpy(signatures[signature_count].name, rule_name, MAX_RULE_NAME-1);

        char* token = strtok(hex_pattern, " ");
        while (token!=NULL && signatures[signature_count].pattern_len < MAX_PATTERN_LEN) {
            signatures[signature_count].pattern[signatures[signature_count].pattern_len++] = (uint8_t)strtol(token, NULL, 16);
            token=strtok(NULL, " ");
        }

        printf("Regra carregada: %s (%zu bytes)\n", 
               signatures[signature_count].name, 
               signatures[signature_count].pattern_len);
        
        signature_count++;
    }

    fclose(file);
    printf("%d regras carregadas com sucesso!\n", signature_count);
    return signature_count;
}

int scan_file_rules(const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("Nao foi possível abrir o arquivo '%s'\n", filename);
        return -1;
    }
    
    uint8_t buffer[4096];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer), file);
    fclose(file);

    int threats_found=0;
    if (bytes_read>=EICAR_SIZE) {
        for (size_t i=0;i<=bytes_read - EICAR_SIZE;i++) {
            if (memcmp(&buffer[i], eicar_signature, EICAR_SIZE)==0) {
                printf(RED "Ameaça detectada! Regra: EICAR | Arquivo: %s\n" RESET, filename);
                threats_found++;
                break;
            }
        }
    }
    
    for (int sig_idx=0;sig_idx < signature_count;sig_idx++) {
        if (bytes_read < signatures[sig_idx].pattern_len) {
            continue;
        }
        
        for (size_t i=0;i<=bytes_read - signatures[sig_idx].pattern_len;i++) {
            if (memcmp(&buffer[i], signatures[sig_idx].pattern, signatures[sig_idx].pattern_len)==0) {
                printf(RED "Ameaça detectada! Regra: %s | Arquivo: %s\n" RESET, signatures[sig_idx].name, filename);
                threats_found++;
                break;
            }
        }
    }
   
    return threats_found;
}

void create_test_file() {
    FILE* file = fopen("eicar_test.txt", "wb");
    if (!file) {
        printf("Erro ao criar arquivo de teste\n");
        return;
    }
    
    fwrite(eicar_signature, 1, EICAR_SIZE, file);
    fclose(file);
    
    printf("Arquivo de teste criado: eicar_test.txt\n");
}

void run_rules_test(const char* filename) {
    printf("Teste com sistema de regras\n");
    
    if (load_signatures("rules.txt")<0) {
        printf("Nao foi possivel carregar regras\n");
        return;
    }
    
    if (filename) {
        printf("Testando arquivo: %s\n", filename);
        int result = scan_file_rules(filename);
        if (result>0) {
            printf(RED "Ameacas detectadas: %d\n" RESET, result);
        } else {
            printf(GREEN "Nenhuma ameaca detectada\n" RESET);
        }
    } else {
        printf("Testando todos os arquivos de teste...\n\n");
        
        char* test_files[] = {
            "eicar_test.txt",
            "malware_test.bin",
            "shellcode_test.bin",
            "clean_file.txt",
            NULL
        };
        
        for (int i=0;test_files[i]!=NULL;i++) {
            printf("Testando: %s\n", test_files[i]);
            int result = scan_file_rules(test_files[i]);
            if (result>0) {
                printf(RED "Ameacas detectadas: %d\n\n" RESET, result);
            } else {
                printf(GREEN "Arquivo limpo\n\n" RESET);
            }
        }
    }
}

void scan_directory(const char* path) {
    DIR* d = opendir(path);
    if(!d) {
        return;
        printf("Não foi possivel abrir diretorio: %s\n", path);
    }
    
    struct dirent* entry;
    while((entry = readdir(d)) != NULL){
        if(strcmp(entry->d_name, ".")==0 || strcmp(entry->d_name, "..")==0) {
            continue;
        }
        
        char fullpath[1024];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);
        
        struct stat st;
        if(stat(fullpath, &st) == -1) {
            continue;
        }
        if(S_ISDIR(st.st_mode)){
            printf(GREEN "Entrando em: %s\n" RESET, fullpath);
            scan_directory(fullpath);
        } else {
            printf("Testando arquivo: %s\n", fullpath);
            int result = scan_file_rules(fullpath);
            if(result>0){
                printf(RED "Ameacas detactadas: %d\n\n" RESET, result);
            } else {
                printf(GREEN "Arquivo limpo.\n" RESET);
            }
        }
    }
    closedir(d);
}

