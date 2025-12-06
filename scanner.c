#include "scanner.h"
#include <dirent.h>
#include <sys/stat.h>
#include <ctype.h>

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
    total_files_scanned++;

    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("Nao foi possível abrir o arquivo '%s'\n", filename);
        return -1;
    }

    const size_t CHUNK = 4096;

    uint8_t buffer[CHUNK + MAX_PATTERN_LEN];
    size_t overlap = MAX_PATTERN_LEN - 1;
    size_t preserved=0;
    size_t bytes_read=0;
    size_t buffer_size=0;
    
    int rule_detected[MAX_SIGNATURES] = {0};
    int eicar_detected = 0;
    int threats_found = 0;

    while ((bytes_read = fread(buffer + preserved, 1, CHUNK, file)) > 0) {

        buffer_size = preserved + bytes_read;

        if (!eicar_detected && buffer_size >= EICAR_SIZE) {
            for (size_t i=0;i<=buffer_size - EICAR_SIZE;i++) {
                if (memcmp(&buffer[i], eicar_signature, EICAR_SIZE) == 0) {

                    printf(RED "Ameaca detectada! Regra: EICAR | Arquivo: %s\n" RESET,
                           filename);

                    eicar_detected=1;
                    threats_found++;
                    break;
                }
            }
        }

        for (int sig_idx = 0; sig_idx < signature_count; sig_idx++) {
            if (rule_detected[sig_idx])
                continue;
                
            size_t pat_len = signatures[sig_idx].pattern_len;

            if (buffer_size < pat_len)
                continue;

            for (size_t i=0;i<=buffer_size - pat_len;i++) {

                if (memcmp(&buffer[i], signatures[sig_idx].pattern, pat_len)==0) {

                    rule_detected[sig_idx]=1;
                    threats_found++;
                    break;
                }
            }
        }
        
        if (buffer_size >= overlap) {
            preserved = overlap;
            memcpy(buffer, buffer + (buffer_size - overlap), overlap);
        } else {
            preserved = buffer_size;
        }
    }

    fclose(file);
    total_threats_found += threats_found;

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
        
       // teste
        char* test_files[] = {
            "eicar_test.txt",
            "malware_test.bin",
            "shellcode_test.bin",
            "clean_file.txt",
            NULL
        };
        
        for (int i=0;test_files[i]!=NULL;i++) {
            //printf("Testando: %s\n", test_files[i]);
            int result = scan_file_rules(test_files[i]);
            if (result>0) {
                printf(RED "Ameacas detectadas: %d\n\n" RESET, result);
            } else {
                printf(GREEN "Arquivo limpo\n\n" RESET);
            }
        }
    }
}

int should_ignore_dir(const char* path) {
    const char* ignore_dirs[] = {
        ".git", ".github", ".vscode", ".idea", ".settings",
        ".gradle", ".mvn",

        "node_modules", "vendor", "__pycache__",
        "env", "venv", ".venv",
        "target",

        "dist", "build", "out", "bin", "obj",

        "logs", "tmp", "cache", ".cache",
        NULL
    };

    for (int i=0; ignore_dirs[i] != NULL; i++) {
        if (strstr(path, ignore_dirs[i]) != NULL) {
            return 1;
        }
    }

    return 0;
}

int should_scan_file(const char* path) {

    const char* ext = strrchr(path, '.');
    if (!ext)
        return 0;
    ext++; // Pula o ponto

    char lower_ext[16];
    int j=0;
    while (*ext && j<15) {
        lower_ext[j++] = tolower(*ext++);
    }
    lower_ext[j]='\0';

    const char* allowed[] = {
        "exe", "dll", "scr", "msi", "com", "pif",
        "elf", "bin", "so",
        "ps1", "bat", "cmd", "vbs", "js",
        "doc", "docm", "xls", "xlsm", "ppt", "pptm",
        "apk", "jar",
        "pdf", "swf",
        "zip", "rar", "7z",
        "vbe",
        "jse",
        "wsf",
        NULL
    };

    for (int i=0; allowed[i] != NULL; i++) {
        if (strcmp(lower_ext, allowed[i])==0) {
            return 1;
        }
    }

    return 0;
}

void scan_directory(const char* path) {
    DIR* d = opendir(path);
    if(!d) {
        printf("Não foi possivel abrir diretorio: %s\n", path);
        return;
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
        if (S_ISDIR(st.st_mode)) {

            if (should_ignore_dir(fullpath)) {
                continue;
            }

            scan_directory(fullpath);

        } else {

            if (!should_scan_file(fullpath)) {
                continue;
            }

            int result = scan_file_rules(fullpath);

            if (result>0) {
                printf(RED "[!] Ameacas detectadas: %d | Arquivo: %s\n\n" 
                       RESET, result, fullpath);
            }
        }
    }
    closedir(d);
}


