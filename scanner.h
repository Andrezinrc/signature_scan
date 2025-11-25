#ifndef SCANNER_H
#define SCANNER_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define MAX_SIGNATURES 100
#define MAX_PATTERN_LEN 256
#define MAX_RULE_NAME 50
#define EICAR_SIZE 68

#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define RESET   "\033[0m"

extern int total_files_scanned;
extern int total_threats_found;
extern clock_t scan_start, scan_end;
extern uint8_t eicar_signature[EICAR_SIZE];

typedef struct {
    char name[MAX_RULE_NAME];
    uint8_t pattern[MAX_PATTERN_LEN];
    size_t pattern_len;
} signature_t;

extern signature_t signatures[MAX_SIGNATURES];
extern int signature_count;

#ifdef __cplusplus
extern "C" {
#endif

// Carrega regras do arquivo rules.txt
int load_signatures(const char* rules_file);

// Scaneia um arquivo com as regras carregadas
int scan_file_rules(const char* filename);

// Cria arquivo de teste EICAR
void create_test_file(void);

// Faz um teste completo de regras
void run_rules_test(const char* filename);

// Exibe sumário de varredura
void show_scan_summary(void);

// Filtros auxiliares
int should_ignore_dir(const char* path);
int should_scan_file(const char* path);

// Varredura recursiva de diretórios
void scan_directory(const char* path);

#ifdef __cplusplus
}
#endif

#endif
