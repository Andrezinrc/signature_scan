#ifndef SCANNER_H
#define SCANNER_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define MAX_SIGNATURES 100
#define MAX_PATTERN_LEN 256
#define MAX_RULE_NAME 50
#define EICAR_SIZE 68

#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define RESET   "\033[0m"

extern uint8_t eicar_signature[EICAR_SIZE];

typedef struct {
    char name[MAX_RULE_NAME];
    uint8_t pattern[MAX_PATTERN_LEN];
    size_t pattern_len;
} signature_t;

extern signature_t signatures[MAX_SIGNATURES];
extern int signature_count;

int load_signatures(const char* rules_file);
int scan_file_rules(const char* filename);
void create_test_file();
void run_rules_test(const char* filename);
void scan_directory(const char* path);

#endif


