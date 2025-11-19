# signature_scan

O objetivo é apenas aprendizado sobre antivírus, assinaturas e análise de bytes em C.

Compilar

```bash
gcc scanner.c -o scanner
```

## Como Usar

Teste Automático

```bash
./scanner rules
```

Testa todos os padrões:

  ·EICAR (assinatura hardcoded)
  ·SIMPLE_MALWARE (DE AD BE EF)
  ·SUSPICIOUS_PATTERN (90 90 90 E8)
  ·Arquivos limpos

## Escaneamento Específico

```bash
./scanner rules arquivo_suspeito.exe
```

## Escaneamento Recursivo

```bash
./scanner --scan-dir /caminho/do/diretorio
```

## Sistema de Regras

Edite rules.txt para adicionar suas próprias assinaturas:

```bash
# Formato: NOME=HEX_HEX_HEX
MINHA_REGRA=AA BB CC DD
OUTRA_REGRA=90 90 90 E8 ?? ?? FF
```

Arquivos de Teste Incluídos

  · eicar_test.txt - Assinatura EICAR padrão
  · malware_test.bin - Padrão DE AD BE EF
  · shellcode_test.bin - NOP sled + CALL
  · clean_file.txt - Arquivo limpo para teste

## Aviso Legal

Projeto estritamente educacional. Desenvolvido para aprendizado em:

 · Cybersecurity e análise de malware
 · Sistemas de detecção por assinatura

O programa cria arquivos de teste, escaneia e mostra se detectou ameaças corretamente.

---
