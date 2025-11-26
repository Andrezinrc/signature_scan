# signature_scan

# ⚠️ AVISO LEGAL

Este projeto é **exclusivamente educacional**.  
Foi desenvolvido para estudo de antivírus, assinaturas, leitura de bytes e análise simples em C.

Não é um antivírus real e **não deve ser usado** para proteção de sistemas, detecção profissional de malware ou qualquer uso crítico.

O autor **não se responsabiliza** por:
- Alarmes falsos ou ausência de detecção
- Perda de arquivos
- Uso inadequado do software
- Consequências do uso incorreto

Use **por sua própria conta e risco**.

---

Projeto para aprendizado sobre antivírus, análise de bytes e sistemas de assinatura em C.

## Compilar

```bash
gcc scanner.c -o scanner
```
Como Usar

## Teste Automático

```bash
./scanner rules
```

Executa todos os testes incluídos:
	•	EICAR (assinatura hardcoded)
	•	SIMPLE_MALWARE (DE AD BE EF)
	•	SUSPICIOUS_PATTERN (90 90 90 E8)
	•	Arquivos limpos

## Escaneamento Específico

```
./scanner rules arquivo_suspeito.exe
```

## Escaneamento Recursivo

```bash
./scanner --scan-dir /caminho/do/diretorio
```

Sistema de Regras

## Edite rules.txt:

Formato: NOME=HEX_HEX_HEX
MINHA_REGRA=AA BB CC DD
OUTRA_REGRA=90 90 90 E8 ?? ?? FF

Arquivos de Teste Incluídos
	•	eicar_test.txt
	•	malware_test.bin
	•	shellcode_test.bin
	•	clean_file.txt

---