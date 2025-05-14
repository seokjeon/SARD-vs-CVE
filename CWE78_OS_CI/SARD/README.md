## AI가 SARD Juliet 데이터에 있는 CWE78에 대해서 취약하다고 찾았던 것들의 특징
```bash
sojeon@swlab-u2404:~/Documents/research/SARD-vs-CVE/CWE78_OS_CI/SARD$ xsv search -s predict 1 test_output.csv | xsv select criterion | uniq
criterion
strcat
```