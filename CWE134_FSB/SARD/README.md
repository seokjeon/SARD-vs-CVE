## AI가 SARD Juliet 데이터에 있는 CWE78에 대해서 취약하다고 찾았던 것들의 특징
```bash
PS C:\SARD-vs-CVE\CWE134_FSB\SARD> Import-Csv test_output.csv | Where-Object { $_.predict -eq '1' } | Select-Object -ExpandProperty criterion | Sort-Object -Unique
_vsnwprintf
fprintf
fwprintf
strcpy
vsnprintf
```