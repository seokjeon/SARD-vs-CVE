# AI가 SARD Juliet 데이터에 있는 CWE400에 대해서 취약하다고 찾았던 것들의 특징
```
C:\Users\user\Downloads\xsv-0.13.0-i686-pc-windows-gnu>xsv search -s predict 1 C:\Users\user\Desktop\SARD-vs-CVE\CWE400_RE\SARD\test_output.csv | xsv select criterion | xsv frequency -s criterion | xsv select value

value
strlen
fopen
fwrite
fclose
```