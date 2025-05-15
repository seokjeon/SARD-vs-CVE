# 📁 SARD-char_fscanf_add_01

## 🔍 취약점 개요
* **취약점 종류**: [CWE-190](https://cwe.mitre.org/data/definitions/190.html) Integer Overflow or Wraparound
* **Source**: `fscanf` 함수로 외부 입력 수신
* **취약 조건**: 입력된 값이 검증되지 않고 산술 연산에 사용됨
* **Sink**: 정수 덧셈(`+`) 연산 수행 시 오버플로우 가능성

## 탐지 결과 요약
총 슬라이스 수: 2개
- KSignSlicer가
    - 라벨 1(취약)으로 계산: 0개
    - 라벨 0(정상)으로 계산: 2개
- AI 모델이 
    - 취약으로 탐지: 0개
    - 정상으로 탐지: 2개

### 탐지 결과

|FileName                                               |Caller                               |Source|Sink |idx|CWE-ID |category      |criterion|line|label|token_length|predict|
|-------------------------------------------------------|-------------------------------------|------|-----|---|------ |--------------|---------|----|-----|------------|-------|
|CWE190_Integer_Overflow__char_fscanf_add_01.c|CWE190_Integer_Overflow__char_fscanf_add_01_bad|False |False|0  |CWE-190|CallExpression|fscanf   |27  |0    |11          |0      |
|CWE190_Integer_Overflow__char_fscanf_add_01.c|goodB2G                                        |False |False|1  |CWE-190|CallExpression|fscanf   |59  |0    |11          |0      |


## 취약점 세부 사항
