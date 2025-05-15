# 📁 SARD-char_console_vprintf_12

## 🔍 취약점 개요
* **취약점 종류**: [CWE-134](https://cwe.mitre.org/data/definitions/134.html) Uncontrolled Format String
* **Source**: `char_console`
* **취약 조건**: 사용자 입력을 포맷 문자열로 직접 사용
* **Sink**: `vprintf()`

## 탐지 결과 요약
총 슬라이스 수: 12개
- KSignSlicer가
    - 라벨 1(취약)으로 계산: 0개
    - 라벨 0(정상)으로 계산: 12개
- AI 모델이 
    - 취약으로 탐지: 2개
    - 정상으로 탐지: 10개

### 탐지 결과

| FileName                                                     | Caller                                                         | Source | Sink | idx | CWE-ID  | category       | criterion | line | label | token_length | predict |
|--------------------------------------------------------------|----------------------------------------------------------------|--------|------|-----|---------|----------------|-----------|------|-------|--------------|---------|
| CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c | CWE134_Uncontrolled_Format_String__char_console_vprintf_12_bad | False  | True | 0   | CWE-134 | CallExpression | strlen    | 58   | 0     | 186          | 0       |
| CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c | CWE134_Uncontrolled_Format_String__char_console_vprintf_12_bad | False  | True | 1   | CWE-134 | CallExpression | fgets     | 63   | 0     | 186          | 0       |
| CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c | CWE134_Uncontrolled_Format_String__char_console_vprintf_12_bad | False  | True | 2   | CWE-134 | CallExpression | strlen    | 67   | 0     | 186          | 0       |
| CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c | CWE134_Uncontrolled_Format_String__char_console_vprintf_12_bad | False  | True | 3   | CWE-134 | CallExpression | strcpy    | 85   | 0     | 186          | 0       |
| CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c | goodB2G                                                        | False  | True | 4   | CWE-134 | CallExpression | strlen    | 136  | 0     | 286          | 0       |
| CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c | goodB2G                                                        | False  | True | 5   | CWE-134 | CallExpression | fgets     | 141  | 0     | 286          | 0       |
| CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c | goodB2G                                                        | False  | True | 6   | CWE-134 | CallExpression | strlen    | 145  | 0     | 286          | 0       |
| CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c | goodB2G                                                        | False  | True | 7   | CWE-134 | CallExpression | strlen    | 164  | 0     | 286          | 0       |
| CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c | goodB2G                                                        | False  | True | 8   | CWE-134 | CallExpression | fgets     | 169  | 0     | 286          | 0       |
| CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c | goodB2G                                                        | False  | True | 9   | CWE-134 | CallExpression | strlen    | 173  | 0     | 286          | 0       |
| CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c | goodG2B                                                        | False  | True | 10  | CWE-134 | CallExpression | strcpy    | 232  | 0     | 86           | 1       |
| CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c | goodG2B                                                        | False  | True | 11  | CWE-134 | CallExpression | strcpy    | 237  | 0     | 86           | 1       |


---

### ❗️ 취약 코드

**문제점**:  
사용자 입력 `data`가 포맷 문자열로 `vprintf(data, args)`에 직접 전달됨.  
이는 `%s`, `%n`, `%x` 등의 포맷 스트링 공격에 노출될 수 있음.

#### Source: `CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c:40`
```c
if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL)
```

#### Sink: `CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c:25`
```c
vprintf(data, args); // ⚠ 포맷 문자열 지정 없음
```

### ✅ 개선 코드

**패치 위치**: `동일 함수, format string 명시`
```c
vprintf("%s", args); // ✅ 안전: 포맷 명시
```

**개선 방법**:
사용자 입력을 그대로 포맷 문자열에 넣지 않고, 명시적으로 "%s"를 지정하여 format string 취약점을 방지함