# 📁 SARD-wchar_t_file_vfprintf_17

## 🔍 취약점 개요
* **취약점 종류**: [CWE-134](https://cwe.mitre.org/data/definitions/134.html) Uncontrolled Format String
* **Source**: `wchar_t_file` (파일로부터 입력)
* **취약 조건**: 파일 입력값을 포맷 문자열로 직접 사용
* **Sink**: `vfwprintf()`

## 탐지 결과 요약
총 슬라이스 수: 6개
- KSignSlicer가
    - 라벨 1(취약)으로 계산: 0개
    - 라벨 0(정상)으로 계산: 6개
- AI 모델이 
    - 취약으로 탐지: 0개
    - 정상으로 탐지: 6개

### 탐지 결과

| FileName                                                      | Caller                                                          | Source | Sink | idx | CWE-ID  | category       | criterion | line | label | token_length | predict |
|---------------------------------------------------------------|-----------------------------------------------------------------|--------|------|-----|---------|----------------|-----------|------|-------|--------------|---------|
| CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_17.c | CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_17_bad | False  | True | 0   | CWE-134 | CallExpression | wcslen    | 54   | 0     | 120          | 0       |
| CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_17.c | CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_17_bad | False  | True | 1   | CWE-134 | CallExpression | fopen     | 59   | 0     | 99           | 0       |
| CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_17.c | CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_17_bad | False  | True | 2   | CWE-134 | CallExpression | fclose    | 69   | 0     | 99           | 0       |
| CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_17.c | goodB2G                                                         | False  | True | 3   | CWE-134 | CallExpression | wcslen    | 106  | 0     | 120          | 0       |
| CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_17.c | goodB2G                                                         | False  | True | 4   | CWE-134 | CallExpression | fopen     | 111  | 0     | 99           | 0       |
| CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_17.c | goodB2G                                                         | False  | True | 5   | CWE-134 | CallExpression | fclose    | 121  | 0     | 99           | 0       |

---

### ❗️ 취약 코드

**문제점**:  
파일에서 입력된 데이터를 포맷 문자열로 직접 사용하면서 `%x`, `%n` 등으로 포맷 스트링 공격에 악용될 수 있음

#### Sink: `CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_17.c:27`
```c
vfwprintf(stdout, data, args); // ⚠ 포맷 문자열 지정 없음
```

### ✅ 개선 코드

**패치 위치**: `goodB2GVaSinkG() 함수 내부`
```c
vfwprintf(stdout, L"%s", args); // ✅ 포맷 문자열 명시
```

**개선 방법**:
사용자 입력이 포함된 문자열을 출력할 때는 반드시 "포맷 문자열"을 명시해줘야 함
"fprintf(stdout, "%s", data);" 형태로 사용하면 포맷 스트링 인젝션 방지 가능