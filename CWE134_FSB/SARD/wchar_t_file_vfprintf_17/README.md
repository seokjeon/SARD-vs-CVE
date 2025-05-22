# 📁 SARD-wchar_t_file_vfprintf_17

> Juliet 테스트케이스의 `wchar_t_file_vfprintf_17` 시나리오에서는 외부 파일로부터 읽은 데이터를 `vfwprintf()` 함수에 포맷 문자열 없이 직접 전달하여 발생하는 포맷 문자열 취약점(CWE-134)을 다룹니다.

## 🔍 취약점 개요

**취약점 종류**: [[CWE-134](https://cwe.mitre.org/data/definitions/134.html)] Uncontrolled Format String  
* **Source**: 파일 입력 (`fgetws`)  
* **취약 조건**: 외부 입력값을 `vfwprintf` 포맷 문자열로 직접 사용  
* **Sink**: `vfwprintf(stdout, data, args);`

---

## 탐지 결과 요약

| 총 슬라이스 수 | KSignSlicer 라벨 1 (취약) | KSignSlicer 라벨 0 (정상) | AI 취약 탐지 | AI 정상 탐지 |
|----------------|---------------------------|----------------------------|---------------|---------------|
| 6개            | 0개                       | 6개                        | 0개           | 6개           |

### ⚠️ 탐지 결과 문제점

1. **Sink 함수가 간접 호출로 단순화되어 탐지 누락**  
   - `vfwprintf()`가 `va_arg` 구조 내부에서 호출되며, 심볼화 후 단순 `FUNC()` 구조로 표현됨

2. **파일 읽기 Source와 Sink 간의 연결 단절**  
   - `fgetws` → `vfwprintf` 흐름이 동일 슬라이스에 포함되지 않아 AI가 전체 흐름을 인식하지 못함

3. **wide-character string 취급에 대한 모델 학습 부족**  
   - `wchar_t`, `vfwprintf` 등 wide string 전용 함수에 대한 학습 데이터가 희소하여 일반 포맷 문자열 탐지보다 성능이 저조함

---

## 🧠 추가 분석 정보

### 🔎 Slicer 추출 코드
```c
for(i = 0; i < 1; i++)
    if (fgetws(data+dataLen, 100-dataLen, pFile) == NULL)
        ...
for(j = 0; j < 1; j++)
    badVaSinkB(data, data); // sink 위치
```
- 📄 **근거**: slicer_result.json

---

### 🧩 토큰화된 코드 (심볼화)
```c
FUNC1(Var3, Var3);
```
- 심볼화 과정에서 `vfwprintf()`가 함수 이름이 제거되고 단순한 함수 호출 `FUNC1()`으로 표현됨
- 포맷 문자열 여부나 wide string 여부 등 중요한 정보가 유실됨
- 📄 **근거**: slicer_result.symbolized.json

---

### 🔤 AI 입력 토큰 시퀀스
```
<s>, int, wchar_t, *, Var, ..., FUNC1(Var, Var), ... </s>
```
- `%s` 등의 포맷 토큰이 없으며, Sink 함수명도 일반화되어 탐지 정확도 저하
- 📄 **근거**: vectors.json

---

### 📉 벡터 예측 요약

| idx | label | predict | 의미 |
|-----|-------|---------|------|
| 0~5 | 0     | 0       | 모두 정상으로 탐지됨

- 📄 **근거**: test_output.csv

---

## 🧪 개선 방향 제안

1. **Sink 추적 구조 강화**: `va_arg` 구조 내 Sink 함수 호출도 정확히 인식되도록 슬라이싱 및 심볼화 개선  
2. **포맷 문자열 여부 보존**: 토큰화 시 `%` 토큰 존재 여부를 유지하여 위험 예측의 주요 단서로 활용  
3. **wide-string 함수군 학습 보완**: `vfwprintf`, `fgetws`, `wchar_t` 기반 입력/출력 흐름에 대한 학습 샘플 확충

---

## 취약점 세부 사항

### 📁 관련 파일 소개

| 파일명 | 설명 |
|--------|------|
| CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_17.c | 파일 입력 기반 wide-character 문자열을 포맷 문자열로 사용하는 테스트 코드 |

---

### ❗️ 취약 코드

**문제점**: 외부 입력을 `vfwprintf` 함수의 포맷 문자열로 직접 사용

#### Source: `CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_17.c:63`
```c
if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL)
```

#### Sink: `CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_17.c:42 (badVaSinkB)`
```c
vfwprintf(stdout, data, args); // 포맷 문자열 취약
```

---

### ✅ 개선 코드

**패치 위치**: `badVaSinkB → goodB2GVaSinkG`

```c
vfwprintf(stdout, L"%s", args); // 포맷 문자열 명시
```

**개선 방법**:
- 외부 입력이 포맷 문자열로 사용되지 않도록 명시적 서식 지정
- wide string 환경에서는 `%ls`, `%S` 등 확장 서식에 유의

---


## 📊 탐지 결과

|FileName|Caller|Source|Sink|idx|CWE-ID|category|criterion|line|label|predict|
|--------|------|------|----|---|------|--------|---------|----|-----|-------|
|CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_17.c|CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_17_bad|False|True|0|CWE-134|CallExpression|wcslen|54|0|0|
|CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_17.c|CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_17_bad|False|True|1|CWE-134|CallExpression|fopen|59|0|0|
|CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_17.c|CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_17_bad|False|True|2|CWE-134|CallExpression|fclose|69|0|0|
|CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_17.c|goodB2G|False|True|3|CWE-134|CallExpression|wcslen|106|0|0|
|CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_17.c|goodB2G|False|True|4|CWE-134|CallExpression|fopen|111|0|0|
|CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_17.c|goodB2G|False|True|5|CWE-134|CallExpression|fclose|121|0|0|
