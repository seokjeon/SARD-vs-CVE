# 📁 SARD-char_console_vprintf_12

> Juliet 테스트케이스의 `char_console_vprintf_12` 시나리오에서, 사용자 콘솔 입력을 `vprintf()` 함수에 포맷 문자열 없이 전달하여 발생하는 포맷 문자열 취약점(CWE-134)을 분석합니다.

## 🔍 취약점 개요

**취약점 종류**: [[CWE-134](https://cwe.mitre.org/data/definitions/134.html)] Uncontrolled Format String

* **Source**: 콘솔 입력(`fgets`)
* **취약 조건**: 외부 입력이 포맷 문자열로 전달됨
* **Sink**: `vprintf(data, args);`

---

## 탐지 결과 요약

| 총 슬라이스 수 | KSignSlicer 라벨 1 (취약) | KSignSlicer 라벨 0 (정상) | AI 취약 탐지 | AI 정상 탐지 |
|----------------|---------------------------|----------------------------|---------------|---------------|
| 12개           | 0개                       | 12개                       | 0개           | 12개          |

### ⚠️ 탐지 결과 문제점

1. **Sink 함수 탐지 누락**  
   - `vprintf()` 호출은 명확한 취약 함수지만 슬라이스에 포함된 호출이 구조적으로 단순화되어 탐지에 실패함

2. **va_arg 흐름 반영 부족**  
   - `va_list`로 전달되는 인자 흐름이 슬라이서에 반영되지 않음. 특히 `vprintf(data, args)`에서 `data`가 포맷 문자열이지만, `args`는 구조적으로 분석되지 않음

3. **Source → Sink 데이터 흐름 누락**  
   - `fgets()` → `vprintf()` 흐름을 하나의 슬라이스로 확보하지 못해 AI 입력 벡터에 연관성이 반영되지 않음

---

## 🧠 추가 분석 정보

### 🔎 Slicer 추출 코드
```c
if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL)
    badVaSinkB(data, data); // 실제 취약 호출
```
- 📄 **근거**: slicer_result.json

---

### 🧩 토큰화된 코드 (심볼화)
```c
char *Var1;
char Var2[100] = STRING;
Var1 = Var2;
if (FUNC1())
  FUNC2(Var1, Var1);
else
  FUNC3(Var1, Var1);
```
- `vprintf(data, args)` → `FUNC2(Var1, Var1)`로 단순화되어 포맷 문자열 여부 파악 불가
- 📄 **근거**: slicer_result.symbolized.json

---

### 🔤 AI 입력 토큰 시퀀스
```
<s>, char, *, Var, 1, =, ..., if, FUNC, ..., FUNC2(Var1, Var1), ... </s>
```
- `%s` 포맷 명시 여부 등 구조적 단서가 누락되어 학습 모델이 포맷 문자열 여부를 판단하지 못함
- 📄 **근거**: vectors.json

---

### 📉 벡터 예측 요약

| idx | label | predict | 의미 |
|-----|-------|---------|------|
| 0~11 | 0     | 0       | 모든 슬라이스를 정상으로 탐지함

- 📄 **근거**: test_output.csv

---

## 🧪 개선 방향 제안

- **슬라이싱 개선**: `va_arg` 구조와 Sink 호출을 포함한 함수 내부 흐름까지 반영
- **심볼화 보완**: 함수 이름 보존 또는 위험 함수로의 주석 기반 tagging 필요
- **AI 학습데이터 보강**: 포맷 문자열 여부(% 존재 등)를 기준으로 라벨링된 데이터 제공

---

## 취약점 세부 사항

### 📁 관련 파일 소개

| 파일명 | 설명 |
|--------|------|
| CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c | 콘솔 입력을 받아 `vprintf()` 호출에 전달하는 테스트 예제 |

---

### ❗️ 취약 코드

**문제점**: 외부 입력을 포맷 문자열로 사용하여 포맷 문자열 취약점 발생

#### Source: `CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c:63`
```c
if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL)
```

#### Sink: `CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c:42 (badVaSinkB)`
```c
vprintf(data, args); // 포맷 문자열 취약점 발생 가능
```

---

### ✅ 개선 코드

**패치 위치**: `badVaSinkB → badVaSinkG`, `data 초기화 부분`

#### 1. 포맷 문자열 명시
```c
vprintf("%s", args); // 포맷 문자열을 명시하여 안전한 출력
```

**개선 방법**:
- 외부 입력값을 포맷 문자열로 직접 사용하지 않고, 문자열 형식을 명시하여 출력
- 파일 내 `badVaSinkG`, `goodB2GVaSinkG`, `goodG2BVaSinkG` 함수에서 공통적으로 사용됨

#### 2. 포맷 문자열 자체 제거
```c
strcpy(data, "fixedstringtest"); // 포맷 문자열 없이 고정된 문자열 사용
```

**개선 방법**:
- 입력값 자체를 고정된 문자열로 대체하여 포맷 문자열 포함 가능성을 원천 차단
- 파일 내 `goodG2B()` 함수의 data 초기화 부분에서 사용됨

---


## 📊 탐지 결과

|FileName|Caller|Source|Sink|idx|CWE-ID|category|criterion|line|label|predict|
|--------|------|------|----|---|------|--------|---------|----|-----|-------|
|CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c|CWE134_Uncontrolled_Format_String__char_console_vprintf_12_bad|False|True|0|CWE-134|CallExpression|strlen|58|0|0|
|CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c|CWE134_Uncontrolled_Format_String__char_console_vprintf_12_bad|False|True|1|CWE-134|CallExpression|fgets|63|0|0|
|CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c|CWE134_Uncontrolled_Format_String__char_console_vprintf_12_bad|False|True|2|CWE-134|CallExpression|strlen|67|0|0|
|CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c|CWE134_Uncontrolled_Format_String__char_console_vprintf_12_bad|False|True|3|CWE-134|CallExpression|strcpy|85|0|0|
|CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c|goodB2G|False|True|4|CWE-134|CallExpression|strlen|136|0|0|
|CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c|goodB2G|False|True|5|CWE-134|CallExpression|fgets|141|0|0|
|CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c|goodB2G|False|True|6|CWE-134|CallExpression|strlen|145|0|0|
|CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c|goodB2G|False|True|7|CWE-134|CallExpression|strlen|164|0|0|
|CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c|goodB2G|False|True|8|CWE-134|CallExpression|fgets|169|0|0|
|CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c|goodB2G|False|True|9|CWE-134|CallExpression|strlen|173|0|0|
|CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c|goodG2B|False|True|10|CWE-134|CallExpression|strcpy|232|0|0|
|CWE134_Uncontrolled_Format_String__char_console_vprintf_12.c|goodG2B|False|True|11|CWE-134|CallExpression|strcpy|237|0|0|