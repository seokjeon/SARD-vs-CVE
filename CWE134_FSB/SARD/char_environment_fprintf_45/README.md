# 📁 SARD-char_environment_fprintf_45

> Juliet 테스트케이스의 `char_environment_fprintf_45` 시나리오에서, 환경변수로부터 읽은 문자열을 `fprintf()` 함수에 포맷 문자열 없이 직접 전달하여 발생한 포맷 문자열 취약점(CWE-134)입니다.

## 🔍 취약점 개요

**취약점 종류**: [[CWE-134](https://cwe.mitre.org/data/definitions/134.html)] Uncontrolled Format String

* **Source**: 환경변수 입력 (`getenv`)
* **취약 조건**: 외부 입력값을 검증 없이 포맷 문자열로 사용
* **Sink**: `fprintf(stdout, data);`

---

## 탐지 결과 요약

| 총 슬라이스 수 | KSignSlicer 라벨 1 (취약) | KSignSlicer 라벨 0 (정상) | AI 취약 탐지 | AI 정상 탐지 |
|----------------|---------------------------|----------------------------|---------------|---------------|
| 8개            | 2개                       | 6개                        | 4개           | 4개           |

Sink(`fprintf`) 관련 슬라이스는 총 3건 있었으며, 이 중 1건은 **취약으로 탐지됨**

### ⚠️ 탐지 결과 문제점

1. **Sink 정보는 있지만 Source 슬라이스 누락**  
   - `getenv()` 호출 위치를 포함하는 슬라이스 부족
2. **AI 분류 모델의 오탐 존재**  
   - `fprintf(data)` 형태는 취약하지만 일부는 정상으로 예측됨
3. **슬라이스 내 의미 단절**  
   - 위험한 `fprintf()` 호출이 별도 문맥 없이 단일 구문으로만 표현됨

---

## 🧠 추가 분석 정보

### 🔎 Slicer 추출 코드
```c
char * data = CWE134_Uncontrolled_Format_String__char_environment_fprintf_45_badData;
fprintf(stdout, data);
```
- 📄 **근거**: slicer_result.json, slicer_result.symbolized.json

---

### 🧩 토큰화된 코드 (심볼화)
```c
char *Var1=Var2;
fprintf(Var3,Var1);
```
- 📄 **근거**: slicer_result.symbolized.json

---

### 🔤 AI 입력 토큰 시퀀스
```
<s>, char, _, *, Var, 1, =, Var, 2, ;, _, fprintf, (, Var, 3, ,, Var, 1, ), ;, </s>
```
- 📄 **근거**: vectors.json

---

## 🧪 개선 방향 제안

- 슬라이싱 개선: Source부터 Sink까지 흐름을 반영한 슬라이스 구조 필요
- 토큰 구조 보강: 포맷 문자열 유무 판단 가능하도록 `%` 토큰과의 관계 표현 필요
- AI 학습 데이터 확장: 다양한 Source–Sink 조합과 위험한 문자열 흐름 포함 필요

---

## 취약점 세부 사항

### 📁 관련 파일 소개

| 파일명       | 설명                      |
| ------------ | ------------------------- |
| CWE134_Uncontrolled_Format_String__char_environment_fprintf_45.c | 환경변수 입력 후 `fprintf()` 호출이 포함된 테스트 코드 |

---

### ❗️ 취약 코드

**문제점**: 환경변수 입력을 포맷 문자열로 사용하여 포맷 문자열 취약점이 발생

#### Source: `CWE134_Uncontrolled_Format_String__char_environment_fprintf_45.c:52`
```c
char * environment = GETENV(ENV_VARIABLE);
if (environment != NULL)
    strncat(data+dataLen, environment, 100-dataLen-1);
```

#### Sink: `CWE134_Uncontrolled_Format_String__char_environment_fprintf_45.c:42`
```c
fprintf(stdout, data); // 포맷 문자열 취약점 발생 가능
```

---

### ✅ 개선 코드

**패치 위치**: `CWE134_Uncontrolled_Format_String__char_environment_fprintf_45.c:42`

#### 1. 포맷 문자열 명시
```c
fprintf(stdout, "%s", data); // 안전하게 출력
```

**개선 방법**:  
- 외부 입력값을 포맷 문자열로 직접 사용하는 것을 금지하고, "%s"와 같은 명시적인 형식 지정자를 통해 출력

---

## 📊 탐지 결과

|FileName|Caller|Source|Sink|idx|CWE-ID|category|criterion|line|label|predict|
|--------|------|------|----|---|------|--------|---------|----|-----|-------|
|CWE134_Uncontrolled_Format_String__char_environment_fprintf_45.c|badSink|False|True|0|CWE-134|CallExpression|fprintf|42|1|1|
|CWE134_Uncontrolled_Format_String__char_environment_fprintf_45.c|CWE134_Uncontrolled_Format_String__char_environment_fprintf_45_bad|False|True|1|CWE-134|CallExpression|strlen|52|0|0|
|CWE134_Uncontrolled_Format_String__char_environment_fprintf_45.c|CWE134_Uncontrolled_Format_String__char_environment_fprintf_45_bad|False|True|2|CWE-134|CallExpression|strncat|58|0|0|
|CWE134_Uncontrolled_Format_String__char_environment_fprintf_45.c|goodG2BSink|False|True|3|CWE-134|CallExpression|fprintf|74|1|1|
|CWE134_Uncontrolled_Format_String__char_environment_fprintf_45.c|goodG2B|False|True|4|CWE-134|CallExpression|strcpy|83|0|0|
|CWE134_Uncontrolled_Format_String__char_environment_fprintf_45.c|goodB2GSink|False|True|5|CWE-134|CallExpression|fprintf|93|0|0|
|CWE134_Uncontrolled_Format_String__char_environment_fprintf_45.c|goodB2G|False|True|6|CWE-134|CallExpression|strlen|103|0|0|
|CWE134_Uncontrolled_Format_String__char_environment_fprintf_45.c|goodB2G|False|True|7|CWE-134|CallExpression|strncat|109|0|0|
