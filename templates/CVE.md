# 📁 CVE-2019-16718

## 🔍 취약점 개요

**🔗 [커밋 링크](https://github.com/radareorg/radare2/commit/dd739f5a45b3af3d1f65f00fe19af1dbfec7aea7)** | **🔗 [CVE 링크](https://www.cvedetails.com/cve/CVE-2019-16718)**  

> Radare2의 서버 설정 기능에서, 사용자 입력을 검증 없이 system() 함수에 전달하는 add_server() 함수로 인해 발생한 명령어 인젝션(CWE-78) 취약점입니다.

**취약점 종류**: [[CWE-78](https://cwe.mitre.org/data/definitions/78.html)] OS Command Injection

* **Source**: 외부에서 제어 가능한 입력값 (예: `getenv`)
* **취약 조건**: 입력값 검증 없이 명령 실행 경로에 직접 사용됨
* **Sink**: 입력값을 검증하지 않고 `system()`, `execl()` 등의 위험한 함수나 구문에 사용

---

## 탐지 결과 요약
cve 설명에 나온 취약한 함수(Caller)에 대한 슬라이스만 고려했을 때,

총 슬라이스 수: 48개  
- KSignSlicer가  
  - 라벨 1(취약)으로 계산: 0개  
  - 라벨 0(정상)으로 계산: 48개  
- AI 모델이  
  - 취약으로 탐지: 0개  
  - 정상으로 탐지: 48개  

Sink(`system()` 함수) 관련 슬라이스는 1건 있었으나, **정상으로 탐지됨**

\* cve 설명에 나온 취약한 함수(Caller) && Sink와 관련된 슬라이스 데이터만 추출

| FileName  | Caller      | Source | Sink  | idx | CWE-ID | category       | criterion | line | label | token\_length | predict |
| --------- | ----------- | ------ | ----- | --- | ------ | -------------- | --------- | ---- | ----- | ------------- | ------- |
| manager.c | add\_server | False  | False | 71  | CWE-   | CallExpression | system    | 486  | -3    | 67            | 0       |

#### SARD는 잘 탐지하는데 이 CVE는 탐지 못했던 이유

AI 모델은 CWE-78의 경우 strcat() 함수가 슬라이스에 존재해야 취약으로 판단하는데, 이 취약점의 경우 system() 함수만 포함되어 있어 정상으로 판단된 것으로 보임.

---

### ⚠️ 탐지 결과 문제점

현재 탐지 결과에서 모든 슬라이스가 정상(라벨 0)으로 판정되었으나, 이는 다음과 같은 기술적 한계로 인한 오탐으로 판단됩니다:

1. **슬라이싱 범위 불완전**
   - 슬라이스가 `system()` 호출 단독 또는 주변 문자열 처리 함수(`strlen`, `snprintf`)만 포함됨
   - 명령어 조합 과정이 포함되지 않아 실행 컨텍스트를 충분히 반영하지 못함
   - 📄 근거: `slicer_result.json`, `before_cmd.c`, `after_cmd.c`

2. **Source/Sink 식별 실패**
   - 모든 슬라이스에서 `"Source": false`, `"Sink": false`로 표기됨
   - `getenv()`를 통해 입력이 유입되지만, 해당 입력 함수가 Source로 인식되지 않음
   - `system()` 또한 Sink로 인식되지 않아 위험 흐름을 감지하지 못함
   - 📄 근거: `slicer_result.json`, `test_output.csv`

3. **슬라이스 단절 및 단편성**
   - 명령어 조립 → 실행 흐름이 함수 간 분산되어 있으나 슬라이스는 단일 함수 범위로 제한됨
   - 그 결과 `input → system()`의 전체 데이터 흐름이 하나의 슬라이스에 담기지 않음
   - 📄 근거: `manager.c`의 함수 흐름 분석 및 슬라이스 기준 비교

---

## 취약점 세부 사항

### 📁 관련 파일 소개

| 파일명            | 설명              |
| -------------- | --------------- |
| `before_cmd.c` | 취약 코드 (수정 전) 포함 |
| `after_cmd.c`  | 개선 코드 (수정 후) 포함 |

---

### ❗️ 취약 코드

**문제점**:
사용자 입력이 적절히 검증되지 않은 채로 `system()` 함수의 인자로 사용되어 **명령어 인젝션**이 발생할 수 있음.

```c
char *input = getenv("USER_INPUT");
system(input);  // 검증 없이 실행
```

---

### ✅ 개선 코드 (두 가지 이상의 개선 방법이 존재할 경우, 아래와 같이 #### 1, #### 2 형태로 번호를 붙여 모두 제시하세요.)

**패치 위치**: `after_cmd.c:10` (예시)

```c
char *input = getenv("USER_INPUT");
if (is_safe(input)) {
    system(input);
}
```

**개선 방법**:

사용자 환경변수에서 유입된 입력값을 직접 실행에 사용하는 것을 방지해야 합니다.

* 입력값에 대해 필터링 또는 화이트리스트 기반 검증을 수행하여, 명령 실행에 사용되는 위험한 문자열을 제거합니다.
* 가능하다면 `system()` 함수 대신 명령어 조립이 명확하게 통제되는 안전한 API(`execvp`, `spawn` 등)를 사용합니다.

---

## 🧠 추가 분석 정보

### 🔎 Slicer 추출 코드

```c
system(input);
```
- 📄 **근거**: `slicer_result.json`, `before_cmd.c`
- 슬라이스는 단일 `system()` 호출만 포함되어 있으며, 입력 조립 흐름은 포함되지 않음

---

### 🧩 토큰화된 코드 (심볼화)

```c
system(Var1);
```
- 📄 **근거**: `slicer_result.symbolized.json`
- 입력 변수는 추상화되었으나, 명령 실행 흐름의 맥락 정보는 부족함

---

### 🔤 AI 입력 토큰 예시

```
<s>, system, (, Var1, ), ;, </s>
```
- 📄 **근거**: `vectors.json`
- 단순한 구조의 토큰 시퀀스로 인해 실행 의미를 충분히 반영하지 못함

---

### 📉 벡터 예측 요약

| idx | label | predict | 입력 길이 | 의미 |
|-----|-------|---------|------------|------|
| 71  | 0     | 0       | 67         | AI가 정상 코드로 판단함 |

- 📄 **근거**: `test_output.csv`
- 실제로는 명령어 인젝션 가능성이 있음에도 AI는 탐지하지 못함

---

## 🧪 개선 방향 제안

- 슬라이스가 `system()` 호출만 포함되어 있으므로, 입력 조립 및 흐름 추적이 누락됨
- `getenv()`를 통한 외부 입력이 존재하지만 슬라이스에 포함되지 않아 Source로 인식되지 않음

1. **슬라이싱 강화**
   - 입력 조립부터 실행까지의 전체 흐름이 슬라이스에 포함되도록 개선
   - 함수 간 흐름도 추적할 수 있는 슬라이싱 전략 필요

2. **Source/Sink 태깅 향상**
   - `getenv()`와 `system()`이 명확히 태깅되도록 분석 도구 개선

3. **풍부한 토큰 표현**
   - 명령 조립 맥락과 사용자 입력 연산 흐름을 인식할 수 있도록 토큰 구조 확장 필요

---

## 탐지 결과
\* cve 설명에 나온 취약한 함수(Caller)에 대한 슬라이스 관련 데이터만 추출

|FileName |Caller                |Source|Sink |idx|CWE-ID|category      |criterion|line|label|token_length|predict|
|---------|----------------------|------|-----|---|------|--------------|---------|----|-----|------------|-------|
|manager.c|build_config          |False |False|0  |CWE-  |CallExpression|strlen   |98  |-3   |375         |0      |
|manager.c|build_config          |False |False|1  |CWE-  |CallExpression|strlen   |98  |-3   |375         |0      |
|manager.c|build_config          |False |False|2  |CWE-  |CallExpression|snprintf |101 |-3   |350         |0      |
|manager.c|build_config          |False |False|3  |CWE-  |CallExpression|fopen    |102 |-3   |375         |0      |
|manager.c|build_config          |False |False|4  |CWE-  |CallExpression|fprintf  |110 |-3   |338         |0      |
|manager.c|build_config          |False |False|5  |CWE-  |CallExpression|fprintf  |111 |-3   |359         |0      |
|manager.c|build_config          |False |False|6  |CWE-  |CallExpression|atoi     |111 |-3   |359         |0      |
|manager.c|build_config          |False |False|7  |CWE-  |CallExpression|fprintf  |112 |-3   |359         |0      |
|manager.c|build_config          |False |False|8  |CWE-  |CallExpression|fprintf  |113 |-3   |323         |0      |
|manager.c|build_config          |False |False|9  |CWE-  |CallExpression|fprintf  |114 |-3   |323         |0      |
|manager.c|build_config          |False |False|10 |CWE-  |CallExpression|fprintf  |115 |-3   |323         |0      |
|manager.c|build_config          |False |False|11 |CWE-  |CallExpression|fprintf  |116 |-3   |323         |0      |
|manager.c|build_config          |False |False|12 |CWE-  |CallExpression|fprintf  |117 |-3   |323         |0      |
|manager.c|build_config          |False |False|13 |CWE-  |CallExpression|fprintf  |118 |-3   |338         |0      |
|manager.c|build_config          |False |False|14 |CWE-  |CallExpression|fclose   |119 |-3   |338         |0      |
|manager.c|construct_command_line|False |False|15 |CWE-  |CallExpression|memset   |133 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|16 |CWE-  |CallExpression|snprintf |134 |-3   |957         |0      |
|manager.c|construct_command_line|False |False|17 |CWE-  |CallExpression|strlen   |140 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|18 |CWE-  |CallExpression|snprintf |141 |-3   |926         |0      |
|manager.c|construct_command_line|False |False|19 |CWE-  |CallExpression|strlen   |144 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|20 |CWE-  |CallExpression|snprintf |145 |-3   |926         |0      |
|manager.c|construct_command_line|False |False|21 |CWE-  |CallExpression|strlen   |149 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|22 |CWE-  |CallExpression|snprintf |150 |-3   |926         |0      |
|manager.c|construct_command_line|False |False|23 |CWE-  |CallExpression|strlen   |154 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|24 |CWE-  |CallExpression|snprintf |155 |-3   |926         |0      |
|manager.c|construct_command_line|False |False|25 |CWE-  |CallExpression|strlen   |158 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|26 |CWE-  |CallExpression|snprintf |159 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|27 |CWE-  |CallExpression|strlen   |162 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|28 |CWE-  |CallExpression|snprintf |163 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|29 |CWE-  |CallExpression|strlen   |166 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|30 |CWE-  |CallExpression|snprintf |167 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|31 |CWE-  |CallExpression|strlen   |170 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|32 |CWE-  |CallExpression|snprintf |171 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|33 |CWE-  |CallExpression|strlen   |174 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|34 |CWE-  |CallExpression|snprintf |175 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|35 |CWE-  |CallExpression|strlen   |178 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|36 |CWE-  |CallExpression|snprintf |179 |-3   |926         |0      |
|manager.c|construct_command_line|False |False|37 |CWE-  |CallExpression|strlen   |182 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|38 |CWE-  |CallExpression|snprintf |183 |-3   |926         |0      |
|manager.c|construct_command_line|False |False|39 |CWE-  |CallExpression|strlen   |186 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|40 |CWE-  |CallExpression|snprintf |187 |-3   |926         |0      |
|manager.c|construct_command_line|False |False|41 |CWE-  |CallExpression|strlen   |190 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|42 |CWE-  |CallExpression|snprintf |191 |-3   |926         |0      |
|manager.c|construct_command_line|False |False|43 |CWE-  |CallExpression|strlen   |194 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|44 |CWE-  |CallExpression|snprintf |195 |-3   |926         |0      |
|manager.c|construct_command_line|False |False|45 |CWE-  |CallExpression|strlen   |199 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|46 |CWE-  |CallExpression|snprintf |200 |-3   |904         |0      |
|manager.c|add_server            |False |False|71 |CWE-  |CallExpression|system   |486 |-3   |67          |0      |