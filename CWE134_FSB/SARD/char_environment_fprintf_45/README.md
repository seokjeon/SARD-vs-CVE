# 📁 SARD-char_environment_fprintf_45

## 🔍 취약점 개요
* **취약점 종류**: [CWE-134](https://cwe.mitre.org/data/definitions/134.html) Uncontrolled Format String
* **Source**: `char_environment`
* **취약 조건**: 환경변수 입력을 포맷 문자열로 직접 사용
* **Sink**: `fprintf()`

## 탐지 결과 요약
총 슬라이스 수: 8개
- KSignSlicer가
    - 라벨 1(취약)으로 계산: 2개
    - 라벨 0(정상)으로 계산: 6개
- AI 모델이 
    - 취약으로 탐지: 4개
    - 정상으로 탐지: 4개

### 탐지 결과

| FileName                                                         | Caller                                                             | Source | Sink | idx | CWE-ID  | category       | criterion | line | label | token_length | predict |
|------------------------------------------------------------------|--------------------------------------------------------------------|--------|------|-----|---------|----------------|-----------|------|-------|--------------|---------|
| CWE134_Uncontrolled_Format_String__char_environment_fprintf_45.c | badSink                                                            | False  | True | 0   | CWE-134 | CallExpression | fprintf   | 42   | 1     | 19           | 1       |
| CWE134_Uncontrolled_Format_String__char_environment_fprintf_45.c | CWE134_Uncontrolled_Format_String__char_environment_fprintf_45_bad | False  | True | 1   | CWE-134 | CallExpression | strlen    | 52   | 0     | 89           | 0       |
| CWE134_Uncontrolled_Format_String__char_environment_fprintf_45.c | CWE134_Uncontrolled_Format_String__char_environment_fprintf_45_bad | False  | True | 2   | CWE-134 | CallExpression | strncat   | 58   | 0     | 89           | 0       |
| CWE134_Uncontrolled_Format_String__char_environment_fprintf_45.c | goodG2BSink                                                        | False  | True | 3   | CWE-134 | CallExpression | fprintf   | 74   | 1     | 19           | 1       |
| CWE134_Uncontrolled_Format_String__char_environment_fprintf_45.c | goodG2B                                                            | False  | True | 4   | CWE-134 | CallExpression | strcpy    | 83   | 0     | 40           | 1       |
| CWE134_Uncontrolled_Format_String__char_environment_fprintf_45.c | goodB2GSink                                                        | False  | True | 5   | CWE-134 | CallExpression | fprintf   | 93   | 0     | 21           | 1       |
| CWE134_Uncontrolled_Format_String__char_environment_fprintf_45.c | goodB2G                                                            | False  | True | 6   | CWE-134 | CallExpression | strlen    | 103  | 0     | 89           | 0       |
| CWE134_Uncontrolled_Format_String__char_environment_fprintf_45.c | goodB2G                                                            | False  | True | 7   | CWE-134 | CallExpression | strncat   | 109  | 0     | 89           | 0       |

---

### ❗️ 취약 코드

**문제점**:  
환경변수에서 입력된 문자열이 포맷 문자열로 사용되며, 사용자에 의해 `%x`, `%n` 등의 포맷 스트링이 포함될 경우 코드 실행 흐름을 제어하거나 메모리 누출 등의 취약점이 발생할 수 있음.

#### Source: `CWE134_Uncontrolled_Format_String__char_environment_fprintf_45.c:42`
```c
char * environment = GETENV(ENV_VARIABLE);
if (environment != NULL)
{
    /* POTENTIAL FLAW: Read data from an environment variable */
    strncat(data+dataLen, environment, 100-dataLen-1);
}
```

#### Sink: `CWE134_Uncontrolled_Format_String__char_environment_fprintf_45.c:26`
```c
fprintf(stdout, data); // ⚠ 포맷 문자열 지정 없음
```

### ✅ 개선 코드

**패치 위치**: `goodB2GSink()`
```c
fprintf(stdout, "%s\n", data); // ✅ 포맷 명시
```

**개선 방법**:
사용자 입력이 포함된 문자열을 출력할 때는 반드시 "포맷 문자열"을 명시해줘야 함
"fprintf(stdout, "%s", data);" 형태로 사용하면 포맷 스트링 인젝션 방지 가능

## 🧠 추가 분석 정보

슬라이서가 해당 코드에 대해 취약하다고 판단한 기준은 다음과 같이 예상됩니다.

### 🔎 탐지된 취약 슬라이스의 공통 특징

- `criterion`이 **`fprintf`**이며,
- 코드에서 포맷 문자열을 명시하지 않고 사용자 입력을 그대로 전달하는 경우:

```c
fprintf(stdout, data); // ⚠ 포맷 문자열 없음
```

이와 같은 패턴을 포함한 슬라이스 (idx = 0, idx = 3)는 모두 `label = 1`로 지정되어 있습니다.

즉, 슬라이서는 명확한 Sink(`fprintf`)와 포맷 문자열 미지정 상태를 취약 조건으로 판단하는 것으로 보입니다.

### ⚠ 탐지되지 않은 슬라이스 (`label = 0`)의 특징

`criterion`이 `strlen`, `strncat`, `strcpy` 등이고,

`GETENV()` 호출 또는 `data` 할당/전달만 존재하는 경우:

```c
char * environment = GETENV(ENV_VARIABLE);
if (environment != NULL)
    strncat(data+dataLen, environment, ...);
```

Sink 함수 호출이 직접 포함되지 않거나,

포맷 문자열이 명시된 경우 (`fprintf(stdout, "%s\n", data);`)는 모두 `label = 0` 처리되었습니다.

### 📌 정리

| 슬라이스 idx | 함수        | criterion | 내용 요약                   | label |
| :----------: | ----------- | :-------- | :-------------------------- | :----: |
|      0       | `badSink`   | `fprintf` | 포맷 문자열 없음            |   1    |
|      3       | `goodG2BSink` | `fprintf` | 고정된 문자열 사용, 포맷 없음 |   1    |
|      5       | `goodB2GSink` | `fprintf` | 포맷 문자열 있음 (`L"%s"`)  |   0    |
|   1, 2, 4, 6, 7  | 기타        | `strlen`, `strncat`, `strcpy` | Sink 없음 또는 흐름 불완전    |   0    |

### ✅ 시사점

슬라이서는 `fprintf()` 호출이 있고, 포맷 문자열이 명시되지 않은 경우에만 `label = 1`로 탐지하는 것으로 보입니다.

반대로, Source가 존재하더라도 Sink가 명시적으로 드러나지 않으면 탐지하지 못합니다.

또한, 안전한 형태로 포맷 문자열이 명시되어 있으면 `label = 0`으로 올바르게 처리됩니다.