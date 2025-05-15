# 📁 SARD-int_fgets_multiply_01

## 🔍 취약점 개요
* **취약점 종류**: [CWE-190](https://cwe.mitre.org/data/definitions/190.html) Integer Overflow or Wraparound
* **Source**: `fgets`로 문자열 입력 후 `atoi`를 통해 정수로 변환
* **취약 조건**: 사용자 입력이 음수가 아니면서도 너무 커서 곱셈 시 `int` 범위를 초과할 수 있음
* **Sink**: `data * 2`와 같은 산술 곱셈 연산

## 🔎 탐지 결과 요약

총 슬라이스 수: 4개  
- **KSignSlicer 라벨 분포**  
  - 라벨 1(취약): 0개  
  - 라벨 0(정상): 4개  
- **AI 모델 예측**  
  - 취약으로 탐지: 0개  
  - 정상으로 탐지: 4개

---

### 📊 탐지 결과 상세

| FileName                                           | Caller                                             | Source | Sink | idx | CWE-ID | category      | criterion | line | label | token_length | predict |
|----------------------------------------------------|----------------------------------------------------|--------|------|-----|--------|----------------|-----------|------|-------|---------------|---------|
| CWE190_Integer_Overflow__int_fgets_multiply_01.c   | CWE190_Integer_Overflow__int_fgets_multiply_01_bad | False  | False| 0   | CWE-190 | CallExpression | fgets     | 32   | 0     | 60            | 0       |
| CWE190_Integer_Overflow__int_fgets_multiply_01.c   | CWE190_Integer_Overflow__int_fgets_multiply_01_bad | False  | False| 1   | CWE-190 | CallExpression | atoi      | 35   | 0     | 102           | 0       |
| CWE190_Integer_Overflow__int_fgets_multiply_01.c   | goodB2G                                            | False  | False| 2   | CWE-190 | CallExpression | fgets     | 79   | 0     | 60            | 0       |
| CWE190_Integer_Overflow__int_fgets_multiply_01.c   | goodB2G                                            | False  | False| 3   | CWE-190 | CallExpression | atoi      | 82   | 0     | 116           | 0       |

---

### ❗️ 취약 코드
**문제점**:  
`fgets()`로 받은 문자열을 `atoi()`로 정수로 변환한 뒤, `data * 2` 연산을 수행하는데 **오버플로우 가능성을 고려하지 않음**

#### Source: `CWE190_Integer_Overflow__int_fgets_multiply_01.c:32`
```c
if (fgets(inputBuffer, CHAR_ARRAY_SIZE, stdin) != NULL)
{
    data = atoi(inputBuffer);
}
```

#### Sink: `CWE190_Integer_Overflow__int_fgets_multiply_01.c:45`
```c
int result = data * 2;
printIntLine(result);
```

---

### ✅ 개선 코드

**패치 위치**: `CWE190_Integer_Overflow__int_fgets_multiply_01.c:89`

```c
if(data > 0)
{
    if (data < (INT_MAX / 2))
    {
        int result = data * 2;
        printIntLine(result);
    }
    else
    {
        printLine("data value is too large to perform arithmetic safely.");
    }
}
```

**개선 방법**:

* 사용자 입력이 `INT_MAX / 2`보다 작을 경우에만 `data * 2` 연산을 수행
* 그 외에는 오버플로우 위험을 알리고 실행하지 않음

---

## 🧠 추가 분석 정보

### 🔎 Slicer 추출 예시
```c
int result = data * 2;
```
- 해당 코드 주변에서 슬라이스가 구성되며, 주요 흐름은 다음과 같음:
  - `fgets()` → `atoi()` → `data * 2`

- 토큰화 결과:
```
int Var1; char Var2[Var3] = STRING; if (fgets(...)) data = atoi(...); int result = data * 2;
```

---

### 📉 벡터 예측 요약

| idx | label | predict | token_length | 의미 |
|-----|-------|---------|---------------|------|
| 0   | 0     | 0       | 60            | 미탐지 (정상으로 판단) |
| 1   | 0     | 0       | 102           | 미탐지 |
| 2   | 0     | 0       | 60            | 미탐지 |
| 3   | 0     | 0       | 116           | 미탐지 |

---

## 🧪 개선 방향 제안

- `fgets` → `atoi` → 산술 곱셈이라는 흐름에서 실제 위험은 `data * 2`에 존재하나, 이 구조가 토큰 벡터 상에 명확히 반영되지 않음
- 산술 연산자와 상수 사용에 대한 의미 정보가 미흡함
- **타입 정보**, **값 크기 추론**, **문맥 기반 데이터 흐름 정보**를 강화하면 탐지율 개선 가능

