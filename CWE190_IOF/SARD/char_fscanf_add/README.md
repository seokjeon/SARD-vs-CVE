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

### ❗️ 취약 코드
**문제점**:  
사용자 입력이 적절히 검증되지 않은 채로 `fscanf()` 함수로 읽어들인 값에 1을 더하면서, **char 타입 범위를 초과하여 정수 오버플로우가 발생**할 수 있음.

#### Source: `CWE190_Integer_Overflow__char_fscanf_add_01.c:21`
```c
fscanf (stdin, "%c", &data);
```

#### Sink: `CWE190_Integer_Overflow__char_fscanf_add_01.c:24`
```c
char result = data + 1;
printHexCharLine(result);
```

---

### ✅ 개선 코드

**패치 위치**: `CWE190_Integer_Overflow__char_fscanf_add_01.c:43`

```c
fscanf (stdin, "%c", &data);
/* FIX: Add a check to prevent an overflow from occurring */
if (data < CHAR_MAX)
{
    char result = data + 1;
    printHexCharLine(result);
}
else
{
    printLine("data value is too large to perform arithmetic safely.");
}
```

**개선 방법**:

* 사용자 입력 후, `data < CHAR_MAX` 조건을 검사하여 **덧셈 연산 전 오버플로우 가능성을 차단**함.
* 안전 조건을 만족하지 않으면 연산을 수행하지 않고 경고 메시지를 출력함으로써 프로그램이 안전하게 작동하도록 개선함.

---

## 🧠 추가 분석 정보

### 🔎 Slicer 추출 코드
```c
fscanf (stdin, "%c", &data);
```

- 이 코드는 두 슬라이스에서 공통적으로 등장하며, **토큰화된 결과**는 다음과 같습니다:
```
fscanf(stdin,STRING,&Var1);
```

- AI 입력 토큰 예시:
```
<s>, fscanf, (, stdin, ,, STRING, ,, &, Var, 1, ), ;, </s>
```

- 입력 토큰 길이: 11 (두 슬라이스 모두 동일)

---

### 📉 벡터 예측 요약

| idx | label | predict | 입력 길이 | 의미 |
|-----|-------|---------|------------|------|
| 0   | 0     | 0       | 11         | AI가 정상 코드로 판단함 |
| 1   | 0     | 0       | 11         | AI가 정상 코드로 판단함 |

- 두 슬라이스 모두 `label=0`, `predict=0`이므로,
  - **실제 CWE-190 위험이 있는 상황이지만**
  - AI는 이를 **정상 코드로 판단**하여 **미탐지**했음을 의미합니다.

---

## 🧪 개선 방향 제안

- 입력값이 산술 연산(`+1`)에 사용된다는 사실이 토큰 수준 벡터에는 **직접적으로 드러나지 않음**
- `fscanf` 자체는 위험하지 않으나, **후속 연산과 연결된 흐름**을 AI가 파악하지 못한 것으로 분석됨
- **데이터 흐름 기반의 정보(CFG/PDG) 추가**, 또는 **연산자를 포함한 문맥 강화 전처리** 필요
