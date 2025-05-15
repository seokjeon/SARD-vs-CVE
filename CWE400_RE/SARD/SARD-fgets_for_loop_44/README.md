# 📁 SARD-fgets_for_loop_44

## 🔍 취약점 개요
* **취약점 종류**: [CWE-400](https://cwe.mitre.org/data/definitions/400.html) Resource Exhaustion
* **Source**: `fgets()`를 통한 사용자 입력
* **취약 조건**: 사용자 입력값에 대한 검증 없이 반복문의 반복 횟수로 사용
* **Sink**: for 루프에서 검증되지 않은 카운트 값 사용

## 탐지 결과 요약
* **총 슬라이스**: 4개
* **KSignSlicer 결과**:
  - 취약: 0개
  - 정상: 4개
* **AI 모델 결과**:
  - 취약: 0개
  - 정상: 4개

### ⚠️ 모든 슬라이스가 정상으로 판단된 원인 분석

1. **함수 포인터 추적의 한계**:
   - 코드 구조: 함수 포인터(`funcPtr`)를 통한 간접 호출 방식 사용
   ```c
   void (*funcPtr) (int) = badSink;
   // ... 중략 ...
   funcPtr(count);  // 간접 호출
   ```
   - 분석 한계:
     - 정적 분석 도구가 함수 포인터를 통한 호출 관계를 제대로 추적하지 못함
     - 실제 호출되는 함수(`badSink`)의 취약한 패턴을 인식하지 못함

2. **슬라이싱 범위 문제**:
   - 현재 슬라이스:
     ```
     fgets() → inputBuffer → atoi() → count
     ```
   - 누락된 중요 부분:
     ```
     count → funcPtr() → badSink() → for loop
     ```
   - 결과: 입력값이 실제로 위험하게 사용되는 부분까지 추적되지 않음

3. **취약점 패턴 분석의 불완전성**:
   - bad 함수의 실제 취약점:
     1) 외부 입력(`fgets`)으로부터 받은 값을 검증 없이
     2) 함수 포인터를 통해 전달하고
     3) for 루프의 반복 횟수로 사용
   
   - 탐지 실패 원인:
     - 함수 포인터로 인한 제어 흐름 추적 실패
     - 슬라이스가 입력 부분(`fgets`, `atoi`)에만 국한됨
     - for 루프에서의 위험한 사용까지 연결되지 않음

4. **개선이 필요한 부분**:
   - 정적 분석 강화:
     - 함수 포인터를 통한 호출 관계 추적
     - 제어 흐름과 데이터 흐름의 통합 분석
   
   - 취약점 패턴 인식 개선:
     - 간접 호출 패턴에 대한 분석 규칙 추가
     - 입력값의 최종 사용 지점까지 추적

이러한 분석의 한계로 인해, 실제로는 리소스 고갈 취약점이 존재하는 코드임에도 불구하고 모든 슬라이스가 정상(0)으로 판단되었습니다. 특히 함수 포인터를 통한 간접 호출 패턴이 분석의 주요 장애물로 작용했음을 알 수 있습니다.

### 탐지 결과
| 파일명 | 호출 함수 | Source | Sink | idx | CWE-ID | 카테고리 | 기준 | 라인 | 라벨 | 토큰 길이 | 예측 |
|--------|-----------|---------|------|-----|---------|-----------|------|------|------|-----------|------|
| CWE400_Resource_Exhaustion__fgets_for_loop_44.c | CWE400_Resource_Exhaustion__fgets_for_loop_44_bad | False | True | 0 | CWE-400 | CallExpression | fgets | 46 | 0 | 48 | 0 |
| CWE400_Resource_Exhaustion__fgets_for_loop_44.c | CWE400_Resource_Exhaustion__fgets_for_loop_44_bad | False | True | 1 | CWE-400 | CallExpression | atoi | 49 | 0 | 56 | 0 |
| CWE400_Resource_Exhaustion__fgets_for_loop_44.c | goodB2G | False | True | 2 | CWE-400 | CallExpression | fgets | 113 | 0 | 48 | 0 |
| CWE400_Resource_Exhaustion__fgets_for_loop_44.c | goodB2G | False | True | 3 | CWE-400 | CallExpression | atoi | 116 | 0 | 56 | 0 |

## 취약점 세부 사항
### 📁 관련 파일 소개
* `CWE400_Resource_Exhaustion__fgets_for_loop_44.c`: 리소스 소진 취약점을 포함한 테스트 케이스 파일

### ❗️ 취약 코드
**문제점**: 사용자로부터 입력받은 값을 검증 없이 반복문의 반복 횟수로 사용하여 리소스 소진 취약점 발생 가능

#### Source: `CWE400_Resource_Exhaustion__fgets_for_loop_44.c:46-49`
```c
/* 취약점: fgets()를 사용하여 사용자로부터 직접 입력을 받음 */
if (fgets(inputBuffer, CHAR_ARRAY_SIZE, stdin) != NULL)
{
    /* 문자열을 정수로 변환하여 반복 횟수로 사용 */
    count = atoi(inputBuffer);
}
```

#### Sink: `CWE400_Resource_Exhaustion__fgets_for_loop_44.c:24-27`
```c
/* 취약점: 사용자 입력값을 검증 없이 반복문의 반복 횟수로 사용 */
for (i = 0; i < (size_t)count; i++)
{
    /* 리소스를 소비하는 작업 수행 */
    printLine("Hello");
}
```

### ✅ 개선 코드
**개선 방법 1 - 입력값 검증**
**패치 위치**: `CWE400_Resource_Exhaustion__fgets_for_loop_44.c:89-96`

```c
/* 개선사항: 반복 횟수에 대한 유효성 검사 추가 */
if (count > 0 && count <= 20)
{
    /* 검증된 범위 내에서만 반복문 실행 */
    for (i = 0; i < (size_t)count; i++)
    {
        printLine("Hello");
    }
}
```

**개선 방법 2 - 안전한 기본값 사용**
**패치 위치**: `CWE400_Resource_Exhaustion__fgets_for_loop_44.c:77-86`

```c
/* 개선사항: 사용자 입력 대신 안전한 고정값 사용 */
int count;
void (*funcPtr) (int) = goodG2BSink;
/* 초기값 설정 */
count = -1;
/* 안전한 상수값으로 설정 */
count = 20;
funcPtr(count);
```

**개선 방법**:
* 방법 1: 입력값 검증
  - 반복 횟수에 대한 상한값(20)과 하한값(0) 설정
  - 입력값이 유효 범위 내에 있는지 검증 후 반복문 실행
  - 검증되지 않은 사용자 입력을 직접 사용하지 않음

* 방법 2: 안전한 기본값 사용
  - 사용자 입력을 받는 대신 안전한 고정값 사용
  - 컴파일 타임에 결정되는 상수값 활용
  - 입력 검증이 필요 없는 안전한 설계 채택 