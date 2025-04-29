# CWE-190: Integer Overflow or Wraparound

## 📌 개요
CWE-190은 **정수 연산 시 값이 데이터 타입의 최대/최소 범위를 초과하여 잘못된 결과를 초래하는 취약점**입니다.  
이는 프로그램의 동작을 예측할 수 없게 만들거나, 악용될 경우 **보안 문제(예: 원격 코드 실행, 권한 상승)**를 초래할 수 있습니다.

## 🛠 주요 원인
- 데이터 타입의 한계 초과 (최대/최소값 초과)
- 연산 전 범위 확인 로직 부재
- 예상치 못한 큰 입력값 처리
- 복잡한 연산에서 데이터 크기 고려 부족

## 📂 관련 파일
이 디렉토리에는 CWE-190을 설명하는 예제 코드가 포함되어 있습니다.

| 파일명 | 설명 |
|--------|------|
| [`CWE190_Integer_Overflow__short_max_square_32.c`](./CWE190_Integer_Overflow__short_max_square_32.c) | `short` 타입 변수의 최대값을 제곱하여 오버플로우 발생 가능 |

---

## 🚨 취약 코드 (BadSink)
📌 **발생 위치**: [`CWE190_Integer_Overflow__short_max_square_32.c`](./CWE190_Integer_Overflow__short_max_square_32.c)  
📌 **줄 번호**: `void CWE190_Integer_Overflow__short_max_square_32_bad()`

아래 코드에서는 `short` 타입 변수에 **최대값(SHRT_MAX)**을 할당한 후,  
이를 제곱하는 과정에서 **오버플로우(Integer Overflow)**가 발생할 수 있습니다.

```c
...

void CWE190_Integer_Overflow__short_max_square_32_bad()
{
    short data;
    short *dataPtr1 = &data;
    short *dataPtr2 = &data;
    data = 0;
    {
        short data = *dataPtr1;
        /* POTENTIAL FLAW: Use the maximum size of the data type */
        data = SHRT_MAX;
        *dataPtr1 = data;
    }
    {
        short data = *dataPtr2;
        {
            /* POTENTIAL FLAW: if (data*data) > SHRT_MAX, this will overflow */
            short result = data * data;
            printIntLine(result);
        }
    }
}

...
```

📌 **문제점**:
- `data` 값이 `SHRT_MAX(= 32,767)`으로 설정됨.
- `data * data` 연산 시 **오버플로우 발생 가능** (`32,767 * 32,767 > 32,767`)
- 결과적으로 **잘못된 연산 결과를 반환하거나 프로그램이 크래시될 수 있음**.

---

## ✅ 개선 코드 (GoodSink - B2G)
📌 **발생 위치**: [`CWE190_Integer_Overflow__short_max_square_32.c`](./CWE190_Integer_Overflow__short_max_square_32.c)  
📌 **줄 번호**: `static void goodB2G()`

📌 **설명**:  
B2G(**Bad Source to Good Sink**) 방식에서는 `data` 값이 `SHRT_MAX`로 설정될 수 있지만,  
이를 **제곱하기 전에 값의 범위를 검증하여** 오버플로우가 발생하지 않도록 합니다.

```c
...

static void goodB2G()
{
    short data;
    short *dataPtr1 = &data;
    short *dataPtr2 = &data;
    data = 0;
    {
        short data = *dataPtr1;
        /* POTENTIAL FLAW: Use the maximum size of the data type */
        data = SHRT_MAX;
        *dataPtr1 = data;
    }
    {
        short data = *dataPtr2;
        /* FIX: Add a check to prevent an overflow from occurring */
        if (abs((long)data) <= (long)sqrt((double)SHRT_MAX))
        {
            short result = data * data;
            printIntLine(result);
        }
        else
        {
            printLine("data value is too large to perform arithmetic safely.");
        }
    }
}

...
```

📌 **개선점**:
- **연산 전 `data` 값이 안전한지 확인**  
  → `if (abs((long)data) <= (long)sqrt((double)SHRT_MAX))`
- 값이 안전한 경우에만 `data * data` 연산 수행  
- 오버플로우가 예상되면 `"data value is too large to perform arithmetic safely."` 메시지 출력

---

## ✅ 개선 코드 (GoodSource - G2B)
📌 **발생 위치**: [`CWE190_Integer_Overflow__short_max_square_32.c`](./CWE190_Integer_Overflow__short_max_square_32.c)  
📌 **줄 번호**: `static void goodG2B()`

📌 **설명**:  
G2B(**Good Source to Bad Sink**) 방식에서는 `data` 값을 **작은 숫자로 제한**하여  
오버플로우가 발생할 가능성을 제거합니다.

```c
...

static void goodG2B()
{
    short data;
    short *dataPtr1 = &data;
    short *dataPtr2 = &data;
    data = 0;
    {
        short data = *dataPtr1;
        /* FIX: Use a small, non-zero value that will not cause an overflow in the sinks */
        data = 2;
        *dataPtr1 = data;
    }
    {
        short data = *dataPtr2;
        {
            /* POTENTIAL FLAW: if (data*data) > SHRT_MAX, this will overflow */
            short result = data * data;
            printIntLine(result);
        }
    }
}

...
```

📌 **개선점**:
- `data` 값을 항상 **작은 값(2)으로 제한**하여 오버플로우 가능성을 제거
- `data * data` 연산을 수행해도 최대값을 초과하지 않도록 보장
- **예상치 못한 큰 입력값을 방지하여 안정적인 프로그램 동작 유지**
