# CWE-476: NULL Pointer Dereference

## 📌 개요
CWE-476은 **NULL 포인터 역참조**로 인해 발생하는 취약점입니다.  
프로그램이 `NULL` 값을 가진 포인터를 역참조하려고 하면 **런타임 오류**가 발생할 수 있으며,  
이는 **프로그램 크래시** 또는 **예측 불가능한 동작**을 유발할 수 있습니다.

## 🛠 주요 원인
- 포인터 변수 초기화 누락 또는 `NULL` 값 설정 후 사용
- 동적 메모리 할당 실패 후 `NULL` 반환 여부 미확인
- 코드 논리 오류로 인해 `NULL` 포인터를 참조하는 경우

## 📂 관련 파일
이 디렉토리에는 CWE-476을 설명하는 예제 코드가 포함되어 있습니다.

| 파일명 | 설명 |
|--------|------|
| [`CWE476_NULL_Pointer_Dereference__int64_t_52a.c`](./CWE476_NULL_Pointer_Dereference__int64_t_52a.c) | `NULL` 포인터를 전달하는 코드 (BadSource) |
| [`CWE476_NULL_Pointer_Dereference__int64_t_52b.c`](./CWE476_NULL_Pointer_Dereference__int64_t_52b.c) | 데이터를 전달만 수행 |
| [`CWE476_NULL_Pointer_Dereference__int64_t_52c.c`](./CWE476_NULL_Pointer_Dereference__int64_t_52c.c) | `NULL` 포인터를 역참조하는 코드 (BadSink) |

---

## 🚨 취약 코드 (BadSink)
📌 **발생 위치**: [`CWE476_NULL_Pointer_Dereference__int64_t_52c.c`](./CWE476_NULL_Pointer_Dereference__int64_t_52c.c)  
📌 **줄 번호**: `void CWE476_NULL_Pointer_Dereference__int64_t_52c_badSink(int64_t * data)`

아래 코드에서는 `data` 포인터가 `NULL`일 가능성이 있음에도 불구하고,  
이를 직접 역참조(`*data` 사용)하고 있어 **런타임 크래시**가 발생할 수 있습니다.

```c
...

void CWE476_NULL_Pointer_Dereference__int64_t_52c_badSink(int64_t * data)
{
    /* POTENTIAL FLAW: Attempt to use data, which may be NULL */
    printLongLongLine(*data);
}

...
```

📌 **문제점**:
- `data`가 `NULL`일 경우 `*data`를 참조하는 부분에서 **Segmentation Fault** 발생 가능
- `NULL` 포인터 체크 없이 직접 역참조하는 것이 문제

---

## ✅ 개선 코드 (GoodSink - B2G)
📌 **발생 위치**: [`CWE476_NULL_Pointer_Dereference__int64_t_52c.c`](./CWE476_NULL_Pointer_Dereference__int64_t_52c.c)  
📌 **줄 번호**: `void CWE476_NULL_Pointer_Dereference__int64_t_52c_goodB2GSink(int64_t * data)`

📌 **설명**:  
B2G(**Bad Source to Good Sink**) 방식에서는 데이터가 `NULL`로 설정될 가능성이 있지만,  
이를 역참조하기 전에 `NULL` 체크를 수행하여 안전한 방식으로 처리합니다.

```c
...

void CWE476_NULL_Pointer_Dereference__int64_t_52c_goodB2GSink(int64_t * data)
{
    /* FIX: Check for NULL before attempting to print data */
    if (data != NULL)
    {
        printLongLongLine(*data);
    }
    else
    {
        printLine("data is NULL");
    }
}

...
```

📌 **개선점**:
- `NULL` 포인터 여부를 확인 (`if (data != NULL)`)
- `NULL`일 경우 `"data is NULL"` 메시지를 출력하여 예외적인 상황을 처리
- **포인터 역참조 전에 검증을 수행함으로써 프로그램 크래시 방지**

---

## ✅ 개선 코드 (GoodSource - G2B)
📌 **발생 위치**: [`CWE476_NULL_Pointer_Dereference__int64_t_52a.c`](./CWE476_NULL_Pointer_Dereference__int64_t_52a.c)  
📌 **줄 번호**: `static void goodG2B()`

📌 **설명**:  
G2B(**Good Source to Bad Sink**) 방식에서는 **초기화된 데이터**를 사용하여  
`NULL` 포인터가 전달되지 않도록 보장합니다.

```c
...

static void goodG2B()
{
    int64_t * data;
    /* FIX: Initialize data */
    {
        int64_t tmpData = 5LL;
        data = &tmpData;
    }
    CWE476_NULL_Pointer_Dereference__int64_t_52b_goodG2BSink(data);
}

...
```

📌 **개선점**:
- `NULL` 포인터를 사용하지 않고, 항상 유효한 주소를 가진 변수를 전달
- `tmpData`를 선언하여 해당 주소를 `data` 포인터에 저장
- **초기화된 포인터를 사용하므로 `NULL` 역참조 문제가 발생하지 않음**