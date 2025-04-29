# CWE-416: Use After Free

## 📌 개요
CWE-416은 **메모리를 해제(free)한 후에도 해당 메모리를 참조하거나 사용하는 경우** 발생하는 취약점입니다.  
이로 인해 **예측 불가능한 동작**이 발생할 수 있으며, 공격자가 해제된 메모리를 조작할 경우  
**원격 코드 실행(RCE) 및 시스템 권한 탈취** 등의 보안 문제가 발생할 수 있습니다.

## 🛠 주요 원인
- `free()` 호출 후 해제된 포인터를 잘못 참조
- 동적 메모리 관리 실수로 인해 해제된 메모리에 접근
- 논리 오류로 인해 메모리 재사용 시 적절한 초기화 없이 사용

## 📂 관련 파일
이 디렉토리에는 CWE-416을 설명하는 예제 코드가 포함되어 있습니다.

| 파일명 | 설명 |
|--------|------|
| [`CWE416_Use_After_Free__malloc_free_long_01.c`](./CWE416_Use_After_Free__malloc_free_long_01.c) | `free()`된 메모리를 참조하는 취약 코드 포함 |

---

## 🚨 취약 코드 (BadSink)
📌 **발생 위치**: [`CWE416_Use_After_Free__malloc_free_long_01.c`](./CWE416_Use_After_Free__malloc_free_long_01.c)  
📌 **줄 번호**: `void CWE416_Use_After_Free__malloc_free_long_01_bad()`

아래 코드에서는 `free(data)`를 호출한 후,  
해제된 메모리를 다시 사용하여 **Use-After-Free** 취약점이 발생합니다.

```c
...

void CWE416_Use_After_Free__malloc_free_long_01_bad()
{
    long * data;
    /* Initialize data */
    data = NULL;
    data = (long *)malloc(100*sizeof(long));
    if (data == NULL) {exit(-1);}
    {
        size_t i;
        for(i = 0; i < 100; i++)
        {
            data[i] = 5L;
        }
    }
    /* POTENTIAL FLAW: Free data in the source - the bad sink attempts to use data */
    free(data);
    /* POTENTIAL FLAW: Use of data that may have been freed */
    printLongLine(data[0]);  // Use-After-Free 발생
}

...
```

📌 **문제점**:
- `free(data);` 이후 `data[0]`을 참조하면서 **Use-After-Free** 취약점 발생
- 해제된 메모리를 접근하면 **런타임 오류** 발생 가능 (정상적인 데이터가 아닐 수도 있음)
- 공격자가 특정 데이터를 조작할 경우 **원격 코드 실행(RCE) 가능성** 존재

---

## ✅ 개선 코드 (GoodSink - B2G)
📌 **발생 위치**: [`CWE416_Use_After_Free__malloc_free_long_01.c`](./CWE416_Use_After_Free__malloc_free_long_01.c)  
📌 **줄 번호**: `static void goodB2G()`

📌 **설명**:  
B2G(**Bad Source to Good Sink**) 방식에서는 `free()` 이후  
데이터를 **사용하지 않음**으로써 Use-After-Free 문제를 해결합니다.

```c
...

static void goodB2G()
{
    long * data;
    /* Initialize data */
    data = NULL;
    data = (long *)malloc(100*sizeof(long));
    if (data == NULL) {exit(-1);}
    {
        size_t i;
        for(i = 0; i < 100; i++)
        {
            data[i] = 5L;
        }
    }
    /* POTENTIAL FLAW: Free data in the source - the bad sink attempts to use data */
    free(data);
    /* FIX: Don't use data that may have been freed already */
    /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
    /* do nothing */
    ; /* empty statement needed for some flow variants */
}

...
```

📌 **개선점**:
- `free(data)` 이후 `data`를 **더 이상 사용하지 않음**
- 프로그램이 **Use-After-Free 오류를 방지하도록 설계됨**

---

## ✅ 개선 코드 (GoodSource - G2B)
📌 **발생 위치**: [`CWE416_Use_After_Free__malloc_free_long_01.c`](./CWE416_Use_After_Free__malloc_free_long_01.c)  
📌 **줄 번호**: `static void goodG2B()`

📌 **설명**:  
G2B(**Good Source to Bad Sink**) 방식에서는 데이터를 해제(`free()`)하지 않음으로써  
`NULL`이 아닌 유효한 메모리를 계속 유지하여 **Use-After-Free 취약점을 방지**합니다.

```c
...

static void goodG2B()
{
    long * data;
    /* Initialize data */
    data = NULL;
    data = (long *)malloc(100*sizeof(long));
    if (data == NULL) {exit(-1);}
    {
        size_t i;
        for(i = 0; i < 100; i++)
        {
            data[i] = 5L;
        }
    }
    /* FIX: Do not free data in the source */
    /* POTENTIAL FLAW: Use of data that may have been freed */
    printLongLine(data[0]);
    /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
}

...
```

📌 **개선점**:
- `free(data);`를 호출하지 않음으로써 **해제된 메모리를 참조하는 문제 해결**
- 동적 메모리를 유지하여 **정상적인 데이터 접근이 가능하도록 보장**
- 단, `free()`를 호출하지 않으면 **메모리 누수(memory leak)** 가 발생할 수 있음  
  → 추가적으로 필요하지 않은 데이터는 프로그램이 종료되기 전에 적절히 해제해야 함
