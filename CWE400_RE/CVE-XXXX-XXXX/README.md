# CWE-400: 리소스 고갈 (Resource Exhaustion)

## 📌 개요
CWE-400은 **CPU, 메모리, 디스크 공간, 네트워크 대역폭 등의 제한된 자원**을 과도하게 사용하여  
시스템 성능을 저하시킬 수 있는 취약점입니다.  
특히, 공격자가 **무제한 루프 실행, 과도한 파일 I/O, 네트워크 요청 과부하** 등의 방법을 이용하여  
서비스 거부 공격(DoS)을 유발할 가능성이 있습니다.

## 🛠 주요 원인
- 과도한 입력 처리
- 부적절한 요청 제한
- 입력 값 검증 부족
- 보호 메커니즘 미흡

## 📂 관련 파일
이 디렉토리에는 CWE-400을 설명하는 예제 코드가 포함되어 있습니다.

| 파일명 | 설명 |
|--------|------|
| [`CWE400_Resource_Exhaustion__rand_fwrite_64a.c`](./CWE400_Resource_Exhaustion__rand_fwrite_64a.c) | 랜덤 값으로 설정된 `count`를 다른 함수로 전달하여 CWE400 발생 가능 |
| [`CWE400_Resource_Exhaustion__rand_fwrite_64b.c`](./CWE400_Resource_Exhaustion__rand_fwrite_64b.c) | `count` 값 검증 여부에 따라 CWE400 취약점 발생 |

---

## 🚨 취약 코드 (BadSink)
📌 **발생 위치**: [`CWE400_Resource_Exhaustion__rand_fwrite_64b.c`](./CWE400_Resource_Exhaustion__rand_fwrite_64b.c)  
📌 **줄 번호**: `void CWE400_Resource_Exhaustion__rand_fwrite_64b_badSink(void * countVoidPtr)`

아래 코드에서는 `count`가 **랜덤 값**으로 설정되며,  
파일에 `count` 횟수만큼 문자열을 기록(`fwrite()`)하는 루프를 실행합니다.  
만약 `count` 값이 **비정상적으로 큰 숫자**라면 **리소스 고갈(Resource Exhaustion)** 문제가 발생할 수 있습니다.

```c
...

void CWE400_Resource_Exhaustion__rand_fwrite_64b_badSink(void * countVoidPtr)
{
    /* cast void pointer to a pointer of the appropriate type */
    int * countPtr = (int *)countVoidPtr;
    /* dereference countPtr into count */
    int count = (*countPtr);
    {
        size_t i = 0;
        FILE *pFile = NULL;
        const char *filename = "output_bad.txt";
        pFile = fopen(filename, "w+");
        if (pFile == NULL)
        {
            exit(1);
        }
        /* POTENTIAL FLAW: For loop using count as the loop variant and no validation
         * This can cause a file to become very large */
        for (i = 0; i < (size_t)count; i++)
        {
            if (strlen(SENTENCE) != fwrite(SENTENCE, sizeof(char), strlen(SENTENCE), pFile))
            {
                exit(1);
            }
        }
        if (pFile)
        {
            fclose(pFile);
        }
    }
}

...
```

📌 **문제점**:
- `count` 값이 검증 없이 사용됨 → **비정상적으로 큰 수**일 경우 리소스 고갈 발생
- `fwrite()`가 너무 많은 반복 실행 → **디스크 공간 부족, 성능 저하** 가능
- 프로그램이 **DoS 공격**에 악용될 위험 존재

---

## ✅ 개선 코드 (GoodSink - B2G)
📌 **발생 위치**: [`CWE400_Resource_Exhaustion__rand_fwrite_64b.c`](./CWE400_Resource_Exhaustion__rand_fwrite_64b.c)  
📌 **줄 번호**: `void CWE400_Resource_Exhaustion__rand_fwrite_64b_goodB2GSink(void * countVoidPtr)`

📌 **설명**:  
B2G(**Bad Source to Good Sink**) 방식에서는 `count`가 **랜덤 값**으로 설정될 수 있지만,  
파일에 기록하기 전에 **값을 검증**하여 적절한 범위 내에서만 사용하도록 보장합니다.

```c
...

void CWE400_Resource_Exhaustion__rand_fwrite_64b_goodB2GSink(void * countVoidPtr)
{
    /* cast void pointer to a pointer of the appropriate type */
    int * countPtr = (int *)countVoidPtr;
    /* dereference countPtr into count */
    int count = (*countPtr);
    {
        size_t i = 0;
        FILE *pFile = NULL;
        const char *filename = "output_good.txt";
        /* FIX: Validate count before using it as the for loop variant to write to a file */
        if (count > 0 && count <= 20)
        {
            pFile = fopen(filename, "w+");
            if (pFile == NULL)
            {
                exit(1);
            }
            for (i = 0; i < (size_t)count; i++)
            {
                if (strlen(SENTENCE) != fwrite(SENTENCE, sizeof(char), strlen(SENTENCE), pFile)) exit(1);
            }
            if (pFile)
            {
                fclose(pFile);
            }
        }
    }
}

...
```

📌 **개선점**:
- `count` 값이 **0보다 크고 20 이하인지 확인** (`if (count > 0 && count <= 20)`)
- 제한된 횟수만큼 파일에 기록하여 **리소스 고갈 방지**
- 프로그램의 **안정성을 유지하면서 DoS 공격 가능성을 차단**

---

## ✅ 개선 코드 (GoodSource - G2B)
📌 **발생 위치**: [`CWE400_Resource_Exhaustion__rand_fwrite_64a.c`](./CWE400_Resource_Exhaustion__rand_fwrite_64a.c)  
📌 **줄 번호**: `static void goodG2B()`

📌 **설명**:  
G2B(**Good Source to Bad Sink**) 방식에서는 `count` 값을 **작은 숫자로 제한**하여  
과도한 리소스 사용을 방지합니다.

```c
...

static void goodG2B()
{
    int count;
    /* Initialize count */
    count = -1;
    /* FIX: Use a relatively small number */
    count = 20;
    CWE400_Resource_Exhaustion__rand_fwrite_64b_goodG2BSink(&count);
}

...
```

📌 **개선점**:
- `count` 값을 **항상 20 이하**로 설정하여 무제한 루프 실행 방지
- 프로그램이 예측 가능한 동작을 하도록 보장
