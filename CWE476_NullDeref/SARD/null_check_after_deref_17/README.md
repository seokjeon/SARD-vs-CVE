## 📁 SARD-CWE476\_NULL\_Pointer\_Dereference\_\_null\_check\_after\_deref\_17

Juliet 테스트케이스의 CWE476\_NULL\_Pointer\_Dereference\_\_null\_check\_after\_deref\_17 시나리오에서, malloc으로 할당한 포인터를 역참조한 이후에 NULL 검사를 수행하는 흐름으로 인해 발생하는 NULL 포인터 역참조(CWE-476) 취약점입니다.

---

### 🔍 취약점 개요

취약점 종류: \[CWE-476] NULL Pointer Dereference

* **Source**: malloc
* **취약 조건**: 포인터를 역참조한 후에 NULL 확인을 수행
* **Sink**: NULL 여부를 확인한 뒤 재역참조 수행

---

### 탐지 결과 요약

| 총 슬라이스 수 | KSignSlicer 라벨 1 (취약) | KSignSlicer 라벨 0 (정상) | AI 취약 탐지 | AI 정상 탐지 |
| -------- | --------------------- | --------------------- | -------- | -------- |
| 2개       | 1개                    | 1개                    | 1개       | 1개       |

* `CWE476_NULL_Pointer_Dereference__null_check_after_deref_17_bad()` 함수에서 발생한 취약 흐름이 슬라이스에 포함되어 있으며, 하나는 정탐(라벨 1), 하나는 정상 코드(라벨 0)으로 탐지됨

---

### ⚠️ 탐지 결과 문제점

* 일부 슬라이스에서 취약 흐름이 포함되어 있음에도 **AI 예측 정확도가 완벽하진 않음**
* 다만 `idx:0` 슬라이스는 AI와 수작업 모두 취약으로 올바르게 탐지하여 정탐 성공
* `malloc()` 결과에 대한 NULL 체크가 **역참조 이후**에 등장한다는 점에서 **불필요한 방어 코드** 패턴임

📄 근거: `slicer_result.json`의 `idx:0` 슬라이스

```c
intPointer = (int *)malloc(sizeof(int));
*intPointer = 5;             // 역참조 발생
if (intPointer != NULL)      // 의미 없는 NULL 체크
    *intPointer = 10;        // 재역참조
```

---

### 취약점 세부 사항

#### 📁 관련 파일 소개

| 파일명                                                                   | 설명                                                  |
| --------------------------------------------------------------------- | --------------------------------------------------- |
| CWE476\_NULL\_Pointer\_Dereference\_\_null\_check\_after\_deref\_17.c | malloc 결과 포인터를 역참조한 뒤에 NULL 체크를 수행하는 취약 흐름을 포함하고 있음 |

---

### ❗️ 취약 코드

문제점: `malloc()`으로 메모리를 할당받은 후 포인터를 역참조한 다음, 그 이후에 `NULL` 여부를 확인하는 잘못된 방어적 코드

📄 Source: CWE476\_NULL\_Pointer\_Dereference\_\_null\_check\_after\_deref\_17.c:25

```c
intPointer = (int *)malloc(sizeof(int));
*intPointer = 5;
printIntLine(*intPointer);
if (intPointer != NULL) {
    *intPointer = 10;
}
printIntLine(*intPointer);
```

→ `malloc()` 실패 시 `*intPointer = 5`에서 이미 프로그램 크래시 발생
→ 이후 NULL 체크는 무의미하며 논리적 결함을 유도함

---

### ✅ 개선 코드



📍 패치 위치: CWE476\_NULL\_Pointer\_Dereference\_\_null\_check\_after\_deref\_17.c:43

```c
intPointer = (int *)malloc(sizeof(int));
*intPointer = 5;
printIntLine(*intPointer);
*intPointer = 10;
printIntLine(*intPointer);
```

#### 개선 방법:

* 사용자 입력 또는 동적 메모리 할당 후 **역참조 전에만** NULL 여부를 검사하도록 흐름 설계
* 이미 역참조한 이후의 NULL 체크는 의미가 없으며 잘못된 방어 코드로 간주됨

---

### 탐지 결과

| FileName                                                              | Caller                                                                   | Source | Sink  | idx | CWE-ID  | category       | criterion | line | label | token\_length | predict |
| --------------------------------------------------------------------- | ------------------------------------------------------------------------ | ------ | ----- | --- | ------- | -------------- | --------- | ---- | ----- | ------------- | ------- |
| CWE476\_NULL\_Pointer\_Dereference\_\_null\_check\_after\_deref\_17.c | CWE476\_NULL\_Pointer\_Dereference\_\_null\_check\_after\_deref\_17\_bad | False  | False | 0   | CWE-476 | CallExpression | malloc    | 25   | 1     | N/A           | 1       |
| CWE476\_NULL\_Pointer\_Dereference\_\_null\_check\_after\_deref\_17.c | good1                                                                    | False  | False | 1   | CWE-476 | CallExpression | malloc    | 43   | 0     | N/A           | 0       |


