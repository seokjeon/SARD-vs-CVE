# CWE-134: 비제어 포맷 문자열 (Uncontrolled Format String)

## 📌 개요  
CWE-134는 **사용자 입력값을 검증 없이 포맷 문자열로 사용하여, 프로그램 동작을 조작할 수 있는 취약점**입니다.  
이 취약점을 악용하면 공격자가 **메모리 덤프 유출, 임의 코드 실행, 시스템 크래시** 등을 유발할 수 있습니다.

## 🛠 주요 원인  
- 가변인자 포맷 함수의 입력값 검증 부족  
- `printf`와 같은 가변인자 포맷 함수는 포맷 문자열을 하드코딩하지 않으면 입력값을 포맷 문자열로 해석함  
- 사용자 입력값을 직접 `printf` 등의 첫 번째 인자로 사용  

## 📂 관련 파일  
이 디렉토리에는 CWE-134를 설명하는 예제 코드가 포함되어 있습니다.  

| 파일명 | 설명 |  
|--------|------|  
| `CWE134_Uncontrolled_Format_String__wchar_t_file_printf_63a.c` | 파일에서 입력을 받아 다른 함수로 전달하여 CWE-134 취약점을 포함할 수 있음 |  
| `CWE134_Uncontrolled_Format_String__wchar_t_file_printf_63b.c` | `wprintf` 함수의 사용 방식에 따라 CWE-134 발생 가능 |  

---

## 🚨 취약 코드 (BadSink)  
📌 **발생 위치**: `CWE134_Uncontrolled_Format_String__wchar_t_file_printf_63b.c`  
📌 **줄 번호**: `void CWE134_Uncontrolled_Format_String__wchar_t_file_printf_63b_badSink(wchar_t * * dataPtr)`  

아래 코드에서는 `wprintf` 함수를 사용할 때, **입력값을 검증 없이 포맷 문자열로 직접 사용**하여  
**포맷 문자열 공격(Format String Attack)**이 발생할 수 있습니다.  

```c
...

void CWE134_Uncontrolled_Format_String__wchar_t_file_printf_63b_badSink(wchar_t * * dataPtr)
{
    wchar_t * data = *dataPtr;
    /* POTENTIAL FLAW: Do not specify the format allowing a possible format string vulnerability */
    wprintf(data);
}

...
```

📌 **문제점**:  
- `wprintf(data);` 호출 시 `data` 값이 `%x %x %x %x` 등과 같은 포맷 문자열을 포함하면,  
  **스택 메모리 덤프 유출 또는 임의 코드 실행 위험**이 발생함.  
- `data`가 외부 입력(예: 파일에서 읽은 값)이라면 공격자가 이를 조작하여 **취약점 악용 가능**.  

---

## ✅ 개선 코드 (GoodSink - B2G)  
📌 **발생 위치**: `CWE134_Uncontrolled_Format_String__wchar_t_file_printf_63b.c`  
📌 **줄 번호**: `void CWE134_Uncontrolled_Format_String__wchar_t_file_printf_63b_goodB2GSink(wchar_t * * dataPtr)`  

📌 **설명**:  
B2G(**Bad Source to Good Sink**) 방식에서는 `data` 값이 사용자 입력일 수 있으므로,  
이를 포맷 문자열의 인자로 **명시적으로 지정하여 사용**합니다.  

```c
...

void CWE134_Uncontrolled_Format_String__wchar_t_file_printf_63b_goodB2GSink(wchar_t * * dataPtr)
{
    wchar_t * data = *dataPtr;
    /* FIX: Specify the format disallowing a format string vulnerability */
    wprintf(L"%s\n", data);
}

...
```

📌 **개선점**:  
- **포맷 문자열을 명시적으로 지정 (`L"%s\n"`)**  
- 입력값이 **포맷 문자열로 해석되지 않도록 제한**  
- **메모리 덤프 유출 및 임의 코드 실행 방지**  

---

## ✅ 개선 코드 (GoodSource - G2B)  
📌 **발생 위치**: `CWE134_Uncontrolled_Format_String__wchar_t_file_printf_63a.c`  
📌 **줄 번호**: `static void goodG2B()`  

📌 **설명**:  
G2B(**Good Source to Bad Sink**) 방식에서는 입력값을 **고정된 문자열로 설정**하여,  
포맷 문자열 취약점이 발생하지 않도록 방지합니다.  

```c
...

static void goodG2B()
{
    wchar_t * data;
    wchar_t dataBuffer[100] = L"";
    data = dataBuffer;
    /* FIX: Use a fixed string that does not contain a format specifier */
    wcscpy(data, L"fixedstringtest");
    CWE134_Uncontrolled_Format_String__wchar_t_file_printf_63b_goodG2BSink(&data);
}

...
```

📌 **개선점**:  
- `data` 값을 **고정된 문자열("fixedstringtest")**로 설정하여 안전성을 확보  
- 입력값이 **포맷 문자열을 포함할 가능성을 차단**  
- 프로그램의 **예측 가능성을 높여 공격 가능성 최소화**  