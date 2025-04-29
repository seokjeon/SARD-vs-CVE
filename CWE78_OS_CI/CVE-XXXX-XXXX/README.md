# CWE-78: OS 명령어 삽입 (OS Command Injection)

## 📌 개요  
CWE-78은 **운영 체제 명령어를 실행할 때 외부 입력값을 적절히 검증하지 않아**  
공격자가 악의적인 명령어를 삽입하거나 변조하여  
시스템에서 의도하지 않은 명령을 실행하도록 만드는 취약점입니다.

## 🛠 주요 원인  
- 외부 입력(사용자의 입력)을 그대로 사용  
- 입력 검증 부족 (특수 문자, 시스템 명령어)  

## 📂 관련 파일  
이 디렉토리에는 CWE-78을 설명하는 예제 코드가 포함되어 있습니다.

| 파일명 | 설명 |  
|--------|------|  
| `CWE78_OS_Command_Injection__wchar_t_console_execl_53a.c` | 데이터 초기화 후 전달 |  
| `CWE78_OS_Command_Injection__wchar_t_console_execl_53b.c` | 데이터 전달만 수행 |  
| `CWE78_OS_Command_Injection__wchar_t_console_execl_53c.c` | 데이터를 다음 단계로 넘겨 실행 취약점을 포함한 흐름 유지 |  
| `CWE78_OS_Command_Injection__wchar_t_console_execl_53d.c` | 입력 데이터 검증 여부에 따라 CWE-78 발생 |  

---

## 🚨 취약 코드 (BadSink)  
📌 **발생 위치**: `CWE78_OS_Command_Injection__wchar_t_console_execl_53d.c`  
📌 **줄 번호**: `void CWE78_OS_Command_Injection__wchar_t_console_execl_53d_badSink(wchar_t * data)`

아래 코드에서는 `wexecl` 함수를 사용할 때,  
**입력값을 검증 없이 명령어 인자로 직접 사용**하여  
**OS 명령어 삽입 취약점(Command Injection)이 발생**할 수 있습니다.

```c
...

void CWE78_OS_Command_Injection__wchar_t_console_execl_53d_badSink(wchar_t * data)
{
    /* wexecl - specify the path where the command is located */
    /* POTENTIAL FLAW: Execute command without validating input possibly leading to command injection */
    EXECL(COMMAND_INT_PATH, COMMAND_INT_PATH, COMMAND_ARG1, COMMAND_ARG3, NULL);
}

...
```

📌 **문제점**:  
- `COMMAND_ARG3`가 `data`를 포함하고 있으며, **사용자 입력값이 그대로 전달됨**  
- 공격자가 **명령어 삽입(payload injection)**을 수행할 수 있음  
  예: `& rm -rf /` 또는 `; cat /etc/passwd`  
- **임의 명령어 실행 위험**이 존재하여 시스템이 손상될 가능성이 큼  

---

## ✅ 개선 코드 (GoodSource - G2B)  
📌 **발생 위치**: `CWE78_OS_Command_Injection__wchar_t_console_execl_53a.c`  
📌 **줄 번호**: `static void goodG2B()`

📌 **설명**:  
G2B(**Good Source to Bad Sink**) 방식에서는 입력값을 **고정된 안전한 문자열로 설정**하여,  
명령어 삽입 취약점이 발생하지 않도록 방지합니다.

```c
...

static void goodG2B()
{
    wchar_t * data;
    wchar_t dataBuffer[100] = COMMAND_ARG2;
    data = dataBuffer;
    /* FIX: Append a fixed string to data (not user / external input) */
    wcscat(data, L"*.*");
    CWE78_OS_Command_Injection__wchar_t_console_execl_53b_goodG2BSink(data);
}

...
```

📌 **개선점**:  
- `data` 값을 **고정된 문자열("*.*")**로 설정하여 명령어 삽입 가능성을 차단  
- **사용자 입력이 개입하지 않도록 설계**  
- 프로그램의 **예측 가능성을 높여 공격 가능성 최소화**  
