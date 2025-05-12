# 📁 SARD-char_connect_socket_execl_34

**🔗 CWE 링크**: [CWE-78](https://cwe.mitre.org/data/definitions/78.html)

| 총 슬라이스 수 | 라벨 1 (취약) | 라벨 0 (정상) | 정탐 | 미탐 |
| -------- | --------- | --------- | -- | -- |
| 2개       | 0개        | 2개        | 0개 | 2개 |


## 🔍 취약점 설명
* **Source**: char_connect_socket()
* **취약 조건**: 입력값 검증 부재
* **Sink**: execl()

### 📁 관련 파일 소개

| 파일명       | 설명                      |
| --------- | ----------------------- |
| `CWE78_OS_Command_Injection__char_connect_socket_execl_34.c` | 데이터 입력 후 전달 |

---

### ❗️ 취약 코드
**문제점**:
사용자 입력이 적절히 검증되지 않은 채로 `execl()` 함수의 인자로 사용되어 **명령어 인젝션**이 발생할 수 있음.

#### Source: `CWE78_OS_Command_Injection__wchar_t_console_execl_53a.c:60`
```c
...
// 예시 취약 코드
if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) /* POTENTIAL FLAW */
...
CWE78_OS_Command_Injection__wchar_t_console_execl_53b_badSink(data);
```

#### Trace
```c
void CWE78_OS_Command_Injection__wchar_t_console_execl_53b_badSink(wchar_t * data)
{
    CWE78_OS_Command_Injection__wchar_t_console_execl_53c_badSink(data);
}
void CWE78_OS_Command_Injection__wchar_t_console_execl_53c_badSink(wchar_t * data)
{
    CWE78_OS_Command_Injection__wchar_t_console_execl_53d_badSink(data);
}
```

#### Sink: `CWE78_OS_Command_Injection__wchar_t_console_execl_53d.c:50`
```c
void CWE78_OS_Command_Injection__wchar_t_console_execl_53d_badSink(wchar_t * data)
{
    /* wexecl - specify the path where the command is located */
    /* POTENTIAL FLAW: Execute command without validating input possibly leading to command injection */
    EXECL(COMMAND_INT_PATH, COMMAND_INT_PATH, COMMAND_ARG1, COMMAND_ARG3, NULL);
}
```

### ✅ 개선 코드

**패치 위치**: `CWE78_OS_Command_Injection__wchar_t_console_execl_53a.c:89`

```c
    wchar_t dataBuffer[100] = COMMAND_ARG2; //COMMAND_ARG2 = "ls "
    data = dataBuffer;
    wcscat(data, L"*.*"); // concat to "ls *.*" which means enumerate all files in cwd"
    CWE78_OS_Command_Injection__wchar_t_console_execl_53b_goodG2BSink(data);
```

**개선 방법**:

* 사용자 입력 대신 미리 정의된 안전한 문자열을 사용하여, 명령어 인자로의 사용자 입력 전달을 차단함으로써 명령어 인젝션을 방지합니다.