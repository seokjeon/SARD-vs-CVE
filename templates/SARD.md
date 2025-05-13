# 📁 SARD-wchar_t_console_execl_53

## 🔍 취약점 개요
* **취약점 종류**: [[CWE-78](https://cwe.mitre.org/data/definitions/78.html)] OS Command Injection
* **Source**: wchar_t_console
* **취약 조건**: 입력값 검증 부재
* **Sink**: execl()

## 탐지 결과 요약
총 슬라이스 수: 2개
- KSignSlicer가
    - 라벨 1(취약)으로 계산: 0개
    - 라벨 0(정상)으로 계산: 2개
- AI 모델이 
    - 취약으로 탐지: 0개
    - 정상으로 탐지: 2개

### 탐지 결과

|FileName                                               |Caller                                                  |Source|Sink |idx|CWE-ID|category      |criterion|line|label|token_length|predict|
|-------------------------------------------------------|--------------------------------------------------------|------|-----|---|------|--------------|---------|----|-----|------------|-------|
|CWE78_OS_Command_Injection__wchar_t_console_execl_53a.c|CWE78_OS_Command_Injection__wchar_t_console_execl_53_bad|False |False|0  |CWE-78|CallExpression|wcslen   |55  |0    |98          |0      |
|CWE78_OS_Command_Injection__wchar_t_console_execl_53a.c|CWE78_OS_Command_Injection__wchar_t_console_execl_53_bad|False |False|1  |CWE-78|CallExpression|wcslen   |64  |0    |98          |0      |


## 취약점 세부 사항
### 📁 관련 파일 소개
파일 한개 면, 작성 안하셔도 됩니다.

| 파일명       | 설명                      |
| --------- | ----------------------- |
| `CWE78_OS_Command_Injection__wchar_t_console_execl_53a.c` | 데이터 입력 후 전달 |
| `CWE78_OS_Command_Injection__wchar_t_console_execl_53b.c` | 데이터 전달만 수행 |
| `CWE78_OS_Command_Injection__wchar_t_console_execl_53c.c` | 데이터를 다음 단계로 넘겨 실행 취약점을 포함한 흐름 유지 |
| `CWE78_OS_Command_Injection__wchar_t_console_execl_53d.c` | CWE-78 발생 |

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
없으면 제외 가능
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
    EXECL(COMMAND_INT_PATH, COMMAND_INT_PATH, COMMAND_ARG1, COMMAND_ARG3, NULL);  /* POTENTIAL FLAW */
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