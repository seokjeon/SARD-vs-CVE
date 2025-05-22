# 📁 SARD-wchar_t_console_execl_53

> Juliet 테스트케이스의 wchar_t_console_execl_53 시나리오에서, 콘솔 입력을 검증 없이 execl() 함수에 전달하는 함수 체인(53a → 53b → 53c → 53d)으로 인해 발생한 명령어 인젝션(CWE-78) 취약점입니다.

## 🔍 취약점 개요

**취약점 종류**: [[CWE-78](https://cwe.mitre.org/data/definitions/78.html)] OS Command Injection

* **Source**: 외부에서 제어 가능한 콘솔 입력 (`fgetws`)
* **취약 조건**: 입력값 검증 부재
* **Sink**: 입력값을 검증하지 않고 `execl()`과 같은 명령 실행 함수에 사용

---

## 탐지 결과 요약

| 총 슬라이스 수 | KSignSlicer 라벨 1 (취약) | KSignSlicer 라벨 0 (정상) | AI 취약 탐지 | AI 정상 탐지 |
|----------------|---------------------------|----------------------------|---------------|---------------|
| 2개            | 0개                       | 2개                        | 0개           | 2개           |

Sink(`execl()` 함수) 관련 슬라이스는 1건 있었으나, **정상으로 탐지됨**

### ⚠️ 탐지 결과 문제점

현재 탐지 결과에서 모든 슬라이스가 정상(라벨 0)으로 판정되었으나, 이는 다음과 같은 기술적 한계로 인한 오탐으로 판단됩니다:

1. **슬라이싱 범위 불완전**
   - Sink(`execl()` 함수) 관련 슬라이스는 1건을 살펴보니, `fgetws`, `wcslen` 등 단일 호출만 포함하고, 실제 실행 함수(`execl`)는 포함되지 않음
   - 취약 동작이 발생하는 `53d.c`의 내용이 슬라이스에서 누락됨
   - 📄 근거: `slicer_result.json`의 idx:x 번째 슬라이스
      ```c
      fgetws(data + dataLen, (int)(100 - dataLen), stdin);
      ```

## 취약점 세부 사항

### 📁 관련 파일 소개 (파일이 한 개이면, 한 개에 대하여 작성하세요.)

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
---

### ✅ 개선 코드 (두 가지 이상의 개선 방법이 존재할 경우, 아래와 같이 #### 1, #### 2 형태로 번호를 붙여 모두 제시하세요.)
소스 코드의 good() or goodG2B() or goodB2G() 함수에 이미 패치 방식이 제시되어 있습니다. 새로운 패치를 제안하기보다는, 패치의 위치와 코드를 중심으로 설명해 주세요.

**패치 위치**: `CWE78_OS_Command_Injection__wchar_t_console_execl_53a.c:89`

```c
    wchar_t dataBuffer[100] = COMMAND_ARG2; //COMMAND_ARG2 = "ls "
    data = dataBuffer;
    wcscat(data, L"*.*"); // concat to "ls *.*" which means enumerate all files in cwd"
    CWE78_OS_Command_Injection__wchar_t_console_execl_53b_goodG2BSink(data);
```

**개선 방법**:

외부 콘솔 입력을 기반으로 명령을 실행하는 흐름을 제거하여 명령어 인젝션 가능성을 차단해야 합니다.

* 사용자 입력 대신 미리 정의된 고정 문자열을 사용하여, 명령 실행 함수(`execl`)에 전달되는 인자를 제어합니다.
* 필요 시 입력값을 허용된 형식으로 제한하거나, 위험한 인자를 포함하지 않도록 별도의 검증 절차를 적용할 수 있습니다.

---

## 탐지 결과

|FileName                                               |Caller                                                  |Source|Sink |idx|CWE-ID|category      |criterion|line|label|token_length|predict|
|-------------------------------------------------------|--------------------------------------------------------|------|-----|---|------|--------------|---------|----|-----|------------|-------|
|CWE78_OS_Command_Injection__wchar_t_console_execl_53a.c|CWE78_OS_Command_Injection__wchar_t_console_execl_53_bad|False |False|0  |CWE-78|CallExpression|wcslen   |55  |0    |98          |0      |
|CWE78_OS_Command_Injection__wchar_t_console_execl_53a.c|CWE78_OS_Command_Injection__wchar_t_console_execl_53_bad|False |False|1  |CWE-78|CallExpression|wcslen   |64  |0    |98          |0      |
