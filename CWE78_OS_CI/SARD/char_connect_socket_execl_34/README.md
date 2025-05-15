# 📁 SARD-char_connect_socket_execl_34

## 🔍 취약점 개요
* **취약점 종류**: [[CWE-78](https://cwe.mitre.org/data/definitions/78.html)] OS Command Injection
* **Source**: char_connect_socket()
* **취약 조건**: 입력값 검증 부재
* **Sink**: execl()

## 탐지 결과 요약
총 슬라이스 수: ８개
- KSignSlicer가
    - 라벨 1(취약)으로 계산: １개
    - 라벨 0(정상)으로 계산: ７개
- AI 모델이 
    - 취약으로 탐지: １개
    - 정상으로 탐지: ７개

### 탐지 결과

|FileName                                               |Caller                                                  |Source|Sink |idx|CWE-ID|category      |criterion|line|label|token_length|predict|
|-------------------------------------------------------|--------------------------------------------------------|------|-----|---|------|--------------|---------|----|-----|------------|-------|
| CWE78_OS_Command_Injection__char_connect_socket_execl_34.c | CWE78_OS_Command_Injection__char_connect_socket_execl_34_bad | False    | False  |     0 | CWE-78   | CallExpression | strlen      |     86 |       0 |            274 |         0 |
| CWE78_OS_Command_Injection__char_connect_socket_execl_34.c | CWE78_OS_Command_Injection__char_connect_socket_execl_34_bad | False    | False  |     1 | CWE-78   | CallExpression | socket      |     97 |       0 |            241 |         0 |
| CWE78_OS_Command_Injection__char_connect_socket_execl_34.c | CWE78_OS_Command_Injection__char_connect_socket_execl_34_bad | False    | False  |     2 | CWE-78   | CallExpression | memset      |    102 |       0 |            129 |         0 |
| CWE78_OS_Command_Injection__char_connect_socket_execl_34.c | CWE78_OS_Command_Injection__char_connect_socket_execl_34_bad | False    | False  |     3 | CWE-78   | CallExpression | connect     |    106 |       0 |            221 |         0 |
| CWE78_OS_Command_Injection__char_connect_socket_execl_34.c | CWE78_OS_Command_Injection__char_connect_socket_execl_34_bad | False    | False  |     4 | CWE-78   | CallExpression | recv        |    113 |       0 |            310 |         0 |
| CWE78_OS_Command_Injection__char_connect_socket_execl_34.c | CWE78_OS_Command_Injection__char_connect_socket_execl_34_bad | False    | False  |     5 | CWE-78   | CallExpression | strchr      |    121 |       0 |            302 |         0 |
| CWE78_OS_Command_Injection__char_connect_socket_execl_34.c | CWE78_OS_Command_Injection__char_connect_socket_execl_34_bad | False    | False  |     6 | CWE-78   | CallExpression | strchr      |    126 |       0 |            302 |         0 |
| CWE78_OS_Command_Injection__char_connect_socket_execl_34.c | goodG2B                                                      | False    | False  |     7 | CWE-78   | CallExpression | strcat      |    165 |       1 |             64 |         1 |

---

## 취약점 세부 사항

### ❗️ 취약 코드
**문제점**:
사용자 입력이 적절히 검증되지 않은 채로 `EXECL()` 함수의 4번째 인자 (COMMAND_ARG3) 로 사용되어 **명령어 인젝션**이 발생할 수 있음.

#### Source: `CWE78_OS_Command_Injection__char_connect_socket_execl_34.c:86-113`
```c
size_t dataLen = strlen(data);
/* POTENTIAL FLAW: Read data using a connect socket */
recvResult = recv(connectSocket,
                  data + dataLen,
                  100 - dataLen - 1,
                  0);

```

#### Trace: `CWE78_OS_Command_Injection__char_connect_socket_execl_34.c:144,63,146`
```c
myUnion.unionFirst = data;
// …
typedef union
{
    char * unionFirst;
    char * unionSecond;
}
// …
char * data = myUnion.unionSecond;

```

#### Sink: `CWE78_OS_Command_Injection__char_connect_socket_execl_34.c:149`
```c
/* POTENTIAL FLAW: Execute command without validating input */
EXECL(COMMAND_INT_PATH,
      COMMAND_INT_PATH,
      COMMAND_ARG1,
      data, // 전처리기 지시자에 의해 COMMAND_ARG3 가 data로 전환
      NULL);

```

### ✅ 개선 코드

**패치 위치**: `CWE78_OS_Command_Injection__char_connect_socket_execl_34.c:165`

```c
    /* 외부 입력을 제거하고, 고정된 문자열만을 명령 인자로 쓰도록 바꾼 */
    char dataBuffer[100] = COMMAND_ARG2; // "dir " 또는 "ls "
    data = dataBuffer;
    /* FIX: Append a fixed string to data (not user / external input) */
    strcat(data, "*.*");                // → data는 이제 "dir *.*" 또는 "ls *.*"
    myUnion.unionFirst = data;
    {
        char * data = myUnion.unionSecond;
        /* 여전히 execl을 쓰지만, data에 들어 있는 값은
           순수히 소스 코드에서 결정된 "*.*" 뿐이므로
           명령어 인젝션이 불가능 */
        EXECL(COMMAND_INT_PATH,
              COMMAND_INT_PATH,
              COMMAND_ARG1,
              COMMAND_ARG3,  // data, 즉 "dir *.*" 또는 "ls *.*"
              NULL);
    }


```

**개선 방법**:
* Source(입력 지점)에서 네트워크 코드를 통째로 제거하고, strcat(data, "\*.\*") 로 고정된 \*.\* 만을 덧붙임. execl 은 그대로 사용하지만, 이제 data 가 절대 변조되지 않으므로 인젝션 경로가 사라집니다. “사용자 제어 입력”을 완전히 배제하고 “코드에 박힌 상수만” 사용하는 게 이 패치의 내용입니다.
