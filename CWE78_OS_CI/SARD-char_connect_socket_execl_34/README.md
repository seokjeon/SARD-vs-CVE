# 📁 SARD-char_connect_socket_execl_34

**🔗 CWE 링크**: [CWE-78](https://cwe.mitre.org/data/definitions/78.html)

| 총 슬라이스 수 | 라벨 1 (취약) | 라벨 0 (정상) | 정탐 | 미탐 |
| -------- | --------- | --------- | -- | -- |
| 8개       | 7개        | 1개        | 7개 | 1개 |

## 용어 정의
- **Source**: 외부(사용자·네트워크) 입력이 코드에 유입되는 지점  
- **Trace**: 그 입력이 함수 호출·변수 대입을 거치며 어떻게 흘러가는지(데이터 전파 경로)  
- **Sink**: 검증되지 않은 입력이 실제로 위험한 함수(명령 실행, 파일 쓰기 등)에 사용돼 취약점을 일으키는 지점

## 🔍 취약점 설명
* **Source**: char_connect_socket()
* **취약 조건**: 입력값 검증 부재
* **Sink**: execl()

### 📁 관련 파일 소개

| 파일명       | 설명                      |
| --------- | ----------------------- |
| `CWE78_OS_Command_Injection__char_connect_socket_execl_34.c` | 사용자가 데이터를 입력하면 버퍼에 적재한뒤 셸에 버퍼주소를 인자로 전달하여 명령수행 |

---

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

**패치 위치**: `CWE78_OS_Command_Injection__char_connect_socket_execl_34.c:131`

```c
    /* === [추가] 허용 문자 검증 (화이트리스트) === */
    for (size_t i = dataLen; i < strlen(data); ++i) {
        char c = data[i];
        /* 영숫자, 점(.), 밑줄(_), 대시(-), 슬래시(/)만 허용 */
        if (!isalnum((unsigned char)c) &&
            c != '.' && c != '_' && c != '-' && c != '/')
        {
            fprintf(stderr, "Invalid character in input: '%c'\n", c);
            return;
        }
    }

    /* === [추가] 쉘 파싱 회피: execv 사용 === */
    char *argv[] = { COMMAND_INT, data + dataLen, NULL };
    /* COMMAND_INT_PATH 예: "/bin/ls", COMMAND_INT 예: "ls" */
    execv(COMMAND_INT_PATH, argv);

    /* 기존 execl 호출은 더 이상 사용하지 않습니다. */

```

**개선 방법**:

* 1. `화이트 리스트` : 사용자 입력 대신 미리 정의된 안전한 문자열을 사용하여, 명령어 인자로의 사용자 입력 전달을 차단함으로써 명령어 인젝션을 방지합니다.
* 2. `execv를 사용하여 셸 파싱 회피` : 지정한 경로의 하나의 프로그램만 실행되며, 문자열 전체를 셸이 파싱하지 않기에, 사용자 입력이 메타문자로 해석되어 추가 명령을 실행시키는 공격 벡터가 사라집니다.

