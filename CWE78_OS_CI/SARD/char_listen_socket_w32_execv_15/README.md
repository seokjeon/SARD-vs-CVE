# 📁 SARD-char_listen_socket_w32_execv_15

**🔗 CWE 링크**: [CWE-78](https://cwe.mitre.org/data/definitions/78.html)

| 총 슬라이스 수 | 라벨 1 (취약) | 라벨 0 (정상) | 정탐 | 미탐 |
| -------- | --------- | --------- | -- | -- |
| 8개       | 2개        | 6개        |2개 | 6개 |


## 🔍 취약점 설명
* **Source**: char_listen_socket()
* **취약 조건**: 입력값 검증 부재
* **Sink**: w32_execv()


### ❗️ 취약 코드
**문제점**:
사용자 입력이 적절히 검증되지 않은 채로 `EXECV()` 함수의 인자로 사용되어 **명령어 인젝션**이 발생할 수 있음.

#### Source: `CWE78_OS_Command_Injection__char_listen_socket_w32_execv_15.c:113`
```c
...
listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
if (bind(listenSocket, (struct sockaddr*)&service, sizeof(service)) == SOCKET_ERROR){break;}
if (listen(listenSocket, LISTEN_BACKLOG) == SOCKET_ERROR){break;}
acceptSocket = accept(listenSocket, NULL, NULL);
if (acceptSocket == SOCKET_ERROR){break;}
recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); /* POTENTIAL FLAW */
```

#### Sink: `CWE78_OS_Command_Injection__char_listen_socket_w32_execv_15.c:158`
```c
#define COMMAND_ARG3 data
...
char *args[] = {COMMAND_INT_PATH, COMMAND_ARG1, COMMAND_ARG3, NULL};
EXECV(COMMAND_INT_PATH, args); /* POTENTIAL FLAW */
```

### ✅ 개선 코드

**패치 위치**: `CWE78_OS_Command_Injection__char_listen_socket_w32_execv_15.c:180`

```c
static void goodG2B1() {
    switch(5) {
        default:
            strcat(data, "*.*");
            break;
    }
    char *args[] = {COMMAND_INT_PATH, COMMAND_ARG1, COMMAND_ARG3, NULL};
    EXECV(COMMAND_INT_PATH, args);
}
```

**개선 방법**:

* 사용자 입력 대신 미리 정의된 안전한 문자열을 사용하여, 명령어 인자로의 사용자 입력 전달을 차단함으로써 명령어 인젝션을 방지합니다.
* goodG2B2()는 goodG2B1()과 유사
