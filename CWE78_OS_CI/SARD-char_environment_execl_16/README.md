# 📁 SARD-char_environment_execl_16

**🔗 CWE 링크**: [CWE-78](https://cwe.mitre.org/data/definitions/78.html)

| 총 슬라이스 수 | 라벨 1 (취약) | 라벨 0 (정상) | 정탐 | 미탐 |
| -------- | --------- | --------- | -- | -- |
| 3개       | 1개        | 2개        | 1개 | 2개 |


## 🔍 취약점 설명
* **Source**: char_environment
* **취약 조건**: 입력값 검증 부재
* **Sink**: execl()

### ❗️ 취약 코드
**문제점**:
사용자 입력이 적절히 검증되지 않은 채로 `execl()` 함수의 인자로 사용되어 **명령어 인젝션**이 발생할 수 있음.

#### Source: `CWE78_OS_Command_Injection__char_environment_execl_16.c:68`
```c
...
char * environment = GETENV(ENV_VARIABLE);
if (environment != NULL){
    strncat(data+dataLen, environment, 100-dataLen-1); /* POTENTIAL FLAW */
}
...
```

#### Sink: `CWE78_OS_Command_Injection__char_environment_execl_16.c:75`
```c
#define COMMAND_ARG3 data
EXECL(COMMAND_INT_PATH, COMMAND_INT_PATH, COMMAND_ARG1, COMMAND_ARG3, NULL); /* POTENTIAL FLAW */
```

### ✅ 개선 코드

**패치 위치**: `CWE78_OS_Command_Injection__char_environment_execl_16.c:91`

```c
#define COMMAND_ARG2 "ls "
char dataBuffer[100] = COMMAND_ARG2;
data = dataBuffer;
...
strcat(data, "*.*");
```

**개선 방법**:

* 사용자 입력 대신 미리 정의된 안전한 문자열을 사용하여, 명령어 인자로의 사용자 입력 전달을 차단함으로써 명령어 인젝션을 방지합니다.