# 📁 SARD-char_file_w32_spawnvp_34

**🔗 CWE 링크**: [CWE-78](https://cwe.mitre.org/data/definitions/78.html)

| 총 슬라이스 수 | 라벨 1 (취약) | 라벨 0 (정상) | 정탐 | 미탐 |
| -------- | --------- | --------- | -- | -- |
| 5개       | 1개        | 4개        | 1개 | 4개 |


## 🔍 취약점 설명
* **Source**: char_file
* **취약 조건**: 입력값 검증 부재
* **Sink**: w32_spawnvp


### ❗️ 취약 코드
**문제점**:
사용자 입력이 적절히 검증되지 않은 채로 `_spawnvp()` 함수의 인자로 사용되어 **명령어 인젝션**이 발생할 수 있음.

#### Source: `CWE78_OS_Command_Injection__char_file_w32_spawnvp_34.c:69`
```c
...
pFile = fopen(FILENAME, "r");
if (pFile != NULL){
    if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) /* POTENTIAL FLAW */
}
...
```

#### Sink: `CWE78_OS_Command_Injection__char_file_w32_spawnvp_34.c:87`
```c
#define COMMAND_ARG3 data
char *args[] = {COMMAND_INT_PATH, COMMAND_ARG1, COMMAND_ARG3, NULL};
_spawnvp(_P_WAIT, COMMAND_INT, args); /* POTENTIAL FLAW */
```

### ✅ 개선 코드

**패치 위치**: `CWE78_OS_Command_Injection__char_file_w32_spawnvp_34.c:104`

```c
char dataBuffer[100] = COMMAND_ARG2;
data = dataBuffer;
/* FIX: Append a fixed string to data (not user / external input) */
strcat(data, "*.*");
```

**개선 방법**:

* 사용자 입력 대신 미리 정의된 안전한 문자열을 사용하여, 명령어 인자로의 사용자 입력 전달을 차단함으로써 명령어 인젝션을 방지합니다.