# 📁 CVE-2019-16718

## 🔍 취약점 개요
**🔗 [커밋 링크](https://github.com/radareorg/radare2/commit/dd739f5a45b3af3d1f65f00fe19af1dbfec7aea7)** | **🔗 [CVE 링크](https://www.cvedetails.com/cve/CVE-2019-16718)** | **[취약점 종류: [CWE-78] OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)** 

> 어떤 프로그램의 어떤 기능에 있는 어떤 함수에서 발생한 어떤 취약점입니다.

* **취약 조건**: (예: `free()` 호출 이후 해당 포인터 재사용)
* **Sink**: 입력값을 검증하지 않고 `system()` / `execl()` / 등의 위험한 함수 혹은 구문에 사용

## 분석 결과 요약
cve 설명에 나온 취약한 함수(Caller)에 대한 슬라이스만 고려했을 때, 

| 총 슬라이스 수 |  취약으로 탐지 | 정상으로 탐지 |
| --------  | -- | -- |
| 48개       | 0개 | 48개 |

Sink(system() 함수) 관련 슬라이스는 1건 있었으나, 정상으로 탐지 됨.

\* cve 설명에 나온 취약한 함수(Caller) && Sink와 관련된 슬라이스 데이터만 추출

|FileName |Caller                |Source|Sink |idx|CWE-ID|category      |criterion|line|label|token_length|predict|
|---------|----------------------|------|-----|---|------|--------------|---------|----|-----|------------|-------|
|manager.c|add_server            |False |False|71 |CWE-  |CallExpression|system   |486 |-3   |67          |0      |

#### SARD는 잘 탐지하는데 이 CVE는 탐지 못했던 이유

AI 모델은 CWE-78의 경우 strcat() 함수가 슬라이스에 존재해야 취약으로 판단하는데, 이 취약점의 경우 system() 함수가 Sink이기에 정상으로 탐지된 것으로 보임.

### 탐지 결과
\* cve 설명에 나온 취약한 함수(Caller)에 대한 슬라이스 관련 데이터만 추출

|FileName |Caller                |Source|Sink |idx|CWE-ID|category      |criterion|line|label|token_length|predict|
|---------|----------------------|------|-----|---|------|--------------|---------|----|-----|------------|-------|
|manager.c|build_config          |False |False|0  |CWE-  |CallExpression|strlen   |98  |-3   |375         |0      |
|manager.c|build_config          |False |False|1  |CWE-  |CallExpression|strlen   |98  |-3   |375         |0      |
|manager.c|build_config          |False |False|2  |CWE-  |CallExpression|snprintf |101 |-3   |350         |0      |
|manager.c|build_config          |False |False|3  |CWE-  |CallExpression|fopen    |102 |-3   |375         |0      |
|manager.c|build_config          |False |False|4  |CWE-  |CallExpression|fprintf  |110 |-3   |338         |0      |
|manager.c|build_config          |False |False|5  |CWE-  |CallExpression|fprintf  |111 |-3   |359         |0      |
|manager.c|build_config          |False |False|6  |CWE-  |CallExpression|atoi     |111 |-3   |359         |0      |
|manager.c|build_config          |False |False|7  |CWE-  |CallExpression|fprintf  |112 |-3   |359         |0      |
|manager.c|build_config          |False |False|8  |CWE-  |CallExpression|fprintf  |113 |-3   |323         |0      |
|manager.c|build_config          |False |False|9  |CWE-  |CallExpression|fprintf  |114 |-3   |323         |0      |
|manager.c|build_config          |False |False|10 |CWE-  |CallExpression|fprintf  |115 |-3   |323         |0      |
|manager.c|build_config          |False |False|11 |CWE-  |CallExpression|fprintf  |116 |-3   |323         |0      |
|manager.c|build_config          |False |False|12 |CWE-  |CallExpression|fprintf  |117 |-3   |323         |0      |
|manager.c|build_config          |False |False|13 |CWE-  |CallExpression|fprintf  |118 |-3   |338         |0      |
|manager.c|build_config          |False |False|14 |CWE-  |CallExpression|fclose   |119 |-3   |338         |0      |
|manager.c|construct_command_line|False |False|15 |CWE-  |CallExpression|memset   |133 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|16 |CWE-  |CallExpression|snprintf |134 |-3   |957         |0      |
|manager.c|construct_command_line|False |False|17 |CWE-  |CallExpression|strlen   |140 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|18 |CWE-  |CallExpression|snprintf |141 |-3   |926         |0      |
|manager.c|construct_command_line|False |False|19 |CWE-  |CallExpression|strlen   |144 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|20 |CWE-  |CallExpression|snprintf |145 |-3   |926         |0      |
|manager.c|construct_command_line|False |False|21 |CWE-  |CallExpression|strlen   |149 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|22 |CWE-  |CallExpression|snprintf |150 |-3   |926         |0      |
|manager.c|construct_command_line|False |False|23 |CWE-  |CallExpression|strlen   |154 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|24 |CWE-  |CallExpression|snprintf |155 |-3   |926         |0      |
|manager.c|construct_command_line|False |False|25 |CWE-  |CallExpression|strlen   |158 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|26 |CWE-  |CallExpression|snprintf |159 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|27 |CWE-  |CallExpression|strlen   |162 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|28 |CWE-  |CallExpression|snprintf |163 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|29 |CWE-  |CallExpression|strlen   |166 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|30 |CWE-  |CallExpression|snprintf |167 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|31 |CWE-  |CallExpression|strlen   |170 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|32 |CWE-  |CallExpression|snprintf |171 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|33 |CWE-  |CallExpression|strlen   |174 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|34 |CWE-  |CallExpression|snprintf |175 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|35 |CWE-  |CallExpression|strlen   |178 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|36 |CWE-  |CallExpression|snprintf |179 |-3   |926         |0      |
|manager.c|construct_command_line|False |False|37 |CWE-  |CallExpression|strlen   |182 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|38 |CWE-  |CallExpression|snprintf |183 |-3   |926         |0      |
|manager.c|construct_command_line|False |False|39 |CWE-  |CallExpression|strlen   |186 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|40 |CWE-  |CallExpression|snprintf |187 |-3   |926         |0      |
|manager.c|construct_command_line|False |False|41 |CWE-  |CallExpression|strlen   |190 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|42 |CWE-  |CallExpression|snprintf |191 |-3   |926         |0      |
|manager.c|construct_command_line|False |False|43 |CWE-  |CallExpression|strlen   |194 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|44 |CWE-  |CallExpression|snprintf |195 |-3   |926         |0      |
|manager.c|construct_command_line|False |False|45 |CWE-  |CallExpression|strlen   |199 |-3   |904         |0      |
|manager.c|construct_command_line|False |False|46 |CWE-  |CallExpression|snprintf |200 |-3   |904         |0      |
|manager.c|add_server            |False |False|71 |CWE-  |CallExpression|system   |486 |-3   |67          |0      |


## 취약점 세부 사항

### 📁 관련 파일 소개
파일 한개 면, 작성 안하셔도 됩니다.

| 파일명       | 설명                      |
| --------- | ----------------------- |
| `CWE78_OS_Command_Injection__wchar_t_console_execl_53a.c` | 데이터 초기화 후 전달 |
| `CWE78_OS_Command_Injection__wchar_t_console_execl_53b.c` | 데이터 전달만 수행 |
| `CWE78_OS_Command_Injection__wchar_t_console_execl_53c.c` | 데이터를 다음 단계로 넘겨 실행 취약점을 포함한 흐름 유지 |
| `CWE78_OS_Command_Injection__wchar_t_console_execl_53d.c` | 입력 데이터 검증 여부에 따라 CWE-78 발생 |

---

### ❗️ 취약 코드

**문제점**:
사용자 입력이 적절히 검증되지 않은 채로 `system()` 함수의 인자로 사용되어 **명령어 인젝션**이 발생할 수 있음.


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

**패치 위치**: `파일명:줄번호`

```c
// 개선된 코드
char *input = getenv("USER_INPUT");
if (is_safe(input)) {
    system(input);
}
```

**개선 방법**:

* 입력값에 대해 필터링 또는 화이트리스트 검증을 추가하여 위험한 문자열을 제거
* 또는, `system()` 함수 대신 안전한 API 사용 고려