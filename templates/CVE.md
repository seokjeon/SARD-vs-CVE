# 📁 CVE-2019-16718

**🔗 [커밋 링크](https://github.com/radareorg/radare2/commit/dd739f5a45b3af3d1f65f00fe19af1dbfec7aea7)** | **🔗 [CVE 링크](https://www.cvedetails.com/cve/CVE-2019-16718)**

| 총 슬라이스 수* |  정탐 | 미탐 |
| --------  | -- | -- |
| 2개       | 0개 | 2개 |

\* cve 설명에 나온 취약한 함수에 대한 슬라이스만 고려

## 🔍 취약점 설명
> 어떤 프로그램의 어떤 기능에 있는 어떤 함수에서 발생한 어떤 취약점입니다.

* **취약 조건**: (예: `free()` 호출 이후 해당 포인터 재사용)
* **취약 동작**: 입력값을 검증하지 않고 `system()` / `execl()` / 등의 위험한 함수 혹은 구문에 사용

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

## SARD와 탐지 결과 비교
KSignSlicer의 AI 모델은 SARD CWE78에 대해 이러한 경우 취약으로 탐지해왔습니다. 그런데 이 취약점은 이러 이러한 사유로 이렇게 탐지된 것으로 보입니다.