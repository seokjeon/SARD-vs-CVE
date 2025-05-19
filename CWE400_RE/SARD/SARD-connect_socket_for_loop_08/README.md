# 📁 SARD-connect_socket_for_loop_08

## 🔍 취약점 개요
* **취약점 종류**: [[CWE-400](https://cwe.mitre.org/data/definitions/400.html)] Resource Exhaustion (리소스 소진)
* **Source**: connect_socket을 통한 외부 입력 데이터
* **취약 조건**: 사용자 입력값에 대한 검증 없이 for 루프의 반복 횟수로 사용
* **Sink**: for 루프 내의 printLine 함수 반복 호출

## 탐지 결과 요약
총 슬라이스 수: 14개
- KSignSlicer가
    - 라벨 1(취약)으로 계산: 0개
    - 라벨 0(정상)으로 계산: 14개
- AI 모델이 
    - 취약으로 탐지: 0개
    - 정상으로 탐지: 14개

### 탐지 결과

|FileName|Caller|Source|Sink|idx|CWE-ID|category|criterion|line|label|token_length|predict|
|--------|------|------|----|----|------|--------|---------|----|----|------------|-------|
|CWE400_Resource_Exhaustion__connect_socket_for_loop_08.c|CWE400_Resource_Exhaustion__connect_socket_for_loop_08_bad|False|False|0|CWE-400|CallExpression|socket|83|0|197|0|
|CWE400_Resource_Exhaustion__connect_socket_for_loop_08.c|CWE400_Resource_Exhaustion__connect_socket_for_loop_08_bad|False|False|1|CWE-400|CallExpression|memset|88|0|138|0|
|CWE400_Resource_Exhaustion__connect_socket_for_loop_08.c|CWE400_Resource_Exhaustion__connect_socket_for_loop_08_bad|False|False|2|CWE-400|CallExpression|connect|92|0|187|0|
|CWE400_Resource_Exhaustion__connect_socket_for_loop_08.c|CWE400_Resource_Exhaustion__connect_socket_for_loop_08_bad|False|False|3|CWE-400|CallExpression|recv|98|0|214|0|
|CWE400_Resource_Exhaustion__connect_socket_for_loop_08.c|CWE400_Resource_Exhaustion__connect_socket_for_loop_08_bad|False|False|4|CWE-400|CallExpression|atoi|106|0|195|0|
|CWE400_Resource_Exhaustion__connect_socket_for_loop_08.c|goodB2G1|False|False|5|CWE-400|CallExpression|socket|165|0|197|0|
|CWE400_Resource_Exhaustion__connect_socket_for_loop_08.c|goodB2G1|False|False|6|CWE-400|CallExpression|memset|170|0|138|0|
|CWE400_Resource_Exhaustion__connect_socket_for_loop_08.c|goodB2G1|False|False|7|CWE-400|CallExpression|connect|174|0|187|0|
|CWE400_Resource_Exhaustion__connect_socket_for_loop_08.c|goodB2G1|False|False|8|CWE-400|CallExpression|recv|180|0|214|0|
|CWE400_Resource_Exhaustion__connect_socket_for_loop_08.c|goodB2G1|False|False|9|CWE-400|CallExpression|atoi|188|0|213|0|
|CWE400_Resource_Exhaustion__connect_socket_for_loop_08.c|goodB2G2|False|False|10|CWE-400|CallExpression|socket|251|0|197|0|
|CWE400_Resource_Exhaustion__connect_socket_for_loop_08.c|goodB2G2|False|False|11|CWE-400|CallExpression|memset|256|0|138|0|
|CWE400_Resource_Exhaustion__connect_socket_for_loop_08.c|goodB2G2|False|False|12|CWE-400|CallExpression|connect|260|0|187|0|
|CWE400_Resource_Exhaustion__connect_socket_for_loop_08.c|goodB2G2|False|False|13|CWE-400|CallExpression|recv|266|0|214|0|

## 취약점 세부 사항
### 📁 관련 파일 소개
| 파일명 | 설명 |
|--------|------|
|`CWE400_Resource_Exhaustion__connect_socket_for_loop_08.c`|소켓 통신을 통해 입력받은 값을 검증 없이 반복문에 사용하는 취약한 코드|

---

### ❗️ 취약 코드 (BAD)
**문제점**:
소켓으로부터 받은 입력값을 적절한 검증 없이 for 루프의 반복 횟수로 사용하여 리소스 소진 취약점이 발생할 수 있습니다. 악의적인 사용자가 매우 큰 값을 입력할 경우 시스템 자원이 고갈될 수 있습니다.

#### Source (BAD): `CWE400_Resource_Exhaustion__connect_socket_for_loop_08.c:83-106`
```c
/* 취약한 부분: 소켓을 통해 count 값을 읽어옴 */
connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
if (connectSocket == INVALID_SOCKET)
{
    break;
}
/* 서비스 구조체 초기화 */
memset(&service, 0, sizeof(service));
service.sin_family = AF_INET;
service.sin_addr.s_addr = inet_addr(IP_ADDRESS);
service.sin_port = htons(TCP_PORT);

/* 서버에 연결 시도 */
if (connect(connectSocket, (struct sockaddr*)&service, sizeof(service)) == SOCKET_ERROR)
{
    break;
}

/* 소켓으로부터 데이터 수신
 * 버퍼 오버플로우 방지를 위해 마지막 문자 하나를 여유로 둠 */
recvResult = recv(connectSocket, inputBuffer, CHAR_ARRAY_SIZE - 1, 0);
if (recvResult == SOCKET_ERROR || recvResult == 0)
{
    break;
}

/* 문자열 종료 처리 */
inputBuffer[recvResult] = '\0';

/* 문자열을 정수로 변환 - 검증 없이 변환하는 것이 취약점 */
count = atoi(inputBuffer);
```

#### Sink (BAD): `CWE400_Resource_Exhaustion__connect_socket_for_loop_08.c:143-148`
```c
size_t i = 0;
/* 취약한 부분: count 값에 대한 검증 없이 반복문 실행
 * 사용자가 매우 큰 값을 입력할 경우 시스템 자원 고갈 가능성 있음 */
for (i = 0; i < (size_t)count; i++)
{
    printLine("Hello");
}
```

### ✅ 개선 코드 (GOOD)

#### 1. goodB2G1/goodB2G2 개선 방식
- Source는 BAD와 동일 (취약한 소켓 입력 사용)
- Sink에서 입력값 검증을 통해 개선

**패치 위치 (Sink)**: `CWE400_Resource_Exhaustion__connect_socket_for_loop_08.c:215-225`
```c
size_t i = 0;
/* 개선된 부분: count 값의 범위를 검증하여 안전하게 처리
 * 1. count가 0보다 커야 함 (음수 방지)
 * 2. count가 20 이하여야 함 (과도한 반복 방지)
 * 3. 조건을 만족하는 경우에만 반복문 실행 */
if (count > 0 && count <= 20)
{
    for (i = 0; i < (size_t)count; i++)
    {
        printLine("Hello");
    }
}
```

#### 2. goodG2B1/goodG2B2 개선 방식
- Source에서 안전한 값을 직접 할당하여 개선
- Sink는 BAD와 동일 (검증 없는 반복문 사용)

**패치 위치 (Source)**: `CWE400_Resource_Exhaustion__connect_socket_for_loop_08.c:315-318`
```c
/* 개선된 부분: 외부 입력 대신 안전한 상수값 사용
 * 1. 소켓 통신 제거
 * 2. 직접 안전한 값(20)을 할당하여 위험 요소 제거 */
count = 20;
```

**개선 방법 요약**:
* goodB2G1/goodB2G2: 입력값 검증을 통한 개선
  - 입력값 범위 제한: 0 < count <= 20
  - 조건을 만족하지 않는 경우 반복문 미실행
  - 소스 코드의 취약점은 그대로 두고 싱크에서 방어

* goodG2B1/goodG2B2: 안전한 입력값 사용
  - 외부 입력 제거
  - 안전한 상수값 직접 할당
  - 소스 코드 자체를 안전하게 수정 