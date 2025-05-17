# 📁 SARD-connect_socket_fwrite_14

## 🔍 취약점 개요
* **취약점 종류**: [[CWE-400](https://cwe.mitre.org/data/definitions/400.html)] Resource Exhaustion (리소스 소진)
* **Source**: connect_socket을 통한 외부 입력 데이터
* **취약 조건**: 사용자 입력값에 대한 검증 없이 파일 쓰기 반복 횟수로 사용
* **Sink**: fwrite 함수를 통한 반복적인 파일 쓰기

## 탐지 결과 요약
총 슬라이스 수: 40개
- KSignSlicer가
    - 라벨 1(취약)으로 계산: 10개
    - 라벨 0(정상)으로 계산: 30개
- AI 모델이 
    - 취약으로 탐지: 15개
    - 정상으로 탐지: 25개

### ⚠️ 탐지 결과 차이 분석
KSignSlicer와 AI 모델의 탐지 결과가 다르게 나타난 원인을 분석한 결과:

1. **함수별 라벨링 패턴과 취약점 판단 기준**:
   - KSignSlicer의 판단:
     - `goodG2B1`/`goodG2B2` 함수만 취약(1)으로 라벨링
     - 이유: 안전한 상수값(20) 사용 → 이 값이 하드코딩된 것을 오히려 취약으로 판단
     - 반면 `goodB2G1`/`goodB2G2`는 정상(0)으로 라벨링 → 입력값 검증 로직 존재
   
   - AI 모델의 판단:
     - `bad` 함수의 파일 조작도 취약으로 탐지 → 더 정확한 판단
     - 근거: 
       1) 검증되지 않은 외부 입력값이 반복 횟수로 직접 사용됨
       2) 파일 조작 함수들(fopen, fwrite)이 반복문 내에서 호출됨
       3) 리소스 고갈 가능성이 있는 패턴 인식

2. **취약점 탐지 패턴의 차이**:
   - KSignSlicer:
     - 정적 규칙 기반 → 하드코딩된 값 사용을 오히려 취약으로 판단
     - 함수 단위 분석 → 전체 데이터 흐름 고려 부족
     - 예시: `count = 20;` 같은 하드코딩을 취약으로 판단
   
   - AI 모델:
     - 데이터 흐름 기반 → 입력부터 사용까지 전체 흐름 고려
     - 패턴 인식 → 리소스 고갈 취약점의 전형적인 패턴 학습
     - 예시: `recv() → atoi() → 미검증 사용` 패턴을 취약으로 인식

3. **함수 호출 컨텍스트 분석의 차이**:
   - KSignSlicer의 한계:
     - 단순 함수 호출 분석 → fwrite 호출 자체만 분석
     - 호출 컨텍스트 미고려 → 반복문 내 호출 여부 구분 못함
     - 결과: 동일한 fwrite 호출도 컨텍스트 따라 다르게 판단해야 하는데 실패
   
   - AI 모델의 강점:
     - 호출 컨텍스트 인식 → 반복문 내 호출 위험성 인지
     - 함수 조합 패턴 학습 → 특정 함수 조합이 취약점 가능성 높임을 학습
     - 결과: bad 함수의 위험한 패턴을 정확히 탐지

이러한 차이로 인해 AI 모델이 KSignSlicer보다 5개 더 많은 취약 케이스를 탐지했으며, 특히 `bad` 함수에서 발생할 수 있는 실제 리소스 고갈 취약점을 더 정확하게 식별했습니다. 이는 AI 모델이 단순한 규칙 기반 분석을 넘어, 코드의 맥락과 데이터 흐름을 종합적으로 고려할 수 있음을 보여줍니다.

### 탐지 결과
| 파일명 | 호출 함수 | Source | Sink | idx | CWE-ID | 카테고리 | 기준 | 라인 | 라벨 | 토큰 길이 | 예측 |
|--------|-----------|--------|------|-----|---------|-----------|------|------|------|-----------|------|
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | CWE400_Resource_Exhaustion__connect_socket_fwrite_14_bad | False | False | 0 | CWE-400 | CallExpression | socket | 72 | 0 | 198 | 0 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | CWE400_Resource_Exhaustion__connect_socket_fwrite_14_bad | False | False | 1 | CWE-400 | CallExpression | memset | 77 | 0 | 139 | 0 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | CWE400_Resource_Exhaustion__connect_socket_fwrite_14_bad | False | False | 2 | CWE-400 | CallExpression | connect | 81 | 0 | 188 | 0 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | CWE400_Resource_Exhaustion__connect_socket_fwrite_14_bad | False | False | 3 | CWE-400 | CallExpression | recv | 87 | 0 | 215 | 0 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | CWE400_Resource_Exhaustion__connect_socket_fwrite_14_bad | False | False | 4 | CWE-400 | CallExpression | atoi | 95 | 0 | 197 | 0 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | CWE400_Resource_Exhaustion__connect_socket_fwrite_14_bad | False | False | 5 | CWE-400 | CallExpression | fopen | 116 | 0 | 99 | 1 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | CWE400_Resource_Exhaustion__connect_socket_fwrite_14_bad | False | False | 6 | CWE-400 | CallExpression | strlen | 125 | 0 | 99 | 1 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | CWE400_Resource_Exhaustion__connect_socket_fwrite_14_bad | False | False | 7 | CWE-400 | CallExpression | fwrite | 125 | 0 | 99 | 1 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | CWE400_Resource_Exhaustion__connect_socket_fwrite_14_bad | False | False | 8 | CWE-400 | CallExpression | strlen | 125 | 0 | 99 | 1 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | CWE400_Resource_Exhaustion__connect_socket_fwrite_14_bad | False | False | 9 | CWE-400 | CallExpression | fclose | 132 | 0 | 99 | 1 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodB2G1 | False | False | 10 | CWE-400 | CallExpression | socket | 169 | 0 | 198 | 0 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodB2G1 | False | False | 11 | CWE-400 | CallExpression | memset | 174 | 0 | 139 | 0 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodB2G1 | False | False | 12 | CWE-400 | CallExpression | connect | 178 | 0 | 188 | 0 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodB2G1 | False | False | 13 | CWE-400 | CallExpression | recv | 184 | 0 | 215 | 0 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodB2G1 | False | False | 14 | CWE-400 | CallExpression | atoi | 192 | 0 | 215 | 0 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodB2G1 | False | False | 15 | CWE-400 | CallExpression | fopen | 221 | 0 | 117 | 0 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodB2G1 | False | False | 16 | CWE-400 | CallExpression | strlen | 228 | 0 | 117 | 0 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodB2G1 | False | False | 17 | CWE-400 | CallExpression | fwrite | 228 | 0 | 117 | 0 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodB2G1 | False | False | 18 | CWE-400 | CallExpression | strlen | 228 | 0 | 117 | 0 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodB2G1 | False | False | 19 | CWE-400 | CallExpression | fclose | 232 | 0 | 117 | 0 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodB2G2 | False | False | 20 | CWE-400 | CallExpression | socket | 266 | 0 | 198 | 0 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodB2G2 | False | False | 21 | CWE-400 | CallExpression | memset | 271 | 0 | 139 | 0 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodB2G2 | False | False | 22 | CWE-400 | CallExpression | connect | 275 | 0 | 188 | 0 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodB2G2 | False | False | 23 | CWE-400 | CallExpression | recv | 281 | 0 | 215 | 0 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodB2G2 | False | False | 24 | CWE-400 | CallExpression | atoi | 289 | 0 | 213 | 0 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodB2G2 | False | False | 25 | CWE-400 | CallExpression | fopen | 313 | 0 | 115 | 0 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodB2G2 | False | False | 26 | CWE-400 | CallExpression | strlen | 320 | 0 | 115 | 0 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodB2G2 | False | False | 27 | CWE-400 | CallExpression | fwrite | 320 | 0 | 115 | 0 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodB2G2 | False | False | 28 | CWE-400 | CallExpression | strlen | 320 | 0 | 115 | 0 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodB2G2 | False | False | 29 | CWE-400 | CallExpression | fclose | 324 | 0 | 115 | 0 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodG2B1 | False | False | 30 | CWE-400 | CallExpression | fopen | 353 | 1 | 99 | 1 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodG2B1 | False | False | 31 | CWE-400 | CallExpression | strlen | 362 | 1 | 99 | 1 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodG2B1 | False | False | 32 | CWE-400 | CallExpression | fwrite | 362 | 1 | 99 | 1 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodG2B1 | False | False | 33 | CWE-400 | CallExpression | strlen | 362 | 1 | 99 | 1 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodG2B1 | False | False | 34 | CWE-400 | CallExpression | fclose | 369 | 1 | 99 | 1 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodG2B2 | False | False | 35 | CWE-400 | CallExpression | fopen | 392 | 1 | 99 | 1 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodG2B2 | False | False | 36 | CWE-400 | CallExpression | strlen | 401 | 1 | 99 | 1 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodG2B2 | False | False | 37 | CWE-400 | CallExpression | fwrite | 401 | 1 | 99 | 1 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodG2B2 | False | False | 38 | CWE-400 | CallExpression | strlen | 401 | 1 | 99 | 1 |
| CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c | goodG2B2 | False | False | 39 | CWE-400 | CallExpression | fclose | 408 | 1 | 99 | 1 |

## 취약점 세부 사항
### 📁 관련 파일 소개
| 파일명 | 설명 |
|--------|------|
|`CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c`|소켓 통신을 통해 입력받은 값을 검증 없이 파일 쓰기 반복 횟수로 사용하는 취약한 코드|

### ❗️ 취약 코드 (BAD)
**문제점**:
소켓으로부터 받은 입력값을 적절한 검증 없이 파일 쓰기 반복 횟수로 사용하여 리소스 소진 취약점이 발생할 수 있습니다. 악의적인 사용자가 매우 큰 값을 입력할 경우 디스크 공간이 고갈될 수 있습니다.

#### Source (BAD): `CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c:72-95`
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

#### Sink (BAD): `CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c:115-133`
```c
FILE *pFile = NULL;
const char *filename = "output_bad.txt";

/* 파일 열기 */
pFile = fopen(filename, "w+");
if (pFile == NULL)
{
    exit(1);
}

/* 취약한 부분: count 값에 대한 검증 없이 파일 쓰기 반복
 * 사용자가 매우 큰 값을 입력할 경우 디스크 공간 고갈 가능성 있음 */
for (i = 0; i < (size_t)count; i++)
{
    if (strlen(SENTENCE) != fwrite(SENTENCE, sizeof(char), strlen(SENTENCE), pFile))
    {
        exit(1);
    }
}

/* 파일 닫기 */
if (pFile)
{
    fclose(pFile);
}
```

### ✅ 개선 코드 (GOOD)

#### 1. goodB2G1/goodB2G2 개선 방식
- Source는 BAD와 동일 (취약한 소켓 입력 사용)
- Sink에서 입력값 검증을 통해 개선

**패치 위치 (Sink)**: `CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c:220-233`
```c
FILE *pFile = NULL;
const char *filename = "output_good.txt";

/* 파일 열기 */
pFile = fopen(filename, "w+");
if (pFile == NULL)
{
    exit(1);
}

/* 개선된 부분: count 값의 범위를 검증하여 안전하게 처리
 * 1. count가 0보다 커야 함 (음수 방지)
 * 2. count가 20 이하여야 함 (과도한 파일 쓰기 방지)
 * 3. 조건을 만족하는 경우에만 파일 쓰기 실행 */
if (count > 0 && count <= 20)
{
    for (i = 0; i < (size_t)count; i++)
    {
        if (strlen(SENTENCE) != fwrite(SENTENCE, sizeof(char), strlen(SENTENCE), pFile))
        {
            exit(1);
        }
    }
}

/* 파일 닫기 */
if (pFile)
{
    fclose(pFile);
}
```

#### 2. goodG2B1/goodG2B2 개선 방식
- Source에서 안전한 값을 직접 할당하여 개선
- Sink는 BAD와 동일 (검증 없는 파일 쓰기 사용)

**패치 위치 (Source)**: `CWE400_Resource_Exhaustion__connect_socket_fwrite_14.c:340-343`
```c
/* 개선된 부분: 외부 입력 대신 안전한 상수값 사용
 * 1. 소켓 통신 제거
 * 2. 직접 안전한 값(20)을 할당하여 위험 요소 제거 */
count = 20;
```

**개선 방법 요약**:
* goodB2G1/goodB2G2: 입력값 검증을 통한 개선
  - 입력값 범위 제한: 0 < count <= 20
  - 조건을 만족하지 않는 경우 파일 쓰기 미실행
  - 소스 코드의 취약점은 그대로 두고 싱크에서 방어

* goodG2B1/goodG2B2: 안전한 입력값 사용
  - 외부 입력 제거
  - 안전한 상수값 직접 할당
  - 소스 코드 자체를 안전하게 수정 