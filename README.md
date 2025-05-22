# SARD-vs-CVE
AI가 SARD는 잘 탐지하지만 CVE는 놓치는 이유를 분석하기 위해 두 데이터를 비교합니다.

## 목차
1. [목표 산출물](#목표-산출물)
2. [절차](#절차)
   - [환경 준비](#환경-준비)
   - [vuln_src.c 선별](#vuln_srcc-선별)
     - [SARD의 경우](#sard의-경우)
     - [CVE의 경우](#cve의-경우)
   - [AI 취약점 탐지 결과물 수집](#ai-취약점-탐지-결과물-수집)
     - [분석 관련 FAQ](#분석-관련-faq)
   - [AI 취약점 탐지 결과물 분석](#ai-취약점-탐지-결과물-분석)
   - [README.md 작성 가이드](#readmemd-작성-가이드)
3. [기여 방법](#기여-방법)
4. [문의 사항](#문의-사항)

## 목표 산출물
CWE별로 CVE와 SARD를 각각 3개 씩 선정하여 다음 형식으로 정리합니다.

```
/CWE134_FSB/
├── CVE-2021-1234/
│   ├── before_{원본 파일명}.c            # 패치 전/후 diff가 있는 파일에만 before_, after_ 접두어를 붙여서 업로드
│   ├── after_{원본 파일명}.c
│   ├── CVE-2021-1234.diff              # 이왕이면 git diff
│   ├── README.md
│   ├── slicer_result.json
│   ├── slicer_result.symbolized.json
│   ├── test_output.csv
│   └── vectors.json
└── SARD
    ├── README.md                       # CWE에 대한 AI의 전반적인 취약점 탐지 경향을 적어주세요
    ├── vectors.json
    ├── slicer_result.json
    ├── slicer_result.symbolized.json
    ├── test_output.csv
    ├── wchar_t_file_printf_63/
    │   ├── {원본 파일명}.c
    │   ├── README.md
    │   ├── test_output.csv
    │   ├── slicer_result.json
    │   ├── slicer_result.symbolized.json
    │   └── vectors.json
    └── short_max_square_32/
        ├── {원본 파일명}.c
        ├── README.md
        ├── slicer_result.json
        ├── slicer_result.symbolized.json
        ├── test_output.csv
        └── vectors.json
```

## 절차
### 환경 준비
먼저 [KSignSlicer](https://github.com/seokjeon/KSignSlicer) 동작 환경을 준비하십시오. 

특히, **모델 학습이 반드시 선행되어 있어야** test_output.csv 추출이 가능합니다.

※ KSignSlicer 저장소 권한이 필요한 경우, 담당자(sojeon@jnu.ac.kr)에게 **GitHub 사용자명과 함께 요청**해 주시기 바랍니다.

### vuln_src.c 선별
#### 분석할 취약점 선택 방법
##### SARD의 경우
- 할당 받은 CWE 중 [SARD Juliet C/C++ 1.3](https://samate.nist.gov/SARD/test-suites/112)에서 해당 CWE 코드 3개 선택
  
※ KSign 영상 자료인 '합본) 모델 설계'와의 버전 호환을 위해, 최신 버전(v1.3.1 with extra support)이 아닌 v1.3 버전을 사용

##### CVE의 경우
- 할당 받은 CWE 중 [BigVul](https://huggingface.co/datasets/bstee615/bigvul)에서 CVE 3개 자유롭게 선택
- 빠른 작업을 위해 [BigVul에서 CWE 별 CVE 3개씩 추천](https://huggingface.co/datasets/bstee615/bigvul/viewer?views%5B%5D=train&sql=%28SELECT+*+FROM+train+WHERE+%22CWE+ID%22+%3D+%27CWE-134%27+LIMIT+3%29%0AUNION+ALL%0A%28SELECT+*+FROM+train+WHERE+%22CWE+ID%22+%3D+%27CWE-190%27+LIMIT+3%29%0AUNION+ALL%0A%28SELECT+*+FROM+train+WHERE+%22CWE+ID%22+%3D+%27CWE-400%27+LIMIT+3%29%0AUNION+ALL%0A%28SELECT+*+FROM+train+WHERE+%22CWE+ID%22+%3D+%27CWE-416%27+LIMIT+3%29%0AUNION+ALL%0A%28SELECT+*+FROM+train+WHERE+%22CWE+ID%22+%3D+%27CWE-476%27+LIMIT+3%29%0AUNION+ALL%0A%28SELECT+*+FROM+train+WHERE+%22CWE+ID%22+%3D+%27CWE-78%27+LIMIT+3%29%0AORDER+BY+%22CWE+ID%22%3B)해놨지만, 이해하기 어려우면 다른 CVE를 선택해도 무방

#### 업로드할 vuln_src.c 선택 기준
기본 원칙: 파일명을 변경하지 않고, 원본 파일 전체를 그대로 제출
- CVE: 취약점 동작 조건을 포함하는 모든 관련 소스 파일 업로드

  **예시: use-after-free 경우, A파일: free 발생 + B파일: free된 변수 USE**
  → A, B 파일 모두 업로드
- SARD: 해당 취약 코드 전체 업로드

### AI 취약점 탐지 결과물 수집
[KSignSlicer 사용법](https://github.com/seokjeon/KSignSlicer?tab=readme-ov-file#%EC%82%AC%EC%9A%A9%EB%B2%95)에 따라 AI 탐지를 수행하고, 그 결과물은 [목표 산출물](#목표-산출물)과 같이 수집합니다. 

> ⚠️ SARD의 경우, 라벨 보존을 위해 --genTest 옵션 없이 실행해야 합니다.

#### 분석 관련 FAQ
* 분석에 도움이 되는 팁들 있으시면 PR 환영합니다

##### ※ Docker 컨테이너에서 파일 복사 방법
예) 컨테이너 이름이 ksigncontainer이고, 결과 디렉토리가 /KSignSlicer/output/{proj_name}인 경우: 

`docker cp ksigncontainer:/KSignSlicer/output/{proj_name}/slicer_result.json .`

##### ※ 분석 중 에러 발생 시, 대응 방안
[예시 링크](https://github.com/seokjeon/SARD-vs-CVE/tree/main/CWE78_OS_CI/CVE-2019-13638*#-%EA%B0%9C%EC%9A%94)와 같이 
- [ ] 폴더 명 뒤에 \~를 붙이고 (예, CVE-2019-13638\~)
- [ ] README 상단에 어떤 명령어를 실행해서 어떤 에러가 나왔는지 기록 

##### ※ diff 파일 추출 방법
`wget https://github.com/username/repo/commit/abc1234.diff`

##### ※ csv를 엑셀로 확인할 때, 
엑셀에서 데이터가 존재하는 모든 row들의 높이를 일괄적으로 설정하려면, 먼저 해당 row들을 선택하고, "홈" 탭에서 "서식" -> "행 높이"를 선택하여 원하는 높이 값을 입력하면 됩니다. 엑셀의 행 높이 설정은 모든 셀에 동일하게 적용됩니다.

##### ※ csv를 markdown 테이블로 변환 방법 
[온라인 csv to md  table 변환 사이트](https://www.convertcsv.com/csv-to-markdown.htm)

### AI 취약점 탐지 결과물 분석
SARD 데이터에서 AI가 취약하다고 탐지한 코드를 우선 선정하여 결과물을 수집하고, 이를 CVE와 비교 분석하십시오.

#### SARD 분석 절차

1. CWE에 해당하는 모든 소스코드를 converged 폴더에 수집합니다.
2. KSignSlicer의 test.py 실행 후 test_output.csv에서 AI 모델이 취약점으로 탐지한 소스코드를 확인합니다. -> 이 결과는 SARD 바로 밑에 저장
3. 취약점이 탐지된 소스코드 중 3개를 선정하여 별도로 [AI 취약점 탐지 결과물을 수집](#ai-취약점-탐지-결과물-수집)을 수행합니다. -> 이 결과는 각 소스코드 폴더 밑에 저장
4. SARD 템플릿에 따라 각 파일에 대한 README를 작성합니다.

#### CVE 분석 절차
1. 선택한 CVE에 대한 폴더를 /KSignSlicer/data/converged 하위에 생성합니다.
2. 생성된 폴더 /KSignSlicer/data/converged/CVE-YYYY-XXXX 하위에 관련된 모든 소스코드를 이동시킵니다.
3. /KSignSlicer/data/cpg.csv/CVE-YYYY-XXXX 폴더를 생성한뒤 다음 명령어를 통해 CPG를 생성합니다.
```bash
tools/ReVeal/code-slicer/joern/joern-parse data/converged/CVE-YYYY-XXXX \
  && mv parsed/data/converged/CVE-YYYY-XXXX/ data/cpg.csv/CVE-YYYY-XXXX/ \
  && rm -rf parsed
```
4. 다음명령어를 통해 슬라이스를 생성합니다.
```bash
mkdir -p output/CVE-YYYY-XXXX \
  && python3 tools/KSignSlicer/slicer.py \
       --src data/converged/CVE-YYYY-XXXX \
       --csv data/cpg.csv/CVE-YYYY-XXXX \
       --output output/CVE-YYYY-XXXX/slicer_result.json --genTest
```
5. 다음 명령어를 통해 토큰 심볼릭을 수행합니다.
```bash
python3 tools/KSignSlicer/symbolic_tokenize.py \
  --src output/CVE-YYYY-XXXX/slicer_result.json \
  --dst output/CVE-YYYY-XXXX/slicer_result.symbolized.json
```
6. 다음 명령어를 통해 모델 테스트를 수행합니다.
```bash
cd output/CVE-YYYY-XXXX/ \
  && python3 ../../tools/KSignSlicer/test.py \
       --verbose \
       --test_file slicer_result.symbolized.json \
       --model_dir ../SARD_Juliet/saved_models \
  && cd -
```

7. test_result.csv에서 CVE 설명의 criterion(취약 관련 함수) 또는 **caller(호출 함수)**로 필터링해, 취약 슬라이스 존재 여부를 확인합니다.
   | Criterion | Slice | CVE 디렉토리       | 처리 / 설명                                                  |
   |-----------|-------|--------------------|-------------------------------------------------------------|
   | 있음      | 있음  | `CVE-YYYY-XXXX`    | 정상 진행                                                   |
   | 있음      | 없음  | `CVE-YYYY-XXXX`    | 슬라이스 누락: 스크립트 오류 / 파일 경로 확인 필요           |
   | 없음      | 있음  | `CVE-YYYY-XXXX`    | 예외: criterion 정의 없이 슬라이스만 생성 – 별도 검토 필요   |
   | 없음      | 없음  | `CVE-YYYY-XXXX~`   | 분석 불가: 디렉토리명에 `~` 추가 후 readme.md 분석 불가 사유 기재 |

   - 취약 슬라이스가 없다면:
      - 소스코드 내 취약점 존재 여부를 재확인합니다.
      - slicer.py의 l_funcs에 해당 함수가 없는지 확인합니다.
      - 슬라이스가 없는 이유를 README에 기록합니다.
   - 오탐 슬라이스가 있다면: 
      - SARD의 탐지된 코드 및 test_output.csv, 벡터 내용을 비교 분석합니다.
      - criterion 차이
      - 문법의 복잡성이 차이 여부
      - 벡터의 길이가 너무 짧거나, 너무 길어서 주요 내용이 누락된 경우
      - slice에서 source -> sink 흐름이 SARD와 지나치게 상이한 경우 등
9. README template에 맞게 내용을 정리합니다.

### README.md 작성 가이드
`templates` 폴더에 있는 `SARD.md`와 `CVE.md` 템플릿 파일을 확인해주시기 바랍니다.

## 기여 방법
"포크 앤 풀" Git 워크플로를 따르세요:
1. GitHub에서 SARD-vs-CVE 레포지토리 fork
2. fork한 프로젝트를 자신의 컴퓨터로 복제
3. 포크에서 새 브랜치를 체크아웃하고 해당 브랜치에서 개발을 시작
4. 커밋하기 전에 변경 사항을 테스트하고 변경 사항이 모든 테스트를 통과하는지 확인하고

   _필요한 경우 각 새 기능 또는 버그 수정에 대한 테스트 케이스를 추가하세요._
6. 변경 사항을 자신의 브랜치에 커밋
7. 작업을 포크에 push
8. 풀 리퀘스트를 제출하여 변경 사항을 검토할 수 있도록 합니다.

## 문의 사항
Issue 남겨주세요!
