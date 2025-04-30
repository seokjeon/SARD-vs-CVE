# SARD-vs-CVE
AI가 SARD는 잘 탐지하지만 CVE는 놓치는 이유를 분석하기 위해 두 데이터를 비교합니다.

## 목차
1. [목표 산출물](#목표-산출물)
2. [절차](#절차)
   - [환경 준비](#환경-준비)
   - [vuln_src.c 선별](#vuln_srcc-선별)
     - [SARD의 경우](#sard의-경우)
     - [CVE의 경우](#cve의-경우)
   - [slicer_result.json와 slicer_result.symbolized.json 추출](#slicer_resultjson와-slicer_resultsymbolizedjson-추출)
   - [vectors.json과 test_output.csv 추출](#vectorsjson과-test_outputcsv-추출)
   - [README.md](#readmemd)
3. [기여 방법](#기여-방법)
4. [문의 사항](#문의-사항)

## 목표 산출물
CWE별로 CVE와 SARD를 각각 3개 씩 선정하여 `vuln_src.c`, `README.md`, `slicer_result.json`, `slicer_result.symbolized.json`, `test_output.csv`, `vectors.json` 형식으로 정리합니다.

```
/CWE134_FSB/
├── CVE-2021-1234/
│   ├── vuln_src.c
│   ├── README.md
│   ├── slicer_result.json
│   ├── slicer_result.symbolized.json
│   ├── test_output.csv
│   └── vectors.json
├── SARD-wchar_t_file_printf_63/
│   ├── vuln_src.c
│   ├── README.md
│   ├── slicer_result.json
│   ├── slicer_result.symbolized.json
│   ├── test_output.csv
│   └── vectors.json
```

## 절차
### 환경 준비
시작에 앞서 [KSignSlicer](https://github.com/seokjeon/KSignSlicer) 동작 환경을 준비해주시기 바랍니다. 

특히, test_output.csv 추출을 위해서는 **디컴파일하지 않은 모델 학습이 반드시 선행되어야** 합니다.

※ KSignSlicer 저장소 권한이 필요한 경우, 담당자(sojeon@jnu.ac.kr)에게 **GitHub 사용자명과 함께 요청**해 주시기 바랍니다.

### vuln_src.c 선별
#### 분석할 취약점 선택 방법
##### SARD의 경우
- 할당 받은 CWE 중 [SARD Juliet C/C++ 1.3](https://samate.nist.gov/SARD/test-suites/112)에서 해당 CWE 코드 2개 자유롭게 선택
  
※ KSign 영상 자료인 '합본) 모델 설계'와의 버전 호환을 위해, 최신 버전(v1.3.1 with extra support)이 아닌 v1.3 버전을 사용

※ [Joern-CWE-Analysis](https://github.com/alpakalee/Joern-CWE-Analysis)에서 이미 분석한 취약점들은 샘플로 미리 입력해두었으니 참고용으로 활용 가능

##### CVE의 경우
- 할당 받은 CWE 중 [BigVul](https://huggingface.co/datasets/bstee615/bigvul)에서 CVE 3개 자유롭게 선택
- 빠른 작업을 위해 [BigVul에서 CWE 별 CVE 3개씩 추천](https://huggingface.co/datasets/bstee615/bigvul/viewer?views%5B%5D=train&sql=%28SELECT+*+FROM+train+WHERE+%22CWE+ID%22+%3D+%27CWE-134%27+LIMIT+3%29%0AUNION+ALL%0A%28SELECT+*+FROM+train+WHERE+%22CWE+ID%22+%3D+%27CWE-190%27+LIMIT+3%29%0AUNION+ALL%0A%28SELECT+*+FROM+train+WHERE+%22CWE+ID%22+%3D+%27CWE-400%27+LIMIT+3%29%0AUNION+ALL%0A%28SELECT+*+FROM+train+WHERE+%22CWE+ID%22+%3D+%27CWE-416%27+LIMIT+3%29%0AUNION+ALL%0A%28SELECT+*+FROM+train+WHERE+%22CWE+ID%22+%3D+%27CWE-476%27+LIMIT+3%29%0AUNION+ALL%0A%28SELECT+*+FROM+train+WHERE+%22CWE+ID%22+%3D+%27CWE-78%27+LIMIT+3%29%0AORDER+BY+%22CWE+ID%22%3B)해놨지만, 이해하기 어려우면 다른 CVE를 선택해도 무방

#### 업로드할 vuln_src.c 선택 기준
기본 원칙: 파일명을 변경하지 않고, 원본 파일 전체를 그대로 제출
- CVE: 취약점 동작 조건을 포함하는 모든 관련 소스 파일 업로드

  **예시: use-after-free 경우, A파일: free 발생 + B파일: free된 변수 USE**
  → A, B 파일 모두 업로드
- SARD: 해당 취약 코드 전체 업로드

### slicer_result.json와 slicer_result.symbolized.json 추출
1. 선택한 vuln_src.c 파일들을 vuln_src 폴더에 위치시킵니다.
2. [KSignSlicer](https://github.com/seokjeon/KSignSlicer) 환경의 Joern을 사용하여 vuln_src에 대한 CPG를 추출합니다. 
3. [slicer.py](https://github.com/seokjeon/KSignSlicer/blob/main/tools/KSignSlicer/slicer.py)를 실행하여 slicer_result.json을 추출합니다.
   * SARD의 경우, 계산된 라벨의 원본을 보존하기 위해 -genTest 옵션 없이 실행해야 합니다.
4. [symbolic_tokenize.py](https://github.com/seokjeon/KSignSlicer/blob/main/tools/KSignSlicer/symbolic_tokenize.py)를 실행하여 slicer_result.symbolized.json을 추출합니다.

### vectors.json과 test_output.csv 추출
[test.py](https://github.com/seokjeon/KSignSlicer/blob/main/tools/KSignSlicer/test.py)를 실행할 때, --verbose 옵션을 추가하면 vectors.json과 test_output.csv가 함께 추출됩니다.

### README.md
<업데이트 중>

- [ ] 폴더 명
- [ ] 취약 동작 요약 (버그 발생 조건, 트리거 흐름)
- [ ] root cause (source → sink 흐름 요약)
- [ ] AI 모델이 탐지/실패한 이유  
  - 슬라이스가 너무 짧음/과다함  
  - 의미 노드 누락 (예: sink 없음)  
  - 벡터 표현이 학습 데이터와 상이

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
