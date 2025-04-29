# SARD-vs-CVE
AI가 SARD는 잘 탐지하지만 CVE는 놓치는 이유를 분석하기 위해 두 데이터를 비교합니다.

## 목차


## 목표 산출물
각 CWE별로 CVE 3개 + SARD 3개를 선정하여 `vuln_src.c`, `slice.json`, `vector`, `README.md` 형식으로 정리합니다.

```
/CWE134_FSB/
├── CVE-2021-1234/
│   ├── vuln_src.c
│   ├── slice.json
│   ├── vector
│   └── README.md
├── SARD-wchar_t_file_printf_63/
│   └── vuln_src.c
│   ├── slice.json
│   ├── vector
│   └── README.md
```

## 순서
### 1. 정리할 소스 코드 선정
#### SARD 소스 코드 선택 방법
- 할당 받은 CWE 중 [SARD Juliet C/C++ 1.3.1 with extra support](https://samate.nist.gov/SARD/test-suites/116)에서 해당 CWE 코드 3개 자유롭게 선택
- [Joern-CWE-Analysis](https://github.com/alpakalee/Joern-CWE-Analysis/tree/main)에 있는 코드도 활용 가능

#### CVE 소스 코드 선택 방법
- 할당 받은 CWE 중 [BigVul](https://huggingface.co/datasets/bstee615/bigvul)에서 CVE 3개 자유롭게 선택
- 빠른 작업을 위해 [BigVul에서 CWE 별 3개씩 추천](https://huggingface.co/datasets/bstee615/bigvul/viewer?views%5B%5D=train&sql=%28SELECT+*+FROM+train+WHERE+%22CWE+ID%22+%3D+%27CWE-134%27+LIMIT+3%29%0AUNION+ALL%0A%28SELECT+*+FROM+train+WHERE+%22CWE+ID%22+%3D+%27CWE-190%27+LIMIT+3%29%0AUNION+ALL%0A%28SELECT+*+FROM+train+WHERE+%22CWE+ID%22+%3D+%27CWE-400%27+LIMIT+3%29%0AUNION+ALL%0A%28SELECT+*+FROM+train+WHERE+%22CWE+ID%22+%3D+%27CWE-416%27+LIMIT+3%29%0AUNION+ALL%0A%28SELECT+*+FROM+train+WHERE+%22CWE+ID%22+%3D+%27CWE-476%27+LIMIT+3%29%0AUNION+ALL%0A%28SELECT+*+FROM+train+WHERE+%22CWE+ID%22+%3D+%27CWE-78%27+LIMIT+3%29%0AORDER+BY+%22CWE+ID%22%3B)해놨지만, 이해하기 어려우면 다른 CVE를 선택해도 무방

### 2. vuln_src.c
- 취약점 조건을 포함하는 모든 소스 파일 업로드
- 파일명 수정 없이 원본 그대로 제출

**예시: use-after-free 경우, A파일: free 발생 + B파일: free된 변수 USE**
→ A, B 파일 모두 업로드

### 3. slice.json
KSignSlicer로 추출하면 나오는 result.json에서 해당 vuln 코드에 대응하는 슬라이스만 선별 저장

### 4. vector
`source_ids = tokenizer.convert_tokens_to_ids(source_tokens)` 결과를  
`{ "slice파일명": source_ids }` 형태로 JSON 저장

### 5. README.md
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
