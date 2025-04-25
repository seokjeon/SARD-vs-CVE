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

## 방법
### 1. 정리할 소스 코드 선정
#### CVE 선정 기준 
1. C/C++ 기반 코드
2. 18개월 이내 발급된 CVE
3. 해당 CWE에 매핑 가능
4. PoC 확인 가능 or patch diff 명확

### 2. vuln_src.c
source → sink 흐름을 포함한 최소 단위 코드로 구성

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
