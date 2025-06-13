
# **Slicer가 CWE476의 코드 파일을 읽지 못하는 문제 발생**

### (.ksign_slicer) root@1ee3bca3aaea:/KSignSlicer# tools/ReVeal/code-slicer/joern/joern-parse data/converged/CWE476_cases     && mv parsed/data/converged/CWE476_cases/ data/cpg.csv/     && rm data/cpg.csv/CWE476_cases/*.csv     && rm -rf parsed
### data/converged/CWE476_cases/CWE476_NULL_Pointer_Dereference__int_01.c
### data/converged/CWE476_cases/CWE476_NULL_Pointer_Dereference__int_02.c
### data/converged/CWE476_cases/CWE476_NULL_Pointer_Dereference__int_03.c

# **위의 과정까지는 수행이 되나, 하단에서 slicer.py가 CWE476의 3개의 코드 파일을 읽지 못하여**
# **비어있는 criterion_list[]가 생성되고, 이에 다음 과정에서도 vul : 0 / non_vul : 0 으로 나옵니다.**

### (.ksign_slicer) root@1ee3bca3aaea:/KSignSlicer# mkdir -p output/CWE476_cases \
###    && python3 tools/KSignSlicer/slicer.py --src data/converged/CWE476_cases --csv data/cpg.csv/CWE476_cases --output output/CWE476_cases/slicer_result.json
###  0%|                                                                                                                                                                         | 0/3 ### [00:00<?, ?it/s]criterion_list []
### criterion_list []
### criterion_list []
### 100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 3/3 [00:00<00:00, 339.00it/s]
### Done

### (.ksign_slicer) root@1ee3bca3aaea:/KSignSlicer# python3 tools/KSignSlicer/symbolic_tokenize.py --src output/CWE476_cases/slicer_result.json --dst output/CWE476_cases/slicer_result.symbolized.json
### 0it [00:00, ?it/s]
### vul : 0
### non_vul : 0
### Done

# **당연히 비어있는 값을 불러오므로 아래의 경우에도 오류가 발생합니다.**

### (.ksign_slicer) root@1ee3bca3aaea:/KSignSlicer# cd output/CWE476_cases/ \
###    && python3 ../../tools/KSignSlicer/test.py --verbose --test_file slicer_result.symbolized.json --model_dir ../SARD_Juliet/saved_models && cd -
### Traceback (most recent call last):
### File "/KSignSlicer/output/CWE476_cases/../../tools/KSignSlicer/test.py", line 438, in <module>
###    main(args)
###  File "/KSignSlicer/output/CWE476_cases/../../tools/KSignSlicer/test.py", line 372, in main
###   model = torch.load(model_dir, weights_only=False)
###            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
###  File "/KSignSlicer/.ksign_slicer/lib/python3.12/site-packages/torch/serialization.py", line 1479, in load
###    with _open_file_like(f, "rb") as opened_file:
###         ^^^^^^^^^^^^^^^^^^^^^^^^
###  File "/KSignSlicer/.ksign_slicer/lib/python3.12/site-packages/torch/serialization.py", line 759, in _open_file_like
###    return _open_file(name_or_buffer, mode)
###           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
###  File "/KSignSlicer/.ksign_slicer/lib/python3.12/site-packages/torch/serialization.py", line 740, in __init__
###    super().__init__(open(name, mode))
###                     ^^^^^^^^^^^^^^^^
### FileNotFoundError: [Errno 2] No such file or directory: '../SARD_Juliet/saved_models/checkpoint-best-acc/model.bin'
=======
# CWE476에 대한 모델 테스트 결과
**본 결과는 슬라이서와 모델이 동일한 예측을 수행했으나, 근본적으로 취약한 코드에 대한 라벨링이 이루어지지 않음을 확인함.**