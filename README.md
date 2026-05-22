# My-PUF-PQC-Cryptography-Architecture-with-Claude.
I wanna integrate PQC with PUF, so I simulate this architecture with Claude in Python
(이건 AI가 아니라 제가 다 작성했습니다...)

## 1. 라이브러리
```python 
import hashlib, hmac, struct, time, gc, os
```
- **hashlib & hmac**: 암호학적 난제(LWE)를 생성할 임시 SEED 파생 함수 및 PUF의 CRP(Challenge-Response Pair) 매핑을 구현합니다.
- **struct**: 하드웨어 통신과 유사하게 데이터를 고정된 바이트 다누이(Big-Endian 4바이트 정수)로 직렬화하여 해시 함수에 주입합니다.
- **gc(Garbage Collector)**: 파이썬 환경에서 참조가 끊긴 비밀킨 데이터 객체를 강제로 청소하여 물리적으로 남아있는 시간을 최소화합니다.
------------------------------------------
## 2. 수학적 환경설정 및 설계
- **LWE 차원 ($N = 8$)**: 공개키인 행렬 $A$의 크기가 $8 \times 8$ 행렬.
  - **LWE(Learning With Errors, 오차 학습 문제)**는 현대 격자 기반 암호(Lattice-based Cryptography)의 보안성을 지탱하는 가장 핵심적인 수학적 난제입니다. (기본 LWE 문제: $Ax + e = b$)
  - 수학적 요소로는 $n$(차원, 문제의 복잡도 결정), $q$(모듈러스, 모든 연산이 일어나는 공간의 크기), $\chi$(오류 분포, 오차 $e$를 뽑아내는 확률의 분포)
  - 현재 코드에서의 LWE 역할은
    - 키 생성 시: 비밀키 벡터 $s$에 오류 $e$를 섞어 공개키 $b = As+e$를 생성.
    - 암호화 시: 메시지 $m$에 오류를 섞엉 암호문 생성.
    - 복호화 시: 메시지 $m$으로 복원할 때, 암호문 $c$에 숨겨진 오류들을 수학적으로 제거하여(이 과정에서 $\chi$가 중요) 본 메시지 $m$을 탐색.
- **소수 모듈러스 ($Q = 251$)**: 모든 연산은 $Z_251$ 격자 공간 위에서 모듈러 연산으로 수행.
- **오류 분포 ($\eta = 1$)**: 중심 극한 정리를 따르는 이항 분포(CBD)를 통해 Noise 값을 $[-1, 0, 1]$로 제한.
  - 이때 Max Noise값은 $Max Noise = |e^T \times r + e_2 - s^T \times e_1| <= N + 1 + N = 17$ 로 최종 복호화 공간의 Margin인 $\frac{Q}{4} = \frac{251}{4} \approx 62$, Max Noise의 최댓값 17이 훨씬 작기에 100% 복호화 성공률을 보장한다. (시뮬레이션이기 때문에 100% 보장을 선언한 것.)
------------------------------------------
## 3. 모듈별 심층 작동 원리
- **[모듈 1] PUF Simulator**
  - 실제 반도체 내부의 미세 공정 편차로 인해 발생하는 고유 전압/전류 값 등을 HMAC-SHA256(해시함수) 구조로 추상화.
  - **```device_secret```**: 반도체가 생산될 때 하드웨어적인 고유값
  - **CRP(Challenge-Response) Structure**: 외부 서버가 매 세션마다 난수 Challenge 값을 던지면, 반도체 내부에서만 ```derive_kyber_seed()```를 통해 512비트의 SEED를 출력. 즉, 키를 내부에 보관하지 않고 Challenge가 입력될 때만 실시간으로, 동적으로 계산.
 
- **[모듈 2 & 3] Toy Kyber KEM (격자 암호 연산)**
  - 현재 코드에서는 시뮬레이션 결과, 연산성, 직관성이 목적이기 때문에 $Toy-Kyber-KEM$을 사용.
  - **keygen(키 생성)**:
    - 하나의 PUF SEED로부터 Domain Separation 기법을 사용하여 행렬용 시드($A$), 비밀키 벡터($s$), 노이즈 벡터($e$)를 독립적으로 생성.
    - 최종적으로 LWE 난제 식 $b = A \times s + e (moq q)$를 계산하여 공개키 $pk(A, b)$를 출력.
  - **encapsulate(캡슐화/암호화)**:
    - 송신자는 공개키 $pk$만 가지고 임시 메시지 $m$을 격자 공간에 인코딩($\lfloor q/2 \rfloor \times m$)하여 암호문 $ct(u, v)$를 생성. 이 과정에서는 PUF나 비밀키 연산이 전혀 없으므로 CPU 자원 절약 가능(-> 고가용성).
  - **decapsulate(역캡슐화/복호화)**:
    - 수신자는 재생성한 비밀키 $s$를 사용해 $w = (v - s^{T} \times u) (mod q)를 계산. 이때 $w$는 복호화에 필요한 수학 난제를 해결하는 힌트라고 생각하면 됨.
    - **원형 거리 계산 알고리즘(Circular Distance Calculation)** 을 통해 격자점 위의 값이 0에 가까운지, $\lfloor q/2 \rfloor$에 가까운지 판단하여 $0$ 도는 $1$의 원래 비트를 정밀하게 복원.
      - **원형 거리 계산**은 일반 거리와 원형 거리 즉, $distance(x, y) = min(|x-y|, N-|x-y|)$를 뜻함. 여기서 $N$은 나올 수 있는 최대의 수를 말함.
     
- **[모듈 4] Delete $s$**
  - PUF-PQC는 항상 마지막에 비밀키 벡터 $s$를 지워야하는데 현재 코드에서는 딕셔너리(Dictionary)로 정의가 되어있음. Python 내에서 딕셔너리는 ```Del``` 함수를 통해 제거해도 메모리 주소가 그대로 남기 때문에 메모리 주소를 덮어쓰기(Overwrite)하고 끊어낸 참조를 없애야함.
  - **```sk["s"][i]=0```**: 저장되어있는 $s$의 딕셔너리인 ```sk```를 모두 0으로 덮어씀.
  - **```sk.clear()```**: 딕셔너리의 참조를 제거.
  - **```gc.collect()```**: GC를 강제로 실행하여 하드웨어 레벨의 강제 레지스터를 소거.
------------------------------------------
## 4. 실험 과정 및 결과
- **단일 PUF 암호 측정 결과**
  - **```DEVICE_ID```**: "SECURE_MCU_SN20250522_001" (임의의 ID 설정)
  - **```CHALLENGE```**: "server_nonce_..." (고정된 값으로 하드코딩한 이유는 디버깅뿐만이 아니라 직관성을 위함)
  - **```PLAINTEXT```**: 일반 메시지
  - **```secret_key_in_memory(self)```**: boolean 타입으로, 메모리에 ```sk``` 딕셔너리가 없으면 True.
  - **```correct```**: boolean 타입으로, decrypted(복호문)과 PLAINTEXT가 같으면 True.
  - **```init_ms```**: 초기화 지연 시간
  - **```enc_ms```**: 암호화 지연 시간
  - **```dec_ms```**: 복호화 지연 시간
  - ***실험 결과***:
  
      |지표|결과|
      |:-:|:-:|
      |암/복호화 정확성|**성공**|
      |비밀키 메모리 잔존|**미잔존(안전)**|
      |비밀키 노출 시간|**0.6991ms**|
      |초기화 지연|**0.9421ms**|
      |암호화 지연|**0.2602ms**|
      |복호화 지연|**0.7087ms**|

- **PUF 20 Round 평균 지연 측정 결과**
  - **```benchmark_performance(rounds: int = 20)**: 성능 측정을 위해 20회 평균 지연 시간 측정 및 연산
  - **```puf```**: PUF 응답 생성 지연 시간
  - **```keygen```**: Kyber 키 생성 지연 시간
  - **```encap```**: 캡슐화 지연 시간
  - **```decap```**: 역캡슐화 지연 시간
  - ***실험 결과***:
  
    |지표|결과|
    |:-:|:-:|
    |PUF 응답 생성|**0.0205ms**|
    |Kyber 키 생성|**0.0549ms**|
    |캡슐화(Encap)|**0.2860ms**|
    |역캡슐화(Decap)|**0.0923ms**|
    |**전체 평균 합산**|**0.4537ms**|

- **신뢰성(Reliability) 테스트 (동일 Challenge 값으로 하나의 Device(반도체)에서 5 Rounds 진행 -> Kyber 키 비교)**
  - **```test_reliability```** : 신뢰성 테스트를 위해 5회 챌린지 연속 진행 후 Kyber 키 비교
  - **```fingerprints```**: SEED로 생성된 공개키의 행렬 $B$를 SHA-256으로 해싱 후 ```Append``` -> 즉, 같다면 이후로 append가 되지 않으니 최종적으로 ```fingerprints```의 길이는 1이어야함
  - **```is_consistent```**: ```fingerprints``` 배열의 길이가 1이면 True.
  - ***실험 결과***:
  
    |지표|결과|
    |:-:|:-:|
    |1회차|**pk 지문: 09074294a9989bf153ff74106c9649b9ca4e750b...**|
    |2회차|**pk 지문: 09074294a9989bf153ff74106c9649b9ca4e750b...**|
    |3회차|**pk 지문: 09074294a9989bf153ff74106c9649b9ca4e750b...**|
    |4회차|**pk 지문: 09074294a9989bf153ff74106c9649b9ca4e750b...**|
    |5회차|**pk 지문: 09074294a9989bf153ff74106c9649b9ca4e750b...**|
    
    -> ***전부 동일*** -> ***Reliability 보장***
      - 일회성이라고 한 Challenge가 전부 동일해야하는 이유는 하나의 반도체에서 같은 Challenge값을 넣으면 항상 같은 Response값을 출력해야하기 때문.

- **고유성(Uniqueness) 테스트 (다른 Device(반도체)로 동일 Challenge 값으로 Kyber 키 비교)**
  - **```device_ids = ["DEVICE_ALPHA_001", "DEVICE_BETA_002", "DEVICE_GAMMA_003"]```**: Device 3개(Alpha, Beta, Gamma)
  - **```fingerprints```**: 신뢰성 테스트 때와 동일한 행렬, 이번엔 다른 값이기에 append가 3번이 정상적으로 이루어져야함. -> 즉, set(fingerprints)와 fingerprints 배열의 길이가 같아야함.
  - **```all_unique```**: set(fingerprints)와 fingerprints 배열의 길이가 같다면 True.
  - ***실험 결과***:
  
    |지표|결과|
    |:-:|:-:|
    |DEVICE_ALPHA_001|**pk 지문: dc7a754070587658a7bdbf6605377d520a9bc72f...**|
    |DEVICE_BETA_002|**pk 지문: 15da41619f7fd16bf27697fcd2c299444c39f8af...**|
    |DEVICE_GAMMA_003|**pk 지문: fad27abeadd6d466161f6f12f951f224b2b802ae...**|

    -> ***전부 비동일*** -> ***Uniqueness 보장***
------------------------------------------
## 5. 한계
- **Fuzzy Extractor**: 온도/전압 변화에 의한 PUF 비트 오류 정정
- **FO 변환**: IND-CCA2으로의 보안 변환 (실제 Kyber 표준)
- **cytpes.memset**: Python GC(CPU 사용량 대폭 증가 요소 및 확실한 메모리 소거가 안될 경우 방지)를 우회
------------------------------------------
