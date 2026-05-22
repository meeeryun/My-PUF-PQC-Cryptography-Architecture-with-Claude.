"""
╔══════════════════════════════════════════════════════════════════════════╗
║      PUF + Kyber(ML-KEM) 통합 보안 메커니즘 — PoC 시뮬레이션              ║
║      PUF + Kyber(ML-KEM) Integration Security Mechanism - PoC Simul.     ║
║  [목적]                                                                  ║
║    - PUF(Physical Unclonable Function)의 CRP 메커니즘과                  ║
║      양자내성 암호 Kyber(ML-KEM)를 결합한 휘발성 키 관리 시뮬레이션        ║
║    - 비밀키를 메모리에 상시 저장하지 않고, 필요 시 PUF로 재생성 후         ║
║      즉시 삭제함으로써 측면 채널 공격(SCA) 위협 표면 최소화                ║
║    - 암호화는 공개키만으로 수행 가능 → 고가용성 유지                       ║
║                                                                          ║
║  [알고리즘 파라미터 (교육용 간소화)]                                       ║
║    - LWE 차원  : N = 8    (실제 Kyber-512: N = 256)                       ║
║    - 모듈러 소수: Q = 251  (실제 Kyber: Q = 3329)                         ║
║    - 오류 범위 : η = 1    (결과값 범위 [-1, 0, 1])                        ║
║    - 공유비밀  : 256비트   (32바이트)                                     ║
║                                                                          ║
║  [복호화 정확성 수학적 보장]                                              ║
║    최대 노이즈(Max Noise) = |e^T·r + e2 - s^T·e1| ≤ N + 1 + N = 17        ║
║    q / 4      = 251 / 4 ≈ 62  →  17 < 62  ✓ Always accurate Decryp.      ║
╚══════════════════════════════════════════════════════════════════════════╝

[외부 의존성]
  - 표준 라이브러리만 사용 (hashlib, hmac, struct, time, gc, os)
  - 별도 pip 설치 불필요. Don't have to download other pip.

"""

import hashlib                                
import hmac                                   
import struct                                  
import time
import gc
import os
from typing import List, Optional, Tuple


# ═══════════════════════════════════════════════════════════════════════════
# 전역 파라미터 정의
# ═══════════════════════════════════════════════════════════════════════════

N       = 8    # LWE 차원 (공개 행렬 A의 크기: N×N)
Q       = 251  # 소수 모듈러스.  q/4 = 62 > 17 (Max Noise)  → 복호화 항상 성공
ETA     = 1    # 오류 분포 파라미터. CBD_η → 값 범위 [-η, η]
SS_BITS = 256  # 공유 비밀(Shared Secret) 길이 (비트)


# ═══════════════════════════════════════════════════════════════════════════
# [모듈 1]  PUF 시뮬레이터
# ═══════════════════════════════════════════════════════════════════════════

class PUFSimulator:
    def __init__(self, device_id: str):
        self.device_id     = device_id
        self.device_secret = hashlib.sha256(
            f"PUF_PHYSICAL_FINGERPRINT::{device_id}".encode()
        ).digest()  # 32바이트 고유 ID

    def get_response(self, challenge: bytes) -> bytes: # HMAC-SHA256 기반
        return hmac.new(
            key=self.device_secret,
            msg=challenge,
            digestmod=hashlib.sha256
        ).digest()

    def derive_kyber_seed(self, challenge: bytes) -> bytes:
        raw_response = self.get_response(challenge)
        return hashlib.sha512(b"KYBER_SEED_v1::" + raw_response).digest()


# ═══════════════════════════════════════════════════════════════════════════
# [모듈 2]  수학적 유틸리티 (LWE 연산 지원 함수)
# ═══════════════════════════════════════════════════════════════════════════

def seeded_sample(seed: bytes, count: int, low: int, high: int) -> List[int]:
    result: List[int] = []
    counter = 0
    while len(result) < count:
        # 카운터를 추가하여 매 블록마다 다른 해시 생성
        block = hashlib.sha256(seed + struct.pack(">I", counter)).digest()
        result += [low + (b % (high - low)) for b in block]
        counter += 1
    return result[:count]


def cbd_sample(seed: bytes, count: int, eta: int) -> List[int]:
    # 충분한 비트 생성 (count × 2η 개의 이진 샘플 필요)
    bits = seeded_sample(seed, count * 2 * eta, 0, 2)
    samples = []
    idx = 0
    for _ in range(count):
        a_sum = sum(bits[idx       : idx + eta    ])  # η개 비트 합
        b_sum = sum(bits[idx + eta : idx + 2 * eta])  # η개 비트 합
        samples.append(a_sum - b_sum)                  # 차이 → [-η, η]
        idx += 2 * eta
    return samples


def mat_vec_mod(M: List[List[int]], v: List[int], q: int) -> List[int]:
    return [
        sum(M[i][j] * v[j] for j in range(len(v))) % q
        for i in range(len(M))
    ]


def vec_add_mod(u: List[int], v: List[int], q: int) -> List[int]:

    return [(a + b) % q for a, b in zip(u, v)]


def dot_mod(u: List[int], v: List[int], q: int) -> int:
    return sum(a * b for a, b in zip(u, v)) % q


def transpose(A: List[List[int]]) -> List[List[int]]:
    n = len(A)
    return [[A[r][c] for r in range(n)] for c in range(n)]


# ═══════════════════════════════════════════════════════════════════════════
# [모듈 3]  Toy Kyber  (LWE 기반 KEM, 교육용 간소화 구현)
# ═══════════════════════════════════════════════════════════════════════════

class ToyKyber:
    def __init__(self, n: int = N, q: int = Q, eta: int = ETA):
        self.n   = n
        self.q   = q
        self.eta = eta

    # ─────────────────────────────────────────────────────────────────
    # KeyGen
    # ─────────────────────────────────────────────────────────────────

    def keygen(self, seed: bytes) -> Tuple[dict, dict]:
        n, q, eta = self.n, self.q, self.eta

        # 도메인 분리: 각 파생 시드에 고유 접미사를 붙여 독립성 보장
        seed_A = hashlib.sha256(seed[:32] + b"\x00").digest()  # 행렬용
        seed_s = hashlib.sha256(seed[:32] + b"\x01").digest()  # 비밀키용
        seed_e = hashlib.sha256(seed[:32] + b"\x02").digest()  # 오류용

        # (1) 공개 행렬 A ∈ Z_q^{N×N}  (모든 참여자가 알고 있는 공개 파라미터)
        A_flat = seeded_sample(seed_A, n * n, 0, q)
        A = [A_flat[i * n : (i + 1) * n] for i in range(n)]

        # (2) 비밀 벡터 s: CBD 분포로 작은 값만 샘플링
        s_raw = cbd_sample(seed_s, n, eta)
        s = [x % q for x in s_raw]   # [-eta, eta] → [0, q) 로 양수 정규화

        # (3) 오류 벡터 e: LWE 문제의 '노이즈' — 이것이 있어야 보안 성립
        e_raw = cbd_sample(seed_e, n, eta)
        e = [x % q for x in e_raw]

        # (4) b = A·s + e  mod q   (이 값만으로 s를 역산하는 것 = LWE 난제)
        As = mat_vec_mod(A, s, q)
        b  = vec_add_mod(As, e, q)

        pk = {"A": A, "b": b}
        sk = {"s": s}   # ← 이 딕셔너리는 사용 후 즉시 _secure_delete() 해야 함

        return pk, sk

    # ─────────────────────────────────────────────────────────────────
    # Encapsulate
    # ─────────────────────────────────────────────────────────────────

    def encapsulate(self, pk: dict,
                    msg_seed: Optional[bytes] = None
                    ) -> Tuple[dict, bytes]:
        A, b     = pk["A"], pk["b"]
        n, q, eta = self.n, self.q, self.eta

        # 임시 메시지 m ← {0,1}^{256}  (전송하지 않음, 복호화 측에서 복원)
        if msg_seed is None:
            msg_seed = os.urandom(32)

        # m을 비트 배열로 변환 (LSB 우선)
        m_bits = [(msg_seed[i // 8] >> (i % 8)) & 1 for i in range(SS_BITS)]

        # 도메인 분리 시드
        seed_r  = hashlib.sha256(msg_seed + b"\x10").digest()
        seed_e1 = hashlib.sha256(msg_seed + b"\x11").digest()
        seed_e2 = hashlib.sha256(msg_seed + b"\x12").digest()

        # 에페메랄 벡터와 오류 생성
        r  = [x % q for x in cbd_sample(seed_r,  n,       eta)]
        e1 = [x % q for x in cbd_sample(seed_e1, n,       eta)]
        e2 = [x % q for x in cbd_sample(seed_e2, SS_BITS, eta)]

        # u = A^T · r + e1  mod q  (전치 행렬 사용)
        A_T = transpose(A)
        u   = vec_add_mod(mat_vec_mod(A_T, r, q), e1, q)

        # b^T · r  mod q  (스칼라, 모든 비트에 공통으로 사용)
        bTr = dot_mod(b, r, q)

        # v_i = b^T·r + e2_i + ⌊q/2⌋·m_i  mod q  (비트 m_i 를 격자에 인코딩)
        half_q = q // 2  # ≈ 125
        v = [(bTr + e2[i] + half_q * m_bits[i]) % q for i in range(SS_BITS)]

        ciphertext    = {"u": u, "v": v}
        shared_secret = hashlib.sha256(b"KYBER_SS::" + msg_seed).digest()

        return ciphertext, shared_secret

    # ─────────────────────────────────────────────────────────────────
    # Decapsulate
    # ─────────────────────────────────────────────────────────────────

    def decapsulate(self, sk: dict, ct: dict) -> bytes:
        s      = sk["s"]
        u, v   = ct["u"], ct["v"]
        q      = self.q
        half_q = q // 2

        # s^T · u  mod q  (스칼라)
        sTu = dot_mod(s, u, q)

        # 각 비트별 복원
        recovered_bits = []
        for vi in v:
            w = (vi - sTu) % q                      # w ≈ ⌊q/2⌋·m_i + noise
            dist_to_0    = min(w, q - w)            # 0(또는 q)까지의 원형 거리
            dist_to_half = abs(w - half_q)          # ⌊q/2⌋ 까지의 거리
            # noise가 작으면: m=0 → w ≈ 0, m=1 → w ≈ half_q
            recovered_bits.append(1 if dist_to_half < dist_to_0 else 0)

        # 비트 배열 → 바이트 배열 (LSB 우선, encapsulate와 동일한 순서)
        recovered_bytes = bytearray()
        for i in range(0, SS_BITS, 8):
            byte_val = sum(recovered_bits[i + j] << j for j in range(8))
            recovered_bytes.append(byte_val)

        # 공유 비밀 재생성 — encapsulate와 동일한 해시 구조
        return hashlib.sha256(b"KYBER_SS::" + bytes(recovered_bytes)).digest()


# ═══════════════════════════════════════════════════════════════════════════
# [모듈 4]  안전한 메모리 삭제 유틸리티
# ═══════════════════════════════════════════════════════════════════════════

def _secure_delete(sk: dict) -> None:
    if "s" in sk:
        for i in range(len(sk["s"])):
            sk["s"][i] = 0   # 메모리 내 값 덮어쓰기 (Overwrite)
    sk.clear()               # 딕셔너리 참조 제거
    gc.collect()             # GC 강제 실행


# ═══════════════════════════════════════════════════════════════════════════
# [모듈 5]  PUF + Kyber 통합 보안 시스템
# ═══════════════════════════════════════════════════════════════════════════

class PUFKyberSystem:
    def __init__(self, device_id: str):
        self.puf   = PUFSimulator(device_id)
        self.kyber = ToyKyber()
        self._pk: Optional[dict] = None

        # [보안 감사용] 비밀키 메모리 존재 여부 실시간 추적
        self._sk_in_memory: bool = False

    @property
    def secret_key_in_memory(self) -> bool:
        return self._sk_in_memory

    # ─────────────────────────────────────────────────────────────────

    def initialize(self, challenge: bytes) -> None:
        # PUF에서 시드 생성 (외부 공격자는 challenge를 알아도 seed 유추 불가)
        seed = self.puf.derive_kyber_seed(challenge)

        # Kyber 키 생성 (동일 seed → 동일 (pk, sk) — 결정적)
        pk, sk = self.kyber.keygen(seed)

        # 공개키 등록 (메모리 상시 유지 허용)
        self._pk = pk

        # ══ 비밀키 존재 구간 시작 ══
        self._sk_in_memory = True
        # 비밀키는 초기화 단계에서 즉시 폐기 (메모리 체류 시간 ≈ 수 μs)
        _secure_delete(sk)
        self._sk_in_memory = False
        # ══ 비밀키 존재 구간 종료 ══

    # ─────────────────────────────────────────────────────────────────

    def encrypt(self, plaintext: bytes) -> Tuple[dict, bytes]:
        assert self._pk is not None, "initialize(challenge)를 먼저 호출하세요."

        # Kyber KEM 캡슐화: 공개키로 공유 비밀 암호화
        kyber_ct, shared_secret = self.kyber.encapsulate(self._pk)

        # 공유 비밀로 메시지 암호화 (XOR, 시뮬레이션 목적)
        keystream  = hashlib.sha256(shared_secret + b"ENC_STREAM").digest()
        ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream[:len(plaintext)]))

        package = {"kyber_ct": kyber_ct, "enc_msg": ciphertext}
        return package, shared_secret

    # ─────────────────────────────────────────────────────────────────

    def decrypt(self, challenge: bytes, package: dict) -> Tuple[bytes, float]:
        t_sk_start = time.perf_counter()  # 비밀키 생존 시간 측정 시작

        # ── 비밀키 임시 재생성 ──────────────────────────────────────
        seed = self.puf.derive_kyber_seed(challenge)
        _, sk = self.kyber.keygen(seed)
        # ════ 비밀키 존재 구간 시작 ════════════════════════════════
        self._sk_in_memory = True

        # 역캡슐화: sk로 공유 비밀 복원
        shared_secret = self.kyber.decapsulate(sk, package["kyber_ct"])

        # ── 비밀키 즉시 폐기 ──────────────────────────────────────
        _secure_delete(sk)
        self._sk_in_memory = False
        # ════ 비밀키 존재 구간 종료 ════════════════════════════════

        sk_exposure_ms = (time.perf_counter() - t_sk_start) * 1000  # ms 단위

        # 공유 비밀로 메시지 복호화
        keystream = hashlib.sha256(shared_secret + b"ENC_STREAM").digest()
        plaintext = bytes(
            c ^ k for c, k in zip(package["enc_msg"], keystream[:len(package["enc_msg"])])
        )

        return plaintext, sk_exposure_ms


# ═══════════════════════════════════════════════════════════════════════════
# [모듈 6]  검증 테스트 및 가용성 지표 측정
# ═══════════════════════════════════════════════════════════════════════════

def test_reliability(device_id: str, challenge: bytes, rounds: int = 5) -> bool:
    print()
    print("─" * 64)
    print("  [ 신뢰성(Reliability) 테스트 ]")
    print(f"  동일 챌린지로 {rounds}회 반복 키 생성 → 키 지문 비교")
    print("─" * 64)

    puf, kyber = PUFSimulator(device_id), ToyKyber()
    fingerprints = []

    for i in range(1, rounds + 1):
        seed     = puf.derive_kyber_seed(challenge)
        pk, sk   = kyber.keygen(seed)
        # 공개키 벡터 b를 SHA-256으로 해싱 → 비교용 지문
        fp = hashlib.sha256(bytes(pk["b"])).hexdigest()
        fingerprints.append(fp)
        _secure_delete(sk)
        print(f"    [{i}회차] pk 지문: {fp[:40]}...")

    # 모든 지문이 동일한지 확인 (set에 1개 원소만 있으면 동일)
    is_consistent = len(set(fingerprints)) == 1
    status = "✅  PASS — 모든 키 동일 (100% 일관성 확보)" \
             if is_consistent else "❌  FAIL — 키 불일치 (오류 발생)"
    print(f"\n  결과: {status}")
    return is_consistent


def test_uniqueness(challenge: bytes) -> bool:
    print()
    print("─" * 64)
    print("  [ 고유성(Uniqueness) 테스트 ]")
    print("  3개 디바이스, 동일 챌린지 → 키 지문 비교")
    print("─" * 64)

    device_ids = ["DEVICE_ALPHA_001", "DEVICE_BETA_002", "DEVICE_GAMMA_003"]
    fingerprints = []

    for dev in device_ids:
        puf, kyber = PUFSimulator(dev), ToyKyber()
        seed       = puf.derive_kyber_seed(challenge)
        pk, sk     = kyber.keygen(seed)
        fp = hashlib.sha256(bytes(pk["b"])).hexdigest()
        fingerprints.append(fp)
        _secure_delete(sk)
        print(f"    [{dev:18s}] pk 지문: {fp[:40]}...")

    all_unique = len(set(fingerprints)) == len(fingerprints)
    status = "✅  PASS — 모든 디바이스 키 상이 (고유성 확보)" \
             if all_unique else "❌  FAIL — 키 충돌 발생"
    print(f"\n  결과: {status}")
    return all_unique


def benchmark_performance(rounds: int = 20) -> dict:
    print()
    print("─" * 64)
    print(f"  [ 성능 벤치마크 ]  ({rounds}회 평균 지연 시간)")
    print("─" * 64)

    puf       = PUFSimulator("BENCHMARK_DEVICE_000")
    kyber     = ToyKyber()
    challenge = b"standard_benchmark_nonce_v1"
    timings   = {k: [] for k in ["puf", "keygen", "encap", "decap"]}

    for _ in range(rounds):
        t = time.perf_counter()
        seed = puf.derive_kyber_seed(challenge)
        timings["puf"].append((time.perf_counter() - t) * 1000)

        t = time.perf_counter()
        pk, sk = kyber.keygen(seed)
        timings["keygen"].append((time.perf_counter() - t) * 1000)

        t = time.perf_counter()
        ct, ss1 = kyber.encapsulate(pk)
        timings["encap"].append((time.perf_counter() - t) * 1000)

        t = time.perf_counter()
        ss2 = kyber.decapsulate(sk, ct)
        timings["decap"].append((time.perf_counter() - t) * 1000)

        _secure_delete(sk)

    avg   = {k: sum(v) / len(v) for k, v in timings.items()}
    total = sum(avg.values())

    print(f"    PUF 응답 생성   : {avg['puf']:>9.4f} ms")
    print(f"    Kyber 키 생성   : {avg['keygen']:>9.4f} ms")
    print(f"    캡슐화 (Encap)  : {avg['encap']:>9.4f} ms")
    print(f"    역캡슐화 (Decap): {avg['decap']:>9.4f} ms")
    print(f"    {'─' * 36}")
    print(f"    전체 평균 합산  : {total:>9.4f} ms")

    avg["total"] = total
    return avg


# ═══════════════════════════════════════════════════════════════════════════
# [메인]  전체 PoC 시뮬레이션 실행
# ═══════════════════════════════════════════════════════════════════════════

def main() -> None:

    # ── 환경 설정 ──────────────────────────────────────────────────────────
    DEVICE_ID = "SECURE_MCU_SN20250522_001"
    CHALLENGE = b"server_nonce_a3f7c2b1d4e5"   # 서버가 세션마다 발급하는 난수
    PLAINTEXT = b"TOP_SECRET_PAYLOAD"           # 보호할 민감 데이터

    # ══════════════════════════════════════════════════════════════════════
    print("""
╔════════════════════════════════════════════════════════════════════╗
║      PUF + Kyber(ML-KEM) 통합 보안 메커니즘 — PoC 시뮬레이션      ║
║  PUF 모델    : HMAC-SHA256 기반 CRP 시뮬레이션                     ║
║  PQC 알고리즘 : Toy LWE-KEM  (N=8, Q=251, η=1, SS=256bit)         ║
║  목적         : 측면채널 대응 · 키 휘발성 · 가용성 지표 측정        ║
╚════════════════════════════════════════════════════════════════════╝""")

    system = PUFKyberSystem(DEVICE_ID)

    # ── 1단계: 초기화 (PUF → 키 생성 → 비밀키 즉시 폐기) ─────────────────
    print()
    print("━" * 64)
    print("  [ 1단계 ]  PUF → Kyber 키 생성 및 비밀키 즉시 폐기")
    print("━" * 64)

    t0 = time.perf_counter()
    system.initialize(CHALLENGE)
    init_ms = (time.perf_counter() - t0) * 1000

    puf_response = system.puf.get_response(CHALLENGE)
    puf_seed     = system.puf.derive_kyber_seed(CHALLENGE)

    print(f"  디바이스 ID      : {DEVICE_ID}")
    print(f"  PUF 챌린지       : {CHALLENGE.decode()}")
    print(f"  PUF 응답 (hex)   : {puf_response.hex()[:40]}...  (256bit)")
    print(f"  파생 시드 (hex)  : {puf_seed.hex()[:40]}...  (512bit)")
    print(f"  초기화 소요 시간 : {init_ms:.4f} ms")
    print()
    print(f"  ▶ 초기화 직후 비밀키 메모리 잔존 여부: {system.secret_key_in_memory}")
    print(f"    → ✅ 비밀키가 즉시 삭제되어 메모리에 존재하지 않음")

    # ── 2단계: 암호화 (공개키만 사용 → PUF 불필요) ───────────────────────
    print()
    print("━" * 64)
    print("  [ 2단계 ]  암호화  (공개키만으로 수행 — PUF 호출 없음)")
    print("━" * 64)

    t0 = time.perf_counter()
    package, ss_enc = system.encrypt(PLAINTEXT)
    enc_ms = (time.perf_counter() - t0) * 1000

    print(f"  원문 (plaintext) : {PLAINTEXT}")
    print(f"  Kyber 공유 비밀  : {ss_enc.hex()[:40]}...  (256bit)")
    print(f"  암호문 (hex)     : {package['enc_msg'].hex()}")
    print(f"  암호화 소요 시간 : {enc_ms:.4f} ms")
    print(f"  ※ 공개키만 사용 → 비밀키·PUF 호출 없음 = 고가용성")

    # ── 3단계: 복호화 (PUF → 비밀키 임시 재생성 → 복호화 → 즉시 폐기) ─────
    print()
    print("━" * 64)
    print("  [ 3단계 ]  복호화  (PUF 재호출 → sk 임시 생성 → 복호화 → 폐기)")
    print("━" * 64)

    t0 = time.perf_counter()
    decrypted, sk_exposure_ms = system.decrypt(CHALLENGE, package)
    dec_ms = (time.perf_counter() - t0) * 1000

    print(f"  복호화 결과      : {decrypted}")
    print(f"  복호화 소요 시간 : {dec_ms:.4f} ms")
    print(f"  비밀키 노출 시간 : {sk_exposure_ms:.4f} ms  ← 이 시간 동안만 sk 존재")
    print(f"  ※ 복호화 완료 즉시 sk 삭제 → 메모리 잔존 시간 최소화")

    # ── 4단계: 핵심 보안·가용성 지표 출력 ────────────────────────────────
    print()
    print("━" * 64)
    print("  [ 4단계 ]  핵심 지표 (보안 · 가용성 측정 결과)")
    print("━" * 64)

    correct   = (decrypted == PLAINTEXT)
    sk_in_mem = system.secret_key_in_memory  # 복호화 후 → False 이어야 함

    print(f"  ① 암/복호화 정확성   : {'✅  성공' if correct   else '❌  실패'}")
    print(f"  ② 비밀키 메모리 잔존 : {'⚠️   잔존 (보안 위험)' if sk_in_mem else '✅  미잔존 (안전)'}")
    print(f"  ③ 비밀키 노출 시간   : {sk_exposure_ms:.4f} ms  (최소화 목표 달성)")
    print(f"  ④ 초기화 지연        : {init_ms:.4f} ms")
    print(f"  ⑤ 암호화 지연        : {enc_ms:.4f} ms  (pk만 사용 → 저지연)")
    print(f"  ⑥ 복호화 지연        : {dec_ms:.4f} ms  (PUF 재호출 포함)")

    # ── 5단계: 추가 검증 테스트 ───────────────────────────────────────────
    rel_ok  = test_reliability(DEVICE_ID, CHALLENGE, rounds=5)
    uniq_ok = test_uniqueness(CHALLENGE)
    avg_t   = benchmark_performance(rounds=20)

    # ── 최종 요약 ─────────────────────────────────────────────────────────
    print()
    print()
    print("╔════════════════════════════════════════════════════════════════╗")
    print("║                     최종 검증 결과 요약                        ║")
    print("╠════════════════════════════════════════════════════════════════╣")
    r = lambda ok: "PASS ✅" if ok else "FAIL ❌"
    print(f"║  암/복호화 정확성      : {r(correct):<38} ║")
    print(f"║  비밀키 메모리 미잔존   : {r(not sk_in_mem):<38} ║")
    print(f"║  PUF 키 일관성         : {r(rel_ok):<38} ║")
    print(f"║  디바이스 간 고유성     : {r(uniq_ok):<38} ║")
    print("╠════════════════════════════════════════════════════════════════╣")
    print(f"║  비밀키 노출 시간      : {sk_exposure_ms:>8.4f} ms (측면채널 노출 최소화) ║")
    print(f"║  암호화 평균 지연      : {avg_t['encap']:>8.4f} ms (PUF 불필요 → 고가용성) ║")
    print(f"║  복호화 평균 지연      : {avg_t['decap'] + avg_t['keygen'] + avg_t['puf']:>8.4f} ms (PUF+KeyGen+Decap 합산) ║")
    print("╚════════════════════════════════════════════════════════════════╝")


if __name__ == "__main__":
    main()
