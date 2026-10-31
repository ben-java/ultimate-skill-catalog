# COSE_Sign1 receipt (SCITT-style) dengan python-cose

Resep menandatangani statement eksekusi menjadi receipt COSE_Sign1 (EdDSA/Ed25519) dan memverifikasinya — pola untuk item SCITT/AI-Agent-Execution di mana receipt harus tamper-evident dan dapat diverifikasi independen.

Dependensi: `pip install cose cbor2 cryptography`. (Generasi kunci via `openssl genpkey -algorithm ED25519`.)

## API quirks yang menyita waktu
- Constructor `Sign1Message` memakai parameter `phdr` / `uhdr`, BUKAN `protected` / `unprotected` — memakai nama yang salah diam-diam mengabaikan header sehingga `alg` tidak terparse (error `'NoneType' object has no attribute 'sign'`).
- `OKPKey` WAJIB diberi `crv` (gunakan id integer `6` untuk Ed25519) DAN set `key.alg = EdDSA`; tanpa itu signature dihitung dengan alg kosong. `CoseCurve` bukan enum dengan atribut `.Ed25519` — jangan cari itu; gunakan id `6`.
- `.encode()` menghasilkan envelope CBOR ber-TAG 18 (`cbor2.CBORTag(18, (protected, unprotected, payload, signature))`). Decode library (`Sign1Message.decode`) rapuh terhadap tag ini — jangan diandalkan.

## Verifikasi manual (reliable)
Unwrap tag, bangun Sig_structure COSE_Sign1, dan verifikasi Ed25519:
```python
import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
obj = cbor2.loads(raw)
tup = obj.value if isinstance(obj, cbor2.CBORTag) else obj
protected_b, _u, payload_b, sig_b = tup
sig_structure = cbor2.dumps(["Signature1", protected_b, b"", payload_b])
Ed25519PublicKey.from_public_bytes(x).verify(sig_b, sig_structure)
```
Path ini terbukti: sign PASS, verify PASS, dan flips satu byte signature → FAIL (tamper-evident).

## Catatan
iu- Simpan kunci privat di luar git (meta/sigstore/), jangan di-commit.
- Untuk integrasi gate: bungkus sign+verify sebagai subcommand CLI, dan tambahkan test negatif tamper (flip byte) sebagai kasus adversarial.
