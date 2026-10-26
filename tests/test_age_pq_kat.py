"""Known-answer test against the C2SP age specification.

The identity, encapsulated key and stanza body are the mlkem768x25519 example
from age.md (github.com/C2SP/C2SP). A file key recovered from them proves the
plugin writes and reads the same construction as the age tool: X-Wing shared
secret straight into the HPKE key schedule, info "age-encryption.org/mlkem768x25519".
"""
import base64
import hashlib

import pytest

from onlykey.age_plugin import xwing
from onlykey.age_plugin.bech32 import bech32_decode

kyber = pytest.importorskip("kyber_py.ml_kem")

IDENTITY = "AGE-SECRET-KEY-PQ-1XX76JRALNLXDMEW0CRK45QMCCH4X06SE84UN3VPM33W6HWDX0H3SK3ZQFR"
ENC_B64 = "".join([
    'U7E10Aon27j1oDrH7fP3B++SPROSnDVvQpBemzOM+ZcsojxJifUbeeYWejMYKNB+H3rlXNvgtDKf',
    'SCkt78oqncr3faY1JtMj0GQPBZ2g6t8o1cMzZgyLMepeVuTQKxLqnM6L48n8dJL2y0N3i7WSOV6c',
    'sB79r9tcIs88Al9iCwVLpt74OzDXAIwD1QlCAvj75ZEnwtgP6Xr6s+wHg9hLD0OSSQOaTdCqzR5s',
    'hQWyrjVs7GCqd/5WbNGYNaolPQJBu9wTNhHjP9XGCTv8iKXkYwXDYujInkF5hOjpCHE8Vu+9UeMI',
    '+l0GJAEervT51bwaf288GiqgapP5g4HF8V4P0+03B/SwXhvxxZpKjTU2OcFS8I9chtEZ7Ucw5bvP',
    'kC1lyjNnqQXZyc4JnAqbFQTlPGnwbEsm0UGE+v0FOxTBznIivHoPHV++5PuYpombiV/lfYy8BFx0',
    'Hk1igNI3iLNjlIg4MLXNWjN3VROlXIiSsWNXjr/Frh/OE87PXoaKhsDPWfv6akd9PxSDqJMQ4j8k',
    '11kCSOnnU8Rw4TSVnTpt7gfYzBULrMr7qDgyH/TYvp0o7mAq4IaraFJmTqm+LjfAJT4PCQOpnMNR',
    'HLyXZn6mtMUujNv7+zR/I9Vqi+bJdQBwNWdJcUQVarqx2zxV2rM7l+j0gsmxjxp5yAPyALzla7Xz',
    'VvbboLMnHeM+CzN4GoB2PC4neVDSw7Dfs8vbm7f9CeDGvhjWrzcSCOsUCalvH1WkbpE0b9cE/TSJ',
    'qwXFXEc8npTSQWH58RXDALNF3qCbW5LaboD4wCloClEakgljT0s0mTdqIwzj4xtdlX0S2dCtaV5M',
    'HQJiQHGwPvBSCiIsh8ZWJPwZ7Ron7xoWgNI0lXRqhKm7fvFNCzF+Ray2kOyKWHbsMy3a5Zx3yZxC',
    'GFwexAxgYfAH9HJ1raHi1XYGpNpBlDXg47U1y4uU7RBeBb4ewETv/B/p8sGW88tIY87dHM2xHjnn',
    'tGXLvkCIkmjXGNULAVYHxDPJTygxSF7uTVPYCBUk5KeLnDVcgWF8p/wxigza47ptMtpVtm9ZrSEu',
    '9vzOnaTN3KO75RkkLuZszhXfmMZ46NQrdS7Y6duCiN501BnR5BUC4dX4iMxchix6aLN3pKv6UOEw',
    'wcx2aSF4Ib963MAtTPEjhqe+dt0VcTar/08uLWv1kQQueFaEGet4KQ975ZqaoU3PmZH9gqTOumX1',
    'EKf0Pnl0F3NMW+lEOlnCEce99zHBwBf7LV0pLNLDONBxpQySrZUQsNfhAq2Ktf5nG2hcGAMFMWIs',
    'EOuOyzEe+l2aHW4/ojOjU1Oqy4TLzVVRlWmPxQde7qKbvBN7CQhDqJHJA2nphQT/4DOdLqkwRiau',
    'Mmnfx9FI3+hYnX25NpnyvM/Pt94vpsRkhcuttu4/G4xOYTNQd2YWjGwhypZ0oPSiriuTbhj6y2qm',
    '33jiwxvegeDz8CmAIhOEY2JoVpjjX9XzuNR2f5KTLmLzEkOcJQ',
])
BODY_B64 = "c/k+TjhBA6Je1DF8rxZhe2Jm8CN0zbkV9rre6nA8g98"
# Recovered by OpenBase with the spec parameters (and by nothing else).
FILE_KEY = bytes.fromhex("df56f61c8e496609c18d25c197451803")


def _b64(s):
    return base64.b64decode(s + "=" * (-len(s) % 4))


def _identity_decaps(seed, enc):
    """What the device does for a stored X-Wing key: SHAKE256 expansion to
    d || z || sk_X, ML-KEM decaps, X25519, combiner."""
    expanded = hashlib.shake_256(seed).digest(96)
    d, z, sk_x = expanded[0:32], expanded[32:64], expanded[64:96]
    _, dk_m = kyber.ML_KEM_768._keygen_internal(d, z)
    pk_x = xwing.x25519_scalarmult_base(sk_x)
    ct_m, ct_x = enc[:1088], enc[1088:1120]
    ss_m = kyber.ML_KEM_768._decaps_internal(dk_m, ct_m)
    ss_x = xwing.x25519_scalarmult(sk_x, ct_x)
    return xwing.xwing_combiner(ss_m, ss_x, ct_x, pk_x)


def _vector():
    hrp, seed = bech32_decode(IDENTITY)
    assert hrp == "age-secret-key-pq-"
    enc, body = _b64(ENC_B64), _b64(BODY_B64)
    assert len(seed) == 32 and len(enc) == 1120 and len(body) == 32
    return bytes(seed), enc, body


def test_opens_the_spec_example():
    seed, enc, body = _vector()
    ss = _identity_decaps(seed, enc)
    assert xwing.open_file_key(ss, enc, body) == FILE_KEY


def test_seal_matches_the_spec_example():
    # Same key schedule, so sealing the known file key reproduces the body.
    seed, enc, body = _vector()
    ss = _identity_decaps(seed, enc)
    assert xwing.seal_file_key(ss, enc, FILE_KEY) == body


def test_legacy_construction_is_not_the_spec():
    # The control: the construction 1.3.0 wrote does NOT open age's stanza...
    seed, enc, body = _vector()
    ss = _identity_decaps(seed, enc)
    with pytest.raises(Exception):
        xwing._open_legacy_file_key(ss, enc, body)
    # ...but a body it wrote still opens through open_file_key().
    hpke_ss = xwing.hpke_extract_and_expand(ss, enc)
    key, nonce = xwing.hpke_key_schedule_base(hpke_ss, b"")
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    legacy_body = ChaCha20Poly1305(key).encrypt(nonce, FILE_KEY, b"")
    assert legacy_body != body
    assert xwing.open_file_key(ss, enc, legacy_body) == FILE_KEY


def test_wrong_secret_fails_both():
    seed, enc, body = _vector()
    ss = bytearray(_identity_decaps(seed, enc))
    ss[0] ^= 1
    with pytest.raises(Exception):
        xwing.open_file_key(bytes(ss), enc, body)

# The recipient age.md publishes for IDENTITY: the spec's PrivateKeyToPublicKey,
# Bech32 with HRP "age1pq". Encoding our 1216-byte X-Wing public key the same
# way is what lets age 1.3+, typage and rage encrypt to an OnlyKey without the
# plugin.
SPEC_RECIPIENT = "".join([
    'age1pq1x34nzsvr0rxjsgdn8zgyhfe8j7ceq5r9rdelkjuh3y235jzxshfg87pzf5zrqtzdx',
    'z95paef6caq5aapdmwjjqpjfdyxnzr2zampc3uxy0dg4z2n2gm9su72p0pc3u0jvev55l694',
    'v78snxg3yzvcl7yda0eyytqj6a0ec477lnhcy5hzpz4zq3pxanve4cn62gqj3pjy5lqj9c6k',
    'yj4v2z8alktn8zh99970x79gjkv7522hv9kfz35zsnxhsx8wwtmu9cy3ftzjgwcp4sshn3ll',
    'nylnpdsyz5jm72vefv4x5vfwytrefxg4wq3mv42wcrvkj742479zrxzpvp2p3e9fed9f0739',
    'vcu80r7ma28qfhnvlv4gfzel9q654dj3zmuvvz893azhxdvs9fxd0r7jzchzcfcs5mkyyjxh',
    'w0n2z6dvp9yn9qfdp29h0azxqyjw6v7fhyuzj7zel0uq6j9rd7wgrpz7mf5dnj43jwsgvrc8',
    'qcnhy7tu6dkdujuxzkp9xj43xe8h92ktre2a3u3s8mm5mrp9nr9pwkgtz4mdlq9hgn4fps4k',
    '57ff6wddn2fy23t47sm20r8km8sd2pcyyafnet8f0dajsrlyjeah4n3mssr6aseevuuskdvq',
    '5lzguyvpgwpta742c6698vgutzqgny8usfg0w2he7kq5vyxjd0f9hqg8xk26y9e4th0gezq9',
    '2q4cpp5p2y9hf5f2cje5l0c3sa3a2qxmm38pxxvhxh99yzmfz0zk7r2s64nnwjhkfgfr3gf8',
    'xnmppcgmaykvh5sh6g7vk9790rf8ws0axmr2t7z8aae5fq2029uvcn2ghgt4fu4wgwdc0k0c',
    'z52qkvwmuzj8p8k5jgf3xzk5zmrkavjekjrpeq408xz3zxazwkc6tyfmhayrkfpjhwtz5mp8',
    'j8guqe43k2q6m2kte03vrw27y3wmqyu5etmt9dnkwcnnpmu9gz9dekfhdevf42ucshphnrk3',
    '8ra6hx8w5f8q5ru0xdhrjxmwqf6cused7zc5xvq43r0zscjglpwlptpwydhqw64xz7ptjdye',
    'yzpq2zkxtmzg29gzjpvzva4d3l0cenn9xs297wf4y4ukwrunf57xj6pm7nvrkwvtrt8hwcmg',
    'v8x7ajw7258ugf9wvkmk4052ekg87tw5vnx8nq2swyzv77v8yqlwsenvamr0zssknwts8rrh',
    'fuwj7ykysnq9jxy0uv3kuyt22djszjdtvpz6d0s0kwh8ryynddzud92emeyvvyqktd0jtj7r',
    'vvg5gch25v8smlvny3kvn5gagyz475ze2y6q466xqmz2n3hs77lddeqyta2nch5k2u5yacuk',
    '9ywnwfdzvyejnucz724hj77hrrmakm7pr3kxsrxq22ejexlud9fy2kdqmkg5yncz7jm5wv2q',
    'jk5w5kvcpqsry2yqffh2la52dxfjkjq5rzhjzeyn6dupn0qwtyv7s4lwg3xdarsdlwe2y3tu',
    'jy480y7z39q259fzx6jhd2j0f5hagqpcpees7hzc2yrk5cy788uk3s7qvp5cpepx24gvws3m',
    '2g433exgwppnkjscec8qu4y9z9r7vccexjcjaen42245lmgmxmuavg9alej92322gvvyy2t6',
    '267v09ch64y0m53jff0vjj96s0ypk60hr3jw4myd6m5hpn3xjstx7tl2szhpr5qe8jj08ydj',
    'c4wy2rch2fhuy3pdfjax5awe9j99ly5hkntzz9fe5zatgjvzdd0kgtxs25njnajyf6ssekp7',
    'gelxquusn4pt25czh3scj68kq79wdn5tgm6yvm9nzavrg043x3msnygf8dweknw5jmqd0uvn',
    'y6ttsn09508k0c55zfnegrm9efhxpfqdkmhh6gjtqmwze9pyyzk3tlhl53k2ykx3qheyty7s',
    'aeq0d3fzv49zc0k',
])


def test_native_recipient_is_the_spec_recipient():
    from onlykey.age_plugin.cli import encode_native_recipient, encode_recipient, decode_recipient
    hrp, seed = bech32_decode(IDENTITY)
    expanded = hashlib.shake_256(bytes(seed)).digest(96)
    ek_m, _ = kyber.ML_KEM_768._keygen_internal(expanded[0:32], expanded[32:64])
    pk = ek_m + xwing.x25519_scalarmult_base(expanded[64:96])
    assert encode_native_recipient(pk) == SPEC_RECIPIENT
    # and the plugin spelling carries the same bytes
    assert bytes(decode_recipient(encode_recipient(pk))) == pk
