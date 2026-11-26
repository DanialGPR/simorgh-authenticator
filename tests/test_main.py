from simorgh.main import generate_totp

SHA1_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
SHA256_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"[:52]

def test_sha1_vectors():
    cases = {59: "94287082", 1111111109: "07081804", 2000000000: "69279037"}
    for t, expected in cases.items():
        assert generate_totp(SHA1_SECRET, digits=8, at_time=t) == expected