import hashlib
 
GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
}
 
SNI_EXT = 0x0000
ALPN_EXT = 0x0010
 
# TLS/SSL version -> JA4 version token.
VERSION_MAP = {
    0x0304: "13",
    0x0303: "12",
    0x0302: "11",
    0x0301: "10",
    0x0300: "s3",
    0x0002: "s2",
}
  
def _strip_grease(values):
    return [v for v in values if v not in GREASE_VALUES]
 
def _hex4(value: int) -> str:
    return format(value, "04x")
  
def _truncated_sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:12]
  
def _negotiated_version(legacy_version: int, supported_versions: list) -> str:
    """
    JA4 uses the highest TLS version the client offers. If the
    supported_versions extension (0x002b) is present, that list wins
    over the legacy ClientHello.version field (which is pinned to
    TLS 1.2 for TLS 1.3 clients).
    """
    candidates = [v for v in (supported_versions or [legacy_version]) if v in VERSION_MAP]
    if not candidates:
        return "00"
    return VERSION_MAP[max(candidates)]
 
 
def compute_ja4(
    ciphers: list,
    extensions: list,
    sni_present: bool,
    alpn: list,
    signature_algorithms: list,
    legacy_version: int = 0,
    supported_versions: list = None,
    is_quic: bool = False,
) -> dict:
    """
    Compute a JA4 client TLS fingerprint from parsed ClientHello
    fields. Returns a dict with the full fingerprint plus its three
    component parts (a: cleartext metadata, b: cipher hash,
    c: extension+sigalg hash).
    """
    proto_char = "q" if is_quic else "t"
    version_token = _negotiated_version(legacy_version, supported_versions)
    sni_char = "d" if sni_present else "i"
 
    clean_ciphers = _strip_grease(ciphers)
    clean_extensions = _strip_grease(extensions)
 
    cipher_count = min(len(clean_ciphers), 99)
    ext_count = min(len(clean_extensions), 99)
 
    if alpn:
        first_alpn = alpn[0]
        alpn_token = (first_alpn[0] + first_alpn[-1]) if first_alpn else "00"
    else:
        alpn_token = "00"
 
    ja4_a = (
        f"{proto_char}{version_token}{sni_char}"
        f"{cipher_count:02d}{ext_count:02d}{alpn_token}"
    )
 
    cipher_part = ",".join(_hex4(c) for c in sorted(clean_ciphers))
    ja4_b = _truncated_sha256(cipher_part) if cipher_part else "0" * 12
 
    # SNI and ALPN are counted in ja4_a but excluded from this hash.
    ext_for_hash = sorted(e for e in clean_extensions if e not in (SNI_EXT, ALPN_EXT))
    ext_part = ",".join(_hex4(e) for e in ext_for_hash)
    sig_part = ",".join(_hex4(s) for s in signature_algorithms)
    combined = f"{ext_part}_{sig_part}" if sig_part else ext_part
    ja4_c = _truncated_sha256(combined) if combined else "0" * 12
 
    return {
        "ja4": f"{ja4_a}_{ja4_b}_{ja4_c}",
        "ja4_a": ja4_a,
        "ja4_b": ja4_b,
        "ja4_c": ja4_c,
    }
 
