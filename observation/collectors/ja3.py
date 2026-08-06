import hashlib

GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
}


def _strip_grease(values):
    return [v for v in values if v not in GREASE_VALUES]


def compute_ja3(tls_version, ciphers, extensions, supported_groups, ec_point_formats):
    ja3_string = "{v},{c},{e},{g},{f}".format(
        v=tls_version,
        c="-".join(str(x) for x in _strip_grease(ciphers)),
        e="-".join(str(x) for x in _strip_grease(extensions)),
        g="-".join(str(x) for x in _strip_grease(supported_groups)),
        f="-".join(str(x) for x in ec_point_formats),
    )
    ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
    return {"ja3_string": ja3_string, "ja3_hash": ja3_hash}
