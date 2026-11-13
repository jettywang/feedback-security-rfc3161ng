from pyasn1.type import univ

__all__ = (
    'id_kp_timeStamping', 'id_sha1', 'id_sha224', 'id_sha256', 'id_sha384',
    'id_sha512', 'id_ct_TSTInfo', 'oid_to_hash',
    'id_rsaEncryption', 'id_RSASSA_PSS', 'id_ecPublicKey', 'id_mgf1',
    'id_sha1WithRSAEncryption', 'id_sha224WithRSAEncryption',
    'id_sha256WithRSAEncryption', 'id_sha384WithRSAEncryption',
    'id_sha512WithRSAEncryption', 'id_ecdsa_with_SHA1',
    'id_ecdsa_with_SHA224', 'id_ecdsa_with_SHA256',
    'id_ecdsa_with_SHA384', 'id_ecdsa_with_SHA512',
)

id_kp_timeStamping = univ.ObjectIdentifier((1, 3, 6, 1, 5, 5, 7, 3, 8))
id_sha1 = univ.ObjectIdentifier((1, 3, 14, 3, 2, 26))
id_sha224 = univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 4))
id_sha256 = univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 1))
id_sha384 = univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 2))
id_sha512 = univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 3))
id_ct_TSTInfo = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 16, 1, 4))

id_rsaEncryption = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 1, 1))
id_RSASSA_PSS = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 1, 10))
id_ecPublicKey = univ.ObjectIdentifier((1, 2, 840, 10045, 2, 1))
id_mgf1 = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 1, 8))

id_sha1WithRSAEncryption = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 1, 5))
id_sha224WithRSAEncryption = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 1, 14))
id_sha256WithRSAEncryption = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 1, 11))
id_sha384WithRSAEncryption = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 1, 12))
id_sha512WithRSAEncryption = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 1, 13))

id_ecdsa_with_SHA1 = univ.ObjectIdentifier((1, 2, 840, 10045, 4, 1))
id_ecdsa_with_SHA224 = univ.ObjectIdentifier((1, 2, 840, 10045, 4, 3, 1))
id_ecdsa_with_SHA256 = univ.ObjectIdentifier((1, 2, 840, 10045, 4, 3, 2))
id_ecdsa_with_SHA384 = univ.ObjectIdentifier((1, 2, 840, 10045, 4, 3, 3))
id_ecdsa_with_SHA512 = univ.ObjectIdentifier((1, 2, 840, 10045, 4, 3, 4))

oid_to_hash = {
    id_sha1: 'sha1',
    id_sha224: 'sha224',
    id_sha256: 'sha256',
    id_sha384: 'sha384',
    id_sha512: 'sha512',
}
