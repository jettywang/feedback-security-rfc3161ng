'''Offline tests for signer certificate selection and signature verification.

The tokens used here are generated locally with freshly created RSA keys and
self-signed certificates, so no public TSA server is contacted. They exercise
the fact that the order of the certificates embedded in a TimeStampToken is
not fixed and must not be relied upon to find the signing certificate.
'''
import datetime
import hashlib

import pytest
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ, tag, useful
from pyasn1_modules import rfc2315, rfc2459, rfc2634, rfc5035
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

import rfc3161ng
from rfc3161ng import InvalidSignatureError, SignerNotFoundError
from rfc3161ng.api import (
    id_aa_signingCertificate,
    id_aa_signingCertificateV2,
    id_attribute_messageDigest,
)

id_attribute_contentType = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 3))
id_rsaEncryption = univ.ObjectIdentifier('1.2.840.113549.1.1.1')

DATA = b'hello rfc3161ng'


def make_certificate(common_name):
    '''Return a freshly generated RSA key and a self-signed certificate.'''
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2035, 1, 1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def _algorithm_identifier(oid):
    algorithm_identifier = rfc2459.AlgorithmIdentifier()
    algorithm_identifier.setComponentByPosition(0, oid)
    return algorithm_identifier


def _make_attribute(oid, value):
    attribute = rfc2315.Attribute()
    attribute.setComponentByName('type', oid)
    values = univ.SetOf()
    values.setComponentByPosition(0, value)
    attribute.setComponentByName('values', values)
    return attribute


def _make_tst_info(digest, hashname, nonce=None):
    tst_info = rfc3161ng.TSTInfo()
    tst_info.setComponentByName('version', 1)
    message_imprint = rfc3161ng.MessageImprint()
    message_imprint.setComponentByPosition(0, _algorithm_identifier(rfc3161ng.get_hash_oid(hashname)))
    message_imprint.setComponentByPosition(1, univ.OctetString(digest))
    tst_info.setComponentByName('messageImprint', message_imprint)
    tst_info.setComponentByName('serialNumber', 42)
    tst_info.setComponentByName('genTime', useful.GeneralizedTime('20261113120000Z'))
    if nonce is not None:
        tst_info.setComponentByName('nonce', int(nonce))
    return tst_info


def _ess_binding(certificate, ess):
    certificate_der = certificate.public_bytes(serialization.Encoding.DER)
    if ess == 'v1':
        cert_hash = hashlib.sha1(certificate_der).digest()
        cert_id = rfc2634.ESSCertID()
        cert_id.setComponentByName('certHash', univ.OctetString(cert_hash))
        binding = rfc2634.SigningCertificate()
        binding.setComponentByName(
            'certs',
            univ.SequenceOf(componentType=rfc2634.ESSCertID()).setComponents(cert_id),
        )
        return id_aa_signingCertificate, binding
    if ess == 'v2':
        cert_hash = hashlib.sha256(certificate_der).digest()
        cert_id = rfc5035.ESSCertIDv2()
        cert_id.setComponentByName('certHash', univ.OctetString(cert_hash))
        binding = rfc5035.SigningCertificateV2()
        binding.setComponentByName(
            'certs',
            univ.SequenceOf(componentType=rfc5035.ESSCertIDv2()).setComponents(cert_id),
        )
        return id_aa_signingCertificateV2, binding
    return None, None


def _make_signer_info(key, certificate, tst_info_der, hashname, ess, tamper_signature):
    digest_oid = rfc3161ng.get_hash_oid(hashname)
    content_digest = hashlib.new(hashname, tst_info_der).digest()

    authenticated_attributes = rfc2315.Attributes().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
    )
    authenticated_attributes.setComponentByPosition(
        0, _make_attribute(id_attribute_contentType, rfc3161ng.id_ct_TSTInfo)
    )
    authenticated_attributes.setComponentByPosition(
        1, _make_attribute(id_attribute_messageDigest, univ.OctetString(content_digest))
    )
    ess_oid, ess_value = _ess_binding(certificate, ess)
    if ess_oid is not None:
        authenticated_attributes.setComponentByPosition(2, _make_attribute(ess_oid, ess_value))

    signed_set = univ.SetOf()
    for index, attribute in enumerate(authenticated_attributes):
        signed_set.setComponentByPosition(index, attribute)
    signature = key.sign(
        encoder.encode(signed_set),
        padding.PKCS1v15(),
        getattr(hashes, hashname.upper())(),
    )
    if tamper_signature:
        signature = b'\x00' + signature[1:]

    certificate_asn1, _ = decoder.decode(
        certificate.public_bytes(serialization.Encoding.DER),
        asn1Spec=rfc2459.Certificate(),
    )
    issuer_and_serial = rfc2315.IssuerAndSerialNumber()
    issuer_and_serial.setComponentByName('issuer', certificate_asn1['tbsCertificate']['issuer'])
    issuer_and_serial.setComponentByName('serialNumber', certificate.serial_number)

    signer_info = rfc2315.SignerInfo()
    signer_info.setComponentByName('version', 1)
    signer_info.setComponentByName('issuerAndSerialNumber', issuer_and_serial)
    signer_info.setComponentByName('digestAlgorithm', _algorithm_identifier(digest_oid))
    signer_info.setComponentByName('authenticatedAttributes', authenticated_attributes)
    signer_info.setComponentByName(
        'digestEncryptionAlgorithm', _algorithm_identifier(id_rsaEncryption)
    )
    signer_info.setComponentByName('encryptedDigest', univ.OctetString(signature))
    return signer_info


def build_token(signers, embedded_certificates, hashname='sha1', ess='v1',
                tamper_signature=False, include_certificates=True, nonce=None):
    '''Build a DER-encoded TimeStampToken.

    ``signers`` is a list of ``(key, certificate)`` pairs; more than one
    produces multiple SignerInfo entries. ``embedded_certificates`` controls
    the (arbitrary) ordering of the certificates carried by the token.
    '''
    digest = hashlib.new(hashname, DATA).digest()
    tst_info_der = encoder.encode(_make_tst_info(digest, hashname, nonce=nonce))

    content_info = rfc2315.ContentInfo()
    content_info.setComponentByName('contentType', rfc3161ng.id_ct_TSTInfo)
    content_info.setComponentByName('content', univ.OctetString(tst_info_der))

    signer_infos = rfc2315.SignerInfos()
    for index, (key, certificate) in enumerate(signers):
        signer_info = _make_signer_info(
            key, certificate, tst_info_der, hashname, ess, tamper_signature
        )
        signer_infos.setComponentByPosition(index, signer_info)

    signed_data = rfc2315.SignedData()
    signed_data.setComponentByName('version', 1)
    signed_data.setComponentByName(
        'digestAlgorithms',
        rfc2315.DigestAlgorithmIdentifiers().setComponents(
            _algorithm_identifier(rfc3161ng.get_hash_oid(hashname))
        ),
    )
    signed_data.setComponentByName('contentInfo', content_info)
    if include_certificates and embedded_certificates:
        certificate_set = rfc2315.ExtendedCertificatesAndCertificates().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
        )
        for index, certificate in enumerate(embedded_certificates):
            certificate_asn1, _ = decoder.decode(
                certificate.public_bytes(serialization.Encoding.DER),
                asn1Spec=rfc2459.Certificate(),
            )
            choice = rfc2315.ExtendedCertificateOrCertificate()
            choice.setComponentByName('certificate', certificate_asn1)
            certificate_set.setComponentByPosition(index, choice)
        signed_data.setComponentByName('certificates', certificate_set)
    signed_data.setComponentByName('signerInfos', signer_infos)

    content = rfc2315.ContentInfo()
    content.setComponentByName('contentType', rfc2315.signedData)
    content.setComponentByName('content', signed_data)
    return encoder.encode(content)


@pytest.fixture(scope='module')
def identities():
    tsa_key, tsa_certificate = make_certificate('Test TSA')
    other_key, other_certificate = make_certificate('Other CA')
    third_key, third_certificate = make_certificate('Third CA')
    return {
        'tsa': (tsa_key, tsa_certificate),
        'other': (other_key, other_certificate),
        'third': (third_key, third_certificate),
    }


def test_certificate_order_does_not_change_result(identities):
    tsa_key, tsa_certificate = identities['tsa']
    _, other_certificate = identities['other']
    _, third_certificate = identities['third']

    for ordering in (
        [tsa_certificate],
        [other_certificate, tsa_certificate],
        [other_certificate, third_certificate, tsa_certificate],
        [third_certificate, other_certificate, tsa_certificate],
    ):
        token = build_token([(tsa_key, tsa_certificate)], ordering)
        assert rfc3161ng.check_timestamp(token, data=DATA, hashname='sha1') is True


def test_ess_v1_and_v2_bindings_verify(identities):
    tsa_key, tsa_certificate = identities['tsa']
    _, other_certificate = identities['other']

    v1_token = build_token(
        [(tsa_key, tsa_certificate)], [other_certificate, tsa_certificate],
        hashname='sha1', ess='v1',
    )
    assert rfc3161ng.check_timestamp(v1_token, data=DATA, hashname='sha1') is True

    v2_token = build_token(
        [(tsa_key, tsa_certificate)], [other_certificate, tsa_certificate],
        hashname='sha256', ess='v2',
    )
    assert rfc3161ng.check_timestamp(v2_token, data=DATA, hashname='sha256') is True


def test_token_without_ess_binding_still_uses_signer_identity(identities):
    tsa_key, tsa_certificate = identities['tsa']
    _, other_certificate = identities['other']
    token = build_token(
        [(tsa_key, tsa_certificate)], [other_certificate, tsa_certificate], ess=None
    )
    assert rfc3161ng.check_timestamp(token, data=DATA, hashname='sha1') is True


def test_explicit_certificate_must_match_identity(identities):
    tsa_key, tsa_certificate = identities['tsa']
    _, other_certificate = identities['other']
    token = build_token(
        [(tsa_key, tsa_certificate)], [other_certificate, tsa_certificate]
    )

    pem_certificate = tsa_certificate.public_bytes(serialization.Encoding.PEM)
    der_certificate = tsa_certificate.public_bytes(serialization.Encoding.DER)
    assert rfc3161ng.check_timestamp(
        token, certificate=pem_certificate, data=DATA, hashname='sha1'
    ) is True
    assert rfc3161ng.check_timestamp(
        token, certificate=der_certificate, data=DATA, hashname='sha1'
    ) is True

    # The supplied certificate does not belong to the SignerInfo: this is a
    # missing/unknown signer, not a cryptographic signature failure.
    with pytest.raises(SignerNotFoundError):
        rfc3161ng.check_timestamp(
            token,
            certificate=other_certificate.public_bytes(serialization.Encoding.DER),
            data=DATA,
            hashname='sha1',
        )


def test_replacing_bound_certificate_is_rejected(identities):
    tsa_key, tsa_certificate = identities['tsa']
    _, other_certificate = identities['other']
    token = build_token(
        [(tsa_key, tsa_certificate)], [other_certificate, tsa_certificate], ess='v1'
    )

    decoded, _ = decoder.decode(token, asn1Spec=rfc3161ng.TimeStampToken())
    signer_info = decoded.content['signerInfos'][0]
    for index, attribute in enumerate(signer_info['authenticatedAttributes']):
        if attribute[0] != id_aa_signingCertificate:
            continue
        wrong_hash = hashlib.sha1(
            other_certificate.public_bytes(serialization.Encoding.DER)
        ).digest()
        wrong_id = rfc2634.ESSCertID()
        wrong_id.setComponentByName('certHash', univ.OctetString(wrong_hash))
        wrong_binding = rfc2634.SigningCertificate()
        wrong_binding.setComponentByName(
            'certs',
            univ.SequenceOf(componentType=rfc2634.ESSCertID()).setComponents(wrong_id),
        )
        signer_info['authenticatedAttributes'].setComponentByPosition(
            index, _make_attribute(id_aa_signingCertificate, wrong_binding)
        )
    broken_token = encoder.encode(decoded)

    with pytest.raises(SignerNotFoundError):
        rfc3161ng.check_timestamp(broken_token, data=DATA, hashname='sha1')


def test_missing_certificate_is_signer_not_found(identities):
    tsa_key, tsa_certificate = identities['tsa']
    token = build_token(
        [(tsa_key, tsa_certificate)], [tsa_certificate], include_certificates=False
    )
    with pytest.raises(SignerNotFoundError):
        rfc3161ng.check_timestamp(token, data=DATA, hashname='sha1')


def test_tampered_signature_is_invalid_signature(identities):
    tsa_key, tsa_certificate = identities['tsa']
    _, other_certificate = identities['other']
    token = build_token(
        [(tsa_key, tsa_certificate)], [other_certificate, tsa_certificate],
        tamper_signature=True,
    )
    with pytest.raises(InvalidSignatureError):
        rfc3161ng.check_timestamp(token, data=DATA, hashname='sha1')


def test_multiple_signers_are_all_verified(identities):
    tsa_key, tsa_certificate = identities['tsa']
    other_key, other_certificate = identities['other']

    valid_token = build_token(
        [(tsa_key, tsa_certificate), (other_key, other_certificate)],
        [other_certificate, tsa_certificate],
    )
    assert rfc3161ng.check_timestamp(valid_token, data=DATA, hashname='sha1') is True

    # Tampering the first signer's signature cannot be hidden by the second one.
    tampered_token = build_token(
        [(tsa_key, tsa_certificate), (other_key, other_certificate)],
        [other_certificate, tsa_certificate],
        tamper_signature=True,
    )
    with pytest.raises(InvalidSignatureError):
        rfc3161ng.check_timestamp(tampered_token, data=DATA, hashname='sha1')

    # A certificate matching none of the SignerInfo identities is refused.
    _, third_certificate = identities['third']
    with pytest.raises(SignerNotFoundError):
        rfc3161ng.check_timestamp(
            valid_token,
            certificate=third_certificate.public_bytes(serialization.Encoding.DER),
            data=DATA,
            hashname='sha1',
        )


def test_ambiguous_identity_without_ess_binding_is_rejected(identities):
    from rfc3161ng.api import select_signer_certificate

    tsa_key, tsa_certificate = identities['tsa']
    other_key, _ = identities['other']
    token = build_token(
        [(tsa_key, tsa_certificate)], [tsa_certificate], ess=None,
        include_certificates=False,
    )
    decoded, _ = decoder.decode(token, asn1Spec=rfc3161ng.TimeStampToken())
    signer_info = decoded.content['signerInfos'][0]

    # A distinct certificate reusing the same issuer name and serial number
    # matches the SignerIdentifier but is not bound by any ESS digest.
    duplicate = (
        x509.CertificateBuilder()
        .subject_name(tsa_certificate.subject)
        .issuer_name(tsa_certificate.issuer)
        .public_key(other_key.public_key())
        .serial_number(tsa_certificate.serial_number)
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2035, 1, 1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(other_key, hashes.SHA256())
    )
    with pytest.raises(SignerNotFoundError):
        select_signer_certificate(signer_info, [tsa_certificate, duplicate])

    # The ESS binding pins the genuine certificate and removes the ambiguity.
    bound_token = build_token(
        [(tsa_key, tsa_certificate)], [duplicate, tsa_certificate], ess='v1'
    )
    decoded_bound, _ = decoder.decode(bound_token, asn1Spec=rfc3161ng.TimeStampToken())
    bound_signer_info = decoded_bound.content['signerInfos'][0]
    assert select_signer_certificate(
        bound_signer_info, [duplicate, tsa_certificate]
    ) == tsa_certificate


def test_ski_signer_identifier_matching(identities):
    # The PKCS#7 token schema used by the library only carries
    # issuerAndSerialNumber, so exercise the SKI SignerIdentifier matching
    # helper directly instead of through a full token.
    from rfc3161ng.api import _certificate_matches_sid, _signer_identifier

    tsa_key, tsa_certificate = identities['tsa']
    _, other_certificate = identities['other']
    token = build_token([(tsa_key, tsa_certificate)], [], include_certificates=False)
    decoded, _ = decoder.decode(token, asn1Spec=rfc3161ng.TimeStampToken())
    signer_info = decoded.content['signerInfos'][0]
    kind, value = _signer_identifier(signer_info)
    assert kind == 'issuerSerial'
    assert _certificate_matches_sid(tsa_certificate, kind, value) is True
    assert _certificate_matches_sid(other_certificate, kind, value) is False

    ski = tsa_certificate.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    ).value.digest
    assert _certificate_matches_sid(tsa_certificate, 'ski', ski) is True
    assert _certificate_matches_sid(other_certificate, 'ski', ski) is False


def test_nonce_roundtrip(identities):
    tsa_key, tsa_certificate = identities['tsa']
    token = build_token(
        [(tsa_key, tsa_certificate)], [tsa_certificate], nonce=7
    )
    assert rfc3161ng.check_timestamp(
        token, data=DATA, hashname='sha1', nonce=7
    ) is True
    with pytest.raises(ValueError):
        rfc3161ng.check_timestamp(
            token, data=DATA, hashname='sha1', nonce=8
        )
