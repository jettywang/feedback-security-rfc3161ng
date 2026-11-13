import datetime
import hashlib
from unittest import mock

import dateutil.tz
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ, useful
from pyasn1_modules import rfc2315, rfc2459

import rfc3161ng
from rfc3161ng import api

HASHNAMES = ('sha1', 'sha256', 'sha384', 'sha512')
RSA_ENCRYPTION = univ.ObjectIdentifier('1.2.840.113549.1.1.1')
ID_CONTENT_TYPE = univ.ObjectIdentifier('1.2.840.113549.1.9.3')
ID_MESSAGE_DIGEST = univ.ObjectIdentifier('1.2.840.113549.1.9.4')


def _imprint(tsq):
    message_imprint = tsq.getComponentByName('messageImprint')
    return (
        message_imprint.hash_algorithm[0],
        bytes(message_imprint.hashed_message),
    )


# ---------------------------------------------------------------------------
# request building / digest resolution rules
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('hashname', HASHNAMES)
def test_direct_request_uses_requested_hashname(hashname):
    data = b'the quick brown fox'
    tsq = rfc3161ng.make_timestamp_request(data=data, hashname=hashname)
    oid, imprint = _imprint(tsq)
    assert oid == api.get_hash_oid(hashname)
    assert imprint == hashlib.new(hashname, data).digest()


@pytest.mark.parametrize('hashname', HASHNAMES)
def test_direct_and_remote_requests_build_identical_message_imprint(hashname):
    data = b'parity between entry points'
    timestamper = rfc3161ng.RemoteTimestamper('http://example.invalid', hashname=hashname)

    direct = rfc3161ng.make_timestamp_request(data=data, hashname=hashname)
    remote_style = rfc3161ng.make_timestamp_request(
        digest=api.resolve_digest(data=data, hashname=timestamper.hashname),
        hashname=timestamper.hashname,
    )
    assert encoder.encode(direct) == encoder.encode(remote_style)
    assert _imprint(direct) == _imprint(remote_style)


def test_default_hashname_remains_sha1_for_compatibility():
    tsq = rfc3161ng.make_timestamp_request(data='test')
    oid, imprint = _imprint(tsq)
    assert oid == api.get_hash_oid('sha1')
    assert imprint == hashlib.sha1(b'test').digest()


def test_empty_message_is_hashed_not_rejected():
    tsq = rfc3161ng.make_timestamp_request(data=b'')
    oid, imprint = _imprint(tsq)
    assert oid == api.get_hash_oid('sha1')
    assert imprint == hashlib.sha1(b'').digest()


def test_empty_message_with_explicit_hashname():
    tsq = rfc3161ng.make_timestamp_request(data=b'', hashname='sha256')
    oid, imprint = _imprint(tsq)
    assert oid == api.get_hash_oid('sha256')
    assert imprint == hashlib.sha256(b'').digest()


def test_precomputed_digest_is_used_verbatim():
    digest = hashlib.sha256(b'precomputed').digest()
    tsq = rfc3161ng.make_timestamp_request(digest=digest, hashname='sha256')
    assert _imprint(tsq) == (api.get_hash_oid('sha256'), digest)


def test_precomputed_digest_takes_precedence_over_data():
    digest = hashlib.sha256(b'winner').digest()
    tsq = rfc3161ng.make_timestamp_request(
        data=b'loser', digest=digest, hashname='sha256')
    assert _imprint(tsq) == (api.get_hash_oid('sha256'), digest)


def test_string_data_is_accepted_and_encoded():
    tsq = rfc3161ng.make_timestamp_request(data='test', hashname='sha256')
    assert _imprint(tsq)[1] == hashlib.sha256(b'test').digest()


def test_missing_data_and_digest_is_an_error():
    with pytest.raises(ValueError):
        rfc3161ng.make_timestamp_request()


@pytest.mark.parametrize('hashname,wrong_size', [
    ('sha1', 19), ('sha256', 31), ('sha384', 47), ('sha512', 63),
])
def test_wrong_digest_length_is_rejected_with_real_exception(hashname, wrong_size):
    with pytest.raises(ValueError):
        rfc3161ng.make_timestamp_request(
            digest=b'\x00' * wrong_size, hashname=hashname)


def test_wrong_digest_length_rejected_even_with_assertions_disabled():
    # python -O strips assert statements; validation must not rely on them.
    import subprocess
    import sys
    code = (
        'import rfc3161ng\n'
        'try:\n'
        "    rfc3161ng.make_timestamp_request(digest=b'short', hashname='sha256')\n"
        'except ValueError:\n'
        '    print("rejected")\n'
        'else:\n'
        '    raise SystemExit("bad digest was accepted")\n'
    )
    result = subprocess.run(
        [sys.executable, '-O', '-c', code], capture_output=True, text=True, check=True)
    assert result.stdout.strip() == 'rejected'


def test_resolve_digest_rules_are_consistent_across_entry_points():
    data = b'shared rules'
    digest = hashlib.sha256(data).digest()
    assert api.resolve_digest(data=data, hashname='sha256') == digest
    assert api.resolve_digest(data=data, digest=digest, hashname='sha256') == digest
    assert api.resolve_digest(data=b'ignored', digest=digest, hashname='sha256') == digest
    assert api.resolve_digest(data=b'', hashname='sha256') == hashlib.sha256(b'').digest()
    with pytest.raises(ValueError):
        api.resolve_digest(hashname='sha256')
    with pytest.raises(ValueError):
        api.resolve_digest(digest=b'too-short', hashname='sha256')


# ---------------------------------------------------------------------------
# offline TimeStampToken construction / verification
# ---------------------------------------------------------------------------

class OfflineTSA:
    '''A minimal, fully offline RFC 3161 TSA used to exercise verification.'''

    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'offline-tsa')])
        self.now = datetime.datetime(2026, 11, 13, tzinfo=dateutil.tz.tzutc())
        self.certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(1)
            .not_valid_before(self.now - datetime.timedelta(days=1))
            .not_valid_after(self.now + datetime.timedelta(days=3650))
            .sign(self.key, hashes.SHA256())
        )
        self.certificate_der = self.certificate.public_bytes(serialization.Encoding.DER)
        self.certificate_asn1 = decoder.decode(
            self.certificate_der, asn1Spec=rfc2459.Certificate())[0]

    @staticmethod
    def _algorithm_identifier(oid):
        algorithm = rfc2459.AlgorithmIdentifier()
        algorithm.setComponentByPosition(0, oid)
        return algorithm

    @staticmethod
    def _attribute(attribute_type, value):
        attribute = rfc2315.Attribute()
        attribute.setComponentByName('type', attribute_type)
        attribute.getComponentByName('values').setComponentByPosition(0, value)
        return attribute

    def build_tsr(self, hashname, digest, nonce=None, serial=1234):
        hash_oid = api.get_hash_oid(hashname)

        message_imprint = rfc3161ng.MessageImprint()
        message_imprint.setComponentByPosition(0, self._algorithm_identifier(hash_oid))
        message_imprint.setComponentByPosition(1, univ.OctetString(digest))

        tst_info = rfc3161ng.TSTInfo()
        tst_info.setComponentByName('version', 'v1')
        tst_info.setComponentByName('messageImprint', message_imprint)
        tst_info.setComponentByName('serialNumber', serial)
        tst_info.setComponentByName(
            'genTime', useful.GeneralizedTime(self.now.strftime('%Y%m%d%H%M%SZ')))
        if nonce is not None:
            tst_info.setComponentByName('nonce', int(nonce))
        tst_info_der = encoder.encode(tst_info)
        content_digest = hashlib.new(hashname, tst_info_der).digest()

        attributes = rfc2315.Attributes()
        attributes.setComponentByPosition(
            0, self._attribute(ID_CONTENT_TYPE, univ.ObjectIdentifier(rfc3161ng.id_ct_TSTInfo)))
        attributes.setComponentByPosition(
            1, self._attribute(ID_MESSAGE_DIGEST, univ.OctetString(content_digest)))

        # CMS signs the DER of the authenticated attributes as a SET OF.
        signed_attributes = univ.SetOf()
        for index, attribute in enumerate(attributes):
            signed_attributes.setComponentByPosition(index, attribute)
        signature = self.key.sign(
            encoder.encode(signed_attributes),
            padding.PKCS1v15(),
            getattr(hashes, hashname.upper())(),
        )

        signer_info = rfc2315.SignerInfo()
        signer_info.setComponentByName('version', 1)
        issuer_and_serial = rfc2315.IssuerAndSerialNumber()
        issuer_and_serial.setComponentByName(
            'issuer', self.certificate_asn1['tbsCertificate']['issuer'])
        issuer_and_serial.setComponentByName(
            'serialNumber', self.certificate_asn1['tbsCertificate']['serialNumber'])
        signer_info.setComponentByName('issuerAndSerialNumber', issuer_and_serial)
        signer_info.setComponentByName(
            'digestAlgorithm', self._algorithm_identifier(hash_oid))
        tagged_attributes = signer_info.getComponentByName('authenticatedAttributes')
        for index, attribute in enumerate(attributes):
            tagged_attributes.setComponentByPosition(index, attribute)
        signer_info.setComponentByName(
            'digestEncryptionAlgorithm', self._algorithm_identifier(RSA_ENCRYPTION))
        signer_info.setComponentByName('encryptedDigest', univ.OctetString(signature))

        token = rfc3161ng.TimeStampToken()
        token.setComponentByName('contentType', rfc2315.signedData)
        signed_data = token.getComponentByName('content')
        signed_data.setComponentByName('version', 1)
        signed_data.getComponentByName('digestAlgorithms').setComponentByPosition(
            0, self._algorithm_identifier(hash_oid))
        content_info = signed_data.getComponentByName('contentInfo')
        content_info.setComponentByName('contentType', rfc3161ng.id_ct_TSTInfo)
        content_info.setComponentByName('content', univ.OctetString(tst_info_der))
        certificate_choice = rfc2315.ExtendedCertificateOrCertificate()
        certificate_choice.setComponentByName('certificate', self.certificate_asn1)
        signed_data.getComponentByName('certificates').setComponentByPosition(
            0, certificate_choice)
        signed_data.getComponentByName('signerInfos').setComponentByPosition(
            0, signer_info)

        response = rfc3161ng.TimeStampResp()
        status = rfc3161ng.PKIStatusInfo()
        status.setComponentByName('status', 'granted')
        response.setComponentByName('status', status)
        response.setComponentByName('timeStampToken', token)
        return response


@pytest.fixture(scope='module')
def tsa():
    return OfflineTSA()


@pytest.mark.parametrize('hashname', HASHNAMES)
def test_valid_timestamp_verifies(tsa, hashname):
    data = b'data to be timestamped'
    digest = api.data_to_digest(data, hashname)
    response = tsa.build_tsr(hashname, digest)
    token_der = encoder.encode(response.time_stamp_token)

    assert rfc3161ng.check_timestamp(
        token_der, certificate=tsa.certificate_der, data=data, hashname=hashname) is True
    # verification from a precomputed digest must follow the same rules
    assert rfc3161ng.check_timestamp(
        token_der, certificate=tsa.certificate_der, digest=digest, hashname=hashname) is True


def test_empty_message_timestamp_verifies(tsa):
    digest = api.data_to_digest(b'', 'sha256')
    response = tsa.build_tsr('sha256', digest)
    token_der = encoder.encode(response.time_stamp_token)
    assert rfc3161ng.check_timestamp(
        token_der, certificate=tsa.certificate_der, data=b'', hashname='sha256') is True


def test_tampered_data_fails_message_imprint_check(tsa):
    digest = api.data_to_digest(b'original', 'sha256')
    response = tsa.build_tsr('sha256', digest)
    token_der = encoder.encode(response.time_stamp_token)
    with pytest.raises(ValueError):
        rfc3161ng.check_timestamp(
            token_der, certificate=tsa.certificate_der, data=b'tampered', hashname='sha256')


def test_wrong_algorithm_fails_message_imprint_check(tsa):
    digest = api.data_to_digest(b'original', 'sha256')
    response = tsa.build_tsr('sha256', digest)
    token_der = encoder.encode(response.time_stamp_token)
    with pytest.raises(ValueError):
        rfc3161ng.check_timestamp(
            token_der, certificate=tsa.certificate_der, data=b'original', hashname='sha1')


def test_wrong_digest_length_fails_before_signature_check(tsa):
    response = tsa.build_tsr('sha256', api.data_to_digest(b'original', 'sha256'))
    token_der = encoder.encode(response.time_stamp_token)
    with pytest.raises(ValueError):
        rfc3161ng.check_timestamp(
            token_der, certificate=tsa.certificate_der,
            digest=b'\x00' * 10, hashname='sha256')


def test_tampered_signature_fails_cryptographic_check(tsa):
    digest = api.data_to_digest(b'original', 'sha256')
    response = tsa.build_tsr('sha256', digest)
    token = response.time_stamp_token
    signer_info = token.content['signerInfos'][0]
    signature = bytearray(bytes(signer_info['encryptedDigest']))
    signature[0] ^= 0xFF
    signer_info.setComponentByName('encryptedDigest', univ.OctetString(bytes(signature)))
    token_der = encoder.encode(token)
    with pytest.raises(Exception):
        rfc3161ng.check_timestamp(
            token_der, certificate=tsa.certificate_der,
            digest=digest, hashname='sha256')


def test_nonce_is_checked(tsa):
    digest = api.data_to_digest(b'nonced', 'sha256')
    response = tsa.build_tsr('sha256', digest, nonce=123456)
    token_der = encoder.encode(response.time_stamp_token)
    assert rfc3161ng.check_timestamp(
        token_der, certificate=tsa.certificate_der,
        digest=digest, hashname='sha256', nonce=123456) is True
    with pytest.raises(ValueError):
        rfc3161ng.check_timestamp(
            token_der, certificate=tsa.certificate_der,
            digest=digest, hashname='sha256', nonce=654321)


def test_response_round_trips_through_codec(tsa):
    digest = api.data_to_digest(b'round trip', 'sha256')
    response = tsa.build_tsr('sha256', digest, nonce=7)
    encoded = encoder.encode(response)
    decoded = rfc3161ng.decode_timestamp_response(encoded)
    assert encoder.encode(decoded) == encoded


class _FakeHttpResponse:
    def __init__(self, content):
        self.content = content

    def raise_for_status(self):
        return None


@pytest.mark.parametrize('hashname', HASHNAMES)
def test_remote_timestamper_request_matches_direct_request(tsa, hashname):
    timestamper = rfc3161ng.RemoteTimestamper(
        'http://example.invalid', certificate=tsa.certificate_der, hashname=hashname)
    data = b'parity over the wire'
    digest = api.data_to_digest(data, hashname)
    response = tsa.build_tsr(hashname, digest)
    fake = _FakeHttpResponse(rfc3161ng.encode_timestamp_response(response))

    with mock.patch('rfc3161ng.api.requests.post', return_value=fake) as posted:
        token = timestamper(data=data)

    sent_request = rfc3161ng.decode_timestamp_request(posted.call_args.kwargs['data'])
    direct_request = rfc3161ng.make_timestamp_request(data=data, hashname=hashname)
    assert rfc3161ng.encode_timestamp_request(sent_request) == \
        rfc3161ng.encode_timestamp_request(direct_request)
    assert rfc3161ng.check_timestamp(
        token, certificate=tsa.certificate_der, data=data, hashname=hashname) is True


def test_remote_timestamper_accepts_empty_message(tsa):
    timestamper = rfc3161ng.RemoteTimestamper(
        'http://example.invalid', certificate=tsa.certificate_der, hashname='sha256')
    digest = api.data_to_digest(b'', 'sha256')
    response = tsa.build_tsr('sha256', digest)
    fake = _FakeHttpResponse(rfc3161ng.encode_timestamp_response(response))
    with mock.patch('rfc3161ng.api.requests.post', return_value=fake):
        token = timestamper(data=b'')
    assert rfc3161ng.check_timestamp(
        token, certificate=tsa.certificate_der, data=b'', hashname='sha256') is True


def test_remote_timestamper_digest_takes_precedence_over_data(tsa):
    timestamper = rfc3161ng.RemoteTimestamper(
        'http://example.invalid', certificate=tsa.certificate_der, hashname='sha256')
    digest = api.data_to_digest(b'winner', 'sha256')
    response = tsa.build_tsr('sha256', digest)
    fake = _FakeHttpResponse(rfc3161ng.encode_timestamp_response(response))
    with mock.patch('rfc3161ng.api.requests.post', return_value=fake) as posted:
        timestamper(data=b'loser', digest=digest)
    sent_request = rfc3161ng.decode_timestamp_request(posted.call_args.kwargs['data'])
    assert bytes(sent_request['messageImprint'].hashed_message) == digest


def test_remote_timestamper_rejects_bad_digest_length_without_network(tsa):
    timestamper = rfc3161ng.RemoteTimestamper(
        'http://example.invalid', certificate=tsa.certificate_der, hashname='sha256')
    with mock.patch('rfc3161ng.api.requests.post') as posted:
        with pytest.raises(ValueError):
            timestamper(digest=b'\x00' * 3)
        posted.assert_not_called()
