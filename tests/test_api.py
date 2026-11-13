"""Offline tests for RFC 3161 timestamp verification.

The tests in this module build TimeStampTokens locally so that no network
access is required.  TSA servers are exercised by the integration tests at
the bottom of the file and are not part of the offline test run.
"""

import hashlib
import os.path
import datetime
import dateutil.tz
import subprocess
import pytest

from tempfile import NamedTemporaryFile
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag, univ
from pyasn1_modules import rfc2315, rfc2459, rfc3279, rfc4055
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

import rfc3161ng
from rfc3161ng import api


def _default_test(tsa_server, certificate=None, username=None, password=None, data='xx', nonce=None, **kwargs):
    if certificate:
        with open(certificate, 'rb') as f:
            certificate_data = f.read()

        kwargs.update({
            'certificate': certificate_data,
        })

    if username and password:
        kwargs.update({
            'username': username,
            'password': password,
        })

    timestamper = rfc3161ng.RemoteTimestamper(tsa_server, **kwargs)
    kwargs = {}
    if nonce:
        kwargs['nonce'] = nonce
    value = timestamper(data=data, **kwargs)
    assert value is not False
    assert isinstance(rfc3161ng.get_timestamp(value), datetime.datetime)
    assert value is not None


def _algorithm_identifier(oid, parameters=None):
    algorithm_identifier = rfc2459.AlgorithmIdentifier()
    algorithm_identifier.setComponentByPosition(0, oid)
    if parameters is not None:
        algorithm_identifier.setComponentByPosition(1, parameters)
    return algorithm_identifier


def _make_certificate(private_key):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'Local Test TSA')])
    not_before = datetime.datetime(2026, 1, 1)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(1)
        .not_valid_before(not_before)
        .not_valid_after(not_before + datetime.timedelta(days=365))
    )
    return builder.sign(private_key, hashes.SHA256())


def _make_tst_info(data, hashname='sha256'):
    tst_info = rfc3161ng.TSTInfo()
    tst_info.setComponentByPosition(0, 1)
    tst_info.setComponentByPosition(1, rfc3161ng.types.TSAPolicyId('1.2.3.4'))
    message_imprint = rfc3161ng.MessageImprint()
    message_imprint.setComponentByPosition(0, _algorithm_identifier(rfc3161ng.get_hash_oid(hashname)))
    message_imprint.setComponentByPosition(1, hashlib.new(hashname, data).digest())
    tst_info.setComponentByPosition(2, message_imprint)
    tst_info.setComponentByPosition(3, 42)
    tst_info.setComponentByPosition(4, '20260101120000Z')
    return tst_info


def _pss_parameters(hashname='sha256', mgf_hashname='sha256', salt_length=32,
                    declared_hashname=None, declared_mgf_hashname=None):
    '''Build RSASSA-PSS-params.

    The signed signature uses ``hashname``/``mgf_hashname``/``salt_length``;
    the ``declared_*`` arguments allow the test to advertise different
    parameters in the algorithm identifier than were used for signing.
    '''
    pss_parameters = rfc4055.RSASSA_PSS_params()

    hash_algorithm = pss_parameters.componentType.getTypeByPosition(0).clone()
    hash_algorithm.setComponentByPosition(
        0, rfc3161ng.get_hash_oid(declared_hashname or hashname))
    pss_parameters.setComponentByPosition(0, hash_algorithm)

    mask_gen_algorithm = pss_parameters.componentType.getTypeByPosition(1).clone()
    mask_gen_algorithm.setComponentByPosition(0, rfc3161ng.id_mgf1)
    mask_gen_algorithm.setComponentByPosition(
        1, encoder.encode(_algorithm_identifier(
            rfc3161ng.get_hash_oid(declared_mgf_hashname or mgf_hashname))))
    pss_parameters.setComponentByPosition(1, mask_gen_algorithm)

    pss_parameters.setComponentByPosition(2, salt_length)
    return pss_parameters


def _make_token(private_key, certificate, data, signature_algorithm='rsa',
                with_signed_attributes=True, hashname='sha256',
                declared_signature_oid=None, pss_hashname='sha256',
                pss_mgf_hashname='sha256', pss_salt_length=32,
                declared_pss_hashname=None, declared_pss_mgf_hashname=None,
                pss_trailer_field=None, raw_ecdsa_signature=False):
    tst_info = _make_tst_info(data, hashname)
    tst_info_der = encoder.encode(tst_info)

    token = rfc3161ng.TimeStampToken()
    token.setComponentByPosition(0, rfc2315.signedData)
    signed_data = token.componentType.getTypeByPosition(1).clone()
    signed_data.setComponentByPosition(0, 3)

    digest_algorithms = rfc2315.DigestAlgorithmIdentifiers()
    digest_algorithms.setComponentByPosition(
        0, _algorithm_identifier(rfc3161ng.get_hash_oid(hashname)))
    signed_data.setComponentByPosition(1, digest_algorithms)

    content_info = rfc2315.ContentInfo()
    content_info.setComponentByPosition(0, rfc3161ng.id_ct_TSTInfo)
    content_info.setComponentByPosition(
        1, encoder.encode(univ.OctetString(tst_info_der)))
    signed_data.setComponentByPosition(2, content_info)

    signer_info = rfc2315.SignerInfo()
    signer_info.setComponentByPosition(0, 1)
    issuer_and_serial = rfc2315.IssuerAndSerialNumber()
    issuer, substrate = decoder.decode(certificate.issuer.public_bytes(), asn1Spec=rfc2459.Name())
    assert not substrate
    issuer_and_serial.setComponentByPosition(0, issuer)
    issuer_and_serial.setComponentByPosition(1, certificate.serial_number)
    signer_info.setComponentByPosition(1, issuer_and_serial)
    signer_info.setComponentByPosition(
        2, _algorithm_identifier(rfc3161ng.get_hash_oid(hashname)))

    if with_signed_attributes:
        attributes = rfc2315.Attributes().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
        message_digest = rfc2315.Attribute()
        message_digest.setComponentByPosition(0, api.id_attribute_messageDigest)
        message_digest_values = message_digest.componentType.getTypeByPosition(1).clone()
        message_digest_values.setComponentByPosition(
            0,
            encoder.encode(univ.OctetString(hashlib.new(hashname, tst_info_der).digest())))
        message_digest.setComponentByPosition(1, message_digest_values)
        attributes.setComponentByPosition(0, message_digest)
        signer_info.setComponentByPosition(3, attributes)

        signed_attributes = rfc2315.Attributes()
        for position, attribute in enumerate(attributes):
            signed_attributes.setComponentByPosition(position, attribute)
        signed = encoder.encode(signed_attributes)
    else:
        signed = tst_info_der

    pss_parameters = None
    if signature_algorithm == 'rsa':
        signature_oid = declared_signature_oid or rfc3161ng.id_rsaEncryption
        signature = private_key.sign(
            signed, padding.PKCS1v15(), getattr(hashes, hashname.upper())())
    elif signature_algorithm == 'pss':
        signature_oid = declared_signature_oid or rfc3161ng.id_RSASSA_PSS
        pss_parameters = _pss_parameters(
            pss_hashname, pss_mgf_hashname, pss_salt_length,
            declared_hashname=declared_pss_hashname,
            declared_mgf_hashname=declared_pss_mgf_hashname)
        if pss_trailer_field is not None:
            pss_parameters.setComponentByPosition(3, pss_trailer_field)
        signature = private_key.sign(
            signed,
            padding.PSS(
                mgf=padding.MGF1(getattr(hashes, pss_mgf_hashname.upper())()),
                salt_length=pss_salt_length,
            ),
            getattr(hashes, pss_hashname.upper())(),
        )
    elif signature_algorithm == 'ecdsa':
        signature_oid = declared_signature_oid or getattr(
            rfc3161ng, 'id_ecdsa_with_' + hashname.upper())
        signature = private_key.sign(
            signed, ec.ECDSA(getattr(hashes, hashname.upper())()))
        if raw_ecdsa_signature:
            values = decoder.decode(signature, asn1Spec=rfc3279.ECDSA_Sig_Value())[0]
            width = (private_key.curve.key_size + 7) // 8
            signature = (
                int(values['r']).to_bytes(width, 'big') +
                int(values['s']).to_bytes(width, 'big')
            )
    elif signature_algorithm == 'unknown':
        signature_oid = declared_signature_oid or univ.ObjectIdentifier('1.2.3.4.5.6.7')
        signature = private_key.sign(
            signed, padding.PKCS1v15(), hashes.SHA256())
    else:
        raise AssertionError('unknown test signature algorithm %r' % (signature_algorithm,))

    signer_info.setComponentByPosition(
        4, _algorithm_identifier(
            signature_oid,
            None if pss_parameters is None else encoder.encode(pss_parameters)))
    signer_info.setComponentByPosition(5, signature)

    signer_infos = rfc2315.SignerInfos()
    signer_infos.setComponentByPosition(0, signer_info)
    signed_data.setComponentByPosition(5, signer_infos)

    token.setComponentByPosition(1, signed_data)
    return encoder.encode(token)


def _certificate_der(certificate):
    return certificate.public_bytes(serialization.Encoding.DER)


_CONTENT = b'local timestamp token content'


@pytest.fixture(params=[True, False], ids=['signed-attributes', 'no-signed-attributes'])
def with_signed_attributes(request):
    return request.param


@pytest.fixture(scope='module')
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope='module')
def ec_key():
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope='module')
def rsa_certificate(rsa_key):
    return _make_certificate(rsa_key)


@pytest.fixture(scope='module')
def ec_certificate(ec_key):
    return _make_certificate(ec_key)


def test_verify_rsa_pkcs1v15_timestamp(rsa_key, rsa_certificate, with_signed_attributes):
    token = _make_token(
        rsa_key, rsa_certificate, _CONTENT,
        signature_algorithm='rsa', with_signed_attributes=with_signed_attributes)
    assert api.check_timestamp(
        token, certificate=_certificate_der(rsa_certificate), data=_CONTENT,
        hashname='sha256')


@pytest.mark.parametrize('hashname', ['sha256', 'sha384', 'sha512'])
def test_verify_rsa_pss_timestamp(rsa_key, rsa_certificate, with_signed_attributes, hashname):
    token = _make_token(
        rsa_key, rsa_certificate, _CONTENT,
        signature_algorithm='pss', with_signed_attributes=with_signed_attributes,
        hashname=hashname, pss_hashname=hashname, pss_mgf_hashname=hashname,
        pss_salt_length=hashlib.new(hashname).digest_size)
    assert api.check_timestamp(
        token, certificate=_certificate_der(rsa_certificate), data=_CONTENT,
        hashname=hashname)


def test_verify_rsa_pss_with_separate_mgf_hash_and_salt(rsa_key, rsa_certificate, with_signed_attributes):
    token = _make_token(
        rsa_key, rsa_certificate, _CONTENT,
        signature_algorithm='pss', with_signed_attributes=with_signed_attributes,
        hashname='sha256', pss_hashname='sha256', pss_mgf_hashname='sha1',
        pss_salt_length=20)
    assert api.check_timestamp(
        token, certificate=_certificate_der(rsa_certificate), data=_CONTENT,
        hashname='sha256')


@pytest.mark.parametrize('hashname', ['sha256', 'sha384', 'sha512'])
def test_verify_ecdsa_timestamp(ec_key, ec_certificate, with_signed_attributes, hashname):
    token = _make_token(
        ec_key, ec_certificate, _CONTENT,
        signature_algorithm='ecdsa', with_signed_attributes=with_signed_attributes,
        hashname=hashname)
    assert api.check_timestamp(
        token, certificate=_certificate_der(ec_certificate), data=_CONTENT,
        hashname=hashname)


def test_reject_rsa_pss_salt_length_mismatch(rsa_key, rsa_certificate, with_signed_attributes):
    token = _make_token(
        rsa_key, rsa_certificate, _CONTENT,
        signature_algorithm='pss', with_signed_attributes=with_signed_attributes,
        pss_salt_length=32)
    # Advertise a salt length different from the one used for signing.
    parsed, substrate = decoder.decode(token, asn1Spec=rfc3161ng.TimeStampToken())
    assert not substrate
    signer_info = parsed.content['signerInfos'][0]
    parameters = decoder.decode(
        bytes(signer_info['digestEncryptionAlgorithm']['parameters']),
        asn1Spec=rfc4055.RSASSA_PSS_params())[0]
    parameters.setComponentByPosition(2, 20)
    signer_info['digestEncryptionAlgorithm'].setComponentByPosition(1, encoder.encode(parameters))
    with pytest.raises(ValueError):
        api.check_timestamp(
            encoder.encode(parsed),
            certificate=_certificate_der(rsa_certificate), data=_CONTENT,
            hashname='sha256')


def test_reject_rsa_pss_hash_parameter_mismatch(rsa_key, rsa_certificate, with_signed_attributes):
    token = _make_token(
        rsa_key, rsa_certificate, _CONTENT,
        signature_algorithm='pss', with_signed_attributes=with_signed_attributes,
        hashname='sha256', pss_hashname='sha256',
        declared_pss_hashname='sha512')
    with pytest.raises(ValueError):
        api.check_timestamp(
            token, certificate=_certificate_der(rsa_certificate), data=_CONTENT,
            hashname='sha256')


def test_reject_rsa_pss_mgf_parameter_mismatch(rsa_key, rsa_certificate, with_signed_attributes):
    token = _make_token(
        rsa_key, rsa_certificate, _CONTENT,
        signature_algorithm='pss', with_signed_attributes=with_signed_attributes,
        pss_hashname='sha256', pss_mgf_hashname='sha256',
        declared_pss_mgf_hashname='sha1')
    with pytest.raises(ValueError):
        api.check_timestamp(
            token, certificate=_certificate_der(rsa_certificate), data=_CONTENT,
            hashname='sha256')


def test_reject_rsa_pss_unsupported_trailer_field(rsa_key, rsa_certificate, with_signed_attributes):
    token = _make_token(
        rsa_key, rsa_certificate, _CONTENT,
        signature_algorithm='pss', with_signed_attributes=with_signed_attributes,
        pss_trailer_field=2)
    with pytest.raises(api.UnsupportedAlgorithmError):
        api.check_timestamp(
            token, certificate=_certificate_der(rsa_certificate), data=_CONTENT,
            hashname='sha256')


def test_reject_ecdsa_signature_in_raw_format(ec_key, ec_certificate, with_signed_attributes):
    token = _make_token(
        ec_key, ec_certificate, _CONTENT,
        signature_algorithm='ecdsa', with_signed_attributes=with_signed_attributes,
        raw_ecdsa_signature=True)
    with pytest.raises(ValueError):
        api.check_timestamp(
            token, certificate=_certificate_der(ec_certificate), data=_CONTENT,
            hashname='sha256')


def test_reject_unknown_signature_algorithm(rsa_key, rsa_certificate, with_signed_attributes):
    token = _make_token(
        rsa_key, rsa_certificate, _CONTENT,
        signature_algorithm='unknown', with_signed_attributes=with_signed_attributes)
    # The signature bytes are a valid PKCS#1 v1.5 signature for the RSA key,
    # but an unknown algorithm identifier must never fall back to it.
    with pytest.raises(api.UnsupportedAlgorithmError) as exc_info:
        api.check_timestamp(
            token, certificate=_certificate_der(rsa_certificate), data=_CONTENT,
            hashname='sha256')
    assert 'unsupported signature algorithm' in str(exc_info.value)
    assert '1.2.3.4.5.6.7' in str(exc_info.value)


def test_reject_unknown_digest_algorithm(rsa_key, rsa_certificate):
    token = _make_token(
        rsa_key, rsa_certificate, _CONTENT, signature_algorithm='rsa',
        with_signed_attributes=True)
    parsed, substrate = decoder.decode(token, asn1Spec=rfc3161ng.TimeStampToken())
    assert not substrate
    signer_infos = parsed.content['signerInfos']
    signer_infos[0]['digestAlgorithm'].setComponentByPosition(
        0, univ.ObjectIdentifier('1.2.3.4.5'))
    with pytest.raises(api.UnsupportedAlgorithmError):
        api.check_timestamp(
            encoder.encode(parsed), certificate=_certificate_der(rsa_certificate),
            data=_CONTENT, hashname='sha256')


def test_reject_ecdsa_signature_with_rsa_key(rsa_key, rsa_certificate):
    token = _make_token(
        rsa_key, rsa_certificate, _CONTENT,
        signature_algorithm='rsa', declared_signature_oid=rfc3161ng.id_ecdsa_with_SHA256)
    with pytest.raises(ValueError):
        api.check_timestamp(
            token, certificate=_certificate_der(rsa_certificate), data=_CONTENT,
            hashname='sha256')


def test_reject_rsa_pss_signature_with_ec_key(ec_key, ec_certificate):
    token = _make_token(
        ec_key, ec_certificate, _CONTENT,
        signature_algorithm='ecdsa', declared_signature_oid=rfc3161ng.id_RSASSA_PSS)
    with pytest.raises(ValueError):
        api.check_timestamp(
            token, certificate=_certificate_der(ec_certificate), data=_CONTENT,
            hashname='sha256')


def test_reject_rsa_pkcs1v15_hash_algorithm_mismatch(rsa_key, rsa_certificate):
    token = _make_token(
        rsa_key, rsa_certificate, _CONTENT,
        signature_algorithm='rsa', hashname='sha256',
        declared_signature_oid=rfc3161ng.id_sha512WithRSAEncryption)
    with pytest.raises(ValueError):
        api.check_timestamp(
            token, certificate=_certificate_der(rsa_certificate), data=_CONTENT,
            hashname='sha256')


def test_reject_ecdsa_hash_algorithm_mismatch(ec_key, ec_certificate):
    token = _make_token(
        ec_key, ec_certificate, _CONTENT,
        signature_algorithm='ecdsa', hashname='sha256',
        declared_signature_oid=rfc3161ng.id_ecdsa_with_SHA384)
    with pytest.raises(ValueError):
        api.check_timestamp(
            token, certificate=_certificate_der(ec_certificate), data=_CONTENT,
            hashname='sha256')


def test_verify_rsa_pss_with_default_parameters(rsa_key, rsa_certificate):
    # An absent RSASSA-PSS-params means SHA-1/MGF1-SHA-1/saltLength 20
    # (RFC 4055 section 3.1).  Sign accordingly and omit the parameters.
    token = _make_token(
        rsa_key, rsa_certificate, _CONTENT,
        signature_algorithm='pss', hashname='sha1', pss_hashname='sha1',
        pss_mgf_hashname='sha1', pss_salt_length=20)
    parsed, substrate = decoder.decode(token, asn1Spec=rfc3161ng.TimeStampToken())
    assert not substrate
    parsed.content['signerInfos'][0]['digestEncryptionAlgorithm'].setComponentByPosition(
        1, univ.Any())
    # An empty parameters field is also valid and means the same defaults.
    token = encoder.encode(parsed)
    assert api.check_timestamp(
        token, certificate=_certificate_der(rsa_certificate), data=_CONTENT,
        hashname='sha1')


def test_verify_rsa_pkcs1v15_with_digest_named_algorithm(rsa_key, rsa_certificate):
    token = _make_token(
        rsa_key, rsa_certificate, _CONTENT,
        signature_algorithm='rsa', hashname='sha256',
        declared_signature_oid=rfc3161ng.id_sha256WithRSAEncryption)
    assert api.check_timestamp(
        token, certificate=_certificate_der(rsa_certificate), data=_CONTENT,
        hashname='sha256')


def test_reject_unknown_mask_generation_function(rsa_key, rsa_certificate):
    token = _make_token(
        rsa_key, rsa_certificate, _CONTENT,
        signature_algorithm='pss', with_signed_attributes=True)
    parsed, substrate = decoder.decode(token, asn1Spec=rfc3161ng.TimeStampToken())
    assert not substrate
    parameters = decoder.decode(
        bytes(parsed.content['signerInfos'][0]['digestEncryptionAlgorithm']['parameters']),
        asn1Spec=rfc4055.RSASSA_PSS_params())[0]
    mask_gen = parameters.componentType.getTypeByPosition(1).clone()
    mask_gen.setComponentByPosition(0, univ.ObjectIdentifier('1.2.3.4.5.6'))
    mask_gen.setComponentByPosition(
        1, encoder.encode(_algorithm_identifier(rfc3161ng.id_sha256)))
    parameters.setComponentByPosition(1, mask_gen)
    parsed.content['signerInfos'][0]['digestEncryptionAlgorithm'].setComponentByPosition(
        1, encoder.encode(parameters))
    with pytest.raises(api.UnsupportedAlgorithmError):
        api.check_timestamp(
            encoder.encode(parsed), certificate=_certificate_der(rsa_certificate),
            data=_CONTENT, hashname='sha256')


def test_reject_invalid_ecdsa_signature_values(ec_key, ec_certificate):
    token = _make_token(
        ec_key, ec_certificate, _CONTENT,
        signature_algorithm='ecdsa', with_signed_attributes=True)
    parsed, substrate = decoder.decode(token, asn1Spec=rfc3161ng.TimeStampToken())
    assert not substrate
    parsed.content['signerInfos'][0]['encryptedDigest'] = bytes.fromhex(
        '3006020100020101')
    with pytest.raises(ValueError):
        api.check_timestamp(
            encoder.encode(parsed), certificate=_certificate_der(ec_certificate),
            data=_CONTENT, hashname='sha256')


def test_reject_invalid_rsa_pss_parameters(rsa_key, rsa_certificate):
    token = _make_token(
        rsa_key, rsa_certificate, _CONTENT,
        signature_algorithm='pss', with_signed_attributes=True)
    parsed, substrate = decoder.decode(token, asn1Spec=rfc3161ng.TimeStampToken())
    assert not substrate
    parsed.content['signerInfos'][0]['digestEncryptionAlgorithm'].setComponentByPosition(
        1, univ.Any(b'\x30\x03\x02\x01\x01'))
    with pytest.raises(ValueError):
        api.check_timestamp(
            encoder.encode(parsed), certificate=_certificate_der(rsa_certificate),
            data=_CONTENT, hashname='sha256')


def test_reject_message_imprint_mismatch(rsa_key, rsa_certificate):
    token = _make_token(
        rsa_key, rsa_certificate, _CONTENT, signature_algorithm='rsa')
    with pytest.raises(ValueError):
        api.check_timestamp(
            token, certificate=_certificate_der(rsa_certificate), data=b'other data',
            hashname='sha256')


def test_verify_timestamp_response_with_openssl():
    with open(os.path.join(os.path.dirname(__file__), '../data/freetsa.crt'), 'rb') as f:
        certificate_data = f.read()

    timestamper = rfc3161ng.RemoteTimestamper('http://freetsa.org/tsr', certificate=certificate_data)

    with NamedTemporaryFile() as data_f, NamedTemporaryFile() as tsr_f:
        data_f.write(b"Hello World from rfc3161ng\n")
        data_f.flush()
        data_f.seek(0)

        tsr = timestamper(data=data_f.read(), return_tsr=True)
        tsr_f.write(encoder.encode(tsr))
        tsr_f.flush()

        args = ["openssl", "ts", "-verify", "-data", data_f.name, "-in", tsr_f.name, "-CAfile", "data/freetsa_cacert.pem", "-untrusted", "data/freetsa.crt"]
        subprocess.check_call(args)


def test_time_certum_pl():
    _default_test(
        'http://time.certum.pl',
        os.path.join(os.path.dirname(__file__), '../data/certum_certificate.crt'),
    )


@pytest.mark.xfail
def test_redwax_eu():
    # https://interop.redwax.eu/rs/timestamp/
    # CA:  https://interop.redwax.eu/test/simple/ca.der
    # Server: 'https://interop.redwax.eu/test/timestamp
    _default_test(
        'https://interop.redwax.eu/test/timestamp',
        certificate=os.path.join('data/redwax-interop-ca.crt'),
        data=b'The RedWax Project',
        hashname='sha256',
    )


@pytest.mark.xfail
def test_redwax_eu_no_certificate():
    # https://interop.redwax.eu/rs/timestamp/
    # CA:  https://interop.redwax.eu/test/simple/ca.der
    # Server: 'https://interop.redwax.eu/test/timestamp
    _default_test(
        'https://interop.redwax.eu/test/timestamp',
        data=b'The RedWax Project',
        hashname='sha256',
    )


def test_freetsa_org():
    _default_test(
        'http://freetsa.org/tsr',
        os.path.join('data/freetsa.crt'),
    )


def test_teszt_e_szigno_hu():
    data = '{"comment": "Envoi en Commission", "to": "Benjamin Dauvergne", "filetype": "Arr\u00eat CC", "from": "Benjamin Dauvergne", "files": [{"name": "affectations_ange1d.xlsx", "digest": "ce57e4ba353107dddaab91b9ad26c0569ffe0f94", "size": 16279}]}'
    _default_test(
        'https://teszt.e-szigno.hu:440/tsa',
        username='teszt',
        password='teszt',
        certificate=os.path.join(os.path.dirname(__file__), '../data/e_szigno_test_tsa2.crt'),
        data=data,
        hashname='sha256',
    )


def test_teszt_e_szigno_hu_with_nonce():
    data = '{"comment": "Envoi en Commission", "to": "Benjamin Dauvergne", "filetype": "Arr\u00eat CC", "from": "Benjamin Dauvergne", "files": [{"name": "affectations_ange1d.xlsx", "digest": "ce57e4ba353107dddaab91b9ad26c0569ffe0f94", "size": 16279}]}'
    _default_test(
        'https://teszt.e-szigno.hu:440/tsa',
        username='teszt',
        password='teszt',
        certificate=os.path.join(os.path.dirname(__file__), '../data/e_szigno_test_tsa2.crt'),
        data=data,
        nonce=2,
        hashname='sha256',
    )


def test_encode_decode_timestamp_request():
    tsq = rfc3161ng.make_timestamp_request(data="test")
    pretty_print_str = "TimeStampReq:\n version=v1\n messageImprint=MessageImprint:\n  hashAlgorithm=AlgorithmIdentifier:\n   algorithm=1.3.14.3.2.26\n\n  hashedMessage=0xa94a8fe5ccb19ba61c4c0873d391e987982fbbd3\n\n certReq=False\n"
    # Some versions of prettyPrint() include quotes, others do not.
    # Hide the difference by removing the quotes.
    assert tsq.prettyPrint().replace("'", "") == pretty_print_str
    bin_tsq = rfc3161ng.encode_timestamp_request(tsq)
    assert bin_tsq == b'0$\x02\x01\x010\x1f0\x07\x06\x05+\x0e\x03\x02\x1a\x04\x14\xa9J\x8f\xe5\xcc\xb1\x9b\xa6\x1cL\x08s\xd3\x91\xe9\x87\x98/\xbb\xd3'
    tsq2 = rfc3161ng.decode_timestamp_request(bin_tsq)
    assert tsq2.getComponentByPosition(1).getComponentByPosition(1) == tsq.getComponentByPosition(1).getComponentByPosition(1)
    # This test is probably still incomplete


def test_generalized_time_decoding():
    from rfc3161ng.api import generalizedtime_to_utc_datetime

    # generalizedTime string, naive == expected datetime
    assert generalizedtime_to_utc_datetime('20180208181004,948468', True) == datetime.datetime(2018, 2, 8, 18, 10, 4, 948468)
    assert generalizedtime_to_utc_datetime('20180208181004', True) == datetime.datetime(2018, 2, 8, 18, 10, 4, 0)
    assert generalizedtime_to_utc_datetime('201802081810', True) == datetime.datetime(2018, 2, 8, 18, 10, 0, 0)
    assert generalizedtime_to_utc_datetime('2018020818', True) == datetime.datetime(2018, 2, 8, 18, 0, 0, 0)
    assert generalizedtime_to_utc_datetime('20180208181004.948468Z', True) == datetime.datetime(2018, 2, 8, 18, 10, 4, 948468)
    assert generalizedtime_to_utc_datetime('20180208181004.948468+01', True) == datetime.datetime(2018, 2, 8, 17, 10, 4, 948468)
    assert generalizedtime_to_utc_datetime('20180208181004.948468-01', True) == datetime.datetime(2018, 2, 8, 19, 10, 4, 948468)
    assert generalizedtime_to_utc_datetime('20180208181004.948468+0130', True) == datetime.datetime(2018, 2, 8, 16, 40, 4, 948468)
    assert generalizedtime_to_utc_datetime('20180208181004.948468Z', False) == datetime.datetime(2018, 2, 8, 18, 10, 4, 948468, tzinfo=dateutil.tz.tzutc())
    assert generalizedtime_to_utc_datetime('20180208181004.948468-01', False) == datetime.datetime(2018, 2, 8, 19, 10, 4, 948468, tzinfo=dateutil.tz.tzutc())
    assert generalizedtime_to_utc_datetime('20180208181004.948468+0130', False) == datetime.datetime(2018, 2, 8, 16, 40, 4, 948468, tzinfo=dateutil.tz.tzutc())
