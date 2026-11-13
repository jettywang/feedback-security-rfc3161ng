import hashlib

import pytest
from pyasn1.codec.der import encoder
from pyasn1.type import univ, tag
from pyasn1_modules import rfc2315, rfc2459

import rfc3161ng
from rfc3161ng import types


TEST_DATA = b'evidence-bound-payload'
REQUEST_POLICY = '1.2.3.4.5'
OTHER_POLICY = '1.9.9.9'
REQUEST_NONCE = 123456789


def _digest(data=TEST_DATA, hashname='sha1'):
    hashobj = hashlib.new(hashname)
    hashobj.update(data)
    return hashobj.digest()


def _status_info(status, status_string=None, fail_bits=None):
    status_info = rfc3161ng.PKIStatusInfo()
    status_info.setComponentByName('status', status)
    if status_string is not None:
        free_text = rfc3161ng.PKIFreeText()
        free_text.setComponentByPosition(0, status_string)
        status_info.setComponentByName('statusString', free_text)
    if fail_bits:
        status_info.setComponentByName(
            'failInfo',
            rfc3161ng.PKIFailureInfo(value=','.join(fail_bits)),
        )
    return status_info


def _build_tst(digest, policy=REQUEST_POLICY, nonce=REQUEST_NONCE, hash_oid=None):
    tst_info = rfc3161ng.TSTInfo()
    tst_info.setComponentByName('version', 'v1')
    if policy is not None:
        tst_info.setComponentByName('policy', types.TSAPolicyId(policy))

    algorithm = rfc2459.AlgorithmIdentifier()
    algorithm.setComponentByPosition(0, hash_oid or rfc3161ng.id_sha1)
    message_imprint = rfc3161ng.MessageImprint()
    message_imprint.setComponentByName('hashAlgorithm', algorithm)
    message_imprint.setComponentByName('hashedMessage', digest)

    tst_info.setComponentByName('messageImprint', message_imprint)
    tst_info.setComponentByName('serialNumber', 42)
    tst_info.setComponentByName('genTime', '20261113000000Z')
    if nonce is not None:
        tst_info.setComponentByName('nonce', nonce)

    content_info = rfc2315.ContentInfo()
    content_info.setComponentByName('contentType', rfc3161ng.id_ct_TSTInfo)
    content_info.setComponentByName('content', univ.OctetString(encoder.encode(tst_info)))

    signed_data = rfc2315.SignedData().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
    )
    signed_data.setComponentByName('version', 1)
    signed_data.setComponentByName('digestAlgorithms', rfc2315.DigestAlgorithmIdentifiers())
    signed_data.setComponentByName('contentInfo', content_info)
    signed_data.setComponentByName('signerInfos', rfc2315.SignerInfos())

    tst = rfc3161ng.TimeStampToken()
    tst.setComponentByName('contentType', rfc2315.signedData)
    tst.setComponentByName('content', signed_data)
    return tst


def _build_tsr(status, token=None, status_string=None, fail_bits=None):
    tsr = rfc3161ng.TimeStampResp()
    tsr.setComponentByName('status', _status_info(status, status_string, fail_bits))
    if token is not None:
        tsr.setComponentByName('timeStampToken', token)
    return tsr


class _FakeHTTPResponse(object):
    def __init__(self, content):
        self.content = content

    def raise_for_status(self):
        # HTTP transport succeeded; acceptance must be decided by the PKI body.
        return None


def _install_transport(monkeypatch, tsr, captured):
    def fake_post(url, data=None, timeout=None, headers=None):
        captured['url'] = url
        captured['request'] = data
        captured['timeout'] = timeout
        captured['headers'] = headers
        return _FakeHTTPResponse(encoder.encode(tsr))

    monkeypatch.setattr(rfc3161ng.api.requests, 'post', fake_post)


def _timestamper(**kwargs):
    options = {'hashname': 'sha1', 'tsa_policy_id': REQUEST_POLICY}
    options.update(kwargs)
    return rfc3161ng.RemoteTimestamper('http://timestamp.example/tsr', **options)


def test_granted_response_is_accepted_without_tsa_certificate(monkeypatch):
    digest = _digest()
    tsr = _build_tsr('granted', token=_build_tst(digest))
    captured = {}
    _install_transport(monkeypatch, tsr, captured)

    timestamper = _timestamper()
    result = timestamper(data=TEST_DATA, nonce=REQUEST_NONCE)

    assert isinstance(result, bytes)
    assert result == encoder.encode(tsr.time_stamp_token)
    assert captured['request'] == rfc3161ng.encode_timestamp_request(
        rfc3161ng.make_timestamp_request(
            data=TEST_DATA,
            digest=digest,
            hashname='sha1',
            nonce=REQUEST_NONCE,
            tsa_policy_id=REQUEST_POLICY,
        )
    )


def test_granted_response_return_tsr(monkeypatch):
    digest = _digest()
    tsr = _build_tsr('granted', token=_build_tst(digest))
    _install_transport(monkeypatch, tsr, {})

    result = _timestamper()(data=TEST_DATA, nonce=REQUEST_NONCE, return_tsr=True)

    assert encoder.encode(result) == encoder.encode(tsr)


def test_rejection_with_token_raises_and_never_returns_token(monkeypatch):
    token = _build_tst(_digest())
    tsr = _build_tsr(
        'rejection',
        token=token,
        status_string='request rejected',
        fail_bits=['badRequest'],
    )
    _install_transport(monkeypatch, tsr, {})

    with pytest.raises(rfc3161ng.TimestampingError) as exc_info:
        _timestamper()(data=TEST_DATA, nonce=REQUEST_NONCE)

    message = str(exc_info.value)
    assert 'rejection' in message
    assert 'PKIStatus 2' in message
    assert 'badRequest' in message
    assert 'request rejected' in message
    assert encoder.encode(token) not in message.encode()


def test_granted_with_mods_is_rejected_even_with_token(monkeypatch):
    token = _build_tst(_digest())
    tsr = _build_tsr('grantedWithMods', token=token)
    _install_transport(monkeypatch, tsr, {})

    with pytest.raises(rfc3161ng.TimestampingError) as exc_info:
        _timestamper()(data=TEST_DATA, nonce=REQUEST_NONCE)

    assert 'grantedWithMods' in str(exc_info.value)
    assert 'PKIStatus 1' in str(exc_info.value)


def test_granted_without_token_raises(monkeypatch):
    tsr = _build_tsr('granted')
    _install_transport(monkeypatch, tsr, {})

    with pytest.raises(rfc3161ng.TimestampingError) as exc_info:
        _timestamper()(data=TEST_DATA, nonce=REQUEST_NONCE)

    assert 'TimeStampToken' in str(exc_info.value)


def test_missing_nonce_raises_without_tsa_certificate(monkeypatch):
    token = _build_tst(_digest(), nonce=None)
    tsr = _build_tsr('granted', token=token)
    _install_transport(monkeypatch, tsr, {})

    # No certificate is configured, yet the nonce association check must run.
    timestamper = _timestamper()
    assert timestamper.certificate is None
    with pytest.raises(rfc3161ng.TimestampingError) as exc_info:
        timestamper(data=TEST_DATA, nonce=REQUEST_NONCE)

    assert 'nonce' in str(exc_info.value)


def test_wrong_nonce_raises(monkeypatch):
    token = _build_tst(_digest(), nonce=REQUEST_NONCE + 1)
    tsr = _build_tsr('granted', token=token)
    _install_transport(monkeypatch, tsr, {})

    with pytest.raises(rfc3161ng.TimestampingError) as exc_info:
        _timestamper()(data=TEST_DATA, nonce=REQUEST_NONCE)

    assert 'nonce' in str(exc_info.value)


def test_replaced_policy_raises(monkeypatch):
    token = _build_tst(_digest(), policy=OTHER_POLICY)
    tsr = _build_tsr('granted', token=token)
    _install_transport(monkeypatch, tsr, {})

    with pytest.raises(rfc3161ng.TimestampingError) as exc_info:
        _timestamper()(data=TEST_DATA, nonce=REQUEST_NONCE)

    assert 'policy' in str(exc_info.value)
    assert REQUEST_POLICY in str(exc_info.value)


def test_missing_policy_raises_when_requested(monkeypatch):
    token = _build_tst(_digest(), policy=None)
    tsr = _build_tsr('granted', token=token)
    _install_transport(monkeypatch, tsr, {})

    with pytest.raises(rfc3161ng.TimestampingError) as exc_info:
        _timestamper()(data=TEST_DATA, nonce=REQUEST_NONCE)

    assert 'policy' in str(exc_info.value)


def test_message_imprint_digest_mismatch_raises(monkeypatch):
    token = _build_tst(b'X' * 20)
    tsr = _build_tsr('granted', token=token)
    _install_transport(monkeypatch, tsr, {})

    with pytest.raises(rfc3161ng.TimestampingError) as exc_info:
        _timestamper()(data=TEST_DATA, nonce=REQUEST_NONCE)

    assert 'messageImprint' in str(exc_info.value)


def test_message_imprint_algorithm_mismatch_raises(monkeypatch):
    token = _build_tst(_digest(), hash_oid=rfc3161ng.id_sha256)
    tsr = _build_tsr('granted', token=token)
    _install_transport(monkeypatch, tsr, {})

    with pytest.raises(rfc3161ng.TimestampingError) as exc_info:
        _timestamper()(data=TEST_DATA, nonce=REQUEST_NONCE)

    assert 'messageImprint' in str(exc_info.value)


def test_response_without_nonce_requested_is_accepted(monkeypatch):
    token = _build_tst(_digest(), nonce=None)
    tsr = _build_tsr('granted', token=token)
    _install_transport(monkeypatch, tsr, {})

    result = _timestamper()(data=TEST_DATA)

    assert isinstance(result, bytes)
    assert result == encoder.encode(tsr.time_stamp_token)


def test_response_without_policy_requested_skips_policy_check(monkeypatch):
    token = _build_tst(_digest(), policy=None)
    tsr = _build_tsr('granted', token=token)
    _install_transport(monkeypatch, tsr, {})

    timestamper = _timestamper(tsa_policy_id=None)
    result = timestamper(data=TEST_DATA, nonce=REQUEST_NONCE)

    assert isinstance(result, bytes)
