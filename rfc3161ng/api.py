import hashlib
import requests
import base64
import re
import datetime
import dateutil.relativedelta
import dateutil.tz

from pyasn1.codec.der import encoder, decoder
from pyasn1_modules import rfc2459, rfc2634, rfc5035
from pyasn1.type import univ, tag
from pyasn1.error import PyAsn1Error
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

import rfc3161ng

__all__ = (
    'RemoteTimestamper', 'check_timestamp', 'get_hash_oid',
    'TimestampingError', 'SignerNotFoundError', 'InvalidSignatureError',
    'get_timestamp', 'make_timestamp_request',
    'encode_timestamp_request', 'encode_timestamp_response',
    'decode_timestamp_request', 'decode_timestamp_response',
)

id_attribute_messageDigest = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 4))

# ESS signingCertificate / signingCertificateV2 signed-attribute OIDs
id_aa_signingCertificate = rfc2634.id_aa_signingCertificate
id_aa_signingCertificateV2 = rfc5035.id_aa_signingCertificateV2

# SubjectKeyIdentifier (SKI) choice tag of CMS SignerIdentifier (RFC 5652)
_sid_ski_tag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)


def get_hash_oid(hashname):
    return rfc3161ng.__dict__['id_' + hashname]


def get_hash_from_oid(oid):
    h = rfc3161ng.oid_to_hash.get(oid)
    if h is None:
        raise ValueError('unsupported hash algorithm', oid)
    return h


def get_hash_class_from_oid(oid):
    h = get_hash_from_oid(oid)
    return getattr(hashlib, h)


class TimestampingError(RuntimeError):
    pass


class SignerNotFoundError(TimestampingError):
    '''No certificate could be bound to a SignerInfo.

    The signer certificate is missing, ambiguous (several certificates match
    the SignerInfo identity / signingCertificate binding), or none of them
    matches the ESS signingCertificate digest.
    '''


class InvalidSignatureError(TimestampingError):
    '''A signer was located, but its cryptographic verification failed.'''


def generalizedtime_to_utc_datetime(gt, naive=True):
    m = re.match(r'(?P<year>\d{4})(?P<month>\d{2})(?P<day>\d{2})(?P<hour>\d{2})(?:(?P<minutes>\d{2})(?:(?P<seconds>\d{2})(?:[.,](?P<fractions>\d*))?)?)?(?P<tz>Z|[+-]\d{2}(?:\d{2})?)?', gt)
    if not m:
        raise ValueError("not an ASN.1 generalizedTime: '%s'" % (gt,))

    d = m.groupdict()
    dt = datetime.datetime(
        int(d['year']),
        int(d['month']),
        int(d['day']),
        int(d['hour']),
        int(d['minutes'] or 0),
        int(d['seconds'] or 0),
        int(float('0.' + d['fractions']) * 1000000 if d['fractions'] else 0)
    )
    if naive:
        if d['tz'] and d['tz'][0] in ('+', '-'):
            diff = dateutil.relativedelta.relativedelta(
                hours=int(d['tz'][1:3]),
                minutes=int(d['tz'][3:5]) if len(d['tz']) > 3 else 0
            )
            if d['tz'][0] == '+':
                dt -= diff
            else:
                dt += diff
        return dt

    if d['tz'] and re.match(r'^[+\-]\d*[^0]\d*$', d['tz']):
        diff = datetime.timedelta(
            hours=int(d['tz'][1:3]),
            minutes=int(d['tz'][3:5]) if len(d['tz']) > 3 else 0
        ).total_seconds()
        name = d['tz'][0:3]
        if len(d['tz']) > 3:
            name += ':' + d['tz'][3:5]
        dt = dt.replace(tzinfo=dateutil.tz.tzoffset(name, diff if d['tz'][0] == '+' else -diff))
    else:
        dt = dt.replace(tzinfo=dateutil.tz.tzutc())

    return dt


def get_timestamp(tst, naive=True):
    try:
        if not isinstance(tst, rfc3161ng.TimeStampToken):
            tst, substrate = decoder.decode(tst, asn1Spec=rfc3161ng.TimeStampToken())
            if substrate:
                raise ValueError("extra data after tst")

        tstinfo = tst.getComponentByName('content').getComponentByPosition(2).getComponentByPosition(1)
        tstinfo, substrate = decoder.decode(tstinfo, asn1Spec=univ.OctetString())
        if substrate:
            raise ValueError("extra data after tst")
        tstinfo, substrate = decoder.decode(tstinfo, asn1Spec=rfc3161ng.TSTInfo())
        if substrate:
            raise ValueError("extra data after tst")
        genTime = tstinfo.getComponentByName('genTime')
        return generalizedtime_to_utc_datetime(str(genTime), naive)
    except PyAsn1Error as exc:
        raise ValueError('not a valid TimeStampToken', exc)


def _load_certificate_bytes(certificate, backend=None):
    backend = backend or default_backend()
    if b'-----BEGIN CERTIFICATE-----' in certificate:
        return x509.load_pem_x509_certificate(certificate, backend)
    return x509.load_der_x509_certificate(certificate, backend)


def load_certificate(signed_data, certificate=b""):
    '''Load a single certificate from raw bytes or from the token.

    Selecting the first embedded certificate is not safe on its own: the
    certificate order inside a TimeStampToken is not fixed. Prefer
    :func:`select_signer_certificate`, which binds a certificate to a
    specific SignerInfo. This helper is kept for backwards compatibility.
    '''
    backend = default_backend()

    if certificate == b"" or certificate is None:
        try:
            embedded = signed_data['certificates']
            if not embedded.hasValue() or not len(embedded):
                raise AttributeError("missing certificate")
            certificate = embedded[0][0]
        except (KeyError, IndexError, TypeError) as exc:
            raise AttributeError("missing certificate") from exc
        data = encoder.encode(certificate)
        return x509.load_der_x509_certificate(data, backend)

    return _load_certificate_bytes(certificate, backend)


def _embedded_certificates(signed_data):
    '''Return the X.509 certificates embedded in a SignedData as crypto objects.'''
    certificates = []
    try:
        embedded = signed_data['certificates']
    except (KeyError, IndexError, TypeError):
        return certificates
    if not embedded.hasValue():
        return certificates
    for choice in embedded:
        # index 0 is the X.509 certificate; index 1 is an obsolete
        # extendedCertificate (CMS only carries plain X.509 certificates).
        if choice.hasValue() and choice.getName() == 'certificate':
            data = encoder.encode(choice[0])
            certificates.append(x509.load_der_x509_certificate(data, default_backend()))
    return certificates


def _certificate_subject_key_identifier(certificate):
    try:
        extension = certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    except x509.ExtensionNotFound:
        return None
    return extension.value.digest


def _signer_identifier(signer_info):
    '''Return ``(kind, value)`` for a CMS SignerIdentifier.

    ``kind`` is either ``'issuerSerial'`` (issuer Name + serial number, the
    PKCS#7/CMS default) or ``'ski'`` (context-tagged [0] subject key
    identifier, RFC 5652).
    '''
    sid = signer_info['issuerAndSerialNumber']
    if sid.tagSet[-1] == _sid_ski_tag:
        return 'ski', bytes(sid)
    return 'issuerSerial', sid


def _certificate_matches_sid(certificate, sid_kind, sid_value):
    if sid_kind == 'ski':
        ski = _certificate_subject_key_identifier(certificate)
        return ski is not None and ski == sid_value
    try:
        serial_number = int(sid_value['serialNumber'])
    except (ValueError, OverflowError):
        return False
    return encoder.encode(sid_value['issuer']) == certificate.issuer.public_bytes() \
        and certificate.serial_number == serial_number


def _decode_ess_cert_ids(signer_info):
    '''Extract ESS signingCertificate(V2) bindings from authenticatedAttributes.

    Returns a list of ``(hash_name, cert_digest, issuer_serial)`` tuples, one
    per ESSCertID(V2) carried by the token (usually a single entry).
    '''
    bindings = []
    try:
        authenticated_attributes = signer_info['authenticatedAttributes']
    except (KeyError, IndexError, TypeError):
        return bindings
    for attribute in authenticated_attributes:
        oid = attribute[0]
        raw_value = bytes(attribute[1][0])
        if oid == id_aa_signingCertificate:
            sc, substrate = decoder.decode(raw_value, asn1Spec=rfc2634.SigningCertificate())
            if substrate:
                raise ValueError('extra data after signingCertificate attribute')
            for cert_id in sc['certs']:
                issuer_serial = cert_id['issuerSerial'] if cert_id['issuerSerial'].hasValue() else None
                bindings.append(('sha1', bytes(cert_id['certHash']), issuer_serial))
        elif oid == id_aa_signingCertificateV2:
            sc, substrate = decoder.decode(raw_value, asn1Spec=rfc5035.SigningCertificateV2())
            if substrate:
                raise ValueError('extra data after signingCertificateV2 attribute')
            for cert_id in sc['certs']:
                hash_oid = cert_id['hashAlgorithm']['algorithm']
                hash_name = get_hash_from_oid(hash_oid)
                issuer_serial = cert_id['issuerSerial'] if cert_id['issuerSerial'].hasValue() else None
                bindings.append((hash_name, bytes(cert_id['certHash']), issuer_serial))
    return bindings


def _certificate_matches_ess(certificate, bindings):
    if not bindings:
        return True
    for hash_name, expected_digest, issuer_serial in bindings:
        digest = hashes.Hash(getattr(hashes, hash_name.upper())(), default_backend())
        digest.update(certificate.public_bytes(serialization.Encoding.DER))
        if digest.finalize() != expected_digest:
            return False
        if issuer_serial is not None:
            general_names = issuer_serial['issuer']
            serial_number = int(issuer_serial['serialNumber'])
            if serial_number != certificate.serial_number:
                return False
            if not _issuer_name_matches(certificate, general_names):
                return False
    return True


def _issuer_name_matches(certificate, general_names):
    # IssuerSerial.issuer is a GeneralNames sequence; only directoryName
    # entries (tag [4]) are meaningful for X.509 issuer comparison.
    for general_name in general_names:
        if general_name.getName() != 'directoryName':
            continue
        if encoder.encode(general_name.getComponent()) == certificate.issuer.public_bytes():
            return True
    return False


def select_signer_certificate(signer_info, candidates, certificate=None):
    '''Bind a certificate to ``signer_info`` and return it.

    ``candidates`` are the certificates embedded in the SignedData; the
    optional explicit ``certificate`` is a cryptography X.509 object supplied
    by the caller. Selection follows the SignerInfo SignerIdentifier and, when
    present, the ESS signingCertificate / signingCertificateV2 digest binding.

    When a certificate is supplied explicitly it is the only one considered:
    it must match the SignerInfo identity and its ESS binding, otherwise the
    signer is considered not found. Without an explicit certificate the
    embedded ``candidates`` are searched, and zero or several matches both
    raise :class:`SignerNotFoundError` rather than silently picking one.
    '''
    sid_kind, sid_value = _signer_identifier(signer_info)
    try:
        bindings = _decode_ess_cert_ids(signer_info)
    except (PyAsn1Error, ValueError) as exc:
        raise SignerNotFoundError('malformed signingCertificate(V2) attribute: %s' % exc)

    if certificate is not None:
        pool = [certificate]
        explicit = True
    else:
        pool = list(candidates)
        explicit = False

    matches = []
    seen = set()
    for candidate in pool:
        der_bytes = candidate.public_bytes(serialization.Encoding.DER)
        if der_bytes in seen:
            continue
        seen.add(der_bytes)
        if not _certificate_matches_sid(candidate, sid_kind, sid_value):
            continue
        if not _certificate_matches_ess(candidate, bindings):
            continue
        matches.append(candidate)

    if not matches:
        if explicit:
            raise SignerNotFoundError(
                'the supplied certificate does not match the SignerInfo '
                'identity or its signingCertificate(V2) binding'
            )
        raise SignerNotFoundError(
            'no certificate matching the SignerInfo identity and '
            'signingCertificate(V2) binding was found'
        )
    if len(matches) > 1:
        raise SignerNotFoundError(
            'several certificates match the SignerInfo identity; the '
            'signingCertificate(V2) binding does not identify a unique one'
        )
    return matches[0]


def check_timestamp(tst, certificate=None, data=None, digest=None, hashname=None, nonce=None):
    hashname = hashname or 'sha1'
    hashobj = hashlib.new(hashname)
    if digest is None:
        if not data:
            raise ValueError("check_timestamp requires data or digest argument")
        hashobj.update(data)
        digest = hashobj.digest()

    if not isinstance(tst, rfc3161ng.TimeStampToken):
        tst, substrate = decoder.decode(tst, asn1Spec=rfc3161ng.TimeStampToken())
        if substrate:
            raise ValueError("extra data after tst")
    signed_data = tst.content
    if nonce is not None and int(tst.tst_info['nonce']) != int(nonce):
        raise ValueError('nonce is different or missing')
    # check message imprint with respect to locally computed digest
    message_imprint = tst.tst_info.message_imprint
    if message_imprint.hash_algorithm[0] != get_hash_oid(hashname) or bytes(message_imprint.hashed_message) != digest:
        raise ValueError('Message imprint mismatch')
    signer_infos = signed_data['signerInfos']
    if not len(signer_infos):
        raise SignerNotFoundError('No signature: the token has no SignerInfo')
    # check content type
    if tst.content['contentInfo']['contentType'] != rfc3161ng.id_ct_TSTInfo:
        raise ValueError("Signed content type is wrong: %s != %s" % (
            tst.content['contentInfo']['contentType'], rfc3161ng.id_ct_TSTInfo
        ))

    explicit_certificate = _load_certificate_bytes(certificate) if certificate else None
    embedded = _embedded_certificates(signed_data)

    # Every SignerInfo must verify; never silently validate only the first one.
    for signer_info in signer_infos:
        signer_certificate = select_signer_certificate(
            signer_info, embedded, certificate=explicit_certificate
        )
        _verify_signer_info(signer_info, signer_certificate, tst)
    return True


def _verify_signer_info(signer_info, certificate, tst):
    signed_data = tst.content
    # check signed data digest
    content = bytes(decoder.decode(bytes(signed_data['contentInfo']['content']), asn1Spec=univ.OctetString())[0])
    # if there is authenticated attributes, they must contain the message
    # digest and they are the signed data otherwise the content is the
    # signed data
    if len(signer_info['authenticatedAttributes']):
        authenticated_attributes = signer_info['authenticatedAttributes']
        signer_digest_algorithm = signer_info['digestAlgorithm']['algorithm']
        signer_hash_class = get_hash_class_from_oid(signer_digest_algorithm)
        signer_hash_name = get_hash_from_oid(signer_digest_algorithm)
        content_digest = signer_hash_class(content).digest()
        for authenticated_attribute in authenticated_attributes:
            if authenticated_attribute[0] == id_attribute_messageDigest:
                try:
                    signed_digest = bytes(decoder.decode(bytes(authenticated_attribute[1][0]), asn1Spec=univ.OctetString())[0])
                    if signed_digest != content_digest:
                        raise InvalidSignatureError('Content digest != signed digest')
                    s = univ.SetOf()
                    for i, x in enumerate(authenticated_attributes):
                        s.setComponentByPosition(i, x)
                    signed_payload = encoder.encode(s)
                    break
                except PyAsn1Error:
                    raise
        else:
            raise InvalidSignatureError('No signed digest')
    else:
        signer_digest_algorithm = signer_info['digestAlgorithm']['algorithm']
        signer_hash_name = get_hash_from_oid(signer_digest_algorithm)
        signed_payload = content
    # check signature
    signature = signer_info['encryptedDigest']
    public_key = certificate.public_key()
    hash_family = getattr(hashes, signer_hash_name.upper())
    try:
        public_key.verify(
            bytes(signature),
            signed_payload,
            padding.PKCS1v15(),
            hash_family(),
        )
    except InvalidSignature:
        raise InvalidSignatureError(
            'signature does not verify against the signer certificate'
        )


class RemoteTimestamper(object):
    def __init__(self, url, certificate=None, capath=None, cafile=None, username=None, password=None, hashname=None, include_tsa_certificate=False, timeout=10, tsa_policy_id=None):
        self.url = url
        self.certificate = certificate
        self.capath = capath
        self.cafile = cafile
        self.username = username
        self.password = password
        self.hashname = hashname or 'sha1'
        self.include_tsa_certificate = include_tsa_certificate
        self.timeout = timeout
        self.tsa_policy_id = tsa_policy_id

    def check_response(self, response, digest, nonce=None):
        '''
           Check validity of a TimeStampResponse
        '''
        tst = response.time_stamp_token
        if self.certificate:
            return self.check(tst, digest=digest, nonce=nonce)
        return tst

    def check(self, tst, data=None, digest=None, nonce=None):
        return check_timestamp(
            tst,
            digest=digest,
            data=data,
            nonce=nonce,
            certificate=self.certificate,
            hashname=self.hashname,
        )

    def timestamp(self, data=None, digest=None, include_tsa_certificate=None, nonce=None, tsa_policy_id=None):
        return self(
            data=data,
            digest=digest,
            include_tsa_certificate=include_tsa_certificate,
            nonce=nonce,
            tsa_policy_id=tsa_policy_id,
        )

    def __call__(self, data=None, digest=None, include_tsa_certificate=None, nonce=None, return_tsr=False, tsa_policy_id=None):
        if data:
            digest = data_to_digest(data, self.hashname)

        request = make_timestamp_request(
            data=data,
            digest=digest,
            hashname=self.hashname,
            include_tsa_certificate=include_tsa_certificate if include_tsa_certificate is not None else self.include_tsa_certificate,
            nonce=nonce,
            tsa_policy_id=tsa_policy_id if tsa_policy_id is not None else self.tsa_policy_id
        )
        binary_request = encode_timestamp_request(request)

        headers = {'Content-Type': 'application/timestamp-query'}
        if self.username is not None:
            username = self.username.encode() if not isinstance(self.username, bytes) else self.username
            password = self.password.encode() if not isinstance(self.password, bytes) else self.password
            base64string = base64.standard_b64encode(b'%s:%s' % (username, password))
            if isinstance(base64string, bytes):
                base64string = base64string.decode()
            headers['Authorization'] = "Basic %s" % base64string
        try:
            response = requests.post(
                self.url,
                data=binary_request,
                timeout=self.timeout,
                headers=headers,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise TimestampingError('Unable to send the request to %r' % self.url, exc)
        tsr = decode_timestamp_response(response.content)
        self.check_response(tsr, digest, nonce=nonce)
        if return_tsr:
            return tsr
        return encoder.encode(tsr.time_stamp_token)


def data_to_digest(data, hashname='sha1'):
    hashobj = hashlib.new(hashname)
    if not isinstance(data, bytes):
        data = data.encode()
    hashobj.update(data)
    return hashobj.digest()


def make_timestamp_request(data=None, digest=None, hashname='sha1', include_tsa_certificate=False, nonce=None, tsa_policy_id=None):
    algorithm_identifier = rfc2459.AlgorithmIdentifier()
    algorithm_identifier.setComponentByPosition(0, get_hash_oid(hashname))
    message_imprint = rfc3161ng.MessageImprint()
    message_imprint.setComponentByPosition(0, algorithm_identifier)
    hashobj = hashlib.new(hashname)
    if digest:
        assert len(digest) == hashobj.digest_size, 'digest length is wrong %s != %s' % (len(digest), hashobj.digest_size)
    elif data:
        digest = data_to_digest(data)
    else:
        raise ValueError('You must pass some data to digest, or the digest')
    message_imprint.setComponentByPosition(1, digest)
    tsq = rfc3161ng.TimeStampReq()
    tsq.setComponentByPosition(0, 'v1')
    tsq.setComponentByPosition(1, message_imprint)
    if tsa_policy_id:
        tsq.setComponentByPosition(2, rfc3161ng.types.TSAPolicyId(tsa_policy_id))
    if nonce is not None:
        tsq.setComponentByPosition(3, int(nonce))
    tsq.setComponentByPosition(4, include_tsa_certificate)
    return tsq


def encode_timestamp_request(request):
    return encoder.encode(request)


def encode_timestamp_response(response):
    return encoder.encode(response)


def decode_timestamp_request(request):
    tsq, substrate = decoder.decode(request, asn1Spec=rfc3161ng.TimeStampReq())
    if substrate:
        raise ValueError('Extra data returned')
    return tsq


def decode_timestamp_response(response):
    tsr, substrate = decoder.decode(response, asn1Spec=rfc3161ng.TimeStampResp())
    if substrate:
        raise ValueError('Extra data returned')
    return tsr
