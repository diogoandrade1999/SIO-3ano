import os
import PyKCS11
import base64

from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import hashes
import cryptography.hazmat.primitives.serialization as serialization


lib = "/usr/local/lib/libpteidpkcs11.so"
backend = default_backend()


class MyCerts:
    def __init__(self, server=False, cc=False):
        self.root_certs = {}
        self.intermediate_certs = {}
        self.server_certs = {}
        self.my_cert = None
        self.other_cert = None
        self.crl_cert = None
        self.server = server
        self.nonce = os.urandom(16)
        self.load_crl()
        if not server:
            for f in os.scandir("./server_certs"):
                if f.is_file():
                    self.load_certificate(f, self.server_certs)
            if cc:
                self.pkcs11 = PyKCS11.PyKCS11Lib()
                self.pkcs11.load(lib)
                self.session = self.pkcs11.openSession(self.pkcs11.getSlotList()[0])
                self.get_ca_cc()
        else:
            self.get_ca_server()
            self.get_certificates_cc()

    def get_nonce(self):
        return self.nonce

    def get_cert(self):
        return base64.b64encode(self.my_cert.public_bytes(Encoding.PEM)).decode('utf-8')

    def set_cert(self, c):
        self.other_cert = x509.load_pem_x509_certificate(base64.b64decode(c.encode('utf-8')), backend)

    def calc_digest(self, message):
        hasher = hashes.Hash(hashes.SHA256(), backend)
        hasher.update(message)
        return hasher.finalize()

    def sign(self, text):
        if not self.server:
            private_key = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                                                    (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]
            mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
            return  bytes(self.session.sign(private_key, text, mechanism))
        else:
            digest = self.calc_digest(text)
            key = self.load_private_key()
            return key.sign(digest, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                            salt_length=padding.PSS.MAX_LENGTH),
                                            utils.Prehashed(hashes.SHA256()))

    def verification(self, signature):
        if not self.server:
            digest = self.calc_digest(self.nonce)
            try:
                self.other_cert.public_key().verify(signature, digest, 
                                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                salt_length=padding.PSS.MAX_LENGTH),
                                                utils.Prehashed(hashes.SHA256()))
            except Exception:
                return False, 'The signature is not authentic.'
        else:
            try:
                self.other_cert.public_key().verify(signature, self.nonce, padding.PKCS1v15(), SHA1())
            except Exception as e:
                print(e)
                return False, 'The signature is not authentic.'
        return True, 'The signature is authentic.'

    def load_private_key(self):
        try:
            with open('./private_key/Server.pem', "rb") as reader: data = reader.read()
            key = serialization.load_pem_private_key(data, None, backend)
        except Exception:
            return None
        return key

    def load_certificate(self, file_path, dictionary):
        try:
            with open(file_path, "rb") as reader: cert_data = reader.read()
            cert = x509.load_pem_x509_certificate(cert_data, backend)
            dictionary[cert.subject.rfc4514_string()] = cert
        except Exception:
            return False
        return True

    def load_crl(self):
        try:
            with open('./crl_certs/ZZZZZ000.crl', "rb") as reader: cert_data = reader.read()
            self.crl_cert = x509.load_der_x509_crl(cert_data, backend)
        except Exception:
            return False
        return True

    def get_issuers(self, certificate, chain=None):
        if chain is None: chain = []
        chain.append(certificate)
        issuer = certificate.issuer.rfc4514_string()
        subject = certificate.subject.rfc4514_string()
        if self.server:
            if issuer == subject and subject in self.root_certs:
                return True, chain
            elif issuer in self.intermediate_certs:
                return self.get_issuers(self.intermediate_certs[issuer], chain)
            elif issuer in self.root_certs:
                return self.get_issuers(self.root_certs[issuer], chain)
        else:
            if issuer == subject and subject in self.server_certs:
                return True, chain
            elif issuer in self.server_certs:
                return self.get_issuers(self.server_certs[issuer], chain)
        return False, 'Can not find chain!'

    def get_certificates_cc(self):
        for f in os.scandir("/etc/ssl/certs"):
            if f.is_file():
                if not self.load_certificate(f, self.root_certs): return False, 'Error to read cert file!'
        for f in os.scandir("./cc_certs"):
            if not self.load_certificate(f, self.intermediate_certs): return False, 'Error to read cert file!'
        return True, ''

    def get_ca_server(self):
        try:
            with open('./server_certs/Server.crt', "rb") as reader: cert_data = reader.read()
            self.my_cert = x509.load_pem_x509_certificate(cert_data, backend)
        except Exception:
            return False
        return True

    def get_ca_cc(self):
        all_attr = [e for e in list(PyKCS11.CKA.keys()) if isinstance(e, int)]
        for obj in self.session.findObjects():
            attr = self.session.getAttributeValue(obj, all_attr)
            attr = dict(zip(map(PyKCS11.CKA.get, all_attr), attr))
            if attr['CKA_CERTIFICATE_TYPE'] != None:
                cert = x509.load_der_x509_certificate(bytes(attr["CKA_VALUE"]), backend)
                x = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
                for k in x:
                    if 'Autenticação do Cidadão' in k.value: self.my_cert = cert
                if self.my_cert is not None: break
        if self.my_cert is None: return False, 'Error to read cert cc!'
        return True, ''

    def validation(self, chain):
        for i in range(len(chain)-1):
            if chain[i].issuer.get_attributes_for_oid(NameOID.COMMON_NAME) != chain[i+1].subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                return False, 'Invalid common name!'
            #if i == 0:
            if datetime.now().timestamp() < chain[i].not_valid_before.timestamp() \
            or chain[i].not_valid_after.timestamp() < datetime.now().timestamp():
                return False, 'Invalid dates!'
            # if chain[i+1].not_valid_before.timestamp() > chain[i].not_valid_before.timestamp() \
            # or chain[i].not_valid_before.timestamp() > chain[i+1].not_valid_after.timestamp():
            #     return False, 'Invalid dates!'
            if self.crl_cert.get_revoked_certificate_by_serial_number(chain[i].serial_number) is not None:
                return False, 'Invalid in crl!'
            try:
                chain[i+1].public_key().verify(chain[i].signature, chain[i].tbs_certificate_bytes, 
                                            padding.PKCS1v15(), chain[i].signature_hash_algorithm)
            except Exception:
                return False, 'Invalid signature!'
            if not self.server:
                if i == 0:
                    purpose = chain[i].extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
                    if len([p for p in purpose if p == x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]) < 1:
                        return False, 'Invalid purpose!'
            else:
                if i == 0:
                    if not chain[i].extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value.digital_signature:
                        print(chain[i])
                        return False, 'Invalid purpose!'
                else:
                    if not chain[i].extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value.key_cert_sign:
                        print(chain[i])
                        return False, 'Invalid purpose!'
        return True, 'Valid!'
