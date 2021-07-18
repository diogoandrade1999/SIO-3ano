from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding

with open('./cc_certs/EC de Autenticacao do Cartao de Cidadao 0003.cer', "rb") as reader:
	cert_data = reader.read()
cert = x509.load_der_x509_certificate(cert_data, default_backend())
with open('./cc_certs/EC de Autenticacao do Cartao de Cidadao 0003.pem', "wb") as w:
	w.write(cert.public_bytes(Encoding.PEM))
