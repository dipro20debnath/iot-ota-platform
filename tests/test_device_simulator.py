import pytest
from unittest.mock import patch, MagicMock
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
from cryptography.hazmat.backends import default_backend

from device_simulator.secure_boot import SecureBoot
from device_simulator.device import IoTDevice

@pytest.fixture
def test_certs():
    # Generate CA key and cert
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Test CA"),
    ])
    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=1)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(ca_key, hashes.SHA256())
    
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    
    return ca_key, ca_cert, ca_cert_pem

def test_secure_boot_init(test_certs):
    _, _, ca_cert_pem = test_certs
    sb = SecureBoot(ca_cert_pem)
    assert sb.ca_cert is not None

def test_device_register():
    with patch('httpx.Client.post') as mock_post:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"id": "dev-123"}
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp
        
        device = IoTDevice("http://test.com", "test-dev", ca_cert_path="fake.pem")
        device.register()
        
        assert device.device_id == "dev-123"
        mock_post.assert_called_once()
