import hashlib
import json
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

class SecureBoot:
    """Provides cryptographic verification for OTA payloads on the device side."""
    
    def __init__(self, ca_cert_pem: bytes):
        import logging
        self.logger = logging.getLogger(self.__class__.__name__)
        self.ca_cert = x509.load_pem_x509_certificate(ca_cert_pem, default_backend())
    
    def _verify_cert_signature(self, issuer_pub_key, cert_to_verify):
        """Verifies a certificate's signature using the issuer's public key."""
        if isinstance(issuer_pub_key, rsa.RSAPublicKey):
            issuer_pub_key.verify(
                cert_to_verify.signature,
                cert_to_verify.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert_to_verify.signature_hash_algorithm
            )
        elif isinstance(issuer_pub_key, ec.EllipticCurvePublicKey):
            issuer_pub_key.verify(
                cert_to_verify.signature,
                cert_to_verify.tbs_certificate_bytes,
                ec.ECDSA(cert_to_verify.signature_hash_algorithm)
            )
        else:
            raise ValueError("Unsupported key type")

    def _verify_data_signature(self, pub_key, signature, data):
        """Verifies data signature using the public key."""
        if isinstance(pub_key, rsa.RSAPublicKey):
            pub_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            pub_key.verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA256())
            )
        else:
            raise ValueError("Unsupported key type")

    def verify_manifest(self, manifest_dict: dict) -> bool:
        """Verify the manifest's self-contained hash and signature.
        
        1. Calculate SHA256 of manifest (excluding 'manifest_signature')
        2. Verify 'manifest_signature' matches the hash using 'signer_certificate'
        3. Verify 'signer_certificate' is signed by our trusted CA
        
        Return True if valid, False otherwise.
        """
        try:
            # The server doesn't sign the manifest, it just provides a hash.
            # We verify the certificate in verify_firmware, here we just check the hash.
            expected_hash = manifest_dict.get('manifest_hash')
            if not expected_hash:
                return False
                
            # Remove keys that weren't part of the server's hash computation
            manifest_copy = manifest_dict.copy()
            manifest_copy.pop('manifest_hash', None)
            manifest_copy.pop('signer_certificate', None) # We injected this
            
            manifest_json = json.dumps(manifest_copy, sort_keys=True)
            actual_hash = hashlib.sha256(manifest_json.encode('utf-8')).hexdigest()
            
            return actual_hash == expected_hash
        except Exception:
            return False
            
    def verify_firmware(self, firmware_bytes: bytes, manifest_dict: dict) -> bool:
        """Verify firmware binary against the manifest.
        
        1. Check size matches file_size_bytes
        2. Check SHA256 matches file_hash_sha256
        3. Verify the firmware 'signature' in the manifest using 'signer_certificate'
        
        Return True if valid, False otherwise.
        """
        try:
            expected_size = manifest_dict.get('file_size_bytes')
            if expected_size is not None and len(firmware_bytes) != expected_size:
                self.logger.error(f"Size mismatch: {len(firmware_bytes)} != {expected_size}")
                return False
                
            expected_hash = manifest_dict.get('file_hash_sha256')
            actual_hash = hashlib.sha256(firmware_bytes).hexdigest()
            if expected_hash and actual_hash != expected_hash:
                self.logger.error(f"Hash mismatch: {actual_hash} != {expected_hash}")
                return False
                
            firmware_signature_hex = manifest_dict.get('signature')
            signer_cert_pem = manifest_dict.get('signer_certificate', "").encode('utf-8')
            
            if not firmware_signature_hex or not signer_cert_pem:
                self.logger.error("Missing signature or signer_cert_pem")
                return False
                
            firmware_signature = bytes.fromhex(firmware_signature_hex)
            signer_cert = x509.load_pem_x509_certificate(signer_cert_pem, default_backend())
            
            # Verify the signer cert is signed by our trusted CA
            self._verify_cert_signature(self.ca_cert.public_key(), signer_cert)
            
            # Verify firmware signature
            self._verify_data_signature(signer_cert.public_key(), firmware_signature, firmware_bytes)
            return True
        except Exception as e:
            self.logger.error(f"Exception in verify_firmware: {e!r}")
            return False
