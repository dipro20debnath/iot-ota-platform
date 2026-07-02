"""
Certificate Chain Validator Module for IoT OTA Firmware Update Platform.

Validates X.509 certificate chains end-to-end, verifying signatures,
validity periods, revocation status, CA constraints, and path-length
rules.

Usage::

    from app.pki.chain_validator import ChainValidator

    validator = ChainValidator()
    validator.add_trusted_root(root_cert)

    result = validator.validate_chain([device_cert, intermediate_cert, root_cert])
    assert result["valid"] is True
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

logger = logging.getLogger(__name__)


class ChainValidator:
    """Validates X.509 certificate chains for the IoT OTA Platform.

    Supports configurable trusted roots and an in-memory revocation
    list.  Chain validation performs the following checks:

    1. Chain is non-empty.
    2. Root certificate is present in the trusted-roots set.
    3. Issuer / subject name chaining.
    4. Cryptographic signature verification (RSA and ECDSA).
    5. Validity period (``notBefore`` ≤ now ≤ ``notAfter``).
    6. Revocation status.
    7. CA flag in BasicConstraints for non-leaf certificates.
    8. Path-length constraints.

    Attributes:
        _trusted_roots: List of trusted root CA certificates.
        _revoked_serials: Set of hex-encoded serial numbers considered
            revoked.
    """

    def __init__(self) -> None:
        """Initialise the ChainValidator with empty trust and revocation stores."""
        self._trusted_roots: list[x509.Certificate] = []
        self._revoked_serials: set[str] = set()
        logger.info("ChainValidator initialised.")

    # ------------------------------------------------------------------
    # Trust and revocation management
    # ------------------------------------------------------------------

    def add_trusted_root(self, cert: x509.Certificate) -> None:
        """Add a certificate to the trusted-root store.

        Args:
            cert: The root CA certificate to trust.
        """
        self._trusted_roots.append(cert)
        serial_hex = format(cert.serial_number, "X")
        logger.info("Trusted root added – serial=%s", serial_hex)

    def add_revoked_serial(self, serial_number: str) -> None:
        """Add a serial number to the revocation list.

        Args:
            serial_number: Hex-encoded serial number to revoke.
        """
        self._revoked_serials.add(serial_number)
        logger.info("Serial %s added to revocation list.", serial_number)

    # ------------------------------------------------------------------
    # Full chain validation
    # ------------------------------------------------------------------

    def validate_chain(self, cert_chain: list[x509.Certificate]) -> dict:
        """Validate a certificate chain from leaf to root.

        The chain must be ordered ``[leaf, intermediate, …, root]`` with
        each certificate's issuer matching the subject of the next
        certificate in the list.

        Checks performed:

        1. **Non-empty** – The chain must contain at least one certificate.
        2. **Trusted root** – The last certificate must be in the
           trusted-root store.
        3. **Name chaining** – Each cert's issuer must match the next
           cert's subject.
        4. **Signature verification** – Each cert's signature is verified
           against its issuer's public key.
        5. **Validity period** – Every certificate must be within its
           ``notBefore`` / ``notAfter`` window.
        6. **Revocation** – No certificate's serial may appear in the
           revocation list.
        7. **CA flag** – All non-leaf certificates must have
           ``BasicConstraints(ca=True)``.
        8. **Path length** – Path-length constraints are respected.

        Args:
            cert_chain: Ordered list of certificates
                ``[leaf, …, root]``.

        Returns:
            A dict with:

            * ``valid`` – ``True`` if all checks pass.
            * ``errors`` – List of human-readable error strings (empty if
              valid).
            * ``chain_length`` – Number of certificates in the chain.
            * ``leaf_subject`` – Subject CN of the leaf certificate (or
              ``""``).
            * ``root_issuer`` – Issuer CN of the root certificate (or
              ``""``).
        """
        errors: list[str] = []

        # --- 1. Non-empty ---
        if not cert_chain:
            return {
                "valid": False,
                "errors": ["Certificate chain is empty."],
                "chain_length": 0,
                "leaf_subject": "",
                "root_issuer": "",
            }

        chain_length = len(cert_chain)
        leaf_subject = self._extract_cn(cert_chain[0].subject) or ""
        root_issuer = self._extract_cn(cert_chain[-1].issuer) or ""

        # --- 2. Trusted root ---
        root_cert = cert_chain[-1]
        if not self._is_trusted_root(root_cert):
            errors.append(
                f"Root certificate (serial={format(root_cert.serial_number, 'X')}) "
                f"is not in the trusted-root store."
            )

        now = datetime.now(timezone.utc)

        for i, cert in enumerate(cert_chain):
            serial_hex = format(cert.serial_number, "X")
            position = "leaf" if i == 0 else ("root" if i == chain_length - 1 else f"intermediate[{i}]")

            # --- 5. Validity period ---
            validity = self.check_validity_period(cert)
            if not validity["valid"]:
                if validity["is_expired"]:
                    errors.append(
                        f"Certificate at position {position} (serial={serial_hex}) "
                        f"has expired (not_after={validity['not_after']})."
                    )
                if validity["not_yet_valid"]:
                    errors.append(
                        f"Certificate at position {position} (serial={serial_hex}) "
                        f"is not yet valid (not_before={validity['not_before']})."
                    )

            # --- 6. Revocation ---
            revocation = self.check_revocation(cert)
            if revocation["revoked"]:
                errors.append(
                    f"Certificate at position {position} (serial={serial_hex}) "
                    f"has been revoked."
                )

            # --- 7 & 8. CA constraints for non-leaf certs ---
            if i < chain_length - 1 and i > 0:
                # This is an intermediate cert — must be a CA
                if not self._has_ca_flag(cert):
                    errors.append(
                        f"Certificate at position {position} (serial={serial_hex}) "
                        f"is not a CA but appears as an intermediate in the chain."
                    )
                # Check path length: the number of certs below this one
                # that are CAs must not exceed path_length.
                self._check_path_length(cert, i, cert_chain, errors)

            # Root must also be a CA (unless it's the only cert)
            if i == chain_length - 1 and chain_length > 1:
                if not self._has_ca_flag(cert):
                    errors.append(
                        f"Root certificate (serial={serial_hex}) "
                        f"is not a CA."
                    )
                self._check_path_length(cert, i, cert_chain, errors)

        # --- 3 & 4. Name chaining and signature verification ---
        for i in range(len(cert_chain) - 1):
            cert = cert_chain[i]
            issuer_cert = cert_chain[i + 1]
            cert_serial = format(cert.serial_number, "X")

            # Name chaining: cert.issuer == issuer_cert.subject
            if cert.issuer != issuer_cert.subject:
                errors.append(
                    f"Name chain broken: certificate (serial={cert_serial}) "
                    f"issuer does not match subject of certificate at "
                    f"position {i + 1}."
                )

            # Signature verification
            if not self.verify_signature(cert, issuer_cert):
                errors.append(
                    f"Signature verification failed: certificate "
                    f"(serial={cert_serial}) was not signed by "
                    f"certificate at position {i + 1}."
                )

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "chain_length": chain_length,
            "leaf_subject": leaf_subject,
            "root_issuer": root_issuer,
        }

    # ------------------------------------------------------------------
    # Signature verification
    # ------------------------------------------------------------------

    def verify_signature(
        self,
        cert: x509.Certificate,
        issuer_cert: x509.Certificate,
    ) -> bool:
        """Verify that *cert* was signed by *issuer_cert*'s private key.

        Handles both RSA and ECDSA public keys.

        * **RSA**: uses PKCS1v15 padding with the certificate's signature
          hash algorithm.
        * **ECDSA**: uses ECDSA with the certificate's signature hash
          algorithm.

        Args:
            cert: The certificate whose signature should be verified.
            issuer_cert: The certificate whose public key allegedly
                created the signature.

        Returns:
            ``True`` if the signature is valid, ``False`` otherwise.
        """
        issuer_public_key = issuer_cert.public_key()

        try:
            if isinstance(issuer_public_key, rsa.RSAPublicKey):
                issuer_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,  # type: ignore[arg-type]
                )
            elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                issuer_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ec.ECDSA(cert.signature_hash_algorithm),  # type: ignore[arg-type]
                )
            else:
                logger.warning(
                    "Unsupported public key type: %s",
                    type(issuer_public_key).__name__,
                )
                return False
            return True
        except InvalidSignature:
            logger.debug(
                "Signature verification failed for cert serial=%s against "
                "issuer serial=%s.",
                format(cert.serial_number, "X"),
                format(issuer_cert.serial_number, "X"),
            )
            return False
        except Exception as exc:
            logger.error("Unexpected error during signature verification: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Validity period
    # ------------------------------------------------------------------

    def check_validity_period(self, cert: x509.Certificate) -> dict:
        """Check whether a certificate is within its validity period.

        Args:
            cert: The certificate to check.

        Returns:
            A dict with:

            * ``valid`` – ``True`` if ``notBefore ≤ now ≤ notAfter``.
            * ``not_before`` – ISO 8601 string of ``notBefore``.
            * ``not_after`` – ISO 8601 string of ``notAfter``.
            * ``is_expired`` – ``True`` if ``now > notAfter``.
            * ``not_yet_valid`` – ``True`` if ``now < notBefore``.
        """
        now = datetime.now(timezone.utc)
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc

        is_expired = now > not_after
        not_yet_valid = now < not_before

        return {
            "valid": not is_expired and not not_yet_valid,
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "is_expired": is_expired,
            "not_yet_valid": not_yet_valid,
        }

    # ------------------------------------------------------------------
    # Revocation
    # ------------------------------------------------------------------

    def check_revocation(self, cert: x509.Certificate) -> dict:
        """Check whether a certificate has been revoked.

        Args:
            cert: The certificate to check.

        Returns:
            A dict with:

            * ``revoked`` – ``True`` if the serial number is in the
              revocation set.
            * ``serial_number`` – Hex-encoded serial number.
        """
        serial_hex = format(cert.serial_number, "X")
        return {
            "revoked": serial_hex in self._revoked_serials,
            "serial_number": serial_hex,
        }

    # ------------------------------------------------------------------
    # Chain summary
    # ------------------------------------------------------------------

    def get_chain_summary(
        self, cert_chain: list[x509.Certificate]
    ) -> list[dict]:
        """Return a summary of each certificate in the chain.

        Args:
            cert_chain: Ordered list of certificates.

        Returns:
            A list of dicts, one per certificate, each containing:

            * ``subject`` – Subject CN.
            * ``issuer`` – Issuer CN.
            * ``serial_number`` – Hex-encoded serial number.
            * ``not_before`` – ISO 8601 string.
            * ``not_after`` – ISO 8601 string.
            * ``is_ca`` – Whether the certificate is a CA.
        """
        summaries: list[dict] = []
        for cert in cert_chain:
            summaries.append({
                "subject": self._extract_cn(cert.subject) or "",
                "issuer": self._extract_cn(cert.issuer) or "",
                "serial_number": format(cert.serial_number, "X"),
                "not_before": cert.not_valid_before_utc.isoformat(),
                "not_after": cert.not_valid_after_utc.isoformat(),
                "is_ca": self._has_ca_flag(cert),
            })
        return summaries

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _is_trusted_root(self, cert: x509.Certificate) -> bool:
        """Check if a certificate is in the trusted-root store.

        Comparison is by DER-encoded bytes for correctness.
        """
        from cryptography.hazmat.primitives import serialization
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        for trusted in self._trusted_roots:
            if trusted.public_bytes(serialization.Encoding.DER) == cert_der:
                return True
        return False

    @staticmethod
    def _has_ca_flag(cert: x509.Certificate) -> bool:
        """Return ``True`` if the cert has BasicConstraints with ``ca=True``."""
        try:
            bc = cert.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )
            return bc.value.ca  # type: ignore[attr-defined]
        except x509.ExtensionNotFound:
            return False

    @staticmethod
    def _get_path_length(cert: x509.Certificate) -> Optional[int]:
        """Return the path-length constraint, or ``None`` if unset."""
        try:
            bc = cert.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )
            return bc.value.path_length  # type: ignore[attr-defined]
        except x509.ExtensionNotFound:
            return None

    def _check_path_length(
        self,
        cert: x509.Certificate,
        position: int,
        cert_chain: list[x509.Certificate],
        errors: list[str],
    ) -> None:
        """Validate path-length constraint for a CA certificate.

        The number of CA certificates *below* this one in the chain must
        not exceed its ``path_length`` value.

        Args:
            cert: The CA certificate to check.
            position: Index of *cert* in *cert_chain*.
            cert_chain: The full chain.
            errors: Mutable list to append error strings to.
        """
        path_length = self._get_path_length(cert)
        if path_length is None:
            return  # Unconstrained

        # Count CA certs between the leaf (index 0) and this cert
        ca_certs_below = 0
        for j in range(1, position):  # skip leaf (index 0)
            if self._has_ca_flag(cert_chain[j]):
                ca_certs_below += 1

        if ca_certs_below > path_length:
            serial_hex = format(cert.serial_number, "X")
            errors.append(
                f"Path-length constraint violated for certificate "
                f"(serial={serial_hex}): path_length={path_length}, "
                f"CA certs below={ca_certs_below}."
            )

    @staticmethod
    def _extract_cn(name: x509.Name) -> Optional[str]:
        """Extract the Common Name from an X.509 Name."""
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if attrs:
            return str(attrs[0].value)
        return None
