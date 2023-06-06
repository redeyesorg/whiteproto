"""WhiteProto cryptography routines."""

import enum
import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from whiteproto.async_executor import cpu_bound_async


def _generate_random(length: int) -> bytes:
    return os.urandom(length)


class Origin(enum.Enum):
    """Data origin."""

    LOCAL = 1
    REMOTE = 2


class InvalidStateError(Exception):
    """Context is in an invalid state."""


class EncryptionFailureError(Exception):
    """Encryption failed."""


def _verify_signature(
    data: bytes, signature: bytes, pubkey: ec.EllipticCurvePublicKey
) -> bool:
    try:
        pubkey.verify(signature, data, ec.ECDSA(hashes.SHA512()))
    except InvalidSignature:
        return False
    return True


class CryptoContext:  # noqa: WPS306
    """WhiteProto crypto context."""

    _preshared_key: bytes
    _private_key: ec.EllipticCurvePrivateKey
    _remote_public_key: ec.EllipticCurvePublicKey
    _session_key: bytes
    _session_cryptor: ChaCha20Poly1305
    _session_nonce: bytes

    def __init__(self: "CryptoContext"):
        self._private_key = ec.generate_private_key(ec.SECP521R1())
        self._session_nonce = _generate_random(64)

    # region Public API

    def get_public_key(self: "CryptoContext") -> ec.EllipticCurvePublicKey:
        """Get my public key.

        Returns:
            Self public key
        """
        return self._private_key.public_key()

    def get_public_bytes(self: "CryptoContext") -> bytes:
        """Get my public key as bytes.

        Returns:
            Public key bytes as X962 compressed point
        """
        return self.get_public_key().public_bytes(
            encoding=Encoding.X962,
            format=PublicFormat.CompressedPoint,
        )

    def get_session_nonce(self: "CryptoContext") -> bytes:
        """Get session nonce.

        Returns:
            Session nonce
        """
        return self._session_nonce

    def set_preshared_key(self: "CryptoContext", preshared_key: bytes) -> None:
        """Sets preshared key.

        Args:
            preshared_key: Preshared key
        """
        self._preshared_key = preshared_key

    def set_session_nonce(self: "CryptoContext", session_nonce: bytes) -> None:
        """Sets session nonce.

        Args:
            session_nonce: Session nonce
        """
        self._session_nonce = session_nonce

    @cpu_bound_async
    def set_remote_public_key(
        self: "CryptoContext", remote_public_bytes: bytes
    ) -> None:
        """Sets remote public key.

        Method with side effects. Also calculates shared secret using
        ECDH, derives session key, and creates session cryptor.

        Args:
            remote_public_bytes: Remote public key as CompressedPoint X962 encoded bytes
        """
        self._remote_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP521R1(), remote_public_bytes
        )
        pre_key = self._private_key.exchange(ec.ECDH(), self._remote_public_key)
        derived = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=self._session_nonce,
            info=b"whiteproto-session-key",
        ).derive(pre_key)
        self._session_key = derived
        self._session_cryptor = ChaCha20Poly1305(self._session_key)

    def calculate_challenge_response(self: "CryptoContext") -> bytes:
        """Calculates response for challenge.

        Response calculated as SHA512(session_nonce + preshared_key).
        Requires preshared key to be set.

        Returns:
            Response as bytes

        Raises:
            InvalidStateError: Preshared key not set
        """
        if not self._preshared_key:
            raise InvalidStateError("Preshared key not set")

        hasher = hashes.Hash(hashes.SHA512())
        hasher.update(self._session_nonce)
        hasher.update(self._preshared_key)
        return hasher.finalize()

    @cpu_bound_async
    def sign(self: "CryptoContext", data: bytes) -> bytes:
        """Signs data.

        Args:
            data: Data to sign

        Returns:
            Signature as bytes
        """
        return self._private_key.sign(data, ec.ECDSA(hashes.SHA512()))

    @cpu_bound_async
    def verify(
        self: "CryptoContext", data: bytes, signature: bytes, origin: Origin
    ) -> bool:
        """Verifies signature.

        Public key for verification chosen based on origin.
        If origin is REMOTE, remote public key must be set.

        Args:
            data: Data to verify
            signature: Signature to verify
            origin: Origin of data

        Returns:
            True if signature is valid, False otherwise
        """
        return _verify_signature(
            data,
            signature,
            self._remote_public_key
            if origin == Origin.REMOTE
            else self.get_public_key(),
        )

    @cpu_bound_async
    def encrypt(self: "CryptoContext", data: bytes, seq: int) -> tuple[bytes, bytes]:
        """Encrypts data.

        Requires remote public key to be set. Sequence number is
        used in authentication to prevent replay attacks, message
        reordering, and manipulations to prevent key rotation.

        Args:
            data: Data to encrypt
            seq: Sequence number

        Returns:
            Tuple of nonce and ciphertext

        Raises:
            InvalidStateError: Remote public key not set
        """
        if not self._session_cryptor:
            raise InvalidStateError("Remote public key not set")
        nonce = _generate_random(12)
        ciphertext = self._session_cryptor.encrypt(
            nonce, data, b"whiteproto-seq-%d" % seq
        )
        return nonce, ciphertext

    @cpu_bound_async
    def decrypt(
        self: "CryptoContext", nonce: bytes, ciphertext: bytes, seq: int
    ) -> bytes:
        """Decrypts data.

        Requires remote public key to be set. Sequence number is
        authenticated to prevent replay attacks, message reordering,
        and manipulations to prevent key rotation.

        Args:
            nonce: Nonce used in encryption
            ciphertext: Ciphertext to decrypt
            seq: Sequence number

        Returns:
            Decrypted data

        Raises:
            InvalidStateError: Remote public key not set
            EncryptionFailureError: Decryption failed
        """
        if not self._session_cryptor:
            raise InvalidStateError("Session key not set")
        try:
            return self._session_cryptor.decrypt(
                nonce, ciphertext, b"whiteproto-seq-%d" % seq
            )
        except InvalidTag:
            raise EncryptionFailureError() from None

    # endregion
