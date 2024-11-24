import abc
import typing
from . import modes


class CipherAlgorithm(metaclass=abc.ABCMeta):
    """An abstract base class for cipher algorithm implementations."""
    @property
    @abc.abstractmethod
    def name(self) -> str:
        """A string identifier specific to the cipher."""
        pass

    @property
    @abc.abstractmethod
    def key_sizes(self) -> frozenset[int]:
        """A set of valid key sizes (in bits) specific to the cipher."""
        pass


class BlockCipherAlgorithm(metaclass=abc.ABCMeta):
    """An abstract base class for block cipher algorithm implementations."""
    key: bytes

    @property
    @abc.abstractmethod
    def key_size(self) -> int:
        """The size of the cipher key (in bits)."""
        pass

    @property
    @abc.abstractmethod
    def block_size(self) -> int:
        """The block size of the cipher-algorithm (in bits)."""
        pass

    @abc.abstractmethod
    def encrypt_block(self, block: bytes, mode: modes.Mode, iv: typing.Optional[bytes] = None) -> bytes:
        """Encrypt a block of data."""
        return block

    @abc.abstractmethod
    def decrypt_block(self, block: bytes, mode: modes.Mode, iv: typing.Optional[bytes] = None) -> bytes:
        """Decrypt a block of data."""
        return block

    @abc.abstractmethod
    def encrypt_iv(self, iv: bytes) -> bytes:
        """Encrypt an IV (Initialization Vector). This is only practically used during CFB (Cipher Feedback) and OFB (Output Feedback) modes."""
        pass
