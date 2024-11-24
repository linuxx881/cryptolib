import abc


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
    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt a block of data."""
        return block

    @abc.abstractmethod
    def decrypt_block(self, block: bytes) -> bytes:
        """Decrypt a block of data."""
        return block
