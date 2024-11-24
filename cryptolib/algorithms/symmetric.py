import struct
from ..cipher import BlockCipherAlgorithm


class TEA(BlockCipherAlgorithm):
    """TEA (Tiny Encryption Algorithm) block cipher implementation."""

    def __init__(self, key: bytes):
        """
        Initialize the TEA cipher with a key.

        :param bytes key: The 16-byte key (128 bits) for TEA.
        """
        if len(key) != 16:
            raise ValueError("TEA requires a 128-bit (16-byte) key.")
        self.key = key

    @property
    def key_size(self) -> int:
        """The key size of TEA (128 bits)."""
        return 128

    @property
    def block_size(self) -> int:
        """The block size of TEA (64 bits)."""
        return 64

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt a 64-bit block using TEA."""
        if len(block) != 8:
            raise ValueError("TEA operates on 64-bit (8-byte) blocks.")

        # Convert the block to two 32-bit unsigned integers
        v0, v1 = struct.unpack("!2I", block)

        # TEA encryption rounds
        sum = 0
        delta = 0x9e3779b9  # Golden ratio constant (used in TEA)
        for _ in range(32):
            sum = (sum + delta) & 0xffffffff
            v0 += ((v1 << 4) + self.key[0] ^ (v1 + sum) ^ (v1 >> 5) + self.key[1]) & 0xffffffff
            v0 &= 0xffffffff
            v1 += ((v0 << 4) + self.key[2] ^ (v0 + sum) ^ (v0 >> 5) + self.key[3]) & 0xffffffff
            v1 &= 0xffffffff

        # Return the encrypted block as bytes
        return struct.pack("!2I", v0, v1)

    def decrypt_block(self, block: bytes) -> bytes:
        """Decrypt a 64-bit block using TEA."""
        if len(block) != 8:
            raise ValueError("TEA operates on 64-bit (8-byte) blocks.")

        # Convert the block to two 32-bit unsigned integers
        v0, v1 = struct.unpack("!2I", block)

        # TEA decryption rounds
        sum = 0xC6EF3720  # Initial value for decryption (opposite of encryption sum)
        delta = 0x9e3779b9
        for _ in range(32):
            v1 -= ((v0 << 4) + self.key[2] ^ (v0 + sum) ^ (v0 >> 5) + self.key[3]) & 0xffffffff
            v1 &= 0xffffffff
            v0 -= ((v1 << 4) + self.key[0] ^ (v1 + sum) ^ (v1 >> 5) + self.key[1]) & 0xffffffff
            v0 &= 0xffffffff
            sum = (sum - delta) & 0xffffffff

        # Return the decrypted block as bytes
        return struct.pack("!2I", v0, v1)
