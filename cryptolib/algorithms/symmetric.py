import struct
import typing
from .. import modes
from ..cipher import BlockCipherAlgorithm


class TEA(BlockCipherAlgorithm):
    """TEA (Tiny Encryption Algorithm) block cipher implementation."""
    ROUNDS = 32
    DELTA = 0x9e3779b9  # Golden ratio constant

    def __init__(self, key: bytes):
        """
        Initialize the TEA cipher with a key.

        :param bytes key: The 16-byte key (128 bits) for TEA.
        """
        if not isinstance(key, bytes):
            raise TypeError(f"'key' must be of type 'bytes', not of type '{type(key).__name__}'.")
        if len(key) != self.key_size // 8:
            raise ValueError(f"TEA requires a {self.key_size}-bit ({self.key_size // 8}-byte) key.")
        self.key = key

    @property
    def key_size(self) -> int:
        """The key size of TEA (128 bits)."""
        return 128

    @property
    def block_size(self) -> int:
        """The block size of TEA (64 bits)."""
        return 64

    def encrypt_block(self, block: bytes, mode: modes.Mode, iv: typing.Optional[bytes] = None) -> bytes:
        """Encrypt a 64-bit block using TEA."""
        if not isinstance(block, bytes):
            raise TypeError(f"'block' must be of type 'bytes', not of type '{type(block).__name__}'.")
        if not isinstance(mode, modes.Mode):
            raise TypeError(f"'mode' must be an instance of type 'Mode' (modes.Mode), not of type '{type(mode).__name__}'.")
        if not isinstance(iv, bytes):
            raise TypeError(f"'iv' must be of type 'bytes', not of type '{type(iv).__name__}'.")

        if len(block) != self.block_size // 8:
            raise ValueError(f"TEA operates on {self.block_size}-bit ({self.block_size // 8}-byte) blocks.")
        if isinstance(mode, modes.IVMode) and (not iv or len(iv) != self.block_size // 8):
            raise ValueError(f"The IV (Initialization Vector) must be {self.block_size}-bits ({self.block_size // 8}-bytes) long for IV-based modes.")

        # Handle IV-based modes
        if isinstance(mode, modes.CBC):
            # CBC Mode: XOR the block with the IV before encryption
            block = bytes(a ^ b for a, b in zip(block, iv))
        elif isinstance(mode, (modes.CFB, modes.OFB)):
            # CFB/OFB Mode: Encrypt the IV, XOR with plaintext to create ciphertext
            encrypted_iv = self._encrypt_iv(iv)
            block = bytes(a ^ b for a, b in zip(block, encrypted_iv))
        elif isinstance(mode, modes.ECB):
            pass
        else:
            raise ValueError("Unsupported cipher mode.")

        # Convert the block to two 32-bit unsigned integers
        v0, v1 = struct.unpack("!2I", block)

        # TEA encryption rounds
        s = 0
        for _ in range(self.ROUNDS):
            s = (s + self.DELTA) & 0xffffffff
            v0 += ((v1 << 4) + self.key[0] ^ (v1 + s) ^ (v1 >> 5) + self.key[1]) & 0xffffffff
            v0 &= 0xffffffff
            v1 += ((v0 << 4) + self.key[2] ^ (v0 + s) ^ (v0 >> 5) + self.key[3]) & 0xffffffff
            v1 &= 0xffffffff

        # Return the encrypted block as bytes
        return struct.pack("!2I", v0, v1)

    def decrypt_block(self, block: bytes, mode: modes.Mode, iv: typing.Optional[bytes] = None) -> bytes:
        """Decrypt a 64-bit block using TEA."""
        if not isinstance(block, bytes):
            raise TypeError(f"'block' must be of type 'bytes', not of type '{type(block).__name__}'.")
        if not isinstance(mode, modes.Mode):
            raise TypeError(f"'mode' must be an instance of type 'Mode' (modes.Mode), not of type '{type(mode).__name__}'.")
        if not isinstance(iv, bytes):
            raise TypeError(f"'iv' must be of type 'bytes', not of type '{type(iv).__name__}'.")

        if len(block) != self.block_size // 8:
            raise ValueError(f"TEA operates on {self.block_size}-bit ({self.block_size // 8}-byte) blocks.")
        if isinstance(mode, modes.IVMode) and (not iv or len(iv) != self.block_size // 8):
            raise ValueError(f"The IV (Initialization Vector) must be {self.block_size}-bits ({self.block_size // 8}-bytes) long for IV-based modes.")

        # Convert the block to two 32-bit unsigned integers
        v0, v1 = struct.unpack("!2I", block)

        # TEA decryption rounds
        s = 0xC6EF3720  # Initial value for decryption (opposite of encryption sum)
        for _ in range(self.ROUNDS):
            v1 -= ((v0 << 4) + self.key[2] ^ (v0 + s) ^ (v0 >> 5) + self.key[3]) & 0xffffffff
            v1 &= 0xffffffff
            v0 -= ((v1 << 4) + self.key[0] ^ (v1 + s) ^ (v1 >> 5) + self.key[1]) & 0xffffffff
            v0 &= 0xffffffff
            s = (s - self.DELTA) & 0xffffffff

        # Reconstruct the decrypted block
        decrypted_block = struct.pack("!2I", v0, v1)

        # Handle IV-based modes
        if isinstance(mode, modes.CBC):
            # CBC Mode: XOR the decrypted block with the IV
            decrypted_block = bytes(a ^ b for a, b in zip(decrypted_block, iv))
        elif isinstance(mode, (modes.CFB, modes.OFB)):
            # CFB/OFB Mode: XOR the ciphertext block with the encrypted IV to recover plaintext
            encrypted_iv = self._encrypt_iv(iv)
            decrypted_block = bytes(a ^ b for a, b in zip(block, encrypted_iv))
        elif isinstance(mode, modes.ECB):
            pass
        else:
            raise ValueError("Unsupported cipher mode.")

        return decrypted_block

    def _encrypt_iv(self, iv: bytes) -> bytes:
        """Encrypt the IV using TEA."""
        if not isinstance(iv, bytes):
            raise TypeError(f"'iv' must be of type 'bytes', not of type '{type(iv).__name__}'.")

        v0, v1 = struct.unpack("!2I", iv)
        s = 0
        for _ in range(self.ROUNDS):
            s = (s + self.DELTA) & 0xffffffff
            v0 += ((v1 << 4) + self.key[0] ^ (v1 + s) ^ (v1 >> 5) + self.key[1]) & 0xffffffff
            v0 &= 0xffffffff
            v1 += ((v0 << 4) + self.key[2] ^ (v0 + s) ^ (v0 >> 5) + self.key[3]) & 0xffffffff
            v1 &= 0xffffffff
        return struct.pack("!2I", v0, v1)
