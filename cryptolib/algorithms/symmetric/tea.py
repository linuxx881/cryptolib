import struct
import typing
from ... import modes
from ...cipher import BlockCipherAlgorithm


class TEA(BlockCipherAlgorithm):
    """TEA (Tiny Encryption Algorithm) block cipher implementation (0.3.1)."""
    VERSION = '0.3.1'
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
        """
        Encrypt a 64-bit block of plaintext using the TEA (Tiny Encryption Algorithm) cipher.

        This method encrypts a single 64-bit block (8 bytes) of data using the TEA algorithm. The block is
        encrypted according to the specified mode of operation, which determines how the cipher interacts
        with the block and the initialization vector (IV), if provided.

        Supported modes include:
            - **CBC (Cipher Block Chaining)**: The plaintext block is XORed with the IV before encryption.
            - **CFB (Cipher Feedback)**: The IV is encrypted, and the resulting ciphertext is XORed with the plaintext block.
            - **OFB (Output Feedback)**: Similar to CFB, but the output of the previous encryption is used for feedback.
            - **ECB (Electronic Codebook)**: Each block is encrypted independently with no chaining or feedback.

        :param bytes block: A 64-bit block of plaintext (8 bytes) to be encrypted. The length of `block` must be
                             exactly 8 bytes (64 bits), or a `ValueError` will be raised.
        :param modes.Mode mode: The cipher mode to use for encryption. This determines how the IV (if required) is
                                 used and how the encryption interacts with the block.
        :param bytes iv: The initialization vector (IV) for modes that require it (e.g., CBC, CFB, OFB).
                          If no IV is required (e.g., for ECB), this parameter can be `None`. The IV must
                          be 8 bytes (64 bits) long for modes that require it.

        :returns: The 64-bit ciphertext block resulting from the encryption. The length of the output is
                  always 8 bytes (64 bits), matching the size of the input block.
        :rtype: bytes

        :raises TypeError: If the `block`, `mode`, or `iv` are not of the correct types.
        :raises ValueError: If the `block` size is not 8 bytes, if the IV (when required) is not 8 bytes long, or if an
                            unsupported cipher mode is provided.
        """
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
            encrypted_iv = self.encrypt_iv(iv)
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
        """
        Decrypt a 64-bit block of ciphertext using the TEA (Tiny Encryption Algorithm) cipher.

        This method decrypts a single 64-bit block (8 bytes) of ciphertext using the TEA algorithm. The block is
        decrypted according to the specified mode of operation, which determines how the cipher interacts
        with the block and the initialization vector (IV), if provided.

        Supported modes include:
            - **CBC (Cipher Block Chaining)**: The ciphertext block is XORed with the IV after decryption.
            - **CFB (Cipher Feedback)**: The IV is encrypted, and the resulting ciphertext is XORed with the ciphertext block to retrieve the plaintext.
            - **OFB (Output Feedback)**: Similar to CFB, but the output of the previous encryption is used for feedback.
            - **ECB (Electronic Codebook)**: Each block is decrypted independently with no chaining or feedback.

        :param bytes block: A 64-bit block of ciphertext (8 bytes) to be decrypted. The length of `block` must be
                             exactly 8 bytes (64 bits), or a `ValueError` will be raised.
        :param modes.Mode mode: The cipher mode to use for decryption. This determines how the IV (if required) is
                                 used and how the decryption interacts with the block.
        :param bytes iv: The initialization vector (IV) for modes that require it (e.g., CBC, CFB, OFB).
                          If no IV is required (e.g., for ECB), this parameter can be `None`. The IV must
                          be 8 bytes (64 bits) long for modes that require it.

        :returns: The 64-bit plaintext block resulting from the decryption. The length of the output is
                  always 8 bytes (64 bits), matching the size of the input block.
        :rtype: bytes

        :raises TypeError: If the `block`, `mode`, or `iv` are not of the correct types.
        :raises ValueError: If the `block` size is not 8 bytes, if the IV (when required) is not 8 bytes long, or if an
                            unsupported cipher mode is provided.
        """
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
            encrypted_iv = self.encrypt_iv(iv)
            decrypted_block = bytes(a ^ b for a, b in zip(block, encrypted_iv))
        elif isinstance(mode, modes.ECB):
            pass
        else:
            raise ValueError("Unsupported cipher mode.")

        return decrypted_block

    def encrypt_iv(self, iv: bytes) -> bytes:
        """
        Encrypt the initialization vector (IV) using the TEA (Tiny Encryption Algorithm) cipher.

        This method is used to encrypt an 8-byte (64-bit) IV for modes like CFB and OFB, where the IV is
        modified during encryption to facilitate the mode's operation. It performs the TEA encryption algorithm
        on the IV in the same way as it does for plaintext, ensuring that the IV is transformed for use in feedback modes.

        :param bytes iv: The 64-bit initialization vector (IV) to be encrypted. The length of `iv` must be exactly
                          8 bytes (64 bits), or a `ValueError` will be raised.

        :returns: The encrypted 64-bit IV, transformed using TEA.
        :rtype: bytes

        :raises TypeError: If `iv` is not of type `bytes`.
        :raises ValueError: If the `iv` size is not 8 bytes (64 bits).
        """
        if not isinstance(iv, bytes):
            raise TypeError(f"'iv' must be of type 'bytes', not of type '{type(iv).__name__}'.")
        if len(iv) != self.block_size // 8:
            raise ValueError(f"The IV (Initialization Vector) must be {self.block_size}-bits ({self.block_size // 8}-bytes) long.")

        v0, v1 = struct.unpack("!2I", iv)
        s = 0
        for _ in range(self.ROUNDS):
            s = (s + self.DELTA) & 0xffffffff
            v0 += ((v1 << 4) + self.key[0] ^ (v1 + s) ^ (v1 >> 5) + self.key[1]) & 0xffffffff
            v0 &= 0xffffffff
            v1 += ((v0 << 4) + self.key[2] ^ (v0 + s) ^ (v0 >> 5) + self.key[3]) & 0xffffffff
            v1 &= 0xffffffff
        return struct.pack("!2I", v0, v1)
