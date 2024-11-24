from abc import ABC


# Abstract base class for all cipher modes
class Mode(ABC):
    """
    A marker class for cipher modes.

    This class is used to identify cipher modes without enforcing any methods.
    """
    pass


# Abstract base class for cipher modes that require an IV (Initialization Vector)
class IVMode(Mode):
    """
    A marker class for cipher modes that require an IV (Initialization Vector).

    Inherits from Mode to identify IV modes.
    """
    pass


# Core modes
class CBC(IVMode):
    """
    CBC mode of operation. Each plaintext block is XOR-ed with the previous ciphertext block before encryption, and vice-versa with decryption. Each block depends on the previous one.

    Requires an IV for encryption and decryption.
    """
    pass


class CFB(IVMode):
    """
    CFB mode of operation. Like CBC, but uses feedback from the previous ciphertext block to encrypt the next block.

    Requires an IV for encryption and decryption.
    """
    pass


class OFB(IVMode):
    """
    OFB mode of operation. Generates a keystream by repeatedly encrypting the IV and XOR-ing it with the plaintext.

    Requires an IV for encryption and decryption.
    """
    pass


class ECB(Mode):
    """
    ECB mode of operation. Each plaintext block is encrypted independently, without chaining or feedback.

    Does not require an IV.
    """
    pass
