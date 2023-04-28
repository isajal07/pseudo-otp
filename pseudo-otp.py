import argparse
import secrets


def gen_key(n: int) -> str:
    """
    Generate an n-bit pseudorandom key using the secrets module.
    """
    return bin(secrets.randbits(n))[2:].zfill(n)


def encrypt(plaintext: str, key: str) -> str:
    """
    Encrypt plaintext using the one-time pad scheme with a PRG key.
    """
    if len(key) < len(plaintext):
        raise ValueError("Key must be at least as long as the plaintext")
    # Convert plaintext and key to binary strings
    plaintext_bits = ''.join(format(ord(c), '08b') for c in plaintext)
    key_bits = ''.join(format(int(c), '08b') for c in key)
    # Generate a pseudorandom bit string the same length as the plaintext
    prg_bits = bin(secrets.randbits(len(plaintext_bits)))[
        2:].zfill(len(plaintext_bits))
    # XOR the plaintext and PRG bits using Python's built-in bitwise XOR operator (^)
    ciphertext_bits = ''.join(str(int(a) ^ int(b))
                              for a, b in zip(plaintext_bits, prg_bits))
    # Convert the ciphertext binary string back to ASCII
    ciphertext = ''.join(
        chr(int(ciphertext_bits[i:i+8], 2)) for i in range(0, len(ciphertext_bits), 8))
    return ciphertext


def decrypt(ciphertext: str, key: str) -> str:
    """
    Decrypt ciphertext using the one-time pad scheme with a PRG key.
    """
    if len(key) < len(ciphertext):
        raise ValueError("Key must be at least as long as the ciphertext")
    # Convert ciphertext and key to binary strings
    ciphertext_bits = ''.join(format(ord(c), '08b') for c in ciphertext)
    key_bits = ''.join(format(int(c), '08b') for c in key)
    # Generate the same pseudorandom bit string used to encrypt the plaintext
    prg_bits = bin(secrets.randbits(len(ciphertext_bits)))[
        2:].zfill(len(ciphertext_bits))
    # XOR the ciphertext and PRG bits using Python's built-in bitwise XOR operator (^)
    plaintext_bits = ''.join(str(int(a) ^ int(b))
                             for a, b in zip(ciphertext_bits, prg_bits))
    # Convert the plaintext binary string back to ASCII
    plaintext = ''.join(
        chr(int(plaintext_bits[i:i+8], 2)) for i in range(0, len(plaintext_bits), 8))
    return plaintext


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Implement a pseudo one-time pad scheme (OTP) using a pseudorandom generator (PRG)")
    parser.add_argument(
        "-gen", type=int, help="Generate an n-bit pseudorandom key")
    parser.add_argument(
        "-enc", nargs=2, help="Encrypt plaintext using the given key")
    parser.add_argument(
        "-dec", nargs=2, help="Decrypt ciphertext using the given key")
    args = parser.parse_args()

    if args.gen:
        print(gen_key(args.gen))
    elif args.enc:
        key = args.enc[0]
        plaintext = args.enc[1]
        print(encrypt(plaintext, key))
    elif args.dec:
        key = args.dec[0]
        ciphertext = args.dec[1]
        print(decrypt(ciphertext, key))
    else:
        print("Please provide one of the following options: -gen <n>, -enc <key> <plaintext>, -dec <key> <ciphertext>")
