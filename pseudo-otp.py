import argparse
import random


def gen(n):
    """Generate an n-bit random key"""
    return bin(random.getrandbits(n))[2:].zfill(n)


def xor_strings(s1, s2):
    """Return XOR of two strings of equal length"""
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))


def text_to_binary(text):
    binary = ""
    # iterate over each character in the text
    for char in text:
        # convert the character to its corresponding binary representation
        binary += format(ord(char), '08b')
    return binary


def binary_to_text(binary):
    # split the binary string into 8-bit chunks
    chunks = [binary[i:i+8] for i in range(0, len(binary), 8)]
    # convert each 8-bit chunk to its corresponding integer value
    values = [int(chunk, 2) for chunk in chunks]
    # convert each integer value to its corresponding ASCII character
    text = ''.join([chr(value) for value in values])
    return text


def enc(key, plaintext):
    """Encrypt plaintext using the key"""
    ciphertext = xor_strings(key, plaintext)
    binary = text_to_binary(ciphertext)
    return binary


def dec(key, binary):
    """Decrypt binary using the key"""
    text = binary_to_text(binary)
    plaintext = xor_strings(key, text)
    return plaintext


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Pseudo one-time pad encryption/decryption')
    parser.add_argument('-gen', type=int, help='Generate an n-bit key')
    parser.add_argument('-enc', nargs=2, help='Encrypt plaintext using a key')
    parser.add_argument('-dec', nargs=2, help='Decrypt ciphertext using a key')
    args = parser.parse_args()

    if args.gen:
        key = gen(args.gen)
        print(key)
    elif args.enc:
        key = args.enc[0]
        plaintext = args.enc[1]
        ciphertext = enc(key, plaintext)
        print(ciphertext)
    elif args.dec:
        key = args.dec[0]
        ciphertext = args.dec[1]
        plaintext = dec(key, ciphertext)
        print(plaintext)
    else:
        parser.print_help()


# def test() -> str:
#     gk = gen(11)
#     enc1 = enc(gk, "hello there")
#     dec1 = dec(gk, enc1)
#     print(dec1)

# test()
