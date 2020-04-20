import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

backend = default_backend()


def add_spaces(message):
    for i in range(len(message) % 32, 32):
        message += " "
    return message


def remove_spaces(message):
    while message[-1] == ' ':
        message = message[:-1]
        if len(message) == 0:
            break
    return message


def encrypt(key, iv, message):
    message = add_spaces(message)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(message.encode('ascii')) + encryptor.finalize()


def decrypt(key, iv, ct):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    message = decryptor.update(ct) + decryptor.finalize()
    message = remove_spaces(message.decode('ascii'))
    return message


def main():

    key = os.urandom(32)
    iv = os.urandom(16)

    message = "hello"

    cipher_text = encrypt(key, iv, message)
    print("Cipher Text :", cipher_text)

    decrypted_message = decrypt(key, iv, cipher_text)
    print("Decrypted Message : " + decrypted_message)


if __name__ == "__main__":
    main()




