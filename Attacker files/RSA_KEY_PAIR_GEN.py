from Crypto.PublicKey import RSA  # Generation of RSA key pais [Public/Private]
from cryptography.fernet import Fernet  # For generating Encryption Key


def rsa_key_gen():  # Private, Public Key generation
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.public_key().export_key()

    with open("private.pem", "wb") as pr_key:
        pr_key.write(private_key)

    with open("public.pem", "wb") as pu_key:
        pu_key.write(public_key)


# File Encryption Key Generator
def encryption_key_gen():
    key = Fernet.generate_key()

    # Saving Encryption Key to file
    with open("symmetric_key.pem", "wb") as encryption_key:
        encryption_key.write(key)


def main():
    rsa_key_gen()
    # encryption_key_gen()


if __name__ == "__main__":
    main()
