from cryptography.fernet import Fernet

# Once the Key is Generate Place it in the Same Directory/Folder with the 404Crypt.py File
# The Key Should Be kept Secret


# Encryption Key Generator
def generate_key():
    key = Fernet.generate_key()
    key_file = "symmetric_key.pem"  # file name

    # Saving Key to file
    with open(key_file, "wb") as encryption_key:
        encryption_key.write(key)

    return key


generate_key()

