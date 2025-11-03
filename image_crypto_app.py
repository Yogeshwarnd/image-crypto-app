import os
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64

def generate_key(key_length=32):
    """Generate a random AES key of specified length (16, 24, or 32 bytes)."""
    return os.urandom(key_length)

def key_to_string(key):
    """Convert key bytes to base64 string for sharing."""
    return base64.b64encode(key).decode('utf-8')

def string_to_key(key_str):
    """Convert base64 string back to key bytes."""
    return base64.b64decode(key_str)

def encrypt_image(data, key, output_enc_file):
    """Encrypt image bytes with given key and save to file."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    encrypted_data = iv + ciphertext
    with open(output_enc_file, 'wb') as f:
        f.write(encrypted_data)
    return True

def decrypt_image(encrypted_data, key, output_image_file):
    """Decrypt image bytes with given key and save to file."""
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
    with open(output_image_file, 'wb') as f:
        f.write(decrypted_data)
    return True

def main():
    parser = argparse.ArgumentParser(description="Image AES Encryptor/Decryptor CLI")
    parser.add_argument('action', choices=['encrypt', 'decrypt'], help="Action to perform")
    parser.add_argument('--input', '-i', required=True, help="Input file (image for encrypt, .enc for decrypt)")
    parser.add_argument('--key-file', '-k', help="For decrypt: Path to key.txt file containing the base64 key")
    parser.add_argument('--output', '-o', help="Output file path (optional, defaults to input.enc or input.jpg)")
    parser.add_argument('--key-length', type=int, choices=[16, 24, 32], default=32, help="Key length in bytes (AES-128/192/256)")

    args = parser.parse_args()

    if args.action == 'encrypt':
        if not os.path.exists(args.input):
            print(f"Error: Input file '{args.input}' does not exist.")
            return 1

        # Read image data
        with open(args.input, 'rb') as f:
            image_data = f.read()

        original_filename = os.path.basename(args.input)
        output_enc_file = args.output or original_filename.rsplit('.', 1)[0] + '.enc'

        # Generate key
        key = generate_key(args.key_length)
        key_str = key_to_string(key)

        # Encrypt
        if encrypt_image(image_data, key, output_enc_file):
            print("Encryption complete!")
            print(f"Encrypted file saved: {output_enc_file}")
            print("\nYour Sharable Key (Copy this!):")
            print(key_str)

            # Save key as file
            key_filename = original_filename.rsplit('.', 1)[0] + '_key.txt'
            key_data = f"Key for {original_filename}: {key_str}".encode('utf-8')
            with open(key_filename, 'wb') as f:
                f.write(key_data)
            print(f"Key file saved: {key_filename}")
        else:
            print("Encryption failed.")
            return 1

    elif args.action == 'decrypt':
        if not os.path.exists(args.input):
            print(f"Error: Input file '{args.input}' does not exist.")
            return 1

        if not args.key_file or not os.path.exists(args.key_file):
            print(f"Error: Key file '{args.key_file}' does not exist.")
            return 1

        # Read encrypted data
        with open(args.input, 'rb') as f:
            enc_data = f.read()

        # Read key from file
        with open(args.key_file, 'r') as f:
            key_line = f.read().strip()
            # Extract base64 key (assuming format "Key for ...: <base64>")
            if ': ' in key_line:
                key_str = key_line.split(': ', 1)[1]
            else:
                key_str = key_line

        try:
            key = string_to_key(key_str)
        except Exception as e:
            print(f"Error: Invalid key format - {str(e)}")
            return 1

        original_ext = ".jpg"  # Default; adjust as needed
        output_image_file = args.output or args.input.rsplit('.', 1)[0] + original_ext

        # Decrypt
        if decrypt_image(enc_data, key, output_image_file):
            print("Decryption complete!")
            print(f"Decrypted image saved: {output_image_file}")
        else:
            print("Decryption failed. Check key and file match.")
            return 1

    return 0

if __name__ == "__main__":
    exit(main())
