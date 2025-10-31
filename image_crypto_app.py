import streamlit as st
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import io

# Page config
st.set_page_config(page_title="Image AES Encryptor/Decryptor", layout="wide")

def generate_key(key_length=32):
    """Generate a random AES key of specified length (16, 24, or 32 bytes)."""
    return os.urandom(key_length)

def key_to_string(key):
    """Convert key bytes to base64 string for sharing."""
    return base64.b64encode(key).decode('utf-8')

def string_to_key(key_str):
    """Convert base64 string back to key bytes."""
    return base64.b64decode(key_str)

@st.cache_data
def encrypt_image(data, key):
    """Encrypt image bytes with given key."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

@st.cache_data
def decrypt_image(encrypted_data, key):
    """Decrypt image bytes with given key."""
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

# Sidebar for navigation
st.sidebar.title("Navigation")
page = st.sidebar.selectbox("Choose action:", ["Encrypt Image", "Decrypt Image"])

if page == "Encrypt Image":
    st.title("🔒 Encrypt Your Image")
    st.write("Upload an image to generate a random key, encrypt it, and download the secure file + key.")
    
    uploaded_file = st.file_uploader("Choose an image file (JPG, PNG, etc.)", type=['jpg', 'jpeg', 'png', 'bmp', 'gif'])
    
    if uploaded_file is not None:
        # Read image data
        image_data = uploaded_file.read()
        original_filename = uploaded_file.name
        
        # Generate key
        key = generate_key(32)  # AES-256
        key_str = key_to_string(key)
        
        if st.button("Generate Key & Encrypt"):
            with st.spinner("Encrypting..."):
                encrypted_data = encrypt_image(image_data, key)
                
                # Create downloadable encrypted file
                encrypted_filename = original_filename.rsplit('.', 1)[0] + '.enc'
                st.download_button(
                    label="Download Encrypted Image",
                    data=encrypted_data,
                    file_name=encrypted_filename,
                    mime="application/octet-stream"
                )
                
                # Display key for copying/sharing
                st.success("Encryption complete!")
                st.subheader("Your Sharable Key (Copy this!):")
                st.code(key_str, language='text')
                
                # Optional: Download key as file
                key_data = f"Key for {original_filename}: {key_str}".encode('utf-8')
                st.download_button(
                    label="Download Key as TXT",
                    data=key_data,
                    file_name=f"{original_filename.rsplit('.', 1)[0]}_key.txt",
                    mime="text/plain"
                )
                
                # Preview original (optional)
                st.image(image_data, caption="Original Image", use_column_width=True)

elif page == "Decrypt Image":
    st.title("🔓 Decrypt Your Image")
    st.write("Upload the encrypted file and paste the key to decrypt and download the original image.")
    
    uploaded_enc_file = st.file_uploader("Choose encrypted file (.enc)", type='enc')
    key_input = st.text_area("Paste the Key Here (Base64 string):", placeholder="e.g., VGVzdEtleTEyMzQ1Njc4OTBhYmNkZWY=")
    
    if uploaded_enc_file is not None and key_input.strip():
        try:
            # Read encrypted data
            enc_data = uploaded_enc_file.read()
            
            # Convert key
            key = string_to_key(key_input.strip())
            
            if st.button("Decrypt Image"):
                with st.spinner("Decrypting..."):
                    decrypted_data = decrypt_image(enc_data, key)
                    
                    # Guess original extension (you may need to adjust based on your files)
                    original_ext = ".jpg"  # Default; in production, store extension with encrypted file
                    decrypted_filename = uploaded_enc_file.name.rsplit('.', 1)[0] + original_ext
                    
                    st.success("Decryption complete!")
                    st.download_button(
                        label="Download Decrypted Image",
                        data=decrypted_data,
                        file_name=decrypted_filename,
                        mime="image/jpeg"  # Adjust based on extension
                    )
                    
                    # Preview decrypted
                    st.image(decrypted_data, caption="Decrypted Image", use_column_width=True)
                    
        except Exception as e:
            st.error(f"Decryption failed: {str(e)}. Check key and file match.")

# Footer
st.sidebar.markdown("---")
st.sidebar.info("💡 Share the .enc file + key with anyone. They can decrypt using this app!")