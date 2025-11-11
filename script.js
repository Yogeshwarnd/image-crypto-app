// Utility functions
function base64Encode(arrayBuffer) {
    const bytes = new Uint8Array(arrayBuffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}
function base64Decode(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}
// PKCS7 Padding/Unpadding
function pkcs7Pad(data, blockSize = 16) {
    const padded = new Uint8Array(data);
    const padLength = blockSize - (padded.length % blockSize);
    const newPadded = new Uint8Array(padded.length + padLength);
    newPadded.set(padded);
    for (let i = 0; i < padLength; i++) {
        newPadded[padded.length + i] = padLength;
    }
    return newPadded.buffer;
}
function pkcs7Unpad(data) {
    const unpadded = new Uint8Array(data);
    const padLength = unpadded[unpadded.length - 1];
    if (padLength > 16 || padLength === 0) throw new Error('Invalid padding');
    for (let i = unpadded.length - padLength; i < unpadded.length; i++) {
        if (unpadded[i] !== padLength) throw new Error('Invalid padding');
    }
    return unpadded.slice(0, -padLength).buffer;
}
// Generate random AES-256 key
async function generateKey() {
    const keyBytes = new Uint8Array(32);
    crypto.getRandomValues(keyBytes);
    const key = await crypto.subtle.importKey('raw', keyBytes.buffer, 'AES-CBC', false, ['encrypt']);
    const keyB64 = btoa(String.fromCharCode(...keyBytes));
    return { key, keyB64 };
}
// Encrypt data
async function encryptData(data, key) {
    const iv = new Uint8Array(16);
    crypto.getRandomValues(iv);
    const paddedData = pkcs7Pad(data);
    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-CBC', iv },
        key,
        paddedData
    );
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(encrypted), iv.length);
    return combined.buffer;
}
// Decrypt data
async function decryptData(encryptedData, key) {
    const data = new Uint8Array(encryptedData);
    const iv = data.slice(0, 16);
    const ciphertext = data.slice(16);
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-CBC', iv },
        key,
        ciphertext.buffer
    );
    return pkcs7Unpad(decrypted);
}
// Handle Encrypt
async function handleEncrypt() {
    const fileInput = document.getElementById('encryptFile');
    const file = fileInput.files[0];
    if (!file) {
        showMessage('encrypt', 'error', 'Please select an image file.');
        return;
    }
    const btn = document.getElementById('encryptBtn');
    const spinner = document.getElementById('encryptSpinner');
    btn.disabled = true;
    spinner.classList.add('active');
    btn.innerHTML = '<i class="fas fa-cog fa-spin"></i> Encrypting...';
    try {
        const arrayBuffer = await file.arrayBuffer();
        const { key, keyB64 } = await generateKey();
        const encryptedBuffer = await encryptData(arrayBuffer, key);
        const originalB64 = base64Encode(arrayBuffer);
        // Preview
        document.getElementById('originalPreview').innerHTML = `
            <h3><i class="fas fa-eye"></i> Original Preview</h3>
            <img src="data:${file.type};base64,${originalB64}" alt="Original Image">
        `;
        // Result
        const encFilename = file.name.replace(/\.[^/.]+$/, '.enc');
        const keyFilename = file.name.replace(/\.[^/.]+$/, '_key.txt');
        document.getElementById('encryptResult').innerHTML = `
            <div class="success result">
                <h3><i class="fas fa-check-circle"></i> Encryption Successful!</h3>
                <div class="key-section">
                    <strong><i class="fas fa-key"></i> Secure Key (Base64 - Copy & Share Safely)</strong>
                    <textarea readonly rows="3">${keyB64}</textarea>
                    <small><i class="fas fa-info-circle"></i> Keep this key private and secure.</small>
                </div>
                <div class="download-links">
                    <a href="${URL.createObjectURL(new Blob([encryptedBuffer], {type: 'application/octet-stream'}))}" download="${encFilename}" class="btn btn-success">
                        <i class="fas fa-download"></i> Download .enc File
                    </a>
                    <a href="${URL.createObjectURL(new Blob([`Key for ${file.name}: ${keyB64}`], {type: 'text/plain'}))}" download="${keyFilename}" class="btn btn-warning">
                        <i class="fas fa-file-alt"></i> Download Key.txt
                    </a>
                </div>
            </div>
        `;
    } catch (err) {
        showMessage('encrypt', 'error', `Encryption failed: ${err.message}`);
    } finally {
        btn.disabled = false;
        spinner.classList.remove('active');
        btn.innerHTML = '<i class="fas fa-key"></i> Generate Key & Encrypt';
    }
}
// Handle Decrypt
async function handleDecrypt() {
    const fileInput = document.getElementById('decryptFile');
    const keyInput = document.getElementById('keyInput');
    const file = fileInput.files[0];
    const keyB64 = keyInput.value.trim();
    if (!file || !keyB64) {
        showMessage('decrypt', 'error', 'Please select an encrypted file and enter the key.');
        return;
    }
    const btn = document.getElementById('decryptBtn');
    const spinner = document.getElementById('decryptSpinner');
    btn.disabled = true;
    spinner.classList.add('active');
    btn.innerHTML = '<i class="fas fa-cog fa-spin"></i> Decrypting...';
    try {
        const arrayBuffer = await file.arrayBuffer();
        const keyData = base64Decode(keyB64);
        const key = await crypto.subtle.importKey('raw', keyData, 'AES-CBC', false, ['decrypt']);
        const decryptedBuffer = await decryptData(arrayBuffer, key);
        const decryptedB64 = base64Encode(decryptedBuffer);
        const mimeType = 'image/jpeg'; // Default; can detect or user-select
        // Preview
        document.getElementById('decryptedPreview').innerHTML = `
            <h3><i class="fas fa-eye"></i> Decrypted Preview</h3>
            <img src="data:${mimeType};base64,${decryptedB64}" alt="Decrypted Image">
        `;
        // Result
        const decFilename = file.name.replace('.enc', '.jpg');
        document.getElementById('decryptResult').innerHTML = `
            <div class="success result">
                <h3><i class="fas fa-check-circle"></i> Decryption Successful!</h3>
                <div class="download-links">
                    <a href="${URL.createObjectURL(new Blob([decryptedBuffer], {type: mimeType}))}" download="${decFilename}" class="btn btn-success">
                        <i class="fas fa-download"></i> Download Image
                    </a>
                </div>
            </div>
        `;
    } catch (err) {
        showMessage('decrypt', 'error', `Decryption failed: ${err.message}. Verify the key and file.`);
    } finally {
        btn.disabled = false;
        spinner.classList.remove('active');
        btn.innerHTML = '<i class="fas fa-unlock-alt"></i> Decrypt Image';
    }
}
function showMessage(page, type, msg) {
    const resultDiv = document.getElementById(`${page}Result`);
    const icon = type === 'error' ? 'fas fa-exclamation-triangle' : 'fas fa-info-circle';
    const className = type === 'error' ? 'error' : 'success';
    resultDiv.innerHTML = `
        <div class="${className} result">
            <h3><i class="${icon}"></i> ${msg}</h3>
        </div>
    `;
}
function showPage(pageId) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
    document.getElementById(pageId).classList.add('active');
    document.getElementById(pageId + '-btn').classList.add('active');
    // Clear results and previews
    ['Result', 'Preview'].forEach(suffix => {
        const el = document.getElementById(`${pageId}${suffix}`);
        if (el) el.innerHTML = '';
    });
}
// Browser support check
if (!window.crypto || !window.crypto.subtle) {
    document.querySelector('.container').innerHTML = `
        <div style="text-align: center; padding: 40px;">
            <i class="fas fa-exclamation-triangle" style="font-size: 4em; color: var(--error-color);"></i>
            <h2>Your browser does not support Web Crypto API.</h2>
            <p>Please use a modern browser like Chrome, Firefox, Edge, or Safari.</p>
        </div>
    `;
}
