import os
import struct
import numpy as np
from flask import Flask, render_template, request, send_file, flash, abort
from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
import io

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# --- Crypto Constants ---
ITERATIONS = 300_000
KEY_LEN = 32 # 256 bits
SALT_LEN = 16
IV_LEN = 12

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 256-bit key from the password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode())

def encrypt_payload(plaintext: str, password: str) -> bytes:
    """
    Encrypts plaintext using AES-256-GCM.
    Returns: SALT + IV + Ciphertext + Tag
    Note: AESGCM.encrypt returns Ciphertext + Tag concatenated.
    """
    salt = os.urandom(SALT_LEN)
    key = derive_key(password, salt)
    iv = os.urandom(IV_LEN)
    aesgcm = AESGCM(key)
    
    # Encrypt
    # encryption_result includes the tag at the end
    ciphertext_and_tag = aesgcm.encrypt(iv, plaintext.encode('utf-8'), None)
    
    return salt + iv + ciphertext_and_tag

def decrypt_payload(raw_data: bytes, password: str) -> str:
    """
    Decrypts the raw payload.
    Expected format: SALT + IV + Ciphertext + Tag
    """
    try:
        if len(raw_data) < SALT_LEN + IV_LEN + 16: # Minimal length check
             raise ValueError("Data too short")
             
        salt = raw_data[:SALT_LEN]
        iv = raw_data[SALT_LEN:SALT_LEN+IV_LEN]
        ciphertext_and_tag = raw_data[SALT_LEN+IV_LEN:]
        
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        
        # This will raise InvalidTag if integrity check fails
        plaintext_bytes = aesgcm.decrypt(iv, ciphertext_and_tag, None)
        return plaintext_bytes.decode('utf-8')
    except InvalidTag:
        raise InvalidTag("ACCESS DENIED: Invalid Key or Tampered Message")
    except Exception as e:
        # Re-raise InvalidTag as generic access denied for security if needed, 
        # but prompt specifically asks to catch InvalidTag.
        # If it's another error (e.g. padding, utf-8), we wraps it.
        raise InvalidTag("ACCESS DENIED: Invalid Key or Tampered Message")

def bits_to_bytes(bits: str) -> bytes:
    return int(bits, 2).to_bytes((len(bits) + 7) // 8, byteorder='big')

def bytes_to_bits(data: bytes) -> str:
    return ''.join(f'{byte:08b}' for byte in data)

# --- Steganography Logic ---

def embed_lsb(image: Image.Image, data: bytes) -> Image.Image:
    """
    Embeds data into the image LSBs in REVERSE order.
    Payload Structure for embedding: [Length (4 bytes)] [Data]
    """
    # 1. Prepare Payload with Length Prefix
    length = len(data)
    length_prefix = struct.pack('>I', length) # 4 bytes big endian
    full_payload = length_prefix + data
    
    payload_bits = bytes_to_bits(full_payload)
    
    # 2. Get Pixels
    # Ensure image is RGB or RGBA. Convert if necessary to avoid palette issues.
    if image.mode not in ('RGB', 'RGBA'):
        image = image.convert('RGB')
        
    pixels = np.array(image)
    flat_pixels = pixels.flatten()
    
    if len(payload_bits) > len(flat_pixels):
        raise ValueError(f"Image is too small. Need {len(payload_bits)} pixels, have {len(flat_pixels)}.")

    # 3. Embed in Reverse Order
    # We start modifying from the LAST pixel backward.
    # flat_pixels[-1] gets the first bit of the payload? 
    # Or flat_pixels[-1] gets the last bit?
    # "Read ... in exact reverse order".
    # Let's assume we write the stream sequentially into the pixels iterated in reverse.
    # index 0 of payload -> last pixel
    # index 1 of payload -> second to last pixel
    
    total_pixels_count = len(flat_pixels)
    
    for i, bit_char in enumerate(payload_bits):
        pixel_idx = total_pixels_count - 1 - i
        bit = int(bit_char)
        
        # Apply LSB
        current_val = flat_pixels[pixel_idx]
        new_val = (current_val & 0xFE) | bit
        flat_pixels[pixel_idx] = new_val
        
    # 4. Reconstruct Image
    stego_pixels = flat_pixels.reshape(pixels.shape)
    return Image.fromarray(stego_pixels.astype('uint8'), image.mode)

def extract_lsb(image: Image.Image) -> bytes:
    """
    Extracts LSB data reading in REVERSE order.
    """
    # 1. Get Pixels
    if image.mode not in ('RGB', 'RGBA'):
        image = image.convert('RGB')
        
    pixels = np.array(image)
    flat_pixels = pixels.flatten()
    total_pixels_count = len(flat_pixels)
    
    # 2. Read Length (First 32 bits from the end)
    length_bits_list = []
    for i in range(32):
        pixel_idx = total_pixels_count - 1 - i
        val = flat_pixels[pixel_idx]
        length_bits_list.append(str(val & 1))
        
    length_bits = "".join(length_bits_list)
    try:
        length = int(length_bits, 2)
    except:
        raise ValueError("Failed to decode length.")
        
    # Validation of length
    if length <= 0 or (length * 8 + 32) > total_pixels_count:
        # This usually means no message is present or it's random noise
        # But we must try to proceed to "Fail gracefully" later if possible,
        # or just error out here.
        # Given "Hacker Test", returning empty or error is fine.
        raise ValueError("No valid message detected (Invalid Length).")

    # 3. Read The Rest
    payload_bits_list = []
    start_bit_idx = 32
    end_bit_idx = 32 + (length * 8)
    
    for i in range(start_bit_idx, end_bit_idx):
        pixel_idx = total_pixels_count - 1 - i
        val = flat_pixels[pixel_idx]
        payload_bits_list.append(str(val & 1))
        
    payload_bits = "".join(payload_bits_list)
    
    # 4. Convert to Bytes
    # int(payload_bits, 2) might be huge, let's chunk it or use int.to_bytes
    # Python handles large ints automatically.
    try:
        # Padding
        if len(payload_bits) % 8 != 0:
             # This theoretically shouldn't happen based on logic above
             pass
        
        extracted_int = int(payload_bits, 2)
        extracted_bytes = extracted_int.to_bytes(length, byteorder='big')
        return extracted_bytes
    except Exception as e:
        raise ValueError(f"Extraction failed: {str(e)}")


# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encode', methods=['POST'])
def encode():
    try:
        if 'image' not in request.files or 'plaintext' not in request.form or 'password' not in request.form:
            flash('Missing data!', 'error')
            return redirect(url_for('index'))
            
        image_file = request.files['image']
        plaintext = request.form['plaintext']
        password = request.form['password']
        
        if image_file.filename == '':
            flash('No selected file', 'error')
            return redirect(url_for('index'))

        if not plaintext:
             flash('Plaintext cannot be empty', 'error')
             return redirect(url_for('index'))
             
        # Process
        img = Image.open(image_file)
        encrypted_payload = encrypt_payload(plaintext, password)
        stego_img = embed_lsb(img, encrypted_payload)
        
        # Save to buffer
        buf = io.BytesIO()
        stego_img.save(buf, format="PNG")
        buf.seek(0)
        
        return send_file(
            buf,
            mimetype='image/png',
            as_attachment=True,
            download_name='kavach_stego_image.png'
        )

    except Exception as e:
        flash(f"Encoding Error: {str(e)}", 'error')
        return redirect(url_for('index'))

@app.route('/decode', methods=['POST'])
def decode():
    try:
        if 'image' not in request.files or 'password' not in request.form:
            flash('Missing data!', 'error')
            return redirect(url_for('index'))
            
        image_file = request.files['image']
        password = request.form['password']
        
        img = Image.open(image_file)
        
        try:
            raw_data = extract_lsb(img)
            plaintext = decrypt_payload(raw_data, password)
            return render_template('index.html', decoded_message=plaintext)
        except InvalidTag:
             # Severe Warning for Tampering/Wrong Password
             severe_warning = "SECURITY ALERT: TAMPERING DETECTED! YOU HAVE BEEN IDENTIFIED. THE INDIAN ARMY IS WATCHING. SERIOUS ACTION WILL BE TAKEN AGAINST YOU."
             return render_template('index.html', error_message=severe_warning)
        except ValueError as ve:
             # LSB extraction might fail if not our image
             return render_template('index.html', error_message=f"ACCESS DENIED: {str(ve)}")
        except Exception as e:
             return render_template('index.html', error_message="ACCESS DENIED: Processing Error")
             
    except Exception as e:
        flash(f"System Error: {str(e)}", 'error')
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)
