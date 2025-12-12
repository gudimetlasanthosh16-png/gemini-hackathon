# 🛡️ PROJECT KAVACH: Secure Steganographic Communication System (SSCS)

> **"Concealment is the first line of defense."**

**Project Kavach** is a military-grade secure communication tool designed for the **Indian Defence Cipher Command**. It combines robust **AES-256-GCM encryption** with **LSB (Least Significant Bit) Steganography** to hide mission-critical intelligence inside harmless image files, ensuring that the existence of the message itself remains undetectable.

---

## 🚀 Key Features

### 🔒 Layer 1: Advanced Cryptography
*   **Algorithm**: AES-256-GCM (Galois/Counter Mode).
*   **Key Derivation**: PBKDF2-HMAC-SHA256 (300,000 Iterations) to prevent rainbow table attacks.
*   **Integrity Check**: Verifies message authenticity using the GCM Auth Tag. If a password is wrong or the image is tampered with, the system outputs: **"ACCESS DENIED"**.

### 🖼️ Layer 2: Visual Stealth (Steganography)
*   **Technique**: Reverse-Order LSB Embedding.
*   **Stealth**: Data is hidden in the least significant bits of the image pixels, making the "Stego-Image" visually identical to the original cover image.
*   **Format Support**: Works with **PNG** (lossless) images to ensure data integrity.

### ⚔️ Tactical Interface
*   **Theme**: Indian Military / Cyber-Warfare Aesthetic.
*   **UI Features**: Dark mode, scanlines, camouflage accents, and tactical data entry points.
*   **User Experience**: Simple "Uplink" (Send) and "Downlink" (Receive) workflow.

---

## 🛠️ Installation & Setup

### Prerequisites
*   Python 3.8+
*   Pip

### 1. Clone the Repository
```bash
git clone https://github.com/gudimetlasanthosh16-png/gemini-hackathon.git
cd gemini-hackathon
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the System
```bash
python app.py
```
*   The system will go online at: `http://127.0.0.1:5000`

---

## 📖 Usage Guide

### 📤 Phase 1: UPLINK (Sender)
1.  Navigate to the **UPLINK (SENDER)** tab.
2.  **Select Target File**: Upload a clean PNG or JPG image.
3.  **Classified Intelligence**: Type the secret message you wish to hide.
4.  **Authorization Code**: Set a strong password for encryption.
5.  Click **INITIATE ENCRYPTION PROTOCOL**.
6.  The system will download a file named `kavach_stego_image.png`. **This image contains your hidden secret.**

### 📥 Phase 2: DOWNLINK (Receiver)
1.  Navigate to the **DOWNLINK (RECEIVER)** tab.
2.  **Load Intercepted Ping**: Upload the `kavach_stego_image.png`.
3.  **Decryption Key**: Enter the password used during encryption.
4.  Click **EXECUTE DECRYPTION**.
5.  **Success**: The secret message is revealed.
6.  **Failure**: If the password is wrong or the file is corrupted, the system shows a **SECURITY BREACH** alert.

---

## 🛡️ Technical Stack
*   **Backend**: Python (Flask)
*   **Crypto Engine**: `cryptography` library (Standardized AES/PBKDF2)
*   **Image Processing**: `Pillow` (PIL) & `NumPy`
*   **Frontend**: HTML5, Modern CSS3 (Glassmorphism + Military Theme), JavaScript

---

## ⚠️ Disclaimer
This project is for educational and hackathon purposes only. It is a demonstration of cryptographic and steganographic principles.

---

**JAI HIND | SATYAMEVA JAYATE**
