# Text-Image-encryption-tool
🔐 Cybersecurity Encryption Toolkit
A Python-based Text & Image Encryption Tool with a modern cybersecurity-themed dark terminal UI built using Tkinter.
This project supports AES-based text encryption (via the cryptography library) and pixel shuffling-based image encryption with visual previews before and after encryption/decryption.

📌 Features
User-Friendly Dashboard – Select Text or Image Encryption from a welcome screen.

Text Encryption/Decryption – AES encryption using password-derived keys (Secure SHA-256 → Fernet).

Image Encryption/Decryption – Pixel shuffling with a numeric key (acts like a password).

Image Previews – See the uploaded/encrypted image and decrypted image side-by-side.

Clear & Copy Buttons – Instantly clear inputs or copy encrypted text to clipboard.

Cybersecurity Themed UI – Dark mode, neon green/cyan accents, monospaced fonts for hacker-tool aesthetic.

🛠 Tech Stack
Python 3.x

Tkinter – GUI framework

Pillow (PIL) – Image handling and thumbnail previews

cryptography – AES text encryption via Fernet

random library – For pixel shuffling in image encryption

📥 Installation
Clone the repository:

bash
git clone https://github.com/yourusername/cybersecurity-encryption-toolkit.git
cd cybersecurity-encryption-toolkit
Install required dependencies:

bash
pip install pillow cryptography
Run the project:

bash
python encryption_toolkit.py

🚀 Usage
Launch the program – The welcome screen appears with two buttons: Text Encryption and Image Encryption.

Text Encryption Mode:

Enter plain text or an encrypted string to decrypt.

Enter a password.

Click Encrypt or Decrypt.

Use Clear to reset or Copy to copy the output.

Image Encryption Mode:

Enter a Numeric Key (integer).

Click Encrypt and choose an image file, then save the encrypted image.

Click Decrypt with the same numeric key to get the original image back.

Previews of the uploaded/encrypted and decrypted images will be shown.

🔑 How It Works
Text Encryption
Uses password-based key derivation (SHA-256) to produce a 32-byte key for AES (via Fernet).

Provides strong encryption that can only be reversed with the same password.

Image Encryption
Converts image pixel data to an array.

Uses a numeric key as the seed for Python's random.shuffle() to rearrange pixels.

Re-shuffling with the same key restores the original image.

⚠ Note: Pixel shuffling is not as strong as AES but is fast and useful for demonstration purposes. For production-level security, use AES or other strong encryption algorithms for image data.

📌 Future Improvements
AES-based image encryption for stronger security.

Drag-and-drop support.

Export encryption keys securely.

Add more themes and customization options.

📜 License
This project is licensed under the MIT License. Feel free to modify and share.
