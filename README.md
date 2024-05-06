# File Encryptor/Decryptor

## Overview

This Python script implements a simple file encryptor/decryptor GUI application using the Tkinter library for the user interface and the Crypto library for encryption and decryption functionalities. The application allows users to select a file, choose an encryption algorithm (AES-256, 3DES, or RSA), enter a password, and then encrypt or decrypt the selected file based on the chosen algorithm.

## Features

- **User Interface:** The GUI provides a user-friendly interface with options to select a file, choose an encryption algorithm, enter a password, and perform encryption or decryption operations.
  
- **Encryption Algorithms:**
  - AES-256 (Advanced Encryption Standard with a 256-bit key size)
  - 3DES (Triple Data Encryption Standard)
  - RSA (Rivest-Shamir-Adleman encryption algorithm)

- **File Selection:**
  - Users can browse and select the file they want to encrypt or decrypt using the "Browse" button.
  - After selecting a file, its path is displayed in the UI.

- **Password Input:**
  - Users must enter a password for encryption or decryption. For RSA encryption, the password is used to derive a session key.

- **Encryption/Decryption Operations:**
  - The application encrypts or decrypts files based on the selected algorithm.
  - For AES-256 and 3DES, the script uses Cipher Block Chaining (CBC) mode for encryption and decryption.
  - For RSA, the script generates a new RSA key pair for each encryption operation.

- **Output File Selection:**
  - After encryption or decryption, users can choose the location and filename for the output file. The default extensions are ".enc" for encrypted files and ".dec" for decrypted files.

- **Information Display:**
  - The application displays information about the encryption or decryption process, including the selected file, algorithm, memory usage, time taken, and status (success or failure).
  - The information is displayed in a text workspace within the GUI.

## Dependencies

- Python 3.x
- Tkinter library (for GUI)
- Crypto library (for encryption and decryption)
- psutil library (for memory usage tracking)

## Installation and Usage

1. Clone the repository or download the Python script.
2. Install the required libraries (`tkinter`, `Crypto`, `psutil`) if they are not already installed.
   3. Run the script (`file_encrypt_decrypt.py`).
4. The GUI application will open.
5. Select a file, choose an encryption algorithm, enter a password, and click the "Encrypt File" or "Decrypt File" button as needed.
6. After the operation is completed, the output file will be saved based on the chosen algorithm and the user-selected location.

## Acknowledgments

- The Crypto library for providing encryption and decryption functionalities.
- Tkinter library for the GUI interface.
- psutil library for memory usage tracking.

## ScreenShots
