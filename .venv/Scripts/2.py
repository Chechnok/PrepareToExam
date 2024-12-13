import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import tkinter as tk
from tkinter import filedialog


# Generate a random 32-byte key and a 12-byte IV (initialization vector)
key = os.urandom(32)  # AES-256 requires a 32-byte key
iv = os.urandom(12)   # GCM mode typically uses a 12-byte IV

# File paths
input_file = "input.txt"
output_file = "ciphertext.bin"


# Create a file selection window
root = tk.Tk()
root.withdraw()  # Hide the root window
input_file = filedialog.askopenfilename(title="Select Input File", filetypes=[("Text Files", "*.txt")])

# Read plaintext from input file
with open(input_file, "r", encoding="utf-8") as f:
    plaintext = f.read().encode()  # Convert text to bytes

# Initialize the AES-GCM cipher
cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
encryptor = cipher.encryptor()

# Encrypt the plaintext
ciphertext = encryptor.update(plaintext) + encryptor.finalize()

# Authentication tag
tag = encryptor.tag

# Write the ciphertext to a binary file
with open(output_file, "wb") as f:
    f.write(ciphertext)

# Output the authentication tag
print("Authentication Tag:", tag.hex())
