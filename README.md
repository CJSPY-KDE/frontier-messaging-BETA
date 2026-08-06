
#!/bin/bash

# Script to update the README.md for Frontier Secure Chat Terminal
# This script creates a new README.md with updated documentation

cat > README.md << 'EOF'
# Frontier Secure Chat Terminal

> **End-to-End Encrypted (E2EE) Messaging for the Terminal.**  
> *No bloat. No tracking. No cloud dependencies (optional). Just raw, secure communication.*

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![C](https://img.shields.io/badge/C-11-orange)
![Libsodium](https://img.shields.io/badge/Libsodium-1.0.18-green)
![Backend](https://img.shields.io/badge/Backend-RestAPI-orange)

**Frontier** is a lightweight, terminal-based messaging application written in C. It leverages **libsodium** for military-grade encryption and a custom REST API bridge for storage. Unlike modern messengers, Frontier is designed for transparency, speed, and user sovereignty.

> **⚠️ BETA WARNING:** Do not use for highly sensitive data. This project is in beta and is not ideal for daily production usage.

---

## 🚀 Features

- **End-to-End Encryption:** Messages are encrypted on your device using **X25519/XSalsa20/Poly1305** before they ever touch the network. The server sees only gibberish.
- **Password-Based Key Derivation:** Your private key is encrypted on disk using `crypto_pwhash` (Argon2id) with moderate limits to resist brute-force attacks.
- **Terminal Native:** Zero GUI dependencies. Runs on Linux, macOS, and WSL. Perfect for remote servers and SSH sessions.
- **Local Key Storage:** Private keys never leave your device unencrypted. They are stored locally in `~/.securechat/` and decrypted only with your password.
- **Minimal Metadata:** No contact syncing, no location tracking, no background processes. You type the ID, you send the message.
- **Message Moderation:** Built-in basic URL filtering to prevent accidental link sharing.
- **Unique User IDs:** Generates a cryptographically random suffix for usernames to prevent collisions (e.g., `username_a1b2c3...`).

---

## 📋 Prerequisites

Before building, ensure you have the following installed:

- **Compiler:** `gcc` or `clang`
- **Libraries:**
  - `libsodium` (Encryption)
  - `libcurl` (Networking)
  - `libcjson` (JSON Parsing)

### Installation on Arch Linux / Manjaro

sudo pacman -S gcc libsodium curl cjson



#Debian/ubuntu

sudo apt update

sudo apt install build-essential libsodium-dev libcurl4-openssl-dev libcjson-dev


##MacOS

brew install gcc libsodium curl cjson


##Build
git clone https://github.com/CJSPY-KDE/frontier-messaging-BETA.git

cd frontier-messaging-BETA

gcc -o frontiermessaging frontiermessaging.c -lcurl -lsodium -lcjson -lpthread -lm

./frontiermessaging

Usage Guide
1. Register
Select 1. Register Account.
Enter a username (min 3 chars) and a strong password (min 8 chars).
Add a bio and interests (optional).
Important: Your password is the only way to decrypt your private key. If you lose it, your account is unrecoverable.
2. Login
Select 2. Login.
Enter your username and password.
The app will fetch your public key from the server and decrypt your local private key.
3. Add a Friend
Select 4. Add Friend.
Enter the friend's Username or their Unique ID (e.g., alice_x9f2...).
The system fetches their public key and adds them to your local list.
4. Send Messages
Select 2. Send Message.
Choose a friend from the list.
Type your message.
Note: URLs (http, https, www, .com, etc.) are blocked by default moderation.
5. View Chat History
Select 3. View Chat History.
Choose a friend to see their last 20 messages, decrypted locally.

Known Limitations
No Message History Sync: If you delete ~/.securechat/secret_key.enc, you lose access to your account. The server does not store your private key.
Beta Status: The backend bridge is a demo service. Do not rely on it for critical communication.
Moderation: Basic URL filtering is enabled on the client side.
Platform: Primarily tested on Linux and macOS. Windows WSL is supported; native Windows requires additional configuration for terminal handling.


