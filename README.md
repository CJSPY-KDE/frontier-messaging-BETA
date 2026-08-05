##NOTE: DO NOT USE FOR SENSITIVE DATA AS ITS IN BETA AND IS NOT IDEAL FOR DAILY USAGE
#  Frontier Secure Chat Terminal

> **End-to-End Encrypted (E2EE) Messaging for the Terminal.**  
> *No bloat. No tracking. No cloud dependencies (optional). Just raw, secure communication.*

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![C](https://img.shields.io/badge/C-11-orange)
![Libsodium](https://img.shields.io/badge/Libsodium-1.0.18-green)
![Supabase](https://img.shields.io/badge/Backend-Supabase-purple)

**Frontier** is a lightweight, terminal-based messaging application written in C. It leverages **libsodium** for military-grade encryption and **Supabase** (or any Postgres DB) for storage. Unlike modern messengers, Frontier is designed for transparency, speed, and user sovereignty.

---

##  Features

- ** End-to-End Encryption:** Messages are encrypted on your device using X25519/XSalsa20/Poly1305 before they ever touch the network. The server sees only gibberish.
- ** Password-Based Key Derivation:** Your private key is encrypted on disk using `crypto_pwhash` (Argon2id) with sensitive parameters to resist brute-force attacks.
- ** Terminal Native:** Zero GUI dependencies. Runs on Linux, macOS, and WSL. Perfect for remote servers and SSH sessions.
- ** Self-Hostable Backend:** Uses Supabase (PostgreSQL) as the transport layer. You can self-host the database for total data sovereignty.
-  Minimal Metadata:** No contact syncing, no location tracking, no background processes. You type the ID, you send the message.

---

##  Prerequisites

Before building, ensure you have the following installed:

- **Compiler:** `gcc` or `clang`
- **Libraries:**
  - `libsodium` (Encryption)
  - `libcurl` (Networking)
  - `libcjson` (JSON Parsing)

### Installation on Arch Linux / Manjaro
sudo pacman -S gcc libsodium curl cjson

##Installation on Debian/Ubuntu
sudo apt update
sduo apt install build-essential libsodium-dev libcurl4-openssl-dev libcjson-dev

##Installation on MacOS
brew install gcc libsodium curl cjson

#build and compiling
git clone https://github.com/CJSPY-KDE/frontier-messaging-BETA.git
cd frontier-messaging-BETA
gcc -o frontiermessaging frontiermessaging.c -lcurl -lsodium -lcjson -lpthread -lm
export SUPABASE_URL="https://avxhbalzbppwofvssfnz.supabase.co"
export SUPABASE_KEY="sb_publishable_DBLlN-ZAUnrEr3izbUxcuw_LGUTUXZf"
./frontiermessaging


