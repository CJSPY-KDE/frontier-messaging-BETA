# Frontier Messaging BETA

A terminal-based ephemeral chat app written in C.
- Messages auto-delete after 2 hours (or immediately after reading).
- Profiles auto-delete after 24 hours of inactivity.
- No email required.
- Open Source.

DEPENDENCIES: 
pacman : sudo pacman -S base-devel sqlite openssl

apt    : sudo apt install build-essential libsqlite3-dev libssl-dev

xcode-select --install

How to get it:
sudo git clone https://github.com/CJSPY-KDE/frontier-messaging-BETA.git
cd frontier-messaging-BETA
gcc frontiermessaging.c -o messenger -lsqlite3 -lssl -lcrypto -lpthread
./messenger


IF YOUR ON WINDOWS YOU NEED: 
MinGW or Visual Studio Build Tools (for the compiler).
SQLite3 and OpenSSL binaries (DLLs/libraries). 


Enjoy this is in beta!


To fully get rid of logs which are on your hard disk there is a delete db button there. DW! this deletes your WHOLE frontier-messaging info. but not real hard drive
ENJOY
