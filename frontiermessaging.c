#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <curl/curl.h>
#include <sodium.h>
#include <cjson/cJSON.h>
#include <stdarg.h>

// ============================================================================
// CONFIGURATION & CONSTANTS
// ============================================================================
#define MAX_USERNAME 32
#define MAX_PASSWORD 64
#define MAX_BIO 256
#define MAX_INTERESTS 128
#define MAX_MESSAGE 512
#define UNIQUE_SUFFIX_LEN 16
#define MAX_MESSAGE_HEX_LEN 2048
#define SAFE_DIR_PERMS 0700
#define SAFE_FILE_PERMS 0600
#define MAX_FRIENDS 100
#define MESSAGE_TTL_SECONDS 7200

const char* BRIDGE_URL_DEFAULT = "https://frontier-bridge.onrender.com";
const char* BRIDGE_URL = NULL;

int current_user_id = -1;
char current_username[MAX_USERNAME];
char unique_user_id[64];
char current_user_uuid[64];
int friends_count = 0;
int keys_loaded = 0;

unsigned char my_public_key[crypto_box_PUBLICKEYBYTES];
unsigned char my_secret_key[crypto_box_SECRETKEYBYTES];

typedef struct {
    int user_id;
    char username[MAX_USERNAME];
    char unique_id[64];
    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
} Friend;

Friend friends_list[MAX_FRIENDS];

// ============================================================================
// INPUT HANDLING & UTILS
// ============================================================================

void clear_input_buffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

void trim_whitespace(char* str) {
    if (!str) return;
    char* start = str;
    while (*start == ' ' || *start == '\t' || *start == '\n' || *start == '\r') start++;
    if (*start == '\0') { str[0] = '\0'; return; }
    char* end = start + strlen(start) - 1;
    while (end > start && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) end--;
    *(end + 1) = '\0';
    if (start != str) memmove(str, start, strlen(start) + 1);
}

void ensure_app_dir() {
    const char* home = getenv("HOME");
    if (!home) { fprintf(stderr, "[!] ERROR: HOME environment variable not set.\n"); exit(1); }
    char dir[256];
    snprintf(dir, sizeof(dir), "%s/.securechat", home);
    if (mkdir(dir, SAFE_DIR_PERMS) != 0 && errno != EEXIST) {
        fprintf(stderr, "[!] ERROR: Could not create app directory.\n"); exit(1);
    }
}

int load_env_vars() {
    const char* env_url = getenv("FRONTIER_BRIDGE_URL");
    if (env_url) {
        BRIDGE_URL = env_url;
    } else {
        BRIDGE_URL = BRIDGE_URL_DEFAULT;
    }
    return 1;
}

// ============================================================================
// CRYPTO & KEY MANAGEMENT
// ============================================================================

int generate_user_keys() {
    if (crypto_box_keypair(my_public_key, my_secret_key) != 0) {
        fprintf(stderr, "[!] CRITICAL: Failed to generate keypair.\n"); return 0;
    }
    return 1;
}

int generate_unique_id(const char* username, char* out) {
    char suffix[UNIQUE_SUFFIX_LEN * 2 + 1];
    unsigned char rand_bytes[UNIQUE_SUFFIX_LEN];
    randombytes_buf(rand_bytes, UNIQUE_SUFFIX_LEN);
    for (int i = 0; i < UNIQUE_SUFFIX_LEN; i++) snprintf(suffix + (i * 2), 3, "%02x", rand_bytes[i]);
    snprintf(out, 64, "%s_%s", username, suffix);
    return 1;
}

int save_secret_key_locally(const char* password) {
    const char* home = getenv("HOME");
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/.securechat/secret_key.enc", home);
    FILE* f = fopen(filepath, "wb");
    if (!f) { perror("[!] ERROR: Could not open file for writing"); return 0; }

    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof(salt));
    unsigned char derived_key[crypto_secretbox_KEYBYTES];

    if (crypto_pwhash(derived_key, crypto_secretbox_KEYBYTES, password, strlen(password), salt,
        crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_ALG_DEFAULT) != 0) {
        fclose(f); fprintf(stderr, "[!] CRITICAL: Key derivation failed.\n"); return 0;
        }

        unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));
    size_t ct_size = crypto_box_SECRETKEYBYTES + crypto_secretbox_MACBYTES;
    unsigned char* ciphertext = malloc(ct_size);
    if (!ciphertext) { fclose(f); return 0; }

    if (crypto_secretbox_easy(ciphertext, my_secret_key, crypto_box_SECRETKEYBYTES, nonce, derived_key) != 0) {
        free(ciphertext); fclose(f); return 0;
    }

    fwrite(salt, 1, sizeof(salt), f);
    fwrite(nonce, 1, sizeof(nonce), f);
    fwrite(ciphertext, 1, ct_size, f);
    fclose(f);
    chmod(filepath, SAFE_FILE_PERMS);

    sodium_memzero(derived_key, sizeof(derived_key));
    sodium_memzero(ciphertext, ct_size);
    free(ciphertext);
    return 1;
}

int load_secret_key_locally(const char* password) {
    const char* home = getenv("HOME");
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/.securechat/secret_key.enc", home);
    FILE* f = fopen(filepath, "rb");
    if (!f) return 0;

    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    size_t ct_size = crypto_box_SECRETKEYBYTES + crypto_secretbox_MACBYTES;
    unsigned char* ciphertext = malloc(ct_size);
    if (!ciphertext) { fclose(f); return 0; }

    if (fread(salt, 1, sizeof(salt), f) != sizeof(salt)) { free(ciphertext); fclose(f); return 0; }
    if (fread(nonce, 1, sizeof(nonce), f) != sizeof(nonce)) { free(ciphertext); fclose(f); return 0; }
    if (fread(ciphertext, 1, ct_size, f) != ct_size) { free(ciphertext); fclose(f); return 0; }
    fclose(f);

    unsigned char derived_key[crypto_secretbox_KEYBYTES];
    if (crypto_pwhash(derived_key, crypto_secretbox_KEYBYTES, password, strlen(password), salt,
        crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_ALG_DEFAULT) != 0) {
        free(ciphertext); return 0;
        }

        if (crypto_secretbox_open_easy(my_secret_key, ciphertext, ct_size, nonce, derived_key) != 0) {
            sodium_memzero(derived_key, sizeof(derived_key)); free(ciphertext); return 0;
        }

        sodium_memzero(derived_key, sizeof(derived_key));
    free(ciphertext);
    keys_loaded = 1;
    return 1;
}

void free_keys() {
    if (!keys_loaded) return;
    sodium_memzero(my_public_key, sizeof(my_public_key));
    sodium_memzero(my_secret_key, sizeof(my_secret_key));
    keys_loaded = 0;
}

// ============================================================================
// NETWORK & CURL HELPERS
// ============================================================================

struct MemoryStruct {
    char* response;
    size_t size;
};

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct* mem = (struct MemoryStruct*)userp;
    char* ptr = realloc(mem->response, mem->size + realsize + 1);
    if (!ptr) { free(mem->response); mem->response = NULL; return 0; }
    mem->response = ptr;
    memcpy(&(mem->response[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->response[mem->size] = '\0';
    return realsize;
}

// ============================================================================
// ENCRYPTION HELPERS
// ============================================================================

void encrypt_message(const char* content, const unsigned char* recipient_pub, char* out_hex) {
    unsigned char nonce[crypto_box_NONCEBYTES];
    size_t ct_size = strlen(content) + crypto_box_MACBYTES;
    unsigned char* ciphertext = malloc(ct_size);
    if (!ciphertext) { out_hex[0] = '\0'; return; }
    randombytes_buf(nonce, sizeof(nonce));
    if (crypto_box_easy(ciphertext, (const unsigned char*)content, strlen(content), nonce, recipient_pub, my_secret_key) != 0) {
        fprintf(stderr, "[!] Encryption failed.\n"); free(ciphertext); out_hex[0] = '\0'; return;
    }
    size_t total_len = sizeof(nonce) + ct_size;
    unsigned char* full_data = malloc(total_len);
    if (!full_data) { free(ciphertext); out_hex[0] = '\0'; return; }
    memcpy(full_data, nonce, sizeof(nonce));
    memcpy(full_data + sizeof(nonce), ciphertext, ct_size);
    for (size_t i = 0; i < total_len; i++) snprintf(out_hex + (i * 2), 3, "%02x", full_data[i]);
    free(ciphertext); free(full_data);
    sodium_memzero(ciphertext, ct_size); sodium_memzero(full_data, total_len);
}

int decrypt_message(const char* hex, const unsigned char* sender_pub, char* out, size_t out_size) {
    size_t hex_len = strlen(hex);
    if (hex_len < (crypto_box_NONCEBYTES * 2)) return 0;

    size_t data_len = hex_len / 2;
    unsigned char* full_data = malloc(data_len);
    if (!full_data) return 0;

    for (size_t i = 0; i < hex_len; i += 2) {
        unsigned char byte;
        if (sscanf(hex + i, "%2hhx", &byte) != 1) {
            free(full_data);
            return 0;
        }
        full_data[i / 2] = byte;
    }

    size_t nonce_len = crypto_box_NONCEBYTES;
    if (data_len <= nonce_len) {
        free(full_data);
        return 0;
    }

    unsigned char nonce[crypto_box_NONCEBYTES];
    memcpy(nonce, full_data, nonce_len);

    size_t ct_len = data_len - nonce_len;
    unsigned char* ciphertext = full_data + nonce_len;

    if (ct_len >= out_size) {
        free(full_data);
        return 0;
    }

    int ret = crypto_box_open_easy((unsigned char*)out, ciphertext, ct_len, nonce, sender_pub, my_secret_key);
    free(full_data);

    if (ret != 0) return 0;
    out[ct_len] = '\0';
    return 1;
}

// ============================================================================
// FRIENDS & MESSAGES
// ============================================================================

void add_friend_to_local(const char* unique_id, const char* username, const unsigned char* public_key, int user_id) {
    if (friends_count >= MAX_FRIENDS) { printf("[!] Friend list full.\n"); return; }

    friends_list[friends_count].user_id = user_id;
    snprintf(friends_list[friends_count].unique_id, 64, "%s", unique_id);
    snprintf(friends_list[friends_count].username, MAX_USERNAME, "%s", username);
    memcpy(friends_list[friends_count].public_key, public_key, crypto_box_PUBLICKEYBYTES);

    friends_count++;
    printf("[+] Friend '%s' added.\n", unique_id);
}

int fetch_public_key_by_target(const char* target, char* pub_key_hex_out, char* username_out, int* user_id_out) {
    char url[1024];
    snprintf(url, sizeof(url), "%s/get-key/%s", BRIDGE_URL, target);

    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    struct MemoryStruct chunk;
    chunk.response = malloc(1);
    chunk.size = 0;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    CURLcode res = curl_easy_perform(curl);
    int success = (res == CURLE_OK && chunk.size > 0);

    if (success) {
        cJSON *json_obj = cJSON_Parse(chunk.response);
        if (json_obj && cJSON_IsObject(json_obj)) {
            cJSON *key_item = cJSON_GetObjectItem(json_obj, "public_key");
            cJSON *name_item = cJSON_GetObjectItem(json_obj, "username");
            cJSON *id_item = cJSON_GetObjectItem(json_obj, "id");

            if (cJSON_IsString(key_item) && cJSON_IsString(name_item) && cJSON_IsNumber(id_item)) {
                size_t hex_len = strlen(key_item->valuestring);
                unsigned char pub_key[crypto_box_PUBLICKEYBYTES];
                if (hex_len != crypto_box_PUBLICKEYBYTES * 2) {
                    success = 0;
                } else {
                    for (size_t i = 0; i < crypto_box_PUBLICKEYBYTES; i++) {
                        sscanf(key_item->valuestring + (i * 2), "%2hhx", &pub_key[i]);
                    }
                    strncpy(pub_key_hex_out, key_item->valuestring, crypto_box_PUBLICKEYBYTES * 2);
                    pub_key_hex_out[crypto_box_PUBLICKEYBYTES * 2] = '\0';
                    strncpy(username_out, name_item->valuestring, MAX_USERNAME - 1);
                    username_out[MAX_USERNAME - 1] = '\0';
                    *user_id_out = id_item->valueint;
                    success = 1;
                }
            } else {
                success = 0;
            }
            cJSON_Delete(json_obj);
        } else {
            success = 0;
        }
    }

    if (chunk.response) free(chunk.response);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return success;
}

int fetch_messages(int friend_user_id, cJSON** json_out) {
    char url[1024];
    snprintf(url, sizeof(url), "%s/inbox/%d", BRIDGE_URL, current_user_id);

    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    struct MemoryStruct chunk;
    chunk.response = malloc(1);
    chunk.size = 0;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    CURLcode res = curl_easy_perform(curl);
    int success = (res == CURLE_OK && chunk.size > 0);

    if (success) {
        cJSON *json_obj = cJSON_Parse(chunk.response);
        if (json_obj && cJSON_IsObject(json_obj)) {
            cJSON *msgs = cJSON_GetObjectItem(json_obj, "messages");
            if (cJSON_IsArray(msgs)) {
                *json_out = json_obj;
                success = 1;
            } else {
                cJSON_Delete(json_obj);
                success = 0;
            }
        } else {
            cJSON_Delete(json_obj);
            success = 0;
        }
    }

    if (chunk.response) free(chunk.response);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return success;
}

// ============================================================================
// MODERATION & MESSAGE SENDING
// ============================================================================

int contains_url(const char* text) {
    if (!text) return 0;
    if (strstr(text, "http://") || strstr(text, "https://") || strstr(text, "ftp://")) return 1;
        if (strstr(text, "www.")) return 1;
        if (strstr(text, ".com") || strstr(text, ".org") || strstr(text, ".net") ||
            strstr(text, ".io") || strstr(text, ".edu") || strstr(text, ".gov")) return 1;
    return 0;
}

int send_message(int recipient_user_id, const char* content) {
    if (!content || strlen(content) == 0) {
        printf("[!] Empty message.\n");
        return 0;
    }

    if (contains_url(content)) {
        printf("[!] MODERATION: Sending links (http, https, www, .com, etc.) is not allowed.\n");
        return 0;
    }

    unsigned char recipient_pub[crypto_box_PUBLICKEYBYTES];
    int found = 0;
    for (int i = 0; i < friends_count; i++) {
        if (friends_list[i].user_id == recipient_user_id) {
            memcpy(recipient_pub, friends_list[i].public_key, crypto_box_PUBLICKEYBYTES);
            found = 1;
            break;
        }
    }
    if (!found) {
        printf("[!] Friend not found in local list.\n");
        return 0;
    }

    char encrypted_hex[MAX_MESSAGE_HEX_LEN];
    encrypt_message(content, recipient_pub, encrypted_hex);
    if (strlen(encrypted_hex) == 0) {
        printf("[!] Encryption failed.\n");
        return 0;
    }

    time_t now = time(NULL);
    char timestamp[32];
    snprintf(timestamp, sizeof(timestamp), "%ld", now);

    cJSON *root = cJSON_CreateObject();
    if (!root) return 0;
    cJSON_AddNumberToObject(root, "sender_id", current_user_id);
    cJSON_AddNumberToObject(root, "recipient_id", recipient_user_id);
    cJSON_AddStringToObject(root, "content", encrypted_hex);
    cJSON_AddStringToObject(root, "timestamp", timestamp);

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json_str) return 0;

    char url[1024];
    snprintf(url, sizeof(url), "%s/send", BRIDGE_URL);

    CURL *curl = curl_easy_init();
    if (!curl) { free(json_str); return 0; }

    struct MemoryStruct chunk;
    chunk.response = malloc(1);
    chunk.size = 0;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    CURLcode res = curl_easy_perform(curl);
    int success = (res == CURLE_OK && chunk.size > 0);

    if (success) {
        cJSON *json_obj = cJSON_Parse(chunk.response);
        if (json_obj && cJSON_IsObject(json_obj)) {
            cJSON *err = cJSON_GetObjectItem(json_obj, "error");
            if (err) {
                printf("[!] Server Error: %s\n", err->valuestring);
                success = 0;
            } else {
                printf("[+] Message sent successfully.\n");
            }
            cJSON_Delete(json_obj);
        } else {
            printf("[!] Invalid response from server.\n");
            success = 0;
        }
    } else {
        printf("[!] Network error: %s\n", curl_easy_strerror(res));
        success = 0;
    }

    if (chunk.response) free(chunk.response);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    free(json_str);

    return success;
}

// ============================================================================
// UI HELPERS
// ============================================================================

void clear_screen() {
    printf("\033[2J\033[H");
    fflush(stdout);
}

void print_logo() {
    printf("\n");
    printf("    ____   ____   ____   _   _   _____   _   ____   ____ \n");
    printf("   |___   |__/   |  |   |\\  |     |     |   |___   |__/  \n");
    printf("   |      |  \\   |__|   | \\ |     |     |   |___   |  \\  \n");
    printf("\n");
    printf("    Frontier Messaging (Terminal)\n\n");
    fflush(stdout);
}

void print_header(const char* title) {
    printf("╔════════════════════════════════════════════════════════╗\n");
    printf("║  %-54s ║\n", title);
    printf("╚════════════════════════════════════════════════════════╝\n");
    fflush(stdout);
}

void print_box_line(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char buf[60];
    vsnprintf(buf, sizeof(buf), fmt, args);
    printf("║  %-54s ║\n", buf);
    va_end(args);
    fflush(stdout);
}

void print_box_empty() {
    printf("╚════════════════════════════════════════════════════════╝\n");
    fflush(stdout);
}

void pause_and_clear() {
    printf("Press Enter to continue...");
    fflush(stdout);
    char dummy[10];
    if (fgets(dummy, sizeof(dummy), stdin) == NULL) {}
    clear_input_buffer();
    clear_screen();
}

void show_friends_list() {
    if (friends_count == 0) {
        print_box_line("No friends yet.");
        return;
    }
    for (int i = 0; i < friends_count; i++) {
        char line[60];
        snprintf(line, sizeof(line), "%d. %s (%s)", i + 1, friends_list[i].username, friends_list[i].unique_id);
        print_box_line("%s", line);
    }
}

void show_chat(int index) {
    if (index < 0 || index >= friends_count) {
        printf("[!] Invalid index.\n");
        return;
    }
    Friend *friend = &friends_list[index];

    print_header("Chat with: ");
    printf("║  %-54s ║\n", friend->username);
    printf("║  Unique ID: %s                                 ║\n", friend->unique_id);
    printf("╚════════════════════════════════════════════════════════╝\n\n");
    fflush(stdout);

    cJSON *root = NULL;
    if (!fetch_messages(friend->user_id, &root)) {
        printf("No messages found or failed to fetch.\n");
        return;
    }

    cJSON *msgs = cJSON_GetObjectItem(root, "messages");
    if (!cJSON_IsArray(msgs)) {
        printf("Invalid message format.\n");
        cJSON_Delete(root);
        return;
    }

    cJSON *item;
    int count = 0;
    cJSON_ArrayForEach(item, msgs) {
        if (count >= 20) break;
        cJSON *content_json = cJSON_GetObjectItem(item, "content");
        cJSON *ts_json = cJSON_GetObjectItem(item, "timestamp");
        cJSON *sender_json = cJSON_GetObjectItem(item, "sender_id");

        if (cJSON_IsString(content_json) && cJSON_IsString(ts_json) && cJSON_IsNumber(sender_json)) {
            if (sender_json->valueint == friend->user_id) {
                char decrypted[MAX_MESSAGE];
                if (decrypt_message(content_json->valuestring, friend->public_key, decrypted, sizeof(decrypted))) {
                    printf("    > %s (Sent: %s)\n", decrypted, ts_json->valuestring);
                } else {
                    printf("    > [Decryption Failed]\n");
                }
            }
        }
        count++;
    }

    cJSON_Delete(root);
    printf("\n> ");
    fflush(stdout);
}

int read_password(char* buffer, size_t size) {
    if (size == 0 || !buffer) return 0;
    printf("Password: ");
    fflush(stdout);

    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    int i = 0;
    int c;
    while (i < (int)size - 1) {
        c = getchar();
        if (c == EOF) { i = 0; break; }
        if (c == '\n' || c == '\r') break;
        if (c == 127 || c == '\b') {
            if (i > 0) { i--; printf("\b \b"); fflush(stdout); }
        } else if (c >= 32) {
            buffer[i++] = (char)c;
            printf("*");
            fflush(stdout);
        }
    }
    buffer[i] = '\0';

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");
    fflush(stdout);
    return i > 0 ? 1 : 0;
}

// ============================================================================
// REGISTRATION & LOGIN
// ============================================================================

int register_user() {
    char u[MAX_USERNAME], p[MAX_PASSWORD], b[MAX_BIO], i[MAX_INTERESTS];

    printf("Username: ");
    fflush(stdout);
    if (!fgets(u, sizeof(u), stdin)) return 0;
    trim_whitespace(u);
    if (strlen(u) < 3) { printf("[!] Username too short (min 3 chars).\n"); return 0; }

    if (read_password(p, MAX_PASSWORD) == 0) { printf("[!] Password read failed.\n"); return 0; }
    if (strlen(p) < 8) { printf("[!] Password must be at least 8 characters.\n"); return 0; }

    printf("Bio: "); fflush(stdout);
    if (!fgets(b, sizeof(b), stdin)) return 0;
    trim_whitespace(b);

    printf("Interests: "); fflush(stdout);
    if (!fgets(i, sizeof(i), stdin)) return 0;
    trim_whitespace(i);

    printf("[*] Generating keys...\n");
    if (!generate_user_keys()) return 0;

    if (!generate_unique_id(u, unique_user_id)) return 0;

    char pub_key_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
    for (size_t k = 0; k < crypto_box_PUBLICKEYBYTES; k++) {
        sprintf(pub_key_hex + (k * 2), "%02x", my_public_key[k]);
    }

    printf("[*] Encrypting and saving keys locally...\n");
    if (!save_secret_key_locally(p)) {
        fprintf(stderr, "[!] Failed to save keys locally.\n");
        free_keys();
        return 0;
    }

    printf("\n============================================================\n");
    printf("[SUCCESS] Account created locally! Your password is your only key.\n");
    printf("          DO NOT FORGET YOUR PASSWORD.\n");
    printf("============================================================\n");
    printf("Your Unique ID: %s\n", unique_user_id);
    printf("============================================================\n");

    printf("Press Enter to continue...");
    fflush(stdout);
    char dummy[10];
    if (fgets(dummy, sizeof(dummy), stdin) == NULL) {}
    clear_input_buffer();

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "username", u);
    cJSON_AddStringToObject(root, "unique_id", unique_user_id);
    cJSON_AddStringToObject(root, "bio", b);
    cJSON_AddStringToObject(root, "interests", i);
    cJSON_AddStringToObject(root, "public_key", pub_key_hex);

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json_str) { free_keys(); return 0; }

    char url[1024];
    snprintf(url, sizeof(url), "%s/register", BRIDGE_URL);

    CURL *curl = curl_easy_init();
    if (!curl) { free(json_str); free_keys(); return 0; }

    struct MemoryStruct chunk;
    chunk.response = malloc(1);
    chunk.size = 0;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    CURLcode res = curl_easy_perform(curl);
    int success = (res == CURLE_OK && chunk.size > 0);

    if (success) {
        cJSON *json_obj = cJSON_Parse(chunk.response);
        if (json_obj && cJSON_IsObject(json_obj)) {
            cJSON *err = cJSON_GetObjectItem(json_obj, "error");
            if (err) {
                printf("[!] Registration failed: %s\n", err->valuestring);
                success = 0;
            }
            cJSON_Delete(json_obj);
        }
    } else {
        printf("[!] Network error during registration: %s\n", curl_easy_strerror(res));
        success = 0;
    }

    if (chunk.response) free(chunk.response);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    free(json_str);

    if (!success) {
        free_keys();
        return 0;
    }

    clear_screen();
    return 1;
}

static time_t last_login_attempt = 0;

int login_user() {
    time_t now = time(NULL);
    if (now - last_login_attempt < 5) {
        printf("[!] Too many login attempts. Wait %d seconds.\n", (int)(5 - (now - last_login_attempt)));
        return 0;
    }
    last_login_attempt = now;

    char u[MAX_USERNAME], p[MAX_PASSWORD];
    printf("Username: ");
    fflush(stdout);
    if (!fgets(u, sizeof(u), stdin)) return 0;
    trim_whitespace(u);

    if (read_password(p, MAX_PASSWORD) == 0) return 0;

    const char* home = getenv("HOME");
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/.securechat/secret_key.enc", home);
    FILE* test = fopen(filepath, "rb");
    if (!test) {
        printf("[!] ERROR: Local key file not found.\n");
        printf("    You may be on a new device or the file was deleted.\n");
        printf("    Since keys are not stored on the server, you cannot recover this account.\n");
        printf("    Please register a new account.\n");
        return 0;
    }
    fclose(test);

    if (!load_secret_key_locally(p)) {
        printf("[!] Failed to decrypt secret key.\n");
        printf("    Wrong password? Or corrupted key file.\n");
        return 0;
    }

    char pub_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
    char username_out[MAX_USERNAME];
    if (fetch_public_key_by_target(u, pub_hex, username_out, &current_user_id)) {
        strncpy(current_username, username_out, MAX_USERNAME);
        printf("[+] Welcome back, %s!\n", current_username);
        return 1;
    } else {
        printf("[!] User not found on server.\n");
        free_keys();
        return 0;
    }
}

// ============================================================================
// MAIN MENU LOOP
// ============================================================================

void main_menu_loop() {
    char choice[10];
    int idx, c;
    int running = 1;

    while (running) {
        clear_screen();
        print_header("Main Menu");
        printf("1. View Friends List\n");
        printf("2. Send Message\n");
        printf("3. View Chat History\n");
        printf("4. Add Friend (Enter Username or Unique ID)\n");
        printf("5. Logout\n");
        printf("6. Exit\n\n");
        printf("Option: ");
        fflush(stdout);

        if (!fgets(choice, sizeof(choice), stdin)) break;
        trim_whitespace(choice);
        if (strcmp(choice, "1") == 0) {
            clear_screen();
            print_header("Friends List");
            show_friends_list();
            print_box_empty();
            pause_and_clear();
        }
        else if (strcmp(choice, "2") == 0) {
            if (friends_count == 0) {
                printf("[!] No friends to send to. Add one first.\n");
                pause_and_clear();
                continue;
            }
            printf("Select friend index (1-%d): ", friends_count);
            fflush(stdout);

            if (scanf("%d", &idx) != 1 || idx < 1 || idx > friends_count) {
                printf("[!] Invalid selection.\n");
                clear_input_buffer();
                pause_and_clear();
                continue;
            }
            clear_input_buffer();

            Friend *f = &friends_list[idx - 1];
            char msg[MAX_MESSAGE];
            printf("Message for %s: ", f->username);
            fflush(stdout);

            if (fgets(msg, sizeof(msg), stdin)) {
                trim_whitespace(msg);
                printf("[*] Encrypting and sending...\n");
                if (send_message(f->user_id, msg)) {
                    printf("[+] Message sent!\n");
                } else {
                    printf("[!] Failed to send message.\n");
                }
            }
            pause_and_clear();
        }
        else if (strcmp(choice, "3") == 0) {
            if (friends_count == 0) {
                printf("[!] No friends to view chat with.\n");
                pause_and_clear();
                continue;
            }
            printf("Select friend index (1-%d): ", friends_count);
            fflush(stdout);

            if (scanf("%d", &idx) != 1 || idx < 1 || idx > friends_count) {
                printf("[!] Invalid selection.\n");
                clear_input_buffer();
                pause_and_clear();
                continue;
            }
            clear_input_buffer();

            clear_screen();
            show_chat(idx - 1);
            char dummy[10];
            if (fgets(dummy, sizeof(dummy), stdin) == NULL) {}
            clear_input_buffer();
        }
        else if (strcmp(choice, "4") == 0) {
            char target[64], username_out[MAX_USERNAME], pub_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
            int user_id_out;

            printf("Enter Friend's Username or Unique ID: ");
            fflush(stdout);
            if (!fgets(target, sizeof(target), stdin)) continue;
            trim_whitespace(target);

            printf("[*] Searching for user...\n");
            if (fetch_public_key_by_target(target, pub_hex, username_out, &user_id_out)) {
                printf("[+] Found user: %s\n", username_out);
                unsigned char pub_key[crypto_box_PUBLICKEYBYTES];
                for (size_t i = 0; i < crypto_box_PUBLICKEYBYTES; i++) {
                    sscanf(pub_hex + (i * 2), "%2hhx", &pub_key[i]);
                }
                add_friend_to_local(target, username_out, pub_key, user_id_out);
            } else {
                printf("[!] User not found.\n");
            }
            pause_and_clear();
        }
        else if (strcmp(choice, "5") == 0) {
            clear_screen();
            free_keys();
            current_user_id = -1;
            friends_count = 0;
            printf("[*] Logged out.\n");
            pause_and_clear();
            return;
        }
        else if (strcmp(choice, "6") == 0) {
            running = 0;
        }
        else {
            printf("[!] Invalid option.\n");
            pause_and_clear();
        }
    }
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

int main() {
    // Ensure cursor is visible at start
    printf("\033[?25h");
    fflush(stdout);

    if (sodium_init() < 0) {
        fprintf(stderr, "[!] CRITICAL: Failed to initialize libsodium.\n");
        return 1;
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);

    if (!load_env_vars()) {
        curl_global_cleanup();
        return 1;
    }

    ensure_app_dir();

    char choice[10];
    while (1) {
        if (current_user_id == -1) {
            clear_screen();
            print_logo();
            print_header("Frontier Messaging");
            printf("║  1. Register Account                             ║\n");
            printf("║  2. Login                                        ║\n");
            printf("║  3. Exit                                         ║\n");
            print_box_empty();
            printf("Option: ");
            fflush(stdout);

            if (!fgets(choice, sizeof(choice), stdin)) break;
            trim_whitespace(choice);

            if (strcmp(choice, "1") == 0) {
                if (register_user()) {
                    printf("[+] Account created! Please login.\n");
                    pause_and_clear();
                } else {
                    printf("[!] Registration failed.\n");
                    pause_and_clear();
                }
            } else if (strcmp(choice, "2") == 0) {
                if (login_user()) {
                    main_menu_loop();
                } else {
                    printf("[!] Login failed.\n");
                    pause_and_clear();
                }
            } else if (strcmp(choice, "3") == 0) {
                printf("[*] Exiting...\n");
                break;
            }
        }
    }

    if (keys_loaded) free_keys();
    curl_global_cleanup();
    printf("\033[?25h"); // Ensure cursor is visible on exit
    return 0;
}
