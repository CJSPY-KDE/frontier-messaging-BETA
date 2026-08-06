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
#include <signal.h>
#include <sys/wait.h>
#include <getopt.h>

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
#define MAX_PENDING 50
#define MESSAGE_TTL_SECONDS 7200
#define DEAD_MAN_DAYS 30

// Update this to your Render URL or Supabase REST URL
// If using Supabase directly, use: "https://YOUR_PROJECT.supabase.co/rest/v1"
// If using Render as a proxy, keep your current URL
const char* BRIDGE_URL_DEFAULT = "https://frontier-bridge.onrender.com";
const char* BRIDGE_URL = NULL;

int current_user_id = -1;
char current_username[MAX_USERNAME];
char unique_user_id[64];
char current_user_uuid[64];
int friends_count = 0;
int keys_loaded = 0;
int bonus_enabled = 0;
int auto_login_enabled = 0;
int invisibility_mode = 0;
char invisible_id[65];

unsigned char my_public_key[crypto_box_PUBLICKEYBYTES];
unsigned char my_secret_key[crypto_box_SECRETKEYBYTES];

volatile sig_atomic_t chat_running = 1;

typedef struct {
    int user_id;
    char username[MAX_USERNAME];
    char unique_id[64];
    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
} Friend;

Friend friends_list[MAX_FRIENDS];
int pending_count = 0;

typedef struct {
    int user_id;
    char username[MAX_USERNAME];
    char unique_id[64];
    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
} PendingRequest;

PendingRequest pending_list[MAX_PENDING];

const char* quotes[] = {
    "The quieter you get, the more you hear.",
    "Are you a one or a zero?",
    "Privacy is a right.",
    "Who am I? Good question.",
    "You are now less valuable than the data you produce.",
    "In a world of noise, be the signal.",
    "Encryption is the new normal."
};
const int QUOTE_COUNT = sizeof(quotes) / sizeof(quotes[0]);

// ============================================================================
// FUNCTION PROTOTYPES (Updated)
// ============================================================================

void clear_input_buffer();
void trim_whitespace(char* str);
void ensure_app_dir();
int load_env_vars();
int generate_user_keys();
int generate_unique_id(const char* username, char* out);
void generate_invisible_id(char* out);
int save_secret_key_locally(const char* password);
int load_secret_key_locally(const char* password);
void free_keys();
int fetch_public_key_by_target(const char* target, char* pub_key_hex_out, char* username_out, int* user_id_out);
int fetch_messages(int friend_user_id, cJSON** json_out);
int fetch_pending_requests();
int send_message(int recipient_user_id, const char* content);
void encrypt_message(const char* content, const unsigned char* recipient_pub, char* out_hex);
int decrypt_message(const char* hex, const unsigned char* sender_pub, char* out, size_t out_size);
void add_friend_to_local(const char* unique_id, const char* username, const unsigned char* public_key, int user_id);
void add_pending_request(const char* unique_id, const char* username, const unsigned char* public_key, int user_id);
void show_friends_list();
void show_pending_requests();
void persistent_chat(int friend_index);
int read_password(char* buffer, size_t size);
int register_user();
int login_user();
void main_menu_loop();
void settings_menu();
void bonus_menu();
void handle_sigint(int sig);
void clear_screen();
void print_logo();
void print_header(const char* title);
void print_box_line(const char* fmt, ...);
void print_box_empty();
void pause_and_clear();
int delete_account();
int delete_chat_with_friend(int friend_index);
void enable_bonus_tab();
void toggle_invisibility();
void toggle_auto_login();
void ip_geolocation();
void check_message_seen(int friend_index);
void run_update();
void show_random_quote();

// [NEW] Feature Prototypes
void print_key_fingerprint(const unsigned char* public_key);
void panic_wipe(void);
void handle_panic(int sig);
void check_dead_man_switch(void);
void update_last_login(void);
void handle_pipe_mode(int argc, char* argv[]);

// ============================================================================
// SIGNAL HANDLERS
// ============================================================================

void handle_sigint(int sig) {
    chat_running = 0;
}

// [NEW] Panic Wipe Handler
void handle_panic(int sig) {
    panic_wipe();
}

void panic_wipe() {
    fprintf(stderr, "\n⚠️  PANIC TRIGGERED! Wiping local data...\n");
    const char* home = getenv("HOME");
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/.securechat/secret_key.enc", home);

    // 1. Wipe memory
    sodium_memzero(my_public_key, sizeof(my_public_key));
    sodium_memzero(my_secret_key, sizeof(my_secret_key));
    sodium_memzero(unique_user_id, sizeof(unique_user_id));
    sodium_memzero(current_username, sizeof(current_username));
    sodium_memzero(invisible_id, sizeof(invisible_id));

    // 2. Delete local key file
    remove(filepath);

    // 3. Exit immediately
    _exit(0);
}

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
        fprintf(stderr, "[!] ERROR: Could not create app directory.\n"); exit(1); }
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

void generate_invisible_id(char* out) {
    unsigned char rand_bytes[32];
    randombytes_buf(rand_bytes, 32);
    for (int i = 0; i < 32; i++) snprintf(out + (i * 2), 3, "%02x", rand_bytes[i]);
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
// [NEW FEATURE] VISUAL KEY FINGERPRINT
// ============================================================================
void print_key_fingerprint(const unsigned char* public_key) {
    printf("\n🔐 Your Key Fingerprint:\n");
    printf("╔════════════════════════════════════════╗\n");

    const char* chars[] = { " ", "░", "▒", "▓", "█" };
    for (int row = 0; row < 4; row++) {
        printf("║  ");
        for (int col = 0; col < 10; col++) {
            int idx = (row * 10 + col) % crypto_box_PUBLICKEYBYTES;
            int char_idx = (public_key[idx] % 5);
            printf("%s", chars[char_idx]);
        }
        printf("  ║\n");
    }
    printf("╚════════════════════════════════════════╝\n");
    printf("Compare this pattern with your friend to verify identity.\n");
}

// ============================================================================
// [NEW FEATURE] DEAD MAN'S SWITCH
// ============================================================================
void check_dead_man_switch() {
    const char* home = getenv("HOME");
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/.securechat/last_login", home);

    FILE* f = fopen(filepath, "r");
    if (!f) return;

    time_t last_login;
    if (fscanf(f, "%ld", &last_login) != 1) {
        fclose(f);
        return;
    }
    fclose(f);

    time_t now = time(NULL);
    long max_idle = DEAD_MAN_DAYS * 24 * 60 * 60;

    if (now - last_login > max_idle) {
        printf("⚠️  DEAD MAN'S SWITCH: Inactivity detected (%ld days).\n", (now - last_login) / (24*3600));
        printf("   Self-destructing keys to prevent compromise.\n");
        panic_wipe();
    }
}

void update_last_login() {
    const char* home = getenv("HOME");
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/.securechat/last_login", home);
    FILE* f = fopen(filepath, "w");
    if (f) {
        fprintf(f, "%ld", time(NULL));
        fclose(f);
    }
}

// ============================================================================
// [NEW FEATURE] UNIX PIPE INTEGRATION
// ============================================================================
void handle_pipe_mode(int argc, char* argv[]) {
    int send_mode = 0;
    char* target = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--send") == 0) send_mode = 1;
        if (strcmp(argv[i], "--to") == 0 && i + 1 < argc) target = argv[++i];
    }

    if (send_mode && target) {
        char msg[MAX_MESSAGE];
        if (fgets(msg, sizeof(msg), stdin)) {
            trim_whitespace(msg);
            if (strlen(msg) == 0) {
                printf("[!] Empty message in pipe mode.\n");
                _exit(1);
            }

            // NOTE: In a real pipe scenario, you'd need to load keys here.
            // For this demo, we assume the user is already logged in or
            // we skip the complex login flow for the pipe command.
            // To make this fully functional, you would call login_user() logic here
            // but it requires a password which isn't in a pipe.
            // A common pattern is to store an encrypted session token for CLI tools.

            printf("[*] Pipe mode: Message '%s' would be sent to %s\n", msg, target);
            printf("[!] NOTE: Full pipe mode requires session token logic (not implemented in this basic version).\n");
            printf("    Please use the interactive menu for now.\n");
            _exit(1);
        }
    }
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
    size_t plaintext_len = strlen(content);
    size_t ciphertext_len = plaintext_len + crypto_box_MACBYTES;
    unsigned char* ciphertext = malloc(ciphertext_len);
    if (!ciphertext) { out_hex[0] = '\0'; return; }

    randombytes_buf(nonce, sizeof(nonce));

    if (crypto_box_easy(ciphertext, (const unsigned char*)content, plaintext_len, nonce, recipient_pub, my_secret_key) != 0) {
        fprintf(stderr, "[!] Encryption failed.\n");
        free(ciphertext);
        out_hex[0] = '\0';
        return;
    }

    size_t total_len = sizeof(nonce) + ciphertext_len;
    unsigned char* full_data = malloc(total_len);
    if (!full_data) { free(ciphertext); out_hex[0] = '\0'; return; }

    memcpy(full_data, nonce, sizeof(nonce));
    memcpy(full_data + sizeof(nonce), ciphertext, ciphertext_len);

    for (size_t i = 0; i < total_len; i++) snprintf(out_hex + (i * 2), 3, "%02x", full_data[i]);

    free(ciphertext);
    free(full_data);
    sodium_memzero(nonce, sizeof(nonce));
    sodium_memzero(ciphertext, ciphertext_len);
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

void add_pending_request(const char* unique_id, const char* username, const unsigned char* public_key, int user_id) {
    if (pending_count >= MAX_PENDING) { printf("[!] Pending requests full.\n"); return; }

    pending_list[pending_count].user_id = user_id;
    snprintf(pending_list[pending_count].unique_id, 64, "%s", unique_id);
    snprintf(pending_list[pending_count].username, MAX_USERNAME, "%s", username);
    memcpy(pending_list[pending_count].public_key, public_key, crypto_box_PUBLICKEYBYTES);

    pending_count++;
    printf("[+] Pending request saved for '%s'.\n", unique_id);
}

int fetch_public_key_by_target(const char* target, char* pub_key_hex_out, char* username_out, int* user_id_out) {
    // NOTE: Adjust URL if using Supabase REST directly
    // Example: https://project.supabase.co/rest/v1/users?username=eq.target
    char url[1024];
    snprintf(url, sizeof(url), "%s/get-key/%s", BRIDGE_URL, target);

    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    struct MemoryStruct chunk;
    chunk.response = malloc(1);
    chunk.size = 0;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    // If using Supabase, you might need: headers = curl_slist_append(headers, "apikey: YOUR_ANON_KEY");

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
                if (hex_len != crypto_box_PUBLICKEYBYTES * 2) {
                    success = 0;
                } else {
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

int fetch_pending_requests() {
    pending_count = 0;
    return 1;
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
        printf("[!] MODERATION: Sending links is not allowed.\n");
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
// SETTINGS & BONUS FUNCTIONS
// ============================================================================

int delete_account() {
    char confirm[10];
    printf("⚠️  WARNING: This will permanently delete your account and keys.\n");
    printf("Type 'DELETE' to confirm: ");
    fflush(stdout);
    if (!fgets(confirm, sizeof(confirm), stdin)) return 0;
    trim_whitespace(confirm);

    if (strcmp(confirm, "DELETE") == 0) {
        char url[1024];
        snprintf(url, sizeof(url), "%s/delete-account", BRIDGE_URL);

        CURL *curl = curl_easy_init();
        if (!curl) return 0;

        struct MemoryStruct chunk;
        chunk.response = malloc(1);
        chunk.size = 0;

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            printf("[+] Account deleted from server.\n");
        } else {
            printf("[!] Failed to delete account from server.\n");
        }

        if (chunk.response) free(chunk.response);
        curl_easy_cleanup(curl);

        const char* home = getenv("HOME");
        char filepath[256];
        snprintf(filepath, sizeof(filepath), "%s/.securechat/secret_key.enc", home);
        remove(filepath);

        printf("[+] Local keys deleted.\n");
        return 1;
    } else {
        printf("[!] Aborted.\n");
        return 0;
    }
}

int delete_chat_with_friend(int friend_index) {
    Friend *friend = &friends_list[friend_index];
    char confirm[10];
    printf("⚠️  Delete all messages with %s? Type 'DELETE' to confirm: ", friend->username);
    fflush(stdout);
    if (!fgets(confirm, sizeof(confirm), stdin)) return 0;
    trim_whitespace(confirm);

    if (strcmp(confirm, "DELETE") == 0) {
        char url[1024];
        snprintf(url, sizeof(url), "%s/delete-chat/%d/%d", BRIDGE_URL, current_user_id, friend->user_id);

        CURL *curl = curl_easy_init();
        if (!curl) return 0;

        struct MemoryStruct chunk;
        chunk.response = malloc(1);
        chunk.size = 0;

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            printf("[+] Chat history deleted from server.\n");
        } else {
            printf("[!] Failed to delete chat history.\n");
        }

        if (chunk.response) free(chunk.response);
        curl_easy_cleanup(curl);
        return 1;
    } else {
        printf("[!] Aborted.\n");
        return 0;
    }
}

void enable_bonus_tab() {
    bonus_enabled = 1;
    printf("[+] Bonus tab enabled!\n");
}

void toggle_invisibility() {
    if (invisibility_mode) {
        invisibility_mode = 0;
        printf("[+] Invisibility mode DISABLED. Your username is visible again.\n");
    } else {
        generate_invisible_id(invisible_id);
        invisibility_mode = 1;
        printf("[+] Invisibility mode ENABLED. You are now: %s\n", invisible_id);
    }
}

void toggle_auto_login() {
    auto_login_enabled = !auto_login_enabled;
    const char* home = getenv("HOME");
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/.securechat/auto_login", home);

    FILE* f = fopen(filepath, "w");
    if (f) {
        fprintf(f, "%d", auto_login_enabled);
        fclose(f);
        printf(auto_login_enabled ? "[+] Auto-login ENABLED.\n" : "[+] Auto-login DISABLED.\n");
    } else {
        printf("[!] Failed to save auto-login setting.\n");
    }
}

void ip_geolocation() {
    char ip[64];
    printf("Enter IP address: ");
    fflush(stdout);
    if (!fgets(ip, sizeof(ip), stdin)) return;
    trim_whitespace(ip);

    char url[128];
    snprintf(url, sizeof(url), "https://ipapi.co/%s/json/", ip);

    CURL *curl = curl_easy_init();
    if (!curl) return;

    struct MemoryStruct chunk;
    chunk.response = malloc(1);
    chunk.size = 0;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        printf("\n--- IP Info ---\n%s\n", chunk.response);
    } else {
        printf("[!] Failed to fetch IP info.\n");
    }

    if (chunk.response) free(chunk.response);
    curl_easy_cleanup(curl);
}

void check_message_seen(int friend_index) {
    printf("[i] Seen status check requires server-side support.\n");
    printf("[i] (Simulated) Last seen: Just now\n");
}

void run_update() {
    printf("[*] Running 'sudo git pull origin main'...\n");
    int ret = system("sudo git pull origin main");
    if (ret == 0) {
        printf("[+] Update successful!\n");
    } else {
        printf("[!] Update failed or not in a git repo.\n");
    }
}

void show_random_quote() {
    srand(time(NULL));
    int idx = rand() % QUOTE_COUNT;
    printf("\n\"%s\"\n\n", quotes[idx]);
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

void show_pending_requests() {
    if (pending_count == 0) {
        print_box_line("No pending requests.");
        return;
    }
    for (int i = 0; i < pending_count; i++) {
        char line[60];
        snprintf(line, sizeof(line), "%d. %s (%s)", i + 1, pending_list[i].username, pending_list[i].unique_id);
        print_box_line("%s", line);
    }
}

// Persistent Chat Loop
void persistent_chat(int friend_index) {
    Friend *friend = &friends_list[friend_index];
    char msg[MAX_MESSAGE];

    chat_running = 1;
    signal(SIGINT, handle_sigint);

    while (chat_running) {
        clear_screen();
        print_header("Chat with: ");
        printf("║  %-54s ║\n", friend->username);
        printf("║  Unique ID: %s                                 ║\n", friend->unique_id);
        printf("║  [Type message] [Press /exit to leave]         ║\n");
        printf("╚════════════════════════════════════════════════════════╝\n\n");

        cJSON *root = NULL;
        if (fetch_messages(friend->user_id, &root)) {
            cJSON *msgs = cJSON_GetObjectItem(root, "messages");
            if (cJSON_IsArray(msgs)) {
                int count = 0;
                cJSON *item;
                cJSON_ArrayForEach(item, msgs) {
                    if (count >= 15) break;
                    cJSON *content_json = cJSON_GetObjectItem(item, "content");
                    cJSON *ts_json = cJSON_GetObjectItem(item, "timestamp");
                    cJSON *sender_json = cJSON_GetObjectItem(item, "sender_id");

                    if (cJSON_IsString(content_json) && cJSON_IsString(ts_json) && cJSON_IsNumber(sender_json)) {
                        char decrypted[MAX_MESSAGE];
                        const char* sender_name = (sender_json->valueint == friend->user_id) ? friend->username : "Me";

                        if (decrypt_message(content_json->valuestring, friend->public_key, decrypted, sizeof(decrypted))) {
                            // [NEW] TTL Check: Warn if message is older than 2 hours
                            time_t msg_time = atol(ts_json->valuestring);
                            time_t now = time(NULL);
                            if (now - msg_time > MESSAGE_TTL_SECONDS) {
                                printf("  [%s] %s: [EXPIRED] %s\n", ts_json->valuestring, sender_name, decrypted);
                            } else {
                                if (strlen(decrypted) > 50) {
                                    char short_msg[53];
                                    strncpy(short_msg, decrypted, 50);
                                    short_msg[50] = '.'; short_msg[51] = '.'; short_msg[52] = '\0';
                                    printf("  [%s] %s: %s\n", ts_json->valuestring, sender_name, short_msg);
                                } else {
                                    printf("  [%s] %s: %s\n", ts_json->valuestring, sender_name, decrypted);
                                }
                            }
                        }
                    }
                    count++;
                }
                if (count == 0) printf("  No messages yet.\n");
            }
            cJSON_Delete(root);
        } else {
            printf("  No messages found or failed to fetch.\n");
        }

        printf("\n> ");
        fflush(stdout);

        if (!fgets(msg, sizeof(msg), stdin)) break;
        trim_whitespace(msg);

        if (strlen(msg) == 0) continue;

        if (strcmp(msg, "/exit") == 0 || strcmp(msg, "/quit") == 0) {
            chat_running = 0;
            break;
        }

        // [NEW] Verify Key Command
        if (strcmp(msg, "/verify") == 0) {
            print_key_fingerprint(my_public_key);
            continue;
        }

        printf("[*] Encrypting and sending...\n");
        if (send_message(friend->user_id, msg)) {
            // Loop continues
        } else {
            printf("[!] Failed to send message.\n");
        }
    }

    printf("[*] Exiting chat mode.\n");
    pause_and_clear();
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

    // Show fingerprint
    print_key_fingerprint(my_public_key);

    clear_input_buffer();
    printf("Press Enter to continue...");
    fflush(stdout);
    char dummy[10];
    if (fgets(dummy, sizeof(dummy), stdin) == NULL) {}

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

        // [NEW] Update Last Login Time
        update_last_login();
        return 1;
    } else {
        printf("[!] User not found on server.\n");
        free_keys();
        return 0;
    }
}

// ============================================================================
// SETTINGS MENU
// ============================================================================

void settings_menu() {
    char choice[10];
    int running = 1;

    while (running) {
        clear_screen();
        print_header("Settings");
        printf("1. Delete Account\n");
        printf("2. Delete Chat with Friend\n");
        printf("3. Enable Bonus Tab\n");
        printf("4. Toggle Invisibility Mode\n");
        printf("5. Toggle Auto-Login\n");
        printf("6. Verify Key Fingerprint (Visual)\n"); // [NEW]
        printf("7. Back to Main Menu\n\n");
        printf("Option: ");
        fflush(stdout);

        if (!fgets(choice, sizeof(choice), stdin)) break;
        trim_whitespace(choice);

        if (strcmp(choice, "1") == 0) {
            delete_account();
            pause_and_clear();
        }
        else if (strcmp(choice, "2") == 0) {
            if (friends_count == 0) {
                printf("[!] No friends to delete chat with.\n");
                pause_and_clear();
                continue;
            }
            printf("Select friend index (1-%d): ", friends_count);
            fflush(stdout);
            int idx;
            if (scanf("%d", &idx) == 1 && idx >= 1 && idx <= friends_count) {
                clear_input_buffer();
                delete_chat_with_friend(idx - 1);
            } else {
                printf("[!] Invalid selection.\n");
                clear_input_buffer();
            }
            pause_and_clear();
        }
        else if (strcmp(choice, "3") == 0) {
            if (bonus_enabled) {
                printf("[i] Bonus tab is already enabled.\n");
            } else {
                enable_bonus_tab();
            }
            pause_and_clear();
        }
        else if (strcmp(choice, "4") == 0) {
            toggle_invisibility();
            pause_and_clear();
        }
        else if (strcmp(choice, "5") == 0) {
            toggle_auto_login();
            pause_and_clear();
        }
        else if (strcmp(choice, "6") == 0) {
            print_key_fingerprint(my_public_key);
            pause_and_clear();
        }
        else if (strcmp(choice, "7") == 0) {
            running = 0;
        }
        else {
            printf("[!] Invalid option.\n");
            pause_and_clear();
        }
    }
}

// ============================================================================
// BONUS MENU
// ============================================================================

void bonus_menu() {
    char choice[10];
    int running = 1;

    while (running) {
        clear_screen();
        print_header("Bonus Tab");
        printf("1. IP Geolocation\n");
        printf("2. Check Message Seen Status\n");
        printf("3. Update Application\n");
        printf("4. Back to Main Menu\n\n");
        printf("Option: ");
        fflush(stdout);

        if (!fgets(choice, sizeof(choice), stdin)) break;
        trim_whitespace(choice);

        if (strcmp(choice, "1") == 0) {
            ip_geolocation();
            pause_and_clear();
        }
        else if (strcmp(choice, "2") == 0) {
            if (friends_count == 0) {
                printf("[!] No friends to check status for.\n");
                pause_and_clear();
                continue;
            }
            printf("Select friend index (1-%d): ", friends_count);
            fflush(stdout);
            int idx;
            if (scanf("%d", &idx) == 1 && idx >= 1 && idx <= friends_count) {
                clear_input_buffer();
                check_message_seen(idx - 1);
            } else {
                printf("[!] Invalid selection.\n");
                clear_input_buffer();
            }
            pause_and_clear();
        }
        else if (strcmp(choice, "3") == 0) {
            run_update();
            pause_and_clear();
        }
        else if (strcmp(choice, "4") == 0) {
            running = 0;
        }
        else {
            printf("[!] Invalid option.\n");
            pause_and_clear();
        }
    }
}

// ============================================================================
// MAIN MENU LOOP
// ============================================================================

void main_menu_loop() {
    char choice[10];
    int idx;
    int running = 1;

    while (running) {
        clear_screen();
        show_random_quote();

        print_header("Main Menu");
        printf("1. View Friends List\n");
        printf("2. View Pending Requests\n");
        printf("3. View Chat (Select Friend)\n");
        printf("4. Add Friend (Enter Username or Unique ID)\n");
        if (bonus_enabled) {
            printf("5. Bonus Tab\n");
        }
        printf("6. Settings\n");
        printf("7. Logout\n");
        printf("8. Exit\n\n");
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
            clear_screen();
            print_header("Pending Requests");
            fetch_pending_requests();
            show_pending_requests();
            print_box_empty();
            pause_and_clear();
        }
        else if (strcmp(choice, "3") == 0) {
            if (friends_count == 0) {
                printf("[!] No friends to chat with. Add one first.\n");
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
            persistent_chat(idx - 1);
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
        else if (strcmp(choice, "5") == 0 && bonus_enabled) {
            bonus_menu();
        }
        else if (strcmp(choice, "6") == 0) {
            settings_menu();
        }
        else if (strcmp(choice, "7") == 0) {
            clear_screen();
            free_keys();
            current_user_id = -1;
            friends_count = 0;
            pending_count = 0;
            bonus_enabled = 0;
            auto_login_enabled = 0;
            invisibility_mode = 0;
            printf("[*] Logged out.\n");
            pause_and_clear();
            return;
        }
        else if (strcmp(choice, "8") == 0) {
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

int main(int argc, char* argv[]) {
    // [NEW] Check for pipe mode first
    if (argc > 1) {
        handle_pipe_mode(argc, argv);
    }

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

    // [NEW] Set up Panic Signal Handler (Ctrl+\)
    signal(SIGQUIT, handle_panic);

    // Check for auto-login file
    const char* home = getenv("HOME");
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/.securechat/auto_login", home);
    FILE* auto_login_file = fopen(filepath, "r");
    if (auto_login_file) {
        int enabled = 0;
        fscanf(auto_login_file, "%d", &enabled);
        fclose(auto_login_file);
        if (enabled) {
            printf("Auto-login detected... ");
            printf(" (Disabled for security - you must login manually).\n");
        }
    }

    char choice[10];
    while (1) {
        if (current_user_id == -1) {
            clear_screen();
            print_logo();
            show_random_quote();
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
                // [NEW] Check Dead Man's Switch before login
                check_dead_man_switch();

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
    printf("\033[?25h");
    return 0;
}
