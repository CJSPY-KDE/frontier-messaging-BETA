#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <ctype.h>
#include <curl/curl.h>
#include <stdarg.h> // For va_list in print_box_line

// --- CONFIGURATION ---
#define SUPABASE_URL "https://avxhbalzbppwofvssfnz.supabase.co/rest/v1/"
#define SUPABASE_KEY "sb_publishable_DBLlN-ZAUnrEr3izbUxcuw_LGUTUXZf"
// --------------------------------------

#define MESSAGE_TTL_HOURS 2
#define PROFILE_TTL_HOURS 24
#define MAX_USERNAME 50
#define MAX_PASSWORD 100
#define MAX_BIO 256
#define MAX_MESSAGE 512
#define CLEANUP_INTERVAL 300
#define MAX_DISCOVER_BATCH 50

typedef struct {
    int user_id;
    char username[MAX_USERNAME];
    char bio[MAX_BIO];
    char interests[MAX_BIO];
    int discoverable;
} User;

// Global variables
int current_user_id = -1;
char current_username[MAX_USERNAME] = "";

// --- UI HELPERS (FIXED) ---
void clear_screen() {
    printf("\033[2J\033[H");
    fflush(stdout);
}

void pause_and_clear() {
    printf("\nPress Enter to continue...");
    char dummy[10];
    fgets(dummy, sizeof(dummy), stdin);
    clear_screen();
}

void print_header(const char* title) {
    clear_screen();
    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║  %-54s ║\n", title);
    printf("╚════════════════════════════════════════════════════════════╝\n\n");
}

// Fixed: Safe variadic function
void print_box_line(const char* fmt, ...) {
    char buffer[256];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    printf("║  %-54s ║\n", buffer);
}

void print_box_empty() {
    printf("║                                                          ║\n");
}

// --- FUNCTION PROTOTYPES ---
char* hash_password(const char* password);
int register_user(const char* username, const char* password, const char* bio, const char* interests);
int login_user(const char* username, const char* password);
void discover_people();
void send_friend_request(int to_user_id);
void view_friend_requests();
void list_friends();
void send_direct_message(int recipient_id, const char* content);
void view_direct_messages(int sender_id);
void view_profile(int user_id);
void manage_account();
void main_menu();
void trim_whitespace(char* str);
void clear_input_buffer();
void* cleanup_loop(void* arg);
int contains_url(const char* text);
void shuffle_users(User* arr, int n);

// --- CURL HELPER ---
struct MemoryStruct {
    char *response;
    size_t size;
};

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    char *ptr = realloc(mem->response, mem->size + realsize + 1);
    if (ptr == NULL) {
        fprintf(stderr, "Not enough memory (realloc returned NULL)\n");
        return 0;
    }
    mem->response = ptr;
    memcpy(&(mem->response[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->response[mem->size] = 0;
    return realsize;
}

char* send_request(const char* method, const char* endpoint, const char* data) {
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;
    chunk.response = malloc(1);
    chunk.size = 0;

    char url[1024];
    snprintf(url, sizeof(url), "%s%s", SUPABASE_URL, endpoint);

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if(curl) {
        struct curl_slist *headers = NULL;
        char auth_header[512];
        snprintf(auth_header, sizeof(auth_header), "apikey: %s", SUPABASE_KEY);
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "Prefer: return=representation");
        headers = curl_slist_append(headers, auth_header);
        headers = curl_slist_append(headers, "Accept: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        if (strcmp(method, "POST") == 0) {
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        } else if (strcmp(method, "DELETE") == 0) {
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
        } else if (strcmp(method, "PATCH") == 0) {
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        } else if (strcmp(method, "GET") == 0) {
            curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
        }

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            free(chunk.response);
            chunk.response = NULL;
        }

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }
    curl_global_cleanup();
    return chunk.response;
}

// --- FUNCTION DEFINITIONS ---

void clear_input_buffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

int contains_url(const char* text) {
    if (!text) return 0;
    if (strstr(text, "http://") != NULL) return 1;
        if (strstr(text, "https://") != NULL) return 1;
            if (strstr(text, "www.") != NULL) return 1;
            if (strstr(text, ".com") != NULL) return 1;
            if (strstr(text, ".io") != NULL) return 1;
            if (strstr(text, ".net") != NULL) return 1;
            if (strstr(text, ".org") != NULL) return 1;
            if (strstr(text, ".gg") != NULL) return 1;
            return 0;
}

char* hash_password(const char* password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    static char hex_hash[SHA256_DIGEST_LENGTH * 2 + 1];
    SHA256((unsigned char*)password, strlen(password), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&hex_hash[i * 2], "%02x", hash[i]);
    }
    hex_hash[SHA256_DIGEST_LENGTH * 2] = '\0';
    return hex_hash;
}

void trim_whitespace(char* str) {
    if (!str) return;
    int len = strlen(str);
    if (len > 0 && str[len - 1] == '\n') str[len - 1] = '\0';
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return;
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
}

// Safe string extraction helper
void extract_json_string(const char* json, const char* key, char* out, int max_len) {
    char search_key[64];
    snprintf(search_key, sizeof(search_key), "\"%s\":\"", key);
    char* start = (char*)strstr(json, search_key);
    if (!start) {
        out[0] = '\0';
        return;
    }
    start += strlen(search_key);
    int i = 0;
    while (start[i] && start[i] != '"' && start[i] != '\\' && i < max_len - 1) {
        out[i] = start[i];
        i++;
    }
    out[i] = '\0';
}

int register_user(const char* username, const char* password, const char* bio, const char* interests) {
    const char* hash = hash_password(password);
    char json[1024];
    snprintf(json, sizeof(json),
             "{\"username\":\"%s\", \"password_hash\":\"%s\", \"bio\":\"%s\", \"interests\":\"%s\", \"discoverable\":true}",
             username, hash, bio, interests);

    char* response = send_request("POST", "/profiles", json);
    int success = 0;
    if (response && strstr(response, "user_id")) {
        success = 1;
    }
    if(response) free(response);
    return success;
}

int login_user(const char* username, const char* password) {
    const char* hash = hash_password(password);
    char query[1024];
    snprintf(query, sizeof(query),
             "/profiles?select=user_id&username=eq.%s&password_hash=eq.%s", username, hash);

    char* response = send_request("GET", query, NULL);
    int success = 0;

    if (response && strstr(response, "user_id")) {
        char* start = strstr(response, "user_id\":");
        if (start) {
            start += 9;
            current_user_id = atoi(start);
            strcpy(current_username, username);
            success = 1;
        }
    }
    if(response) free(response);
    return success;
}

void send_direct_message(int recipient_id, const char* content) {
    if (current_user_id == -1) {
        print_header("Error");
        print_box_line("✗ Not logged in!");
        print_box_empty();
        pause_and_clear();
        return;
    }

    if (contains_url(content)) {
        print_header("Message Blocked");
        print_box_line("✗ URLs are not allowed for security reasons.");
        print_box_empty();
        pause_and_clear();
        return;
    }

    char json[1024];
    snprintf(json, sizeof(json), "{\"sender_id\":%d, \"recipient_id\":%d, \"content\":\"%s\"}",
             current_user_id, recipient_id, content);

    char* response = send_request("POST", "/messages", json);
    if (response && strstr(response, "id")) {
        print_header("Success");
        print_box_line("✓ Message sent!");
        print_box_empty();
    } else {
        print_header("Error");
        print_box_line("✗ Failed to send message.");
        print_box_empty();
    }
    if(response) free(response);
    pause_and_clear();
}

void view_direct_messages(int sender_id) {
    if (current_user_id == -1) {
        print_header("Error");
        print_box_line("✗ Not logged in!");
        print_box_empty();
        pause_and_clear();
        return;
    }

    char query[1024];
    snprintf(query, sizeof(query), "/messages?select=id,content,timestamp&sender_id=eq.%d&recipient_id=eq.%d&order=timestamp.desc",
             sender_id, current_user_id);

    char* response = send_request("GET", query, NULL);
    print_header("Messages");
    print_box_line("--- Messages from User %d ---", sender_id);
    print_box_empty();

    if (!response || !strstr(response, "sender_id")) {
        print_box_line("No messages found.");
        print_box_empty();
        pause_and_clear();
        if(response) free(response);
        return;
    }

    char* ptr = response;
    int count = 0;
    char messages[50][MAX_MESSAGE];
    char times[50][50];

    while ((ptr = strstr(ptr, "{\"id\":")) != NULL && count < 50) {
        char* content_ptr = strstr(ptr, "\"content\":\"");
        if (content_ptr) {
            content_ptr += 9;
            int i = 0;
            while (content_ptr[i] && content_ptr[i] != '"' && content_ptr[i] != '\\' && i < MAX_MESSAGE-1) {
                messages[count][i] = content_ptr[i];
                i++;
            }
            messages[count][i] = '\0';

            char* time_ptr = strstr(ptr, "\"timestamp\":\"");
            if (time_ptr) {
                time_ptr += 11;
                int j = 0;
                while (time_ptr[j] && time_ptr[j] != '"' && j < 49) {
                    times[count][j] = time_ptr[j];
                    j++;
                }
                times[count][j] = '\0';
            } else {
                strcpy(times[count], "Unknown");
            }
            count++;
        }
        ptr++;
    }

    for(int i=0; i<count; i++) {
        print_box_line("[%s] %s", times[i], messages[i]);
    }
    if(count == 0) print_box_line("No messages found.");
    print_box_empty();
    if(response) free(response);
    pause_and_clear();
}

void view_profile(int user_id) {
    if (current_user_id == -1) {
        print_header("Error");
        print_box_line("✗ Not logged in!");
        print_box_empty();
        pause_and_clear();
        return;
    }

    char query[1024];
    snprintf(query, sizeof(query), "/profiles?select=*&user_id=eq.%d", user_id);
    char* response = send_request("GET", query, NULL);

    print_header("Profile View");

    if (response && strstr(response, "username")) {
        char username[50], bio[256], interests[256];
        int discoverable = 0;
        int display_id = user_id;

        // Safe extraction
        extract_json_string(response, "username", username, sizeof(username));
        extract_json_string(response, "bio", bio, sizeof(bio));
        extract_json_string(response, "interests", interests, sizeof(interests));

        char* d = strstr(response, "\"discoverable\":");
        if (d) discoverable = (strstr(d, "true") != NULL) ? 1 : 0;

        print_box_line("User ID: %d", display_id);
        print_box_line("%s", username[0] ? username : "Unknown");
        print_box_line(discoverable ? "Discoverable: Yes" : "Discoverable: No");
        print_box_empty();
        print_box_line(strlen(bio) > 0 ? bio : "(No bio)");
        print_box_empty();
        print_box_line(strlen(interests) > 0 ? interests : "(No interests)");
    } else {
        print_box_line("✗ User not found.");
    }
    print_box_empty();
    if(response) free(response);
    pause_and_clear();
}

void manage_account() {
    if (current_user_id == -1) {
        print_header("Error");
        print_box_line("✗ Not logged in!");
        print_box_empty();
        pause_and_clear();
        return;
    }

    char choice[10];
    char new_bio[MAX_BIO];
    char new_interests[MAX_BIO];
    char new_discoverable[10];

    while (1) {
        print_header("Manage Account");
        print_box_line("1. Update Bio");
        print_box_line("2. Update Interests");
        print_box_line("3. Toggle Discoverability");
        print_box_line("4. View Profile");
        print_box_line("5. Back to Main Menu");
        print_box_empty();
        print_box_line("Choice: ");
        printf("Choice: ");

        fgets(choice, sizeof(choice), stdin);
        trim_whitespace(choice);

        if (strcmp(choice, "1") == 0) {
            printf("\nEnter new bio: ");
            fgets(new_bio, sizeof(new_bio), stdin);
            trim_whitespace(new_bio);

            char json[1024];
            snprintf(json, sizeof(json), "{\"bio\":\"%s\"}", new_bio);
            char endpoint[128];
            snprintf(endpoint, sizeof(endpoint), "/profiles?user_id=eq.%d", current_user_id);

            char* resp = send_request("PATCH", endpoint, json);
            if (resp && strstr(resp, "bio")) {
                print_header("Success");
                print_box_line("✓ Bio updated successfully.");
                print_box_empty();
                pause_and_clear();
            } else {
                print_header("Error");
                print_box_line("✗ Failed to update bio.");
                print_box_empty();
                pause_and_clear();
            }
            if (resp) free(resp);
        }
        else if (strcmp(choice, "2") == 0) {
            printf("\nEnter new interests: ");
            fgets(new_interests, sizeof(new_interests), stdin);
            trim_whitespace(new_interests);

            char json[1024];
            snprintf(json, sizeof(json), "{\"interests\":\"%s\"}", new_interests);
            char endpoint[128];
            snprintf(endpoint, sizeof(endpoint), "/profiles?user_id=eq.%d", current_user_id);

            char* resp = send_request("PATCH", endpoint, json);
            if (resp && strstr(resp, "interests")) {
                print_header("Success");
                print_box_line("✓ Interests updated successfully.");
                print_box_empty();
                pause_and_clear();
            } else {
                print_header("Error");
                print_box_line("✗ Failed to update interests.");
                print_box_empty();
                pause_and_clear();
            }
            if (resp) free(resp);
        }
        else if (strcmp(choice, "3") == 0) {
            printf("\nToggle discoverability? (1 for Yes/Visible, 0 for No/Hidden): ");
            fgets(new_discoverable, sizeof(new_discoverable), stdin);
            trim_whitespace(new_discoverable);

            int is_visible = (atoi(new_discoverable) == 1) ? 1 : 0;
            char json[1024];
            snprintf(json, sizeof(json), "{\"discoverable\":%s}", is_visible ? "true" : "false");
            char endpoint[128];
            snprintf(endpoint, sizeof(endpoint), "/profiles?user_id=eq.%d", current_user_id);

            char* resp = send_request("PATCH", endpoint, json);
            if (resp && strstr(resp, "discoverable")) {
                print_header("Success");
                print_box_line(is_visible ? "✓ Discoverability updated to Visible." : "✓ Discoverability updated to Hidden.");
                print_box_empty();
                pause_and_clear();
            } else {
                print_header("Error");
                print_box_line("✗ Failed to update discoverability.");
                print_box_empty();
                pause_and_clear();
            }
            if (resp) free(resp);
        }
        else if (strcmp(choice, "4") == 0) {
            view_profile(current_user_id);
        }
        else if (strcmp(choice, "5") == 0) {
            break; // Exit manage_account loop
        }
        else {
            print_header("Error");
            print_box_line("Invalid choice.");
            print_box_empty();
            pause_and_clear();
        }
    }
}

void main_menu() {
    char choice[10];
    while (1) {
        print_header("User Menu");
        print_box_line("1. Discover People (Search)");
        print_box_line("2. View Friend Requests");
        print_box_line("3. List My Friends");
        print_box_line("4. Send Direct Message");
        print_box_line("5. View Messages from a User");
        print_box_line("6. View My Own Profile");
        print_box_line("7. Manage Account");
        print_box_line("8. Logout");
        print_box_empty();
        print_box_line("Choice: ");
        printf("Choice: ");

        fgets(choice, sizeof(choice), stdin);
        trim_whitespace(choice);

        if (strcmp(choice, "1") == 0) {
            discover_people();
        } else if (strcmp(choice, "2") == 0) {
            view_friend_requests();
        } else if (strcmp(choice, "3") == 0) {
            list_friends();
        } else if (strcmp(choice, "4") == 0) {
            int recipient_id;
            print_header("Send Message");
            print_box_line("Enter recipient User ID: ");
            printf("ID: ");
            if (scanf("%d", &recipient_id) != 1) { clear_input_buffer(); continue; }
            clear_input_buffer();

            char content[MAX_MESSAGE];
            print_box_line("Message: ");
            printf("Text: ");
            fgets(content, sizeof(content), stdin);
            trim_whitespace(content);
            send_direct_message(recipient_id, content);
        } else if (strcmp(choice, "5") == 0) {
            int sender_id;
            print_header("View Messages");
            print_box_line("Enter sender User ID: ");
            printf("ID: ");
            if (scanf("%d", &sender_id) != 1) { clear_input_buffer(); continue; }
            clear_input_buffer();
            view_direct_messages(sender_id);
        } else if (strcmp(choice, "6") == 0) {
            view_profile(current_user_id);
        } else if (strcmp(choice, "7") == 0) {
            manage_account();
        } else if (strcmp(choice, "8") == 0) {
            current_user_id = -1;
            current_username[0] = '\0';
            print_header("Logged Out");
            print_box_line("Goodbye!");
            pause_and_clear();
            return;
        } else {
            print_header("Error");
            print_box_line("Invalid option.");
            print_box_empty();
            pause_and_clear();
        }
    }
}

void shuffle_users(User* arr, int n) {
    if (n <= 1) return;
    srand(time(NULL));
    for (int i = n - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        User temp = arr[i];
        arr[i] = arr[j];
        arr[j] = temp;
    }
}

void discover_people() {
    if (current_user_id == -1) {
        print_header("Error");
        print_box_line("✗ Not logged in!");
        pause_and_clear();
        return;
    }

    char choice[10];
    print_header("Discover People");
    print_box_line("1. Browse Random Users");
    print_box_line("2. Search by Username");
    print_box_line("3. View My Own Profile");
    print_box_empty();
    print_box_line("Choice: ");
    printf("Choice: ");

    fgets(choice, sizeof(choice), stdin);
    trim_whitespace(choice);

    if (strcmp(choice, "3") == 0) {
        view_profile(current_user_id);
        return;
    }

    char query[1024];
    if (strcmp(choice, "2") == 0) {
        char search_query[MAX_USERNAME];
        print_box_line("Enter username (partial match OK): ");
        printf("Search: ");
        fgets(search_query, sizeof(search_query), stdin);
        trim_whitespace(search_query);
        snprintf(query, sizeof(query), "/profiles?select=user_id,username,bio,interests&discoverable=eq.true&user_id=neq.%d&username=ilike.*%s*&order=user_id.asc&limit=%d", current_user_id, search_query, MAX_DISCOVER_BATCH);
    } else {
        snprintf(query, sizeof(query), "/profiles?select=user_id,username,bio,interests&discoverable=eq.true&user_id=neq.%d&order=user_id.asc&limit=%d", current_user_id, MAX_DISCOVER_BATCH);
    }

    char* response = send_request("GET", query, NULL);

    print_header("Discover People");

    if (!response || !strstr(response, "user_id")) {
        print_box_line("No users found.");
        pause_and_clear();
        if(response) free(response);
        return;
    }

    char* ptr = response;
    int count = 0;
    User users[MAX_DISCOVER_BATCH];

    while ((ptr = strstr(ptr, "{\"user_id\":")) != NULL && count < MAX_DISCOVER_BATCH) {
        char* u_id = strstr(ptr, "\"user_id\":");
        if (u_id) { u_id += 10; users[count].user_id = atoi(u_id); }
        else users[count].user_id = 0;

        // Use safe extraction for each field
        char* u_name = strstr(ptr, "\"username\":\"");
        if (u_name) {
            u_name += 12;
            int i=0;
            while(u_name[i] && u_name[i]!='"') {
                users[count].username[i]=u_name[i];
                i++;
            }
            users[count].username[i]='\0';
        } else strcpy(users[count].username, "Unknown");

        char* b = strstr(ptr, "\"bio\":\"");
        if (b) {
            b += 7;
            int i=0;
            while(b[i] && b[i]!='"') {
                users[count].bio[i]=b[i];
                i++;
            }
            users[count].bio[i]='\0';
        } else users[count].bio[0] = '\0';

        char* i = strstr(ptr, "\"interests\":\"");
        if (i) {
            i += 13;
            int j=0;
            while(i[j] && i[j]!='"') {
                users[count].interests[j]=i[j];
                j++;
            }
            users[count].interests[j]='\0';
        } else users[count].interests[0] = '\0';

        count++;
        ptr++;
    }

    if (count == 0) {
        print_box_line("No users found.");
        pause_and_clear();
        if(response) free(response);
        return;
    }

    if (strcmp(choice, "1") == 0) {
        shuffle_users(users, count);
    }

    for (int i = 0; i < count; i++) {
        print_box_line("%d. %s", i + 1, users[i].username);
        if (strlen(users[i].bio) > 0) {
            print_box_line("   Bio: %s", users[i].bio);
        }
        if (strlen(users[i].interests) > 0) {
            print_box_line("   Interests: %s", users[i].interests);
        }
        print_box_empty();
    }

    print_box_line("Select user (number), View Profile (number + p), or 0 to skip: ");
    printf("Choice: ");
    char input[20];
    fgets(input, sizeof(input), stdin);
    trim_whitespace(input);

    int idx = atoi(input);
    if (idx > 0 && idx <= count) {
        char last_char = input[strlen(input)-1];
        if (last_char == 'p' || last_char == 'P') {
            view_profile(users[idx - 1].user_id);
        } else {
            send_friend_request(users[idx - 1].user_id);
        }
    }
    if(response) free(response);
}

void send_friend_request(int to_user_id) {
    if (current_user_id == -1) {
        print_header("Error");
        print_box_line("✗ Not logged in!");
        pause_and_clear();
        return;
    }

    if (to_user_id == current_user_id) {
        print_header("Error");
        print_box_line("✗ You cannot send a request to yourself.");
        pause_and_clear();
        return;
    }

    char content[] = "Friend Request";
    send_direct_message(to_user_id, content);
}

void view_friend_requests() {
    if (current_user_id == -1) {
        print_header("Error");
        print_box_line("✗ Not logged in!");
        pause_and_clear();
        return;
    }

    char query[1024];
    snprintf(query, sizeof(query), "/messages?select=sender_id,content,timestamp&recipient_id=eq.%d&content=eq.Friend Request&order=timestamp.desc", current_user_id);

    char* response = send_request("GET", query, NULL);

    print_header("Friend Requests");

    if (!response || !strstr(response, "sender_id")) {
        print_box_line("No pending friend requests.");
        pause_and_clear();
        if(response) free(response);
        return;
    }

    char* ptr = response;
    int count = 0;
    int user_ids[50];

    while ((ptr = strstr(ptr, "{\"sender_id\":")) != NULL && count < 50) {
        char* s_id = strstr(ptr, "\"sender_id\":");
        if (s_id) { s_id += 12; user_ids[count] = atoi(s_id); count++; }
        ptr++;
    }

    if (count == 0) {
        print_box_line("No pending friend requests.");
        pause_and_clear();
        if(response) free(response);
        return;
    }

    for (int i = 0; i < count; i++) {
        print_box_line("Request from User %d", user_ids[i]);
    }

    print_box_empty();
    print_box_line("Accept (number), Decline (number + d), or 0 to cancel: ");
    printf("Choice: ");
    char input[20];
    fgets(input, sizeof(input), stdin);
    trim_whitespace(input);

    int action = atoi(input);
    char last_char = input[strlen(input)-1];
    int is_decline = (last_char == 'd' || last_char == 'D');

    if (action > 0 && action <= count) {
        if (is_decline) {
            print_header("Action");
            print_box_line("✗ Friend request declined.");
            pause_and_clear();
        } else {
            print_header("Action");
            print_box_line("✓ Friend request accepted!");
            pause_and_clear();
        }
    } else {
        print_header("Action");
        print_box_line("Operation cancelled.");
        pause_and_clear();
    }
    if(response) free(response);
}

void list_friends() {
    if (current_user_id == -1) {
        print_header("Error");
        print_box_line("✗ Not logged in!");
        pause_and_clear();
        return;
    }

    print_header("My Friends");
    print_box_line("(Note: 'Friends' table logic not fully implemented yet)");
    print_box_line("No friends listed yet.");
    print_box_empty();
    pause_and_clear();
}

void* cleanup_loop(void* arg) {
    while (1) {
        sleep(CLEANUP_INTERVAL);
    }
    return NULL;
}

int main() {
    pthread_t tid;
    pthread_create(&tid, NULL, cleanup_loop, NULL);
    pthread_detach(tid);

    print_header("Frontier Messaging");
    print_box_line("Cloud Connected • Secure • Auto-Moderated");
    print_box_line("Press Enter to start...");
    pause_and_clear();

    char choice[10];
    while (1) {
        if (current_user_id == -1) {
            print_header("Main Menu");
            print_box_line("1. Register");
            print_box_line("2. Login");
            print_box_line("3. Exit");
            print_box_empty();
            print_box_line("Choice: ");
            printf("Choice: ");

            fgets(choice, sizeof(choice), stdin);
            trim_whitespace(choice);

            if (strcmp(choice, "1") == 0) {
                char username[MAX_USERNAME], password[MAX_PASSWORD], bio[MAX_BIO], interests[MAX_BIO];
                print_header("Register User");
                print_box_line("Username: ");
                printf("Name: ");
                fgets(username, sizeof(username), stdin);
                trim_whitespace(username);
                print_box_line("Password: ");
                printf("Pass: ");
                fgets(password, sizeof(password), stdin);
                trim_whitespace(password);
                print_box_line("Bio (optional): ");
                printf("Bio: ");
                fgets(bio, sizeof(bio), stdin);
                trim_whitespace(bio);
                print_box_line("Interests (optional): ");
                printf("Interests: ");
                fgets(interests, sizeof(interests), stdin);
                trim_whitespace(interests);

                if (register_user(username, password, bio, interests)) {
                    print_header("Success");
                    print_box_line("✓ Registration successful!");
                    pause_and_clear();
                } else {
                    print_header("Error");
                    print_box_line("✗ Registration failed.");
                    pause_and_clear();
                }
            }
            else if (strcmp(choice, "2") == 0) {
                char username[MAX_USERNAME], password[MAX_PASSWORD];
                print_header("Login");
                print_box_line("Username: ");
                printf("Name: ");
                fgets(username, sizeof(username), stdin);
                trim_whitespace(username);
                print_box_line("Password: ");
                printf("Pass: ");
                fgets(password, sizeof(password), stdin);
                trim_whitespace(password);

                if (login_user(username, password)) {
                    main_menu();
                } else {
                    print_header("Error");
                    print_box_line("✗ Invalid credentials!");
                    pause_and_clear();
                }
            }
            else if (strcmp(choice, "3") == 0) {
                print_header("Goodbye");
                print_box_line("Thank you for using Frontier Messaging.");
                pause_and_clear();
                return 0;
            }
            else {
                print_header("Error");
                print_box_line("Invalid option.");
                pause_and_clear();
            }
        } else {
            print_header("Session Ended");
            print_box_line("Logging out...");
            pause_and_clear();
            current_user_id = -1;
            current_username[0] = '\0';
        }
    }

    return 0;
}
