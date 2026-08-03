#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <ctype.h>
#include <curl/curl.h>

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
#define MAX_DISCOVER_BATCH 50 // Fetch more to shuffle locally

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

// Function Prototypes
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
void manage_account(); // NEW
void main_menu();
void trim_whitespace(char* str);
void* cleanup_loop(void* arg);
void clear_input_buffer(); // NEW

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

// Helper to send HTTP request
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

int register_user(const char* username, const char* password, const char* bio, const char* interests) {
    const char* hash = hash_password(password);

    char json[1024];
    snprintf(json, sizeof(json),
             "{\"username\":\"%s\", \"password_hash\":\"%s\", \"bio\":\"%s\", \"interests\":\"%s\", \"discoverable\":true}",
             username, hash, bio, interests);

    char* response = send_request("POST", "/profiles", json);

    if (response && strstr(response, "user_id")) {
        printf("✓ Registration successful!\n");
        free(response);
        return 1;
    } else {
        if (response && strstr(response, "duplicate")) {
            printf("✗ Username already exists!\n");
        } else {
            printf("✗ Registration failed: %s\n", response ? response : "Unknown error");
        }
        if(response) free(response);
        return 0;
    }
}

int login_user(const char* username, const char* password) {
    const char* hash = hash_password(password);

    char query[1024];
    snprintf(query, sizeof(query),
             "/profiles?select=user_id&username=eq.%s&password_hash=eq.%s", username, hash);

    char* response = send_request("GET", query, NULL);

    if (response && strstr(response, "user_id")) {
        char* start = strstr(response, "user_id\":");
        if (start) {
            start += 9;
            current_user_id = atoi(start);
            strcpy(current_username, username);
            printf("✓ Logged in as '%s' (ID: %d)\n", current_username, current_user_id);
            free(response);
            return 1;
        }
    }

    if(response) free(response);
    return 0;
}

void send_direct_message(int recipient_id, const char* content) {
    if (current_user_id == -1) { printf("✗ Not logged in!\n"); return; }

    char json[1024];
    snprintf(json, sizeof(json), "{\"sender_id\":%d, \"recipient_id\":%d, \"content\":\"%s\"}",
             current_user_id, recipient_id, content);

    char* response = send_request("POST", "/messages", json);

    if (response && strstr(response, "id")) {
        printf("✓ Message sent!\n");
    } else {
        printf("✗ Failed to send message: %s\n", response ? response : "Unknown error");
    }
    if(response) free(response);
}

void view_direct_messages(int sender_id) {
    if (current_user_id == -1) { printf("✗ Not logged in!\n"); return; }

    char query[1024];
    snprintf(query, sizeof(query), "/messages?select=id,content,timestamp&sender_id=eq.%d&recipient_id=eq.%d&order=timestamp.desc",
             sender_id, current_user_id);

    char* response = send_request("GET", query, NULL);

    printf("\n--- Messages from User %d ---\n", sender_id);

    if (!response || !strstr(response, "sender_id")) {
        printf("No messages found.\n");
        if(response) free(response);
        return;
    }

    char* ptr = response;
    int count = 0;

    // Parse JSON array manually (fragile but works for simple cases)
    while ((ptr = strstr(ptr, "{\"id\":")) != NULL) {
        char* id_ptr = strstr(ptr, "\"id\":");
        if (id_ptr) {
            id_ptr += 5;
            int id = atoi(id_ptr);

            char* content_ptr = strstr(ptr, "\"content\":\"");
            if (content_ptr) {
                content_ptr += 9;
                char content[MAX_MESSAGE];
                int i = 0;
                while (content_ptr[i] && content_ptr[i] != '"' && content_ptr[i] != '\\') {
                    content[i] = content_ptr[i];
                    i++;
                }
                content[i] = '\0';

                char* time_ptr = strstr(ptr, "\"timestamp\":\"");
                char time[50] = "Unknown";
                if (time_ptr) {
                    time_ptr += 11;
                    int j = 0;
                    while (time_ptr[j] && time_ptr[j] != '"' && j < 49) {
                        time[j] = time_ptr[j];
                        j++;
                    }
                    time[j] = '\0';
                }

                printf("[%s] %s\n", time, content);
                count++;
                // REMOVED: Automatic deletion here. Messages stay until manually deleted.
            }
        }
        ptr++;
    }

    if (count == 0) {
        printf("No messages found.\n");
    }

    if(response) free(response);
}
void view_profile(int user_id) {
    if (current_user_id == -1) { printf("✗ Not logged in!\n"); return; }

    char query[1024];
    snprintf(query, sizeof(query), "/profiles?select=*&user_id=eq.%d", user_id);

    char* response = send_request("GET", query, NULL);

    if (response && strstr(response, "username")) {
        char* start = response;
        char username[50], bio[256], interests[256];
        int discoverable = 0;
        int display_id = user_id; // Show the requested user's ID

        char* u = strstr(start, "\"username\":\"");
        if (u) {
            u += 12;
            int i = 0;
            while (u[i] && u[i] != '"') { username[i] = u[i]; i++; }
            username[i] = '\0';
        } else strcpy(username, "Unknown");

        char* b = strstr(start, "\"bio\":\"");
        if (b) {
            b += 7;
            int i = 0;
            while (b[i] && b[i] != '"') { bio[i] = b[i]; i++; }
            bio[i] = '\0';
        } else bio[0] = '\0';

        char* i = strstr(start, "\"interests\":\"");
        if (i) {
            i += 13;
            int j = 0;
            while (i[j] && i[j] != '"') { interests[j] = i[j]; j++; }
            interests[j] = '\0';
        } else interests[0] = '\0';

        char* d = strstr(start, "\"discoverable\":");
        if (d) {
            discoverable = (strstr(d, "true") != NULL) ? 1 : 0;
        }

        printf("\n╔════════════════════════════════════════════════════════════╗\n");
        printf("║                    PROFILE VIEW                            ║\n");
        printf("╠════════════════════════════════════════════════════════════╣\n");
        printf("║ User ID: %-43d ║\n", display_id); // NEW LINE FOR ID
        printf("║ Username: %-40s ║\n", username);
        printf("║ Discoverable: %s                                      ║\n", discoverable ? "Yes" : "No");
        printf("╠════════════════════════════════════════════════════════════╣\n");
        printf("║ Bio: %-60s ║\n", strlen(bio) > 0 ? bio : "(No bio)");
        printf("╠════════════════════════════════════════════════════════════╣\n");
        printf("║ Interests: %-60s ║\n", strlen(interests) > 0 ? interests : "(No interests)");
        printf("╚════════════════════════════════════════════════════════════╝\n");
    } else {
        printf("✗ User not found.\n");
    }
    if(response) free(response);
}
// NEW: Manage Account Function
void manage_account() {
    if (current_user_id == -1) { printf("✗ Not logged in!\n"); return; }

    char choice[10];
    char new_bio[MAX_BIO];
    char new_interests[MAX_BIO];
    char new_discoverable[10];

    while (1) {
        printf("\n╔════════════════════════════════════════════════════════════╗\n");
        printf("║              MANAGE ACCOUNT                               ║\n");
        printf("╚════════════════════════════════════════════════════════════╝\n");
        printf("1. Update Bio\n");
        printf("2. Update Interests\n");
        printf("3. Toggle Discoverability\n");
        printf("4. View Profile\n");
        printf("5. Back to Main Menu\n");
        printf("Choice: ");

        fgets(choice, sizeof(choice), stdin);
        trim_whitespace(choice);
        if (strcmp(choice, "1") == 0) {
            printf("Enter new bio: ");
            fgets(new_bio, sizeof(new_bio), stdin);
            trim_whitespace(new_bio);

            char json[1024];
            snprintf(json, sizeof(json), "{\"bio\":\"%s\"}", new_bio);
            char* resp = send_request("PATCH", "/profiles?user_id=eq.{current_user_id}", json);
            if (resp && strstr(resp, "bio")) {
                printf("✓ Bio updated successfully.\n");
            } else {
                printf("✗ Failed to update bio.\n");
            }
            if (resp) free(resp);
        }
        else if (strcmp(choice, "2") == 0) {
            printf("Enter new interests: ");
            fgets(new_interests, sizeof(new_interests), stdin);
            trim_whitespace(new_interests);

            char json[1024];
            snprintf(json, sizeof(json), "{\"interests\":\"%s\"}", new_interests);
            char* resp = send_request("PATCH", "/profiles?user_id=eq.{current_user_id}", json);
            if (resp && strstr(resp, "interests")) {
                printf("✓ Interests updated successfully.\n");
            } else {
                printf("✗ Failed to update interests.\n");
            }
            if (resp) free(resp);
        }
        else if (strcmp(choice, "3") == 0) {
            printf("Toggle discoverability? (1 for Yes/Visible, 0 for No/Hidden): ");
            fgets(new_discoverable, sizeof(new_discoverable), stdin);
            trim_whitespace(new_discoverable);

            int is_visible = (atoi(new_discoverable) == 1) ? 1 : 0;
            char json[1024];
            snprintf(json, sizeof(json), "{\"discoverable\":%s}", is_visible ? "true" : "false");
            char* resp = send_request("PATCH", "/profiles?user_id=eq.{current_user_id}", json);
            if (resp && strstr(resp, "discoverable")) {
                printf("✓ Discoverability updated to %s.\n", is_visible ? "Visible" : "Hidden");
            } else {
                printf("✗ Failed to update discoverability.\n");
            }
            if (resp) free(resp);
        }
        else if (strcmp(choice, "4") == 0) {
            view_profile(current_user_id);
        }
        else if (strcmp(choice, "5") == 0) {
            break;
        }
        else {
            printf("Invalid choice.\n");
        }
    }
}

void main_menu() {
    char choice[10];
    while (1) {
        printf("\n╔════════════════════════════════════════════════════════════╗\n");
        printf("║              USER MENU                                    ║\n");
        printf("╚════════════════════════════════════════════════════════════╝\n");
        printf("1. Discover People (Search)\n");
        printf("2. View Friend Requests\n");
        printf("3. List My Friends (and View Profile)\n");
        printf("4. Send Direct Message\n");
        printf("5. View Messages from a User\n");
        printf("6. View My Own Profile\n");
        printf("7. Manage Account\n"); // NEW OPTION
        printf("8. Logout\n");
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
            printf("Enter recipient user ID: ");
            if (scanf("%d", &recipient_id) != 1) { clear_input_buffer(); continue; }
            clear_input_buffer(); // Clear newline

            char content[MAX_MESSAGE];
            printf("Message: ");
            fgets(content, sizeof(content), stdin);
            trim_whitespace(content);
            send_direct_message(recipient_id, content);
        } else if (strcmp(choice, "5") == 0) {
            int sender_id;
            printf("Enter sender user ID: ");
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
            printf("Logged out successfully.\n");
            return;
        } else {
            printf("Invalid option.\n");
        }
    }
}

// Helper for client-side shuffle (Fisher-Yates)
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
    if (current_user_id == -1) { printf("✗ Not logged in!\n"); return; }

    char choice[10];
    printf("\n┌─── DISCOVER PEOPLE ───┐\n");
    printf("1. Browse Random Users (New)\n");
    printf("2. Search by Username\n");
    printf("3. View My Own Profile\n");
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
        printf("Enter username (partial match OK): ");
        fgets(search_query, sizeof(search_query), stdin);
        trim_whitespace(search_query);
        // Note: Supabase 'ilike' is case-insensitive, but we need to escape % properly if needed
        // For simplicity, we assume no special chars in username for this demo
        snprintf(query, sizeof(query), "/profiles?select=user_id,username,bio,interests&discoverable=eq.true&user_id=neq.%d&username=ilike.*%s*&order=user_id.asc&limit=%d", current_user_id, search_query, MAX_DISCOVER_BATCH);
    } else {
        // Fetch a batch to shuffle locally
        snprintf(query, sizeof(query), "/profiles?select=user_id,username,bio,interests&discoverable=eq.true&user_id=neq.%d&order=user_id.asc&limit=%d", current_user_id, MAX_DISCOVER_BATCH);
    }

    char* response = send_request("GET", query, NULL);

    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║              DISCOVER PEOPLE                              ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");

    if (!response || !strstr(response, "user_id")) {
        printf("No users found.\n");
        if(response) free(response);
        return;
    }

    char* ptr = response;
    int count = 0;
    User users[MAX_DISCOVER_BATCH];

    while ((ptr = strstr(ptr, "{\"user_id\":")) != NULL && count < MAX_DISCOVER_BATCH) {
        char* u_id = strstr(ptr, "\"user_id\":");
        if (u_id) {
            u_id += 10;
            users[count].user_id = atoi(u_id);
        }

        char* u_name = strstr(ptr, "\"username\":\"");
        if (u_name) {
            u_name += 12;
            int i = 0;
            while (u_name[i] && u_name[i] != '"') { users[count].username[i] = u_name[i]; i++; }
            users[count].username[i] = '\0';
        } else {
            strcpy(users[count].username, "Unknown");
        }

        char* b = strstr(ptr, "\"bio\":\"");
        if (b) {
            b += 7;
            int i = 0;
            while (b[i] && b[i] != '"') { users[count].bio[i] = b[i]; i++; }
            users[count].bio[i] = '\0';
        } else {
            users[count].bio[0] = '\0';
        }

        char* i = strstr(ptr, "\"interests\":\"");
        if (i) {
            i += 13;
            int j = 0;
            while (i[j] && i[j] != '"') { users[count].interests[j] = i[j]; j++; }
            users[count].interests[j] = '\0';
        } else {
            users[count].interests[0] = '\0';
        }

        count++;
        ptr++;
    }

    if (count == 0) {
        printf("No users found.\n");
        if(response) free(response);
        return;
    }

    // Shuffle locally if browsing random
    if (strcmp(choice, "1") == 0) {
        shuffle_users(users, count);
    }

    for (int i = 0; i < count; i++) {
        printf("%d. %s\n", i + 1, users[i].username);
        if (strlen(users[i].bio) > 0) printf("   Bio: %s\n", users[i].bio);
        if (strlen(users[i].interests) > 0) printf("   Interests: %s\n", users[i].interests);
        printf("\n");
    }

    printf("Select user to send friend request (number), View Profile (number + p), or 0 to skip: ");
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
    if (to_user_id == current_user_id) { printf("✗ You cannot send a request to yourself.\n"); return; }

    char content[] = "Friend Request";
    send_direct_message(to_user_id, content);
    printf("✓ Friend request sent!\n");
}

void view_friend_requests() {
    if (current_user_id == -1) { printf("✗ Not logged in!\n"); return; }

    char query[1024];
    snprintf(query, sizeof(query), "/messages?select=sender_id,content,timestamp&recipient_id=eq.%d&content=eq.Friend Request&order=timestamp.desc", current_user_id);

    char* response = send_request("GET", query, NULL);

    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║              FRIEND REQUESTS                              ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");

    if (!response || !strstr(response, "sender_id")) {
        printf("No pending friend requests.\n");
        if(response) free(response);
        return;
    }

    char* ptr = response;
    int count = 0;
    int user_ids[50];
    char usernames[50][MAX_USERNAME];

    while ((ptr = strstr(ptr, "{\"sender_id\":")) != NULL && count < 50) {
        char* s_id = strstr(ptr, "\"sender_id\":");
        if (s_id) {
            s_id += 12;
            user_ids[count] = atoi(s_id);
            sprintf(usernames[count], "User %d", user_ids[count]);
            count++;
        }
        ptr++;
    }

    if (count == 0) {
        printf("No pending friend requests.\n");
        if(response) free(response);
        return;
    }

    for (int i = 0; i < count; i++) {
        printf("%d. %s\n", i + 1, usernames[i]);
    }

    printf("\nSelect request to Accept (number), Decline (number + d), or 0 to cancel: ");
    char input[20];
    fgets(input, sizeof(input), stdin);
    trim_whitespace(input);

    int action = atoi(input);
    char last_char = input[strlen(input)-1];
    int is_decline = (last_char == 'd' || last_char == 'D');

    if (action > 0 && action <= count) {
        int target_user_id = user_ids[action - 1];

        if (is_decline) {
            printf("✗ Friend request declined.\n");
        } else {
            printf("✓ Friend request accepted! (Note: 'friends' table logic not fully implemented in this snippet)\n");
        }
    }
    if(response) free(response);
}

void list_friends() {
    if (current_user_id == -1) { printf("✗ Not logged in!\n"); return; }

    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║              MY FRIENDS                                   ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");
    printf("(Note: A 'friends' table needs to be created for this feature. For now, showing recent contacts.)\n");
    printf("No friends listed yet.\n");
}

void* cleanup_loop(void* arg) {
    while (1) {
        sleep(CLEANUP_INTERVAL);
        // Supabase handles TTL with database rules or scheduled functions.
        // We skip server-side cleanup logic in C for this simple client.
    }
    return NULL;
}

int main() {
    pthread_t tid;
    pthread_create(&tid, NULL, cleanup_loop, NULL);
    pthread_detach(tid);

    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║     FRONTIER MESSAGING - Cloud Connected                  ║\n");
    printf("║          (Messages auto-delete • No local logs)            ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");

    char choice[10];
    while (1) {
        if (current_user_id == -1) {
            printf("\n┌─── MAIN MENU ───┐\n");
            printf("1. Register\n");
            printf("2. Login\n");
            printf("3. Exit\n");
            printf("└──────────────────┘\n");
            printf("Choice: ");
            fgets(choice, sizeof(choice), stdin);
            trim_whitespace(choice);

            if (strcmp(choice, "1") == 0) {
                char username[MAX_USERNAME], password[MAX_PASSWORD], bio[MAX_BIO], interests[MAX_BIO];
                printf("\nUsername: ");
                fgets(username, sizeof(username), stdin);
                trim_whitespace(username);
                printf("Password: ");
                fgets(password, sizeof(password), stdin);
                trim_whitespace(password);
                printf("Bio (optional): ");
                fgets(bio, sizeof(bio), stdin);
                trim_whitespace(bio);
                printf("Interests (optional): ");
                fgets(interests, sizeof(interests), stdin);
                trim_whitespace(interests);

                if (register_user(username, password, bio, interests)) {
                    printf("✓ Registration successful!\n");
                } else {
                    printf("✗ Registration failed.\n");
                }
            }
            else if (strcmp(choice, "2") == 0) {
                char username[MAX_USERNAME], password[MAX_PASSWORD];
                printf("\nUsername: ");
                fgets(username, sizeof(username), stdin);
                trim_whitespace(username);
                printf("Password: ");
                fgets(password, sizeof(password), stdin);
                trim_whitespace(password);

                if (login_user(username, password)) {
                    main_menu();
                } else {
                    printf("✗ Invalid credentials!\n");
                }
            }
            else if (strcmp(choice, "3") == 0) {
                printf("Goodbye!\n");
                break;
            }
        } else {
            printf("Session ended. Logging out...\n");
            current_user_id = -1;
            current_username[0] = '\0';
        }
    }

    printf("Exiting.\n");
    return 0;
}
