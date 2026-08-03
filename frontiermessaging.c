#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <openssl/sha.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <ctype.h>

#define DB_NAME "ephemeral_messages.db"
#define MESSAGE_TTL_HOURS 2
#define PROFILE_TTL_HOURS 24
#define MAX_USERNAME 50
#define MAX_PASSWORD 100
#define MAX_BIO 256
#define MAX_MESSAGE 512
#define MAX_GROUP_NAME 100
#define CLEANUP_INTERVAL 300

typedef struct {
    int user_id;
    char username[MAX_USERNAME];
    char bio[MAX_BIO];
    char interests[MAX_BIO];
    int discoverable;
} User;

typedef struct {
    int group_id;
    char group_name[MAX_GROUP_NAME];
    int creator_id;
    char description[MAX_BIO];
    int is_permanent;
} Group;

// Global variables
sqlite3 *db;
int current_user_id = -1;
char current_username[MAX_USERNAME] = "";

// Function Prototypes
void init_db();
void start_cleanup_thread();
void* cleanup_loop(void* arg);
void delete_expired_messages();
void delete_inactive_profiles();
void delete_expired_groups();
char* hash_password(const char* password);
int register_user(const char* username, const char* password, const char* bio, const char* interests);
int login_user(const char* username, const char* password);
void discover_people();
void send_friend_request(int to_user_id);
void view_friend_requests();
void list_friends();
void send_direct_message(int recipient_id, const char* content);
void view_direct_messages(int sender_id);
void main_menu();
void trim_whitespace(char* str);
void delete_database();

// --- FUNCTION DEFINITIONS ---

void init_db() {
    if (sqlite3_open(DB_NAME, &db) != SQLITE_OK) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        exit(1);
    }

    const char* sql =
    "CREATE TABLE IF NOT EXISTS profiles ("
    "   user_id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "   username TEXT UNIQUE NOT NULL,"
    "   password_hash TEXT NOT NULL,"
    "   bio TEXT DEFAULT '',"
    "   interests TEXT DEFAULT '',"
    "   created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "   last_alive_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "   discoverable INTEGER DEFAULT 1"
    ");"
    "CREATE TABLE IF NOT EXISTS messages ("
    "   id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "   sender_id INTEGER NOT NULL,"
    "   recipient_id INTEGER,"
    "   content TEXT NOT NULL,"
    "   timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,"
    "   FOREIGN KEY(sender_id) REFERENCES profiles(user_id),"
    "   FOREIGN KEY(recipient_id) REFERENCES profiles(user_id)"
    ");"
    "CREATE TABLE IF NOT EXISTS groups ("
    "   group_id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "   group_name TEXT NOT NULL,"
    "   creator_id INTEGER NOT NULL,"
    "   description TEXT DEFAULT '',"
    "   created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "   expires_at TIMESTAMP,"
    "   is_permanent INTEGER DEFAULT 0,"
    "   FOREIGN KEY (creator_id) REFERENCES profiles(user_id)"
    ");"
    "CREATE TABLE IF NOT EXISTS group_members ("
    "   member_id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "   group_id INTEGER NOT NULL,"
    "   user_id INTEGER NOT NULL,"
    "   joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "   FOREIGN KEY(group_id) REFERENCES groups(group_id),"
    "   FOREIGN KEY(user_id) REFERENCES profiles(user_id),"
    "   UNIQUE(group_id, user_id)"
    ");"
    "CREATE TABLE IF NOT EXISTS friend_requests ("
    "   request_id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "   from_user_id INTEGER NOT NULL,"
    "   to_user_id INTEGER NOT NULL,"
    "   status TEXT DEFAULT 'pending',"
    "   created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "   FOREIGN KEY (from_user_id) REFERENCES profiles(user_id),"
    "   FOREIGN KEY (to_user_id) REFERENCES profiles(user_id),"
    "   UNIQUE(from_user_id, to_user_id)"
    ");"
    "CREATE TABLE IF NOT EXISTS friends ("
    "   user_id1 INTEGER NOT NULL,"
    "   user_id2 INTEGER NOT NULL,"
    "   since DATETIME DEFAULT CURRENT_TIMESTAMP,"
    "   PRIMARY KEY(user_id1, user_id2),"
    "   FOREIGN KEY(user_id1) REFERENCES profiles(user_id),"
    "   FOREIGN KEY(user_id2) REFERENCES profiles(user_id)"
    ");";

    char* errMsg = 0;
    if (sqlite3_exec(db, sql, 0, 0, &errMsg) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", errMsg);
        sqlite3_free(errMsg);
    }
}

void send_direct_message(int recipient_id, const char* content) {
    if (current_user_id == -1) {
        printf("✗ Not logged in!\n");
        return;
    }
    sqlite3_stmt* stmt;
    const char* sql = "INSERT INTO messages (sender_id, recipient_id, content, timestamp) VALUES (?, ?, ?, datetime('now'));";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, current_user_id);
        sqlite3_bind_int(stmt, 2, recipient_id);
        sqlite3_bind_text(stmt, 3, content, -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) == SQLITE_DONE) {
            printf("✓ Message sent!\n");
        } else {
            printf("✗ Failed to send message: %s\n", sqlite3_errmsg(db));
        }
    }
    sqlite3_finalize(stmt);
}

void view_direct_messages(int sender_id) {
    if (current_user_id == -1) {
        printf("✗ Not logged in!\n");
        return;
    }

    sqlite3_stmt* stmt;
    const char* sql = "SELECT id, content, timestamp FROM messages WHERE sender_id = ? AND recipient_id = ? ORDER BY timestamp ASC;";

    sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    sqlite3_bind_int(stmt, 1, sender_id);
    sqlite3_bind_int(stmt, 2, current_user_id);

    printf("\n--- Messages from User %d ---\n", sender_id);

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int msg_id = sqlite3_column_int(stmt, 0);
        const char* content = (const char*)sqlite3_column_text(stmt, 1);
        const char* time = (const char*)sqlite3_column_text(stmt, 2);

        printf("[%s] %s\n", time, content);
        count++;

        char sql_del[256];
        snprintf(sql_del, sizeof(sql_del), "DELETE FROM messages WHERE id = %d;", msg_id);
        sqlite3_exec(db, sql_del, 0, 0, 0);
    }

    if (count == 0) {
        printf("No messages found.\n");
    }

    sqlite3_finalize(stmt);
}

void main_menu() {
    char choice[10];

    while (1) {
        printf("\n╔════════════════════════════════════════════════════════════╗\n");
        printf("║              USER MENU                                    ║\n");
        printf("╚════════════════════════════════════════════════════════════╝\n");
        printf("1. Discover People (Search)\n");
        printf("2. View Friend Requests\n");
        printf("3. List My Friends\n");
        printf("4. Send Direct Message\n");
        printf("5. View Messages from a User\n");
        printf("6. Logout\n");
        printf("7. ⚠️  DELETE DATABASE (Wipe All Data) ⚠️\n");
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
            scanf("%d", &recipient_id);
            getchar(); // consume newline
            char content[MAX_MESSAGE];
            printf("Message: ");
            fgets(content, sizeof(content), stdin);
            trim_whitespace(content);
            send_direct_message(recipient_id, content);
        } else if (strcmp(choice, "5") == 0) {
            int sender_id;
            printf("Enter sender user ID: ");
            scanf("%d", &sender_id);
            getchar(); // consume newline
            view_direct_messages(sender_id);
        } else if (strcmp(choice, "6") == 0) {
            current_user_id = -1;
            current_username[0] = '\0';
            printf("Logged out successfully.\n");
            return;
        } else if (strcmp(choice, "7") == 0) {
            delete_database();
            return; // Exit menu after deletion
        } else {
            printf("Invalid option.\n");
        }
    }
}

void delete_database() {
    char confirm[10];
    printf("⚠️  WARNING: This will permanently delete ALL data (users, messages, friends). ⚠️\n");
    printf("Type 'DELETE' to confirm: ");
    fgets(confirm, sizeof(confirm), stdin);
    trim_whitespace(confirm);

    if (strcmp(confirm, "DELETE") == 0) {
        sqlite3_close(db);
        remove(DB_NAME);
        printf("✓ Database deleted successfully.\n");
        // Re-initialize empty database
        init_db();
    } else {
        printf("✗ Deletion cancelled.\n");
    }
}

int main() {
    init_db();
    start_cleanup_thread();

    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║     EPHEMERAL MESSENGER - Terminal Based Chat App       ║\n");
    printf("║          (Messages auto-delete • No logs saved)          ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");

    char choice[10];
    while (1) {
        if (current_user_id == -1) {
            // --- NOT LOGGED IN MENU ---
            printf("\n┌─── MAIN MENU ───┐\n");
            printf("1. Register\n");
            printf("2. Login\n");
            printf("3. Exit\n");
            printf("4. ⚠️  DELETE DATABASE (Wipe All Data) ⚠️\n");
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

                int result = register_user(username, password, bio, interests);
                if (result == 1) {
                    printf("✓ Registration successful!\n");
                } else if (result == 0) {
                    printf("✗ Username already exists!\n");
                } else {
                    printf("✗ Registration failed due to a database error.\n");
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
                    printf("✓ Logged in as '%s'\n", current_username);
                    main_menu();
                } else {
                    printf("✗ Invalid credentials!\n");
                }
            }
            else if (strcmp(choice, "3") == 0) {
                printf("Goodbye!\n");
                break;
            }
            else if (strcmp(choice, "4") == 0) {
                delete_database();
            }
        } else {
            printf("Session ended. Logging out...\n");
            current_user_id = -1;
            current_username[0] = '\0';
        }
    }

    sqlite3_close(db);
    printf("Database closed. Exiting.\n");
    return 0;
}

void start_cleanup_thread() {
    pthread_t tid;
    pthread_create(&tid, NULL, cleanup_loop, NULL);
    pthread_detach(tid);
}

void* cleanup_loop(void* arg) {
    while (1) {
        sleep(CLEANUP_INTERVAL);
        delete_expired_messages();
        delete_inactive_profiles();
        delete_expired_groups();
    }
    return NULL;
}

void delete_expired_messages() {
    char sql[256];
    time_t cutoff = time(NULL) - (MESSAGE_TTL_HOURS * 3600);
    struct tm* tm_info = localtime(&cutoff);
    char cutoff_time[50];
    strftime(cutoff_time, sizeof(cutoff_time), "%Y-%m-%d %H:%M:%S", tm_info);

    snprintf(sql, sizeof(sql), "DELETE FROM messages WHERE created_at < '%s';", cutoff_time);
    sqlite3_exec(db, sql, 0, 0, 0);
}

void delete_inactive_profiles() {
    char sql[256];
    time_t cutoff = time(NULL) - (PROFILE_TTL_HOURS * 3600);
    struct tm* tm_info = localtime(&cutoff);
    char cutoff_time[50];
    strftime(cutoff_time, sizeof(cutoff_time), "%Y-%m-%d %H:%M:%S", tm_info);

    snprintf(sql, sizeof(sql), "DELETE FROM profiles WHERE last_alive_at < '%s';", cutoff_time);
    sqlite3_exec(db, sql, 0, 0, 0);
}

void delete_expired_groups() {
    sqlite3_exec(db, "DELETE FROM groups WHERE is_permanent = 0 AND expires_at < CURRENT_TIMESTAMP;", 0, 0, 0);
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
    int len = strlen(str);
    if (len > 0 && str[len - 1] == '\n') {
        str[len - 1] = '\0';
    }
}

int register_user(const char* username, const char* password, const char* bio, const char* interests) {
    const char* hash = hash_password(password);
    sqlite3_stmt* stmt;

    const char* sql = "INSERT INTO profiles (username, password_hash, bio, interests) VALUES (?, ?, ?, ?);";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, hash, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, bio, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, interests, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_DONE) {
        return 1; // Success
    } else {
        // Check for unique constraint violation (username exists)
        if (sqlite3_errcode(db) == SQLITE_CONSTRAINT_UNIQUE) {
            return 0; // Username exists
        }
        // Handle other errors (like NOT NULL constraint)
        fprintf(stderr, "Registration failed: %s\n", sqlite3_errmsg(db));
        return -1;
    }
}

int login_user(const char* username, const char* password) {
    const char* hash = hash_password(password);
    sqlite3_stmt* stmt;

    const char* sql = "SELECT user_id FROM profiles WHERE username = ? AND password_hash = ?;";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, hash, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        current_user_id = sqlite3_column_int(stmt, 0);
        strcpy(current_username, username);

        // Update last_alive_at
        char sql_update[256];
        snprintf(sql_update, sizeof(sql_update), "UPDATE profiles SET last_alive_at = CURRENT_TIMESTAMP WHERE user_id = %d;", current_user_id);
        sqlite3_exec(db, sql_update, 0, 0, 0);

        sqlite3_finalize(stmt);
        return 1;
    }

    sqlite3_finalize(stmt);
    return 0;
}

void discover_people() {
    if (current_user_id == -1) {
        printf("✗ Not logged in!\n");
        return;
    }

    sqlite3_stmt* stmt;
    char search_query[MAX_USERNAME];
    int use_search = 0;

    printf("\n┌─── DISCOVER PEOPLE ───┐\n");
    printf("1. Browse Random Users\n");
    printf("2. Search by Username\n");
    printf("Choice: ");

    char choice[10];
    fgets(choice, sizeof(choice), stdin);
    trim_whitespace(choice);

    if (strcmp(choice, "2") == 0) {
        use_search = 1;
        printf("Enter username (partial match OK): ");
        fgets(search_query, sizeof(search_query), stdin);
        trim_whitespace(search_query);
    }

    const char* sql;
    if (use_search) {
        sql = "SELECT user_id, username, bio, interests FROM profiles "
        "WHERE discoverable = 1 AND user_id != ? AND username LIKE ? "
        "ORDER BY RANDOM() LIMIT 10;";
    } else {
        sql = "SELECT user_id, username, bio, interests FROM profiles "
        "WHERE discoverable = 1 AND user_id != ? ORDER BY RANDOM() LIMIT 10;";
    }

    sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    sqlite3_bind_int(stmt, 1, current_user_id);

    if (use_search) {
        char search_pattern[MAX_USERNAME + 2];
        snprintf(search_pattern, sizeof(search_pattern), "%%%s%%", search_query);
        sqlite3_bind_text(stmt, 2, search_pattern, -1, SQLITE_STATIC);
    }

    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║              DISCOVER PEOPLE                              ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");

    int count = 0;
    User users[10];

    while (sqlite3_step(stmt) == SQLITE_ROW && count < 10) {
        users[count].user_id = sqlite3_column_int(stmt, 0);
        strcpy(users[count].username, (const char*)sqlite3_column_text(stmt, 1));
        strcpy(users[count].bio, (const char*)sqlite3_column_text(stmt, 2) ?: "");
        strcpy(users[count].interests, (const char*)sqlite3_column_text(stmt, 3) ?: "");
        count++;
    }
    sqlite3_finalize(stmt);

    if (count == 0) {
        printf("No users found matching your criteria.\n");
        return;
    }

    for (int i = 0; i < count; i++) {
        printf("%d. %s\n", i + 1, users[i].username);
        if (strlen(users[i].bio) > 0) printf("   Bio: %s\n", users[i].bio);
        if (strlen(users[i].interests) > 0) printf("   Interests: %s\n", users[i].interests);
        printf("\n");
    }

    printf("Select user to send friend request (or 0 to skip): ");
    char choice_user[10];
    fgets(choice_user, sizeof(choice_user), stdin);
    trim_whitespace(choice_user);

    int idx = atoi(choice_user);
    if (idx > 0 && idx <= count) {
        send_friend_request(users[idx - 1].user_id);
    }
}

void send_friend_request(int to_user_id) {
    if (to_user_id == current_user_id) {
        printf("✗ You cannot send a request to yourself.\n");
        return;
    }

    char sql[300];
    // Use a transaction or ignore conflict if already exists
    snprintf(sql, sizeof(sql),
             "INSERT OR IGNORE INTO friend_requests (from_user_id, to_user_id, status) VALUES (%d, %d, 'pending');",
             current_user_id, to_user_id);

    int rc = sqlite3_exec(db, sql, 0, 0, 0);
    if (rc == SQLITE_OK) {
        printf("✓ Friend request sent!\n");
    } else {
        printf("✗ Could not send request. (Maybe already sent?)\n");
    }
}

void view_friend_requests() {
    if (current_user_id == -1) {
        printf("✗ Not logged in!\n");
        return;
    }

    sqlite3_stmt* stmt;
    const char* sql = "SELECT request_id, from_user_id, username FROM friend_requests "
    "JOIN profiles ON friend_requests.from_user_id = profiles.user_id "
    "WHERE to_user_id = ? AND status = 'pending';";

    sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    sqlite3_bind_int(stmt, 1, current_user_id);

    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║              FRIEND REQUESTS                              ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");

    int count = 0;
    int request_ids[50];
    int user_ids[50];
    char usernames[50][MAX_USERNAME];

    while (sqlite3_step(stmt) == SQLITE_ROW && count < 50) {
        request_ids[count] = sqlite3_column_int(stmt, 0);
        user_ids[count] = sqlite3_column_int(stmt, 1);
        strcpy(usernames[count], (const char*)sqlite3_column_text(stmt, 2));
        count++;
    }
    sqlite3_finalize(stmt);

    if (count == 0) {
        printf("No pending friend requests.\n");
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
    int is_decline = (strlen(input) > 1 && input[strlen(input) - 1] == 'd');

    if (action > 0 && action <= count) {
        int target_request_id = request_ids[action - 1];
        int target_user_id = user_ids[action - 1];

        if (is_decline) {
            char sql_del[256];
            snprintf(sql_del, sizeof(sql_del), "DELETE FROM friend_requests WHERE request_id = %d;", target_request_id);
            sqlite3_exec(db, sql_del, 0, 0, 0);
            printf("✗ Friend request declined.\n");
        } else {
            // Accept
            char sql_update[256];
            snprintf(sql_update, sizeof(sql_update), "UPDATE friend_requests SET status = 'accepted' WHERE request_id = %d;", target_request_id);
            sqlite3_exec(db, sql_update, 0, 0, 0);

            // Insert friendship (both ways)
            char sql_friend[256];
            snprintf(sql_friend, sizeof(sql_friend),
                     "INSERT OR IGNORE INTO friends (user_id1, user_id2) VALUES (%d, %d);",
                     current_user_id, target_user_id);
            char sql_friend_rev[256];
            snprintf(sql_friend_rev, sizeof(sql_friend_rev),
                     "INSERT OR IGNORE INTO friends (user_id1, user_id2) VALUES (%d, %d);",
                     target_user_id, current_user_id);

            sqlite3_exec(db, sql_friend, 0, 0, 0);
            sqlite3_exec(db, sql_friend_rev, 0, 0, 0);

            printf("✓ Friend request accepted!\n");
        }
    }
}

void list_friends() {
    if (current_user_id == -1) {
        printf("✗ Not logged in!\n");
        return;
    }

    sqlite3_stmt* stmt;
    const char* sql = "SELECT DISTINCT p.username FROM friends "
    "JOIN profiles p ON (friends.user_id1 = ? AND p.user_id = friends.user_id2) "
    "OR (friends.user_id2 = ? AND p.user_id = friends.user_id1) "
    "WHERE friends.user_id1 = ? OR friends.user_id2 = ?;";

    sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    sqlite3_bind_int(stmt, 1, current_user_id);
    sqlite3_bind_int(stmt, 2, current_user_id);
    sqlite3_bind_int(stmt, 3, current_user_id);
    sqlite3_bind_int(stmt, 4, current_user_id);

    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║              MY FRIENDS                                   ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        printf("%d. %s\n", count + 1, sqlite3_column_text(stmt, 0));
        count++;
    }

    if (count == 0) {
        printf("You have no friends yet.\n");
    }

    sqlite3_finalize(stmt);
}

// Helper to check if user is friend (optional for future use)
int is_friend(int user_id) {
    sqlite3_stmt* stmt;
    const char* sql = "SELECT 1 FROM friends WHERE (user_id1 = ? AND user_id2 = ?) OR (user_id1 = ? AND user_id2 = ?);";
    sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    sqlite3_bind_int(stmt, 1, current_user_id);
    sqlite3_bind_int(stmt, 2, user_id);
    sqlite3_bind_int(stmt, 3, user_id);
    sqlite3_bind_int(stmt, 4, current_user_id);

    int result = (sqlite3_step(stmt) == SQLITE_ROW) ? 1 : 0;
    sqlite3_finalize(stmt);
    return result;
}
