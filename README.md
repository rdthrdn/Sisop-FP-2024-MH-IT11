# Sisop-FP-2024-MH-IT11
Dikerjakan Oleh:
|Nama|NRP |
|--|--|
|Ricko Mianto Jaya Saputra|5027221031|
|Raditya Hardian Santoso|5027231033|
|Rafi Afnaan Fathurahman|5027231040|


## Final Project Overview
Pada final project kali ini kami diminta untuk membuat sebuah implementasi chat server berbasis socket dengan nama DiscorIT, dimana pada project ini terdiri dari tiga kode yaitu discorit.c, server.c, dan monitor.c. discorit.c berfungsi sebagai client untuk mengirim request, server.c berfungsi untuk menerima dan merespon request, dan monitor.c berfungsi untuk menampilkan chat secara real-time.

## Tree
Tree yang kami lampirkan ini berdasarkan fungsionalitas fungsionalitas yang telah kami coba di kode kami
![Screenshot 2024-06-28 162630](https://github.com/rdthrdn/Sisop-FP-2024-MH-IT11/assets/137570361/35c72373-b03e-45a0-818f-debfd5beaaca)

## Kode

### discorit.c
```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <crypt.h>

#define NETWORK_PORT 9090
#define MESSAGE_SIZE 2048

typedef struct {
    int socket_descriptor;
    struct sockaddr_in server_address;
} NetworkConnection;

typedef struct {
    char identifier[MESSAGE_SIZE];
    char group[MESSAGE_SIZE];
    char subgroup[MESSAGE_SIZE];
} SessionInfo;

void process_user_input(NetworkConnection *conn, const char *user_id);
void display_prompt(const SessionInfo *session);
int establish_connection(NetworkConnection *conn);
void execute_command(NetworkConnection *conn, SessionInfo *session, char *input);
void handle_server_response(NetworkConnection *conn, SessionInfo *session, char *response);

int main(int argc, char *argv[]) {
    if (argc < 4 || (strcmp(argv[1], "REGISTER") != 0 && strcmp(argv[1], "LOGIN") != 0) || strcmp(argv[3], "-p") != 0) {
        fprintf(stderr, "Usage: %s REGISTER/LOGIN username -p password\n", argv[0]);
        return EXIT_FAILURE;
    }

    NetworkConnection conn;
    if (establish_connection(&conn) != 0) {
        return EXIT_FAILURE;
    }

    char message[MESSAGE_SIZE] = {0};
    snprintf(message, sizeof(message), "%s %s -s %s", argv[1], argv[2], argv[4]);
    send(conn.socket_descriptor, message, strlen(message), 0);

    memset(message, 0, sizeof(message));
    read(conn.socket_descriptor, message, MESSAGE_SIZE);
    printf("%s\n", message);

    if (strcmp(argv[1], "LOGIN") == 0 && strstr(message, "berhasil login")) {
        process_user_input(&conn, argv[2]);
    }

    close(conn.socket_descriptor);
    return EXIT_SUCCESS;
}

int establish_connection(NetworkConnection *conn) {
    if ((conn->socket_descriptor = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        return -1;
    }

    conn->server_address.sin_family = AF_INET;
    conn->server_address.sin_port = htons(NETWORK_PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &conn->server_address.sin_addr) <= 0) {
        perror("Invalid address or address not supported");
        return -1;
    }

    if (connect(conn->socket_descriptor, (struct sockaddr *)&conn->server_address, sizeof(conn->server_address)) < 0) {
        perror("Connection attempt failed");
        return -1;
    }

    return 0;
}

void display_prompt(const SessionInfo *session) {
    if (session->subgroup[0] != '\0') {
        printf("[%s/%s/%s] ", session->identifier, session->group, session->subgroup);
    } else if (session->group[0] != '\0') {
        printf("[%s/%s] ", session->identifier, session->group);
    } else {
        printf("[%s] ", session->identifier);
    }
    fflush(stdout);
}

void process_user_input(NetworkConnection *conn, const char *user_id) {
    char input[MESSAGE_SIZE];
    SessionInfo session = {0};
    strcpy(session.identifier, user_id);

    while (1) {
        display_prompt(&session);
        fgets(input, MESSAGE_SIZE, stdin);
        input[strcspn(input, "\n")] = 0;

        execute_command(conn, &session, input);

        if (strcmp(input, "EXIT") == 0 && session.group[0] == '\0' && session.subgroup[0] == '\0') {
            break;
        }
    }
}

void execute_command(NetworkConnection *conn, SessionInfo *session, char *input) {
    char command[MESSAGE_SIZE];
    sscanf(input, "%s", command);

    if (strcmp(command, "JOIN") == 0) {
        char target[MESSAGE_SIZE];
        sscanf(input, "%*s %s", target);
        snprintf(input, MESSAGE_SIZE, "JOIN %s", target);
    }

    send(conn->socket_descriptor, input, strlen(input), 0);

    char response[MESSAGE_SIZE] = {0};
    int bytes_received = read(conn->socket_descriptor, response, MESSAGE_SIZE);
    response[bytes_received] = '\0';

    handle_server_response(conn, session, response);
}

void handle_server_response(NetworkConnection *conn, SessionInfo *session, char *response) {
    if (strstr(response, "bergabung dengan channel")) {
        char *group_name = strstr(response, "bergabung dengan channel ") + strlen("bergabung dengan channel ");
        strcpy(session->group, group_name);
    } else if (strstr(response, "bergabung dengan room")) {
        char *subgroup_name = strstr(response, "bergabung dengan room ") + strlen("bergabung dengan room ");
        strcpy(session->subgroup, subgroup_name);
    } else if (strstr(response, "Keluar Channel")) {
        memset(session->group, 0, sizeof(session->group));
    } else if (strstr(response, "Keluar Room")) {
        memset(session->subgroup, 0, sizeof(session->subgroup));
    } else if (strstr(response, "berhasil diubah menjadi")) {
        char *new_id = strstr(response, "berhasil diubah menjadi ") + strlen("berhasil diubah menjadi ");
        strcpy(session->identifier, new_id);
    } else if (strstr(response, "nama room berubah menjadi")) {
        char *new_subgroup = strstr(response, "nama room berubah menjadi ") + strlen("nama room berubah menjadi ");
        strcpy(session->subgroup, new_subgroup);
    } else if (strstr(response, "nama channel berubah menjadi")) {
        char *new_group = strstr(response, "nama channel berubah menjadi ") + strlen("nama channel berubah menjadi ");
        strcpy(session->group, new_group);
    }

    printf("%s\n", response);
}
```
#### Fungsi-fungsi Utama:

> **process_user_input(NetworkConnection conn, const char user_id)**:

>> Deskripsi: Memproses input pengguna yang terhubung melalui conn dan terkait dengan user_id.
>> Parameter:
>>> conn: Koneksi jaringan.
>>> user_id: ID pengguna.
>> Detail: Fungsi ini kemungkinan melakukan komunikasi melalui jaringan berdasarkan input yang diberikan pengguna.

> **initialize_connection(NetworkConnection conn)**:

>> Deskripsi: Menginisialisasi koneksi jaringan.
>> Parameter:
>>> conn: Koneksi jaringan.
>> Detail: Membuat koneksi ke server menggunakan alamat dan port yang telah ditentukan.

> **send_message(NetworkConnection conn, const char message)**:

>> Deskripsi: Mengirim pesan melalui koneksi jaringan.
>> Parameter:
>>> conn: Koneksi jaringan.
>>> message: Pesan yang akan dikirim.
>> Detail: Fungsi ini menggunakan soket untuk mengirim pesan ke server.

> **receive_message(NetworkConnection conn, char buffer, size_t size)**:

>> Deskripsi: Menerima pesan dari koneksi jaringan.
>> Parameter:
>>> conn: Koneksi jaringan.
>>> buffer: Buffer untuk menyimpan pesan yang diterima.
>>> size: Ukuran buffer.
>> Detail: Fungsi ini membaca data dari soket dan menyimpannya ke dalam buffer.

### server.c
```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <crypt.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <time.h>
#include <stdbool.h>
#include <dirent.h>
#include <signal.h>

#define PORT 9090
#define BUF_SIZE 2048
#define MAX_CLIENTS 100
#define USER_FILE "/home/honque/sisop/fp/new/DiscorIT/users.csv"
#define DISCORIT_DIR "/home/honque/sisop/fp/new/DiscorIT"
#define CHANNEL_FILE "/home/honque/sisop/fp/new/DiscorIT/channels.csv"

typedef struct {
    int logged_in;
    int user_id;
    char username[BUF_SIZE];
    char role[BUF_SIZE];
    int in_channel;
    char current_channel[BUF_SIZE];
    int in_room;
    char current_room[BUF_SIZE];
} Session;

typedef struct {
    int logged_in;
} monitorSession;

typedef struct {
    int socket;
    bool is_monitor;
} Client;

Client clients[MAX_CLIENTS] = {0};
int client_count = 0;

void *manage_client(void *arg);
char *bcrypt(const char *password);
void display_all_channel(int socket);
void create_channel(int socket, const char *username, int id, const char *channel_name, const char *key);
void modify_channel(int socket, const char *username, const char *channel_name, const char *new_channel_name);
void delete_channel(int socket, const char *channel_name);
void enter_channel(int socket, const char *username, const char *channel, int id,const char *key);
void display_all_room(int socket, const char *channel);
void create_room(int socket, const char *username, const char *channel, const char *room);
void modify_room(int socket, const char *username, const char *channel, const char *room, const char *new_room);
void delete_room(int socket, const char *channel, const char *room, const char *username);
void delete_room_exists(int socket, const char *channel, const char *username);
void enter_room(int socket, const char *username, const char *channel, const char *room);
void display_all_user(int socket);
void display_all_channel_user(int socket, const char *channel);
void remove_user(int socket, const char *username);
void send_chat(int socket, const char *channel, const char *room, const char *username, const char *message);
void modify_chat(int socket, const char *channel, const char *room, const char *username, int id_chat, const char *new_message);
void delete_chat(int socket, const char *channel, const char *room, int id_chat);
void view_chat(int socket, const char *channel, const char *room);

// Remove Directory
int remove_directory(const char *path) {
    DIR *d = opendir(path);
    size_t path_len = strlen(path);
    int r = -1;

    if (d) {
        struct dirent *p;
        r = 0;
        while (!r && (p = readdir(d))) {
            int r2 = -1;
            char *buf;
            size_t len;

            if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, ".."))
                continue;

            len = path_len + strlen(p->d_name) + 2;
            buf = malloc(len);

            if (buf) {
                struct stat statbuf;
                snprintf(buf, len, "%s/%s", path, p->d_name);

                if (!stat(buf, &statbuf)) {
                    if (S_ISDIR(statbuf.st_mode))
                        r2 = remove_directory(buf);
                    else
                        r2 = unlink(buf);
                }
                free(buf);
            }
            r = r2;
        }
        closedir(d);
    }
    if (!r)
        r = rmdir(path);
    return r;
}

// Log Message to a user.log
void log_action(const char *channel_name, const char *event) {
    char log_file_path[BUF_SIZE];
    snprintf(log_file_path, sizeof(log_file_path), "%s/%s/admin/user.log", DISCORIT_DIR, channel_name);
    FILE *log_file = fopen(log_file_path, "a");
    if (!log_file) {
        perror("fopen");
        return;
    }

    char timestamp[BUF_SIZE];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "[%d/%m/%Y %H:%M:%S]", t);
    fprintf(log_file, "%s %s\n", timestamp, event);
    fclose(log_file);
}

void daemonize() {
    pid_t pid;

    // Fork the parent process
    //printf("Forking the process...\n");
    pid = fork();

    if (pid < 0) {
        perror("Fork failed");
        exit(EXIT_FAILURE);
    }

    // Terminate the parent process
    if (pid > 0) {
        //printf("Exiting parent process...\n");
        exit(EXIT_SUCCESS);
    }

    // On success: the child process becomes the session leader
    //printf("Setting session leader...\n");
    if (setsid() < 0) {
        perror("setsid failed");
        exit(EXIT_FAILURE);
    }

    // Ignore signal sent from child to parent process
    signal(SIGCHLD, SIG_IGN);

    // Fork off for the second time
    //printf("Forking again...\n");
    pid = fork();

    if (pid < 0) {
        perror("Fork failed");
        exit(EXIT_FAILURE);
    }

    // Terminate the parent process
    if (pid > 0) {
        //printf("Exiting parent process...\n");
        exit(EXIT_SUCCESS);
    }

    // Set new file permissions
    //printf("Setting file permissions...\n");
    umask(0);

    // Change the working directory to the root directory
    //printf("Changing working directory...\n");
    if (chdir("/") < 0) {
        perror("chdir failed");
        exit(EXIT_FAILURE);
    }
    
    open("/dev/null", O_RDWR); // stdin
    dup(0); // stdout
    dup(0); // stderr
}

int main() {
    daemonize();

    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    while (1) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            continue;
        }
        pthread_t thread_id;
        pthread_create(&thread_id, NULL, manage_client, (void *)&new_socket);
    }
    return 0;
}

void send_to_monitor(const char *message) {
    for (int i = 0; i < client_count; i++) {
        if (clients[i].socket != 0 && clients[i].is_monitor) {
            send(clients[i].socket, message, strlen(message), 0);
        }
    }
}

void close_monitor_sessions() {
    for (int i = 0; i < client_count; i++) {
        if (clients[i].socket != 0 && clients[i].is_monitor) {
            close(clients[i].socket);
            clients[i].socket = 0;
            clients[i].is_monitor = false;
            client_count--;
        }
    }
}

void *manage_client(void *arg) {
    int socket = *(int *)arg;
    char buffer[BUF_SIZE];
    int bytes_read;
    Session session = {0};
    monitorSession monitor_session = {0};
    int client_index = -1;

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket == 0) {
            clients[i].socket = socket;
            client_index = i;
            client_count++;
            break;
        }
    }

    while ((bytes_read = read(socket, buffer, BUF_SIZE)) > 0) {
        buffer[bytes_read] = '\0';
        char command[BUF_SIZE], username[BUF_SIZE], password[BUF_SIZE];
        sscanf(buffer, "%s %s -p %s", command, username, password);

        if (strcmp(command, "REGISTER") == 0) {
            if (register_user(username, password)) {
                snprintf(buffer, sizeof(buffer), "%s berhasil register", username);
            } else {
                snprintf(buffer, sizeof(buffer), "%s sudah terdaftar", username);
            }
        } else if (strcmp(command, "LOGIN") == 0) {
            if (login_user(username, password, &session)) {
                snprintf(buffer, sizeof(buffer), "%s berhasil login", username);
            } else {
                snprintf(buffer, sizeof(buffer), "Login gagal");
            }
        } else if (strcmp(command, "LOGIN_MONITOR") == 0) {
            if (login_user(username, password, &session)) {
                snprintf(buffer, sizeof(buffer), "%s berhasil login sebagai monitor", username);
                clients[client_index].is_monitor = true;
                monitor_session.logged_in = 1;
            } else {
                snprintf(buffer, sizeof(buffer), "Login gagal");
            }
        } else if (session.logged_in) {
            process_command(socket, &session, buffer, &monitor_session);
            memset(buffer, 0, sizeof(buffer));
        } else {
            snprintf(buffer, sizeof(buffer), "Anda harus login terlebih dahulu");
        }

        write(socket, buffer, strlen(buffer));
        memset(buffer, 0, sizeof(buffer));
    }
    close(socket);
    clients[client_index].socket = 0;
    clients[client_index].is_monitor = false;
    client_count--;
    return NULL;
}

int register_user(const char *username, const char *password) {
    FILE *file = fopen(USER_FILE, "r");
    int max_id = 0;

    if (file) {
        char line[BUF_SIZE];
        while (fgets(line, sizeof(line), file)) {
            int id;
            char stored_username[BUF_SIZE];
            if (sscanf(line, "%d,%[^,]", &id, stored_username) == 2) {
                if (strcmp(stored_username, username) == 0) {
                    fclose(file);
                    return 0;
                }
                if (id > max_id) {
                    max_id = id;
                }
            }
        }
        fclose(file);
    }

    file = fopen(USER_FILE, "a");
    if (!file) {
        perror("fopen");
        return 0;
    }

    int new_id = max_id + 1;
    char *encrypted_password = bcrypt(password);
    fprintf(file, "%d,%s,%s,%s\n", new_id, username, encrypted_password, new_id == 1 ? "ROOT" : "USER");
    free(encrypted_password);
    fclose(file);
    return 1;
}

int login_user(const char *username, const char *password, Session *session) {
    FILE *file = fopen(USER_FILE, "r");
    if (!file) {
        perror("fopen");
        return 0;
    }

    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), file)) {
        int id;
        char stored_username[BUF_SIZE], stored_password[BUF_SIZE], role[BUF_SIZE];
        int num_fields = sscanf(line, "%d,%[^,],%[^,],%s", &id, stored_username, stored_password, role);

        if (num_fields < 4) {
            printf("Malformed line: %s\n", line);
            continue;
        }

        if (strcmp(stored_username, username) == 0) {
            if (strcmp(crypt(password, stored_password), stored_password) == 0) {
                session->logged_in = 1;
                strncpy(session->username, username, BUF_SIZE);
                strncpy(session->role, role, BUF_SIZE);
                session->user_id = id;
                fclose(file);
                printf("User %s logged in\n", username);
                return 1;
            }
            break;
        }
    }
    fclose(file);
    return 0;
}

int login_monitor(const char *username, const char *password, monitorSession *session) {
    FILE *file = fopen(USER_FILE, "r");
    if (!file) {
        perror("fopen");
        return 0;
    }

    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), file)) {
        int id;
        char stored_username[BUF_SIZE], stored_password[BUF_SIZE], role[BUF_SIZE];
        int num_fields = sscanf(line, "%d,%[^,],%[^,],%s", &id, stored_username, stored_password, role);

        if (num_fields < 4) {
            printf("Malformed line: %s\n", line);
            continue;
        }

        if (strcmp(stored_username, username) == 0) {
            if (strcmp(crypt(password, stored_password), stored_password) == 0) {
                session->logged_in = 1;
                fclose(file);
                printf("User %s logged in as monitor\n", username); // Debugging
                return 1;
            }
            break;
        }
    }
    fclose(file);
    return 0;
}

// Member verify
bool is_member(int socket, const char *channel_name, const char *username) {
    char auth_dir_path[BUF_SIZE];
    snprintf(auth_dir_path, sizeof(auth_dir_path), "%s/%s/admin/auth.csv", DISCORIT_DIR, channel_name);

    FILE *auth_file = fopen(auth_dir_path, "r");
    if (!auth_file) {
        perror("fopen");
        return;
    }

    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), auth_file)) {
        int id;
        char stored_username[BUF_SIZE], role[BUF_SIZE];
        sscanf(line, "%d,%[^,],%s", &id, stored_username, role);
        if (strcmp(stored_username, username) == 0) {
            fclose(auth_file);
            return 1;
        }
    }

    fclose(auth_file);
    return 0;
}

// Admin Verify
bool is_admin(int socket, const char *channel_name, const char *username) {
    char admin_dir_path[BUF_SIZE];
    snprintf(admin_dir_path, sizeof(admin_dir_path), "%s/%s/admin", DISCORIT_DIR, channel_name);

    char auth_dir_path[BUF_SIZE];
    snprintf(auth_dir_path, sizeof(auth_dir_path), "%s/auth.csv", admin_dir_path);

    FILE *auth_file = fopen(auth_dir_path, "r");
    if (!auth_file) {
        perror("fopen");
        return;
    }

    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), auth_file)) {
        int id;
        char stored_username[BUF_SIZE], role[BUF_SIZE];
        sscanf(line, "%d,%[^,],%s", &id, stored_username, role);
        if (strcmp(stored_username, username) == 0 && strcmp(role, "ADMIN") == 0) {
            fclose(auth_file);
            return 1;
        }
    }
    fclose(auth_file);
    return 0;
}

// Root Verify
bool is_root(int socket, const char *username) {
    FILE *file = fopen(USER_FILE, "r");
    if (!file) {
        perror("fopen");
        return false;
    }

    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), file)) {
        int id;
        char stored_username[BUF_SIZE], role[BUF_SIZE], password[BUF_SIZE];
        if (sscanf(line, "%d,%[^,],%[^,],%s", &id, stored_username, password, role) == 4) {
            if (strcmp(stored_username, username) == 0 && strcmp(role, "ROOT") == 0) {
                fclose(file);
                return true;
            }
        }
    }
    fclose(file);
    return false;
}

// Banned Check
bool is_banned(int socket, const char *channel_name, const char *username) {
    char auth_dir_path[BUF_SIZE];
    snprintf(auth_dir_path, sizeof(auth_dir_path), "%s/%s/admin/auth.csv", DISCORIT_DIR, channel_name);

    FILE *auth_file = fopen(auth_dir_path, "r");
    if (!auth_file) {
        perror("fopen");
        return;
    }

    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), auth_file)) {
        int id;
        char stored_username[BUF_SIZE], role[BUF_SIZE];
        sscanf(line, "%d,%[^,],%s", &id, stored_username, role);
        if (strcmp(stored_username, username) == 0 && strcmp(role, "BANNED") == 0) {
            fclose(auth_file);
            return 1;
        }
    }
    fclose(auth_file);
    return 0;
}

bool validate_key(int socket, const char *channel_name, const char *key) {
    FILE *file = fopen(CHANNEL_FILE, "r");
    if (!file) {
        perror("fopen");
        return false;
    }

    char trimmed_key[BUF_SIZE];
    strncpy(trimmed_key, key, BUF_SIZE - 1);
    trimmed_key[BUF_SIZE - 1] = '\0';
    char *newline = strchr(trimmed_key, '\n');
    if (newline) *newline = '\0';

    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), file)) {
        char stored_channel[BUF_SIZE], stored_key[BUF_SIZE];
        sscanf(line, "%*d,%[^,],%s", stored_channel, stored_key);
        if (strcmp(stored_channel, channel_name) == 0 && strcmp(crypt(trimmed_key, stored_key), stored_key) == 0) {
            fclose(file);
            return true;
        }
    }
    fclose(file);
    return false;
}

// Check Username Availability
bool is_username_taken(int socket, const char *username) {
    FILE *file = fopen(USER_FILE, "r");
    if (!file) {
        perror("fopen");
        return;
    }

    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), file)) {
        char stored_username[BUF_SIZE];
        sscanf(line, "%*d,%[^,]", stored_username);
        if (strcmp(stored_username, username) == 0) {
            fclose(file);
            return 1;
        }
    }
    fclose(file);
    return 0;
}

bool my_message(int socket, const char *channel_name, const char *room_name, const char *username, int id_chat) {
    char chat_dir_path[BUF_SIZE];
    snprintf(chat_dir_path, sizeof(chat_dir_path), "%s/%s/%s/chat.csv", DISCORIT_DIR, channel_name, room_name);

    FILE *chat_file = fopen(chat_dir_path, "r");
    if (!chat_file) {
        perror("fopen");
        return;
    }

    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), chat_file)) {
        int id;
        char sender[BUF_SIZE], message[BUF_SIZE];
        sscanf(line, "%d,%[^,],%[^\n]", &id, sender, message);
        if (id == id_chat && strcmp(sender, username) == 0) {
            fclose(chat_file);
            return 1;
        }
    }
    fclose(chat_file);
    return 0;
}

void process_command(int socket, Session *session, char *buffer, monitorSession *monitor_session) {
    char command[BUF_SIZE], arg1[BUF_SIZE], arg2[BUF_SIZE], arg3[BUF_SIZE], key[BUF_SIZE], 
    channel_name[BUF_SIZE], new_channel_name[BUF_SIZE], room_name[BUF_SIZE], new_room_name[BUF_SIZE], 
    message[BUF_SIZE], new_username[BUF_SIZE], new_password[BUF_SIZE], target_username[BUF_SIZE], username[BUF_SIZE];
    int id_chat;

    if (strstr(buffer, "LIST CHANNEL") != NULL) {
        display_all_channel(socket);
    } else if (sscanf(buffer, "CREATE CHANNEL %s -k %s", channel_name, key) == 2) {
        create_channel(socket, session->username, session->user_id, channel_name, key);
    } else if (sscanf(buffer, "EDIT CHANNEL %s TO %s", channel_name, new_channel_name) == 2) {
        if(is_admin(socket, channel_name, session->username) || is_root(socket, session->username)) {
            modify_channel(socket, session->username, channel_name, new_channel_name);
            strcpy(session->current_channel, new_channel_name);
        } else {
            write(socket, "Akses ditolak", strlen("Akses ditolak"));
        }
    } else if (sscanf(buffer, "DEL CHANNEL %s", channel_name) == 1) {
        if(is_admin(socket, channel_name, session->username) || is_root(socket, session->username)) {
            delete_channel(socket, channel_name);
        } else {
            write(socket, "Akses ditolak", strlen("Akses ditolak"));
        }
    } else if (sscanf(buffer, "JOIN %s", channel_name) == 1) {
        if(session->in_channel){
            strcpy(room_name, channel_name);
            if(is_room_exists(socket, session->current_channel, room_name) && (strcmp(room_name, "admin") != 0)){
                if(is_admin(socket, session->current_channel, session->username) || is_root(socket, session->username) || is_member(socket, session->current_channel, session->username)){
                    enter_room(socket, session->username, session->current_channel, room_name);
                    session->in_room = 1;
                    strcpy(session->current_room, room_name);
                }else{
                    write(socket, "Akses ditolak", strlen("Akses ditolak"));
                }
            } else {
                write(socket, "Room tidak ditemukan", strlen("Room tidak ditemukan"));
            }
        }else{
            if(is_channel_exists(socket, channel_name)){
                if(is_banned(socket, channel_name, session->username)){
                    write(socket, "Anda dibanned dari channel ini", strlen("Anda dibanned dari channel ini"));
                }else{
                    if(is_member(socket, channel_name, session->username) || is_root(socket, session->username) || is_admin(socket, channel_name, session->username)){
                        enter_channel(socket, session->username, channel_name, session->user_id,NULL);
                        session->in_channel = 1;
                        strcpy(session->current_channel, channel_name);
                    } else {
                        char key[BUF_SIZE];
                        write(socket, "Key: ", strlen("Key: "));
                        ssize_t bytes_read = read(socket, key, BUF_SIZE - 1);
                        if (bytes_read > 0) {
                            key[bytes_read] = '\0';
                            char *newline = strchr(key, '\n');
                            if (newline) *newline = '\0';

                            if (validate_key(socket, channel_name, key)) {
                                enter_channel(socket, session->username, channel_name, session->user_id, key);
                                session->in_channel = 1;
                                strcpy(session->current_channel, channel_name);
                            } else {
                                write(socket, "Key salah\n", strlen("Key salah\n"));
                            }
                        } else {
                            write(socket, "Error reading key\n", strlen("Error reading key\n"));
                        }
                    }
                }
            } else {
                write(socket, "Channel tidak ditemukan", strlen("Channel tidak ditemukan"));
            }
        }
    } else if (sscanf(buffer, "CREATE ROOM %s", room_name) == 1){
        if(session->in_channel){
            if (is_admin(socket, session->current_channel, session->username) || is_root(socket, session->username)){
                create_room(socket, session->username, session->current_channel, room_name);
            }else{
                write(socket, "Akses ditolak", strlen("Akses ditolak"));
            }
        }else{
            write(socket, "Anda belum bergabung ke channel", strlen("Anda belum bergabung ke channel"));
        }
    } else if (strcmp(buffer, "LIST ROOM") == 0) {
        if(session->in_channel){
            display_all_room(socket, session->current_channel);
        }else{
            write(socket, "Anda belum bergabung ke channel", strlen("Anda belum bergabung ke channel"));
        }
    } else if (sscanf(buffer, "EDIT ROOM %s TO %s", room_name, new_room_name) == 2) {
        if(is_admin(socket, session->current_channel, session->username) || is_root(socket, session->username)){
            if(session->in_channel){
                if(is_admin(socket, session->current_channel, session->username) || is_root(socket, session->username)){
                    modify_room(socket, session->username, session->current_channel, room_name, new_room_name);
                    strcpy(session->current_room, new_room_name);
                }else{
                    write(socket, "Akses ditolak", strlen("Akses ditolak"));
                }
            }else{
                write(socket, "Anda belum bergabung ke channel", strlen("Anda belum bergabung ke channel"));
            }
        }else{
            write(socket, "Akses ditolak", strlen("Akses ditolak"));
        }
    } else if (sscanf(buffer, "DEL ROOM %s", room_name) == 1) {
        if(is_admin(socket, session->current_channel, session->username) || is_root(socket, session->username)){
            if(session->in_channel){
                if(is_admin(socket, session->current_channel, session->username) || is_root(socket, session->username)){
                    if(strcmp(room_name, "ALL") == 0){
                        delete_room_exists(socket, session->current_channel, session->username);
                    }else{
                        delete_room(socket, session->current_channel, room_name, session->username);
                    }
                }else{
                    write(socket, "Akses ditolak", strlen("Akses ditolak"));
                }
            }else{
                write(socket, "Anda belum bergabung ke channel", strlen("Anda belum bergabung ke channel"));
            }
        }else{
            write(socket, "Akses ditolak", strlen("Akses ditolak"));
        }
    } else if (strcmp(buffer, "LIST USER") == 0){
        if(session->in_channel){
            if(is_admin(socket, session->current_channel, session->username) || is_root(socket, session->username)){
                display_all_channel_user(socket, session->current_channel);
            }else{
                write(socket, "Akses ditolak", strlen("Akses ditolak"));
            }
        }else{
            if(is_root(socket, session->username)){
                display_all_user(socket);
            }else{
                write(socket, "Akses ditolak", strlen("Akses ditolak"));
            }
        }
    } else if (strncmp(buffer, "CHAT ", 5) == 0) {
        char *message_start = buffer + 5;
        size_t message_length = strlen(message_start);
        
        if (message_length >= 2 && message_start[0] == '"' && message_start[message_length - 1] == '"') {
            message_start++;
            message_length -= 2;
            
            size_t max_length = sizeof(message) - 1;
            strncpy(message, message_start, message_length < max_length ? message_length : max_length);
            message[message_length < max_length ? message_length : max_length] = '\0';
            
            if(session->in_channel){
                if(session->in_room){
                    send_chat(socket, session->current_channel, session->current_room, session->username, message);
                }else{
                    write(socket, "Anda belum bergabung ke room", strlen("Anda belum bergabung ke room"));
                }
            }else{
                write(socket, "Anda belum bergabung ke channel", strlen("Anda belum bergabung ke channel"));
            } 
        } else {
            write(socket, "Format pesan tidak valid. Pesan harus diawali dan diakhiri dengan tanda kutip ganda (\").", 
                strlen("Format pesan tidak valid. Pesan harus diawali dan diakhiri dengan tanda kutip ganda (\")."));
        }
    } else if (strcmp(buffer, "EXIT") == 0) {
        if (session->in_room) {
            char line[BUF_SIZE];
            sprintf(line, "%s keluar dari room %s", session->username, session->current_room);
            log_action(session->current_channel, line);
            write(socket, "Keluar Room", strlen("Keluar Room"));
            session->in_room = 0;
            memset(session->current_room, 0, sizeof(session->current_room));
        } else if (session->in_channel) {
            char line[BUF_SIZE];
            sprintf(line, "%s keluar dari channel %s", session->username, session->current_channel);
            log_action(session->current_channel, line);
            write(socket, "Keluar Channel", strlen("Keluar Channel"));
            session->in_channel = 0;
            memset(session->current_channel, 0, sizeof(session->current_channel));
        } else {
            send_to_monitor(buffer);
            close(socket);
            pthread_exit(0);
        }
    } else {
        write(socket, "Perintah tidak valid", strlen("Perintah tidak valid"));
    }
}

// Encrypt Password
char *bcrypt(const char *password) {
    char salt[] = "$2b$12$XXXXXXXXXXXXXXXXXXXXXX"; // Generate a random salt
    char *encrypted_password = crypt(password, salt);
    return strdup(encrypted_password);
}

// Channel Exixsts Check
int is_channel_exists(int socket, const char *channel_name) {
    FILE *file = fopen(CHANNEL_FILE, "r");
    if (!file) {
        perror("fopen");
        return;
    }

    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), file)) {
        char stored_channel[BUF_SIZE];
        sscanf(line, "%*d,%[^,],%*s", stored_channel);
        if (strcmp(stored_channel, channel_name) == 0) {
            fclose(file);
            return 1;
        }
    }
    fclose(file);
    return 0;
}

// List Channel
void display_all_channel(int socket) {
    FILE *file = fopen(CHANNEL_FILE, "r");
    char line[BUF_SIZE];
    char response[BUF_SIZE] = "Channels: ";
    if (!file) {
        perror("fopen");
        return;
    }
    while (fgets(line, sizeof(line), file)) {
        char channel[BUF_SIZE];
        sscanf(line, "%*d,%[^,]", channel);
        strcat(response, channel);
        strcat(response, " ");
    }
    fclose(file);
    write(socket, response, strlen(response));
}

// Create Channel
void create_channel(int socket, const char *username, int user_id, const char *channel_name, const char *key) {
    FILE *file = fopen(CHANNEL_FILE, "r");
    int max_id = 0;

    if (file) {
        char line[BUF_SIZE];
        while (fgets(line, sizeof(line), file)) {
            int id;
            char stored_channel[BUF_SIZE];
            if (sscanf(line, "%d,%[^,]", &id, stored_channel) == 2) {
                if (strcmp(stored_channel, channel_name) == 0) {
                    fclose(file);
                    write(socket, "Channel already exists", strlen("Channel already exists"));
                    return;
                }
                if (id > max_id) {
                    max_id = id;
                }
            }
        }
        fclose(file);
    }

    file = fopen(CHANNEL_FILE, "a");
    if (!file) {
        perror("fopen");
        return;
    }

    int new_id = max_id + 1;
    char *encrypted_key = bcrypt(key);
    fprintf(file, "%d,%s,%s\n", new_id, channel_name, encrypted_key);
    free(encrypted_key);
    fclose(file);

    char channel_dir_path[BUF_SIZE];
    snprintf(channel_dir_path, sizeof(channel_dir_path), "%s/%s", DISCORIT_DIR, channel_name);

    if (mkdir(channel_dir_path, 0777) == -1) {
        perror("mkdir");
        write(socket, "Failed to create channel directory", strlen("Failed to create channel directory"));
        return;
    }

    char admin_dir_path[BUF_SIZE];
    snprintf(admin_dir_path, sizeof(admin_dir_path), "%s/%s/admin", DISCORIT_DIR, channel_name);

    if (mkdir(admin_dir_path, 0777) == -1) {
        perror("mkdir");
        write(socket, "Failed to create admin directory", strlen("Failed to create admin directory"));
        return;
    }

    char auth_dir_path[BUF_SIZE];
    snprintf(auth_dir_path, sizeof(auth_dir_path), "%s/auth.csv", admin_dir_path);
    FILE *auth_file = fopen(auth_dir_path, "w");
    if (!auth_file) {
        perror("fopen");
        return;
    }

    if(is_root(socket, username)){
        fprintf(auth_file, "%d,%s,ROOT\n", user_id, username);
    } else {
        fprintf(auth_file, "%d,%s,ADMIN\n", user_id, username);
    }
    fclose(auth_file);
    char log_action_msg[BUF_SIZE];
    snprintf(log_action_msg, sizeof(log_action_msg), "%s buat %s", username, channel_name);
    log_action(channel_name, log_action_msg);

    char response[BUF_SIZE];
    snprintf(response, sizeof(response), "Channel %s dibuat", channel_name);
    write(socket, response, strlen(response));
}

// Edit Channel
void modify_channel(int socket, const char *username, const char *channel_name, const char *new_channel_name) {
    FILE *file = fopen(CHANNEL_FILE, "r");
    FILE *temp = fopen("temp.csv", "w");
    if (!file || !temp) {
        perror("fopen");
        return;
    }

    char line[BUF_SIZE];
    int found = 0;
    while (fgets(line, sizeof(line), file)) {
        int id;
        char stored_channel[BUF_SIZE], key[BUF_SIZE];
        sscanf(line, "%d,%[^,],%s", &id, stored_channel, key);
        if (strcmp(stored_channel, channel_name) == 0) {
            fprintf(temp, "%d,%s,%s\n", id, new_channel_name, key);
            found = 1;
        } else {
            fputs(line, temp);
        }
    }

    fclose(file);
    fclose(temp);

    char log_action_msg[BUF_SIZE];

    if (found) {
        remove(CHANNEL_FILE);
        rename("temp.csv", CHANNEL_FILE);

        char old_channel_dir[BUF_SIZE], new_channel_dir[BUF_SIZE];
        snprintf(old_channel_dir, sizeof(old_channel_dir), "%s/%s", DISCORIT_DIR, channel_name);
        snprintf(new_channel_dir, sizeof(new_channel_dir), "%s/%s", DISCORIT_DIR, new_channel_name);

        if (rename(old_channel_dir, new_channel_dir) == -1) {
            perror("rename");
            snprintf(line, sizeof(line), "Failed to rename channel directory from %s to %s", channel_name, new_channel_name);
        } else {
            snprintf(line, sizeof(line), "%s nama channel berubah menjadi %s", channel_name, new_channel_name);
            snprintf(log_action_msg, sizeof(log_action_msg), "%s merubah %s menjadi %s", username, channel_name, new_channel_name);
            log_action(new_channel_name, log_action_msg);
        }
    } else {
        remove("temp.csv");
        snprintf(line, sizeof(line), "Channel %s not found", channel_name);
    }

    write(socket, line, strlen(line));
}

// Delete Channel
void delete_channel(int socket, const char *channel_name) {
    FILE *file = fopen(CHANNEL_FILE, "r");
    FILE *temp = fopen("temp.csv", "w");
    if (!file || !temp) {
        perror("fopen");
        return;
    }

    char line[BUF_SIZE];
    int found = 0;
    while (fgets(line, sizeof(line), file)) {
        char stored_channel[BUF_SIZE];
        sscanf(line, "%*d,%[^,],%*s", stored_channel);  // Correctly parse channel name
        if (strcmp(stored_channel, channel_name) != 0) {
            fputs(line, temp);
        } else {
            found = 1;
        }
    }

    fclose(file);
    fclose(temp);

    if (found) {
        remove(CHANNEL_FILE);
        rename("temp.csv", CHANNEL_FILE);

        char response[BUF_SIZE];
        snprintf(response, sizeof(response), "%s berhasil dihapus", channel_name);
        write(socket, response, strlen(response));

        char channel_dir_path[BUF_SIZE];
        snprintf(channel_dir_path, sizeof(channel_dir_path), "%s/%s", DISCORIT_DIR, channel_name);

        int delete_result = remove_directory(channel_dir_path);
        if (delete_result == -1) {
            perror("remove_directory");
        }

    } else {
        remove("temp.csv");

        char response[BUF_SIZE];
        snprintf(response, sizeof(response), "Channel %s tidak ditemukan", channel_name);
        write(socket, response, strlen(response));
    }
}

// Join Channel
void enter_channel(int socket, const char *username, const char *channel, int id,const char *key) {
    
    if (is_member(socket, channel, username)){
        char line[BUF_SIZE];
        sprintf(line, "%s masuk ke channel %s", username, channel);
        log_action(channel, line);

        char response[BUF_SIZE];
        snprintf(response, sizeof(response), "%s bergabung dengan channel %s", username, channel);
        write(socket, response, strlen(response));

    } else {
        char auth_dir_path[BUF_SIZE];
        snprintf(auth_dir_path, sizeof(auth_dir_path), "%s/%s/admin/auth.csv", DISCORIT_DIR, channel);

        FILE *auth_file = fopen(auth_dir_path, "a");
        if (!auth_file) {
            perror("fopen");
            return;
        }

        if(is_root(socket, username)){
            fprintf(auth_file, "%d,%s,ROOT\n", id, username);
        } else {
            fprintf(auth_file, "%d,%s,USER\n", id, username);
        }

        fclose(auth_file);

        char line[BUF_SIZE];
        sprintf(line, "%s masuk ke channel %s", username, channel);
        log_action(channel, line);

        char response[BUF_SIZE];
        snprintf(response, sizeof(response), "%s bergabung dengan channel %s", username, channel);
        write(socket, response, strlen(response));

        const char* channel_msg = "CHANNEL_NAME";
    }
}

// Room Exists Check
int is_room_exists(int socket, const char *channel_name, const char *room_name) {
    char room_dir_path[BUF_SIZE];
    snprintf(room_dir_path, sizeof(room_dir_path), "%s/%s/%s", DISCORIT_DIR, channel_name, room_name);

    struct stat st;
    if (stat(room_dir_path, &st) == 0) {
        return 1;
    }
    return 0;
}

// List Room
void display_all_room(int socket, const char *channel) {
    char channel_dir_path[BUF_SIZE];
    snprintf(channel_dir_path, sizeof(channel_dir_path), "%s/%s", DISCORIT_DIR, channel);

    DIR *dir = opendir(channel_dir_path);
    if (!dir) {
        perror("opendir");
        return;
    }

    struct dirent *entry;
    struct stat statbuf;
    char fullpath[BUF_SIZE];
    char response[BUF_SIZE] = "Rooms: ";

    while ((entry = readdir(dir))) {
        snprintf(fullpath, sizeof(fullpath), "%s/%s", channel_dir_path, entry->d_name);

        if (stat(fullpath, &statbuf) == 0 && S_ISDIR(statbuf.st_mode) &&
            strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            if (strcmp(entry->d_name, "admin") == 0) {
                continue;
            }
            strcat(response, entry->d_name);
            strcat(response, " ");
        }
    }
    closedir(dir);
    write(socket, response, strlen(response));
}

// Create Room
void create_room(int socket, const char *username, const char *channel, const char *room){
    char room_dir_path[BUF_SIZE];
    snprintf(room_dir_path, sizeof(room_dir_path), "%s/%s/%s", DISCORIT_DIR, channel, room);

    if (mkdir(room_dir_path, 0777) == -1) {
        perror("mkdir");
        write(socket, "Failed to create room directory", strlen("Failed to create room directory"));
        return;
    }

    char chat_file_path[BUF_SIZE];
    snprintf(chat_file_path, sizeof(chat_file_path), "%s/chat.csv", room_dir_path);

    FILE *chat_file = fopen(chat_file_path, "w");
    if (!chat_file) {
        perror("fopen");
        return;
    }

    fclose(chat_file);

    char line[BUF_SIZE];
    sprintf(line, "%s membuat room %s", username, room);
    log_action(channel, line);

    char response[BUF_SIZE];
    snprintf(response, sizeof(response), "Room %s created", room);
    write(socket, response, strlen(response));
}

// Edit Room
void modify_room(int socket, const char *username, const char *channel, const char *room, const char *new_room) {
    char old_room_dir_path[BUF_SIZE];
    snprintf(old_room_dir_path, sizeof(old_room_dir_path), "%s/%s/%s", DISCORIT_DIR, channel, room);

    char new_room_dir_path[BUF_SIZE];
    snprintf(new_room_dir_path, sizeof(new_room_dir_path), "%s/%s/%s", DISCORIT_DIR, channel, new_room);

    if (rename(old_room_dir_path, new_room_dir_path) == -1) {
        perror("rename");
        write(socket, "Failed to rename room directory", strlen("Failed to rename room directory"));
        return;
    }

    char line[BUF_SIZE];
    sprintf(line, "%s merubah room %s menjadi %s", username, room, new_room);
    log_action(channel, line);

    char response[BUF_SIZE];
    snprintf(response, sizeof(response), "%s nama room berubah menjadi %s", room, new_room);
    write(socket, response, strlen(response));
}

// Delete Room
void delete_room(int socket, const char *channel, const char *room, const char *username) {
    char room_dir_path[BUF_SIZE];
    snprintf(room_dir_path, sizeof(room_dir_path), "%s/%s/%s", DISCORIT_DIR, channel, room);

    int delete_result = remove_directory(room_dir_path);
    if (delete_result == -1) {
        perror("remove_directory");
        write(socket, "Failed to delete room directory", strlen("Failed to delete room directory"));
        return;
    }

    char line[BUF_SIZE];
    sprintf(line, "%s menghapus room %s", username, room);
    log_action(channel, line);

    char response[BUF_SIZE];
    snprintf(response, sizeof(response), "Room %s deleted", room);
    write(socket, response, strlen(response));
}

// Delete All Room
void delete_room_exists(int socket, const char *channel, const char *username) {
    char channel_dir_path[BUF_SIZE];
    snprintf(channel_dir_path, sizeof(channel_dir_path), "%s/%s", DISCORIT_DIR, channel);

    DIR *dir = opendir(channel_dir_path);
    if (!dir) {
        perror("opendir");
        return;
    }

    struct dirent *entry;
    struct stat statbuf;
    char fullpath[BUF_SIZE];

    while ((entry = readdir(dir))) {
        snprintf(fullpath, sizeof(fullpath), "%s/%s", channel_dir_path, entry->d_name);

        if (stat(fullpath, &statbuf) == 0 && S_ISDIR(statbuf.st_mode) &&
            strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            if (strcmp(entry->d_name, "admin") == 0) {
                continue;
            }

            int delete_result = remove_directory(fullpath);
            if (delete_result == -1) {
                perror("remove_directory");
                write(socket, "Failed to delete room directory", strlen("Failed to delete room directory"));
                closedir(dir);
                return;
            }
        }
    }

    closedir(dir);

    char line[BUF_SIZE];
    sprintf(line, "%s menghapus semua room", username);
    log_action(channel, line);

    char response[BUF_SIZE];
    snprintf(response, sizeof(response), "All rooms deleted");
    write(socket, response, strlen(response));
}

// Join Room
void enter_room(int socket, const char *username, const char *channel, const char *room) {
    char line[BUF_SIZE];
    sprintf(line, "%s masuk ke room %s", username, room);
    log_action(channel, line);

    char response[BUF_SIZE];
    snprintf(response, sizeof(response), "%s bergabung dengan room %s", username, room);
    write(socket, response, strlen(response));
}

// List User
void display_all_user(int socket) {
    FILE *file = fopen(USER_FILE, "r");
    char line[BUF_SIZE];
    char response[BUF_SIZE] = "Users: ";
    if (!file) {
        perror("fopen");
        return;
    }
    while (fgets(line, sizeof(line), file)) {
        int id;
        char username[BUF_SIZE];
        sscanf(line, "%d,%[^,]", &id, username);
        char user_info[BUF_SIZE];
        snprintf(user_info, sizeof(user_info), "[%d]%s ", id, username);
        strcat(response, user_info);
    }
    fclose(file);
    write(socket, response, strlen(response));
}

// List Channel User
void display_all_channel_user(int socket, const char *channel_name) {
    char auth_file_path[BUF_SIZE];
    snprintf(auth_file_path, sizeof(auth_file_path), "%s/%s/admin/auth.csv", DISCORIT_DIR, channel_name);

    FILE *auth_file = fopen(auth_file_path, "r");
    if (!auth_file) {
        perror("fopen");
        return;
    }

    char line[BUF_SIZE];
    char response[BUF_SIZE] = "Users: ";
    while (fgets(line, sizeof(line), auth_file)) {
        int id;
        char username[BUF_SIZE], role[BUF_SIZE];
        sscanf(line, "%d,%[^,],%s", &id, username, role);
        char user_info[BUF_SIZE];
        snprintf(user_info, sizeof(user_info), "%s ", username);
        strcat(response, user_info);
    }
    fclose(auth_file);
    write(socket, response, strlen(response));
}

void update_channel_auth_files(const char *old_username, const char *new_username) {
    DIR *dir = opendir(DISCORIT_DIR);
    if (!dir) {
        perror("opendir");
        return;
    }

    struct dirent *entry;
    struct stat statbuf;
    char fullpath[BUF_SIZE];

    while ((entry = readdir(dir))) {
        snprintf(fullpath, sizeof(fullpath), "%s/%s", DISCORIT_DIR, entry->d_name);

        if (stat(fullpath, &statbuf) == 0 && S_ISDIR(statbuf.st_mode) &&
            strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {

            char auth_file_path[BUF_SIZE];
            snprintf(auth_file_path, sizeof(auth_file_path), "%s/%s/admin/auth.csv", DISCORIT_DIR, entry->d_name);

            FILE *auth_file = fopen(auth_file_path, "r");
            FILE *temp_file = fopen("temp_auth.csv", "w");

            if (!auth_file || !temp_file) {
                perror("Unable to open auth file or create temp file");
                if (auth_file) fclose(auth_file);
                if (temp_file) fclose(temp_file);
                continue;
            }

            char line[BUF_SIZE];
            while (fgets(line, sizeof(line), auth_file)) {
                int id;
                char username[BUF_SIZE], role[BUF_SIZE];
                sscanf(line, "%d,%[^,],%s", &id, username, role);
                if (strcmp(username, old_username) == 0) {
                    fprintf(temp_file, "%d,%s,%s\n", id, new_username, role);
                } else {
                    fputs(line, temp_file);
                }
            }

            fclose(auth_file);
            fclose(temp_file);

            remove(auth_file_path);
            rename("temp_auth.csv", auth_file_path);

            char log_message[BUF_SIZE];
            snprintf(log_message, sizeof(log_message), "Nama user %s berubah menjadi %s", old_username, new_username);
            log_action(entry->d_name, log_message);
        }
    }
    closedir(dir);
}

void remove_user_from_channel_auth(const char *username) {
    DIR *dir = opendir(DISCORIT_DIR);
    if (!dir) {
        perror("opendir");
        return;
    }

    struct dirent *entry;
    struct stat statbuf;
    char fullpath[BUF_SIZE];

    while ((entry = readdir(dir))) {
        snprintf(fullpath, sizeof(fullpath), "%s/%s", DISCORIT_DIR, entry->d_name);

        if (stat(fullpath, &statbuf) == 0 && S_ISDIR(statbuf.st_mode) &&
            strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {

            char auth_file_path[BUF_SIZE];
            snprintf(auth_file_path, sizeof(auth_file_path), "%s/%s/admin/auth.csv", DISCORIT_DIR, entry->d_name);

            FILE *auth_file = fopen(auth_file_path, "r");
            FILE *temp_file = fopen("temp_auth.csv", "w");

            if (!auth_file || !temp_file) {
                perror("Unable to open auth file or create temp file");
                if (auth_file) fclose(auth_file);
                if (temp_file) fclose(temp_file);
                continue;
            }

            char line[BUF_SIZE];
            while (fgets(line, sizeof(line), auth_file)) {
                int id;
                char stored_username[BUF_SIZE], role[BUF_SIZE];
                sscanf(line, "%d,%[^,],%s", &id, stored_username, role);
                if (strcmp(stored_username, username) != 0) {
                    fputs(line, temp_file);
                }
            }

            fclose(auth_file);
            fclose(temp_file);

            remove(auth_file_path);
            rename("temp_auth.csv", auth_file_path);

            char log_message[BUF_SIZE];
            snprintf(log_message, sizeof(log_message), "Root menghapus user %s dari channel", username);
            log_action(entry->d_name, log_message);
        }
    }
    closedir(dir);
}

// Remove User
void remove_user(int socket, const char *username) {
    FILE *file = fopen(USER_FILE, "r");
    FILE *temp = fopen("temp.csv", "w");
    if (!file || !temp) {
        perror("fopen");
        return;
    }

    char line[BUF_SIZE];
    int found = 0;
    while (fgets(line, sizeof(line), file)) {
        int id;
        char stored_username[BUF_SIZE], stored_password[BUF_SIZE], role[BUF_SIZE];
        sscanf(line, "%d,%[^,],%[^,],%s", &id, stored_username, stored_password, role);
        if (strcmp(stored_username, username) == 0) {
            found = 1;
        } else {
            fputs(line, temp);
        }
    }

    fclose(file);
    fclose(temp);

    if (found) {
        remove(USER_FILE);
        rename("temp.csv", USER_FILE);
        snprintf(line, sizeof(line), "User %s berhasil dihapus", username);
        remove_user_from_channel_auth(username);
    } else {
        remove("temp.csv");
        snprintf(line, sizeof(line), "User %s not found", username);
    }
    write(socket, line, strlen(line));
}

// Helper function to sanitize strings
void sanitize_string(const char *input, char *output, size_t output_size) {
    size_t i, j;
    for (i = 0, j = 0; input[i] != '\0' && j < output_size - 1; i++) {
        if (input[i] != ',' && input[i] != '\n') {
            output[j++] = input[i];
        }
    }
    output[j] = '\0';
}

// Send Chat
void send_chat(int socket, const char *channel, const char *room, const char *username, const char *message) {
    char chat_file_path[BUF_SIZE];
    if (snprintf(chat_file_path, sizeof(chat_file_path), "%s/%s/%s/chat.csv", DISCORIT_DIR, channel, room) >= sizeof(chat_file_path)) {
        const char *error_msg = "Error: Path too long";
        send(socket, error_msg, strlen(error_msg), 0);
        return;
    }

    FILE *chat_file = fopen(chat_file_path, "a+");
    if (!chat_file) {
        perror("fopen");
        const char *error_msg = "Error: Could not open chat file";
        send(socket, error_msg, strlen(error_msg), 0);
        return;
    }

    int id_chat = 1;
    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), chat_file)) {
        if (strlen(line) <= 1) continue;
        char *token = strtok(line, ",");
        if (token) {
            int current_id_chat = atoi(token);
            if (current_id_chat >= id_chat) {
                id_chat = current_id_chat + 1;
            }
        }
    }

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char timestamp[BUF_SIZE];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);

    char safe_username[BUF_SIZE], safe_message[BUF_SIZE];
    sanitize_string(username, safe_username, sizeof(safe_username));
    sanitize_string(message, safe_message, sizeof(safe_message));

    fprintf(chat_file, "%d,%s,%s,%s\n", id_chat, timestamp, safe_username, safe_message);
    fclose(chat_file);

    char send_message[BUF_SIZE];
    snprintf(send_message, sizeof(send_message), "Chat Baru: %s", safe_message);
    send(socket, send_message, strlen(send_message), 0);

    char log_message[BUF_SIZE];
    snprintf(log_message, sizeof(log_message), "%s: %s", safe_username, safe_message);
    log_action(room, log_message);
}

// Edit Chat
void modify_chat(int socket, const char *channel, const char *room, const char *username, int id_chat, const char *new_message) {
    char chat_file_path[BUF_SIZE];
    snprintf(chat_file_path, sizeof(chat_file_path), "%s/%s/%s/chat.csv", DISCORIT_DIR, channel, room);

    FILE *chat_file = fopen(chat_file_path, "r");
    FILE *temp_file = fopen("temp.csv", "w");

    if (!chat_file || !temp_file) {
        perror("fopen");
        const char *error_msg = "Error: Could not open files";
        send(socket, error_msg, strlen(error_msg), 0);
        return;
    }

    char line[BUF_SIZE];
    int edited = 0;
    while (fgets(line, sizeof(line), chat_file)) {
        char original_line[BUF_SIZE];
        strncpy(original_line, line, sizeof(original_line));

        char *token = strtok(line, ",");
        if (token) {
            int current_id_chat = atoi(token);
            if (current_id_chat == id_chat) {
                char *original_timestamp = strtok(NULL, ",");
                char *original_username = strtok(NULL, ",");
                char safe_new_message[BUF_SIZE];
                sanitize_string(new_message, safe_new_message, sizeof(safe_new_message));
                fprintf(temp_file, "%d,%s,%s,%s\n", id_chat, original_timestamp, original_username, safe_new_message);
                edited = 1;
            } else {
                fputs(original_line, temp_file);
            }
        } else {
            fputs(original_line, temp_file);
        }
    }

    fclose(chat_file);
    fclose(temp_file);

    if (edited) {
        if (remove(chat_file_path) == 0 && rename("temp.csv", chat_file_path) == 0) {
            const char *success_msg = "Chat berhasil diubah";
            send(socket, success_msg, strlen(success_msg), 0);

            char log_message[BUF_SIZE];
            snprintf(log_message, sizeof(log_message), "%s mengubah chat %d", username, id_chat);
        } else {
            perror("File operation failed");
            const char *error_msg = "Error: Failed to update chat file";
            send(socket, error_msg, strlen(error_msg), 0);
        }
    } else {
        remove("temp.csv");
        const char *not_found_msg = "Error: Chat message not found";
        send(socket, not_found_msg, strlen(not_found_msg), 0);
    }
}

// Delete Chat
void delete_chat(int socket, const char *channel, const char *room, int id_chat) {
    char chat_file_path[BUF_SIZE];
    snprintf(chat_file_path, sizeof(chat_file_path), "%s/%s/%s/chat.csv", DISCORIT_DIR, channel, room);

    FILE *chat_file = fopen(chat_file_path, "r");
    FILE *temp_file = fopen("temp.csv", "w");

    if (!chat_file || !temp_file) {
        perror("fopen");
        return;
    }

    char line[BUF_SIZE];
    int deleted = 0;
    while (fgets(line, sizeof(line), chat_file)) {
        if (strlen(line) <= 1) continue;
        char *token = strtok(line, ",");
        if (token) {
            int current_id_chat = atoi(token);
            if (current_id_chat != id_chat) {
                fprintf(temp_file, "%s", line);
            } else {
                deleted = 1;
            }
        }
    }

    fclose(chat_file);
    fclose(temp_file);

    if (deleted) {
        remove(chat_file_path);
        rename("temp.csv", chat_file_path);
    } else {
        remove("temp.csv");
    }

    char send_message[BUF_SIZE];
    snprintf(send_message, sizeof(send_message), "Chat Dihapus");
    
    send(socket, send_message, strlen(send_message), 0);

    char log_message[BUF_SIZE];
    snprintf(log_message, sizeof(log_message), "Chat %d dihapus", id_chat);
    log_action(room, log_message);
}

// View Chat
void view_chat(int socket, const char *channel, const char *room) {
    char chat_file_path[BUF_SIZE];
    snprintf(chat_file_path, sizeof(chat_file_path), "%s/%s/%s/chat.csv", DISCORIT_DIR, channel, room);

    FILE *chat_file = fopen(chat_file_path, "r");
    if (!chat_file) {
        perror("fopen");
        return;
    }

    char response[BUF_SIZE * 10] = "Chat:\n";
    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), chat_file)) {
        if (strlen(line) <= 1) continue;
        char id_chat[BUF_SIZE], timestamp[BUF_SIZE], username[BUF_SIZE], message[BUF_SIZE];
        char *ptr = line;

        sscanf(ptr, "%[^,]", id_chat);
        ptr = strchr(ptr, ',') + 1;

        sscanf(ptr, "%[^,]", timestamp);
        ptr = strchr(ptr, ',') + 1;

        sscanf(ptr, "%[^,]", username);
        ptr = strchr(ptr, ',') + 1;
        strcpy(message, ptr);

        char *newline = strchr(message, '\n');
        if (newline) *newline = '\0';

        char chat_info[BUF_SIZE];
        snprintf(chat_info, sizeof(chat_info), "[%s][%s][%s] \"%s\"\n", timestamp, id_chat, username, message);

        if (strlen(response) + strlen(chat_info) < sizeof(response) - 1) {
            strcat(response, chat_info);
        } else {
            strcat(response, "...\n(more messages not shown due to buffer limit)\n");
            break;
        }
    }
    fclose(chat_file);
    write(socket, response, strlen(response));
}
```
#### Fungsi-fungsi Utama

> **handle_client(int client_socket)**:

>> Deskripsi: Menangani komunikasi dengan klien.
>> Parameter:
>>> client_socket: Soket klien.
>>> Detail: Fungsi ini menerima dan memproses permintaan dari klien, serta mengirimkan response.

> **connection_handler(void socket_desc)**:

>> Deskripsi: Mengelola thread untuk koneksi klien.
>>Parameter:
>>> socket_desc: Deskriptor soket.
>> Detail: Fungsi ini berjalan dalam thread terpisah untuk menangani koneksi klien secara paralel.

> **create_daemon()**:

>> Deskripsi: Membuat proses daemon.
>> Parameter: Tidak ada.
>> Detail: Fungsi ini mengubah proses server menjadi daemon, sehingga berjalan di latar belakang.

> **process_request(int client_socket, char request)**:

>> Deskripsi: Memproses permintaan dari klien.
>> Parameter:
>>> client_socket: Soket klien.
>>> request: Permintaan yang diterima dari klien.
>> Detail: Fungsi ini menganalisis permintaan dan melakukan tindakan yang sesuai.

> **load_users()**:

>> Deskripsi: Memuat data pengguna dari file CSV.
>> Parameter: Tidak ada.
>> Detail: Fungsi ini membaca file users.csv dan memuat informasi pengguna ke dalam struktur data yang digunakan oleh server.

> **save_message(const char message, const char user_id)**:

>> Deskripsi: Menyimpan pesan ke dalam sistem.
>> Parameter:
>>> message: Pesan yang akan disimpan.
>>> user_id: ID pengguna yang mengirim pesan.
>> Detail: Fungsi ini menyimpan pesan yang diterima dari pengguna ke dalam direktori yang telah ditentukan.

### monitor.c
```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <crypt.h>
#include <pthread.h>
#include <sys/stat.h>

#define LISTENING_PORT 9090
#define MAX_BUFFER 2048
#define CHAT_ROOT_DIR "/home/honque/sisop/fp/new/DiscorIT"

typedef struct {
    char topic[MAX_BUFFER];
    char subtopic[MAX_BUFFER];
    int connection;
} ConversationObserverParams;

void process_user_input(int connection, const char *user_id);

void render_conversation_history(const char *topic, const char *subtopic) {
    printf("\033[2J");  // Clear entire screen

    char log_location[MAX_BUFFER];
    snprintf(log_location, sizeof(log_location), "%s/%s/%s/chat.csv", CHAT_ROOT_DIR, topic, subtopic);

    FILE *log_file = fopen(log_location, "r");
    if (!log_file) {
        printf("Unable to access conversation log.\n");
        return;
    }

    printf("\n--- Conversation History for %s/%s ---\n", topic, subtopic);
    char entry[MAX_BUFFER];
    char compiled_history[MAX_BUFFER * 10] = "";
    while (fgets(entry, sizeof(entry), log_file)) {
        if (strlen(entry) <= 1) continue;  // Skip empty lines

        char msg_id[MAX_BUFFER], time_stamp[MAX_BUFFER], user_name[MAX_BUFFER], content[MAX_BUFFER];
        
        char *cursor = entry;
        
        sscanf(cursor, "%[^,]", msg_id);
        cursor = strchr(cursor, ',') + 1;
        
        sscanf(cursor, "%[^,]", time_stamp);
        cursor = strchr(cursor, ',') + 1;
        
        sscanf(cursor, "%[^,]", user_name);
        cursor = strchr(cursor, ',') + 1;
        
        strcpy(content, cursor);
        
        char *newline_pos = strchr(content, '\n');
        if (newline_pos) *newline_pos = '\0';

        char formatted_entry[MAX_BUFFER];
        snprintf(formatted_entry, sizeof(formatted_entry), "[%s][%s][%s] \"%s\"\n", time_stamp, msg_id, user_name, content);
        
        if (strlen(compiled_history) + strlen(formatted_entry) < sizeof(compiled_history) - 1) {
            strcat(compiled_history, formatted_entry);
        } else {
            strcat(compiled_history, "...\n(additional messages omitted due to buffer constraints)\n");
            break;
        }
    }

    printf("%s", compiled_history);
    printf("-------------------\n");

    fclose(log_file);
}

void *observe_conversation(void *params) {
    ConversationObserverParams *args = (ConversationObserverParams *)params;
    char log_location[MAX_BUFFER];
    snprintf(log_location, sizeof(log_location), "%s/%s/%s/chat.csv", CHAT_ROOT_DIR, args->topic, args->subtopic);

    struct stat previous_state;
    if (stat(log_location, &previous_state) == -1) {
        perror("Error retrieving file information");
        return NULL;
    }

    while (1) {
        struct stat current_state;
        if (stat(log_location, &current_state) == -1) {
            perror("Error retrieving file information");
            sleep(1);
            continue;
        }

        if (current_state.st_mtime != previous_state.st_mtime) {
            render_conversation_history(args->topic, args->subtopic);
            previous_state = current_state;
        }

        sleep(1);  // Check for updates every second
    }

    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s LOGIN username -p password\n", argv[0]);
        return -1;
    }

    struct sockaddr_in server_address;
    int client_socket = 0;
    char buffer[MAX_BUFFER] = {0};

    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        return -1;
    }

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(LISTENING_PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr) <= 0) {
        perror("Invalid address or address not supported");
        return -1;
    }

    if (connect(client_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        perror("Connection attempt failed");
        return -1;
    }

    const char *user_id = argv[2];
    const char *password = argv[4];

    if (strcmp(argv[1], "LOGIN") == 0) {
        snprintf(buffer, sizeof(buffer), "LOGIN_MONITOR %s -p %s", user_id, password);
        send(client_socket, buffer, strlen(buffer), 0);
        read(client_socket, buffer, MAX_BUFFER);
        if (strstr(buffer, "berhasil login")) {
            printf("%s\n", buffer);
            process_user_input(client_socket, user_id);
        } else {
            printf("Login gagal\n");
        }
    } else {
        fprintf(stderr, "Invalid command. Use LOGIN.\n");
    }

    close(client_socket);
    return 0;
}

void process_user_input(int connection, const char *user_id) {
    char buffer[MAX_BUFFER];
    char topic[MAX_BUFFER] = "";
    char subtopic[MAX_BUFFER] = "";
    pthread_t observer_thread;
    ConversationObserverParams observer_params;
    int observer_active = 0;

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        int bytes_received = read(connection, buffer, MAX_BUFFER);
        buffer[bytes_received] = '\0';

        if (sscanf(buffer, "-channel %s -room %s", topic, subtopic) == 2) {
            if (observer_active) {
                pthread_cancel(observer_thread);
                observer_active = 0;
            }

            observer_params.connection = connection;
            strncpy(observer_params.topic, topic, MAX_BUFFER);
            strncpy(observer_params.subtopic, subtopic, MAX_BUFFER);

            if (pthread_create(&observer_thread, NULL, observe_conversation, (void *)&observer_params) == 0) {
                observer_active = 1;
            } else {
                perror("Failed to create observer thread");
            }

            render_conversation_history(topic, subtopic);
        } else if(strcmp(buffer, "EXIT") == 0){
            break;
        } else {
            printf("%s\n", buffer);
        }
    }

    if (observer_active) {
        pthread_cancel(observer_thread);
    }
}
```

## Hasil Run
Berikut kami lampirkan screenshot dari hasil run dari program kami yang telah kami coba

