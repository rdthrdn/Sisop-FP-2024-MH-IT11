#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdbool.h>
#include <time.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
// #include <bcrypt.h>

#define PORT 8080
#define MAX_CLIENTS 10
#define MAX_BUFFER_SIZE 10240
#define SALT_SIZE 64
#define USERS_FILE "/home/kali/arsipsisop/fp/DiscorIT/users.csv"
#define CHANNELS_FILE "/home/kali/arsipsisop/fp/DiscorIT/channels.csv"
#define MAX_CHANNELS 10
#define BUFFER_SIZE 1024
#define MAX_ROOMS 10

typedef struct {
    int socket;
    struct sockaddr_in address;
    char logged_in_user[50];
    char logged_in_role[10];
    char logged_in_channel[50];
    char logged_in_room[50];
} client_info;

client_info *clients[MAX_CLIENTS];
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

char channels[MAX_CHANNELS][MAX_BUFFER_SIZE];
char channelKeys[MAX_CHANNELS][MAX_BUFFER_SIZE];
int channel_count = 0;

typedef struct {
    char roomName[MAX_BUFFER_SIZE];
    char channelName[MAX_BUFFER_SIZE];
} RoomInfo;

RoomInfo rooms[MAX_ROOMS];
int room_count = 0;


// Fungsi untuk mendapatkan waktu saat ini
void get_current_time(char *buffer) {
    time_t rawtime;
    struct tm *timeinfo;

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    strftime(buffer, 80, "%d/%m/%Y %H:%M:%S", timeinfo);
}

// Fungsi untuk mengirim pesan ke semua client dalam channel dan room yang sama
void broadcast_message(const char *message, const char *channel, const char *room) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] && strcmp(clients[i]->logged_in_channel, channel) == 0 && strcmp(clients[i]->logged_in_room, room) == 0) {
            send(clients[i]->socket, message, strlen(message), 0);
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

// Fungsi untuk menulis log ke file user.log
void write_log(const char *channel, const char *message) {
    char filename[BUFFER_SIZE];
    snprintf(filename, sizeof(filename), "/home/kali/arsipsisop/fp/DiscorIT/%s/admin/user.log", channel);

    int fd = open(filename, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd == -1) {
        perror("open");
        return;
    }

    struct flock lock;
    memset(&lock, 0, sizeof(lock));
    lock.l_type = F_WRLCK;

    if (fcntl(fd, F_SETLKW, &lock) == -1) {
        perror("fcntl");
        close(fd);
        return;
    }

    char timestamp[80];
    get_current_time(timestamp);
    dprintf(fd, "[%s] %s\n", timestamp, message);

    lock.l_type = F_UNLCK;
    fcntl(fd, F_SETLK, &lock);
    close(fd);
}

// Fungsi untuk memeriksa apakah channel ada
bool is_channel_exists(const char *channel_name) {
    for (int i = 0; i < channel_count; i++) {
        if (strcmp(channels[i], channel_name) == 0) {
            return true;
        }
    }
    return false;
}

// Fungsi untuk memeriksa apakah room ada
bool is_room_exists(const char *room_name, const char *channel_name) {
    for (int i = 0; i < room_count; i++) {
        if (strcmp(rooms[i].roomName, room_name) == 0 && strcmp(rooms[i].channelName, channel_name) == 0) {
            return true;
        }
    }
    return false;
}

// Fungsi untuk memeriksa apakah pengguna sudah terdaftar
bool is_user_registered(const char *username) {
    FILE *fp = fopen(USERS_FILE, "r");
    if (fp == NULL) {
        perror("fopen");
        return false;
    }

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *user = strtok(line, ",");
        if (token && strcmp(token, username) == 0) {
            fclose(fp);
            return true;
        }
    }

    fclose(fp);
    return false;
}

// Fungsi untuk mendaftarkan pengguna baru
void register_user(const char *username, const char *password, client_info *client) {
    if (username == NULL || password == NULL) {
        send(client->socket, "Error: Username atau password tidak boleh kosong\n", 49, 0);
        return;
    }
    create_directory("/home/kali/arsipsisop/fp/DiscorIT", client);

    FILE *file = fopen(USERS_FILE, "r+");
    if (!file) {
        file = fopen(USERS_FILE, "w+");
        if (!file) {
            perror("Tidak dapat membuka atau membuat file");
            send(client->socket, "Error: Cannot open or create users.csv.\n", 39, 0);
            return;
        }
    }

    char line[256];
    bool user_exists = false;
    int user_count = 0;

    while (fgets(line, sizeof(line), file)) {
        char *token = strtok(line, ",");
        if (token == NULL) continue;
        token = strtok(NULL, ",");
        if (token && strcmp(token, username) == 0) {
            user_exists = true;
            break;
        }
        user_count++;
    }

    if (user_exists) {
        char response[100];
        snprintf(response, sizeof(response), "Error: %s sudah terdaftar\n", username);
        if (write(client->socket, response, strlen(response)) < 0) {
            perror("Gagal mengirim respons ke client");
        }
        fclose(file);
        return;
    }

    fseek(file, 0, SEEK_END);

    char salt[SALT_SIZE];
    snprintf(salt, sizeof(salt), "$2y$12$%.22s", "inistringsaltuntukbcrypt"); // SALT dapat dimodifikasi

    char hash[BCRYPT_HASHSIZE];
    if (bcrypt_hashpw(password, salt, hash) != 0) {
        fprintf(stderr, "Error: bcrypt_hashpw failed.\n"); // Debug error
        send(client->socket, "Error: Registration failed.\n", 27, 0);
        fclose(file);
        return;
    }

    fprintf(file, "%d,%s,%s,%s\n", user_count + 1, username, hash, user_count == 0 ? "ROOT" : "USER");
    fclose(file);

    send(client->socket, "Registration successful.\n", 25, 0);
}

// Fungsi untuk login pengguna
void login_user(int client_socket, char *username, char *password, ClientInfo *client) {
    FILE *fp = fopen("DiscorIT/users.csv", "r");
    if (fp == NULL) {
        perror("fopen");
        send(client_socket, "Login failed. Server error.\n", 28, 0);
        return;
    }

    char line[MAX_BUFFER_SIZE];
    bool found = false;
    while (fgets(line, MAX_BUFFER_SIZE, fp) != NULL) {
        char *user = strtok(line, ",");
        char *pass = strtok(NULL, ",");
        if (strcmp(user, username) == 0 && strcmp(pass, password) == 0) {
            found = true;
            strcpy(client->username, username);
            break;
        }
    }

    fclose(fp);

    if (found) {
        send(client_socket, "Login successful.\n", 18, 0);
        // Tambahkan logika untuk memperbarui informasi client di sini
    } else {
        send(client_socket, "Invalid username or password.\n", 30, 0);
    }
}

// Fungsi untuk menampilkan daftar channel
void list_channels(int client_socket) {
    char response[MAX_BUFFER_SIZE] = "List of channels:\n";
    for (int i = 0; i < channel_count; i++) {
        snprintf(response + strlen(response), MAX_BUFFER_SIZE - strlen(response), "%s\n", channels[i]); // Menggunakan snprintf
    }
    send(client_socket, response, strlen(response), 0);
}

// Fungsi untuk membuat channel
void create_channel(int client_socket, char *channel_name, char *key, ClientInfo *client) {
    if (channel_count >= MAX_CHANNELS) {
        send(client_socket, "Maximum channels reached.\n", 25, 0);
        return;
    }

    if (is_channel_exists(channel_name)) {
        send(client_socket, "Channel already exists.\n", 23, 0);
        return;
    }

    strcpy(channels[channel_count], channel_name);
    strcpy(channelKeys[channel_count], key);
    channel_count++;

    // Buat direktori channel dan subdirektori admin
    char channel_dir[MAX_BUFFER_SIZE];
    snprintf(channel_dir, MAX_BUFFER_SIZE, "DiscorIT/%s", channel_name);
    if (mkdir(channel_dir, 0755) == -1) {
        perror("mkdir");
        send(client_socket, "Failed to create channel.\n", 25, 0);
        return;
    }

    char admin_dir[MAX_BUFFER_SIZE];
    snprintf(admin_dir, MAX_BUFFER_SIZE, "%s/admin", channel_dir);
    if (mkdir(admin_dir, 0755) == -1) {
        perror("mkdir");
        send(client_socket, "Failed to create channel.\n", 25, 0);
        return;
    }

    // Tambahkan admin ke channel (user yang membuat channel)
    char auth_file[MAX_BUFFER_SIZE];
    snprintf(auth_file, MAX_BUFFER_SIZE, "%s/auth.csv", admin_dir);
    FILE *fp = fopen(auth_file, "a");
    if (fp == NULL) {
        perror("fopen");
        send(client_socket, "Failed to create channel.\n", 25, 0);
        return;
    }

    // Mendapatkan ID pengguna dari file users.csv
    int user_id = -1;
    FILE *user_fp = fopen("DiscorIT/users.csv", "r");
    if (user_fp != NULL) {
        char line[MAX_BUFFER_SIZE];
        while (fgets(line, MAX_BUFFER_SIZE, user_fp) != NULL) {
            char *name = strtok(line, ",");
            if (strcmp(name, client->username) == 0) {
                sscanf(line, "%d,", &user_id);
                break;
            }
        }
        fclose(user_fp);
    }

    if (user_id != -1) {
        fprintf(fp, "%d,%s,ADMIN\n", user_id, client->username);
    } else {
        fprintf(fp, "%s,ADMIN\n", client->username); // Jika ID tidak ditemukan, gunakan username saja
    }
    fclose(fp);

    // Tambahkan channel ke channels.csv
    fp = fopen("DiscorIT/channels.csv", "a");
    if (fp == NULL) {
        perror("fopen");
    } else {
        fprintf(fp, "%d,%s,%s\n", channel_count, channel_name, key);
        fclose(fp);
    }

    send(client_socket, "Channel created successfully.\n", 30, 0);

    char log_message[MAX_BUFFER_SIZE];
    snprintf(log_message, MAX_BUFFER_SIZE, "%s created channel \"%s\"", client->username, channel_name);
    write_log(channel_name, log_message);
}

// Fungsi untuk bergabung ke channel
void join_channel(int client_socket, char *channel_name, char *key, ClientInfo *client) {
    // Cek apakah channel ada
    if (!is_channel_exists(channel_name)) {
        send(client_socket, "Channel not found.\n", 18, 0);
        return;
    }

    // Temukan index channel
    int channelIndex = -1;
    for (int i = 0; i < channel_count; i++) {
        if (strcmp(channels[i], channel_name) == 0) {
            channelIndex = i;
            break;
        }
    }

    // Jika channel ditemukan, verifikasi key
    if (channelIndex != -1) {
        if (strcmp(channelKeys[channelIndex], key) == 0) {
            strcpy(client->channel, channel_name);
            strcpy(client->room, ""); // Reset room saat pindah channel
            send(client_socket, "Joined channel successfully.\n", 29, 0);

            char log_message[MAX_BUFFER_SIZE];
            snprintf(log_message, MAX_BUFFER_SIZE, "%s joined channel \"%s\"", client->username, channel_name);
            write_log(channel_name, log_message);
        } else {
            send(client_socket, "Incorrect channel key.\n", 22, 0);
        }
    }
}

void edit_channel(const char *old_channel, const char *new_channel) {
    FILE *file = fopen(CHANNELS_FILE, "r+");
    if (!file) {
        perror("fopen");
        return;
    }
    FILE *temp = fopen("temp.csv", "w");
    if (!temp) {
        perror("fopen temp");
        fclose(file);
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char *token = strtok(line, ",");
        if (token && strcmp(token, old_channel) == 0) {
            fprintf(temp, "%s,%s\n", new_channel, strtok(NULL, ","));
        } else {
            fprintf(temp, "%s", line);
        }
    }

    fclose(file);
    fclose(temp);

    remove(CHANNELS_FILE);
    rename("temp.csv", CHANNELS_FILE);
}

void delete_channel(const char *channel) {
    FILE *file = fopen(CHANNELS_FILE, "r+");
    if (!file) {
        perror("fopen");
        return;
    }
    FILE *temp = fopen("temp.csv", "w");
    if (!temp) {
        perror("fopen temp");
        fclose(file);
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char *token = strtok(line, ",");
        if (token && strcmp(token, channel) != 0) {
            fprintf(temp, "%s", line);
        }
    }

    fclose(file);
    fclose(temp);

    remove(CHANNELS_FILE);
    rename("temp.csv", CHANNELS_FILE);
}

// Fungsi untuk membuat room
void create_room(int client_socket, char *room_name, ClientInfo *client) {
    if (room_count >= MAX_ROOMS) {
        send(client_socket, "Maximum rooms reached.\n", 22, 0);
        return;
    }
    if (strlen(client->channel) == 0) { // Tambahkan pengecekan apakah user sudah di channel
        send(client_socket, "You are not in any channel.\n", 28, 0);
        return;
    }

    if (is_room_exists(room_name, client->channel)) {
        send(client_socket, "Room already exists.\n", 20, 0);
        return;
    }

    strcpy(rooms[room_count].roomName, room_name);
    strcpy(rooms[room_count].channelName, client->channel);
    room_count++;

    // Buat file chat.csv di dalam direktori room
    char room_dir[MAX_BUFFER_SIZE];
    snprintf(room_dir, MAX_BUFFER_SIZE, "DiscorIT/%s/%s", client->channel, room_name);
    if (mkdir(room_dir, 0755) == -1) {
        perror("mkdir");
        send(client_socket, "Failed to create room.\n", 22, 0);
        return;
    }

    char chat_file[MAX_BUFFER_SIZE];
    snprintf(chat_file, MAX_BUFFER_SIZE, "%s/chat.csv", room_dir);
    FILE *fp = fopen(chat_file, "w"); // Buat file kosong
    if (fp == NULL) {
        perror("fopen");
        send(client_socket, "Failed to create room.\n", 22, 0);
        return;
    }
    fclose(fp);

    send(client_socket, "Room created successfully.\n", 27, 0);

    char log_message[MAX_BUFFER_SIZE];
    snprintf(log_message, MAX_BUFFER_SIZE, "%s created room \"%s\"", client->username, room_name);
    write_log(client->channel, log_message);
}

// Fungsi untuk bergabung ke room
void join_room(int client_socket, char *room_name, ClientInfo *client) {
    if (strlen(client->channel) == 0) {
        send(client_socket, "You are not in any channel.\n", 28, 0);
        return;
    }
    if (!is_room_exists(room_name, client->channel)) {
        send(client_socket, "Room not found.\n", 15, 0);
        return;
    }
    strcpy(client->room, room_name);
    send(client_socket, "Joined room successfully.\n", 26, 0);

    char log_message[MAX_BUFFER_SIZE];
    snprintf(log_message, MAX_BUFFER_SIZE, "%s joined room \"%s\"", client->username, room_name);
    write_log(client->channel, log_message);
}

void edit_room(const char *channel, const char *old_room, const char *new_room) {
    char old_path[256], new_path[256];
    snprintf(old_path, sizeof(old_path), "DiscorIT/%s/%s", channel, old_room);
    snprintf(new_path, sizeof(new_path), "DiscorIT/%s/%s", channel, new_room);

    if (rename(old_path, new_path) != 0) {
        perror("rename");
    }
}

void delete_room(const char *channel, const char *room) {
    char path[256];
    snprintf(path, sizeof(path), "DiscorIT/%s/%s", channel, room);

    if (remove(path) != 0) {
        perror("remove");
    }
}

void send_chat(int client_socket, char *message, ClientInfo *client) {
    // Pastikan client berada di channel dan room
    if (strlen(client->channel) == 0 || strlen(client->room) == 0) {
        send(client_socket, "You are not in any channel or room.\n", 36, 0);
        return;
    }

    char chat_file[MAX_BUFFER_SIZE];
    snprintf(chat_file, MAX_BUFFER_SIZE, "DiscorIT/%s/%s/chat.csv", client->channel, client->room);

    // Buka file chat.csv dalam mode append
    FILE *fp = fopen(chat_file, "a");
    if (fp == NULL) {
        perror("fopen");
        send(client_socket, "Failed to send chat.\n", 20, 0);
        return;
    }

    // Dapatkan ID chat berikutnya
    int next_chat_id = 1;
    fseek(fp, 0, SEEK_END);
    if (ftell(fp) > 0) {
        fseek(fp, -1, SEEK_CUR); // Mundur satu karakter untuk melewati newline terakhir
        while (fgetc(fp) != '\n') {
            fseek(fp, -2, SEEK_CUR);
        }
        fscanf(fp, "%*d,%d", &next_chat_id);
        next_chat_id++;
    }

    char timestamp[80];
    get_current_time(timestamp);

    // Format pesan chat sebelum dikirim ke client lain
    char formatted_message[MAX_BUFFER_SIZE];
    snprintf(formatted_message, MAX_BUFFER_SIZE, "[%s][%d][%s] \"%s\"\n", timestamp, next_chat_id, client->username, message);

    fprintf(fp, "%s,%d,%s,%s\n", timestamp, next_chat_id, client->username, message);
    fclose(fp);

    broadcast_message(formatted_message, client->channel, client->room);
}

void edit_chat(const char *channel, const char *room, int chat_id, const char *new_text) {
    char path[256];
    snprintf(path, sizeof(path), "DiscorIT/%s/%s/chat.csv", channel, room);

    FILE *file = fopen(path, "r+");
    if (!file) {
        perror("fopen");
        return;
    }
    FILE *temp = fopen("temp.csv", "w");
    if (!temp) {
        perror("fopen temp");
        fclose(file);
        return;
    }

    char line[1024];
    while (fgets(line, sizeof(line), file)) {
        int id;
        sscanf(line, "%*s %d", &id);
        if (id == chat_id) {
            fprintf(temp, "%d,%s,%s\n", chat_id, strtok(NULL, ","), new_text);
        } else {
            fprintf(temp, "%s", line);
        }
    }

    fclose(file);
    fclose(temp);

    remove(path);
    rename("temp.csv", path);
}

void delete_chat(const char *channel, const char *room, int chat_id) {
    char path[256];
    snprintf(path, sizeof(path), "DiscorIT/%s/%s/chat.csv", channel, room);

    FILE *file = fopen(path, "r+");
    if (!file) {
        perror("fopen");
        return;
    }
    FILE *temp = fopen("temp.csv", "w");
    if (!temp) {
        perror("fopen temp");
        fclose(file);
        return;
    }

    char line[1024];
    while (fgets(line, sizeof(line), file)) {
        int id;
        sscanf(line, "%*s %d", &id);
        if (id != chat_id) {
            fprintf(temp, "%s", line);
        }
    }

    fclose(file);
    fclose(temp);

    remove(path);
    rename("temp.csv", path);
}

void ban_user(const char *channel, const char *username) {
    char path[256];
    snprintf(path, sizeof(path), "DiscorIT/%s/admin/auth.csv", channel);

    FILE *file = fopen(path, "r+");
    if (!file) {
        perror("fopen");
        return;
    }
    FILE *temp = fopen("temp.csv", "w");
    if (!temp) {
        perror("fopen temp");
        fclose(file);
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char temp_username[50];
        sscanf(line, "%*d,%49[^,]", temp_username);
        if (strcmp(temp_username, username) == 0) {
            char id[10], role[10];
            sscanf(line, "%[^,],%[^,],%*s", id, username);
            fprintf(temp, "%s,%s,BANNED\n", id, username);
        } else {
            fprintf(temp, "%s", line);
        }
    }

    fclose(file);
    fclose(temp);

    remove(path);
    rename("temp.csv", path);
}

void unban_user(const char *channel, const char *username) {
    char path[256];
    snprintf(path, sizeof(path), "DiscorIT/%s/admin/auth.csv", channel);

    FILE *file = fopen(path, "r+");
    if (!file) {
        perror("fopen");
        return;
    }
    FILE *temp = fopen("temp.csv", "w");
    if (!temp) {
        perror("fopen temp");
        fclose(file);
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char temp_username[50];
        sscanf(line, "%*d,%49[^,]", temp_username);
        if (strcmp(temp_username, username) == 0) {
            char id[10], role[10];
            sscanf(line, "%[^,],%[^,],%*s", id, username);
            fprintf(temp, "%s,%s,USER\n", id, username);
        } else {
            fprintf(temp, "%s", line);
        }
    }

    fclose(file);
    fclose(temp);

    remove(path);
    rename("temp.csv", path);
}

void remove_user(const char *channel, const char *username) {
    char path[256];
    snprintf(path, sizeof(path), "DiscorIT/%s/admin/auth.csv", channel);

    FILE *file = fopen(path, "r+");
    if (!file) {
        perror("fopen");
        return;
    }
    FILE *temp = fopen("temp.csv", "w");
    if (!temp) {
        perror("fopen temp");
        fclose(file);
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char temp_username[50];
        sscanf(line, "%*d,%49[^,]", temp_username);
        if (strcmp(temp_username, username) != 0) {
            fprintf(temp, "%s", line);
        }
    }

    fclose(file);
    fclose(temp);

    remove(path);
    rename("temp.csv", path);
}

// Fungsi untuk menangani perintah dari client
void *handle_client(void *arg) {
    client_info *cli = (client_info *)arg;
    char buffer[BUFFER_SIZE];
    int n;

    // Inisialisasi status client baru terhubung
    strcpy(cli->logged_in_user, "");
    strcpy(cli->logged_in_role, "");
    strcpy(cli->logged_in_channel, "");
    strcpy(cli->logged_in_room, "");

    while ((n = read(cli->socket, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[n] = '\0';
        printf("Pesan dari client: %s\n", buffer);

        char *command = strtok(buffer, " ");
        if (command == NULL) {
            send(cli->socket, "Error: Perintah tidak valid.\n", 28, 0);
            continue;
        }

        // ########## REGISTER ##########
        if (strcmp(command, "REGISTER") == 0) {
            char *username = strtok(NULL, " ");
            char *passwordFlag = strtok(NULL, " ");
            char *password = strtok(NULL, " ");
            if (username && passwordFlag && strcmp(passwordFlag, "-p") == 0 && password) {
                register_user(username, password, cli);
            } else {
                send(cli->socket, "Error: Invalid REGISTER format.\n", 31, 0);
            }

        // ########## LOGIN ##########
        } else if (strcmp(command, "LOGIN") == 0) {
            char *username = strtok(NULL, " ");
            char *passwordFlag = strtok(NULL, " ");
            char *password = strtok(NULL, " ");
            if (username && passwordFlag && strcmp(passwordFlag, "-p") == 0 && password) {
                login_user(username, password, cli);
            } else {
                send(cli->socket, "Error: Invalid LOGIN format.\n", 28, 0);
            }
        // ########## CREATE CHANNEL ##########
        } else if (strcmp(command, "CREATE") == 0) {
            if (strlen(cli->logged_in_user) == 0) { // Pastikan user sudah login
                send(cli->socket, "Error: You must be logged in to create a channel.\n", 49, 0);
                continue;
            }
            char *subcommand = strtok(NULL, " ");
            if (subcommand && strcmp(subcommand, "CHANNEL") == 0) {
                char *channel = strtok(NULL, " ");
                char *keyFlag = strtok(NULL, " ");
                char *key = strtok(NULL, " ");
                if (channel && keyFlag && strcmp(keyFlag, "-k") == 0 && key) {
                    create_channel(cli->logged_in_user, channel, key, cli);
                } else {
                    send(cli->socket, "Error: Invalid CREATE CHANNEL format.\n", 37, 0);
                }
            // ########## CREATE ROOM ##########
            } else if (subcommand && strcmp(subcommand, "ROOM") == 0 && strlen(cli->logged_in_channel) > 0) {
                char *room = strtok(NULL, " ");
                if (room) {
                    create_room(cli->logged_in_user, cli->logged_in_channel, room, cli);
                } else {
                    send(cli->socket, "Error: Room name is required.\n", 30, 0);
                }
            } else {
                send(cli->socket, "Error: Invalid CREATE format or not in a channel.\n", 48, 0);
            }
        // ########## LIST ##########
        } else if(strcmp(token, "LIST") == 0){
            char *subcommand = strtok(NULL, " ");
            if (subcommand && strcmp(subcommand, "CHANNEL") == 0) {
                list_channels(cli);
            } else if (subcommand && strcmp(subcommand, "ROOM") == 0) {
                if (strlen(cli->logged_in_channel) == 0) {
                    send(cli->socket, "Error: You are not in any channel.\n", 35, 0);
                } else {
                    list_rooms(cli->logged_in_channel, cli);
                }
            } else if (subcommand && strcmp(subcommand, "USER") == 0) {
                if (strlen(cli->logged_in_channel) == 0) {
                    send(cli->socket, "Error: You are not in any channel.\n", 35, 0);
                } else {
                    strstr(cli->logged_in_role, "ROOT") != NULL ? list_users_root(cli) : list_users(cli->logged_in_channel, cli);
                }
            } else {
                send(cli->socket, "Error: Invalid LIST format.\n", 27, 0);
            }
        // ########## JOIN CHANNEL ##########
        } else if (strcmp(token, "JOIN") == 0) {
            if (strlen(cli->logged_in_user) == 0) { // Pastikan user sudah login
                send(cli->socket, "Error: You must be logged in to join a channel.\n", 48, 0);
                continue;
            }

            char *subcommand = strtok(NULL, " ");
            if (subcommand && strcmp(subcommand, "CHANNEL") == 0) {
                char *channel = strtok(NULL, " ");
                char *key = strtok(NULL, "\n"); 
                // Menambahkan \n untuk mendapatkan key yang benar
                key[strcspn(key, "\n")] = 0; // Menghapus \n jika ada

                if (channel && key) {
                    join_channel(cli->logged_in_user, channel, key, cli);
                } else {
                    send(cli->socket, "Error: Channel name and key are required.\n", 41, 0);
                }
            // ########## JOIN ROOM ##########
            } else if (subcommand && strcmp(subcommand, "ROOM") == 0 && strlen(cli->logged_in_channel) > 0) {
                char *room = strtok(NULL, " ");
                if (room) {
                    join_room(cli->logged_in_channel, room, cli);
                } else {
                    send(cli->socket, "Error: Room name is required.\n", 30, 0);
                }
            } else {
                send(cli->socket, "Error: Invalid JOIN format.\n", 27, 0);
            }
        // ########## CHAT ##########
        } else if (strcmp(token, "CHAT") == 0) {
            if (strlen(cli->logged_in_channel) == 0 || strlen(cli->logged_in_room) == 0) {
                send(cli->socket, "Error: You must be in a channel and room to chat.\n", 49, 0);
                continue;
            }
            char *message = strtok(NULL, "\"");
            if (message == NULL) {
                send(cli->socket, "Error: Chat message is required.\n", 33, 0);
                continue;
            }
            send_chat(cli->logged_in_user, cli->logged_in_channel, cli->logged_in_room, message, cli);
        // ########## SEE CHAT ##########
        } else if (strcmp(token, "SEE") == 0) {
            token = strtok(NULL, " ");
            if (token == NULL || strcmp(token, "CHAT") != 0 || strlen(cli->logged_in_channel) == 0 || strlen(cli->logged_in_room) == 0) {
                send(cli->socket, "Error: Invalid SEE CHAT format or you are not in a room.\n", 55, 0);
            } else {
                see_chat(cli->logged_in_channel, cli->logged_in_room, cli);
            }
} else if (strcmp(token, "EDIT") == 0) {
            char *subcommand = strtok(NULL, " ");
            if (subcommand == NULL) {
                send(cli->socket, "Error: Invalid EDIT format.\n", 27, 0);
                continue;
            }

            // ########## EDIT CHAT ##########
            if (strcmp(subcommand, "CHAT") == 0) {
                char *id_str = strtok(NULL, " ");
                char *new_text = strtok(NULL, "\"");
                if (id_str == NULL || new_text == NULL || strlen(cli->logged_in_channel) == 0 || strlen(cli->logged_in_room) == 0) {
                    send(cli->socket, "Error: Invalid EDIT CHAT format or you are not in a room.\n", 55, 0);
                    continue;
                }
                int id_chat = atoi(id_str);
                edit_chat(cli->logged_in_channel, cli->logged_in_room, id_chat, new_text, cli);

            // ########## EDIT CHANNEL ##########
            } else if (strcmp(subcommand, "CHANNEL") == 0) {
                char *old_channel = strtok(NULL, " ");
                char *to_keyword = strtok(NULL, " ");
                char *new_channel = strtok(NULL, " ");
                if (old_channel == NULL || new_channel == NULL || strcmp(to_keyword, "TO") != 0) {
                    send(cli->socket, "Error: Invalid EDIT CHANNEL format.\n", 34, 0);
                    continue;
                }
                if (strlen(cli->logged_in_channel) > 0 || strlen(cli->logged_in_room) > 0) {
                    send(cli->socket, "Error: You must exit the current channel/room first.\n", 51, 0);
                    continue;
                } else {
                    edit_channel(old_channel, new_channel, cli);
                }
            // ########## EDIT ROOM ##########
            } else if (strcmp(subcommand, "ROOM") == 0) {
                char *old_room = strtok(NULL, " ");
                char *to_keyword = strtok(NULL, " ");
                char *new_room = strtok(NULL, " ");
                if (old_room == NULL || new_room == NULL || strcmp(to_keyword, "TO") != 0) {
                    send(cli->socket, "Error: Invalid EDIT ROOM format.\n", 31, 0);
                    continue;
                }
                if (strlen(cli->logged_in_room) > 0) {
                    send(cli->socket, "Error: You must exit the current room first.\n", 45, 0);
                    continue;
                } else {
                    edit_room(cli->logged_in_channel, old_room, new_room, cli);
                }

            // ########## EDIT PROFILE SELF ##########
            } else if (strcmp(subcommand, "PROFILE") == 0) {
                char *self_keyword = strtok(NULL, " ");
                char *option = strtok(NULL, " ");
                char *new_value = strtok(NULL, " ");
                if (self_keyword == NULL || new_value == NULL || strcmp(self_keyword, "SELF") != 0 || (strcmp(option, "-u") != 0 && strcmp(option, "-p") != 0)) {
                    send(cli->socket, "Error: Invalid EDIT PROFILE SELF format.\n", 39, 0);
                    continue;
                }
                bool is_password = (strcmp(option, "-p") == 0);
                edit_profile_self(cli->logged_in_user, new_value, is_password, cli);
            // ########## EDIT USER (ROOT) ##########
            } else if (strcmp(subcommand, "WHERE") == 0 && strcmp(cli->logged_in_role, "ROOT") == 0) {
                char *target_user = strtok(NULL, " ");
                char *option = strtok(NULL, " ");
                char *new_value = strtok(NULL, " ");
                if (target_user == NULL || option == NULL || new_value == NULL) {
                    send(cli->socket, "Error: Invalid EDIT WHERE format.\n", 32, 0);
                    continue;
                }
                bool is_password = (strcmp(option, "-p") == 0);
                edit_user(target_user, new_value, is_password, cli);
            } else {
                send(cli->socket, "Error: Invalid EDIT format.\n", 27, 0);
            }
        // ########## DEL ##########
        } else if (strcmp(token, "DEL") == 0){
            char *subcommand = strtok(NULL, " ");
            if (subcommand == NULL) {
                send(cli->socket, "Error: Format perintah DEL tidak valid.\n", 37, 0);
                continue;
            }
            
            // ########## DEL CHAT ##########
            if (strcmp(subcommand, "CHAT") == 0) {
                if (strlen(cli->logged_in_channel) == 0 || strlen(cli->logged_in_room) == 0) {
                    send(cli->socket, "Error: Anda belum tergabung dalam room.\n", 39, 0);
                    continue;
                }

                char *chat_id_str = strtok(NULL, " ");
                if (chat_id_str == NULL) {
                    send(cli->socket, "Error: Penggunaan perintah: DEL CHAT <id>\n", 41, 0);
                    continue;
                }
                int chat_id = atoi(chat_id_str);
                delete_chat(cli->logged_in_channel, cli->logged_in_room, chat_id, cli);

            // ########## DEL CHANNEL ##########
            } else if (strcmp(subcommand, "CHANNEL") == 0) {
                if (strlen(cli->logged_in_channel) > 0 || strlen(cli->logged_in_room) > 0) {
                    send(cli->socket, "Error: Anda harus keluar dari channel dan room terlebih dahulu.\n", 58, 0);
                    continue;
                }

                char *channel = strtok(NULL, " ");
                if (channel == NULL) {
                    send(cli->socket, "Error: Penggunaan perintah: DEL CHANNEL <channel>\n", 47, 0);
                    continue;
                }
                delete_channel(channel, cli);

            // ########## DEL ROOM ##########
            } else if (strcmp(subcommand, "ROOM") == 0) {
                if (strlen(cli->logged_in_channel) == 0) {
                    send(cli->socket, "Error: Anda harus bergabung ke dalam channel terlebih dahulu.\n", 56, 0);
                    continue;
                }
                char *room = strtok(NULL, " ");
                if (room == NULL) {
                    if (strlen(cli->logged_in_room) == 0) {
                        send(cli->socket, "Error: Anda harus berada di dalam room untuk menghapusnya.\n", 56, 0);
                        continue;
                    } else {
                        delete_room(cli->logged_in_channel, cli->logged_in_room, cli);
                    }
                } else if (strcmp(room, "ALL") == 0) {
                    if (strlen(cli->logged_in_room) > 0) {
                        send(cli->socket, "Error: Anda harus keluar dari room terlebih dahulu.\n", 50, 0);
                        continue;
                    } else {
                        delete_all_rooms(cli->logged_in_channel, cli);
                    }
                } else {
                    delete_room(cli->logged_in_channel, room, cli);
                }
            } else {
                send(cli->socket, "Error: Format perintah DEL tidak valid.\n", 37, 0);
            }

        // ########## BAN ##########
        } else if (strcmp(token, "BAN") == 0) {
            if (strlen(cli->logged_in_channel) == 0) {
                send(cli->socket, "Error: Anda belum bergabung dalam channel.\n", 42, 0);
                continue;
            }
            char *user_to_ban = strtok(NULL, " ");
            if (user_to_ban == NULL) {
                send(cli->socket, "Error: Format perintah BAN tidak valid.\n", 38, 0);
                continue;
            }
            ban_user(cli->logged_in_channel, user_to_ban, cli);

        // ########## UNBAN ##########
        } else if (strcmp(token, "UNBAN") == 0) {
            if (strlen(cli->logged_in_channel) == 0) {
                send(cli->socket, "Error: Anda belum bergabung dalam channel.\n", 42, 0);
                continue;
            }
            char *user_to_unban = strtok(NULL, " ");
            if (user_to_unban == NULL) {
                send(cli->socket, "Error: Format perintah UNBAN tidak valid.\n", 39, 0);
                continue;
            }
            unban_user(cli->logged_in_channel, user_to_unban, cli);

        // ########## REMOVE USER ##########
        } else if (strcmp(token, "REMOVE") == 0) {
            char *subcommand = strtok(NULL, " ");
            if (subcommand == NULL) {
                send(cli->socket, "Error: Format perintah REMOVE tidak valid.\n", 40, 0);
                continue;
            }
            if (strcmp(subcommand, "USER") == 0) {
                if (strlen(cli->logged_in_channel) == 0) {
                    send(cli->socket, "Error: Anda belum bergabung dalam channel.\n", 42, 0);
                    continue;
                }
                char *target_user = strtok(NULL, " ");
                if (target_user == NULL) {
                    send(cli->socket, "Error: Penggunaan perintah: REMOVE USER <username>\n", 48, 0);
                    continue;
                }
                remove_user(cli->logged_in_channel, target_user, cli);
            } else if (strcmp(cli->logged_in_role, "ROOT") == 0) { // Hanya ROOT yang bisa REMOVE tanpa USER
                remove_user_root(subcommand, cli);
            } else {
                send(cli->socket, "Error: Anda tidak memiliki izin untuk menghapus user secara permanen.\n", 64, 0);
            }
        // ########## EXIT ##########
        } else if (strcmp(token, "EXIT") == 0) {
            handle_exit(cli);
        } else {
            send(cli->socket, "Error: Perintah tidak dikenali.\n", 32, 0);
        }
    }

    // Hapus client dari daftar client
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; i++) {
        if (clients[i] == cli) {
            free(clients[i]); 
            clients[i] = NULL; 
            memmove(&clients[i], &clients[i + 1], (client_count - i - 1) * sizeof(client_info *));
            client_count--;
            break;
        }
    }
    pthread_mutex_unlock(&client_mutex);

    close(client_socket);
    pthread_exit(NULL);
}


int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    pthread_t thread_id[MAX_CLIENTS];
    
    // Inisialisasi channels.csv
    FILE *channelFile = fopen("DiscorIT/channels.csv", "r");
    if (channelFile) {
        char line[MAX_BUFFER_SIZE];
        while (fgets(line, sizeof(line), channelFile) != NULL && channel_count < MAX_CHANNELS) {
            sscanf(line, "%*d,%[^,],%s", channels[channel_count], channelKeys[channel_count]);
            channel_count++;
        }
        fclose(channelFile);
    }

    // Buat socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Atur opsi socket untuk penggunaan kembali alamat
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons(SERVER_PORT);

    // Bind socket ke alamat dan port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Mulai mendengarkan koneksi masuk
    if (listen(server_fd, 3) < 0) { // 3 adalah backlog, jumlah koneksi pending yang diizinkan
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", SERVER_PORT);

    while (1) { // Loop terus-menerus untuk menerima koneksi baru
        // Terima koneksi masuk
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        // Cek apakah sudah mencapai batas maksimum client
        pthread_mutex_lock(&client_mutex);
        if (client_count >= MAX_CLIENTS) {
            send(new_socket, "Server is full.\n", 15, 0);
            close(new_socket); 
            pthread_mutex_unlock(&client_mutex);
            continue;
        }

        // Tambahkan client baru ke array clients
        clients[client_count].socket = new_socket;
        client_count++;
        pthread_mutex_unlock(&client_mutex);

        // Buat thread baru untuk menangani client
        if (pthread_create(&thread_id[client_count - 1], NULL, handle_client, (void*)&new_socket) != 0) {
            perror("pthread_create");
            // Jika gagal membuat thread, tutup socket dan kurangi client_count
            close(new_socket);
            pthread_mutex_lock(&client_mutex);
            client_count--;
            pthread_mutex_unlock(&client_mutex);
        }
    }
    
    // Tutup server socket (tidak akan pernah tercapai karena loop tak terbatas)
    close(server_fd);
    return 0;
}
