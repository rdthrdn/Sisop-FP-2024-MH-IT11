#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <crypt.h>
#include <errno.h>
#include <time.h>

#define PORT 8081

int socket_setup(int id, char *username)
{
	int status, valread, client_fd;
	struct sockaddr_in serv_addr;
	char message[4096];
	char buffer[4096] = { 0 };
	char current_directory[4096];
	strcpy(current_directory, username);

	if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
	{
		printf("\n Socket creation error \n");
		return -1;
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);

	if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) 
	{
		printf("\nInvalid address/ Address not supported \n");
		return -1;
	}

	if ((status = connect(client_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) < 0) 
	{
		printf("\nConnection Failed \n");
		return -1;
	}

	while(1)
	{
		printf("[%s] ", current_directory);
		memset(message, 0, sizeof(message));
		memset(buffer, 0, sizeof(buffer));

		fgets(message, 4096, stdin);
		message[strlen(message) - 1] = '\0';
		printf("\n");

    if (strncmp(message, "-channel", 8)!= 0 && strncmp(message, "-room", 5)!= 0)
    {
      printf("Invalid format\n");
      continue;
    }

    strcat(message, " MONITOR");
    strcat(message, id);

    send(client_fd, message, strlen(message), 0);
    valread = read(client_fd, buffer, sizeof(buffer) - 1);
    buffer[valread] = '\0';
    printf("%s\n", buffer);
	}

	close(client_fd);
	return 0;
}

char* generate_salt()
{
	char salt[] = "$2a$12$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
	const char* charset = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	for (int i = 0; i < 22; i++) 
		salt[7 + i] = charset[rand() % 64];
	return strdup(salt);
}

char* bcrypt(const char* password, const char* salt)
{
	char* hashed = crypt(password, salt);
	if (hashed == NULL) 
	{
		perror("crypt");
		exit(EXIT_FAILURE);
	}
	return strdup(hashed);
}

int verify_password(const char* password, const char* stored_hash)
{
	char salt[30];
	strncpy(salt, stored_hash, 29);
	salt[29] = '\0'; 

	char* hashed = crypt(password, salt);
	if (hashed == NULL) 
	{
		perror("crypt");
		return 0;
	}

	return strcmp(hashed, stored_hash) == 0;
}

void login(char* username, char* password) 
{
	FILE *users = fopen("users.csv", "r");
	if (users == NULL) return;

	char line[256];
	char file_username[50], file_password[100], role[10];
	int id;

	while (fgets(line, sizeof(line), users)) 
	{
		sscanf(line, "%d,%49[^,],%99[^,],%9s", &id, file_username, file_password, role);

		if (strcmp(username, file_username) == 0 && verify_password(password, file_password)) 
		{
			fclose(users);
			printf("%s berhasil login\n", username);
			socket_setup(id, username);
			return;
		}
	}

	printf("Username atau password salah\n");
	fclose(users);
}

int main(int argc, char const* argv[])
{
	srand(time(NULL));
	if (argc < 5)
	{
		printf("Usage: %s LOGIN username -p password\n", argv[0]);
		return 0;
	}

	else if (strcmp(argv[1], "LOGIN") == 0)
	{
		if (argc != 5)
		{
			printf("Usage: %s LOGIN username -p password\n", argv[0]);
			return 0;
		}

		if (strcmp(argv[3], "-p") != 0)
		{
			printf("Usage: %s LOGIN username -p password\n", argv[0]);
			return 0;
		}
		login(argv[2], argv[4]);
	}

	else
	{
		printf("Usage: %s REGISTER/LOGIN username -p password\n", argv[0]);
		return 0;
	}
	return 0;
}
