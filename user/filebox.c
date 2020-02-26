#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include <openssl/sha.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/io.h>

#define TMP_KEY_PATH "/tmp/filebox_crypto_key"
#define CONFIG_PATH "/etc/strongbox.cnf"
#define PASSWD_MAX_LENGTH 21
#define CMD_MAX_LENGTH 80
#define PATH_MAX_LENGTH 256

char PASSWD_FILE[PATH_MAX_LENGTH];

void sha256(char *src, char *result)
{
    unsigned char md[33] = {0};
    char tmp[3] = {0};
    SHA256(src, strlen(src), md);
    for (int i = 0; i < 32; i++)
    {
        sprintf(tmp, "%02x", md[i]);
        strcat(result, tmp);
    }
}

void set_password()
{
    char repeat_pwd[PASSWD_MAX_LENGTH] = {0};
    char pwd[PASSWD_MAX_LENGTH] = {0};
    while (1)
    {
        printf("Please input your password (length <= %d):\n", PASSWD_MAX_LENGTH - 1);
        system("stty -echo");
        scanf("%s", pwd);
        printf("\n");
        printf("Please repeat your password:\n");
        scanf("%s", repeat_pwd);
        printf("\n");
        system("stty echo");
        if (strcmp(pwd, repeat_pwd) != 0)
        {
            printf("Password is wrong! Please try again!\n");
        }
        else
        {
            break;
        }
    };
    char *sha256_pwd = malloc(65);
    memset(sha256_pwd, 0, 65);
    sha256(pwd, sha256_pwd);

    FILE *file = fopen(PASSWD_FILE, "w");
    fputs(sha256_pwd, file);
    fclose(file);
    free(sha256_pwd);
}

int check_password()
{
    char buf[65];
    char pwd[PASSWD_MAX_LENGTH] = {0};

    FILE *file = fopen(PASSWD_FILE, "r");
    char *read_sha256 = fgets(buf, 65, file);
    fclose(file);

    char *sha256_pwd = malloc(65);

    printf("Please login filebox program by inputting your password: \n");

    system("stty -echo");
    for (int i = 5; i >= 1; i--)
    {
        memset(sha256_pwd, 0, 65);
        scanf("%s", pwd);
        printf("\n");
        sha256(pwd, sha256_pwd);
        if (strcmp(read_sha256, sha256_pwd) == 0)
        {
            system("stty echo");
            printf("Login Successfully!\n");
            free(sha256_pwd);
            return 1;
        }
        else if (i > 1)
        {
            printf("Password error! You have %d chance left to try again!\n", i - 1);
            printf("Please input your password: \n");
        }
    }
    system("stty echo");
    printf("Login Fail!\n");
    free(sha256_pwd);
    return 0;
}

// produce cipher key for file encryption/decryption
// use sha256(passwd) to produce random num
void create_key(unsigned char *key)
{
    FILE *file;
    char *sha256_pwd;
    char buf[65];
    unsigned int seed = 0;

    file = fopen(PASSWD_FILE, "r");
    sha256_pwd = fgets(buf, 65, file);
    fclose(file);

    for (int i = 0; i < 64; i++)
        seed += sha256_pwd[i];
    seed *= 2;

    srand(seed);
    for (int i = 0; i < 16; i++)
    {
        *(key + i) = (unsigned char)(rand() % 256);
    }
}

int main(int argc, char *argv[])
{
    printf("    ______ _____ _      ______ ____   ______   __     \n"
           "   |  ____|_   _| |    |  ____|  _ \\ / __ \\ \\ / /  \n"
           "   | |__    | | | |    | |__  | |_) | |  | \\ V /     \n"
           "   |  __|   | | | |    |  __| |  _ <| |  | |> <       \n"
           "   | |     _| |_| |____| |____| |_) | |__| / . \\     \n"
           "   |_|    |_____|______|______|____/ \\____/_/ \\_\\  \n"
           "\n"
           "   *----------------------------------------------*  \n"
           "   |    By: Jiajun Du, Dingjie Zhong, Minkai Xu   |  \n"
           "   |            Version: 20191226                 |  \n"
           "   *----------------------------------------------*  \n");
    printf("Welcome to our filebox program!\n");

    strcpy(PASSWD_FILE, getenv("HOME"));
    strcat(PASSWD_FILE, "/.filebox_key");

    if (access(PASSWD_FILE, F_OK))
    {
        printf("You haven't used the program yet.\n");
        printf("Let's register it by following steps.\n");
        set_password();
    }

    int is_login = check_password();
    if (is_login == 0)
        return 0;

    // create cipher key and save it to TMP_KEY_FILE
    unsigned char *key = (unsigned char *)malloc(16);
    memset(key, 0, 16);
    create_key(key);

    FILE *file = fopen(TMP_KEY_PATH, "w");
    fwrite(key, 1, 16, file);
    fclose(file);

    char *path = malloc(PATH_MAX_LENGTH);
    getcwd(path, PATH_MAX_LENGTH);

    setbuf(stdin, NULL);
    char cmd[CMD_MAX_LENGTH];
    char tmp[CMD_MAX_LENGTH];
    while (1)
    {
        printf("> %s: ", path);
        fgets(cmd, CMD_MAX_LENGTH, stdin);
        cmd[strlen(cmd) - 1] = '\0'; //消除行末的换行符
        if (strcmp(cmd, "exit") == 0)
        {
            if (path)
                free(path);
            memset(cmd, 0, CMD_MAX_LENGTH);
            strcpy(cmd, "rm ");
            strcat(cmd, TMP_KEY_PATH);
            system(cmd);
            break;
        }
        else if (strcmp(cmd, "help") == 0)
        {
            printf("Commands are:\n\n"
                   "reset          reset your password\n"
                   "show           show filebox path\n"
                   "change <path>  change filebox path to <path>\n"
                   "cd <path>      change current working directory to <path>\n"
                   "help           show usage help\n"
                   "exit           exit this program\n"
                   "\n"
                   "Shell commands (ls, cat, cp, etc..) are also available.\n");
        }
        else if (strcmp(cmd, "reset") == 0)
        {
            set_password();
            setbuf(stdin, NULL);
        }
        else if (strcmp(cmd, "show") == 0)
        {
            if (access(CONFIG_PATH, F_OK) != 0)
            {
                printf("Config file does not exits! Need to use \'change\' to set a filebox path.\n");
            }
            else
            {
                FILE *file = fopen(CONFIG_PATH, "r");
                char filebox[PATH_MAX_LENGTH] = {0};
                fgets(filebox, PATH_MAX_LENGTH, file);
                printf("Filebox path is %s\n", filebox);
                fclose(file);
            }
        }
        else if (strncmp(cmd, "change", 6) == 0)
        {
            strcpy(tmp, cmd);
            int len = strlen(tmp);
            if (tmp[len - 1] != '/')
                tmp[len - 1] = '/'; //目录以/结尾
            char *p = strtok(tmp, " ");
            if (strcmp(p, "change") == 0)
            {
                p = strtok(NULL, " ");
                if (p != NULL)
                {
                    if (access(CONFIG_PATH, W_OK) == 0)
                    {
                        FILE *file = fopen(CONFIG_PATH, "w");
                        fputs(p, file);
                        printf("New filebox path is %s\n", p);
                        printf("Need to reload the kernel module to take effect.\n");
                        fclose(file);
                    }
                    else
                    {
                        printf("Failed to modify config file. Try to re-run this program with \'sudo\'?\n");
                    }
                }
            }
        }
        else if (strncmp(cmd, "cd", 2) == 0)
        {
            strcpy(tmp, cmd);
            char *p = strtok(tmp, " ");
            if (strcmp(p, "cd") == 0)
            {
                p = strtok(NULL, " ");
                if (p != NULL)
                {
                    chdir(p);
                    getcwd(path, PATH_MAX_LENGTH);
                }
            }
        }
        else
        {
            system(cmd);
        }
    }
    return 0;
}