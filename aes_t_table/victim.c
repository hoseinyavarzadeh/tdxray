#define VICTIM
#include "ttoolbox.h"
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <openssl/aes.h>
#include "config.h"

#define CRESET "\033[39m"
#define CGRN "\033[92m"

#define PORT 12123

static const unsigned char key[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
};

static AES_KEY key_struct;

static void encrypt_once(unsigned char byte) {
    unsigned char plaintext[] = {byte, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char ciphertext[128];
    unsigned int i, j;

    for (i = 0; i < NUMBER_OF_ENCRYPTIONS_VISUAL; ++i) {
        for (j = 1; j < 16; ++j)
            plaintext[j] = rand() % 256;

        AES_encrypt(plaintext, ciphertext, &key_struct);
    }
}

static int listen_for_key_bytes() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t sin_size;
    unsigned char buffer[0x100];
    ssize_t num_bytes, i;
    int opt = 1;

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Allow address reuse
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("setsockopt");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Bind socket
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    memset(&(server_addr.sin_zero), 0, 8);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
        perror("bind");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Listen
    if (listen(server_fd, 1) == -1) {
        perror("listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Listening on port " CGRN "%d" CRESET " ...\n", PORT);
    sin_size = sizeof(struct sockaddr_in);
    client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &sin_size);
    if (client_fd == -1) {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    printf("Connection from %s\n", inet_ntoa(client_addr.sin_addr));
    // Read byte-by-byte
    while ((num_bytes = read(client_fd, buffer, sizeof(buffer))) > 0) {
        for (i = 0; i < num_bytes; ++i)
            encrypt_once(buffer[i]);
        send(client_fd, buffer, 1, 0);
    }
    if (num_bytes < 0)
        perror("recv");

    printf("Done\n");
    close(client_fd);
    close(server_fd);
    return 0;
}

static unsigned long get_aes_encrypt_addr() {
    unsigned char ciphertext[32] = {0, };
    unsigned char plaintext[32] = {0, };

    AES_encrypt(plaintext, ciphertext, &key_struct);

    return (unsigned long) dlsym(RTLD_NEXT, "AES_encrypt");
}

int main() {
    char offset_s[128] = {0,};
    unsigned char* base, *probe, *termination, *aes_encrypt;
    size_t offset, encrypt_offset;
    FILE* f;
    size_t size, map_size;
    int fd;
    unsigned long probe_gpa, term_gpa, encrypt_gpa;

    if (getuid() != 0) {
        printf("I need root privileges\n");
        exit(EXIT_FAILURE);
    }

    fd = open("./openssl/libcrypto.so", O_RDONLY);
    size = lseek(fd, 0, SEEK_END);
    if (size == 0)
        exit(EXIT_FAILURE);

    map_size = size;
    if (map_size & 0xFFF != 0) {
        map_size |= 0xFFF;
        map_size += 1;
    }
    base = mmap(0, map_size, PROT_READ, MAP_SHARED, fd, 0);

    termination = mmap(0, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS | MAP_POPULATE | MAP_PRIVATE, -1 , 0);
    memset(termination, 0xba, PAGE_SIZE);

    AES_set_encrypt_key(key, 128, &key_struct);

    f = popen("readelf -a ./openssl/libcrypto.so | grep Te0 | grep -oE ': [a-z0-9]*' | awk '{print $2}'", "r");
    !fgets(offset_s, sizeof(offset_s) - 1, f);
    offset = strtoull(offset_s, 0, 16);
    fclose(f);

    f = popen("readelf -a ./openssl/libcrypto.so | grep AES_encrypt | grep -oE ': [a-z0-9]*' | awk '{print $2}'", "r");
    !fgets(offset_s, sizeof(offset_s) - 1, f);
    encrypt_offset = strtoull(offset_s, 0, 16);
    fclose(f);

    probe = base + offset;
    aes_encrypt = base + encrypt_offset;
    // encrypt_va = get_aes_encrypt_addr();

    printf("p: %lx\n", *(unsigned long*) probe);
    printf("e: %lx\n", *(unsigned long*) aes_encrypt);
    // printf("encrypt va: 0x%lx\n", encrypt_va);

    probe_gpa = virt_to_phys(probe);
    term_gpa = virt_to_phys(termination);
    encrypt_gpa = virt_to_phys(encrypt_once);
    // encrypt_gpa = virt_to_phys((void*)(((unsigned long) probe & ~0xffful) + 0x1000));

    printf("Probe GPA: 0x%lx\n", probe_gpa);
    printf("Termination Page GPA: 0x%lx\n", term_gpa);
    printf("Encrypt GPA: 0x%lx\n",  encrypt_gpa);
    printf("Start the attacker with " CGRN "./attacker 127.0.0.1 0x%lx 0x%lx 0x%lx" CRESET "\n", probe_gpa, term_gpa, encrypt_gpa);

    listen_for_key_bytes();
    asm volatile ("mov (%%rax), %%rax\n" :: "a"(termination));
    return 0;
}