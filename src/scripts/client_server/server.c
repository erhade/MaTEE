#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* UUID of the AES example trusted application */
#define TA_AES_UUID                                        \
    {                                                      \
        0x5dbac793, 0xf574, 0x4871,                        \
        {                                                  \
            0x8a, 0xd3, 0x04, 0x33, 0x1e, 0xc1, 0x7f, 0x24 \
        }                                                  \
    }

/*
 * TA_AES_CMD_PREPARE - Allocate resources for the AES ciphering
 * param[0] (value) a: TA_AES_ALGO_xxx, b: unused
 * param[1] (value) a: key size in bytes, b: unused
 * param[2] (value) a: TA_AES_MODE_ENCODE/_DECODE, b: unused
 * param[3] unused
 */
#define TA_AES_CMD_PREPARE 0

#define TA_AES_ALGO_ECB 0
#define TA_AES_ALGO_CBC 1
#define TA_AES_ALGO_CTR 2

#define TA_AES_SIZE_128BIT (128 / 8)
#define TA_AES_SIZE_256BIT (256 / 8)

#define TA_AES_MODE_ENCODE 1
#define TA_AES_MODE_DECODE 0

/*
 * TA_AES_CMD_SET_KEY - Allocate resources for the AES ciphering
 * param[0] (memref) key data, size shall equal key length
 * param[1] unused
 * param[2] unused
 * param[3] unused
 */
#define TA_AES_CMD_SET_KEY 1

/*
 * TA_AES_CMD_SET_IV - reset IV
 * param[0] (memref) initial vector, size shall equal block length
 * param[1] unused
 * param[2] unused
 * param[3] unused
 */
#define TA_AES_CMD_SET_IV 2

/*
 * TA_AES_CMD_CIPHER - Cipher input buffer into output buffer
 * param[0] (memref) input buffer
 * param[1] (memref) output buffer (shall be bigger than input buffer)
 * param[2] unused
 * param[3] unused
 */
#define TA_AES_CMD_CIPHER 3

#define AES_TEST_BUFFER_SIZE 4096
#define AES_TEST_KEY_SIZE 16
#define AES_BLOCK_SIZE 16

#define DECODE 0
#define ENCODE 1

#define ERREX_EXIT(err_api, exit_num, err_num)              \
    fprintf(stderr, "%s:%s\n", err_api, strerror(err_num)); \
    exit(exit_num)

typedef struct client_info
{
    TEEC_Context *ctx;
    int recv_sockfd;
    struct sockaddr_in client_addr;
} cInfo;

void prepare_aes(TEEC_Session *sess, int encode)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                     TEEC_VALUE_INPUT,
                                     TEEC_VALUE_INPUT,
                                     TEEC_NONE);

    op.params[0].value.a = TA_AES_ALGO_CTR;
    op.params[1].value.a = TA_AES_SIZE_128BIT;
    op.params[2].value.a = encode ? TA_AES_MODE_ENCODE : TA_AES_MODE_DECODE;

    res = TEEC_InvokeCommand(sess, TA_AES_CMD_PREPARE,
                             &op, &origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand(PREPARE) failed 0x%x origin 0x%x",
             res, origin);
}

void set_key(TEEC_Session *sess, TEEC_SharedMemory *key, size_t key_sz)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
                                     TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].memref.parent = key;
	op.params[0].memref.size = key_sz;
	op.params[0].memref.offset = 0;

    res = TEEC_InvokeCommand(sess, TA_AES_CMD_SET_KEY,
                             &op, &origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand(SET_KEY) failed 0x%x origin 0x%x",
             res, origin);
}

void set_iv(TEEC_Session *sess, TEEC_SharedMemory *iv, size_t iv_sz)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
                                     TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].memref.parent = iv;
	op.params[0].memref.size = iv_sz;
	op.params[0].memref.offset = 0;

    res = TEEC_InvokeCommand(sess, TA_AES_CMD_SET_IV,
                             &op, &origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand(SET_IV) failed 0x%x origin 0x%x",
             res, origin);
}

void cipher_buffer(TEEC_Session *sess, TEEC_SharedMemory *in, TEEC_SharedMemory *out, size_t sz)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
                                     TEEC_MEMREF_PARTIAL_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
	op.params[0].memref.parent = in;
	op.params[0].memref.size = sz;
	op.params[0].memref.offset = 0;
	op.params[1].memref.parent = out;
	op.params[1].memref.size = sz;
	op.params[1].memref.offset = 0;

    res = TEEC_InvokeCommand(sess, TA_AES_CMD_CIPHER,
                             &op, &origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand(CIPHER) failed 0x%x origin 0x%x",
             res, origin);
}

void err_exit(const char *err_api)
{
    const int exit_num = 1;
    perror(err_api);
    exit(exit_num);
}

void errex_exit(const char *err_api, const int exit_num, const int err_num)
{
    fprintf(stderr, "%s:%s\n", err_api, strerror(err_num));
    exit(exit_num);
}

void *client_thread(void *thread_data)
{
    cInfo *client = (cInfo *)thread_data;
    int size;
    char client_ip[INET_ADDRSTRLEN] = "";
    TEEC_UUID uuid = TA_AES_UUID;
    TEEC_Result res;
    TEEC_Session sess;
    uint32_t origin;
    TEEC_SharedMemory shm_key;
    TEEC_SharedMemory shm_iv;
    TEEC_SharedMemory shm_clear;
    TEEC_SharedMemory shm_ciph;
    TEEC_SharedMemory shm_temp;
    memset(&shm_key, 0, sizeof(shm_key));
    memset(&shm_iv, 0, sizeof(shm_iv));
    memset(&shm_clear, 0, sizeof(shm_clear));
    memset(&shm_ciph, 0, sizeof(shm_ciph));
    memset(&shm_temp, 0, sizeof(shm_temp));

    /* Open a session with the TA */
    res = TEEC_OpenSession(client->ctx, &sess, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
             res, origin);

    shm_key.buffer = malloc(AES_TEST_KEY_SIZE);
	shm_key.size = AES_TEST_KEY_SIZE;
	shm_key.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
    res = TEEC_RegisterSharedMemory(client->ctx, &shm_key);
    if (res != TEEC_SUCCESS)
		errx(1, "TEEC_RegisterSharedMemory failed with code 0x%x", res);

    shm_iv.buffer = malloc(AES_BLOCK_SIZE);
	shm_iv.size = AES_BLOCK_SIZE;
	shm_iv.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
    res = TEEC_RegisterSharedMemory(client->ctx, &shm_iv);
    if (res != TEEC_SUCCESS)
		errx(1, "TEEC_RegisterSharedMemory failed with code 0x%x", res);

    shm_clear.buffer = malloc(AES_TEST_BUFFER_SIZE);
	shm_clear.size = AES_TEST_BUFFER_SIZE;
	shm_clear.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
    res = TEEC_RegisterSharedMemory(client->ctx, &shm_clear);
    if (res != TEEC_SUCCESS)
		errx(1, "TEEC_RegisterSharedMemory failed with code 0x%x", res);

    shm_ciph.buffer = malloc(AES_TEST_BUFFER_SIZE);
	shm_ciph.size = AES_TEST_BUFFER_SIZE;
	shm_ciph.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
    res = TEEC_RegisterSharedMemory(client->ctx, &shm_ciph);
    if (res != TEEC_SUCCESS)
		errx(1, "TEEC_RegisterSharedMemory failed with code 0x%x", res);

    shm_temp.buffer = malloc(AES_TEST_BUFFER_SIZE);
	shm_temp.size = AES_TEST_BUFFER_SIZE;
	shm_temp.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
    res = TEEC_RegisterSharedMemory(client->ctx, &shm_temp);
    if (res != TEEC_SUCCESS)
		errx(1, "TEEC_RegisterSharedMemory failed with code 0x%x", res);

    inet_ntop(AF_INET, &client->client_addr.sin_addr.s_addr, client_ip, sizeof(client_ip));
    printf("[+] Client %s:%d Connected\n", client_ip, ntohs(client->client_addr.sin_port));

    while (1)
    {
        size = read(client->recv_sockfd, shm_clear.buffer, AES_TEST_BUFFER_SIZE);
        if (size < 0)
        {
            if (EINTR == errno)
                continue;

            err_exit("READ");
        }
        else if (size == 0) // closed by client
        {
            printf("[-] Client %s:%d Disconnected\n", client_ip, ntohs(client->client_addr.sin_port));
            break;
        }
        printf("[*] Processing Client %s:%d Task\n", client_ip, ntohs(client->client_addr.sin_port));

        prepare_aes(&sess, ENCODE);

        memset(shm_key.buffer, 0xa5, shm_key.size); /* Load some dummy value */
        set_key(&sess, &shm_key, AES_TEST_KEY_SIZE);

        memset(shm_iv.buffer, 0, shm_iv.size); /* Load some dummy value */
        set_iv(&sess, &shm_iv, AES_BLOCK_SIZE);

        cipher_buffer(&sess, &shm_clear, &shm_ciph, AES_TEST_BUFFER_SIZE);

        prepare_aes(&sess, DECODE);

        memset(shm_key.buffer, 0xa5, shm_key.size); /* Load some dummy value */
        set_key(&sess, &shm_key, AES_TEST_KEY_SIZE);

        memset(shm_iv.buffer, 0, shm_iv.size); /* Load some dummy value */
        set_iv(&sess, &shm_iv, AES_BLOCK_SIZE);

        cipher_buffer(&sess, &shm_ciph, &shm_temp, AES_TEST_BUFFER_SIZE);

        /* Check decoded is the clear content */
        if (memcmp(shm_clear.buffer, shm_temp.buffer, AES_TEST_BUFFER_SIZE))
            printf("[*] Clear text and decoded text differ => ERROR\n");
        else
            printf("[*] Clear text and decoded text match\n");

        while (write(client->recv_sockfd, shm_temp.buffer, AES_TEST_BUFFER_SIZE) == -1)
        {
            if (EINTR == errno)
                continue;

            err_exit("WRITE");
        }
    }

    TEEC_ReleaseSharedMemory(&shm_key);
    TEEC_ReleaseSharedMemory(&shm_iv);
    TEEC_ReleaseSharedMemory(&shm_clear);
    TEEC_ReleaseSharedMemory(&shm_ciph);
    TEEC_ReleaseSharedMemory(&shm_temp);
    close(client->recv_sockfd);
    free(client);
    TEEC_CloseSession(&sess);

    printf("[*] Thread %lu Successfully Exit\n", pthread_self());
    return NULL;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("[*] Usage: %s {Listen Port}\n", argv[0]);
        exit(1);
    }

    int listen_sock = -1;
    int recv_sock = -1;
    int ret = -1;
    int opt = 1;
    struct sockaddr_in server_addr, client_addr;
    socklen_t len = sizeof(client_addr);
    pthread_t tid;
    TEEC_Context ctx;
    TEEC_Result res;

    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    // TCP
    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock < 0)
        err_exit("SOCKET");

    // Port Reuse
    ret = setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const void *)&opt, sizeof(opt));
    if (ret < 0)
        err_exit("SETSOCKEOPT");

    // Binding IP, Port
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons((unsigned short)atoi(argv[1]));
    server_addr.sin_addr.s_addr = 0; // 0: bind all ip of the host, i.e. 0.0.0.0
    ret = bind(listen_sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (ret < 0)
        err_exit("BIND");

    // Listening
    ret = listen(listen_sock, 128); // normally set as 128
    if (ret < 0)
        err_exit("LISTEN");

    printf("Successfully Set the Server, Now Waiting For Connections\n");
    printf("[*] Listening On 0.0.0.0:%s ...\n\n", argv[1]);

    // Main Part
    while (1)
    {
        recv_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &len);
        if (recv_sock < 0)
        {
            if (errno == ECONNABORTED || errno == EINTR)
                continue;

            err_exit("ACCEPT");
        }

        cInfo *client_data = malloc(sizeof(cInfo));
        if (!client_data)
            fprintf(stderr, "MALLOC\n");

        client_data->ctx = &ctx;
        client_data->recv_sockfd = recv_sock;
        client_data->client_addr = client_addr;

        ret = pthread_create(&tid, NULL, client_thread, (void *)client_data);
        if (ret != 0)
            errex_exit("PTHREAD_CREATE", 1, ret);
        ret = pthread_detach(tid); // thread will automatically reclaim the resources at its Death
        if (ret != 0)
            errex_exit("PTHREAD_DETACH", 1, ret);
    }

    close(listen_sock);
    TEEC_FinalizeContext(&ctx);

    return 0;
}
