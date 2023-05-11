#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#define AES_TEST_BUFFER_SIZE 4096

struct client_params
{
    struct sockaddr_in server_addr;
    char *message;
};

static long get_current_time(struct timespec *ts)
{
    if (clock_gettime(CLOCK_REALTIME, ts) < 0)
    {
        perror("clock_gettime");
        exit(1);
    }
    return 0;
}

static uint64_t timespec_diff_ns(struct timespec *start, struct timespec *end)
{
    uint64_t ns = 0;

    if (end->tv_nsec < start->tv_nsec)
    {
        ns += 1000000000 * (end->tv_sec - start->tv_sec - 1);
        ns += 1000000000 - start->tv_nsec + end->tv_nsec;
    }
    else
    {
        ns += 1000000000 * (end->tv_sec - start->tv_sec);
        ns += end->tv_nsec - start->tv_nsec;
    }
    return ns;
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

void *task_thread(void *thread_data)
{
    int sock_fd = -1;
    int ret;
    struct client_params *params = (struct client_params *)thread_data;

    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0)
        err_exit("SOCKET");

    ret = connect(sock_fd, (struct sockaddr *)&(params->server_addr), sizeof(struct sockaddr_in));
    if (ret < 0)
        err_exit("CONNECT");

    printf("[*] Successfully Established Connection\n");

    char *msg = params->message;
    ret = write(sock_fd, msg, strlen(msg));
    if (ret < 0)
        err_exit("WRITE");

    char recv_buf[AES_TEST_BUFFER_SIZE];
    int n = read(sock_fd, recv_buf, AES_TEST_BUFFER_SIZE);
    if (n < 0)
    {
        perror("read");
        exit(EXIT_FAILURE);
    }

    close(sock_fd);
    printf("[-] Finished Connection.\n");
    return NULL;
}

int main(int argc, char *argv[])
{
    if (argc < 4)
    {
        printf("[*] Usage: %s {Server IP} {Server Port} {Thread Num}\n", argv[0]);
        exit(1);
    }

    int ret;
    int THREADS_NUM = atoi(argv[3]);
    pthread_t tid[THREADS_NUM];
    char *server_ip = argv[1];
    int server_port = atoi(argv[2]);
    struct client_params params[THREADS_NUM];
    struct timespec start_time = {0};
    struct timespec end_time = {0};

    get_current_time(&start_time);

    for (int i = 0; i < THREADS_NUM; i++)
    {
        params[i].server_addr.sin_family = AF_INET;
        params[i].server_addr.sin_addr.s_addr = inet_addr(server_ip);
        params[i].server_addr.sin_port = htons(server_port);

        char *message = malloc(AES_TEST_BUFFER_SIZE);
        memset(message, 0xa5, AES_TEST_BUFFER_SIZE);
        params[i].message = message;

        ret = pthread_create(&tid[i], NULL, task_thread, (void *)&params[i]);
        if (ret != 0)
            errex_exit("PTHREAD_CREATE", 1, ret);
    }

    for (int i = 0; i < THREADS_NUM; i++)
    {
        pthread_join(tid[i], NULL);
        get_current_time(&end_time);
    }

    for (int i = 0; i < THREADS_NUM; i++)
    {
        free(params[i].message);
    }
    uint64_t time_diff = timespec_diff_ns(&start_time, &end_time);
    double time_ms = (double)time_diff / 1000000.0;
    printf("[*] Total threads execution time: %gms\n", time_ms);
}
