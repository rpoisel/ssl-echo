#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#include "util_socket.h"

#define MAX_STR_LEN 1024

/* prototypes */
static void sigIntHandler(int sig);
static void connection_handler();
static ssize_t recvline(int fd, char* buf, size_t buf_len);
static ssize_t sendbuf(int fd, const char* buf, size_t buf_len);

/* globals */
int socket_listen = -1;
int socket_conn = -1;

/* main entry point */
int main(int argc, char* argv[])
{
    short port = -1;
    char* endptr = NULL;

    /* command line arguments */
    if (argc == 2)
    {
        port = strtol(argv[1], &endptr, 0);
        if (*endptr)
        {
            fprintf(stderr, "Invalid port number.\n");
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        fprintf(stderr, "Usage: %s <port-number>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /* signal handler to shutdown clearly */
    if (signal(SIGINT, sigIntHandler) == SIG_ERR)
    {
        perror("signal");
        exit(EXIT_FAILURE);
    }

    socket_listen = setup_socket(port);

    /* wait for connections */
    for (;;)
    {
        if ((socket_conn = accept(socket_listen, NULL, NULL)) < 0)
        {
            perror("accept");
            exit(EXIT_FAILURE);
        }
        connection_handler();
    }

    return EXIT_SUCCESS;
}

static void sigIntHandler(int sig)
{
    fprintf(stderr, "Shutting down ... \n");
    if (socket_listen != -1)
    {
        close(socket_listen);
    }
    if (socket_conn != -1)
    {
        close(socket_conn);
    }
    exit(EXIT_SUCCESS);
}

static void connection_handler()
{
    char buffer[MAX_STR_LEN] = { '\0' };
    unsigned cnt = -1;

    /* handle connections */
    if (recvline(socket_conn, buffer, MAX_STR_LEN) < 0)
    {
        fprintf(stderr, "Could not read line. Ignoring client. \n");
        exit(EXIT_FAILURE);
    }
    else
    {
        for (cnt = 0; cnt < strlen(buffer); cnt++)
        {
            buffer[cnt] = toupper(buffer[cnt]);
        }

        if (sendbuf(socket_conn, buffer, strlen(buffer)) < 0)
        {
            fprintf(stderr, "Could not write line.\n");
            exit(EXIT_FAILURE);
        }
    }

    /* close connection to client */
    if (close(socket_conn) < 0)
    {
        fprintf(stderr, "Error during close(2). \n");
        exit(EXIT_FAILURE);
    }
    buffer[0] = '\0';
    socket_conn = -1;
}

static ssize_t recvline(int fd, char* buf, size_t buf_len)
{
    size_t cnt = 0;
    ssize_t rc = 0;
    char* buf_ptr = buf;
    char c = '\0';

    for (cnt = 1; cnt < buf_len; cnt++)
    {
        if ((rc = recv(fd, &c, 1, 0) > 0))
        {
            *buf_ptr = c;
            buf_ptr++;
            if (c == '\n')
            {
                break;
            }
        }
        else if (rc == 0)
        {
            if (cnt == 1)
            {
                return 0;
            }
            else
            {
                break;
            }
        }
        else
        {
            if (errno == EINTR)
            {
                continue;
            }
            fprintf(stderr, "Error during recv(2).\n");
            exit(EXIT_FAILURE);
        }
    }
    *buf_ptr = '\0';
    return cnt;
}

static ssize_t sendbuf(int fd, const char* buf, size_t buf_len)
{
    size_t chars_left = buf_len;
    ssize_t chars_written = 0;
    const char* buf_ptr = buf;

    while (chars_left > 0)
    {
        if ((chars_written = send(fd, buf, chars_left, 0)) <= 0)
        {
            if (errno == EINTR)
            {
                chars_written = 0;
            }
            else
            {
                fprintf(stderr, "Error during send(2). \n");
                return -1;
            }
        }
        chars_left -= chars_written;
        buf_ptr += chars_written;
    }

    return buf_len;
}
