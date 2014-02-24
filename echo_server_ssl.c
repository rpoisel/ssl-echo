#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>

#include <openssl/ssl.h>

#include "util_socket.h"

#define MAX_STR_LEN 1024

/* additional info
 * http://simplestcodings.blogspot.com.br/2010/08/secure-server-client-using-openssl-in-c.html
 * http://stackoverflow.com/questions/11705815/client-and-server-communication-using-ssl-c-c-ssl-protocol-dont-works
 * http://lcalligaris.wordpress.com/2011/04/07/implementing-a-secure-socket/
 */

/* prototypes */
static void sigIntHandler(int sig);
static void setup_libssl();
static void load_certs_keys(const char* cert_file, const char* key_file);
static void connection_handler();
static ssize_t recvline(SSL* ssl, char* buf, size_t buf_len);
static ssize_t sendbuf(SSL* ssl, const char* buf, size_t buf_len);

/* globals */
int socket_listen = -1;
int socket_conn = -1;
SSL_CTX* ssl_ctx;

/* main entry point */
int main(int argc, char* argv[])
{
    short port = -1;
    char* endptr = NULL;

    setup_libssl();

    /* command line arguments */
    if (argc == 3)
    {
        port = strtol(argv[1], &endptr, 0);
        if (*endptr)
        {
            fprintf(stderr, "Invalid port number.\n");
            exit(EXIT_FAILURE);
        }
        load_certs_keys(argv[2], argv[2]);
    }
    else
    {
        fprintf(stderr, "Usage: %s <port-number> <certificate-file>\n",
                argv[0]);
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
    if (NULL != ssl_ctx)
    {
        SSL_CTX_free(ssl_ctx);
    }
    ssl_ctx = NULL;
    exit(EXIT_SUCCESS);
}

static void setup_libssl()
{
    SSL_library_init();
    SSL_load_error_strings();
    ssl_ctx = SSL_CTX_new(SSLv23_server_method());

    if (NULL == ssl_ctx)
    {
        fprintf(stderr, "Could not create SSL context(s).\n");
        exit(EXIT_FAILURE);
    }
}

static void load_certs_keys(const char* cert_file, const char* key_file)
{
    if (SSL_CTX_use_certificate_file(ssl_ctx, cert_file,
    SSL_FILETYPE_PEM) <= 0)
    {
        fprintf(stderr, "Could not load certificate file.\n");
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file,
    SSL_FILETYPE_PEM) <= 0)
    {
        fprintf(stderr, "Could not load private key file.\n");
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_check_private_key(ssl_ctx) != 1)
    {
        fprintf(stderr, "Private key does not match "
                "the public certificate\n");
        exit(EXIT_FAILURE);
    }
}

static void connection_handler()
{
    char buffer[MAX_STR_LEN] = { '\0' };
    unsigned cnt = -1;
    SSL* ssl; /* SSL descriptor */
    int ret = -1;
    ssize_t num_bytes_read = 0;

    if (NULL == (ssl = SSL_new(ssl_ctx)))
    {
        fprintf(stderr, "SSL_new failed.\n");
        exit(EXIT_FAILURE);
    }
    SSL_set_fd(ssl, socket_conn);

    ret = SSL_accept(ssl);
    if (ret != 1)
    {
        fprintf(stderr, "SSL_accept failed: ");
        switch (SSL_get_error(ssl, ret))
        {
            case SSL_ERROR_ZERO_RETURN:
                fprintf(stderr, "SSL_ERROR_ZERO_RETURNn");
                break;
            case SSL_ERROR_WANT_READ:
                fprintf(stderr, "SSL_ERROR_WANT_READn");
                break;
            case SSL_ERROR_WANT_WRITE:
                fprintf(stderr, "SSL_ERROR_WANT_WRITEn");
                break;
            case SSL_ERROR_WANT_CONNECT:
                fprintf(stderr, "SSL_ERROR_WANT_CONNECTn");
                break;
            case SSL_ERROR_WANT_ACCEPT:
                fprintf(stderr, "SSL_ERROR_WANT_ACCEPTn");
                break;
            case SSL_ERROR_WANT_X509_LOOKUP:
                fprintf(stderr, "SSL_ERROR_WANT_X509_LOOKUPn");
                break;
            case SSL_ERROR_SYSCALL:
                fprintf(stderr, "SSL_ERROR_SYSCALLn");
                break;
            case SSL_ERROR_SSL:
                fprintf(stderr, "SSL_ERROR_SSLn");
                break;
            default:
                break;
        }
        fprintf(stderr, "\n");
        SSL_free(ssl);
        close(socket_conn);
        return;
    }

    /* handle connections */
    for (;;)
    {
        num_bytes_read = recvline(ssl, buffer, MAX_STR_LEN);
        if (num_bytes_read < 0)
        {
            fprintf(stderr, "Could not read line. Ignoring client. \n");
            /* exit(EXIT_FAILURE); */
            break;
        }
        else if (num_bytes_read == 0)
        {
            fprintf(stderr, "Client has closed connection. \n");
            break;
        }
        else
        {
            fprintf(stderr, "Data received: %s", buffer);
            for (cnt = 0; cnt < strlen(buffer); cnt++)
            {
                buffer[cnt] = toupper(buffer[cnt]);
            }

            if (sendbuf(ssl, buffer, strlen(buffer)) < 0)
            {
                fprintf(stderr, "Could not write line.\n");
                /* exit(EXIT_FAILURE); */
                break;
            }
        }
    }

    /* close connection to client */
    SSL_free(ssl);
    if (close(socket_conn) < 0)
    {
        fprintf(stderr, "Error during close(2). \n");
        exit(EXIT_FAILURE);
    }
    buffer[0] = '\0';
    socket_conn = -1;
}

static ssize_t recvline(SSL* ssl, char* buf, size_t buf_len)
{
    size_t cnt = 0;
    ssize_t rc = 0;
    char* buf_ptr = buf;
    char c = '\0';

    for (cnt = 1; cnt < buf_len; cnt++)
    {
        if ((rc = SSL_read(ssl, &c, 1) > 0))
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

static ssize_t sendbuf(SSL* ssl, const char* buf, size_t buf_len)
{
    size_t chars_left = buf_len;
    ssize_t chars_written = 0;
    const char* buf_ptr = buf;

    while (chars_left > 0)
    {
        if ((chars_written = SSL_write(ssl, buf, chars_left)) <= 0)
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
