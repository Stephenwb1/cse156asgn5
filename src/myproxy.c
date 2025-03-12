#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define TLS_client_method SSLv23_client_method
#endif

SSL_CTX *initialize_ssl() {
    // Initialize OpenSSL library (necessary for OpenSSL 1.0.x)
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Use SSLv23_client_method() for compatibility with older OpenSSL versions
    const SSL_METHOD *method = SSLv23_client_method();  // SSLv23 is a generic client method
    return SSL_CTX_new(method);
}

int verify_certificate(SSL *ssl) {
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        fprintf(stderr, "No certificate presented by the server.\n");
        return 0; // Fail verification
    }

    // Get verification result
    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        fprintf(stderr, "Certificate verification failed: %s\n",
                X509_verify_cert_error_string(verify_result));
        X509_free(cert);
        return 0; // Fail verification
    }

    // Print Certificate Issuer (Optional Debugging)
    X509_NAME *issuer = X509_get_issuer_name(cert);
    printf("Certificate Issued By: ");
    X509_NAME_print_ex_fp(stdout, issuer, 0, XN_FLAG_MULTILINE);
    printf("\n");

    X509_free(cert);
    return 1; // Success
}

#define MAX_BUFFER_SIZE 32000
#define MAX_REQUEST_SIZE 64000
#define MAX_FORBIDDEN_SITES 1000
#define DEFAULT_HTTPS_PORT "443"
#define HTTP_VERSION "HTTP/1.1"

// Global variables
char *forbidden_sites_file = NULL;
char *access_log_file = NULL;
char forbidden_sites[MAX_FORBIDDEN_SITES][256];
int num_forbidden_sites = 0;
pthread_mutex_t forbidden_sites_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
int allow_untrusted = 0;

// Signal handler flag
volatile sig_atomic_t reload_forbidden_sites = 0;

// Structure to hold client connection information
typedef struct {
  int client_socket;
  struct sockaddr_in client_addr;
} client_info;

// Function prototypes
void *handle_client(void *arg);
int load_forbidden_sites();
int is_site_forbidden(const char *host);
void log_access(const char *client_ip, const char *url,
                const char *request_line, int status_code, int response_size);
int connect_to_server(const char *host, const char *port);
void handle_sigint(int sig);
void handle_sigstp(int sig);
void send_error_response(int client_socket, int status_code,
                         const char *status_text);
int parse_url(const char *url, char *host, char *port, char *path);
void send_request(SSL *ssl, const char *request);
void receive_response(SSL *ssl);
SSL *connect_ssl(int sock, SSL_CTX *ctx);

void send_request(SSL *ssl, const char *request) {
  SSL_write(ssl, request, strlen(request));
}

void receive_response(SSL *ssl) {
  char buffer[4096];
  int bytes;
  while ((bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
    buffer[bytes] = '\0';
    printf("%s", buffer);
  }
}

SSL *connect_ssl(int sock, SSL_CTX *ctx) {
  SSL *ssl = SSL_new(ctx);
  SSL_set_fd(ssl, sock);
  if (SSL_connect(ssl) != 1) {
    ERR_print_errors_fp(stderr);
    return NULL;
  }
  if (!allow_untrusted) {
    if (!verify_certificate(ssl)) {
      fprintf(stdout, "Rejected connection due to invalid certificate\n");
      SSL_shutdown(ssl);
      SSL_free(ssl);
      return NULL;
    }
  }
  return ssl;
}

// Signal handler for SIGINT (Ctrl+C)
void handle_sigint(int sig __attribute__((unused))) {
  printf("Received SIGINT. Reloading forbidden sites...\n");
  reload_forbidden_sites = 1;
}

void handle_sigstp(int sig __attribute__((unused))) {
  printf("Received SIGSTP (CTRL+Z). Terminating...\n");
  exit(EXIT_SUCCESS);
}

// Load forbidden sites from file
int load_forbidden_sites() {
  FILE *file = fopen(forbidden_sites_file, "r");
  if (file == NULL) {
    perror("Error opening forbidden sites file");
    return -1;
  }

  pthread_mutex_lock(&forbidden_sites_mutex);

  num_forbidden_sites = 0;
  char line[256];

  while (fgets(line, sizeof(line), file) &&
         num_forbidden_sites < MAX_FORBIDDEN_SITES) {
    // Skip comments and empty lines
    if (line[0] == '#' || line[0] == '\n') {
      continue;
    }

    // Remove trailing newline
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n') {
      line[len - 1] = '\0';
    }

    strncpy(forbidden_sites[num_forbidden_sites], line,
            sizeof(forbidden_sites[0]) - 1);
    forbidden_sites[num_forbidden_sites][sizeof(forbidden_sites[0]) - 1] = '\0';
    num_forbidden_sites++;
  }

  pthread_mutex_unlock(&forbidden_sites_mutex);
  fclose(file);

  printf("Loaded %d forbidden sites\n", num_forbidden_sites);
  return 0;
}

// Check if a site is in the forbidden list
int is_site_forbidden(const char *host) {
  if (host == NULL) {
    return 0;
  }

  pthread_mutex_lock(&forbidden_sites_mutex);

  for (int i = 0; i < num_forbidden_sites; i++) {
    if (strcasecmp(host, forbidden_sites[i]) == 0) {
      pthread_mutex_unlock(&forbidden_sites_mutex);
      return 1;
    }
  }

  pthread_mutex_unlock(&forbidden_sites_mutex);
  return 0;
}

// Log access to the access log file
void log_access(const char *client_ip, const char *url,
                const char *request_line, int status_code, int response_size) {
  time_t now;
  struct tm *gmt;
  char time_str[64];

  time(&now);
  gmt = gmtime(&now);
  strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%S.000Z", gmt);

  pthread_mutex_lock(&log_mutex);

  printf("access_log_file: %s\n", access_log_file);
  fflush(stdout);
  FILE *log_file = fopen(access_log_file, "a");
  if (log_file == NULL) {
    perror("Error opening access log file");
    pthread_mutex_unlock(&log_mutex);
    return;
  }

  fprintf(log_file, "%s %s \"%s %s HTTP/1.1\" %d %d\n", time_str, client_ip,
          request_line, url, status_code, response_size);

  fclose(log_file);
  pthread_mutex_unlock(&log_mutex);
}

// Parse the URL to extract host, port, and path
int parse_url(const char *url, char *host, char *port, char *path) {
  // Check if the URL starts with http://
  if (strncmp(url, "http://", 7) != 0) {
    return -1;
  }

  const char *host_start = url + 7;
  const char *path_start = strchr(host_start, '/');
  const char *port_start = strchr(host_start, ':');

  // Extract the host
  if (path_start) {
    // Host with path
    if (port_start && port_start < path_start) {
      // Host with port and path
      strncpy(host, host_start, port_start - host_start);
      host[port_start - host_start] = '\0';

      // Extract port
      strncpy(port, port_start + 1, path_start - port_start - 1);
      port[path_start - port_start - 1] = '\0';
    } else {
      // Host without port but with path
      strncpy(host, host_start, path_start - host_start);
      host[path_start - host_start] = '\0';

      // Use default HTTPS port
      strcpy(port, DEFAULT_HTTPS_PORT);
    }

    // Extract path
    strcpy(path, path_start);
  } else {
    // Host without path
    if (port_start) {
      // Host with port but no path
      strncpy(host, host_start, port_start - host_start);
      host[port_start - host_start] = '\0';

      // Extract port
      strcpy(port, port_start + 1);
    } else {
      // Host without port and without path
      strcpy(host, host_start);

      // Use default HTTPS port
      strcpy(port, DEFAULT_HTTPS_PORT);
    }

    // Set path to /
    strcpy(path, "/");
  }

  return 0;
}

// Connect to the remote server
int connect_to_server(const char *host, const char *port) {
  struct addrinfo hints, *res, *res0;
  int server_socket;
  int error;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  error = getaddrinfo(host, port, &hints, &res0);
  if (error) {
    fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(error));
    return -1; // Cannot resolve hostname (502 Bad Gateway)
  }

  for (res = res0; res; res = res->ai_next) {
    server_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (server_socket < 0) {
      continue;
    }

    if (connect(server_socket, res->ai_addr, res->ai_addrlen) == 0) {
      break; // Successfully connected
    }

    close(server_socket);
    server_socket = -1;
  }

  freeaddrinfo(res0);

  if (server_socket < 0) {
    return -2; // Cannot connect to server (504 Gateway Timeout)
  }

  return server_socket;
}

// Send an error response to the client
void send_error_response(int client_socket, int status_code,
                         const char *status_text) {
  char response[MAX_BUFFER_SIZE];
  int response_len;

  response_len = snprintf(response, sizeof(response),
                          "%s %d %s\r\n"
                          "Content-Type: text/html\r\n"
                          "Connection: close\r\n\r\n"
                          "<html><head><title>%d %s</title></head>"
                          "<body><h1>%d %s</h1></body></html>\r\n",
                          HTTP_VERSION, status_code, status_text, status_code,
                          status_text, status_code, status_text);

  write(client_socket, response, response_len);
}

// Handle client connections
void *handle_client(void *arg) {
  client_info *info = (client_info *)arg;
  int client_socket = info->client_socket;
  struct sockaddr_in client_addr = info->client_addr;
  char client_ip[INET_ADDRSTRLEN];

  // Get client IP address
  inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);

  // Buffer for the HTTP request
  char request_buffer[MAX_REQUEST_SIZE] = {0};
  int total_bytes = 0;

  // Read the request from the client
  while ((total_bytes =
              read(client_socket, request_buffer, MAX_REQUEST_SIZE - 1)) > 0) {
    request_buffer[total_bytes] = '\0';
    if (strstr(request_buffer, "\r\n\r\n") != NULL)
      break; // End of headers
  }
  if (total_bytes <= 0) {
    close(client_socket);
    free(info);
    return NULL;
  }

  // Parse the HTTP request line
  char method[16], url[MAX_BUFFER_SIZE], http_version[16];
  if (sscanf(request_buffer, "%15s %8191s %15s", method, url, http_version) !=
      3) {
    send_error_response(client_socket, 400, "Bad Request");
    close(client_socket);
    free(info);
    return NULL;
  }

  // Only allow GET and HEAD requests
  if (strcmp(method, "GET") != 0 && strcmp(method, "HEAD") != 0) {
    send_error_response(client_socket, 501, "Not Implemented");
    close(client_socket);
    free(info);
    return NULL;
  }

  // Parse the URL to extract host, port, and path
  char host[256], port[16], path[MAX_BUFFER_SIZE];
  if (parse_url(url, host, port, path) != 0) {
    send_error_response(client_socket, 400, "Bad Request");
    close(client_socket);
    free(info);
    return NULL;
  }

  // Check for forbidden sites
  if (is_site_forbidden(host)) {
    send_error_response(client_socket, 403, "Forbidden URL");
    close(client_socket);
    free(info);
    return NULL;
  }

  // Connect to the destination server
  int server_socket = connect_to_server(host, port);
  if (server_socket < 0) {
    send_error_response(client_socket, 502, "Bad Gateway");
    close(client_socket);
    free(info);
    return NULL;
  }

  // Initialize SSL context
  SSL_CTX *ssl_ctx = initialize_ssl();
  if (!ssl_ctx) {
    send_error_response(client_socket, 500, "Internal Server Error");
    close(server_socket);
    close(client_socket);
    free(info);
    return NULL;
  }

  // Establish SSL connection
  SSL *ssl = connect_ssl(server_socket, ssl_ctx);
  if (!ssl) {
    send_error_response(client_socket, 502, "Bad Gateway");
    SSL_CTX_free(ssl_ctx);
    close(server_socket);
    close(client_socket);
    free(info);
    return NULL;
  }

  // Modify the request to include the `X-Forwarded-For` header
  char modified_request[MAX_REQUEST_SIZE] = {0};
  char *headers_start = strstr(request_buffer, "\r\n") + 2;
  snprintf(modified_request, sizeof(modified_request), "%s %s %s\r\n%s", method,
           path, HTTP_VERSION, headers_start);

  char xff_header[256];
  snprintf(xff_header, sizeof(xff_header), "\nX-Forwarded-For: %s\r\n",
           client_ip);

  // Insert X-Forwarded-For before end of headers
  char *end_of_headers = strstr(modified_request, "\r\n\r\n");
  if (end_of_headers) {
    char temp[MAX_REQUEST_SIZE] = {0};
    strcpy(temp, end_of_headers);
    *end_of_headers = '\0';
    strcat(modified_request, xff_header);
    strcat(modified_request, temp);
  }

  // Send the modified request to the server over SSL
  if (SSL_write(ssl, modified_request, strlen(modified_request)) <= 0) {
    send_error_response(client_socket, 502, "Bad Gateway");
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    close(server_socket);
    close(client_socket);
    free(info);
    return NULL;
  }

  printf("[handle_client] Sent modified request:\n%s\n", modified_request);
  fflush(stdout);

  // Read and forward the response to the client
  char buffer[MAX_BUFFER_SIZE];
  int bytes_read;
  int response_size = 0;
  int status_code = 0;
  int first_chunk = 1; // Track if it's the first chunk

  struct timeval timeout;
  timeout.tv_sec = 0; // 5-second timeout
  timeout.tv_usec = 500000;

  setsockopt(server_socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout,
             sizeof(timeout));

  /*printf("before reading\n");*/
  /*fflush(stdout);*/
  // also to get status_code and response size for log_access
  while ((bytes_read = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
    /*printf("bytes read in loop: %d\n", bytes_read);*/
    /*fflush(stdout);*/
    if (first_chunk) {
      // Null-terminate and parse the status code from the first response chunk
      buffer[bytes_read] = '\0';
      sscanf(buffer, "HTTP/%*s %d", &status_code);
      if (status_code == 0)
        status_code = 200; // Default to 200 if parsing fails
      first_chunk = 0;
      /*printf("first chunk = 0\n");*/
      /*fflush(stdout);*/
    }

    /*printf("response size: %d\n", response_size);*/
    /*fflush(stdout);*/
    response_size += bytes_read; // Accumulate total response size
    send(client_socket, buffer, bytes_read, 0);
    /*printf("while reading: bytes read: %d\n", bytes_read);*/
    /*fflush(stdout);*/
  }
  /*printf("bytes read after while loop: %d\n", bytes_read);*/
  /*fflush(stdout);*/

  // **Handle SSL_read blocking or errors**
  if (bytes_read < 0) {
    int ssl_err = SSL_get_error(ssl, bytes_read);
    if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
      printf("SSL_read timed out\n");
    } else {
      perror("SSL_read failed");
    }
  } else {
    printf("SSL_read finished normally.\n");
  }

  printf("after reading\n");
  fflush(stdout);
  log_access(client_ip, url, method, status_code, response_size);

  // Clean up
  SSL_free(ssl);
  SSL_CTX_free(ssl_ctx);
  close(server_socket);
  close(client_socket);
  free(info);

  return NULL;
}

int main(int argc, char *argv[]) {
  int listen_port = 0;
  int listen_socket;
  struct sockaddr_in server_addr;

  // Parse command line arguments
  int opt;
  while ((opt = getopt(argc, argv, "p:a:l:u")) != -1) {
    switch (opt) {
    case 'p':
      listen_port = atoi(optarg);
      break;
    case 'a':
      forbidden_sites_file = strdup(optarg);
      break;
    case 'l':
      access_log_file = strdup(optarg);
      break;
    case 'u':
      allow_untrusted = 1;
      break;
    default:
      fprintf(stderr,
              "Usage: %s -p listen_port -a forbidden_sites_file -l "
              "access_log_file [-u]\n",
              argv[0]);
      exit(EXIT_FAILURE);
    }
  }

  // Check if required arguments are provided
  if (listen_port == 0 || forbidden_sites_file == NULL ||
      access_log_file == NULL) {
    fprintf(
        stderr,
        "Usage: %s -p listen_port -a forbidden_sites_file -l access_log_file\n",
        argv[0]);
    exit(EXIT_FAILURE);
  }

  // Load forbidden sites
  if (load_forbidden_sites() != 0) {
    fprintf(stderr, "Failed to load forbidden sites.\n");
    exit(EXIT_FAILURE);
  }

  // Set up signal handler for SIGINT
  struct sigaction sa;
  sa.sa_handler = handle_sigint;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;

  if (sigaction(SIGINT, &sa, NULL) == -1) {
    perror("Error setting up signal handler");
    exit(EXIT_FAILURE);
  }

  // signal handler for sigstop (ctrl z)
  struct sigaction sa_tstp;
  sa_tstp.sa_handler = handle_sigstp;
  sigemptyset(&sa_tstp.sa_mask);
  sa_tstp.sa_flags = 0;

  if (sigaction(SIGTSTP, &sa_tstp, NULL) == -1) {
    perror("Error setting up SIGTSTP handler");
    exit(EXIT_FAILURE);
  }

  // Create socket
  listen_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (listen_socket < 0) {
    perror("Error creating socket");
    exit(EXIT_FAILURE);
  }

  // Set socket options for reuse
  int reuse = 1;
  if (setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &reuse,
                 sizeof(reuse)) < 0) {
    perror("Error setting socket options");
    close(listen_socket);
    exit(EXIT_FAILURE);
  }

  // Prepare server address
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(listen_port);

  // Bind socket
  if (bind(listen_socket, (struct sockaddr *)&server_addr,
           sizeof(server_addr)) < 0) {
    perror("Error binding socket");
    close(listen_socket);
    exit(EXIT_FAILURE);
  }

  // Listen for connections
  if (listen(listen_socket, 10) < 0) {
    perror("Error listening on socket");
    close(listen_socket);
    exit(EXIT_FAILURE);
  }

  printf("Proxy server started on port %d\n", listen_port);

  // Main loop for accepting connections
  while (1) {
    // Check if we need to reload forbidden sites
    if (reload_forbidden_sites) {
      printf("Reloading forbidden sites...\n");
      load_forbidden_sites();
      reload_forbidden_sites = 0;
    }

    // Accept client connection
    client_info *client = (client_info *)malloc(sizeof(client_info));
    if (client == NULL) {
      perror("Failed to allocate memory for client info");
      continue;
    }

    socklen_t client_len = sizeof(client->client_addr);
    client->client_socket = accept(
        listen_socket, (struct sockaddr *)&(client->client_addr), &client_len);

    if (client->client_socket < 0) {
      perror("Error accepting connection");
      free(client);
      continue;
    }

    // Create a thread to handle the client
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, handle_client, (void *)client) != 0) {
      perror("Error creating thread");
      close(client->client_socket);
      free(client);
      continue;
    }

    // Detach thread to automatically clean up when it exits
    pthread_detach(thread_id);
  }

  // Clean up (this code is unreachable, but good practice)
  close(listen_socket);
  free(forbidden_sites_file);
  free(access_log_file);

  return 0;
}
