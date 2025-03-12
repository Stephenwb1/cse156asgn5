README - Multi-threaded HTTP Proxy Server
Stephen Wend-Bell
swendbel@ucsc.edu
2036245

Overview:
This application is a multi-threaded HTTP proxy server that forwards client requests to the intended web server, retrieves responses, and relays them back to the client. It supports concurrent client connections using threading and maintains a log of requests processed.

List of Files:
- myproxy.c : Main source code for the proxy server
- Makefile : Build script for compiling the proxy
- doc/README.txt : Documentation file
- tests/ : Directory containing scripts and logs from test cases

How to Use:
1. Compile the proxy server:
   $ gcc -o proxy proxy.c -lpthread -lssl -lcrypto

2. Run the proxy server on a specified port:
   $ ./proxy <port>
   Example: ./myproxy -p 9000 -a forbidden_sites.txt -l access.log

3. Configure your web client (such as curl or a browser) to use the proxy:
   Example: $ curl -x localhost:9000 http://www.example.com/

4. The proxy logs access information and forwards the request to the destination server.

Internal Design:
- The proxy creates a listening socket and accepts client connections.
- Each client request is handled in a separate thread.
- The proxy establishes a connection to the target server and forwards the request.
- Responses are read from the server, logged, and sent back to the client.
- Access logs include client IP, request method, URL, status code, and response size.
- The server supports handling HTTPS connections using the CONNECT method.

Shortcomings:
- Does not support caching, so each request is forwarded in real-time.
- Limited error handling for malformed requests.
- Potential performance bottleneck under very high loads.


Test Cases:

Test 1: Basic HTTP Request
Description: A simple HTTP GET request through the proxy.
Command: curl -x localhost:9000 http://www.example.com/
Expected Result: The HTML content of www.example.com is displayed, and a log entry is recorded.

Test 2: Concurrent Requests
Description: Simulate multiple clients accessing the proxy.
Command: ab -n 100 -c 10 -X localhost:9000 http://www.ucsc.edu/
Expected Result: 100 requests processed with no failures, showing concurrency performance.

Test 3: Large Response Handling
Description: Request a large webpage to test buffer handling.
Command: curl -x localhost:9000 http://www.ucsc.edu/
Expected Result: Full webpage loads without hanging or truncation.

Test 4: HTTPS CONNECT Request
Description: Send an HTTPS request through the proxy.
Command: curl -x localhost:9000 -U user:pass -k https://www.google.com/
Expected Result: CONNECT method is processed correctly, and the request is forwarded securely.

Test 5: Invalid Request Handling
Description: Send an invalid request to test error handling.
Command: echo "INVALID REQUEST" | nc localhost 9000
Expected Result: Proxy rejects the request with an error message and logs it.

End of Document

