#!/bin/bash
# Socket Sender Usage Examples
# These examples demonstrate various ways to use the Socket Sender

echo "Socket Sender Usage Examples"
echo "=============================="
echo ""

# Example 1: Simple TCP message
echo "Example 1: Send a simple TCP message"
echo "Command: python3 socket_sender.py -H localhost -p 8080 -m 'Hello, World!'"
echo ""

# Example 2: UDP message
echo "Example 2: Send a UDP message"
echo "Command: python3 socket_sender.py -H localhost -p 5000 -m 'UDP Message' -P udp"
echo ""

# Example 3: Verbose output
echo "Example 3: Send with verbose output"
echo "Command: python3 socket_sender.py -H localhost -p 8080 -m 'Test' -v"
echo ""

# Example 4: Read from file
echo "Example 4: Read message from file"
echo "Command: python3 socket_sender.py -H localhost -p 8080 -f examples/message.txt"
echo ""

# Example 5: Repeat sending
echo "Example 5: Send message multiple times with delay"
echo "Command: python3 socket_sender.py -H localhost -p 8080 -m 'Repeated' -r 5 -d 1"
echo ""

# Example 6: HTTP request
echo "Example 6: Send an HTTP request"
echo "Command: python3 socket_sender.py -H www.example.com -p 80 -m 'GET / HTTP/1.0\r\n\r\n' -v"
echo ""

# Example 7: JSON data
echo "Example 7: Send JSON data"
echo "Command: python3 socket_sender.py -H localhost -p 9000 -m '{\"action\":\"test\",\"data\":\"value\"}'"
echo ""

# Example 8: Custom timeout
echo "Example 8: Send with custom timeout"
echo "Command: python3 socket_sender.py -H localhost -p 8080 -m 'Test' -t 10"
echo ""

echo "Note: Make sure to start a test server first using:"
echo "python3 examples/test_server.py -H localhost -p 8080"
