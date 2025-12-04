# Socket Sender Examples

This directory contains example files and scripts to help you get started with Socket Sender.

## Files

- **test_server.py** - A simple test server that echoes back messages (TCP and UDP)
- **message.txt** - Sample message file for testing file input
- **usage_examples.sh** - Shell script with example commands

## Running the Test Server

### TCP Server
```bash
python3 test_server.py -H localhost -p 8080 -P tcp
```

### UDP Server
```bash
python3 test_server.py -H localhost -p 5000 -P udp
```

### Both TCP and UDP (on different ports)
```bash
python3 test_server.py -H localhost -p 8080 -P both
# TCP on port 8080, UDP on port 8081
```

## Example Usage with Test Server

1. **Start the test server** (in one terminal):
```bash
cd examples
python3 test_server.py -H localhost -p 8080 -P tcp
```

2. **Send a message** (in another terminal):
```bash
python3 socket_sender.py -H localhost -p 8080 -m "Hello from Socket Sender!"
```

## Quick Examples

### Basic TCP Send
```bash
python3 ../socket_sender.py -H localhost -p 8080 -m "Hello, World!"
```

### UDP Send
```bash
python3 ../socket_sender.py -H localhost -p 5000 -m "UDP Message" -P udp
```

### Send from File
```bash
python3 ../socket_sender.py -H localhost -p 8080 -f message.txt
```

### Verbose Mode
```bash
python3 ../socket_sender.py -H localhost -p 8080 -m "Debug message" -v
```

### Repeated Sends
```bash
python3 ../socket_sender.py -H localhost -p 8080 -m "Test" -r 10 -d 0.5
```

## Testing Different Scenarios

### Test Connection Refused
```bash
# No server running on port 9999
python3 ../socket_sender.py -H localhost -p 9999 -m "Test"
```

### Test Timeout
```bash
# Very short timeout
python3 ../socket_sender.py -H localhost -p 8080 -m "Test" -t 1
```

### Send Binary Data
```bash
# Send raw bytes (you might need to adjust encoding)
echo -ne "\x00\x01\x02\x03" > binary.dat
python3 ../socket_sender.py -H localhost -p 8080 -f binary.dat
```

## Tips

- Use `-v` flag for debugging and detailed output
- The test server echoes back all messages it receives
- TCP is the default protocol
- Default timeout is 5 seconds
- Press Ctrl+C to stop the test server
