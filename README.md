# Socket Sender

A versatile network socket sender for TCP and UDP protocols. Send data over network sockets with a simple command-line interface.

## Features

- **TCP and UDP Support**: Send data using either TCP or UDP protocols
- **Flexible Input**: Send messages directly via command line or from files
- **Repeat Sending**: Send messages multiple times with configurable delays
- **Timeout Control**: Configure socket timeout for your needs
- **Verbose Logging**: Optional detailed logging for debugging
- **Response Handling**: Automatically receives and displays responses from servers
- **Easy to Use**: Simple command-line interface with sensible defaults

## Installation

### From Source

```bash
git clone https://github.com/02gur/Socket-Sender.git
cd Socket-Sender
python setup.py install
```

### Using pip (Local)

```bash
pip install -e .
```

## Usage

### Basic Examples

#### Send a TCP message:
```bash
python socket_sender.py -H localhost -p 8080 -m "Hello, World!"
```

#### Send a UDP message:
```bash
python socket_sender.py -H 192.168.1.100 -p 5000 -m "UDP Message" -P udp
```

#### Send with verbose output:
```bash
python socket_sender.py -H localhost -p 8080 -m "Test" -v
```

#### Read message from file:
```bash
python socket_sender.py -H localhost -p 8080 -f message.txt
```

#### Repeat sending with delay:
```bash
python socket_sender.py -H localhost -p 8080 -m "Repeated" -r 5 -d 1
```

### Command-Line Options

```
usage: socket_sender.py [-h] -H HOST -p PORT [-P {tcp,udp}] [-m MESSAGE]
                        [-f FILE] [-t TIMEOUT] [-v] [-r REPEAT] [-d DELAY]

Socket Sender - Send data over TCP or UDP sockets

optional arguments:
  -h, --help            show this help message and exit
  -H HOST, --host HOST  Target host address (IP or hostname)
  -p PORT, --port PORT  Target port number
  -P {tcp,udp}, --protocol {tcp,udp}
                        Protocol to use (default: tcp)
  -m MESSAGE, --message MESSAGE
                        Message to send
  -f FILE, --file FILE  Read message from file
  -t TIMEOUT, --timeout TIMEOUT
                        Socket timeout in seconds (default: 5)
  -v, --verbose         Enable verbose output
  -r REPEAT, --repeat REPEAT
                        Number of times to repeat sending (default: 1)
  -d DELAY, --delay DELAY
                        Delay between repeated sends in seconds (default: 0)
```

## Use Cases

- **Testing Network Services**: Quickly test TCP/UDP servers during development
- **Network Debugging**: Send test packets to diagnose network issues
- **Load Testing**: Repeatedly send messages to test server performance
- **Protocol Testing**: Verify server responses to different message types
- **Automation**: Integrate into scripts for automated network testing

## Examples

### Testing a Web Server
```bash
python socket_sender.py -H www.example.com -p 80 -m "GET / HTTP/1.0\r\n\r\n" -v
```

### Sending JSON Data
```bash
python socket_sender.py -H localhost -p 9000 -m '{"action":"test","data":"value"}'
```

### Load Testing
```bash
python socket_sender.py -H localhost -p 8080 -m "Load test" -r 100 -d 0.1
```

## Requirements

- Python 3.7 or higher
- No external dependencies (uses Python standard library only)

## Development

### Running Tests

```bash
pytest
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Author

Özgür Ş.

## Acknowledgments

Built with Python's standard socket library for reliable network communication.
