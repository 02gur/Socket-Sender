#!/usr/bin/env python3
"""
Socket Sender - A versatile network socket sender for TCP and UDP protocols.

This module provides functionality to send data over network sockets using
both TCP and UDP protocols with various configuration options.
"""

import socket
import sys
import argparse
import logging
import time
from typing import Optional


class SocketSender:
    """A class to handle sending data over TCP and UDP sockets."""
    
    def __init__(self, host: str, port: int, protocol: str = 'tcp', 
                 timeout: int = 5, verbose: bool = False):
        """
        Initialize the SocketSender.
        
        Args:
            host: Target host address (IP or hostname)
            port: Target port number
            protocol: Protocol to use ('tcp' or 'udp')
            timeout: Socket timeout in seconds
            verbose: Enable verbose logging
        """
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.timeout = timeout
        self.verbose = verbose
        
        # Setup logging
        log_level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
    def send_tcp(self, message: str) -> bool:
        """
        Send a message over TCP.
        
        Args:
            message: The message to send
            
        Returns:
            True if successful, False otherwise
        """
        sock = None
        try:
            self.logger.info(f"Establishing TCP connection to {self.host}:{self.port}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            sock.connect((self.host, self.port))
            self.logger.debug(f"Connected to {self.host}:{self.port}")
            
            # Send the message
            message_bytes = message.encode('utf-8')
            sock.sendall(message_bytes)
            self.logger.info(f"Sent {len(message_bytes)} bytes over TCP")
            
            # Try to receive a response
            try:
                response = sock.recv(4096)
                if response:
                    self.logger.info(f"Received response: {response.decode('utf-8', errors='ignore')}")
            except socket.timeout:
                self.logger.debug("No response received (timeout)")
            
            return True
            
        except socket.timeout:
            self.logger.error(f"Connection timeout to {self.host}:{self.port}")
            return False
        except ConnectionRefusedError:
            self.logger.error(f"Connection refused by {self.host}:{self.port}")
            return False
        except Exception as e:
            self.logger.error(f"Error sending TCP message: {e}")
            return False
        finally:
            if sock:
                sock.close()
                self.logger.debug("TCP socket closed")
    
    def send_udp(self, message: str) -> bool:
        """
        Send a message over UDP.
        
        Args:
            message: The message to send
            
        Returns:
            True if successful, False otherwise
        """
        sock = None
        try:
            self.logger.info(f"Sending UDP message to {self.host}:{self.port}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send the message
            message_bytes = message.encode('utf-8')
            sock.sendto(message_bytes, (self.host, self.port))
            self.logger.info(f"Sent {len(message_bytes)} bytes over UDP")
            
            # Try to receive a response
            try:
                response, addr = sock.recvfrom(4096)
                if response:
                    self.logger.info(f"Received response from {addr}: {response.decode('utf-8', errors='ignore')}")
            except socket.timeout:
                self.logger.debug("No response received (timeout)")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending UDP message: {e}")
            return False
        finally:
            if sock:
                sock.close()
                self.logger.debug("UDP socket closed")
    
    def send(self, message: str) -> bool:
        """
        Send a message using the configured protocol.
        
        Args:
            message: The message to send
            
        Returns:
            True if successful, False otherwise
        """
        if self.protocol == 'tcp':
            return self.send_tcp(message)
        elif self.protocol == 'udp':
            return self.send_udp(message)
        else:
            self.logger.error(f"Unsupported protocol: {self.protocol}")
            return False


def main():
    """Main entry point for the Socket Sender CLI."""
    parser = argparse.ArgumentParser(
        description='Socket Sender - Send data over TCP or UDP sockets',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Send a TCP message
  python socket_sender.py -H localhost -p 8080 -m "Hello, World!"
  
  # Send a UDP message
  python socket_sender.py -H 192.168.1.100 -p 5000 -m "UDP Message" -P udp
  
  # Send with verbose output
  python socket_sender.py -H localhost -p 8080 -m "Test" -v
  
  # Read message from file
  python socket_sender.py -H localhost -p 8080 -f message.txt
        """
    )
    
    parser.add_argument('-H', '--host', 
                       required=True,
                       help='Target host address (IP or hostname)')
    parser.add_argument('-p', '--port',
                       type=int,
                       required=True,
                       help='Target port number')
    parser.add_argument('-P', '--protocol',
                       choices=['tcp', 'udp'],
                       default='tcp',
                       help='Protocol to use (default: tcp)')
    parser.add_argument('-m', '--message',
                       help='Message to send')
    parser.add_argument('-f', '--file',
                       help='Read message from file')
    parser.add_argument('-t', '--timeout',
                       type=int,
                       default=5,
                       help='Socket timeout in seconds (default: 5)')
    parser.add_argument('-v', '--verbose',
                       action='store_true',
                       help='Enable verbose output')
    parser.add_argument('-r', '--repeat',
                       type=int,
                       default=1,
                       help='Number of times to repeat sending (default: 1)')
    parser.add_argument('-d', '--delay',
                       type=float,
                       default=0,
                       help='Delay between repeated sends in seconds (default: 0)')
    
    args = parser.parse_args()
    
    # Get the message
    message = None
    if args.message:
        message = args.message
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                message = f.read()
        except Exception as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            return 1
    else:
        parser.error("Either -m/--message or -f/--file must be provided")
    
    # Create sender and send message
    sender = SocketSender(
        host=args.host,
        port=args.port,
        protocol=args.protocol,
        timeout=args.timeout,
        verbose=args.verbose
    )
    
    success_count = 0
    for i in range(args.repeat):
        if args.repeat > 1:
            sender.logger.info(f"Send attempt {i+1}/{args.repeat}")
        
        if sender.send(message):
            success_count += 1
        
        if i < args.repeat - 1 and args.delay > 0:
            time.sleep(args.delay)
    
    if args.repeat > 1:
        sender.logger.info(f"Completed {success_count}/{args.repeat} successful sends")
    
    return 0 if success_count > 0 else 1


if __name__ == '__main__':
    sys.exit(main())
