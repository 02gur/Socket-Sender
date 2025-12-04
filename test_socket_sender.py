#!/usr/bin/env python3
"""
Unit tests for Socket Sender.
"""

import unittest
import socket
import threading
import time
from socket_sender import SocketSender


class TestSocketSender(unittest.TestCase):
    """Test cases for SocketSender class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_host = 'localhost'
        self.tcp_port = 18080
        self.udp_port = 15000
        
    def start_tcp_server(self, port):
        """Start a simple TCP echo server for testing."""
        def run_server():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((self.test_host, port))
                s.listen(1)
                s.settimeout(5)
                try:
                    conn, addr = s.accept()
                    with conn:
                        data = conn.recv(4096)
                        if data:
                            conn.sendall(b'Echo: ' + data)
                except socket.timeout:
                    pass
        
        thread = threading.Thread(target=run_server)
        thread.daemon = True
        thread.start()
        time.sleep(0.1)  # Give server time to start
        return thread
    
    def start_udp_server(self, port):
        """Start a simple UDP echo server for testing."""
        def run_server():
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.bind((self.test_host, port))
                s.settimeout(5)
                try:
                    data, addr = s.recvfrom(4096)
                    if data:
                        s.sendto(b'Echo: ' + data, addr)
                except socket.timeout:
                    pass
        
        thread = threading.Thread(target=run_server)
        thread.daemon = True
        thread.start()
        time.sleep(0.1)  # Give server time to start
        return thread
    
    def test_tcp_send_success(self):
        """Test successful TCP message sending."""
        self.start_tcp_server(self.tcp_port)
        
        sender = SocketSender(
            host=self.test_host,
            port=self.tcp_port,
            protocol='tcp',
            timeout=2,
            verbose=False
        )
        
        result = sender.send("Test message")
        self.assertTrue(result)
    
    def test_udp_send_success(self):
        """Test successful UDP message sending."""
        self.start_udp_server(self.udp_port)
        
        sender = SocketSender(
            host=self.test_host,
            port=self.udp_port,
            protocol='udp',
            timeout=2,
            verbose=False
        )
        
        result = sender.send("Test message")
        self.assertTrue(result)
    
    def test_tcp_connection_refused(self):
        """Test TCP connection to non-existent server."""
        sender = SocketSender(
            host=self.test_host,
            port=19999,  # Port with no server
            protocol='tcp',
            timeout=1,
            verbose=False
        )
        
        result = sender.send("Test message")
        self.assertFalse(result)
    
    def test_invalid_protocol(self):
        """Test handling of invalid protocol."""
        sender = SocketSender(
            host=self.test_host,
            port=self.tcp_port,
            protocol='invalid',
            timeout=2,
            verbose=False
        )
        
        result = sender.send("Test message")
        self.assertFalse(result)
    
    def test_sender_initialization(self):
        """Test SocketSender initialization."""
        sender = SocketSender(
            host='example.com',
            port=8080,
            protocol='tcp',
            timeout=10,
            verbose=True
        )
        
        self.assertEqual(sender.host, 'example.com')
        self.assertEqual(sender.port, 8080)
        self.assertEqual(sender.protocol, 'tcp')
        self.assertEqual(sender.timeout, 10)
        self.assertTrue(sender.verbose)


if __name__ == '__main__':
    unittest.main()
