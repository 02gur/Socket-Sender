#!/usr/bin/env python3
"""
Simple test server for demonstrating Socket Sender.
This server can receive both TCP and UDP messages.
"""

import socket
import sys
import argparse
import threading


def tcp_server(host, port):
    """Run a simple TCP echo server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(5)
        print(f"TCP Server listening on {host}:{port}")
        
        while True:
            try:
                conn, addr = s.accept()
                with conn:
                    print(f"TCP Connection from {addr}")
                    data = conn.recv(4096)
                    if data:
                        message = data.decode('utf-8', errors='ignore')
                        print(f"TCP Received: {message}")
                        # Echo back
                        response = f"TCP Echo: {message}"
                        conn.sendall(response.encode('utf-8'))
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"TCP Error: {e}")


def udp_server(host, port):
    """Run a simple UDP echo server."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((host, port))
        print(f"UDP Server listening on {host}:{port}")
        
        while True:
            try:
                data, addr = s.recvfrom(4096)
                if data:
                    message = data.decode('utf-8', errors='ignore')
                    print(f"UDP Received from {addr}: {message}")
                    # Echo back
                    response = f"UDP Echo: {message}"
                    s.sendto(response.encode('utf-8'), addr)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"UDP Error: {e}")


def main():
    parser = argparse.ArgumentParser(description='Simple test server for Socket Sender')
    parser.add_argument('-H', '--host', default='localhost', help='Host to bind to')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Port to bind to')
    parser.add_argument('-P', '--protocol', choices=['tcp', 'udp', 'both'], 
                       default='tcp', help='Protocol(s) to use')
    
    args = parser.parse_args()
    
    threads = []
    
    try:
        if args.protocol in ['tcp', 'both']:
            tcp_thread = threading.Thread(target=tcp_server, args=(args.host, args.port))
            tcp_thread.daemon = True
            tcp_thread.start()
            threads.append(tcp_thread)
        
        if args.protocol in ['udp', 'both']:
            udp_port = args.port if args.protocol == 'udp' else args.port + 1
            udp_thread = threading.Thread(target=udp_server, args=(args.host, udp_port))
            udp_thread.daemon = True
            udp_thread.start()
            threads.append(udp_thread)
        
        print("Server(s) started. Press Ctrl+C to stop.")
        for thread in threads:
            thread.join()
            
    except KeyboardInterrupt:
        print("\nShutting down server(s)...")
        return 0


if __name__ == '__main__':
    sys.exit(main())
