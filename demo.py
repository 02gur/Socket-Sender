#!/usr/bin/env python3
"""
Socket Sender Demo Script
This script demonstrates the capabilities of Socket Sender by starting
a test server and running various send operations.
"""

import subprocess
import time
import sys
import signal


def run_command(cmd, description):
    """Run a command and display its output."""
    print(f"\n{'='*60}")
    print(f"Demo: {description}")
    print(f"Command: {cmd}")
    print('='*60)
    
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    
    return result.returncode == 0


def main():
    """Run the demo."""
    print("Socket Sender Demo")
    print("==================\n")
    print("Starting TCP test server on port 8080...")
    
    # Start test server in background
    server = subprocess.Popen(
        ['python3', 'examples/test_server.py', '-H', 'localhost', '-p', '8080', '-P', 'tcp'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Give server time to start
    time.sleep(1)
    
    try:
        # Demo 1: Simple TCP message
        run_command(
            'python3 socket_sender.py -H localhost -p 8080 -m "Hello, World!"',
            "Send a simple TCP message"
        )
        time.sleep(0.5)
        
        # Demo 2: Verbose output
        run_command(
            'python3 socket_sender.py -H localhost -p 8080 -m "Verbose test" -v',
            "Send with verbose output"
        )
        time.sleep(0.5)
        
        # Demo 3: Send from file
        run_command(
            'python3 socket_sender.py -H localhost -p 8080 -f examples/message.txt',
            "Send message from file"
        )
        time.sleep(0.5)
        
        # Demo 4: Repeat sending
        run_command(
            'python3 socket_sender.py -H localhost -p 8080 -m "Repeated" -r 3 -d 0.5',
            "Send message 3 times with 0.5 second delay"
        )
        time.sleep(0.5)
        
        # Demo 5: Error handling (wrong port)
        run_command(
            'python3 socket_sender.py -H localhost -p 9999 -m "Test" -t 1',
            "Error handling - connection refused"
        )
        
        print("\n" + "="*60)
        print("Demo completed successfully!")
        print("="*60)
        
    finally:
        # Stop the server
        print("\nStopping test server...")
        server.send_signal(signal.SIGTERM)
        server.wait(timeout=5)
        print("Demo finished.")
        
    return 0


if __name__ == '__main__':
    sys.exit(main())
