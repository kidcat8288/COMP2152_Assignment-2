"""
Author: Camille Yu
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

# TODO: Import the required modules (Step ii)
# socket, threading, sqlite3, os, platform, datetime
import socket
import threading
import sqlite3
import os
import platform
import datetime
from contextlib import closing
import sys

# TODO: Print Python version and OS name (Step iii)
print("Python version:", sys.version)
print("Python OS name:", os.name)

# TODO: Create the common_ports dictionary (Step iv)

# Maps common network port numbers to their corresponding service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt",
}


# TODO: Create the NetworkTool parent class (Step v)
# - Constructor: takes target, stores as private self.__target
# - @property getter for target
# - @target.setter with empty string validation
# - Destructor: prints "NetworkTool instance destroyed"
class NetworkTool:
    def __init__(self, target: str):
        self._target = target

    # Getter for target
    @property
    def target(self):
        return self._target

    @target.setter
    def target(self, value):
        if not value.strip():
            # raise ValueError("target cannot be empty.")
            return
        self._target = value

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q3: What is the benefit of using @property and @target.setter?

"""
1.Codes are cleaner and easier to read.
2.Form encapsulation without changing the interface.So we can add logic without breaking existing code.
"""

# Q1: How does PortScanner reuse code from NetworkTool?


"""
PortScanner reuses code from NetworkTool through inheritance, allowing it to automatically access
all non-private methods and attributes defined in the parent class.
"""

# TODO: Create the PortScanner child class that inherits from NetworkTool (Step vi)
# - Constructor: call super().__init__(target), initialize self.scan_results = [], self.lock = threading.Lock()
# - Destructor: print "PortScanner instance destroyed", call super().__del__()


# Constructor
class PortScanner(NetworkTool):
    def __init__(self, target):
        # call the parent constructor
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    #
    #     Q4: What would happen without try-except here?
    """
   While scanning ports, there is no error handling, which could cause the entire program to crash.
   If the socket attempts to connect to a port that is closed or filtered by a firewall, the operating system will return an error.
   This failed connection can result in a runtime exception

    """

    #
    #     - try-except with socket operations
    #     - Create socket, set timeout, connect_ex
    #     - Determine Open/Closed status
    #     - Look up service name from common_ports (use "Unknown" if not found)
    #     - Acquire lock, append (port, status, service_name) tuple, release lock
    #     - Close socket in finally block
    #     - Catch socket.error, print error message

    def scan_port(self, port):
        print(f"Start scanning for {port}...")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))

            if result == 0:
                status = "Open"
            else:
                status = "Closed"

            service_name = "Unknown"
            for port_number, port_name in common_ports.items():
                if port_number == port:
                    service_name = port_name
                    break

            with self.lock:
                self.scan_results.append((port, status, service_name))

        except socket.error as error_message:
            print(f"Error scanning port {port}: {error_message}")

        finally:
            sock.close()
            print(f"Finished scanning for {port}")

    # - get_open_ports(self):
    #     - Use list comprehension to return only "Open" results
    def get_open_ports(self):
        # open_ports = []
        # for item in self.scan_results:
        #     port, status, _ = item
        #     if status == "Open":
        #         open_ports.append(port)

        return [item[0] for item in self.scan_results if item[1] == "Open"]

    #
    #     Q2: Why do we use threading instead of scanning one port at a time?
    #     TODO: Your 2-4 sentence answer here... (Part 2, Q2)
    """
    We use threading instead of scanning one port at a time because threading allows
    multiple ports to be scanned simultaneously rather than sequentially.
    This parallel execution significantly reduces the total scanning time,
    especially when many ports must be checked.

    """

    # - scan_range(self, start_port, end_port):
    #     - Create threads list
    #     - Create Thread for each port targeting scan_port
    #     - Start all threads (one loop)
    #     - Join all threads (separate loop)
    def scan_range(self, start_port, end_port):
        threads = []

        for p in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(p,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()


# TODO: Create save_results(target, results) function (Step vii)
# - Connect to scan_history.db
# - CREATE TABLE IF NOT EXISTS scans (id, target, port, status, service, scan_date)
# - INSERT each result with datetime.datetime.now()
# - Commit, close
# - Wrap in try-except for sqlite3.Error
def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                port INTEGER,
                status TEXT,
                service TEXT,
                scan_date TEXT
            );
        """
        )
        conn.commit()
        print("`scans` table exists")

        scan_date = str(datetime.datetime.now())
        for port, status, service in results:
            with closing(conn.cursor()) as c:
                sql = """INSERT INTO scans(target, port, status, service, scan_date)values(?,?,?,?,?)"""
                c.execute(sql, (target, port, status, service, scan_date))

        conn.commit()
        print(f"Results have been saved: {len(results)} rows")
    except Exception as e:
        print(f"ERROR: {e}")
    finally:
        conn.close()


# TODO: Create load_past_scans() function (Step viii)
# - Connect to scan_history.db
# - SELECT all from scans
# - Print each row in readable format
# - Handle missing table/db: print "No past scans found."
# - Close connection


def load_past_scans():

    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()

        if not rows:
            print("No past scans found.")
        else:
            for _, target, port, status, service, date in rows:
                print(f"[{date}] {target} : Port {port} ({service}) - {status}")

        conn.close()
    except sqlite3.Error:
        print("No past scans found.")


# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":

    # TODO: Get user input with try-except (Step ix)
    # - Target IP (default "127.0.0.1" if empty)
    # - Start port (1-1024)
    # - End port (1-1024, >= start port)
    # - Catch ValueError: "Invalid input. Please enter a valid integer."
    # - Range check: "Port must be between 1 and 1024."

    target_ip = input("Enter target IP (default 127.0.0.1): ")
    if not target_ip:
        target_ip = "127.0.0.1"

    try:
        start_port = int(input("Enter start port (1-1024): "))
        end_port = int(input("Enter end port (1-1024): "))
        if 1 <= start_port <= 1024 and 1 <= end_port <= 1024:
            if end_port >= start_port:
                print("End port must be greater than or equal to start port.")
        else:
            print("Port must be between 1 and 1024.")
    except ValueError:
        print("Invalid input. Please enter a valid integer.")

    # TODO: After valid input (Step x)
    # - Create PortScanner object
    # - Print "Scanning {target} from port {start} to {end}..."
    # - Call scan_range()
    # - Call get_open_ports() and print results
    # - Print total open ports found
    # - Call save_results()
    # - Ask "Would you like to see past scan history? (yes/no): "
    # - If "yes", call load_past_scans()

    ps = PortScanner(target_ip)
    print(f"Scanning: {target_ip} from port{start_port} to {end_port}")
    ps.scan_range(start_port, end_port)

    print(f"Open ports: {ps.get_open_ports()}")
    print(f"Total open ports: {len(ps.get_open_ports())}")

    save_results(target_ip, ps.scan_results)
    ask = input("Would you like to see past scan history? (yes/no):")
    if ask == "yes":
        load_past_scans()


# Q5: New Feature Proposal
# TODO: Your 2-3 sentence description here... (Part 2, Q5)
# Diagram: See diagram_studentID.png in the repository root
"""I propose a Verified Service Reporter that creates a clean list of only active,
recognized services. Using list comprehension, the program can instantly filter out all 'Unknown' or 'Closed' ports
into a single summary, making it easier for a technician to see exactly what software is currently reachable on the network."""
