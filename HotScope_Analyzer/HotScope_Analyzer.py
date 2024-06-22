import argparse
import threading
import logging
import os
import sys
import time
from scapy.all import sniff, IP, IPv6, conf
from colorama import init, Fore, Style

# Initialize Colorama
init()

# Set the path to the manuf file for Linux
manuf_file_path = os.path.join('/home', 'kali', 'Documents', 'Albus_Exploit_Project', 'manuf.txt')

# Ensure the manuf file exists
if not os.path.isfile(manuf_file_path):
    raise FileNotFoundError(f"{Fore.RED}The manuf file was not found at {manuf_file_path}. Please download it from Wireshark's repository.{Style.RESET_ALL}")

# Set the SCAPY_MANUF_PATH environment variable
os.environ['SCAPY_MANUF_PATH'] = manuf_file_path

class PacketInterceptor:
    def __init__(self, iface=None, filter_rule="", log_file=None):
        """
        Initializes the PacketInterceptor.
        
        :param iface: Network interface to use for capturing packets.
        :param filter_rule: BPF filter rule to apply for packet capture.
        :param log_file: Path to log file to save or read captured data.
        """
        self.iface = iface
        self.filter_rule = filter_rule
        self.log_file = log_file
        self.running = False
        self.thread = None

    def _process_packet(self, packet):
        """
        Processes a captured packet.
        
        :param packet: The captured packet.
        """
        try:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            src_addr = packet[IP].src if IP in packet else packet[IPv6].src if IPv6 in packet else "Unknown"
            dst_addr = packet[IP].dst if IP in packet else packet[IPv6].dst if IPv6 in packet else "Unknown"
            
            log_entry = f"Time: {timestamp}, Src: {src_addr}, Dst: {dst_addr}, Packet: {packet.summary()}"
            
            # Directly print the log entry to reduce overhead from logging
            print(f"{Fore.GREEN}{log_entry}{Style.RESET_ALL}")
            
            if self.log_file:
                with open(self.log_file, 'a') as log:
                    log.write(f"{log_entry}\n")
        except Exception as e:
            logging.error(f"{Fore.RED}Error processing packet: {e}{Style.RESET_ALL}")

    def _start_sniffing(self):
        """
        Starts sniffing packets on the specified interface.
        """
        logging.info(f"{Fore.CYAN}Starting packet capture...{Style.RESET_ALL}")
        try:
            sniff(iface=self.iface, filter=self.filter_rule, prn=self._process_packet, store=False)
        except Exception as e:
            logging.error(f"{Fore.RED}Error capturing packets: {e}{Style.RESET_ALL}")

    def start(self):
        if not self.running:
            self.running = True
            try:
                self.thread = threading.Thread(target=self._start_sniffing)
                self.thread.daemon = True  # Make the thread a daemon thread
                self.thread.start()
                logging.info(f"{Fore.CYAN}Packet interceptor started{Style.RESET_ALL}")
            except Exception as e:
                logging.error(f"{Fore.RED}Failed to start packet interceptor: {e}{Style.RESET_ALL}")

    def stop(self):
        if self.running:
            self.running = False
            try:
                if self.thread and self.thread.is_alive():
                    self.thread.join(timeout=1)
                logging.info(f"{Fore.CYAN}Packet interceptor stopped{Style.RESET_ALL}")
            except Exception as e:
                logging.error(f"{Fore.RED}Error stopping packet interceptor: {e}{Style.RESET_ALL}")

    def display_log(self):
        """
        Display the contents of the log file.
        """
        try:
            if os.path.isfile(self.log_file):
                logging.info(f"{Fore.CYAN}Displaying log file: {self.log_file}{Style.RESET_ALL}")
                with open(self.log_file, 'r') as log:
                    for line in log:
                        print(line.strip())
            else:
                logging.error(f"{Fore.RED}Log file not found: {self.log_file}{Style.RESET_ALL}")
        except Exception as e:
            logging.error(f"{Fore.RED}Error reading log file: {e}{Style.RESET_ALL}")

def is_admin():
    """
    Check if the script is running with administrative privileges.
    """
    try:
        return os.geteuid() == 0
    except AttributeError:
        logging.error(f"{Fore.RED}Non-UNIX-like system, cannot check for root privileges.{Style.RESET_ALL}")
        return False
    except Exception as e:
        logging.error(f"{Fore.RED}Error checking admin status: {e}{Style.RESET_ALL}")
        return False

def list_interfaces():
    """
    List available network interfaces.
    """
    try:
        print(f"{Fore.CYAN}Available interfaces:{Style.RESET_ALL}")
        for iface in sorted(conf.ifaces.data.values(), key=lambda i: i.name):
            print(iface.name)
    except Exception as e:
        logging.error(f"{Fore.RED}Error listing interfaces: {e}{Style.RESET_ALL}")

def main():
    print(f"{Fore.BLACK}Welcome{Style.RESET_ALL}")
    print(f"     {Fore.BLUE}To{Style.RESET_ALL}")
    print(f"""{Fore.YELLOW}
        +------------------------------------------------+
        | _   _       _       ____                       |
        || | | | ___ | |_    / ___|  ___ ___  _ __   ___ |
        || |_| |/ _ \| __|___\___ \ / __/ _ \| '_ \ / _ \|
        ||  _  | (_) | ||_____|__) | (_| (_) | |_) |  __/|
        ||_| |_|\___/ \__|   |____/ \___\___/| .__/ \___||
        |   / \   _ __   __ _| |_   _ _______|_|__       |
        |  / _ \ | '_ \ / _` | | | | |_  / _ \ '__|      |
        | / ___ \| | | | (_| | | |_| |/ /  __/ |         |
        |/_/   \_\_| |_|\__,_|_|\__, /___\___|_|         |
        |                       |___/                    |
        +------------------------------------------------+

        {Style.RESET_ALL}"""
    )
    print(f"{Fore.RED}A tool to intercept and analyze network packets{Style.RESET_ALL}")
    print(f"{Fore.RED}Use -h or --help to show the help menu{Style.RESET_ALL}")
    parser = argparse.ArgumentParser(description=f"{Fore.RED}A tool to intercept and analyze network packets.")
    parser.add_argument('-i', '--iface', type=str, help="Network interface to use for capturing packets (e.g., eth0).")
    parser.add_argument('-f', '--filter', type=str, default="", help="BPF filter rule to apply for packet capture (e.g., 'tcp').")
    parser.add_argument('-l', '--list', action='store_true', help="List available network interfaces and exit.")
    parser.add_argument('-s', '--savelog', type=str, nargs='?', const='logfile.log', help="Path to a log file to save captured network traffic (default is 'logfile.log').")
    parser.add_argument('--logfile', type=str, help="Path to a log file to display its contents.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    try:
        if args.list:
            list_interfaces()
            sys.exit(0)

        if args.logfile:
            # Display contents of the provided log file
            interceptor = PacketInterceptor(log_file=args.logfile)
            interceptor.display_log()
            sys.exit(0)

        # Handle missing iface argument
        if not args.iface:
            print(f"{Fore.RED}Error: The following arguments are required: -i/--iface for Network interface.{Style.RESET_ALL}")
            sys.exit(1)

        # Ensure script is run with root/administrator privileges
        if not is_admin():
            logging.error(f"{Fore.RED}This script must be run as root.{Style.RESET_ALL}")
            sys.exit(1)

        # If --savelog is provided without a path, use 'logfile.log' in the current directory
        log_file_path = args.savelog if args.savelog else None
        if log_file_path:
            # Validate directory of provided path or use default filename
            log_dir = os.path.dirname(log_file_path)
            if log_dir and not os.path.exists(log_dir):
                print(f"{Fore.RED}Error: The path '{log_dir}' is invalid.{Style.RESET_ALL}")
                sys.exit(1)
            if not log_dir:  # if only filename is provided, ensure it's in current dir
                log_file_path = os.path.join(os.getcwd(), log_file_path)

        interceptor = PacketInterceptor(args.iface, args.filter, log_file_path)
        interceptor.start()
        try:
            input(f"{Fore.YELLOW}Press Enter to stop...{Style.RESET_ALL}\n")
        finally:
            interceptor.stop()
            print(f"{Fore.GREEN}Packet interceptor stopped{Style.RESET_ALL}")
            sys.exit(0)
    except Exception as e:
        logging.error(f"{Fore.RED}Error in main function: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
