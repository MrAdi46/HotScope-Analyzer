
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
    
# Hot-Scope Analyzer

Hot-Scope Analyzer is a Python tool designed for intercepting and analyzing network packets in real-time or from log files. It leverages Scapy for packet manipulation and Colorama for enhanced terminal output.

## Features

- **Real-time Packet Capture:** Capture and display network traffic in real-time.
- **Packet Analysis:** View detailed information about captured packets including source and destination addresses, and timestamps.
- **Log File Support:** Save captured network traffic to a log file and display contents from a specified log file.
- **Interface Listing:** List available network interfaces for packet capture.

## Requirements
 - Python 3.7 or higher and Linux OS

Ensure you have Python 3.x installed along with the following dependencies:

- argparse
- scapy
- colorama

You can install these dependencies using `pip`:

```bash
pip install -r requirements.txt
```

Esure that You had the manuf.txt file present in the same directory as HotScope_Analazer.py file


## Usage

### Basic Usage

To start capturing network packets:

```bash
python packet_sniffer.py -i <interface>
```

Replace `<interface>` with the network interface name (e.g., eth0).

### Options

- `-i, --iface <interface>`: Specify the network interface for packet capture.
- `-f, --filter <filter>`: Apply a BPF filter rule for packet capture (optional).
- `-l, --list`: List available network interfaces and exit.
- `-s, --savelog [path]`: Save captured network traffic to a specified log file. If no path is provided, it defaults to `logfile.log`.
- `--logfile <path>`: Display contents of a specified log file.

### Examples

List available network interfaces:

```bash
python packet_sniffer.py -l
```

Save captured traffic to a log file:

```bash
python packet_sniffer.py -i eth0 -s captured_traffic.log
```

Display contents of a log file:

```bash
python packet_sniffer.py --logfile captured_traffic.log
```

### Notes

- Ensure the script is run with administrative privileges (root) for capturing packets.
- The `manuf.txt` file from Wireshark's repository is required for MAC address vendor lookup.

## Troubleshooting

- If encountering issues with packet capture or dependencies, ensure all required Python packages are installed (`argparse`, `scapy`, `colorama`).
- Check permissions and administrative privileges when running the script.

## License
- This project is licensed under the MIT License. See the [LICENSE] file for details. 

## Contact
For questions, suggestions, or issues, please reach out via the following channels:

- **GitHub Issues**: [Create an issue](https://github.com/MrAdi46/HotScope-Analyzer/issues)
- **GitHub Discussions**: [Join the discussion](https://github.com/MrAdi46/HotScope-Analyzer/discussions)
- **LinkedIn**: [Aditya Pachghare](https://www.linkedin.com/in/aditya-pachghare-a440a2228/)

### Feel free to contact us for:

- **Bug Reports**: If you encounter any issues while using HotScope-Analyzer.
- **Feature Requests**: If you have ideas on how to improve HotScope-Analyzer.
- **General Inquiries**: If you have questions or need assistance.

## Security Notice

### Reporting Security Issues

Security is a top priority for us. If you discover any security issues or vulnerabilities in HotScope Analyzer, please help us by responsibly disclosing it to us on **LinkedIn**. We will investigate all legitimate reports and do our best to quickly fix the problem.

### Scope of this Notice

This notice covers only vulnerabilities in the HotScope Analyzer tool itself and its directly associated components maintained within this repository. It does not cover vulnerabilities in dependencies of the tool or in underlying systems. For vulnerabilities in dependencies, please refer to the respective projects.

### Best Practices for Users

To ensure the security of your environment when using HotScope Analyzer, we recommend the following best practices:

- **Regular Updates**: Keep HotScope Analyzer and its dependencies up to date with the latest versions to incorporate security fixes.
  
- **Secure Configuration**: Use secure configurations, such as running the tool with minimal privileges necessary for its operation.
  
- **Monitoring and Auditing**: Regularly monitor and audit the tool's usage and output for any suspicious activities or unexpected behaviors.

### Disclaimer

HotScope Analyzer is provided "as-is" without any warranties. The developers are not responsible for any damages or liabilities resulting from the use or misuse of this tool.

---

**Note**: Please do not disclose security-related issues publicly without allowing us time to address them.
