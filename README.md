# Firewall Rule Generator

## Overview

The **Firewall Rule Generator** is a Python-based tool designed to help users create and manage firewall rules easily. It supports generating rules for various firewall systems, including `iptables`, `ufw`, and Windows Firewall. The tool provides an interactive interface for users to input their desired rule parameters, ensuring the rules are valid and properly formatted for the selected firewall system.

## Key Features

- **Interactive Input**: Prompts users for necessary information like action, port, protocol, and IP addresses.
- **Firewall System Support**: Generates rules for `iptables`, `ufw`, and Windows Firewall.
- **Advanced Rule Options**: Allows for specification of source and destination IP addresses and network interfaces (for `iptables`).
- **Validation**: Ensures that user inputs are valid, including port ranges and protocol types.

## Installation

Ensure you have Python 3.x installed. Clone the repository and run the script directly:

```
git clone https://github.com/kh2g21/firewall-rule-generator.git
cd firewall-rule-generator
```

