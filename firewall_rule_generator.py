import re

def validate_port(port):
    """Validate that the port number is within the valid range."""
    return 1 <= port <= 65535

def validate_protocol(protocol):
    """Validate that the protocol is either tcp or udp."""
    return protocol in ['tcp', 'udp']

def validate_action(action):
    """Validate that the action is either accept or drop."""
    return action.upper() in ['ACCEPT', 'DROP']

def get_input(prompt, validation_func=None, error_msg="Invalid input"):
    """Prompt user for input and validate it."""
    while True:
        user_input = input(prompt).strip()
        if validation_func and not validation_func(user_input):
            print(error_msg)
        else:
            return user_input

def generate_iptables_rule(action, port, protocol, src_ip=None, dst_ip=None, interface=None):
    """Generate iptables rule based on user input."""
    rule = f"iptables -A INPUT -p {protocol} --dport {port} -j {action.upper()}"
    if src_ip:
        rule += f" -s {src_ip}"
    if dst_ip:
        rule += f" -d {dst_ip}"
    if interface:
        rule += f" -i {interface}"
    return rule

def generate_ufw_rule(action, port, protocol, src_ip=None, dst_ip=None):
    """Generate ufw rule based on user input."""
    rule = f"ufw {action.lower()} {protocol}/{port}"
    if src_ip:
        rule += f" from {src_ip}"
    if dst_ip:
        rule += f" to {dst_ip}"
    return rule

def generate_windows_rule(action, port, protocol, src_ip=None, dst_ip=None):
    """Generate Windows Firewall rule based on user input."""
    rule = f"netsh advfirewall firewall add rule name=\"Custom Rule\" dir=in action={action.upper()} protocol={protocol} localport={port}"
    if src_ip:
        rule += f" remoteip={src_ip}"
    if dst_ip:
        rule += f" localip={dst_ip}"
    return rule

def main():
    print("Welcome to the Firewall Rule Generator!")

    # Get user inputs
    system = get_input("Enter the firewall system (iptables, ufw, windows): ", 
                       lambda x: x in ['iptables', 'ufw', 'windows'], 
                       "Invalid system. Choose from 'iptables', 'ufw', 'windows'.")

    action = get_input("Enter the action (ACCEPT or DROP): ", 
                       validate_action, 
                       "Invalid action. Choose 'ACCEPT' or 'DROP'.")

    port = int(get_input("Enter the port: ", 
                         lambda x: x.isdigit() and validate_port(int(x)), 
                         "Invalid port. Enter a number between 1 and 65535."))

    protocol = get_input("Enter the protocol (tcp or udp): ", 
                         validate_protocol, 
                         "Invalid protocol. Choose 'tcp' or 'udp'.")

    src_ip = get_input("Enter the source IP (e.g., 192.168.0.10/32, or leave empty): ")
    dst_ip = get_input("Enter the destination IP (e.g., 0.0.0.0/0, or leave empty): ")
    interface = None
    if system == 'iptables':
        interface = get_input("Enter the network interface (or leave empty): ")

    # Generate rules
    if system == 'iptables':
        rule = generate_iptables_rule(action, port, protocol, src_ip, dst_ip, interface)
    elif system == 'ufw':
        rule = generate_ufw_rule(action, port, protocol, src_ip, dst_ip)
    elif system == 'windows':
        rule = generate_windows_rule(action, port, protocol, src_ip, dst_ip)

    print(f"Generated rule for {system}:")
    print(rule)

if __name__ == "__main__":
    main()
