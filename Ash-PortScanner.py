import os
import socket
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, IntPrompt
import shodan
import dns.resolver
import requests

# Initialize console for rich output
console = Console()

# Shodan API setup
SHODAN_API_KEY = "x"  # Replace with your actual API key or set as an environment variable
shodan_client = shodan.Shodan(SHODAN_API_KEY)

# Function to perform a port scan
def port_scan(target):
    # List of common known ports 
    common_ports = [
        21,   # FTP
        22,   # SSH
        23,   # Telnet
        25,   # SMTP
        53,   # DNS
        80,   # HTTP
        110,  # POP3
        143,  # IMAP
        443,  # HTTPS
        445,  # SMB
        3306, # MySQL
        3389, # RDP
        8080  # HTTP Alternative
    ]
    
    console.print(f"[blue]Starting scan for common ports on {target}...[/blue]")
    results = []
    
    for port in common_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((target, port)) == 0:
                    results.append(f"Port {port} is open!")
        except Exception as e:
            results.append(f"Error on port {port}: {e}")
    
    if not results:
        results.append("[yellow]No open common ports found.[/yellow]")
    return results


# Function to fetch data from Shodan
def fetch_shodan_data(target):
    console.print(f"[green]Fetching Shodan data for {target}...[/green]")
    try:
        # Resolve domain to IP if it's not already an IP
        resolved_ip = target
        if not is_valid_ip(target):
            resolved_ip = socket.gethostbyname(target)
            console.print(f"[blue]Resolved {target} to {resolved_ip}[/blue]")

        # Fetch Shodan data using the resolved IP
        host = shodan_client.host(resolved_ip)
        table = Table(title=f"Shodan Data for {target} ({resolved_ip})")
        table.add_column("Field", style="bold cyan")
        table.add_column("Value", style="bold yellow")

        # Add basic data
        table.add_row("IP", host["ip_str"])
        table.add_row("Organization", host.get("org", "N/A"))
        table.add_row("Operating System", host.get("os", "N/A"))
        table.add_row("Ports", ", ".join(map(str, host.get("ports", []))))

        # Add geolocation data if available
        if "latitude" in host and "longitude" in host:
            table.add_row("Latitude", str(host["latitude"]))
            #table.add_row("Longitude", str(host["longitude"]))
        table.add_row("City", host.get("city", "N/A"))
        table.add_row("Region", host.get("region_code", "N/A"))
        table.add_row("Country", host.get("country_name", "N/A")) 

        console.print(table)
    except shodan.APIError as e:
        console.print(f"[red]Error fetching Shodan data: {e}[/red]")
    except socket.gaierror:
        console.print(f"[red]Error: Could not resolve {target} to an IP address.[/red]")

# Helper function to validate IP addresses
def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False
    

# Function to retrieve DNS records
def dns_lookup(domain):
    try:
        resolver = dns.resolver.Resolver()
        records = resolver.resolve(domain, 'A')
        console.print("[cyan]Gathering DNS information[/cyan]")
        return [str(record) for record in records]
    except Exception as e:
        return [f"DNS Error: {e}"]


def sub_domains(target):
    try:
        with open('subdomains.txt', 'r') as file:
            subdomains = file.read().splitlines()  # Get each subdomain as a list
    except FileNotFoundError:
        console.print("[red]Error: 'subdomains.txt' file not found![/red]")
        return

    console.print(f"[blue]Starting subdomain enumeration for {target}...[/blue]")
    
    for subdomain in subdomains:
        url1 = f"http://{subdomain}.{target}"  # HTTP
        url2 = f"https://{subdomain}.{target}"  # HTTPS
        try:
            response1 = requests.get(url1, timeout=2)
            if response1.status_code == 200:
                console.print(f"[green]Discovered URL: {url1}[/green]")
        except requests.ConnectionError:
            pass  # Ignore unreachable URLs
        
        try:
            response2 = requests.get(url2, timeout=2)
            if response2.status_code == 200:
                console.print(f"[green]Discovered URL: {url2}[/green]")
        except requests.ConnectionError:
            pass  # Ignore unreachable URLs


# Main menu
def main_menu():
    while True:
        console.print("\n[bold green]Main Menu[/bold green]")
        console.print("1. Perform a Port Scan")
        console.print("2. Fetch Shodan Data for a Target")
        console.print("3. DNS Resolver (if no VIP for Shodan API)")
        console.print("4. Sub domain search")
        console.print("5. All options in one")
        console.print("6 Exit")

        
        choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4", "5", "6"])
        
        if choice == "1":
            target = Prompt.ask("Enter the target domain")
            results = port_scan(target)
            console.print("\n[cyan]Port Scan Results:[/cyan]")
            for result in results:
                console.print(result)

        elif choice == "2":
            ip = Prompt.ask("Enter the target IP")
            fetch_shodan_data(ip)

        elif choice =="3":
            target = Prompt.ask("Enter the target domain")
            results = dns_lookup(target)
            console.print(results)

        elif choice == "4":
            target = Prompt.ask("Enter the target domain")
            sub_domains(target)


        elif choice == "5":
            target = Prompt.ask("Enter the target domain or IP")

            # Step 1: Perform DNS Lookup (if it's a domain)
            if not is_valid_ip(target):
                try:
                    console.print(f"[blue]Performing DNS lookup for {target}...[/blue]")
                    resolved_ip = socket.gethostbyname(target)
                    console.print(f"[green]Resolved {target} to IP: {resolved_ip}[/green]")
                except socket.gaierror:
                    console.print(f"[red]Error: Could not resolve {target} to an IP address.[/red]")
                    continue
            else:
                resolved_ip = target

            # Step 2: Perform Port Scan
            #console.print(f"[blue]Starting port scan on {resolved_ip}...[/blue]")
            port_scan_results = port_scan(resolved_ip)
            console.print("\n[cyan]Port Scan Results:[/cyan]")
            for result in port_scan_results:
                console.print(result)

            # Step 3: Fetch Shodan Data
            console.print(f"[blue]Fetching Shodan data for {resolved_ip}...[/blue]")
            fetch_shodan_data(resolved_ip)

            # Step 4 Sub domain enumeration 
            sub_domains(target)


   
        

        elif choice == "6":
            console.print("[bold red]Exiting the program. Goodbye![/bold red]")
            break

if __name__ == "__main__":
    main_menu()
