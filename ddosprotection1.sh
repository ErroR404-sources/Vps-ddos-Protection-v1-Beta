#!/bin/bash

# Flush existing rules and set default policies
iptables -F
iptables -X
iptables -P INPUT DROP
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP

# Allow loopback traffic
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Accept established and related incoming connections
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Allow SSH (change port if not using default 22)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow Pterodactyl Panel ports (adjust ports as needed)
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
iptables -A INPUT -p tcp --dport 8443 -j ACCEPT

# Allow Wings ports (adjust ports as needed)
iptables -A INPUT -p tcp --dport 8081 -j ACCEPT

# Block incoming traffic on ports 80 and 443 (HTTP and HTTPS)
iptables -A INPUT -p tcp --dport 80 -j DROP
iptables -A INPUT -p tcp --dport 443 -j DROP

# DDoS protection measures using iptables
# Adjust the following rules based on your specific requirements and traffic patterns
# Example rules:
# Limit new connections per IP to 20 per minute (adjust as needed)
iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 20 --connlimit-mask 32 -j DROP

# Drop invalid packets
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Drop ICMP flood attacks (adjust ICMP types as needed)
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
iptables -A INPUT -p icmp -j DROP

# Rate limit UDP packets (adjust rate as needed)
iptables -A INPUT -p udp -m limit --limit 50/s -j ACCEPT
iptables -A INPUT -p udp -j DROP

# Drop fragments
iptables -A INPUT -f -j DROP

# Log and drop all other incoming traffic
iptables -A INPUT -j LOG --log-prefix "iptables-dropped: "
iptables -A INPUT -j DROP

# Save iptables rules
iptables-save > /etc/iptables/rules.v4

echo "DDoS protection script applied successfully."
