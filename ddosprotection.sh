#!/bin/bash

# Define variables
IPTABLES_RULES_FILE="/etc/iptables/rules.v4"
MODSECURITY_CONF="/etc/nginx/modsec/main.conf"

# Update system and install necessary packages
apt-get update
apt-get install -y nginx iptables-persistent fail2ban libnginx-mod-security2

# Function to set up Layer 4 (L4) DDoS protection using iptables
setup_l4_protection() {
    # Flush existing rules and set default policies
    iptables -F
    iptables -X
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    # Allow loopback traffic
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # Accept established incoming connections
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Enable SYN cookies to handle SYN flood attacks
    echo 1 > /proc/sys/net/ipv4/tcp_syncookies

    # Drop invalid packets
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

    # Rate limit incoming TCP connections to protect against SYN floods
    iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 100 --connlimit-mask 32 -j DROP

    # Limit ICMP requests (adjust as needed)
    iptables -A INPUT -p icmp -m limit --limit 1/s --limit-burst 10 -j ACCEPT
    iptables -A INPUT -p icmp -j DROP

    # Set up rate limiting for UDP traffic
    iptables -A INPUT -p udp -m limit --limit 100/s --limit-burst 500 -j ACCEPT
    iptables -A INPUT -p udp -j DROP

    # Log and drop all other incoming traffic
    iptables -A INPUT -j LOG --log-prefix "iptables-dropped: " --log-level 7
    iptables -A INPUT -j DROP

    # Save iptables rules
    iptables-save > $IPTABLES_RULES_FILE

    echo "L4 DDoS protection rules applied successfully."
}

# Function to set up Layer 7 (L7) DDoS protection using ModSecurity with nginx
setup_l7_protection() {
    # Enable ModSecurity module
    ln -s /usr/share/modsecurity-crs /etc/nginx/modsec
    ln -s /etc/nginx/modsec/modsecurity.conf-recommended $MODSECURITY_CONF

    # Configure nginx with ModSecurity
    cat <<EOF > /etc/nginx/sites-available/default
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    server_name _;

    location / {
        include $MODSECURITY_CONF;
        proxy_pass http://localhost:8080;  # Adjust this to your Pterodactyl Panel URL
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Host \$http_host;
    }
}
EOF

    # Test nginx configuration
    nginx -t

    # Restart nginx to apply changes
    systemctl restart nginx

    echo "L7 DDoS protection (ModSecurity with nginx) configured successfully."
}

# Function to configure Fail2Ban with a custom jail for DDoS blocking
setup_fail2ban() {
    # Create a custom jail for DDoS blocking
    cat <<EOF > /etc/fail2ban/jail.d/ddos.conf
[ddos]
enabled = true
filter = ddos
action = iptables-allports[name=ddos, protocol=all]
logpath = /var/log/nginx/access.log
maxretry = 300
findtime = 300
bantime = 3600
EOF

    # Create Fail2Ban filter for DDoS detection
    cat <<EOF > /etc/fail2ban/filter.d/ddos.conf
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*HTTP.*" 403
ignoreregex =
EOF

    # Restart Fail2Ban to apply changes
    systemctl restart fail2ban

    echo "Fail2Ban configured for DDoS blocking."
}

# Main script execution
echo "Starting advanced DDoS protection setup..."

setup_l4_protection
setup_l7_protection
setup_fail2ban

echo "Advanced DDoS protection setup completed."
