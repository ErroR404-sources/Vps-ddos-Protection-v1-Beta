#!/bin/bash

# Set IPTables chain names
CHAIN_INCOMING="DDOS_INCOMING"
CHAIN_OUTGOING="DDOS_OUTGOING"

# Set IPSet names
IPSET_LAYER4="layer4_botnets"
IPSET_LAYER7="layer7_botnets"

# Set Fail2Ban jail name
JAIL_NAME="ddos_protect"

# Set IP reputation lists
REPUTATION_LISTS=("https://www.spamhaus.org/drop/edrop.txt" "https://www.sorbs.net/dynamic-ip-block-list.txt")

# Create IPTables chains
iptables -N $CHAIN_INCOMING
iptables -N $CHAIN_OUTGOING

# Create IPSet
ipset create $IPSET_LAYER4 hash:ip
ipset create $IPSET_LAYER7 hash:ip

# Add IP reputation lists to IPSet
for list in "${REPUTATION_LISTS[@]}"; do
  wget -q -O - "$list" | awk '{print $1}' | ipset add $IPSET_LAYER4 -
  wget -q -O - "$list" | awk '{print $1}' | ipset add $IPSET_LAYER7 -
done

# Configure IPTables rules
iptables -A $CHAIN_INCOMING -p tcp -m set --match-set $IPSET_LAYER4 src -j DROP
iptables -A $CHAIN_INCOMING -p udp -m set --match-set $IPSET_LAYER4 src -j DROP
iptables -A $CHAIN_INCOMING -p icmp -m set --match-set $IPSET_LAYER4 src -j DROP

iptables -A $CHAIN_OUTGOING -p tcp -m set --match-set $IPSET_LAYER7 dst -j DROP
iptables -A $CHAIN_OUTGOING -p udp -m set --match-set $IPSET_LAYER7 dst -j DROP
iptables -A $CHAIN_OUTGOING -p icmp -m set --match-set $IPSET_LAYER7 dst -j DROP

# Configure Fail2Ban jail
fail2ban-client set $JAIL_NAME addfilter ddos_protect
fail2ban-client set $JAIL_NAME addignoreip 127.0.0.1/8
fail2ban-client set $JAIL_NAME maxretry 3
fail2ban-client set $JAIL_NAME findtime 3600
fail2ban-client set $JAIL_NAME bantime 86400

# Start Fail2Ban jail
fail2ban-client start $JAIL_NAME

# Add IPTables rules to INPUT and OUTPUT chains
iptables -A INPUT -j $CHAIN_INCOMING
iptables -A OUTPUT -j $CHAIN_OUTGOING
