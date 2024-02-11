#!/bin/bash
sudo apt install suricata
# Prompt the user for IP address and subnet
read -p "Enter starting IP address: " ip_address
read -p "Enter subnet mask (in CIDR notation, e.g., 24 for /24): " subnet

# Format the HOME_NET value
home_net="[${ip_address}/${subnet}]"

# Construct the new value for EXTERNAL_NET
external_net="EXTERNAL_NET: \"!\$HOME_NET\""

# Escape special characters for sed
escaped_home_net=$(printf '%s\n' "$home_net" | sed -e 's/[\/&]/\\&/g')
escaped_external_net=$(printf '%s\n' "$external_net" | sed -e 's/[\/&]/\\&/g')

# Use sed to replace HOME_NET and EXTERNAL_NET in the Suricata configuration file
sudo sed -i "s/HOME_NET: .*/HOME_NET: \"$escaped_home_net\"/g; s/EXTERNAL_NET: .*/$escaped_external_net/g" /etc/suricata/suricata.yaml

echo "HOME_NET updated to ${home_net}"
echo "EXTERNAL_NET updated to ${external_net}"

# Define the rules to be added
rules="
alert icmp any any -> \$HOME_NET any (msg:\"PING DETECTED!\";flow:to_server;sid:1000100;rev:1;)
alert tcp any any -> \$HOME_NET 22 (msg:\"SSH Traffic Detected\";flow:to_server; sid:1000101; rev:1;)
alert tcp any any -> \$HOME_NET 22 (msg:\"Possible SSH brute forcing!\";flow:to_server; threshold: type both, track by_src, count 15, seconds 30; sid:1000200; rev:1;)
alert tcp \$EXTERNAL_NET any -> \$HOME_NET any (msg:\"Possible Malware Download\"; flow:to_server,established; content:\"txt\"; nocase; sid:10000007; rev:1;)
alert tcp any any -> \$HOME_NET any (msg:\"Possible SYN Flood (DoS) Attack Detected\"; flags: S; threshold: type threshold, track by_src, count 50000, seconds 5; sid:10000110; rev:1;)
alert tcp any any -> \$HOME_NET any (msg:\"Possible Potential malicious login page detected\"; content:\"<form method=\\\"post\\\"\"; content:\"<input type=\\\"password\\\"\"; sid:1000001;)
alert udp \$EXTERNAL_NET 53 -> \$HOME_NET any (msg:\"Possible DNS amplification attack\"; content:\"|00 00 00 00 00 00|\"; sid:1000007;)
alert tcp \$EXTERNAL_NET any -> \$HOME_NET any (msg:\"Possible Port Scanning\"; flags:S; threshold: type threshold, track by_src, count 5, seconds 60; sid:1000006;)
"

if [ ! -f /etc/suricata/rules/myrules.rules ]; then
    # Create the myrules.rules file if it does not exist
    
    sudo touch /etc/suricata/rules/myrules.rules
    echo "$rules" | sudo tee -a /etc/suricata/rules/myrules.rules > /dev/null
    echo "Rules added to /etc/suricata/rules/myrules.rules"
else
    # Check if each rule already exists in myrules.rules, add only if it's not there
    while IFS= read -r rule; do
        if ! sudo grep -qF "$rule" /etc/suricata/rules/myrules.rules; then
            echo "$rule" | sudo tee -a /etc/suricata/rules/myrules.rules > /dev/null
        fi
    done <<< "$rules"
fi

if sudo grep -q "suricata.rules" /etc/suricata/suricata.yaml; then
   sudo sed -i 's/- suricata.rules/- myrules.rules/' /etc/suricata/suricata.yaml
fi

sudo service suricata restart

tail -f /var/log/suricata/fast.log

