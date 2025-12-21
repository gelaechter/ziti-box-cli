#!bin/bash

# arguments: $RELEASE $LINUXFAMILY $BOARD $BUILD_DESKTOP
#
# This is the image customization script

# NOTE: It is copied to /tmp directory inside the image
# and executed there inside chroot environment
# so don't reference any files that are not already installed

# NOTE: If you want to transfer files between chroot and host
# userpatches/overlay directory on host is bind-mounted to /tmp/overlay in chroot
# The sd card's root path is accessible via $SDCARD variable.

RELEASE=$1
LINUXFAMILY=$2
BOARD=$3
BUILD_DESKTOP=$4

# Install required software
apt update
apt install --assume-yes tmux micro tcpdump isc-dhcp-server dnsutils

# Add our controller to /etc/hosts
cat <<"EOF" >> /etc/hosts

# OpenZiti
192.168.178.49 ziti.pommer.info
EOF

# Install tunnel
curl -sSLf https://get.openziti.io/tun/scripts/install-ubuntu.bash | bash
# Copy .jwt
cp *.jwt /opt/openziti/etc/identities/
sudo chown -cR :ziti        /opt/openziti/etc/identities
sudo chmod -cR ug=rwX,o-rwx /opt/openziti/etc/identities
# Activate Tunnel:
sudo systemctl enable ziti-edge-tunnel.service

# Install ZFW
wget https://github.com/netfoundry/zfw/releases/download/v0.9.22/zfw-tunnel_0.9.22_arm64.deb
dpkg -i zfw-tunnel_0.9.22_arm64.deb

# Set ebpf_config
cat <<"EOF" > /opt/openziti/etc/ebpf_config.json
{"InternalInterfaces": [{"Name": "enp1s0"}],
 "ExternalInterfaces": []}
EOF

# Set user rules
cat <<"EOF" > /opt/openziti/bin/user/user_rules.sh
#!/bin/bash
/usr/sbin/zfw --verbose enp1s0
/usr/sbin/zfw --verbose ziti0
EOF

# Change mode of user rules
sudo chmod 700 /opt/openziti/bin/user/user_rules.sh

# Enable ZFW
sudo systemctl enable ziti-fw-init.service
sudo systemctl enable ziti-wrapper.service

# Clear preconfigured netplan settings
rm /etc/netplan/*
# Write netplan config
cat <<"EOF" > /etc/netplan/50-zitibox.yaml
network:
    ethernets:
        end0:
            dhcp4: true
            optional: true
        enp1s0:
            addresses:
            - 10.1.1.1/24
    version: 2
EOF
# Change permissions
chmod a=,u=rw /etc/netplan/50-zitibox.yaml
# Apply netplan config
netplan generate
netplan apply

# Configure dhcpd
mv /etc/dhcp/dhcpd.conf /etc/dhcp/dhcp.conf.bak
cat <<"EOF" > /etc/dhcp/dhcpd.conf
subnet 10.1.1.0 netmask 255.255.255.0 {
  range 10.1.1.100 10.1.1.254;
  option domain-name-servers 100.64.0.2;
  option subnet-mask 255.255.255.0;
  option routers 10.1.1.1;
  option broadcast-address 10.1.1.255;
  default-lease-time 2592000;
  max-lease-time 2592000;
  authoritative;
}
EOF

# Disable DHCPD for IPv6
systemctl disable isc-dhcp-server6

# Disable armbian first login procedure
rm /root/.not_logged_in_yet