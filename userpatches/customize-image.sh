#!/usr/bin/env bash

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

# Configure wireshark installation settings using debconf
echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections

# Add ZET keyring
curl -sSLf https://get.openziti.io/tun/package-repos.gpg \
  | gpg --dearmor --output /usr/share/keyrings/openziti.gpg
chmod a+r /usr/share/keyrings/openziti.gpg
echo "deb [signed-by=/usr/share/keyrings/openziti.gpg] https://packages.openziti.org/zitipax-openziti-deb-stable jammy main" \
  > /etc/apt/sources.list.d/openziti.list

# Install required software
apt update
apt install --assume-yes ziti-edge-tunnel=1.7.12 isc-dhcp-server tcpdump tshark

# Add our controller to /etc/hosts
cat <<"EOF" >> /etc/hosts

# OpenZiti
192.168.178.49 ziti.pommer.info
EOF

# Install tunnel
curl -sSLf https://get.openziti.io/tun/package-repos.gpg \
  | gpg --dearmor --output /usr/share/keyrings/openziti.gpg
chmod a+r /usr/share/keyrings/openziti.gpg
echo "deb [signed-by=/usr/share/keyrings/openziti.gpg] https://packages.openziti.org/zitipax-openziti-deb-stable ${UBUNTU_LTS} main" \
  > /etc/apt/sources.list.d/openziti.list

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

# Create a ziticli user for capturing traffic on the Ziti Box
useradd ziticli
mkdir -p /home/ziticli/.ssh/
chown -R ziticli:ziticli /home/ziticli/
touch /home/ziticli/.ssh/authorized_keys

# Create a pcap group and add ziticli to it
groupadd pcap
usermod -a -G pcap ziticli
chgrp pcap /usr/bin/tcpdump
setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump

# Add sudo entry to allow ziticli to use zfw
echo "ziticli ALL=(ALL) NOPASSWD: /opt/openziti/bin/zfw" > /etc/sudoers.d/50-ziticli
chmod 0440 /etc/sudoers.d/50-ziticli

# Add commands into ziticli home
cat <<"EOF" > /home/ziticli/capture_traffic.bash
#!/bin/bash
tcpdump -i enp1s0 -l -w - \
  | tshark -N n -l -r - -T json \
  -j "ip tcp udp" \
  -e ip.src_host \
  -e ip.dst_host \
  -e tcp.srcport \
  -e tcp.dstport \
  -e udp.srcport \
  -e udp.dstport \
  -e dns.qry.name \
  'tcp or udp or dns'
EOF

# Disable armbian first login procedure
rm /root/.not_logged_in_yet