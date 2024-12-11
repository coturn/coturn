#!/bin/bash
#####################################################################################
############## purpose                 : install coturn as a server          ########
############## verification on aws     : tested & verified on aws ec2        ########
############## platform                : aws ec2                             ########
############## aws ubuntu version      : ubuntu 22.04 LTS                    ########
############## coturn base version     : 4.6.3                               ########
############## dependent tools         : installs prometheus client as well  ########
############## file permissions        : chmod 777 install_coturn_on_aws_ec2.sh #####
############## run command             : ./install_coturn_on_aws_ec2.sh      ########
############## developer               : hariprasad.t@samsung.com            ########
#####################################################################################

coturn_package="https://github.com/coturn/coturn/archive/refs/tags/4.6.3.tar.gz"
coturn_version="4.6.3"

if [ "$#" -eq 0 ]
then
  echo "coturn version is not supplied as argument, installing below version as default."
  echo "default coturn package: $coturn_package"
else
  coturn_package="https://github.com/coturn/coturn/archive/refs/tags/$1.tar.gz"
  coturn_version="$1"
  echo "installing coturn package: $coturn_package"
fi

echo "--------> this script installs coturn server version $1 on aws ec2 instance..."

echo "--------> create user turnserver..."
sudo adduser --gecos "" --disabled-password turnserver

echo "--------> updating packages..."
sudo DEBIAN_FRONTEND=noninteractive apt-get -y update
sudo DEBIAN_FRONTEND=noninteractive apt-get -y upgrade

### install all dependent packages
echo "--------> installing dependent packages..."
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y gcc make openssl-dev build-essential pkg-config libsystemd-dev musl-dev sqlite
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y libssl-dev libsqlite3-dev libevent-dev libpq-dev libmysqlclient-dev libhiredis-dev libmicrohttpd-dev

### download prometheus client libraries
echo "--------> installing prometheus client..."
wget https://github.com/digitalocean/prometheus-client-c/releases/download/v0.1.3/libprom-dev-0.1.3-Linux.deb
wget https://github.com/digitalocean/prometheus-client-c/releases/download/v0.1.3/libpromhttp-dev-0.1.3-Linux.deb
sudo dpkg -i prometheus-client/libprom-dev-0.1.3-Linux.deb
sudo dpkg -i prometheus-client/libpromhttp-dev-0.1.3-Linux.deb

### download coturn source code
echo "--------> downloading coturn $coturn_package"
wget "$coturn_package"
tar -xf "$coturn_version.tar.gz"
cd "coturn-$coturn_version"
./configure

### compile & install coturn
make
echo "--------> installing coturn ..."
sudo make install

sudo bash -c "cat > /etc/default/coturn << EOL
TURNSERVER_ENABLED=1
EXTRA_OPTIONS=-v
EOL"

echo "--------> generating random key for realm..."
secret_key=$(bash -c 'openssl rand -hex 32')

### fetch ec2 public ip and private ip using metadata token (applicable for v2 version of metadata)
echo "--------> retrieving public & private ips of ec2 instance..."
aws_token=$(bash -c 'curl -s -X PUT "http://instance-data/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"')
public_ip=$(bash -c 'curl -s -H "X-aws-ec2-metadata-token:'$aws_token'" -X GET "http://instance-data/latest/meta-data/public-ipv4"')
private_ip=$(bash -c 'curl -s -H "X-aws-ec2-metadata-token:'$aws_token'" -X GET "http://instance-data/latest/meta-data/local-ipv4"')

echo "--------> public ip: $public_ip, private ip: $private_ip"

sudo bash -c "mv /etc/turnserver.conf /etc/turnserver.conf.original"

### create configuration file for coturn with basic expected parameters
### change below values as per your requirement.. like ports, username, password, etc.
echo "--------> applying new config changes..."
sudo bash -c "cat > /etc/turnserver.conf << EOL
listening-port=3478
tls-listening-port=5349
# allow only TLSv1.2+
no-tlsv1
no-tlsv1_1
userdb=/usr/local/var/db/turndb
no-cli
min-port=45000
max-port=65535
log-file=/var/log/turnserver/turnserver.log
verbose
fingerprint
realm=${secret_key}
lt-cred-mech
user=username:password
external-ip=${public_ip}/${private_ip}
new-log-timestamp
new-log-timestamp-format \"%FT%T%z\"
log-binding
prometheus
EOL"

### make coturn as auto recoverable by making it as a service
sudo bash -c "cat > /lib/systemd/system/coturn.service << EOL
[Unit]
Description=coTURN STUN Server
Documentation=man:coturn(1) man:turnadmin(1) man:turnserver(1)
After=network.target

[Service]
User=turnserver
Group=turnserver
Type=notify
EnvironmentFile=/etc/default/coturn
ExecStart=/usr/local/bin/turnserver -c /etc/turnserver.conf --pidfile=
Restart=on-failure
InaccessibleDirectories=/home
PrivateTmp=yes
LimitCORE=infinity
LimitNOFILE=1000000
LimitNPROC=60000
LimitRTPRIO=infinity
LimitRTTIME=7000000

[Install]
WantedBy=multi-user.target
EOL"

### memory based database configurations
sudo bash -c "sudo mkdir -p /var/lib/turn/turndb"
sudo bash -c "sudo chown turnserver:turnserver /var/lib/turn/turndb"

### apply log rotation policy to avoid "disk full" issues
echo "--------> setting log rotation policy..."
sudo bash -c "sudo mkdir -p /var/log/turnserver"
sudo bash -c "sudo chown turnserver:turnserver /var/log/turnserver"
sudo bash -c "cat > /etc/logrotate.d/coturn << EOL
/var/log/turnserver/*.log
{
        rotate 7
        daily
        missingok
        notifempty
        compress
        postrotate
                /bin/systemctl kill -s HUP coturn.service
        endscript
}
EOL"

sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 3478/udp
sudo ufw allow 5349/tcp

#Running coTURN on privileged port 443
sudo bash -c "setcap cap_net_bind_service=+ep /usr/local/bin/turnserver"

sudo bash -c "sudo chown turnserver:turnserver /etc/default/coturn"
sudo bash -c "sudo chown turnserver:turnserver /etc/turnserver.conf"

echo "--------> starting coturn as a service..."
sudo systemctl enable coturn.service
sudo systemctl daemon-reload
sudo systemctl restart coturn.service
echo "--------> coturn is running successfully..."

####
echo "------ verification steps after installation -------"
echo "a. check with command: ps -eaf | grep turnserver"
echo "b. check with command: systemctl status coturn"
echo "c. check configuration: cat /etc/turnserver.conf"
echo "----------------------------------------------------"
####