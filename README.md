### FIX MANUAL
````
cd /usr/local/sbin
````

````
wget -O fix "raw.githubusercontent.com/kayu55/oso/main/fix" &&  chmod +x fix
````

````
wget -O XrayFix "raw.githubusercontent.com/kayu55/oso/main/XrayFix" &&  chmod +x XrayFix
````

### OSO
```
apt update && apt upgrade -y && update-grub && sleep 2 && sysctl -w net.ipv6.conf.all.disable_ipv6=1 && sysctl -w net.ipv6.conf.default.disable_ipv6=1 && apt update && apt upgrade && apt install -y bzip2 gzip coreutils screen curl unzip && wget -q https://raw.githubusercontent.com/kayu55/oso/main/scprem.sh && chmod +x scprem.sh && ./scprem.sh
````

### DIGITALOCEAN
````
apt update && apt upgrade -y && update-grub && sleep 2 && sysctl -w net.ipv6.conf.all.disable_ipv6=1 && sysctl -w net.ipv6.conf.default.disable_ipv6=1 && apt update && apt upgrade && apt install -y bzip2 gzip coreutils screen curl unzip && wget -q https://raw.githubusercontent.com/kayu55/oso/main/scprem1.sh && chmod +x scprem1.sh && ./scprem1.sh
````

## Ws-pro

````
wget https://raw.githubusercontent.com/kayu55/oso/main/wspro.sh &&  chmod +x wspro.sh && ./wspro.sh
````

### Dongrade dropbear 2019

````
wget https://raw.githubusercontent.com/kayu55/oso/main/drop.sh && chmod +x drop.sh && ./drop.sh
````
