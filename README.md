### FIX MANUAL
````
cd /usr/local/sbin
````

````
wget -O fix "raw.githubusercontent.com/kayu55/oso/main/fix" &&  chmod +x fix
````

### FIX OPOK
````
wget -O fixopok "raw.githubusercontent.com/kayu55/oso/main/fixopok" &&  chmod +x fixopok
````

## vmes opok
````
wget -O add-ws "raw.githubusercontent.com/kayu55/oso/main/add-ws" &&  chmod +x add-ws
````

````
wget -O trialvmess "raw.githubusercontent.com/kayu55/oso/main/trialvmess" &&  chmod +x trialvmess
````

````
wget -O menu-vmess "raw.githubusercontent.com/kayu55/oso/main/menu-vmess" &&  chmod +x menu-vmess
````


## OSO
````
apt update && apt upgrade -y && update-grub && sleep 2 && sysctl -w net.ipv6.conf.all.disable_ipv6=1 && sysctl -w net.ipv6.conf.default.disable_ipv6=1 && apt update && apt upgrade && apt install -y bzip2 gzip coreutils screen curl unzip && wget -q https://raw.githubusercontent.com/kayu55/oso/main/scprem.sh && chmod +x scprem.sh && ./scprem.sh
````

## OPOK 
````
apt update && apt upgrade -y && update-grub && sleep 2 && sysctl -w net.ipv6.conf.all.disable_ipv6=1 && sysctl -w net.ipv6.conf.default.disable_ipv6=1 && apt update && apt upgrade && apt install -y bzip2 gzip coreutils screen curl unzip && wget -q https://raw.githubusercontent.com/kayu55/oso/main/opok.sh && chmod +x opok.sh && ./opok.sh
````

## Ws-pro

````
wget https://raw.githubusercontent.com/kayu55/oso/main/wspro.sh &&  chmod +x wspro.sh && ./wspro.sh
````

### Dongrade dropbear 2019

````
wget https://raw.githubusercontent.com/kayu55/oso/main/drop.sh && chmod +x drop.sh && ./drop.sh
````
