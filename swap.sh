#!/bin/bash
clear
fun_bar() {

}
    # Fungsi: Menginstall swap 1GB dan alat monitoring gotop
res1() {
    clear
    print_install "Memasang Swap 2 GB"

    # Mengambil versi terbaru gotop
    gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v${gotop_latest}_linux_amd64.deb"

    # Download & install gotop
    curl -sL "$gotop_link" -o /tmp/gotop.deb
    dpkg -i /tmp/gotop.deb >/dev/null 2>&1

    # Membuat swap file 2GB
    dd if=/dev/zero of=/swapfile bs=1M count=2048
    mkswap /swapfile
    chown root:root /swapfile
    chmod 0600 /swapfile
    swapon /swapfile >/dev/null 2>&1

    # Tambahkan swap ke fstab agar aktif saat boot
    sed -i '$ i\/swapfile swap swap defaults 0 0' /etc/fstab

    # Sinkronisasi waktu dengan server Indonesia
    chronyd -q 'server 0.id.pool.ntp.org iburst'
    chronyc sourcestats -v
    chronyc tracking -v

    print_success "Swap 2 GB berhasil dipasang"
}
}
netfilter-persistent
clear
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | lolcat
echo -e " \e[1;97;101m        SWAP BERHASIL            \e[0m"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | lolcat
echo -e ""
echo -e "  \033[1;91m Update Service\033[1;37m"
fun_bar 'res1'
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | lolcat
echo -e ""
read -n 1 -s -r -p "Press [ Enter ] to back on menu"
menu
