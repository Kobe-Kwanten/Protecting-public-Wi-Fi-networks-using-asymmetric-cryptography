#!/bin/bash
echo "Starting client!"
sudo ~/Documents/Thesis/Implementatie/Userspace/hostap/wpa_supplicant/wpa_supplicant -D nl80211 -i wlan1 -c ~/Documents/Thesis/Implementatie/Userspace/hostap/wpa_supplicant/supp_saepk_random_mac.conf -dd -K | grep "Preauth-Attacks: T" >> probe_verify.log
echo $!