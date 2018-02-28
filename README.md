# Learn Ethical Hacking From Scratch with Zaid Sabih
Here are the commands that will be used in the course
## Network
### Change MAC Address
* Get the interface down
  * `ifconfig wlan0 down`
* Use macchanger
  * `macchanger --random wlan0`
* Get the interface up
  * `ifconfig wlan0 up`
### Change Wireless Card Mode
#### Method 1
* Start Monitor Mode
  * `airmon-ng start wlan0`
* Stop Monitor Mode
  * `airmon-ng stop wlan0mon`
#### Method 2
* Get the interface down
  * `ifconfig wlan0 down`
* Change Mode
  * `ifconfig wlan0 mode monitor`
* Get the interface up
  * `ifconfig wlan0 up`
#### Method 3
* Get the interface down
  * `ifconfig wlan0 down`
* Kill Process
  * `airmon-ng check kill`
* Start Monitor Mode
  * `airmon-ng start wlan0`
### Packet Sniffing
* Start Sniffing
  * `airodump-ng wlan0mon`
* Sniff In A Specific Network
  * `airodump-ng --channel <network channel> --bssid <network bssid> --write <file-name> wlan0mon`
* Deauth Attacks
  * `aireplay-ng --deauth <mun-of-packets> -a <network bssid> -c <target bssid> wlan0mon`
