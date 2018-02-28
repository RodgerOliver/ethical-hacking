# Learn Ethical Hacking From Scratch with Zaid Sabih
Here are the commands that will be used in the course
## Network
### Change MAC Address
interface = wlan0
* Get the interface down
  * `ifconfig wlan0 down`
* Use macchanger
  * `macchanger --random wlan0`
* Get the interface up
  * `ifconfig wlan0 up`
### Change Wireless Card Mode
#### Method 1
* Start Monitor Mode
  * `airmon-ng start <interface>`
* Stop Monitor Mode
  * `airmon-ng stop <interface>`
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
  * `airmon-ng start <interface>`
