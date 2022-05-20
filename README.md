# ShonyDanza
A customizable, easy-to-navigate tool for researching, pen testing, and defending with the power of Shodan. 

![Demo GIF](demo/shonydanza_demo.gif)

With ShonyDanza, you can:
- Obtain IPs based on search criteria
- Automatically exclude honeypots from the results based on your pre-configured thresholds
- Pre-configure all IP searches to filter on your specified net range(s)
- Pre-configure search limits
- Use build-a-search to craft searches with easy building blocks
- Use stock searches and pre-configure your own stock searches
- Check if IPs are known malware C2s
- Get host and domain profiles
- Scan on-demand 
- Find exploits
- Get total counts for searches and exploits
- Automatically save exploit code, IP lists, host profiles, domain profiles, and scan results to directories within ShonyDanza

## Installation
`git clone https://github.com/fierceoj/ShonyDanza.git`</br>

> Requirements
- python3
- shodan library

`cd ShonyDanza`</br>
`pip3 install -r requirements.txt`

## Usage
> Edit config.py to include your desired configurations</br>
`cd configs`</br>
`sudo nano config.py`</br>

```
#config file for shonydanza searches

#REQUIRED
#maximum number of results that will be returned per search
#default is 100

SEARCH_LIMIT = 100


#REQUIRED
#IPs exceeding the honeyscore limit will not show up in IP results
#scale is 0.0 to 1.0
#adjust to desired probability to restrict results by threshold, or keep at 1.0 to include all results

HONEYSCORE_LIMIT = 1.0


#REQUIRED - at least one key: value pair
#add a shodan dork to the dictionary below to add it to your shonydanza stock searches menu
#see https://github.com/jakejarvis/awesome-shodan-queries for a great source of queries
#check into "vuln:" filter if you have Small Business Plan or higher (e.g., vuln:cve-2019-11510)

STOCK_SEARCHES = {
'ANONYMOUS_FTP':'ftp anonymous ok',
'RDP':'port:3389 has_screenshot:true',
'OPEN_TELNET':'port:23 console gateway -password',
'APACHE_DIR_LIST':'http.title:"Index of /"',
'SPRING_BOOT':'http.favicon.hash:116323821',
'HP_PRINTERS':'"Serial Number:" "Built:" "Server: HP HTTP"',
'DOCKER_API':'"Docker Containers:" port:2375',
'ANDROID_ROOT_BRIDGE':'"Android Debug Bridge" "Device" port:5555',
'MONGO_EXPRESS_GUI':'"Set-Cookie: mongo-express=" "200 OK"',
'CVE-2019-11510_PULSE_VPN':'http.html:/dana-na/',
'CVE-2019-19781_CITRIX_NETSCALER':'http.waf:"Citrix NetScaler"',
'CVE-2020-5902_F5_BIGIP':'http.favicon.hash:-335242539 "3992"',
'CVE-2020-3452_CISCO_ASA_FTD':'200 "Set-Cookie: webvpn;"'
}


#OPTIONAL
#IP or cidr range constraint for searches that return list of IP addresses
#use comma-separated list to designate multiple (e.g. 1.1.1.1,2.2.0.0/16,3.3.3.3,3.3.3.4) 

#NET_RANGE = '0.0.0.0/0'
```

> Run </br>
`cd ../`</br>
`python3 shonydanza.py`</br>

See this [how-to article](https://null-byte.wonderhowto.com/forum/to-use-shonydanza-find-target-and-exploit-0318883/) for additional usage instruction. </br> NOTE: The API key config info for this article is no longer accurate, since it was removed as a hardcodable property in the config file some time back, and the script instead uses getpass() to retrieve it. Otherwise, the tutorial should still be useful. Working on updating the blog, but at this time the blogging platform will not allow me to update it. 

## Legal Disclaimer
This project is made for educational and ethical testing purposes only. Usage of ShonyDanza for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

