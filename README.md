# ShonyDanza

A customizable, easy-to-navigate tool to aid in researching, pen testing, and defending with the power of Shodan. 

With ShonyDanza, you can:
- Obtain IPs based on search criteria
- Automatically exclude honeypots from the results
- Pre-configure all IP searches to filter on your specified net range(s)
- Pre-configure search limits
- Craft searches with easy building blocks
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
> Edit config.py to include your API key and desired configurations</br>
`cd configs`</br>
`sudo nano config.py`</br>

```
#config file for shonydanza searches

#REQUIRED
#shodan account API key

API_KEY = ''


#REQUIRED
#maximum number of results that will be returned per search
#default is 100

SEARCH_LIMIT = 100


#REQUIRED
#IPs exceeding the honeyscore limit will not show up in IP results
#adjust to desired probability to adjust results, or change to 1.0 to include all results

HONEYSCORE_LIMIT = 0.5


#REQUIRED - at least one key: value pair
#stock searches that can be selected from a menu
#add search to the dictionary to automatically add it to your shonydanza menu

STOCK_SEARCHES = {
'ANONYMOUS_FTP':'ftp anonymous ok',
'RDP':'port:3389 has_screenshot:true'
}


#OPTIONAL
#IP or cidr range constraint for searches that return list of IP addresses
#use comma-separated list to designate multiple (e.g. 1.1.1.1,2.2.0.0/16,3.3.3.3,3.3.3.4) 

#NET_RANGE = '0.0.0.0/0'
```

> Run </br>
`python3 shonydanza.py`

## Legal Disclaimer
This project is made for educational and ethical testing purposes only. Usage of ownklok scripts for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

