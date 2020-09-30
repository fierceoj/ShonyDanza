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
#add a Shodan dork to the dictionary below to add it to your shonydanza stock searches menu
#see https://github.com/jakejarvis/awesome-shodan-queries for a great source of queries
#check into "vuln:" filter if you have Shodan Small Business Plan or higher (e.g., vuln:cve-2019-11510)

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
