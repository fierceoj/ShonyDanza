#!/usr/bin/env python3

import shodan
from configs import config
import getpass
import requests
import time
import json
import sys
import ast 

def banner():
	print("""
\033[33m
		

███████╗██╗  ██╗ ██████╗ ███╗   ██╗██╗   ██╗██████╗  █████╗ ███╗   ██╗███████╗ █████╗     
██╔════╝██║  ██║██╔═══██╗████╗  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗████╗  ██║╚══███╔╝██╔══██╗    
███████╗███████║██║   ██║██╔██╗ ██║ ╚████╔╝ ██║  ██║███████║██╔██╗ ██║  ███╔╝ ███████║    
╚════██║██╔══██║██║   ██║██║╚██╗██║  ╚██╔╝  ██║  ██║██╔══██║██║╚██╗██║ ███╔╝  ██╔══██║    
███████║██║  ██║╚██████╔╝██║ ╚████║   ██║   ██████╔╝██║  ██║██║ ╚████║███████╗██║  ██║    
╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝    
																						  

		Author: fierceoj
		GitHub: https://github.com/fierceoj/
""")

#main menu
def menu():
	print("""
\033[92m
[1] Get IPs
[2] Count results by search terms
[3] Check malware C2 IPs
[4] Get honeyscore
[5] Get host profile
[6] Get domain profile
[7] Scan on-demand 
[8] Find exploits
[9] Check API plan info
[10] Exit
""")


#print IP results and save to file (optional)
#default path for results file is ip_lists directory
def print_ips(results):
	if results['matches']:
		ips = []
		if config.HONEYSCORE_LIMIT == 1.0:
			for result in results['matches']:
				ip = result['ip_str']
				print(ip)
				ips.append(ip)
		else:
			not_honeypots = 0
			for result in results['matches']:
				ip = result['ip_str']
				if honeyscore(ip) <= config.HONEYSCORE_LIMIT:
					print(ip)
					ips.append(ip)
					not_honeypots += 1
				time.sleep(1)
			if not_honeypots == 0:
				print('Only honeypots were found.')

		print("""\n\033[92mSave IPs to file?
		[1] Yes
		[2] No
		""")

		save_ips_to_file = int(input('\033[92m> Enter Selection: '))

		if save_ips_to_file == 2:
			pass

		elif save_ips_to_file == 1:
			file_name = input('\033[39m> Enter file name (path optional, default path is ip_lists/) : ')
			if '/' not in file_name:
				file_name = 'ip_lists/' + file_name
			with open(file_name, 'w') as f:
				f.write('\n'.join(ips))

			print('\n\033[1;92mResults saved to file:\033[0;39m ' + file_name)

		else:
			print('\033[31mInvalid Choice\033[39m')

	else:
		print('No matches found.')

#function to print domain DNS records to stdout and to file in domain_profiles
def print_dns_records(record, f):
	subdomain = record.get('subdomain')
	print('\033[1;92mSubdomain:\033[0;39m ' + str(subdomain))
	print('Subdomain: ' + str(subdomain), file=f)

	value = record.get('value')
	print('\033[1;92mValue:\033[0;39m ' + str(value))
	print('Value: ' + str(value), file=f)
	print('\n')
	print('\n', file=f) 

#get IPs by keyword search
def ip_by_keyword(search_term):
	try:
		search_query = search_term + ' net:' + config.NET_RANGE
	except:
		search_query = search_term

	results = api.search(search_query, limit=config.SEARCH_LIMIT)
	print_ips(results)

#get IPs by OS search
def ip_by_os(os, keyword):
	if keyword:
		search_query = keyword + ' os:' + '"' + os + '"'
	else:
		search_query = 'os:' + '"' + os + '"'
	try:
		search_query = search_query + ' net:' + config.NET_RANGE
	except:
		pass
 
	results = api.search(search_query, limit=config.SEARCH_LIMIT)
	print_ips(results)

#get IPs by product/version search
def ip_by_product(product, version, keyword):
	if keyword:
		search_query = keyword + ' product:' + '"' + product + '"'
	else:
		search_query = 'product:' + '"' + product + '"'

	if version:
		search_query = search_query + ' version:' + '"' + version + '"'
	 
	try:
		search_query = search_query + ' net:' + config.NET_RANGE
	except:
		pass

	results = api.search(search_query, limit=config.SEARCH_LIMIT)
	print_ips(results)

#get IPs by port search
def ip_by_port(port, keyword):
	if keyword:
		search_query = keyword + ' port:' + '"' + port + '"'
	else:
		search_query = 'port:' + '"' + port + '"'
	try:
		search_query = search_query + ' net:' + config.NET_RANGE
	except:
		pass

	results = api.search(search_query, limit=config.SEARCH_LIMIT)
	print_ips(results)

#build a search with multiple components to get IPs
def build_ip_search(port, product, version, os, keyword):
	search_query = ''
	if port:
		search_query = 'port:' + '"' + port + '"'
	if product:
		search_query = search_query + ' product:' + '"' + product + '"'
	if version:
		search_query = search_query + ' version:' + '"' + version + '"'
	if os:
		search_query = search_query + ' os:' + '"' + os + '"'
	if keyword:
		search_query = keyword + ' ' + search_query

	try:
		search_query = search_query + ' net:' + config.NET_RANGE
	except:
		pass 

	results = api.search(search_query, limit=config.SEARCH_LIMIT)
	print_ips(results) 

#use a stock search from configs file to get IPs
def ip_by_stock_search():
	while True:
		for k,v in config.STOCK_SEARCHES.items():
			print('\033[93m\t\t\t\t\t\t[' + str(list(config.STOCK_SEARCHES).index(k) + 1) + '] ' + k + ': ' + '\033[0;39m' + v)

		print('\t\t\t\t\t\t\033[93m[' + str(len(config.STOCK_SEARCHES) + 1) + '] Return to Get IPs menu') 

		option = int(input('\033[93m> Enter Selection: '))

		for k,v in config.STOCK_SEARCHES.items():
			if option == (len(config.STOCK_SEARCHES) + 1):
				return
			elif option == (list(config.STOCK_SEARCHES).index(k) + 1):
				search_query = v
				try:
					search_query = search_query + ' net:' + config.NET_RANGE
				except:
					pass 

				results = api.search(search_query, limit=config.SEARCH_LIMIT)
				print_ips(results)

		
#count results for a user-defined search
def count_by_keyword(search_term):
	try:
		search_query = search_term + ' net:' + config.NET_RANGE
	except:
		search_query = search_term

	results = api.count(search_query)
	count = str(results.get('total'))
	print('Count: ' + count)

#check if an IP is on the Shodan Malware Hunter list
def check_malware_ip(ip):
	search_query = 'category:malware net:' + str(ip)
	results = api.search(search_query, limit=config.SEARCH_LIMIT)
	if results['matches']:
		for result in results['matches']:

			ip_str = result.get('ip_str')
			print('\033[1;92mIP\033[0;39m: ' + str(ip_str))

			malware = result.get('product')
			print('\033[1;92mMalware:\033[0;39m ' + str(malware))

			port = result.get('port')
			print('\033[1;92mPort:\033[0;39m ' + str(port))

			domains = result.get('domains')
			print('\033[1;92mDomains:\033[0;39m ' + str(domains))

			hostnames = result.get('hostnames')
			print('\033[1;92mHostnames:\033[0;39m ' + str(hostnames))

			isp = result.get('isp')
			print('\033[1;92mISP:\033[0;39m ' + str(isp))

			org = result.get('org')
			print('\033[1;92mOrg:\033[0;39m ' + str(org))

			asn = result.get('asn')
			print('\033[1;92mASN:\033[0;39m ' + str(asn))

			country = result.get('location').get('country_name')
			print('\033[1;92mCountry:\033[0;39m ' + str(country))
			print('\n')

			data = result.get('data')
			print('\033[1;92mData:\033[0;39m\n ' + str(data))
	else:
		print('No  matches found.')	

#get the honeyscore of an IP
#honeyscore is probability that IP is a honeypot
def honeyscore(ip):
	url = 'https://api.shodan.io/labs/honeyscore/' + ip + '?key=' + API_KEY
	response = requests.get(url)
	if "error" in response.text:
		score = 1.1
	else:
		score = float(response.text)
	return score

#get information for a host IP 
#saves results file to host_profiles directory
def get_host_profile(ip):
	
	try:

		#saves host results in a file as well as prints to stdout
		filename = 'host_profiles/' + str(ip).replace('.', '-') + '_' + 'profile'
		f = open(filename, 'a')

		results = api.host(ip)

		print("\n===========================================================")
		print('*****************     Basic Host Info     *****************')
		print("===========================================================\n")

		print("\n===========================================================", file=f)
		print('*****************     Basic Host Info     *****************', file=f)
		print("===========================================================\n", file=f)

		ip_str = results.get('ip_str')
		print('\033[1;92mIP:\033[0;39m ' + str(ip_str))
		print('IP: ' + str(ip_str), file=f)

		vulns = results.get('vulns')
		print('\033[1;92mVulns:\033[0;39m ' + str(vulns))
		print('Vulns: ' + str(vulns), file=f)

		ports = results.get('ports')
		print('\033[1;92mPorts:\033[0;39m ' + str(ports))
		print('Ports: ' + str(ports), file=f)

		os = results.get('os')
		print('\033[1;92mOS:\033[0;39m ' + str(os))
		print('OS: ' + str(os), file=f)

		domains = results.get('domains')
		print('\033[1;92mDomains:\033[0;39m ' + str(domains))
		print('Domains: ' + str(domains), file=f)

		hostnames = results.get('hostnames')
		print('\033[1;92mHostnames:\033[0;39m ' + str(hostnames))
		print('Hostnames: ' + str(hostnames), file=f)

		isp = results.get('isp')
		print('\033[1;92mISP:\033[0;39m ' + str(isp))
		print('ISP: ' + str(isp), file=f)

		org = results.get('org')
		print('\033[1;92mOrg:\033[0;39m ' + str(org))
		print('Org: ' + str(org), file=f)

		asn = results.get('asn')
		print('\033[1;92mASN:\033[0;39m ' + str(asn))
		print('ASN: ' + str(asn), file=f)

		country = results.get('country_name')
		print('\033[1;92mCountry:\033[0;39m ' + str(country))
		print('Country: ' + str(country), file=f)
		print('\n')
		print('\n', file=f)

		for result in results.get('data'):
			print("\n==========================================================")
			print('******************     Host Service     ******************')
			print("==========================================================\n")

			print("\n==========================================================", file=f)
			print('******************     Host Service     ******************', file=f)
			print("==========================================================\n", file=f)

			software = result.get('product')
			print('\033[1;92mSoftware:\033[0;39m ' + str(software))
			print('Software: ' + str(software), file=f)

			version = result.get('version')
			print('\033[1;92mVersion:\033[0;39m ' + str(version))
			print('Version: ' + str(version), file=f)

			port = result.get('port')
			print('\033[1;92mPort:\033[0;39m ' + str(port))
			print('Port: ' + str(port), file=f)

			data = result.get('data')
			print('\n')
			print('\n', file=f)
			print('\033[1;92mData:\033[0;39m\n' + str(data))
			print('Data:\n' + str(data), file=f)

		print('\n\033[1;92mResults saved to file:\033[0;39m ' + filename)
		f.close()		

	except shodan.APIError as e:
		print(f'Error: {e}')

#get DNS records for a domain
#saves results file to domain_profiles directory
def get_domain_profile(domain):
	
	url = 'https://api.shodan.io/dns/domain/' + domain + '?key=' + API_KEY
	response = requests.get(url)
	
	if "error" in response.json():
		print('Error occurred for that domain.')
		return

	filename = 'domain_profiles/' + str(domain).replace('.', '-') + '_' + 'profile'
	f = open(filename, 'a')

	results = response.json()

	print("\n===========================================================")
	print('***********************     Tags     **********************')
	print("===========================================================\n")

	print("\n===========================================================", file=f)
	print('***********************     Tags     **********************', file=f)
	print("===========================================================\n", file=f)

	tags = results.get('tags')
	tags = '\n\t'.join(tags)
	print('\033[1;92mTags:\033[0;39m \n\t' + str(tags))
	print('Tags: \n\t' + str(tags), file=f)
	print('\n')
	print('\n', file=f)
	
	a_records = []
	aaaa_records = []
	cname_records = []
	mx_records = []
	ns_records = []
	soa_records = []
	txt_records = []
	other_records = []

	if results.get('data'):	
		for result in results['data']:	
			if result.get('type') == 'A':
				a_records.append(result)
			elif result.get('type') == 'AAAA':
				aaaa_records.append(result)
			elif result.get('type') == 'CNAME':
				cname_records.append(result)
			elif result.get('type') == 'MX':
				mx_records.append(result)
			elif result.get('type') == 'NS':
				ns_records.append(result)
			elif result.get('type') == 'SOA':
				soa_records.append(result)
			elif result.get('type') == 'TXT':
				txt_records.append(result)
			else:
				other_records.append(result)

	else:
		print('No information found for that domain.', file=f)
		f.close()
		return

	print("\n===========================================================")
	print('********************     A Records     ********************')
	print("===========================================================\n")

	print("\n===========================================================", file=f)
	print('********************     A Records     ********************', file=f)
	print("===========================================================\n", file=f)

	for record in a_records:
		print_dns_records(record, f)

	print("\n============================================================")
	print('*******************     AAAA Records    ********************')
	print("============================================================\n")

	print("\n============================================================", file=f)
	print('*******************     AAAA Records    ********************', file=f)
	print("============================================================\n", file=f)

	for record in aaaa_records:
		print_dns_records(record, f)

	print("\n============================================================")
	print('*******************     CNAME Records    *******************')
	print("============================================================\n")

	print("\n============================================================", file=f)
	print('*******************     CNAME Records    *******************', file=f)
	print("============================================================\n", file=f)
  
	for record in cname_records:
		print_dns_records(record, f)

	print("\n============================================================")
	print('********************     MX Records    *********************')
	print("============================================================\n")

	print("\n============================================================", file=f)
	print('********************     MX Records    *********************', file=f)
	print("============================================================\n", file=f)
  
	for record in mx_records:
		print_dns_records(record, f)

	print("\n============================================================")
	print('********************     NS Records    *********************')
	print("============================================================\n")

	print("\n============================================================", file=f)
	print('********************     NS Records    *********************', file=f)
	print("============================================================\n", file=f)
  
	for record in ns_records:
		print_dns_records(record, f)

	print("\n============================================================")
	print('********************    SOA Records    *********************')
	print("============================================================\n")

	print("\n============================================================", file=f)
	print('********************    SOA Records    *********************', file=f)
	print("============================================================\n", file=f)
  
	for record in soa_records:
		print_dns_records(record, f)

	print("\n============================================================")
	print('********************    TXT Records    *********************')
	print("============================================================\n")

	print("\n============================================================", file=f)
	print('********************    TXT Records    *********************', file=f)
	print("============================================================\n", file=f)
	
	for record in txt_records:
		print_dns_records(record, f)

	print("\n=============================================================")
	print('*******************    Other Records    ********************')
	print("============================================================\n")

	print("\n=============================================================", file=f)
	print('*******************    Other Records    ********************', file=f)
	print("============================================================\n", file=f)
  
	for record in other_records:
		print_dns_records(record, f)

	print('\033[1;92mResults saved to file:\033[0;39m ' + filename)
	f.close()

#scan IPs, CIDR ranges, hostnames, ports, protocols
def run_scan(scan_object):
	try:
		results = api.scan(scan_object)

		count = results.get('count')
		print('\033[1;92mCount:\033[0;39m ' + str(count))

		id = results.get('id')
		print('\033[1;92mID:\033[0;39m ' + str(id))

		credits_left = results.get('credits_left')
		print('\033[1;92mCredits left:\033[0;39m ' + str(credits_left))
	
	except shodan.APIError as e:
			print(f'Error: {e}')

#get the status of a pending scan
def get_scan_status(scan_id):
	try:
		results = api.scan_status(scan_id)
	
		id = results.get('id')
		print('\033[1;92mID:\033[0;39m ' + str(id))

		status = results.get('status')
		print('\033[1;92mStatus:\033[0;39m ' + str(status))

		count = results.get('count')
		print('\033[1;92mCount:\033[0;39m ' + str(count))

		created = results.get('created')
		print('\033[1;92mCreated:\033[0;39m ' + str(created))

	except shodan.APIError as e:
			print(f'Error: {e}')

#view the scan results when scan is completed
#saves results file to scan_results directory
def view_scan_results(scan_id):
	try:
		search_query = 'scan:' + str(scan_id)
		results = api.search(search_query)

		filename = 'scan_results/' + str(scan_id)
		f = open(filename, 'a')

		if results['matches']:
			for result in results['matches']:
				print("\n============================================================")
				print('************************   Match   *************************')
				print("============================================================\n")

				print("\n============================================================", file=f)
				print('************************   Match   *************************', file=f)
				print("============================================================\n", file=f)

				timestamp = result.get('timestamp')
				print('\033[1;92mTimestamp:\033[0;39m ' + str(timestamp))
				print('Timestamp: ' + str(timestamp), file=f)

				ip_str = result.get('ip_str')
				print('\033[1;92mIP:\033[0;39m ' + str(ip_str))
				print('IP: ' + str(ip_str), file=f)

				vulns = result.get('vulns')
				print('\033[1;92mVulns:\033[0;39m ' + str(vulns))
				print('Vulns: ' + str(vulns), file=f)

				transport = result.get('transport')
				print('\033[1;92mTransport:\033[0;39m ' + str(transport))
				print('Transport: ' + str(transport), file=f)

				port = result.get('port')
				print('\033[1;92mPort:\033[0;39m ' + str(port))
				print('Port: ' + str(port), file=f)

				os = result.get('os')
				print('\033[1;92mOS:\033[0;39m ' + str(os))
				print('OS: ' + str(os), file=f)

				domains = result.get('domains')
				print('\033[1;92mDomains:\033[0;39m ' + str(domains))
				print('Domains: ' + str(domains), file=f)
		
				hostnames = result.get('hostnames')
				print('\033[1;92mHostnames:\033[0;39m ' + str(hostnames))
				print('Hostnames: ' + str(hostnames), file=f)	

				isp = result.get('isp')
				print('\033[1;92mISP:\033[0;39m ' + str(isp))
				print('ISP: ' + str(isp), file=f)
		
				org = result.get('org')
				print('\033[1;92mOrg:\033[0;39m ' + str(org))
				print('Org: ' + str(org), file=f)

				asn = result.get('asn')
				print('\033[1;92mASN:\033[0;39m ' + str(asn))
				print('ASN: ' + str(asn), file=f)

				country = result.get('location').get('country_name')
				print('\033[1;92mCountry:\033[0;39m ' + str(country))
				print('Country: ' + str(country), file=f)

				software = result.get('product')
				print('\033[1;92mSoftware:\033[0;39m ' + str(software))
				print('Software: ' + str(software), file=f)

				version = result.get('version')
				print('\033[1;92mVersion:\033[0;39m ' + str(version))
				print('Version: ' + str(version), file=f)

				data = result.get('data')
				print('\n')
				print('\n', file=f)
				print('\033[1;92mData:\033[0;39m\n' + str(data))
				print('Data:\n' + str(data), file=f)
				print('\n')
				print('\n', file=f)

			print('\033[1;92mResults saved to file:\033[0;39m ' + filename)

		else:
			print('Scan ID produced no results.')

		f.close()
		
	except shodan.APIError as e:
			print(f'Error: {e}')


#print exploit information
#option to save code to a file in default exploits directory or elsewhere
def print_exploits(results):
	
	if results['matches']:
		for result in results['matches']:
			description = result.get('description')
			author = result.get('author')
			date = result.get('date')    
			source = result.get('source')    
			platform = result.get('platform')
			port = result.get('port')
			type = result.get('type')
			cve = result.get('cve')
			bid = result.get('bid')
			msb = result.get('msb')    
			osvdb = result.get('osvdb')
			print('\033[1;92mDescription:\033[0;39m ' + str(description))
			print('\033[1;92mAuthor:\033[0;39m ' + str(author))
			print('\033[1;92mDate:\033[0;39m ' + str(date))
			print('\033[1;92mSource:\033[0;39m ' + str(source))
			print('\033[1;92mPlatform:\033[0;39m ' + str(platform))
			print('\033[1;92mPort:\033[0;39m ' + str(port))
			print('\033[1;92mType:\033[0;39m ' + str(type))
			print('\033[1;92mCVE:\033[0;39m ' + str(cve))
			print('\033[1;92mBugtraq ID:\033[0;39m ' + str(bid))
			print('\033[1;92mMicrosoft Security Bulletin ID:\033[0;39m ' + str(msb))
			print('\033[1;92mOSVDB:\033[0;39m ' + str(osvdb))
			print('\n')
			print("""\033[96mView Code?
		[1] Yes
		[2] No
		[3] No and return to exploits menu
		""")  

			get_code = int(input('\033[96m> Enter Selection: '))
						
			print('\033[39m\n') 
			
			if get_code == 3:
				break

			elif get_code == 2:
				pass

			elif get_code == 1:
				code = result.get('code')
				print('\033[1;92mCode:\033[0;39m')
				print(code)
				print('\n')
				print("""\033[96mSave code to file?
		[1] Yes
		[2] No
		[3] No and return to exploits menu
		""")
				save_code_to_file = int(input('\033[96m> Enter Selection: '))
				if save_code_to_file == 3:
					break
				elif save_code_to_file == 2:
					pass
				elif save_code_to_file == 1:
					file_name = input('\033[39m> Enter file name (path optional, default path is exploits/) : ')
					if '/' not in file_name:
						file_name = 'exploits/' + file_name
					with open(file_name, 'w') as f:
						f.write(code)

					print('\n\033[1;92mResults saved to file:\033[0;39m ' + file_name)

				else:
					print('\033[31mInvalid Choice\033[39m\n')
			else:
				print('\033[31mInvalid Choice\033[39m\n')

	else:
		print('No matches found.')

#find exploits by keyword search
def exploits_by_keyword(search_term):
	results = api.exploits.search(search_term)
	print_exploits(results)

#find exploits by exploit description
def exploits_by_description(description, keyword):
	if keyword:
		search_query = keyword + ' description:' + '"' + description + '"'
	else:
		search_query = 'description:' + '"' + description + '"'

	results = api.exploits.search(search_query)
	print_exploits(results)

#find exploits by platform
def exploits_by_platform(platform, keyword):
	if keyword:
		search_query = keyword + ' platform:' + '"' + platform + '"'
	else:
		search_query = 'platform:' + '"' + platform + '"'

	results = api.exploits.search(search_query)
	print_exploits(results)

#find exploits by port number
def exploits_by_port(port, keyword):
	if keyword:
		search_query = keyword + ' port:' + '"' + port + '"'
	else:
		search_query = 'port:' + '"' + port + '"'

	results = api.exploits.search(search_query)
	print_exploits(results)

#find exploits by exploit type (dos, exploit, local, remote, shellcode, webapps)
def exploits_by_type(type, keyword):
	if keyword:
		search_query = keyword + ' type:' + '"' + type + '"'
	else:	
		search_query = 'type:' + '"' + type + '"'

	results = api.exploits.search(search_query)
	print_exploits(results)

#find exploits by CVE number
def exploits_by_cve(cve, keyword):
	if keyword:
		search_query = keyword + ' ' + cve
	else:
		search_query = cve

	results = api.exploits.search(search_query)
	print_exploits(results)

#build an exploit search with multiple search components
def build_exploit_search(platform, port, type, description, cve, keyword):
	search_query = ''
	if platform:
		search_query = 'platform:' + '"' + platform + '"'
	if port:
		search_query = search_query + ' port:' + '"' + port + '"'
	if type:
		search_query = search_query + ' type:' + '"' + type + '"'
	if description:
		search_query = search_query + ' description' + '"' + description + '"'
	if cve:
		search_query = search_query + ' ' + cve
	if keyword:
		search_query = keyword + ' ' + search_query

	results = api.exploits.search(search_query)
	print_exploits(results)

#count exploits by user-defined search
def count_exploits_by_keyword(search_term):
	try:
		results = api.exploits.count(search_term)
		count = str(results.get('total'))
		print('Count: ' + count)

	except shodan.APIError as e:
			print(f'Error: {e}')


#get api plan and status info
def api_plan_info():
	results = api.info()

	plan = results.get('plan')
	print('\n\033[1;92mplan:\033[0;39m ' + str(plan))

	usage_limits_scan_credits = results.get('usage_limits').get('scan_credits')
	usage_limits_query_credits = results.get('usage_limits').get('query_credits')
	usage_limits_monitored_ips = results.get('usage_limits').get('monitored_ips')
	print('\033[1;92musage_limits:\033[0;39m')
	print('\033[1;92m\t- scan_credits:\033[0;39m ' + str(usage_limits_scan_credits))
	print('\033[1;92m\t- query_credits:\033[0;39m ' + str(usage_limits_query_credits))
	print('\033[1;92m\t- monitored_ips:\033[0;39m ' + str(usage_limits_monitored_ips))

	scan_credits = results.get('scan_credits')
	print('\033[1;92mscan_credits:\033[0;39m ' + str(scan_credits))

	query_credits = results.get('query_credits')
	print('\033[1;92mquery_credits:\033[0;39m ' + str(query_credits))

	monitored_ips = results.get('monitored_ips')
	print('\033[1;92mmonitored_ips:\033[0;39m ' + str(monitored_ips))

	unlocked = results.get('unlocked')
	print('\033[1;92munlocked:\033[0;39m ' + str(unlocked))

	unlocked_left = results.get('unlocked_left')
	print('\033[1;92munlocked_left:\033[0;39m ' + str(unlocked_left))

	https = results.get('https')
	print('\033[1;92mhttps:\033[0;39m ' + str(https))

	telnet = results.get('telnet')
	print('\033[1;92mtelnet:\033[0;39m ' + str(telnet))	



#main
def main():
	#script is incompatible with Python2
	if sys.version.startswith('2'):
		sys.exit('Works with Python3 only.')

	#print the shonydanza banner
	banner()

	#get main menu and sub-menu selections
	while True:

		menu()

		option = int(input('\033[92m> Enter Selection: '))

		if option == 1:
			
			while True:
				print("""
				\033[96m
				[1] Get IPs by port
				[2] Get IPs by software product/version
				[3] Get IPs by OS
				[4] Get IPs by search terms
				[5] Build-a-search to get IPs
				[6] Use stock searches
				[7] Return to main menu
				""")

				option = int(input('\033[96m> Enter Selection: '))

				if option == 1:
					port = input('\033[39m> Enter port: ')
					keyword = input('\033[39m> Enter additional Shodan search term(s) (OPTIONAL): ')
					print('\n')
					ip_by_port(port, keyword)
				elif option == 2:
					product = input('\033[39m> Enter product: ')
					version = input('\033[39m> Enter version (OPTIONAL): ')
					keyword = input('\033[39m> Enter additional Shodan search term(s) (OPTIONAL): ')
					print('\n')
					ip_by_product(product, version, keyword)
				elif option == 3:
					os = input('\033[39m> Enter OS: ')
					keyword = input('\033[39m> Enter additional Shodan search term(s) (OPTIONAL): ')
					print('\n')
					ip_by_os(os, keyword)
				elif option == 4:
					search_term = input('\033[39m> Enter Shodan search: ')
					print('\n')
					ip_by_keyword(search_term)
				elif option == 5:
					port = input('\033[39m> Enter port (OPTIONAL): ')
					product = input('\033[39m> Enter product (OPTIONAL): ')
					version = input('\033[39m> Enter version (OPTIONAL): ')
					os = input('\033[39m> Enter OS (OPTIONAL): ')
					keyword = input('\033[39m> Enter additional Shodan search term(s) (OPTIONAL): ')
					print('\n')
					build_ip_search(port, product, version, os, keyword)
				elif option == 6:
					ip_by_stock_search()
				elif option == 7:
					break
				else:
					print('\033[31mInvalid Choice')
		elif option == 2:
			search_term = input('\033[39m> Enter Shodan search: ')
			print('\n')
			count_by_keyword(search_term)
		elif option == 3:
			ip = input('\033[39m> Enter IP(s) or CIDR range: ')
			print('\n')
			check_malware_ip(ip)
		elif option == 4:
			ip = input('\033[39m> Enter IP: ')
			print('\n')
			score = honeyscore(ip)
			if score == 1.1:
				score = 'Error occurred for that IP.'
			print('Honeypot probability score: ' + str(score))
		elif option == 5:
			ip = input('\033[39m> Enter host IP: ')
			print('\n')
			get_host_profile(ip)
		elif option == 6:
			domain = input('\033[39m> Enter domain: ')
			print('\n')
			get_domain_profile(domain)
		elif option == 7:
			scan_object = {}
			while True:
				print("""
				\033[96m
				[1] Initiate scan
				[2] Check scan status
				[3] View scan results
				[4] Show available protocols
				[5] Return to main menu
				""")

				option = int(input('\033[96m> Enter Selection: '))
			
				if option == 1:
					scan_object = []
					while True:
						print("""
						\033[93m
						[1] Basic scan
						[2] Scan particular ports/protocols
						[3] Return to Scan on-demand menu
						""")

						option = int(input('\033[93m> Enter Selection: '))

						if option == 1:
							targets = input('\033[39m> Enter IP(s), CIDR range(s), or hostname(s) (comma-separated): ')
						
							scan_object = targets.replace(' ', '').split(',')
							
							if len(scan_object) == 1:
								scan_object = ''.join(scan_object)

							run_scan(scan_object)

						elif option == 2:
							scan_object = {}
							while True:
								target = input('\033[39m> Enter IP, CIDR range, or hostname (or type "scan" when ready to scan): ')
								if target == 'scan':
									break

								port_protocol = ast.literal_eval(input("""
\033[39m> Ports and protocols required format: [(22, 'ssh'), (503, 'modbus'), (80, 'http')] 
Enter below: 
"""))
								print('\n')

								scan_object.update({target:port_protocol})

							run_scan(scan_object)

						elif option == 3:
							break

						else:
							print('\033[31mInvalid Choice')
				elif option == 2: 
					scan_id = input('\033[39m> Enter scan ID: ')
					print('\n')
					get_scan_status(scan_id)
				elif option == 3:
					scan_id = input('\033[39m> Enter scan ID: ')
					print('\n')
					view_scan_results(scan_id)
				elif option == 4:
					protocols = api.protocols()
					for protocol in protocols:
						print('\033[1;92m' + protocol + ':\033[0;39m ' + protocols[protocol])
				elif option == 5:
					break

				else:
					print('\033[31mInvalid Choice')
					

		elif option == 8:

			while True:
				print("""
				\033[96m
				[1] Find exploits by platform
				[2] Find exploits by port
				[3] Find exploits by type
				[4] Find exploits by description
				[5] Find exploits by CVE
				[6] Find exploits by search term
				[7] Build-a-search to find exploits
				[8] Count exploits by search terms
				[9] Return to main menu
				""")

				option = int(input('\033[96m> Enter Selection: '))
			
				if option == 1:
					platform = input('\033[39m> Enter platform: ')
					keyword = input('\033[39m> Enter additional Shodan search term(s) (OPTIONAL): ')
					print('\n')
					exploits_by_platform(platform, keyword)
				elif option == 2:
					port = input('\033[39m> Enter port: ')
					keyword = input('\033[39m> Enter additional Shodan search term(s) (OPTIONAL): ')	
					print('\n')
					exploits_by_port(port, keyword)
				elif option == 3:
					type = input('\033[39m> Enter type (dos, exploit, local, remote, shellcode, or webapps): ')
					keyword = input('\033[39m> Enter additional Shodan search term(s) (OPTIONAL): ')
					exploits_by_type(type, keyword)
				elif option == 4:
					description = input('\033[39m> Enter exploit description: ')
					keyword = input('\033[39m> Enter additional Shodan search term(s) (OPTIONAL): ')
					exploits_by_description(description, keyword)
				elif option ==5:
					cve = input('\033[39m> Enter CVE: ')
					keyword = input('\033[39m> Enter additional Shodan search term(s) (OPTIONAL): ')
					exploits_by_cve(cve, keyword)
				elif option == 6:
					search_term = input('\033[39m> Enter search term: ')
					print('\n')
					exploits_by_keyword(search_term)
				elif option == 7:
					platform = input('\033[39m> Enter platform (OPTIONAL): ')
					port = input('\033[39m> Enter port (OPTIONAL): ')
					type = input('\033[39m> Enter type (dos, exploit, local, remote, shellcode, or webapps) (OPTIONAL): ')
					description = input('\033[39m> Enter exploit description (OPTIONAL): ')
					cve = input('\033[39m> Enter CVE (OPTIONAL): ')
					keyword = input('\033[39m> Enter additional Shodan search term(s) (OPTIONAL): ')
					build_exploit_search(platform, port, type, description, cve, keyword)
				elif option == 8:
					search_term = input('\033[39m> Enter search term: ')
					print('\n')
					count_exploits_by_keyword(search_term)
				elif option == 9:
					break
				else:
					print('\033[31mInvalid Choice')
		elif option == 9:
			api_plan_info()
		elif option == 10:
			break
		else:
			print('\033[31mInvalid Choice.')

	#return prompt to default color scheme
	print('\033[39m')

	
if __name__ == "__main__":
	#get valid API Key
	try:
		API_KEY = getpass.getpass('Enter API Key: ')
		api = shodan.Shodan(API_KEY)
	except shodan.APIError as e:
		print(f'Error: {e}')

	main()

