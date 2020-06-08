#!/usr/bin/env python3

import shodan
from configs import config
import requests
import sys 

banner = """
        

███████╗██╗  ██╗ ██████╗ ███╗   ██╗██╗   ██╗██████╗  █████╗ ███╗   ██╗███████╗ █████╗     
██╔════╝██║  ██║██╔═══██╗████╗  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗████╗  ██║╚══███╔╝██╔══██╗    
███████╗███████║██║   ██║██╔██╗ ██║ ╚████╔╝ ██║  ██║███████║██╔██╗ ██║  ███╔╝ ███████║    
╚════██║██╔══██║██║   ██║██║╚██╗██║  ╚██╔╝  ██║  ██║██╔══██║██║╚██╗██║ ███╔╝  ██╔══██║    
███████║██║  ██║╚██████╔╝██║ ╚████║   ██║   ██████╔╝██║  ██║██║ ╚████║███████╗██║  ██║    
╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝    
                                                                                          
"""

tonydanza = """
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓██████████████▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓█████████████████████▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓█████████████████████████▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒█████████████████████████████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒███████████████████████████████▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██████████████▓▓█████████████████▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓████████████▒▒▒▒▒▓████████████████▌▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒║███████████▒▒▒▒▒▒▒▒▓████████████████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓██████████▒▒▒▒▒▒▒▒▒▒▒████████████████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒█████████▓▒▒▄▒▒▒▒▒▒▒▒▒▒▒▓▓████████████▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓███████████▓▓▓▓▒▒▒▒▒▒▓█████████████████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒║████████▓▒▒▒▒▓▓▓▓▒▒▒▒▓█████▓▓▓██████████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒████████▒▒▓████▒▒▒▒▒▒▒▓▓▒▒▒█▓██▓▒████████▌▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒▒▒▒▒▒▒▒▒▒░░░▒▒███████▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▒▒▒▒▒▒▒▒▓███████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒▒▒░░░░░░░░░░░▒▓██████▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▒▒▒▒▒▒▒▓▓███████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
░░░░░░░░░░░░░░░╟███████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▒▓▒▒▒▒▒▓█████████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒░░░░░░░░░░░░░░░╚█████▓▓▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▒▒▒▒▒▒▒▓████████▌▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
░░░░░░░░░░░░░░░░░░█████▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓███████▒░░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
░░░░░░░░░░░░░░░░░░░╙▀███▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓█▓▒▒▒▓██████▀░░░░░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
░░░░░░░░░░░░░░░░░░░░░░▀█▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▒▒▒▓█████▀░░░░░░░░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
░░░░░░░░░░░░░░░░░░░░░░░░▒▒▒▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓████░░░░░░░░░░░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
░░░░░░░░░░░░░░░░░░░░░░░░╫▒▒▒▓▓▒▒▒▒▒▒▒▒▒▒▒▓▓██████░░░░░░░░░░░░░░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
░░░░░░░░░░░░░░░░░░░▒▒▒▒▒▒▒▒▒▒▒▓▓▒▒▒▒▒▒▒▓▓████████▄░░░░░░░░░░░░░░░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒
░░░░░░░░░░░░░▒▒▒▒▒▒▒▒▒▒▒▓▒▒▒▒▒▒▒▒▓▓█▓█████████████▓▄░░░░░░░░░░░░░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒
░░░░░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓██▒▓▒▒▓▒▒▒░░░░░░░░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓██▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░░░▒▒▒▒▒▒▒▒▒▒▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
"""

menu = """
\33[32m
[1] Get IPs by search term
[2] Count results by search term
[3] Check malware C2 IP(s)
[4] Get IPs by OS
[5] Get IPs by software product/version
[6] Get IPs by port
[7] Get honeyscore
[8] Get host profile
[9] Get domain profile
[10]Scan IP(s)
[11]Find exploits
[12]Get API key info
"""

try:
	api = shodan.Shodan(config.API_KEY)
except shodan.APIError as e:
 	print(f'Error: {e}')

try:
	exploits_api = shodan.Shodan.Exploits(config.API_KEY)
except shodan.APIError as e:
	print(f'Error: {e}')

def print_ips(results):
	if results['matches']:
		not_honeypots = 0
		for result in results['matches']:
			ip = result['ip_str']
			if honeyscore(ip) <= config.honeyscore_limit:
				print(ip)
				not_honeypots += 1
		if not_honeypots == 0:
			print('Only honeypots were found.')
	else:
		print('No matches found.')

def ip_by_keyword(search_term):
	try:
		search_query = search_term + ' net:' + config.net_range
	except:
		search_query = search_term

	results = api.search(search_query, limit=config.search_limit)
	print_ips(results)

def count_by_keyword(search_term):
	try:
		search_query = search_term + ' net:' + config.net_range
	except:
		search_query  = search_term

	results = api.count(search_query)
	count = str(results['total'])
	print('Count: ' + count)

def check_malware_ip(ip):
	search_query = 'category:malware net:' + str(ip)
	results = api.search(search_query, limit=config.search_limit)
	if results['matches']:
		for result in results['matches']:
			ip_str = result['ip_str']
			print('IP: ' + str(ip_str))

			port = result['port']
			print('Port: ' + str(port))

			domains = result['domains']
			print('Domains: ' + str(domains))

			hostnames = result['hostnames']
			print('Hostnames: ' + str(hostnames))

			data = result['data']
			print('Data: ' + str(data))

			malware = result['product']
			print('Malware: ' + str(malware))

			isp = result['isp']
			print('ISP: ' + str(isp))

			org = result['org']
			print('Org: ' + str(org))

			asn = result['asn']
			print('ASN: ' + str(asn))

			country = result['location']['country_name']
			print('Country: ' + str(country))
			print('\n')
	else:
		print('No  matches found.')	

def ip_by_os(os):
	try:
		search_query = 'os:' + '"' + os + '"' + ' net:' + config.net_range
	except:
		search_query = 'os:' + '"' + os + '"'
	results = api.search(search_query, limit=config.search_limit)
	print_ips(results)

def ip_by_product(product, version):
	try:
		if version:
			search_query = 'product:' + '"' + product + '"' + ' version:' + '"' + version + '"' + ' net:' + config.net_range
		else:
			search_query = 'product:' + '"' + product + '"' + ' net:' + config.net_range
	except:
		if version:
			search_query = 'product:' + '"' + product + '"' + ' version:' + '"' + version + '"'
		else:
			search_query = 'product:' + '"' + product + '"'
	results = api.search(search_query, limit=config.search_limit)
	print_ips(results)

def ip_by_port(port):
	try:
		search_query = 'port:' + '"' + port + '"' + ' net:' + config.net_range
	except:
		search_query = 'port:' + '"' + port + '"'
	results = api.search(search_query, limit=config.search_limit)
	print_ips(results)

def honeyscore(ip):
	url = 'https://api.shodan.io/labs/honeyscore/' + ip + '?key=' + config.API_KEY
	response = requests.get(url)
	score = float(response.text)
	return score

def get_host_profile(ip):
	results = api.host(ip)

	print("\n===========================================================")
	print('*****************     Basic Host Info     *****************')
	print("===========================================================\n")

	ip_str = results['ip_str']
	print('IP: ' + str(ip_str))

	ports = results['ports']
	print('Ports: ' + str(ports))

	os = results['os']
	print('OS: ' + str(os))

	domains = results['domains']
	print('Domains: ' + str(domains))

	hostnames = results['hostnames']
	print('Hostnames: ' + str(hostnames))

	isp = results['isp']
	print('ISP: ' + str(isp))

	org = results['org']
	print('Org: ' + str(org))

	asn = results['asn']
	print('ASN: ' + str(asn))

	country = results['country_name']
	print('Country: ' + str(country))
	print('\n')

	for result in results['data']:
		print("\n==========================================================")
		print('******************     Host Service     ******************')
		print("==========================================================\n")

		software = result['product']
		print('Software: ' + str(software))

		version = result.get('version')
		print('Version: ' + str(version))

		port = result['port']
		print('Port: ' + str(port))

		data = result['data']
		print('\n')
		print(str(data))
		
		
def get_domain_profile(domain):
	url = 'https://api.shodan.io/dns/domain/' + domain + '?key=' + config.API_KEY
	response = requests.get(url)
	print(response.text)

def scan_ip(ip):
	pass

def find_exploits():
	pass

def api_key_info():
	print(api.info())

def main():
	if sys.version.startswith('2'):
		sys.exit('Works with Python3 only.')

	print('\033[33m' + banner)

	while True:

		print(menu)

		option = int(input('\33[32m> Enter Selection: '))

		if option == 1:
			search_term = input('\033[39mEnter search term: ')
			print('\n')
			ip_by_keyword(search_term)
		elif option == 2:
			search_term = input('\033[39mEnter search term: ')
			print('\n')
			count_by_keyword(search_term)
		elif option == 3:
			ip = input('\033[39mEnter IP(s) or CIDR range: ')
			print('\n')
			check_malware_ip(ip)
		elif option == 4:
			os = input('\33[32m> Enter OS: ')
			print('\n')
			ip_by_os(os)			
		elif option == 5:
			product = input('\33[39m> Enter product: ')
			version = input('\33[39m> Enter version: ')
			print('\n')
			ip_by_product(product, version)
		elif option == 6:
			port = input('\33[39m> Enter port: ')
			print('\n')
			ip_by_port(port)
		elif option == 7:
			ip = input('\33[39m> Enter IP: ')
			print('\n')
			score = honeyscore(ip)
			print('Honeypot probability score: ' + str(score))
		elif option == 8:
			ip = input('\33[39m> Enter host IP: ')
			print('\n')
			get_host_profile(ip)
		elif option == 9:
			domain = input ('\33[39m> Enter domain: ')
			print('\n')
			get_domain_profile(domain)
		elif option == 12:
			print('\33[39m')
			api_key_info()
		elif option == 13:
			break
		else:
			print('Invalid Choice.')

	print('\033[39m' + tonydanza)


if __name__ == "__main__":
	main()
