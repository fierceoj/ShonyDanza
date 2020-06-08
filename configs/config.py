#configs for shonydanza searches

#put your shodan API key here
API_KEY = ''

#cidr range constraint for searches that return list of IP addresses
#optional
#net_range = '0.0.0.0/0'

#maximum number of results that will be returned per search
#default is 100
search_limit = 100

#IPs exceeding the honeyscore limit will not show up in search results(except for honeyscore search)
#set to 1.0 to include all results
honeyscore_limit = 0.5
