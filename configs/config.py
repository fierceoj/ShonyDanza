#configs for shonydanza searches

#shodan account API key
#required
API_KEY = ''

#IP or cidr range constraint for searches that return list of IP addresses
#optional 
#net_range = '0.0.0.0/0'

#maximum number of results that will be returned per search
#required
#default is 100
search_limit = 100

#honeyscore probability limit
#IPs exceeding the honeyscore limit will not show up in search results 
#required
#change to 1.0 to include all results
honeyscore_limit = 0.5
