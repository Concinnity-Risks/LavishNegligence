#!/usr/bin/env python
#
# CA-Cert-Graph.py
# Stream the SSL/TLS certificates that Shodan is collecting at the moment
#
# WARNING: This script only works with people that have a subscription API plan!
# And by default the Streaming API only returns 1% of the data that Shodan gathers.
# If you wish to have more access please contact us at support@shodan.io for pricing
# information.
#
# Author: achillean (altered by blackswanburst)

import shodan
import json
import datetime
#from pybloom_live import BloomFilter

def pretty(d, indent=0):
   for key, value in d.items():
      print('\t' * indent + str(key))
      if isinstance(value, dict):
        pretty(value, indent+1)
      elif isinstance(value, unicode):
        print('\t' * (indent+1) + str(value.encode("ascii","ignore")))
      else:
        print('\t' * (indent+1) + str(value))

#print("Constructing bloomfilter...")
#bf = BloomFilter(4000000000, 0.001)

# Configuration
API_KEY = "Vljqpo0npsoY2ITMe1Fapm0noazG8LR9"

# Open a file
print("Preparing graphs...")
graph = open(datetime.datetime.today().strftime('%Y-%m-%d-%H-%M')+"-Cert-Graph.csv", "w")
#graph.write("Source,Target,Expired,IssuedDate,ExpiryDate,Version,SignatureAlgorithm,KeyType,Bits\n")
print("Initialising variables...")
# Setup the api
api = shodan.Shodan(API_KEY)
#iteration counter
n = 0
#unique = 0
print('Listening for certs...')
for banner in api.stream.ports([443, 8443]):
    #pretty(banner)
    if 'ssl' in banner and 'cert' in banner['ssl']:
        n += 1
        #pretty(banner['ssl']['cert'])
        if n >= 1000000:
            # Close opened file
            graph.close()
            print("Closing file after 100K Certs")
            break
        #elif banner['ssl']['cert']['fingerprint']['sha256'] in bf:
        else:
            graph.write(json.dumps(banner['ssl'])+"\n")
graph.close()
