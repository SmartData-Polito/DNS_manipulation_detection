#!/usr/bin/python

import json
import pandas as pd
import sys
from StringIO import StringIO
import pyasn
from collections import Counter
from pyspark import SparkConf, SparkContext

# INPUT
in_log=sys.argv[1]
out_aggregated=sys.argv[2]


def main():
 
    conf = (SparkConf()
             .setAppName("Rogue DNS Resolvers Discovery - Aggregation (Resolver)")
             .set("spark.dynamicAllocation.enabled", "false")
             .set("spark.task.maxFailures", 128)
             .set("spark.yarn.max.executor.failures", 128)
             .set("spark.executor.cores", "8")
             .set("spark.executor.memory", "7G")
             .set("spark.executor.instances", "500")
             .set("spark.network.timeout", "300")
    )
    
    sc = SparkContext(conf = conf)
    log=sc.textFile(in_log)

    # Parse each line of the DNS log file
    log_mapped=log.mapPartitions(emit_tuples)

    # Reduce tuples, aggregate by (resolver)
    log_reduced=log_mapped.reduceByKey(reduce_tuples)

    # Put in final format
    log_final=log_reduced.map(final_map)

    # Save on file
    log_final.saveAsTextFile(out_aggregated)



def emit_tuples(lines):

    # Create a pyasn to get ASNs
    asndb = pyasn.pyasn('ASN_VIEW_2017')
    
    # Iterate over the lines
    for line in lines:
        try:
    
            # Parse the lines
            FT,TT,DUR,SMAC,DMAC,SRC,DST,OUT,IN,BYTES,PROTO,SPT,DPT,SID,DQ,DQNL,DQC,DQT,DRES,DFAA,DFTC,\
            DFRD,DFRA,DFZ0,DFAD,DFCD,DANCOUNT,DANS,DANTTLS,\
            _IPV,_IPTTL_q,_IPTTL_r,_DOPCODE,_DQDCOUNT,_DNSCOUNT,_DARCOUNT,_DANTYPES,_DANLENS,_DANLEN,\
            _DAUTHDATA,_DAUTHTYPES,_DAUTHTTLS,_DAUTHLENS,_DAUTHLEN,_DADDDATA,_DADDTYPES,_DADDTTLS,\
            _DADDLENS,_DADDLEN \
            =parse_line(line)
            #_c_FQDN,_c_SUBDOMAIN,_c_DOMAIN,_c_SLD,_c_TLD,_c_TLD_UNKNOWN,_c_FQDN_ERR,_c_DST_ASN,_c_DST_COUNTRY \
            #=list(pd.read_csv(StringIO(line),header=None).loc[0])

            # Get Only Recursive Queries
            if DRES == "NOERROR" and DFRD == "1" and DFRA == "1":

                # Create Key            
                key = DST

                # Parse simple fields
                clients     = Counter ((SRC,))
                queries     = Counter ((DQ,))
                resp_codes  = Counter ((DRES,))

                # Parse Returned Server IPs
                servers = Counter()
                records=str(DANS).split('|-><-|')
                for record in records:
                    if is_valid_ipv4(record):
                        servers[record]+=1

                # Get Subnets
                subnets = Counter()
                for ip in servers:
                    try:
                        subnet = ".".join(ip.split(".")[0:3])+".0"
                        subnets[subnet]+=1
                    except Exception as e:
                        pass    
                         
                # Get ASNs
                asns = Counter()
                for ip in servers:
                    try:
                        this_asn = str(asndb.lookup(ip)[0])
                        if this_asn == "None":
                            this_asn = ".".join(ip.split(".")[0:2]  ) + ".0.0"
                        if ip.startswith("127.0."):
                            this_asn=ip
                    except Exception as e:
                        this_asn=ip      
                    asns[this_asn]+=1

                value = (1,clients,queries,resp_codes,servers,subnets,asns)

                # Produce an output tuple
                tup = (key,value)            

                yield tup

        except:
            pass

# Reduce is just merging the two sets
def reduce_tuples(tup1,tup2):
    n1, clients1,queries1,resp_codes1,servers1,subnets1,asns1=tup1
    n2, clients2,queries2,resp_codes2,servers2,subnets2,asns2=tup2

    return (       n1+n2, \
                   clients1+clients2, \
                   queries1+queries2, \
                   resp_codes1+resp_codes2,   \
                   servers1+servers2,   \
                   subnets1+subnets2,   \
                   asns1+asns2  )
                   
# In the end, just print the Counter in a Pandas friendly format
def final_map(tup):
    (res, (n,clients,queries,resp_codes,servers,subnets,asns)) = tup

    n_str=str(n)
    clients_str='"' + json.dumps(clients).replace('"','""').replace(",",";")+ '"'
    queries_str= '"' + json.dumps(queries).replace('"','""').replace(",",";")+ '"'
    resp_codes_str= '"' + json.dumps(resp_codes).replace('"','""').replace(",",";")+ '"'
    servers_str= '"' + json.dumps(servers).replace('"','""').replace(",",";")+ '"'
    subnets_str= '"' + json.dumps(subnets).replace('"','""').replace(",",";")+ '"'
    asns_str= '"' + json.dumps(asns).replace('"','""').replace(",",";")+ '"'

    return ",".join([res,n_str,clients_str,queries_str,resp_codes_str,servers_str,subnets_str,asns_str])

# Check if an IPv4 is valid
def is_valid_ipv4(s):
    a = s.split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True

def parse_line(line):
    fields = []
    current_field=""
    in_quote=False
    for c in line:
        if not in_quote and c == ",":
            fields.append(current_field)
            current_field=""
        elif in_quote and c == '"':
            in_quote=False
        elif not in_quote and c == '"':
            in_quote=True
        else:
            current_field+=c
    fields.append(current_field)
    return fields    
    
main()



