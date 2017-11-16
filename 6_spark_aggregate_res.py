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

    # Parse each line of the ATA DNS log file
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
            fields=parse_line(line)
            # Handle the two log formats (short and long)
            if len(fields) == 45:
                NB,FT,SMAC,DMAC,DST,SRC,PROTO,BYTES,SPT,DPT,SID,DQ,DQNL,\
                DQC,DQT,DRES,DFAA,DFTC,\
                DFRD,DFRA,DFZ0,DFAD,DFCD,DANCOUNT,DANS,DANTTLS,\
                _IPV,_IPTTL,_DOPCODE,_DQDCOUNT,_DNSCOUNT,_DARCOUNT,_DANTYPES,_DANLENS,_DANLEN,\
                _DAUTHDATA,_DAUTHTYPES,_DAUTHTTLS,_DAUTHLENS,_DAUTHLEN,_DADDDATA,\
                _DADDTYPES,_DADDTTLS,_DADDLENS,_DADDLEN \
                =fields
            else:
                FT,TT,DUR,SMAC,DMAC,SRC,DST,OUT,IN,BYTES,PROTO,SPT,DPT,SID,DQ,DQNL,\
                DQC,DQT,DRES,DFAA,DFTC,\
                DFRD,DFRA,DFZ0,DFAD,DFCD,DANCOUNT,DANS,DANTTLS,\
                _IPV,_IPTTL_q,_IPTTL_r,_DOPCODE,_DQDCOUNT,_DNSCOUNT,_DARCOUNT,_DANTYPES,_DANLENS,_DANLEN,\
                _DAUTHDATA,_DAUTHTYPES,_DAUTHTTLS,_DAUTHLENS,_DAUTHLEN,_DADDDATA,\
                _DADDTYPES,_DADDTTLS,_DADDLENS,_DADDLEN \
                =fields

            # Get Only Recursive Queries
            if DRES == "NOERROR" and DFRD == "1" and DFRA == "1":

                # Create Key            
                key = DST

                # Parse simple fields
                clients     = set ((SRC,))
                queries     = set ((DQ,))

                # Parse Returned Server IPs
                servers = set()
                records=str(DANS).split('|-><-|')
                for record in records:
                    if is_valid_ipv4(record):
                        servers.add(record)

                         
                # Get ASNs
                asns = set()
                for ip in servers:
                    try:
                        this_asn = str(asndb.lookup(ip)[0])
                        if this_asn == "None":
                            this_asn = ".".join(ip.split(".")[0:2]  ) + ".0.0"
                        if ip.startswith("127.0."):
                            this_asn=ip
                    except Exception as e:
                        this_asn=ip      
                    asns.add(this_asn)

                value = (1,clients,queries,servers,asns)

                # Produce an output tuple
                tup = (key,value)            

                yield tup

        except:
            pass


# Reduce is just merging the two sets
def reduce_tuples(tup1,tup2):
    n1, clients1,queries1,servers1,asns1=tup1
    n2, clients2,queries2,servers2,asns2=tup2

    ret = (       n1+n2, \
                   clients1|clients2, \
                   queries1|queries2, \
                   servers1|servers2,   \
                   asns1|asns2  )


    return ret
                   
# In the end, just print the Counter in a Pandas friendly format
def final_map(tup):
    (res, (n,clients,queries,servers,asns)) = tup

    n_str=str(n)
    clients_str='"' + json.dumps(list(clients)).replace('"','""').replace(",",";")+ '"'
    queries_str= '"' + json.dumps(list(queries)).replace('"','""').replace(",",";")+ '"'
    servers_str= '"' + json.dumps(list(servers)).replace('"','""').replace(",",";")+ '"'
    asns_str= '"' + json.dumps(list(asns)).replace('"','""').replace(",",";")+ '"'

    return ",".join([res,n_str,clients_str,queries_str,servers_str,asns_str])

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



