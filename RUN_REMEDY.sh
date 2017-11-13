#!/bin/bash


# A - INPUT, OUTPUT AND PARAMETERS
# ================================

# Input Files
LOG_DNS=$1

# Output DIRECTORY 
OUT_DIR=$2

# Parameters to filter out unfrequent resolvers and domains
MIN_RESOLUTIONS=100 # A domain is considered for anomaly detection if at least resolved <MIN_RESOLUTIONS> times 
ASN_VIEW="ASN_VIEW_2017" # A ASN_VIEW file used to get the Autonomous System Number (ASN) for a given IP address

# Define PySpark Python binaries
export PYSPARK_PYTHON=/usr/bin/python
export PYSPARK_DRIVER_PYTHON=/usr/bin/python



# B - RUN THE CODE
# ================
mkdir -p $OUT_DIR


# 1. Aggregate the DNS LOG
hdfs dfs -rm -r aggregate-res-dom.csv # Remove eventual previous <LOG_DNS_AGGREGATED>
spark-submit --master yarn --deploy-mode client \
             --files $ASN_VIEW \
              1_spark_aggregate_res_dom.py \
              $LOG_DNS aggregate-res-dom.csv
hdfs dfs -getmerge aggregate-res-dom.csv ${OUT_DIR}/aggregate-res-dom.csv # Copy locally 
 
             
# 2. Run anomaly detection             
./2_find_anomalies_res_dom.py ${OUT_DIR}/aggregate-res-dom.csv ${OUT_DIR}/anomalies-res-dom.csv $MIN_RESOLUTIONS


# 3. Calculate parameters from trace
spark-submit --master yarn --deploy-mode client \
             --files $ASN_VIEW \
              --num-executors 564 \
              --driver-memory 16G \
              3_calculate_params.py \
              $LOG_DNS ${OUT_DIR}/anomalies-res-dom.csv ${OUT_DIR}/params.json


# 4. Aggregate Resolver ASN
hdfs dfs -rm -r aggregate-res-asn.csv
spark-submit --master yarn --deploy-mode client \
             --files $ASN_VIEW \
              --num-executors 564 \
              --driver-memory 16G \
              4_spark_aggregate_res_asn.py \
              $LOG_DNS aggregate-res-asn.csv
hdfs dfs -getmerge aggregate-res-asn.csv ${OUT_DIR}/aggregate-res-asn.csv

# 5. Find Anomalies Resolver ASN
./5_find_anomalies_res_asn.py ${OUT_DIR}/aggregate-res-asn.csv ${OUT_DIR}/params.json \
                              ${OUT_DIR}/anomalies-res-dom.csv \
                              ${OUT_DIR}/anomalies-res-asn-dom.csv

# 6. Compute per resolver stats
hdfs dfs -rm -r aggregate-res.csv
spark-submit --master yarn --deploy-mode client \
             --files $ASN_VIEW \
              --num-executors 564 \
              --driver-memory 16G \
              6_spark_aggregate_res.py \
              $LOG_DNS aggregate-res.csv
hdfs dfs -getmerge aggregate-res.csv ${OUT_DIR}/aggregate-res.csv

# 7. Create final report
./7_create_final_report.py ${OUT_DIR}/aggregate-res.csv ${OUT_DIR}/anomalies-res-asn-dom.csv \
                           ${OUT_DIR}/final-report-res.csv



