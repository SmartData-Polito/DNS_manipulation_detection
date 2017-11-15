# REMeDy: Automatic Detection of DNS Manipulations
REMeDy is a system that assists operators to identify
the use of rogue DNS resolvers in their networks. REMeDy is a
completely automatic and parameter-free system that evaluates the
consistency of responses across the resolvers active in the network.
It operates by passively analyzing DNS traffic and, as such, requires
no active probing of third-party servers. REMeDy is able to detect
resolvers that manipulate answers, including resolvers that affect
unpopular domains.


For information about this Readme file and this tool please write to
[martino.trevisan@polito.it](mailto:martino.trevisan@polito.it)


## Prerequisites and Installation
You need Python and Apache Spark installed on you machine.
Few python packages are needed: `numpy pandas pyasn`.
You can install them using the `pip` tool.

You can install `REMeDy` issuing the git command:
```
git clone https://github.com/marty90/DNS_manipulation_detection
```

## How To Run It
### Prepare the dataset
As first, obtain a dataset. In this example, we imagine to have a dataset called `ISP1_anon.gz`.

You must uncompress the archive. Just type:
```
zcat ISP1_anon.gz > ISP1_anon
```
REMeDy expect the dataset is on HDFS, so copy it on HDFS:
```
hdfs dfs -copyFromLocal ISP1_anon ISP1_anon
```
### Run REMeDy
To run REMeDy, use the script called `RUN_REMEDY.sh`. It expects two arguments: the input dataset and the output directory.
In this example, you may want to run:
```
./RUN_REMEDY.sh ISP1_anon ISP1_anon_output
```
In `ISP1_anon_output` (in your **local** file system), you find the output of REMeDy.
The **important** file is `final-report-res.csv`. It contains the retrieved manipulations, along with per-resolver statistics.
It is CSV file with the following columns:
* `resolver`:  The IP address of a resolver

**General Resolver Statistics**

* `queried_domains`: How many (unique) domains have been queried to that resolver
* `count`: How many queries did that resolver receive
* `clients`: How many clients contacted the resolver

**Anomaly Details** these columns are not-empty only where some anomaly is found for that resolver

* `asn`: destination ASN of manipulated answers
* `domains`: manipulated domains
* `servers`: IP address returned in manipulated answers











