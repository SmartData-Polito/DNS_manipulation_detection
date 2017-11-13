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


## Prerequisites
You need Python and Apache Spark installed on you machine.
Few python packages are needed: `numpy pandas pyasn`

