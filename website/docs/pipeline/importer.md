---
id: importer
title: Importer
sidebar_label: Importer
---
A netsage-netflow-importer-daemon reads any new nfcapd files that have come in after a configurable delay and writes the results to the netsage_deidentifier_raw RabbitMQ queue.
All flow data waits in the netsage_deidentifier_raw queue until it is read in and processed by the logstash pipeline.

The importer uses the nfdump command with -a to aggregate raw flows within the file by source and destination IPs, ports, and protocal. The  -L `threshold` option is used to throw out any aggregated flows under a threshold number of bytes. This threshold is specified in the importer config file. 

NOTE: The importer will be deprecated in the future and replace with a logstash operation.

### Configuration
Configuration files for the importer are netsage_netflow_importer.xml and netsage_shared.xml. Comments in the files briefly describe the options.

To avoid re-reading nfcapd files, the names of files that have already been read are stored in netflow_importer.cache. 