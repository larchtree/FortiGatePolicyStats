# FortiGatePolicyStats
A script to pull policy stats from a FortiGate every 60 seconds and send them to Splunk to be graphed on a dashboard.

## Install

### FortiGate_PolicyInfo.py
- modify the list of firewalls that you are going to monitor 
- Run script and save output as a csv file 
> FortiGate_PolicyInfo.py > fortigate_policy.csv
- Upload fortigate_policy.csv to Splunk as a lookup (Lookups » Lookup table files)

### Create objects in Splunk
- Create 2 new indexes called "fgt_interface" and "fgt_policy"
- In "Data inputs » TCP", add a new input for interface stats
```
TCP Port Number : 2500
Sourcetype : _json
Index : fgt_interface
```
- In "Data inputs » TCP", add a new input for policy stats
```
TCP Port Number : 2501
Sourcetype : _json
Index : fgt_policy
```
- Create a new dashboard, and then edit source
- Paste contents of "SplunkDasboard.xml" as the new dashboard

### FortiGate_TrafficStats.py	
- This script will log into the firewalls and pull interface and policy stats, then format the information into json and send it into Splunk in a way that the dashboard can interpret and graph the data. 
- Need to modify the first section of this file to match your site.
- Splunk ports do not need to be modified, unless you changed defined a different port in Splunk
