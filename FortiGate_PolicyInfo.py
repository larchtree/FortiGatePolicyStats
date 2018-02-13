import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#Log into FortiGates and create a csv file of all the current fw policies
#This information will be used in a lookup table in Splunk


#Build a list of Fortigates credentials to log into
Fortigate_1 = { "ip" : '10.0.0.1', "port": '443', "user": 'read_only', "pass" : '1234', 'vdom': 'root' }
Fortigate_2 = { "ip" : '10.0.0.2', "port": '443', "user": 'read_only', "pass" : '1234', 'vdom': 'root' }
 
FortiGates = [ Fortigate_1, Fortigate_2 ]



#need a check to see if FGT is alive and logged in
def FGTLogin(FortiGate):
  login_url = 'https://%s:%s/logincheck' % (FortiGate['ip'], FortiGate['port'])
  login_payload = {'username': FortiGate['user'], 'secretkey': FortiGate['pass']}

  r = requests.post(login_url, data=login_payload, verify=False)
  return r.cookies

def FGTLogout(FortiGate):
  r = requests.get('https://%s:%s/logout' % (FortiGate['ip'], FortiGate['port']), cookies=FortiGate['cookiejar'], verify=False)


#policy stats and names
def GetPolicyNames(FortiGate):
  r = requests.get('https://%s:%s/api/v2/monitor/firewall/policy?datasource=1&with_meta=1&vdom=%s' % (FortiGate['ip'], FortiGate['port'], FortiGate['vdom']), cookies=FortiGate['cookiejar'], verify=False)
  content_json = json.loads(r.content)

  TrafficStats = {"serial": content_json['serial'], "results": {} }

  for item in content_json['results']:
    if item["policyid"] != 0:
      TrafficStats["results"][item["policyid"]] = item
  return TrafficStats

#convert json to list
def ProcessPolicyNames(TrafficStats):
  PolicyInfoList = []
  for item in TrafficStats["results"].keys():
    PolicyItem = []
    for Info in PolicyInfo:
      if Info in TrafficStats["results"][item].keys():
        if isinstance(TrafficStats["results"][item][Info], list):
          PolicyItem.append(":".join(TrafficStats["results"][item][Info]))
        else:
          if isinstance(TrafficStats["results"][item][Info], unicode):
            if len(TrafficStats["results"][item][Info]) == 0:
              PolicyItem.append(str(item))
            else:
              PolicyItem.append(str(TrafficStats["results"][item][Info]))
          else:
            PolicyItem.append(str(TrafficStats["results"][item][Info]))
      else:
        PolicyItem.append(str(item))
    PolicyInfoList.append(PolicyItem)
  return PolicyInfoList



PolicyInfo = [ 'policyid', 'name', 'from_zone', 'to_zone', 'action', 'uuid' ]

CSVFile = ""
CSVFile = ",".join(["serial"] + PolicyInfo)




for fortigate in FortiGates:
  fortigate['cookiejar'] = FGTLogin(fortigate)

  TrafficStats = GetPolicyNames(fortigate)

  PolicyInfoList = ProcessPolicyNames (TrafficStats)

  for item in PolicyInfoList:
    CSVFile += "\n"
    CSVFile += ",".join([TrafficStats["serial"]] + item)

  FGTLogout(fortigate)



print CSVFile







