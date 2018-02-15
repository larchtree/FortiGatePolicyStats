import requests
import json
import socket
import threading
import datetime
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#This script pulls all interface and policy stats every 60 seconds
# and sends that info to Splunk to be processed


#Build a list of Fortigates credentials to log into
Fortigate_1 = { "ip" : '10.0.0.1', "port": '443', "user": 'read_only', "pass" : '1234', 'vdom': 'root' }
Fortigate_2 = { "ip" : '10.0.0.2', "port": '443', "user": 'read_only', "pass" : '1234', 'vdom': 'root' }

FortiGates = [ Fortigate_1, Fortigate_2 ]

#Splunk server
Splunk_IP = '10.0.0.3'

#Create TCP data inputs in Splunk of Sourcetype "_json"
Splunk_interface = 2500 #goes to index "fgt_interface" on Splunk
Splunk_policy    = 2501 #goes to index "fgt_policy" on Splunk


#log in and get auth cookies
def FGTLogin(FortiGate):
  login_url = 'https://%s:%s/logincheck' % (FortiGate['ip'], FortiGate['port'] )
  login_payload = {'username': FortiGate['user'], 'secretkey': FortiGate['pass'] }

  r = requests.post(login_url, data=login_payload, verify=False)
  return r.cookies


def FGTLogout(FortiGate):
  r = requests.get('https://%s:%s/logout' % (FortiGate['ip'], FortiGate['port']), cookies=FortiGate['cookiejar'], verify=False)

#Get a list of interfaces that are in the "up" state
#some interfaces are ignored, such as ssl.root
def GetInterfaceList(FortiGate):
  r = requests.get('https://%s:%s/api/v2/monitor/system/available-interfaces?global=1' % (FortiGate['ip'], FortiGate['port'] ), cookies=FortiGate['cookiejar'], verify=False)

  content_json = json.loads(str(r.content))

  InterfaceList = { "_time" : str(datetime.datetime.now()) }
  for VDOM in content_json:
    InterfaceList['serial'] = VDOM['serial']
    for item in VDOM['results']:
      if "status" in item.keys():
        if item["status"] == "up" and item["name"] != "ssl.root":
          Interface = {} 
          Interface["name"] = item["name"]
          if "ipv4_addresses" in item.keys():
            Interface["ip_address"] = item["ipv4_addresses"][0]["ip"]
 
          if "alias" in item.keys():
            Interface["alias"] = item["alias"]

          #check for physical link, only include if up
          if "link" in item.keys():
            if "up" == item["link"]:
              InterfaceList[item["name"]] = Interface
          else:
            InterfaceList[item["name"]] = Interface
  return InterfaceList


#Need to add all interfaces as a dashboard widget to get traffic stats
def GetInterfaceHistory(FortiGate, Interface):
  r = requests.get('https://%s:%s/api/v2/monitor/system/traffic-history?interface=%s&time_period=hour' % (FortiGate['ip'], FortiGate['port'], Interface), cookies=FortiGate['cookiejar'], verify=False)
  content_json = json.loads(str(r.content))
  if content_json:
    if content_json['status'] == 'success':
      return content_json['results']['last_rx'], content_json['results']['last_tx']
  return 0, 0

#policy stats only (no names)
def GetPolicySessions(FortiGate):
  r = requests.get('https://%s:%s/api/v2/monitor/firewall/policy?stats_only=1' % (FortiGate['ip'], FortiGate['port']), cookies=FortiGate['cookiejar'], verify=False)
  content_json = json.loads(str(r.content))
  TrafficStats = {"_time" : str(datetime.datetime.now()) }
  for item in content_json['results']:
    TrafficStats[item["policyid"]] = item
  return TrafficStats


#policy stats and names
def GetPolicyNames(FortiGate):
  r = requests.get('https://%s:%s/api/v2/monitor/firewall/policy?datasource=1&with_meta=1&vdom=%s' % (FortiGate['ip'], FortiGate['port'], FortiGate['vdom']), cookies=FortiGate['cookiejar'], verify=False)
  content_json = json.loads(str(r.content))
  TrafficStats = {"_time" : str(datetime.datetime.now()), "serial": content_json["serial"], "results": {} }
  for item in content_json['results']:
    TrafficStats["results"][item["policyid"]] = item
  return TrafficStats


def SendSplunk(data, TCP_PORT):
  TCP_IP = Splunk_IP
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((TCP_IP, TCP_PORT))
  s.send(data)
  s.close()


def SubmitInterfaceStats(FortiGate):
  InterfaceList = GetInterfaceList(FortiGate)
  InterfaceList["list"] = []

  Ignored = ["list", "_time", "serial"]
  for item in InterfaceList.keys():
    if item not in Ignored:
      last_rx, last_tx = GetInterfaceHistory(FortiGate, item)
      InterfaceList[item]["last_rx"] = last_rx
      InterfaceList[item]["last_tx"] = last_tx
      InterfaceList["list"].append(item)
  ###print (json.dumps(InterfaceList, sort_keys=True))
  SendSplunk(json.dumps(InterfaceList), Splunk_interface)


def SubmitPolicyStats(FortiGate):
  TrafficStats = GetPolicyNames(FortiGate)

  #Splunk doesn't like large events, so we have to
  # split up messages into smaller chunks of data
  SplunkSize = 20

  TrafficSplunk = {"_time" : TrafficStats["_time"], "serial" : TrafficStats["serial"], "results": {} }

  count = 0
  for item in TrafficStats["results"].keys():
    if count < SplunkSize:
      TrafficSplunk["results"][item] = TrafficStats["results"][item]
      count += 1
    else:
      TrafficSplunk["list"] = TrafficSplunk["results"].keys()
      ###print json.dumps(TrafficSplunk, sort_keys=True)
      SendSplunk(json.dumps(TrafficSplunk, sort_keys=True), Splunk_policy)

      #reset variable for next pass
      count = 0
      TrafficSplunk = {"_time" : TrafficStats["_time"], "serial" : TrafficStats["serial"], "results": {} }
  
  #send last message to splunk
  TrafficSplunk["list"] = TrafficSplunk["results"].keys()
  ###print json.dumps(TrafficSplunk, sort_keys=True)
  SendSplunk(json.dumps(TrafficSplunk, sort_keys=True), Splunk_policy)


def FGT_Scheduler():
  threading.Timer(60.0, FGT_Scheduler).start()
  for FortiGate in FortiGates:
    SubmitInterfaceStats(FortiGate)
    SubmitPolicyStats(FortiGate)
  print (str(datetime.datetime.now()))


#log in to all FortiGates and save auth cookie
for FortiGate in FortiGates:
  FortiGate['cookiejar'] = FGTLogin(FortiGate)

#start a loop and pull information every 60 seconds
FGT_Scheduler()


#  SubmitInterfaceStats(FortiGate)
#  SubmitPolicyStats(FortiGate)

#FGTLogout(FortiGate)

