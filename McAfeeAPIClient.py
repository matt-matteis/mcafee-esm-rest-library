#!/usr/bin/python

import json
import base64
import requests

def APIrequest(endpointURL, requestType, requestData,  sessionId):
    headerData = {'Content-Type': 'application/json', 'Authorization': 'Session '+sessionId}
    if requestType == 'post':
        request = requests.post(url=endpointURL, data=requestData, headers=headerData, verify=False)
    elif requestType == 'delete':
        request = requests.delete(url=endpointURL, headers=headerData, verify=False)
    else:
        return "McAfee REST API only supports POST and DELETE methods" 

    return request.text

class McAfeeESM(object):
    def __init__(self, endpoint, username, password):
        self.endpoint = endpoint
        self.username = username
        self.password = password
        self.sessionId = None

    def getSessionId(self):
        authEncoded = base64.b64encode(self.username+":"+self.password)
        headerData = {'Content-Type': 'application/json', 'Authorization': 'Basic '+authEncoded}
        loginURL = self.endpoint+'/rs/esm/login'
        request = requests.post(url=loginURL, data={}, headers=headerData, verify=False)
        sessionId =  request.headers['Location']
        self.sessionId = sessionId

        return sessionId

    def deleteSessionId(self):
        logoutURL = self.endpoint+'/rs/esm/logout'
        response = APIrequest(logoutURL, 'delete', '', self.sessionId)

    def getReceiversList(self):
        receiverListURL = self.endpoint+'/rs/esm/devGetDeviceList?filterByRights=false'
        data = json.dumps({"types": ["RECEIVER"]})
        response = APIrequest(receiverListURL, 'post', data, self.sessionId)
        response = json.loads(response)
        response = response['return']
        
        fullReceiverList = [{'name': str(receiver['name']), 'id': receiver['id']['id']} for receiver in response]
        return fullReceiverList

    def addDataSource(self, newDataSource):
        addDataSourceURL = self.endpoint+'/rs/esm/dsAddDataSource'
        response = APIrequest(addDataSourceURL, 'post', json.dumps(newDataSource.dsJson), self.sessionId)

    def removeDataSource(self, receiverId, dsId):
        removeDataSourceURL = self.endpoint+'/rs/esm/dsDeleteDataSource'
        data = json.dumps({"receiverId": {"id": receiverId}, "datasourceId": {"id": dsId}})
        response = APIrequest(removeDataSourceURL, 'post', data, self.sessionId)

    def getDataSources(self, receiverId):
        getDataSourcesURL = self.endpoint+'/rs/esm/dsGetDataSourceList'
        data = json.dumps({"receiverId": {"id": receiverId}})
        response = APIrequest(getDataSourcesURL, 'post', data, self.sessionId)
        response = json.loads(response)
        response = response['return']

        fullDataSourceList = [{'name': str(datasource['name']), 'id': datasource['id']['id']} for datasource in response]
        return fullDataSourceList

class DataSourceDetail(object):
    def __init__(self, status, ipAddress, name, parentId, typeId):
        if status.lower() == "enabled":
            self.enabled = True
        else:
            self.enabled = False
        self.ipAddress = ipAddress
        self.name = name
        self.parentId = parentId
        self.typeId = typeId
        self.url = ""
        self.zoneId = 0
        self.idmId = 0
        self.childEnabled = True
        self.childCount = 0
        self.childType = 1
        self.parameters = [{"key": "elm_logging", "value": "no"}, {"key": "pool", "value": ""}, {"key": "hostname", "value": self.ipAddress}, {"key": "keepme", "value": ""}, {"key": "parsing", "value": "yes"}]

        # Linux datasource
        if self.typeId == 65:
            dsDetailParams = [{"key": "autolearn", "value": "F"}, {"key": "require_tls", "value": "F"}, {"key": "syslog_port", "value": "514"}, {"key": "mask", "value": "0"}, {"key": "require_tls", "value": "F"}, {"key": "snmp_trap_id", "value": "0"}, {"key": "syslog_port", "value": "514"}, {"key": "type", "value": "49190"}, {"key": "tz_id", "value": "EST5EDT"}]

            for i in dsDetailParams:
                self.parameters.append(i)

        # Windows datasource
        elif self.typeId == 43:
            dsDetailParams = [{"key": "profile_engineid", "value": ""}, {"key": "profile_id", "value": "4"}, {"key": "profile_ipaddress", "value": "::"}, {"key": "profile_port", "value": "0"}, {"key": "profile_snmp_seclevel", "value": ""}, {"key": "profile_snmpv1community", "value": ""}, {"key": "profile_snmpv3authmode", "value": ""}, {"key": "use_rpc", "value": "yes"}, {"key": "snmp_trap_id", "value": "0"}, {"key": "wmi_interval", "value": "600"}, {"key": "wmi_logs", "value": "system,application,security"}, {"key": "wmi_version", "value": "0"}, {"key": "profile_snmpv3password", "value": ""}, {"key": "profile_snmpv3username", "value": ""}, {"key": "wmi_password", "value": ""}, {"key": "wmi_username", "value": ""}]

        self.dsJson = {"datasource": {"childCount": self.childCount, "childEnabled": self.childEnabled, "childType": self.childType, "enabled": self.enabled, "idmId": self.idmId, "ipAddress": self.ipAddress, "name": self.name, "parameters": self.parameters, "parentId": {"id": self.parentId}, "typeId": {"id": self.typeId}, "url": self.url, "zoneId": self.zoneId}}


    def dsPrettyPrint(self):
        print json.dumps(self.dsJson, indent=4, sort_keys=True)
