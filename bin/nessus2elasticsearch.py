#!/usr/bin/env python
#coding: utf-8
########################################################################
#Programmer: Deiner Zapata Silva
#E-mail: deinerzapata@gmail.com
#Date: 10/02/2020
#Description: Parse nessus files to json and load to Elasticsearch.
########################################################################
from utils import *
from libnessus.parser import NessusParser
from credentials import *
from elastic import *
#from libnessus.plugins.backendpluginFactory import BackendPluginFactory
import glob

index_settings = {u'mappings': {u'vulnerability': {u'properties': {u'host-fqdn': {u'type': u'string'},
    u'host_ip': {u'type': 'ip', "index" : "not_analyzed","doc_values": "true"},
    u'host_name': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
    u'operating-system': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
    u'scantime': {u'format': u'dateOptionalTime', u'type': u'date'},
    u'system-type': {u'type': u'string'},
    u'vulninfo': {u'properties': {u'apple-sa': {u'type': u'string'},
      u'bid': {u'type': u'string'},
      u'canvas_package': {u'type': u'string'},
      u'cert': {u'type': u'string'},
      u'cpe': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
      u'cve': {u'type': u'string'},
      u'cvss_base_score': {u'type': u'float'},
      u'cvss_temporal_score': {u'type': u'string'},
      u'cvss_temporal_vector': {u'type': u'string'},
      u'cvss_vector': {u'type': u'string'},
      u'cwe': {u'type': u'string'},
      u'd2_elliot_name': {u'type': u'string'},
      u'description': {u'type': u'string'},
      u'edb-id': {u'type': u'string'},
      u'exploit_available': {u'type': u'boolean'},
      u'exploit_framework_canvas': {u'type': u'string'},
      u'exploit_framework_core': {u'type': u'string'},
      u'exploit_framework_d2_elliot': {u'type': u'string'},
      u'exploit_framework_metasploit': {u'type': u'string'},
      u'exploitability_ease': {u'type': u'string'},
      u'exploited_by_malware': {u'type': u'string'},
      u'fname': {u'type': u'string'},
      u'iava': {u'type': u'string'},
      u'iavb': {u'type': u'string'},
      u'metasploit_name': {u'type': u'string'},
      u'osvdb': {u'type': u'string'},
      u'owasp': {u'type': u'string'},
      u'patch_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
       u'type': u'date'},
      u'pluginFamily': {u'type': u'string'},
      u'pluginID': {u'type': u'string'},
      u'pluginName': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
      u'plugin_modification_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
       u'type': u'date'},
      u'plugin_name': {u'type': u'string'},
      u'plugin_output': {u'type': u'string'},
      u'plugin_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
       u'type': u'date'},
      u'plugin_type': {u'type': u'string'},
      u'port': {u'type': u'string'},
      u'protocol': {u'type': u'string'},
      u'rhsa': {u'type': u'string'},
      u'risk_factor': {u'type': u'string'},
      u'script_version': {u'type': u'string'},
      u'secunia': {u'type': u'string'},
      u'see_also': {u'type': u'string'},
      u'severity': {u'type': u'integer'},
      u'solution': {u'type': u'string'},
      u'stig_severity': {u'type': u'string'},
      u'svc_name': {u'type': u'string'},
      u'synopsis': {u'type': u'string'},
      u'vuln_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
       u'type': u'date'},
      u'xref': {u'type': u'string'}}}}}}} 
source_files = "*.nessus"
list_files = glob.glob(source_files)

print(" INFO | nessus2elasticsearch | Loading files [*.nessus]")
elk = elasticsearch()
for file in list_files:
    try:
        nessus_obj_list = NessusParser.parse_fromfile(file)
    except:
        print(" ERROR | nessus2elasticsearch | File cannot be imported : {0}".format(file))
        continue
    for i in nessus_obj_list.hosts:
        bucket_documents = []
        data_json = {
            "scantime": "{0}".format(nessus_obj_list.endtime),
            "host_ip": "{0}".format(i.ip),
            "host_name": "{0}".format(i.name),
            "host_fqdn": "{0}".format(i.get_host_property('host-fqdn')),
            "operating-system": "{0}".format(i.get_host_property('operating-system')),
            "system-type": "{0}".format(i.get_host_property('system-type')),
            "mac-address": "{0}".format(i.get_host_property('mac-address')),
            "os": "{0}".format(i.get_host_property('os')),
            "netbios-name": "{0}".format(i.get_host_property('netbios-name')),
            "source_file": "{0}".format(file)
        }
        
        for v in i.get_report_items:
            vulinfo =  v.get_vuln_info 
            
            if 'plugin_output' in vulinfo:
                del vulinfo['plugin_output'] # Hace la carga mas ligera
            
            data_json.update( {'vulinfo' : vulinfo} )
            
            try:
                vulnerability = "{0}-{1}-{2}".format( vulinfo['pluginID'], vulinfo['pluginName'], vulinfo['severity'])
            except:
                vulnerability = "None"
                print_json(data_json)
                print(" ERROR | nessus2elasticsearch | vulnearbility = None | Press a any key to continue...")
            finally:
                data_json.update( {'vulnerability': vulnerability} )
            bucket_documents.append(data_json)
        #Sending Bucket to Elasticsearch
        rpt = elk.post_bulk(bucket_documents,header_json={"index":{"_index":"nessus-analytics","_type":"_doc"}})
        try:
            
            if 'errors' in rpt:
                if rpt['errors'] :
                    print(" INFO  | nessus2elasticsearch | Response from ElasticSearch | Errors: {0}".format( rpt['errors'] ))
            else:
                print(" ERROR | nessus2elasticsearch | Response from ElasticSearch | error_field_not_found")
                print_json(rpt)
                input(" INFO  | nessus2elasticsearch | error_field_not_found | Press any key to continue ...")
        except:
            print(" ERROR | nessus2elasticsearch | Catch a except | Response from ElasticSearch")
            print_json(rpt)
            input(" INFO  | nessus2elasticsearch | Catch a except | Press any key to continue ...")
    print(" INFO | nessus2elasticsearch | File imported successfully: {0}".format(file))
