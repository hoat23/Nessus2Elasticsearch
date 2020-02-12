#!/usr/bin/env python
#coding: utf-8
########################################################################
#Programmer: Deiner Zapata Silva
#E-mail: deinerzapata@gmail.com
#Date: 12/02/2020
#Description: Parse nessus files (.nessus) to json and load to Elasticsearch.
########################################################################
import xmltodict
import json
from utils import *
from credentials import *
from elastic import *
import glob

def buildjsonfromlist(list_array, name_key, name_value):
    data_json = {}
    cont=0
    for k_v in list_array:
        if name_key in data_json:
            str_key = name_key + str(cont)
        else:
            str_key = k_v[name_key]
        data_json.update( {str_key: k_v[name_value]} )
    return data_json

source_files = "*.nessus"
list_files = glob.glob(source_files)

print(" INFO | nessus2elasticsearch | Loading files [*.nessus]")

elk = elasticsearch()
for file in list_files:
    try:
        with open(file,encoding='utf-8') as file_xml:
            data_xml = xmltodict.parse(file_xml.read())
            data_xml = data_xml['NessusClientData_v2']
            report_json = data_xml['Report']
            metadata = {
                "@name": report_json['@name'],
                "@xmlns:cm": report_json['@xmlns:cm'],
                "source_file": "{0}".format( file )
            }
            
            for ReportHost in report_json['ReportHost']:
                data_host = {
                    "@name": ReportHost['@name'],
                    "HostProperties": buildjsonfromlist( ReportHost['HostProperties']['tag'] , "@name", "#text")
                }
                bucket_documents = []
                for ReportItem in ReportHost['ReportItem']:
                    data_json = {}
                    data_json.update(data_host)
                    if 'plugin_output' in ReportItem:
                        del ReportItem['plugin_output']
                    data_json.update({ "ReportItem": ReportItem})
                    data_json.update({ "Metadata": metadata })
                    #print_json(data_json)
                    bucket_documents.append(data_json)
                #Sending Bucket to Elasticsearch
                rpt = elk.post_bulk(bucket_documents,header_json={"index":{"_index":"nessus-xml","_type":"_doc"}})
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
    except:
         print(" ERROR | nessus2elasticsearch | Error open file {0}".format(file))
                
