#coding: UTF-8 
#########################################################################################
# Developer: Deiner Zapata Silva.
# Date: 20/02/2020
# Last update: 20/02/2020
# Description: Codigo para actualizar un grupo de ips según un rango
#########################################################################################
import sys
import requests
import json
#from elasticsearch import *
from elastic import *
from utils import *
#######################################################################################

def update_by_query(index_name , full_path_file, name_field_elk, name_field_csv, delimiter=",", encoding="utf-8", slices=6):
    elk = elasticsearch()
    full_url_elk =  "{0}/{1}/_update_by_query?slices={2}".format( elk.get_url_elk() , index_name , slices)
    array_data_json = loadCSVtoJSON(full_path_file,encoding=encoding, delimiter = delimiter)
    for data_json in array_data_json:
        #list_keys = list ( data_json.keys() )
        if len(data_json[name_field_csv]) > 1:
            value_field_csv =  "{0}".format( data_json[name_field_csv] )
            
            os =  "{0}".format( data_json['os'] )
            version =  "{0}".format( data_json['version'] )
            service_pack =  "{0}".format( data_json['service_pack'] )
            
            query = {
                "bool": {
                    "must": [
                        {"term": { name_field_elk : value_field_csv}}
                    ],
                    "must_not": [
                        {"exists": { "field": "os" } }
                    ]
                }
            }

            post_data = {
                "query": query,
                "script": {
                    "inline": """
                    ctx._source['netbios-name'] = '{0}';
                    ctx._source['os'] = '{1}';
                    ctx._source['version'] = '{2}';
                    ctx._source['service_pack'] = '{3}';
                    """.format(value_field_csv, os, version, service_pack),
                    "lang": "painless"
                }
            }

            get_data = {
                "query": query,
                "size": 0,
                "track_total_hits": True
            }

            sede_servicio_red_cidr_mask = "{0}|".format(name_field_csv)
            #rpt_elk = elk.req_post(full_url_elk, post_data,timeout=None)
            rpt_elk = elk.req_get(elk.get_url_elk()+"/"+index_name+"/_search", data=get_data, timeout=None)
            
            try:
                took = rpt_elk['took']
                total = rpt_elk['total']
                updated = rpt_elk['updated']
            except:
                took = -1
                total = 0
                updated = 0
            doc_count = rpt_elk["hits"]["total"]["value"]
            if 'error' in rpt_elk:
                print_json(rpt_elk)
            else:
                #print('INFO  | took: {0:6d}| total:{1:6d}| updated {2:6d} | {3}'.format( took, total, updated, value_field_csv))
                print('INFO  | count: {0:6d}| {1}'.format( doc_count, value_field_csv))
            
        else:
            print("ERROR  | field void {0}".format(data_json['cidr_mask']))
            print_json(data_json)


if __name__ == "__main__":    
    """
    - Field_from_index  - [field: "HostProperties.netbios-name.keyword"]
    - Field_from_csv    - [field: "directory_name"]
    """
    index_name = "nessus-xml-*"
    path_file = ".\data\CLIENTE\EnriquecidoEquiposClienteUsandoExcel.csv"
    name_field_elk = "HostProperties.netbios-name.keyword"
    name_field_csv = "directory_name"
    update_by_query(index_name, path_file, name_field_elk, name_field_csv, delimiter=";", encoding="utf-8-sig", slices=6)
    pass
