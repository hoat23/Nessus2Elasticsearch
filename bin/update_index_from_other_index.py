#coding: UTF-8 
#########################################################################################
# Developer: Deiner Zapata Silva.
# Date: 20/02/2020
# Last update: 20/0272020
# Description: Codigo para actualizar un grupo de ips según un rango
#########################################################################################
import sys
import requests
import json
#from elasticsearch import *
from elastic import *
from utils import *
#######################################################################################

def update_by_query(elk, full_url_elk, full_path_file):
    array_data_json = loadCSVtoJSON(full_path_file,encoding="utf-8", delimiter = ",")
    for data_json in array_data_json:
        #list_keys = list ( data_json.keys() )
        if len(data_json['cidr_mask']) > 1:
            cidr_mask =  "{0}".format( data_json['cidr_mask'] )
            red =  "{0}".format( data_json['red'] )
            sede =  "{0}".format( data_json['sede'] )
            servicio =  "{0}".format( data_json['servicio'] )
            vlan_user =  "{0}".format( data_json['vlan_user'] )
            query = {
                "bool": {
                    "must": [
                        {"term": { "HostProperties.host-ip":  data_json['cidr_mask']}}
                    ]
                }
            }
            post_data = {
                "query": query,
                "script": {
                    "inline": """
                    ctx._source['cidr_mask'] =  '{0}';
                    ctx._source['red'] = '{1}';
                    ctx._source['sede'] = '{2}';
                    ctx._source['servicio'] = '{3}';
                    ctx._source['vlan_user'] = '{4}';
                    """.format(cidr_mask, red, sede, servicio, vlan_user),
                    "lang": "painless"
                }
            }
            sede_servicio_red_cidr_mask = "{0}|{1}|{2}|{3}".format(sede,servicio,red,cidr_mask)
            #print_json(post_elasticsearch)
            rpt_elk = elk.req_post(full_url_elk, post_data,timeout=None)
            if 'error' in rpt_elk:
                print_json(rpt_elk)
            else:
                print('INFO  | took: {0:06d}| total:{1:06d}| updated {2:06d} | {3}'.format( rpt_elk['took'], rpt_elk['total'], rpt_elk['updated'], sede_servicio_red_cidr_mask))
            #input("press a key to continue . . .")
        else:
            print("ERROR  | field void {0}".format(data_json['cidr_mask']))
            print_json(data_json)


if __name__ == "__main__":    
    """
    - index_database_of_ips          - [field: "server_ip"]
    - index_data_to_add_by_cidr_mask - [field: "cidr_mask"]
    """
    elk = elasticsearch()
    index_name = "nessus-xml-*"
    full_url_elk =  "{0}/{1}/_update_by_query?slices=6".format( elk.get_url_elk() , index_name )
    full_path_file = ".\data\CLIENT\database_cidr_mask.csv"
    update_by_query(elk, full_url_elk, full_path_file)
    pass
