# Nessus2Elasticsearch

This program read a file with extension "*.nessus" and parse to json format for load to elasticsearch index.

Example data_json:
```
{
        "_index" : "nessus-analytics",
        "_type" : "_doc",
        "_id" : "8V_OMHABE8Flxjz2MpmB",
        "_score" : 1.0,
        "_source" : {
          "host_ip" : "192.168.1.2",
          "mac-address" : "None",
          "vulnerability" : "10736-DCE Services Enumeration-0",
          "system-type" : "None",
          "host_fqdn" : "dominio.com.pe",
          "operating-system" : "None",
          "scantime" : "2020-02-04 09:36:28",
          "netbios-name" : "None",
          "host_name" : "192.168.1.2",
          "os" : "other",
          "vulninfo" : {
            "port" : "135",
            "pluginID" : "10736",
            "protocol" : "tcp",
            "os_identification" : "True",
            "risk_factor" : "None",
            "pluginName" : "DCE Services Enumeration",
            "plugin_modification_date" : "2020/01/22",
            "asset_inventory" : "True",
            "plugin_publication_date" : "2001/08/26",
            "severity" : "0",
            "plugin_name" : "DCE Services Enumeration",
            "pluginFamily" : "Windows",
            "solution" : "n/a",
            "synopsis" : "A DCE/RPC service is running on the remote host.",
            "fname" : "dcetest.nasl",
            "plugin_type" : "combined",
            "description" : "By sending a Lookup request to the portmapper (TCP 135 or epmapper PIPE) it was possible to enumerate the Distributed Computing Environment (DCE) services running on the remote port. Using this information it is possible to connect and bind to each service by sending an RPC request to the remote port/pipe.",
            "script_version" : "1.55",
            "svc_name" : "epmap"
          },
          "source_file" : "nessus_file.nessus"
        }
      }
     
```

If want load in another index just change the next line code:

```
#Sending Bucket to Elasticsearch
rpt = elk.post_bulk(bucket_documents,header_json={"index":{"_index":"nessus-analytics","_type":"_doc"}})
```

### For errors of parsing

For a specific type of encoding add <encoding="utf-8"> to parser.py from NessusParser library.

```
#Path: C:/Python34/Lib/site-packages/libnessus/parser.py
    ...
    @classmethod
    def parse_fromfile(cls, nessus_report_path, data_type="XML", strict=False):
        try:
            with open(nessus_report_path, 'r', encoding="utf-8") as fileobj:
                fdata = fileobj.read()
                rval = cls.parse(fdata, data_type, strict)
        except IOError:
            raise
        return rval
   ...     
```
### Estructure of Nessus file
```
NessusClientData_v2
  - Policy
      - FamilySelection
        - FamilyItem
        [
          - FamilyName
          - Status
        ]
      - IndividualPluginSelection
        - PluginItem
        [
          - Family
          - PluginId
          - PluginName
          - Status
        ]
      - Preferences
        - PluginsPreferences
          - item
          [
            - fullName
            - pluginId
            - pluginName
            - preferenceName
            - preferenceType
            - preferenceValues
            - selectedValue
          ]
        - ServerPreferences
          - preference
          [
            - name
            - value
          ]
          policyName
  - Report
      - @name
      - @xmls:cm
      - ReportHost 
        [
          - @name
          - HostProperties
            - tags
            [
              - #text
              - @name
            ]
          - ReportItem
          [
            - @pluginID
            - @pluginName
            - @port
            - @protocol
            - @severity
            - @svc_name
            - agent
            - always_run
            - description
            - fname
            - plugin_modification_date
            - plugin_name
            - plugin_output
            - plugin_publication_date
            - plugin_type
            - risk_factor
            - script_version
            - solution
            - synopsis  
          ]
        ]
```
### Additional libraries 

+ utils, credentials, elastic
  + From Repository: https://github.com/hoat23/ElasticSearch/tree/master/bin.
+ NessusParser
  + From Repository: https://github.com/bmx0r/python-libnessus.

