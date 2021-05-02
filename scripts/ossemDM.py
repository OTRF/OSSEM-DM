#!/usr/bin/env python

# Author: Jose Rodriguez (@Cyb3rPandaH)
# License: GNU General Public License v3 (GPLv3)

import yaml
import copy
import glob
from os import path
import json
from jinja2 import Template
from attackcti import attack_client
import pandas as pd
from pandas import json_normalize
pd.set_option("max_colwidth", None)
yaml.Dumper.ignore_aliases = lambda *args : True

# ******** Process Relationships yaml Files ****************

# Aggregating relationships yaml files (all relationships and ATT&CK)

print("[+] Opening relationships yaml files..")
relationships_files = glob.glob(path.join(path.dirname(__file__), "..", "relationships", "[!_]*.yml"))
all_relationships_files = []
attack_relationships_files = []

print("[+] Creating python lists (all relationships and ATT&CK) with yaml files content..")
for relationship_file in relationships_files:
    relationship_yaml = yaml.safe_load(open(relationship_file).read())
    all_relationships_files.append(relationship_yaml)
    if relationship_yaml['attack'] != None:
        attack_relationships_files.append(relationship_yaml)

print("[+] Creating aggregated yaml file with all relationships..")
with open(f'../relationships/_all_ossem_relationships.yml', 'w') as file:
    yaml.dump(all_relationships_files, file, sort_keys = False)

print("[+] Creating aggregated yaml file with relationships mapped to ATT&CK..")
with open(f'../use-cases/mitre_attack/attack_relationships.yml', 'w') as file:
    yaml.dump(attack_relationships_files, file, sort_keys = False)

# Creating ATT&CK data source event mappings cvs file
print(f"[+] Creating ATT&CK data source event mappings CSV file..")
import csv 

processed_dr = []

for dr in attack_relationships_files:
    for t in dr['security_events']:
        record = dict()
        record['Data Source'] = dr['attack']['data_source']
        record['Component'] = dr['attack']['data_component']
        record['Source'] = dr['behavior']['source']
        record['Relationship'] = dr['behavior']['relationship']
        record['Target'] = dr['behavior']['target']
        record['EventID'] = t['event_id']
        record['Event Name'] = t['name']
        record['Event Platform'] = t['platform']
        record['Log Provider'] = t['log_provider']
        record['Log Channel'] = t['log_channel']
        record['Audit Category'] = t.get('audit_category', None)
        record['Audit Sub-Category'] = t.get('audit_sub_category', None)
        if t['log_channel'] == "Security":
            record['Enable Commands'] = f"auditpol /set /subcategory:{t['audit_sub_category']} /success:enable /failure:enable"
        elif t['log_channel'] == "Microsoft-Windows-Sysmon/Operational":
            record['Enable Commands'] = f"<{t['audit_category']} onmatch='exclude' />"
        else:
            record['Enable Commands'] = None
        if t['log_channel'] == "Security":
            record['GPO Audit Policy'] = f"Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> {t['audit_category']} -> Audit {t['audit_sub_category']}"
        else:
            record['GPO Audit Policy'] = None
        processed_dr.append(record)

header_fields = ['Data Source', 'Component', 'Source', 'Relationship', 'Target', 'EventID', 'Event Name', 'Event Platform', 'Log Provider', 'Log Channel', 'Audit Category', 'Audit Sub-Category', 'Enable Commands',  'GPO Audit Policy' ]
with open('../use-cases/mitre_attack/attack_events_mapping.csv', 'w', newline='')  as output_file:
    dict_writer = csv.DictWriter(output_file, header_fields)
    dict_writer.writeheader()
    dict_writer.writerows(processed_dr)


# ******** Creating (Sub)Techniques to Security Events mapping yaml file ****************

# Getting ATT&CK - Enterprise Matrix
print("[+] Getting ATT&CK - Enterprise form TAXII Server..")

# Instantiating attack_client class
lift = attack_client()
# Getting techniques for windows platform - enterprise matrix
attck = lift.get_enterprise_techniques(stix_format = False)
# Removing revoked techniques
attck = lift.remove_revoked(attck)
# Creating Dataframe
attck = json_normalize(attck)
attck = attck[['technique_id','x_mitre_is_subtechnique','technique','tactic','platform','data_sources']]
attck = attck.explode('data_sources').reset_index(drop = True)
attck[['data_source','data_component']] = attck.data_sources.str.split(pat = ": ", expand = True)
attck = attck.drop(columns = ['data_sources'])
attck['data_source'] = attck['data_source'].str.lower()
attck['data_component'] = attck['data_component'].str.lower()

print("[+] Getting ATT&CK relationships events mapping..")
yamlFile = open('../use-cases/mitre_attack/attack_relationships.yml', 'r') # Accessing yaml file
dict = yaml.safe_load(yamlFile) # Loading names of data sources into a dictionary object
yamlFile.close() # Closing yaml file
attck_mapping = pd.DataFrame(dict)
attck_mapping = attck_mapping[['name','attack','behavior','security_events']]
attck_mapping = attck_mapping.explode('security_events').reset_index(drop = True)

print("[+] Merging ATT&CK framework & relationships events mapping..")
attack = attck_mapping['attack'].apply(pd.Series)
behavior = attck_mapping['behavior'].apply(pd.Series)
security_events = attck_mapping['security_events'].apply(pd.Series).rename(columns={'name':'event_name','platform':'event_platform'})
attck_mapping = pd.concat([attck_mapping,attack,behavior,security_events], axis = 1).drop(['attack','behavior','security_events'], axis = 1)
attck_mapping = attck_mapping.reindex(columns = ['data_source', 'data_component','name','source', 'relationship','target', 'event_id', 'event_name', 'event_platform', 'audit_category','audit_sub_category','log_channel', 'log_provider'])
attck_mapping['data_source'] = attck_mapping['data_source'].str.lower()
attck_mapping['data_component'] = attck_mapping['data_component'].str.lower()

technique_to_events = pd.merge(attck, attck_mapping, how = 'left', on = ['data_source','data_component'])
technique_to_events_dict = technique_to_events.reset_index().to_dict(orient = 'records')
for x in technique_to_events_dict:
    x.pop('index')

print("[+] Creating (Sub)Technqiues to Security Events mapping Yaml file..")
with open("../use-cases/mitre_attack/techniques_to_events_mapping.yaml", 'w') as yamlfile:
    data = yaml.dump(technique_to_events_dict, yamlfile,sort_keys = False, default_flow_style = False)