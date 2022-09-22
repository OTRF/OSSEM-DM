#!/usr/bin/env python

# Author: Jose Rodriguez (@Cyb3rPandaH)
# License: GNU General Public License v3 (GPLv3)

import yaml
import glob
import os
import json
from attackcti import attack_client
import pandas as pd
from pandas import NA, json_normalize
pd.set_option("max_colwidth", None)
yaml.Dumper.ignore_aliases = lambda *args : True
# To avoid taxi logs when downloading the framework
import logging
logging.getLogger('taxii2client').setLevel(logging.CRITICAL)
# To add uuid to relationships files
import re
from datetime import date

###### Variables #####
current_directory = os.path.dirname(__file__)
relationships_directory = os.path.join(current_directory, '../relationships')
usecases_directory = os.path.join(current_directory, '../use-cases')
all_relationships_file = os.path.join(relationships_directory, '_all_ossem_relationships.yml')
all_relationships_json_file = os.path.join(relationships_directory, '_all_ossem_relationships.json')
attack_relationships_file = os.path.join(usecases_directory, 'mitre_attack/attack_relationships.yml')
attack_events_mappings_file = os.path.join(usecases_directory, 'mitre_attack/attack_events_mapping.csv')
techniques_to_events_yaml = os.path.join(usecases_directory, 'mitre_attack/techniques_to_events_mapping.yaml')
techniques_to_events_json = os.path.join(usecases_directory, 'mitre_attack/techniques_to_events_mapping.json')
entities_directory = os.path.join(current_directory, "../../docs/cdm/entities")

# Aggregating relationships yaml files (all relationships and ATT&CK)

print("[+] Opening relationships yaml files..")
relationships_files = glob.glob(os.path.join(relationships_directory, "[!_]*.yml"))
all_relationships_files = []
attack_relationships_files = []

print("[+] Getting Current relationships IDs ..")
num_id = dict() # a dictionary with year as key and list of numbers as values
for relationship_file in relationships_files:
    file = open(relationship_file,'r+')
    first_line = file.readlines()[0].rstrip() # read first line
    file.close()
    if re.search("^relationship_id\:\sREL\-[\d]{4}\-\d{4}", first_line): # If file already has an ID
        search = re.search("^relationship_id\:\sREL\-([\d]{4})\-([\d]{4})$", first_line) # Grab it
        if search.group(1) not in num_id.keys(): # adding year as key of the dict
            num_id[search.group(1)] = []
        num_id[search.group(1)].append(int(search.group(2))) # adding number to corresponding key

print("[+] Adding ID to new relationships files ..")
current_date = date.today()
year = str(current_date.year)
for relationship_file in relationships_files:
    file = open(relationship_file,'r+')
    file_lines = file.readlines() # read current content

    if re.search("^relationship_id\:\sREL\-[\d]{4}\-\d{4}", file_lines[0].rstrip()): # If file already has an ID
        continue
    else:
        if year not in num_id.keys():
            to_write = 'relationship_id: REL-' + year + '-' + '0001' + '\n' # First relationship of the year
            num_id[year] = [1]
        else:
            number = max(num_id[year])+1
            to_write = 'relationship_id: REL-' + year + '-' + '0'*(4 - len(str(number))) + str(number) + '\n'
            num_id[year].append(number)
        
        file.seek(0) # Going to the beggining of the file
        file.write(to_write) # write the new text
        for line in file_lines:
            file.write(line)
        file.close()

print("[+] Creating python lists (all relationships and ATT&CK) with yaml files content..")
for relationship_file in relationships_files:
    relationship_yaml = yaml.safe_load(open(relationship_file).read())
    all_relationships_files.append(relationship_yaml)
    if relationship_yaml['attack'] != None:
        attack_relationships_files.append(relationship_yaml)

print("[+] Creating aggregated yaml file with all relationships..")
with open(all_relationships_file, 'w') as file:
    yaml.dump(all_relationships_files, file, sort_keys = False)

print("[+] Creating aggregated json file with all relationships..")
with open(all_relationships_json_file, 'w') as relationshipsjsonfile:
    data = json.dump(all_relationships_files, relationshipsjsonfile, indent=4)

print("[+] Creating aggregated yaml file with relationships mapped to ATT&CK..")
with open(attack_relationships_file, 'w') as file:
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
        record['OSSEM Id'] = dr['relationship_id']
        record['EventID'] = t['event_id']
        record['Event Name'] = t['name']
        record['Event Platform'] = t['platform']
        record['Log Source'] = t.get('log_source', None)
        record['Filter in Log'] = t.get('filter_in', None)
        record['Audit Category'] = t.get('audit_category', None)
        record['Audit Sub-Category'] = t.get('audit_sub_category', None)
        record['Channel'] = t.get('channel', None)
        if t['platform'] == "windows" and t.get('log_source', None) == "Microsoft-Windows-Security-Auditing":
            record['Enable Commands'] = f"auditpol /set /subcategory:{t['audit_sub_category']} /success:enable /failure:enable"
        elif t['platform'] == "windows" and t.get('log_source', None) == "Microsoft-Windows-Sysmon":
            record['Enable Commands'] = f"<{t['audit_category']} onmatch='exclude' />"
        else:
            record['Enable Commands'] = None
        if t.get('log_source', None) == "Microsoft-Windows-Security-Auditing":
            record['GPO Audit Policy'] = f"Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> {t['audit_category']} -> Audit {t['audit_sub_category']}"
        else:
            record['GPO Audit Policy'] = None
        processed_dr.append(record)

header_fields = ['Data Source', 'Component', 'Source', 'Relationship', 'Target', 'OSSEM Id', 'EventID', 'Event Name', 'Event Platform', 'Log Source', 'Filter in Log', 'Audit Category', 'Audit Sub-Category','Channel', 'Enable Commands',  'GPO Audit Policy' ]
with open(attack_events_mappings_file, 'w', newline='')  as output_file:
    dict_writer = csv.DictWriter(output_file, header_fields)
    dict_writer.writeheader()
    dict_writer.writerows(processed_dr)


# ******** Creating (Sub)Techniques to Security Events mapping yaml file ****************

# Getting ATT&CK - Enterprise Matrix
print("[+] Getting ATT&CK - Enterprise from TAXII Server..")

# Instantiating attack_client class
lift = attack_client()
# Getting techniques for windows platform - enterprise matrix
attck = lift.get_enterprise_techniques(stix_format = False, enrich_data_sources=True)
# Creating Dataframe
attck = json_normalize(attck)
attck = attck[['technique_id','is_subtechnique','technique','tactic','platform','data_sources']]
# Exploding List of data source objects
attck = attck.explode('data_sources').reset_index(drop = True)
data_source_component = attck['data_sources'].apply(pd.Series)[['name','data_components']].rename(columns={'name':'data_source','data_components':'data_component_data'})
attck = pd.concat([attck,data_source_component],axis=1).drop(columns=['data_sources'])
# Exploding List of data_components
attck = attck.explode('data_component_data').reset_index(drop = True)
component_data = attck['data_component_data'].apply(pd.Series)[['name']].rename(columns={'name':'data_component'})
attck = pd.concat([attck,component_data],axis=1).drop(columns=['data_component_data'])
# Data Sources and Data Components to lowercase --> to merge with mapping
attck['data_source'] = attck['data_source'].str.lower()
attck['data_component'] = attck['data_component'].str.lower()

print("[+] Getting ATT&CK relationships events mapping..")
yamlFile = open(attack_relationships_file, 'r') # Accessing yaml file
dict = yaml.safe_load(yamlFile) # Loading names of data sources into a dictionary object
yamlFile.close() # Closing yaml file
attck_mapping = pd.DataFrame(dict)
attck_mapping = attck_mapping[['relationship_id','name','attack','behavior','security_events']]
attck_mapping = attck_mapping.explode('security_events').reset_index(drop = True)

print("[+] Merging ATT&CK framework & relationships events mapping..")
attack = attck_mapping['attack'].apply(pd.Series)
behavior = attck_mapping['behavior'].apply(pd.Series)
security_events = attck_mapping['security_events'].apply(pd.Series).rename(columns={'name':'event_name','platform':'event_platform'})
attck_mapping = pd.concat([attck_mapping,attack,behavior,security_events], axis = 1).drop(['attack','behavior','security_events'], axis = 1)
attck_mapping = attck_mapping.reindex(columns = ['data_source', 'data_component','relationship_id','name','source', 'relationship','target', 'event_id', 'event_name', 'event_platform', 'audit_category','audit_sub_category','channel','log_source','filter_in'])
attck_mapping['data_source'] = attck_mapping['data_source'].str.lower()
attck_mapping['data_component'] = attck_mapping['data_component'].str.lower()

# Merging dataframes
technique_to_events = pd.merge(attck, attck_mapping, how = 'left', on = ['data_source','data_component']).dropna(axis=0,how='any',subset='name')
technique_to_events['Event_Platform_In_Technique'] = technique_to_events[['platform','event_platform']].apply(lambda x: 'yes' if x['event_platform'] in list((map(lambda m: m.lower(),x['platform']))) else 'no', axis=1)
technique_to_events = technique_to_events[technique_to_events['Event_Platform_In_Technique'] == 'yes']
technique_to_events_dict = technique_to_events.drop(columns=['Event_Platform_In_Technique']).reset_index().to_dict(orient = 'records')

# Removing index from dictionary
for x in technique_to_events_dict:
    x.pop('index')

print("[+] Creating (Sub)Technqiues to Security Events mapping Yaml file..")
with open(techniques_to_events_yaml, 'w') as yamlfile:
    data = yaml.dump(technique_to_events_dict, yamlfile,sort_keys = False, default_flow_style = False)

print("[+] Creating (Sub)Technqiues to Security Events mapping JSON file..")
with open(techniques_to_events_json, 'w') as jsonfile:
    data = json.dump(technique_to_events_dict, jsonfile, indent=4)