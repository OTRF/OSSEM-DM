#!/usr/bin/env python

# Author: Jose Rodriguez (@Cyb3rPandaH)
# License: GNU General Public License v3 (GPLv3)

from attackcti import attack_client
import pandas as pd
from pandas import json_normalize
pd.set_option("max_colwidth", None)
import json
import yaml


import copy
import glob
from os import path
import json
from jinja2 import Template

# ******** Process aat&ck yaml Files ****************

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
print(attck.head)

yamlFile = open('../docs/mitre_attack/attack_relationships.yml', 'r') # Accessing yaml file
dict = yaml.safe_load(yamlFile) # Loading names of data sources into a dictionary object
yamlFile.close() # Closing yaml file
attck_mapping = pd.DataFrame(dict)
attck_mapping = attck_mapping[['name','attack','behavior','security_events']]
attck_mapping = attck_mapping.explode('security_events').reset_index(drop = True)


attack = attck_mapping['attack'].apply(pd.Series)
behavior = attck_mapping['behavior'].apply(pd.Series)
security_events = attck_mapping['security_events'].apply(pd.Series).rename(columns={'name':'event_name','platform':'event_platform'})
attck_mapping = pd.concat([attck_mapping,attack,behavior,security_events], axis = 1).drop(['attack','behavior','security_events'], axis = 1)
attck_mapping = attck_mapping.reindex(columns = ['data_source', 'data_component','name','source', 'relationship','target', 'event_id', 'event_name', 'event_platform', 'audit_category','audit_sub_category','log_channel', 'log_provider'])
attck_mapping['data_source'] = attck_mapping['data_source'].str.lower()
attck_mapping['data_component'] = attck_mapping['data_component'].str.lower()

technique_to_events = pd.merge(attck, attck_mapping, how = 'left', on = ['data_source','data_component'],validate = 'm:m' )
technique_to_events_json = technique_to_events.reset_index().to_dict(orient = 'records')
print(technique_to_events_json[0])

#technique_to_events_json = json.loads(technique_to_events_json)
#print(technique_to_events_json)
with open("test.yaml", 'w') as yamlfile:
    data = yaml.dump(technique_to_events_json, yamlfile,sort_keys = False, default_flow_style = False)