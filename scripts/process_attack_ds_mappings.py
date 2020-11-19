#!/usr/bin/env python

# Author: Jose Rodriguez (@Cyb3rPandaH)
# License: GNU General Public License v3 (GPLv3)

import yaml
import copy
import glob
from os import path
import json
from jinja2 import Template

# ******** Process Every ATT&CK Data Source YAML File ****************
print("[+] Opening yaml files..")
attack_ds_files = glob.glob(path.join(path.dirname(__file__), "..", "attack_event_mapping", "[!_]*.yml"))
all_ds_files = []
for ds_file in attack_ds_files:
    print(ds_file)
    all_ds_files.append(yaml.safe_load(open(ds_file).read()))
    
print(f"[+] Creating a master YAML file..")
with open(f'../attack_event_mapping/_all_attack_ds_mappings.yml', 'w') as file:
    yaml.dump(all_ds_files, file, sort_keys=False, width=4096)

# DATA SOURCES DEFINITIONS DOCS
print(f"[+] Creating ATT&CK data source definitions doc..")
data_sources_template = Template(open('templates/attack_ds_definitions.md').read())
data_sources_render = copy.deepcopy(all_ds_files)
data_sources_markdown = data_sources_template.render(data_sources=data_sources_render)
open('../docs/mitre_attack/data_sources.md', 'w').write(data_sources_markdown)

# DATA SOURCES EVENT MAPPINGS DOCS
print(f"[+] Creating ATT&CK data source event mappings doc..")
data_sources_event_mappings_template = Template(open('templates/attack_ds_event_mappings.md').read())
data_sources_event_mappings_render = copy.deepcopy(all_ds_files)
data_sources_event_mappings_markdown = data_sources_event_mappings_template.render(ds_event_mappings=data_sources_event_mappings_render)
open('../docs/mitre_attack/security_events_mappings.md', 'w').write(data_sources_event_mappings_markdown)

# Relationships 
print(f"[+] Creating Data Model Relationships doc..")
relationships = []
for ds in all_ds_files:
    for dc in ds['data_components']:
        for re in dc['relationships']:
            if re['source_data_element'] and re['relationship'] and re['target_data_element']:
                redict = dict()
                redict['source'] = re['source_data_element']
                redict['relationship'] = re['relationship']
                redict['target'] = re['target_data_element']
                if redict not in relationships:
                    relationships.append(redict)
    data_model_relationships_template = Template(open('templates/dm_relationships.md').read())
data_model_relationships_render = copy.deepcopy(relationships)
data_model_relationships_markdown = data_model_relationships_template.render(all_relationships=data_model_relationships_render)
open('../docs/data_model/relationships.md', 'w').write(data_model_relationships_markdown)