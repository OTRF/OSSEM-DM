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

# CREATE CSV FILE
print(f"[+] Creating ATT&CK data source event mappings CSV file..")
import csv 

processed_ds = []

for ds in all_ds_files:
    for dc in ds['data_components']:
        for dr in dc['relationships']:
            for t in dr['telemetry']:
                record = dict()
                record['Data Source'] = ds['name']
                record['Component'] = dc['name']
                record['Source'] = dr['source_data_element']
                record['Relationship'] = dr['relationship']
                record['Target'] = dr['target_data_element']
                record['EventID'] = t['event_id']
                record['Event Name'] = t['event_name']
                record['Log Provider'] = t['log_provider']
                record['Log Channel'] = t['log_channel']
                record['Audit Category'] = t.get('audit_category', 'NA')
                record['Audit Sub-Category'] = t.get('audit_sub_category', 'NA')
                if t['log_channel'] == "Security":
                    record['Enable Commands'] = f"auditpol /set /subcategory:{t['audit_sub_category']} /success:enable /failure:enable"
                elif t['log_channel'] == "Microsoft-Windows-Sysmon/Operational":
                    record['Enable Commands'] = f"<{t['audit_category']} onmatch='exclude' />"
                else:
                    record['Enable Commands'] = 'NA'
                if t['log_channel'] == "Security":
                    record['GPO Audit Policy'] = f"Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> {t['audit_category']} -> Audit {t['audit_sub_category']}"
                else:
                    record['GPO Audit Policy'] = 'NA'
                processed_ds.append(record)

header_fields = ['Data Source', 'Component', 'Source', 'Relationship', 'Target', 'EventID', 'Event Name', 'Log Provider', 'Log Channel', 'Audit Category', 'Audit Sub-Category', 'Enable Commands',  'GPO Audit Policy' ]
with open('../docs/mitre_attack/security_events_mappings.csv', 'w', newline='')  as output_file:
    dict_writer = csv.DictWriter(output_file, header_fields)
    dict_writer.writeheader()
    dict_writer.writerows(processed_ds)