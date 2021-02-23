#!/usr/bin/env python

# Author: Roberto Rodriguez (@Cyb3rWard0g)
# License: GNU General Public License v3 (GPLv3)

import yaml
import glob
from os import path

# ******** Process Every ATT&CK Data Source YAML File ****************
print("[+] Opening yaml files..")
attack_ds_files = glob.glob(path.join(path.dirname(__file__), "..", "attack_event_mapping", "[!_]*.yml"))

for ds_file in attack_ds_files:
    yaml_file = yaml.safe_load(open(ds_file).read())
    print(f"[+] Processing {yaml_file['name']}..")
    for data_component in yaml_file['data_components']:
        for relationship in data_component['relationships']:
            print(f"    [*] Processing {relationship['name']}..")
            file_name = f"{(relationship['name']).replace(' ','_').lower()}.yml"
            rdict = dict()
            rdict['name'] = relationship['name']
            rdict['contributors'] = yaml_file['contributors']
            rdict['attack'] = dict()
            rdict['attack']['data_source'] = yaml_file['name']
            rdict['attack']['data_component'] = data_component['name']
            rdict['relationship'] = dict()
            rdict['relationship']['source'] = relationship['source_data_element']
            rdict['relationship']['link'] = relationship['relationship']
            rdict['relationship']['target'] = relationship['target_data_element']
            rdict['security_events'] = []
            for event in relationship['telemetry']:
                event_dict = dict()
                event_dict['name'] = event['event_name']
                event_dict['event_id'] = event['event_id']
                event_dict['platform'] = yaml_file['platforms'][0]
                if 'audit_category' in event.keys():
                    event_dict['audit_category'] = event['audit_category']
                if 'audit_sub_category' in event.keys():
                    event_dict['audit_sub_category'] = event['audit_sub_category']
                event_dict['log_channel'] = event['log_channel']
                event_dict['log_provider'] = event['log_provider']
                rdict['security_events'].append(event_dict)
            with open(f'../relationships/{file_name}', 'w') as file:
                yaml.dump(rdict, file, sort_keys=False, width=4096)
            