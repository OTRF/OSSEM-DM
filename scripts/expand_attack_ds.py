#!/usr/bin/env python

# Author: Jose Rodriguez (@Cyb3rPandaH)
# License: GNU General Public License v3 (GPLv3)

import yaml
import copy
from jinja2 import Template

yamlFile = yaml.safe_load(open('../attack_event_mapping/_attack_data_sources_all.yaml').read())

for yf in yamlFile:
    file_name = yf['name'].lower().replace(" ","_")

    print(f"[+] Writing YAML dump for {file_name}")
    with open(f'../attack_event_mapping/{file_name}.yml', 'w') as file:
        yaml.dump(yf, file, sort_keys=False)

# DATA SOURCES DEFINITIONS DOCS
data_sources_template = Template(open('templates/data_sources_definitions.md').read())
data_sources_render = copy.deepcopy(yamlFile)
data_sources_markdown = data_sources_template.render(data_sources=data_sources_render)
open('../docs/attack_ds_definitions.md', 'w').write(data_sources_markdown)

# DATA SOURCES DEFINITIONS DOCS
data_sources_event_mappings_template = Template(open('templates/data_sources_event_mappings.md').read())
data_sources_event_mappings_render = copy.deepcopy(yamlFile)
data_sources_event_mappings_markdown = data_sources_event_mappings_template.render(ds_event_mappings=data_sources_event_mappings_render)
open('../docs/attack_ds_event_mappings.md', 'w').write(data_sources_event_mappings_markdown)
