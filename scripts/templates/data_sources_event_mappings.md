# ATT&CK DS Event Mappings

|Data Source|Component|Source|Relationship|Target|Event Provider|EventID|
| :---| :---| :---| :---| :---| :---| :---|
{% for ds in ds_event_mappings|sort(attribute='name') %}{% for dc in ds['data_components'] %}{% for dr in dc['relationships'] %}{% for t in dr['telemetry']%}{% for e in t['event_id'] %}|{{ds['name']}}|{{dc['name']}}|{{dr['source_data_element']}}|{{dr['relationship']}}|{{dr['target_data_element']}}|{{t['event_provider']}}|{{e}}|
{% endfor %}{% endfor %}{% endfor %}{% endfor %}{% endfor %}