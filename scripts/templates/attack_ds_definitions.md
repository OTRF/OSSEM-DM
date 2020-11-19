# ATT&CK Data Sources

|Name|Definitions|
| :---| :---|
{% for d in data_sources|sort(attribute='name') %} |{{d['name']}}|{{d['definition']}}|
{% endfor %}