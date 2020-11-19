# Data Model Relationships

|Source|Relationship|Target|
| :---| :---| :---|
{% for re in all_relationships|sort(attribute='source') %}|{{re['source']}}|{{re['relationship']}}|{{re['target']}}|
{% endfor %}