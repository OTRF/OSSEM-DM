# OSSEM Detection Model (DM)

[![Open Source Love](https://badges.frapsoft.com/os/v3/open-source.svg?v=103)](https://github.com/ellerbrock/open-source-badges/)
![Open_Threat_Research Community](https://img.shields.io/badge/Open_Threat_Research-Community-brightgreen.svg)
[![Twitter](https://img.shields.io/twitter/follow/OSSEM_Project.svg?style=social&label=Follow)](https://twitter.com/OSSEM_Project)

This part of the project focuses on defining the required data in form of data objects and the relationships among each other needed to facilitate the creation of data analytics and validate detection of adversary techniques. We have also extended this concept to the MITRE-ATT&CK framework [here](use-cases/mitre_attack).

## Available documents
|File|Description|
|---|---|
|[OSSEM Event Mappings (YAML file)](relationships/_all_ossem_relationships.yml)|Security event logs mapped to OSSEM relationships (Includes ATT&CK data sources metadata)||
|[ATT&CK Event Mappings (MD file)](https://github.com/OTRF/OSSEM/tree/master/docs/dm/mitre_attack/attack_ds_events_mappings.md)|Security event logs mapped to ATT&CK Data Sources Objects||
|[ATT&CK Event Mappings (YAML file)](use-cases/mitre_attack/attack_relationships.yml)|Security event logs mapped to ATT&CK Data Sources Objects||
|[ATT&CK Event Mappings (CVS file)](use-cases/mitre_attack/attack_events_mapping.csv)|Security event logs mapped to ATT&CK Data Sources Objects||

## Documentation Format and Schema

We document relationships in YAML format **(.yml extension)** using the following schema:

|Component|Mandatory|Data Type|Description|Example|
|---|---|---|---|---|
|**relationship_id**|Yes|String|ID that uniquely identifies a relationship. It considers three components: string REL + creation year + sequence number (4 digits) that is restarted every year.`This field is not required when contributing a relationship yaml file because it is added using a Python script.`|REL-2022-0175|
|**name**|Yes|String|Name of the relationship that describes the activity around data entities.|Process created Process|
|**contributors**|Yes|List of Strings|People that helped with the creation or update of yaml files. Additional context can be provided such as Twitter handle.|Jose Rodriguez @Cyb3rPandaH|
|**attack**|No|Dictionary|Mapping to Data Sources and Components from the ATT&CK framework||
|data_source|No|String|ATT&CK data source|process|
|data_component|No|String|ATT&CK data component|process creation|
|**behavior**|Yes|Dictionary|Describes the interaction between entities. It considers three components: source entity, relationship, and target entity.||
|source|Yes|String|Usually the entity that performs the activity.|process|
|relationship|Yes|String|Action or activity performed or related to source entity|created|
|target|Yes|String|Usually the entity affected by the activity|process|
|**security_events**|Yes|List of Dictionaries|Telemetry that provides context of the relationship.||
|event_id|Yes|String|ID uniquely identifies and differentiate events from the same source.|'4688'|
|name|Yes|String|Name of the event. Is some cases, it might be similar to its ID.|A new process has been created.|
|platform|Yes|String|Operating system or application where the event can be collected.|Windows|
|audit_cateogry|No|String|Windows related field. It describes the audit policy subcategory an event belongs to.|Detailed Tracking|
|audit_sub_category|No|String|Windows related field. It describes the audit policy subcategory an event belongs to.|Process Creation|
|channel|No|String|Windows related field. It describes a group of events.|Security|
|log_source|Yes|String|Describes the source that provides an event or we can collect the event from.|Microsoft-Windows-Security-Auditing|
|filter_in|No|List of Dictionaries|For events that use the same schema and provide different security context based on the activity or the object they are describing. For example: `DeviceProcessEvents` from Microsoft Defender for Endpoint provides different context based on field `ActionType`. Another example would be event `4656` from Microsoft Windows Security Auditing because the context is different based on field `ObjectType`.|ActionType: ProcessCreated|
|event_version|No|List of Strings|This information help us when relating OSSEM-DM with OSSEM-DD. If event metadata contains a version, this means that there is an OSSEM dictionary available. `For now, this field is not required when contributing a relationship yaml file.`|'2'|
|**references**|No|List of Strings|Any web link that could provide more context about the relationship and\or security events mapped to it.| https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688|
|**notes**|No|List of Strings|Any comment or note that could help to get a better understanding of the relationship YAML file.| For event 4688 - You must enable "Administrative Templates\System\Audit Process Creation\Include command line in process creation events" group policy to include command line in process creation events.|


Here is YAML example that you can use as a reference when contributing relationships:
```yaml
name: Process created Process
contributors:
- Jose Rodriguez @Cyb3rPandaH
attack:
  data_source: process
  data_component: process creation
behavior:
  source: process
  relationship: created
  target: process
security_events:
- event_id: '4688'
  name: A new process has been created.
  platform: windows
  audit_category: Detailed Tracking
  audit_sub_category: Process Creation
  channel: Security
  log_source: Microsoft-Windows-Security-Auditing
  event_version:
  - '2'
- event_id: DeviceProcessEvents
  name: DeviceProcessEvents
  platform: windows
  log_source: Microsoft Defender for Endpoint
  filter_in:
  - ActionType: ProcessCreated
  event_version:
  - '1'
- event_id: 1
  name: Process Creation.
  platform: windows
  audit_category: ProcessCreate
  channel: Microsoft-Windows-Sysmon/Operational
  log_source: Microsoft-Windows-Sysmon
  event_version:
  - '4.32'
references:
- https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-1-process-creation
notes:
- For event 4688 - You must enable "Administrative Templates\System\Audit Process Creation\Include command line in process creation events" group policy to include command line in process creation events.
```



## References
* [Defining ATT&CK Data Sources, Part I: Enhancing the Current State](https://medium.com/mitre-attack/defining-attack-data-sources-part-i-4c39e581454f)
* [Defining ATT&CK Data Sources, Part II: Operationalizing the Methodology](https://medium.com/mitre-attack/defining-attack-data-sources-part-ii-1fc98738ba5b)
* [ATT&CK Data Sources GitHub repository](https://github.com/mitre-attack/attack-datasources)
* [CAR Analytics](https://car.mitre.org/wiki/Main_Page)
* [Common Information Model](https://github.com/Cyb3rWard0g/OSSEM/blob/master/common_information_model)
* [STIX Cybox ObjectRelationshipVOcab-1.1](http://stixproject.github.io/data-model/1.2/cyboxVocabs/ObjectRelationshipVocab-1.1/)
* [Cybox Object](http://cyboxproject.github.io/documentation/objects/)
* [STIX Version 2.0. Part 4 - Cyber Observable Object](https://docs.oasis-open.org/cti/stix/v2.0/stix-v2.0-part4-cyber-observable-objects.html)
* [Finding Cyber Threats with ATTCK Based Analytics](https://www.mitre.org/sites/default/files/publications/16-3713-finding-cyber-threats%20with%20att%26ck-based-analytics.pdf)
* [CAR Analytics Data Model](https://car.mitre.org/wiki/Data_Model)
* [Quantifying your hunt - not your parent's red teaming](http://www.irongeek.com/i.php?page=videos/bsidescharm2018/track-1-06-quantify-your-hunt-not-your-parents-red-teaming-devon-kerr)