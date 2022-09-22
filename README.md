# OSSEM Detection Model (DM)

[![Open Source Love](https://badges.frapsoft.com/os/v3/open-source.svg?v=103)](https://github.com/ellerbrock/open-source-badges/)
![Open_Threat_Research Community](https://img.shields.io/badge/Open_Threat_Research-Community-brightgreen.svg)
[![Twitter](https://img.shields.io/twitter/follow/OSSEM_Project.svg?style=social&label=Follow)](https://twitter.com/OSSEM_Project)

This part of the project focuses on defining the required telemetry to gather security context of different behaviors that happen in a network environment. Network behaviors are described using data entities and the interaction or relationships among them. These relationships and its metadata may facilitate the creation of data analytics and validate detection of adversary techniques. We have also extended this concept to the [MITRE-ATT&CK](use-cases/mitre_attack) framework.

## Projects Using the OSSEM Detection Model

* [Threat Hunter Playbook](https://threathunterplaybook.com/hunts/windows/intro.html)

## Documentation Format and Schema

We document relationships metadata in YAML format **(.yml extension)** using the following schema:

### a) General **Metadata**

* Metadata that help to identify and describe the relationship

|Field|Mandatory|Data Type|Description|Example|
|---|---|---|---|---|
|relationship_id|Yes|String|ID that uniquely identifies a relationship. It considers three components: string REL + creation year + sequence number (4 digits) that is restarted every year.`This field is not required when contributing a relationship yaml file because it is added using a Python script.`|REL-2022-0175|
|name|Yes|String|Name of the relationship that describes the activity around data entities. Usually, entities' names have the first character of earch word capitalized.|Process created Process|
|contributors|Yes|List of Strings|People that helped with the creation or update of yaml files. Additional context can be provided such as Twitter handle.|Jose Rodriguez @Cyb3rPandaH|
|references|No|List of Strings|Any web link that could provide more context about the relationship and\or security events mapped to it.| https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688|
|notes|No|List of Strings|Any comment or note that could help to get a better understanding of the relationship YAML file and/or security events mapped to it.| For event 4688 - You must enable "Administrative Templates\System\Audit Process Creation\Include command line in process creation events" group policy to include command line in process creation events.|

### b) ATT&CK Data Sources Mapping (**attack**)

* Metadata that describes the mapping of relationships to Data Sources and Data Components from the [MITRE-ATT&CK](https://attack.mitre.org/datasources/) framework.
* This section of the YAML file is not mandatory, and it should be described using a Dictionary.

|Field|Mandatory|Data Type|Description|Example|
|---|---|---|---|---|
|data_source|No|String|ATT&CK data source|process|
|data_component|No|String|ATT&CK data component|process creation|

### c) Network Environment Behavior (**behavior**)

* Metadata that describes the interaction among entities. It considers three components: source entity, relationship, and target entity. Entities' names are aligned with the [OSSEM Common Data Model](https://github.com/OTRF/OSSEM-CDM/tree/master/schemas/entities) project.
* This sections of the YAML file is mandatory, and it should be described using a Dictionary.

|Field|Mandatory|Data Type|Description|Example|
|---|---|---|---|---|
|source|Yes|String|Usually the entity that performs the activity.|process|
|relationship|Yes|String|Action or activity performed or related to source entity|created|
|target|Yes|String|Usually the entity affected by the activity|process|

### d) Security Telemetry Mapping (**security_events**)

* Metadata that describes the mapping of security telemetry to relationships.
* This section of the YAML file is mandatory, and it should be described using a List of Dictionaries, where each dictionary represents a specific event log or source of data.
* Even though this section is mandatory, some of the fields within this section are not since they only apply for specific telemetry sources.
  * We use fields `audit_category`, `audit_sub_category`, and `channel` when mapping Microsoft Windows Security Auditing events.
  * We use field `audit_category` in Windows Sysmon events in order to populate the `Enable Commands` columns of the [ATT&CK CSV](use-cases/mitre_attack/attack_events_mapping.csv) file
  * We use field `filter_in` to provide additional context when an event log or telemetry source describes multiple objects or actions using the same schema. A good example of this is Windows Security Auditing event 4656, where the object context varies based on the ObjectType field (Process, Key, Service, etc).

|Field|Mandatory|Data Type|Description|Example|
|---|---|---|---|---|
|event_id|Yes|String|ID uniquely identifies and differentiate events from the same source.|'4688'|
|name|Yes|String|Name of the event. Is some cases, it might be similar to its ID.|A new process has been created.|
|platform|Yes|String|Operating system or application where the event can be collected.|Windows|
|audit_cateogry|No|String|Windows related field. It describes the audit policy subcategory an event belongs to.|Detailed Tracking|
|audit_sub_category|No|String|Windows related field. It describes the audit policy subcategory an event belongs to.|Process Creation|
|channel|No|String|Windows related field. It describes a group of events for a target audience. They belong to one of the four types: admin, operational, analytic, and debug.|Security|
|log_source|Yes|String|Describes the source that provides an event or we can collect the event from. In Windows environments, for [ETW-based](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing) events, this field represent the `Provider`.|Microsoft-Windows-Security-Auditing|
|filter_in|No|List of Dictionaries|For events that use the same schema and provide different security context based on the activity or the object they are describing. For example: `DeviceProcessEvents` from Microsoft Defender for Endpoint provides different context based on field `ActionType`. Another example would be event `4656` from Microsoft Windows Security Auditing because the context is different based on field `ObjectType`.|ActionType: ProcessCreated|
|event_version|No|List of Strings|This information help us when relating OSSEM-DM with OSSEM-DD. If event metadata contains a version, this means that there is an OSSEM dictionary available. `For now, this field is not required when contributing a relationship yaml file.`|'2'|

## Contribution Example

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
- event_id: '1'
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

## Available documents
|File|Description|
|---|---|
|[OSSEM Event Mappings in YAML](relationships/_all_ossem_relationships.yml)|Security event logs mapped to OSSEM relationships in `YAML` format. (Includes ATT&CK data sources metadata)||
|[OSSEM Event Mappings in JSON](relationships/_all_ossem_relationships.json)|Security event logs mapped to OSSEM relationships in `JSON` format. (Includes ATT&CK data sources metadata)||
|[ATT&CK Event Mappings in YAML](use-cases/mitre_attack/attack_relationships.yml)|Security event logs mapped to ATT&CK Data Sources Objects in `YAML` format.||
|[ATT&CK Event Mappings in CSV](use-cases/mitre_attack/attack_events_mapping.csv)|Security event logs mapped to ATT&CK Data Sources Objects in `CSV` format.||

## References

### Presentations:
* [Started from the Bottom: Exploiting Data Sources to Uncover ATT&CK Behaviors](https://youtu.be/eKeydMrXsOE)

### Related Projects:
* [OSSEM Data Dictionaries](https://github.com/OTRF/OSSEM-DD)
* [OSSEM Common Data Model](https://github.com/OTRF/OSSEM-CDM)

### ATT&CK:
* [ATT&CK Data Sources](https://attack.mitre.org/datasources/)
* [Defining ATT&CK Data Sources, Part I: Enhancing the Current State](https://medium.com/mitre-attack/defining-attack-data-sources-part-i-4c39e581454f)
* [Defining ATT&CK Data Sources, Part II: Operationalizing the Methodology](https://medium.com/mitre-attack/defining-attack-data-sources-part-ii-1fc98738ba5b)
* [Finding Cyber Threats with ATTCK Based Analytics](https://www.mitre.org/sites/default/files/publications/16-3713-finding-cyber-threats%20with%20att%26ck-based-analytics.pdf)
* [ATT&CK Data Sources GitHub repository - DEPRECATED](https://github.com/mitre-attack/attack-datasources)

### Other:
* [CAR Analytics](https://car.mitre.org/wiki/Main_Page)
* [CAR Analytics Data Model](https://car.mitre.org/wiki/Data_Model)
* [STIX Cybox ObjectRelationshipVOcab-1.1](http://stixproject.github.io/data-model/1.2/cyboxVocabs/ObjectRelationshipVocab-1.1/)
* [Cybox Object](http://cyboxproject.github.io/documentation/objects/)
* [STIX Version 2.0. Part 4 - Cyber Observable Object](https://docs.oasis-open.org/cti/stix/v2.0/stix-v2.0-part4-cyber-observable-objects.html)
* [Quantifying your hunt - not your parent's red teaming](http://www.irongeek.com/i.php?page=videos/bsidescharm2018/track-1-06-quantify-your-hunt-not-your-parents-red-teaming-devon-kerr)