# OSSEM Relationships

|Source|Relationship|Target|
| :---| :---| :---|
|application|authenticated|user|
|application domain|started|None|
|application host|started|None|
|driver|loaded|None|
|firewall|started|None|
|firewall|stopped|None|
|host|permitted listener on|ip|
|host|permitted listener on|port|
|host|permitted listener on|process|
|host|permitted port bind on|ip|
|host|permitted port bind on|port|
|host|permitted port bind on|process|
|host|blocked connection from|ip|
|host|blocked connection from|port|
|host|blocked connection from|process|
|host|blocked connection to|ip|
|host|blocked connection to|port|
|host|blocked connection to|process|
|host|blocked listener on|ip|
|host|blocked listener on|port|
|host|blocked listener on|process|
|host|blocked port bind on|ip|
|host|blocked port bind on|port|
|host|blocked port bind on|process|
|logon session|modified|None|
|process|modified|windows registry key|
|process|modified|windows registry key value|
|process|removed|firewall rule|
|process|requested access to|ad object|
|process|requested access to|file|
|process|requested access to|process|
|process|requested access to|windows registry key|
|process|terminated|None|
|process|attempted to access|file|
|process|created|process|
|process|modified|firewall rule|
|process|created|thread|
|process|created|windows registry key|
|process|created|windows registry key value|
|process|deleted|file|
|process|deleted|windows registry key|
|process|deleted|windows registry key value|
|process|executed|command|
|process|executed|dns query|
|process|executed|Script|
|process|listened on|port|
|process|loaded|module|
|process|modified|file|
|process|modified|firewall|
|process|attempted to access|process|
|process|attempted to access|windows registry key|
|process|attempted to bind on|port|
|process|attempted to listen on|port|
|process|bound to|port|
|process|connected from|host|
|process|connected from|ip|
|process|connected from|port|
|process|connected to|host|
|process|connected to|ip|
|process|connected to|pipe|
|process|connected to|port|
|process|created|file|
|process|created|pipe|
|process|accessed|process|
|process|added|firewall rule|
|process|attempted connection from|ip|
|process|attempted connection from|port|
|process|attempted connection to|ip|
|process|attempted connection to|port|
|service|started|None|
|service|stopped|None|
|user|deleted|wmi object|
|user|disabled|schedule job|
|user|disabled|user|
|user|enabled|schedule job|
|user|enabled|user|
|user|executed|command|
|user|granted access to|user|
|user|listed|firewall rule|
|user|listed firewall rule from|ip|
|user|loaded|module|
|user|locked|user|
|user|modified|None|
|user|modified|ad object|
|user|modified|cloud service|
|user|modified cloud service from|ip|
|user|modified|file|
|user|modified|firewall|
|user|modified|firewall rule|
|user|modified firewall rule from|ip|
|user|modified|network share|
|user|modified|schedule job|
|user|modified|user|
|user|created logon session from|ip|
|user|created logon session from|port|
|user|created|network share|
|user|created|process|
|user|created|schedule job|
|user|created|service|
|user|created|user|
|user|created|windows registry key|
|user|created|windows registry key value|
|user|created|wmi object|
|user|deleted|ad object|
|user|deleted|file|
|user|deleted|network share|
|user|deleted|schedule job|
|user|deleted|user|
|user|attempted to access|process|
|user|attempted to access|windows registry key|
|user|attempted to authenticate from|ip|
|user|attempted to authenticate from|port|
|user|attempted to authenticate to|application|
|user|attempted to authenticate to|host|
|user|attempted to log off from|host|
|user|attempted to modify|user|
|user|authenticated from|ip|
|user|connected from|host|
|user|connected from|ip|
|user|connected from|port|
|user|connected to|host|
|user|connected to|ip|
|user|connected to|port|
|user|created|ad object|
|user|created|file|
|user|added|firewall rule|
|user|added firewall rule from|ip|
|user|attempted to access|ad object|
|user|attempted to access|file|
|user|retrieved information about firewall from|ip|
|user|retrieved information about|firewall rule|
|user|retrieved information about firewall rule from|ip|
|user|started|application host|
|user|started|cloud service|
|user|started cloud service from|ip|
|user|stopped|cloud service|
|user|stopped cloud service from|ip|
|user|terminated|logon session|
|user|terminated|process|
|user|unlocked|user|
|user|attempted to access|network share|
|user|created|logon session|
|user|deleted|windows registry key|
|user|modified|windows registry key|
|user|retrieved information about|firewall|
|user|modified|windows registry key value|
|user|removed access from|user|
|user|removed|firewall rule|
|user|removed firewall rule from|ip|
|user|requested access to|ad object|
|user|requested access to|file|
|user|requested access to|service|
|user|requested access to|windows registry key|
|user|restored|ad object|
|user|retrieved information about|cloud service|
|user|retrieved information about cloud service from|ip|
|wmi object|created|None|
