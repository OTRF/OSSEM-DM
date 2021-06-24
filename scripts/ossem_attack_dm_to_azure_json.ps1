

# Set current directory
[Environment]::CurrentDirectory=(Get-Location -PSProvider FileSystem).ProviderPath
# Set json file url
$uri = "https://raw.githubusercontent.com/OTRF/OSSEM-DM/main/use-cases/mitre_attack/techniques_to_events_mapping.json"
# Initialize web client
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$wc = new-object System.Net.WebClient
# Download json file
$wc.DownloadFile($uri, "techniques_to_events_mapping.json")

# Extract metadata from json file
$allMappings = @{}
foreach ($item in $mappings) {
    if ($item.log_channel -eq 'Security'){
        if (!($allMappings.contains($item.data_source))){
            $allMappings.$($item.data_source) = @{}
        }
        if (!($allMappings[$item.data_source].contains($item.data_component))){
            $allMappings[$item.data_source][$item.data_component] = @()
        }
        if (!($allMappings[$item.data_source][$item.data_component] | Where-Object {$_.EventID -eq "$($item.event_id)"})) {
            $eventObject = @{
                EventID = "$($item.event_id)"
                EventName = "$($item.event_name)"
            }
            if ($item.filter_in.ToString() -ne 'NaN'){
                $eventObject += @{Filters = $item.filter_in}
            }
            $allMappings[$item.data_source][$item.data_component] += $eventObject
        }
    }
}

# Create XML files for each ATT&CK data source
foreach ($ds in $allMappings.Keys){
    $fileName = -join (($ds -replace " ","-").ToLower(), '.xml')
    $StringWriter = New-Object System.IO.StringWriter
    $XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter
    $xmlWriter.Formatting = "indented"
    $xmlWriter.Indentation = 2
    $xmlWriter.IndentChar = ' '
    $xmlWriter.WriteStartDocument()
    $xmlWriter.WriteStartElement("QueryList")
    $xmlWriter.WriteComment("ATT&CK Data Source - $ds")

    $Counter = 0
    foreach ($dc in $allMappings[$ds].Keys) {
        # Create query element
        $xmlWriter.WriteStartElement("Query")
            $xmlWriter.WriteAttributeString("Id", "$Counter")
            $xmlWriter.WriteAttributeString("Path", "Security")
            $xmlWriter.WriteComment("ATT&CK Data Component - $dc")
            # Create query strings
            $query = ""
            $leftover = @()
            foreach ($event in $allMappings[$ds][$dc]){
                $xmlWriter.WriteComment("$($Event.EventID) - $($Event.EventName)")
                if ($Event.Filters){
                    $leftover += $Event
                }
                else {
                    $query = -join ($query, " EventID=$($Event.EventID) ")
                    if (!($allMappings[$ds][$dc][-1]['EventID'] -eq $($Event.EventID))){
                        $query = -join ($query, "or")
                    }
                }
            }
            if ($allMappings[$ds][$dc].Count -ne $leftover.Count){
                $query = $query.Trim()
                $query = -join ("*[System[(", $query, ")]]")
                if ($leftover.Count -ne 0){
                    $query = -join ($query, ' or ')
                }
            }
            # Process leftover
            if ($leftover){
                foreach ($l in $leftover){
                    $query = -join ($query, "(*[System[EventID=$($l.EventID)]] and (")
                    foreach ($f in $l.Filters) {
                        $key = $f | get-member -MemberType NoteProperty | select -expandproperty Name
                        $query = -join ($query, "(*[EventData[Data[@Name='$($key)']='$($f.$key)'")
                        if (!($l.Filters[-1] -eq $($f))){
                            $query = -join ($query, "]] or ")
                        }
                        else {
                            $query = -join ($query, "]])))")
                        }
                    }
                    if (!($leftover[-1] -eq $($l))){
                        $query = -join ($query, " or ")
                    }
                }
            }
            # Create Select (query) Element
            $xmlWriter.WriteStartElement("Select")
                $xmlWriter.WriteAttributeString("Path", "Security")
                $xmlWriter.WriteString("$query")
            $xmlWriter.WriteEndElement() | out-null
        $xmlWriter.WriteEndElement() | out-null
        $counter += 1
    }
    # Write Close Tag for QueryList Element
    $xmlWriter.WriteEndDocument() | out-null
    # Finish The Document
    $xmlWriter.Flush() | out-null
    $StringWriter.Flush() | out-null
    #Create File
    $StringWriter.ToString() | out-file $fileName
    $xmlWriter.Close()
}
# Creating json file with OSSEM Detection Relationship for Azure Sentinel To-Go
$allFiles = Get-ChildItem -Path *.xml

$AllDataSources = @()
$DataSource = [ordered]@{}
# Name of Data Source
$DataSource['Name'] = "eventLogsDataSource"
# Transfer Period
$DataSource['scheduledTransferPeriod'] = "PT1M"
# Streams
$DataSource['streams'] = @(
    "Microsoft-SecurityEvent"
)
# Process XPath Queries
$DataSource['xPathQueries'] = @()
foreach ($file in $allFiles){
    [xml]$XmlQuery = Get-Content -path $file
    $queries = $xmlQuery.QueryList.Query
    ForEach ($query in $queries){
        $QueryString = "$(-join ($query.Select.Path, '!', $query.Select.'#text'))"
        if ("$QueryString" -notin $DataSource['xPathQueries']){
            $DataSource['xPathQueries'] += $QueryString
        } 
    }
}
$AllDataSources += $DataSource

@{
    windowsEventLogs = $AllDataSources
} | Convertto-Json -Depth 4 | Set-Content "ossem-attack.json" -Encoding UTF8
