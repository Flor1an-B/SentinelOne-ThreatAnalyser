"""End-to-end test with mock data — no API connection needed."""
import sys, os, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from s1_analyser.data_collector import AnalysisBundle
from s1_analyser.analyzer import ThreatAnalyzer
from s1_analyser.process_tree import ProcessTreeBuilder, render_ascii_tree
from s1_analyser.reporters.csv_reporter import CSVReporter
from s1_analyser.reporters.markdown_reporter import MarkdownReporter
from s1_analyser.reporters.html_reporter import HTMLReporter

STORYLINE = "ABC123-MOCK-STORYLINE"

mock_events = [
    {
        "id": "e1", "createdAt": "2024-03-15T10:00:00.000Z",
        "objectType": "process", "eventType": "PROCESSCREATION",
        "processName": "explorer.exe", "pid": "5000", "parentPid": "1000",
        "processUniqueKey": "KEY-explorer", "parentProcessUniqueKey": "KEY-system",
        "processCmd": "C:\\Windows\\explorer.exe",
        "processUserName": "DESKTOP-ABC\\John",
        "processIntegrityLevel": "Medium",
        "relatedToThreat": False, "processIsMalicious": False,
    },
    {
        "id": "e2", "createdAt": "2024-03-15T10:01:00.000Z",
        "objectType": "process", "eventType": "PROCESSCREATION",
        "processName": "cmd.exe", "pid": "7777", "parentPid": "5000",
        "processUniqueKey": "KEY-cmd", "parentProcessUniqueKey": "KEY-explorer",
        "processCmd": "cmd.exe /c powershell -enc BASE64PAYLOADHERE",
        "processUserName": "DESKTOP-ABC\\John",
        "processIntegrityLevel": "High",
        "relatedToThreat": True, "processIsMalicious": True,
    },
    {
        "id": "e3", "createdAt": "2024-03-15T10:01:30.000Z",
        "objectType": "file", "eventType": "FILECREATION",
        "processName": "cmd.exe", "pid": "7777",
        "processUniqueKey": "KEY-cmd", "parentProcessUniqueKey": "KEY-explorer",
        "fileFullName": "C:\\Users\\John\\AppData\\Local\\Temp\\dropper.exe",
        "fileSha1": "aabbccdd1234567890aabbccdd1234567890aabb",
        "fileSize": 245760,
        "relatedToThreat": True, "processIsMalicious": True,
    },
    {
        "id": "e4", "createdAt": "2024-03-15T10:01:45.000Z",
        "objectType": "registry", "eventType": "REGISTRYCREATION",
        "processName": "cmd.exe",
        "processUniqueKey": "KEY-cmd",
        "registryPath": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware",
        "relatedToThreat": True,
    },
    {
        "id": "e5", "createdAt": "2024-03-15T10:02:00.000Z",
        "objectType": "ip", "eventType": "NETWORKCONNECTION",
        "processName": "dropper.exe", "pid": "9999",
        "processUniqueKey": "KEY-dropper", "parentProcessUniqueKey": "KEY-cmd",
        "dstIp": "185.234.219.47", "dstPort": 443, "protocol": "TCP",
        "relatedToThreat": True,
    },
    {
        "id": "e6", "createdAt": "2024-03-15T10:02:05.000Z",
        "objectType": "dns", "eventType": "DNSLOOKUP",
        "processName": "dropper.exe",
        "processUniqueKey": "KEY-dropper", "parentProcessUniqueKey": "KEY-cmd",
        "dnsRequest": "evil-c2-server.onion.to",
        "dnsResponse": "185.234.219.47",
        "relatedToThreat": True,
    },
    {
        "id": "e7", "createdAt": "2024-03-15T10:03:00.000Z",
        "objectType": "file", "eventType": "FILERENAME",
        "processName": "dropper.exe",
        "processUniqueKey": "KEY-dropper", "parentProcessUniqueKey": "KEY-cmd",
        "fileFullName": "C:\\Users\\John\\Documents\\report.docx.locked",
        "oldFileName": "C:\\Users\\John\\Documents\\report.docx",
        "relatedToThreat": False,
    },
    {
        "id": "e8", "createdAt": "2024-03-15T10:01:15.000Z",
        "objectType": "login", "eventType": "LOGINSUCCESS",
        "processName": "cmd.exe",
        "processUniqueKey": "KEY-cmd",
        "loginsUserName": "DESKTOP-ABC\\Administrator",
        "loginsBaseType": "INTERACTIVE",
    },
    {
        "id": "e9", "createdAt": "2024-03-15T10:02:30.000Z",
        "objectType": "scheduled_task", "eventType": "TASKSCHEDULED",
        "processName": "schtasks.exe",
        "processUniqueKey": "KEY-schtask", "parentProcessUniqueKey": "KEY-cmd",
        "taskName": "MaliciousPersistence",
        "taskPath": "C:\\Windows\\Temp\\update.bat",
    },
]

mock_threat = {
    "id": "threat-id-12345",
    "threatInfo": {
        "threatName": "Ransom.MockMalware.A",
        "storyline": STORYLINE,
        "sha1": "aabbccdd1234567890aabbccdd1234567890aabb",
        "filePath": "C:\\Users\\John\\AppData\\Local\\Temp\\dropper.exe",
        "classification": "Malware",
        "confidenceLevel": "malicious",
        "detectionType": "static",
        "incidentStatus": "unresolved",
        "mitigationStatus": "not_mitigated",
        "initiatingUsername": "DESKTOP-ABC\\John",
        "identifiedAt": "2024-03-15T10:01:00.000Z",
        "createdAt": "2024-03-15T10:01:00.000Z",
        "updatedAt": "2024-03-15T10:05:00.000Z",
        "detectionEngines": [{"key": "reputation"}, {"key": "behavioral"}],
    },
    "agentDetectionInfo": {
        "agentOsName": "Windows 10 Pro",
        "agentVersion": "23.3.2.2",
        "agentIpV4": "192.168.1.100",
        "agentDomain": "WORKGROUP",
        "agentLastLoggedInUserName": "John",
        "siteName": "Default Site",
        "accountName": "Company Inc.",
    },
    "agentRealtimeInfo": {
        "agentComputerName": "DESKTOP-ABC",
        "agentMachineType": "desktop",
        "agentNetworkStatus": "connected",
        "agentIsActive": True,
        "agentIsDecommissioned": False,
    },
    "indicators": [
        {
            "category": "Ransomware",
            "description": "Process creates encrypted files",
            "ids": [1001],
            "tactics": [{
                "name": "Impact",
                "source": "MITRE",
                "techniques": [{"name": "T1486 - Data Encrypted for Impact",
                                "link": "https://attack.mitre.org/techniques/T1486"}],
            }],
        },
        {
            "category": "Persistence",
            "description": "Registry run key modification",
            "ids": [1002],
            "tactics": [{
                "name": "Persistence",
                "source": "MITRE",
                "techniques": [{"name": "T1547.001 - Registry Run Keys",
                                "link": "https://attack.mitre.org/techniques/T1547/001"}],
            }],
        },
    ],
}

bundle = AnalysisBundle(storyline_id=STORYLINE)
bundle.threat = mock_threat
bundle.events = mock_events

result = ThreatAnalyzer().analyze(bundle)
print("Analysis complete:")
print(f"  Total events:       {result.total_events}")
print(f"  Detection triggers: {len(result.detection_triggers)}")
print(f"  MITRE techniques:   {len(result.mitre_techniques)}")
print(f"  Encryption indic.:  {len(result.encryption_indicators)}")
print(f"  Network IOCs:       {len(result.network_iocs)}")
print(f"  File IOCs:          {len(result.file_iocs)}")
print(f"  Susp. registry:     {len(result.suspicious_registry)}")

roots = ProcessTreeBuilder().build(mock_events)
print(f"\nProcess tree ({len(roots)} root(s)):")
for line in render_ascii_tree(roots):
    print(line)

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_output")
os.makedirs(out, exist_ok=True)

csv_path = CSVReporter().write(result, out)
print(f"\nCSV:  {os.path.basename(csv_path)} ({os.path.getsize(csv_path):,} bytes)")

md_path = MarkdownReporter().write(result, out)
print(f"MD:   {os.path.basename(md_path)} ({os.path.getsize(md_path):,} bytes)")

html_path = HTMLReporter().write(result, out)
print(f"HTML: {os.path.basename(html_path)} ({os.path.getsize(html_path):,} bytes)")

print("\nAll tests PASSED!")
print(f"Reports written to: {out}")
