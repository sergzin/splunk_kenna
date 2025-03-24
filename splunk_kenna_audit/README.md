Splunk modular input app for Cisco VA audit logs 
========================================

This app will download audit logs from Cisco Vulnerability Aggregator aka Kenna. 

### Description

Kenna offers API 
https://apidocs.kennasecurity.com/reference/audit-log-search
TODO: add more stuff here

### Packaging

* Install splunk packaging tool - `pip install splunk-packaging-toolkit`
* Generate app manifest - `slim generate-manifest -o splunk_kenna_audit/app.manifest splunk_kenna_audit`
* Package app - `slim package splunk_kenna_audit`

### inputs.conf 
by default this app should run only once per day