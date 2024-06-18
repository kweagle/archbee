---
title: "Endpoint Scan"
slug: "endpoint-scan"
hidden: false
createdAt: "2017-04-18T14:30:56.294Z"
updatedAt: "2020-05-07T15:20:43.833Z"
---
[block:callout]
{
  "type": "warning",
  "body": "Rapid7 recommends using the Insight Agent instead of the Endpoint Scan. The Insight Agent collects real-time data, is capable of more detections, and allows you to use [scheduled forensics](https://insightidr.help.rapid7.com/docs/scheduled-forensics). See the [Insight Agent](https://insightagent.help.rapid7.com/docs/overview) documentation for Insight Agent deployment instructions.
  
  Use of the Endpoint Scan is limited in a few ways:
  * You can edit existing IP ranges for the Endpoint Scan, but you can no longer add new ones. 
  * If you're a Managed Detection and Response (MDR) customer, you can't use the Endpoint Scan. Instead, you must install the Insight Agent on at least 80% of your endpoints to enable full-service monitoring (though, Rapid7 recommends installing the Insight Agent on every endpoint possible).
  * The Endpoint Scan is available for Windows assets only.
  ",
  "title": "Limitations of the Endpoint Scan"
}
[/block]

The Endpoint Scan, or Scan Mode, can run an agentless scan that gathers data from endpoints once an hour alongside the Collector. 

The Endpoint Scan collects the required data from assets that do not have the Insight Agent installed and immediately shuts down when the scan is complete. 
 
## Before you begin

Before you set up the Endpoint Scan, review the following sections:
* [Requirements](doc:endpoint-scan#requirements)
* [Bandwidth impact](doc:endpoint-scan#bandwidth-impact)

Then you can configure the [Endpoint Scan](doc:endpoint-scan#configure-the-endpoint-scan-and-endpoint-range).

### Requirements

Permission requirements include:
* The Endpoint Scan requires admin credentials. Prepare a [Service Account](doc:set-up-a-service-account) with admin credentials in order to authenticate to the target endpoints for data collection.
* A user profile must be created on the designated endpoint(s) for the account being used to run the endpoint scan. The user must log onto the designated endpoint before the Endpoint Scan process takes place.
* In order to deploy multiple Endpoint Scans of the same OS type across a network, you must configure a host Collector for each domain with its own credentials.

Networking requirements include: 
* The Endpoint Scan must be able to establish a WMI (Windows) with the endpoints.
* Endpoints must be able to initiate a connection back to the Collector on a port between 20,000–30,000.
* If you have a firewall or web proxy that restricts outgoing connections, you must grant permission for the Collector to connect to the backend servers. See [Firewall Rules](doc:firewall-rules) for specific information.

Review the [Network Requirements](doc:collector-requirements#networking-requirements) to make sure the Endpoint Scan functions properly on your network. Note that when scanning the defined IP ranges, the Endpoint Scan cannot see systems that leave the network.
[block:callout]
{
  "type": "info",
  "title": "Install the Insight Agent for critical servers and remote endpoints",
  "body": "For critical servers and endpoints belonging to remote employees, you should install the Insight Agent to enable real-time streaming of events and assets off of the network."
}
[/block]

### Bandwidth impact

Once you enter an IP address or IP address range, the Collector starts a scan within minutes. Because a typical Collector scan takes between 30–60 minutes, the Endpoint Scan scans an asset only once every hour or once every 2 hours for a class C (/24) subnet. 
 
For most environments, there is minimal or negligible bandwidth impact because the scanner enforces a 30-minute cool-down period between each scan. 
[block:parameters]
{
  "data": {
    "h-1": "Time between scans of each endpoint",
    "h-0": "IPs / CPU",
    "0-0": "1–16,000",
    "0-1": "1 hour for each scan",
    "1-0": "16,000–32,000",
    "1-1": "2.5 hours for each scan",
    "2-0": "32,000–64,000",
    "2-1": "5–8 hours for each scan"
  },
  "cols": 2,
  "rows": 3
}
[/block]
A single Collector can handle about 16,000 endpoints scanned for each CPU that it has available. You may split up the endpoint IP ranges over multiple Endpoint Scan scans. However, to avoid overlapping endpoint ranges, do not define an IP address or IP range on multiple Collectors.
[block:callout]
{
  "type": "danger",
  "body": "Be cautious with /8 and /16 subnets or you may configure the Endpoint Scan to scan too many assets."
}
[/block]

#### Low-bandwidth environments

For extremely low-bandwidth environments, the Endpoint Scan uses the following resources during a scan: 
  * Approximately 300KB for each asset for each scan to gather endpoint information
  * An additional 10MB transfer for each scan to transfer data to the Collector

## Configure the Endpoint Scan

When configuring the Endpoint Scan, you can edit only IP ranges that were previously specified. Adding new ranges is no longer supported.

**To edit IP ranges for the Endpoint Scan:**
1. From the InsightIDR navigation, select **Assets & Endpoints**. 
2. Click the **Endpoint Assets Scanned** metric. The Endpoint Scan page displays, showing IP ranges that were added previously.
3. Click the **Pencil** icon next to the IP range to edit. The Edit endpoint scan IP address range panel displays.
4. In the panel, edit the **IP range name** or **Credential**. (You can't edit the **IP range definition** or the **Collector name**.)
5. Click **Update range**. The panel closes and the IP range is updated in the table.

[block:callout]
{
  "type": "info",
  "body": "The Endpoint Scan range cannot be larger than CIDR /16, which is a maximum of 65,536 hosts. If possible, use the smallest range needed to cover your specific Endpoint Scan range. For individual assets, include /32 CIDR notation.",
  "title": "Ranges cannot be larger than CIDR /16"
}
[/block]

### Asset data collection

The Endpoint Scan collects the following data from your assets and endpoints:
  * Local user activity
  * Windows logon activity
  * Event log tampering
  * Process hash identification
  * Process commonality analysis
  * Process malware analysis
 
However, the Endpoint Scan does **not** collect the following data:
  * Forensic jobs
  * Real-time or continuous collection
  * Exploit mitigated
  * Honey file accessed
  * Local honey credential privilege escalation attempt
  * Protocol poisoning detected
  * Remote file execution detected
 
## Troubleshooting

If you experience issues when using the Endpoint Scan, review the following solutions:
* [Endpoints not returning logs during an Endpoint Scan](doc:endpoint-scan#endpoints-not-returning-logs-during-an-endpoint-scan)
* [Read Scan Log Results](doc:endpoint-scan#read-scan-log-results)
* [Error Codes](doc:endpoint-scan#error-codes)
* [Error 0x80041003](doc:endpoint-scan#error-0x80041003)

### Endpoints not returning logs during an Endpoint Scan

**If you do not see endpoints returning logs in their scans or from the Insight Agents, complete the following steps:**
1. Confirm that the expected ports are open and available. See [Network Requirements](doc:collector-requirements#networking-requirements) for specific information.
2. If you correctly configure the external firewall and web proxies, check a sample endpoint for agent log files in either of the following folders:
   * `C:\Windows\Temp\`
   * `C:\Users\IDR_service_account\AppData\Local\Temp\`
3. Find the Rapid7 folder and look for the following 3 files:
   * `agent.log`
   * `config.json`
   * `powershell.log`
4. Compress the files and send them to Rapid7 Support for review. 

### Read Endpoint Scan log results

At the end of each scan, the Endpoint Scan will report the results of the scan in the `collector.log`. 
 
If you experience issues with the Endpoint Scan, you can review the log for errors by using the following command:
```
2015-08-24 17:03:04.943 INFO win-endpoint-monitor-scheduled-scan-00 com.rapid7.domain.collector.endpointmonitor.AbstractEndpointMonitorDataSource:203 - bulk scan total statistics for all ranges: BulkAssetScanStatistics{totals=ScanStatistics{success=192, domainController=2, unavailable=70570, error=324, badCredential=13, timedOut=187, ipsScanned=71086}, totalScanTime=13435777}
2015-08-24 17:03:04.943 WARN win-endpoint-monitor-scheduled-scan-00 com.rapid7.domain.collector.endpointmonitor.AbstractEndpointMonitorDataSource:224 - Failed to scan 10.0.000.00 and 123 other asset(s): com.rapid7.net.wmi.exception.WMIException: Message not found for errorCode: 0x80041003
```

### Error codes

Use the following table to determine what an error means in your scan log:
[block:parameters]
{
  "data": {
    "h-0": "Error Code",
    "h-1": "Definition",
    "0-1": "There is no asset listening on the IP that was attempted. There may be a firewall blocking the connection, part of the network may be unreachable, or there are simply no assets running on that IP address.",
    "0-0": "`unavailable`",
    "1-1": "An error code was received from the endpoint during attempted communication.",
    "2-1": "There was an attempt to connect to the endpoint but the attempt was denied.",
    "3-1": "A connection was established but no response was received.",
    "1-0": "`error`",
    "2-0": "`badcredential`",
    "3-0": "`timedout`"
  },
  "cols": 2,
  "rows": 4
}
[/block]

#### Error messages on the Endpoint Scan page

Many errors on the Endpoint Scan page are due to network interruptions that self-resolve. However, take note of the following errors:
*  If you notice that an entire IP range is showing errors, there may be a networking issue.
*  If a particular endpoint consistently shows the same error, you may have misconfigured that device or it is otherwise inaccessible.

### Error 0x80041003

An endpoint returning `error 0x80041003` means that the endpoint does not allow remote WMI queries. 

**To fix this error:**
1. On the endpoint, either run `wmimgmt`, or go to **Administrative Tools > Computer Management**. The WMI Control Panel appears.
2. On the left panel, right click **WMI Control (Local) > Properties**.
3. Select the **Security** tab.
4. Expand the **Root** folder and select the **CIMV2** option.
5. Click **Security** to display the ROOT\CIMV2 security and add the credential you configured in the Endpoint Scan.
6. Be sure to grant the following permissions to the newly added credential:
   * Execute Methods
   * Enable Account
   * Remote Enable
