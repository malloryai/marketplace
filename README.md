## Mallory Skills Agent

This repository contains the necessary files for adding `mallory-agent` as a skill to claude code. The mallory agent provides the latest threat intelligence information about threat actors, their ttps, exploits, vulnerabilities and malware. It uses the mallory api to obtain the necessary information. 

An API key is required for this skill. Visit `https://app.mallory.ai/api/keys` to obtain a key and place it in a .api_key file.


## Some example use cases below.

### Attack Surface Management 

* Correlate an organization to its top level domains
* Search for subdomains 
* Resolve subdomains to hosts, scope an analysis
* Analyze an application for exposures or vulneraibilities

### Exposure Management 

* Monitor a technology for recent component or library vulnerabilities
* Monitor the news for recent component or library vulnerabilities
* Search github repositories for affected instances of a given vulnerability 
* Search gitlab repositories for affected instances of a given vulnerability    

### Exploit Analysis
 
 * Obtain new samples from Mallory
 * Analyze exploit for efficacy and capability

### Malware Analysis
 
 * Obtain new samples from Virustotal
 * Analyze samples for maliciousness

### Detection Engineering 

* Monitor the news for new TTPs and IoC information
* Generate detection candidates in KQL / SQL / Sigma 
* Search SIEMs for identification of the behavior
