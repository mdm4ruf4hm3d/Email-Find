# Email-Find


Additionally, you can use some Open Source Intelligence (OSINT) tools to check email reputation and enrich the findings. Visit the given site below and do a reputation check on the sender address and the address found in the return path.


    Tool: https://emailrep.io/

Email reputation check


Here, if you find any suspicious URLs and IP addresses, consider using some OSINT tools for further investigation. While we will focus on using Virustotal and InQuest, having similar and alternative services in the analyst toolbox is worthwhile and advantageous.


Tool	Purpose
VirusTotal
	A service that provides a cloud-based detection toolset and sandbox environment.
InQuest
	A service provides network and file analysis by using threat analytics.
IPinfo.io
	A service that provides detailed information about an IP address by focusing on geolocation data and service provider.
Talos Reputation
	An IP reputation check service is provided by Cisco Talos.
Urlscan.io
	A service that analyses websites by simulating regular user behaviour.
Browserling
	A browser sandbox is used to test suspicious/malicious links.
Wannabrowser
	A browser sandbox is used to test suspicious/malicious links.

After completing the mentioned initial checks, you can continue with body and attachment analysis. Now, let's focus on analysing the email body and attachments. The sample doesn't have URLs, only an attachment. You need to compute the value of the file to conduct file-based reputation checks and further your analysis. As shown below, you can use the sha256sum tool/utility to calculate the file's hash value.
