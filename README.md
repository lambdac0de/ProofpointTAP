# ProofpointTAP

This is a simple PowerShell module wrapper for Proofpoint's TAP dashboard APIs. The official documentation of the Proofpoint TAP APIS is here:
https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation

### What is Proofpoint TAP?

Proofpoint Targeted Attack Protection (TAP) is Proofpoint's module that protects their customers from advanced persistent threats targetting specific people, mostly in an enterprise, delivered through emails. It's practically composed of attachment scanning, URL protection, threat intelligence feeds, and multiple sandbox and condemnation sources. 

Don't take my word for it! look at their datasheet here: 
https://www.proofpoint.com/sites/default/files/proofpoint_tap-datasheet-a4.pdf

#### IMPORTANT!

This is my own implementation of a PowerShell wrapper, to utilize the TAP APIs more efficiently by administrators. This code is not related to the vendor or the product in any way

#### Usage

1. Obtain your TAP credentials (service principal and secret) and paste them in `settings.json`<br><br>
   <i>Putting credentials in plain text is certianly a bad idea, so think of a crafty way encyrpting the credentials and modifying the  code to accomodate (consider using MSDPAPI/ securestrings) </i>
   
2. Place the whole directory in any of the PowerShell module paths `$env:PSModulePath`
3. Import the module and start using the API wrappers! `Import-Module ProofpointTAP`
