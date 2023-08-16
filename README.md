# Prisma SD-WAN Zscaler Tag Update (Preview)
The purpose of this script is to update the Zscaler extended tag VPN ENDPOINT NAME

#### License
MIT

#### Requirements
* Active CloudGenix Account - Please generate your API token and add it to cloudgenix_settings.py
* Python >=3.7

#### Installation:
 Scripts directory. 
 - **Github:** Download files to a local directory, manually run the scripts. 
 - pip install -r requirements.txt

### Examples of usage:
 Please generate your API token and add it to cloudgenix_settings.py
 
 1. ./zscaler_tag_update.py -S "Branch-Site-1" -N "US-Zscaler"
      - Will update Branch-Site-1 Zsclaer extended tag VPN ENDPOINT NAME if it has have the AUTO-zscaler tag present
 2. ./zscaler_tag_update.py -S All -N "US-Zscaler"
      - Will update all sites Zsclaer extended tag VPN ENDPOINT NAME if they have the AUTO-zscaler tag present

### Caveats and known issues:
 - This is a PREVIEW release, hiccups to be expected. Please file issues on Github for any problems.

#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b1** | Initial Release. |


#### For more info
 * Get help and additional Prisma SD-WAN Documentation at <https://docs.paloaltonetworks.com/prisma/cloudgenix-sd-wan.html>
