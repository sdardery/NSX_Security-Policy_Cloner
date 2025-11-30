NSX Security policy cloner Readme

Important points :

1- This is ideal for Brownfield to Greenfield

2- For Brownfield to Brownfield, please note that once a policy is cloned it will overwrite an existing policy in the destination if the path(name) exists. This script also creates any dependent Security Rules, Custom Security Groups & Custom Services so it will also overwrite them in the destination.

3- the PS1 file and  policies.txt should be in same folder

Steps :

1- Export DFW configuration (https://techdocs.broadcom.com/us/en/vmware-cis/nsx/nsxt-dc/3-2/administration-guide/security/distributed-firewall/export-or-import-a-firewall-configuration.html Steps 1-5)

2- Open Export CSV file and take the security policy paths of those policies you want to clone and paste them in policies.txt (Ive included examples in the txt file).

3- Run the PS1 script from powershell (Make sure the file is unblocked once downloaded from github : right click on the ps1 file and go to properties and tick on unblock that appears in the General tab)

4- The script will  ask you to authenticate both source and Destination NSX.

5- Once script is complete , confirm results in dest NSX UI.


UPDATE 1.6 :

1- Added support for infinite nested services.

2- Added support for creation of group members existing in "applied to" field.

3- Verbosed version for clearer debugging.

Update 2.0 : 

1- Added infinite Nested Groups


