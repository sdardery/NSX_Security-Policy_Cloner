NSX Security policy cloner Read ME
Important points :
-This is ideal for Brownfield to Greenfield
-For Brownfield to Brownfield, please note that once a policy is cloned it will overwrite an existing policy in the destination if exists. This script also creates any dependent security groups so it will also overwrite the security group in the destination.
-place ps1 file and policies.txt in same folder

1- Export DFW configuration
2- Open Export CSV file and take the security policy paths of those policies you want to clone and paste them in policies.txt
3- run the ps1 script from powershell 
4- The script will only ask you to place source NSX fqdn/ip-username-password and destination NSX fqdn/ip-username-password
5- Once script is complete , confirm results in dest nsx ui.
