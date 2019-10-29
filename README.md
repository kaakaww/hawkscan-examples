# Hawkscan Examples

This repo contains example stackhawk.yml configuration files for [HawkScan](https://hub.docker.com/r/stackhawk/hawkscan/)
 by [StackHawk](https://www.stackhawk.com/). For more information read the [documentation](https://docs.stackhawk.com/).
 
 
## Authentication

Most modern web applications require some kind of authentication to access the 
routes of the application. Below is a list of example configurations demonstrating
the different combinations of authentication and authorization supported by StackHawk.
Each file contains inline comments on the various settings.


|Credential Type|HTTP Content-Type|Authorization Type|Example Config|
|-----------------|:---------------:|------------------|--------------|
|Username/Password|`application/x-www-form-urlencoded`|Cookie|[stackhawk-auth-form-cookie.yml](configs/authentication/stackhawk-auth-form-cookie.yml)|
|Username/Password|`application/x-www-form-urlencoded`|Bearer Token|[stackhawk-auth-form-token.yml](configs/authentication/stackhawk-auth-form-token.yml)|
|Username/Password|`application/json`|Bearer Token|[stackhawk-auth-json-token.yml](configs/authentication/stackhawk-auth-json-token.yml)|
|Username/Password|`application/json`|Custom Token|[stackhawk-auth-json-token-custom1.yml](configs/authentication/stackhawk-auth-json-token-custom1.yml)|
|External|N/A|Query Param|[stackhawk-auth-external-token.yml](configs/authentication/stackhawk-auth-external-token.yml)|
|External|N/A|Bearer Token|[stackhawk-auth-external-token.yml](configs/authentication/stackhawk-auth-external-token-header.yml)|

This is not all possible combinations that are supported but some of the more common ones.

For more information see the related documentation [Authenticated Scanning](https://docs.stackhawk.com/hawkscan/configuration/authenticated-scanning)