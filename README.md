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

For more information see the related documentation [Authenticated Scanning](https://docs.stackhawk.com/hawkscan/configuration/authenticated-scanning.html)

### Authentication and session management scripts

Custom authentication and session management scripts can be used to handle complex authentication and authorization scenarios.
If a preconfigured authentication and/or authorization style doesn't meet your needs you can replace either with a custom script.

HawkScan supports writing custom scripts in javascript and kotlin via [ZAP scripting support](https://www.zaproxy.org/docs/desktop/start/features/scripts/).
If you can't find an example in this repository you're encouraged to check out the [ZAP community scripts](https://github.com/zaproxy/community-scripts) repository for more examples.

To use authentication scripts in HawkScan you'll need to

- Create script files with functions defined to match the interface of the [script type](https://www.zaproxy.org/docs/desktop/start/features/scripts/).
- Add your script to the [hawkAddons.scripts](https://docs.stackhawk.com/hawkscan/configuration/#hawkaddonscripts) configuration section.
- Add the [authentication.script](https://docs.stackhawk.com/hawkscan/configuration/#appauthenticationscript) and/or [authentication.sessionScript](https://docs.stackhawk.com/hawkscan/configuration/#appauthenticationsessionscript) configuration sections.

The [stackhawk-auth-scripts-token-for-cookie.yml](configs/authentication/stackhawk-auth-scripts-token-for-cookie.yml) file is an example of using a custom
authentication and session script together. The example authentication script, [token-for-cookie.kts](scripts/examples/authentication/token-for-cookie.kts), and
session management script, [token-and-cookie.kts](scripts/examples/session/token-and-cookie.kts), are examples of using an external token to request a cookie for
use in session management. 

To get started scripting, copy and rename the templates defined for [authentication](scripts/templates/authentication/authentication-template.kts) and [session management](scripts/templates/session/session-template.kts) into your project.  

When using authentication scripts in hawkscan you'll need to place the scripts in folder structure denoting their type with the location of the script directory relative to the stackhawk.yml file.

```shell
my-webapp/
  stackhawk.yml
  scripts/
    authentication/
      my-auth-script.kts
    session/
      my-session-script.kts
  ...
```

Your `stackhawk.yml` file should include the scripts in `hawkAddOn.scripts`.

```yaml
...
hawkAddOn:
 scripts:
  - name: my-auth-script.kts
    type: authentication
    path: scripts
  - name: my-session-script.kts
    type: session
    path: scripts
```

This will load your scripts into the scanner for use as authentication or session management.

Lastly you'll need to specify the scripts as the method for authentication and/or session management in your `stackhawk.yml`

```yaml
authentication:
  script: 
    name: my-auth-script.kts
    credentials:
      myToken: ${MY_TOKEN:something-secret}
  sessionScript:
    name: my-session-script.kts
```

Once you've created your scripts and configured `stackhawk.yml` to use them, you can run the stackhawk/hawkscan docker image
as you normally would. HawkScan's normal authentication checks will use your scripts and will return success or errors if they've worked or not.

If your authentication script is failing, and/or not producing the expected results, you can run the stackhawk/hawkscan docker image
like so to get the logs from the scanner. 

```shell
docker run -e API_KEY=$HAWK_API_KEY --rm --name hawkscan --entrypoint=bash -v $(pwd):/hawk -it stackhawk/hawkscan -c 'shawk; cat zap.out'
```

As mentioned in the [troubleshooting docs](https://docs.stackhawk.com/hawkscan/troubleshooting.html#script-debugging), you can add logging to your scripts to track down issues.

```kotlin
import org.apache.log4j.LogManager
val logger = LogManager.getLogger("my-script")
```
