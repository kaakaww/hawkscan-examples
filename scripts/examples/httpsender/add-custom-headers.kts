// This kotlin script adds one or more additional, custom headers headers to the HTTP/S requests that HawkScan makes to the target application.

// Corresponding config for stackhawk.yml:
// hawkAddOn:
//   scripts:
//     - name: add-custom-headers.kts
//       type: httpsender
//       path: (relative path to /httpsender subdirectory)

// Note: If path: is not specified, the scanner will assume that the script is in an /httpsender subdirectory directory under the directory that stackhawk.yml is in

import org.apache.log4j.LogManager
import org.parosproxy.paros.network.HttpMessage
import org.zaproxy.zap.extension.script.HttpSenderScriptHelper
import org.zaproxy.zap.extension.script.ScriptVars

val logger = LogManager.getLogger("httpsender log:")

// modify a request before it's sent to the web application

fun sendingRequest(msg: HttpMessage, initiator: Int, helper: HttpSenderScriptHelper) {
    // substitute your own header names and values below ("header name", "header value")
    // use one setHeader line per header; lines can be added or removed as needed
    logger.info(" pre header addition: \n ${msg.requestHeader} \n")
    msg.requestHeader.setHeader("X-KaaKaww", "my-hawksome-header")
    msg.requestHeader.setHeader("X-Max-KaaKaww", "hawksomer-header")
    logger.info(" post header addition: \n ${msg.requestHeader} \n")
}

// modify the response from the web application before sending to the client

fun responseReceived(msg: HttpMessage, initiator: Int, helper: HttpSenderScriptHelper) {
// no logic needed here when just adding headers; however, the responseReceived function itself needs to be present
}
