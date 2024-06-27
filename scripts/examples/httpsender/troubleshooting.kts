import org.apache.log4j.LogManager
import org.parosproxy.paros.network.HttpMessage
import org.zaproxy.zap.extension.script.HttpSenderScriptHelper
import org.zaproxy.zap.extension.script.ScriptVars
import java.io.FileWriter
import java.io.IOException



//*****IF SCRIPT  FILENAME CHANGES, YOU MUST CHANGE THIS VAL*****
val scriptName = "troubleshooting.kts"
//************************************

// Use ScriptVars from config to set logLevel, appropriate values
// can be seen in the when branch below. Default to METADATA
val logLevel = ScriptVars.getScriptVar(scriptName,"logLevel") ?: "METADATA"

// if defined in config, logLocation must contain either "hawkscanlog" (default) or a valid path
// allows to log to the standard log or to a local file
val logLocation = ScriptVars.getScriptVar(scriptName,"logLocation") ?: "hawkscanlog"

// if defined in config, logType must contain "AUTHENTICATION", "SPIDER", "SCANNER"
// or a string list of same such as "AUTHENTICATION SPIDER" or "SCANNER, MANUAL"
val logType = ScriptVars.getScriptVar(scriptName,"logType") ?: "ALL"

val initiators = listOf("ALL","PROXY","SCANNER","SPIDER","FUZZER","AUTHENTICATION","MANUAL")

//attempt to split logType into valid substrings, but if not, naively log everything
fun splitLogType(logType: String, initiators: List<String>): List<Int> {
    val lTList = logType.split(",", " ", ", ")
    val initList = mutableListOf<Int>()
    for (t in lTList) {
        if (t == "ALL") {
            for (i in initiators) {
                initList += initiators.indexOf(i)
            }
            return initList
        }
        if (initiators.contains(t)) {
            initList.add(initiators.indexOf(t))
        }
    }
    return initList
}

fun request_banner(init: Int): String {
    val banner = "\n//******REQUEST FROM ${initiators[init]}*******//\n"
    return banner
}
//val request_banner = "\n//***********REQUEST****************//\n"
val response_banner = "\n//************RESPONSE**************//\n"
val entry_end = "\n//************************************//\n"


// modify a request before it's sent to the web application
fun sendingRequest(msg: HttpMessage, initiator: Int, helper: HttpSenderScriptHelper) {
}

// modify the response from the web application before sending to the client
fun responseReceived(msg: HttpMessage, initiator: Int, helper: HttpSenderScriptHelper) {
    val logTypeList = splitLogType(logType, initiators)
    val httpRequestAndResponse: String
    if (logTypeList.isEmpty()) throw IllegalArgumentException("logType $logType is not allowed. " +
            "Please read the docs or the source")
    if (!logTypeList.contains(initiator)) return
    when (logLevel) {
        //Some additional thoughts: full request + response headers (no resp body)
        //Identify and log the initiator; part of metadata output?
        //Oneline, just the request prime?
        //Banners separating request header/body and response header/body and end-of-record
        "COMPLETE" -> {
            httpRequestAndResponse = request_banner(initiator) +
                    msg.requestHeader.toString() +
                    msg.requestBody.toString() +
                    response_banner + msg.responseHeader.toString() +
                    msg.responseBody.toString() +
                    entry_end
        }
        "SNIPPED" -> {
            val snipLength = 160
            val responsePayload = if (msg.responseBody.toString().length > snipLength) {
                msg.responseBody.toString().take(snipLength/2) +
                        "\n***SNIPPED***\n" +
                        msg.responseBody.toString().takeLast(snipLength/2)
            } else msg.responseBody.toString()
            httpRequestAndResponse = request_banner(initiator) +
                    msg.requestHeader.toString() +
                    msg.requestBody.toString() +
                    response_banner + msg.responseHeader.toString() +
                    responsePayload + entry_end
            //string slice to only include top/bottom 80 chars of response body
        }
        "FULLREQ" -> {
            httpRequestAndResponse = request_banner(initiator) +
                    msg.requestHeader.toString() +
                    msg.requestBody.toString() +
                    response_banner + msg.responseHeader.toString() +
                    entry_end
        }
        "HEADERS" -> {
            httpRequestAndResponse = request_banner(initiator) +
                    msg.requestHeader.toString() +
                    response_banner + msg.responseHeader.toString() +
                    entry_end
        }
        "METADATA" -> {
            httpRequestAndResponse = request_banner(initiator) +
                    msg.requestHeader.primeHeader.toString() +
                    "\n" + msg.responseHeader.primeHeader.toString() +
                    "\nRTT (ms): ${msg.timeElapsedMillis}" + entry_end
        }
        "ONELINE" -> {
            httpRequestAndResponse = request_banner(initiator) +
                    msg.requestHeader.primeHeader.toString() +
                    entry_end
        }
        else -> {
            throw IllegalArgumentException("\nlogLevel value $logLevel not supported." +
                    "\nlogType must be either undefined (defaults to METADATA)" +
                    "\nor one of (COMPLETE|SNIPPED|FULLREQ|HEADERS|METADATA|ONELINE)")
        }
    }

    if (logLocation == "hawkscanlog") {
        val logger = LogManager.getLogger("troubleshooting-logs")
        logger.info("request/response data: $httpRequestAndResponse")

    } else {
        appendToFile(httpRequestAndResponse, logLocation) //maybe works now
    }
}

//does nothing yet
fun appendToFile(logEntry: String, logLocation: String) {
    try {
        val writer = FileWriter(logLocation, true)
        //in v3, need to add a timestamp to the log entry.  Right now, running multiple times
        //with same log file will continue to aggregate results
        writer.append(logEntry)
        writer.flush()
        writer.close()
    } catch (e: IOException) {
        fileFail()
    }
}

fun fileFail(): Nothing {
    val err_message = "This IS NOT an authentication error.  Most likely you have specified " +
            "a non-usable path or filename in the logLocation variable in your stackhawk.yml config" +
            "\nyou entered: $logLocation"
    throw IOException(err_message)
}
