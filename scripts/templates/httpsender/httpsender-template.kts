import org.apache.log4j.LogManager
import org.parosproxy.paros.network.HttpMessage
import org.zaproxy.zap.extension.script.HttpSenderScriptHelper
import org.zaproxy.zap.extension.script.ScriptVars

val logger = LogManager.getLogger("sender1")

fun sendingRequest(msg: HttpMessage, initiator: Int, helper: HttpSenderScriptHelper) {
    // modify a request before it's sent to the web application
    logger.info("sender2 script $initiator")
}

fun responseReceived(msg: HttpMessage, initiator: Int, helper: HttpSenderScriptHelper) {
    // modify the response from the web application before sending to the client
    val clientHdr = ScriptVars.getScriptVar("sender2.kts", "client_header")
    msg.responseHeader.setHeader("X-Client-Header", clientHdr)
}
