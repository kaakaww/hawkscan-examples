import org.apache.log4j.LogManager
import org.parosproxy.paros.network.HttpMessage
import com.stackhawk.hste.extension.script.HttpSenderScriptHelper
import com.stackhawk.hste.extension.script.ScriptVars

val logger = LogManager.getLogger("sender1")

// modify a request before it's sent to the web application
fun sendingRequest(msg: HttpMessage, initiator: Int, helper: HttpSenderScriptHelper) {
    logger.info("sender2 script $initiator")
}

// modify the response from the web application before sending to the client
fun responseReceived(msg: HttpMessage, initiator: Int, helper: HttpSenderScriptHelper) {
    val clientHdr = ScriptVars.getScriptVar("sender2.kts", "client_header")
    msg.responseHeader.setHeader("X-Client-Header", clientHdr)
}
