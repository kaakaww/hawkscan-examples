import org.apache.log4j.Logger
import org.parosproxy.paros.network.HttpMessage
import org.zaproxy.zap.extension.ascan.ScriptsActiveScanner


val logger = Logger.getLogger("tenancy_check")

fun log(msg: String) {
    logger.debug("[tenancy_check] $msg")
}

fun alert(activeScanner: ScriptsActiveScanner, msg: HttpMessage, evidence: String) {
    val risk = 3 // 0: info, 1: low, 2: medium, 3: high
    val confidence = 3 // 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed
    val title = "Tenancy Check failed"
    val description = "User was able to access users not in their company"
    val solution = "Enforce tenancy"
    val reference = "https://personal.rhul.ac.uk/vsai/149/Multi-tenancy%20doc%20300614.pdf"
    val otherInfo = "see: https://www.cloudreach.com/en/blog/multi-tenant-security-in-the-cloud-what-you-need-to-know/"
    var pluginId = ""; //Custom Plugin ID

    activeScanner.newAlert()
        .setPluginId(pluginId)
        .setRisk(risk)
        .setConfidence(confidence)
        .setName(title)
        .setDescription(description)
        .setEvidence(evidence)
        .setOtherInfo(otherInfo)
        .setSolution(solution)
        .setReference(reference)
        .setMessage(msg)
        .raise();
}

fun scanNode(activeScanner: ScriptsActiveScanner, origMessage: HttpMessage) {
    return
}

fun scan(activeScanner: ScriptsActiveScanner, origMessage: HttpMessage, param: String, value: String) {
    var uri = origMessage.requestHeader.uri

    log("scanning $uri")

    // Copy requests before reusing them
    val msg = origMessage.cloneRequest()

    var requestHeader = msg.requestHeader
    uri = requestHeader.uri

    log("Here is the param $param  and this is the $value")

    activeScanner.setParam(msg, param, "user")


    log("scanning 2${uri.path} with $param value of user4")

    requestHeader.setHeader("Content-Type", "application/json")

    activeScanner.sendAndReceive(msg, false, false)

    var responseHeader = msg.responseHeader
    var responseBody = msg.responseBody

    var checkString = "12345678"
    //Check for users outside of logged in user's tenancy
    var evidenceIdx = responseBody.toString()
        .indexOf(checkString)

    log(msg.toString())

    // Test the response here, and make other requests as required
    if (responseHeader.statusCode == 200 && evidenceIdx >= 0) {
        alert(activeScanner, msg, responseBody.toString().substring(evidenceIdx, evidenceIdx + checkString.length))
    }
}

