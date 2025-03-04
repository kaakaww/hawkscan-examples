// Custom Weak Auth - a passive custom test script
// Register me with:
//   hawk register plugin "Custom Weak Auth"
//   hawk list plugin

import com.stackhawk.hste.extension.pscan.PluginPassiveScanner
import com.stackhawk.hste.extension.scripts.scanrules.ScriptsPassiveScanner
import net.htmlparser.jericho.Source
import org.apache.log4j.LogManager
import org.parosproxy.paros.network.HttpMessage
import javax.script.ScriptException


val logger = LogManager.getLogger("custom-weak-auth")
logger.info("Loaded weak-auth passive script")
val ntlmRegex = "WWW-Authenticate: NTLM".toRegex()

@Throws(ScriptException::class)
fun scan(scriptsPassiveScanner: ScriptsPassiveScanner, msg: HttpMessage, source: Source)
{
    logger.debug("Checking a message...")
    val match = ntlmRegex.find(msg.responseHeader.toString())
    match?.let {
        val groupValues = it.groupValues
        val firstGroupValue = groupValues.first()
        logger.info("NTLM match found!! $firstGroupValue")
        alert(scriptsPassiveScanner, msg, firstGroupValue)
    }
}

fun alert(passiveScanner: ScriptsPassiveScanner, msg: HttpMessage, evidence: String) {
    val risk = 3 // 0: info, 1: low, 2: medium, 3: high
    val confidence = 3 // 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed
    val title = "NTLM Auth Enabled"
    val description = "NTLM is an outdated form of authentication and is vulnerable to various attacks."
    val solution = "Disable NTLM authentication for this application."
    val reference = "https://www.controlgap.com/blog/understanding-the-risks-associated-with-ntlm-authentication"
    val otherInfo = ""
    val pluginId = 1000059 // <-- change me based on registered custom script ID!

    passiveScanner.newAlert()
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
        .raise()

}

fun appliesToHistoryType(historyType: Int): Boolean {
    return PluginPassiveScanner.getDefaultHistoryTypes().contains(historyType)
}