import net.htmlparser.jericho.Source
import org.parosproxy.paros.network.HttpMessage
import com.stackhawk.hste.extension.scripts.scanrules.ScriptsPassiveScanner
import org.apache.log4j.LogManager
import kotlin.text.Regex

/**
 * Future work:
 * - Add support for more types of sensitive data
 * - Add support for providing regexes via config
 * - Add support for checking for data in headers & params
 * - How to deal with finding count limitations (is it by plugin or by title or ...)
 *
 */

/**
 * Passively scans an HTTP message. The scan function will be called for
 * request/response made via ZAP, actual messages depend on the function
 * "appliesToHistoryType", defined below.
 *
 * scan function receives the following objects from HawkScan:
 * @param ps - the PassiveScan parent object that will do all the core interface tasks
 *     (i.e.: providing access to Threshold settings, raising alerts, etc.).
 *     This is an ScriptsPassiveScanner object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 * @param src - the Jericho Source representation of the message being scanned.
 */

val logger = LogManager.getLogger("sensitiveDataDisclosure")
/**
 * A few static values that will apply to all findings
 */
val cweId = 200 //CWE-200 Exposure of Sensitive Information to an Unauthorized Actor
val wascId = 13 //WASC-13 Information Leakage
val pluginId = 1000058

/**
    Create a useful, reusable object that also sets some default values for an alert.
    When this script is registered, the default pluginId should be updated to
    reflect the id obtained from StackHawk.
*/
class SensitiveDataBlob (
    val slug: String,
    val title: String,
    val description: String,
    val pattern: Regex,
    val solution: String = "Don't disclose sensitive information of type $slug",
    val reference: String = "",
    val other: String = "",
    val risk: Int = 2, // 0: info, 1: low, 2: medium, 3: high
    val confidence: Int = 3, // 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed
//risk and confidence MUST both not be 0, or the alert will not be raised and included in the findings output (see AlertEventConsumer class)
) {}


/* Set up unwanted filetypes for efficient scanning and reduced FPs */
val unwantedFiletypes = arrayOf<String>(
    "image/png",
    "image/jpeg",
    "image/gif",
    "application/x-shockwave-flash",
    "application/pdf",
)

/*
    Set up default objects to alert on, and customize content and values.
    If new types of sensitive data are desired, simply add a blob to the blobs list
    with an appropriate regex, description, risk, etc
*/
fun defineSearchParams(): List<SensitiveDataBlob> {
    val blobs = mutableListOf<SensitiveDataBlob>()

    blobs.add(
        SensitiveDataBlob(
            slug = "email", title = "Information Disclosure - Email Addresses",
            description = "User email addresses discovered in HTTP message body.  Public disclosure of user emails can be a minor violation of PII, but can also disclose potential usernames or other internal state",
            pattern = Regex("([a-zA-Z0-9_.+-]+@[a-zA-Z0-9]+[a-zA-Z0-9-]*[.][a-zA-Z0-9-.]*[a-zA-Z0-9]{2,})"),
            risk = 1,
        )
    )

    blobs.add(
        SensitiveDataBlob(
            slug = "internalIPs", title = "Information Disclosure - Internal IP Addresses",
            description = "Internal IP addresses discovered in HTTP message body.",
            pattern = Regex("((172[.]\\d{1,3}[.]\\d{1,3}[.]\\d{1,3})|(192[.]168[.]\\d{1,3}[.]\\d{1,3})|(10[.]\\d{1,3}[.]\\d{1,3}[.]\\d{1,3})|([fF][eE][89aAbBcCdDeEfF]0?::))"),
            risk = 1
        )
    )

    blobs.add(
        SensitiveDataBlob(
            slug = "phone numbers", title = "Information Disclosure - Phone Numbers",
            description = "Potential PII in the form of personal phone numbers disclosed",
            pattern = Regex("([+]\\d{1,2}\\s)?[(]?\\d{3}[)]?[\\s.-]\\d{3}[\\s.-]\\d{4}"),
            risk = 1
        )
    )
//    blobs.add(
//        SensitiveDataBlob(
//            slug = "iban", title = "Information Disclosure - International Banking Numbers",
//            description = "IBAN patterns identified in HTTP message body.  Disclosure of customers' IBAN numbers is a serious breach of financial PII",
//            pattern = Regex("([A-Za-z]{2}[0-9]{2}[A-Za-z]{4}[0-9]{10})"),
//            solution = "Identify the business logic that is allowing these numbers to be exposed and fix it",
//            risk = 3,
//        )
//    )
//
//    blobs.add(
//        SensitiveDataBlob(
//            slug = "googleKey", title = "Information Disclosure - Google API Keys",
//            description = "Potential Google API key secrets discovered in HTTP message body.  This could allow an attacker to reuse the key and access user confidential information and privileges via the Google API",
//            pattern = Regex("AIza[0-9A-Za-z\\-_]{35}"),
//            risk = 3,
//        )
//    )
//
//    blobs.add(
//        SensitiveDataBlob(
//            slug = "awsAccess", title = "Information Disclosure - AWS Access Token",
//            description = "Potential AWS Access token identified in HTTP message body. This disclosure could be combined with other data disclosures leading to a compromise of the associated AWS account.",
//            pattern = Regex("(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])"),
//            risk = 2,
//        )
//    )
//
//    blobs.add(
//        SensitiveDataBlob(
//            slug = "awsSecret", title = "Information Disclosure - AWS Secret Token",
//            description = "Potential AWS Secret token identified in HTTP message body. This could allow an attacker to reuse the secret key and compromise the AWS account.",
//            pattern = Regex("(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
//            risk = 3,
//        )
//    )
    return blobs
}


fun scan(
    ps: ScriptsPassiveScanner,
    msg: HttpMessage,
    src: Source
): Unit {

    val dataTypes: List<SensitiveDataBlob> = defineSearchParams() // set up the desired data leakage search criteria

    // lets check its not one of the files types that are never likely to contain stuff, like pngs and jpegs
    val contentType = msg.responseHeader.getHeader("Content-Type");
    if (unwantedFiletypes.indexOf(contentType) >= 0) {
        logger.debug("Exited due to wrong content-type\n")
        // if we find one of the unwanted headers quit this scan, this saves time and reduces false positives
        return;
    } else {

        // now lets run our regex against the response body
        val body = msg.responseBody.toString()
        dataTypes.forEach { entry ->
            if (entry.pattern.containsMatchIn(body)) {
                logger.debug("Found a match for ${entry.slug} using ${entry.pattern.toString()}")
                // Look for data matching the entry's regex pattern
                val foundDisclosures = entry.pattern.findAll(body, 0)
                alert(ps, msg, src, entry, foundDisclosures)
            }
        }
    }
}
/*
    Raise an alert. Called by scan function when data disclosures are found
*/
fun alert(
    ps: ScriptsPassiveScanner,
    msg: HttpMessage,
    src: Source,
    blob: SensitiveDataBlob,
    foundDisclosures: Sequence<MatchResult>,
): Unit {
    logger.debug("Entered the raiseAlert function in the $pluginId script.  Matched ${blob.slug} using ${blob.pattern}")
    val evidence = mutableListOf<String>()
    foundDisclosures.forEach { entry -> evidence.add(entry.value)}

    ps.newAlert()
        .setPluginId(pluginId)
        .setRisk(blob.risk)
        .setConfidence(blob.confidence)
        .setName(blob.title)
        .setDescription(blob.description)
        .setParam("The param")
        .setEvidence(evidence[0]) //evidence string should be the match from the msg body to enable platform highlighting
        .setOtherInfo(blob.other + "\n\n" + evidence.joinToString("\n"))
        .setSolution(blob.solution)
        .setReference(blob.reference)
        .setCweId(cweId)
        .setWascId(wascId)
        .setMessage(msg) //newAlert MUST set the message, or the alert will not be included in the findings output
        .raise()
    logger.debug("Reached the end of raiseAlert function for $pluginId.  Should have raised an alert for a PII match.")
}





/**
 * Tells whether the scanner applies to the given history type. NOT USED IN THIS SCRIPT
 *
 * @param {Number} historyType - The ID of the history type of the message to be scanned.
 * @return {boolean} Whether the message with the given type should be scanned by this scanner.
 */
fun appliesToHistoryType(
    historyType: Int
): Boolean {
    // For example, to just scan spider messages:
    // return historyType == org.parosproxy.paros.model.HistoryReference.TYPE_SPIDER;

    // Default behaviour scans default types.
    return ScriptsPassiveScanner.getDefaultHistoryTypes().contains(historyType)
}
