// Import necessary Java classes
import com.stackhawk.hste.extension.script.HttpSenderScriptHelper
import org.apache.commons.codec.digest.HmacAlgorithms
import org.apache.commons.codec.digest.DigestUtils
import org.apache.commons.codec.digest.HmacUtils
import java.net.URL
import org.apache.log4j.LogManager
import org.parosproxy.paros.network.HttpMessage
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.time.ZonedDateTime
import kotlin.text.*
import com.stackhawk.hste.extension.script.ScriptVars

val logger = LogManager.getLogger("***AWS SigV4 Signer***")
val scriptName = "aws-sigv4.kts"

// Get keys, region, service from config variables
val accessKey = ScriptVars.getScriptVar(scriptName, "accessKey") ?: "MyAccessKey"
val secretKey = ScriptVars.getScriptVar(scriptName, "secretKey") ?: "MySecretKey"
val region = ScriptVars.getScriptVar(scriptName, "region") ?: "us-east-1"
val service = ScriptVars.getScriptVar(scriptName, "service") ?: "execute-api"
// token is only required if using temporary access/secret keys
val token = ScriptVars.getScriptVar(scriptName, "token") ?: ""

// create signature-required time stamps in UTC
val date = ZonedDateTime.now(ZoneOffset.UTC)
val amzformatter = DateTimeFormatter.ofPattern("uuuuMMdd'T'HHmmss'Z'")
val stampformatter = DateTimeFormatter.ofPattern("uuuuMMdd")
val amzdate = amzformatter.format(date)
val datestamp = stampformatter.format(date)

// Helper function to sign a message with a key using HMAC-SHA256
fun sign(key: ByteArray, msg: String): ByteArray
{
    msg.encodeToByteArray()
    val msgDigest = HmacUtils(HmacAlgorithms.HMAC_SHA_256, key).hmac(msg)
    return msgDigest
}

// AWS-specific function to generate the signature key
fun getSignatureKey(key: String, dateStamp: String, regionName: String, serviceName: String): ByteArray
{
    val kDate = sign("AWS4${key}".encodeToByteArray(), dateStamp)
    val kRegion = sign(kDate, regionName)
    val kService = sign(kRegion, serviceName)
    val kSigning = sign(kService, "aws4_request")
    return kSigning
}

fun sendingRequest(msg: HttpMessage, initiator: Int, helper: HttpSenderScriptHelper) {
    logger.info("sendingRequest function called")
    logger.info("Date/Time Stamps look like:\nLong: $amzdate Short: $datestamp")
    val parsedUrl = URL(msg.requestHeader.uri.toString()) //not sure if we need to replace anything
//    val canonicalUri = encodeURIComponent(parsedUrl.getPath() || "/").replace(/[!'()*]/g, escape);
    val canonicalUri = parsedUrl.path
    val method = msg.requestHeader.method
    val host = msg.requestHeader.hostName
    var canonicalQuerystring = ""

    if (parsedUrl.query != "") {
        // Replace any + * from ZAP Payloads with %20/%2A - + * breaks signature
        val query = parsedUrl.query
            .replace("+", "%20")
            .replace("*", "%2A")

        // sort parameters
        val paramsList = query.split("&")
        val querystringSorted = paramsList.sorted().joinToString("&")

        // validate key-value pairs (or singletons) and join to the canonical query string
        for (queryParam in querystringSorted.split("&")) {
            val paramSplit = queryParam.split("=")
            val paramKey = paramSplit[0]
            var paramValue = ""
            if (paramSplit.size > 1) {
                paramValue = paramSplit[1]
            }
            if (paramKey.isNotBlank()) {
                canonicalQuerystring += "&" + listOf(paramKey, paramValue).joinToString("=")
            }
        }
    }

    val payload = msg.requestBody.toString()
    val payloadHash = DigestUtils.sha256Hex(payload.encodeToByteArray())
    val canonicalHeaders = "content-type:application/json\nhost:${host}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:$amzdate\n"
    val signedHeaders = "content-type;host;x-amz-content-sha256;x-amz-date"

    val canonicalRequest = "${method}\n${canonicalUri}\n${canonicalQuerystring}\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}"

    val algorithm = "AWS4-HMAC-SHA256"
    val credentialScope = "$datestamp/$region/$service/aws4_request"
    val canonicalRequestHash = DigestUtils.sha256Hex(canonicalRequest.encodeToByteArray())

    val stringToSign = "$algorithm\n$amzdate\n$credentialScope\n$canonicalRequestHash"

    val signingKey = getSignatureKey(secretKey, datestamp, region, service)
    val signature = HmacUtils(HmacAlgorithms.HMAC_SHA_256, signingKey).hmacHex(stringToSign)
    val authorizationHeader = "$algorithm Credential=${accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}"

    val headers = mutableMapOf(
        "content-type" to "application/json",
        "X-Amz-Content-Sha256" to payloadHash,
        "x-amz-date" to amzdate,
        "Authorization" to authorizationHeader
    )
    // Check if token is necessary
    if (token.isNotEmpty()) {
        headers["token"] = token
    }
    // Add headers to message
    headers.forEach {
        msg.requestHeader.setHeader(it.key, it.value)
    }
}

fun responseReceived(msg: HttpMessage, initiator: Int, helper: HttpSenderScriptHelper) {
    logger.info("responseReceived function called")
    logger.info("\n${msg.requestHeader}\n${msg.requestBody}")
    logger.info("\n${msg.responseHeader}\n${msg.responseBody}")
}