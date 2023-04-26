import org.parosproxy.paros.network.HttpMessage
import org.zaproxy.zap.extension.ascan.ScriptsActiveScanner

/**
 * Scans a "node", i.e. an individual entry in the Sites Tree.
 * The scanNode function will typically be called once for every page.
 *
 * @param as - the ActiveScan parent object that will do all the core interface tasks
 *     (i.e.: sending and receiving messages, providing access to Strength and Threshold settings,
 *     raising alerts, etc.). This is an ScriptsActiveScanner object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 */
fun scanNode(activeScanner: ScriptsActiveScanner, origMessage: HttpMessage) {
    // Debugging can be done using println like this
    print("scan called for url=${origMessage.requestHeader.uri}");

    // Copy requests before reusing them
    val msg = origMessage.cloneRequest();

    // sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
    activeScanner.sendAndReceive(msg, false, false);

    // Test the responses and raise alerts as below

    // Check if the scan was stopped before performing lengthy tasks
    if (activeScanner.isStop()) {
        return
    }
    // Do lengthy task...

    // Raise less reliable alert (that is, prone to false positives) when in LOW alert threshold
    // Expected values: "LOW", "MEDIUM", "HIGH"
    if (activeScanner.alertThreshold.toString() == "LOW") {
        // ...
    }

    // Do more tests in HIGH attack strength
    // Expected values: "LOW", "MEDIUM", "HIGH", "INSANE"
    if (activeScanner.attackStrength.toString() == "HIGH") {
        // ...
    }
}

/**
 * Scans a specific parameter in an HTTP message.
 * The scan function will typically be called for every parameter in every URL and Form for every page.
 *
 * @param as - the ActiveScan parent object that will do all the core interface tasks
 *     (i.e.: sending and receiving messages, providing access to Strength and Threshold settings,
 *     raising alerts, etc.). This is an ScriptsActiveScanner object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 * @param {string} param - the name of the parameter being manipulated for this test/scan.
 * @param {string} value - the original parameter value.
 */
fun scan(activeScanner: ScriptsActiveScanner, origMessage: HttpMessage, param: String, value: String) {
    // Debugging can be done using println like this
    print(
        "scan called for url=${origMessage.requestHeader.uri} " +
                " param=$param value=$value"
    )

    // Copy requests before reusing them
    val msg = origMessage.cloneRequest();

    // setParam (message, parameterName, newValue)
    activeScanner.setParam(msg, param, "Your attack");

    // sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
    activeScanner.sendAndReceive(msg, false, false);

    // Test the response here, and make other requests as required
    if (true) {    // Change to a test which detects the vulnerability
        // risk: 0: info, 1: low, 2: medium, 3: high
        // confidence: 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed
        activeScanner.newAlert()
            .setPluginId("changeme")
            .setRisk(1)
            .setConfidence(1)
            .setName("Active Vulnerability title")
            .setDescription("Full description")
            .setParam(param)
            .setAttack("Your attack")
            .setEvidence("Evidence")
            .setOtherInfo("Any other info")
            .setSolution("The solution")
            .setReference("References")
            .setCweId(0)
            .setWascId(0)
            .setMessage(msg)
            .raise();
    }
}