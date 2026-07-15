const ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 920002
name: Example Missing Content Security Policy
description: An HTML response did not include a Content-Security-Policy header.
solution: Define and deploy a restrictive Content-Security-Policy response header.
references:
  - https://www.zaproxy.org/docs/desktop/addons/script-console/
risk: low
confidence: high
cweId: 693
wascId: 15
status: alpha
`);
}

function scan(ps, msg, src) {
  const responseHeader = msg.getResponseHeader();
  const contentType = String(responseHeader.getHeader("Content-Type") || "");
  const policy = responseHeader.getHeader("Content-Security-Policy");
  if (!contentType.includes("text/html") || policy !== null) {
    return;
  }

  ps.newAlert()
    .setEvidence("Content-Security-Policy header absent")
    .setMessage(msg)
    .raise();
}
