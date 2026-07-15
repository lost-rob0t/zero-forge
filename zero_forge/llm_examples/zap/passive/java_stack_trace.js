const ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 920001
name: Example Java Stack Trace Disclosure
description: A Java stack trace was found in an existing HTTP response body.
solution: Log exceptions server-side and return generic error responses.
references:
  - https://www.zaproxy.org/docs/desktop/addons/script-console/
risk: medium
confidence: high
cweId: 209
wascId: 13
status: alpha
`);
}

function scan(ps, msg, src) {
  const contentType = String(
    msg.getResponseHeader().getHeader("Content-Type") || ""
  );
  if (!contentType.includes("text") && !contentType.includes("json")) {
    return;
  }

  const body = msg.getResponseBody().toString();
  const match = /(?:Exception in thread|at [a-zA-Z0-9_.$]+\([^)]*\.java:\d+\))/.exec(body);
  if (match === null) {
    return;
  }

  ps.newAlert()
    .setEvidence(match[0])
    .setMessage(msg)
    .raise();
}
