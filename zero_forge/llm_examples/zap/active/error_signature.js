const ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 910002
name: Example Error Signature Detection
description: A harmless malformed value caused a new server-side error signature.
solution: Use typed parameter handling and avoid exposing internal error details.
references:
  - https://www.zaproxy.org/docs/desktop/addons/script-console/
category: injection
risk: medium
confidence: medium
cweId: 209
wascId: 13
status: alpha
`);
}

function scan(as, msg, param, value) {
  if (as.isStop()) {
    return;
  }

  const attack = "zf-invalid-'";
  const errorPattern = /(syntax error|stack trace|unhandled exception)/i;
  const baselineMatch = errorPattern.exec(msg.getResponseBody().toString());
  const probe = msg.cloneRequest();
  as.setParam(probe, param, attack);
  as.sendAndReceive(probe, false, false);

  const body = probe.getResponseBody().toString();
  const match = errorPattern.exec(body);
  if (match === null || baselineMatch !== null) {
    return;
  }

  as.newAlert()
    .setParam(param)
    .setAttack(attack)
    .setEvidence(match[0])
    .setMessage(probe)
    .raise();
}
