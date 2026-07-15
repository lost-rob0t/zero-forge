const ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 910001
name: Example Reflected Input Detection
description: A unique non-executable marker was reflected in the HTTP response.
solution: Apply context-aware output encoding and validate untrusted input.
references:
  - https://www.zaproxy.org/docs/desktop/addons/script-console/
category: injection
risk: low
confidence: medium
cweId: 79
wascId: 8
status: alpha
`);
}

function scan(as, msg, param, value) {
  if (as.isStop()) {
    return;
  }

  const attack = "zf-reflection-8f7d3c";
  const baselineBody = msg.getResponseBody().toString();
  if (baselineBody.indexOf(attack) !== -1) {
    return;
  }

  const probe = msg.cloneRequest();
  as.setParam(probe, param, attack);
  as.sendAndReceive(probe, false, false);

  const body = probe.getResponseBody().toString();
  if (body.indexOf(attack) === -1) {
    return;
  }

  as.newAlert()
    .setParam(param)
    .setAttack(attack)
    .setEvidence(attack)
    .setMessage(probe)
    .raise();
}
