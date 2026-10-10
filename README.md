# NCBA: Local Machine-Identity Telemetry Monitor

**Source:** [github.com/jagananmol-dev/cyber_39](https://github.com/jagananmol-dev/cyber_39)

NCBA (Network-Centric Behavioral Analytics) addresses a specific machine-identity security problem: a stolen workload credential can be used to impersonate a service, while ordinary certificate renewal does not tell an operator whether the certificate is being used abnormally. This project is a **local, operator-run telemetry analysis tool**. Import workload/network events, capture a reviewed normal-traffic baseline, compare new observations against that baseline, and examine why an event was flagged.

## Run locally

**No external account, identity provider, API key, database, Docker installation, or cloud subscription is required.** This is a Node.js application, not a Windows `.exe`.

Install [Node.js 20 LTS](https://nodejs.org/) or another supported Node.js 18+ release. In PowerShell, go to the project folder and run:

```powershell
npm install
$env:PORT = "3000"
npm start
```

Open **http://127.0.0.1:3000**. To use another port, change `3000` in `$env:PORT`. The service listens on `127.0.0.1` by default, so it is accessible only from the same computer. `/healthz` returns `{"status":"ok"}` when it is running. Stop it with **Ctrl+C**.

If you already installed the dependencies:

```powershell
$env:PORT = "3000"
npm start
```

## Try the detection workflow

### Option A: See the complete example

Click **Run local incident drill**. NCBA creates a **clearly labelled synthetic** workload, a 10-event known-good baseline, and two simulated incident observations showing token replay, an unfamiliar source, a TLS fingerprint change, a new destination, abnormal request volume, and a threat-intelligence match. The resulting alert is training data, not a real incident.

### Option B: Analyse your own exported telemetry

1. Export a small JSON batch of normal gateway, reverse-proxy, or sensor activity using the schema below. Use metadata only: **do not upload private keys, tokens, credentials, HTTP request/response bodies, or other secrets**.
2. Use **Download known-good baseline example** to see the exact format. A minimum of five samples per workload is required.
3. Select the baseline file. Choose **Verified normal traffic — capture or replace baseline**, then click **Import and analyse**. Replacing a baseline resets the reference profile for its workload, so only use reviewed, representative traffic.
4. Export a later, separate batch and compare it with the baseline. Choose **New observations — compare with the saved baseline** and import it. A workload without a saved baseline is deliberately rejected rather than given an invented score.
5. Select a workload to inspect its score, rule events, new sources/destinations/TLS fingerprints, unusual UTC hours, traffic spikes, and sample-based confidence.
6. Use **Clear local telemetry and baselines** when you want to remove imported activity. The app asks for confirmation and retains the local audit history.

The supplied **Download incident observation example** is labelled `orders-api-demo`. Capture the matching baseline example first. These safe documentation-range IP addresses and example fingerprints are synthetic.

## Telemetry JSON schema

The file must be a JSON object with an `events` array. Each event requires `workload`, an ISO 8601 `timestamp` with timezone, and an `eventType`. `type`, `sourceIp`, `destination`, `tlsFingerprint`, and `requestsPerMinute` are optional.

```json
{
  "events": [
    {
      "workload": "orders-api",
      "type": "API Gateway",
      "timestamp": "2026-10-10T08:15:00Z",
      "eventType": "connection",
      "sourceIp": "192.0.2.10",
      "destination": "orders-api",
      "tlsFingerprint": "sha256:replace-with-a-reviewed-fingerprint",
      "requestsPerMinute": 18
    }
  ]
}
```

Use a consistent workload name across the baseline and observation files. Source IPs must be valid IPv4/IPv6 literals. Fingerprints are opaque identifiers (maximum 128 characters); upload a fingerprint, **never the certificate/private key**. Imports accept at most 1,000 events / 1 MB per request; each event must be no more than 90 days old or five minutes in the future.

Recognized `eventType` values:

- `connection`
- `authentication_failure`
- `token_replay`
- `certificate_expired`
- `certificate_mismatch`
- `rate_anomaly`
- `unexpected_egress`
- `threat_intelligence_match`

The exporter is responsible for mapping its log fields to this schema. NCBA does not sniff packets, tail another application's files, subscribe to a SIEM, or automatically connect to Kubernetes/SPIRE.

## How the explainable assessment works

The local rules compare each workload's imported observations against its explicitly captured baseline:

- **Behavior (40%):** strongest recognized security-event severity in the observation window. Token replay and threat-intelligence matches score 100; authentication failures 55; rate anomalies 75; unexpected egress 85; certificate expiration/mismatch 95.
- **Time / traffic (30%):** proportion of events in UTC hours not seen in the baseline, compared with traffic at least three times the baseline median.
- **Peer / identity drift (20%):** mean proportion of events using source IPs, destinations, or TLS fingerprints absent from the baseline.
- **Threat intelligence (10%):** 100 when the imported batch contains a `threat_intelligence_match`; otherwise 0. This is an event supplied by your telemetry source, **not a threat-feed lookup performed by NCBA**.

The weighted, rounded result maps to **0–29: allow and monitor; 30–59: step-up verification; 60–84: throttle and investigate; 85–100: containment review**. These are demonstration policy recommendations, not measured breach probabilities. Confidence is marked low/moderate/high based on baseline and observation sample counts; a high score from a small sample is not a confirmed attack. Investigate the event evidence and tune your telemetry mapping and policies before relying on results.

Each workload needs five baseline events. New baseline events replace that workload's existing reference sets. Peer comparisons are per workload's own sample, not automatically learned from a fleet of similar systems. The scoring is deterministic rule-based analysis, **not trained machine learning**, and does not claim a validated false-positive rate.

## What this solves—and what it cannot do by itself

This version is useful without external credentials: it accepts actual exported metadata, creates a reference for known-good behavior, flags specified certificate/authentication/traffic indicators, reports its evidence and confidence, and preserves a local record of analysis. It is practical for a local demonstration, sample-export investigation, and initial evaluation of the event schema.

It does **not** issue/renew SPIFFE certificates, retrieve X.509 metadata from a live handshake, detect attacks absent from the imported fields/rules, quarantine a Pod, block an IP, revoke a credential, authenticate the analyst, provide the two-person quorum, forward logs to immutable storage, or protect a production service. Implementing those controls safely requires connecting to and testing against the actual SPIRE, gateway/IDS, Kubernetes policy, and operator-identity systems; this standalone project deliberately does not pretend to change them. It is not a substitute for deployed security monitoring or incident response.

## Local data and security

- The web/API service binds to `127.0.0.1`, and does not expose itself to your LAN by default.
- The server rejects non-loopback hostnames and cross-origin state-changing requests; keep the browser URL on `127.0.0.1` or `localhost`.
- JSON state is stored under `data/state.json` beside the project; this path can be changed with `NCBA_DATA_FILE`.
- The browser does not send uploaded files to any external service. The selected JSON is parsed locally by the browser and sent to the local NCBA server only.
- Imported telemetry can contain personal or operational identifiers such as IP addresses and service names. Store only information you are authorized to process, protect your Windows account and disk, and clear data when no longer needed.
- The audit chain is SHA-256 hash-linked to make accidental edits detectable. It is kept on the same computer and is **not** immutable or protection from an administrator who can modify the data file.
- Do not put this demo behind a public reverse proxy: it has no login, HTTPS, or operator authorization.

## REST API

| Method | Path | Description |
|---|---|---|
| `GET` | `/healthz` | Local process health |
| `GET` | `/api/entities` | Workloads with captured baselines and their latest assessment |
| `POST` | `/api/telemetry/baselines` | Capture or replace baselines from `{ "events": [...] }` |
| `POST` | `/api/telemetry/ingest` | Compare events against saved baselines and record assessments |
| `POST` | `/api/telemetry/demo` | Create one clearly labelled synthetic training incident |
| `GET` | `/api/telemetry?limit=50` | Read recent events and baseline summaries |
| `DELETE` | `/api/telemetry` | Clear events, baselines, and workload inventory; retain audit history |
| `GET` | `/api/audit?limit=20` | Read recent local audit events (maximum 100) |
| `GET` | `/api/audit/verify` | Verify the local hash chain |

If importing with PowerShell/curl, the same JSON file schema and 1 MB batch limit apply. The server returns an explicit 4xx JSON error for invalid values, unbaselined workloads, malformed events, or undersized baselines.

## Tests and files

```powershell
npm test
```

Tests cover risk thresholds, baseline-derived detection, attack evidence, invalid-event rejection, missing/undersized baselines, persistence, the clearly labelled synthetic drill, and local data deletion.

| File | Purpose |
|---|---|
| `server.js` | Local-only Express server, telemetry schema validation, and REST API |
| `telemetry-engine.js` | Workload baseline capture and explainable telemetry analysis |
| `risk-engine.js` | Weighted rule-based scores and operator-review policy bands |
| `state-store.js` | Atomic local persistence and hash-linked audit history |
| `index.html`, `styles.css`, `script.js` | Local telemetry intake and evidence dashboard |
| `test/ncba.test.js` | API and detector integration tests |
| `package.json`, `package-lock.json` | Scripts and locked Node.js dependencies |

The source archive [NCBA-Cybersecurity-Case-Study.zip](./NCBA-Cybersecurity-Case-Study.zip) contains the README, application, test suite, and package files; it excludes runtime state and `node_modules`.
