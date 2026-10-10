# NCBA — Local Machine-Identity Telemetry Monitor

**GitHub:** [jagananmol-dev/cyber_39](https://github.com/jagananmol-dev/cyber_39) | **Download:** [NCBA-Cybersecurity-Case-Study.zip](./NCBA-Cybersecurity-Case-Study.zip)

NCBA (Network-Centric Behavioral Analytics) is a local web application for reviewing machine-identity security telemetry. Establish a reviewed baseline for a workload, import later gateway or sensor events, and examine explainable alerts for events such as token replay, unfamiliar network endpoints, certificate changes, unusual activity hours, and request-rate spikes.

> **Important:** NCBA analyzes telemetry you provide; it does not collect live network traffic or enforce production security actions. It is a local proof of concept, not a production security monitor.

## Start the application on Windows

### Requirements

- Windows PowerShell
- Node.js 18 or later (Node.js 20 LTS recommended), which includes npm
- No Docker, database, cloud account, login, API key, or `.exe` is needed

Open PowerShell in the project directory. If you are using the downloaded project in its default Desktop location:

```powershell
Set-Location "$HOME\OneDrive\Desktop\Cyber"
npm install
$env:PORT = "3217"
npm start
```

Open **http://127.0.0.1:3217** in your browser. The server uses port `3000` if `PORT` is not set. If the port is already in use, choose another port in PowerShell and open the matching address:

```powershell
$env:PORT = "3218"
npm start
```

Stop the server with **Ctrl+C**. To check that it is running, open **http://127.0.0.1:3217/healthz**; the response should be `{"status":"ok"}`.

## Try it without preparing telemetry

1. Open the dashboard and click **Run local incident drill**.
2. Review the generated assessment, evidence, confidence, and local audit entry.
3. Note that the workload and events are clearly identified as **synthetic training data**, not a live incident.
4. To remove local telemetry and baselines, click **Clear local telemetry and baselines** and confirm.

The training drill is the quickest way to confirm the application is working. It creates a known-good baseline and then simulates token replay, an unfamiliar source and TLS fingerprint, a new destination, unusual traffic, and a threat-intelligence match.

## Analyse your own telemetry

NCBA accepts a JSON export from a gateway, reverse proxy, SIEM, or sensor. It does not connect to these systems automatically.

1. Export **metadata only** as a JSON file matching the schema below. Never include private keys, passwords, API tokens, request or response bodies, or other secrets.
2. In **Download known-good baseline example**, download the example and inspect its `events` array. Use at least **five valid events for each workload**.
3. Choose the file in **Telemetry intake**. Set **Verified normal traffic — capture or replace baseline**, then select **Import and analyse**.
4. Verify that the baseline represents legitimate, ordinary activity. If replacing an existing baseline, the dashboard asks you to confirm. Incorrect baselines can hide abnormal behavior.
5. Export a separate, later set of events. Choose **New observations — compare with the saved baseline**, and import it. NCBA rejects observations for workloads without a baseline.
6. Select a workload from the inventory to review its risk factors and the specific evidence behind its assessment.

The **Download incident observation example** uses the workload name `orders-api-demo`. Capture its matching baseline example first if you want to import that observation example.

## Telemetry file format

The file must be a JSON object with an `events` array. `workload`, `timestamp`, and `eventType` are required for each event. The workload name must remain consistent between its baseline and observation imports.

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

| Field | Required | Description and validation |
|---|---|---|
| `workload` | Yes | Workload/service name, 1–80 characters |
| `timestamp` | Yes | ISO 8601 date and time with an explicit timezone, for example `2026-10-10T08:15:00Z` |
| `eventType` | Yes | One of the event types listed below |
| `type` | No | `API Gateway`, `Partner Gateway`, `Internal Proxy`, `Legacy Auth Proxy`, `Webhook Entry Point`, `Microservice`, or `IoT Device`. Defaults to `Microservice` |
| `sourceIp` | No | Valid IPv4 or IPv6 address |
| `destination` | No | Destination/service name, up to 128 characters |
| `tlsFingerprint` | No | Opaque fingerprint identifier, up to 128 characters; never upload a certificate or private key |
| `requestsPerMinute` | No | Integer from 0 to 1,000,000; defaults to 0 |

Recognized `eventType` values:

- `connection`
- `authentication_failure`
- `token_replay`
- `certificate_expired`
- `certificate_mismatch`
- `rate_anomaly`
- `unexpected_egress`
- `threat_intelligence_match`

Each import can include up to **1,000 events** and must be no larger than **1 MB**. Timestamps must be no more than 90 days old and no more than five minutes in the future. If a field is missing or invalid, the API returns a validation error.

## How the assessment works

The detector applies transparent, fixed rules to the imported observations and the workload's explicitly captured baseline:

- **Behavior (40%):** strongest recognized rule event. Token replay and threat-intelligence matches score 100; authentication failure 55; rate anomaly 75; unexpected egress 85; certificate expiration or mismatch 95.
- **Temporal deviation (30%):** the larger of the percentage of events at UTC hours absent from the baseline and the percentage of events with request rates at least three times the baseline median.
- **Peer/identity variance (20%):** average percentage of events with source IPs, destinations, or TLS fingerprints absent from that workload's baseline.
- **Threat-intelligence match (10%):** 100 if the imported observations include `threat_intelligence_match`, otherwise 0. The importer supplies this finding; NCBA does **not** query an external threat-intelligence feed.

The weighted score is a demonstration policy indicator, **not the probability that an attack is occurring**:

| Score | Dashboard recommendation |
|---|---|
| 0–29 | Allow and monitor |
| 30–59 | Step-up verification |
| 60–84 | Throttle / investigate |
| 85–100 | Containment review |

Confidence is based on the sample size: **High** requires at least 20 baseline and 10 observation events; **Moderate** requires at least 10 baseline and 3 observation events; otherwise it is **Low**. A high score, especially from a small sample, is not confirmation of an attack. Review its displayed event evidence before taking action.

This is deterministic, rule-based detection—not trained machine learning. Baselines are maintained per workload, rather than learned from peer groups. The app does not claim a validated false-positive rate. Your telemetry exporter must accurately map its source events to this format.

## Local storage and privacy

- NCBA binds to `127.0.0.1`; its web interface is intended for this computer only.
- Runtime data is saved to `data/state.json` in the project folder. Set `NCBA_DATA_FILE` before starting the server if you need a different data-file location.
- The browser parses the selected JSON file locally and sends it to the local NCBA process. The application has no external telemetry upload or third-party API connection.
- Imported data may contain service names, IP addresses, and other operational or personal information. Only import data you are authorized to process, and protect the computer and its files accordingly.
- **Clear local telemetry and baselines** deletes imported events, workload records, and baselines. It deliberately retains audit history.
- The audit log is linked using SHA-256 hashes to help detect edits. Because it is stored on the same computer, it is **not immutable** and cannot prevent an administrator from changing the file.
- Keep the service on loopback. Do not expose it using a public address or reverse proxy: this local tool does not provide user authentication, HTTPS, or production access controls.

Older local state created by the earlier demonstration version is upgraded automatically. Previously entered sample workloads are not treated as real baselines; import and review actual known-good telemetry before analysing observations.

## REST API

The browser and local integrations use these endpoints:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/healthz` | Local process health check |
| `GET` | `/api/entities` | Workloads with captured baselines and their latest assessment |
| `POST` | `/api/telemetry/baselines` | Capture or replace a baseline from `{ "events": [...] }` |
| `POST` | `/api/telemetry/ingest` | Compare imported events with saved baselines |
| `POST` | `/api/telemetry/demo` | Generate a labelled synthetic training scenario |
| `GET` | `/api/telemetry?limit=50` | Read recent stored telemetry and baseline summaries |
| `DELETE` | `/api/telemetry` | Remove telemetry, baselines, and workload inventory; retain audit events |
| `GET` | `/api/audit?limit=20` | Read recent audit entries (maximum 100) |
| `GET` | `/api/audit/verify` | Verify the local audit hash chain |

Example PowerShell import, assuming your file is named `baseline.json`:

```powershell
$events = Get-Content .\baseline.json -Raw
Invoke-RestMethod `
  -Uri "http://127.0.0.1:3217/api/telemetry/baselines" `
  -Method Post `
  -ContentType "application/json" `
  -Body $events
```

To ingest a later observation file, use the same command with the observations path and `/api/telemetry/ingest`.

## Troubleshooting

| Symptom | What to try |
|---|---|
| `npm` or `node` is not recognized | Install Node.js 18+ and reopen PowerShell |
| Port `3217` is already in use | Set `$env:PORT = "3218"` and open `http://127.0.0.1:3218` |
| Dashboard says no workloads are baselined | Import at least five valid known-good events per workload as a baseline |
| `BASELINE_REQUIRED` error | Capture a baseline using exactly the same workload name before importing observations |
| `INVALID_TIMESTAMP` error | Use a complete ISO 8601 timestamp with a timezone, such as `2026-10-10T08:15:00Z` |
| Replacement-baseline confirmation appears | Confirm only if the new events have been reviewed as representative legitimate traffic |
| Previous demo state is visible | The new app migrates old state but does not infer baselines from it; import your own reviewed baseline |

## Tests and project files

Run the test suite from the project directory:

```powershell
npm test
```

The tests cover policy thresholds, detection against known-good baselines, event validation, unbaselined workload rejection, audit verification, data deletion, and migration of previous local state.

| File | Purpose |
|---|---|
| `server.js` | Loopback-only Express server, validation, telemetry and audit API |
| `telemetry-engine.js` | Baseline capture and explainable observation analysis |
| `risk-engine.js` | Weighted risk calculation and advisory response tiers |
| `state-store.js` | Local persistence and hash-linked audit history |
| `index.html` | Dashboard layout and instructions |
| `styles.css` | Responsive dashboard styling |
| `script.js` | Local telemetry import, evidence display, and API integration |
| `test/ncba.test.js` | Detector, API, storage, and security checks |
| `package.json` / `package-lock.json` | Node.js scripts and locked dependencies |

## Production limitations

This standalone local app **does not** sniff packets, subscribe to a SIEM, connect to Kubernetes or SPIRE/SPIFFE, retrieve live certificates, renew or revoke credentials, quarantine workloads, block network traffic, authenticate operators, or write to immutable storage. The `threat_intelligence_match` event must be identified by your own upstream system. The recommended responses are advisory, and the demonstration audit log is stored locally.

Use NCBA for local analysis of exported metadata and demonstrations. Do **not** rely on it by itself to protect production workloads or replace deployed monitoring, certificate lifecycle controls, or incident response.
