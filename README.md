# NCBA Machine Identity Security Demonstrator

**Repository:** [github.com/jagananmol-dev/cyber_39](https://github.com/jagananmol-dev/cyber_39)

NCBA (Network-Centric Behavioral Analytics) is a runnable proof of concept for the cybersecurity case study on compromised non-person entity (NPE) credentials. It demonstrates how short-lived workload certificates, behavior-oriented risk analysis, tiered response, and an audit trail can work together to reduce the time an attacker can misuse a stolen machine identity.

## Problem addressed

APIs, microservices, containers, and IoT devices authenticate with machine identities and certificates. Long-lived credentials can give an attacker time to impersonate a service and move laterally after a compromise. Certificate renewal by itself does not detect suspicious use between issuance and expiration, and some legacy workloads cannot run an endpoint agent.

This demonstrator brings the following pieces together in one local application:

1. **Short-lived credential lifecycle:** Configure a certificate lifetime from 1 to 24 hours. Analysis automatically simulates renewal at 80% of that lifetime and writes a renewal event; the manual renewal control is also available.
2. **Machine-oriented behavior scoring:** Calculate a 0–100 risk score from behavior anomaly (40%), temporal deviation (30%), peer-group variance (20%), and threat intelligence (10%).
3. **Tiered policy response:** Scores below 30 are allowed and monitored; 30–59 request additional verification; 60–84 trigger throttling and closer observation; 85–100 recommend blocking and revocation.
4. **Agentless visibility:** Workloads can be marked as lacking an endpoint agent; the proposed architecture can still observe network-derived signals.
5. **Controlled response actions:** Revoke, isolate, and restore actions require two distinct approver names in this demonstration. Certificate renewal resets certificate age.
6. **Audit evidence:** Assessment, creation, renewal, and response events are persisted locally in a SHA-256 hash-chained log. The dashboard verifies the chain and reports its status.

## What is implemented and what is simulated

The Node.js/Express dashboard, input validation, risk engine, local JSON persistence, response policy, approval-name checks, and audit-chain verification are implemented and runnable. The supplied entities are sample data.

This is an **educational local proof of concept**, not a production security control. It does not issue or renew real certificates, inspect live network traffic, train or run machine-learning models, block network routes, authenticate approvers, or connect to a blockchain. SPIRE/SPIFFE, Vault, Snort/eBPF, PostgreSQL/InfluxDB, Kafka/Redis, Hyperledger Fabric, and Kubernetes are architectural integration targets from the case study, not installed or connected components here. The audit chain is tamper-evident only while its hashes remain intact; it is neither immutable storage nor a substitute for a permissioned ledger. Do not use this demo to protect production workloads.

## Requirements

- Node.js 18 or later (Node.js 20 LTS recommended)
- npm (included with Node.js)
- Windows, macOS, or Linux

No database, external service, administrator rights, or `.exe` is required. This is a Node.js web application, so it runs with Node.js rather than as a standalone Windows executable.

## Run the application

Open PowerShell or a terminal in the project directory:

```powershell
npm install
npm start
```

Open [http://localhost:3000](http://localhost:3000) in a browser. Use **Analyze** to save the current risk assessment. The risk controls provide an unsaved preview until analysis is run.

To use a different port:

```powershell
$env:PORT = "8080"
npm start
```

The application creates `data/state.json` on first start. This file contains local demonstration entities and audit events and is intentionally excluded from source control and the distributable archive. Keep it if you want to retain demo activity between runs. To start again with the sample data, stop the server and remove that specific file.

## Use the dashboard

1. Select a workload from **Machine Identity Monitor**, or choose **New Entity**.
2. Configure its type, 1–24 hour certificate lifetime, certificate age, runtime-agent status, and four behavior signals.
3. Review the live risk preview, weighted factor values, policy response, and renewal status.
4. Select **Analyze** to persist the assessment and add an audit event.
5. Enter two different approver names and choose **Revoke Client**, **Isolate Route**, or **Restore Access**. Duplicate or missing approvers are rejected by the API. This is a demo quorum check, not cryptographic approval.
6. Choose **Renew Certificate** to demonstrate resetting certificate age to zero.
7. Check **Audit trail** for the latest events and its hash-chain verification result.

## REST API

The server exposes a small JSON API on the same origin:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/entities` | List workload identities with current score and certificate status |
| `POST` | `/api/entities` | Create a workload identity |
| `POST` | `/api/analyze` | Validate and persist a risk assessment |
| `POST` | `/api/entities/:id/actions` | Renew, revoke, isolate, or restore a workload identity |
| `GET` | `/api/audit?limit=20` | Read the most recent audit events (maximum 100) |
| `GET` | `/api/audit/verify` | Verify the complete audit hash chain |

The assessment request uses `id`, `name`, `type`, `certificateLifetimeHours`, `certificateAgeHours`, `agentInstalled`, `behaviorAnomaly`, `temporalDeviation`, `peerVariance`, and `threatIntelligence`. The four signal scores must be integers between 0 and 100. Action requests use `{ "action": "revoke", "approvers": ["analyst-a", "analyst-b"] }`; the approval names must be distinct.

## Development and tests

```powershell
npm test
npm run dev
```

The tests exercise score weights and policy tiers, the 80% renewal threshold, API validation, persisted assessments, quorum-protected actions, and audit verification.

## Project files

| File | Responsibility |
|---|---|
| `server.js` | Express server, REST routes, validation, and error responses |
| `risk-engine.js` | Weighted risk policy and certificate renewal calculations |
| `state-store.js` | Atomic local state persistence and hash-chained audit events |
| `index.html` | Dashboard structure and user controls |
| `styles.css` | Responsive dashboard styling |
| `script.js` | Dashboard behavior and API integration |
| `test/ncba.test.js` | Risk engine and API integration tests |
| `package.json` / `package-lock.json` | Node.js scripts and dependency lock |

## Source archive

`NCBA-Cybersecurity-Case-Study.zip` contains the application source, tests, package manifests, and this README. It excludes `node_modules`, generated runtime data, and generated archives; install dependencies with `npm install` after extraction. The archive is intended to remain below the 100 MB upload limit.

## Case-study architecture mapping

| Proposed case-study layer | Demonstration in this project |
|---|---|
| Preventive: short-lived certificates | 1–24 hour lifetime input, automatic renewal simulation at 80%, manual renewal control |
| Detective: behavior baselines and network telemetry | Four editable signals and a transparent weighted score |
| Responsive: verification, throttling, blocking, revocation | Score-based recommendations and approval-name-gated demo actions |
| Audit: immutable event history | Locally persisted SHA-256 hash chain with integrity verification; no blockchain |
| Workload identity and network integrations | Documented as future integration points; not connected in this demo |
