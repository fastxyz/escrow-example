# Escrow Example

Refundable payment flow with three-party escrow: Client, Provider, Evaluator.

## Overview

Enables applications to provide "refundable payment" experiences. A Client funds a job, a Provider submits a deliverable, and an Evaluator decides whether to complete (pay provider) or reject (refund client). The evaluator is always compensated regardless of outcome.

Based on the FastSet paper section 4.11, with naming aligned to [EIP-8183](https://eips.ethereum.org/EIPS/eip-8183).

## Flow

```mermaid
sequenceDiagram
    participant Client
    participant Provider
    participant Evaluator
    participant Proxy

    Evaluator->>Proxy: POST /v1/submit-transaction<br/>CreateConfig(evaluator: Eve, fee: 10%)

    Client->>Proxy: POST /v1/submit-transaction<br/>CreateJob(config_id: abc, provider: Bob, provider_fee: 100)

    Provider->>Proxy: GET /v1/escrow-jobs?provider=Bob
    Proxy-->>Provider: [{job_id: def, status: Funded, ...}]

    Evaluator->>Proxy: GET /v1/escrow-jobs?evaluator=Eve
    Proxy-->>Evaluator: [{job_id: def, status: Submitted, ...}]

    alt Provider submits deliverable
      Provider->>Proxy: POST /v1/submit-transaction<br/>Submit(job_id: def, deliverable: 0xca..fe)
    else Evaluator rejects
      Evaluator->>Proxy: POST /v1/submit-transaction<br/>Reject(job_id: def)
      Note over Proxy: 100 -> Alice, 10 -> Eve
    end

    alt Evaluator approves
        Evaluator->>Proxy: POST /v1/submit-transaction<br/>Complete(job_id: def)
        Note over Proxy: 100 -> Bob, 10 -> Eve
    else Evaluator rejects
        Evaluator->>Proxy: POST /v1/submit-transaction<br/>Reject(job_id: def)
        Note over Proxy: 100 -> Alice (refund), 10 -> Eve
    end

    Client->>Proxy: GET /v1/escrow-jobs/def?certs=true
    Proxy-->>Client: {job, certificates}
```

## Roles

- **Client**: Creates and funds escrow jobs.
- **Provider**: Fulfills jobs by submitting a deliverable.
- **Evaluator**: Reviews deliverables and decides to complete or reject.
