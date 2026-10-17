# Quantum AQRS Blockchain Simulation

This repository demonstrates an Adaptive Quantum-Readiness Scoring (AQRS) blockchain workflow. It compares classical ECDSA against post-quantum Dilithium signatures, measures signing and verification overhead, builds a simple blockchain of signed transactions, and produces results, charts, and API responses for inspection.

## What the project does

The codebase has two main execution paths:

1. Offline simulation via `main.py`, which generates transactions, runs every signing mode, computes AQRS scores, saves `results.json`, and writes plots into `plots/`.
2. Interactive Flask app via `app.py`, which exposes API endpoints for signing, verifying, and inspecting transactions and blocks in real time.

## Workflow Overview

The end-to-end simulation follows this sequence:

1. Generate transactions with randomized sender, receiver, amount, timestamp, and risk level.
2. Classify each transaction as `LOW`, `MEDIUM`, or `HIGH` risk based on amount.
3. Run the transaction set through five modes:
   - `ECDSA`
   - `DIL2`
   - `DIL3`
   - `DIL5`
   - `AQRS`
4. Sign and verify each transaction in the selected mode.
5. Add signed transactions to the blockchain and mine blocks when a block fills up.
6. Aggregate timing, signature-size, throughput, and chain-size metrics.
7. Compute AQRS scores relative to the ECDSA baseline.
8. Persist results to `results.json` and generate plots under `plots/`.

## How the modules fit together

- `main.py` orchestrates the full offline run.
- `transaction_generator.py` creates synthetic transactions and assigns risk levels.
- `signature_engine.py` wraps ECDSA and Dilithium key generation, signing, verification, and AQRS risk-based selection.
- `blockchain.py` maintains the blockchain and auto-mines blocks when the pending pool reaches the configured size.
- `simulation.py` runs the full benchmark for one mode and returns structured metrics.
- `aqrs_calculator.py` computes AQRS scores for each mode.
- `visualizer.py` creates the comparison charts and summary table.
- `app.py` provides the web/API version of the workflow.

## Offline Simulation Flow

`main.py` is the best entry point when you want a repeatable benchmark run:

1. It generates 100 transactions.
2. It runs all five modes over the same transaction set.
3. It calculates AQRS scores.
4. It saves a structured `results.json` file.
5. It generates plots in `plots/` and prints a summary table.

The generated `results.json` file includes:

- per-mode totals and averages,
- per-transaction records,
- chain size and throughput metrics,
- computed AQRS scores.

## Web App / API Flow

`app.py` exposes a Flask service for interactive testing:

- `GET /` serves the front-end `index.html`.
- `POST /api/transaction` creates a signed transaction, verifies it, appends it to the in-memory transaction list, and adds blocks every 5 transactions.
- `POST /api/sign-message` signs an arbitrary message.
- `POST /api/verify-message` verifies a signature for a message.
- `GET /api/transactions` returns all stored transactions.
- `GET /api/blocks` returns the current block list.
- `GET /api/stats` returns aggregate counts and average signing times.

The API version keeps state in memory, so it is best for demos and local experimentation rather than production use.

## AQRS logic

AQRS is the adaptive part of the system:

- `LOW` risk transactions map to Dilithium level 2.
- `MEDIUM` risk transactions map to Dilithium level 3.
- `HIGH` risk transactions map to Dilithium level 5.

The AQRS score rewards stronger security while penalizing signing, verification, and signature-size overhead relative to the ECDSA baseline.

## Requirements

Install the dependencies listed in `aqrs_blockchain/requirements.txt`:

- `cryptography`
- `dilithium-py`
- `matplotlib`
- `pandas`
- `flask`
- `flask-cors`

## Setup and Run

From the repository root:

```bash
cd Quantum/aqrs_blockchain
pip install -r requirements.txt
```

Run the offline benchmark:

```bash
python main.py
```

Run the Flask app:

```bash
python app.py
```

Then open the local server at `http://127.0.0.1:5000`.

## Generated outputs

After a simulation run, the following artifacts are created or updated:

- `results.json` for structured benchmark results.
- `plots/` for individual and combined charts.
- Console output with the summary table and AQRS scores.

## Notes for GitHub

- This repository contains a nested package directory, so the runnable application code lives under `Quantum/aqrs_blockchain/`.
- If you want GitHub visitors to understand the project quickly, keep this README at the repository root and treat it as the main entry point.
