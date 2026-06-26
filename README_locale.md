# RBS (Ransomware Behavior Simulator)

RBS è un tool di **Purple Teaming** progettato per riprodurre le TTP (Tactics, Techniques, and Procedures) osservabili dei ransomware moderni. 

Il suo scopo è consentire ai team di sicurezza di testare l'efficacia dei propri sistemi di difesa (EDR/SIEM/XDR) in un ambiente controllato, senza ricorrere a crittografia reale o azioni distruttive irreversibili.

## Safety Model
RBS è costruito con un approccio "safety-first":
- **XOR Logic**: Utilizza XOR con una chiave statica (`RBS-LAB-KEY-2026`) per simulare la crittografia. Il ripristino è istantaneo e garantito.
- **Path Guardrails**: Blocchi di sicurezza integrati impediscono operazioni su directory critiche come `/`, `/etc`, `$HOME`, e altre cartelle di sistema.
- **Mock-only TTPs**: Le tattiche distruttive (es. T1490 - Inhibit Recovery) vengono simulate tramite log `WOULD_EXECUTE`, senza mai eseguire comandi reali.
- **Dry-run Mode**: Consente il tuning delle regole di rilevamento senza toccare alcun file sul disco.

## Requirements
- Python 3.10+
- Nessuna dipendenza esterna (stdlib only)

## Quick Start

```bash
# 1. Seed lab sample files
python3 rbs_sim.py --seed --target ./lab_data

# 2. Simulate ransomware behavior (reversible)
python3 rbs_sim.py --simulate --target ./lab_data --mock-anti-recovery --report ./report.json

# 3. Restore everything
python3 rbs_sim.py --restore --target ./lab_data
