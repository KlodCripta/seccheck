# English

<p align="center">
  <img src="seccheck_poster.png" width="500" alt="SecCheck poster">
</p>

<h1 align="center">SecCheck – Security & Integrity Check</h1>

<p align="center">
A Bash tool for Arch Linux that helps you read and understand system security signals more clearly.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Arch%20Linux-supported-1793D1?style=for-the-badge&logo=arch-linux">
  <img src="https://img.shields.io/badge/Bash-Script-green?style=for-the-badge&logo=gnu-bash">
  <img src="https://img.shields.io/badge/status-stable-green?style=for-the-badge">
</p>

---

SecCheck is a Bash tool designed for Arch Linux and its derivatives.

It does not introduce new scanning techniques and it does not replace existing tools.  
Instead, it combines real system checks and presents them in a clearer and more readable way.

The goal is simple: help you understand what is happening on your system without getting lost in raw output or generic warnings.

SecCheck uses three core components.  
It relies on rkhunter to detect suspicious patterns, Lynis to perform a system audit, and pacman to verify package integrity.

At the end of a scan, results are summarized and presented with a visual risk indicator.

If something needs attention, SecCheck can optionally run a contextual verification phase.  
This step analyzes files, packages and paths involved, helping distinguish between normal behavior, false positives and potential anomalies.

---
## Screenshot

<p align="center">
  <img src="screenshots/01_menu.png" width="300">
</p>

---

## Output

All output is bilingual.

Messages are shown in English with an Italian translation directly below each line.

---

## Installation

### Clone the repository

```bash
git clone https://github.com/KlodCripta/seccheck.git
cd seccheck
chmod +x seccheck.sh
./seccheck.sh
```

---

## AUR (coming soon)

SecCheck will be available on AUR.

---

## Usage

```bash
./seccheck.sh
```

SecCheck requires elevated privileges for some checks. If needed, it will request them automatically during execution.
The tool provides a simple menu to run a full scan or individual modules.

At the end of the scan, a report is generated.
If anomalies are detected, you will be prompted to run contextual verification.

---

## Requirements

- Arch Linux or Arch-based distribution
- rkhunter
- lynis

Dependencies are checked automatically.
If missing, SecCheck can install them on request.

---

## Philosophy

SecCheck is not an antivirus.

It does not guarantee that a system is safe and it does not claim to detect every threat.

It is designed to reduce ambiguity and help interpret system signals more clearly.

---

## Testing

SecCheck includes a test harness to validate the parsing logic.

Run all tests:
bash seccheck_test.sh

Run specific modules:
bash seccheck_test.sh RK
bash seccheck_test.sh LY

The test suite currently includes 57 cases covering:
- rkhunter output parsing
- lynis warnings and suggestions
- pacman integrity checks

---

## License

This project is released under the MIT License.

---

## Italiano

<p align="center">
  <img src="seccheck_poster.png" width="500" alt="SecCheck poster">
</p>

<h1 align="center">SecCheck – Security & Integrity Check</h1>

<p align="center">
A Bash tool for Arch Linux that helps you read and understand system security signals more clearly.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Arch%20Linux-supported-1793D1?style=for-the-badge&logo=arch-linux">
  <img src="https://img.shields.io/badge/Bash-Script-green?style=for-the-badge&logo=gnu-bash">
  <img src="https://img.shields.io/badge/status-stable-green?style=for-the-badge">
</p>

---

SecCheck è un tool scritto in Bash pensato per Arch Linux e derivate.

Non introduce nuovi metodi di scansione e non sostituisce strumenti esistenti.
Mette insieme controlli reali già disponibili nel sistema e li presenta in modo più leggibile.

L’obiettivo è semplice: aiutarti a capire cosa sta succedendo nel sistema senza dover interpretare output grezzi o warning poco chiari.

SecCheck utilizza tre componenti principali.
Usa rkhunter per individuare segnali sospetti, Lynis per eseguire un audit del sistema e pacman per verificare l’integrità dei pacchetti.

Al termine della scansione, i risultati vengono riassunti e mostrati con un indicatore visivo del rischio.

Se vengono rilevati elementi che meritano attenzione, il tool può eseguire una verifica contestuale opzionale.
Questa fase analizza file, pacchetti e percorsi coinvolti, aiutando a distinguere tra comportamenti normali, falsi positivi e possibili anomalie.

---
## Screenshot

<p align="center">
  <img src="screenshots/01_menu.png" width="300">
</p>

---

## Output

L’output è bilingue.

Ogni messaggio viene mostrato in inglese con traduzione italiana subito sotto.

---

## Installazione

Clonare il repository

```bash
git clone https://github.com/KlodCripta/seccheck.git
cd seccheck
chmod +x seccheck.sh
./seccheck.sh
```

## AUR (in arrivo)

SecCheck sarà disponibile su AUR.

---

## Utilizzo

```bash
./seccheck.sh
```

SecCheck richiede privilegi elevati per alcuni controlli. Se necessario, li richiederà automaticamente durante l’esecuzione.
Il tool propone un menu semplice per eseguire una scansione completa o singoli moduli.

Al termine viene generato un report.
Se vengono rilevate anomalie, viene proposta la verifica contestuale.

---

## Requisiti

- Arch Linux o derivata
- rkhunter
- lynis

Le dipendenze vengono controllate automaticamente.
Se mancanti, SecCheck può installarle su richiesta.

---

## Filosofia

SecCheck non è un antivirus.

Non garantisce che un sistema sia sicuro e non pretende di rilevare ogni minaccia.

È uno strumento pensato per ridurre l’ambiguità e aiutare a interpretare meglio i segnali del sistema.

---

## Test

SecCheck include un sistema di test per verificare la logica di parsing.

Eseguire tutti i test:
bash seccheck_test.sh

Eseguire moduli specifici:
bash seccheck_test.sh RK
bash seccheck_test.sh LY

La suite contiene attualmente 57 casi che coprono:
- parsing output rkhunter
- warning e suggerimenti di lynis
- controlli di integrità pacman

---

## Licenza

Questo progetto è rilasciato sotto licenza MIT.
