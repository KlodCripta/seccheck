fixtures/ — Snapshot di output reali per test di regressione
=============================================================

Uso:
  Salva qui l'output grezzo di rkhunter/lynis quando cambia versione.
  Poi esegui il parser manualmente per verificare che regga ancora.

Esempio:
  sudo rkhunter --check --nocolors --sk > fixtures/rkhunter_$(rkhunter --version | head -1 | grep -oP '[\d.]+').txt
  bash seccheck_test.sh

File consigliati da salvare:
  rkhunter_1.4.6.txt   — output rkhunter versione attuale
  lynis_3.1.x.txt      — output lynis versione attuale
  pacman_qkk.txt       — output pacman -Qkk versione attuale

Regola fondamentale:
  Salva sempre l'output GREZZO, senza grep, senza pulizia, senza modifiche.
  Se ripulisci i file perdi gli edge case e i test diventano inaffidabili.

Nota: questi file contengono dati del tuo sistema.
Non caricarli su GitHub se contengono percorsi o info sensibili.
