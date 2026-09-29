# Atomic Arch indicator set

Bundled set **2026.09.27**, assembled 27 September 2026. Sources describe the
11–12 June 2026 campaign. SecCheck does not download an indicator feed.

The detection implementation is written for SecCheck. No third-party scanner
script or malware payload is bundled. The references below credit the published
technical observations used to define the checks; their source code, article text
and artwork are not incorporated into the module.

| Check | Interpretation | Source |
| --- | --- | --- |
| Exact tokens `atomic-lockfile`, `js-digest`, `lockfile-js` in installation scripts, npm/Bun manifests, npm cache indexes and startup definitions | Possible exposure. A reference, old cache or package name does not prove a malicious version was installed or executed. | [Sonatype original research](https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency) |
| SHA-256 `6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b` | Presence of the documented `deps` payload bytes; urgent investigation. Execution is not established by a hash match. | [Primary technical analysis](https://ioctl.fail/preliminary-analysis-of-aur-malware/) |
| systemd service with an executable in `/var/lib` or a local home, `Restart=always`, `RestartSec=30` or `30s` | A combination worth reviewing, **not** a unique malware signature. Legitimate services can match. | [Primary technical analysis](https://ioctl.fail/preliminary-analysis-of-aur-malware/) |
| `/sys/fs/bpf/hidden_pids`, `hidden_names`, `hidden_inodes` | Name-based heuristic; not proof of a malicious map or rootkit. | [Primary technical analysis](https://ioctl.fail/preliminary-analysis-of-aur-malware/) |
| pacman install/upgrade records dated 11–12 June for the four packages below | Historical exposure clue. Dates alone cannot identify an affected build. | Arch AUR reports below |

Arch reports: [gnome-randr-rust](https://lists.archlinux.org/archives/list/aur-general%40lists.archlinux.org/thread/L2JXQNYBGWOQQQXDEPEAICBHKFEFANUC/),
[workbench](https://lists.archlinux.org/archives/list/aur-general%40lists.archlinux.org/thread/P7D3YBLJKI5UF5MR7CCZ5EGEOXPWF7CX/),
[rtspeccy-git](https://lists.archlinux.org/archives/list/aur-general%40lists.archlinux.org/thread/OKMAWCX73IH4HXUCBGUNAW3SQJ3H4OWE/),
[exodus-wallet-bin](https://lists.archlinux.org/archives/list/aur-general%40lists.archlinux.org/thread/FGXPCB3ZVCJIV7FX323SBAX2JHYB7ZS4/).

## Scope and limits

`pacman -Qm` inventories foreign packages; this does not mean every listed package
came from AUR. SecCheck reads pacman's local `install` scripts and plain history,
common yay/paru/pikaur/pacaur/aura caches, npm and Bun caches, global npm installations,
temporary directories, system/user autostart definitions and local `~/.local/bin`.
Local homes are resolved from `/etc/passwd`, including custom home locations.
Use repeated `--aur-path /absolute/path` options for project or custom cache roots.

Default bounds: 20,000 files in total, depth 12 per root, 2 MiB per text file,
64 MiB per hash candidate, 16 MiB of plain pacman history, 180-second traversal
budget plus a bounded in-flight read. Each traversal and read has a timeout.
Skipped reads, exhausted bounds and missing history make the module **partial**.
Absent optional directories are normal; scanned roots and limits are in the report.
Hash candidates are `deps`, `install-deps`, `linux`, files in `~/.local/bin`,
and literal executable paths from matching startup services. This is not a full-disk
hash search. Archives, binary Bun lockfiles, rotated/compressed history, arbitrary
projects, remote/encrypted/unmounted homes and kernel memory are outside the default scope.

Files are inspected as data. No `PKGBUILD`, install script or payload is sourced or
executed. Symlinks are skipped; this Bash tool is not a race-proof forensic acquisition
tool on a system controlled by an attacker. A running rootkit can hide artifacts.
An empty result cannot certify safety or exclude previous execution/data theft.

## Italiano

Il set identifica tracce documentate della campagna di giugno 2026. Un riferimento
in cache indica una possibile esposizione; l'hash indica la presenza di quei byte.
Nessuno dei due dimostra, da solo, l'esecuzione del malware. I nomi delle mappe BPF e
le impostazioni dei servizi sono indizi da verificare, anche con possibili falsi positivi.

Il controllo è statico e limitato ai percorsi indicati nel rapporto. Gli archivi,
le cache personalizzate non indicate, lo storico rimosso e la memoria del kernel
non vengono analizzati. Un risultato senza segnalazioni non è un certificato di sicurezza.
