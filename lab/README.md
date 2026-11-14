# Practice lab

TR4P in front of OWASP Juice Shop, a training application that is
vulnerable on purpose. Use it to watch how scanners and automated agents
behave against the trap.

**Only on your own machine, only against this lab.** Both ports are bound to
`127.0.0.1`. Do not expose the lab, and do not aim attack tools at anything
you do not own or have written permission to test.

```bash
docker compose -f compose.yaml -f lab/compose.yaml up -d --build
docker compose logs main          # dashboard setup code
```

- Site through the trap: `http://127.0.0.1:8080`
- Dashboard: `http://127.0.0.1:8787`

Things to try from the same machine:

1. Browse normally. Nothing should be flagged.
2. Run a scanner or a directory brute-forcer against port 8080 and watch
   sessions move from low to medium to high.
3. Fetch `/.env`, use a secret from it, and see the session go to the decoy.
4. Press Release in the dashboard and confirm the session is back on the
   real application.

The lab needs more memory than the 512 MB default, because the training
application is not small. The default first run of the trap in this lab
keeps its data in the same `data` volume as the normal setup: remove it with
`docker compose -f compose.yaml -f lab/compose.yaml down -v` when done.

This lab file is provided as is and has not been run as part of the
project's automated checks.
