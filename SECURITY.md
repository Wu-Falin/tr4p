# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub's private
vulnerability reporting: open the repository's **Security** tab and choose
**Report a vulnerability**. Do not open a public issue for something that
could put users at risk.

Useful reports include what you did, what happened, what you expected, and
the version or commit. You will get an acknowledgement, and a fix or an
explanation once the report has been assessed.

## What counts

- Anything that lets a visitor reach the protected site, the dashboard, the
  install secret or the configuration when they should not.
- Anything that makes the trap execute, evaluate or store attacker input in
  a harmful way, or makes the decoy open outbound connections.
- Ways to make the trap exhaust the defender's own resources.
- Ways to get an ordinary visitor trapped by a single request.

Recognising that a site runs TR4P is not by itself a vulnerability: the
project says openly that a skilled attacker can. Ideas that make it harder
are welcome as normal issues.

## Scope and conduct

Test only against installations you own or are authorized to test. This
project is a defensive tool: reports and contributions that add ways to
harm a visitor's machine are out of scope and will not be accepted.

## Deployment basics

- Keep the dashboard on loopback. Reach it through an SSH tunnel or a VPN.
- Keep the home directory private and back up the seed.
- Run `tr4p doctor` after changing the configuration.
