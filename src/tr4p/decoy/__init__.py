"""The decoy: an emulated application served to sessions in the high tier.

It runs as its own process, started with an empty environment in an empty
directory, and is told only what it needs through its standard input: a seed
derived for it alone, the look of the site, and the fake secrets to show. It
never sees the real configuration, the install secret or the protected site.

Nothing in this package opens an outbound connection, reads a file or runs a
command. Every page is text computed from the seed.
"""
