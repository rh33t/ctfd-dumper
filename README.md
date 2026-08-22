# ctfd-dumper

> Back up a CTFd event to a Markdown writeup repo.

A command-line tool that turns any [CTFd](https://ctfd.io) event into a local writeup
repo: one Markdown file per challenge (description, hints, points, tags) plus its
attachments, ready for Git or Obsidian.

Re-run it during or after the CTF: it fetches only what changed and **never touches the
solutions you wrote**.

Needs Python 3.11+ and one library (`httpx`).

## Install

```sh
git clone <repo>
cd ctfd-dumper
pip install -r requirements.txt
```

## Run it

You log in one of two ways.

**With an API token** (CTFd menu > Settings > Access Tokens > Generate):

```sh
python main.py --url https://myctf.ctfd.io --token ctfd_xxx
```

**With your email and password** (it asks for the password):

```sh
python main.py --url https://myctf.ctfd.io --email me@example.com
```

Files are saved in a new folder in your current directory, so `cd` to where you keep your
CTFs first.

## Save your login in a file

Typing the URL and token every time is tedious. Put them in a `creds.toml` file:

```toml
[ctfd]
url = "https://myctf.ctfd.io"
token = "ctfd_xxx"
# or use email + password instead of a token:
# email = "me@example.com"
# password = "my%pass@word"
```

Then just:

```sh
python main.py --creds creds.toml
```

Passwords with `%`, `@`, or `#` work as-is, no escaping. **This file holds your login,
so it's already in `.gitignore`. Don't share it or commit it.**

## All the options

Run `python main.py -h` for the full list.

## What you get

```
~/ctfs/myctf/
└── challenges/
    ├── README.md                index of all challenges, by category
    └── crypto/baby-rsa/
        ├── README.md            the challenge, plus a ## Solution section
        └── files/chall.zip      its attachments
```

Synchronization state stays outside the dump in
`~/.local/share/ctfd-dumper/<ctf-name>.json` (or `$XDG_DATA_HOME/ctfd-dumper`).

Each challenge page starts with tags Obsidian can read (`id`, `name`, `category`, `value`,
`solved`, and more), so your dump works with Obsidian Dataview.

## Good to know

- **Your solutions are safe.** Write them under the `## Solution` heading. Everything above
  it is refreshed each run; everything below it is left exactly as you wrote it.
- **Broken files self-heal.** Each run re-checks files on disk, so half-downloaded ones get
  fixed. Files over 100 MiB are skipped with a warning.
- **Your token stays private.** It's only ever sent to the CTF site, never anywhere else,
  even when a download redirects.
- **Removed challenges are kept.** If a challenge disappears from the site, it's reported
  but left on your disk. Locked ones (`???`) are skipped.
