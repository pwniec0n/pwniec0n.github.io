# pwniec0n landing page repo

## Additions
2026 - developer mode to simplify dev workflow

```
              git-tracked
          js/content.enc.js
                  │
       content.py decrypt
                  │
                  ▼
       decrypted/content.html ◄── EDIT THIS
                  │
             browser preview
                  │
                  ▼
        decrypted/dev.html
                  │
        content.py encrypt
                  │
                  ▼
          js/content.enc.js
                  │
              git commit
```


# C0nvention

The protected HTML content for the site is committed only in encrypted form.

Production content is stored in:

```text
js/content.enc.js
```

Plaintext development files are generated locally under:

```text
decrypted/
```

The entire `decrypted/` directory is excluded from Git.

## Setup

Install the Python dependency:

```bash
pip install -r requirements.txt
```

Python is only used as a local content build tool. No Python web server or application is required.

## First-Time Migration

The old version of the site stored `ct_serial` directly inside `js/crypto.js`.

Copy the existing value:

```js
const ct_serial = "...";
```

into:

```text
js/content.enc.js
```

After this initial migration, `content.py` manages `content.enc.js` automatically.

## Start Development

Decrypt the current production content:

```bash
python tools/content.py decrypt
```

Enter the current site password when prompted.

This generates:

```text
decrypted/content.html
decrypted/dev.html
```

The entire directory is gitignored.

## Edit the Site

Edit:

```text
decrypted/content.html
```

This is the plaintext protected HTML.

After making changes, regenerate the development preview:

```bash
python tools/content.py refresh
```

Then open:

```text
decrypted/dev.html
```

directly in a browser.

A local HTTP server is not required for the current site.

If browser security restrictions are introduced later by new functionality, an optional static server can be used:

```bash
python -m http.server 8000
```

and the preview opened at:

```text
http://localhost:8000/decrypted/dev.html
```

## Encrypt Changes

When the content is ready to deploy:

```bash
python tools/content.py encrypt
```

Enter and confirm the desired site password.

This reads:

```text
decrypted/content.html
```

and regenerates:

```text
js/content.enc.js
```

using:

```text
PBKDF2-HMAC-SHA256
100,000 iterations
256-bit AES key
AES-GCM
16-byte random salt
12-byte random IV
```

The browser derives the same AES key from the entered password and decrypts the payload locally.

## Check Before Committing

Run:

```bash
git status
```

Normal content changes should show:

```text
modified: js/content.enc.js
```

The following must never appear as tracked files:

```text
decrypted/content.html
decrypted/dev.html
```

You can verify that Git is ignoring them with:

```bash
git status --ignored
```

which should show:

```text
!! decrypted/
```

## Typical Workflow

```bash
# Materialize local plaintext
python tools/content.py decrypt

# Edit decrypted/content.html

# Regenerate browser preview
python tools/content.py refresh

# Open decrypted/dev.html and test

# Encrypt finished changes
python tools/content.py encrypt

# Verify only intended files are tracked
git status

# Commit
git add js/content.enc.js
git commit -m "Update convention content"
```

## Utility

Check the state of the local workspace with:

```bash
python tools/content.py status
```

## Repository Layout

```text
.
├── index.html
├── README.md
├── requirements.txt
├── .gitignore
├── css/
│   └── style.css
├── js/
│   ├── crypto.js
│   ├── script.js
│   └── content.enc.js
├── tools/
│   ├── content.py
│   └── dev.template.html
├── images/
├── svg/
└── decrypted/
    ├── content.html
    └── dev.html
```

`decrypted/` exists only on developer machines and is never committed or deployed.

## Security Model

GitHub Pages receives the encrypted payload and browser-side decryption code.

Knowing or downloading the JavaScript is therefore expected. Access to the protected HTML depends on possession of the password and the cost of deriving candidate keys.

The raw password is not persisted in a JavaScript-readable cookie.



copy real existing blob into js/content.enc.js

python tools/content.py decrypt

gives
decrypted/dev.html

```
decrypted/content.html
          │
 content.py encrypt
          │
          ▼
 js/content.enc.js
          │
      git commit
          │
          ▼
    GitHub Pages
```




