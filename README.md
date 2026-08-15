# pwniec0n landing page repo

## Additions
2026 - developer mode to simplify dev workflow


`python tools/content.py decrypt` to create `content.html` (editable)

`python tools/content.py encrypt` encrypts `content.html` and inserts it into a javascript variable.


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




