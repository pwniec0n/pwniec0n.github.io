// based on: https://blog.elantha.com/encrypt-in-the-browser/

async function encrypt(content, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const key = await getKey(password, salt);

  const iv = crypto.getRandomValues(new Uint8Array(12));

  const contentBytes = stringToBytes(content);

  const cipher = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, contentBytes)
  );

  return {
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    cipher: bytesToBase64(cipher),
  };
}

let decrypt = async function (encryptedData, password) {
  const salt = base64ToBytes(encryptedData.salt);

  const key = await getKey(password, salt);

  const iv = base64ToBytes(encryptedData.iv);

  const cipher = base64ToBytes(encryptedData.cipher);

  const contentBytes = new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher)
  );

  return bytesToString(contentBytes);
};

async function getKey(password, salt) {
  const passwordBytes = stringToBytes(password);

  const initialKey = await crypto.subtle.importKey(
    "raw",
    passwordBytes,
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    initialKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// conversion helpers

function bytesToString(bytes) {
  return new TextDecoder().decode(bytes);
}

function stringToBytes(str) {
  return new TextEncoder().encode(str);
}

function bytesToBase64(arr) {
  return btoa(Array.from(arr, (b) => String.fromCharCode(b)).join(""));
}

function base64ToBytes(base64) {
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
}

// other helpers
async function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Encrypted Content
const ct_serial = "eyJzYWx0IjogInFTUUFlM1pOV0hZaUtNWjR0ZUc5UXc9PSIsIml2IjogIlh2MEJsZjEwb2pNNHY2V0EiLCJjaXBoZXIiOiAiZFFtSDRMbWM4dWMyZW9vS0ROUDdIK055OUpiUktPSWNBSnFrZ0lnb1F6OFZnZDdIRlJlclozdlJsSEE3eUpwS2pUMElleVh6eElCMDhDRnZiQTBxUjZXSitsR01SbWNpNWh4S3FSZ1FoMUtoTHR6bXc0NTFwTEF0eEFkd09MbGpvTEl6bHdDbHEyeVhzbDZGTVRrVVhJNFJlRU9SWFRnYis4bkZtUDNabWFrVzg4S0hlQXJjVGdJdUxuSTRZSU11enVpUHJSbnRPU2tPSmlJMXM3TzdBN1laajBHWXg3Yjg1emp2NkwzTEs3TjBCME5IREpicWNlQkNsZS8wb0FQRzdUd1lpekcxNlQzcHIzTzllTzNXek8vWExvWmQxd3ZaMm1DZkpIcTh3S1JWdGZ0VVpIcHg5SHA0c1l5UldFYWlnS2VOS1ZwcER0eG41YUtDdzdTdmwwQlFUWmZHK0twNWJ4TzJ4ZjJGa3d5eUtDK081a2p0MWRqZXNFb2EyL1NReVdZNHQ3S0pSUTNtUnd3d2l4NThIUUVPbG1RclF1R1hmandvVVE1dE0ybEc2TTNML0JCUFZiMXNERVNPNCtUcVBYZFR0SXFUb09BQUFNYWNnK2wrNEFKWmFCSDl2V29Zd1BpNUFHZTg4ZU1OZ0ZXS0t2R1NydUhodDZsM3JvZGRsUGw4NSsvY2xPU3JNamxjWENLN0EyZjZNelNrWDNhR2FVNXRGdnVKWTZjMENlMUJIV2E5MzVmNU5ZUU54ZnIyL2ZlL1ptNFJhQU5HdHU2eHN4b3hqR0NyQkhhR000YXBaUW1yZnZPR3dLWlpkd0tZU0FHdTBqWU84QVVFSC9DWitmekFxZXNXcmVFbS9OWkFEQ3ZTMGhDb1c1M3RJN1hEMUpnUmNZSnR6SWV0VmNyTlJjZ3ZVSGJvWjF2TkplakN1bFQwc1J5NkZTVGpWVlpUeXRobllmbWNNaGlqKzcyNWlzeEg1MTJ5Y3hjSEJrenlsdGc5aFE5VmdPQkJvMk83T20zZmpad2lXU3FSNldKajBvdU0zRmlFVWp6emFNYzRiTHorNkpZVVB4d0ZoTUU2VGdpVEdWb1k3SEc0clRUY0hGT2pNbUdMR09oQmxzcXRPTTJnN1JoNVFLUnNVRVF1VzFqMm1PSjk4Tk45dS9FNzlvbW1uSHNtYjZBVmlVdlNTWnYvYksyMVg0eVJJZ3BNS3JaZEVvaXI2VHNURkZvWFNFNzkrdXdueGFQWDViZndkMmZubWtodzZSUGxDSTJYNTRxRWd5TmtEMUkwWXpvQzNSUllaQktmUnVoSENrZGdXN2hqdEdVSHM0ZHFaM1ErWGw5cThEWEhtT21JSldLd1dCclNDS0NYK2p0Q1I3MGFqQ2piR2dMcGZQWks4NDJsUkNqV1d2RkJrc2x1VmxRT3d6L0NSN2FhZTBNbzhPOGdpQk9ic0hTRVp6ekZvNFg4SzBZc3I3RElmbGRDN2lpTWw5QU5LNmlMZmF0b2trZnhNVWJiekxQTWQ0dHR5TElhUzk4SWQvOFlabGFRbXFkWWttSStXSmJpb0hkK09FZjZlVGNGZXduUmtsbGQ2Qlp6YlhOL2VkVDN2TG5SZlJPbExiT3NHcEFidUJSMEdPN0tkSk1venFLbzZUNDM1aTBwWEZodE8xTXdjS0EzMGlxcEkwUlQ4RFAxUU5HcDhGQXNXY3pyY1V1V0F6NXpVSTBpTDlzbWhmb3B4NjlMREhWUlNrcEVYYnZkK0JNZlI3c2ZTUzZRN2ExUFpWWDNETXl5ejg0SGRMdFo2UXhjTzhITWZmUlRicVZhamp4UmUxNkZDdCtwSjhNNFdXbjJSZGdGRzBCQ2N4MkJneEM1RGpqRnBYdTZvOCtPYm01QmRDNSs2NHcwRXNlM3IrbThWVGIvS05UZGtVb2h0LzZoTmJEaVZNNHZQcDY4elM0RS9rckRGTEx5SkloTTM4ZXRTM0ZxLys4VFc5aTB5b0hqQzNEWXEzQ2xvanBWNVlmYzBJeURkMXhxek1zakx0T1BqN3o4cEhUK0NFd0pwUm9FVThybGdVS2REYXNQWlNRVUovTlhHc240RHU5SmU4UnVNMGlkVkJpd3BkVkgzQm5FVWhtZWllT3BuRUN6ZGZRZU5qd2s2SzBHbU9VLzZqSEFrSmFJL0xaOUUvTS9RWlg1SVZOZ2lrRVNSeXZCaDU0d3E5SllsTVJaczdva015ZTM0NWh5SkNQOU1SbU1manRtMjdRQ3Z2VTFWWFk0aDdyMVpyZ3FCdnNJMjRjdVRSMG96Nm9IVGdpbEVUR2hJdTgxNTNRSHhqUmF4WDhhU21abWVzQzF4QUc4cjc5ZVAvTGtXQXlINlRIczZHMFd2Wi9HcU12REtXQ3A0VzFKbVZmajZjU1hpMXhPTmlZaGwrRU1JdytCMWFiSkhEVHdROGxrUUkxK1lUNDdoNVJNWXBMYURpaWExR1cyWkZNcmZ4Znk4Y3lmWU5qTlNUbUwyWkozUE5oRGtTaTZZeHBhd1FqRUV3YTkzWnArbVpRQmxSTG5mM056THh0amVJcng2M2syb1hyR1ZwcmtEQkJmRkdpSVB0MHpqckxOVzJPQ0wrc25CSlRrRlpEREh6VlNaanFpYnBFM211Y292NzhhcGxpOGVpRGVHT0U1WVQ1cFF1WFlkNFEydTM1UjhGWHFKeXJ4QncwV1luRHNESnNHVXZGTENKbHY5elFJbmZWZ1E2OEFiZXVmS0FsMVAyemw3OVc3WDRYQTR4Qk5YeGdWZXN5MC94cGdJWmszU1VETGRpUm5sTzJsUXg4OGdOd3IvcTJmbkpUWDkweGwzSnUwZHBjZmpwOTZQeWN4cUt3VXYybGxHZnBWdTFuQWVzNi9UMTJQaHJaWFV2WGJJdGhtYnV3a3hpVDhocGVETGZxQmhTd2NYM0pUYi9BTjg3L3dvaU93aEErVXc2Y3dad3JMd2dOa1JvYjY3Y1RyeXptSW5TNkhxYm5hY1ZjY0ZtaEJwTkd6Yy9tYnBtazFkUjFCSFNBdmQ2NFR5dUdHdWxRbFBpSXNFbjd2RHU5YU1ZTmFJODJiWmlJZnBZQUMyL3I5ZTQxUHd4TlFsUmNndjduOGlDZElQelhzaFdBWW1Ja2x0RFo0ci9EZTJrVW5ETVdGd1BQc1RaTXBvM1cvQ0o4VXJWVUc5UHU3MEYzSCswQkU0alBYT04zU2lOVVEvWDhzMi9tUmdoaTUzYW9zdzRuRDlmb1VCaXBIa1lFeE1ISHlQc01qZUlsZk9XVWhEUFp5TUhBM083RU9GeEhJbkc3NTJwa2hKS1lPZEY3Z212QXdpeCsrcnhVZ2RnMkdGR1ludGRsZ2xXVVNQOUJoY1Z3Ri9rNnk5SGZENnNET0Y0dURGL0M4VU9JK3MvdFlFaERGQTVWSWxJVDRKeFNqVmRHNjc2azg3eXdiRlBnb0NWY0FoeDExZ1ovelZxSmc2bFg5RzcvY05XQ3lUeW9sdTAzaFVYY00wQ0NDRWVrVGtKZGNmWGhjcytOMlRQUXhvQ2dMdjZQczB4L1FZeHV5NGNzWXkra3ZjaEZvTzZYdzlBUUZYcjRIKzJUSVV3K25vVTAySTA2dkpnY2VCUGpGYm9LU3QxR1FKTmZxUy9OSUFiajVxN3NlTW1BWnJiZ0lhdmFVMWp0WlB5WkdXK1V3Z1VsUC8wTVRXanBFZGRYdzJJWDdXc0NNQTB0aVF6MDVQNXh5WmxrdWhvVjV5WkJzZDdOTDRUaXUvbmFHWlN5NzVwWVZQZUJaTzNvTjk2RG10RWxkbFBha3BQVTNFTXRvRnN1ZytGSTIzTXJWMHRLSDJlTHJOZUR2RlhPSlpOckw3V1Y0NGpqVDNtUGhsZFFTY3RYYS9qUm9CcVVDT0MxejJQSDlFKzhUWGI1RTBWZDhjb0VDaEhsWGdNMkk1bE1YVjBJTW9XaUM3b2d3VjdoaU4yUDBlVDNVVFdyTmZVRTlhQjlrMW5ja016dEM3UW1PNmNDUjdIUmFtSDNocUdjemM4YW1Dak0wdlpHZlFhVld3TW5wRUlNV2FHRGZzSjJNK1Q5R0pNRnhPMUZNMVp6V3dBQjBPV1pPTU5GVzlqZHdIVjNESDc5SGhUakZCRDBoQzZKZDV2c3Z6ZnVUUWp6MHIxYmJLbXl5dXZOaFlSMDZEcThvbk5OQjhrRGVGWG5UeTd6enZGSVNtQThVRWxudWxnL1NXZmlPL25DR2lxaS95YjdBdzM1d09YL0hpV0hOYkVwYzZEcnNoNjZ1Z2ZXNnJERFpuQkw0RS9LN2l4WTI1WnRleWFiSkxxN3ViVnYyTXphdzBncXJOd0lMUFE9PSJ9";

async function revealContent(inputPassword) {
  try {
    const ct = JSON.parse(atob(ct_serial));
    const decryptedText = await decrypt(ct, inputPassword); // Await the async function
    document.getElementById('contents').innerHTML = decryptedText;
    console.log('==== conents below =====')
    console.log(decryptedText);
    console.log('==== conents above =====')


    // Regular expression to match <script> tags and capture their contents
    const sre = /<script\b[^>]*>([\s\S]*?)<\/script>/gm;
    let m;

    // Iterate over all matches and capture the script contents
    while ((m = sre.exec(decryptedText)) !== null) {
      var ns = document.createElement('script');
      ns.innerHTML = m[1];
      document.head.appendChild(ns);
      console.log(m[1]);
      eval(m[1]);
    }

    document.getElementById('password-input').classList.remove('error');
    document.getElementById('password-input').classList.add('success');
    await sleep(1000);
    document.getElementById('render-container').classList.remove('above');

    document.getElementById('password-container').classList.add('hidden');
    document.getElementById('logo').classList.add('small');

    // set the password cookie
    document.cookie = "password=" + inputPassword + ';samesite=strict';

  } catch (error) {
    document.getElementById('password-input').classList.add('error');
    console.error('Password incorrect');
    //alert('Password incorrect');
  }
}

// Set up the event handler
document.addEventListener('DOMContentLoaded', (event) => {
  const inputField = document.getElementById('password-input');

  // check if the password is stored in cookies
  if (document.cookie != null) {
    let cookies = document.cookie.split(';');
    cookies.forEach(element => {
      curCookie = element.split('=');
      if (curCookie[0] === 'password') {
        revealContent(curCookie[1]);
      }
    });
  }

  // Input field event listener
  inputField.addEventListener('keydown', async function (event) {
    if (event.key === 'Enter') {
      const inputPassword = inputField.value;
      await revealContent(inputPassword);
    }
  });
});