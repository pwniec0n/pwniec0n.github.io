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
const ct_serial = "eyJzYWx0IjoibFVQUXFHSkRMUmZwMHkxL1NXSDJmdz09IiwiaXYiOiJJQjA5YkRPcmZXSnh3MXlBIiwiY2lwaGVyIjoiVStzZ05DeHVpUWJGaFcyRDJNSGVRbGZUWm45Q0xnWTJIb3QxdkFBSXlBdm9reXd2ZW1abnRlL214dzRaanNXSitUQWhoV1Y4T1dnaDdNNzQ1VlNybGVueW9JWGpvdGdvVTVaZkRucERFYkhrclRiVThsZnFmUGhjV1R4YlFWTlhDcEVHc2Nhdk9kcWY0ZEVNRmh1WFFqc3pyandEL2xSK3lNVTFReWhRR0htR3d3WXhsTWdVUG5vM1dZOWJIZDh1eUJCdmtaQUR6KzRBUGZjQzVwclZXS3pKN0cxdHh0VG9tZ2F5a1VIYTJIODJSYzhqcS9oZURXajVkeXZmbVY1TVh2blNNcmFwTDhkb2JUZHF3OVlQemROaVRWcnJKTUtucEw0SUNxZWx6KzN0d3dwZFEzUFZOSmkxVFJFZGpobDVLbTVtNVI5RkJVcWhobVoyWU92MHIxZmhWeHJjUlNHcmxad0srVnNqcVkyOEVPQmlhU3RncUF1b09YSHZuY3JYVGEyOWl5aStHOE5INUNzSHJlZXgwaHlhQ3FpM3lRWVNwWlQzRjZZQ2pUbndhRTd3ZXpUaWF3OXdVM1VPdnBoTkZsdVFRc1FEeHN4clY1bmx6Q3hhR2ZkdHdGWjVnczlNaGxic2lleWdzelZUOWIxbGlsMzMxYnQyZXU5S0tFaVpoMUVEVkFzbFFHLy9oUmRtKy9ybnhlOVljZmZ0anZpL3oyRTVrd1M3eW0rRGNTU2E1dUNSZysrTGJsSXF1dW9JWTVITDk1VnpqcFFVS0VhWDlBdmFiMFltVkExRmt3aGNIYjJkNDRRZ0JKNVVUbUpCREFKWmNCWE15TEpOcEJocWhCRXRldVZMaVRPVUx4WDNxeGhDdGNRNFREb0ZDSVBTN05JdDEvNnpRYzFBdnZ1c0RyMnBzalJ2eTVlelZUUDI4NDBSdjRzbWxUUVBWeWV3K0NOMGNCM0ZjaFN0UEQyOTFhNU5YbDBYdVA3Rm10UUE4RFZJWWl2dzQ4T2g1MkVaMXVXTzUxdTUrYnZIVFl1SVRaMDUvVm42NFVVenBQWWdkeWI5QWpWbExJRnRTbmxuY2Jlby9xUUJPMFFmUzU0UUhNS215STNxcldGWGZXZ3kxR1BKSUNCVmQvNy80YmNaNTF3bmxreVVMOHFJZ1lxdlpkZ0kwZ2xpUlJiVkFPVWxKb1h3aTU4OGRmb2FqWHlIdXFSdzd4VEJ1RWZubmJjdlpFRTJrNjVzdTE0bENMVTk0RXVMbDF4bVJlNmoyQmlOU29UYkxpU2t5M2FpNUtGL0xLUk43VldrNFo3Y0JQcGlNRHRiUENWUmtBWGlCMFAxZFpqSE1rb3lzd3cxaGtIdkQrU1ZqaEoyZTQ1a0ZJZjVzWklDMk1SYjN5aGt6NjRiTVVmOEVWSUYxNWVRNml0WE1ubEU4RW12b3hqZnZpS3RFbUJacjVGcUZ4RUkvNW1FOENmNy9CQlNzUHJtWkl6ZmV2MDBncXl5aWlFS0dJTGZGZjcxaGFhcU53bitxRUJXMGUvZncwMnlRTE5LOC9IZDVYVlFJZUtDSDdYTFl3M1lBVXhxZnNXajZCVWp0QVNERStEMmdrWVFpazlLVXVhcTQwZEN4TlVES3UzWlo3VSt3TkM1Q2xNWDIrNldFU1l3b0xhbXdaWEhXbFl6Zno0Zy9DbWZkb1NxcWlvUlcxUmR5YStaL0ExaUVDZENydm5WTFlOQi8yMTlRdS9CS1hTQjFvNFBUMlpYU2tPaGJrdVZWOFpRVzdsQlJzc0hST2MrY3BTcjB3ZVRSQXVrSXdYajEyM3BFeHorWVlieGVlYU0vTDhRWk95MjQzdkMram5YKzN2NHphUXpublI3Ukx0R0xSN1hPQjAvK3FPVUthNWlVOGhERm5jYTcvYWVzaUtrM0VWSWxKUTg1SWJrU1Fjd3BEOGdEM1A3OHh2OWN4Q3FQSzltSTlYcTl1NFQybTVXaUVra0owT1hkRlNSTEF5WmdzeTU2RG95YXVPbWFCSWNkSDRKOTRnZmc0UGVXRUdxS2Z0Mzdqem80M05kMmxLWUY1VWlVTUJURXZERGQ0amhUZ1pUVHZNNjFMNHlBdktQc01mL0tNWVI4Qldoc3B2WHhWc2lOdW9SZ1A3TG5pL3MrS0ZsazFUTVdzK05JSHFJQXhrZFI2MW82enFyMFJldXJsY2tnTDFoaU5LOEh5WGpycVNyNTlBQUNvMzc0OFN5MFdhcHNZUGFqMmdodEZXR0RwbHV1MFRkQXhPc0hFU3daTkVEUDBNTFNoRU55cjZFRWJkTVZScktGSmlEMTkwLzNYYnZKRXhrTHVlcllyOE5EdGY5Z1RSbDBJS2FKQ1pWUlpmUEw2NGZpTDl0dzlpMUtZM2h4YmwxWFg1WStIR1dEYTZ5bks1c000WHdZaDNXR3JiY0VRRVhneE5mdFg3TWxRK3FtZndqdld1b1UyYVdYUEVJaEp0MzdNRGJlS05vblpJNkIrVktydnh5d1N2WTVaRWVLVDB2aFlNTCtGSUd4T21LTDZjYnFYZnV1R1BHUjBhL3BjSmxBWThxMlkvcklva20xZUwrNTEyNXpybUlnYndCc1hBcmJaeGk5THE4bTZPMGNPNENodW5YVnZvNzhETThXRVhtOENxRTY5dUowR0tTVW84YVJJMkxCTHBHTm9SbDlUYnFiTnRQamVkR2swVzY1ZGZ5b2pTSU43a0ZUVlJxb0FRRXVBWW5PM25QWkQzQUFJd3VjY28xWTVuekx5UUVrbGVxUUluRWptTDZBMGpWMEpCanhFSjcrV2NKWGVlbVRwaC9nNFRlTnNNQWdaQVhQYm43WHU5VndlR29CMitSd0NEcjNUYm9ZekFkVktwU0dOMEpvL3Z3dm1YMkpDQTNsWnJ6c3hXQXpKR0NHRFhYZWRMakwybkhtSWlJNk1NaUV6SjQ5V1ZhUmFJV3p1a2J6WUdzaDR2em9NZzFpK2JCdURpZ3c3b1pDZVFQeUh6SUlVYjBLU2YwdTRDWE1XZzdJc1h2TDNkdVRMMEJFaFgybkhmeHhldHAzaEdMWkxpb2lGUCs3TitJeTFydnRWVmJkQU4wbGNlOFNQUDJRdlJNS2JTQWdoZWZlQkF6cUhSTWY3L1lPdjdITU0yR0gvTVJwSjRqRXhHcEJSLysraTdPbDlaZ0hGMTVqbXhTMnkwUHRwNGJ5K000ZjU3KzI0K0M4RkZ0c1RkblhXR2szeEFwTjFEVUludlhZT2dDODJkWnlFSmVZZzN0aWh5VGR5MjZNQzF3ZGJTeVZpRWk4MTBwaTRlUFZ5c3o0N1JnZllkalArQTFPaDU5d1hQZG5pTlRRTTZnQVAzLzVmUnpZdm5JUmxOc2k0THNyOERKTU5ZOXltakFvdTRTSndNWjN6QlVvWWNWM1RHS0E3ejBFUzJJOVB4WG9maVJZSFN2MkZJdE9XK2RpWVU3TDNvSlpYYi9YNUhVOFllZTJIY2l2cjg2NHF0ejZ6VjNtQXRNZ3B3WU4rMzhVYTBoa2pLYWZ2K3dQcWRDM04rUnFzVVJvNElQc0ZBVUc5bkFVNnFCbEVLZXd5c1dUczQ2VThwQ1V3TkZ2SkV1QVZ5VkpPWmo2RjNhNVd5M3FOWDhYa3Q4OU1oWmZLbU90ZXU1UlpFNFdveDFNR3MrandIOFNJa3h4KzZ6VVB0UWZaa3ZDZmgvdW50SzZiS1VDUCtMRVVsbGFzeWJFWjN0aEt4Q2xWNGxaMmtQVGlHN3ltbDVIYitCbTdjbE5ndFUrQ1ZmcGV6TTlUWHlCdTJKcmZDRTBjaGJDeFcrWTRGUGpRenJOQXBMM3hLQWFrSDFBZTdtci8yWWhaeUl2OHM5ME1OZVZNalE4SWsycTJ3eGVSd0hGYU9DTzE0WkhjZHZoaHhCL0R5L1Y2MVJtSnZNMTk5dTMvVXc4Q0JGU3pFZ01rbUp4UnRDK0E4WVlOcklZWGExaWMyU3BrWlhQVmRaSDV4Yk9WK0swdjhLTTRZcWVxWmVzcHRUSjFpNXU1SngybkxJWVUzVFN3WTQyWEQ4RlRMd3pHV3dKUmtnbmRodFZpcVduWm15UG5QYTUrSU4zby9GT0ptTEZwd3p3YW9HRnI1NVA0UHhpVFpWTzB6SnExa2l5SklwWnVuYjdTYnZJR2FlZzB0T0ZGeDZxSVJPUkwvbHdzblNTT0JCQ01OSzcyM3dXNEtkK0dVay9uY2Y1ZHhTTE80cnVTWkw1aHZXcHo5ZitpK1oyRHlBV2VKdmNZdW9oMFVuYzhCQ2VocEVhMHUyU1FTVXlpWWZwNExVdWpKR0pYU1c3ckkxNGZtMktoZkpnUi9ja25UNGVjS2lQZjZDdDBLRmJiTkVFdnJkcklkUjFMSE15TXVzOENDYnk3OTFMVEl0bzkwOTgySys0ZGQrenNHUEthOWVhZWc3OVI4cE1VZm81YzFUcSt4dUFPbUpOdWVpZ2VyVTJpekxEeTU0MXBjZFlSR0NVT2o4dHp5TlBXODVSWGhQV1NjZ0tocjFoTkxNdXRrYVdXWTMwSDJ4MzdSdzAwOHF0VkR5THNPdCtRQ0lWSllPUFdNai9vaVBNVy95bHcxVkwyK2NVa2FLakhaTFVLOTRSSmJTNjZKSWswd213QjduOHlpdEJaLy9OL2daTmNYZ29wUHZLYUV4aXFZZmFZZXFKK2FxbnlwcWRpR2tZQnJHYm9nNjNtOVZ5Q1liTGNKMldqSUlmano4Z0NpUGNRYzA4d3V3S3JJSkZWUlZGUlZpNXhrSUVLa0QxLzNFd0ZnQXFmcU5YVUZERkJsaThtL0NqcDNTYyt3Smkvc1NhNkZ6NGpkUnZOeGpDeEduZmlhblZFRTJsSFlEbFVxQklPMlpaUVNmNlNYVGhvNGs0VW5kb0duWHBVd3NQUkNDVmQzd2pJKzRYYWdCNTNhUSt0MzRHRnRsR1QxNGNCWWtWZm9LTGxHN0czWkZpbWdXcXNCU1J4eXhkdlAxZmhOUGxOTjhxcjJlR1BqVDVDa1E1N095OHFWTVRGMTRwVVU1UzBNQlA4eWJ4VFFSS243QXA4UmVlSWZDNHhWUXUyWVpBYllLMDhReHJmQlQ3bHluaGFrUlNMUmF4L1Q5Nk1ad0NPUnZhcWxGN1h0WmMrSEg2T0pCKzVyaGpmNGlON1JwUjRLc1ptc0MxK0FRNy9OcnhzWTJLZ3FydXR4UmE1VTFQMHdpQmZxT1ZkK1BuUTdKLzV4WHBuL1dTSW10dWtnYjVCU1hFM0x0RkhJMzBoMzFlMi83NDNMTTBJQ05WYWM5dU1ISXNKdEdKdXc3Zy8zWFV5NERsRUhWWEtkN2ttSlZhZ0NqY01lK1RHaVJ4bUpFN0txbjZ6azQzVjV4MmlURHIzL2F3VnVOOVZEa1FXSVhVTGY2T0gzZ1NDczIzaklRajQxUFZPQWxJZjRqWlNaWGVYWDZOK21FNllzc2JYbm9DY042VC9zbHovSDVxQUh3cHpaZU5NTjE2VW1POC9YWStueFdDcmtINjJmRURlQWE5NGM4T01sZTJBVDM3MEtVSi9YTlpjWW9pcXRsa0NCb3FDZStEMnJJOWd5SHYyZjBrdDRWazUxUytKVFZXczJDQVlFMUtsbEhtV3FueWZUdEdBbngvQ2Vpd09BZ1gyVHhTM2YwQWlmdW41aFJ3VU8vL1JFVTRHZjFWSlRLa0V2SytHcVJWSzZkK09vRjlxZG4wb0k3VXNhakdPcUxBeWJYeHNXb09OZXR2cmNDenFwY2s5Q3ZXc05QOTdqZk5lSDhaMldLZEtkYWNzWjVqOWE5aTF3ZlFZZ2NFVTI2MG1ZMTZWQkZ5QjZTa1NDSmtjUE5YR2dxWHNhK1N0ZisxaUdscTZlMURndWtsYWdXYzd0NjBIU3k4K3VMWlFBMU5TQ0dqTlZkOWlqakN0K2UzcVVjSzdTdlVNZ1AxVERrR29waHNWMmEzOGRWTEtFaXdFMFVWbFYyakRjWUVHK3RIekEzU3hwVVZaNXcyN2VrZ2txNHVEM3MwN1V4cTVUTEUwekRwTTdpc3ZWSkZoTEpYRm9vNkZqeVh6RWFPNFpUWFdHZlpDZUVBcnJ0aFh3RnVQTUdmMmR0Qy9XdFlaYy9hbXgycHRHMWlqMlRraFNsUXpTM2JtNnd3bFZKK2hWcUhaY2RBeXZrcVNBTG5qTXhQRDdLTmYwbVZvREF6Wis1ZTQvYWEvU2k2clYyM0NjSXE0TURhZis1dGl4b3FCZzZJZHUrZHA3MkNZeTJlbkdWMHFnRWpBd0lVeXBaVnZNY0xiVFRUYmhjaklnOUdxN3JyQzVHTnVvRHkyNkhya01LOVNKM2hJRUR3Q0FJOCtMeWo1YzlYclhsbXNGOWtOak10WXc3QitEMDZkN2NBa2lyaGlYemo0VEh5Zkx6aUswbUJXVmJyZGJocjB1ZEl5N0ZTRWNjTVFoL2ZMRGlBTjZwcVN4ZHl4TWUyNEJLYk9HSUhkdCtlLzVWcmNNa3ZxN014M0IzRlJFYWtIUENMYkNOZnZHcmdEVDBGUVpWYTRXcnMyUjVWekxqb1JUUlc2RUU1eTMvRUZGVWZ1QnBOeGhsbG1QV2lneVNxSUU4bFFnRkhRNWoyYkEvY2NIRFpDUGplZ21pZERFUnVIelAzVG5PRkl4d0VQa3VjdEtxNmlXWDQrOVRGOU52RFVhc1NFOXk5WkloYS9HQ3Y5Y0ZnQTZIZWlWd3JpVXhKUE82NGsrWVNHeVVpQm1CTzc1ZmxydzliMFpXSGZpNmV5VG5pZWtaVTZKZC84TWFlSHl5TmJEdkJHaFN5V242STFlZlUzRy9VaDdpK3YxczBaQ1JZZmNHbm5FK0kxNS9lbk5rNlRlbGVKRWNWZXdxSjkrNnEvbU5xcGdiditaRGNhcGphQjg0aEJORks0QkZ3Znl6MzQ4S0xaZWRXbGc5WVVwcGJWTm1mRXFVakVQa1VvSlhUSEdldC9obXI5VDdoVExkYzg2ZjR5cUlBZXJnTlU4R29yUStyeDdtUlg1N3FKaUF3cnNBZVJlL2pUd1FESHhSWkRqbjZVdVdCbXRWRmhjZGZBN3lUT1J0cFBJeUtDMlhQSEYrQ1V2b2sxN2IzWEk2TVAvTDhHOGsvTVIxQlU2cjZydWFtNDc2QmlsQThRd0FXbWRKUXNVcDB5d0JkNStjMmdMR3VBb2NaK1Yxb240N3RabVBCVUlhaTdjb0E5SGFtRUplemhGeFVVcjNFSDRLZmd5emVOZi9TMzV5WFlpTmVXdXlESFV6Z0psSFJOOTFkdVE5S3ZpUloreHdaeFVnZG15TVNwdmxpOStGSzJBZkJNTVVSRHVqM1RwYVlXUGNCRkdKYW9LSVFwVHM0VFNWd1VVbFJUbHpnTXQ4UjNLYnFRREhwaGhINjlnSUxXcGx6QmRUTnhOWXBVRDV2azBPNlpnYWlZMTNuS2VLOE1tTzk3U2dJRTFqZm0wenhmaXZydWFENzZUbXJHQ0dmRmZVc0xoOTgyMmFYWmxYNmZXTzRncVkyOUkvbUtMWisvYVRaYVMvZHM3VXFnTHFOeVVIZ1l3MllpdUpKeERYMWdHdFV0SWxDMDRyUzJ6bHNCQ0ZUMG9LbCt1Z2dmTnJZZ3VCRTRPNW9KZ3g5YThXT0ZGeEs3WUtta3IzRDRjM2tDQTVSeHVYZnM0b2N6ZWs4ZVNhMS9qQnJVYUtFV0pTMlFCbk5Pd1J2MUZuT0RGZmdZN2VFeU1LUzZQQ3lQZVRIVHFxaFFGVWo4cUUzOWorUnNBQ05FUXJRRVJGMjhtUkhPang2aUg3OFFpWmgxb29sSmE1MjZ4YUJ1dS8xWjh6TW82cWJzVDh1TVAxVUVnS1hqWm5JQVhJYVZuYTNYRk1adnVFNEVkUWE0UXdIOThxTHJ0NzV1S1RIV1lRSE9IQTZWSGhibjBnZjlHY3A2VHV1Ukc0UThmTmJyVTFlYmtlNjYxdWZjckk5TVIyYll6dGpOZ1pLaWUvaDJ1R21JTGhocjljUllEUklpYzFURnVFYlBXWEozM291MDR4NUxuaURtUk1mVm0zNkZHS3RuTmxXb1ozOC9BQVhiMkV0UkIzd3ZVWHR6eDZtOGdNY3B2M3c5WVV2Yy95UFFaL2MrRHQzanpGaGplTFpDR3p2T0NObzBQNTlSUTQ0MEc0dW9jbDFLZkphWlNlcitMMmVhc2QzbDlCbUcxWHpzQU1mUXY0dXVZNTkwZGlpNHFhM2N3VVN6L1lXeUViY1hvSHpjb0RLSG1ySW9rMm9uZEs2UkxBbVF0L2dUdUZQOW5qc1hnbnZoVDFGZDloK1NBM2lDbkUwS1N3bUxpVDY1V21ZNEdnQmJXNHR1bXNyVUZOYWNnQy92SzNQaEZBOEdoNDNIcjlIMUZvL1YzQlJ2dVBiYXBrOWMwK01DWSswK1FjYmZoM1pLcElFUWI0QUFGdXRBOER4ak0wZk8wRyszLzgwQ3BFWDVKY3RyL29GempWd0E2V2VaUVNMdlR3cmxxVjlZN0s2YkpMaWtRQ2ZHQ1pPQUFQbFFSazNScVhwbGtIYTlJSk5KTzhYWFZCcW9PNVd2SHJ5ZVJvOFhpNnV2UENWZXBZZW5IaUtxNStOWmxKWU5SN3YrQUd4MlY5QkEyWklsbDRyQjdTNUVTQzM4ZkJkTktMZVhsQlNnSEhNZ3JESXRMUC9GUC95Mk55ekxEek1ObVpaa0FxazZtb3BPVWtIdHByWEprSyswNjAremYwRzZVazJseS9hSVN1NUJUTFRUaG52QUF2Nk9pcnYxMmZwY3cvSTNqSzUyTUdRZGxLZVRvcXlwWHBHMXVvMU9xUDdwcUlLbGpyTFF1S3RuQS9SMmRkRDhkaVBBdE9sVjl1MStNVGtjbmI2am5mMytFL0xVZjR6T2RmMWYxVWlnSjlsTUo0Mjh1dDBXa1NKUUpMN1ZxZ0JGUlV0c1FCeXlPTjVkSWRwK3JnYkZxWC8xamRuQW9RS0ZhRUJhdklPWU5uNEprbTlvWWpWMTZMdk9WazFLU1U5cnJaWGVoa0xucngyY1RxTlNSaGFxQXU5YkVTa204MDFRMkRSMGZacDJleEVxV2RVbnZ3U0FVQlJlY2I3K3RtZm1ZcXVlVzJwOEVuTTBmeHBJK3lrdzd0akR6cnlhaHVnT2FUeGVLT2V1d21HYUg0cHNyckEzWlRNTlBYMHJ0TlRkNXJBYmdmWU9DUUs2blJENGh0VjlSL0RQcG5Oc2hWVnVoYzd3ZVRybWtobldTNWlyUmFQTW44RkN6a2Y1NWVhVCtubUFPeXMvSWlOM0FMZno2aVlKN0o3U3I4Ny9aN251Q1NjZ2xNTEhHT2FYWmNNOTlKNUlzQ1EwNlArRGU4elhETUtDNVhES2ZhRThHSHFPaTZQM2R2RnByV3k1NXVNbW9VdU9OZXlmcUpsYWpYeVMxUmRQYkNmc3U0SDk2OUNNWnp6MlhIMnN6NTE1QldRWnVQUTZpUnFGSzhMSFZ1VU1uMEtWV3JtYUdRRDZORXcxc1cxeWZzL0o1VGp4NldnU0ZVYW1RQVM4c1c1cnhSQ1Q3blJBMk9zMzRyUzQzUFBtNVdKa05BSEU3Z2piTWMxMlhPeGViSDNPZ3FPSUh4T2dkWHFpY3A3OGdjQ003WCthTW5ZYngvMVFzOE9nK3l4cnhJMEZpaldSRzRyU2REMUxDQllDMVRGMTZ2ajI3a2lQSUZmSU1kWDF1L0ZEeGtKSDRQVi9DQWJpS3lyNUIzVU5nLzR4WStPcXVDWlZHVVc1UFNIVU4rc0tURFo4M0lOek5STU5COXZPN0Y0cGVFQ2xtV2gvTG9QSG8rZmhIZU9MVnFFbW13RTNDSkovcnlMZ1oxS0FCclA2cXF2Y1RucStDajRVNDdVbkJOajFwWUpvSS9LZzZqVDZETEFQQmg1UGg1R1dHVDRUb21mV0Q5WXNTS2t6T3pxeFhJOEtGOFdzcHFOL2JEeFU1SFVSelNuVkx6THNtdkJ5bStnNDNOVEtiVFNZbkp5WUhjYmszZnppMXVmUVhQTG9tcCtLU1hHNnBvTmlBY082aGMvZUVKY2NUQSs1MWEvMzRBRFozUmxrQ1p4ZExSejZiL1lnNTFuY2l0ZXZoSWFDT3F6TzNIVmkxdTE2NHBiSjZOYnFLTk5CNTBDejc5bGxIcmxqbzNkR09EN3M0c0xRZWtCNUVVK0h5NUtkeVRqSFYvOUNjekZHcklpa0R1dlA5U1plZFJDMWY4ZGFpbFZkMVRiMVlNQUZST0FRPT0ifQ==";

async function revealContent(inputPassword) {
  try {
    const ct = JSON.parse(atob(ct_serial));
    const decryptedText = await decrypt(ct, inputPassword); // Await the async function
    document.getElementById('contents').innerHTML = decryptedText;
    // console.log('==== conents below =====')
    // console.log(decryptedText);
    // console.log('==== conents above =====')


    // Regular expression to match <script> tags and capture their contents
    const sre = /<script\b[^>]*>([\s\S]*?)<\/script>/gm;
    let m;

    // Iterate over all matches and capture the script contents
    while ((m = sre.exec(decryptedText)) !== null) {
      var ns = document.createElement('script');
      ns.innerHTML = m[1];
      document.head.appendChild(ns);
      // console.log(m[1]);
      eval(m[1]);
    }

    document.getElementById('password-input').classList.remove('error');
    document.getElementById('password-input').classList.add('success');
    await sleep(1000);
    document.getElementById('render-container').classList.remove('above');

    document.getElementById('password-container').classList.add('hidden');
    document.getElementById('about').classList.add('hidden');
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