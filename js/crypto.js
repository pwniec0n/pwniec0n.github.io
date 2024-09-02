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
const ct_serial = "eyJzYWx0IjoiQ3lKYzBObWNqaklPRjdFeXkvUEJFQT09IiwiaXYiOiI1OTZjNU00RnlPRWVaTDIrIiwiY2lwaGVyIjoiMDRMTFZ6Q1kzS3Vkd0VqbSs4QkxIaHc0eDJicnVJUkFxN1ZMZmRuaitVNmF2dE9kbWZoQ3JDUGFCcFE1a25PK0M0eE4wTjhLREpRYjdJS0Z6SGo5WWJCUGZXTmVIYW53UUlNMnlFa1YzQ2wyUytON0UxWXprT2Z3TGJ0emZXbXR6UmljS1VybEJ5S1FvYlBhbXNJK1JlbVYrbzVsZDJadTNuTXdmZ3J5UVFHalJla1NkUitQZldKeEl6WXBlZFJaRmIzTE9CUlRhSVJmNFVXM2cvQUpKbTh5dXo5KzRKYjhJRWw1aGJ0WE5wZURQenhwYmllK0E1bnY1c3FMRkxRWUVjbHBoRzhnNUdtVkpabGZXaVJBNG12b1J3L1FDQVJRc2NkZGs3dk83YXJxS1M4a2UzVGlPOEZQOURkMjVYMDRXZmVQK3EvbFF6ZlQveVc0bG5MdWM4V2tTTyswTVZzMkMzWjhHT3pEZ3Q2Q0lkN3h1bmVldFR3d2U1NDNYWXBuSTFTMUQ2aE9rbWlJOUZvbUNjU29yRlpVRjNsdzdacFJyeHM4R1BENkRKbG00dk1OdVhmZU10SnFQdysyZEpGWC9MSEJ0T1NOYmV5VXVoY0FHQzN3Ui84YWRjUVBWRDRBTkdTdUJVUjJWanoxaXplTWNJazBFTlhhUGlrNnpyak9zZkdKK1BKL3F5d0t4YWdMQ0dRNGVVTjNpWncwNGN3Zk5ZZjRNR1V2cHk4YnVZbUpaVzhpTTBwbjFpSndNclFQbHBRTlB1NUdCbVErMGV2NDVPeGpaUE40T3RIRUkvdVdUNjAzQjdjbUhBQnp0K3JrbVlPelBQSjJoaVBDd1VlRzUwQWZKRGJCZzZmeVp4RzhYaUc4S01Ya21GMWZDeW41b1hPb3pXVUdNS1VFdENwNnpkVWpQRUlWUFVzSFE5dndmQnRXYkNja2ovTHpwV2NtZE5UMW0vSEhCMkJ3bVlBZlVxbXUyTmFNMUplQ2YwUmdBSGw1U1RaODFsakhZU0pzc0xvRUVvQ1haYnl0RDNjSDB6eXhuK3BNM2MySTJkQTUySE1paFlPa0pyeUtLZ0FmOWFFeVY3ZG9zRjk0bkNvZXlFUC9KNTZFVW1SdUFKdWRGMUs1NENsSXE1bnNxbVk5dUhidVFxOVA5SS9FNFNsbGpxQmUzcTVQQmlJaW5URzg3dENncjhxbG5hMTROZ1huZGlRamtRSkQzMUpybjlVUGhrbEQ2cUkxUjNaV1h4VUJtbXdJNHNWL0ZRZEIzeWRoUThlRGRLaXgzMGVubmVIbVBIdnlrS2preGdLMGs4dnovVzVsakxmdjY1RE5XaExOZlcxMU5vdXdrYStYakZ2U0YwamFmTTNXL3BuUjhHaTRlS0ZyYm5tVVRNL3BLN1pQQSthUW5FdU5KVWZTNndvRXRTYjkwSmxvNTQzaWliZWRWblZYQ3YrdXdHQ1o2TnVlSjRhU1p6bTlxNjZyeUdPUVZEZlE5QjRaMFNNUm1jRVlFcm8zcmwremlJSFZ6UjNJK3lCWGNSSDB2UGlJRGVCdFVscFZtUURKYnBtL01DaGsvZXJrTC9qZUdldll2YkR1cmw4VGhoenk5dVNWcnRzdlVlK3BDZVB3b2h4Vkc3SXdRU1U3eEkvRjUyZElNMXh0eVZ4L0RuSVEveDczbmdpYk8vK3gzZUpFYzFFZDV6c3YydGlpWEtkTzlCSzYzUWd1R3JnSDluak1sUDE5VkY1M2VwMDBYVmd3MitVbk04eXFiMTZQeFpiWUhDTjd2cFdCTTNkb01XdkxuRHJvSExjZHFmWHVSWCtvbTVPamxEQng3SUNUSWczMDVmTUg3V2FHdHFGYnlETm9JdlMxcFVHY1FiTGZIcjB2YnAyUWYvcHJCcE1IeGpoWnpkeWlNY2IyWnZJTzBjY2VBWklHdGhGM1VSSnBGT3V3UHduVERwS09wQ0k5dFduYjJlWFVsb0NFSnR0YUJsN0RFNUR5V1dVd3VtRGhza3dOM0JrZWVMWGtBM1h6dk5SVTUvU0pEVlVuSHU4Rzh0WmdTR3lMRGVzVzFjaURwZEdqTUlVSGhSNCt1TndTZ2ZnaUxDK0xta0d0eXBvRlRHdDh0OWJ6cjNNeW5XWjlZeXBnT0hNbi9hMEJ4QmxNNzRUWHJlbGtuUEZZVXE4c1BNSFNhM3hMdzdaeDJpNDRQaW51Rk0vTEpqa2Z6eng4dDY5RWRGa09VNVVOWG5MZEJTb2Joby8vTElCeUYwUy9HYnc1T3dvcG9KRXM1S1YrQzRzQ3A3b1BOWkZSVGJhcTZndHRsYjljT2k2Uk14bXloTkdabE9xbFpFbjhOS3ZCVkVzb1JMZ0d6NGVzNnR3MlNLbXppYzYxUFpibzYxZ0RKdjRBVGRJWithNTdGVllncG1iU3A0bUkvdnZsd0taeDhPYWtRNndvYzg1eTBka2s1ZElGblROeUUrb1V4RUF6dmVyRGxoQUpBeFdMUkRPTW9LY3QwMkx4bVFLTk1aV0dpd3VoMFArQUM1emlKcUdwbEo3VmNVLzBuRzBPMVhGZ2VIRDdVZllKT3preHVybzBCMEptcE8zbHpZeER4dUVyV0ZBd1hmV2JzK214ZS9xRGtQLzJFd0hxZVgyZUxUVVB1VFlLWkdHdFptYnZBa3VVQUhSTVFOTXFNb3grWkhiamJUWHV6NlZBRmZUanNVUGJTcWFTRENIYnd0WDluSXlLYXpwWUJDTnl3L3gzVzJZeGtLMGhHVjFBN29acTlRYTVSdCtmcFl1UkJpN0p3Z29kYWN5SFRpNytzN1pTSURyYXRzVFdSR244UTJIb0ZQRGFSUy9nL2U5RTE0OXRHUkFVQ214dmUxYXVCejlNcnZmaVQwVXdYbE5iT1kwOWNhdGxHdDVKeVp1Q1l2QWgyekRxSVdsSEFwZXNMS2o5cU5aUXlxZjM2Lzk1K1BQT3VLa3V1SU9pc1dCMmlJMVVrellCN2UvYkpYN3pPZmRSWnQ4NWMxYXRMb09GblBwbzlNN2VWcUhsT2tmc05mYU9FWlZwMDlsYzNmV3l2N1QrZUxSQTFuZ3I0MCtkeFlnK3J4c2FJTWkwM3kzWDJReS90bytLSE1za3cvZ1RqMlREMTlsbHBHNmFTTlRiSXd5S1JEMGdZZURBbE1Dc2JXZTBEdzBrb0V4aDRCL2JyYjJORXJIT3A0Y2JJbzRPUjZNK1lrU21vUzJ2TGl6M2g5SW5WMzVrY3NkY24rckVCaFg3Zlc0WmdBNi9TK1IxYTFXTmdaSys0Zm1qWHoyYno4d3JxZHBQR2VNY09GMDU5aEVMT2c0cWpMdFkwSlhPTldWZUpyRno1MTJlbnRqRmxPTnRFVmllRmE1WFc5OEpSZ0JmOHVwQllDZnhKN0ZvaklxeHEyWER5aWxxeWgweFBSQ1RZVllUclBodUl6dWxrMVAyZzNMUkEzajNIc3lLRkY0bjA3NGtONFU1ZHVUOXFORk1yemdYakVjenkreEZua3lTUktXR1E2WVRFdDVkZ3JzZk9SQmY3eVRpMkdpbjIzK3FxT0wwbC9jUlBKamtldXRvSk9NQUQ2Q2taMW1QU2w3d1VsOHREUnZvTXNFOCs5TjUybjk4Q0VSeEM5RjFIWTlkU1VGemIzdkNpeU9Edm9mUFRpeDBMQU9VRWVNbU1nNkwwVlZKM1UzR0ZKd1NBMTQ5UFZpNHVSbFAwcmVURnprMGhBSmVaNlpuaXFjOEtRTWpGcTRqZWNVVTN5M2xSbktNM3RFeDBLVjhqVDZGOThQOVhVMHVVMFZmMkkrVUpiZXBZSlcvUERseUMrN2F3N0FvOHRRSHhjS2J1RXh4ZG5IRHZKOW5tZXNVWHVqOXpTTWxnd0NLem1WWmpleUxuTzZQdE1ndnVTLzA1MDJWampSR2V2WDRNS0d1blBML1cwTlVCRGtNTG9Tbzk4WVI3QWYyaG9YZ21TMXNVSk9jd0JyQzY2cDFTU3AySlZ2UUMwcTZEL3c2VERnTTgzV01abHNkMkd6c2RUQTdtQWVBKzM2aSs2V3FYL1J2bm4wNXFUWEpmdGprQXgwUU5uNzdmQ2s2TkdWRHVhQUd6aGhWWnFqbFNsekNabVNLSnNseWZPczNhTFZSUUM2RjFEaHBnRmpMb2k2VDRyQ3pYKzV2M045bU9ZMTlzb2Y4bkZTckxHM3BGamlsRTg4YVhXcS9ncm9zOGw2N2F4NXlPQ0FwNVlnbi9yMjhRWGRtN0x3VjdFK25BeEtwU2t4L3cvaDdKSGt1SDlJVHhZZVphTEw4b29tcVpzSlRvaTBjSWJibnI5UXl1WDI3QzZRbHJ4Y1c1Z0tSWEhmVlR4Q2Y1Z2k2VlFKS0g5dlUyQ3pKRENXd096TWtodmdldTRJRkFJVWtWVWoxVnFkdC85dXNpVENVcWRGYlJDZXpXOU9qd1EvU09xOXJvNFU0YS90c3ZpcjNXNG9jRmRSbEJONlVLdUhEWTBrU1N0UXorRWlwRnhmeVllblhlZHNaY3hLYml4SmpuZGE0OUsvT0xoZ3RxNWsxSjF6QWpMdUM2S1FOdGgyUTdaaGdlVFJWbTlJbWFYK3Bhai8wVDI1dlg1ek9ac0djb3NuTXdkS2puT1JDTzliMUY0bkxmVEkrN0llckRYYlZkbVhzZGJ0S1JpV2JqM1luL0p5WHlzRnphR3Zqdmo2YnZDRldvclFtWFhzU3UyOFFDZjRZaEdQSEpHTS9NYzZ5WTZvb2h3ajhrOXhBd2xkc0dRbUZSTDI4dTlna095OWhmM2Rxb0VRS2NnSHdOV0ZlRG5nZzdkalgyWWlTRnUrVVRrZmZYR0RQMmc3WGc4K0MxOWxmU2RnWjlndFkrMXIzQXZEdTFiUVVrNlY3eE4xL25UUFFJSUVRTCtLMkovN1JpRmFjVUpzRUZWeVBZN1IzQjFTbUU3VWNSWW91MGxVK25hUmo4blR3bGdGeVA0VDJJMndkM1NGM3VYMThiM3JmNG5vL0tOUENGeFVGWk9EUVFMemtscnBkOWVONllsQ0VWUzZjMFhpZGw1VFpzaVBsUDdCcS8wSUVGdUpQWGJUaStpOXdzZW55anE1L2I5V2FZYnArQ21tbkVLbDJuYms0ZHNScktXQlFkUWZycllHd3g1emdVTTZYdWpsTi9rR0pVTTdLMjlBeDVyeXJWOFIrOFVtdDIrbVF5d0FJa3U0OExhWHRVMEFEL3Ftc0xscExLOTlqL2NTUDlYa0hsU3V1WWZ0Mko4VlhzaFRjUjEvZmZlcVVzc2lZek50RW56QnoySGJ2TTJpU1YzMkUyWllXOUVHU1ovSjlDTDR3NGxJSUtMWWZrZFkvZXZtTlR0WEZ6R0ZnOHJnVC9iZ2FTNFFaZVNJV2lVdmpEeDEzMS9MOWM0UjlVUWVOQW5nMVNyK3Z5WDVPcDhHbVZHSEFrbi9uaVozVm0rVDhYRGpPaDM2eXJ0UFFUc0R6Q09sTEFlQWtzTlBxS3BSdGlsZ0FLRjNWRjRONW10WndRQUJQYjBXSHpOcHBVcGpXeHZ1WllabVZRU3VpTmk1ZmlncWExQXZKQWNCZmRqZFBBdlN3OVJIWjBHc2trblluRlE3U2VQNndxbVJwTkQvYlhlZFNpNmZYb0Q2UyswNWY4T1Z4UE9IYnJiYmdpQ2x0RTc2ZXZCNGhHSVIrQ0Rnb2hkRThBUG5EK1ZwOUc5UE1qOUJjR2hidE5aamE1UGlGT1JKdUlhV3ZublZOQWZhb1c5RWhtQ0hidWxKY2x2aDQxcURTS2JqNWYrOHVRSnAyaHM0YzNiRFlkUEIrWDFuVnpyQzNtRWp5aGdERnFuUGpBQ2toTG9maTQyR1Bva0lDOTJGTUpMRzRZc1B2NEVWWmJSbkVTUlN2b2V1dTE4dHArUmxUTDY3ckhWb3pPclRlbC9ZdGtPRTBVR1E2c0pEd0FBNEdJWjhYM2tTN3NKMHZhbG5GcGdwcmtuMXp4WWdqYXY5VWd5N3lMcDYyaG02THVXQWlreUVzVGRtY1R0UmtsUm9OdXBORlI0UkpGam95WS9TUk5HMXltN2ZnUkhMaDQ0OGg2Si9YOUdHdGV1Sm0wV2FjaFVPeEtRMHVMMnJ3d1BHb01vaWgrWkZXV2diWTVrQ1RiYWtYZG9YTHBwODJUM3lyMEpUcVJQaHlYNlNKMVF5SXdjekh0aTZEbDhVam9aNkVXaXZ2TGFjOU1MTnRIc0tIYzhtYWIwY1psYVFYbzZrcGRzd2xsdUVEazVLNXFoanVybE1qY2ZGbWZZYm1JU3hPQ0E5NGk5ZXl4QmlXdlIrL1FPWVcvM21OR2tHMy9zZ1RxRkVOUklkaHJIVmhHeWVNLzR3SzNXSFE4Q2syMmZXb1h2WlB1c1dGSTJHVCtadnpjcDFpa29hL1ZSOWgvZUJWdG0zSklCM0k0eDU2WXVGUndlcUt2SzFYSmMwcFNZYVd2OXVyMEhHSW1JcXhDNnJwNVg0NSt0cGE5WnBTNjJoUm5OeFRXN3dlcFAvMFEzZFU5TkZFcVA2WXliQVd2MVkxZlZ2cjR5ejg4THJRVWI2OE5GaFBDemhXZy9JK21oMWQ3SUpENEdacHd6ZDlSSnNMaWNHdVhwSzhTYW1WaXovSEwvaitXUkVNODNwTjdUczl3cWhWMmtDdEtIT3lsYlRWaW94eVNzSURKTTFYbkh1aXFLT09QeEVEVWhjOGRRMitweHBrT2Y0K2ZNK2Z3dHRlS0xWZUZidmFNV0cxamt4cFZ4NjRSYWpuVWcvdDEyZW1zMlJWZ0thRG8zWGoybmFOcnR6YkdGVE8wL3VLV1lOK0hhd3Irc3NlRmxkSWM5SjdiYlRLaHlnb2ltek0wREVOU2lQUkZHd3lXaC83d1dUaDZxazNJZFBXaE1aWSttcmN5bHRQS3plZ0ZyM2RKK2RXV1pwNXJUd2ZnYXdBdVBnQVBZRUpQN3ZQMnhkczdleFZybG8wNGtsM2hmSVpWakNMbmNEcW5TN0NkaW1zcklIVXpmcjlHeVRyKy9OMWlqWWhwM1pmMDZOTEVjQ2JpV2QxNjM1L1B0eWJPVmdvQXJMbDB1NTVLeFlzbGJJYTBhdVRtM2Y2dUdDRUF4WUtiMzJvNWViOGdoYlZFU1VTNFl0cnM3RzhRSkNUc3U0UVh5blNDY1NGVHQrZGFZeC94ZERYalN4SHJYaER3RUs0SGNFditSNFpSY2dXVWZmQUNhSTJnZU9NU2huc1FKcWZsZzNvWWVTRk5rNWE3TXBLYnFuNEN5M3VXVXJpVHA5WElYYW5DUlc1ZXZsZ2ZjT3k2M1NBb2FsbG5XUHh0bTRGZFNSSllVcnQyNW9YS1l6R0dSYVo3WFZ3K1VEZ1FtbElrMTMrMlRYZ0V5T051aVFWUkVSZ0lCbEIvRUhLd0t3ZFhxdzJSdW5VN08wQ2JQbEdaSlM1MUxGS1FoL3RQUENCbE5rUXRtd3dlZXQvR3k3S3B0Rk0wUCtKeEhmQldCNWFhS0grTFc3KytFdEczV0dNdWRIT0xHeFZTKzgwdVZyT3A2SVdqVmJrL2Y0dkp3aElYYUN5VlFIMjk3UEpWVTdDdGg1cjFzaVNITUw0VVROS1JQZzYrTHBYbTFzVFpZUG9YYXY0Wm9XQkU1VU82VnYwZnM3b29yK0xGNGVoRHY1NDJyeW1Lb3pQc3ZaTHBPTGpyREFPNS9lOUdDajRsNWtQZGpBNXBSWWh3M3BBRngrTXIwVlNpZ1dQRWJ5VVUveXVQUkRwbUV3OWt2RmljbllXRmZjSXlkZHJFODZOOVlIL3ZkVUNWQ1lwTGI5WEU3WDBTNDRxY0p0NzVSZkdRQWdscCsrSUN0S0FpUXZBRUNnSG1mYVBwdFltRjlTSjRwMGsvQndiUXF5YklGWlF3UE9wRUlrR1lSclF4czJVOGtZZmx5TDQrQmFhZ2J4cFZiTjFkaXlXbjRNcGgvQU1qMXhOaHFpVFB2cVBiWGcyWlZldGYzY2VobUh1THpJaW1nMTRjNXhSNnRSTGt5ODl4SnhreWhGNVp5WUo2MGxvMEhIUXQvUHdkQ00xRWtqZXUxeHlRcldKc0d2NHMzY21NaldlbGpVSGVtNkZtOE9rRStQYWVIektta0ppWEVZbUdKbXIzVmJwdHJTUDZYSENMZkVITk1FZkZjVmdlYkt4YWhIWE15T3NOSUk2U3M3ZnB0WnA0Sk45TmZ1bEd2L08vMlNqRFJZWTNLdXBtb1NDM1ltRmRTcURtdWFPT0s5am5HV3ZrWTZxY1ZGTFFQZVk2MUN0SkNTaElYcTFTL2tUeTlKVlB6SXVGNHpsS3BaZ2lWczNMTGFmakx3QU5hZk52M3orclVUR2NjMUZ3Z1RsZmgwclVmbUNqMUV3QWlpMXE2c053cEpOVUVxMlhHN1lXajFFQUMrN1V3aWZsTitZOW11QXMvOD0ifQ==";

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
      // console.log(m[1]);
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