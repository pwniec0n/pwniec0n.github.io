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
const ct_serial = "eyJzYWx0IjoiWEZzbkJOMlpEV25abGoyMmY4NUd6UT09IiwiaXYiOiJFMmZRRk0zMzBqVEU4NzVNIiwiY2lwaGVyIjoidGk4N1o3dzlqOGpHc3NOZ2VhcExMZlhsUG4xVGJzd29kMkNKZHBiNzByT1lpRmlVTDU3M0tqQ09WbTFhUGo3QUlxZWdaMVMraHFTSWdIM3NNdUVkaERkMnhnMFpSeThXdkMvSzFhQVkzTWdaOW0rcjllMkRWa1dlNU1IamdHczh0WGtYZnozam95UGdubEFucGxxVTRLWkswRDIzQllTTTc0UTRGSzVxMDR0OGY4dTFyZ0YzVDdJUlloUUYyQjFmSHphcVJEVkJrOTJCUVNWa2pDR1dqKzBlVTFhYitBMnpPRUFTY3A0aFZsazVGVEhJQ0l3Mzg1cTBBT2hITE8yaU14OWdMZlQyKzNpeUpYUWZ1VEVKUWlGb2JjaExlblNDblJuNnNiQVNMc2tVaWZQWjBFQ3VzNXNIVjNtL2MzUzc1YXBUblVqT2l2Z3FCTVFOYVdpU1ljVGFsT25oYkxiUHg1UzZuKzlLVldhQzBNenJzVms0OUgrZWF3dUR3U2JwVGNjdlVQOHpmQ0lwenQ0NVBHQkZGUVJYeXR6ZEkxVzFJMDlyYVpscWlwZjUrSG9GWVBUUHgrajIzZEptQitqbmtqOGgwYzRLbWRWcFVYZTloY0tqaWZSR2crSEVQYlQyb3JXdURBNTBpYU5mNWJqRkRJc0o1SnByWFAyQS9NYTcxWWErOUFuM2VEN3JlOGhiZk8rTys0ZmJXTmEvS2pDOS9hN1Y2eFJiRVNZODVkTFpON1hqdC9udHVLL1AwQ0EzUEUvN2cvN29YUnhtVlVIZjgrUlpTK1ZVdk1nVTVBYW1sNUlwc2tsditTVEI3UzFtdldMWFJmQ1o5UlErNFJIVWw4K2Y2dzk4OXpLd1NoVU5JSEtMRGhBWGc5NW9Tay93VzNCUnBaU1Q2WFJjTmZ0ajdxVDhNbFFVaFdTSFlLZUlaK2lmOFZtSis2Mm1LTEV0ZGpycUowK09xemo5clVpNVNIUGhvU0ZmbzdtN1NMSWxKMGlFaitSOE5JZi9zQkUvTVFBTThMSnVEc2p0dXEyU3VHY1o2M0U1ZjJZV2hCNERsM0R5WFh1dWVZaEhsc0JCK3NUbnJoNTR2dm9pQjgxSDd0NDc0YzVaZ0NDMXpVZEQ1UlExeU9QY3kxNVNobXp4NkFjQnIrYi9Dc0xYa3pENHRkS2ZsSFlScExkQ0J0Nzl1YzYrYzR4elBmWDFSQmQrWWFKa0FFVG4zQW1mNU5PcWZxakNRMm91OEUxTERKYklPS2o2SmVENHlFaHk1M0hESi9oTURlemh3dDZCUmd5QjFuaGw1eWZxWEFLWUZIbXh6RkhLUHVjb2NVUld5RTBNNDd5dm1TVy96aWdKOE1zeURjSkprcmxXc2FEeWJUQ2ZSRHcrVFVybVBpOHdKK3p5dCszaEpjeXBRRkdDQ3lDMjZZQ3FsaTJxNXBDekwxSTRwQ3VNSXRuc3R4eUlncWE3SDlMeXhhWHpzVWx5Qm1EamhMZzFCZUxxWTgwQnR1Z2VNMHR3Ni9YWnhoTFh4WG5ZeWNVTHJsdEdYN2RPMnY1SW01MjJYc0R6dVdOb2tWbjY5aUY2NlQ5OU05WnFGNGlEU0FZVkY0Y0d0aUp4RTZZYlN1azYrRENxUGZ4UU1QbzNoTDJOZXk0TVRhMDRLQTRkTkJyOHhzeG52OU15WjZmanpZUlZFNU4wYUZtY2VLYUZ2MlZJNmdVK1dnWkV0Y2ZaalVZazdIaVN4WGVYbDdpL0xTWTJvREMxcnRHdVExdUwxNHVpSXhDcGYyWUt5bkNBWFc4OFNZd29IQzVaTExHY3pzMk5xeW5iT3I1OGQwcS80bnhTNHVpVi9GQk9hcFUrMjVSdXNlZUhVM3l5UXdjQVBwY1RCRTJXMFlySitHQS95UHo3NnNnYjlwK3cwcm9BTDQ4bVNCMjB3TW5KYUk5cFFEY3UyS21EbllxdlFyQlF5UXp5eDFwNmhJZW1mRGpkTVJ3eHkzY0pnM2gwaDVlZUc0QXRQeUZYWE9hMkdYdHRDdWdWWVZRS2w1VVl0RUN3VXI2a2xOendQaWwyNHVwZ3doTlljVlI0TzA2bDNnbTlSN2VoZHFhYXpUVzc0RkFPSHBTUGVWMElJYXQxd0JqVE1YWG51R2NBNEs4bnR6aHlnMUg0eXNTaWRHbVA4ZmQxdjZ0dERRTkFmRkRTaWlUOVdRMC8waktBa21rL0R6QzNsUVduclZBazl3UHpVclQ3REdMYWd4d01majZiYUVRTUoxa0t3U0RpWnI0RU8xSVp0WWJ1NUZsa3dTSG9YUkFqN2JtV25VbXlKVUF3ajVxRVdTbWlQSFNWUVpHS21YMExSTkRaZzNrRE1CT3RqQTdaZEozN0cyS1lZdFMzcVgwK1NaTkRzSnZLdWk0MkhvdVRLQ0crNXZLTml6UjN4RitGbjk4SEtMTkxDV2crNkVPNDh6NWE2VDhvYjhwSFVrbEdYaXZjSDVhZm1wRzZ0WmdVSWtqY0EyR0h2THA4Q3Z5VDYwOWZ6aVI5SGxRVkRoQnhTRVRHMk4xcmZRMzE2VnJDUjU5UmhDdktqTGNuQWR2by9DeWlFenpQRHhsUVlCc3ZmSmVYQStYOGhlNmNZOTE1SCtpdkptYnBOUWhmWm1Cc3FCTzdENERZVlJ4cnRXeE9WMkFCb1M4NUNhcm4vYmxXM0VTZjJQSW5oSFRzc2d5dGRwK3IySHIzVUhQbThrYjRkc242R29sVjZkVDl4MHdJK0lMMkY1MlRqZlpNTUI4alhaYUcwK1BzaUNqaURDeGUvK1YyV00rOFpZcG1TSmNzUWhleGpRWGM3TzJxYVZFK29QaVlTQTJBaHRTU084TGtBWk9xQ0dXQm14MEoyYzZXc29McnNwOUdqZkcyeHNTa3FodzFoYllKS3JNY1hxSXlZNWNxYnYrYlo0RndCdTBTa1R5THhWbUd4YmhEK0YyOVQ3KzNwWHMwM3lvUEdjalhsNmVJTjJlckJaaE1URnp6dXNmRS9EVkNTWVlocElxazcrQmhiY1NCa0JwdUhqa3g3QXVYbmdMWjdoNlBraUwveDBMdWRtUjc5UklKQWNWMmRhMXp6N3RMS2lDU1N3V2RNM21NRWdYU241WkVXVFhjSldjMWplWXMyZUphVUJPcW1uN1JKNnNHUzdHeHJBTm1CL0gxUlZvWTJ4S1graVRncHRaYVBsWGgzVlRBWEVJa093Yzd2bmJFQlhVMW9xTXpiSGZmSGg4NmJJWjd0d1BJR0dkYzZqTHpuT1h5R0JoWWFiTXhJcENtWm9WUXVxOUw5STdiRnNNRmdzTnM5VHorSWxzNkZkOEdwb212YTl1SUtjS2hoMXhBYm9SL3VocFovcHFPUzhMTGExT09KR0xHd1VNNVRqUWpVdkxyZExzOU02WkRFak9UVHBGSEdaZzduMlhRN3Y5VllFUHBiNEdaY1J2RkVHcC95eEJHR2dQcDZ6eEcvL1plR05DazRaUThac1JpeTNiNHZSY01Rd2w4S0JpSk9EQjJleW9vVVdnWndPdVo1WFIrNVpseElRUmNGQkw3OWk3NkR2NE9ZNGd2dHBWNlNhdDJFTlhqSDVzcHNBandPcXJTcm9QN1RzZTdlTXMxU09qeUdkVFN3bEpOYUZtRnp1ZkZ6S0s2RkVKVmoyL2ZKc0F2SVpDQnQyUkhUL1AvdE44aFhmVmtYOXBYNzQ5TVBrSktWUWh5M21jRnV1alViRy9iYm94RXluL0VydmJXQ1VvcmF1aEwyQ3JBcFZpb0xIcWlJMGh1M2U4b3NsaU96WEw3ODc1dk5rbm5yWnpYSU5jZjhVbU04QnI3Rk1DV3U0RnZ6OEE5U0xlYTNzSWJ2MjB2STNMamJBS3FnZE9jWlRvR1NiN01KMWx2VEJReU8yYVJONlZ2clE4emJTZmJPMHVWNkIvdnZQZ1RPZ2tVMVdMMmg0N28vRWtNeFE1NndQNGRWdkRYdHI5dSthWjM5L1AvWnp1TlN4ODhPUXdML1RCNC9NQktEaHdjMVo0NDBTaTB5MjU3dTdOc2xXTjl1bGtER3B4eFBtdDFUeVI4bUxxSzhCQUFJYzVnYUlMN2pUMGxISHZZVjlqQ2NYWVM0NHpiQ2l4SHdRTmlXM1NyT0wvVktWSEJ4OGFYdVFLa29uaVcyUjlsUTAvZHV2S2ZOM0pIOXozeWlqRm44QXhxa2hnNk5jNlpNd3NONmdhbXcxalFQeVNTV09lNDRvYXRlbDFmSXF2cnEyWTQzMjZyZ3ErVjh3d2VKRlJiVkVXMlRLeEc0Slg3MFRmWTZFMEU5MVY2YmVVUFcrS0I4eFJYeXM1UEljak9jLzdBRElaL3NTZkUwY0RveVBmMm1pS1lOOGhLUFZnZ3ZIVnBhZXl5NkpSUlROMEV0dks1YWIxcWhvdkFCUzBjR1NqT0lFZUVyZzBxQktUQjErS2dFYVVwQkthWEdDdnUrQnlnZm5mQy9xZmlvcjlPSVl3QmtOOUMyN1JQYjhwNk00WERBQWNiU3pvWFI4MWdsME03QkxITFFsSVhxRFYxWHhoaW9vSGw0TzRZMFRSR1M5NHFhTk0zYkRWZElwWVFCU0FVRG5QN1VHVVRjSjk3QXhiWGpuTnAyUTBtWjZNaDlLeXN6VmhRN2hvaHVmNzRiWTNMbzRzQ0hqK050ZWNXdFEzNzJKdzBMSWF5cjBockVRQ3hPaG5KUmJ5TEZ3dm1XVGJycmtQbktsdC9hRUVMZDJNQ2dPT3FRYVZieHJkRVNpbTR5WXA2Vm0rZHFKc3ArUTdaVU12QUN3eFNhczF0M05SbXVLTi9uOENPOXdVSTJ6R00vNi9EUDhkV2lobkM0Z3dUaGgrWkp5UDJCTHVwWFVGcXlaK3dMYzRXYUJpcldTYXhSVnY3dUR0M3dNTUlCTWZwWlVsVUV1WHhYZzNoWVpkcXRxSU9XOUJDMEdZY21MOUlGN3plUWVONlB3WUJiN2ZtZ0lucTM1SlRVMXRINDNMS1V5T2V4STF2RVlodnlKOExXYjJZSGIwdzRoU3ZrRlBwZkN3RUVhbFI3Q3NOYjdqS2JRd2dMNUZEQjQrR3VmamJ4ZEVtTjE1ODY4eEZLd1pLWWpWayt5SGpIQ3gvWUUrNVN3MTlvYWpJYVg0YzN1dlZGbkh1TGlLbnZVbUVYV09ZUFF3cE42UFhscHllM05ZWU5MNkkvbjQ3OXFCYndLVHFoM1JpWDVMQ1Q1VHdIZXJDUG5zYW5JQWljOUtUQ2pKQVYwWmdyeUJ6dDVEZ0dKY2ZKZVNtTmM5dGp3UVJpMDdLK2pSbXdhT3pRa3MxWG9RWldUeE1tSXFsTldXU2ZuVEJJQ1cyK2xZeUJNQWE0UlN0Y0IrMkNuWTJ2QTRQU2R2WGZZY0duUVZBa25aSzhXdDFQVndaenQrWkcwblVTNjdRMmd6cWFqMWN1N2x0UHUzS3hYY0ZzTUd0ZXBtdm9qUllldnZDU0VVaVluem9mZ0o5T1dCR1B0N3V1RElpSkp2dmpXa3VEQ3RrNnEwellVZHRMeFI5YUYzb0g0YWNMelE1cERWSU9DbWRzZWpnWVQwNnNLaVR4U2xCdExjZ21MZVBISkVpTi82WFU0WkRQV25CTFZrSWJzQ1N3QTUyTkZYK0dUL2wyUThZbm9kYTlpM200YVRlL0dMV290TG9NOStHeWwxZi9abFZYOExieWFVcW5UK1dRdnYyNXdlSWlFOWZlSDdpMGlKT0NlbDh1M3VrWXNwb2IveHRrZGEzTTI0OGQvSnZQU08xc0N3cnpqZUtpaE83WlBTTW9LNWdTQllxMU1xakZ5RDA5VU5iWXQ4Sk95cXdFWWVQWEJibzE5MUgvMUJ6VnppOVVuTGhNcnJiQnBkVmRyeUZPWGVFM3BiK2dEZnE3RHk1eTNYOWhoOU05NkpIODhJdUlvQmRwdk1EU2laZXpSMkNFU0EyNWQzWVdjSXMyejg0ZXljY1pDZG95U2ZyeGZ3VlV3TTlqTkhqS014WTFabFdPbThMOHc2SUZhYWY4TlJ0Y083b1VINURzQjZ6NXlnd01kejNMUFo2WjZpRjJmT1d0NVFFd0l2TWF5VmVBVE5HWWpGUkNFWWhNK1Z5QVFZZkZEL1QrWkk0aW9Iam1kTHJVejJEMEQwQy8zS240YTE0T3VUNE5CemRabENyck5zZVpscUsxUEdta25keFRRVDdSdTc0aFpqb05rRDM3VVBleXFaa05VTkJNbVBnWVd0OStGWWJLSWc4aW1MU0hQbFdrWWFpY2pLb0EzOFZvM3hDWUQ3OWpNNUdmb0wwd0FNbnRGRldGUTJzdmhMcURzZkJEZ1l3ZXNveTYwdmlGUFMrTGxuQXdMeXNIVFhvbGNQSDhYNERyNmhON0E1Z3JuZ1JhUDZPZkdQUlZLZmZiUXBHZVBNS2FUcUVpUERzdXNXUDdPYkpORzdxR25LK0VBZG9UZFMxVCtXdW1QMkkvOWdNbVBsUDE4YlYvY0xyVVZidjVZNk0xdHRweGxQdkRTem41aDVRck9qU3BGS04rdzhxSkVzTUpvSjFQT3p5QlVNUllOamx2dlZucmhPZWpXeVFudDl1RTNqWlJwQnZCTnFKZURaUm42OFJHY1Z2NDVtU3B1Q3laZ3JHQXFCOFdqUjQ2a1Z5ZWgxcnJkTmlCMlVPd2tXWjVQRW91d1ZQVitNMlV4a1pmdVFrTVhnWTRiL3lCR1owVUZVaTJ0RjVPVWJOQVpsbzM4UUxLN1R3WEFGVHlWTWFGVmIrajg1bXpqRG14MjFIelY1bXpBS2MwQnkySWFCSFBhSkVDTm1KZTlCRHFrM1FhUTRGbWUydzBIOThjY1BmUkhvWmFaalJmbVlMRnRHWmdsWjBrZXMvaDZsa0V0b0YzbHhiaU9uU0VlQ082bEtaekcvZGZEdjhHUnVQNHZVR1VTU0hLTmlxQllnOG94Z2NueDFXd3pEdU1LZFB2SEJka0NPZGJ0dThtR0N1S1Joano2VWZ2QjY0Ym84bFp6NUs1VUYyZ0Z5T2Q3MkY1YWdNVnY2d2plcnRHL1lGeThWSExvWXpPeldsMzlHQnhOV29CVEJKekI5RVRoVXdIVDZFMDNLbTdUZTZHNjM3eDY0MjhKQTEycFlQTlV1L29OQ1pUcy80ZjF4WTU0eGxYdk5kUHVKZDF4WjdGa1lFc0Y1OFlMZW5IK3oxRXdac0xNVFhoVWpKSUdCdGQyam5mdWlJR1A4NjJ5SDFsYmtaT0FCdzBjYmFKWnBMbFNObFdPRE83d0hXY2tSY0tWWXlsMXcxQ0pqMGhIbWpIblkxUG9HZ09TZjZPTDkweVRZaDFnTExheTBrU0hTNUZTdVRiSGZMY2RjUkdnM3JSZ2h6YzlKVEZqNHlTazNBTXp0TEtEc3J2emRKTk9DSnd2amFZZlBUWTBPRW1Hb3k1UEc0Vmw2cFBlTDBoMU5mUUpQNHoySzVYTGFUZXM4NVExSkNRSkIrQmVrdGxzME9mb2NrZGpJRTZFbGJ5L2oyd0lPTVRvdUU1Y3ZZbDdqdFNDZWI4N21pNEtJWXlOb1o2WUs0SzNFS1ZuOWNiVEtKcks4K2NzSHdqbm9McmJldmo1dDdaTkEweERTdERMOGV1QmdtbjcwN240Skh4ZUJ4QmtqOHZQM3JuenVyckJScTZlTkxPUnd3aksvVzFXdS9ydTI3WVgzSW5OK05kS3V0eW5ZSnNTWDg1RFpnKzhmTmloWnRDWjViTWFSbjZDY3c0ZkVvanVxeTFxNlZ5MU9MNVNiNUs5bkRkdXAvWisyVERwYytQMXFRU3FNeFVUcGM4RXlyKzhSRHNPa3dhaHR1TjR5UWlXN1EyM09Ha0hqZDVTLzJjQzRiV2JaaVBBakFuc3Jxem14aExHRGErNS9TL3BNdWJ5cFlJZ3dQYzMxVG50NWJmaC9XQ3BWK0NjdFVSd1JZT1p6V243K2ZOaUdwTzgwWXNvOFY0cnl5SnY1eW12eGJWcExtVmJVME5kL3JXb1M1ajhtNGwwUEd2dzQyTjByVGNmSEJXQW80ZzB6K3Jld3IxT1NkZno5dE9FUUMyaFg3RWNLZldJSkgifQ==";

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