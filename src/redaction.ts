/**
 * OPSEC: sensor IP (v4/v6), MAC (titik dua / titik), FQDN, dan hostname satu label
 * sebelum data dikirim ke AI cloud. Dipisah dari server agar dapat diuji langsung.
 */
const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
// IPv6 penuh / terkompresi (`::`) — sengaja tidak menangkap jam `12:03:45`.
const IPV6_REGEX =
  /(?<![\w:])(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}(?::[0-9a-fA-F]{0,4}){1,7}|::[0-9a-fA-F]{0,4})(?![\w:])/g;
const MAC_REGEX = /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g;
const MAC_DOT_REGEX = /\b(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}\b/g;
const HOSTNAME_REGEX = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,24})\b/g;
// Hostname satu label bergaya militer (mis. PUSKODAL-SRV-01); huruf besar agar
// tidak memangsa istilah teknis seperti "usb-storage".
const SINGLE_LABEL_HOST_REGEX = /\b[A-Z][A-Z0-9]{2,}(?:-[A-Z0-9]{2,})+\b/g;

export function redactSensitive(text: unknown): string {
  return String(text ?? '')
    .replace(IPV6_REGEX, '[REDACTED_MIL_IP]')
    .replace(IPV4_REGEX, '[REDACTED_MIL_IP]')
    .replace(MAC_REGEX, '[REDACTED_MAC]')
    .replace(MAC_DOT_REGEX, '[REDACTED_MAC]')
    .replace(HOSTNAME_REGEX, '[REDACTED_HOST]')
    .replace(SINGLE_LABEL_HOST_REGEX, '[REDACTED_HOST]');
}
