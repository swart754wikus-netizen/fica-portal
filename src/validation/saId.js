// South African ID number: YYMMDD SSSS C A Z
//  SSSS: 0000-4999 female, 5000-9999 male; C: 0 citizen, 1 permanent resident; Z: Luhn check digit.
export function luhnValid(digits) {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
  }
  return sum % 10 === 0;
}

export function parseSaId(id, now = new Date()) {
  const s = String(id ?? '').replace(/\s/g, '');
  if (!/^\d{13}$/.test(s)) return { valid: false, error: 'ID number must be 13 digits' };
  const yy = Number(s.slice(0, 2)), mm = Number(s.slice(2, 4)), dd = Number(s.slice(4, 6));
  const century = 2000 + yy > now.getFullYear() ? 1900 : 2000;
  const dob = new Date(Date.UTC(century + yy, mm - 1, dd));
  if (dob.getUTCMonth() !== mm - 1 || dob.getUTCDate() !== dd) return { valid: false, error: 'ID number has an invalid date of birth' };
  const citizenship = s[10];
  if (!['0', '1'].includes(citizenship)) return { valid: false, error: 'ID number has an invalid citizenship digit' };
  if (!luhnValid(s)) return { valid: false, error: 'ID number checksum is invalid' };
  return {
    valid: true,
    dateOfBirth: dob.toISOString().slice(0, 10),
    gender: Number(s.slice(6, 10)) >= 5000 ? 'M' : 'F',
    citizen: citizenship === '0',
  };
}
