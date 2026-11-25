// Deterministic, explainable risk scoring driven by config/rmcp.json.
// Every point added is recorded so the KYC report can show *why* a client is rated as they are.
export function assessRisk(input, screening, rmcp) {
  const w = rmcp.weights;
  const factors = [];
  const add = (factor, points, note) => { if (points) factors.push({ factor, points, note }); };

  if (screening.sanctions?.match) add('Sanctions list match', w.sanctionsMatch, screening.sanctions.detail);
  if (input.pepDeclared || screening.pep?.match) add('Politically exposed person (PEP/DPIP/FPPO)', w.pep, screening.pep?.detail || 'Self-declared');
  if (screening.adverseMedia?.match) add('Adverse media', w.adverseMedia, screening.adverseMedia.detail);
  if (!screening.identity?.verified) add('Identity not verified', w.identityNotVerified, screening.identity?.detail);
  if (!screening.address?.verified) add('Address not verified', w.addressNotVerified, screening.address?.detail);
  add('Non face-to-face onboarding', w.nonFaceToFace, 'Digital onboarding channel');

  if (input.nationality && input.nationality !== 'ZA') add('Foreign national', w.foreignNational, input.nationality);
  for (const [label, code] of [['Nationality', input.nationality], ['Country of residence', input.countryOfResidence]]) {
    if (rmcp.countries.highRisk.includes(code)) add(`${label}: high-risk jurisdiction`, rmcp.countries.highRiskWeight, code);
    else if (rmcp.countries.increasedMonitoring.includes(code)) add(`${label}: jurisdiction under increased monitoring`, rmcp.countries.increasedMonitoringWeight, code);
  }

  add('Source of funds', rmcp.sourceOfFunds[input.sourceOfFunds] ?? rmcp.sourceOfFunds.other, input.sourceOfFunds);
  if (rmcp.occupation.highRisk.includes(input.occupation)) add('High-risk occupation/industry', rmcp.occupation.highRiskWeight, input.occupation);

  // ---- Accounting-firm factors: client type, services, beneficial owners ----
  if (input.clientType) {
    const label = { individual: 'Individual', company: 'Company / CC', trust: 'Trust', partnership: 'Partnership' }[input.clientType] || input.clientType;
    add('Client type', rmcp.clientType?.[input.clientType] ?? 0, label);
  }
  if (input.entity?.subtype && rmcp.entitySubtype?.[input.entity.subtype]) add('Entity type', rmcp.entitySubtype[input.entity.subtype], input.entity.subtype);
  const tcsp = (input.services || []).filter((s) => (rmcp.services?.[s] ?? 0) > 0);
  if (tcsp.length) add('Trust & company services requested', Math.max(...tcsp.map((s) => rmcp.services[s])), tcsp.join(', '));
  const st = rmcp.structure || {};
  if (input.entity?.cashIntensive) add('Cash-intensive business', st.cashIntensive, input.entity.natureOfBusiness);
  if (input.entity?.countriesOfOperation) add('Operates outside South Africa', st.operatesOutsideSA, input.entity.countriesOfOperation);
  const related = input.related || [];
  if (related.some((p) => p.isEntity)) add('Complex / layered ownership', st.complexStructure, 'An owner is itself a company or trust');
  const relScreen = screening.related || [];
  const pepPeople = related.filter((p) => p.pep).map((p) => p.name).concat(relScreen.filter((r) => r.pep?.match).map((r) => r.name));
  if (pepPeople.length) add('PEP among owners / controllers', st.relatedPep, [...new Set(pepPeople)].join(', '));
  const foreign = related.filter((p) => !p.isEntity && p.nationality && p.nationality !== 'ZA');
  if (foreign.length) add('Foreign owners / controllers', st.relatedForeignNational, foreign.map((p) => p.name).join(', '));
  const media = relScreen.filter((r) => r.adverseMedia?.match);
  if (media.length) add('Adverse media: owners / controllers', st.relatedAdverseMedia, media.map((r) => r.name).join(', '));
  const relSanctioned = relScreen.filter((r) => r.sanctions?.match);
  if (relSanctioned.length) add('Sanctions match: owners / controllers', w.sanctionsMatch, relSanctioned.map((r) => r.name).join(', '));

  const value = Number(input.expectedValueZar) || 0;
  const band = rmcp.transactionValueBands.find((b) => b.maxZar === null || value <= b.maxZar);
  add('Annual income / turnover', band?.weight ?? 0, `R ${value.toLocaleString('en-ZA')}`);

  const score = factors.reduce((s, f) => s + f.points, 0);
  let level = score >= rmcp.thresholds.high ? 'high' : score >= rmcp.thresholds.medium ? 'medium' : 'low';
  // Hard rule: any sanctions match is always high risk regardless of score config.
  if (screening.sanctions?.match || relSanctioned.length) level = 'high';

  const dd = rmcp.dueDiligence[level];
  return { score, level, ddLevel: dd.level, ddLabel: dd.label, requiresCompliance: dd.requiresCompliance, factors, rmcpVersion: rmcp.version };
}
