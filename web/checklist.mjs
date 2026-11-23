const controls=[
 ['content-security-policy','Content security policy','An enforcing CSP limits allowed resources. A report-only policy records reports without enforcement.'],
 ['strict-transport-security','HTTPS persistence','HSTS tells browsers to use HTTPS on future visits; review max-age and subdomain scope on the HTTPS response.'],
 ['x-content-type-options','Content type protection','The recognized value is nosniff. Check that the response also has the correct Content-Type.'],
 ['x-frame-options','Framing policy','Review DENY or SAMEORIGIN, or an enforcing CSP frame-ancestors policy. Embeddable pages may intentionally allow framing.'],
 ['referrer-policy','Referrer disclosure','Choose a policy appropriate for links leaving the site. A missing header can still use the browser default.'],
 ['permissions-policy','Browser feature permissions','Limit browser capabilities to those the application needs. Absence alone is not evidence of a vulnerability.'],
];
export function securityChecklist(report){
 const entries=[...new Set(report.rows.map(r=>r.entry??'Pasted response'))];
 return entries.flatMap(entry=>controls.map(([header,title,detail])=>{
  const rows=report.rows.filter(r=>(r.entry??'Pasted response')===entry),matches=rows.filter(r=>r.header===header);
  const framing=header==='x-frame-options'&&rows.some(r=>r.header==='content-security-policy'&&r.reading.includes('frame-ancestors'));
  return {entry,title,header,reading:matches.map(r=>r.reading).join(' · ')||(framing?'CSP frame-ancestors observed':'Not observed in this capture'),detail};
 }));
}
