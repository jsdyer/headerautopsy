import { $, announce, downloadJSON, el, installTheme, stat, table, tag, wireDrop } from './ui.mjs';
import { compareHeaderSets, parseHAR, parseHeaders } from './model.mjs';
import { PAGE, REDIRECT } from './captures.mjs';
import {securityChecklist} from './checklist.mjs';
import {statusReferences} from './status-reference.mjs';

let report = null;
let comparison = null;
let comparing = false;
let generation = 0;
let page = 0;
let comparisonPage = 0;
const PAGE_SIZE = 36;

function statusContext(target, values, label = '') {
  const entries = statusReferences(values);
  const nodes = entries.map(item => {
    const card = el('article', undefined, 'status-reference');
    card.append(el('h3', `${label}${item.code} · ${item.title}`), el('p', item.family, 'muted'), el('p', item.detail));
    const links = el('p');
    const reference = el('a', item.specific ? 'Read the specification' : 'Check the IANA registry');
    reference.href = item.reference; reference.rel = 'noreferrer';
    links.append(reference);
    if (item.specific) { const registry = el('a', 'IANA status registry'); registry.href = item.registry; registry.rel = 'noreferrer'; links.append(document.createTextNode(' · '), registry); }
    card.append(links);
    return card;
  });
  target.replaceChildren(...(nodes.length ? nodes : [el('p', `${label}No HTTP status was supplied. Paste the response status line or import a HAR to interpret it.`)]));
}

function rows() {
  if (!report) return;
  const query = $('query').value.toLowerCase().trim();
  const choice = $('category').value;
  const filtered = report.rows.filter((r) => (!choice || r.group === choice) &&
    [r.header, r.detail, r.reading, r.group].some((value) => value.toLowerCase().includes(query)));
  const total = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  page = Math.max(0, Math.min(page, total - 1));
  table($('headers'), filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE).map((r) => [
    r.entry ?? '—', el('code', r.header), r.reading, r.detail,
  ]), 4, 'No headers match these filters.');
  $('page-info').textContent = `Page ${page + 1} of ${total} · ${filtered.length} headers`;
  $('prev').disabled = page === 0;
  $('next').disabled = page + 1 >= total;
}

function show(value, clearPaste) {
  report = value;
  comparison = null;
  $('comparison').hidden = true;
  if (clearPaste) $('paste').value = '';
  page = 0;
  $('query').value = '';
  $('category').replaceChildren(new Option('All categories', ''), ...[...new Set(value.rows.map((r) => r.group))].sort().map((group) => new Option(group, group)));
  $('stats').replaceChildren(stat('Input', value.source), stat('Headers', value.rows.length), stat('HTTP status codes', value.status.join(', ') || 'Unavailable'),
    stat('Infrastructure and review clues', value.findings.length));
  const detail = $('findings');
  detail.replaceChildren(...value.findings.map((finding) => {
    const li = el('li');
    li.append(tag(finding.level, finding.level === 'Review' ? 'review' : undefined), el('h3', finding.title), el('p', finding.detail));
    return li;
  }));
  $('empty-findings').hidden = value.findings.length > 0;
  table($('security-controls'),securityChecklist(value).map(r=>[r.entry,r.title,r.reading,r.detail]),4,'No captured responses.');
  statusContext($('status-context'), value.status);
  $('report').hidden = false;
  rows();
  announce(value.limited ? 'Analysis ready. The capture exceeded the inspection limit; results show the portion read.' : 'Analysis ready. The report contains interpreted values only.');
}

function readingCell(items) {
  if (items.length < 2) return items[0];
  const list = el('ul');
  list.replaceChildren(...items.map((item) => el('li', item)));
  return list;
}

function comparisonRows() {
  if (!comparison) return;
  const query = $('compare-query').value.trim().toLowerCase();
  const group = $('compare-category').value;
  const change = $('change-filter').value;
  const filtered = comparison.headers.filter((row) => {
    const matchesChange = change === 'differences' ? row.change !== 'Matching' : !change || change === row.change;
    return matchesChange && (!group || group === row.group)
      && [row.header, row.group, row.detail, ...row.baselineReadings, ...row.candidateReadings]
        .some((value) => value.toLowerCase().includes(query));
  });
  const total = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  comparisonPage = Math.max(0, Math.min(comparisonPage, total - 1));
  const slice = filtered.slice(comparisonPage * PAGE_SIZE, (comparisonPage + 1) * PAGE_SIZE);
  table($('compare-rows'), slice.map((row) => {
    const label = el('div');
    label.append(el('code', row.header), el('small', row.detail));
    const level = row.change === 'Added' ? 'positive' : ['Removed', 'Changed'].includes(row.change) ? 'review' : undefined;
    return [label, tag(row.change, level), readingCell(row.baselineReadings), readingCell(row.candidateReadings)];
  }), 4, 'No compared readings match these filters.');
  $('compare-page').textContent = `Page ${comparisonPage + 1} of ${total} · ${filtered.length} headers`;
  $('compare-prev').disabled = comparisonPage === 0;
  $('compare-next').disabled = comparisonPage + 1 >= total;
}

function showComparison(value) {
  comparison = value;
  report = null;
  $('report').hidden = true;
  $('comparison').hidden = false;
  comparisonPage = 0;
  $('compare-query').value = '';
  $('change-filter').value = 'differences';
  const groups = [...new Set(value.headers.map((row) => row.group))].sort();
  $('compare-category').replaceChildren(new Option('All categories', ''), ...groups.map((group) => new Option(group, group)));
  const status = [value.baseline, value.candidate].map((side) => side.status.join(', ') || 'Unknown').join(' → ');
  $('compare-stats').replaceChildren(stat('Baseline → candidate status', status),
    ...['Added', 'Removed', 'Changed'].map((change) => stat(change + ' headers', value.headers.filter((row) => row.change === change).length)));
  statusContext($('baseline-context'), value.baseline.status, 'Baseline: ');
  statusContext($('candidate-context'), value.candidate.status, 'Candidate: ');
  $('compare-warning').hidden = !(value.baseline.limited || value.candidate.limited);
  const findings = [...value.introduced.map((item) => ['Added clue', item]), ...value.cleared.map((item) => ['Clue no longer seen', item])];
  $('compare-findings').replaceChildren(...findings.map(([label, finding]) => {
    const li = el('li');
    li.append(tag(label, finding.level === 'Review' ? 'review' : undefined), el('h3', finding.title), el('p', finding.detail));
    return li;
  }));
  $('compare-findings').hidden = !findings.length;
  comparisonRows();
  announce('Comparison ready. Only interpreted readings are included in the report.');
}

function setMode(next) {
  if (next === comparing) return;
  generation++;
  comparing = next;
  report = comparison = null;
  $('report').hidden = $('comparison').hidden = true;
  $('single-mode').setAttribute('aria-pressed', String(!next));
  $('compare-mode').setAttribute('aria-pressed', String(next));
  $('candidate-input').hidden = !next;
  $('choose').hidden = next;
  $('paste-label').textContent = next ? 'Baseline response headers' : 'HTTP response headers';
  $('analyse').textContent = next ? 'Compare headers' : 'Analyze headers';
  $('capture').textContent = next ? 'Open redirect and page' : 'Open captured page headers';
  $('input-guide').textContent = next
    ? 'Paste one HTTP response header block in each field. Compare before and after a change, or use copies from different browsers or networks.'
    : 'Paste response headers or open a sanitized HAR. Browsers may leave cookie and authorization headers out of sanitized exports.';
  announce(next ? 'Paste both responses or open the captured redirect and page.' : 'Paste response headers, open a HAR file, or open the captured page headers.');
}

function clear() {
  generation++;
  report = comparison = null;
  $('report').hidden = $('comparison').hidden = true;
  for (const id of ['headers', 'findings', 'stats', 'compare-rows', 'compare-findings', 'compare-stats']) $(id).replaceChildren();
  $('paste').value = '';
  $('candidate').value = '';
  announce(comparing ? 'Paste both responses or open the captured redirect and page.' : 'Paste response headers, open a HAR file, or open the captured page headers.');
}

async function read(file) {
  if (!file) return;
  if (comparing) {
    announce('Use Single response or HAR to inspect a capture file.', true);
    return;
  }
  const current = ++generation;
  try {
    if (file.size > 12000000) throw new Error('Choose a HAR file of 12 MB or less.');
    announce('Reading response headers from the HAR file.');
    const text = await file.text();
    if (current === generation) show(parseHAR(text), true);
  } catch (error) {
    if (current === generation) announce(error.message, true);
  }
}

function analyse() {
  generation++;
  try {
    if (comparing) showComparison(compareHeaderSets($('paste').value, $('candidate').value));
    else show(parseHeaders($('paste').value), false);
  } catch (error) {
    if (comparing) {
      comparison = null;
      $('comparison').hidden = true;
    }
    announce(error.message, true);
  }
}

$('single-mode').addEventListener('click', () => setMode(false));
$('compare-mode').addEventListener('click', () => setMode(true));
$('analyse').addEventListener('click', analyse);
$('capture').addEventListener('click', () => {
  $('paste').value = comparing ? REDIRECT : PAGE;
  if (comparing) $('candidate').value = PAGE;
  analyse();
});
$('clear').addEventListener('click', clear);
$('choose').addEventListener('click', () => $('file').click());
$('export').addEventListener('click', () => { if (report) downloadJSON(report, 'header-autopsy-report.json'); });
$('query').addEventListener('input', () => { page = 0; rows(); });
$('category').addEventListener('change', () => { page = 0; rows(); });
$('prev').addEventListener('click', () => { page--; rows(); });
$('next').addEventListener('click', () => { page++; rows(); });
$('compare-export').addEventListener('click', () => { if (comparison) downloadJSON(comparison, 'header-autopsy-comparison.json'); });
for (const id of ['compare-query', 'change-filter', 'compare-category']) {
  $(id).addEventListener('input', () => { comparisonPage = 0; comparisonRows(); });
}
$('compare-prev').addEventListener('click', () => { comparisonPage--; comparisonRows(); });
$('compare-next').addEventListener('click', () => { comparisonPage++; comparisonRows(); });
wireDrop($('input'), $('file'), read);
installTheme();
