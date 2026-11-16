import { $, announce, downloadJSON, el, installTheme, stat, table, tag, wireDrop } from './ui.mjs';
import { parseHAR, parseHeaders } from './model.mjs';
import { SAMPLE } from './sample.mjs';

let report = null;
let generation = 0;
let page = 0;
const PAGE_SIZE = 36;

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
  $('report').hidden = false;
  rows();
  announce(value.limited ? 'Analysis ready. The capture exceeded the inspection limit; results show the portion read.' : 'Analysis ready. The report contains interpreted values only.');
}

function clear() {
  generation++;
  report = null;
  $('report').hidden = true;
  $('headers').replaceChildren();
  $('findings').replaceChildren();
  $('stats').replaceChildren();
  $('paste').value = '';
  announce('Paste response headers, open a HAR file, or try the example.');
}

async function read(file) {
  if (!file) return;
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
  try { show(parseHeaders($('paste').value), false); }
  catch (error) { announce(error.message, true); }
}

$('analyse').addEventListener('click', analyse);
$('sample').addEventListener('click', () => { $('paste').value = SAMPLE; analyse(); });
$('clear').addEventListener('click', clear);
$('choose').addEventListener('click', () => $('file').click());
$('export').addEventListener('click', () => { if (report) downloadJSON(report, 'header-autopsy-report.json'); });
$('query').addEventListener('input', () => { page = 0; rows(); });
$('category').addEventListener('change', () => { page = 0; rows(); });
$('prev').addEventListener('click', () => { page--; rows(); });
$('next').addEventListener('click', () => { page++; rows(); });
wireDrop($('input'), $('file'), read);
installTheme();
