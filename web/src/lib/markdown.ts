import { createElement as h, Fragment, type ReactNode } from "react";

// Tiny Markdown renderer for AI output. It builds React elements, so every piece of text is escaped by React and no
// HTML string is ever produced. Supported: # headings, - / 1. lists, ``` fences, > quotes, --- rules, | tables |,
// **bold**, `code`, [text](http(s) url). Anything else stays plain text.

const SAFE_URL = /^https?:\/\/[^\s<>"']+$/i;
const INLINE = /(`[^`\n]+`)|(\*\*[^*\n]+\*\*)|\[([^\]\n]+)\]\(([^)\s]+)\)/g;

function inline(text: string, key: string): ReactNode[] {
  const out: ReactNode[] = [];
  let last = 0, i = 0;
  for (const m of text.matchAll(INLINE)) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const k = `${key}-${i++}`;
    if (m[1]) out.push(h("code", { key: k }, m[1].slice(1, -1)));
    else if (m[2]) out.push(h("strong", { key: k }, inline(m[2].slice(2, -2), k)));
    else if (SAFE_URL.test(m[4])) out.push(h("a", { key: k, href: m[4], target: "_blank", rel: "noopener noreferrer" }, m[3]));
    else out.push(m[0]); // javascript:, data:, relative … shown as text
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

const cells = (row: string) => row.trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim());
const isTableSep = (row = "") => /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(row);

export function renderMarkdown(src: string): ReactNode {
  const lines = src.replace(/\r\n?/g, "\n").split("\n");
  const blocks: ReactNode[] = [];
  let i = 0;
  const key = () => `b${blocks.length}`;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) { i++; continue; }
    const fence = /^\s*```/.exec(line);
    if (fence) {
      const body: string[] = [];
      for (i++; i < lines.length && !/^\s*```/.test(lines[i]); i++) body.push(lines[i]);
      i++; // closing fence (or end of input)
      blocks.push(h("pre", { key: key() }, h("code", null, body.join("\n"))));
      continue;
    }
    const head = /^(#{1,6})\s+(.*)$/.exec(line);
    if (head) {
      const level = Math.min(head[1].length + 2, 6); // # → h3: the page already owns h1/h2
      blocks.push(h(`h${level}`, { key: key() }, inline(head[2].replace(/\s+#+\s*$/, ""), key())));
      i++;
      continue;
    }
    if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(line)) { blocks.push(h("hr", { key: key() })); i++; continue; }
    if (line.includes("|") && isTableSep(lines[i + 1])) {
      const k = key();
      const header = cells(line);
      const rows: string[][] = [];
      for (i += 2; i < lines.length && lines[i].includes("|") && lines[i].trim(); i++) rows.push(cells(lines[i]));
      blocks.push(h("div", { key: k, className: "md-table" }, h("table", null,
        h("thead", null, h("tr", null, header.map((c, j) => h("th", { key: j }, inline(c, `${k}h${j}`))))),
        h("tbody", null, rows.map((r, ri) => h("tr", { key: ri }, header.map((_, j) => h("td", { key: j }, inline(r[j] ?? "", `${k}r${ri}c${j}`)))))))));
      continue;
    }
    const list = /^\s*([-*+]|\d+[.)])\s+/.exec(line);
    if (list) {
      const ordered = /\d/.test(list[1]);
      const re = ordered ? /^\s*\d+[.)]\s+(.*)$/ : /^\s*[-*+]\s+(.*)$/;
      const items: string[] = [];
      while (i < lines.length) {
        const m = re.exec(lines[i]);
        if (m) items.push(m[1]);
        else if (items.length && /^\s{2,}\S/.test(lines[i])) items[items.length - 1] += ` ${lines[i].trim()}`; // wrapped item
        else break;
        i++;
      }
      const k = key();
      blocks.push(h(ordered ? "ol" : "ul", { key: k }, items.map((t, j) => h("li", { key: j }, inline(t, `${k}-${j}`)))));
      continue;
    }
    if (/^\s*>/.test(line)) {
      const body: string[] = [];
      for (; i < lines.length && /^\s*>/.test(lines[i]); i++) body.push(lines[i].replace(/^\s*>\s?/, ""));
      blocks.push(h("blockquote", { key: key() }, renderMarkdown(body.join("\n"))));
      continue;
    }
    const para: string[] = [];
    for (; i < lines.length && lines[i].trim() && !/^\s*(```|#{1,6}\s|[-*+]\s|\d+[.)]\s|>)/.test(lines[i]); i++) para.push(lines[i].trim());
    if (!para.length) { para.push(line.trim()); i++; } // a line that only looked like a block start
    const k = key();
    blocks.push(h("p", { key: k }, inline(para.join(" "), k)));
  }
  return h(Fragment, null, blocks);
}
