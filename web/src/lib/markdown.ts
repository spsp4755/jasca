import { createElement as h, Fragment, type ReactNode } from "react";

// Small safe renderer: builds React elements only (React escapes text), so no raw HTML ever reaches the DOM.
// Supports headings, bullet/numbered lists, fenced code, paragraphs, `code`, **bold**, and [text](http(s)://…) links.
// shortcut: no tables, nesting or emphasis other than bold; upgrade if AI output needs them.

const INLINE = /(`[^`]+`|\*\*[^*]+\*\*|\[[^\]]+\]\(https?:\/\/[^\s)]+\))/g;

function inline(text: string, key: string): ReactNode[] {
  return text.split(INLINE).map((part, i) => {
    const k = `${key}-${i}`;
    if (part.startsWith("`") && part.length > 2) return h("code", { key: k }, part.slice(1, -1));
    if (part.startsWith("**") && part.length > 4) return h("strong", { key: k }, part.slice(2, -2));
    const m = /^\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)$/.exec(part);
    if (m) return h("a", { key: k, href: m[2], target: "_blank", rel: "noopener noreferrer" }, m[1]);
    return part;
  });
}

export function renderMarkdown(src: string): ReactNode {
  const lines = src.replace(/\r\n?/g, "\n").split("\n");
  const out: ReactNode[] = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    const key = `b${i}`;
    if (/^```/.test(line)) {
      const buf: string[] = [];
      for (i++; i < lines.length && !/^```/.test(lines[i]); i++) buf.push(lines[i]);
      i++;
      out.push(h("pre", { key, className: "code" }, h("code", null, buf.join("\n"))));
    } else if (/^#{1,6}\s/.test(line)) {
      const lvl = Math.min(line.match(/^#+/)![0].length + 1, 6); // h1 is the page title; shift down
      out.push(h(`h${lvl}`, { key }, inline(line.replace(/^#+\s+/, ""), key)));
      i++;
    } else if (/^\s*([-*]|\d+\.)\s+/.test(line)) {
      const ordered = /^\s*\d+\./.test(line);
      const items: ReactNode[] = [];
      for (; i < lines.length && /^\s*([-*]|\d+\.)\s+/.test(lines[i]); i++) {
        items.push(h("li", { key: `${key}-${i}` }, inline(lines[i].replace(/^\s*([-*]|\d+\.)\s+/, ""), `${key}-${i}`)));
      }
      out.push(h(ordered ? "ol" : "ul", { key }, items));
    } else if (!line.trim()) {
      i++;
    } else {
      const buf: string[] = [];
      for (; i < lines.length && lines[i].trim() && !/^(```|#{1,6}\s|\s*([-*]|\d+\.)\s+)/.test(lines[i]); i++) buf.push(lines[i]);
      out.push(h("p", { key }, inline(buf.join(" "), key)));
    }
  }
  return h(Fragment, null, out);
}
