import type { ReactNode } from "react";
import styles from "./markdown.module.css";

/**
 * Renders the light Markdown the AI writes in report text: paragraphs, `-`/`*`/`1.` lists
 * (nested by indent), `#` headings, `**bold**` and `` `code` ``. Builds React elements only,
 * never HTML, so untrusted text cannot inject markup. Plain text renders as plain paragraphs.
 */
export function Markdown({ text, className }: { text: string; className?: string }) {
  return <div className={[styles.markdown, className].filter(Boolean).join(" ")}>{blocks(text)}</div>;
}

type Block =
  | { kind: "p"; lines: string[] }
  | { kind: "h"; text: string }
  | { kind: "list"; ordered: boolean; items: Item[] };
interface Item { text: string; children: Block | null; indent: number }

const LIST = /^(\s*)([-*+]|\d+[.)])\s+(.*)$/;
const HEADING = /^\s{0,3}#{1,6}\s+(.*?)\s*#*$/;

function blocks(text: string): ReactNode[] {
  const out: Block[] = [];
  let para: string[] | null = null;
  // stack of open lists, outermost first
  let lists: { block: Extract<Block, { kind: "list" }>; indent: number }[] = [];
  const close = () => { para = null; lists = []; };

  for (const raw of text.replace(/\r\n?/g, "\n").split("\n")) {
    if (!raw.trim()) { close(); continue; }
    const heading = HEADING.exec(raw);
    if (heading) { close(); out.push({ kind: "h", text: heading[1] }); continue; }
    const item = LIST.exec(raw);
    if (item) {
      para = null;
      const indent = item[1].replace(/\t/g, "  ").length;
      const ordered = /\d/.test(item[2]);
      while (lists.length && indent < lists.at(-1)!.indent) lists.pop();
      const top = lists.at(-1);
      const entry: Item = { text: item[3], children: null, indent };
      if (top && indent === top.indent) {
        top.block.items.push(entry);
      } else if (top && indent > top.indent) {
        const parent = top.block.items.at(-1)!;
        const block = { kind: "list" as const, ordered, items: [entry] };
        parent.children = block;
        lists.push({ block, indent });
      } else {
        const block = { kind: "list" as const, ordered, items: [entry] };
        out.push(block);
        lists = [{ block, indent }];
      }
      continue;
    }
    // a continuation line of the last list item
    const top = lists.at(-1);
    if (top && /^\s/.test(raw)) { const last = top.block.items.at(-1)!; last.text += ` ${raw.trim()}`; continue; }
    lists = [];
    if (para) para.push(raw.trim());
    else { para = [raw.trim()]; out.push({ kind: "p", lines: para }); }
  }
  return out.map(render);
}

function render(block: Block, key: number): ReactNode {
  if (block.kind === "h") return <p key={key} className={styles.heading}>{inline(block.text)}</p>;
  // a line that is bold on its own (`**待关注**`) is a section label, like a heading
  const label = block.kind === "p" && block.lines.length === 1 ? /^\*\*([^*]+?)\*\*[:：]?$/.exec(block.lines[0]) : null;
  if (label) return <p key={key} className={styles.heading}>{label[1]}</p>;
  if (block.kind === "p") {
    return <p key={key}>{block.lines.flatMap((line, i) => (i ? [<br key={`b${i}`} />, ...inline(line, i)] : inline(line, i)))}</p>;
  }
  const items = block.items.map((item, i) => <li key={i}>{inline(item.text)}{item.children && render(item.children, 0)}</li>);
  return block.ordered ? <ol key={key}>{items}</ol> : <ul key={key}>{items}</ul>;
}

/** `code` first so its content stays literal, then **bold** in the rest. */
function inline(text: string, keyBase = 0): ReactNode[] {
  return text.split(/(`[^`\n]+`)/g).flatMap((part, i) => {
    if (!part) return [];
    if (part.length > 2 && part.startsWith("`") && part.endsWith("`")) return [<code key={`${keyBase}c${i}`}>{part.slice(1, -1)}</code>];
    return part.split(/(\*\*[^*\n]+?\*\*)/g).filter(Boolean).map((piece, j) => (
      piece.length > 4 && piece.startsWith("**") && piece.endsWith("**")
        ? <strong key={`${keyBase}s${i}.${j}`}>{piece.slice(2, -2)}</strong>
        : piece
    ));
  });
}
