"use client";

import { useMemo, useState } from "react";
import { Check, Copy } from "lucide-react";
import { cn } from "@/lib/cn";

const KEYWORDS =
  /\b(const|let|var|await|async|import|from|export|default|return|function|if|else|for|of|try|catch|throw|new|type|interface|true|false|null|undefined|as|extends|implements)\b/;

type Token = { value: string; kind: "plain" | "string" | "number" | "keyword" | "comment" | "property" };

function tokenize(source: string): Token[] {
  const pattern =
    /(\/\/[^\n]*|#[^\n]*|\/\*[\s\S]*?\*\/|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\b\d+(?:\.\d+)?\b|[A-Za-z_$][\w$]*)(\s*:)?/g;
  const tokens: Token[] = [];
  let cursor = 0;
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(source))) {
    if (match.index > cursor) {
      tokens.push({ value: source.slice(cursor, match.index), kind: "plain" });
    }
    const [full, core, colon] = match;
    let kind: Token["kind"] = "plain";

    if (core.startsWith("//") || core.startsWith("#") || core.startsWith("/*")) kind = "comment";
    else if (core.startsWith('"') || core.startsWith("'")) kind = "string";
    else if (/^\d/.test(core)) kind = "number";
    else if (KEYWORDS.test(core)) kind = "keyword";
    else if (colon) kind = "property";

    tokens.push({ value: core, kind });
    if (colon) tokens.push({ value: colon, kind: "plain" });

    cursor = match.index + full.length;
  }

  if (cursor < source.length) {
    tokens.push({ value: source.slice(cursor), kind: "plain" });
  }
  return tokens;
}

const tone: Record<Token["kind"], string> = {
  plain: "text-[#cfc9e6]",
  string: "text-[#c9b5ff]",
  number: "text-[#a892ff]",
  keyword: "text-[#974fff]",
  comment: "text-[#5f5a72] italic",
  property: "text-[#e6e0ff]",
};

export function CodeBlock({
  code,
  filename,
  language,
  copyable = true,
  className,
}: {
  code: string;
  filename?: string;
  language?: string;
  copyable?: boolean;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);
  const tokens = useMemo(() => tokenize(code), [code]);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
    }
  };

  return (
    <figure className={cn("code-surface relative", className)}>
      <div className="flex items-center justify-between border-b border-hairline-soft px-4 py-2.5">
        <div className="flex items-center gap-3">
          <span className="flex gap-1" aria-hidden="true">
            <span className="h-1.5 w-1.5 bg-[#3a3350]" />
            <span className="h-1.5 w-1.5 bg-[#3a3350]" />
            <span className="h-1.5 w-1.5 bg-[#3a3350]" />
          </span>
          <span className="mono-sm text-ash">{filename ?? "example"}</span>
        </div>
        <div className="flex items-center gap-3">
          {language && <span className="mono-sm text-ash">{language}</span>}
          {copyable && (
            <button
              type="button"
              onClick={copy}
              className="mono-sm flex items-center gap-1.5 px-1.5 py-1 text-ash transition-colors hover:text-lavender"
              aria-label={copied ? "Copied to clipboard" : "Copy code to clipboard"}
            >
              {copied ? (
                <>
                  <Check className="h-3 w-3" aria-hidden="true" /> Copied
                </>
              ) : (
                <>
                  <Copy className="h-3 w-3" aria-hidden="true" /> Copy
                </>
              )}
            </button>
          )}
        </div>
      </div>
      <pre className="overflow-x-auto p-4 leading-[1.85] sm:p-5">
        <code className="font-mono text-[11.5px] sm:text-[12px]">
          {tokens.map((token, index) => (
            <span key={index} className={tone[token.kind]}>
              {token.value}
            </span>
          ))}
        </code>
      </pre>
    </figure>
  );
}
