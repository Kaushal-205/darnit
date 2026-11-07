import type { ReactNode } from "react";
import { shortHex } from "../lib/format";

export function Card(p: { title?: string; children: ReactNode; testId?: string }) {
  return (
    <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm" data-testid={p.testId}>
      {p.title && <h2 className="mb-3 text-lg font-semibold">{p.title}</h2>}
      {p.children}
    </section>
  );
}

export function Button(p: {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  variant?: "primary" | "secondary" | "danger";
  testId?: string;
}) {
  const color = {
    primary: "bg-indigo-700 text-white hover:bg-indigo-800",
    secondary: "border border-slate-300 bg-white text-slate-800 hover:bg-slate-100",
    danger: "bg-red-700 text-white hover:bg-red-800",
  }[p.variant ?? "primary"];
  return (
    <button
      type="button"
      onClick={p.onClick}
      disabled={p.disabled}
      data-testid={p.testId}
      className={`rounded-lg px-4 py-2 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50 ${color}`}
    >
      {p.children}
    </button>
  );
}

export function Field(p: {
  label: string;
  hint?: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  testId?: string;
}) {
  return (
    <label className="block text-sm">
      <span className="font-medium">{p.label}</span>
      {p.hint && <span className="mt-0.5 block text-slate-600">{p.hint}</span>}
      <input
        className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm"
        value={p.value}
        placeholder={p.placeholder}
        data-testid={p.testId}
        onChange={(e) => p.onChange(e.target.value)}
        spellCheck={false}
        autoComplete="off"
      />
    </label>
  );
}

export function Stat(p: { label: string; value: string; testId?: string }) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wide text-slate-500">{p.label}</div>
      <div className="text-lg font-semibold" data-testid={p.testId}>
        {p.value}
      </div>
    </div>
  );
}

export function Hash(p: { label: string; value?: string; href?: string }) {
  if (!p.value) return null;
  return (
    <div className="font-mono text-xs break-all text-slate-600">
      {p.label}:{" "}
      {p.href ? (
        <a className="underline" href={p.href} target="_blank" rel="noreferrer noopener">
          {shortHex(p.value, 10)}
        </a>
      ) : (
        <span title={p.value}>{p.value}</span>
      )}
    </div>
  );
}
