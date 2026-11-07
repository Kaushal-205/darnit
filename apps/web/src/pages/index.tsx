import { useEffect, useState } from "react";
import { App } from "../components/App";

/** Static shell: the app runs only in the browser, where the passkey, keys and settings live. */
export default function Index() {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  return mounted ? <App /> : <p className="p-6 text-sm text-slate-600">Loading…</p>;
}
