import { NextApp } from "./components/NextApp";

// The redesigned shell is now the only UI (the classic flag-gated path was
// removed once every section reached parity). See components/NextApp.tsx.
export default function App() {
  return <NextApp />;
}
