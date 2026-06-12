import { LangToggle } from "./LangToggle";
import { ThemeToggle } from "./ThemeToggle";

export function Header() {
  return (
    <header className="sticky top-0 z-20 border-b bg-card/80 backdrop-blur supports-[backdrop-filter]:bg-card/60">
      <div className="container flex h-16 items-center justify-between gap-4">
        <img
          src="/logo.svg"
          alt="BomLens — an SBOM generator"
          className="h-9 w-auto shrink-0"
        />
        <div className="flex shrink-0 items-center gap-2">
          <LangToggle />
          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}
