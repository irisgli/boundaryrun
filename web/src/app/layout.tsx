import type { Metadata } from "next";
import Link from "next/link";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });

export const metadata: Metadata = {
  title: "BoundaryRun",
  description: "Evidence viewer for BoundaryRun investigations and evaluations.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}>
      <body className="min-h-full flex flex-col">
        <header className="border-b border-line bg-panel">
          <div className="mx-auto max-w-[1400px] px-5 py-2.5 flex items-baseline gap-5">
            <Link href="/" className="text-foreground font-semibold tracking-tight hover:no-underline">
              BoundaryRun
            </Link>
            <span className="text-muted text-xs">evidence viewer</span>
            <nav className="ml-auto flex gap-4 text-xs">
              <Link href="/">Runs</Link>
              <Link href="/about">What the numbers mean</Link>
            </nav>
          </div>
        </header>
        <main className="mx-auto w-full max-w-[1400px] px-5 py-5 flex-1">{children}</main>
        <footer className="border-t border-line text-muted text-[11px] px-5 py-2 mx-auto w-full max-w-[1400px]">
          Every value on these pages is read from report.json, audit.jsonl and summary.json on disk at request time.
          Nothing is computed client side and nothing is sampled.
        </footer>
      </body>
    </html>
  );
}
