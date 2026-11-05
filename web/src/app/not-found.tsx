import Link from "next/link";

export default function NotFound() {
  return (
    <div className="space-y-2">
      <h1 className="text-base font-semibold">Not found</h1>
      <p className="text-muted">No report or summary with that identifier exists under the runs directory.</p>
      <Link href="/">Back to runs</Link>
    </div>
  );
}
