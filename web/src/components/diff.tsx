export function Diff({ text }: { text: string }) {
  if (!text.trim()) return <p className="text-muted text-xs">Empty diff.</p>;
  const lines = text.replace(/\n$/, "").split("\n");
  return (
    <pre className="block diff">
      {lines.map((line, i) => {
        let cls = "";
        if (line.startsWith("+++") || line.startsWith("---")) cls = "file";
        else if (line.startsWith("@@")) cls = "hunk";
        else if (line.startsWith("+")) cls = "add";
        else if (line.startsWith("-")) cls = "del";
        return (
          <span key={i} className={cls}>
            {line}
            {"\n"}
          </span>
        );
      })}
    </pre>
  );
}
