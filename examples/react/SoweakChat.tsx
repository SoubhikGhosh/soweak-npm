import { FormEvent, useCallback, useState } from "react";
import { Decision, SecurityError, sanitizeHtml } from "soweak";
import { useSoweak } from "./useSoweak";

interface Message {
  role: "user" | "assistant" | "system";
  content: string;
}

export function SoweakChat() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [draft, setDraft] = useState("");
  const [blocked, setBlocked] = useState<string | null>(null);

  const { scanInput, scanOutput, ask } = useSoweak({
    canaries: ["x7K2-PRODSEC-9F4E"],
    llmEndpoint: "/api/chat",
    onAudit: (decision) => {
      // Ship to telemetry. Decision is shared across input/output boundaries.
      // console.debug("[soweak]", decision.action, decision.signals.length);
    },
  });

  const onSubmit = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      setBlocked(null);
      const text = draft.trim();
      if (!text) return;

      // 1. Pre-scan input.
      const inDecision = scanInput(text);
      if (Decision.isBlocked(inDecision)) {
        setBlocked(`Input blocked: ${inDecision.reason}`);
        return;
      }
      const userText = inDecision.payload.text; // may be redacted

      setMessages((m) => [...m, { role: "user", content: userText }]);
      setDraft("");

      // 2. Call LLM. safeFetch will throw SecurityError if the response is blocked.
      try {
        const reply = await ask(userText);
        // 3. Belt-and-braces — also scan the textual reply ourselves.
        const outDecision = scanOutput(reply);
        if (Decision.isBlocked(outDecision)) {
          setBlocked(`Reply blocked: ${outDecision.reason}`);
          return;
        }
        const safeReply = outDecision.payload.text;
        setMessages((m) => [...m, { role: "assistant", content: safeReply }]);
      } catch (err) {
        if (err instanceof SecurityError) {
          setBlocked(`Reply blocked: ${err.message}`);
        } else {
          setBlocked(`Network error: ${(err as Error).message}`);
        }
      }
    },
    [draft, scanInput, scanOutput, ask],
  );

  return (
    <div style={{ maxWidth: 720, margin: "0 auto", padding: 16 }}>
      <h2>soweak-guarded chat</h2>
      <div style={{ minHeight: 240, border: "1px solid #ddd", padding: 12 }}>
        {messages.map((m, i) => (
          <p key={i}>
            <b>{m.role}:</b>{" "}
            {/* Sanitize any HTML before render — the output detector flags it,
                but this is the actual render-time safe step. */}
            <span dangerouslySetInnerHTML={{ __html: sanitizeHtml(m.content) }} />
          </p>
        ))}
        {messages.length === 0 && <p style={{ color: "#888" }}>(no messages yet)</p>}
      </div>
      {blocked && (
        <div
          style={{
            marginTop: 8,
            padding: 8,
            background: "#fee",
            border: "1px solid #f88",
            color: "#900",
          }}
        >
          {blocked}
        </div>
      )}
      <form onSubmit={onSubmit} style={{ marginTop: 8, display: "flex", gap: 8 }}>
        <input
          style={{ flex: 1, padding: 8 }}
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder="Ask something..."
        />
        <button type="submit">Send</button>
      </form>
    </div>
  );
}
