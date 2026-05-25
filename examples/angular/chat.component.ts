import { CommonModule } from "@angular/common";
import { Component, inject, signal } from "@angular/core";
import { FormsModule } from "@angular/forms";
import { Decision, SecurityError, sanitizeHtml } from "soweak";
import { SoweakService } from "./soweak.service";

interface Message {
  role: "user" | "assistant";
  html: string;
}

@Component({
  selector: "soweak-chat",
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="container">
      <h2>soweak-guarded chat</h2>
      <div class="log">
        <p *ngFor="let m of messages()">
          <b>{{ m.role }}:</b>
          <span [innerHTML]="m.html"></span>
        </p>
        <p *ngIf="messages().length === 0" class="muted">(no messages yet)</p>
      </div>
      <div *ngIf="blocked()" class="blocked">{{ blocked() }}</div>
      <form (ngSubmit)="onSubmit()">
        <input [(ngModel)]="draft" name="draft" placeholder="Ask something..." />
        <button type="submit">Send</button>
      </form>
    </div>
  `,
  styles: [
    `
      .container {
        max-width: 720px;
        margin: 0 auto;
        padding: 16px;
      }
      .log {
        min-height: 240px;
        border: 1px solid #ddd;
        padding: 12px;
      }
      .muted {
        color: #888;
      }
      .blocked {
        margin-top: 8px;
        padding: 8px;
        background: #fee;
        border: 1px solid #f88;
        color: #900;
      }
      form {
        display: flex;
        gap: 8px;
        margin-top: 8px;
      }
      input {
        flex: 1;
        padding: 8px;
      }
    `,
  ],
})
export class SoweakChatComponent {
  private readonly soweak = inject(SoweakService);

  messages = signal<Message[]>([]);
  draft = "";
  blocked = signal<string | null>(null);

  async onSubmit(): Promise<void> {
    this.blocked.set(null);
    const text = this.draft.trim();
    if (!text) return;

    const inDecision = this.soweak.scanInput(text);
    if (Decision.isBlocked(inDecision)) {
      this.blocked.set(`Input blocked: ${inDecision.reason}`);
      return;
    }
    const userText = inDecision.payload.text;
    this.messages.update((m) => [...m, { role: "user", html: sanitizeHtml(userText) }]);
    this.draft = "";

    try {
      const res = await this.soweak.safeFetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt: userText }),
      });
      const data = (await res.json()) as { output?: string; content?: string };
      const reply = data.output ?? data.content ?? "";

      const outDecision = this.soweak.scanOutput(reply);
      if (Decision.isBlocked(outDecision)) {
        this.blocked.set(`Reply blocked: ${outDecision.reason}`);
        return;
      }
      this.messages.update((m) => [
        ...m,
        { role: "assistant", html: sanitizeHtml(outDecision.payload.text) },
      ]);
    } catch (err) {
      if (err instanceof SecurityError) {
        this.blocked.set(`Reply blocked: ${err.message}`);
      } else {
        this.blocked.set(`Network error: ${(err as Error).message}`);
      }
    }
  }
}
