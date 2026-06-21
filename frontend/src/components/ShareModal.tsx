import { useState } from "react";
import { X } from "lucide-react";
import { shareProject, revokeShare } from "@/lib/api";
import type { Project, ProjectShare } from "@/types/project";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

export function ShareModal({
  project,
  open,
  onOpenChange,
  onSharesChange,
}: {
  project: Project;
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onSharesChange?: (shares: ProjectShare[]) => void;
}) {
  const [email, setEmail] = useState("");
  const [sharing, setSharing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [shares, setShares] = useState<ProjectShare[]>(project.shares ?? []);
  const [revoking, setRevoking] = useState<string | null>(null);

  async function handleShare() {
    const trimmed = email.trim();
    if (!trimmed) return;
    setSharing(true);
    setError(null);
    try {
      const share = await shareProject(project.id, trimmed);
      const next = [...shares.filter((s) => s.id !== share.id), share];
      setShares(next);
      onSharesChange?.(next);
      setEmail("");
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to share project";
      // Try to extract a cleaner error from JSON error body
      try {
        const parsed = JSON.parse(msg);
        setError(parsed.detail ?? msg);
      } catch {
        setError(msg);
      }
    } finally {
      setSharing(false);
    }
  }

  async function handleRevoke(shareId: string) {
    setRevoking(shareId);
    try {
      await revokeShare(project.id, shareId);
      const next = shares.filter((s) => s.id !== shareId);
      setShares(next);
      onSharesChange?.(next);
    } catch {
      // keep share in list if revoke fails
    } finally {
      setRevoking(null);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Share "{project.name}"</DialogTitle>
        </DialogHeader>

        <div className="space-y-4 pt-1">
          <div className="flex gap-2">
            <Input
              type="email"
              placeholder="colleague@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && !sharing && handleShare()}
              disabled={sharing}
            />
            <Button onClick={handleShare} disabled={sharing || !email.trim()}>
              {sharing ? "Sharing…" : "Invite"}
            </Button>
          </div>

          {error && (
            <p className="text-sm text-destructive">{error}</p>
          )}

          {shares.length > 0 && (
            <div>
              <p className="mb-2 text-xs font-medium uppercase tracking-wider text-muted-foreground">
                Shared with
              </p>
              <ul className="space-y-1.5">
                {shares.map((s) => (
                  <li
                    key={s.id}
                    className="flex items-center justify-between rounded-md bg-muted/40 px-3 py-1.5"
                  >
                    <span className="text-sm">{s.shared_with_email}</span>
                    <button
                      onClick={() => handleRevoke(s.id)}
                      disabled={revoking === s.id}
                      className="ml-2 rounded p-0.5 text-muted-foreground hover:text-destructive disabled:opacity-40"
                      aria-label={`Revoke access for ${s.shared_with_email}`}
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {shares.length === 0 && (
            <p className="text-sm text-muted-foreground">
              No one else has access yet. Invite them by email above.
            </p>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
