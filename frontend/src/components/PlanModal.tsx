import { useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Copy, Download, RefreshCw, X } from "lucide-react";
import type { RemediationPlan } from "@/types/project";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";

export function PlanModal({
  open,
  onOpenChange,
  plan,
  loading,
  error,
  nodeTitle,
  onRegenerate,
  regenerating,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  plan: RemediationPlan | null;
  loading: boolean;
  error: string | null;
  nodeTitle: string;
  onRegenerate: () => void;
  regenerating: boolean;
}) {
  const [copied, setCopied] = useState(false);

  function handleCopy() {
    if (!plan) return;
    navigator.clipboard.writeText(plan.plan).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  function handleDownload() {
    if (!plan) return;
    const blob = new Blob([plan.plan], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `remediation-${nodeTitle.replace(/[^a-z0-9]/gi, "-").toLowerCase()}.md`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {/* [&>button]:hidden suppresses the default absolute close button so our in-header one takes over */}
      <DialogContent className="flex max-h-[90vh] max-w-3xl flex-col gap-0 p-0 [&>button]:hidden">
        <DialogHeader className="flex-row items-center gap-3 border-b border-border pl-6 pr-4 py-4">
          <DialogTitle className="min-w-0 flex-1 truncate text-base font-semibold">
            Fix Plan — <span className="font-mono">{nodeTitle}</span>
          </DialogTitle>
          <div className="flex shrink-0 items-center gap-2">
            {plan?.cached && (
              <span className="rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground">
                cached
              </span>
            )}
            {plan && (
              <>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleCopy}
                  className="h-7 text-xs"
                >
                  <Copy className="mr-1 h-3 w-3" />
                  {copied ? "Copied!" : "Copy"}
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleDownload}
                  className="h-7 text-xs"
                >
                  <Download className="mr-1 h-3 w-3" />
                  .md
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={onRegenerate}
                  disabled={regenerating}
                  className="h-7 text-xs"
                >
                  <RefreshCw
                    className={`mr-1 h-3 w-3 ${regenerating ? "animate-spin" : ""}`}
                  />
                  Regen
                </Button>
              </>
            )}
            <DialogClose className="rounded-md p-1.5 text-muted-foreground transition-opacity hover:bg-muted hover:text-foreground hover:opacity-100 opacity-70">
              <X className="h-5 w-5" />
              <span className="sr-only">Close</span>
            </DialogClose>
          </div>
        </DialogHeader>

        <div className="flex-1 overflow-y-auto px-6 py-5">
          {loading && (
            <div className="flex flex-col items-center gap-3 py-16 text-center">
              <span className="inline-block h-5 w-5 animate-spin rounded-full border-2 border-primary border-t-transparent" />
              <p className="text-sm text-muted-foreground">
                Creating your remediation plan…
              </p>
              <p className="text-xs text-muted-foreground">
                This usually takes 15–30 seconds.
              </p>
            </div>
          )}

          {error && !loading && (
            <div className="rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3 text-sm text-destructive">
              {error}
            </div>
          )}

          {plan && !loading && (
            <div
              className="prose prose-sm dark:prose-invert max-w-none
              prose-headings:font-semibold prose-headings:tracking-tight
              prose-h2:mt-6 prose-h2:text-base prose-h2:border-b prose-h2:border-border prose-h2:pb-1
              prose-h3:mt-4 prose-h3:text-sm
              prose-code:rounded prose-code:bg-muted prose-code:px-1 prose-code:py-0.5 prose-code:text-xs prose-code:font-mono prose-code:before:content-none prose-code:after:content-none
              prose-pre:bg-muted prose-pre:rounded-lg prose-pre:text-xs
              prose-li:marker:text-muted-foreground
              prose-a:text-primary"
            >
              <ReactMarkdown remarkPlugins={[remarkGfm]}>
                {plan.plan}
              </ReactMarkdown>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
