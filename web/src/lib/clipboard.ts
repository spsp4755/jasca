// The only place allowed to touch navigator.clipboard. It is missing on plain-HTTP intranet pages,
// so fall back to a hidden textarea + execCommand('copy'). Resolves true on success.
export async function copyText(text: string): Promise<boolean> {
  try {
    if (window.isSecureContext && navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch { /* fall through to the textarea path */ }
  const back = document.activeElement as HTMLElement | null; // give focus back so keyboard users stay on the button
  const ta = document.createElement("textarea");
  try {
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.cssText = "position:fixed;top:0;left:0;opacity:0";
    document.body.appendChild(ta);
    ta.select();
    return document.execCommand("copy");
  } catch {
    return false;
  } finally {
    ta.remove();
    back?.focus?.();
  }
}
