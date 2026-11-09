import type { ReactNode } from "react";
import Icon, { type IconName } from "./Icon";

/** Empty state: say what is missing and what to do next (`action`). */
export default function Empty({ title, description, action, icon = "inbox", compact }: {
  title: ReactNode; description?: ReactNode; action?: ReactNode; icon?: IconName; compact?: boolean;
}) {
  return (
    <div className={`empty${compact ? " empty-compact" : ""}`}>
      <span className="empty-icon"><Icon name={icon} size={compact ? 18 : 20} /></span>
      <p className="empty-title">{title}</p>
      {description && <p className="empty-desc">{description}</p>}
      {action && <div className="empty-action">{action}</div>}
    </div>
  );
}
