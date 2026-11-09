import { useEffect, type ReactNode } from "react";
import { Link } from "react-router-dom";

export type Crumb = { label: string; to?: string };

export default function PageHeader({ title, description, actions, crumbs }: {
  title: ReactNode; description?: ReactNode; actions?: ReactNode; crumbs?: Crumb[];
}) {
  useEffect(() => { if (typeof title === "string") document.title = `${title} · JASCA`; }, [title]);
  return (
    <header className="page-header">
      <div className="page-header-text">
        {crumbs && crumbs.length > 0 && (
          <nav aria-label="현재 위치" className="crumbs">
            <ol>
              {crumbs.map((c, i) => (
                <li key={i}>{c.to ? <Link to={c.to}>{c.label}</Link> : <span aria-current="page">{c.label}</span>}</li>
              ))}
            </ol>
          </nav>
        )}
        <h1 tabIndex={-1}>{title}</h1>
        {description && <p className="page-desc">{description}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}
