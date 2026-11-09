import { forwardRef, type ButtonHTMLAttributes } from "react";
import Icon, { type IconName } from "./Icon";

export type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "ghost" | "danger";
  size?: "sm" | "md";
  icon?: IconName;
  /** Shows a spinner, disables the button and sets aria-busy. */
  loading?: boolean;
};

const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "secondary", size = "md", icon, loading, className, children, disabled, type = "button", ...rest }, ref,
) {
  const cls = ["btn", `btn-${variant}`, size === "sm" && "btn-sm", !children && "btn-icon", className].filter(Boolean).join(" ");
  return (
    <button ref={ref} type={type} className={cls} disabled={disabled || loading} aria-busy={loading || undefined} {...rest}>
      {loading ? <span className="spinner" aria-hidden="true" /> : icon && <Icon name={icon} size={size === "sm" ? 14 : 16} />}
      {children}
    </button>
  );
});
export default Button;
