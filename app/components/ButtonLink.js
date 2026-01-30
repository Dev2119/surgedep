// components/ButtonLink.js
import Link from "next/link";

export default function ButtonLink({ children, href, variant = "primary" }) {
  const base = "px-5 py-2 font-semibold rounded-lg transition";

  const styles = {
    primary: "bg-blue-600 text-white hover:bg-blue-700 shadow-md",
    secondary: "bg-gray-300 text-gray-900 hover:bg-gray-400 shadow-md",
    outline: "border border-blue-600 text-blue-600 hover:bg-blue-50",
  };

  return (
    <Link href={href} className={`${base} ${styles[variant]}`}>
      {children}
    </Link>
  );
}
