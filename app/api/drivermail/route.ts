// app/api/drivermail/route.js
import nodemailer from "nodemailer";

export const runtime = "nodejs";        // ensure Node.js runtime (not edge)
export const dynamic = "force-dynamic"; // avoid static optimization for API

export async function POST(req) {
  try {
    const { fullName, phoneNumber, bromodel } = await req.json();

    if (!fullName || !phoneNumber || !bromodel) {
      return Response.json(
        { success: false, message: "Missing required fields." },
        { status: 400 }
      );
    }

    // --- derive domain / URL from headers ---
    const headers = req.headers;
    const referer = headers.get("referer") || "";               // exact page the form was on (if sent)
    const xfh = headers.get("x-forwarded-host") || "";          // behind proxies (Vercel, Nginx)
    const host = headers.get("host") || "";
    const proto =
      headers.get("x-forwarded-proto") ||
      (referer ? new URL(referer).protocol.replace(":", "") : "https");

    const siteOrigin = referer
      ? new URL(referer).origin
      : (xfh || host) ? `${proto}://${xfh || host}` : "";

    const siteDomain = siteOrigin ? new URL(siteOrigin).hostname : "Unknown Domain";
    const domainInfo = referer || siteOrigin || "Unknown Domain";

    // --- create transporter from env vars ---
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: Number(process.env.SMTP_PORT) === 465 || process.env.SMTP_SECURE === "true",
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    });

    const to = process.env.MAIL_TO || process.env.SMTP_USER;
    const from = process.env.MAIL_FROM || process.env.SMTP_USER;

    const subject = `Driver Request: ${bromodel} from ${fullName}`;

    const text = `New Driver Request
From: ${domainInfo}
Host: ${siteDomain}
Name: ${fullName}
Phone: ${phoneNumber}
Printer Model: ${bromodel}`;

    const html = `
      <div style="font-family:Arial, sans-serif; line-height:1.6">
        <h2>New Driver Request</h2>
        <p><strong>From:</strong> ${escapeHtml(domainInfo)}</p>
        <p><strong>Host:</strong> ${escapeHtml(siteDomain)}</p>
        <p><strong>Name:</strong> ${escapeHtml(fullName)}</p>
        <p><strong>Phone:</strong> ${escapeHtml(phoneNumber)}</p>
        <p><strong>Printer Model:</strong> ${escapeHtml(bromodel)}</p>
        <hr />
        <p>Sent from your website drivermail form.</p>
      </div>
    `;

    await transporter.sendMail({ from, to, subject, text, html, replyTo: from });

    return Response.json({ success: true });
  } catch (err) {
    console.error("drivermail error:", err);
    return Response.json(
        { success: false, message: "Email send failed." },
        { status: 500 }
    );
  }
}

// Basic HTML escape to prevent markup injection in emails
function escapeHtml(str = "") {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
