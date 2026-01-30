// app/api/contact/route.js
export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { NextResponse } from "next/server";
import nodemailer from "nodemailer";

/**
 * Full, corrected contact-mail API route.
 * - Validates input
 * - Validates environment configuration
 * - Verifies SMTP connection
 * - Sends mail with explicit envelope (to expose SMTP-level RCPT failures)
 * - Returns clear HTTP status codes and sanitized errors
 */

export async function POST(req) {
  try {
    const payload = await req.json().catch(() => null);
    if (!payload) {
      return NextResponse.json({ success: false, error: "Invalid JSON payload" }, { status: 400 });
    }

    const { fullName, modelNumber, phoneNumber, description } = payload;

    // Basic required fields validation
    if (!fullName || !modelNumber || !phoneNumber) {
      return NextResponse.json({ success: false, error: "Missing required fields" }, { status: 400 });
    }

    // Environment sanity check (do not log secrets)
    const requiredEnvs = ["SMTP_HOST", "SMTP_USER", "SMTP_PASS", "MAIL_FROM", "MAIL_TO"];
    const missing = requiredEnvs.filter((k) => !process.env[k] || !String(process.env[k]).trim());
    if (missing.length) {
      console.error("Missing ENV keys:", missing.join(", "));
      return NextResponse.json({ success: false, error: "Email not configured on server" }, { status: 500 });
    }

    // Simple email validation
    const mailFrom = String(process.env.MAIL_FROM).trim();
    const mailTo = String(process.env.MAIL_TO).trim();
    const replyTo = process.env.REPLY_TO ? String(process.env.REPLY_TO).trim() : undefined;

    if (!isEmail(mailFrom) || !isEmail(mailTo) || (replyTo && !isEmail(replyTo))) {
      console.error("Invalid MAIL_FROM or MAIL_TO env values (masked):", maskEmail(mailFrom), maskEmail(mailTo), replyTo ? maskEmail(replyTo) : "");
      return NextResponse.json({ success: false, error: "Server email addresses appear invalid" }, { status: 500 });
    }

    // Derive domain / origin info from headers for context in the email
    const headers = req.headers || new Headers();
    const referer = headers.get?.("referer") || "";
    const xfh = headers.get?.("x-forwarded-host") || "";
    const host = headers.get?.("host") || "";
    const proto =
      headers.get?.("x-forwarded-proto") ||
      (referer ? new URL(referer).protocol.replace(":", "") : "https");

    const siteOrigin = referer ? new URL(referer).origin : (xfh || host) ? `${proto}://${xfh || host}` : "";
    const siteDomain = siteOrigin ? new URL(siteOrigin).hostname : "Unknown Domain";
    const domainInfo = referer || siteOrigin || "Unknown Domain";

    // Create transporter
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: String(process.env.SMTP_SECURE || "false").toLowerCase() === "true",
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
      // Optional: add tls options if your provider needs them (uncomment & adjust)
      // tls: { rejectUnauthorized: false },
    });

    // Verify SMTP connection early
    try {
      await transporter.verify();
      console.log("SMTP verify OK for host:", process.env.SMTP_HOST);
    } catch (verifyErr) {
      console.error("SMTP verify failed:", sanitizeErrorForLogs(verifyErr));
      return NextResponse.json({ success: false, error: "Email transport verification failed" }, { status: 500 });
    }

    // Prepare email content
    const subject = `Contact Form - ${String(modelNumber)}`;
    const text =
      `From: ${domainInfo}\n` +
      `Host: ${siteDomain}\n` +
      `Full Name: ${fullName}\n` +
      `Model Number: ${modelNumber}\n` +
      `Phone Number: ${phoneNumber}\n\n` +
      `${description || ""}`;

    const html = `
      <h2>New Contact Query</h2>
      <p><strong>From:</strong> ${escapeHtml(domainInfo)}</p>
      <p><strong>Host:</strong> ${escapeHtml(siteDomain)}</p>
      <p><strong>Full Name:</strong> ${escapeHtml(fullName)}</p>
      <p><strong>Model Number:</strong> ${escapeHtml(modelNumber)}</p>
      <p><strong>Phone Number:</strong> ${escapeHtml(phoneNumber)}</p>
      <p><strong>Description:</strong></p>
      <p>${escapeHtml(description || "")}</p>
    `;

    // Send mail with explicit envelope so SMTP RCPT TO failures appear clearly
    try {
      const info = await transporter.sendMail({
        from: `"Website Query" <${mailFrom}>`,
        to: mailTo,
        replyTo: replyTo || undefined,
        subject,
        text,
        html,
        envelope: {
          from: mailFrom,
          to: mailTo,
        },
      });

      // info.accepted/info.rejected are arrays from nodemailer
      console.log("Message sent (id):", info.messageId);
      console.log("SMTP accepted:", Array.isArray(info.accepted) ? info.accepted.map(maskEmail).join(", ") : info.accepted);
      console.log("SMTP rejected:", Array.isArray(info.rejected) ? info.rejected.map(maskEmail).join(", ") : info.rejected);

      // If the provider explicitly rejected recipients at SMTP level, return 502
      if (Array.isArray(info.rejected) && info.rejected.length) {
        return NextResponse.json({ success: false, error: "Recipient rejected by remote mail server" }, { status: 502 });
      }

      return NextResponse.json({ success: true }, { status: 200 });
    } catch (sendErr) {
      // Log a sanitized version for diagnostics, and return the core message to caller for debugging
      console.error("sendMail error:", sanitizeErrorForLogs(sendErr));
      // The raw SMTP error message often lives on sendErr.message
      const debugMessage = sendErr && sendErr.message ? String(sendErr.message) : "Email send failed";
      // For production, you may want to hide debugMessage and return a generic message.
      return NextResponse.json({ success: false, error: debugMessage }, { status: 500 });
    }
  } catch (err) {
    console.error("contactmail route unexpected error:", sanitizeErrorForLogs(err));
    return NextResponse.json({ success: false, error: "Server error" }, { status: 500 });
  }
}

/* -------------------- Helpers -------------------- */

function escapeHtml(str) {
  return String(str || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function isEmail(s) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(s || "").trim());
}

// Mask email for logs: a**...@domain.com
function maskEmail(s) {
  try {
    const email = String(s || "");
    const [local, domain] = email.split("@");
    if (!local || !domain) return email;
    const head = local.slice(0, Math.min(2, local.length));
    return `${head}***@${domain}`;
  } catch {
    return String(s);
  }
}

// Reduce large error objects to safe strings for logs (avoid printing secrets)
function sanitizeErrorForLogs(err) {
  try {
    if (!err) return "";
    if (typeof err === "string") return err;
    if (err instanceof Error) {
      // include name and message only
      return `${err.name}: ${err.message}`;
    }
    // Fallback: try JSON safe string
    return JSON.stringify(err, Object.keys(err).slice(0, 5));
  } catch {
    return "Error (failed to sanitize)";
  }
}
