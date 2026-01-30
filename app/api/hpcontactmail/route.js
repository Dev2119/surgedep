import nodemailer from "nodemailer";

export async function POST(req) {
  try {
    const { name, mnumber, pnumber, message } = await req.json();

    // ✅ Safely extract headers
    const headers = req.headers;
    const referer = headers.get("referer");
    const host = headers.get("host");
    const domainInfo = referer || host || "Unknown Domain";

    // ✅ Input validation
    if (!name || !mnumber || !pnumber || !message) {
      return new Response(
        JSON.stringify({ success: false, error: "Missing fields" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // ✅ Create transporter
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.MAIL_CONTACT_USER,
        pass: process.env.MAIL_CONTACT_PASS,
      },
    });

    // ✅ Send mail
    await transporter.sendMail({
      from: `"Contact Form" <${process.env.MAIL_CONTACT_USER}>`,
      to: process.env.MAIL_CONTACT_TO,
      subject: "New Contact HP Form Submission",
      text: `From: ${domainInfo}
Name: ${name}
Model: ${mnumber}
Phone: ${pnumber}
Message: ${message}`,
    });

    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    console.error("Mail error:", error);
    return new Response(
      JSON.stringify({ success: false, error: error.message }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }
}
