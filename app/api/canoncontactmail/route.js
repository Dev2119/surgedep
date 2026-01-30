import nodemailer from "nodemailer";

export async function POST(req) {
  try {
    const { name, mnumber, pnumber, message } = await req.json();

    // Safely extract referer/host from headers
    const headers = req.headers;
    const referer = headers.get("referer");
    const host = headers.get("host");
    const domainInfo = referer || host || "Unknown Domain";

    // Validate input fields
    if (!name || !mnumber || !pnumber || !message) {
      return new Response(
        JSON.stringify({ success: false, error: "Missing fields" }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    // Create transporter
    let transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.MAIL_CONTACT_USER,
        pass: process.env.MAIL_CONTACT_PASS,
      },
    });

    // Send email
    await transporter.sendMail({
      from: `"CANON Form" <${process.env.MAIL_CONTACT_USER}>`,
      to: process.env.MAIL_CONTACT_TO,
      subject: "New Contact CANON Form Submission",
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
      {
        status: 500,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
}
