import nodemailer from "nodemailer";

export async function POST(req) {
  try {
    const { bromodel, fullName, phoneNumber } = await req.json();

    // Get headers properly
    const headers = req.headers;
    const referer = headers.get("referer");
    const host = headers.get("host");
    const domainInfo = referer || host || "Unknown Domain";

    if (!bromodel) {
      return new Response(
        JSON.stringify({ success: false, error: "Printer model missing" }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    // Setup transporter
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.MAIL_BRO_USER,
        pass: process.env.MAIL_BRO_PASS,
      },
    });

    // Send the mail
    await transporter.sendMail({
      from: `"BROTHER Form" <${process.env.MAIL_BRO_USER}>`,
      to: process.env.MAIL_BRO_TO,
      subject: "New BROTHER Printer Submission",
      text: `From: ${domainInfo}\nModel: ${bromodel}\nFull Name: ${fullName}\nPhone Number: ${phoneNumber}`,
      html: `
        <p><b>From:</b> ${domainInfo}</p>
        <p><b>BROTHER Printer Model:</b> ${bromodel}</p>
        <p><b>Full Name:</b> ${fullName}</p>
        <p><b>Phone Number:</b> ${phoneNumber}</p>
      `,
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
