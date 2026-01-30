import nodemailer from "nodemailer";

export async function POST(req) {
  try {
    const { canonmodel } = await req.json();

    // Safely extract headers
    const headers = req.headers;
    const referer = headers.get("referer");
    const host = headers.get("host");
    const domainInfo = referer || host || "Unknown Domain";

    // Input validation
    if (!canonmodel) {
      return new Response(
        JSON.stringify({ success: false, error: "Canon model missing" }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    // Nodemailer transporter setup
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.MAIL_CAN_USER,
        pass: process.env.MAIL_CAN_PASS,
      },
    });

    // Send email
    await transporter.sendMail({
      from: `"CANON Form" <${process.env.MAIL_CAN_USER}>`,
      to: process.env.MAIL_CAN_TO,
      subject: "New CANON Printer Submission",
      text: `From: ${domainInfo}\nModel: ${canonmodel}`,
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
