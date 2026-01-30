import nodemailer from "nodemailer";

export async function POST(req) {
  try {
    const { hpmodel } = await req.json();

    // ✅ Safely get domain info from headers
    const headers = req.headers;
    const referer = headers.get("referer");
    const host = headers.get("host");
    const domainInfo = referer || host || "Unknown Domain";

    // ✅ Validate input
    if (!hpmodel) {
      return new Response(
        JSON.stringify({ success: false, error: "HP model missing" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // ✅ Set up mail transporter
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.MAIL_HP_USER,
        pass: process.env.MAIL_HP_PASS,
      },
    });

    // ✅ Send email
    await transporter.sendMail({
      from: `"HP Form" <${process.env.MAIL_HP_USER}>`,
      to: process.env.MAIL_HP_TO,
      subject: "New HP Printer Submission",
      text: `From: ${domainInfo}\nHP Printer Model: ${hpmodel}`,
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
