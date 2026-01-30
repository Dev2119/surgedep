import nodemailer from "nodemailer";

export async function POST(req) {
  try {
    const { EPmodel } = await req.json();

    // ✅ Extract domain info safely from headers
    const headers = req.headers;
    const referer = headers.get("referer");
    const host = headers.get("host");
    const domainInfo = referer || host || "Unknown Domain";

    // ✅ Validate input
    if (!EPmodel) {
      return new Response(
        JSON.stringify({ success: false, error: "Epson model missing" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // ✅ Setup transporter
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.MAIL_EP_USER,
        pass: process.env.MAIL_EP_PASS,
      },
    });

    // ✅ Send email
    await transporter.sendMail({
      from: `"EPSON Form" <${process.env.MAIL_EP_USER}>`,
      to: process.env.MAIL_EP_TO,
      subject: "New EPSON Printer Submission",
      text: `From: ${domainInfo}\nEPSON Printer Model: ${EPmodel}`,
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
