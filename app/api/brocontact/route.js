import nodemailer from "nodemailer";

export async function POST(req) {
  try {
    const { name, mnumber, pnumber, message } = await req.json();

    if (!name || !mnumber || !pnumber || !message) {
      return new Response(
        JSON.stringify({ success: false, error: "Missing fields" }),
        { status: 400 }
      );
    }

    // Get domain info
    
     const headers = req.headers;
    const referer = headers.get("referer");
    const host = headers.get("host");
    const domainInfo = referer || host || "Unknown Domain";

    let transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.MAIL_CONTACT_USER,
        pass: process.env.MAIL_CONTACT_PASS,
      },
    });

    await transporter.sendMail({
      from: `"Contact Form" <${process.env.MAIL_CONTACT_USER}>`,
      to: process.env.MAIL_CONTACT_TO,
      subject: "New Contact BROTER Form Submission",
      text: `From: ${domainInfo}\nName: ${name}\nModel: ${mnumber}\nPhone: ${pnumber}\nMessage: ${message}`,
    });

    return new Response(JSON.stringify({ success: true }), { status: 200 });
  } catch (error) {
    console.error("Mail error:", error);
    return new Response(
      JSON.stringify({ success: false, error: error.message }),
      { status: 500 }
    );
  }
}
