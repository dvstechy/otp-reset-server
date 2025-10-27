// server.js
const express = require("express");
const cors = require("cors");
require("dotenv").config();
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");
const sgMail = require("@sendgrid/mail");

const app = express();
app.use(express.json());
app.use(
  cors({
    origin: "http://localhost:4028",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.options("*", cors());
// ---------------------------
// Supabase client
const supabase = createClient(
  process.env.VITE_SUPABASE_URL,
  process.env.VITE_SUPABASE_ANON_KEY
);

// Admin client for updating passwords
const adminSupabase = createClient(
  process.env.VITE_SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// SendGrid setup
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// ---------------------------
// Utility: Generate OTP
function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Utility: Send OTP Email
async function sendOtpEmail(to, otp) {
  const msg = {
    to,
    from: process.env.SMTP_USER, // must be a verified sender in SendGrid
    subject: "Your OTP for Password Reset",
    html: `
      <div style="font-family: Helvetica, sans-serif; color: #000;">
        <h1>Heritage Bites Password Reset</h1>
        <p>Dear User,</p>
        <p>Your OTP is:</p>
        <h2 style="color:#DC2626;">${otp}</h2>
        <p>This OTP is valid for <b>10 minutes</b>.</p>
        <p>Do not share it with anyone.</p>
      </div>
    `,
  };

  await sgMail.send(msg);
}

// ---------------------------
// 1️⃣ Send OTP
app.post("/sendOtp", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email is required" });

    const { data: user, error: userError } = await supabase
      .from("users")
      .select("*")
      .eq("email", email)
      .single();

    if (userError || !user) return res.status(404).json({ error: "User not found" });

    const otp = generateOtp();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString();

    await supabase.from("users").update({ otp, otp_expiry: otpExpiry }).eq("email", email);

    try {
      await sendOtpEmail(email, otp);
    } catch (err) {
      console.error("SendGrid error:", err);
     if (err.response && err.response.body) {
    console.error("SendGrid response body:", err.response.body);
  }
  return res.status(500).json({ error: "Failed to send OTP email" });
}

    res.json({ message: "OTP sent successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ---------------------------
// 2️⃣ Verify OTP
app.post("/verifyOtp", async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: "Email and OTP required" });

    const { data: user, error: fetchError } = await supabase
      .from("users")
      .select("*")
      .eq("email", email)
      .single();

    if (fetchError || !user) return res.status(404).json({ error: "User not found" });

    if (user.otp !== otp) return res.status(400).json({ error: "Invalid OTP" });

    const otpExpiry = new Date(user.otp_expiry);
    if (new Date() > otpExpiry) return res.status(400).json({ error: "OTP expired" });

    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetTokenExpiry = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    await supabase
      .from("users")
      .update({
        reset_token: resetToken,
        reset_token_expiry: resetTokenExpiry,
        otp: null,
        otp_expiry: null,
      })
      .eq("email", email);

    res.json({ message: "OTP verified successfully", resetToken });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
});
///
// ---------------------------
// 3️⃣ Reset Password
app.post("/resetPassword", async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;
    if (!resetToken || !newPassword)
      return res.status(400).json({ error: "Missing reset token or password" });

    const { data: user, error: fetchError } = await supabase
      .from("users")
      .select("*")
      .eq("reset_token", resetToken)
      .single();

    if (fetchError || !user) return res.status(404).json({ error: "Invalid reset token" });

    if (user.reset_token_expiry && new Date(user.reset_token_expiry) < new Date())
      return res.status(400).json({ error: "Reset token expired" });

    // Update Supabase Auth password
    const { error: updateError } = await adminSupabase.auth.admin.updateUserById(
      user.id, // Make sure this is the Supabase auth ID
      { password: newPassword }
    );

    if (updateError) return res.status(500).json({ error: updateError.message });

    await supabase
      .from("users")
      .update({ reset_token: null, reset_token_expiry: null })
      .eq("id", user.id);

    res.json({ message: "Password updated successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
});

console.log("SENDGRID_API_KEY:", !!process.env.SENDGRID_API_KEY);
console.log("SMTP_USER:", !!process.env.SMTP_USER);
// ---------------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ OTP + Reset API running on port ${PORT}`));
//comment