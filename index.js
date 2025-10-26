const express = require("express");
const cors = require("cors");
require("dotenv").config();
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.use(cors());
app.use(express.json());

const supabase = createClient(
  process.env.VITE_SUPABASE_URL,
  process.env.VITE_SUPABASE_ANON_KEY
);

// -----------------------------------
// 🔹 Utility: Generate OTP
function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// 🔹 Utility: Send Email
async function sendEmail(to, otp) {
  const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false, // TLS
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});


  const mailOptions = {
    from: `"Heritage Bites" <${process.env.SMTP_USER}>`,
    to,
    subject: "Your OTP for Reset Password",
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

  return transporter.sendMail(mailOptions);
}

// -----------------------------------
// 🔹 1. Send OTP Route
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
    await sendEmail(email, otp);

    res.json({ message: "OTP sent successfully" });
  } catch (error) {
    console.error("Error sending OTP:", error);
    res.status(500).json({ error: "Failed to send OTP" });
  }
});

// -----------------------------------
// 🔹 2. Verify OTP Route
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
    console.error("Error verifying OTP:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// -----------------------------------
// 🔹 3. Reset Password Route
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

    // Use service role key to update password
    const adminSupabase = createClient(
      process.env.VITE_SUPABASE_URL,
      process.env.SUPABASE_SERVICE_ROLE_KEY
    );

    const { error: updateError } = await adminSupabase.auth.admin.updateUserById(user.user_id, {
      password: newPassword,
    });

    if (updateError) return res.status(500).json({ error: updateError.message });

    await adminSupabase
      .from("users")
      .update({ reset_token: null, reset_token_expiry: null })
      .eq("user_id", user.user_id);

    res.json({ message: "Password updated successfully" });
  } catch (error) {
    console.error("Error resetting password:", error);
    res.status(500).json({ error: "Something went wrong" });
  }
});

// -----------------------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ OTP + Reset API running on port ${PORT}`));
