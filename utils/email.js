const nodemailer = require("nodemailer");
require("dotenv").config();

// Nodemailer transporter configuration
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER, // Use a valid email
        pass: process.env.EMAIL_PASS, // Use App Password if using Gmail
    },
});


async function sendCredentials(email, username, password) {
    // if (!confirm(Are you sure you want to send credentials to ${email}?)) return;
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Your Faculty Login Credentials",
        text: `Hello,\n\nYour login credentials are:\nUsername: ${username}\nPassword: ${password}\n\nPlease change your password after logging in.\n\nRegards,\nAdmin Team,`
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`✅ Email sent to ${email}`);
    } catch (error) {
        console.error(`❌ Error sending email to ${email}:`, error);
        throw new Error("Failed to send email.");
    }
}

async function sendCredentialsToAll(facultyList) {
    let successCount = 0;
    let failureCount = 0;

    for (const faculty of facultyList) {
        const { email, username, password } = faculty;
        try {
            await sendCredentials(email, username, password);
            successCount++;
        } catch (error) {
            failureCount++;
        }
    }

    console.log(`✅ Successfully sent ${successCount} emails, ❌ Failed to send ${failureCount} emails.`);
}

module.exports = { sendCredentials, sendCredentialsToAll };