
import { db } from "../db.js";
import bcrypt from "bcrypt";
import { body, validationResult } from "express-validator";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import nodemailer from "nodemailer";
import { OAuth2Client } from "google-auth-library";

dotenv.config();

const oAuth2Client = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  "postmessage"
);

const transporter = nodemailer.createTransport({
  service: "Gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const sendVerificationEmail = async (email, userId) => {
  const token = jwt.sign({ id: userId }, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });
  const verifyUrl = `${process.env.FRONTEND_ORIGIN}/verify?token=${token}`;

  await transporter.sendMail({
    to: email,
    subject: "Verify your account",
    html: `<p>Click the link to verify your account:</p><a href="${verifyUrl}">${verifyUrl}</a>`,
  });
};

const cookieOptions = {
  httpOnly: true,
  secure:
    process.env.NODE_ENV === "production" ||
    process.env.COOKIE_SECURE_DEV === "true",
  sameSite: "Lax",
  path: "/",
  maxAge: 7 * 24 * 60 * 60 * 1000,
};

export const googleLogin = async (req, res) => {
  const { code } = req.body;

  try {
    const { tokens } = await oAuth2Client.getToken(code);
    const { id_token } = tokens;

    if (!id_token) {
      return res.status(400).json("Authentication failed. No ID token received.");
    }

    const ticket = await oAuth2Client.verifyIdToken({
      idToken: id_token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const { email, name } = payload;

    if (!email) {
      return res.status(400).json("Authentication failed: Email not found in Google payload.");
    }

    const usernameFromEmail = email.split("@")[0];

    db.query(
      "SELECT id, username, email FROM users WHERE email = ?",
      [email],
      (err, existingUsers) => {
        if (err) {
          console.error("DB error during Google login user lookup:", err);
          return res.status(500).json("Error during Google login.");
        }

        const userData = existingUsers[0];

        const token = jwt.sign(
          { id: userData?.id ?? undefined },
          process.env.JWT_SECRET,
          { expiresIn: "7d" }
        );

        if (userData) {
          return res
            .cookie("access_token", token, cookieOptions)
            .status(200)
            .json({ message: "Login successful", user: userData });
        }

        const currentDate = new Date().toISOString().split("T")[0];
        const newUser = [
          name,
          email,
          usernameFromEmail,
          null, // password
          "user",
          true, // isVerified
           // birthday
          currentDate,
        ];

        db.query(
          "INSERT INTO users (name, email, username, password, role, isVerified, memberSince) VALUES (?)",
          [newUser],
          (insertErr, result) => {
            if (insertErr) {
              console.error("DB error during Google user insert:", insertErr);
              return res.status(500).json("Failed to register via Google.");
            }

            const createdUser = {
              id: result.insertId,
              email,
              username: usernameFromEmail,
            };

            const token = jwt.sign(
              { id: result.insertId },
              process.env.JWT_SECRET,
              { expiresIn: "7d" }
            );

            return res
              .cookie("access_token", token, cookieOptions)
              .status(200)
              .json({
                message: "Registered and logged in successfully with Google",
                user: createdUser,
              });
          }
        );
      }
    );
  } catch (err) {
    console.error("Google login processing error:", err);
    return res.status(500).json("Google login failed. Please try again.");
  }
};

export const register = [
  body("name").notEmpty().trim().escape().withMessage("Name is required."),
  body("email").isEmail().normalizeEmail().withMessage("Valid email required."),
  body("username")
    .notEmpty()
    .trim()
    .escape()
    .isLength({ min: 3, max: 20 })
    .withMessage("Username must be 3–20 characters."),
  body("password")
    .isLength({ min: 6 })
    .withMessage("Password must be at least 6 characters."),
  body("birthday")
    .notEmpty()
    .withMessage("Birthday is required.")
    .isDate()
    .withMessage("Invalid date format."),

  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, username, password, birthday } = req.body;

    db.query(
      "SELECT id FROM users WHERE email = ? OR username = ?",
      [email, username],
      async (err, existingUsers) => {
        if (err) {
          console.error("DB error during register user lookup:", err);
          return res.status(500).json("An unexpected error occurred.");
        }

        if (existingUsers.length) {
          return res.status(409).json("User already exists with this email or username.");
        }

        const hash = bcrypt.hashSync(password, bcrypt.genSaltSync(10));
        const currentDate = new Date().toISOString().split("T")[0];
        const userFields = [
          name,
          email,
          username,
          hash,
          "user",
          false,
          null, // verificationToken
          birthday,
          currentDate,
        ];

        db.query(
          "INSERT INTO users(name, email, username, password, role, isVerified, verificationToken, birthday, memberSince) VALUES(?)",
          [userFields],
          async (insertErr, result) => {
            if (insertErr) {
              console.error("DB error during user registration insert:", insertErr);
              return res.status(500).json("Failed to register user.");
            }

            try {
              await sendVerificationEmail(email, result.insertId);
              return res.status(200).json("User created. Please verify your email.");
            } catch (emailErr) {
              console.error("Error sending verification email:", emailErr);
              return res
                .status(500)
                .json("User registered, but email verification failed. Please contact support.");
            }
          }
        );
      }
    );
  },
];

export const login = (req, res) => {
  const { username, password } = req.body;

  db.query(
    "SELECT id, username, password, isVerified FROM users WHERE username = ?",
    [username],
    (err, users) => {
      if (err) {
        console.error("DB error during login user lookup:", err);
        return res.status(500).json("An unexpected error occurred.");
      }

      const user = users[0];

      if (!user) {
        return res.status(404).json("Incorrect username or password");
      }

      if (!user.isVerified) {
        return res.status(200).json("Please verify your email before logging in.");
      }

      if (!user.password) {
        return res.status(400).json("This account was created with Google. Please use Google login.");
      }

      const isPasswordCorrect = bcrypt.compareSync(password, user.password);

      if (!isPasswordCorrect) {
        return res.status(400).json("Incorrect username or password");
      }

      const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
        expiresIn: "7d",
      });

      const { password: _, ...userInfo } = user;

      res
        .cookie("access_token", token, cookieOptions)
        .status(200)
        .json({ ...userInfo, message: "Login successful" });
    }
  );
};


export const verifyEmail = (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.status(400).json("Verification token is missing.");
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error("JWT verification error:", err);
      const errorMessage =
        err.name === "TokenExpiredError"
          ? "Verification link has expired. Please request a new one."
          : "Invalid verification link.";
      return res.status(403).json(errorMessage);
    }

    const userId = decoded.id;

    db.query(
      "UPDATE users SET isVerified = true, verificationToken = NULL WHERE id = ?",
      [userId],
      (updateErr, result) => {
        if (updateErr) {
          console.error("DB error during email verification update:", updateErr);
          return res
            .status(500)
            .json("Email verification failed. Please try again later.");
        }

        if (result.affectedRows === 0) {
          return res
            .status(404)
            .json("User not found or account already verified.");
        }

        res.status(200).json("Email verified successfully.");
      }
    );
  });
};

export const logout = (req, res) => {
  res
    .clearCookie("access_token", cookieOptions)
    .status(200)
    .json("Logout successful.");
};
