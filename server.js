import nodemailer from "nodemailer";
import { PayOS } from "@payos/node";
import express from "express";
import { MongoClient, ObjectId } from "mongodb";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
const MAIL_HOST = process.env.MAIL_HOST;
const MAIL_PORT = Number(process.env.MAIL_PORT || 587);
const MAIL_SECURE = String(process.env.MAIL_SECURE || "false") === "true";
const MAIL_USER = process.env.MAIL_USER;
const MAIL_PASS = process.env.MAIL_PASS;
const MAIL_FROM = process.env.MAIL_FROM || MAIL_USER;
const PAYOS_CLIENT_ID = process.env.PAYOS_CLIENT_ID;
const PAYOS_API_KEY = process.env.PAYOS_API_KEY;
const PAYOS_CHECKSUM_KEY = process.env.PAYOS_CHECKSUM_KEY;
const PAYOS_RETURN_URL = process.env.PAYOS_RETURN_URL;
const PAYOS_CANCEL_URL = process.env.PAYOS_CANCEL_URL;
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const DB_NAME = process.env.DB_NAME || "webacc";
const JWT_SECRET = process.env.JWT_SECRET || "secret_key";

if (!MONGO_URI) {
  console.error("❌ Thiếu MONGO_URI trong file .env");
  process.exit(1);
}

const client = new MongoClient(MONGO_URI);
let db;

// Kết nối MongoDB
async function connectDB() {
  try {
    await client.connect();
    db = client.db(DB_NAME);

    // users
    await db.collection("users").createIndex({ username: 1 }, { unique: true });

    // products
    await db.collection("products").createIndex({ slug: 1 }, { unique: true });
        await db.collection("pending_registers").createIndex({ email: 1 }, { unique: true });
    await db.collection("pending_registers").createIndex({ username: 1 }, { unique: true });
    await db.collection("pending_registers").createIndex(
      { otpExpireAt: 1 },
      { expireAfterSeconds: 0 }
    );
    console.log("✅ Kết nối MongoDB thành công");
  } catch (error) {
    console.error("❌ Lỗi kết nối MongoDB:", error.message);
    process.exit(1);
  }
}
const mailTransporter =
  MAIL_HOST && MAIL_USER && MAIL_PASS
    ? nodemailer.createTransport({
        host: MAIL_HOST,
        port: MAIL_PORT,
        secure: MAIL_SECURE,
        auth: {
          user: MAIL_USER,
          pass: MAIL_PASS
        }
      })
    : null;

function generateOTP() {
  return String(Math.floor(100000 + Math.random() * 900000));
}
//tao payos
const payOS = new PayOS({
  clientId: PAYOS_CLIENT_ID,
  apiKey: PAYOS_API_KEY,
  checksumKey: PAYOS_CHECKSUM_KEY
});
// ===================== API TEST =====================
app.get("/", (req, res) => {
  res.json({ message: "Backend Node.js + MongoDB đang chạy" });
});

// ===================== REGISTER =====================
app.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({
        field: "general",
        message: "Vui lòng nhập đầy đủ thông tin"
      });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailRegex.test(email)) {
      return res.status(400).json({
        field: "email",
        message: "Email không đúng định dạng"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        field: "password",
        message: "Mật khẩu phải từ 6 ký tự trở lên"
      });
    }

    const existingUsername = await db.collection("users").findOne({ username });
    if (existingUsername) {
      return res.status(409).json({
        field: "username",
        message: "Tên đăng nhập đã tồn tại"
      });
    }

    const existingEmail = await db.collection("users").findOne({ email });
    if (existingEmail) {
      return res.status(409).json({
        field: "email",
        message: "Email đã tồn tại"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await db.collection("users").insertOne({
      username,
      email,
      password: hashedPassword,
      role: "user",
      balance: 0,
      createdAt: new Date()
    });

    res.status(201).json({
      message: "Đăng ký thành công",
      userId: result.insertedId
    });
  } catch (error) {
    console.error("Lỗi /register:", error.message);
    res.status(500).json({
      field: "general",
      message: "Lỗi server"
    });
  }
});
app.post("/register/check", async (req, res) => {
  try {
    const { username, email } = req.body;

        if (username) {
      const existingUsername = await db.collection("users").findOne({ username });
      const pendingUsername = await db.collection("pending_registers").findOne({ username });

      if (existingUsername || pendingUsername) {
        return res.json({
          field: "username",
          exists: true,
          message: "Tên đăng nhập đã tồn tại hoặc đang chờ xác minh"
        });
      }
    }

        if (email) {
      const existingEmail = await db.collection("users").findOne({ email });
      const pendingEmail = await db.collection("pending_registers").findOne({ email });

      if (existingEmail || pendingEmail) {
        return res.json({
          field: "email",
          exists: true,
          message: "Email đã tồn tại hoặc đang chờ xác minh"
        });
      }
    }

    return res.json({
      exists: false
    });
  } catch (error) {
    console.error("Lỗi /register/check:", error.message);
    return res.status(500).json({
      field: "general",
      exists: false,
      message: "Lỗi server"
    });
  }
});
//api moi gui mail dk
app.post("/register/start", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({
        field: "general",
        message: "Vui lòng nhập đầy đủ thông tin"
      });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailRegex.test(email)) {
      return res.status(400).json({
        field: "email",
        message: "Email không đúng định dạng"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        field: "password",
        message: "Mật khẩu phải từ 6 ký tự trở lên"
      });
    }

    const existingUsername = await db.collection("users").findOne({ username });
    if (existingUsername) {
      return res.status(409).json({
        field: "username",
        message: "Tên đăng nhập đã tồn tại"
      });
    }

    const existingEmail = await db.collection("users").findOne({ email });
    if (existingEmail) {
      return res.status(409).json({
        field: "email",
        message: "Email đã tồn tại"
      });
    }

    if (!mailTransporter) {
      return res.status(500).json({
        message: "Server chưa cấu hình gửi email"
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const otp = generateOTP();
    const otpExpireAt = new Date(Date.now() + 10 * 60 * 1000);

    await db.collection("pending_registers").deleteMany({
      $or: [{ email }, { username }]
    });

    const pendingResult = await db.collection("pending_registers").insertOne({
  username,
  email,
  passwordHash,
  otp,
  otpExpireAt,
  createdAt: new Date()
});

try {
  await mailTransporter.sendMail({
    from: MAIL_FROM,
    to: email,
    subject: "Mã xác minh đăng ký XD Store",
    html: `
      <div style="font-family:Arial,sans-serif;line-height:1.6">
        <h2>Mã xác minh đăng ký</h2>
        <p>Mã OTP của bạn là:</p>
        <div style="font-size:28px;font-weight:700;letter-spacing:4px;color:#0b67d0">${otp}</div>
        <p>Mã có hiệu lực trong 10 phút.</p>
        <p>Nếu bạn không thực hiện đăng ký, hãy bỏ qua email này.</p>
      </div>
    `
  });
} catch (mailError) {
  await db.collection("pending_registers").deleteOne({
    _id: pendingResult.insertedId
  });

  console.error("Gửi mail lỗi:", mailError.message);

  return res.status(500).json({
    message: "Gửi email xác minh thất bại"
  });
}
    return res.json({
      message: "Đã gửi mã xác minh"
    });
  } catch (error) {
    console.error("Lỗi /register/start:", error.message);
    return res.status(500).json({
      message: "Lỗi server"
    });
  }
});

app.post("/register/verify", async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({
        message: "Thiếu email hoặc mã OTP"
      });
    }

    const pending = await db.collection("pending_registers").findOne({ email });

    if (!pending) {
      return res.status(400).json({
        message: "Không tìm thấy yêu cầu đăng ký hoặc mã đã hết hạn"
      });
    }

    if (pending.otp !== otp) {
      return res.status(400).json({
        message: "Mã OTP không đúng"
      });
    }

    if (new Date() > new Date(pending.otpExpireAt)) {
      await db.collection("pending_registers").deleteOne({ _id: pending._id });
      return res.status(400).json({
        message: "Mã OTP đã hết hạn"
      });
    }

    const existingUsername = await db.collection("users").findOne({ username: pending.username });
    if (existingUsername) {
      return res.status(409).json({
        message: "Tên đăng nhập đã tồn tại"
      });
    }

    const existingEmail = await db.collection("users").findOne({ email: pending.email });
    if (existingEmail) {
      return res.status(409).json({
        message: "Email đã tồn tại"
      });
    }

    const result = await db.collection("users").insertOne({
      username: pending.username,
      email: pending.email,
      password: pending.passwordHash,
      role: "user",
      balance: 0,
      createdAt: new Date()
    });

    await db.collection("pending_registers").deleteOne({ _id: pending._id });

    const token = jwt.sign(
  {
    userId: result.insertedId,
    username: pending.username,
    role: "user"
  },
  JWT_SECRET,
  { expiresIn: "7d" }
);

return res.status(201).json({
  message: "Đăng ký thành công",
  token,
  user: {
    id: result.insertedId,
    username: pending.username,
    email: pending.email,
    role: "user"
  }
});
  } catch (error) {
    console.error("Lỗi /register/verify:", error.message);
    return res.status(500).json({
      message: "Lỗi server"
    });
  }
});

app.post("/register/resend-otp", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Thiếu email" });
    }

    const pending = await db.collection("pending_registers").findOne({ email });

    if (!pending) {
      return res.status(404).json({
        message: "Không tìm thấy yêu cầu đăng ký"
      });
    }

    if (!mailTransporter) {
      return res.status(500).json({
        message: "Server chưa cấu hình gửi email"
      });
    }

    const otp = generateOTP();
    const otpExpireAt = new Date(Date.now() + 10 * 60 * 1000);

    await db.collection("pending_registers").updateOne(
      { _id: pending._id },
      {
        $set: {
          otp,
          otpExpireAt,
          updatedAt: new Date()
        }
      }
    );

    await mailTransporter.sendMail({
      from: MAIL_FROM,
      to: email,
      subject: "Mã xác minh đăng ký XD Store",
      html: `
        <div style="font-family:Arial,sans-serif;line-height:1.6">
          <h2>Gửi lại mã xác minh đăng ký</h2>
          <p>Mã OTP mới của bạn là:</p>
          <div style="font-size:28px;font-weight:700;letter-spacing:4px;color:#0b67d0">${otp}</div>
          <p>Mã có hiệu lực trong 10 phút.</p>
        </div>
      `
    });

    return res.json({
      message: "Đã gửi lại mã OTP"
    });
  } catch (error) {
    console.error("Lỗi /register/resend-otp:", error.message);
    return res.status(500).json({
      message: "Lỗi server"
    });
  }
});
// ===================== LOGIN =====================
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

if (!username || !password) {
  return res.status(400).json({ message: "Vui lòng nhập tên đăng nhập hoặc email và mật khẩu" });
}

const loginValue = username.trim().toLowerCase();

const user = await db.collection("users").findOne(
  loginValue.includes("@")
    ? { email: loginValue }
    : { username: username.trim() }
);

    if (!user) {
      return res.status(401).json({ message: "Tài khoản không tồn tại" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "Sai mật khẩu" });
    }

    const token = jwt.sign(
  {
    userId: user._id,
    username: user.username,
    role: user.role || "user"
  },
  JWT_SECRET,
  { expiresIn: "7d" }
);

    res.json({
  message: "Đăng nhập thành công",
  token,
  user: {
    id: user._id,
    username: user.username,
    email: user.email,
    role: user.role || "user"
  }
});
  } catch (error) {
    console.error("Lỗi /login:", error.message);
    res.status(500).json({ message: "Lỗi server" });
  }
});
function adminMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Thiếu token" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    if (decoded.role !== "admin") {
      return res.status(403).json({ message: "Bạn không có quyền admin" });
    }

    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Token không hợp lệ" });
  }
}
// ===================== Quen mat khau =====================
app.post("/change-password", authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;

    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({ message: "Vui lòng nhập đầy đủ thông tin" });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ message: "Mật khẩu mới phải có ít nhất 6 ký tự" });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ message: "Mật khẩu mới không khớp" });
    }

    const user = await db.collection("users").findOne({
      _id: new ObjectId(req.user.userId)
    });

    if (!user) {
      return res.status(404).json({ message: "Không tìm thấy người dùng" });
    }

    if (!user.password) {
      return res.status(400).json({
        message: "Tài khoản này không có mật khẩu thường để đổi"
      });
    }

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Mật khẩu hiện tại không đúng" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await db.collection("users").updateOne(
      { _id: user._id },
      {
        $set: {
          password: hashedPassword,
          passwordUpdatedAt: new Date()
        }
      }
    );

    return res.json({ message: "Đổi mật khẩu thành công" });
  } catch (error) {
    console.error("Lỗi /change-password:", error.message);
    return res.status(500).json({ message: "Lỗi server" });
  }
});

app.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Vui lòng nhập email" });
    }

    const user = await db.collection("users").findOne({ email });

    if (!user) {
      return res.json({
        message: "Nếu email tồn tại, mã xác minh đã được gửi"
      });
    }

    if (!mailTransporter) {
      return res.status(500).json({
        message: "Server chưa cấu hình gửi email"
      });
    }

    const otp = generateOTP();
    const otpExpireAt = new Date(Date.now() + 10 * 60 * 1000);

    await db.collection("users").updateOne(
      { _id: user._id },
      {
        $set: {
          resetOtp: otp,
          resetOtpExpireAt: otpExpireAt,
          resetOtpCreatedAt: new Date()
        }
      }
    );

    await mailTransporter.sendMail({
      from: MAIL_FROM,
      to: email,
      subject: "Mã đặt lại mật khẩu XD Store",
      html: `
        <div style="font-family:Arial,sans-serif;line-height:1.6">
          <h2>Đặt lại mật khẩu</h2>
          <p>Mã OTP đặt lại mật khẩu của bạn là:</p>
          <div style="font-size:28px;font-weight:700;letter-spacing:4px;color:#0b67d0">${otp}</div>
          <p>Mã có hiệu lực trong 10 phút.</p>
          <p>Nếu bạn không yêu cầu đặt lại mật khẩu, hãy bỏ qua email này.</p>
        </div>
      `
    });

    return res.json({
      message: "Nếu email tồn tại, mã xác minh đã được gửi"
    });
  } catch (error) {
    console.error("Lỗi /forgot-password:", error.message);
    return res.status(500).json({ message: "Lỗi server" });
  }
});

app.post("/reset-password", async (req, res) => {
  try {
    const { email, otp, newPassword, confirmPassword } = req.body;

    if (!email || !otp || !newPassword || !confirmPassword) {
      return res.status(400).json({ message: "Vui lòng nhập đầy đủ thông tin" });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ message: "Mật khẩu mới phải có ít nhất 6 ký tự" });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ message: "Mật khẩu mới không khớp" });
    }

    const user = await db.collection("users").findOne({ email });

    if (!user || !user.resetOtp || !user.resetOtpExpireAt) {
      return res.status(400).json({
        message: "Yêu cầu đặt lại mật khẩu không hợp lệ hoặc đã hết hạn"
      });
    }

    if (user.resetOtp !== otp) {
      return res.status(400).json({ message: "Mã OTP không đúng" });
    }

    if (new Date() > new Date(user.resetOtpExpireAt)) {
      await db.collection("users").updateOne(
        { _id: user._id },
        {
          $unset: {
            resetOtp: "",
            resetOtpExpireAt: "",
            resetOtpCreatedAt: ""
          }
        }
      );

      return res.status(400).json({ message: "Mã OTP đã hết hạn" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await db.collection("users").updateOne(
      { _id: user._id },
      {
        $set: {
          password: hashedPassword,
          passwordUpdatedAt: new Date()
        },
        $unset: {
          resetOtp: "",
          resetOtpExpireAt: "",
          resetOtpCreatedAt: ""
        }
      }
    );

    return res.json({ message: "Đặt lại mật khẩu thành công" });
  } catch (error) {
    console.error("Lỗi /reset-password:", error.message);
    return res.status(500).json({ message: "Lỗi server" });
  }
});
// ===================== AUTH MIDDLEWARE =====================
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Thiếu token" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Token không hợp lệ" });
  }
}

// ===================== PROFILE =====================
app.get("/profile", authMiddleware, async (req, res) => {
  try {
    const user = await db.collection("users").findOne(
      { username: req.user.username },
      { projection: { password: 0 } }
    );

    res.json(user);
  } catch (error) {
    res.status(500).json({ message: "Lỗi server" });
  }
});
app.get("/wallet", authMiddleware, async (req, res) => {
  try {
    const user = await db.collection("users").findOne(
      { _id: new ObjectId(req.user.userId) },
      { projection: { password: 0 } }
    );

    if (!user) {
      return res.status(404).json({ message: "Không tìm thấy user" });
    }

    res.json({
      balance: user.balance || 0,
      username: user.username,
      email: user.email
    });
  } catch (error) {
    console.error("Lỗi /wallet:", error.message);
    res.status(500).json({ message: "Lỗi server" });
  }
});
app.post("/topup/create", authMiddleware, async (req, res) => {
  try {
    const amount = Number(req.body.amount);

    if (!amount || amount < 1000) {
      return res.status(400).json({ message: "Số tiền nạp không hợp lệ" });
    }

    const orderCode = Number(String(Date.now()).slice(-9));
    const transferCode =
      "NAP-" +
      String(req.user.userId).slice(-6).toUpperCase() +
      "-" +
      Math.floor(100000 + Math.random() * 900000);

    const topupData = {
      userId: new ObjectId(req.user.userId),
      amount,
      orderCode,
      transferCode,
      status: "pending",
      createdAt: new Date()
    };

    const insertResult = await db.collection("topup_requests").insertOne(topupData);

    const paymentLink = await payOS.paymentRequests.create({
      orderCode,
      amount,
      description: transferCode.slice(0, 25),
      items: [
        {
          name: "Nap tien tai khoan",
          quantity: 1,
          price: amount
        }
      ],
      returnUrl: PAYOS_RETURN_URL,
      cancelUrl: PAYOS_CANCEL_URL
    });

    console.log("paymentLink payOS:", paymentLink);

    const checkoutUrl =
      paymentLink?.checkoutUrl || paymentLink?.data?.checkoutUrl || null;

    const qrCode =
      paymentLink?.qrCode || paymentLink?.data?.qrCode || null;

    res.json({
      message: "Tạo link nạp tiền thành công",
      topupId: insertResult.insertedId,
      orderCode,
      amount,
      transferCode,
      checkoutUrl,
      qrCode
    });
  } catch (error) {
    console.error("Lỗi /topup/create:", error.message);
    res.status(500).json({ message: "Lỗi server" });
  }
});
app.get("/payos-webhook", (req, res) => {
  res.status(200).send("payOS webhook endpoint is running");
});
app.post("/payos-webhook", async (req, res) => {
  try {
    console.log("payOS webhook body:", req.body);

    let webhookData = null;

    try {
      webhookData = await payOS.webhooks.verify(req.body);
    } catch (verifyError) {
      console.log("Webhook verify fail:", verifyError.message);
      return res.status(200).json({ success: true, message: "Webhook received" });
    }

   const payload = webhookData?.data ? webhookData.data : webhookData;
const orderCode = payload?.orderCode;
const amount = payload?.amount;

console.log("webhookData sau verify:", webhookData);
console.log("payload dùng để xử lý:", payload);

if (!orderCode) {
  console.log("Không có orderCode trong webhook");
  return res.status(200).json({ success: true });
}

    const topup = await db.collection("topup_requests").findOne({ orderCode });

    if (!topup) {
      console.log("Không tìm thấy topup với orderCode:", orderCode);
      return res.status(200).json({ success: true });
    }

    if (topup.status === "paid") {
      return res.status(200).json({ success: true });
    }

    const user = await db.collection("users").findOne({ _id: topup.userId });

    if (!user) {
      console.log("Không tìm thấy user:", topup.userId);
      return res.status(200).json({ success: true });
    }

    const paidAmount = Number(amount || topup.amount);
    const balanceBefore = Number(user.balance || 0);
    const balanceAfter = balanceBefore + paidAmount;

    await db.collection("users").updateOne(
      { _id: topup.userId },
      { $set: { balance: balanceAfter } }
    );

    await db.collection("topup_requests").updateOne(
      { _id: topup._id },
      {
        $set: {
          status: "paid",
          paidAt: new Date(),
          paidAmount
        }
      }
    );

    await db.collection("transactions").insertOne({
      userId: topup.userId,
      type: "topup",
      amount: paidAmount,
      balanceBefore,
      balanceAfter,
      note: `Nạp tiền payOS - ${topup.transferCode}`,
      orderCode,
      createdAt: new Date()
    });

    return res.status(200).json({ success: true });
  } catch (error) {
    console.error("Lỗi /payos-webhook:", error.message);
    return res.status(200).json({ success: true });
  }
});
// ===================== hàm ẩn dữ liệu mật//

function sanitizeProduct(product) {
  if (!product) return product;

  const safeProduct = { ...product };
  delete safeProduct.delivery;

  return safeProduct;
}
// ===================== PRODUCTS =====================

// lấy tất cả sản phẩm
app.get("/products", async (req, res) => {
  try {
    const products = await db
      .collection("products")
      .find({})
      .sort({ createdAt: -1 })
      .toArray();

    const safeProducts = products.map(sanitizeProduct);

    res.json(safeProducts);
  } catch (error) {
    console.error("Lỗi /products:", error.message);
    res.status(500).json({ message: "Lỗi lấy danh sách sản phẩm" });
  }
});
// lấy chi tiết 1 sản phẩm theo slug
app.get("/products/:slug", async (req, res) => {
  try {
    const product = await db.collection("products").findOne({
      slug: req.params.slug
    });

    if (!product) {
      return res.status(404).json({ message: "Không tìm thấy sản phẩm" });
    }

    res.json(sanitizeProduct(product));
  } catch (error) {
    console.error("Lỗi /products/:slug:", error.message);
    res.status(500).json({ message: "Lỗi lấy chi tiết sản phẩm" });
  }
});
//----lay danh sach san pham cho admin---//
app.get("/admin/products", adminMiddleware, async (req, res) => {
  try {
    const products = await db
      .collection("products")
      .find({})
      .sort({ createdAt: -1 })
      .toArray();

    res.json(products);
  } catch (error) {
    console.error("Lỗi /admin/products:", error.message);
    res.status(500).json({ message: "Lỗi lấy danh sách sản phẩm admin" });
  }
});
// thêm sản phẩm
app.post("/products", adminMiddleware, async (req, res) => {
  try {
    const {
  slug,
  title,
  follow,
  desc,
  tags,
  price,
  image,
  status,
  detail,
  delivery
} = req.body;

    if (!slug || !title || !price || !image) {
      return res.status(400).json({ message: "Thiếu dữ liệu sản phẩm" });
    }

    const existingProduct = await db.collection("products").findOne({ slug });

    if (existingProduct) {
      return res.status(409).json({ message: "Slug sản phẩm đã tồn tại" });
    }

    const newProduct = {
      slug,
      title,
      follow: Number(follow) || 0,
      desc: desc || "",
      tags: Array.isArray(tags) ? tags : [],
      price: Number(price),
      image, // ví dụ: "images/anh2.jpg"
      status: status || "available", // available | sold
      detail: detail || {},
      delivery: delivery || {},
      createdAt: new Date()
    };

    const result = await db.collection("products").insertOne(newProduct);

    res.status(201).json({
      message: "Thêm sản phẩm thành công",
      productId: result.insertedId
    });
  } catch (error) {
    console.error("Lỗi POST /products:", error.message);
    res.status(500).json({ message: "Lỗi thêm sản phẩm" });
  }
});

// sửa sản phẩm
app.put("/products/:id", adminMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = { ...req.body };

    delete updateData._id;

    if (updateData.follow !== undefined) {
      updateData.follow = Number(updateData.follow) || 0;
    }

    if (updateData.price !== undefined) {
      updateData.price = Number(updateData.price) || 0;
    }

    const result = await db.collection("products").updateOne(
      { _id: new ObjectId(id) },
      {
        $set: updateData
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ message: "Không tìm thấy sản phẩm" });
    }

    res.json({ message: "Cập nhật sản phẩm thành công" });
  } catch (error) {
    console.error("Lỗi PUT /products/:id:", error.message);
    res.status(500).json({ message: "Lỗi cập nhật sản phẩm" });
  }
});

// đánh dấu đã bán
app.put("/products/:id/sold", adminMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await db.collection("products").updateOne(
      { _id: new ObjectId(id) },
      {
        $set: {
          status: "sold"
        }
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ message: "Không tìm thấy sản phẩm" });
    }

    res.json({ message: "Đã cập nhật trạng thái đã bán" });
  } catch (error) {
    console.error("Lỗi PUT /products/:id/sold:", error.message);
    res.status(500).json({ message: "Lỗi cập nhật trạng thái sản phẩm" });
  }
});

// xóa sản phẩm
app.delete("/products/:id", adminMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await db.collection("products").deleteOne({
      _id: new ObjectId(id)
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({ message: "Không tìm thấy sản phẩm" });
    }

    res.json({ message: "Xóa sản phẩm thành công" });
  } catch (error) {
    console.error("Lỗi DELETE /products/:id:", error.message);
    res.status(500).json({ message: "Lỗi xóa sản phẩm" });
  }
});
// ===================== MUA SẢN PHẨM BẰNG SỐ DƯ =====================
app.post("/purchase/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ message: "ID sản phẩm không hợp lệ" });
    }

    const productId = new ObjectId(id);

    const product = await db.collection("products").findOne({ _id: productId });
    if (!product) {
      return res.status(404).json({ message: "Không tìm thấy sản phẩm" });
    }

    if (product.status === "sold") {
      return res.status(400).json({ message: "Sản phẩm này đã bán" });
    }

    const user = await db.collection("users").findOne({
      _id: new ObjectId(req.user.userId)
    });

    if (!user) {
      return res.status(404).json({ message: "Không tìm thấy người dùng" });
    }

    const price = Number(product.price || 0);
    const balanceBefore = Number(user.balance || 0);

    if (balanceBefore < price) {
      return res.status(400).json({
        message: "Số dư không đủ để mua sản phẩm",
        balance: balanceBefore,
        price
      });
    }

    const productUpdate = await db.collection("products").updateOne(
      { _id: productId, status: { $ne: "sold" } },
      {
        $set: {
          status: "sold",
          soldAt: new Date(),
          buyerId: new ObjectId(req.user.userId),
          buyerUsername: user.username
        }
      }
    );

    if (productUpdate.matchedCount === 0) {
      return res.status(400).json({ message: "Sản phẩm vừa được người khác mua" });
    }

    const walletUpdate = await db.collection("users").updateOne(
      {
        _id: new ObjectId(req.user.userId),
        balance: { $gte: price }
      },
      {
        $inc: { balance: -price }
      }
    );

    if (walletUpdate.matchedCount === 0) {
      await db.collection("products").updateOne(
        { _id: productId },
        {
          $set: { status: "available" },
          $unset: {
            soldAt: "",
            buyerId: "",
            buyerUsername: ""
          }
        }
      );

      return res.status(400).json({ message: "Số dư không đủ để mua sản phẩm" });
    }

    const updatedUser = await db.collection("users").findOne({
      _id: new ObjectId(req.user.userId)
    });

    const balanceAfter = Number(updatedUser.balance || 0);

    await db.collection("transactions").insertOne({
      userId: new ObjectId(req.user.userId),
      type: "purchase",
      productId: product._id,
      productTitle: product.title,
      amount: price,
      balanceBefore,
      balanceAfter,
      note: `Mua sản phẩm: ${product.title}`,
      createdAt: new Date()
    });

    await db.collection("orders").insertOne({
  userId: new ObjectId(req.user.userId),
  username: user.username,
  productId: product._id,
  productTitle: product.title,
  productPrice: price,
  deliveryInfo: {
    loginAccount: product.delivery?.loginAccount || "",
    loginPassword: product.delivery?.loginPassword || "",
    recoveryEmail: product.delivery?.recoveryEmail || "",
    twoFA: product.delivery?.twoFA || "",
    note: product.delivery?.note || ""
  },
  status: "completed",
  createdAt: new Date()
});

    return res.json({
      message: "Mua sản phẩm thành công",
      product: {
        id: product._id,
        title: product.title,
        price,
        image: product.image,
        follow: product.follow || 0,
        desc: product.desc || ""
      },
      wallet: {
        balanceBefore,
        balanceAfter
      },
      deliveryInfo: {
  loginAccount: product.delivery?.loginAccount || "Chưa cập nhật",
  loginPassword: product.delivery?.loginPassword || "Chưa cập nhật",
  recoveryEmail: product.delivery?.recoveryEmail || "Chưa cập nhật",
  twoFA: product.delivery?.twoFA || "Chưa cập nhật",
  note: product.delivery?.note || "Không có ghi chú"
}
    });
  } catch (error) {
    console.error("Lỗi /purchase/:id:", error.message);
    return res.status(500).json({ message: "Lỗi xử lý mua sản phẩm" });
  }
});
//======================đơn hàng đã mua=================//
app.get("/my-orders", authMiddleware, async (req, res) => {
  try {
    const userId = new ObjectId(req.user.userId);

    const orders = await db.collection("orders")
      .find(
        { userId },
        {
          projection: {
            productTitle: 1,
            productPrice: 1,
            status: 1,
            createdAt: 1
          }
        }
      )
      .sort({ createdAt: -1 })
      .toArray();

    res.json(orders);
  } catch (error) {
    console.error("Lỗi /my-orders:", error.message);
    res.status(500).json({ message: "Lỗi lấy danh sách đơn hàng" });
  }
});
//---lấy chi tiết 1 đơn hàng //
app.get("/my-orders/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ message: "ID đơn hàng không hợp lệ" });
    }

    const order = await db.collection("orders").findOne({
      _id: new ObjectId(id),
      userId: new ObjectId(req.user.userId)
    });

    if (!order) {
      return res.status(404).json({ message: "Không tìm thấy đơn hàng" });
    }

    res.json({
      _id: order._id,
      productTitle: order.productTitle,
      productPrice: order.productPrice,
      status: order.status,
      createdAt: order.createdAt,
      deliveryInfo: order.deliveryInfo || {}
    });
  } catch (error) {
    console.error("Lỗi /my-orders/:id:", error.message);
    res.status(500).json({ message: "Lỗi lấy chi tiết đơn hàng" });
  }
});
// ===================== RUN SERVER =====================
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Server chạy tại http://localhost:${PORT}`);
  });
});