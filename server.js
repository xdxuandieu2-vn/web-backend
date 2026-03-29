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

    console.log("✅ Kết nối MongoDB thành công");
  } catch (error) {
    console.error("❌ Lỗi kết nối MongoDB:", error.message);
    process.exit(1);
  }
}
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
      if (existingUsername) {
        return res.json({
          field: "username",
          exists: true,
          message: "Tên đăng nhập đã tồn tại"
        });
      }
    }

    if (email) {
      const existingEmail = await db.collection("users").findOne({ email });
      if (existingEmail) {
        return res.json({
          field: "email",
          exists: true,
          message: "Email đã tồn tại"
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
// ===================== LOGIN =====================
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: "Vui lòng nhập username và password" });
    }

    const user = await db.collection("users").findOne({ username });

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
// ===================== Thêm webhook payOS để tự cộng tiền//


// ===================== PRODUCTS =====================

// lấy tất cả sản phẩm
app.get("/products", async (req, res) => {
  try {
    const products = await db
      .collection("products")
      .find({})
      .sort({ createdAt: -1 })
      .toArray();

    res.json(products);
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

    res.json(product);
  } catch (error) {
    console.error("Lỗi /products/:slug:", error.message);
    res.status(500).json({ message: "Lỗi lấy chi tiết sản phẩm" });
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
      detail
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
        username: product.detail?.username || "",
        category: product.detail?.category || "",
        livestream: !!product.detail?.livestream,
        shopEnabled: !!product.detail?.shopEnabled,
        note: product.detail?.note || ""
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
        username: product.detail?.username || "Chưa cập nhật",
        category: product.detail?.category || "Chưa cập nhật",
        livestream: !!product.detail?.livestream,
        shopEnabled: !!product.detail?.shopEnabled,
        note: product.detail?.note || "Không có ghi chú"
      }
    });
  } catch (error) {
    console.error("Lỗi /purchase/:id:", error.message);
    return res.status(500).json({ message: "Lỗi xử lý mua sản phẩm" });
  }
});
// ===================== RUN SERVER =====================
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Server chạy tại http://localhost:${PORT}`);
  });
});