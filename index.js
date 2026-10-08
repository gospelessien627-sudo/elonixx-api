import express from "express";
import mongoose from "mongoose";
import dns from "node:dns/promises";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();

dns.setServers(["1.1.1.1", "8.8.8.8"]);

const app = express();

const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";

if (!MONGODB_URI) console.warn("WARNING: MONGODB_URI is not configured.");
if (!JWT_SECRET) console.warn("WARNING: JWT_SECRET is not configured.");

if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
  console.warn("WARNING: ADMIN_EMAIL or ADMIN_PASSWORD is not configured.");
}

/* ================= MIDDLEWARE ================= */

app.use(cors({
  origin: true,
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* ================= DATABASE ================= */

let connectionPromise;

async function connectDB() {
  if (mongoose.connection.readyState === 1) {
    return mongoose.connection;
  }

  if (!MONGODB_URI) {
    throw new Error("MONGODB_URI is missing.");
  }

  if (!connectionPromise) {
    connectionPromise = mongoose.connect(MONGODB_URI, {
      serverSelectionTimeoutMS: 10000,
    }).catch((error) => {
      connectionPromise = null;
      throw error;
    });
  }

  return connectionPromise;
}

/* ================= USER MODEL ================= */

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },
  password: {
    type: String,
    required: true,
  },
  balance: {
    type: Number,
    default: 0,
  },
  deposited: {
    type: Number,
    default: 0,
  },
  withdrawn: {
    type: Number,
    default: 0,
  },
}, {
  timestamps: true,
});

const User = mongoose.models.User ||
  mongoose.model("User", userSchema);

/* ================= TRANSACTION MODEL ================= */

const transactionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  transactionId: {
    type: String,
    required: true,
    unique: true,
  },
  type: {
    type: String,
    enum: ["deposit", "withdrawal", "transfer", "payment"],
    required: true,
  },
  amount: {
    type: Number,
    required: true,
    min: 0,
  },
  paymentMethod: {
    type: String,
    default: "",
  },
  accountNumber: {
    type: String,
    default: "",
  },
  accountName: {
    type: String,
    default: "",
  },
  status: {
    type: String,
    enum: ["pending", "processing", "completed", "failed"],
    default: "pending",
  },
}, {
  timestamps: true,
});

const Transaction = mongoose.models.Transaction ||
  mongoose.model("Transaction", transactionSchema);

/* ================= WITHDRAWAL ACCOUNT MODEL ================= */

const withdrawalAccountSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  bankName: {
    type: String,
    required: true,
    trim: true,
  },
  accountNumber: {
    type: String,
    required: true,
    trim: true,
  },
  accountName: {
    type: String,
    required: true,
    trim: true,
  },
}, {
  timestamps: true,
});

const WithdrawalAccount = mongoose.models.WithdrawalAccount ||
  mongoose.model("WithdrawalAccount", withdrawalAccountSchema);

/* ================= HELPERS ================= */

function generateTransactionId() {
  return "TXN-" + Date.now() + "-" +
    Math.random().toString(36).substring(2, 8).toUpperCase();
}

function requireJWTSecret(res) {
  if (!JWT_SECRET) {
    res.status(500).json({
      success: false,
      message: "JWT_SECRET is not configured.",
    });

    return false;
  }

  return true;
}

/* ================= USER AUTHENTICATION ================= */

async function authenticate(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader?.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "A valid authorization token is required.",
      });
    }

    if (!requireJWTSecret(res)) return;

    const token = authHeader.slice(7);
    const decoded = jwt.verify(token, JWT_SECRET);

    if (decoded.role !== "user" || !decoded.userId) {
      return res.status(403).json({
        message: "User access required.",
      });
    }

    req.userId = decoded.userId;
    req.user = decoded;

    next();
  } catch (error) {
    console.error("User authentication error:", error.message);

    return res.status(401).json({
      message: "Invalid or expired authentication token.",
    });
  }
}

/* ================= ADMIN AUTHENTICATION ================= */

async function authenticateAdmin(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader?.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "Admin authorization token is required.",
      });
    }

    if (!requireJWTSecret(res)) return;

    if (!ADMIN_EMAIL) {
      return res.status(500).json({
        message: "ADMIN_EMAIL is not configured.",
      });
    }

    const token = authHeader.slice(7);
    const decoded = jwt.verify(token, JWT_SECRET);

    const tokenEmail = String(decoded.adminEmail || "")
      .trim()
      .toLowerCase();

    if (
      decoded.role !== "admin" ||
      tokenEmail !== ADMIN_EMAIL
    ) {
      return res.status(403).json({
        message: "Admin access required.",
      });
    }

    req.admin = {
      role: "admin",
      adminEmail: ADMIN_EMAIL,
    };

    next();
  } catch (error) {
    console.error("Admin authentication error:", error.message);

    return res.status(401).json({
      message: "Invalid or expired admin token.",
    });
  }
}

/* ================= ROOT ================= */

app.get("/", async (req, res) => {
  try {
    await connectDB();

    return res.json({
      success: true,
      message: "ElonixxWallet API is running.",
    });
  } catch (error) {
    console.error("Root database error:", error);

    return res.status(500).json({
      success: false,
      message: "Database connection failed.",
    });
  }
});

/* ================= TEST ================= */

app.get("/api/test", async (req, res) => {
  try {
    await connectDB();

    return res.json({
      success: true,
      message: "Backend and MongoDB are connected.",
    });
  } catch (error) {
    console.error("Test route error:", error);

    return res.status(500).json({
      success: false,
      message: "Database connection failed.",
    });
  }
});

/* ================= REGISTER ================= */

app.post("/api/register", async (req, res) => {
  try {
    await connectDB();

    if (!JWT_SECRET) {
      return res.status(500).json({
        message: "JWT_SECRET is not configured.",
      });
    }

    const { name, email, password } = req.body || {};

    if (!name || !email || !password) {
      return res.status(400).json({
        message: "Name, email and password are required.",
      });
    }

    const cleanName = String(name).trim();
    const cleanEmail = String(email).trim().toLowerCase();
    const cleanPassword = String(password);

    if (cleanName.length < 2) {
      return res.status(400).json({
        message: "Name must be at least 2 characters.",
      });
    }

    if (cleanPassword.length < 6) {
      return res.status(400).json({
        message: "Password must be at least 6 characters.",
      });
    }

    const existingUser = await User.findOne({
      email: cleanEmail,
    });

    if (existingUser) {
      return res.status(409).json({
        message: "An account with this email already exists.",
      });
    }

    const hashedPassword = await bcrypt.hash(cleanPassword, 12);

    const user = await User.create({
      name: cleanName,
      email: cleanEmail,
      password: hashedPassword,
      balance: 0,
      deposited: 0,
      withdrawn: 0,
    });

    const token = jwt.sign(
      {
        userId: user._id.toString(),
        role: "user",
      },
      JWT_SECRET,
      {
        expiresIn: "7d",
      }
    );

    return res.status(201).json({
      message: "Registration successful.",
      role: "user",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        balance: user.balance,
        deposited: user.deposited,
        withdrawn: user.withdrawn,
      },
    });
  } catch (error) {
    console.error("Registration error:", error);

    if (error.code === 11000) {
      return res.status(409).json({
        message: "An account with this email already exists.",
      });
    }

    return res.status(500).json({
      message: "Registration failed.",
    });
  }
});

/* ================= LOGIN ================= */

app.post("/api/login", async (req, res) => {
  try {
    await connectDB();

    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required.",
      });
    }

    const cleanEmail = String(email).trim().toLowerCase();
    const cleanPassword = String(password);

    if (
      ADMIN_EMAIL &&
      ADMIN_PASSWORD &&
      cleanEmail === ADMIN_EMAIL &&
      cleanPassword === ADMIN_PASSWORD
    ) {
      if (!requireJWTSecret(res)) return;

      const token = jwt.sign(
        {
          role: "admin",
          adminEmail: ADMIN_EMAIL,
        },
        JWT_SECRET,
        {
          expiresIn: "7d",
        }
      );

      return res.status(200).json({
        message: "Admin login successful!",
        role: "admin",
        email: ADMIN_EMAIL,
        token,
      });
    }

    const user = await User.findOne({
      email: cleanEmail,
    });

    if (!user || !(await bcrypt.compare(cleanPassword, user.password))) {
      return res.status(401).json({
        message: "Invalid email or password.",
      });
    }

    if (!requireJWTSecret(res)) return;

    const token = jwt.sign(
      {
        userId: user._id.toString(),
        role: "user",
      },
      JWT_SECRET,
      {
        expiresIn: "7d",
      }
    );

    return res.status(200).json({
      message: "Login successful.",
      role: "user",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        balance: user.balance,
        deposited: user.deposited,
        withdrawn: user.withdrawn,
      },
    });
  } catch (error) {
    console.error("Login error:", error);

    return res.status(500).json({
      message: "Login failed.",
    });
  }
});

/* ================= USER DASHBOARD ================= */

app.get("/api/dashboard", authenticate, async (req, res) => {
  try {
    await connectDB();

    const user = await User.findById(req.userId)
      .select("-password");

    if (!user) {
      return res.status(404).json({
        message: "User not found.",
      });
    }

    return res.json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        balance: user.balance,
        deposited: user.deposited,
        withdrawn: user.withdrawn,
        createdAt: user.createdAt,
      },
    });
  } catch (error) {
    console.error("Dashboard error:", error);

    return res.status(500).json({
      message: "Failed to load dashboard.",
    });
  }
});

/* ================= USER TRANSACTIONS ================= */

app.get("/api/transactions", authenticate, async (req, res) => {
  try {
    await connectDB();

    const transactions = await Transaction.find({
      userId: req.userId,
    }).sort({
      createdAt: -1,
    });

    return res.json({
      success: true,
      transactions,
    });
  } catch (error) {
    console.error("Transactions error:", error);

    return res.status(500).json({
      message: "Failed to load transactions.",
    });
  }
});

/* ================= GET WITHDRAWAL ACCOUNTS ================= */

app.get("/api/withdrawal-accounts", authenticate, async (req, res) => {
  try {
    await connectDB();

    const accounts = await WithdrawalAccount.find({
      userId: req.userId,
    }).sort({
      createdAt: -1,
    });

    return res.json({
      success: true,
      accounts,
    });
  } catch (error) {
    console.error("Withdrawal accounts error:", error);

    return res.status(500).json({
      message: "Failed to load withdrawal accounts.",
    });
  }
});

/* ================= ADD WITHDRAWAL ACCOUNT ================= */

app.post("/api/withdrawal-accounts", authenticate, async (req, res) => {
  try {
    await connectDB();

    const { bankName, accountNumber, accountName } = req.body || {};

    if (!bankName || !accountNumber || !accountName) {
      return res.status(400).json({
        message: "Bank name, account number and account name are required.",
      });
    }

    const account = await WithdrawalAccount.create({
      userId: req.userId,
      bankName: String(bankName).trim(),
      accountNumber: String(accountNumber).trim(),
      accountName: String(accountName).trim(),
    });

    return res.status(201).json({
      success: true,
      message: "Withdrawal account added successfully.",
      account,
    });
  } catch (error) {
    console.error("Add withdrawal account error:", error);

    return res.status(500).json({
      message: "Failed to add withdrawal account.",
    });
  }
});

/* ================= CREATE WITHDRAWAL ================= */

app.post("/api/withdrawals", authenticate, async (req, res) => {
  try {
    await connectDB();

    const {
      amount,
      paymentMethod,
      accountNumber,
      accountName,
    } = req.body || {};

    if (
      amount === undefined ||
      amount === null ||
      String(amount).trim() === ""
    ) {
      return res.status(400).json({
        message: "Please enter a withdrawal amount.",
      });
    }

    const numericAmount = Number(amount);

    if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
      return res.status(400).json({
        message: "Please enter a valid withdrawal amount.",
      });
    }

    if (!accountNumber || !accountName) {
      return res.status(400).json({
        message: "Account number and account name are required.",
      });
    }

    const user = await User.findById(req.userId);

    if (!user) {
      return res.status(404).json({
        message: "User not found.",
      });
    }

    if (numericAmount > user.balance) {
      return res.status(400).json({
        message: "Insufficient balance.",
      });
    }

    const transaction = await Transaction.create({
      userId: user._id,
      transactionId: generateTransactionId(),
      type: "withdrawal",
      amount: numericAmount,
      paymentMethod: paymentMethod || "Bank Transfer",
      accountNumber: String(accountNumber).trim(),
      accountName: String(accountName).trim(),
      status: "pending",
    });

    return res.status(201).json({
      success: true,
      message: "Withdrawal request submitted successfully.",
      transaction,
    });
  } catch (error) {
    console.error("Withdrawal error:", error);

    return res.status(500).json({
      message: "Failed to submit withdrawal.",
    });
  }
});

/* ================= ADMIN OVERVIEW ================= */

app.get("/api/admin/overview", authenticateAdmin, async (req, res) => {
  try {
    await connectDB();

    const [
      totalUsers,
      totalTransactions,
      totalWithdrawals,
      pendingWithdrawals,
      completedWithdrawals,
      processingWithdrawals,
      failedWithdrawals,
      users,
    ] = await Promise.all([
      User.countDocuments(),

      Transaction.countDocuments(),

      Transaction.countDocuments({
        type: "withdrawal",
      }),

      Transaction.countDocuments({
        type: "withdrawal",
        status: "pending",
      }),

      Transaction.countDocuments({
        type: "withdrawal",
        status: "completed",
      }),

      Transaction.countDocuments({
        type: "withdrawal",
        status: "processing",
      }),

      Transaction.countDocuments({
        type: "withdrawal",
        status: "failed",
      }),

      User.find()
        .select("-password")
        .sort({ createdAt: -1 }),
    ]);

    return res.json({
      success: true,
      statistics: {
        totalUsers,
        totalTransactions,
        totalWithdrawals,
        pendingWithdrawals,
        completedWithdrawals,
        processingWithdrawals,
        failedWithdrawals,
      },
      users,
    });
  } catch (error) {
    console.error("Admin overview error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to load admin overview.",
    });
  }
});

/* ================= ADMIN WITHDRAWALS ================= */

app.get("/api/admin/withdrawals", authenticateAdmin, async (req, res) => {
  try {
    await connectDB();

    const withdrawals = await Transaction.find({
      type: "withdrawal",
    })
      .populate("userId", "-password")
      .sort({ createdAt: -1 });

    return res.json({
      success: true,
      withdrawals,
    });
  } catch (error) {
    console.error("Admin withdrawals error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to load withdrawals.",
    });
  }
});

/* ================= ADMIN UPDATE WITHDRAWAL STATUS ================= */

app.patch(
  "/api/admin/withdrawals/:id/status",
  authenticateAdmin,
  async (req, res) => {
    try {
      await connectDB();

      const { status } = req.body || {};

      const allowedStatuses = [
        "pending",
        "processing",
        "completed",
        "failed",
      ];

      if (!allowedStatuses.includes(status)) {
        return res.status(400).json({
          message: "Invalid withdrawal status.",
        });
      }

      if (!mongoose.isValidObjectId(req.params.id)) {
        return res.status(400).json({
          message: "Invalid withdrawal ID.",
        });
      }

      const withdrawal = await Transaction.findOne({
        _id: req.params.id,
        type: "withdrawal",
      });

      if (!withdrawal) {
        return res.status(404).json({
          message: "Withdrawal transaction not found.",
        });
      }

      withdrawal.status = status;

      await withdrawal.save();

      return res.json({
        success: true,
        message: "Withdrawal status updated successfully.",
        withdrawal,
      });
    } catch (error) {
      console.error("Update withdrawal status error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to update withdrawal status.",
      });
    }
  }
);

/* ================= ADMIN UPDATE USER BALANCE ================= */
/* This route must be above the 404 handler. */

app.patch(
  "/api/admin/users/:id/balance",
  authenticateAdmin,
  async (req, res) => {
    try {
      await connectDB();

      const { amount } = req.body || {};

      if (
        amount === undefined ||
        amount === null ||
        String(amount).trim() === ""
      ) {
        return res.status(400).json({
          success: false,
          message: "Balance amount is required.",
        });
      }

      const numericAmount = Number(amount);

      if (!Number.isFinite(numericAmount) || numericAmount < 0) {
        return res.status(400).json({
          success: false,
          message: "Enter a valid balance of zero or greater.",
        });
      }

      if (!mongoose.isValidObjectId(req.params.id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid user ID.",
        });
      }

      const user = await User.findById(req.params.id);

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "User not found.",
        });
      }

      // Change only the balance.
      // Deposited and withdrawn totals are not changed here.
      user.balance = numericAmount;

      await user.save();

      return res.status(200).json({
        success: true,
        message: "User balance updated successfully.",
        user: {
          _id: user._id,
          id: user._id,
          name: user.name,
          email: user.email,
          balance: user.balance,
          deposited: user.deposited,
          withdrawn: user.withdrawn,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt,
        },
      });
    } catch (error) {
      console.error("Admin update user balance error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to update user balance.",
      });
    }
  }
);

/* ================= ADMIN CHECK ================= */

app.get("/api/admin/me", authenticateAdmin, async (req, res) => {
  return res.json({
    success: true,
    role: "admin",
    email: req.admin.adminEmail,
  });
});

/* ================= 404 HANDLER ================= */
/* Keep this after every API route. */

app.use((req, res) => {
  return res.status(404).json({
    success: false,
    message: `Route ${req.method} ${req.originalUrl} not found.`,
  });
});

/* ================= GLOBAL ERROR HANDLER ================= */

app.use((error, req, res, next) => {
  console.error("Global server error:", error);

  if (res.headersSent) {
    return next(error);
  }

  return res.status(500).json({
    success: false,
    message: "Internal server error.",
  });
});

/* ================= VERCEL EXPORT ================= */

export default app;