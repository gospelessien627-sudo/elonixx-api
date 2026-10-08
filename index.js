import express from "express";
import mongoose from "mongoose";
import dns from "node:dns/promises";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";
import { randomUUID } from "node:crypto";

dotenv.config();

dns.setServers(["1.1.1.1", "8.8.8.8"]);

const app = express();

/* =====================================================
   CONFIGURATION
===================================================== */

const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "")
  .trim()
  .toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";

const FRONTEND_URL = (process.env.FRONTEND_URL || "")
  .split(",")
  .map((url) => url.trim().replace(/\/$/, ""))
  .filter(Boolean);

if (!MONGODB_URI) {
  console.warn("WARNING: MONGODB_URI is not configured.");
}

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.warn(
    "WARNING: Set a strong JWT_SECRET containing at least 32 characters."
  );
}

if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
  console.warn(
    "WARNING: ADMIN_EMAIL or ADMIN_PASSWORD is not configured."
  );
}

/* =====================================================
   MIDDLEWARE
===================================================== */

app.disable("x-powered-by");

app.use(
  cors({
    origin(origin, callback) {
      // Requests without an Origin include server-to-server
      // requests and some development tools.
      if (!origin) return callback(null, true);

      if (
        FRONTEND_URL.includes(origin.replace(/\/$/, "")) ||
        (
          process.env.NODE_ENV !== "production" &&
          /^http:\/\/localhost(:\d+)?$/.test(origin)
        )
      ) {
        return callback(null, true);
      }

      return callback(new Error("Origin is not allowed by CORS."));
    },
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));

/* =====================================================
   DATABASE
===================================================== */

let connectionPromise;

async function connectDB() {
  if (mongoose.connection.readyState === 1) {
    return mongoose.connection;
  }

  if (!MONGODB_URI) {
    throw new Error("MONGODB_URI is missing.");
  }

  if (!connectionPromise) {
    connectionPromise = mongoose
      .connect(MONGODB_URI, {
        serverSelectionTimeoutMS: 10000,
      })
      .catch((error) => {
        connectionPromise = null;
        throw error;
      });
  }

  return connectionPromise;
}

/* =====================================================
   USER MODEL
===================================================== */

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      minlength: 2,
      maxlength: 100,
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      maxlength: 254,
    },

    password: {
      type: String,
      required: true,
      select: false,
    },

    balance: {
      type: Number,
      default: 0,
      min: 0,
    },

    deposited: {
      type: Number,
      default: 0,
      min: 0,
    },

    withdrawn: {
      type: Number,
      default: 0,
      min: 0,
    },
  },
  {
    timestamps: true,
  }
);

const User =
  mongoose.models.User ||
  mongoose.model("User", userSchema);

/* =====================================================
   TRANSACTION MODEL
===================================================== */

const transactionSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
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
      min: 0.01,
    },

    paymentMethod: {
      type: String,
      default: "",
      maxlength: 100,
    },

    accountNumber: {
      type: String,
      default: "",
      maxlength: 50,
    },

    accountName: {
      type: String,
      default: "",
      maxlength: 150,
    },

    status: {
      type: String,
      enum: ["pending", "processing", "completed", "failed"],
      default: "pending",
    },
  },
  {
    timestamps: true,
  }
);

transactionSchema.index({ userId: 1, createdAt: -1 });
transactionSchema.index({ type: 1, status: 1, createdAt: -1 });

const Transaction =
  mongoose.models.Transaction ||
  mongoose.model("Transaction", transactionSchema);

/* =====================================================
   WITHDRAWAL ACCOUNT MODEL
===================================================== */

const withdrawalAccountSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },

    bankName: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100,
    },

    accountNumber: {
      type: String,
      required: true,
      trim: true,
      maxlength: 50,
    },

    accountName: {
      type: String,
      required: true,
      trim: true,
      maxlength: 150,
    },
  },
  {
    timestamps: true,
  }
);

const WithdrawalAccount =
  mongoose.models.WithdrawalAccount ||
  mongoose.model("WithdrawalAccount", withdrawalAccountSchema);

/* =====================================================
   HELPERS
===================================================== */

function generateTransactionId() {
  return `TXN-${randomUUID()}`;
}

function requireJWTSecret(res) {
  if (!JWT_SECRET || JWT_SECRET.length < 32) {
    res.status(500).json({
      success: false,
      message: "Server authentication is not configured correctly.",
    });

    return false;
  }

  return true;
}

function publicUser(user) {
  return {
    id: String(user._id),
    _id: String(user._id),
    name: user.name,
    email: user.email,
    balance: user.balance,
    deposited: user.deposited,
    withdrawn: user.withdrawn,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}

function isValidAmount(value) {
  return (
    value !== undefined &&
    value !== null &&
    String(value).trim() !== "" &&
    Number.isFinite(Number(value)) &&
    Number(value) > 0
  );
}

function safeErrorMessage(error) {
  if (error?.name === "ValidationError") {
    return "Some submitted information is invalid.";
  }

  return "The request could not be completed.";
}

/* =====================================================
   USER AUTHENTICATION
===================================================== */

async function authenticate(req, res, next) {
  try {
    if (!requireJWTSecret(res)) return;

    const authorization = req.headers.authorization || "";

    if (!authorization.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "A valid authorization token is required.",
      });
    }

    const token = authorization.slice(7);
    const decoded = jwt.verify(token, JWT_SECRET);

    if (decoded.role !== "user" || !decoded.userId) {
      return res.status(403).json({
        success: false,
        message: "User access is required.",
      });
    }

    if (!mongoose.isValidObjectId(decoded.userId)) {
      return res.status(401).json({
        success: false,
        message: "Invalid authentication token.",
      });
    }

    req.userId = decoded.userId;
    req.user = decoded;

    return next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired authentication token.",
    });
  }
}

/* =====================================================
   ADMIN AUTHENTICATION
===================================================== */

async function authenticateAdmin(req, res, next) {
  try {
    if (!requireJWTSecret(res)) return;

    if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
      return res.status(500).json({
        success: false,
        message: "Admin authentication is not configured.",
      });
    }

    const authorization = req.headers.authorization || "";

    if (!authorization.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Admin authorization token is required.",
      });
    }

    const token = authorization.slice(7);
    const decoded = jwt.verify(token, JWT_SECRET);

    const tokenEmail = String(decoded.adminEmail || "")
      .trim()
      .toLowerCase();

    if (
      decoded.role !== "admin" ||
      tokenEmail !== ADMIN_EMAIL
    ) {
      return res.status(403).json({
        success: false,
        message: "Admin access is required.",
      });
    }

    req.admin = {
      role: "admin",
      adminEmail: ADMIN_EMAIL,
    };

    return next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired admin token.",
    });
  }
}

/* =====================================================
   ROOT AND HEALTH CHECKS
===================================================== */

app.get("/", async (req, res) => {
  try {
    await connectDB();

    return res.json({
      success: true,
      message: "ElonixxWallet API is running.",
    });
  } catch (error) {
    console.error("Root route error:", error.message);

    return res.status(503).json({
      success: false,
      message: "Database connection failed.",
    });
  }
});

app.get("/api/test", async (req, res) => {
  try {
    await connectDB();

    return res.json({
      success: true,
      message: "Backend and MongoDB are connected.",
    });
  } catch (error) {
    console.error("Health check error:", error.message);

    return res.status(503).json({
      success: false,
      message: "Database connection failed.",
    });
  }
});

/* =====================================================
   REGISTER
===================================================== */

app.post("/api/register", async (req, res) => {
  try {
    await connectDB();

    if (!requireJWTSecret(res)) return;

    const { name, email, password } = req.body || {};

    if (
      typeof name !== "string" ||
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        success: false,
        message: "Name, email and password are required.",
      });
    }

    const cleanName = name.trim();
    const cleanEmail = email.trim().toLowerCase();

    if (cleanName.length < 2 || cleanName.length > 100) {
      return res.status(400).json({
        success: false,
        message: "Name must contain between 2 and 100 characters.",
      });
    }

    if (
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail) ||
      cleanEmail.length > 254
    ) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid email address.",
      });
    }

    if (password.length < 6 || password.length > 128) {
      return res.status(400).json({
        success: false,
        message: "Password must contain between 6 and 128 characters.",
      });
    }

    const existingUser = await User.findOne({
      email: cleanEmail,
    }).lean();

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "An account with this email already exists.",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

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
        userId: String(user._id),
        role: "user",
      },
      JWT_SECRET,
      {
        expiresIn: "7d",
      }
    );

    return res.status(201).json({
      success: true,
      message: "Registration successful.",
      role: "user",
      token,
      user: publicUser(user),
    });
  } catch (error) {
    console.error("Registration error:", error);

    if (error.code === 11000) {
      return res.status(409).json({
        success: false,
        message: "An account with this email already exists.",
      });
    }

    return res.status(500).json({
      success: false,
      message: safeErrorMessage(error),
    });
  }
});

/* =====================================================
   LOGIN
===================================================== */

app.post("/api/login", async (req, res) => {
  try {
    await connectDB();

    if (!requireJWTSecret(res)) return;

    const { email, password } = req.body || {};

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required.",
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    // Admin credentials come from environment variables.
    if (
      ADMIN_EMAIL &&
      ADMIN_PASSWORD &&
      cleanEmail === ADMIN_EMAIL &&
      password === ADMIN_PASSWORD
    ) {
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

      return res.json({
        success: true,
        message: "Admin login successful.",
        role: "admin",
        email: ADMIN_EMAIL,
        token,
      });
    }

    const user = await User.findOne({
      email: cleanEmail,
    }).select("+password");

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password.",
      });
    }

    const token = jwt.sign(
      {
        userId: String(user._id),
        role: "user",
      },
      JWT_SECRET,
      {
        expiresIn: "7d",
      }
    );

    return res.json({
      success: true,
      message: "Login successful.",
      role: "user",
      token,
      user: publicUser(user),
    });
  } catch (error) {
    console.error("Login error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Login failed.",
    });
  }
});

/* =====================================================
   GET CURRENT USER DASHBOARD
===================================================== */

app.get("/api/dashboard", authenticate, async (req, res) => {
  try {
    await connectDB();

    const user = await User.findById(req.userId);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found.",
      });
    }

    return res.json({
      success: true,
      user: publicUser(user),
    });
  } catch (error) {
    console.error("Dashboard error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Failed to load dashboard.",
    });
  }
});

/* =====================================================
   GET USER TRANSACTIONS
===================================================== */

app.get("/api/transactions", authenticate, async (req, res) => {
  try {
    await connectDB();

    const transactions = await Transaction.find({
      userId: req.userId,
    })
      .sort({ createdAt: -1 })
      .lean();

    return res.json({
      success: true,
      transactions,
    });
  } catch (error) {
    console.error("Transactions error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Failed to load transactions.",
    });
  }
});

/* =====================================================
   GET USER WITHDRAWAL ACCOUNTS
===================================================== */

app.get(
  "/api/withdrawal-accounts",
  authenticate,
  async (req, res) => {
    try {
      await connectDB();

      const accounts = await WithdrawalAccount.find({
        userId: req.userId,
      })
        .sort({ createdAt: -1 })
        .lean();

      return res.json({
        success: true,
        accounts,
      });
    } catch (error) {
      console.error("Withdrawal accounts error:", error.message);

      return res.status(500).json({
        success: false,
        message: "Failed to load withdrawal accounts.",
      });
    }
  }
);

/* =====================================================
   ADD USER WITHDRAWAL ACCOUNT
===================================================== */

app.post(
  "/api/withdrawal-accounts",
  authenticate,
  async (req, res) => {
    try {
      await connectDB();

      const { bankName, accountNumber, accountName } = req.body || {};

      if (
        typeof bankName !== "string" ||
        typeof accountNumber !== "string" ||
        typeof accountName !== "string"
      ) {
        return res.status(400).json({
          success: false,
          message: "Bank name, account number and account name are required.",
        });
      }

      const cleanBank = bankName.trim();
      const cleanNumber = accountNumber.trim();
      const cleanName = accountName.trim();

      if (
        !cleanBank ||
        !cleanNumber ||
        !cleanName ||
        cleanBank.length > 100 ||
        cleanNumber.length > 50 ||
        cleanName.length > 150
      ) {
        return res.status(400).json({
          success: false,
          message: "Please provide valid bank account details.",
        });
      }

      const account = await WithdrawalAccount.create({
        userId: req.userId,
        bankName: cleanBank,
        accountNumber: cleanNumber,
        accountName: cleanName,
      });

      return res.status(201).json({
        success: true,
        message: "Withdrawal account added successfully.",
        account,
      });
    } catch (error) {
      console.error("Add withdrawal account error:", error.message);

      return res.status(500).json({
        success: false,
        message: "Failed to add withdrawal account.",
      });
    }
  }
);

/* =====================================================
   CREATE WITHDRAWAL REQUEST
   The balance is checked here, but deducted only when
   the admin completes the withdrawal.
===================================================== */

app.post("/api/withdrawals", authenticate, async (req, res) => {
  try {
    await connectDB();

    const {
      amount,
      paymentMethod,
      accountNumber,
      accountName,
    } = req.body || {};

    if (!isValidAmount(amount)) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid withdrawal amount.",
      });
    }

    const numericAmount = Number(amount);

    if (
      !Number.isFinite(numericAmount) ||
      numericAmount > 1_000_000_000_000
    ) {
      return res.status(400).json({
        success: false,
        message: "Withdrawal amount is outside the allowed range.",
      });
    }

    if (
      typeof accountNumber !== "string" ||
      typeof accountName !== "string" ||
      !accountNumber.trim() ||
      !accountName.trim()
    ) {
      return res.status(400).json({
        success: false,
        message: "Account number and account name are required.",
      });
    }

    const user = await User.findById(req.userId).lean();

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found.",
      });
    }

    if (numericAmount > user.balance) {
      return res.status(400).json({
        success: false,
        message: "Insufficient balance.",
      });
    }

    const transaction = await Transaction.create({
      userId: user._id,
      transactionId: generateTransactionId(),
      type: "withdrawal",
      amount: numericAmount,
      paymentMethod:
        typeof paymentMethod === "string" && paymentMethod.trim()
          ? paymentMethod.trim().slice(0, 100)
          : "Bank Transfer",
      accountNumber: accountNumber.trim().slice(0, 50),
      accountName: accountName.trim().slice(0, 150),
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
      success: false,
      message: "Failed to submit withdrawal.",
    });
  }
});

/* =====================================================
   ADMIN CHECK
===================================================== */

app.get("/api/admin/me", authenticateAdmin, (req, res) => {
  return res.json({
    success: true,
    role: "admin",
    email: req.admin.adminEmail,
  });
});

/* =====================================================
   ADMIN OVERVIEW
===================================================== */

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
        .sort({ createdAt: -1 })
        .lean(),
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

      users: users.map(publicUser),
    });
  } catch (error) {
    console.error("Admin overview error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Failed to load admin overview.",
    });
  }
});

/* =====================================================
   ADMIN WITHDRAWALS
===================================================== */

app.get(
  "/api/admin/withdrawals",
  authenticateAdmin,
  async (req, res) => {
    try {
      await connectDB();

      const withdrawals = await Transaction.find({
        type: "withdrawal",
      })
        .populate("userId", "name email balance deposited withdrawn")
        .sort({ createdAt: -1 })
        .lean();

      return res.json({
        success: true,
        withdrawals,
      });
    } catch (error) {
      console.error("Admin withdrawals error:", error.message);

      return res.status(500).json({
        success: false,
        message: "Failed to load withdrawals.",
      });
    }
  }
);

/* =====================================================
   ADMIN UPDATE WITHDRAWAL STATUS

   MongoDB transactions keep the user balance and
   withdrawal status consistent.

   This route requires a MongoDB deployment that supports
   multi-document transactions, such as a replica set.
===================================================== */

app.patch(
  "/api/admin/withdrawals/:id/status",
  authenticateAdmin,
  async (req, res) => {
    let session;

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
          success: false,
          message: "Invalid withdrawal status.",
        });
      }

      if (!mongoose.isValidObjectId(req.params.id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid withdrawal ID.",
        });
      }

      session = await mongoose.startSession();

      let updatedWithdrawal = null;
      let failure = null;

      await session.withTransaction(async () => {
        const withdrawal = await Transaction.findOne({
          _id: req.params.id,
          type: "withdrawal",
        }).session(session);

        if (!withdrawal) {
          failure = {
            status: 404,
            message: "Withdrawal transaction not found.",
          };
          return;
        }

        if (
          withdrawal.status === "completed" ||
          withdrawal.status === "failed"
        ) {
          failure = {
            status: 409,
            message: `This withdrawal is already ${withdrawal.status}.`,
          };
          return;
        }

        // Only debit funds when completing a withdrawal.
        if (status === "completed") {
          const user = await User.findOneAndUpdate(
            {
              _id: withdrawal.userId,
              balance: { $gte: withdrawal.amount },
            },
            {
              $inc: {
                balance: -withdrawal.amount,
                withdrawn: withdrawal.amount,
              },
            },
            {
              new: true,
              session,
              runValidators: true,
            }
          );

          if (!user) {
            failure = {
              status: 400,
              message:
                "The user does not have enough available balance to complete this withdrawal.",
            };
            return;
          }
        }

        withdrawal.status = status;
        await withdrawal.save({ session });

        updatedWithdrawal = withdrawal.toObject();
      });

      if (failure) {
        return res.status(failure.status).json({
          success: false,
          message: failure.message,
        });
      }

      return res.json({
        success: true,
        message: "Withdrawal status updated successfully.",
        withdrawal: updatedWithdrawal,
      });
    } catch (error) {
      console.error("Update withdrawal status error:", error);

      return res.status(500).json({
        success: false,
        message:
          "Failed to update withdrawal status. Check the database transaction configuration.",
      });
    } finally {
      if (session) {
        await session.endSession();
      }
    }
  }
);

/* =====================================================
   ADMIN UPDATE USER BALANCE
   This sets the balance to the requested amount.
   It does not change deposited or withdrawn totals.
===================================================== */

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

      if (
        !Number.isFinite(numericAmount) ||
        numericAmount < 0 ||
        numericAmount > 1_000_000_000_000
      ) {
        return res.status(400).json({
          success: false,
          message: "Enter a valid non-negative balance.",
        });
      }

      if (!mongoose.isValidObjectId(req.params.id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid user ID.",
        });
      }

      const user = await User.findByIdAndUpdate(
        req.params.id,
        { $set: { balance: numericAmount } },
        { new: true, runValidators: true }
      );

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "User not found.",
        });
      }

      return res.json({
        success: true,
        message: "User balance updated successfully.",
        user: publicUser(user),
      });
    } catch (error) {
      console.error("Admin balance update error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to update user balance.",
      });
    }
  }
);

/* =====================================================
   404 HANDLER
===================================================== */

app.use((req, res) => {
  return res.status(404).json({
    success: false,
    message: `Route ${req.method} ${req.originalUrl} not found.`,
  });
});

/* =====================================================
   ERROR HANDLER
===================================================== */

app.use((error, req, res, next) => {
  console.error("Global server error:", error.message);

  if (res.headersSent) {
    return next(error);
  }

  if (error.message === "Origin is not allowed by CORS.") {
    return res.status(403).json({
      success: false,
      message: "This frontend origin is not allowed.",
    });
  }

  return res.status(500).json({
    success: false,
    message: "Internal server error.",
  });
});

/* =====================================================
   VERCEL EXPORT
===================================================== */

export default app;