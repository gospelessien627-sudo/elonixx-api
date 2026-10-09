import express from "express";
import mongoose from "mongoose";
import dns from "node:dns/promises";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";
import crypto from "node:crypto";

dotenv.config();

dns.setServers(["1.1.1.1", "8.8.8.8"]);

const app = express();

app.use(
  cors({
    origin: process.env.FRONTEND_URL
      ? process.env.FRONTEND_URL.split(",").map((url) => url.trim())
      : true,
    credentials: true,
  })
);

app.use(express.json({ limit: "1mb" }));

// --------------------------------------------------
// ENVIRONMENT CONFIGURATION
// --------------------------------------------------

const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL?.toLowerCase().trim();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

const JWT_EXPIRES_IN = "7d";

if (!JWT_SECRET) {
  console.error("Missing JWT_SECRET environment variable.");
}

if (!MONGODB_URI) {
  console.error("Missing MONGODB_URI environment variable.");
}

// --------------------------------------------------
// DATABASE CONNECTION
// --------------------------------------------------

let databaseConnectionPromise;

async function connectDB() {
  if (mongoose.connection.readyState === 1) {
    return mongoose.connection;
  }

  if (!MONGODB_URI) {
    throw new Error("MONGODB_URI is not configured.");
  }

  if (!databaseConnectionPromise) {
    databaseConnectionPromise = mongoose
      .connect(MONGODB_URI, {
        serverSelectionTimeoutMS: 15000,
      })
      .then(() => {
        console.log("MongoDB connected successfully.");
        return mongoose.connection;
      })
      .catch((error) => {
        databaseConnectionPromise = null;
        throw error;
      });
  }

  return databaseConnectionPromise;
}

// --------------------------------------------------
// HELPERS
// --------------------------------------------------

function normalizeEmail(email) {
  return typeof email === "string"
    ? email.trim().toLowerCase()
    : "";
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function parsePositiveAmount(value) {
  const amount = Number(value);

  if (!Number.isFinite(amount) || amount <= 0) {
    return null;
  }

  // Money is stored to two decimal places.
  const rounded = Math.round((amount + Number.EPSILON) * 100) / 100;

  if (rounded <= 0 || rounded > 1_000_000_000_000) {
    return null;
  }

  return rounded;
}

function createToken(payload) {
  if (!JWT_SECRET) {
    throw new Error("JWT_SECRET is not configured.");
  }

  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
  });
}

function asyncHandler(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

function publicUser(user) {
  return {
    id: user._id,
    _id: user._id,
    name: user.name,
    email: user.email,
    role: user.role,
    balance: user.balance,
    totalDeposits: user.totalDeposits,
    totalWithdrawals: user.totalWithdrawals,
    createdAt: user.createdAt,
  };
}

// --------------------------------------------------
// USER MODEL
// --------------------------------------------------

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100,
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },

    password: {
      type: String,
      required: true,
      select: false,
    },

    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
    },

    balance: {
      type: Number,
      default: 0,
      min: 0,
    },

    totalDeposits: {
      type: Number,
      default: 0,
      min: 0,
    },

    totalWithdrawals: {
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

// --------------------------------------------------
// TRANSACTION MODEL
// --------------------------------------------------

const transactionSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },

    type: {
      type: String,
      enum: ["deposit", "withdrawal", "adjustment"],
      required: true,
    },

    amount: {
      type: Number,
      required: true,
      min: 0.01,
    },

    status: {
      type: String,
      enum: ["pending", "completed", "approved", "rejected", "failed"],
      default: "completed",
    },

    description: {
      type: String,
      default: "",
      maxlength: 500,
    },

    reference: {
      type: String,
      unique: true,
      sparse: true,
    },

    metadata: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
  },
  {
    timestamps: true,
  }
);

const Transaction =
  mongoose.models.Transaction ||
  mongoose.model("Transaction", transactionSchema);

// --------------------------------------------------
// WITHDRAWAL ACCOUNT MODEL
// --------------------------------------------------

const withdrawalAccountSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },

    accountName: {
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

    bankName: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100,
    },

    bankCode: {
      type: String,
      default: "",
      trim: true,
      maxlength: 30,
    },
  },
  {
    timestamps: true,
  }
);

const WithdrawalAccount =
  mongoose.models.WithdrawalAccount ||
  mongoose.model("WithdrawalAccount", withdrawalAccountSchema);

// --------------------------------------------------
// WITHDRAWAL MODEL
// --------------------------------------------------

const withdrawalSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },

    account: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "WithdrawalAccount",
      required: true,
    },

    amount: {
      type: Number,
      required: true,
      min: 0.01,
    },

    status: {
      type: String,
      enum: ["pending", "approved", "rejected"],
      default: "pending",
      index: true,
    },

    reference: {
      type: String,
      required: true,
      unique: true,
    },

    adminNote: {
      type: String,
      default: "",
      maxlength: 500,
    },

    processedAt: {
      type: Date,
      default: null,
    },

    processedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

const Withdrawal =
  mongoose.models.Withdrawal ||
  mongoose.model("Withdrawal", withdrawalSchema);

// --------------------------------------------------
// AUTHENTICATION MIDDLEWARE
// --------------------------------------------------

function authenticate(req, res, next) {
  const authorization = req.headers.authorization;

  if (!authorization || !authorization.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Authentication required.",
    });
  }

  const token = authorization.slice(7).trim();

  try {
    if (!JWT_SECRET) {
      throw new Error("JWT_SECRET is not configured.");
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    if (!decoded.id || !decoded.role) {
      return res.status(401).json({
        success: false,
        message: "Invalid authentication token.",
      });
    }

    req.auth = {
      id: decoded.id,
      role: decoded.role,
    };

    next();
  } catch {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired token.",
    });
  }
}

function requireAdmin(req, res, next) {
  if (!req.auth || req.auth.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Administrator access required.",
    });
  }

  next();
}

async function getAuthenticatedUser(req) {
  return User.findById(req.auth.id);
}

// --------------------------------------------------
// HEALTH CHECK
// --------------------------------------------------

app.get(
  "/",
  asyncHandler(async (req, res) => {
    await connectDB();

    res.json({
      success: true,
      message: "ElonixxWallet API is running.",
      database: "connected",
    });
  })
);

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "API is healthy.",
  });
});

// --------------------------------------------------
// REGISTER
// --------------------------------------------------

app.post(
  "/api/register",
  asyncHandler(async (req, res) => {
    await connectDB();

    const name =
      typeof req.body.name === "string"
        ? req.body.name.trim()
        : "";

    const email = normalizeEmail(req.body.email);
    const password = req.body.password;

    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Name, email, and password are required.",
      });
    }

    if (name.length > 100 || !validEmail(email)) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid name and email address.",
      });
    }

    if (typeof password !== "string" || password.length < 8) {
      return res.status(400).json({
        success: false,
        message: "Password must contain at least 8 characters.",
      });
    }

    if (password.length > 128) {
      return res.status(400).json({
        success: false,
        message: "Password is too long.",
      });
    }

    const existingUser = await User.findOne({ email });

    if (existingUser || email === ADMIN_EMAIL) {
      return res.status(409).json({
        success: false,
        message: "An account with this email already exists.",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await User.create({
      name,
      email,
      password: hashedPassword,
      role: "user",
      balance: 0,
      totalDeposits: 0,
      totalWithdrawals: 0,
    });

    const token = createToken({
      id: user._id.toString(),
      role: "user",
    });

    return res.status(201).json({
      success: true,
      message: "Registration successful.",
      token,
      user: publicUser(user),
    });
  })
);

// --------------------------------------------------
// LOGIN
// --------------------------------------------------

app.post(
  "/api/login",
  asyncHandler(async (req, res) => {
    await connectDB();

    const email = normalizeEmail(req.body.email);
    const password = req.body.password;

    if (!email || typeof password !== "string" || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required.",
      });
    }

    // Admin login is configured through environment variables.
    if (
      ADMIN_EMAIL &&
      ADMIN_PASSWORD &&
      email === ADMIN_EMAIL &&
      password === ADMIN_PASSWORD
    ) {
      const token = createToken({
        id: `admin:${email}`,
        role: "admin",
      });

      return res.json({
        success: true,
        message: "Admin login successful.",
        token,
        role: "admin",
        user: {
          id: `admin:${email}`,
          name: "Administrator",
          email,
          role: "admin",
        },
      });
    }

    const user = await User.findOne({ email }).select("+password");

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password.",
      });
    }

    const passwordMatches = await bcrypt.compare(
      password,
      user.password
    );

    if (!passwordMatches) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password.",
      });
    }

    const token = createToken({
      id: user._id.toString(),
      role: user.role,
    });

    return res.json({
      success: true,
      message: "Login successful.",
      token,
      role: user.role,
      user: publicUser(user),
    });
  })
);

// --------------------------------------------------
// USER DASHBOARD
// --------------------------------------------------

app.get(
  "/api/dashboard",
  authenticate,
  asyncHandler(async (req, res) => {
    await connectDB();

    if (req.auth.role === "admin") {
      return res.status(403).json({
        success: false,
        message: "Use the admin dashboard endpoint.",
      });
    }

    const user = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found.",
      });
    }

    const [transactions, pendingWithdrawals] = await Promise.all([
      Transaction.find({ user: user._id })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),

      Withdrawal.countDocuments({
        user: user._id,
        status: "pending",
      }),
    ]);

    return res.json({
      success: true,
      user: publicUser(user),
      balance: user.balance,
      totalDeposits: user.totalDeposits,
      totalWithdrawals: user.totalWithdrawals,
      pendingWithdrawals,
      transactions,
    });
  })
);

// --------------------------------------------------
// USER TRANSACTIONS
// --------------------------------------------------

app.get(
  "/api/transactions",
  authenticate,
  asyncHandler(async (req, res) => {
    await connectDB();

    if (req.auth.role === "admin") {
      return res.status(403).json({
        success: false,
        message: "Use the admin endpoints.",
      });
    }

    const user = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found.",
      });
    }

    const limitValue = Number.parseInt(req.query.limit, 10);
    const limit =
      Number.isInteger(limitValue) && limitValue > 0
        ? Math.min(limitValue, 100)
        : 50;

    const transactions = await Transaction.find({
      user: user._id,
    })
      .sort({ createdAt: -1 })
      .limit(limit)
      .lean();

    return res.json({
      success: true,
      transactions,
    });
  })
);

// --------------------------------------------------
// GET WITHDRAWAL ACCOUNTS
// --------------------------------------------------

app.get(
  "/api/withdrawal-accounts",
  authenticate,
  asyncHandler(async (req, res) => {
    await connectDB();

    if (req.auth.role !== "user") {
      return res.status(403).json({
        success: false,
        message: "This endpoint is for users.",
      });
    }

    const accounts = await WithdrawalAccount.find({
      user: req.auth.id,
    })
      .sort({ createdAt: -1 })
      .lean();

    return res.json({
      success: true,
      accounts,
    });
  })
);

// --------------------------------------------------
// ADD WITHDRAWAL ACCOUNT
// --------------------------------------------------

app.post(
  "/api/withdrawal-accounts",
  authenticate,
  asyncHandler(async (req, res) => {
    await connectDB();

    if (req.auth.role !== "user") {
      return res.status(403).json({
        success: false,
        message: "This endpoint is for users.",
      });
    }

    const accountName =
      typeof req.body.accountName === "string"
        ? req.body.accountName.trim()
        : "";

    const accountNumber =
      typeof req.body.accountNumber === "string"
        ? req.body.accountNumber.trim()
        : "";

    const bankName =
      typeof req.body.bankName === "string"
        ? req.body.bankName.trim()
        : "";

    const bankCode =
      typeof req.body.bankCode === "string"
        ? req.body.bankCode.trim()
        : "";

    if (!accountName || !accountNumber || !bankName) {
      return res.status(400).json({
        success: false,
        message:
          "Account name, account number, and bank name are required.",
      });
    }

    if (
      accountName.length > 100 ||
      accountNumber.length > 50 ||
      bankName.length > 100 ||
      bankCode.length > 30
    ) {
      return res.status(400).json({
        success: false,
        message: "One or more account fields are too long.",
      });
    }

    const user = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found.",
      });
    }

    const account = await WithdrawalAccount.create({
      user: user._id,
      accountName,
      accountNumber,
      bankName,
      bankCode,
    });

    return res.status(201).json({
      success: true,
      message: "Withdrawal account added successfully.",
      account,
    });
  })
);

// --------------------------------------------------
// CREATE WITHDRAWAL
// --------------------------------------------------

app.post(
  "/api/withdrawals",
  authenticate,
  asyncHandler(async (req, res) => {
    await connectDB();

    if (req.auth.role !== "user") {
      return res.status(403).json({
        success: false,
        message: "This endpoint is for users.",
      });
    }

    const amount = parsePositiveAmount(req.body.amount);
    const accountId = req.body.accountId || req.body.account;

    if (!amount) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid withdrawal amount.",
      });
    }

    if (
      !accountId ||
      !mongoose.isValidObjectId(accountId)
    ) {
      return res.status(400).json({
        success: false,
        message: "A valid withdrawal account is required.",
      });
    }

    const account = await WithdrawalAccount.findOne({
      _id: accountId,
      user: req.auth.id,
    });

    if (!account) {
      return res.status(404).json({
        success: false,
        message: "Withdrawal account not found.",
      });
    }

    /*
     * Atomically reserve the funds before creating the request.
     * Two concurrent requests cannot spend the same available balance.
     */
    const user = await User.findOneAndUpdate(
      {
        _id: req.auth.id,
        balance: { $gte: amount },
      },
      {
        $inc: { balance: -amount },
      },
      {
        new: true,
        runValidators: true,
      }
    );

    if (!user) {
      const existingUser = await User.exists({
        _id: req.auth.id,
      });

      return res.status(existingUser ? 400 : 404).json({
        success: false,
        message: existingUser
          ? "Insufficient balance."
          : "User not found.",
      });
    }

    const reference = `WD-${crypto.randomUUID()}`;

    let withdrawal;

    try {
      withdrawal = await Withdrawal.create({
        user: user._id,
        account: account._id,
        amount,
        status: "pending",
        reference,
      });

      await Transaction.create({
        user: user._id,
        type: "withdrawal",
        amount,
        status: "pending",
        description: "Withdrawal request submitted",
        reference,
        metadata: {
          withdrawalId: withdrawal._id,
        },
      });
    } catch (error) {
      /*
       * Compensate if creating the withdrawal or transaction fails.
       * The balance was already reserved above.
       */
      if (withdrawal) {
        await Withdrawal.deleteOne({ _id: withdrawal._id });
      }

      await User.updateOne(
        { _id: user._id },
        { $inc: { balance: amount } }
      );

      throw error;
    }

    return res.status(201).json({
      success: true,
      message: "Withdrawal request submitted successfully.",
      withdrawal,
      balance: user.balance,
    });
  })
);

// --------------------------------------------------
// ADMIN OVERVIEW
// --------------------------------------------------

app.get(
  "/api/admin/overview",
  authenticate,
  requireAdmin,
  asyncHandler(async (req, res) => {
    await connectDB();

    const [
      totalUsers,
      users,
      totalTransactions,
      transactions,
      pendingWithdrawals,
      totalWithdrawals,
      balanceResult,
      pendingAmountResult,
    ] = await Promise.all([
      User.countDocuments({ role: "user" }),

      User.find({ role: "user" })
        .select("-password")
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),

      Transaction.countDocuments(),

      Transaction.find()
        .populate("user", "name email")
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),

      Withdrawal.countDocuments({ status: "pending" }),

      Withdrawal.countDocuments(),

      User.aggregate([
        { $match: { role: "user" } },
        {
          $group: {
            _id: null,
            totalBalance: { $sum: "$balance" },
          },
        },
      ]),

      Withdrawal.aggregate([
        { $match: { status: "pending" } },
        {
          $group: {
            _id: null,
            pendingAmount: { $sum: "$amount" },
          },
        },
      ]),
    ]);

    return res.json({
      success: true,
      totalUsers,
      totalTransactions,
      totalWithdrawals,
      pendingWithdrawals,
      totalBalance: balanceResult[0]?.totalBalance || 0,
      pendingAmount: pendingAmountResult[0]?.pendingAmount || 0,
      users,
      transactions,
    });
  })
);

// --------------------------------------------------
// ADMIN WITHDRAWALS LIST
// --------------------------------------------------

app.get(
  "/api/admin/withdrawals",
  authenticate,
  requireAdmin,
  asyncHandler(async (req, res) => {
    await connectDB();

    const status = req.query.status;

    const filter = {};

    if (
      status &&
      ["pending", "approved", "rejected"].includes(status)
    ) {
      filter.status = status;
    }

    const withdrawals = await Withdrawal.find(filter)
      .populate("user", "name email balance")
      .populate(
        "account",
        "accountName accountNumber bankName bankCode"
      )
      .sort({ createdAt: -1 })
      .limit(500)
      .lean();

    return res.json({
      success: true,
      withdrawals,
    });
  })
);

// --------------------------------------------------
// ADMIN UPDATE WITHDRAWAL STATUS
// --------------------------------------------------

app.patch(
  "/api/admin/withdrawals/:id/status",
  authenticate,
  requireAdmin,
  asyncHandler(async (req, res) => {
    await connectDB();

    const { id } = req.params;
    const { status, adminNote = "" } = req.body;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid withdrawal ID.",
      });
    }

    if (!["approved", "rejected"].includes(status)) {
      return res.status(400).json({
        success: false,
        message: "Status must be approved or rejected.",
      });
    }

    if (
      typeof adminNote !== "string" ||
      adminNote.length > 500
    ) {
      return res.status(400).json({
        success: false,
        message: "Admin note must be 500 characters or fewer.",
      });
    }

    /*
     * Claim only pending requests. This prevents two admin actions
     * from processing the same request more than once.
     */
    const withdrawal = await Withdrawal.findOneAndUpdate(
      {
        _id: id,
        status: "pending",
      },
      {
        $set: {
          status,
          adminNote,
          processedAt: new Date(),
          processedBy: mongoose.isValidObjectId(req.auth.id)
            ? req.auth.id
            : null,
        },
      },
      {
        new: true,
      }
    );

    if (!withdrawal) {
      const existing = await Withdrawal.findById(id);

      if (!existing) {
        return res.status(404).json({
          success: false,
          message: "Withdrawal not found.",
        });
      }

      return res.status(409).json({
        success: false,
        message: `This withdrawal has already been ${existing.status}.`,
        withdrawal: existing,
      });
    }

    try {
      if (status === "rejected") {
        // Refund only when a pending request is rejected.
        const refundResult = await User.updateOne(
          { _id: withdrawal.user },
          { $inc: { balance: withdrawal.amount } }
        );

        if (refundResult.matchedCount !== 1) {
          throw new Error(
            "Withdrawal rejected but the user refund could not be completed."
          );
        }
      }

      if (status === "approved") {
        // The amount was already reserved when the request was created.
        // Do not deduct the balance a second time.
        await User.updateOne(
          { _id: withdrawal.user },
          { $inc: { totalWithdrawals: withdrawal.amount } }
        );
      }

      await Transaction.updateOne(
        { reference: withdrawal.reference },
        {
          $set: {
            status: status === "approved" ? "completed" : "rejected",
            description:
              status === "approved"
                ? "Withdrawal approved"
                : "Withdrawal rejected and refunded",
          },
        }
      );
    } catch (error) {
      /*
       * Do not silently claim that accounting succeeded.
       * An operational error here needs attention and reconciliation.
       */
      console.error(
        "Withdrawal accounting error:",
        withdrawal._id,
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "The withdrawal status changed, but accounting needs administrator review.",
        withdrawal,
      });
    }

    return res.json({
      success: true,
      message:
        status === "approved"
          ? "Withdrawal approved successfully."
          : "Withdrawal rejected and balance refunded.",
      withdrawal,
    });
  })
);

// --------------------------------------------------
// ADMIN UPDATE USER BALANCE
// --------------------------------------------------

app.patch(
  "/api/admin/users/:id/balance",
  authenticate,
  requireAdmin,
  asyncHandler(async (req, res) => {
    await connectDB();

    const { id } = req.params;
    const amount = Number(req.body.amount);
    const operation = req.body.operation || "set";
    const description =
      typeof req.body.description === "string"
        ? req.body.description.trim()
        : "Administrator balance adjustment";

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid user ID.",
      });
    }

    if (
      !Number.isFinite(amount) ||
      amount < 0 ||
      amount > 1_000_000_000_000
    ) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid non-negative balance amount.",
      });
    }

    if (!["set", "add", "subtract"].includes(operation)) {
      return res.status(400).json({
        success: false,
        message: "Operation must be set, add, or subtract.",
      });
    }

    if (description.length > 500) {
      return res.status(400).json({
        success: false,
        message: "Description is too long.",
      });
    }

    const roundedAmount =
      Math.round((amount + Number.EPSILON) * 100) / 100;

    const user = await User.findById(id);

    if (!user || user.role !== "user") {
      return res.status(404).json({
        success: false,
        message: "User not found.",
      });
    }

    let updatedUser;
    let change;

    if (operation === "set") {
      change = roundedAmount - user.balance;

      if (change < 0) {
        updatedUser = await User.findOneAndUpdate(
          {
            _id: id,
            balance: { $gte: Math.abs(change) },
          },
          {
            $set: { balance: roundedAmount },
          },
          { new: true }
        );
      } else {
        updatedUser = await User.findByIdAndUpdate(
          id,
          { $set: { balance: roundedAmount } },
          { new: true }
        );
      }
    } else if (operation === "add") {
      change = roundedAmount;

      updatedUser = await User.findByIdAndUpdate(
        id,
        { $inc: { balance: roundedAmount } },
        { new: true }
      );
    } else {
      change = -roundedAmount;

      updatedUser = await User.findOneAndUpdate(
        {
          _id: id,
          balance: { $gte: roundedAmount },
        },
        { $inc: { balance: -roundedAmount } },
        { new: true }
      );
    }

    if (!updatedUser) {
      return res.status(400).json({
        success: false,
        message: "The balance update could not be completed.",
      });
    }

    if (change !== 0) {
      try {
        await Transaction.create({
          user: updatedUser._id,
          type: "adjustment",
          amount: Math.abs(change),
          status: "completed",
          description,
          reference: `ADJ-${crypto.randomUUID()}`,
          metadata: {
            operation,
            change,
            adminId: req.auth.id,
          },
        });
      } catch (error) {
        console.error("Balance audit transaction error:", error);

        return res.status(500).json({
          success: false,
          message:
            "Balance was updated, but the audit record could not be saved. Administrator review is required.",
          user: publicUser(updatedUser),
        });
      }
    }

    return res.json({
      success: true,
      message: "User balance updated successfully.",
      user: publicUser(updatedUser),
      balance: updatedUser.balance,
    });
  })
);

// --------------------------------------------------
// ADMIN DETAILS
// --------------------------------------------------

app.get(
  "/api/admin/me",
  authenticate,
  requireAdmin,
  asyncHandler(async (req, res) => {
    return res.json({
      success: true,
      user: {
        id: req.auth.id,
        email: ADMIN_EMAIL || "",
        role: "admin",
      },
    });
  })
);

// --------------------------------------------------
// 404 HANDLER
// --------------------------------------------------

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: `Route not found: ${req.method} ${req.path}`,
  });
});

// --------------------------------------------------
// GLOBAL ERROR HANDLER
// --------------------------------------------------

app.use((error, req, res, next) => {
  console.error("API error:", error);

  if (res.headersSent) {
    return next(error);
  }

  if (error?.code === 11000) {
    return res.status(409).json({
      success: false,
      message: "A record with these details already exists.",
    });
  }

  if (error instanceof mongoose.Error.ValidationError) {
    return res.status(400).json({
      success: false,
      message: "Validation failed.",
      errors: Object.values(error.errors).map(
        (item) => item.message
      ),
    });
  }

  if (error instanceof mongoose.Error.CastError) {
    return res.status(400).json({
      success: false,
      message: "Invalid ID or field value.",
    });
  }

  return res.status(500).json({
    success: false,
    message:
      process.env.NODE_ENV === "production"
        ? "An internal server error occurred."
        : error.message,
  });
});

// --------------------------------------------------
// LOCAL DEVELOPMENT
// --------------------------------------------------

// Vercel uses the exported Express app.
// Run `node index.jsx` locally if your Node version supports JSX
// filenames as ordinary JavaScript entry points.

if (process.env.NODE_ENV !== "production" && !process.env.VERCEL) {
  connectDB()
    .then(() => {
      app.listen(PORT, () => {
        console.log(`ElonixxWallet API running on port ${PORT}`);
      });
    })
    .catch((error) => {
      console.error("Failed to connect to MongoDB:", error.message);
    });
}

export default app;