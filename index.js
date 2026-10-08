import express from "express";
import cors from "cors";
import dns from "node:dns/promises";
import mongoose from "mongoose";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();

dns.setServers(["1.1.1.1", "8.8.8.8"]);

const app = express();

/* =====================================================
   ENVIRONMENT VARIABLES
===================================================== */

const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;

const ADMIN_EMAIL =
  process.env.ADMIN_EMAIL;

const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD;

/* =====================================================
   ENVIRONMENT CHECK
===================================================== */

console.log("=================================");
console.log("ELONIXX BACKEND STARTING");
console.log("=================================");

console.log(
  "MONGODB_URI:",
  MONGODB_URI ? "FOUND" : "MISSING"
);

console.log(
  "JWT_SECRET:",
  JWT_SECRET ? "FOUND" : "MISSING"
);

console.log(
  "ADMIN_EMAIL:",
  ADMIN_EMAIL ? "FOUND" : "MISSING"
);

console.log(
  "ADMIN_PASSWORD:",
  ADMIN_PASSWORD ? "FOUND" : "MISSING"
);

/* =====================================================
   CORS
===================================================== */

const allowedOrigins = [
  "https://elonixx.com",
  "https://www.elonixx.com",
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      console.log(
        "Blocked CORS origin:",
        origin
      );

      return callback(
        new Error("Not allowed by CORS")
      );
    },

    methods: [
      "GET",
      "POST",
      "PUT",
      "PATCH",
      "DELETE",
      "OPTIONS",
    ],

    allowedHeaders: [
      "Content-Type",
      "Authorization",
    ],

    credentials: true,
  })
);

/* =====================================================
   JSON
===================================================== */

app.use(express.json());

/* =====================================================
   DATABASE CONNECTION
===================================================== */

let mongoConnection = null;

async function connectDatabase() {
  if (!MONGODB_URI) {
    throw new Error(
      "MONGODB_URI environment variable is missing."
    );
  }

  if (
    mongoose.connection.readyState === 1
  ) {
    return mongoose.connection;
  }

  if (mongoConnection) {
    return mongoConnection;
  }

  mongoConnection = mongoose
    .connect(MONGODB_URI, {
      serverSelectionTimeoutMS: 10000,
      connectTimeoutMS: 10000,
    })
    .then((connection) => {
      console.log(
        "MongoDB connected successfully."
      );

      return connection;
    })
    .catch((error) => {
      mongoConnection = null;

      console.error(
        "MongoDB connection failed:",
        error
      );

      throw error;
    });

  return mongoConnection;
}

/* =====================================================
   USER MODEL
===================================================== */

const userSchema =
  new mongoose.Schema(
    {
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
    },

    {
      timestamps: true,
    }
  );

const User =
  mongoose.models.User ||
  mongoose.model(
    "User",
    userSchema
  );

/* =====================================================
   TRANSACTION MODEL
===================================================== */

const transactionSchema =
  new mongoose.Schema(
    {
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
        enum: [
          "deposit",
          "withdrawal",
        ],
        required: true,
      },

      amount: {
        type: Number,
        required: true,
      },

      paymentMethod: {
        type: String,
        default: "Bank Transfer",
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
        enum: [
          "pending",
          "processing",
          "completed",
          "failed",
        ],
        default: "pending",
      },
    },

    {
      timestamps: true,
    }
  );

const Transaction =
  mongoose.models.Transaction ||
  mongoose.model(
    "Transaction",
    transactionSchema
  );

/* =====================================================
   WITHDRAWAL ACCOUNT MODEL
===================================================== */

const withdrawalAccountSchema =
  new mongoose.Schema(
    {
      userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true,
      },

      provider: {
        type: String,
        required: true,
        trim: true,
      },

      accountName: {
        type: String,
        required: true,
        trim: true,
      },

      accountNumber: {
        type: String,
        required: true,
        trim: true,
      },

      isDefault: {
        type: Boolean,
        default: false,
      },
    },

    {
      timestamps: true,
    }
  );

const WithdrawalAccount =
  mongoose.models.WithdrawalAccount ||
  mongoose.model(
    "WithdrawalAccount",
    withdrawalAccountSchema
  );

/* =====================================================
   GENERATE TRANSACTION ID
===================================================== */

function generateId() {
  return (
    Date.now().toString(36) +
    Math.random()
      .toString(36)
      .substring(2, 10)
  );
}

/* =====================================================
   USER AUTHENTICATION
===================================================== */

async function authenticate(
  req,
  res,
  next
) {
  try {
    if (!JWT_SECRET) {
      return res.status(500).json({
        success: false,
        message:
          "JWT_SECRET is not configured on the server.",
      });
    }

    const authorization =
      req.headers.authorization;

    if (!authorization) {
      return res.status(401).json({
        success: false,
        message:
          "Authentication required.",
      });
    }

    if (
      !authorization.startsWith(
        "Bearer "
      )
    ) {
      return res.status(401).json({
        success: false,
        message:
          "Invalid authorization format.",
      });
    }

    const token =
      authorization.substring(7);

    const decoded =
      jwt.verify(
        token,
        JWT_SECRET
      );

    /*
     * Admin tokens must not be accepted
     * by normal user routes.
     */

    if (
      decoded.role === "admin"
    ) {
      return res.status(403).json({
        success: false,
        message:
          "Administrator token cannot access this route.",
      });
    }

    await connectDatabase();

    const user =
      await User.findById(
        decoded.userId
      ).select("-password");

    if (!user) {
      return res.status(401).json({
        success: false,
        message:
          "User not found.",
      });
    }

    req.user = user;

    next();
  } catch (error) {
    console.error(
      "AUTH ERROR:",
      error
    );

    return res.status(401).json({
      success: false,
      message:
        "Invalid or expired token.",
    });
  }
}

/* =====================================================
   ADMIN AUTHENTICATION
===================================================== */

async function authenticateAdmin(
  req,
  res,
  next
) {
  try {
    if (!JWT_SECRET) {
      return res.status(500).json({
        success: false,
        message:
          "JWT_SECRET is not configured on the server.",
      });
    }

    const authorization =
      req.headers.authorization;

    if (!authorization) {
      return res.status(401).json({
        success: false,
        message:
          "Admin authentication required.",
      });
    }

    if (
      !authorization.startsWith(
        "Bearer "
      )
    ) {
      return res.status(401).json({
        success: false,
        message:
          "Invalid authorization format.",
      });
    }

    const token =
      authorization.substring(7);

    const decoded =
      jwt.verify(
        token,
        JWT_SECRET
      );

    if (
      decoded.role !== "admin"
    ) {
      return res.status(403).json({
        success: false,
        message:
          "Administrator access required.",
      });
    }

    if (
      decoded.adminEmail !==
      ADMIN_EMAIL
    ) {
      return res.status(403).json({
        success: false,
        message:
          "Invalid administrator account.",
      });
    }

    req.admin = {
      email:
        decoded.adminEmail,
      role:
        decoded.role,
    };

    next();
  } catch (error) {
    console.error(
      "ADMIN AUTH ERROR:",
      error
    );

    return res.status(401).json({
      success: false,
      message:
        "Invalid or expired admin token.",
    });
  }
}

/* =====================================================
   ROOT
===================================================== */

app.get("/", async (req, res) => {
  try {
    await connectDatabase();

    return res.json({
      success: true,
      message:
        "Elonixx API is running 🚀",
      status: "online",
      database: "connected",
      chat: "disabled",
    });
  } catch (error) {
    console.error(
      "ROOT ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Database connection failed.",
    });
  }
});

/* =====================================================
   TEST
===================================================== */

app.get(
  "/api/test",
  async (req, res) => {
    try {
      await connectDatabase();

      return res.json({
        success: true,
        message:
          "Elonixx backend is connected successfully!",
        database: "connected",
      });
    } catch (error) {
      console.error(
        "TEST ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Backend cannot connect to MongoDB.",
        error:
          error.message,
      });
    }
  }
);

/* =====================================================
   REGISTER
===================================================== */

app.post(
  "/api/register",
  async (req, res) => {
    console.log(
      "================================="
    );

    console.log(
      "REGISTRATION REQUEST RECEIVED"
    );

    console.log(
      "================================="
    );

    try {
      if (!MONGODB_URI) {
        console.error(
          "MONGODB_URI is missing."
        );

        return res.status(500).json({
          success: false,
          message:
            "Server database configuration is missing.",
        });
      }

      if (!JWT_SECRET) {
        console.error(
          "JWT_SECRET is missing."
        );

        return res.status(500).json({
          success: false,
          message:
            "Server authentication configuration is missing.",
        });
      }

      await connectDatabase();

      console.log(
        "Database ready for registration."
      );

      const {
        name,
        email,
        password,
      } = req.body || {};

      console.log(
        "Registration email:",
        email
      );

      if (
        !name ||
        !email ||
        !password
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Name, email and password are required.",
        });
      }

      const cleanName =
        String(name).trim();

      const cleanEmail =
        String(email)
          .trim()
          .toLowerCase();

      const cleanPassword =
        String(password);

      if (cleanName.length < 2) {
        return res.status(400).json({
          success: false,
          message:
            "Name must contain at least 2 characters.",
        });
      }

      if (cleanEmail.length < 5) {
        return res.status(400).json({
          success: false,
          message:
            "Please enter a valid email address.",
        });
      }

      if (cleanPassword.length < 6) {
        return res.status(400).json({
          success: false,
          message:
            "Password must contain at least 6 characters.",
        });
      }

      console.log(
        "Checking whether email already exists..."
      );

      const existingUser =
        await User.findOne({
          email: cleanEmail,
        });

      if (existingUser) {
        console.log(
          "Registration rejected: email already exists."
        );

        return res.status(409).json({
          success: false,
          message:
            "An account with this email already exists.",
        });
      }

      console.log(
        "Hashing password..."
      );

      const hashedPassword =
        await bcrypt.hash(
          cleanPassword,
          12
        );

      console.log(
        "Creating MongoDB user..."
      );

      const user =
        new User({
          name: cleanName,
          email: cleanEmail,
          password: hashedPassword,
          balance: 0,
          deposited: 0,
          withdrawn: 0,
        });

      await user.save();

      console.log(
        "User created:",
        user._id.toString()
      );

      console.log(
        "Creating authentication token..."
      );

      const token =
        jwt.sign(
          {
            userId:
              user._id.toString(),
            role:
              "user",
          },
          JWT_SECRET,
          {
            expiresIn: "7d",
          }
        );

      return res.status(201).json({
        success: true,

        message:
          "Account created successfully.",

        user: {
          id:
            user._id.toString(),

          name:
            user.name,

          email:
            user.email,

          balance:
            user.balance,

          deposited:
            user.deposited,

          withdrawn:
            user.withdrawn,
        },

        token,
      });
    } catch (error) {
      console.error(
        "================================="
      );

      console.error(
        "REGISTRATION ERROR"
      );

      console.error(
        "================================="
      );

      console.error(
        "Name:",
        error?.name
      );

      console.error(
        "Message:",
        error?.message
      );

      console.error(
        "Code:",
        error?.code
      );

      console.error(
        "Full error:",
        error
      );

      if (
        error?.code === 11000
      ) {
        return res.status(409).json({
          success: false,
          message:
            "An account with this email already exists.",
        });
      }

      if (
        error?.name ===
        "ValidationError"
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid account information.",
          details:
            Object.values(
              error.errors || {}
            )
              .map(
                (item) =>
                  item.message
              )
              .join(", "),
        });
      }

      if (
        error?.name ===
        "JsonWebTokenError"
      ) {
        return res.status(500).json({
          success: false,
          message:
            "Unable to create authentication token.",
        });
      }

      if (
        error?.name ===
          "MongoServerError" ||
        error?.name ===
          "MongooseServerSelectionError"
      ) {
        return res.status(500).json({
          success: false,
          message:
            "Database error while creating the account.",
          details:
            error.message,
        });
      }

      return res.status(500).json({
        success: false,

        message:
          "Unable to create account.",

        details:
          error?.message ||
          "Unknown server error.",
      });
    }
  }
);

/* =====================================================
   LOGIN
===================================================== */

app.post(
  "/api/login",
  async (req, res) => {
    try {
      if (!JWT_SECRET) {
        return res.status(500).json({
          success: false,
          message:
            "JWT_SECRET is not configured.",
        });
      }

      const {
        email,
        password,
      } = req.body || {};

      if (
        !email ||
        !password
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Email and password are required.",
        });
      }

      const normalizedEmail =
        String(email)
          .trim()
          .toLowerCase();

      /* =================================================
         ADMIN LOGIN
      ================================================= */

      if (
        ADMIN_EMAIL &&
        ADMIN_PASSWORD &&
        normalizedEmail ===
          ADMIN_EMAIL
            .trim()
            .toLowerCase() &&
        String(password) ===
          String(ADMIN_PASSWORD)
      ) {
        const adminToken =
          jwt.sign(
            {
              role:
                "admin",

              adminEmail:
                ADMIN_EMAIL
                  .trim()
                  .toLowerCase(),
            },
            JWT_SECRET,
            {
              expiresIn: "7d",
            }
          );

        return res.json({
          success: true,

          role: "admin",

          message:
            "Admin login successful.",

          email:
            ADMIN_EMAIL
              .trim()
              .toLowerCase(),

          token:
            adminToken,
        });
      }

      /* =================================================
         NORMAL USER LOGIN
      ================================================= */

      await connectDatabase();

      const user =
        await User.findOne({
          email:
            normalizedEmail,
        });

      if (!user) {
        return res.status(401).json({
          success: false,
          message:
            "Invalid email or password.",
        });
      }

      const passwordMatches =
        await bcrypt.compare(
          String(password),
          user.password
        );

      if (!passwordMatches) {
        return res.status(401).json({
          success: false,
          message:
            "Invalid email or password.",
        });
      }

      const token =
        jwt.sign(
          {
            userId:
              user._id.toString(),

            role:
              "user",
          },
          JWT_SECRET,
          {
            expiresIn: "7d",
          }
        );

      return res.json({
        success: true,

        role: "user",

        message:
          "Login successful.",

        user: {
          id:
            user._id.toString(),

          name:
            user.name,

          email:
            user.email,

          balance:
            user.balance,

          deposited:
            user.deposited,

          withdrawn:
            user.withdrawn,
        },

        token,
      });
    } catch (error) {
      console.error(
        "LOGIN ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to login.",
        details:
          error?.message,
      });
    }
  }
);

/* =====================================================
   DASHBOARD
===================================================== */

app.get(
  "/api/dashboard",
  authenticate,
  async (req, res) => {
    try {
      await connectDatabase();

      const transactions =
        await Transaction.find({
          userId:
            req.user._id,
        })
          .sort({
            createdAt: -1,
          })
          .limit(20);

      const withdrawalAccounts =
        await WithdrawalAccount.find({
          userId:
            req.user._id,
        }).sort({
          isDefault: -1,
          createdAt: -1,
        });

      return res.json({
        success: true,

        user: {
          id:
            req.user._id.toString(),

          name:
            req.user.name,

          email:
            req.user.email,

          balance:
            req.user.balance,

          deposited:
            req.user.deposited,

          withdrawn:
            req.user.withdrawn,
        },

        transactions,

        withdrawalAccounts,
      });
    } catch (error) {
      console.error(
        "DASHBOARD ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to load dashboard.",
      });
    }
  }
);

/* =====================================================
   TRANSACTIONS
===================================================== */

app.get(
  "/api/transactions",
  authenticate,
  async (req, res) => {
    try {
      await connectDatabase();

      const transactions =
        await Transaction.find({
          userId:
            req.user._id,
        }).sort({
          createdAt: -1,
        });

      return res.json({
        success: true,
        transactions,
      });
    } catch (error) {
      console.error(
        "TRANSACTIONS ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to load transactions.",
      });
    }
  }
);

/* =====================================================
   WITHDRAWAL ACCOUNTS
===================================================== */

app.get(
  "/api/withdrawal-accounts",
  authenticate,
  async (req, res) => {
    try {
      await connectDatabase();

      const accounts =
        await WithdrawalAccount.find({
          userId:
            req.user._id,
        }).sort({
          isDefault: -1,
          createdAt: -1,
        });

      return res.json({
        success: true,
        accounts,
      });
    } catch (error) {
      console.error(
        "ACCOUNTS ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to load withdrawal accounts.",
      });
    }
  }
);

/* =====================================================
   ADD WITHDRAWAL ACCOUNT
===================================================== */

app.post(
  "/api/withdrawal-accounts",
  authenticate,
  async (req, res) => {
    try {
      await connectDatabase();

      const {
        provider,
        accountName,
        accountNumber,
      } = req.body || {};

      if (
        !provider ||
        !accountName ||
        !accountNumber
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Provider, account name and account number are required.",
        });
      }

      const accountCount =
        await WithdrawalAccount.countDocuments(
          {
            userId:
              req.user._id,
          }
        );

      const account =
        await WithdrawalAccount.create({
          userId:
            req.user._id,

          provider:
            String(provider).trim(),

          accountName:
            String(accountName).trim(),

          accountNumber:
            String(accountNumber).trim(),

          isDefault:
            accountCount === 0,
        });

      return res.status(201).json({
        success: true,
        message:
          "Withdrawal account added successfully.",
        account,
      });
    } catch (error) {
      console.error(
        "ADD ACCOUNT ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to add withdrawal account.",
      });
    }
  }
);

/* =====================================================
   WITHDRAWAL
===================================================== */

app.post(
  "/api/withdrawals",
  authenticate,
  async (req, res) => {
    try {
      await connectDatabase();

      const {
        amount,
        accountNumber,
        accountName,
        paymentMethod,
      } = req.body || {};

      const numericAmount =
        Number(amount);

      if (
        !Number.isFinite(
          numericAmount
        ) ||
        numericAmount <= 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Enter a valid withdrawal amount.",
        });
      }

      if (
        !accountNumber ||
        !accountName
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Account number and account name are required.",
        });
      }

      if (
        numericAmount >
        req.user.balance
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Insufficient available balance.",
        });
      }

      const transaction =
        await Transaction.create({
          userId:
            req.user._id,

          transactionId:
            generateId(),

          type:
            "withdrawal",

          amount:
            numericAmount,

          paymentMethod:
            paymentMethod ||
            "Bank Transfer",

          accountNumber:
            String(
              accountNumber
            ).trim(),

          accountName:
            String(
              accountName
            ).trim(),

          status:
            "pending",
        });

      return res.status(201).json({
        success: true,

        message:
          "Withdrawal request submitted successfully. Your request is pending review.",

        transaction,
      });
    } catch (error) {
      console.error(
        "WITHDRAWAL ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to create withdrawal request.",
      });
    }
  }
);

/* =====================================================
   ADMIN OVERVIEW
===================================================== */

app.get(
  "/api/admin/overview",
  authenticateAdmin,
  async (req, res) => {
    try {
      await connectDatabase();

      const [
        totalUsers,
        totalTransactions,
        totalWithdrawals,
        pendingWithdrawals,
        completedWithdrawals,
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

        User.find()
          .select("-password")
          .sort({
            createdAt: -1,
          }),
      ]);

      return res.json({
        success: true,

        statistics: {
          totalUsers,

          totalTransactions,

          totalWithdrawals,

          pendingWithdrawals,

          completedWithdrawals,
        },

        users,
      });
    } catch (error) {
      console.error(
        "ADMIN OVERVIEW ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to load admin overview.",
      });
    }
  }
);

/* =====================================================
   ADMIN WITHDRAWALS
===================================================== */

app.get(
  "/api/admin/withdrawals",
  authenticateAdmin,
  async (req, res) => {
    try {
      await connectDatabase();

      const withdrawals =
        await Transaction.find({
          type:
            "withdrawal",
        })
          .populate(
            "userId",
            "-password"
          )
          .sort({
            createdAt: -1,
          });

      return res.json({
        success: true,

        withdrawals,
      });
    } catch (error) {
      console.error(
        "ADMIN WITHDRAWALS ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to load withdrawals.",
      });
    }
  }
);

/* =====================================================
   ADMIN UPDATE WITHDRAWAL STATUS
===================================================== */

app.patch(
  "/api/admin/withdrawals/:id/status",
  authenticateAdmin,
  async (req, res) => {
    try {
      await connectDatabase();

      const {
        id,
      } = req.params;

      const {
        status,
      } = req.body || {};

      const allowedStatuses = [
        "pending",
        "processing",
        "completed",
        "failed",
      ];

      if (
        !allowedStatuses.includes(
          status
        )
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid withdrawal status.",
        });
      }

      const withdrawal =
        await Transaction.findOne({
          _id: id,
          type:
            "withdrawal",
        });

      if (!withdrawal) {
        return res.status(404).json({
          success: false,
          message:
            "Withdrawal request not found.",
        });
      }

      withdrawal.status =
        status;

      await withdrawal.save();

      const updatedWithdrawal =
        await Transaction.findById(
          withdrawal._id
        ).populate(
          "userId",
          "-password"
        );

      return res.json({
        success: true,

        message:
          "Withdrawal status updated successfully.",

        withdrawal:
          updatedWithdrawal,
      });
    } catch (error) {
      console.error(
        "ADMIN UPDATE WITHDRAWAL ERROR:",
        error
      );

      if (
        error?.name ===
        "CastError"
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid withdrawal ID.",
        });
      }

      return res.status(500).json({
        success: false,
        message:
          "Unable to update withdrawal status.",
      });
    }
  }
);

/* =====================================================
   API 404
===================================================== */

app.use(
  "/api",
  (req, res) => {
    return res.status(404).json({
      success: false,
      message:
        "API endpoint not found.",
      path:
        req.path,
    });
  }
);

/* =====================================================
   GENERAL 404
===================================================== */
app.use(
  (req, res) => {
    return res.status(404).json({
      success: false,
      message:
        "Endpoint not found.",
      path:
        req.path,
    });
  }
);

/* =====================================================
   VERCEL
===================================================== */

export default app;