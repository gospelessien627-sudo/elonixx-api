import express from "express";
import cors from "cors";
import dns from "node:dns/promises";
import mongoose from "mongoose";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();

dns.setServers(["1.1.1.1", "8.8.8.8"]);

/* =====================================================
   EXPRESS
===================================================== */

const app = express();

/* =====================================================
   ENVIRONMENT VARIABLES
===================================================== */

const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;

/* =====================================================
   ENVIRONMENT CHECK
===================================================== */

if (!MONGODB_URI) {
  console.error("ERROR: MONGODB_URI is missing.");
}

if (!JWT_SECRET) {
  console.error("ERROR: JWT_SECRET is missing.");
}

/* =====================================================
   CORS
===================================================== */

const allowedOrigins = [
  "https://elonixx.com",
  "https://www.elonixx.com",
];

app.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests without an Origin header
      // such as server-to-server requests.
      if (!origin) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

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

app.use(express.json());

/* =====================================================
   MONGODB CONNECTION
===================================================== */

let mongoConnection = null;

async function connectDatabase() {
  if (!MONGODB_URI) {
    throw new Error(
      "MONGODB_URI environment variable is missing."
    );
  }

  if (mongoose.connection.readyState === 1) {
    return mongoose.connection;
  }

  if (mongoConnection) {
    return mongoConnection;
  }

  mongoConnection = mongoose
    .connect(MONGODB_URI, {
      serverSelectionTimeoutMS: 10000,
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
        "MongoDB connection error:",
        error
      );

      throw error;
    });

  return mongoConnection;
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
   AUTHENTICATION MIDDLEWARE
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
          "JWT_SECRET is not configured.",
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
      "AUTHENTICATION ERROR:",
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
   API ROOT
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
      "API ROOT ERROR:",
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
   API TEST
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
      });
    }
  }
);

/* =====================================================
   HOME
===================================================== */

app.get(
  "/api/home",
  async (req, res) => {
    try {
      await connectDatabase();

      return res.json({
        success: true,
        app: "ElonixxWallet",
        message:
          "Welcome to ElonixxWallet.",
        status: "online",
        secure: true,
      });
    } catch (error) {
      console.error(
        "HOME ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to connect to database.",
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
    try {
      await connectDatabase();

      if (!JWT_SECRET) {
        return res.status(500).json({
          success: false,
          message:
            "JWT_SECRET is not configured.",
        });
      }

      const {
        name,
        email,
        password,
      } = req.body;

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

      const normalizedEmail =
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

      if (cleanPassword.length < 6) {
        return res.status(400).json({
          success: false,
          message:
            "Password must contain at least 6 characters.",
        });
      }

      const existingUser =
        await User.findOne({
          email:
            normalizedEmail,
        });

      if (existingUser) {
        return res.status(409).json({
          success: false,
          message:
            "An account with this email already exists.",
        });
      }

      const hashedPassword =
        await bcrypt.hash(
          cleanPassword,
          12
        );

      const user =
        await User.create({
          name: cleanName,
          email: normalizedEmail,
          password: hashedPassword,
          balance: 0,
          deposited: 0,
          withdrawn: 0,
        });

      const token =
        jwt.sign(
          {
            userId:
              user._id.toString(),
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
        "REGISTER ERROR:",
        error
      );

      if (error.code === 11000) {
        return res.status(409).json({
          success: false,
          message:
            "An account with this email already exists.",
        });
      }

      return res.status(500).json({
        success: false,
        message:
          "Unable to create account.",
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
      await connectDatabase();

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
      } = req.body;

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
          },
          JWT_SECRET,
          {
            expiresIn: "7d",
          }
        );

      return res.json({
        success: true,

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
   GET WITHDRAWAL ACCOUNTS
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
      } = req.body;

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

      const cleanProvider =
        String(provider).trim();

      const cleanAccountName =
        String(accountName).trim();

      const cleanAccountNumber =
        String(accountNumber).trim();

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
            cleanProvider,

          accountName:
            cleanAccountName,

          accountNumber:
            cleanAccountNumber,

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
      } = req.body;

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
   EXPLICIT UNKNOWN API ROUTE
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