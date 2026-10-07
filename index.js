import express from "express";
import cors from "cors";

const app = express();

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Elonixx API is running 🚀"
  });
});

app.get("/api/test", (req, res) => {
  res.json({
    success: true,
    message: "Elonixx backend is connected!"
  });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Elonixx API running on port ${PORT}`);
});