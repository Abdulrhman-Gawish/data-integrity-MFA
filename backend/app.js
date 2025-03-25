const express = require("express");
const dotenv = require("dotenv");
const cookieParser = require("cookie-parser");
dotenv.config();

const connectDB = require("./config/conn");
const authRoute = require("./routes/authRoute");
const productRoute = require("./routes/productRoute");
const app = express();

app.use(express.json());
app.use(cookieParser());

app.use("/api/auth", authRoute);
app.use("/api/products", productRoute);



app.listen(process.env.PORT, async () => {
  await connectDB();
  console.log("Server Running");
});
