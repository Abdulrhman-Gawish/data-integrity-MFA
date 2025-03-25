const mongoose = require("mongoose");
const dotenv = require("dotenv");
dotenv.config();
const connectDB = async () => {
  try {
    // console.log(process.env.DB_URI); 
    
    await mongoose.connect(process.env.DB_URI);
    console.log("Connected to DB");
  } catch (error) {
    console.log("Fail connect");
    console.log(error.message);
  }
};

module.exports = connectDB;
