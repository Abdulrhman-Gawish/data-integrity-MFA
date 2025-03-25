const Product = require("../models/product");
const createProduct = async (req, res) => {
  try {
    const { name, description, price, stock } = req.body;
    if (!name || !description || !price || !stock) {
      return res
        .status(404)
        .json({ success: false, message: "All failds required" });
    }

    const product = await Product.create({
      name,
      description,
      price,
      stock,
    });

    res.status(201).json({ success: true, product });
  } catch (error) {
    console.log("Server error", error.message);
    res.status(500).json({ success: false, message: error.message });
  }
};

const updateProduct = async (req, res) => {
  try {
    const { id } = req.params;
    const product = await Product.findByIdAndUpdate(id, req.body, {
      new: true,
    });

    if (!product) {
      return res
        .status(404)
        .json({ success: false, message: "Can't find this product" });
    }

    res.status(200).json({ success: true, product });
  } catch (error) {
    console.log("Server error", error.message);
    res.status(500).json({ success: false, message: error.message });
  }
};

const deleteProduct = async (req, res) => {
  try {
    const { id } = req.params;
    const product = await Product.findByIdAndDelete(id);
    if (!product) {
      return res
        .status(404)
        .json({ success: false, message: "Can't find this product" });
    }

    res.status(200).json({ success: true, message: "Deleted Successfully " });
  } catch (error) {
    console.log("Server error", error.message);
    res.status(500).json({ success: false, message: error.message });
  }
};

const getProducts = async (req, res) => {
  try {
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 20;
    const skip = (page - 1) * limit;

    const products = await Product.find({}).limit(limit).skip(skip);
    if (!products || products.length === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Can't find any product" });
    }

    res
      .status(200)
      .json({ success: true, totalCount: products.length, data: products });
  } catch (error) {
    console.log("Server error", error.message);
    res.status(500).json({ success: false, message: error.message });
  }
};

module.exports = {
  createProduct,
  updateProduct,
  deleteProduct,
  getProducts,
};
