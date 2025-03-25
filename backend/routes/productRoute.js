const express = require("express");
const router = express.Router();
const productController = require("../controller/productController");
const verifyToken = require("../middleware/verifyToken");
const checkRole = require("../middleware/checkRole");
const userRole = require("../utils/enums/userRole");

router
  .route("/")
  .post(verifyToken, productController.createProduct)
  .get(verifyToken, productController.getProducts);

router
  .route("/:id")
  .patch(verifyToken, productController.updateProduct)
  .delete(
    verifyToken,
    checkRole([userRole.ADMIN]),
    productController.deleteProduct
  );

module.exports = router;
