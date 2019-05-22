import express from "express";
import * as userController from "./user";

const router = express.Router();
router.post("/register", userController.register);

export default router;