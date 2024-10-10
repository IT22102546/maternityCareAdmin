import express from "express";
import { deleteUser, updateUser } from "../controllers/shop.controller.js";

const router = express.Router();

router.put("/update/:brnumber" , updateUser);  
router.delete("/delete/:brnumber" , deleteUser); 


export default router;