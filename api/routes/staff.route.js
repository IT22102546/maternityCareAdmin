import express from "express";
import { assignStaff, createStaff,getallStaff, getStaff, removeAssignedJob, removeStaff, testStaff, updateStaff,staffsignup,staffsignin } from "../controllers/staff.controller.js";

const router = express.Router();

router.get("/test", testStaff);
router.post("/create", createStaff);
router.get("/getAllStaff", getallStaff);
router.get("/getAllStaff/:brnumber", getStaff);
router.put("/assign-staff/:staffPhone/:brnumber", assignStaff);
router.put("/remove-assigned-job/:staffPhone/:brnumber", removeAssignedJob);
router.put("/update-staff/:staffPhone/:brnumber", updateStaff);
router.delete("/delete-staff/:staffPhone/:brnumber", removeStaff );
//router.put("/complete-staff/:staffPhone/", completeStaff);
router.post("/staffsignup",staffsignup);
router.post("/staffsignin",staffsignin);
export default router;