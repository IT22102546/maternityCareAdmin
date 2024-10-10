import express from "express";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import cors from "cors";
import admin from "firebase-admin";
import serviceAccount from "./firebase-service-account.json" assert { type: "json" };
import authRoute from "./routes/auth.route.js";
import shopRoute from "./routes/shop.route.js";


dotenv.config();

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore(); 

const app = express();
app.use(cookieParser());
app.use(express.json());

const corsOptions = {
  origin: 'http://localhost:5173',
};
app.use(cors(corsOptions));

const checkFirestoreConnection = async () => {
  try {
    const testDocRef = db.collection('test').doc('connectionTest');
    await testDocRef.set({ status: "connected", timestamp: new Date() }); 
    const doc = await testDocRef.get(); 
    if (doc.exists) {
      console.log("Firestore is connected:", doc.data());
    } else {
      console.log("No such document!");
    }
  } catch (error) {
    console.error("Error connecting to Firestore:", error);
  }
};

app.listen(3000, async () => {
  console.log("Server is running on Port 3000");
  await checkFirestoreConnection(); 
});


app.use("/api/auth",authRoute);
app.use("/api/shop",shopRoute);

app.use((err,req,res,next)=>{
    const statusCode = err.statusCode || 500;
    const message = err.message || 'Internal Server Error';
    return res.status(statusCode).json({
        success:false,
        message,
        statusCode
    });
})
