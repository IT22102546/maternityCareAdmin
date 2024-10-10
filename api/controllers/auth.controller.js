import admin from 'firebase-admin';
import { errorHandler } from '../utils/error.js'; 
import jwt from 'jsonwebtoken';  
import { v4 as uuidv4 } from 'uuid';

export const signup = async (req, res, next) => {
  const { username, password, email } = req.body;

  const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+])[A-Za-z\d!@#$%^&*()_+]{5,}$/;

  if (!username || !password || !email) {
    return next(errorHandler(400, 'Please fill in all fields.'));
  } else if (!passwordRegex.test(password)) {
    return next(errorHandler(400, 'Password must be at least 5 characters long with one uppercase letter, one digit, and one symbol.'));
  }

  try {
    // Check if shopname already exists
    const shopnameSnapshot = await admin.firestore()
      .collection('users')
      .where('username', '==', username)
      .get();

    if (!shopnameSnapshot.empty) {
      return next(errorHandler(400, 'Shop name already exists. Please choose a different one.'));
    }

    // Check if brnumber already exists
    const brnumberSnapshot = await admin.firestore()
      .collection('users')
      .where('email', '==', email)
      .get();

    if (!brnumberSnapshot.empty) {
      return next(errorHandler(400, 'Business Registration Number already exists.'));
    }

    
    const userID = uuidv4();  
    
    const userRecord = await admin.auth().createUser({
      userID,
      email
    });

    console.log('User Record:', userRecord);

    
    const userRef = admin.firestore().collection('users').doc(userRecord.uid);
    await userRef.set({
      username,
      email,
      password,
      userID,  
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

  
    res.status(201).json({
      success: true,
      message: 'User created successfully',
      uid: userRecord.uid,
      userID,
    });
  } catch (error) {
    console.error('Signup error:', error);
    return next(errorHandler(500, error.message || 'Internal Server Error'));
  }
};



export const signin = async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
      return next(errorHandler(400, 'Please provide both Email and password.'));
  }

  try {
      
      const emailSnapshot = await admin.firestore()
          .collection('users')
          .where('email', '==', email)
          .get();

      if (emailSnapshot.empty) {
          console.log('User not found with BR Number:', email); 
          return next(errorHandler(404, 'User with the provided Business Registration Number not found.'));
      }

      
      const userDoc = emailSnapshot.docs[0];
      const userData = userDoc.data();

   
      if (password !== userData.password) {
          console.log('Password mismatch for Email:', email); 
          return next(errorHandler(401, 'Invalid credentials.'));
      }

      // Create a token
      const token = jwt.sign(
          { uid: userDoc.id, email: userData.email }, // Payload
          process.env.JWT_SECRET,
          { expiresIn: '1h' } 
      );

      // Set token in cookies
      res.cookie('access_token', token, {
          httpOnly: true, 
          secure: process.env.NODE_ENV === 'production', 
          maxAge: 3600000 
      });

     
      res.status(200).json({
          success: true,
          message: 'Login successful',
          user: {
              email: userData.email,
              username: userData.username,
              createdAt: userData.createdAt,
          },
      });

  } catch (error) {
      console.error('Sign-in error:', error); 
      return next(errorHandler(500, error.message || 'Internal Server Error'));
  }
};

{/*

   if (email && email !== userData.email) {
            try {
                // Update Firebase Auth
                await admin.auth().updateUser(userId, { email: email });
                console.log('Updated email in Firebase Auth for user:', userId);

                // Ensure Firestore reflects the updated email
                updateData.email = email;

                // Also update Firestore email to match
                if (Object.keys(updateData).length > 0) {
                    await userDoc.ref.update(updateData);
                }
            } catch (error) {
                console.error('Error updating email in Firebase Auth:', error);
                return next(errorHandler(500, 'Error updating email.'));
            }
        }
  */}