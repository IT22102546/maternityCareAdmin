import admin from 'firebase-admin';
import { errorHandler } from '../utils/error.js';

export const updateUser = async (req, res, next) => {
    const db = admin.firestore();
    const brnumber = req.params.brnumber;
    
    if (!brnumber) {
        return next(errorHandler(400, 'BR Number is required.'));
    }

    console.log('BR Number:', brnumber);  // Debugging line

    try {
        // Fetch user document by BR Number
        const userSnapshot = await db.collection('users')
            .where('brnumber', '==', brnumber)
            .get();
        
        if (userSnapshot.empty) {
            return next(errorHandler(404, 'User with the provided BR Number not found.'));
        }

        const userDoc = userSnapshot.docs[0];
        const userId = userDoc.id;  // Firestore Document ID
        const userData = userDoc.data();

        // Proceed with update
        const { shopname, email, newBrnumber } = req.body;
        const updateData = {};

        // Update Firestore fields
        if (shopname) {
            if (shopname.length >= 3) {
                updateData.shopname = shopname;
            } else {
                return next(errorHandler(400, 'Shop name must be at least 3 characters long.'));
            }
        }

        if (newBrnumber && newBrnumber !== userData.brnumber) {
            // Check if the new BR Number already exists
            const existingBrnumberSnapshot = await db.collection('users')
                .where('brnumber', '==', newBrnumber)
                .get();

            if (!existingBrnumberSnapshot.empty) {
                return next(errorHandler(400, 'The new BR Number already exists.'));
            }

            // Update BR Number
            updateData.brnumber = newBrnumber;
        }

        // Apply updates to Firestore first
        if (Object.keys(updateData).length > 0) {
            await userDoc.ref.update(updateData);
            console.log('Updated Firestore user data:', updateData);
        }

        // Update Firebase Authentication fields
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

        // Fetch updated user document from Firestore
        const updatedUserDoc = await userDoc.ref.get();
        const updatedUser = updatedUserDoc.data();

        res.status(200).json({ success: true, user: updatedUser });
    } catch (error) {
        console.error('Update user error:', error);
        next(errorHandler(500, 'Internal Server Error'));
    }
};

export const deleteUser = async (req, res, next) => {
    const db = admin.firestore();
    const brnumber = req.params.brnumber;

    if (!brnumber) {
        return next(errorHandler(400, 'BR Number is required.'));
    }

    try {
        // Fetch user document by BR Number
        const userSnapshot = await db.collection('users')
            .where('brnumber', '==', brnumber)
            .get();

        if (userSnapshot.empty) {
            return next(errorHandler(404, 'User with the provided BR Number not found.'));
        }

        const userDoc = userSnapshot.docs[0];
        const userId = userDoc.id;  // Firestore Document ID

        
        await userDoc.ref.delete();
        console.log('Deleted user document from Firestore:', userId);

      
        try {
            await admin.auth().deleteUser(userId);
            console.log('Deleted user from Firebase Auth:', userId);
        } catch (error) {
            console.error('Error deleting user from Firebase Auth:', error);
            return next(errorHandler(500, 'Error deleting user from Firebase Auth.'));
        }

        res.status(200).json({ success: true, message: 'User deleted successfully' });
    } catch (error) {
        console.error('Delete user error:', error);
        next(errorHandler(500, 'Internal Server Error'));
    }
};