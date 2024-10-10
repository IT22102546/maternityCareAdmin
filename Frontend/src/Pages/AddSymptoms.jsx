import React, { useState, useEffect, useRef } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { addDoc, collection, getFirestore } from "firebase/firestore";
import { getDownloadURL, getStorage, ref, uploadBytesResumable } from "firebase/storage";
import { Formik } from 'formik';
import { useNavigate } from 'react-router-dom';
import { app } from '../firebase';

export default function AddSymptoms() {
  const [image, setImage] = useState(null);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [isUploading, setIsUploading] = useState(false);
  const db = getFirestore(app);
  const storage = getStorage();
  const navigate = useNavigate();
  const currentUser = useSelector((state) => state.user.currentUser);

  const handleImageUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      setImage(file);
    }
  };

  const onSubmitMethod = async (values, { resetForm }) => {
    try {
      setIsUploading(true);

      let downloadUrl = '';
      if (image) {
        const storageRef = ref(storage, 'symptoms/' + Date.now() + ".jpg");
        const uploadTask = uploadBytesResumable(storageRef, image);

        await new Promise((resolve, reject) => {
          uploadTask.on('state_changed',
            (snapshot) => {
              const progress = (snapshot.bytesTransferred / snapshot.totalBytes) * 100;
              setUploadProgress(progress);
            },
            (error) => {
              console.error("Upload Error: ", error);
              alert("Failed to upload image");
              setIsUploading(false);
              reject(error);
            },
            async () => {
              downloadUrl = await getDownloadURL(uploadTask.snapshot.ref);
              resolve();
            }
          );
        });
      }

      const symptomData = {
        advice: values.advice,
        details: values.details,
        duration: values.duration,
        month: values.month,
        name: values.name,
        remedies: values.remedies,
        severity: values.severity,
        userName: currentUser?.username || 'Anonymous',
        userEmail: currentUser?.email || '',
        createdAt: Date.now().toString()
      };

      const docRef = await addDoc(collection(db, "symptoms"), symptomData);
      if (docRef.id) {
        alert("Symptom added successfully!");
        resetForm();
        setImage(null);
      }

      setIsUploading(false);
      setUploadProgress(0);
    } catch (error) {
      console.error("Error adding document: ", error);
      alert("Failed to add symptom");
      setIsUploading(false);
    }
  };

  const handleGoBack = () => {
    navigate("/dashboard?tab=profile");
  };

  return (
    <div className="max-w-4xl mx-auto bg-white shadow-md rounded-lg p-8 mt-8">
      <h1 className="text-3xl font-bold text-center mb-6">Add New Symptom</h1>

      <Formik
        initialValues={{
          name: '',
          details: '',
          duration: '',
          month: '',
          remedies: '',
          severity: '',
          advice: ''
        }}
        onSubmit={(values, actions) => onSubmitMethod(values, actions)}
        validate={(values) => {
          const errors = {};
          if (!values.name) {
            errors.name = "Please Enter Symptom Name";
            alert("Please Enter Symptom Name");
          }
          return errors;
        }}
      >
        {({ handleChange, handleBlur, handleSubmit, setFieldValue, values, errors }) => (
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="flex flex-col space-y-2">
              <label className="text-lg font-medium">Symptom Name</label>
              <input
                type="text"
                className="border border-gray-300 rounded-lg p-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Enter Symptom Name"
                onChange={handleChange('name')}
                onBlur={handleBlur('name')}
                value={values.name}
                disabled={isUploading}
              />
            </div>

            <div className="flex flex-col space-y-2">
              <label className="text-lg font-medium">Details</label>
              <textarea
                className="border border-gray-300 rounded-lg p-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Enter Details"
                onChange={handleChange('details')}
                onBlur={handleBlur('details')}
                value={values.details}
                rows="5"
                disabled={isUploading}
              />
            </div>

            <div className="flex flex-col space-y-2">
              <label className="text-lg font-medium">Duration</label>
              <input
                type="text"
                className="border border-gray-300 rounded-lg p-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Enter Duration (e.g. First Trimester)"
                onChange={handleChange('duration')}
                onBlur={handleBlur('duration')}
                value={values.duration}
                disabled={isUploading}
              />
            </div>

            <div className="flex flex-col space-y-2">
              <label className="text-lg font-medium">Month</label>
              <input
                type="number"
                className="border border-gray-300 rounded-lg p-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Enter Month"
                onChange={handleChange('month')}
                onBlur={handleBlur('month')}
                value={values.month}
                disabled={isUploading}
              />
            </div>

            <div className="flex flex-col space-y-2">
              <label className="text-lg font-medium">Remedies</label>
              <input
                type="text"
                className="border border-gray-300 rounded-lg p-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Enter Remedies"
                onChange={handleChange('remedies')}
                onBlur={handleBlur('remedies')}
                value={values.remedies}
                disabled={isUploading}
              />
            </div>

            <div className="flex flex-col space-y-2">
              <label className="text-lg font-medium">Severity</label>
              <select
                className="border border-gray-300 rounded-lg p-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                onChange={(e) => setFieldValue('severity', e.target.value)}
                value={values.severity}
                disabled={isUploading}
              >
                <option value="">Select Severity</option>
                <option value="Mild">Mild</option>
                <option value="Moderate">Moderate</option>
                <option value="Severe">Severe</option>
              </select>
            </div>

            <div className="flex flex-col space-y-2">
              <label className="text-lg font-medium">Advice</label>
              <textarea
                className="border border-gray-300 rounded-lg p-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Enter Advice"
                onChange={handleChange('advice')}
                onBlur={handleBlur('advice')}
                value={values.advice}
                rows="3"
                disabled={isUploading}
              />
            </div>

            <button
              type="submit"
              className="bg-blue-500 text-white font-semibold py-3 rounded-lg hover:bg-blue-600 transition duration-200 w-full"
              disabled={isUploading}
            >
              {isUploading ? "Uploading..." : "Submit"}
            </button>

            <button
              type="button"
              className="mt-4 bg-gray-500 text-white font-semibold py-3 rounded-lg hover:bg-gray-600 transition duration-200 w-full"
              onClick={handleGoBack}
              disabled={isUploading}
            >
              Back to Profile
            </button>
          </form>
        )}
      </Formik>
    </div>
  );
}
