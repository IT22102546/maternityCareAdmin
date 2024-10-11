import React, { useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { addDoc, collection, getFirestore } from "firebase/firestore";
import { getDownloadURL, getStorage, ref, uploadBytesResumable } from "firebase/storage";
import { Formik } from 'formik';
import { useNavigate } from 'react-router-dom';
import { app } from '../firebase';  // Ensure you have firebase config set up
import ReactQuill from 'react-quill';  // For description input
import 'react-quill/dist/quill.snow.css'; // Quill styles

export default function AddExercise() {
  const [image, setImage] = useState(null);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [isUploading, setIsUploading] = useState(false);
  const db = getFirestore(app); // Firestore instance
  const storage = getStorage(); // Firebase storage instance
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

      let downloadUrl = "";
      if (image) {
        const storageRef = ref(storage, 'exercises/' + Date.now() + ".jpg");
        const uploadTask = uploadBytesResumable(storageRef, image);

        await new Promise((resolve, reject) => {
          uploadTask.on(
            'state_changed',
            (snapshot) => {
              const progress = (snapshot.bytesTransferred / snapshot.totalBytes) * 100;
              setUploadProgress(progress);
            },
            (error) => {
              console.error("Upload Error: ", error);
              alert("Failed to upload image");
              reject(error);
              setIsUploading(false);
            },
            async () => {
              downloadUrl = await getDownloadURL(uploadTask.snapshot.ref);
              resolve();
            }
          );
        });
      }

      const exerciseData = {
        ...values,
        imageUrl: downloadUrl,
        createdBy: currentUser?.username || 'Anonymous',
        createdAt: new Date().toISOString(),
      };

      await addDoc(collection(db, "exercises"), exerciseData);
      alert("Exercise added successfully!");
      resetForm();
      setImage(null);
      setUploadProgress(0);
      setIsUploading(false);
    } catch (error) {
      console.error("Error adding exercise: ", error);
      alert("Failed to add exercise");
      setIsUploading(false);
    }
  };

  const handleGoBack = () => {
    navigate("/dashboard?tab=profile");
  };

  return (
    <div className="max-w-4xl mx-auto bg-white shadow-md rounded-lg p-8 mt-8">
      <h1 className="text-3xl font-bold text-center mb-6">Add New Exercise</h1>

      <Formik
        initialValues={{
          exerciseName: '',
          description: '',
          pregnancyStage: '',
          intensity: '',
          ageRange: '',
          duration: '',
          videoUrl: '',
        }}
        onSubmit={(values, actions) => onSubmitMethod(values, actions)}
        validate={(values) => {
          const errors = {};
          if (!values.exerciseName) {
            errors.exerciseName = "Please enter the exercise name";
          }
          if (!values.pregnancyStage) {
            errors.pregnancyStage = "Please select the pregnancy stage";
          }
          if (!values.intensity) {
            errors.intensity = "Please select exercise intensity";
          }
          return errors;
        }}
      >
        {({ handleChange, handleBlur, handleSubmit, setFieldValue, values, errors, touched }) => (
          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Exercise Name */}
            <div className="flex flex-col space-y-2">
              <label className="text-lg font-medium">Exercise Name</label>
              <input
                type="text"
                className="border border-gray-300 rounded-lg p-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Enter Exercise Name"
                onChange={handleChange('exerciseName')}
                onBlur={handleBlur('exerciseName')}
                value={values.exerciseName}
                disabled={isUploading}
              />
              {errors.exerciseName && touched.exerciseName && (
                <div className="text-red-500 text-sm">{errors.exerciseName}</div>
              )}
            </div>

            {/* Description */}
            <div className="flex flex-col space-y-2">
              <label className="text-lg font-medium">Description</label>
              <ReactQuill
                theme="snow"
                value={values.description}
                onChange={(content) => setFieldValue('description', content)}
                className="pb-4"
                style={{ height: '250px' }} 
                readOnly={isUploading}
              />
            </div>

            {/* Pregnancy Stage */}
            <div className="flex flex-col space-y-2">
              <label className="text-lg font-medium">Pregnancy Stage</label>
              <select
                className="border border-gray-300 rounded-lg p-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                onChange={(e) => setFieldValue('pregnancyStage', e.target.value)}
                value={values.pregnancyStage}
                disabled={isUploading}
              >
                <option value="">Select Pregnancy Stage</option>
                <option value="firstTrimester">First Trimester</option>
                <option value="secondTrimester">Second Trimester</option>
                <option value="thirdTrimester">Third Trimester</option>
              </select>
              {errors.pregnancyStage && touched.pregnancyStage && (
                <div className="text-red-500 text-sm">{errors.pregnancyStage}</div>
              )}
            </div>

            {/* Intensity */}
            <div className="flex flex-col space-y-2">
              <label className="text-lg font-medium">Intensity</label>
              <select
                className="border border-gray-300 rounded-lg p-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                onChange={(e) => setFieldValue('intensity', e.target.value)}
                value={values.intensity}
                disabled={isUploading}
              >
                <option value="">Select Intensity</option>
                <option value="Low">Low</option>
                <option value="Medium">Medium</option>
                <option value="High">High</option>
              </select>
              {errors.intensity && touched.intensity && (
                <div className="text-red-500 text-sm">{errors.intensity}</div>
              )}
            </div>

            {/* Age Range */}
            <div className="flex flex-col space-y-2">
              <label className="text-lg font-medium">Age Range</label>
              <select
                className="border border-gray-300 rounded-lg p-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                onChange={(e) => setFieldValue('ageRange', e.target.value)}
                value={values.ageRange}
                disabled={isUploading}
              >
                <option value="">Select Age Range</option>
                <option value="20-30">20-30</option>
                <option value="30-40">30-40</option>
                <option value="40+">40+</option>
              </select>
            </div>

            {/* Duration */}
            <div className="flex flex-col space-y-2">
              <label className="text-lg font-medium">Duration (in minutes)</label>
              <input
                type="number"
                className="border border-gray-300 rounded-lg p-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Enter Duration"
                onChange={handleChange('duration')}
                onBlur={handleBlur('duration')}
                value={values.duration}
                disabled={isUploading}
              />
            </div>

            {/* Video URL */}
            <div className="flex flex-col space-y-2">
              <label className="text-lg font-medium">Video URL</label>
              <input
                type="text"
                className="border border-gray-300 rounded-lg p-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Enter Video URL"
                onChange={handleChange('videoUrl')}
                onBlur={handleBlur('videoUrl')}
                value={values.videoUrl}
                disabled={isUploading}
              />
            </div>

            {/* Image Upload */}
            <div className="flex flex-col space-y-2">
              <label className="text-lg font-medium">Upload Image</label>
              <input
                type="file"
                className="border border-gray-300 rounded-lg p-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                onChange={handleImageUpload}
                disabled={isUploading}
              />
              {isUploading && (
                <p className="text-sm text-blue-500">Uploading: {Math.round(uploadProgress)}%</p>
              )}
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              className="bg-blue-500 text-white font-semibold py-3 rounded-lg hover:bg-blue-600 transition duration-200 w-full"
              disabled={isUploading}
            >
              {isUploading ? "Uploading..." : "Submit"}
            </button>

            {/* Back Button */}
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
