import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { getFirestore, doc, getDoc, updateDoc } from 'firebase/firestore';
import { getStorage, ref, uploadBytes, getDownloadURL } from 'firebase/storage';
import { app } from '../firebase'; // Ensure firebase configuration is set up correctly
import ReactQuill from 'react-quill';
import 'react-quill/dist/quill.snow.css';

export default function EditExercise() {
  const { exerciseId } = useParams(); // Get exerciseId from URL params
  const [exerciseName, setExerciseName] = useState('');
  const [intensity, setIntensity] = useState('');
  const [ageRange, setAgeRange] = useState('');
  const [imageUrl, setImageUrl] = useState('');
  const [newImageFile, setNewImageFile] = useState(null);
  const [description, setDescription] = useState(''); // Exercise description
  const [duration, setDuration] = useState('');
  const [pregnancyStage, setPregnancyStage] = useState('');
  const [videoUrl, setVideoUrl] = useState('');
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();
  const db = getFirestore(app); // Firestore instance
  const storage = getStorage(app); // Firebase Storage reference

  console.log(exerciseId);
  
  useEffect(() => {
    if (exerciseId) {
      fetchExercise();
    } else {
      console.error('Invalid exerciseId');
    }
  }, [exerciseId]);

  const fetchExercise = async () => {
    try {
      const docRef = doc(db, 'exercises', exerciseId); // Reference to the exercise document
      const docSnap = await getDoc(docRef);

      if (docSnap.exists()) {
        const exerciseData = docSnap.data();
        setExerciseName(exerciseData.exerciseName || ''); // Set exercise name
        setIntensity(exerciseData.intensity || ''); // Set intensity
        setImageUrl(exerciseData.imageUrl || ''); // Set current image URL
        setDescription(exerciseData.description || ''); // Set description
        setDuration(exerciseData.duration || ''); // Set duration
        setPregnancyStage(exerciseData.pregnancyStage || ''); // Set pregnancy stage
        setVideoUrl(exerciseData.videoUrl || ''); // Set video URL
        setLoading(false);
      } else {
        console.log('No such document!');
      }
    } catch (error) {
      console.error('Error fetching exercise:', error);
    }
  };

  const handleImageUpload = async () => {
    if (!newImageFile) {
      return imageUrl; // Return the current image URL if no new image is selected
    }

    try {
      const imageRef = ref(storage, `exercises/${exerciseId}-${newImageFile.name}`);
      const snapshot = await uploadBytes(imageRef, newImageFile);
      const downloadURL = await getDownloadURL(snapshot.ref);
      return downloadURL;
    } catch (error) {
      console.error('Error uploading image:', error);
      return imageUrl; // Return the current image URL in case of error
    }
  };

  const handleSaveChanges = async () => {
    try {
      const updatedImageURL = await handleImageUpload(); // Upload image if new image is selected
      const exerciseRef = doc(db, 'exercises', exerciseId);
      await updateDoc(exerciseRef, {
        exerciseName,
        intensity,
        imageUrl: updatedImageURL, // Update image URL
        description, // Update exercise description
        duration, // Update duration
        pregnancyStage, // Update pregnancy stage
        videoUrl, // Update video URL
      });

      alert('Exercise updated successfully!');
      navigate('/dashboard?tab=exercises'); // Navigate back to dashboard
    } catch (error) {
      console.error('Error updating exercise:', error);
    }
  };

  if (loading) {
    return <div>Loading...</div>;
  }

  return (
    <div className="max-w-4xl mx-auto bg-white shadow-md rounded-lg p-8 mt-8">
      <h1 className="text-3xl font-bold text-center mb-6 text-blue-600">Edit Exercise</h1>

      {/* Exercise Name */}
      <div className="mb-6">
        <label className="block mb-2 font-medium text-blue-700">Exercise Name:</label>
        <input
          type="text"
          className="border border-blue-300 p-2 rounded-lg w-full text-blue-700"
          value={exerciseName}
          onChange={(e) => setExerciseName(e.target.value)}
        />
      </div>

      {/* Intensity */}
      <div className="mb-6">
        <label className="block mb-2 font-medium text-blue-700">Intensity:</label>
        <select
          className="border border-blue-300 p-2 rounded-lg w-full text-blue-700"
          value={intensity}
          onChange={(e) => setIntensity(e.target.value)}
        >
          <option value="">Select Intensity</option>
          <option value="Low">Low</option>
          <option value="Medium">Medium</option>
          <option value="High">High</option>
        </select>
      </div>

      {/* Duration */}
      <div className="mb-6">
        <label className="block mb-2 font-medium text-blue-700">Duration (in minutes):</label>
        <input
          type="number"
          className="border border-blue-300 p-2 rounded-lg w-full text-blue-700"
          value={duration}
          onChange={(e) => setDuration(e.target.value)}
        />
      </div>

      {/* Pregnancy Stage */}
      <div className="mb-6">
        <label className="block mb-2 font-medium text-blue-700">Pregnancy Stage:</label>
        <select
          className="border border-blue-300 p-2 rounded-lg w-full text-blue-700"
          value={pregnancyStage}
          onChange={(e) => setPregnancyStage(e.target.value)}
        >
          <option value="">Select Pregnancy Stage</option>
          <option value="firstTrimester">First Trimester</option>
          <option value="secondTrimester">Second Trimester</option>
          <option value="thirdTrimester">Third Trimester</option>
        </select>
      </div>

      {/* Video URL */}
      <div className="mb-6">
        <label className="block mb-2 font-medium text-blue-700">Video URL:</label>
        <input
          type="text"
          className="border border-blue-300 p-2 rounded-lg w-full text-blue-700"
          value={videoUrl}
          onChange={(e) => setVideoUrl(e.target.value)}
        />
      </div>

      {/* Current Image */}
      <div className="mb-6">
        <label className="block mb-2 font-medium text-blue-700">Current Image:</label>
        <img src={imageUrl} alt="Current Exercise" className="w-full h-48 object-cover rounded-lg mb-4" />
        <label className="block mb-2 font-medium text-blue-700">Upload New Image:</label>
        <input
          type="file"
          className="border border-blue-300 p-2 rounded-lg w-full text-blue-700"
          accept="image/*"
          onChange={(e) => setNewImageFile(e.target.files[0])}
        />
      </div>

      {/* Description */}
      <div className="mb-6">
        <label className="block mb-2 font-medium text-blue-700">Description:</label>
        <ReactQuill
          theme="snow"
          value={description}
          onChange={setDescription} // Handle content updates
          className="bg-white rounded-lg"
        />
      </div>

      {/* Save Changes */}
      <button
        className="bg-blue-500 text-white px-4 py-2 rounded-lg"
        onClick={handleSaveChanges}
      >
        Save Changes
      </button>
    </div>
  );
}
