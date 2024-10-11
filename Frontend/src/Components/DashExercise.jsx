import React, { useState, useEffect, useRef } from 'react';
import { useSelector } from 'react-redux';
import { getDocs, collection, getFirestore, doc, deleteDoc } from 'firebase/firestore';
import { useNavigate } from 'react-router-dom';
import { app } from '../firebase';
import html2pdf from 'html2pdf.js'; 

export default function DashExercise() {
  const [exercises, setExercises] = useState([]);
  const [filteredExercises, setFilteredExercises] = useState([]);
  const [categories] = useState(['Low', 'Medium', 'High']); // Hardcoded intensity levels
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedIntensity, setSelectedIntensity] = useState('All');
  const currentUser = useSelector((state) => state.user.currentUser);
  const db = getFirestore(app);
  const navigate = useNavigate();
  const reportRef = useRef();

  useEffect(() => {
    if (currentUser) {
      fetchExercises();
    }
  }, [currentUser]);

  useEffect(() => {
    applyFilters();
  }, [searchTerm, selectedIntensity, exercises]);

  const fetchExercises = async () => {
    setLoading(true);
    try {
      const querySnapshot = await getDocs(collection(db, 'exercises')); 
      const exercisesList = [];
      querySnapshot.forEach((doc) => {
        exercisesList.push({ ...doc.data(), id: doc.id });
      });
      setExercises(exercisesList);
      setLoading(false);
    } catch (error) {
      console.error("Error fetching exercises: ", error);
      setLoading(false);
    }
  };

  const applyFilters = () => {
    let filtered = exercises;

    // Filter by selected intensity if not "All"
    if (selectedIntensity && selectedIntensity !== 'All') {
      filtered = filtered.filter(exercise => exercise.intensity === selectedIntensity);
    }

    // Filter by search term
    if (searchTerm) {
      filtered = filtered.filter(exercise =>
        exercise.exerciseName.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    setFilteredExercises(filtered);
  };

  const handleDeleteExercise = async (exerciseId) => {
    const confirmed = window.confirm('Are you sure you want to delete this exercise?');
    if (!confirmed) return;

    try {
      await deleteDoc(doc(db, 'exercises', exerciseId)); 
      setExercises(exercises.filter(exercise => exercise.id !== exerciseId));
      alert('Exercise deleted successfully!');
    } catch (error) {
      console.error('Error deleting exercise: ', error);
    }
  };

  const handleEditExercise = (exerciseId) => {
    navigate(`/edit-exercise/${exerciseId}`);
  };

  const generateReport = () => {
    const element = reportRef.current;
    const options = {
      margin: 1,
      filename: 'exercises-report.pdf',
      image: { type: 'jpeg', quality: 0.98 },
      html2canvas: { scale: 2 },
      jsPDF: { unit: 'in', format: 'letter', orientation: 'portrait' },
    };

    html2pdf()
      .from(element)
      .set(options)
      .save();
  };

  if (loading) {
    return <div>Loading...</div>;
  }

  return (
    <div className="max-w-4xl mx-auto bg-white shadow-md rounded-lg p-8 mt-8" ref={reportRef}>
      <h1 className="text-3xl font-bold text-center mb-6 text-blue-600">My Exercises</h1>

      <div className="mb-6 p-4 bg-blue-100 rounded-lg shadow-md">
        <h2 className="text-xl font-semibold text-center text-blue-700">
          Total Exercises: {exercises.length}
        </h2>
      </div>

      <div className="mb-6 flex justify-between items-center">
        <div className="flex-1 mr-4">
          <label className="block mb-2 font-medium text-blue-700">Filter by Intensity:</label>
          <select
            className="border border-blue-300 p-2 rounded-lg w-full text-blue-700"
            value={selectedIntensity}
            onChange={(e) => setSelectedIntensity(e.target.value)}
          >
            <option value="All">All</option>
            {categories.map((category, index) => (
              <option key={index} value={category}>
                {category}
              </option>
            ))}
          </select>
        </div>

        <div className="flex-1">
          <label className="block mb-2 font-medium text-blue-700">Search by Exercise Name:</label>
          <input
            type="text"
            className="border border-blue-300 p-2 rounded-lg w-full text-blue-700"
            placeholder="Search by exercise name"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
        {filteredExercises.length > 0 ? (
          filteredExercises.map((exercise) => (
            <div key={exercise.id} className="border p-4 rounded-lg shadow-md">
              <img src={exercise.imageUrl} alt={exercise.exerciseName} className="w-full h-48 object-cover rounded-lg mb-4" />
              <h2 className="text-xl font-semibold mb-2 text-blue-700">{exercise.exerciseName}</h2>
              <p className="text-gray-600">{exercise.intensity} Intensity</p>
              <p className="text-gray-600">Duration: {exercise.duration} minutes</p>
              <div className="flex justify-between mt-4">
                <button className="text-blue-500" onClick={() => handleEditExercise(exercise.id)}>Edit</button>
                <button className="text-red-500" onClick={() => handleDeleteExercise(exercise.id)}>Delete</button>
              </div>
            </div>
          ))
        ) : (
          <p>No exercises found.</p>
        )}
      </div>
    </div>
  );
}
