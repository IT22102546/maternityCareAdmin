import React, { useState, useEffect } from 'react';
import { useSelector } from 'react-redux';
import { getDocs, collection, getFirestore, doc, deleteDoc } from 'firebase/firestore';
import { useNavigate } from 'react-router-dom';
import { app } from '../firebase';

export default function DashSymptoms() {
  const [symptomsData, setSymptomsData] = useState([]);
  const [filteredSymptoms, setFilteredSymptoms] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedMonth, setSelectedMonth] = useState('All');
  const currentUser = useSelector((state) => state.user.currentUser);
  const db = getFirestore(app);
  const navigate = useNavigate();

  useEffect(() => {
    if (currentUser) {
      fetchSymptomsData();
    }
  }, [currentUser]);

  useEffect(() => {
    applyFilters();
  }, [searchTerm, selectedMonth, symptomsData]);

  const fetchSymptomsData = async () => {
    setLoading(true);
    try {
      const querySnapshot = await getDocs(collection(db, 'symptoms'));
      const symptoms = [];
      querySnapshot.forEach((doc) => {
        symptoms.push({ ...doc.data(), id: doc.id });
      });
      setSymptomsData(symptoms);
      setLoading(false);
    } catch (error) {
      console.error("Error fetching symptoms: ", error);
      setLoading(false);
    }
  };

  const applyFilters = () => {
    let filtered = symptomsData;

    if (selectedMonth !== 'All') {
      filtered = filtered.filter(symptom => symptom.month === parseInt(selectedMonth));
    }

    if (searchTerm) {
      filtered = filtered.filter(symptom =>
        symptom.name.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    setFilteredSymptoms(filtered);
  };

  const handleDeleteSymptom = async (symptomId) => {
    const confirmed = window.confirm('Are you sure you want to delete this symptom?');
    if (!confirmed) return;

    try {
      await deleteDoc(doc(db, 'symptoms', symptomId));
      setSymptomsData(symptomsData.filter(symptom => symptom.id !== symptomId));
      alert('Symptom deleted successfully!');
    } catch (error) {
      console.error('Error deleting symptom: ', error);
    }
  };

  const handleEditSymptom = (symptomId) => {
    navigate(`/edit-symptom/${symptomId}`);
  };

  if (loading) {
    return <div>Loading...</div>;
  }

  return (
    <div className="max-w-4xl mx-auto bg-white shadow-md rounded-lg p-8 mt-8">
      <h1 className="text-3xl font-bold text-center mb-6 text-blue-600">Symptoms</h1>

      <div className="mb-6 p-4 bg-blue-100 rounded-lg shadow-md">
        <h2 className="text-xl font-semibold text-center text-blue-700">
          Total Symptoms: {symptomsData.length}
        </h2>
      </div>

      <div className="mb-6 flex justify-between items-center">
        <div className="flex-1 mr-4">
          <label className="block mb-2 font-medium text-blue-700">Filter by Month:</label>
          <select
            className="border border-blue-300 p-2 rounded-lg w-full text-blue-700"
            value={selectedMonth}
            onChange={(e) => setSelectedMonth(e.target.value)}
          >
            <option value="All">All</option>
            {[...Array(12)].map((_, i) => (
              <option key={i + 1} value={i + 1}>
                {i + 1}
              </option>
            ))}
          </select>
        </div>

        <div className="flex-1">
          <label className="block mb-2 font-medium text-blue-700">Search by Name:</label>
          <input
            type="text"
            className="border border-blue-300 p-2 rounded-lg w-full text-blue-700"
            placeholder="Search by symptom name"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
      </div>

      <table className="min-w-full bg-white">
        <thead>
          <tr>
            <th className="text-left py-2 px-4 border-b">Title</th>
            <th className="text-left py-2 px-4 border-b">Month</th>
            <th className="text-left py-2 px-4 border-b">Description</th>
            <th className="text-left py-2 px-4 border-b">Actions</th>
          </tr>
        </thead>
        <tbody>
          {filteredSymptoms.length > 0 ? (
            filteredSymptoms.map((symptom) => (
              <tr key={symptom.id}>
                <td className="py-2 px-4 border-b">{symptom.name}</td>
                <td className="py-2 px-4 border-b">{symptom.month}</td>
                <td className="py-2 px-4 border-b">{symptom.details}</td>
                <td className="py-2 px-4 border-b">
                  <button className="text-blue-500 mr-4" onClick={() => handleEditSymptom(symptom.id)}>Edit</button>
                  <button className="text-red-500" onClick={() => handleDeleteSymptom(symptom.id)}>Delete</button>
                </td>
              </tr>
            ))
          ) : (
            <tr>
              <td colSpan="4" className="text-center py-4">No symptoms found.</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
