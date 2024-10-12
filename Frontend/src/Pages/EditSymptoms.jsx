import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { doc, getDoc, updateDoc, getFirestore } from 'firebase/firestore';
import { Formik } from 'formik';
import { app } from '../firebase';

export default function EditSymptoms() {
  const { symptomId } = useParams(); // Extract symptom ID from route parameters
  const [symptomData, setSymptomData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const db = getFirestore(app);
  const navigate = useNavigate();

  // Fetch the symptom data based on the symptomId
  useEffect(() => {
    const fetchSymptom = async () => {
      try {
        const docRef = doc(db, 'symptoms', symptomId);
        const docSnap = await getDoc(docRef);

        if (docSnap.exists()) {
          setSymptomData(docSnap.data());
        } else {
          alert('Symptom not found');
          navigate('/dashboard?tab=symptoms');
        }
        setLoading(false);
      } catch (error) {
        console.error('Error fetching symptom:', error);
        setLoading(false);
      }
    };

    fetchSymptom();
  }, [db, symptomId, navigate]);

  const onSubmitMethod = async (values) => {
    setIsSubmitting(true);
    try {
      const docRef = doc(db, 'symptoms', symptomId);
      await updateDoc(docRef, {
        name: values.name,
        details: values.details,
        duration: values.duration,
        month: values.month,
        remedies: values.remedies,
        severity: values.severity,
        advice: values.advice,
        updatedAt: Date.now().toString(),
      });

      alert('Symptom updated successfully!');
      navigate('/dashboard?tab=symptoms');
    } catch (error) {
      console.error('Error updating symptom:', error);
      alert('Failed to update symptom');
    }
    setIsSubmitting(false);
  };

  const handleGoBack = () => {
    navigate('/dashboard?tab=symptoms');
  };

  if (loading) {
    return <div>Loading...</div>;
  }

  return (
    <div className="max-w-4xl mx-auto bg-white shadow-md rounded-lg p-8 mt-8">
      <h1 className="text-3xl font-bold text-center mb-6">Edit Symptom</h1>

      {symptomData && (
        <Formik
          initialValues={{
            name: symptomData.name || '',
            details: symptomData.details || '',
            duration: symptomData.duration || '',
            month: symptomData.month || '',
            remedies: symptomData.remedies || '',
            severity: symptomData.severity || '',
            advice: symptomData.advice || ''
          }}
          onSubmit={(values) => onSubmitMethod(values)}
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
                  disabled={isSubmitting}
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
                  disabled={isSubmitting}
                  rows="5"
                />
              </div>

              {/* Dropdown for Duration */}
              <div className="flex flex-col space-y-2">
                <label className="text-lg font-medium">Duration</label>
                <select
                  className="border border-gray-300 rounded-lg p-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  onChange={handleChange('duration')}
                  value={values.duration}
                  disabled={isSubmitting}
                >
                  <option value="">Select Duration</option>
                  <option value="First Trimester">First Trimester</option>
                  <option value="Second Trimester">Second Trimester</option>
                  <option value="Third Trimester">Third Trimester</option>
                </select>
              </div>

              {/* Dropdown for Month */}
              <div className="flex flex-col space-y-2">
                <label className="text-lg font-medium">Month</label>
                <select
                  className="border border-gray-300 rounded-lg p-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  onChange={(e) => setFieldValue('month', Number(e.target.value))} // Convert to number
                  value={values.month}
                  disabled={isSubmitting}
                >
                  <option value="">Select Month</option>
                  {[...Array(9)].map((_, i) => (
                    <option key={i + 1} value={i + 1}> {/* Keep it as number */}
                      {i + 1}
                    </option>
                  ))}
                </select>
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
                  disabled={isSubmitting}
                />
              </div>

              <div className="flex flex-col space-y-2">
                <label className="text-lg font-medium">Severity</label>
                <select
                  className="border border-gray-300 rounded-lg p-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  onChange={(e) => setFieldValue('severity', e.target.value)}
                  value={values.severity}
                  disabled={isSubmitting}
                >
                  <option value="">Select Severity</option>
                  <option value="Mild">Mild</option>
                  <option value="Moderate">Moderate</option>
                  <option value="Severe">Severe</option>
                </select>
              </div>

              <div className="flex flex-col space-y-2">
                <label className="text-lg font-medium">Advice</label>
                <input
                  type="text"
                  className="border border-gray-300 rounded-lg p-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="Enter Advice"
                  onChange={handleChange('advice')}
                  onBlur={handleBlur('advice')}
                  value={values.advice}
                  disabled={isSubmitting}
                />
              </div>

              <button
                type="submit"
                className="bg-blue-500 text-white font-semibold py-3 rounded-lg hover:bg-blue-600 transition duration-200 w-full"
                disabled={isSubmitting}
              >
                {isSubmitting ? 'Updating...' : 'Update Symptom'}
              </button>

              <button
                type="button"
                className="mt-4 bg-gray-500 text-white font-semibold py-3 rounded-lg hover:bg-gray-600 transition duration-200 w-full"
                onClick={handleGoBack}
                disabled={isSubmitting}
              >
                Back to Symptoms
              </button>
            </form>
          )}
        </Formik>
      )}
    </div>
  );
}
