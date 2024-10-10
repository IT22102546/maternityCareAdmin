import React, { useState, useEffect, useRef } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { addDoc, collection, getDocs, getFirestore } from "firebase/firestore";
import { getDownloadURL, getStorage, ref, uploadBytesResumable } from "firebase/storage";
import { Formik } from 'formik';
import { useNavigate } from 'react-router-dom';
import { app } from '../firebase';
import QRCode from 'react-qr-code';
import html2canvas from 'html2canvas'; 
import ReactQuill from 'react-quill';  // Import React Quill
import 'react-quill/dist/quill.snow.css'; // Import Quill styles

export default function AddArticles() {
  const [image, setImage] = useState(null);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [isUploading, setIsUploading] = useState(false);
  const [categoryList, setCategoryList] = useState([]);
  const [qrCodeUrl, setQrCodeUrl] = useState("");
  const db = getFirestore(app);
  const storage = getStorage();
  const navigate = useNavigate();
  const qrRef = useRef();

  const currentUser = useSelector((state) => state.user.currentUser);

  useEffect(() => {
    getCategoryList();
  }, []);

  const getCategoryList = async () => {
    setCategoryList([]);
    const querySnapshot = await getDocs(collection(db, "Category"));
    const categories = [];
    querySnapshot.forEach((doc) => {
      categories.push(doc.data());
    });
    setCategoryList(categories);
  };

  const handleImageUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      setImage(file);
    }
  };

  const onSubmitMethod = async (values, { resetForm }) => {
    try {
      setIsUploading(true);

      const storageRef = ref(storage, 'articles/' + Date.now() + ".jpg");
      const uploadTask = uploadBytesResumable(storageRef, image);

      uploadTask.on('state_changed',
        (snapshot) => {
          const progress = (snapshot.bytesTransferred / snapshot.totalBytes) * 100;
          setUploadProgress(progress);
        },
        (error) => {
          console.error("Upload Error: ", error);
          alert("Failed to upload image");
          setIsUploading(false);
        },
        async () => {
          const downloadUrl = await getDownloadURL(uploadTask.snapshot.ref);
          values.image = downloadUrl;

          values.userName = currentUser?.username || 'Anonymous';
          values.userEmail = currentUser?.email || '';

          const docRef = await addDoc(collection(db, "articles"), values);
          if (docRef.id) {
            alert("Post added successfully!");

            resetForm();
            setImage(null);
          }

          setIsUploading(false);
          setUploadProgress(0);
        }
      );
    } catch (error) {
      console.error("Error adding document: ", error);
      alert("Failed to add post");
      setIsUploading(false);
    }
  };

  const handleGoBack = () => {
    navigate("/dashboard?tab=profile");
  };

  const handleDownloadQR = async () => {
    if (qrRef.current) {
      const canvas = await html2canvas(qrRef.current);
      const link = document.createElement('a');
      link.download = 'product-qr-code.png';
      link.href = canvas.toDataURL();
      link.click();
    }
  };

  return (
    <div className="max-w-4xl mx-auto bg-white shadow-md rounded-lg p-8 mt-8">
      <h1 className="text-3xl font-bold text-center mb-6">Add New Article</h1>

      <Formik
        initialValues={{
          title: '',
          desc: '',
          category: '',
          image: '',
          userName: '',
          userEmail: '',
          createdAt: Date.now().toString()
        }}
        onSubmit={(values, actions) => onSubmitMethod(values, actions)}
        validate={(values) => {
          const errors = {};
          if (!values.title) {
            errors.title = "Please Enter Title";
            alert("Please Enter Title");
          }
          return errors;
        }}
      >
        {({ handleChange, handleBlur, handleSubmit, setFieldValue, values, errors }) => (
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="flex flex-col space-y-2">
              <label className="text-lg font-medium">Title</label>
              <input
                type="text"
                className="border border-gray-300 rounded-lg p-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Enter Product Title"
                onChange={handleChange('title')}
                onBlur={handleBlur('title')}
                value={values.title}
                disabled={isUploading}
              />
            </div>

            <div className="flex flex-col space-y-2">
              <label className="text-lg font-medium">Category</label>
              <select
                className="border border-gray-300 rounded-lg p-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                onChange={(e) => setFieldValue('category', e.target.value)}
                value={values.category}
                disabled={isUploading}
              >
                <option value="">Select Category</option>
                <option value="Nutrition">Nutrition</option>
                <option value="Exercises">Exercises</option>
                <option value="Symptoms">Symptoms</option>
              </select>
            </div>

            <div className="flex flex-col space-y-2">
                <label className="text-lg font-medium">Content</label>
                <ReactQuill
                  theme="snow"
                  value={values.desc}
                  onChange={(content) => setFieldValue('desc', content)}
                  className='pb-4'
                  style={{ height: '250px' }} 
                  readOnly={isUploading}
                />
              </div>

            <div className="flex flex-col space-y-2">
              <label className="text-lg font-medium">Image</label>
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
