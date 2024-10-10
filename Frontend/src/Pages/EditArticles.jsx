import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { getFirestore, doc, getDoc, updateDoc } from 'firebase/firestore';
import { getStorage, ref, uploadBytes, getDownloadURL } from 'firebase/storage';
import { app } from '../firebase';
import ReactQuill from 'react-quill';
import 'react-quill/dist/quill.snow.css'; // Import Quill styles

export default function EditArticles() {
  const { articleId } = useParams(); // Retrieve articleId from the URL
  const [article, setArticle] = useState(null);
  const [title, setTitle] = useState('');
  const [category, setCategory] = useState('');
  const [image, setImage] = useState('');
  const [newImageFile, setNewImageFile] = useState(null);
  const [desc, setContent] = useState(''); // Add state for content
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();
  const db = getFirestore(app);
  const storage = getStorage(app); // Firebase Storage reference

  useEffect(() => {
    fetchArticle();
  }, []);

  const fetchArticle = async () => {
    try {
      const docRef = doc(db, 'articles', articleId);
      const docSnap = await getDoc(docRef);

      if (docSnap.exists()) {
        const articleData = docSnap.data();
        setArticle(articleData);
        setTitle(articleData.title);
        setCategory(articleData.category);
        setImage(articleData.image); 
        setContent(articleData.desc); 
        setLoading(false);
      } else {
        console.log('No such document!');
      }
    } catch (error) {
      console.error('Error fetching article: ', error);
    }
  };

  const handleImageUpload = async () => {
    if (!newImageFile) {
      return image; // Return the current image URL if no new image is selected
    }

    try {
      const imageRef = ref(storage, `articles/${articleId}-${newImageFile.name}`);
      const snapshot = await uploadBytes(imageRef, newImageFile);
      const downloadURL = await getDownloadURL(snapshot.ref);
      return downloadURL;
    } catch (error) {
      console.error('Error uploading image: ', error);
      return image; 
    }
  };

  const handleSaveChanges = async () => {
    try {
      const updatedImageURL = await handleImageUpload(); 
      const articleRef = doc(db, 'articles', articleId);
      await updateDoc(articleRef, {
        title,
        category,
        image: updatedImageURL, 
        desc, 
      });

      alert('Article updated successfully!');
      navigate('/dashboard?tab=articles'); 
    } catch (error) {
      console.error('Error updating article: ', error);
    }
  };

  if (loading) {
    return <div>Loading...</div>;
  }

  return (
    <div className="max-w-4xl mx-auto bg-white shadow-md rounded-lg p-8 mt-8">
      <h1 className="text-3xl font-bold text-center mb-6 text-blue-600">Edit Article</h1>

      <div className="mb-6">
        <label className="block mb-2 font-medium text-blue-700">Title:</label>
        <input
          type="text"
          className="border border-blue-300 p-2 rounded-lg w-full text-blue-700"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
        />
      </div>

      <div className="mb-6">
        <label className="block mb-2 font-medium text-blue-700">Category:</label>
        <input
          type="text"
          className="border border-blue-300 p-2 rounded-lg w-full text-blue-700"
          value={category}
          onChange={(e) => setCategory(e.target.value)}
        />
      </div>

      <div className="mb-6">
        <label className="block mb-2 font-medium text-blue-700">Current Image:</label>
        <img src={image} alt="Current Article" className="w-full h-48 object-cover rounded-lg mb-4" />
        <label className="block mb-2 font-medium text-blue-700">Upload New Image:</label>
        <input
          type="file"
          className="border border-blue-300 p-2 rounded-lg w-full text-blue-700"
          accept="image/*"
          onChange={(e) => setNewImageFile(e.target.files[0])}
        />
      </div>

      <div className="mb-6">
        <label className="block mb-2 font-medium text-blue-700">Content:</label>
        <ReactQuill
          theme="snow"
          value={desc}
          onChange={setContent} // Handle content updates
          className="bg-white rounded-lg"
        />
      </div>

      <button
        className="bg-blue-500 text-white px-4 py-2 rounded-lg"
        onClick={handleSaveChanges}
      >
        Save Changes
      </button>
    </div>
  );
}
