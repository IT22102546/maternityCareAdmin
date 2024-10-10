import React, { useState, useEffect, useRef } from 'react';
import { useSelector } from 'react-redux';
import { getDocs, collection, getFirestore, doc, deleteDoc } from 'firebase/firestore';
import { useNavigate } from 'react-router-dom';
import { app } from '../firebase';
import html2pdf from 'html2pdf.js'; 

export default function DashArticles() {
  const [userProducts, setUserProducts] = useState([]);
  const [filteredProducts, setFilteredProducts] = useState([]);
  const [categories] = useState(['Nutrition', 'Symptoms', 'Exercise']); // Hardcoded categories
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('All');
  const currentUser = useSelector((state) => state.user.currentUser);
  const db = getFirestore(app);
  const navigate = useNavigate();
  const reportRef = useRef();

  useEffect(() => {
    if (currentUser) {
      fetchUserProducts();
    }
   
  }, [currentUser]);

  useEffect(() => {
    applyFilters();
  }, [searchTerm, selectedCategory, userProducts]);

  const fetchUserProducts = async () => {
    setLoading(true);
    try {
      const querySnapshot = await getDocs(collection(db, 'articles')); 
      const products = [];
      querySnapshot.forEach((doc) => {
        products.push({ ...doc.data(), id: doc.id });
      });
      setUserProducts(products);
      setLoading(false);
    } catch (error) {
      console.error("Error fetching articles: ", error);
      setLoading(false);
    }
  };

  const applyFilters = () => {
    let filtered = userProducts;

    // Filter by selected category if not "All"
    if (selectedCategory && selectedCategory !== 'All') {
      filtered = filtered.filter(product => product.category === selectedCategory);
    }

    // Filter by search term
    if (searchTerm) {
      filtered = filtered.filter(product =>
        product.title.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    setFilteredProducts(filtered);
  };

  const handleDeleteProduct = async (productId) => {
    const confirmed = window.confirm('Are you sure you want to delete this article?');
    if (!confirmed) return;

    try {
      await deleteDoc(doc(db, 'articles', productId)); 
      setUserProducts(userProducts.filter(product => product.id !== productId));
      alert('Article deleted successfully!');
    } catch (error) {
      console.error('Error deleting article: ', error);
    }
  };

  const handleEditProduct = (productId) => {
    navigate(`/edit-article/${productId}`);
  };

  const generateReport = () => {
    const element = reportRef.current;
    const options = {
      margin: 1,
      filename: 'articles-report.pdf',
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
    <div className="max-w-4xl mx-auto bg-white shadow-md rounded-lg p-8 mt-8">
      <h1 className="text-3xl font-bold text-center mb-6 text-blue-600">My Articles</h1>

      <div className="mb-6 p-4 bg-blue-100 rounded-lg shadow-md">
        <h2 className="text-xl font-semibold text-center text-blue-700">
          Total Articles: {userProducts.length}
        </h2>
      </div>

      <div className="mb-6 flex justify-between items-center">
        <div className="flex-1 mr-4">
          <label className="block mb-2 font-medium text-blue-700">Filter by Category:</label>
          <select
            className="border border-blue-300 p-2 rounded-lg w-full text-blue-700"
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
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
          <label className="block mb-2 font-medium text-blue-700">Search by Name:</label>
          <input
            type="text"
            className="border border-blue-300 p-2 rounded-lg w-full text-blue-700"
            placeholder="Search by article name"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
      </div>


      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
        {filteredProducts.length > 0 ? (
          filteredProducts.map((product) => (
            <div key={product.id} className="border p-4 rounded-lg shadow-md">
              <img src={product.image} alt={product.title} className="w-full h-48 object-cover rounded-lg mb-4" />
              <h2 className="text-xl font-semibold mb-2 text-blue-700">{product.title}</h2>
              <div className="flex justify-between mt-4">
                <button className="text-blue-500" onClick={() => handleEditProduct(product.id)}>Edit</button>
                <button className="text-red-500" onClick={() => handleDeleteProduct(product.id)}>Delete</button>
              </div>
            </div>
          ))
        ) : (
          <p>No articles found.</p>
        )}
      </div>
    </div>
  );
}
