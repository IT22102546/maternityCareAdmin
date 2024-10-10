import React from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import SignUp from './Pages/SignUp'
import PrivateRoute from './Components/PrivateRoute';
import DashBoard from './Pages/DashBoard';
import AddCategory from './Pages/AddSymptoms';
import AddArticles from './Pages/AddArticles';
import EditArticles from './Pages/EditArticles';
import AddSymptoms from './Pages/AddSymptoms';


export default function App() {
  return (
    <BrowserRouter>
   
      <Routes>
        <Route path="/sign-up" element={<SignUp/>}/>
       

        <Route element={<PrivateRoute/>}/>
          <Route path="/dashboard" element={<DashBoard/>}/> 
          <Route path="/addsymptoms" element={<AddSymptoms/>}/> 
          <Route path="/addarticles" element={<AddArticles/>}/>
          <Route path="/edit-article/:articleId" element={<EditArticles />} />
          

        <Route/>

       
       
      </Routes>

    </BrowserRouter>
  )
}
