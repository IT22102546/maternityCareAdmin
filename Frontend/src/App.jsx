import React from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import SignUp from './Pages/SignUp'
import PrivateRoute from './Components/PrivateRoute';
import DashBoard from './Pages/DashBoard';
import AddCategory from './Pages/AddSymptoms';
import AddArticles from './Pages/AddArticles';
import EditArticles from './Pages/EditArticles';
import AddSymptoms from './Pages/AddSymptoms';
import EditSymptoms from './Pages/EditSymptoms';
import AddExercise from './Pages/AddExercise';
import EditExercise from './Pages/EditExercise';


export default function App() {
  return (
    <BrowserRouter>
   
      <Routes>
        <Route path="/sign-up" element={<SignUp/>}/>
       

        <Route element={<PrivateRoute/>}/>
          <Route path="/dashboard" element={<DashBoard/>}/> 
          <Route path="/addsymptom" element={<AddSymptoms/>}/> 
          <Route path="/addarticles" element={<AddArticles/>}/>
          <Route path="/edit-article/:articleId" element={<EditArticles />} />
          <Route path="/edit-symptom/:symptomId" element={<EditSymptoms />} />
          <Route path="/addexercise" element={<AddExercise/>}/>
          <Route path="/edit-exercise/:exerciseId" element={<EditExercise/>}/>

        <Route/>

       
       
      </Routes>

    </BrowserRouter>
  )
}
