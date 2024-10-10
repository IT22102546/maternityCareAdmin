import { useEffect, useState } from "react";
import { Alert, Button, Modal, TextInput } from "flowbite-react";
import { useDispatch, useSelector } from "react-redux";
import { deleteUserFailure, deleteUserStart, deleteUserSuccess, signOut, updateUserFailure, updateUserStart, updateUserSuccess } from "../redux/user/userSlice";
import { HiOutlineExclamationCircle } from "react-icons/hi";
import { Link, useNavigate } from "react-router-dom";

export default function DashProfile() {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const { currentUser, loading } = useSelector((state) => state.user);
  const [formData, setFormData] = useState({});
  const [updateSuccess, setUpdateSuccess] = useState(null);
  const [updateUserError, setUpdateUserError] = useState(null);
  const [showModel, setShowModel] = useState(false);

 
  useEffect(() => {
    const fetchUserData = async () => {
      try {
        const res = await fetch(`/api/shop/current`);
        const data = await res.json();
        if (data.success) {
          dispatch(updateUserSuccess(data.user)); 
          setFormData(data.user); 
        }
      } catch (error) {
        console.error('Failed to fetch user data:', error);
      }
    };

    if (!currentUser) {
      fetchUserData();
    } else {
      setFormData(currentUser); 
    }
  }, [currentUser, dispatch]);

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.id]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      dispatch(updateUserStart());
      const res = await fetch(`/api/shop/update/${currentUser.brnumber}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(formData),
      });
      const data = await res.json();
      if (data.success === false) {
        dispatch(updateUserFailure(data.message));
        setUpdateUserError(data.message);
        setUpdateSuccess(null);
        return;
      }
      dispatch(updateUserSuccess(data.user)); 
      setUpdateSuccess("User profile updated successfully");
      setUpdateUserError(null);
    } catch (error) {
      dispatch(updateUserFailure(error));
      setUpdateUserError(error.message);
      setUpdateSuccess(null);
    }
  };

  const handleDeleteUser = async () => {
    try {
      dispatch(deleteUserStart());
      const res = await fetch(`/api/shop/delete/${currentUser.brnumber}`, {
        method: "DELETE",
      });
      const data = await res.json();
      if (data.success === false) {
        dispatch(deleteUserFailure());
        return;
      }
      dispatch(deleteUserSuccess());
      navigate("/");
    } catch (error) {
      dispatch(deleteUserFailure(error));
    }
  };

  const handleSignOut = async () => {
    try {
      await fetch("/api/shop/signout");
      dispatch(signOut());
      navigate("/");
    } catch (error) {
      console.log(error);
    }
  };

  return (
    <div
      className="relative flex justify-center items-center min-h-screen w-full bg-cover bg-center"
      
    >
      {/* Overlay for better text readability */}
      <div className="absolute inset-0 bg-black opacity-50"></div>

      {/* Profile content */}
      <div className="relative z-10 bg-white bg-opacity-90 p-8 rounded-lg shadow-xl w-full max-w-lg mx-auto">
        <h1 className="my-7 text-center font-semibold text-3xl text-gray-800">
          Profile
        </h1>
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <TextInput
            type="text"
            id="username"
            placeholder="User Name"
            value={formData.username || currentUser.username || ""}
            onChange={handleChange}
            className="rounded-lg"
          />
          <TextInput
            type="email"
            id="email"
            placeholder="Email"
            value={formData.email || currentUser.email || ""}
            onChange={handleChange}
            className="rounded-lg"
          />
          
         <Link to="/addarticles">
          <Button type="button" gradientDuoTone="purpleToBlue" className="w-full bg-slate-400 text-black" outline>
              Add New Article
          </Button>
        </Link> 
        <Link to="/addsymptom">
          <Button
            type="button"
            gradientDuoTone="purpleToBlue"
            className="w-full bg-slate-400 text-black rounded-lg"
            outline
          >
                Add Symptoms
            </Button>
          </Link> 
      </form>
        <div className="text-red-500 flex justify-between mt-5">
          <span onClick={() => setShowModel(true)} className="cursor-pointer">
            Delete Account
          </span>
          <span onClick={handleSignOut} className="cursor-pointer">
            Sign Out
          </span>
        </div>
        {updateSuccess && <Alert color="success" className="mt-5">{updateSuccess}</Alert>}
        {updateUserError && <Alert color="failure" className="mt-5">{updateUserError}</Alert>}
      </div>

      {/* Modal */}
      <Modal show={showModel} onClose={() => setShowModel(false)} popup size="md">
        <Modal.Header />
        <Modal.Body>
          <div className="text-center">
            <HiOutlineExclamationCircle className="h-14 w-14 text-gray-400 dark:text-gray-200 mb-4 mx-auto" />
            <h3 className="mb-5 text-lg text-gray-500 dark:text-gray-200">
              Are you sure you want to Delete your Account?
            </h3>
          </div>
          <div className="flex justify-center gap-4">
            <Button color="failure" onClick={handleDeleteUser} className="bg-red-600">
              Yes, I am sure
            </Button>
            <Button color="gray" onClick={() => setShowModel(false)} className="bg-green-600">
              No, cancel
            </Button>
          </div>
        </Modal.Body>
      </Modal>
    </div>
  );
}
