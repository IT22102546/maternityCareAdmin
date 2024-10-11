import { Sidebar } from "flowbite-react";
import { useEffect, useState } from "react";
import { HiArchive, HiArrowSmRight, HiCheck, HiDocument, HiFolderAdd, HiGift, HiInformationCircle, HiOutlineDeviceTablet, HiOutlineInformationCircle, HiOutlineUserGroup, HiShieldCheck, HiUser, HiUserGroup} from 'react-icons/hi';
import { useDispatch, useSelector } from "react-redux";
import { Link, useLocation } from "react-router-dom";
import { signOut } from "../redux/user/userSlice";
import { useNavigate } from "react-router-dom";


export default function DashSideBar() {
  const dispatch = useDispatch();
  const navigate = useNavigate();

  const { currentUser } = useSelector(state => state.user);
  const location = useLocation();
  const [tab, setTab] = useState();

  useEffect(() => {
    const urlParams = new URLSearchParams(location.search);
    const tabFromUrl = urlParams.get('tab');
    if (tabFromUrl) {
      setTab(tabFromUrl);
    }
  }, [location.search]);

  const handleSignOut = async () => {
    try {
      await fetch('/api/user/signout');
      dispatch(signOut());
      navigate('/');
    } catch (error) {
      console.log(error);
    }
  };

  return (
    <Sidebar className="w-full md:w-56 bg-gray-900 text-white h-full shadow-lg rounded-lg transition-transform duration-300 ease-in-out p-1.5">
  <Sidebar.Items>
    <Sidebar.ItemGroup>

      <Link to='/dashboard?tab=profile' key="profile">
        <Sidebar.Item 
          active={tab === 'profile'} 
          icon={HiUser} 
          label={'Admin' } 
          labelColor='light'
          className={`hover:bg-gray-700 hover:text-white transition-all duration-200 ease-in-out 
                      ${tab === 'profile' ? 'bg-blue-500 text-white shadow-md scale-105' : ''} p-4 mb-4`}
          as='div'
        >
          Profile
        </Sidebar.Item>
      </Link>

      <Link to='/dashboard?tab=articles' key="articles">
        <Sidebar.Item
          active={tab === 'articles'}
          icon={HiInformationCircle}
          className={`hover:bg-gray-700 hover:text-white transition-all duration-200 ease-in-out 
                      ${tab === 'articles' ? 'bg-blue-500 text-white shadow-md scale-105' : ''} p-4 mb-4`}
          as='div'
        >
          Articles
        </Sidebar.Item>
      </Link>

      <Link to='/dashboard?tab=symptoms' key="symptoms">
        <Sidebar.Item
          active={tab === 'symptoms'}
          icon={HiOutlineInformationCircle}
          className={`hover:bg-gray-700 hover:text-white transition-all duration-200 ease-in-out 
                      ${tab === 'crowd' ? 'bg-blue-500 text-white shadow-md scale-105' : ''} p-4 mb-4`}
          as='div'
        >
          Symptoms
        </Sidebar.Item>
      </Link>

      <Link to='/dashboard?tab=exercise' key="exercise">
        <Sidebar.Item
          active={tab === 'exercise'}
          icon={HiCheck}
          className={`hover:bg-gray-700 hover:text-white transition-all duration-200 ease-in-out 
                      ${tab === 'crowd' ? 'bg-blue-500 text-white shadow-md scale-105' : ''} p-4 mb-4`}
          as='div'
        >
          Exercise
        </Sidebar.Item>
      </Link>

      

      <Sidebar.Item 
        icon={HiArrowSmRight} 
        className="cursor-pointer mt-8 p-4 hover:bg-red-600 hover:text-white transition-all duration-200 ease-in-out rounded-lg shadow-md"
        onClick={handleSignOut}
        key="signout"
      >
        Sign Out
      </Sidebar.Item>
    </Sidebar.ItemGroup>
  </Sidebar.Items>
</Sidebar>

  

  );
}
