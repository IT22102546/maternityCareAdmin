import { Button, Sidebar } from "flowbite-react";
import { useEffect, useState } from "react";
import { HiDocument, HiGift } from 'react-icons/hi';
import { useDispatch, useSelector } from "react-redux";
import { Link, useLocation } from "react-router-dom";
import { signOut } from "../redux/user/userSlice";
import { useNavigate } from "react-router-dom";
import logo from '../Pages/Images/staffMemberDashSideBar.jpg'; // Ensure this path is correct

export default function StaffMemberDashSideBar() {
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

  return (
    <div 
      className="relative h-screen" 
      style={{ 
        backgroundImage: `url(${logo})`, 
        backgroundSize: 'cover', 
        backgroundPosition: 'center',
      }}
    >
      <div className="bg-black bg-opacity-50 h-full">
        <Sidebar 
          className="w-full md:w-64 h-full shadow-2xl rounded-r-xl"
        >
          <Sidebar.Items>
            <Sidebar.ItemGroup>
              <Link to='/dashboard?tab=products' key="products">
                <Sidebar.Item 
                  active={tab === 'products'}
                  icon={HiGift}
                  className={`p-5 hover:bg-gray-600 hover:shadow-md rounded-lg transition-all duration-300 ease-in-out transform hover:scale-105 flex items-center gap-4 ${
                    tab === 'products' ? 'bg-gray-600 scale-105' : ''
                  }`}
                  as='div'
                >
                  Products
                </Sidebar.Item>
              </Link>

              <Link to='/all-task-to-staff' key="staff">
                <Sidebar.Item
                  active={tab === 'staff'}
                  icon={HiDocument}
                  className={`p-5 hover:bg-gray-600 hover:shadow-md rounded-lg transition-all duration-300 ease-in-out transform hover:scale-105 flex items-center gap-4 ${
                    tab === 'staff' ? 'bg-gray-600 scale-105' : ''
                  }`}
                  as='div'
                >
                  View Tasks
                </Sidebar.Item>
              </Link>

              <Button 
                className="mt-8 w-full bg-red-500 hover:bg-red-600 text-white font-semibold rounded-lg shadow-lg transition-all duration-300 ease-in-out transform hover:scale-105"
                onClick={() => {
                  dispatch(signOut());
                  navigate('/');
                }}
              >
                Sign Out
              </Button>
            </Sidebar.ItemGroup>
          </Sidebar.Items>
        </Sidebar>
      </div>
    </div>
  );
}
