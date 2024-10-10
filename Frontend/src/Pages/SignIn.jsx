import { Alert, Button, Label, Spinner, TextInput } from "flowbite-react";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { signInStart, signInSuccess, signInFailure } from '../redux/user/userSlice';
import { useDispatch, useSelector } from 'react-redux';

export default function SignIn() {
    const [formData, setFormData] = useState({ email: '', password: '' });
    const { loading, error } = useSelector((state) => state.user);
    const [showPassword, setShowPassword] = useState(false);
    const navigate = useNavigate();
    const dispatch = useDispatch();

    const handleChange = (e) => {
        setFormData({ ...formData, [e.target.id]: e.target.value.trim() });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!formData.email || !formData.password) {
            dispatch(signInFailure("Please fill all fields"));
            return;
        }
        try {
            dispatch(signInStart());
            const res = await fetch('/api/auth/signin', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    email: formData.email,
                    password: formData.password,
                }),
            });

            const data = await res.json();
            if (!data.success) {
                dispatch(signInFailure(data.message));
                return;
            }
            dispatch(signInSuccess(data.user)); 
            localStorage.setItem('token', data.token); 
            navigate('/dashboard?tab=profile'); 
        } catch (error) {
            dispatch(signInFailure(error.message));
        }
    };

    const togglePasswordVisibility = () => {
        setShowPassword(!showPassword);
    };

    return (
        <div className="min-h-screen flex items-center justify-center" style={{
            backgroundImage: `url('')`,
            backgroundSize: 'cover',
            backgroundPosition: 'center',
            backgroundRepeat: 'no-repeat',
        }}>
            <div className="w-full max-w-md bg-white p-6 rounded-lg shadow-lg">
                <p className="text-center text-2xl font-cinzel font-semibold">Sign In</p>
                <form onSubmit={handleSubmit} className="flex flex-col gap-4 mt-5">
                    <div>
                        <Label value="Email Address"/>
                        <TextInput
                            type="text"
                            placeholder="Email"
                            id="email"
                            value={formData.brnumber}
                            onChange={handleChange}
                        />
                    </div>
                    <div>
                        <Label value="Your password" />
                        <div className="relative">
                            <TextInput
                                type={showPassword ? "text" : "password"}
                                placeholder="Password"
                                id="password"
                                value={formData.password}
                                onChange={handleChange}
                            />
                            <button
                                type="button"
                                className="absolute top-2 right-3 focus:outline-none"
                                onClick={togglePasswordVisibility}
                            >
                                {showPassword ? (
                                    <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.5c5.185 0 9.448 4.014 9.95 9.048a.944.944 0 0 1 0 .904C21.448 16.486 17.185 20.5 12 20.5S2.552 16.486 2.05 13.452a.944.944 0 0 1 0-.904C2.552 8.514 6.815 4.5 12 4.5zM12 6a9 9 0 0 0-8.72 6.752.944.944 0 0 1 0 .496A9 9 0 0 0 12 18a9 9 0 0 0 8.72-4.752.944.944 0 0 1 0-.496A9 9 0 0 0 12 6z" />
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 12.75a2.25 2.25 0 1 1 0-4.5 2.25 2.25 0 0 1 0 4.5z" />
                                    </svg>
                                ) : (
                                    <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 15a7 7 0 01-7-7M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                    </svg>
                                )}
                            </button>
                        </div>
                    </div>
                    <Button className="bg-slate-500" gradientDuoTone='purpleToBlue' type="submit">
                        {loading ? (
                            <>
                                <Spinner size='sm' />
                                <span className="pl-3">Loading</span>
                            </>
                        ) : 'Sign In'}
                    </Button>
                </form>
                
                <div className="flex gap-2 text-sm mt-5">
                    <span>Don't have an account?</span>
                    <Link to='/sign-up' className="text-blue-500">Sign Up</Link>
                </div>
                {error && (
                    <Alert className="mt-5" color='failure'>
                        {error}
                    </Alert>
                )}
            </div>
        </div>
    );
}
