import { useState } from "react";
import { Alert, Button, Label, TextInput, Spinner } from "flowbite-react";
import { Link, useNavigate } from "react-router-dom";

export default function SignUp() {
    const [formData, setFormData] = useState({});
    const [error, setError] = useState(false);
    const [loading, setLoading] = useState(false);
    const [showPassword, setShowPassword] = useState(false);
    const navigate = useNavigate();

    const handleChange = (e) => {
        setFormData({ ...formData, [e.target.id]: e.target.value.trim() });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!formData.username || !formData.password || !formData.email) {
            return setError('Please Fill all Fields');
        }

        try {
            setLoading(true);
            setError(false);
            const res = await fetch('/api/auth/signup', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(formData),
            });

            const data = await res.json();
            console.log(data);
            setLoading(false);
            if (data.success === false) {
                setError(data.message);
                return;
            }
            navigate('/');
        } catch (error) {
            setLoading(false);
            setError(error.message);
        }
    };

    const togglePasswordVisibility = () => {
        setShowPassword(!showPassword);
    };

    return (
        <div
            className="min-h-screen flex items-center justify-center"
            style={{
                backgroundImage: `url('')`,
                backgroundSize: 'cover',
                backgroundPosition: 'center',
                backgroundRepeat: 'no-repeat',
            }}
        >
            <div className="p-6 max-w-lg w-full bg-white bg-opacity-80 rounded-lg shadow-lg">
                <p className="text-center text-2xl font-cinzel font-semibold">Sign Up</p>
                <form className="flex flex-col gap-4 mt-5" onSubmit={handleSubmit}>
                    <div>
                        <Label value="Your username" />
                        <TextInput type="text" placeholder="User Name" id="username" onChange={handleChange} />
                    </div>
                    <div>
                        <Label value="Your email" />
                        <TextInput type="email" placeholder="name@company.com" id="email" onChange={handleChange} />
                    </div>
                    <div>
                        <Label value="Your password" />
                        <div className="relative">
                            <TextInput
                                type={showPassword ? "text" : "password"}
                                placeholder="Password"
                                id="password"
                                onChange={handleChange}
                            />
                            <button
                                type="button"
                                className="absolute top-2 right-3 focus:outline-none"
                                onClick={togglePasswordVisibility}
                            >
                                {showPassword ? (
                                    <svg
                                        xmlns="http://www.w3.org/2000/svg"
                                        className="h-6 w-6 text-gray-500"
                                        fill="none"
                                        viewBox="0 0 24 24"
                                        stroke="currentColor"
                                    >
                                        <path
                                            strokeLinecap="round"
                                            strokeLinejoin="round"
                                            strokeWidth={2}
                                            d="M12 4.5c5.185 0 9.448 4.014 9.95 9.048a.944.944 0 0 1 0 .904C21.448 16.486 17.185 20.5 12 20.5S2.552 16.486 2.05 13.452a.944.944 0 0 1 0-.904C2.552 8.514 6.815 4.5 12 4.5zM12 6a9 9 0 0 0-8.72 6.752.944.944 0 0 1 0 .496A9 9 0 0 0 12 18a9 9 0 0 0 8.72-4.752.944.944 0 0 1 0-.496A9 9 0 0 0 12 6z"
                                        />
                                        <path
                                            strokeLinecap="round"
                                            strokeLinejoin="round"
                                            strokeWidth={2}
                                            d="M12 12.75a2.25 2.25 0 1 1 0-4.5 2.25 2.25 0 0 1 0 4.5z"
                                        />
                                    </svg>
                                ) : (
                                    <svg
                                        xmlns="http://www.w3.org/2000/svg"
                                        className="h-6 w-6 text-gray-500"
                                        fill="none"
                                        viewBox="0 0 24 24"
                                        stroke="currentColor"
                                    >
                                        <path
                                            strokeLinecap="round"
                                            strokeLinejoin="round"
                                            strokeWidth={2}
                                            d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
                                        />
                                        <path
                                            strokeLinecap="round"
                                            strokeLinejoin="round"
                                            strokeWidth={2}
                                            d="M11 15a7 7 0 01-7-7M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                                        />
                                    </svg>
                                )}
                            </button>
                        </div>
                    </div>
                    <Button disabled={loading} type="submit" className="bg-slate-500">
                        {loading ? (
                            <>
                                <Spinner size="sm" />
                                <span className="pl-3">Loading</span>
                            </>
                        ) : (
                            'Sign Up'
                        )}
                    </Button>
                    
                </form>
                <div className="flex gap-2 text-sm mt-5">
                    <span>Have an Account?</span>
                    <Link to="/sign-in" className="text-blue-500">
                        Sign In
                    </Link>
                </div>
                <div className="text-red-600">
                    {error && (
                        <Alert className="mt-5" color="failure">
                            {error}
                        </Alert>
                    )}
                </div>
            </div>
        </div>
    );
}
