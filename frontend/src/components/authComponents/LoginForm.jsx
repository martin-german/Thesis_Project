import FormError from "./FormError";
import GoogleAuthBtn from "../utilityComponents/GoogleAuthBtn";

function LoginForm({
  username,
  password,
  setUsername,
  setPassword,
  errors,
  successMessage,
  onGoogleLogin,
}) {
  return (
    <>
      <h2 className="text-xl font-bold mb-4">Login</h2>

      <div className="mb-2 w-full">
        <label
          htmlFor="username"
          className="block text-sm font-medium text-gray-800 mb-1"
        >
          Username
        </label>
        <input
          id="username"
          type="text"
          placeholder="Username"
          className={`w-full p-2 border rounded ${
            errors.username ? "border-red-500" : ""
          }`}
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        {errors.username && <FormError message={errors.username} />}
      </div>

      <div className="mb-2 w-full">
        <label
          htmlFor="password"
          className="block text-sm font-medium text-gray-800 mb-1"
        >
          Password
        </label>
        <input
          id="password"
          type="password"
          placeholder="Password"
          className={`w-full p-2 border rounded ${
            errors.password ? "border-red-500" : ""
          }`}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        {errors.password && <FormError message={errors.password} />}
      </div>

      {errors.general && (
        <p className="text-center font-bold text-red-600">{errors.general}</p>
      )}
      {successMessage && (
        <p className="text-center text-green-600 font-bold">{successMessage}</p>
      )}

      <div className="flex justify-center mt-4">
        <button
          type="submit"
          className="px-4 py-2 text-sm rounded-md font-bold transition duration-300 shadow-sm hover:shadow-lg bg-teal-600 hover:bg-teal-700 text-white"
          disabled={successMessage}
        >
          Login
        </button>
      </div>

      <div className="flex justify-center mt-4">
        <GoogleAuthBtn onSuccess={onGoogleLogin} />
      </div>
    </>
  );
}

export default LoginForm;
