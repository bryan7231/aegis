import { SignUp } from "@clerk/react";
import { useAuth } from "@clerk/react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useEffect } from "react";
import "./auth.css";

export default function SignUpPage() {
  const { isSignedIn, isLoaded } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (isLoaded && isSignedIn) {
      navigate({ to: "/", replace: true });
    }
  }, [isLoaded, isSignedIn, navigate]);

  return (
    <div className="auth-page">
      <h1 className="auth-brand">Aegis</h1>
      <SignUp routing="hash" />
      <p className="auth-switch">
        Already have an account? <Link to="/sign-in">Sign in</Link>
      </p>
    </div>
  );
}
