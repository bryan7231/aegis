import { SignIn } from "@clerk/react";
import { useAuth } from "@clerk/react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useEffect } from "react";
import "./auth.css";

export default function SignInPage() {
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
      <SignIn routing="hash" />
      <p className="auth-switch">
        Don't have an account? <Link to="/sign-up">Sign up</Link>
      </p>
    </div>
  );
}
