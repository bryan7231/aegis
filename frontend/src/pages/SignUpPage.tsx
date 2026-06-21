import { SignUp } from "@clerk/react";
import { useAuth } from "@clerk/react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useEffect } from "react";

export default function SignUpPage() {
  const { isSignedIn, isLoaded } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (isLoaded && isSignedIn) {
      navigate({ to: "/", replace: true });
    }
  }, [isLoaded, isSignedIn, navigate]);

  return (
    <div className="flex min-h-svh flex-col items-center justify-center gap-6 px-4 py-8">
      <h1 className="m-0 text-3xl font-semibold tracking-tight">Aegis</h1>
      <SignUp routing="hash" />
      <p className="m-0 text-sm text-muted-foreground">
        Already have an account?{" "}
        <Link to="/sign-in" className="text-primary hover:underline">
          Sign in
        </Link>
      </p>
    </div>
  );
}
