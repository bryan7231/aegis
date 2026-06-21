import { SignIn } from "@clerk/react";
import { useAuth } from "@clerk/react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useEffect } from "react";

export default function SignInPage() {
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
      <SignIn routing="hash" />
      <p className="m-0 text-sm text-muted-foreground">
        Don't have an account?{" "}
        <Link to="/sign-up" className="text-primary hover:underline">
          Sign up
        </Link>
      </p>
    </div>
  );
}
