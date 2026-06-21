import {
  createRouter,
  createRoute,
  createRootRoute,
  Outlet,
} from "@tanstack/react-router";
import { useAuth } from "@clerk/react";
import { useEffect } from "react";
import { useNavigate } from "@tanstack/react-router";
import App from "./pages/App";
import SignInPage from "./pages/SignInPage";
import SignUpPage from "./pages/SignUpPage";

function AuthLayout() {
  const { isSignedIn, isLoaded } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (isLoaded && !isSignedIn) {
      navigate({ to: "/sign-in", replace: true });
    }
  }, [isLoaded, isSignedIn, navigate]);

  if (!isLoaded) return <div className="flex min-h-svh items-center justify-center text-muted-foreground">Loading…</div>;
  if (!isSignedIn) return null;

  return <Outlet />;
}

const rootRoute = createRootRoute();

const authRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: "auth",
  component: AuthLayout,
});

const indexRoute = createRoute({
  getParentRoute: () => authRoute,
  path: "/",
  component: App,
});

const signInRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sign-in",
  component: SignInPage,
});

const signUpRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sign-up",
  component: SignUpPage,
});

const routeTree = rootRoute.addChildren([
  authRoute.addChildren([indexRoute]),
  signInRoute,
  signUpRoute,
]);

export const router = createRouter({ routeTree });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
