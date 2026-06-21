import {
  createRouter,
  createRoute,
  createRootRoute,
  Outlet,
} from "@tanstack/react-router";
import { useAuth } from "@clerk/react";
import { useEffect } from "react";
import { useNavigate } from "@tanstack/react-router";
import { configureAuth } from "@/lib/api";
import App from "./pages/App";
import { ProjectPage } from "./pages/ProjectPage";
import { LandingPage } from "./pages/LandingPage";
import SignInPage from "./pages/SignInPage";
import SignUpPage from "./pages/SignUpPage";

function AuthLayout() {
  const { isSignedIn, isLoaded, getToken } = useAuth();
  const navigate = useNavigate();

  // Called during render (not useEffect) so _getToken is set before
  // any child component's useEffect fires and makes API requests.
  configureAuth(getToken);

  useEffect(() => {
    if (isLoaded && !isSignedIn) {
      navigate({ to: "/landing", replace: true });
    }
  }, [isLoaded, isSignedIn, navigate]);

  if (!isLoaded) return <div className="flex min-h-svh items-center justify-center text-muted-foreground">Loading…</div>;
  if (!isSignedIn) return null;

  return <Outlet />;
}

const rootRoute = createRootRoute();

const landingRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/landing",
  component: LandingPage,
});

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

const projectRoute = createRoute({
  getParentRoute: () => authRoute,
  path: "/projects/$projectId",
  component: ProjectPage,
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
  landingRoute,
  authRoute.addChildren([indexRoute, projectRoute]),
  signInRoute,
  signUpRoute,
]);

export const router = createRouter({ routeTree });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
